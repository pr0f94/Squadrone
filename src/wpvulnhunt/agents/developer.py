"""DeveloperAgent — Opus-tier WordPress expert.

Two roles:
  1. `consult()` — answer ad-hoc questions raised by other agents via the consult_developer tool.
  2. `propose_setup()` — given a hypothesis, return wp-cli commands that configure the sandbox so
     the bug is reachable (called from the verify stage before the PoC loop).
"""

from __future__ import annotations

import json
import logging
from typing import Literal, Optional

from pydantic import BaseModel

from ..schemas.hypothesis import Hypothesis
from ..services.llm import call_llm_oneshot
from .prompts_io import load_prompt
from .runtime import _strip_fences

logger = logging.getLogger(__name__)


class SetupPlan(BaseModel):
    rationale: str = ""
    commands: list[list[str]] = []
    # Set by propose_setup_followup. None on initial propose_setup or when the model
    # omits the field (back-compat). "poc_code" means the PoC script crashed before
    # reaching the exploit — verify stage should keep iterating, not early-exit.
    failure_class: Optional[Literal["setup", "exploit_shape", "poc_code"]] = None


def _autoclose_unbalanced(content: str) -> str:
    """Repair a partially-emitted JSON value by inserting/appending missing closers.

    Walks the content tracking the bracket stack outside of string literals
    and emits a corrected version:
      - Any opener still on the stack at end-of-input has its matching closer
        appended (in correct nesting order).
      - A closer that does NOT match the current top of stack (e.g. a `}`
        emitted before the array it lives in was closed) is preceded by the
        closers needed to match — so `{[[]}` becomes `{[[]]}`.

    String literals are recognised; `\\"` escapes are honoured.

    Targets the LLM failure mode where the model emits almost-valid JSON but
    drops a trailing `]` or `}`.
    """
    result: list[str] = []
    stack: list[str] = []
    in_string = False
    escape = False
    for ch in content:
        if escape:
            result.append(ch)
            escape = False
            continue
        if in_string:
            result.append(ch)
            if ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
            result.append(ch)
            continue
        if ch == "{":
            stack.append("}")
            result.append(ch)
        elif ch == "[":
            stack.append("]")
            result.append(ch)
        elif ch in "}]":
            # Auto-insert intermediate closers if this closer doesn't match.
            while stack and stack[-1] != ch:
                result.append(stack.pop())
            if stack and stack[-1] == ch:
                stack.pop()
                result.append(ch)
            # else: stray closer with empty stack — drop it (input was already
            # malformed beyond what we can rescue).
        else:
            result.append(ch)
    # Append leftover closers in LIFO order
    while stack:
        result.append(stack.pop())
    return "".join(result)


def _parse_json_resilient(content: str) -> Optional[dict]:
    """Parse JSON from an LLM response, tolerating common malformations.

    Handles four common failure modes:
      1. Plain valid JSON (happy path)
      2. Trailing prose / second JSON object after the first ("Extra data" error)
      3. JSON wrapped in markdown fences or with leading prose
      4. Unbalanced/missing trailing brackets where a deeply nested commands
         array's outer `]` was omitted

    Returns the parsed dict, or None if no JSON object can be recovered.
    """
    if not content:
        return None
    stripped = _strip_fences(content).strip()
    # Fast path
    try:
        parsed = json.loads(stripped)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        pass
    # Bracket-balancing fallback: append missing closers and retry from each
    # candidate `{` start. Must come BEFORE the trailing-data fallback —
    # otherwise raw_decode finds a small INNER complete object and returns
    # it instead of recovering the outer (unclosed) one.
    if stripped.count("{") + stripped.count("[") > stripped.count("}") + stripped.count("]"):
        for start in (i for i, ch in enumerate(stripped) if ch == "{"):
            candidate = _autoclose_unbalanced(stripped[start:])
            try:
                parsed = json.loads(candidate)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                return parsed
    # Trailing-data fallback: extract the first complete JSON object.
    decoder = json.JSONDecoder()
    for start in (i for i, ch in enumerate(stripped) if ch == "{"):
        try:
            parsed, _end = decoder.raw_decode(stripped[start:])
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


class DeveloperAgent:
    def __init__(self, model: str, budget_tracker=None, followup_model: str | None = None):
        self.model = model
        # Followup is a structured diagnostic task; defaults to a cheaper tier than the
        # main developer model (which handles initial reasoning + ad-hoc consult).
        self.followup_model = followup_model or model
        self.budget_tracker = budget_tracker
        self.system_prompt = load_prompt("developer")
        self.setup_prompt = load_prompt("developer_setup")
        self.setup_followup_prompt = load_prompt("developer_setup_followup")

    async def _call_setup_json(self, *, model: str, messages: list[dict], agent_name: str) -> dict | None:
        """Call a setup-oriented prompt and retry once if no JSON object is recoverable."""
        content = await call_llm_oneshot(
            model=model,
            messages=messages,
            budget_tracker=self.budget_tracker,
            max_tokens=4096,
            agent_name=agent_name,
        )
        parsed = _parse_json_resilient(content)
        if parsed is not None:
            return parsed

        logger.warning("%s: could not extract JSON object from response (len=%d); retrying once",
                       agent_name, len(content))
        retry_messages = [
            *messages,
            {
                "role": "assistant",
                "content": content or "",
            },
            {
                "role": "user",
                "content": (
                    "Your previous response was empty or not valid JSON. "
                    "Return ONLY one JSON object matching this shape: "
                    "{\"rationale\":\"...\",\"commands\":[[\"eval\",\"...\"]],"
                    "\"failure_class\":null}. Use an empty commands array if no setup is needed."
                ),
            },
        ]
        retry_content = await call_llm_oneshot(
            model=model,
            messages=retry_messages,
            budget_tracker=self.budget_tracker,
            max_tokens=4096,
            agent_name=f"{agent_name}.retry",
        )
        parsed = _parse_json_resilient(retry_content)
        if parsed is None:
            logger.warning("%s: retry also failed to produce JSON (len=%d)",
                           agent_name, len(retry_content))
        return parsed

    async def consult(
        self,
        question: str,
        code_snippet: str,
        context: Optional[str] = None,
    ) -> str:
        user_parts = [f"QUESTION:\n{question}", f"CODE:\n```php\n{code_snippet}\n```"]
        if context:
            user_parts.append(f"CONTEXT:\n{context}")
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": "\n\n".join(user_parts)},
        ]
        return await call_llm_oneshot(
            model=self.model,
            messages=messages,
            budget_tracker=self.budget_tracker,
            agent_name="developer.consult",
        )

    async def propose_setup(
        self,
        hypothesis: Hypothesis,
        plugin_slug: str = "",
        code_slice: Optional[str] = None,
        readme_excerpt: Optional[str] = None,
    ) -> SetupPlan:
        """Ask the developer expert what `wp` CLI commands are needed to make this bug reachable.

        Returns a SetupPlan with rationale + a list of arg-lists; each command is run as
        `wp --allow-root <args...>` inside the sandbox. Both fields may be empty if no setup
        is needed (or the developer's response was unparseable).
        """
        user_parts = []
        if plugin_slug:
            user_parts.append(f"PLUGIN_SLUG: {plugin_slug}")
        user_parts.append(f"HYPOTHESIS:\n{hypothesis.model_dump_json(indent=2)}")
        if code_slice:
            # Cap to keep token cost bounded; the developer just needs to see entry-point context.
            snippet = code_slice if len(code_slice) <= 12000 else code_slice[:12000] + "\n... [truncated]"
            user_parts.append(f"CODE AT/AROUND ENTRY POINT ({hypothesis.file}):\n```php\n{snippet}\n```")
        if readme_excerpt:
            excerpt = readme_excerpt[:2000]
            user_parts.append(f"README EXCERPT:\n{excerpt}")
        messages = [
            {"role": "system", "content": self.setup_prompt},
            {"role": "user", "content": "\n\n".join(user_parts)},
        ]
        parsed = await self._call_setup_json(
            model=self.model,
            messages=messages,
            agent_name="developer.propose_setup",
        )
        if parsed is None:
            return SetupPlan()
        commands_raw = parsed.get("commands") or []
        if not isinstance(commands_raw, list):
            commands_raw = []
        out: list[list[str]] = []
        for cmd in commands_raw:
            if isinstance(cmd, list) and all(isinstance(x, (str, int, float)) for x in cmd):
                out.append([str(x) for x in cmd])
        rationale = str(parsed.get("rationale") or "").strip()
        if rationale or out:
            logger.info("propose_setup [%s]: %s — %d commands", hypothesis.id, rationale[:200], len(out))
        return SetupPlan(rationale=rationale, commands=out)

    async def propose_setup_followup(
        self,
        hypothesis: Hypothesis,
        prior_plan: "SetupPlan",
        last_iteration: int,
        last_stdout: str,
        last_stderr: str,
        last_error_log: str,
        schema_diagnostics: str = "",
    ) -> SetupPlan:
        """After a failed PoC iteration, ask the developer if the failure was setup-shaped.

        Returns a SetupPlan with *additional* commands to run (or empty if the failure
        looks like an exploit-shape problem the PoC author should handle). Caller is
        responsible for capping how many followups it requests per hypothesis.
        """
        prior_cmds = "\n".join(f"  - wp {' '.join(c)}" for c in prior_plan.commands) or "  (none)"
        parts = [
            f"HYPOTHESIS:\n{hypothesis.model_dump_json(indent=2)}",
            f"PRIOR SETUP RATIONALE:\n{prior_plan.rationale or '(none)'}",
            f"PRIOR SETUP COMMANDS (already executed):\n{prior_cmds}",
            f"FAILED PoC ITERATION: #{last_iteration}",
            f"PoC STDOUT (truncated):\n{(last_stdout or '')[:3000]}",
            f"PoC STDERR (truncated):\n{(last_stderr or '')[:1500]}",
            f"WP DEBUG.LOG (truncated):\n{(last_error_log or '')[:1500]}",
        ]
        if schema_diagnostics:
            parts.append(f"SCHEMA DIAGNOSTICS:\n{schema_diagnostics[:4000]}")
        messages = [
            {"role": "system", "content": self.setup_followup_prompt},
            {"role": "user", "content": "\n\n".join(parts)},
        ]
        parsed = await self._call_setup_json(
            model=self.followup_model,
            messages=messages,
            agent_name="developer.propose_setup_followup",
        )
        if parsed is None:
            return SetupPlan()
        commands_raw = parsed.get("commands") or []
        if not isinstance(commands_raw, list):
            commands_raw = []
        out: list[list[str]] = []
        for cmd in commands_raw:
            if isinstance(cmd, list) and all(isinstance(x, (str, int, float)) for x in cmd):
                out.append([str(x) for x in cmd])
        rationale = str(parsed.get("rationale") or "").strip()
        failure_class = parsed.get("failure_class")
        if failure_class not in ("setup", "exploit_shape", "poc_code"):
            failure_class = None
        logger.info("propose_setup_followup [%s] iter %d: class=%s %s — %d commands",
                    hypothesis.id, last_iteration, failure_class or "(unset)",
                    rationale[:200], len(out))
        return SetupPlan(rationale=rationale, commands=out, failure_class=failure_class)
