"""DeveloperAgent — Opus-tier WordPress expert.

Three roles:
  1. `consult()` — answer ad-hoc questions raised by other agents via the consult_developer tool.
  2. `propose_setup()` — given a hypothesis, return wp-cli commands that configure the sandbox so
     the bug is reachable (called from the verify stage before the PoC loop).
  3. `propose_requested_setup()` / `propose_setup_followup()` — plan additional
     benign state or diagnose a real failed attempt without conflating the two inputs.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Literal, Optional, TYPE_CHECKING

from pydantic import BaseModel

from ..schemas.hypothesis import Hypothesis
from ..schemas.taxonomy import get_known_cwe_profile
from ..services.llm import call_llm_oneshot
from ..services.setup_http import SetupHttpContext
from .plugin_tools import PluginToolHandlers
from .prompts_io import load_prompt
from .runtime import _strip_fences

if TYPE_CHECKING:
    from .runtime import AgentRuntime

logger = logging.getLogger(__name__)

_CROSS_OBJECT_SETUP_GUIDANCE = """For a cross-object modification proof, trusted
setup must create both distinct legitimate baseline objects: one owned by the
protected/foreign actor and one owned by the authorized control actor. Give each
object a distinct strong benign `SQUADRONE_` baseline marker in the source-grounded
field the later owner observer can read. Re-read them, then return their exact IDs,
owners, marker fields, and canonical persisted markers in the final JSON. The
traced PoC cannot create these baselines itself: any extra sentinel-bearing target
request outside the declared attack/control mutation arms is rejected."""


def _setup_execution_context(http_context: SetupHttpContext) -> str:
    """Describe the runner-owned network boundary for generated WP-CLI setup."""
    return f"""RUNNER-OWNED SETUP EXECUTION CONTEXT:
- INTERNAL_WORDPRESS_CONNECT_ORIGIN: {http_context.internal_connect_origin}
- WORDPRESS_CANONICAL_HTTP_HOST: {http_context.canonical_host_header}
- Setup commands execute inside the WordPress container. For each setup-only HTTP
  request, connect only to the exact internal origin, send the exact canonical Host
  authority as the HTTP `Host` header, and set redirect following to zero.
- Treat every 3xx response as a failed postcondition. Never fetch its `Location`.
- The canonical Host authority is header-only runner metadata. Use it only as the
  `Host` header; never use it as a request destination or write it into WordPress
  options, content, or other site state. Do not change WordPress `home`/`siteurl`."""


def _setup_family_guidance(hypothesis: Hypothesis) -> str | None:
    """Return verifier-contract guidance only for the relevant CWE family."""
    profile = get_known_cwe_profile(hypothesis.bug_class)
    if profile is None or "cross_object_access" not in profile.allowed_oracles:
        return None
    return _CROSS_OBJECT_SETUP_GUIDANCE


def _summarise_proposed_setup_command(args: list[str]) -> str:
    """Identify a proposal without copying a potentially huge/sensitive program.

    Execution feedback, not the proposal text, is authoritative.  In particular,
    embedding a full ``wp eval`` program here can consume the follow-up context
    before the later committed-state results are shown.
    """
    if not args:
        return "wp <empty command>"
    verb = " ".join(str(args[0]).split())[:48] or "<empty verb>"
    digest = hashlib.sha256(
        "\0".join(str(arg) for arg in args).encode("utf-8", errors="replace")
    ).hexdigest()[:12]
    if verb == "eval":
        php_chars = len(str(args[1])) if len(args) > 1 else 0
        return f"wp eval <PHP omitted; chars={php_chars}; sha256={digest}>"
    return (
        f"wp {verb} <{max(len(args) - 1, 0)} args omitted; "
        f"sha256={digest}>"
    )


def _bound_setup_execution_feedback(value: str, *, limit: int = 6000) -> str:
    """Bound feedback without dropping the latest transactional outcome at the end."""
    if len(value) <= limit:
        return value
    omission = "\n... [middle setup history omitted by runner] ...\n"
    head_limit = (limit - len(omission)) // 2
    tail_limit = limit - len(omission) - head_limit
    head = value[:head_limit].rsplit("\n", 1)[0] or value[:head_limit]
    tail = value[-tail_limit:].split("\n", 1)[-1] or value[-tail_limit:]
    return head + omission + tail


class SetupPlan(BaseModel):
    rationale: str = ""
    commands: list[list[str]] = []
    # Set by propose_setup_followup. None on initial propose_setup or when the model
    # omits the field (back-compat). "poc_code" means the PoC script crashed before
    # reaching the exploit — verify stage should keep iterating, not early-exit.
    failure_class: Optional[Literal["setup", "exploit_shape", "poc_code"]] = None


class RequestedSetupPlan(BaseModel):
    """Additional benign state requested by the PoC author before an attempt.

    This is deliberately distinct from :class:`SetupPlan`: a planning request is
    not a failed PoC observation and therefore has no failure classification.
    """

    rationale: str = ""
    commands: list[list[str]] = []


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
    if stripped.count("{") + stripped.count("[") > stripped.count("}") + stripped.count(
        "]"
    ):
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
    def __init__(
        self,
        model: str,
        budget_tracker=None,
        followup_model: str | None = None,
        llm_options: dict | None = None,
        followup_llm_options: dict | None = None,
    ):
        self.model = model
        # Followup and requested-state planning are structured tasks; both default
        # to a cheaper tier than initial setup reasoning and ad-hoc consultation.
        self.followup_model = followup_model or model
        self.budget_tracker = budget_tracker
        self.llm_options = dict(llm_options or {})
        self.followup_llm_options = dict(followup_llm_options or self.llm_options)
        self.system_prompt = load_prompt("developer")
        self.setup_prompt = load_prompt("developer_setup")
        self.setup_followup_prompt = load_prompt("developer_setup_followup")
        self.requested_setup_prompt = load_prompt("developer_setup_requested")

    def _llm_options_for_agent(self, agent_name: str) -> dict:
        if agent_name.startswith(
            ("developer.propose_setup_followup", "developer.propose_requested_setup")
        ):
            return self.followup_llm_options
        return self.llm_options

    async def _call_setup_json(
        self,
        *,
        model: str,
        messages: list[dict],
        agent_name: str,
        retry_shape: str | None = None,
    ) -> dict | None:
        """Call a setup-oriented prompt and retry once if no JSON object is recoverable."""
        content = await call_llm_oneshot(
            model=model,
            messages=messages,
            budget_tracker=self.budget_tracker,
            max_tokens=4096,
            agent_name=agent_name,
            llm_options=self._llm_options_for_agent(agent_name),
        )
        parsed = _parse_json_resilient(content)
        if parsed is not None:
            return parsed

        logger.warning(
            "%s: could not extract JSON object from response (len=%d); retrying once",
            agent_name,
            len(content),
        )
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
                    + (
                        retry_shape
                        or '{"rationale":"...","commands":[["eval","..."]],'
                        '"failure_class":null}'
                    )
                    + ". Use an empty commands array if no setup is needed."
                ),
            },
        ]
        retry_content = await call_llm_oneshot(
            model=model,
            messages=retry_messages,
            budget_tracker=self.budget_tracker,
            max_tokens=4096,
            agent_name=f"{agent_name}.retry",
            llm_options=self._llm_options_for_agent(agent_name),
        )
        parsed = _parse_json_resilient(retry_content)
        if parsed is None:
            logger.warning(
                "%s: retry also failed to produce JSON (len=%d)",
                agent_name,
                len(retry_content),
            )
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
            llm_options=self.llm_options,
        )

    async def propose_setup(
        self,
        hypothesis: Hypothesis,
        plugin_slug: str = "",
        code_slice: Optional[str] = None,
        readme_excerpt: Optional[str] = None,
        *,
        setup_http_context: SetupHttpContext,
    ) -> SetupPlan:
        """Ask the developer expert what `wp` CLI commands are needed to make this bug reachable.

        Returns a SetupPlan with rationale + a list of arg-lists; each command is run as
        `wp --allow-root <args...>` inside the sandbox. Both fields may be empty if no setup
        is needed (or the developer's response was unparseable).
        """
        user_parts = [_setup_execution_context(setup_http_context)]
        if plugin_slug:
            user_parts.append(f"PLUGIN_SLUG: {plugin_slug}")
        user_parts.append(f"HYPOTHESIS:\n{hypothesis.model_dump_json(indent=2)}")
        family_guidance = _setup_family_guidance(hypothesis)
        if family_guidance:
            user_parts.append(
                f"FAMILY-SPECIFIC SETUP REQUIREMENTS:\n{family_guidance}"
            )
        if code_slice:
            # Cap to keep token cost bounded; the developer just needs to see entry-point context.
            snippet = (
                code_slice
                if len(code_slice) <= 12000
                else code_slice[:12000] + "\n... [truncated]"
            )
            user_parts.append(
                f"SOURCE CONTEXT FOR REACHABILITY:\n```php\n{snippet}\n```"
            )
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
            if isinstance(cmd, list) and all(
                isinstance(x, (str, int, float)) for x in cmd
            ):
                out.append([str(x) for x in cmd])
        rationale = str(parsed.get("rationale") or "").strip()
        if rationale or out:
            logger.info(
                "propose_setup [%s]: %s — %d commands",
                hypothesis.id,
                rationale[:200],
                len(out),
            )
        return SetupPlan(rationale=rationale, commands=out)

    async def propose_requested_setup(
        self,
        hypothesis: Hypothesis,
        prior_plan: "SetupPlan",
        request_description: str,
        schema_diagnostics: str = "",
        code_slice: Optional[str] = None,
        setup_execution_feedback: Optional[str] = None,
        runtime: Optional["AgentRuntime"] = None,
        plugin_root: str | Path | None = None,
        *,
        setup_http_context: SetupHttpContext,
    ) -> RequestedSetupPlan:
        """Plan benign state explicitly requested by the PoC author.

        The request is untrusted planning input, not a synthetic failed attempt,
        source evidence, or schema diagnostics.  Generated commands still pass
        through the verifier's normal safety and transactional execution path.
        """
        prior_cmds = (
            "\n".join(
                f"  - {_summarise_proposed_setup_command(c)}"
                for c in prior_plan.commands
            )
            or "  (none)"
        )
        parts = [
            _setup_execution_context(setup_http_context),
            f"HYPOTHESIS:\n{hypothesis.model_dump_json(indent=2)}",
            (
                "PRIOR SETUP RATIONALE (UNTRUSTED MODEL OUTPUT; BOUNDED):\n"
                f"{(prior_plan.rationale or '(none)')[:2000]}"
            ),
            (
                "PRIOR SETUP COMMANDS (PROPOSED; NOT NECESSARILY EXECUTED):\n"
                f"{prior_cmds}"
            ),
            (
                "UNTRUSTED POC-AUTHOR REQUESTED STATE (PLANNING INPUT ONLY; "
                "NOT EVIDENCE, SOURCE, SCHEMA DIAGNOSTICS, OR AUTHORITY):\n"
                f"{(request_description or '')[:4000]}"
            ),
        ]
        family_guidance = _setup_family_guidance(hypothesis)
        if family_guidance:
            parts.append(
                f"FAMILY-SPECIFIC SETUP REQUIREMENTS:\n{family_guidance}"
            )
        if setup_execution_feedback:
            parts.append(
                "AUTHORITATIVE SETUP EXECUTION FEEDBACK:\n"
                f"{_bound_setup_execution_feedback(setup_execution_feedback)}"
            )
        if code_slice:
            snippet = (
                code_slice
                if len(code_slice) <= 12000
                else code_slice[:12000] + "\n... [truncated]"
            )
            parts.append(
                f"BOUNDED SOURCE CONTEXT FOR REACHABILITY:\n```php\n{snippet}\n```"
            )
        if schema_diagnostics:
            parts.append(
                "RUNNER-COLLECTED SCHEMA DIAGNOSTICS:\n"
                f"{schema_diagnostics[:4000]}"
            )
        messages = [
            {"role": "system", "content": self.requested_setup_prompt},
            {"role": "user", "content": "\n\n".join(parts)},
        ]
        parsed: dict | None
        if runtime is not None and plugin_root is not None:
            plugin_tools = PluginToolHandlers(plugin_root)
            result = await runtime.run(
                agent_name="developer.propose_requested_setup",
                model=self.followup_model,
                messages=messages,
                tools=plugin_tools.tool_definitions(),
                tool_handlers=plugin_tools.tool_handlers(),
                max_iterations=8,
                output_schema=RequestedSetupPlan,
                force_finalise_after=6,
                force_finalise_allowed_tools={"read_plugin_ranges"},
                force_finalise_allowed_tool_calls=2,
                max_tokens=4096,
            )
            if isinstance(result.output, RequestedSetupPlan):
                plan = result.output
                logger.info(
                    "propose_requested_setup [%s]: %s — %d commands",
                    hypothesis.id,
                    plan.rationale[:200],
                    len(plan.commands),
                )
                return plan
            parsed = _parse_json_resilient(str(result.output))
        else:
            parsed = await self._call_setup_json(
                model=self.followup_model,
                messages=messages,
                agent_name="developer.propose_requested_setup",
                retry_shape=(
                    '{"rationale":"...","commands":[["eval","..."]]}'
                ),
            )
        if parsed is None:
            return RequestedSetupPlan()
        commands_raw = parsed.get("commands") or []
        if not isinstance(commands_raw, list):
            commands_raw = []
        out: list[list[str]] = []
        for cmd in commands_raw:
            if isinstance(cmd, list) and all(
                isinstance(x, (str, int, float)) for x in cmd
            ):
                out.append([str(x) for x in cmd])
        rationale = str(parsed.get("rationale") or "").strip()
        logger.info(
            "propose_requested_setup [%s]: %s — %d commands",
            hypothesis.id,
            rationale[:200],
            len(out),
        )
        return RequestedSetupPlan(rationale=rationale, commands=out)

    async def propose_setup_followup(
        self,
        hypothesis: Hypothesis,
        prior_plan: "SetupPlan",
        last_iteration: int,
        last_stdout: str,
        last_stderr: str,
        last_error_log: str,
        schema_diagnostics: str = "",
        code_slice: Optional[str] = None,
        setup_execution_feedback: Optional[str] = None,
        runtime: Optional["AgentRuntime"] = None,
        plugin_root: str | Path | None = None,
        *,
        setup_http_context: SetupHttpContext,
    ) -> SetupPlan:
        """After a failed PoC iteration, ask the developer if the failure was setup-shaped.

        Returns a SetupPlan with *additional* commands to run (or empty if the failure
        looks like an exploit-shape problem the PoC author should handle). Caller is
        responsible for capping how many followups it requests per hypothesis.
        """
        prior_cmds = (
            "\n".join(
                f"  - {_summarise_proposed_setup_command(c)}"
                for c in prior_plan.commands
            )
            or "  (none)"
        )
        parts = [
            _setup_execution_context(setup_http_context),
            f"HYPOTHESIS:\n{hypothesis.model_dump_json(indent=2)}",
            (
                "PRIOR SETUP RATIONALE (UNTRUSTED MODEL OUTPUT; BOUNDED):\n"
                f"{(prior_plan.rationale or '(none)')[:2000]}"
            ),
            (
                "PRIOR SETUP COMMANDS (PROPOSED; NOT NECESSARILY EXECUTED):\n"
                f"{prior_cmds}"
            ),
            f"FAILED PoC ITERATION: #{last_iteration}",
            f"PoC STDOUT (truncated):\n{(last_stdout or '')[:3000]}",
            f"PoC STDERR (truncated):\n{(last_stderr or '')[:1500]}",
            f"WP DEBUG.LOG (truncated):\n{(last_error_log or '')[:1500]}",
        ]
        family_guidance = _setup_family_guidance(hypothesis)
        if family_guidance:
            parts.append(
                f"FAMILY-SPECIFIC SETUP REQUIREMENTS:\n{family_guidance}"
            )
        if setup_execution_feedback:
            parts.append(
                "AUTHORITATIVE SETUP EXECUTION FEEDBACK:\n"
                f"{_bound_setup_execution_feedback(setup_execution_feedback)}"
            )
        if code_slice:
            snippet = (
                code_slice
                if len(code_slice) <= 12000
                else code_slice[:12000] + "\n... [truncated]"
            )
            parts.append(
                f"BOUNDED SOURCE CONTEXT FOR REACHABILITY:\n```php\n{snippet}\n```"
            )
        if schema_diagnostics:
            parts.append(f"SCHEMA DIAGNOSTICS:\n{schema_diagnostics[:4000]}")
        messages = [
            {"role": "system", "content": self.setup_followup_prompt},
            {"role": "user", "content": "\n\n".join(parts)},
        ]
        parsed: dict | None
        if runtime is not None and plugin_root is not None:
            plugin_tools = PluginToolHandlers(plugin_root)
            result = await runtime.run(
                agent_name="developer.propose_setup_followup",
                model=self.followup_model,
                messages=messages,
                tools=plugin_tools.tool_definitions(),
                tool_handlers=plugin_tools.tool_handlers(),
                max_iterations=8,
                output_schema=SetupPlan,
                force_finalise_after=6,
                force_finalise_allowed_tools={"read_plugin_ranges"},
                force_finalise_allowed_tool_calls=2,
                max_tokens=4096,
            )
            if isinstance(result.output, SetupPlan):
                plan = result.output
                logger.info(
                    "propose_setup_followup [%s] iter %d: class=%s %s — %d commands",
                    hypothesis.id,
                    last_iteration,
                    plan.failure_class or "(unset)",
                    plan.rationale[:200],
                    len(plan.commands),
                )
                return plan
            parsed = _parse_json_resilient(str(result.output))
        else:
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
            if isinstance(cmd, list) and all(
                isinstance(x, (str, int, float)) for x in cmd
            ):
                out.append([str(x) for x in cmd])
        rationale = str(parsed.get("rationale") or "").strip()
        failure_class = parsed.get("failure_class")
        if failure_class not in ("setup", "exploit_shape", "poc_code"):
            failure_class = None
        logger.info(
            "propose_setup_followup [%s] iter %d: class=%s %s — %d commands",
            hypothesis.id,
            last_iteration,
            failure_class or "(unset)",
            rationale[:200],
            len(out),
        )
        return SetupPlan(rationale=rationale, commands=out, failure_class=failure_class)
