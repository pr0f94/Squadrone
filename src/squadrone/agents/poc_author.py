"""PoC author — picks a Jinja template, renders it, asks the LLM to refine."""

from __future__ import annotations

import ast
import logging
import re
from importlib.resources import files
from typing import TYPE_CHECKING, Optional

from jinja2 import Template

from pathlib import Path

from ..schemas.finding import PoCAttempt
from ..schemas.hypothesis import Hypothesis
from ..schemas.taxonomy import KNOWN_CWE_REGISTRY
from .plugin_tools import PluginToolHandlers
from .prompts_io import load_prompt
from .tools import (
    CONSULT_DEVELOPER_TOOL,
    READ_PLUGIN_FILE_TOOL,
    REQUEST_ADDITIONAL_SETUP_TOOL,
)

if TYPE_CHECKING:
    from .runtime import AgentRuntime

# Async callback used when a PoC needs additional legitimate sandbox setup.
from typing import Awaitable, Callable

SetupCallback = Callable[[str], Awaitable[str]]

logger = logging.getLogger(__name__)


_BUG_CLASS_TEMPLATE: dict[str, str] = {
    bug_class.value: profile.poc_template
    for bug_class, profile in KNOWN_CWE_REGISTRY.items()
    if profile.poc_template is not None
}

_FENCE_BLOCK_RE = re.compile(r"```(?:python)?\s*\n(.*?)\n```", re.DOTALL)


def _select_template(bug_class: str) -> str | None:
    return _BUG_CLASS_TEMPLATE.get(bug_class)


def _render_template(name: str, **vars) -> str:
    raw = (files("squadrone.poc_templates") / name).read_text()
    return Template(raw).render(**vars)


def _strip_to_script(text: str) -> str:
    """Extract a Python script from an LLM response: prefer fenced block, fall back to whole text."""
    s = text.strip()
    # Whole content fenced
    if s.startswith("```"):
        lines = s.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        return "\n".join(lines).strip()
    # Embedded fenced block — pick the first one
    m = _FENCE_BLOCK_RE.search(s)
    if m:
        return m.group(1).strip()
    return s


def _is_runnable_python(text: str) -> tuple[bool, str]:
    """Check whether `text` parses as Python AND looks like a real script (not prose)."""
    if not text.strip():
        return False, "empty"
    try:
        ast.parse(text)
    except SyntaxError as e:
        return False, f"SyntaxError: {e.msg} at line {e.lineno}"
    # Defence-in-depth: a single-string-literal "script" also parses but is useless prose.
    if "import " not in text and "from " not in text:
        return False, "no import statements found — looks like prose"
    return True, ""


class PoCAuthorAgent:
    NAME = "poc_author"
    PROMPT = "poc_author"
    INTERNAL_RETRIES = (
        2  # extra LLM calls per write() if the response isn't valid Python
    )
    MAX_ITERATIONS = (
        12  # Agent turns per write; file PoCs often need more source reads.
    )
    FORCE_FINALISE_AFTER = 8  # nudge the agent to stop investigating after N tool calls

    def __init__(
        self,
        runtime: "AgentRuntime",
        model: str,
        plugin_root: Optional[str] = None,
        # When supplied, the PoC author can request additional legitimate setup.
        setup_callback: Optional["SetupCallback"] = None,
    ):
        self.runtime = runtime
        self.model = model
        self.plugin_root = Path(plugin_root).resolve() if plugin_root else None
        self.plugin_tools = (
            PluginToolHandlers(self.plugin_root) if self.plugin_root else None
        )
        self.setup_callback = setup_callback

    async def _request_additional_setup(self, args: dict) -> str:
        """Apply developer-proposed setup through the live sandbox callback."""
        if self.setup_callback is None:
            return "[request_additional_setup] disabled: no setup_callback wired"
        description = (args.get("description") or "").strip()
        if not description:
            return "[request_additional_setup] missing required `description` argument"
        try:
            return await self.setup_callback(description)
        except Exception as e:
            return f"[request_additional_setup] callback raised: {e}"

    def _read_plugin_file(self, args: dict) -> str:
        """Use the same range-aware source reader as recon and specialists."""
        if self.plugin_tools is None:
            return "[read_plugin_file] no plugin_root configured for this run"
        return self.plugin_tools.read_plugin_file(args)

    def _read_entry_point_source(
        self, hypothesis: Hypothesis, max_lines: int = 600
    ) -> Optional[str]:
        if self.plugin_root is None or not hypothesis.file:
            return None
        rel = hypothesis.file
        candidate = self.plugin_root / rel
        if not candidate.is_file():
            # Try stripping common path prefixes
            slug = self.plugin_root.name
            for prefix in (f"wp-content/plugins/{slug}/", f"{slug}/"):
                if rel.startswith(prefix):
                    candidate = self.plugin_root / rel[len(prefix) :]
                    if candidate.is_file():
                        break
        if not candidate.is_file():
            return None
        try:
            text = candidate.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        lines = text.splitlines()
        start = max(0, hypothesis.line - 121)
        end = min(len(lines), start + max_lines)
        numbered = [f"{i + 1:5}  {lines[i]}" for i in range(start, end)]
        body = "\n".join(numbered)
        if start > 0 or end < len(lines):
            body += (
                f"\n\n... [showing lines {start + 1}-{end} of {len(lines)}; "
                "use read_plugin_file with start_line/end_line for other ranges]"
            )
        return body

    async def write(
        self,
        hypothesis: Hypothesis,
        target_url: str,
        previous_attempts: list[PoCAttempt],
        extra_context: Optional[dict] = None,
    ) -> str:
        template_name = _select_template(hypothesis.bug_class.value)
        if template_name is None:
            raise ValueError(
                f"no automatic PoC template is declared for {hypothesis.bug_class.value}"
            )
        skeleton = _render_template(
            template_name,
            target_url=target_url,
            ajax_action=(extra_context or {}).get(
                "ajax_action", hypothesis.entry_point
            ),
            injectable_param=(extra_context or {}).get("injectable_param", "id"),
            test_username=(extra_context or {}).get("test_username", "subscriber_user"),
            test_password=(extra_context or {}).get("test_password", "password"),
            extra_params=(extra_context or {}).get("extra_params", ""),
            attacker_role=(extra_context or {}).get("attacker_role")
            or (hypothesis.evidence_summary or {}).get("attacker_role")
            or "unknown",
        )

        system = load_prompt(self.PROMPT)
        user_parts = [
            f"TARGET_URL: {target_url}",
            f"HYPOTHESIS:\n{hypothesis.model_dump_json(indent=2)}",
            f"TEMPLATE ({template_name}):\n```python\n{skeleton}\n```",
        ]
        # Surface the sandbox's provisioned credentials as a structured table so
        # the PoC author picks from a known set instead of recalling defaults
        # from the system prompt (which can drift if sandbox config changes).
        user_accounts = (extra_context or {}).get("user_accounts") or []
        if user_accounts:
            account_lines = "\n".join(
                f"  - {a['login']!r} / {a['password']!r}  (role: {a['role']})"
                for a in user_accounts
            )
            user_parts.append(
                "USER_ACCOUNTS (provisioned by sandbox — use these exact credentials):\n"
                f"{account_lines}\n"
                "Pick the LOWEST-privilege account that satisfies your hypothesis "
                "preconditions. Use `from wp_login import wp_login` for the login flow."
            )
        entry_source = self._read_entry_point_source(hypothesis)
        if entry_source:
            user_parts.append(
                f"ENTRY POINT SOURCE ({hypothesis.file}):\n```php\n{entry_source}\n```"
            )
            user_parts.append(
                "You also have a `read_plugin_file(path, start_line, end_line)` tool. Use it to read any other "
                "file in the plugin (helper classes, included files, JS that consumes server "
                "output, the shortcode rendering file, etc.) instead of asking the developer."
            )
        setup_summary = (extra_context or {}).get("setup_summary")
        if setup_summary:
            user_parts.append(f"SANDBOX SETUP:\n{setup_summary}")
        if previous_attempts:
            history_parts: list[str] = []
            for attempt in previous_attempts[-3:]:
                script_excerpt = "(script unavailable)"
                try:
                    script_excerpt = Path(attempt.script_path).read_text(
                        encoding="utf-8",
                        errors="replace",
                    )[:4000]
                except OSError:
                    pass
                history_parts.append(
                    f"--- attempt {attempt.iteration} ---\n"
                    f"result={attempt.result.value} http_status={attempt.http_status}\n"
                    f"response: {(attempt.response_snippet or '')[:500]}\n"
                    f"errors:   {(attempt.error_log_snippet or '')[:500]}\n"
                    f"developer_analysis: {attempt.developer_analysis or '(none)'}\n"
                    f"script tried:\n```python\n{script_excerpt}\n```"
                )
            history = "\n\n".join(history_parts)
            user_parts.append(f"PREVIOUS ATTEMPTS:\n{history}")

        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": "\n\n".join(user_parts)},
        ]

        tools = [CONSULT_DEVELOPER_TOOL]
        tool_handlers: dict = {}
        if self.plugin_root is not None:
            tools.append(READ_PLUGIN_FILE_TOOL)
            tool_handlers["read_plugin_file"] = self._read_plugin_file
        if self.setup_callback is not None:
            tools.append(REQUEST_ADDITIONAL_SETUP_TOOL)
            tool_handlers["request_additional_setup"] = self._request_additional_setup

        last_script = ""
        last_reason = ""
        for attempt in range(1 + self.INTERNAL_RETRIES):
            result = await self.runtime.run(
                agent_name=self.NAME,
                model=self.model,
                messages=messages,
                tools=tools,
                tool_handlers=tool_handlers or None,
                max_iterations=self.MAX_ITERATIONS,
                force_finalise_after=self.FORCE_FINALISE_AFTER,
            )
            script = _strip_to_script(str(result.output))
            ok, reason = _is_runnable_python(script)
            if ok:
                return script
            last_script, last_reason = script, reason
            logger.warning(
                "poc_author: response not runnable Python (attempt %d/%d): %s",
                attempt + 1,
                1 + self.INTERNAL_RETRIES,
                reason,
            )
            # Append corrective feedback for next try
            messages = messages + [
                {"role": "assistant", "content": str(result.output)},
                {
                    "role": "user",
                    "content": (
                        f"Your previous response was not runnable Python: {reason}. "
                        "Output ONLY the complete Python script — start with `import` statements, "
                        "no prose, no markdown fences, no explanation. The script must be valid "
                        "Python that can be passed to python3 directly."
                    ),
                },
            ]

        logger.error(
            "poc_author: gave up after %d attempts; returning best effort (%s)",
            1 + self.INTERNAL_RETRIES,
            last_reason,
        )
        return last_script
