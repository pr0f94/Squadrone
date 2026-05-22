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
from ..schemas.hypothesis import BugClass, Hypothesis
from .prompts_io import load_prompt
from .tools import CONSULT_DEVELOPER_TOOL, READ_PLUGIN_FILE_TOOL, REQUEST_ADDITIONAL_SETUP_TOOL

if TYPE_CHECKING:
    from .runtime import AgentRuntime

# W9 callback type — async fn(description: str) -> confirmation str
from typing import Awaitable, Callable
SetupCallback = Callable[[str], Awaitable[str]]

logger = logging.getLogger(__name__)


_BUG_CLASS_TEMPLATE: dict[str, str] = {
    BugClass.SQLI.value: "sqli_timebased.py.j2",
    BugClass.MISSING_CAP_CHECK.value: "auth_bypass.py.j2",
    BugClass.MISSING_NONCE.value: "auth_bypass.py.j2",
    BugClass.PATH_TRAVERSAL.value: "path_traversal.py.j2",
    BugClass.ARBITRARY_FILE_WRITE.value: "file_upload.py.j2",
    BugClass.SSRF.value: "ssrf.py.j2",
}

_FENCE_BLOCK_RE = re.compile(r"```(?:python)?\s*\n(.*?)\n```", re.DOTALL)


def _select_template(bug_class: str) -> str:
    return _BUG_CLASS_TEMPLATE.get(bug_class, "auth_bypass.py.j2")


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
    INTERNAL_RETRIES = 2  # extra LLM calls per write() if the response isn't valid Python
    READ_FILE_MAX_BYTES = 60_000  # cap any single read_plugin_file response
    MAX_ITERATIONS = 12  # tool-loop turns per write() call. File-ops PoCs need more recon than auth/xss.
    FORCE_FINALISE_AFTER = 8  # nudge the agent to stop investigating after N tool calls

    def __init__(
        self,
        runtime: "AgentRuntime",
        model: str,
        plugin_root: Optional[str] = None,
        # W9: collaborative dev+poc loop — when supplied, the LLM gets a tool to ask
        # for additional sandbox setup mid-write. The callback receives a free-form
        # description and returns a confirmation string (or error message).
        setup_callback: Optional["SetupCallback"] = None,
    ):
        self.runtime = runtime
        self.model = model
        self.plugin_root = Path(plugin_root).resolve() if plugin_root else None
        self.setup_callback = setup_callback

    async def _request_additional_setup(self, args: dict) -> str:
        """W9 tool handler. Async — calls the closure that the verify orchestrator
        provides; that closure dispatches to developer.propose_setup_followup, runs
        the resulting commands against the live sb, and returns a summary."""
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
        """Tool handler: read a file from the plugin source dir, capped to keep tokens bounded."""
        if self.plugin_root is None:
            return "[read_plugin_file] no plugin_root configured for this run"
        rel = (args.get("path") or "").strip()
        max_lines = int(args.get("max_lines") or 500)
        if not rel:
            return "[read_plugin_file] missing required `path` argument"
        target = (self.plugin_root / rel).resolve()
        # Constrain to plugin dir — no traversal escape
        try:
            target.relative_to(self.plugin_root)
        except ValueError:
            return f"[read_plugin_file] refused: '{rel}' resolves outside plugin root"
        if not target.is_file():
            return f"[read_plugin_file] not found: {rel} (resolved to {target})"
        try:
            text = target.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            return f"[read_plugin_file] read failed: {e}"
        lines = text.splitlines()
        truncated = False
        if len(lines) > max_lines:
            lines = lines[:max_lines]
            truncated = True
        out = "\n".join(lines)
        if len(out) > self.READ_FILE_MAX_BYTES:
            out = out[: self.READ_FILE_MAX_BYTES]
            truncated = True
        if truncated:
            out += f"\n\n... [truncated; full file is {len(text)} bytes / {len(text.splitlines())} lines]"
        return f"--- {rel} ---\n{out}"

    def _read_entry_point_source(self, hypothesis: Hypothesis, max_lines: int = 600) -> Optional[str]:
        if self.plugin_root is None or not hypothesis.file:
            return None
        rel = hypothesis.file
        candidate = self.plugin_root / rel
        if not candidate.is_file():
            # Try stripping common path prefixes
            slug = self.plugin_root.name
            for prefix in (f"wp-content/plugins/{slug}/", f"{slug}/"):
                if rel.startswith(prefix):
                    candidate = self.plugin_root / rel[len(prefix):]
                    if candidate.is_file():
                        break
        if not candidate.is_file():
            return None
        try:
            text = candidate.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        lines = text.splitlines()
        truncated = len(lines) > max_lines
        if truncated:
            lines = lines[:max_lines]
        body = "\n".join(lines)
        if truncated:
            body += f"\n\n... [truncated; full file is {len(text.splitlines())} lines]"
        return body

    async def write(
        self,
        hypothesis: Hypothesis,
        target_url: str,
        previous_attempts: list[PoCAttempt],
        extra_context: Optional[dict] = None,
    ) -> str:
        template_name = _select_template(hypothesis.bug_class.value)
        skeleton = _render_template(
            template_name,
            target_url=target_url,
            ajax_action=(extra_context or {}).get("ajax_action", hypothesis.entry_point),
            injectable_param=(extra_context or {}).get("injectable_param", "id"),
            test_username=(extra_context or {}).get("test_username", "subscriber_user"),
            test_password=(extra_context or {}).get("test_password", "password"),
            extra_params=(extra_context or {}).get("extra_params", ""),
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
            user_parts.append(f"ENTRY POINT SOURCE ({hypothesis.file}):\n```php\n{entry_source}\n```")
            user_parts.append(
                "You also have a `read_plugin_file(path)` tool. Use it to read any other "
                "file in the plugin (helper classes, included files, JS that consumes server "
                "output, the shortcode rendering file, etc.) instead of asking the developer."
            )
        setup_summary = (extra_context or {}).get("setup_summary")
        if setup_summary:
            user_parts.append(f"SANDBOX SETUP:\n{setup_summary}")
        if previous_attempts:
            history = "\n\n".join(
                f"--- attempt {a.iteration} ---\n"
                f"result={a.result.value} http_status={a.http_status}\n"
                f"response: {(a.response_snippet or '')[:300]}\n"
                f"errors:   {(a.error_log_snippet or '')[:300]}\n"
                f"developer_analysis: {a.developer_analysis or '(none)'}"
                for a in previous_attempts
            )
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
                attempt + 1, 1 + self.INTERNAL_RETRIES, reason,
            )
            # Append corrective feedback for next try
            messages = messages + [
                {"role": "assistant", "content": str(result.output)},
                {"role": "user", "content": (
                    f"Your previous response was not runnable Python: {reason}. "
                    "Output ONLY the complete Python script — start with `import` statements, "
                    "no prose, no markdown fences, no explanation. The script must be valid "
                    "Python that can be passed to python3 directly."
                )},
            ]

        logger.error("poc_author: gave up after %d attempts; returning best effort (%s)",
                     1 + self.INTERNAL_RETRIES, last_reason)
        return last_script
