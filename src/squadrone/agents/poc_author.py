"""PoC author — picks a Jinja template, renders it, asks the LLM to refine."""

from __future__ import annotations

import ast
import json
import logging
import re
from importlib.resources import files
from typing import TYPE_CHECKING, Awaitable, Callable, Optional, TypedDict
from urllib.parse import parse_qsl, urlsplit

from jinja2 import Template

from pathlib import Path

from ..schemas.finding import PoCAttempt
from ..schemas.hypothesis import Hypothesis
from ..schemas.taxonomy import (
    BugClass,
    KNOWN_CWE_REGISTRY,
    OPEN_CWE_POC_TEMPLATE,
    get_known_cwe_profile,
)
from .plugin_tools import PluginToolHandlers
from .prompts_io import load_prompt
from .tools import (
    CONSULT_DEVELOPER_TOOL,
    REQUEST_ADDITIONAL_SETUP_TOOL,
)

if TYPE_CHECKING:
    from .runtime import AgentRuntime

SetupCallback = Callable[[str], Awaitable[str]]

logger = logging.getLogger(__name__)


_BUG_CLASS_TEMPLATE: dict[str, str] = {
    bug_class.value: profile.poc_template
    for bug_class, profile in KNOWN_CWE_REGISTRY.items()
    if profile.poc_template is not None
}
_OPEN_CWE_TEMPLATE = OPEN_CWE_POC_TEMPLATE

_FENCE_BLOCK_RE = re.compile(r"```(?:python)?\s*\n(.*?)\n```", re.DOTALL)
_HTTP_ENTRY_POINT_RE = re.compile(
    r"^\s*(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+"
    r"(?P<target>/\S*)(?:\s+(?:via\b|->).*)?\s*$",
    re.IGNORECASE,
)
_WORDPRESS_HOOK_ENTRY_POINT_RE = re.compile(
    r"^\s*(?P<prefix>wp_ajax_nopriv_|wp_ajax_|admin_post_nopriv_|admin_post_)"
    r"(?P<action>[A-Za-z0-9_.:-]+)(?:\s+(?:via\b|->).*)?\s*$"
)
_PHP_REQUEST_PARAMETER_RE = re.compile(
    r"\$_(?:GET|POST|REQUEST)\s*\[\s*(['\"])([A-Za-z_][A-Za-z0-9_.:-]{0,127})\1\s*\]",
    re.IGNORECASE,
)
_DESCRIBED_REQUEST_PARAMETER_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_.:-]{0,127})\s+"
    r"(?:query|string|form|body|json|request|url)\s+parameter\b",
    re.IGNORECASE,
)


class _EntryPointTransport(TypedDict):
    method: str
    route: str
    dispatch: dict[str, str]


def _select_template(bug_class: str) -> str | None:
    """Select an exact known template or the fail-closed open-CWE scaffold."""
    try:
        parsed = BugClass(bug_class)
    except (TypeError, ValueError):
        return None
    profile = get_known_cwe_profile(parsed)
    if profile is not None:
        return profile.poc_template
    return _OPEN_CWE_TEMPLATE


def _render_template(name: str, **vars) -> str:
    raw = (files("squadrone.poc_templates") / name).read_text()
    return Template(raw).render(**vars)


def _parse_entry_point_transport(entry_point: str) -> _EntryPointTransport:
    """Derive a conservative HTTP seed from a structured entry-point label.

    Only an explicit origin-relative HTTP entry or a standard WordPress action
    hook is recognized. Ambiguous prose deliberately produces empty values so
    the fail-closed PoC skeleton cannot turn a callback label into a live route.
    """
    fallback: _EntryPointTransport = {
        "method": "",
        "route": "",
        "dispatch": {},
    }
    if not isinstance(entry_point, str):
        return fallback

    http_match = _HTTP_ENTRY_POINT_RE.fullmatch(entry_point)
    if http_match:
        parsed = urlsplit(http_match.group("target"))
        route = parsed.path
        if (
            not route.startswith("/")
            or route.startswith("//")
            or parsed.scheme
            or parsed.netloc
            or parsed.fragment
        ):
            return fallback

        try:
            query_pairs = parse_qsl(
                parsed.query,
                keep_blank_values=True,
                strict_parsing=True,
            )
        except ValueError:
            query_pairs = []

        dispatch: dict[str, str] = {}
        query_keys = [key for key, _value in query_pairs]
        if len(query_keys) == len(set(query_keys)) and all(
            key.strip() and value.strip() for key, value in query_pairs
        ):
            dispatch = {
                f"query:{key}": value
                for key, value in sorted(query_pairs, key=lambda item: item[0])
            }

        return {
            "method": http_match.group("method").upper(),
            "route": route,
            "dispatch": dispatch,
        }

    hook_match = _WORDPRESS_HOOK_ENTRY_POINT_RE.fullmatch(entry_point)
    if not hook_match:
        return fallback
    prefix = hook_match.group("prefix")
    route = (
        "/wp-admin/admin-ajax.php"
        if prefix.startswith("wp_ajax_")
        else "/wp-admin/admin-post.php"
    )
    return {
        "method": "POST",
        "route": route,
        "dispatch": {"form:action": hook_match.group("action")},
    }


def _infer_injectable_parameter(hypothesis: Hypothesis) -> str:
    """Conservatively seed a named request parameter from structured evidence."""
    evidence = hypothesis.evidence_summary or {}
    values = [
        str(evidence.get("source") or ""),
        *[str(item) for item in hypothesis.taint_path],
        hypothesis.sink_code,
    ]
    for value in values:
        php_match = _PHP_REQUEST_PARAMETER_RE.search(value)
        if php_match:
            return php_match.group(2)
        described_match = _DESCRIBED_REQUEST_PARAMETER_RE.search(value)
        if described_match:
            return described_match.group(1)
    return "id"


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


def _format_previous_attempts(previous_attempts: list[PoCAttempt]) -> str:
    """Render bounded retry context, including the validator's authoritative reason."""
    history_parts: list[str] = []
    for attempt in previous_attempts[-3:]:
        script_excerpt = "(script unavailable)"
        validation_reason = (attempt.validation_reason or "(none provided)")[:1000]
        try:
            script_excerpt = Path(attempt.script_path).read_text(
                encoding="utf-8",
                errors="replace",
            )[:4000]
        except OSError:
            pass
        history_parts.append(
            f"--- attempt {attempt.iteration} ---\n"
            f"phase={attempt.phase} result={attempt.result.value} "
            f"http_status={attempt.http_status}\n"
            f"validator_rejection: {validation_reason}\n"
            f"response: {(attempt.response_snippet or '')[:500]}\n"
            f"errors:   {(attempt.error_log_snippet or '')[:500]}\n"
            f"developer_analysis: {attempt.developer_analysis or '(none)'}\n"
            f"script tried:\n```python\n{script_excerpt}\n```"
        )
    return "\n\n".join(history_parts)


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
        # Tool feedback is drained into an internal syntax retry exactly once. The
        # outer verifier independently rebuilds canonical setup context from its
        # execution ledger for later PoC attempts.
        self._pending_setup_feedback: list[str] = []

    async def _request_additional_setup(self, args: dict) -> str:
        """Apply developer-proposed setup through the live sandbox callback."""
        if self.setup_callback is None:
            return "[request_additional_setup] disabled: no setup_callback wired"
        description = (args.get("description") or "").strip()
        if not description:
            return "[request_additional_setup] missing required `description` argument"
        try:
            feedback = await self.setup_callback(description)
            self._pending_setup_feedback.append(feedback)
            return feedback
        except Exception as e:
            return f"[request_additional_setup] callback raised: {e}"

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
        # A completed prior write must never leak tool feedback into a new attempt.
        self._pending_setup_feedback.clear()
        template_name = _select_template(hypothesis.bug_class.value)
        if template_name is None:
            raise ValueError(
                f"no automatic PoC template is declared for {hypothesis.bug_class.value}"
            )
        entry_transport = _parse_entry_point_transport(hypothesis.entry_point)
        ssrf_oracle = (extra_context or {}).get("ssrf_oracle") or {}
        ssrf_oracle_mode = str(ssrf_oracle.get("mode") or "http")
        source_transport = (extra_context or {}).get("ssrf_http_transport")
        source_destination_parameter = ""
        source_destination_location = ""
        if isinstance(source_transport, dict):
            alternatives = source_transport.get("alternatives")
            if isinstance(alternatives, list) and alternatives:
                source_transport = alternatives[0]
            if (
                isinstance(source_transport, dict)
                and isinstance(source_transport.get("method"), str)
                and isinstance(source_transport.get("route"), str)
                and isinstance(source_transport.get("dispatch"), dict)
            ):
                entry_transport = {
                    "method": source_transport["method"],
                    "route": source_transport["route"],
                    "dispatch": dict(source_transport["dispatch"]),
                }
                if isinstance(
                    source_transport.get("destination_parameter"),
                    str,
                ):
                    source_destination_parameter = source_transport[
                        "destination_parameter"
                    ]
                if isinstance(source_transport.get("destination_location"), str):
                    source_destination_location = source_transport[
                        "destination_location"
                    ]
        skeleton = _render_template(
            template_name,
            bug_class=hypothesis.bug_class.value,
            target_url=target_url,
            ajax_action=(extra_context or {}).get(
                "ajax_action", hypothesis.entry_point
            ),
            injectable_param=(extra_context or {}).get("injectable_param")
            or source_destination_parameter
            or _infer_injectable_parameter(hypothesis),
            test_username=(extra_context or {}).get("test_username", ""),
            test_password=(extra_context or {}).get("test_password", ""),
            extra_params=(extra_context or {}).get("extra_params", ""),
            attacker_role=(extra_context or {}).get("attacker_role")
            or (hypothesis.evidence_summary or {}).get("attacker_role")
            or "unknown",
            request_method=entry_transport["method"],
            request_route=entry_transport["route"],
            request_dispatch=entry_transport["dispatch"],
            ssrf_attack_url=str(ssrf_oracle.get("attack_url") or ""),
            ssrf_control_url=str(ssrf_oracle.get("control_url") or ""),
            ssrf_oracle_mode=ssrf_oracle_mode,
            ssrf_destination_location=source_destination_location,
        )

        system = load_prompt(self.PROMPT)
        user_parts = [
            f"TARGET_URL: {target_url}",
            f"HYPOTHESIS:\n{hypothesis.model_dump_json(indent=2)}",
            f"TEMPLATE ({template_name}):\n```python\n{skeleton}\n```",
        ]
        if template_name == _OPEN_CWE_TEMPLATE:
            user_parts.append(
                "OPEN-CWE FALLBACK: This CWE has no specialized PoC template. "
                "Choose the existing structured oracle whose independently measured "
                "attack/control effect directly proves this hypothesis. Adapt the "
                "fail-closed scaffold from source evidence; do not infer an exploit "
                "shape from the CWE number alone."
            )
        # Surface the sandbox's provisioned credentials as a structured table so
        # the PoC author picks from a known set instead of recalling defaults
        # from the system prompt (which can drift if sandbox config changes).
        user_accounts = (extra_context or {}).get("user_accounts") or []
        if user_accounts:
            account_lines = "\n".join(
                f"  - {a['login']!r} / {a['password']!r}  "
                f"(role: {a['role']}, WordPress user ID: {a.get('id', 'unknown')})"
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
                "You also have bounded `grep_plugin`, `glob_plugin`, and "
                "`read_plugin_file` tools. Use them to locate and read other plugin "
                "files (helper classes, included files, installer/setup code, JS that "
                "consumes server output, shortcode rendering files, etc.) instead of "
                "asking the developer."
            )
        setup_summary = (extra_context or {}).get("setup_summary")
        if setup_summary:
            user_parts.append(f"SANDBOX SETUP:\n{setup_summary}")
        if hypothesis.bug_class == BugClass.SSRF:
            attack_url = str(ssrf_oracle.get("attack_url") or "")
            control_url = str(ssrf_oracle.get("control_url") or "")
            if attack_url and control_url:
                mode_guidance = (
                    "The URLs address a verifier-owned protected file outside the "
                    "web root. Submit them unchanged through the vulnerable URL "
                    "wrapper; never try to open the file from the PoC process. For "
                    "a direct unauthenticated PHP endpoint, the attack and control "
                    "must be the first two target requests: do not probe, discover, "
                    "visit the home page, or log in first."
                    if ssrf_oracle_mode == "local_resource"
                    else "The URLs address the verifier's parent-owned HTTP service. "
                    "Submit them unchanged through the vulnerable network-fetch path."
                )
                user_parts.append(
                    "TRUSTED_SSRF_ORACLE (verifier-owned; use these only as the "
                    "destination values submitted through the real vulnerable entry "
                    "point):\n"
                    + json.dumps(
                        {
                            "schema_version": 2,
                            "mode": ssrf_oracle_mode,
                            "attack_url": attack_url,
                            "control_url": control_url,
                        },
                        sort_keys=True,
                    )
                    + "\nThe expected response marker is deliberately withheld. Extract "
                    "a unique SQUADRONE_SSRF_<64 lowercase hex> marker dynamically "
                    "from the attack response and never place a SQUADRONE_ value in "
                    "any request. The parent independently validates the response and "
                    "oracle ledger. " + mode_guidance
                )
        if previous_attempts:
            user_parts.append(
                f"PREVIOUS ATTEMPTS:\n{_format_previous_attempts(previous_attempts)}"
            )

        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": "\n\n".join(user_parts)},
        ]

        tools = [CONSULT_DEVELOPER_TOOL]
        tool_handlers: dict = {}
        if self.plugin_tools is not None:
            tools.extend(self.plugin_tools.tool_definitions())
            tool_handlers.update(self.plugin_tools.tool_handlers())
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
                force_finalise_allowed_tools=(
                    {"request_additional_setup"}
                    if self.setup_callback is not None
                    else None
                ),
            )
            script = _strip_to_script(str(result.output))
            ok, reason = _is_runnable_python(script)
            if ok:
                self._pending_setup_feedback.clear()
                return script
            last_script, last_reason = script, reason
            logger.warning(
                "poc_author: response not runnable Python (attempt %d/%d): %s",
                attempt + 1,
                1 + self.INTERNAL_RETRIES,
                reason,
            )
            # A fresh runtime call does not inherit the prior tool transcript. Add
            # only feedback produced since the last call so exact setup object IDs
            # remain available without duplicating the original prompt state.
            setup_feedback = self._pending_setup_feedback
            self._pending_setup_feedback = []
            correction = (
                f"Your previous response was not runnable Python: {reason}. "
                "Output ONLY the complete Python script — start with `import` statements, "
                "no prose, no markdown fences, no explanation. The script must be valid "
                "Python that can be passed to python3 directly."
            )
            if setup_feedback:
                correction += (
                    "\n\nAUTHORITATIVE SETUP FEEDBACK FROM THE PRIOR TOOL TURN:\n"
                    + "\n\n".join(setup_feedback)
                    + "\nUse these exact returned values in the corrected script."
                )
            messages = messages + [
                {"role": "assistant", "content": str(result.output)},
                {"role": "user", "content": correction},
            ]

        logger.error(
            "poc_author: gave up after %d attempts; returning best effort (%s)",
            1 + self.INTERNAL_RETRIES,
            last_reason,
        )
        self._pending_setup_feedback.clear()
        return last_script
