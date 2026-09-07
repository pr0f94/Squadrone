"""PoC author — picks a Jinja template, renders it, asks the LLM to refine."""

from __future__ import annotations

import ast
import json
import logging
import posixpath
import re
from importlib.resources import files
from typing import TYPE_CHECKING, Awaitable, Callable, Optional, TypedDict
from urllib.parse import parse_qsl, urlsplit

from jinja2 import Template

from pathlib import Path

from ..schemas.finding import PoCAttempt, PoCStatus
from ..schemas.hypothesis import Hypothesis
from ..schemas.taxonomy import (
    BugClass,
    KNOWN_CWE_REGISTRY,
    OPEN_CWE_POC_TEMPLATE,
    get_known_cwe_profile,
)
from ..services.roles import normalize_attacker_role
from ..services.diagnostics import bound_diagnostic
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
_PHP_OBJECT_ARM_TOKEN_RE = re.compile(r"sqpobjt1\.[0-9a-f]{64}\Z")
PHP_OBJECT_INERT_IMPACT_DESCRIPTION = (
    "The exact request path instantiated the verifier-owned inert canary and "
    "ran only its in-memory __wakeup receipt hook; no natural gadget, file "
    "effect, command execution, or remote-code-execution chain was proved."
)
_DETAILED_PREVIOUS_ATTEMPT_LIMIT = 3
_OLDER_ATTEMPT_LEDGER_MAX_ATTEMPTS = 8
_OLDER_ATTEMPT_LEDGER_MAX_CHARS = 3072
_OLDER_ATTEMPT_LEDGER_NUMBER_MAX_CHARS = 16
_OLDER_ATTEMPT_LEDGER_HEADER = (
    "=== OLDER ATTEMPT OUTCOME LEDGER "
    "(parent-classified fixed vocabulary; no historical child text) ==="
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
        raw_target = http_match.group("target")
        if re.search(r"%(?![0-9A-Fa-f]{2})", raw_target):
            return fallback
        parsed = urlsplit(raw_target)
        route = parsed.path
        if (
            not route.startswith("/")
            or route.startswith("//")
            or "//" in route
            or route != posixpath.normpath(route)
            or "%" in route
            or "\\" in route
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
                max_num_fields=64,
            )
        except ValueError:
            return fallback

        query_keys = [key for key, _value in query_pairs]
        if len(query_keys) != len(set(query_keys)) or any(
            not key.strip()
            or key != key.strip()
            or not value.strip()
            or value != value.strip()
            or not key.isascii()
            or not key.isprintable()
            or not value.isascii()
            or not value.isprintable()
            for key, value in query_pairs
        ):
            return fallback
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


def _older_attempt_outcome_category(attempt: PoCAttempt) -> str:
    """Reduce historical text to one fixed parent-side outcome category."""
    if attempt.result == PoCStatus.SUCCESS:
        return "accepted"
    reason = (attempt.validation_reason or "").casefold()
    if reason.startswith("trusted parent php object diagnostic:"):
        return "php_object_receipt_rejected"
    if reason in {
        "php object executable-surface attestation failed",
        "php object executable-surface restoration failed",
    }:
        return "php_object_surface_integrity_failure"
    if reason == "php object attack/control transport incomplete" or re.fullmatch(
        r"poc process exited -?\d+ before php object transport completed",
        reason,
    ):
        return "php_object_transport_incomplete"
    if re.fullmatch(r"poc http supervision failed: [a-z0-9_]+", reason):
        return "parent_http_supervision_failure"
    if reason == "poc execution timed out" or re.fullmatch(
        r"poc timed out after \d+(?:\.\d+)?s",
        reason,
    ):
        return "poc_timeout"
    if reason == "poc execution failed" or re.fullmatch(
        r"poc process exited -?\d+",
        reason,
    ):
        return "poc_process_failure"
    if reason.startswith("clean-state snapshot failed:"):
        return "snapshot_failure"
    if attempt.rejected_observation is not None:
        return "child_observation_rejected"
    if (
        reason == "missing final squadrone_result=<json> observation"
        or reason == "poc emitted more than one structured result observation"
        or reason == "structured result observation is not the final output line"
        or reason.startswith("invalid observation json:")
        or reason.startswith("observation schema validation failed:")
    ):
        return "child_observation_invalid"
    return "runner_validation_failed"


def _bounded_ledger_number(value: int | None) -> str:
    """Keep even malformed historical integer fields from defeating the ledger cap."""
    rendered = str(value)
    if len(rendered) <= _OLDER_ATTEMPT_LEDGER_NUMBER_MAX_CHARS:
        return rendered
    edge_chars = (_OLDER_ATTEMPT_LEDGER_NUMBER_MAX_CHARS - 3) // 2
    return f"{rendered[:edge_chars]}...{rendered[-edge_chars:]}"


def _format_older_attempt_ledger(previous_attempts: list[PoCAttempt]) -> str:
    """Summarize older attempts without copying historical child-derived text."""
    older_attempts = previous_attempts[:-_DETAILED_PREVIOUS_ATTEMPT_LIMIT]
    if not older_attempts:
        return ""

    retained_attempts = older_attempts[-_OLDER_ATTEMPT_LEDGER_MAX_ATTEMPTS:]
    omitted_attempts = len(older_attempts) - len(retained_attempts)
    ledger_parts = [_OLDER_ATTEMPT_LEDGER_HEADER]
    if omitted_attempts:
        ledger_parts.append(
            f"... {omitted_attempts} older attempts omitted; "
            "latest bounded entries retained ..."
        )
    ledger_parts.extend(
        "- "
        f"iteration={_bounded_ledger_number(attempt.iteration)} "
        f"phase={attempt.phase} result={attempt.result.value} "
        f"outcome={_older_attempt_outcome_category(attempt)}"
        for attempt in retained_attempts
    )
    ledger = "\n".join(ledger_parts)
    return ledger[:_OLDER_ATTEMPT_LEDGER_MAX_CHARS].rstrip()


def _format_previous_attempts(previous_attempts: list[PoCAttempt]) -> str:
    """Render bounded retry context, including authoritative older lessons."""
    history_parts: list[str] = []
    for attempt in previous_attempts[-_DETAILED_PREVIOUS_ATTEMPT_LIMIT:]:
        script_excerpt = "(script unavailable)"
        validation_reason = bound_diagnostic(
            attempt.validation_reason or "(none provided)", limit=1000
        )
        if attempt.observation is not None:
            impact = attempt.observation.impact
            observation_context = (
                "runner_observation=accepted "
                f"oracle={attempt.observation.oracle} "
                f"verdict={attempt.observation.verdict} "
                "impact="
                f"C:{impact.confidentiality}/I:{impact.integrity}/"
                f"A:{impact.availability}"
            )
        elif attempt.rejected_observation is not None:
            observation_context = (
                "runner_observation=rejected; the child self-report is diagnostic "
                "only and none of its success declarations are established; "
                f"reported_oracle={attempt.rejected_observation.oracle}"
            )
        else:
            observation_context = "runner_observation=absent"
        response_snippet = bound_diagnostic(
            attempt.response_snippet or "", limit=500
        )
        if attempt.rejected_observation is not None:
            response_snippet = "(withheld after rejected child observation)"
            error_context = "(withheld after rejected child observation)"
            developer_context = "(withheld after rejected child observation)"
        else:
            error_context = bound_diagnostic(
                attempt.error_log_snippet or "", limit=500
            )
            developer_context = bound_diagnostic(
                attempt.developer_analysis or "(none)", limit=500
            )
        try:
            script_excerpt = bound_diagnostic(
                Path(attempt.script_path).read_text(
                    encoding="utf-8",
                    errors="replace",
                ),
                limit=4000,
            )
        except OSError:
            pass
        history_parts.append(
            f"--- attempt {attempt.iteration} ---\n"
            f"phase={attempt.phase} result={attempt.result.value} "
            f"http_status={attempt.http_status}\n"
            f"{observation_context}\n"
            f"validator_rejection: {validation_reason}\n"
            f"response: {response_snippet}\n"
            f"errors:   {error_context}\n"
            f"developer_analysis: {developer_context}\n"
            f"script tried:\n```python\n{script_excerpt}\n```"
        )
    detailed_history = "\n\n".join(history_parts)
    older_ledger = _format_older_attempt_ledger(previous_attempts)
    if not older_ledger:
        return detailed_history
    return f"{older_ledger}\n\n{detailed_history}"


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
        php_include_oracle = (extra_context or {}).get("php_include_oracle") or {}
        php_object_oracle = (extra_context or {}).get("php_object_oracle") or {}
        attacker_role = (
            (extra_context or {}).get("attacker_role")
            or (hypothesis.evidence_summary or {}).get("attacker_role")
            or "unknown"
        )
        php_include_unauthenticated = (
            normalize_attacker_role(attacker_role) == "unauthenticated"
        )
        source_transport = (
            (extra_context or {}).get("php_object_http_transport")
            or (extra_context or {}).get("php_include_http_transport")
            or (extra_context or {}).get("ssrf_http_transport")
        )
        source_destination_parameter = ""
        source_destination_location = ""
        source_object_field = ""
        source_object_location = ""
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
                if isinstance(source_transport.get("object_field"), str):
                    source_object_field = source_transport["object_field"]
                if isinstance(source_transport.get("object_location"), str):
                    source_object_location = source_transport["object_location"]
        php_object_attack_token = str(php_object_oracle.get("attack_token") or "")
        php_object_control_token = str(php_object_oracle.get("control_token") or "")
        if (
            php_object_oracle.get("mode") != "php_object"
            or _PHP_OBJECT_ARM_TOKEN_RE.fullmatch(php_object_attack_token) is None
            or _PHP_OBJECT_ARM_TOKEN_RE.fullmatch(php_object_control_token) is None
            or php_object_attack_token == php_object_control_token
        ):
            php_object_attack_token = ""
            php_object_control_token = ""
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
            attacker_role=attacker_role,
            request_method=entry_transport["method"],
            request_route=entry_transport["route"],
            request_dispatch=entry_transport["dispatch"],
            ssrf_attack_url=str(ssrf_oracle.get("attack_url") or ""),
            ssrf_control_url=str(ssrf_oracle.get("control_url") or ""),
            ssrf_oracle_mode=ssrf_oracle_mode,
            ssrf_destination_location=source_destination_location,
            php_include_attack_path=str(php_include_oracle.get("attack_path") or ""),
            php_include_control_path=str(php_include_oracle.get("control_path") or ""),
            php_include_header_name=str(php_include_oracle.get("header_name") or ""),
            php_include_destination_location=source_destination_location,
            php_include_unauthenticated=php_include_unauthenticated,
            php_object_attack_token=php_object_attack_token,
            php_object_control_token=php_object_control_token,
            php_object_field=source_object_field,
            php_object_location=source_object_location,
            php_object_impact_description=PHP_OBJECT_INERT_IMPACT_DESCRIPTION,
        )

        system = load_prompt(self.PROMPT)
        user_parts = [
            f"TARGET_URL: {target_url}",
            f"HYPOTHESIS:\n{hypothesis.model_dump_json(indent=2)}",
            f"TEMPLATE ({template_name}):\n```python\n{skeleton}\n```",
        ]
        verification_target = (extra_context or {}).get("verification_target")
        if isinstance(verification_target, dict):
            user_parts.append(
                "RUNNER VERIFICATION TARGET (source-reviewed aspiration, never "
                "permission to overclaim):\n"
                + json.dumps(verification_target, sort_keys=True)
                + "\nAim to measure this outcome directly. A valid lower-impact proof "
                "remains useful, but it is not the terminal strategy while the "
                "target effect can be tested in this sandbox."
            )
        verified_partial_proof = (extra_context or {}).get(
            "verified_partial_proof"
        )
        if isinstance(verified_partial_proof, dict):
            user_parts.append(
                "RUNNER-CONFIRMED LOWER-BOUND PROOF (reproduced twice from clean "
                "state):\n"
                + json.dumps(verified_partial_proof, sort_keys=True)
                + "\nThe runner retained this finding as a fallback. Use this one "
                "bounded refinement strategy to measure the missing target effect; "
                "do not merely re-emit the same or a weaker proof. Preserve the "
                "working entry point, actor boundary, and negative-control quality."
            )
        executable_upload_oracle = (extra_context or {}).get(
            "executable_upload_oracle"
        )
        if isinstance(executable_upload_oracle, dict):
            user_parts.append(
                "TRUSTED_EXECUTABLE_UPLOAD_ORACLE (parent-verified):\n"
                + json.dumps(executable_upload_oracle, sort_keys=True)
                + "\nRead the exact base64 payload and attack/control filenames from "
                "the named environment variables on every execution; fail closed if "
                "any is missing. For a base64 API, submit the payload environment "
                "value unchanged. For multipart, strict-base64-decode it once and "
                "submit those exact bytes. Send exactly two comparable upload "
                "requests in attack-then-control order, changing only the supplied "
                "filename (.php versus .txt), and parse each server-returned URL. "
                "Do not probe either URL. Emit a claim-free response_marker handoff: "
                "verdict=not_vulnerable; all CIA dimensions none; request contains "
                "only method and URL; and each of attack/control contains only "
                "observed=false, marker_present=false, and uploaded_url. The parent "
                "binds the exact bytes, filenames, source route, signed actor, and "
                "returned URLs, then issues its fresh challenge after the process "
                "exits. Never emit child status, identity, actor, upload-success, "
                "execution, marker, or CIA claims for this handoff."
            )
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
        if php_include_oracle:
            public_keys = {
                key: str(php_include_oracle.get(key) or "")
                for key in (
                    "attack_path",
                    "control_path",
                    "attack_basename",
                    "control_basename",
                    "header_name",
                )
            }
            if all(public_keys.values()):
                actor_contract = (
                    "This proof is unauthenticated: both attack and control must "
                    'emit attacker_user_id as the literal JSON string "anonymous" '
                    '(never 0, "0", null/None, "guest", or a username), with '
                    "identity_verified=true."
                    if php_include_unauthenticated
                    else "This proof is authenticated: after a successful wp_login, "
                    "both attack and control must emit the same positive WordPress "
                    "user ID measured from login.identity.user_id (never a configured "
                    "or guessed ID, username, 0, or null/None), with "
                    "identity_verified=true."
                )
                user_parts.append(
                    "TRUSTED_PHP_INCLUDE_ORACLE (verifier-owned):\n"
                    + json.dumps(
                        {"schema_version": 1, **public_keys},
                        sort_keys=True,
                    )
                    + "\nUse these paths only through the exact source-derived "
                    "request field that reaches the cited PHP include/require. "
                    "The attack file exists and the distinct control sibling does "
                    "not. Derive the two traversal destination values from the "
                    "cited fixed directory, filename prefix, and suffix; do not "
                    "request or open either path directly from Python. When the "
                    "request value is concatenated immediately after a fixed filename "
                    "prefix, the traversal must begin with /.. (a separator followed "
                    "by a parent segment), not bare .., so PHP virtual-CWD resolution "
                    "can cancel the synthetic prefix component; derive this from the "
                    "exact completed expression and do not add a redundant separator "
                    "when the sink already supplies one. "
                    + actor_contract
                    + " After any "
                    "necessary login/setup traffic, send exactly two proof-bound "
                    "target requests in order: attack, then control. Extract exactly "
                    "one SQUADRONE_PHP_INCLUDE_<64 lowercase hex> value from the "
                    "named response header on the attack; the control must have no "
                    "such header. Emit response_marker with the extracted value as "
                    "attack.marker, include_path and destination_value for both arms, "
                    "the actor identity required above, and identical "
                    "request_fingerprint objects "
                    "using destination_parameter/destination_location/dispatch. "
                    "Claim confidentiality=low and no integrity or availability: "
                    "this proves the inclusion primitive, not attacker file-write "
                    "or arbitrary-code-execution amplification. The parent validates "
                    "the secret receipt, exact wire fields, immutable canary, absent "
                    "control, and fresh clean-state replay. Never invent or preseed "
                    "the marker, add exploratory target requests, or substitute a "
                    "different local file."
                )
        if php_object_attack_token and php_object_control_token:
            object_transport = {
                "method": entry_transport["method"],
                "route": entry_transport["route"],
                "dispatch": entry_transport["dispatch"],
                "object_field": source_object_field,
                "object_location": source_object_location,
            }
            actor_contract = (
                'Use attacker_user_id="anonymous" with identity_verified=true in '
                "both arms and do not log in."
                if php_include_unauthenticated
                else "After wp_login, use the same positive WordPress user ID from "
                "login.identity.user_id in both arms with identity_verified=true."
            )
            user_parts.append(
                "TRUSTED_PHP_OBJECT_ORACLE (verifier-owned):\n"
                + json.dumps(
                    {
                        "schema_version": 1,
                        "mode": "php_object",
                        "attack_token": php_object_attack_token,
                        "control_token": php_object_control_token,
                        "transport": object_transport,
                    },
                    sort_keys=True,
                )
                + "\nSubmit the two opaque tokens unchanged as the exact form-field "
                "value selected by the source-derived transport. Never construct, "
                "encode, decode, inspect, log, or emit PHP serialized bytes, a class "
                "name, embedded NUL, proof, secret, or receipt. Before the attack, "
                "you may perform only the standard wp_login flow or bounded GET/HEAD "
                "reads of a public form or nonce; do not send any other POST or "
                "mutating preflight request. When the source workflow requires a "
                "rendered form, consume the exact public page URL and stable form "
                "identity from authoritative SANDBOX SETUP, set the template's "
                "FORM_BOOTSTRAP_REQUIRED decision to true, and make one "
                "non-redirecting GET. Select exactly one coherent source-grounded "
                "form; retain its hidden and other non-submit successful controls, "
                "reusable nonce, duplicate fields, and exact rendered names. Supply "
                "deterministic semantic values for every source-required or rendered "
                "required field. Set FORM_BOOTSTRAP_REQUIRED=false only when source "
                "proves no such bootstrap is needed, and then set "
                "SOURCE_COMPLETE_FORM_FIELDS to the complete ordered source-required "
                "field baseline; use an explicit empty list only when source proves "
                "dispatch plus the object field are the entire envelope. Leave that "
                "direct baseline unset in rendered-form mode. Exclude dispatch and "
                "the object field from REQUIRED_FORM_FIELDS because the scaffold "
                "applies them later. Leaving either decision undecided must fail "
                "closed. Build the complete baseline before overlaying dispatch or "
                "the object field. Any required state or configuration setup must use "
                "the managed setup tools before script execution. Immediately before "
                "proof, clone the fully bootstrapped/login session into separate "
                "attack and control sessions with identical headers and cookies, so "
                "an attack response Set-Cookie cannot alter control. The "
                "attack and control must then be the next two target requests, in "
                "that order, with identical method, path, query, headers, cookies, "
                "and form fields except for the opaque token. Set "
                "allow_redirects=False on both so a redirect cannot interleave. A "
                "source-valid reusable nonce may be identical in both arms. "
                + actor_contract
                + " Emit object_instantiation with only the shared request "
                "fingerprint, actor identity, instantiated=true for attack and false "
                "for control, and effect=verifier_inert_canary_wakeup. Do not emit a "
                "receipt, token, payload, class, generation, or proof as evidence. "
                "Claim exactly confidentiality=none, integrity=low, and "
                "availability=none, preserving the template's impact description "
                "verbatim. This canary proves only that attacker bytes "
                "survived the real transport and invoked its inert __wakeup hook; it "
                "does not prove any shipped natural gadget, file effect, command "
                "execution, or RCE. The parent privately validates attack/control "
                "wire traces and uses a fresh generation for the clean replay while "
                "the same authored token strings remain stable."
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
