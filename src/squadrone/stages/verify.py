"""Verify stage — sandbox boot + PoC iteration loop per accepted hypothesis."""

from __future__ import annotations

import json
import logging
import re
import shutil
import tempfile
import uuid
from bisect import bisect_right
from contextlib import asynccontextmanager
from importlib.resources import files as _pkg_files
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from ..agents.developer import DeveloperAgent, SetupPlan
from ..agents.poc_author import PoCAuthorAgent, _parse_entry_point_transport
from ..agents.runtime import AgentRuntime
from ..schemas.config import PipelineConfig
from ..schemas.finding import DedupStatus, Finding, PoCAttempt, PoCStatus
from ..schemas.hypothesis import Hypothesis, SecurityOutcome, TriagedArtifact
from ..schemas.taxonomy import BugClass, OPEN_CWE_POC_TEMPLATE
from ..services.artifacts import (
    atomic_write_json,
    atomic_write_jsonl,
    atomic_write_text,
    read_jsonl_models,
)
from ..services.budget import BudgetTracker
from ..services.decision_ledger import append_decision
from ..services.quality_gate import infer_attacker_role
from ..services.roles import normalize_attacker_role
from ..services.sandbox import (
    SandboxManager,
    WORDPRESS_WEB_USER,
    validate_confirmation_observations,
    validate_plugin_slug,
)
from ..services import verify_helpers

logger = logging.getLogger(__name__)

VERIFY_COMPLETE_FILENAME = "verify_complete.json"
OPEN_CWE_MANUAL_REVIEW_FILENAME = "manual_review.json"
_OPEN_CWE_MANUAL_REVIEW_SOURCE = "verify_open_cwe"


class VerifyStageError(RuntimeError):
    """Verification finished its pass with one or more unresolved candidates."""

    def __init__(self, errors: list[tuple[str, str]], findings: list[Finding]) -> None:
        self.errors = errors
        self.findings = findings
        summary = "; ".join(
            f"{hypothesis_id}: {reason}" for hypothesis_id, reason in errors
        )
        super().__init__(
            f"verification incomplete for {len(errors)} candidate(s): {summary}"
        )


_XSS_CHECK_SRC = (
    _pkg_files("squadrone") / "poc_templates" / "xss_check.py"
).read_text()
_WP_LOGIN_SRC = (_pkg_files("squadrone") / "poc_templates" / "wp_login.py").read_text()
_POC_RESULT_SRC = (
    _pkg_files("squadrone") / "poc_templates" / "poc_result.py"
).read_text()


def _zip_plugin(plugin_path: str, slug: str) -> tuple[str, Path]:
    """Create a zip with the plugin folder at top level — wp plugin install expects this."""
    slug = validate_plugin_slug(slug)
    src = Path(plugin_path).resolve()
    staging = Path(tempfile.mkdtemp(prefix=f"squadrone-zip-{slug}-"))
    target = staging / slug
    shutil.copytree(src, target)
    out = shutil.make_archive(
        str(staging / slug), "zip", root_dir=str(staging), base_dir=slug
    )
    return out, staging


def _next_finding_id() -> str:
    return f"f-{uuid.uuid4().hex[:10]}"


_WP_SETUP_HARD_ERROR_RE = re.compile(
    r"WordPress database error|Unknown column|Table .* doesn't exist|does not exist|"
    r"^Error:\s|(?:PHP )?Fatal error:|Uncaught (?:Error|Exception)|Parse error",
    re.IGNORECASE | re.MULTILINE,
)

_PHP_WARNING_RE = re.compile(
    r"^(?:PHP Warning:|Warning:.*?\sin\s+\S+\.php\s+on line\s+\d+\s*$)",
    re.IGNORECASE | re.MULTILINE,
)

_PLUGIN_WARNING_LINE_RE = re.compile(
    r"^(?:PHP )?Warning:.*?/wp-content/(?:plugins|themes)/.+? on line \d+\s*$",
    re.IGNORECASE,
)

_INTENTIONAL_EVAL_OUTPUT_RE = re.compile(
    r"\b(?:WP_CLI\s*::\s*(?:log|line|success)|echo|print)\b",
    re.IGNORECASE,
)

_DIRECT_STORAGE_WRITE_RE = re.compile(
    r"\$wpdb\s*->\s*(?:insert|update|delete|replace|query)\s*\(|"
    r"\b(?:insert\s+into|update\s+[`'\"]?\w+|delete\s+from|replace\s+into)\b",
    re.IGNORECASE,
)

_XSS_PAYLOAD_SEED_RE = re.compile(
    r"<\s*script\b|"
    r"\bon(?:load|error|mouseover|focus|click|toggle)\s*=|javascript\s*:",
    re.IGNORECASE,
)

_SQLI_PAYLOAD_SEED_RE = re.compile(
    r"(?:\bunion\s+select\b|\bor\s+1\s*=\s*1\b|\bsleep\s*\(|benchmark\s*\(|--\s|/\*)",
    re.IGNORECASE,
)

_TRAVERSAL_PAYLOAD_SEED_RE = re.compile(
    r"(?:\.\./|\.\.\\|/etc/passwd|wp-config\.php|php://|file://)",
    re.IGNORECASE,
)

_SERIALIZED_OBJECT_SEED_RE = re.compile(r"\bO:\d+:\"[^\"]+\":", re.IGNORECASE)

_SHELL_PAYLOAD_SEED_RE = re.compile(
    r"(?:\b(?:id|whoami|uname)\b\s*[;&|`$]|\$\(|`[^`]+`)", re.IGNORECASE
)

_FILESYSTEM_PERMISSION_MUTATION_RE = re.compile(
    r"(?:\b(?:chmod|chown|chgrp)\s*(?:\(|\s)|"
    r"\bwp_chmod_(?:file|dir)\s*\(|"
    r"(?:->|::)\s*chmod\s*\(|"
    r"\bumask\s*\()",
    re.IGNORECASE,
)

_SETUP_PLUGIN_LIFECYCLE_ACTIONS = {
    "activate",
    "auto-updates",
    "deactivate",
    "delete",
    "install",
    "toggle",
    "uninstall",
    "update",
}

_PHP_PLUGIN_LIFECYCLE_RE = re.compile(
    r"\b(?:activate_plugins?|deactivate_plugins?|delete_plugins?)\s*\(",
    re.IGNORECASE,
)

_PHP_CURRENT_USER_OVERRIDE_RE = re.compile(
    r"\bwp_set_current_user\s*\(",
    re.IGNORECASE,
)

_PHP_ROLE_CAPABILITY_MUTATION_RE = re.compile(
    r"\b(?:set_role|add_cap|remove_cap|add_role|remove_role|wp_set_password|"
    r"reset_password|wp_delete_user|wpmu_delete_user|remove_user_from_blog|"
    r"grant_super_admin|revoke_super_admin)\b",
    re.IGNORECASE,
)

_PHP_USER_SECURITY_UPDATE_RE = re.compile(
    r"\bwp_update_user\s*\([^)]{0,4000}"
    r"(?:['\"](?:role|user_pass)['\"]\s*=>|\buser_(?:pass|level)\b)",
    re.IGNORECASE | re.DOTALL,
)

_PHP_USER_UPDATE_REFERENCE_RE = re.compile(
    r"\bwp_update_user\b",
    re.IGNORECASE,
)

_PHP_ELEVATED_USER_CREATE_RE = re.compile(
    r"\bwp_insert_user\s*\([^)]{0,4000}['\"]role['\"]\s*=>\s*['\"]"
    r"(?:administrator|admin|super[-_ ]?admin(?:istrator)?)['\"]",
    re.IGNORECASE | re.DOTALL,
)

_DIRECT_CREDENTIAL_STORAGE_RE = re.compile(
    r"(?:['\"]user_pass['\"]|\buser_pass\s*=)",
    re.IGNORECASE,
)

_WP_APPLICATION_PASSWORD_CLI_MUTATION_RE = re.compile(
    r"\buser\b.{0,1000}\bapplication-password\b.{0,1000}"
    r"\b(?:create|update|delete(?:-all)?|revoke|reset|record-usage)\b",
    re.IGNORECASE | re.DOTALL,
)

_PHP_APPLICATION_PASSWORD_MUTATION_RE = re.compile(
    r"\b(?:create_new_application_password|update_application_password|"
    r"delete_application_password|delete_all_application_passwords|"
    r"record_application_password_usage|set_user_application_passwords)\b",
    re.IGNORECASE,
)

_APPLICATION_PASSWORD_STORAGE_KEY_RE = re.compile(
    r"(?:\b_application_passwords\b|\bUSERMETA_KEY_APPLICATION_PASSWORDS\b)",
    re.IGNORECASE,
)

_MANAGED_CAPABILITY_KEY_RE = re.compile(
    r"(?:\bwp_user_roles\b|(?:^|[^A-Za-z0-9])(?:[A-Za-z0-9_]+_)?"
    r"(?:capabilities|user_level)(?:[^A-Za-z0-9]|$))",
    re.IGNORECASE,
)

_ACTIVE_PLUGIN_STATE_KEY_RE = re.compile(
    r"\b(?:active_plugins|active_sitewide_plugins)\b",
    re.IGNORECASE,
)

_PHP_RAW_STATE_WRITE_RE = re.compile(
    r"\b(?:"
    r"(?:add|update|delete)_(?:option|site_option|network_option|blog_option)|"
    r"(?:add|update|delete)_(?:post|user|comment|term)_meta|"
    r"(?:add|update|delete)_metadata|"
    r"wp_(?:insert|update)_(?:post|user|comment)|"
    r"file_put_contents|fwrite|fputs|copy|rename|touch|move_uploaded_file"
    r")\s*\(",
    re.IGNORECASE,
)

_PHP_RAW_STATE_WRITE_REFERENCE_RE = re.compile(
    r"['\"](?:"
    r"(?:add|update|delete)_(?:option|site_option|network_option|blog_option)|"
    r"(?:add|update|delete)_(?:post|user|comment|term)_meta|"
    r"(?:add|update|delete)_metadata|"
    r"wp_(?:insert|update)_(?:post|user|comment)|"
    r"file_put_contents|fwrite|fputs|copy|rename|touch|move_uploaded_file"
    r")[ '\"]*[,)]",
    re.IGNORECASE,
)

_WP_CLI_RAW_WRITE_RE = re.compile(
    r"(?:^|\s)(?:"
    r"(?:(?:site\s+)?option|transient)\s+(?:add|update|delete|patch)|"
    r"(?:post|comment|term)\s+(?:create|update|delete)|"
    r"(?:post|comment|term|user)\s+meta\s+(?:add|update|delete)|"
    r"db\s+(?:query|import)|media\s+import"
    r")(?:\s|$)",
    re.IGNORECASE,
)

_WP_CLI_USER_MUTATION_ACTIONS = {
    "add-cap",
    "add-role",
    "delete",
    "remove-cap",
    "remove-role",
    "reset-password",
    "set-role",
}

_WP_CLI_USER_ACTIONS = _WP_CLI_USER_MUTATION_ACTIONS | {
    "create",
    "get",
    "list",
    "update",
}

_WP_CLI_ROLE_MUTATION_ACTIONS = {
    "add-cap",
    "create",
    "delete",
    "remove-cap",
    "reset",
}

_PRIVILEGED_ROLE_ALIASES = {
    "admin",
    "administrator",
    "super-admin",
    "super-administrator",
    "super_administrator",
    "superadministrator",
}

_EMBEDDED_WP_CLI_SECURITY_MUTATION_RE = re.compile(
    r"\b(?:"
    r"plugin\s+(?:activate|deactivate|install|delete|uninstall|update|toggle)|"
    r"user\s+(?:set-role|add-role|remove-role|add-cap|remove-cap|"
    r"reset-password|delete)|super-admin\s+(?:add|remove)|"
    r"role\s+(?:create|delete|add-cap|remove-cap|reset)"
    r")\b",
    re.IGNORECASE,
)

_EMBEDDED_WP_CLI_ELEVATED_USER_CREATE_RE = re.compile(
    r"(?:\buser\s+create\b.{0,2000}--role(?:=|\s+)"
    r"(?:administrator|admin|super[-_ ]?admin(?:istrator)?)\b|"
    r"--role(?:=|\s+)(?:administrator|admin|super[-_ ]?admin(?:istrator)?)"
    r"\b.{0,2000}\buser\s+create\b)",
    re.IGNORECASE | re.DOTALL,
)

_PHP_DIRECT_FILE_WRITE_RE = re.compile(
    r"(?:\b(?:file_put_contents|fwrite|fputs|copy|rename|touch|symlink|link|"
    r"move_uploaded_file)|(?:->|::)\s*put_contents)\s*\(",
    re.IGNORECASE,
)

_SQL_DIRECT_FILE_WRITE_RE = re.compile(
    r"\binto\s+(?:out|dump)file\b",
    re.IGNORECASE,
)

_EXECUTABLE_FILE_PAYLOAD_RE = re.compile(
    r"<\?(?:php|=)?|\b(?:assert|system|shell_exec|passthru|exec|popen|proc_open)"
    r"\s*\(",
    re.IGNORECASE,
)

_SETUP_FOLLOWUP_CAP = 2
_POC_REQUESTED_SETUP_FOLLOWUP_CAP = 2
_ATOMIC_SETUP_RETRY_CAP = 1


def _find_cli_action(
    args: list[str], start: int, known_actions: set[str]
) -> tuple[int, str] | None:
    """Find a known WP-CLI action even when command options are interspersed."""
    for index in range(start, len(args)):
        candidate = args[index].lower()
        if candidate in known_actions:
            return index, candidate
    return None


def _cli_option_values(args: list[str], option: str) -> list[str]:
    """Return both ``--option=value`` and ``--option value`` spellings."""
    needle = f"--{option.lower()}"
    values: list[str] = []
    for index, token in enumerate(args):
        lowered = token.lower()
        if lowered.startswith(needle + "="):
            values.append(lowered.split("=", 1)[1])
        elif lowered == needle and index + 1 < len(args):
            values.append(args[index + 1].lower())
    return values


def _setup_command_is_raw_state_write(args: list[str]) -> bool:
    """Identify direct core/CLI storage writes, not source-defined setup APIs."""
    command = " ".join(args)
    return bool(
        _DIRECT_STORAGE_WRITE_RE.search(command)
        or _PHP_RAW_STATE_WRITE_RE.search(command)
        or _PHP_RAW_STATE_WRITE_REFERENCE_RE.search(command)
        or _WP_CLI_RAW_WRITE_RE.search(command)
    )


def _setup_command_directly_writes_file(args: list[str]) -> bool:
    """Identify generated commands that directly create or mutate file contents."""
    command = " ".join(args)
    evaluates_php = any(token.lower() in {"eval", "eval-file"} for token in args)
    wp_cli_media_import = bool(
        re.search(r"(?:^|\s)media\s+import(?:\s|$)", command, re.IGNORECASE)
    )
    return (
        (evaluates_php and bool(_PHP_DIRECT_FILE_WRITE_RE.search(command)))
        or wp_cli_media_import
        or bool(_SQL_DIRECT_FILE_WRITE_RE.search(command))
    )


def _setup_command_mutates_managed_context(args: list[str]) -> str | None:
    """Reject identity overrides and plugin lifecycle changes owned by the sandbox."""
    for index, token in enumerate(args):
        if token.lower() != "plugin":
            continue
        if _find_cli_action(args, index + 1, _SETUP_PLUGIN_LIFECYCLE_ACTIONS):
            return (
                "setup command mutates the managed plugin lifecycle; the target "
                "plugin is already installed and activated by the sandbox"
            )

    command = " ".join(args)
    if _EMBEDDED_WP_CLI_SECURITY_MUTATION_RE.search(command):
        return "setup command mutates a sandbox-managed plugin or user security state"
    if _WP_APPLICATION_PASSWORD_CLI_MUTATION_RE.search(command):
        return "setup command mutates a managed user's application-password credentials"
    if _EMBEDDED_WP_CLI_ELEVATED_USER_CREATE_RE.search(command):
        return "setup command creates an elevated WordPress user"
    if _PHP_PLUGIN_LIFECYCLE_RE.search(command):
        return (
            "setup command calls a plugin lifecycle API; the target plugin is "
            "already installed and activated by the sandbox"
        )

    if any(
        token.lower() == "--user" or token.lower().startswith("--user=")
        for token in args
    ):
        return (
            "setup command overrides the WordPress user; the runner already selects "
            "the configured administrator"
        )
    if _PHP_CURRENT_USER_OVERRIDE_RE.search(command):
        return (
            "setup command calls wp_set_current_user(); the runner already selects "
            "the configured administrator"
        )

    # The verifier's attacker/control identities are provisioned independently of
    # generated setup. Direct role or capability edits would invalidate the claimed
    # attacker boundary even when the PoC labels the request with the old role.
    for index, token in enumerate(args):
        lowered = token.lower()
        if lowered == "user":
            action_item = _find_cli_action(args, index + 1, _WP_CLI_USER_ACTIONS)
            if action_item is None:
                continue
            _, action = action_item
            if action in _WP_CLI_USER_MUTATION_ACTIONS:
                return "setup command mutates a managed user's role or capabilities"
            if action == "create" and any(
                role.replace(" ", "-") in _PRIVILEGED_ROLE_ALIASES
                for role in _cli_option_values(args, "role")
            ):
                return "setup command creates an elevated WordPress user"
            if action == "update" and any(
                candidate.lower() == "--role"
                or candidate.lower().startswith("--role=")
                or candidate.lower() == "--user_pass"
                or candidate.lower().startswith("--user_pass=")
                or candidate.lower() == "--user-pass"
                or candidate.lower().startswith("--user-pass=")
                for candidate in args
            ):
                return "setup command mutates a managed user's role or credentials"
        elif lowered == "super-admin" and _find_cli_action(
            args, index + 1, {"add", "remove"}
        ):
            return "setup command mutates a user's network administrator status"
        elif lowered == "role":
            action_item = _find_cli_action(
                args,
                index + 1,
                _WP_CLI_ROLE_MUTATION_ACTIONS,
            )
            if (
                action_item is not None
                and action_item[1] in _WP_CLI_ROLE_MUTATION_ACTIONS
            ):
                return "setup command mutates WordPress role capabilities"

    if _PHP_ROLE_CAPABILITY_MUTATION_RE.search(command):
        return "setup command calls a user identity, role, or capability mutation API"
    if _PHP_ELEVATED_USER_CREATE_RE.search(command):
        return "setup command creates an elevated WordPress user"
    if _PHP_USER_SECURITY_UPDATE_RE.search(command):
        return "setup command changes a user's role or credentials"
    if _PHP_USER_UPDATE_REFERENCE_RE.search(
        command
    ) and _DIRECT_CREDENTIAL_STORAGE_RE.search(command):
        # `wp_update_user()` can be dispatched indirectly through
        # call_user_func(), call_user_func_array(), or a variable callable. The
        # managed-state snapshot deliberately does not retain password hashes,
        # so reject these credential updates lexically regardless of call form.
        return "setup command changes a user's role or credentials"
    if _PHP_APPLICATION_PASSWORD_MUTATION_RE.search(command):
        # These distinctive WordPress core method names remain visible when
        # dispatched through call_user_func(), an array callable, or variables.
        return "setup command mutates a managed user's application-password credentials"
    if _APPLICATION_PASSWORD_STORAGE_KEY_RE.search(
        command
    ) and _setup_command_is_raw_state_write(args):
        return "setup command writes application-password credential storage directly"
    if _DIRECT_CREDENTIAL_STORAGE_RE.search(
        command
    ) and _DIRECT_STORAGE_WRITE_RE.search(command):
        return "setup command writes WordPress credential storage directly"
    if _MANAGED_CAPABILITY_KEY_RE.search(command) and _setup_command_is_raw_state_write(
        args
    ):
        return "setup command writes WordPress role or capability storage directly"
    if _ACTIVE_PLUGIN_STATE_KEY_RE.search(
        command
    ) and _setup_command_is_raw_state_write(args):
        return (
            "setup command writes managed plugin activation state directly; plugin "
            "lifecycle is owned by the sandbox"
        )
    return None


def _setup_command_plants_exploit_payload(
    args: list[str], hyp: Hypothesis | None
) -> str | None:
    """Detect setup that would invalidate the verification environment.

    Setup is allowed to create normal plugin state, but a confirmed PoC should not be
    based on `wpdb->insert`/`wp db query` writing the malicious value directly into the
    column/file/option that the hypothesis later reads. This guard blocks obvious
    direct exploit-payload seeding and permission manipulation while allowing benign
    runtime prerequisites.
    """
    command = " ".join(args)
    if _FILESYSTEM_PERMISSION_MUTATION_RE.search(command):
        return (
            "setup command mutates filesystem permissions or ownership; "
            "sandbox install ownership is managed internally"
        )
    direct_file_write = _setup_command_directly_writes_file(args)
    if direct_file_write and _EXECUTABLE_FILE_PAYLOAD_RE.search(command):
        return "setup command directly wrote executable file content"
    if hyp is not None and hyp.bug_class.value == "CWE-434" and direct_file_write:
        return (
            "setup command directly created or wrote a file for a file-write/upload "
            "finding"
        )
    if hyp is None or not _setup_command_is_raw_state_write(args):
        return None
    if hyp.root_cause_cwe == "CWE-79" and _XSS_PAYLOAD_SEED_RE.search(command):
        return "setup command directly wrote an XSS payload into storage"
    if hyp.bug_class.value == "CWE-89" and _SQLI_PAYLOAD_SEED_RE.search(command):
        return "setup command directly wrote an SQL injection payload into storage"
    if hyp.bug_class.value == "CWE-22" and _TRAVERSAL_PAYLOAD_SEED_RE.search(command):
        return "setup command directly wrote a traversal payload into storage"
    if hyp.bug_class.value == "CWE-502" and _SERIALIZED_OBJECT_SEED_RE.search(command):
        return "setup command directly wrote a serialized object payload into storage"
    if hyp.bug_class.value == "CWE-78" and _SHELL_PAYLOAD_SEED_RE.search(command):
        return "setup command directly wrote a command-injection payload into storage"
    return None


def _summarise_forbidden_setup(results: list[dict]) -> str:
    blocked = [item for item in results if _setup_result_taints_confirmation(item)]
    lines: list[str] = []
    for item in blocked:
        cmd = " ".join(item.get("args", [])[:10])
        reason = (
            item.get("forbidden_setup_reason")
            or item.get("forbidden_payload_seed_reason")
            or "unsafe setup mutation"
        )
        lines.append(f"- wp {cmd} ({reason})")
    return "\n".join(lines)


def _summarise_setup_results(results: list[dict]) -> str:
    lines: list[str] = []
    for item in results:
        blocked = item.get("blocked_before_execution") is True
        if blocked:
            status = "BLOCKED BEFORE EXECUTION"
        elif item.get("failed") and item.get("executed", True) is not False:
            status = "FAILED AFTER EXECUTION — STATE MAY BE PARTIAL"
        elif item.get("failed"):
            status = "FAILED"
        elif item.get("advisory_bootstrap_warning"):
            status = "OK WITH WARNINGS"
        else:
            status = "OK"
        cmd = " ".join(item.get("args", [])[:8])
        output = " ".join(
            part.strip().replace("\n", " ")
            for part in (item.get("output") or "", item.get("stderr") or "")
            if part.strip()
        )
        if len(output) > 500:
            output = output[:500] + "..."
        if blocked:
            suffix = (
                " No part of this command ran. Submit a new command containing only "
                "permitted prerequisite operations."
            )
            output = (output + suffix).strip()
        lines.append(f"{status}: wp {cmd} -> {output}")
    return "\n".join(lines)


def _setup_result_taints_confirmation(item: dict) -> bool:
    """Whether a forbidden setup result can have contaminated the sandbox.

    New results explicitly record atomic pre-execution blocks. Older artifacts did
    not, so a legacy forbidden result remains conservatively tainting.
    """
    if not (
        item.get("forbidden_payload_seed") or item.get("managed_context_violation")
    ):
        return False
    if item.get("blocked_before_execution") is True:
        return False
    return item.get("executed", True) is not False


def _managed_setup_state_drift(before: dict, after: dict) -> str | None:
    """Describe a security-boundary change without persisting sensitive state."""
    if before.get("target_plugin_active") is not True:
        return "target plugin was not active before generated setup"
    if after.get("target_plugin_active") is not True:
        return "generated setup deactivated the target plugin"

    def _normalised_paths(value: object) -> frozenset[str]:
        if isinstance(value, dict):
            values = value.keys()
        elif isinstance(value, (list, tuple, set, frozenset)):
            values = value
        else:
            return frozenset()
        return frozenset(str(path) for path in values)

    if _normalised_paths(before.get("active_plugins")) != _normalised_paths(
        after.get("active_plugins")
    ) or _normalised_paths(before.get("active_sitewide_plugins")) != _normalised_paths(
        after.get("active_sitewide_plugins")
    ):
        return "generated setup changed managed plugin activation state"

    before_users = before.get("users") or {}
    after_users = after.get("users") or {}
    changed_users = sorted(
        login
        for login in set(before_users) | set(after_users)
        if before_users.get(login) != after_users.get(login)
    )
    if changed_users:
        return (
            "generated setup changed a managed user's roles or capabilities, "
            "identity, or credentials: " + ", ".join(changed_users)
        )

    before_privileged = before.get("privileged_users") or {}
    after_privileged = after.get("privileged_users") or {}
    changed_privileged = sorted(
        login
        for login in set(before_privileged) | set(after_privileged)
        if before_privileged.get(login) != after_privileged.get(login)
    )
    if changed_privileged:
        return (
            "generated setup created or changed an elevated WordPress user: "
            + ", ".join(changed_privileged)
        )
    return None


def _setup_output_confirms_postcondition(args: list[str], output: str) -> bool:
    """Whether stdout deliberately reports a successful, inspectable result.

    WP-CLI can emit warnings while loading an active plugin before dispatching the
    requested command.  A warning is safe to treat as advisory only when the command
    subsequently produced an explicit success marker or structured output that the
    generated setup code intentionally printed.  Arbitrary non-empty stdout is not a
    postcondition.
    """
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if any(line.lower().startswith("success:") for line in lines):
        return True

    eval_index = next(
        (
            index
            for index, token in enumerate(args)
            if token.lower() in {"eval", "eval-file"}
        ),
        None,
    )
    if eval_index is None:
        return False
    evaluated_source = " ".join(args[eval_index + 1 :])
    if not _INTENTIONAL_EVAL_OUTPUT_RE.search(evaluated_source):
        return False

    for line in reversed(lines):
        try:
            value = json.loads(line)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if isinstance(value, (dict, list)):
            return True
    return False


def _plugin_bootstrap_warnings_are_advisory(
    args: list[str], output: str, stderr: str
) -> bool:
    """Recognise non-fatal plugin/theme bootstrap warnings after a postcondition.

    The path restriction prevents a command's own core/filesystem warning from being
    hidden.  All warning lines must be attributable to loaded plugin/theme code, and
    stdout must independently confirm the requested setup result.
    """
    warning_lines = [
        line.strip()
        for line in stderr.splitlines()
        if _PHP_WARNING_RE.match(line.strip())
    ]
    return bool(
        warning_lines
        and all(_PLUGIN_WARNING_LINE_RE.fullmatch(line) for line in warning_lines)
        and _setup_output_confirms_postcondition(args, output)
    )


def _trusted_setup_wp_user(sb: SandboxManager) -> str:
    """Select the verified numeric administrator, with a test-double fallback."""
    admin_id_reader = getattr(sb, "baseline_admin_user_id", None)
    if callable(admin_id_reader):
        return str(admin_id_reader())
    return str(sb.config.wp_admin_email)


async def _run_setup_commands(
    sb: SandboxManager,
    commands: list[list[str]],
    *,
    hypothesis: Hypothesis | None = None,
    plugin_slug: str | None = None,
) -> list[dict]:
    """Execute developer-proposed wp-cli commands inside the sandbox."""
    if not commands or sb.wp_cli is None:
        return []
    results: list[dict] = []
    for args in commands:
        policy_reason = _setup_command_mutates_managed_context(args)
        payload_reason = _setup_command_plants_exploit_payload(args, hypothesis)
        forbidden_reason = policy_reason or payload_reason
        if forbidden_reason:
            logger.warning(
                "setup wp %s blocked before execution: %s",
                " ".join(args[:6]),
                forbidden_reason,
            )
            results.append(
                {
                    "args": args,
                    "returncode": -1,
                    "output": "",
                    "stderr": forbidden_reason,
                    "failed": True,
                    "forbidden_payload_seed": bool(payload_reason),
                    "forbidden_payload_seed_reason": payload_reason,
                    "forbidden_setup_reason": forbidden_reason,
                    "managed_context_violation": False,
                    "blocked_before_execution": True,
                    "executed": False,
                }
            )
            continue

        state_reader = getattr(sb, "capture_setup_security_state", None)
        before_state: dict | None = None
        if plugin_slug and callable(state_reader):
            try:
                before_state = await state_reader(plugin_slug)
                baseline_error = _managed_setup_state_drift(
                    before_state,
                    before_state,
                )
            except Exception as exc:
                baseline_error = (
                    "could not establish managed setup security state: "
                    f"{str(exc)[:300]}"
                )
            if baseline_error:
                logger.warning(
                    "setup wp %s blocked before execution: %s",
                    " ".join(args[:6]),
                    baseline_error,
                )
                results.append(
                    {
                        "args": args,
                        "returncode": -1,
                        "output": "",
                        "stderr": baseline_error,
                        "failed": True,
                        "forbidden_payload_seed": False,
                        "forbidden_payload_seed_reason": None,
                        "forbidden_setup_reason": baseline_error,
                        "managed_context_violation": False,
                        "blocked_before_execution": True,
                        "executed": False,
                    }
                )
                continue

        try:
            rc, out, err = await sb.wp_cli._exec_result(
                *args,
                user=WORDPRESS_WEB_USER,
                wp_user=_trusted_setup_wp_user(sb),
            )
            combined = "\n".join(x for x in (out, err) if x)
            has_hard_error = bool(_WP_SETUP_HARD_ERROR_RE.search(combined))
            has_php_warning = bool(_PHP_WARNING_RE.search(err or ""))
            advisory_bootstrap_warning = bool(
                rc == 0
                and not has_hard_error
                and has_php_warning
                and _plugin_bootstrap_warnings_are_advisory(args, out, err)
            )
            failed = bool(
                rc != 0
                or has_hard_error
                or (has_php_warning and not advisory_bootstrap_warning)
            )
            result: dict = {
                "args": args,
                "returncode": rc,
                "output": out,
                "stderr": err,
                "failed": failed,
                "advisory_bootstrap_warning": advisory_bootstrap_warning,
                "forbidden_payload_seed": bool(payload_reason),
                "forbidden_payload_seed_reason": payload_reason,
                "forbidden_setup_reason": None,
                "managed_context_violation": False,
                "blocked_before_execution": False,
                "executed": True,
            }
        except Exception as e:
            logger.warning("setup wp %s failed: %s", " ".join(args[:6]), e)
            result = {
                "args": args,
                "returncode": -1,
                "output": "",
                "stderr": str(e),
                "failed": True,
                "forbidden_payload_seed": False,
                "forbidden_payload_seed_reason": None,
                "forbidden_setup_reason": None,
                "managed_context_violation": False,
                "blocked_before_execution": False,
                # The WP-CLI call was dispatched and could have partially run.
                "executed": True,
            }

        if before_state is not None:
            try:
                after_state = await state_reader(plugin_slug)
                state_violation = _managed_setup_state_drift(
                    before_state,
                    after_state,
                )
            except Exception as exc:
                state_violation = (
                    "could not verify managed setup security state after execution: "
                    f"{str(exc)[:300]}"
                )
            if state_violation:
                result["failed"] = True
                result["managed_context_violation"] = True
                result["forbidden_setup_reason"] = state_violation
                result["stderr"] = "\n".join(
                    part
                    for part in (result.get("stderr") or "", state_violation)
                    if part
                )

        results.append(result)
        combined = "\n".join(
            part
            for part in (result.get("output") or "", result.get("stderr") or "")
            if part
        )
        log = logger.warning if result.get("failed") else logger.info
        log("setup wp %s -> %s", " ".join(args[:6]), combined.strip()[:160])
    return results


# Tables referenced in raw SQL — used to seed schema diagnostics for the followup developer call.
_TABLE_RE = re.compile(
    r"\$wpdb->prefix\s*\.\s*['\"]([a-z0-9_]+)['\"]|"
    r"\b((?:wp_)?(?:aysquiz_|nf3_|nf_|wf|et_|elementor_|wcfm_|wc_|woocommerce_)[a-z0-9_]+)\b",
    re.IGNORECASE,
)


async def _collect_schema_diagnostics(
    sb: SandboxManager, commands: list[list[str]]
) -> str:
    """Run DESCRIBE on tables that appear in prior setup commands so the followup developer
    sees the real schema instead of guessing again."""
    if sb.wp_cli is None or not commands:
        return ""
    blob = " ".join(" ".join(c) for c in commands)
    tables: list[str] = []
    for m in _TABLE_RE.finditer(blob):
        name = m.group(1) or m.group(2)
        if name and name not in tables:
            tables.append(name)
    if not tables:
        return ""
    out_parts: list[str] = []
    for tbl in tables[:6]:  # cap to avoid runaway diagnostics
        try:
            php = (
                f"global $wpdb; $t = $wpdb->prefix . '{tbl.removeprefix('wp_')}'; "
                'if (in_array($t, $wpdb->get_col("SHOW TABLES"))) { '
                '  $rows = $wpdb->get_results("DESCRIBE `$t`", ARRAY_A); '
                "  echo $t . ': ' . json_encode(array_map(fn($r)=>$r['Field'].' '.$r['Type'],$rows)); "
                "} else { echo $t . ': (table does not exist)'; }"
            )
            res = await sb.wp_cli._eval(php)
            out_parts.append(res.strip())
        except Exception as e:
            out_parts.append(f"{tbl}: diagnostics failed ({e})")
    return "\n".join(out_parts)


_SOURCE_LOCATION_RE = re.compile(
    r"(?P<path>[A-Za-z0-9_./-]+\.php):(?P<line>[1-9][0-9]*)",
)

_SETUP_SEMANTIC_TOKEN_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]{4,}\b")
_SETUP_ROUTE_PATH_RE = re.compile(r"/[A-Za-z0-9_./-]+")
_SETUP_SEMANTIC_TOKEN_STOPWORDS = frozenset(
    {
        "attacker",
        "callback",
        "classes",
        "filename",
        "logged",
        "multipart",
        "plugin",
        "request",
        "response",
        "subscriber",
        "target",
        "uploads",
        "wordpress",
    }
)


def _setup_semantic_tokens(hypothesis: Hypothesis) -> list[str]:
    """Extract source identifiers that can locate an uncited entry-point guard."""
    # Setup needs the registration and reachability guard, not every downstream
    # symbol in a potentially long taint path. Keeping this entry-focused also
    # prevents common sink helpers from pulling unrelated files into the bounded
    # context ahead of the real route.
    source_text = "\n".join([hypothesis.entry_point, *hypothesis.taint_path[:2]])
    tokens: list[str] = []

    # Preserve the final route segment, including dashed/all-lowercase routes that
    # do not look like PHP identifiers. The leading slash makes short route names
    # substantially less noisy when searched in source.
    route_paths = _SETUP_ROUTE_PATH_RE.findall(hypothesis.entry_point)
    if route_paths:
        tail = route_paths[-1].rstrip("/").rsplit("/", 1)[-1]
        route_token = f"/{tail}"
        if len(tail) >= 4 and route_token not in tokens:
            tokens.append(route_token)

    for token in _SETUP_SEMANTIC_TOKEN_RE.findall(source_text):
        lowered = token.lower()
        if lowered in _SETUP_SEMANTIC_TOKEN_STOPWORDS:
            continue
        # Prefer identifiers over prose. Underscores and camelCase are strong PHP
        # source signals; an all-lowercase route component is too noisy on its own.
        # Class names are retained at lower priority because their bootstrap site
        # often carries the option storage or module construction needed for setup.
        if "_" not in token and re.search(r"[a-z][A-Z]", token) is None:
            continue
        if token not in tokens:
            tokens.append(token)
    return tokens[:16]


def _add_semantic_setup_locations(
    plugin_root: Path,
    hypothesis: Hypothesis,
    locations: dict[str, set[int]],
    *,
    max_extra_files: int = 4,
) -> None:
    """Add bounded snippets for entry identifiers when hypotheses omit file:line refs."""
    tokens = _setup_semantic_tokens(hypothesis)
    if not tokens:
        return

    matches: list[tuple[int, int, str, set[int]]] = []
    for candidate in sorted(plugin_root.rglob("*.php")):
        try:
            lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        first_line_by_token: dict[int, int] = {}
        for line_number, line in enumerate(lines, start=1):
            for token_rank, token in enumerate(tokens):
                if token_rank not in first_line_by_token and token in line:
                    first_line_by_token[token_rank] = line_number
        if first_line_by_token:
            rel_file = candidate.relative_to(plugin_root).as_posix()
            matches.append(
                (
                    -len(first_line_by_token),
                    min(first_line_by_token),
                    rel_file,
                    set(first_line_by_token.values()),
                )
            )

    added_files = 0
    for _term_count, _rank, rel_file, matched_lines in sorted(matches):
        if rel_file not in locations:
            if added_files >= max_extra_files:
                continue
            added_files += 1
        locations.setdefault(rel_file, set()).update(matched_lines)


def _resolve_plugin_file(plugin_root: Path, rel_file: str) -> Path | None:
    candidate = plugin_root / rel_file
    if not candidate.is_file():
        for prefix in (
            "wp-content/plugins/" + plugin_root.name + "/",
            plugin_root.name + "/",
        ):
            if rel_file.startswith(prefix):
                candidate = plugin_root / rel_file[len(prefix) :]
                if candidate.is_file():
                    break
    return candidate if candidate.is_file() else None


_SETUP_CONTEXT_TRUNCATION_MARKER = "\n... [source context truncated]"


def _render_setup_source_section(
    rel_file: str,
    lines: list[str],
    cited_lines: set[int],
    *,
    head_lines: int = 35,
    radius: int = 25,
) -> str:
    """Render one deterministic setup-source section around selected anchors."""
    selected = set(range(1, min(len(lines), head_lines) + 1))
    for line in cited_lines:
        selected.update(
            range(max(1, line - radius), min(len(lines), line + radius) + 1)
        )

    rendered = [f"--- {rel_file} ---"]
    previous = 0
    for line in sorted(selected):
        if previous and line > previous + 1:
            rendered.append("...")
        rendered.append(f"{line:5}  {lines[line - 1]}")
        previous = line
    return "\n".join(rendered)


def _truncate_setup_source_section(section: str, max_chars: int) -> str:
    """Prefix-truncate an optional section without exceeding its exact budget."""
    if max_chars <= 0:
        return ""
    if len(section) <= max_chars:
        return section
    marker = _SETUP_CONTEXT_TRUNCATION_MARKER
    if max_chars <= len(marker):
        return section[:max_chars]
    return section[: max_chars - len(marker)] + marker


def _build_setup_code_context(
    plugin_root: Path,
    hypothesis: Hypothesis,
    *,
    max_chars: int = 12_000,
) -> str | None:
    """Build source context for setup from every file cited by the hypothesis."""
    if max_chars <= 0:
        return None

    locations: dict[str, set[int]] = {}
    source_text = "\n".join(
        [
            hypothesis.entry_point,
            *hypothesis.taint_path,
            hypothesis.reasoning,
            str(hypothesis.evidence_summary or {}),
        ]
    )
    for match in _SOURCE_LOCATION_RE.finditer(source_text):
        locations.setdefault(match.group("path"), set()).add(int(match.group("line")))

    if hypothesis.file:
        locations.setdefault(hypothesis.file, set()).add(hypothesis.line)

    # Retain source provenance. On overflow, an exact hypothesis anchor must not
    # be displaced by broader semantic matches in the same file.
    explicit_locations = {path: set(lines) for path, lines in locations.items()}

    # Specialist output does not always retain file:line citations for the entry
    # route. Recover the registration/feature-gate file from source identifiers so
    # setup agents do not have to invent plugin option names after a route-level 404.
    _add_semantic_setup_locations(plugin_root, hypothesis, locations)
    if hypothesis.file:
        sink_lines = locations.pop(hypothesis.file)
        # Keep the primary sink, but render entry/registration files first so a
        # large sink file cannot consume the bounded context before its guard.
        locations[hypothesis.file] = sink_lines

    source_sections: list[tuple[str, list[str], str]] = []
    for rel_file, cited_lines in locations.items():
        candidate = _resolve_plugin_file(plugin_root, rel_file)
        if candidate is None:
            continue
        try:
            lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue

        section = _render_setup_source_section(rel_file, lines, cited_lines)
        source_sections.append((rel_file, lines, section))

    if not source_sections:
        return None

    full_context = "\n\n".join(section for _path, _lines, section in source_sections)
    if len(full_context) <= max_chars:
        # Keep the established rendering byte-for-byte when no prioritisation is
        # needed. The overflow path below changes only context that was already
        # being truncated.
        return full_context

    primary_index = next(
        (
            index
            for index, (path, _lines, _section) in enumerate(source_sections)
            if path == hypothesis.file
        ),
        None,
    )
    if primary_index is None:
        return _truncate_setup_source_section(full_context, max_chars) or None

    primary_path, primary_lines, _primary_full = source_sections.pop(primary_index)
    explicit_primary = explicit_locations.get(primary_path, {hypothesis.line})
    semantic_primary = sorted(
        locations.get(primary_path, set()).difference(explicit_primary)
    )

    # In an oversized context, keep a compact bootstrap/configuration window and
    # the exact hypothesis anchor. The earliest semantic match in the primary
    # file is normally its registration/bootstrap site; later matches are often
    # repeated callers and must not crowd the cited sink out of the budget.
    config_anchor = semantic_primary[0] if semantic_primary else None
    auxiliary_budget_target = max_chars // 4 if source_sections else 0
    primary_budget_target = max_chars - auxiliary_budget_target

    primary_section = ""
    compact_shapes = (
        (35, 20, 12),
        (35, 12, 8),
        (20, 8, 4),
        (8, 4, 2),
        (0, 0, 0),
    )
    for head_lines, config_radius, anchor_radius in compact_shapes:
        selected = set()
        for line in explicit_primary:
            selected.update(
                range(
                    max(1, line - anchor_radius),
                    min(len(primary_lines), line + anchor_radius) + 1,
                )
            )
        if config_anchor is not None:
            selected.update(
                range(
                    max(1, config_anchor - config_radius),
                    min(len(primary_lines), config_anchor + config_radius) + 1,
                )
            )
        candidate_section = _render_setup_source_section(
            primary_path,
            primary_lines,
            selected,
            head_lines=head_lines,
            radius=0,
        )
        primary_section = candidate_section
        if len(candidate_section) <= primary_budget_target:
            break

    if len(primary_section) > max_chars:
        # A pathological single source line can exceed the whole context cap.
        # Fall back to the exact cited line rather than prefix-truncating an
        # earlier bootstrap region and silently losing the anchor altogether.
        anchor = min(max(hypothesis.line, 1), len(primary_lines))
        primary_section = _render_setup_source_section(
            primary_path,
            primary_lines,
            {anchor},
            head_lines=0,
            radius=0,
        )
        primary_section = _truncate_setup_source_section(primary_section, max_chars)

    separator_budget = 2 if source_sections and len(primary_section) < max_chars else 0
    remaining = max_chars - len(primary_section) - separator_budget
    auxiliary_sections: list[str] = []
    auxiliary_used = 0
    for _path, _lines, section in source_sections:
        separator = 2 if auxiliary_sections else 0
        available = remaining - auxiliary_used - separator
        if available <= 0:
            break
        bounded = _truncate_setup_source_section(section, available)
        if not bounded:
            break
        auxiliary_sections.append(bounded)
        auxiliary_used += separator + len(bounded)
        if len(bounded) < len(section):
            break

    if auxiliary_sections:
        context = "\n\n".join([*auxiliary_sections, primary_section])
    else:
        context = primary_section
    return context[:max_chars] or None


def _read_readme(plugin_root: Path) -> str | None:
    for name in ("readme.txt", "README.txt", "readme.md", "README.md"):
        p = plugin_root / name
        if p.is_file():
            try:
                return p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
    return None


def _required_attacker_account(
    user_accounts: list[dict], expected_attacker_role: str
) -> dict | None:
    """Resolve an authenticated hypothesis to one verified sandbox account."""
    normalized_role = normalize_attacker_role(expected_attacker_role)
    if normalized_role == "unauthenticated":
        return None

    acceptable_roles = {normalized_role}
    if normalized_role == "low_priv":
        # ``low_priv`` is an abstract boundary rather than a WordPress role. Use
        # the lowest concrete account the sandbox proved, preferring Subscriber.
        acceptable_roles = {"subscriber", "customer", "contributor", "author"}
    for role in (
        "subscriber",
        "customer",
        "contributor",
        "author",
        *sorted(acceptable_roles),
    ):
        if role not in acceptable_roles:
            continue
        account = next(
            (
                candidate
                for candidate in user_accounts
                if normalize_attacker_role(candidate.get("role")) == role
            ),
            None,
        )
        if account is not None:
            return account

    raise RuntimeError(
        "required authenticated attacker role is unavailable in the verified "
        f"sandbox account manifest: {normalized_role}"
    )


_SSRF_PARAMETER_NAME = r"[A-Za-z_][A-Za-z0-9_.:-]{0,127}"
_SSRF_PHP_PARAMETER_RE = re.compile(
    rf"\$_(?P<method>GET|POST)\s*\[\s*(['\"])(?P<parameter>{_SSRF_PARAMETER_NAME})\2\s*\]",
    re.IGNORECASE,
)
_SSRF_NAMED_LOCATION_PARAMETER_RE = re.compile(
    rf"\b(?P<parameter>{_SSRF_PARAMETER_NAME})\s+"
    r"(?P<location>query|form)\s+parameter\b",
    re.IGNORECASE,
)
_SSRF_LOCATION_EXPLICIT_NAMED_PARAMETER_RE = re.compile(
    r"\b(?P<location>query|form)\s+parameter\s+"
    rf"(?:named|called)\s+[`'\"]?(?P<parameter>{_SSRF_PARAMETER_NAME})",
    re.IGNORECASE,
)
_SSRF_LOCATION_QUOTED_PARAMETER_RE = re.compile(
    r"\b(?P<location>query|form)\s+parameter\s+"
    rf"(?P<quote>[`'\"])(?P<parameter>{_SSRF_PARAMETER_NAME})(?P=quote)",
    re.IGNORECASE,
)
_SSRF_METHOD_NAMED_PARAMETER_RE = re.compile(
    r"\b(?P<method>GET|POST)\s+(?:request\s+)?parameter\s+"
    rf"(?:(?:named|called)\s+)?[`'\"]?(?P<parameter>{_SSRF_PARAMETER_NAME})",
    re.IGNORECASE,
)
_SSRF_NAMED_METHOD_PARAMETER_RE = re.compile(
    rf"\b(?P<parameter>{_SSRF_PARAMETER_NAME})\s+"
    r"(?P<method>GET|POST)\s+(?:request\s+)?parameter\b",
    re.IGNORECASE,
)
_SSRF_METHOD_PARAMETER_NAME_RE = re.compile(
    r"\b(?P<method>GET|POST)\s+"
    rf"(?P<parameter>{_SSRF_PARAMETER_NAME})\s+parameter\b",
    re.IGNORECASE,
)
_SSRF_PARAMETER_STOPWORDS = frozenset(
    {"a", "an", "for", "from", "in", "named", "on", "the", "to"}
)
_SSRF_REST_QUERY_PARAMETER_RE = re.compile(
    rf"->\s*get_query_params\s*\(\s*\)\s*\[\s*"
    rf"(?P<quote>['\"])(?P<parameter>{_SSRF_PARAMETER_NAME})(?P=quote)\s*\]",
    re.IGNORECASE,
)
_SSRF_HTTP_SINK_RE = re.compile(
    r"\b(?:wp_(?:safe_)?remote_(?:get|post|head|request)|"
    r"file_get_contents|fopen|readfile|curl_init)\s*\(",
    re.IGNORECASE,
)
_SSRF_FUNCTION_RE = re.compile(
    r"\bfunction\s*(?:&\s*)?(?:[A-Za-z_][A-Za-z0-9_]*\s*)?\(",
    re.IGNORECASE,
)
_SSRF_NAMED_FUNCTION_RE = re.compile(
    r"\bfunction\s*(?:&\s*)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
    re.IGNORECASE,
)
_SSRF_MAX_SOURCE_BYTES = 2 * 1024 * 1024
_SSRF_SINK_ANCHOR_RADIUS_LINES = 12
_SSRF_ASSIGNMENT_RADIUS_LINES = 80
_SSRF_MAX_CALL_CHARS = 16 * 1024
_SSRF_LOCAL_FILE_SCHEME_RE = re.compile(r"(?<![A-Za-z0-9])file:/+", re.IGNORECASE)


def _ssrf_oracle_mode(hypothesis: Hypothesis) -> Literal["http", "local_resource"]:
    """Select a trusted backend from the source-reviewed vulnerability claim."""
    evidence = hypothesis.evidence_summary or {}
    values = [
        hypothesis.entry_point,
        hypothesis.sink,
        hypothesis.sink_code,
        hypothesis.reasoning,
        hypothesis.preconditions,
        *(str(item) for item in hypothesis.taint_path),
        *(str(value) for value in evidence.values() if isinstance(value, str)),
    ]
    return (
        "local_resource"
        if any(_SSRF_LOCAL_FILE_SCHEME_RE.search(value) for value in values)
        else "http"
    )


def _ssrf_oracle_modes_for_hypotheses(
    hypotheses: list[Hypothesis],
) -> frozenset[Literal["http", "local_resource"]]:
    """Return only the sandbox resources required by known SSRF candidates."""
    modes: set[Literal["http", "local_resource"]] = set()
    for hypothesis in hypotheses:
        if hypothesis.bug_class.oracle_key in {
            BugClass.SSRF.name,
            BugClass.SSRF.value,
        }:
            modes.add(_ssrf_oracle_mode(hypothesis))
    return frozenset(modes)


def _infer_ssrf_destination_evidence_candidates(
    hypothesis: Hypothesis,
) -> frozenset[tuple[str, Literal["query", "form"]]]:
    """Resolve every explicit model-described input for source cross-checking."""
    evidence_source = (hypothesis.evidence_summary or {}).get("source")
    values = [
        *(str(item) for item in hypothesis.taint_path),
        hypothesis.sink_code,
        hypothesis.sink,
    ]
    if isinstance(evidence_source, str):
        values.insert(0, evidence_source)

    candidates: set[tuple[str, Literal["query", "form"]]] = set()

    def add(parameter: str, location: str) -> None:
        if parameter.casefold() in _SSRF_PARAMETER_STOPWORDS:
            return
        normalized_location: Literal["query", "form"] = (
            "query" if location.casefold() in {"get", "query"} else "form"
        )
        candidates.add((parameter, normalized_location))

    for value in values:
        for match in _SSRF_PHP_PARAMETER_RE.finditer(value):
            add(match.group("parameter"), match.group("method"))
        for match in _SSRF_NAMED_LOCATION_PARAMETER_RE.finditer(value):
            add(match.group("parameter"), match.group("location"))
        for pattern in (
            _SSRF_LOCATION_EXPLICIT_NAMED_PARAMETER_RE,
            _SSRF_LOCATION_QUOTED_PARAMETER_RE,
        ):
            for match in pattern.finditer(value):
                add(match.group("parameter"), match.group("location"))
        for pattern in (
            _SSRF_METHOD_NAMED_PARAMETER_RE,
            _SSRF_NAMED_METHOD_PARAMETER_RE,
            _SSRF_METHOD_PARAMETER_NAME_RE,
        ):
            for match in pattern.finditer(value):
                add(match.group("parameter"), match.group("method"))

    return frozenset(candidates)


def _infer_ssrf_destination_evidence(
    hypothesis: Hypothesis,
) -> tuple[str, Literal["query", "form"]] | None:
    """Return one unambiguous model-described SSRF input, when available."""
    candidates = _infer_ssrf_destination_evidence_candidates(hypothesis)
    return next(iter(candidates)) if len(candidates) == 1 else None


def _resolve_ssrf_source_file(plugin_root: str | Path, rel_file: str) -> Path | None:
    """Resolve one cited PHP file without permitting traversal or symlink escape."""
    try:
        root = Path(plugin_root).resolve(strict=True)
    except OSError:
        return None
    if not root.is_dir() or not isinstance(rel_file, str) or "\x00" in rel_file:
        return None

    normalized = rel_file.replace("\\", "/").strip()
    for prefix in (
        f"wp-content/plugins/{root.name}/",
        f"{root.name}/",
    ):
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix) :]
            break
    relative = PurePosixPath(normalized)
    if (
        not normalized
        or relative.is_absolute()
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        return None
    try:
        candidate = (root / Path(*relative.parts)).resolve(strict=True)
        candidate.relative_to(root)
    except (OSError, ValueError):
        return None
    if not candidate.is_file() or candidate.suffix.casefold() != ".php":
        return None
    try:
        if candidate.stat().st_size > _SSRF_MAX_SOURCE_BYTES:
            return None
    except OSError:
        return None
    return candidate


def _mask_php_non_code(source: str) -> str:
    """Mask strings/comments while preserving offsets used for bounded parsing."""
    masked = list(source)
    state = "code"
    index = 0
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if char == "'":
                masked[index] = " "
                state = "single"
            elif char == '"':
                masked[index] = " "
                state = "double"
            elif char == "#":
                masked[index] = " "
                state = "line_comment"
            elif char == "/" and following == "/":
                masked[index] = masked[index + 1] = " "
                index += 1
                state = "line_comment"
            elif char == "/" and following == "*":
                masked[index] = masked[index + 1] = " "
                index += 1
                state = "block_comment"
        elif state in {"single", "double"}:
            if char != "\n":
                masked[index] = " "
            if char == "\\" and following:
                if following != "\n":
                    masked[index + 1] = " "
                index += 1
            elif (state == "single" and char == "'") or (
                state == "double" and char == '"'
            ):
                state = "code"
        elif state == "line_comment":
            if char == "\n":
                state = "code"
            else:
                masked[index] = " "
        else:
            if char != "\n":
                masked[index] = " "
            if char == "*" and following == "/":
                masked[index + 1] = " "
                index += 1
                state = "code"
        index += 1
    return "".join(masked)


def _matching_delimiter(
    masked: str,
    opening: int,
    open_char: str,
    close_char: str,
    *,
    limit: int | None = None,
) -> int | None:
    """Find a balanced delimiter within one explicitly bounded source range."""
    if opening < 0 or opening >= len(masked) or masked[opening] != open_char:
        return None
    end = min(len(masked), limit) if limit is not None else len(masked)
    depth = 0
    for index in range(opening, end):
        if masked[index] == open_char:
            depth += 1
        elif masked[index] == close_char:
            depth -= 1
            if depth == 0:
                return index
            if depth < 0:
                return None
    return None


def _enclosing_php_function(
    masked: str,
    anchor: int,
) -> tuple[int, int] | None:
    """Return the innermost named/anonymous function block enclosing an anchor."""
    ranges: list[tuple[int, int]] = []
    for match in _SSRF_FUNCTION_RE.finditer(masked, 0, anchor + 1):
        opening_parenthesis = match.end() - 1
        closing_parenthesis = _matching_delimiter(
            masked,
            opening_parenthesis,
            "(",
            ")",
            limit=min(len(masked), opening_parenthesis + _SSRF_MAX_CALL_CHARS),
        )
        if closing_parenthesis is None:
            continue
        terminator_match = re.search(r"[;{]", masked[closing_parenthesis + 1 :])
        if terminator_match is None:
            continue
        terminator = closing_parenthesis + 1 + terminator_match.start()
        if masked[terminator] != "{":
            continue
        closing_brace = _matching_delimiter(masked, terminator, "{", "}")
        if closing_brace is not None and terminator < anchor <= closing_brace:
            ranges.append((terminator, closing_brace))
    if not ranges:
        return None
    return max(ranges, key=lambda item: item[0])


def _source_line_starts(source: str) -> list[int]:
    starts = [0]
    starts.extend(index + 1 for index, char in enumerate(source) if char == "\n")
    return starts


def _line_at_offset(line_starts: list[int], offset: int) -> int:
    return bisect_right(line_starts, offset)


def _call_arguments(
    source: str,
    masked: str,
    opening_parenthesis: int,
    closing_parenthesis: int,
) -> tuple[str, ...] | None:
    """Extract top-level call arguments without guessing through bad syntax."""
    round_depth = square_depth = brace_depth = 0
    start = opening_parenthesis + 1
    arguments: list[str] = []
    for index in range(opening_parenthesis + 1, closing_parenthesis):
        char = masked[index]
        if char == "(":
            round_depth += 1
        elif char == ")":
            if round_depth == 0:
                return None
            round_depth -= 1
        elif char == "[":
            square_depth += 1
        elif char == "]":
            if square_depth == 0:
                return None
            square_depth -= 1
        elif char == "{":
            brace_depth += 1
        elif char == "}":
            if brace_depth == 0:
                return None
            brace_depth -= 1
        elif char == "," and not (round_depth or square_depth or brace_depth):
            value = source[start:index].strip()
            if not value:
                return None
            arguments.append(value)
            start = index + 1
    value = source[start:closing_parenthesis].strip()
    if value:
        arguments.append(value)
    elif arguments:
        return None
    return tuple(arguments)


def _first_call_argument(
    source: str,
    masked: str,
    opening_parenthesis: int,
    closing_parenthesis: int,
) -> str | None:
    """Extract a call's first top-level argument."""
    arguments = _call_arguments(
        source,
        masked,
        opening_parenthesis,
        closing_parenthesis,
    )
    return arguments[0] if arguments else None


def _literal_request_sources(
    expression: str,
) -> set[tuple[str, Literal["query", "form"]]]:
    """Extract only literal request-key reads with an unambiguous input channel."""
    candidates: set[tuple[str, Literal["query", "form"]]] = set()
    for match in _SSRF_PHP_PARAMETER_RE.finditer(expression):
        location: Literal["query", "form"] = (
            "query" if match.group("method").casefold() == "get" else "form"
        )
        candidates.add((match.group("parameter"), location))
    for match in _SSRF_REST_QUERY_PARAMETER_RE.finditer(expression):
        candidates.add((match.group("parameter"), "query"))
    return candidates


def _enclosing_named_php_function(
    source: str,
    masked: str,
    anchor: int,
) -> tuple[str, tuple[str, ...], int, int] | None:
    """Return the innermost named function and its bounded source body."""
    candidates: list[tuple[str, tuple[str, ...], int, int]] = []
    for match in _SSRF_NAMED_FUNCTION_RE.finditer(masked, 0, anchor + 1):
        opening_parenthesis = match.end() - 1
        closing_parenthesis = _matching_delimiter(
            masked,
            opening_parenthesis,
            "(",
            ")",
            limit=min(len(masked), opening_parenthesis + _SSRF_MAX_CALL_CHARS),
        )
        if closing_parenthesis is None:
            continue
        terminator_match = re.search(r"[;{]", masked[closing_parenthesis + 1 :])
        if terminator_match is None:
            continue
        body_start = closing_parenthesis + 1 + terminator_match.start()
        if masked[body_start] != "{":
            continue
        body_end = _matching_delimiter(masked, body_start, "{", "}")
        if body_end is None or not body_start < anchor <= body_end:
            continue
        parameters = _call_arguments(
            source,
            masked,
            opening_parenthesis,
            closing_parenthesis,
        )
        if parameters is None:
            continue
        candidates.append((match.group("name"), parameters, body_start, body_end))
    if not candidates:
        return None
    return max(candidates, key=lambda item: item[2])


def _parameter_name(parameter: str) -> str | None:
    """Return one PHP function-parameter variable without interpreting defaults."""
    declaration = parameter.split("=", 1)[0]
    matches = re.findall(r"\$([A-Za-z_][A-Za-z0-9_]*)", declaration)
    return matches[0] if len(matches) == 1 else None


def _parameter_call_sources(
    source: str,
    masked: str,
    *,
    function_name: str,
    parameter_index: int,
    definition_body: tuple[int, int],
) -> tuple[frozenset[tuple[str, Literal["query", "form"]]], bool]:
    """Trace one URL parameter through direct same-file calls to its function."""
    pattern = re.compile(rf"\b{re.escape(function_name)}\s*\(", re.IGNORECASE)
    candidates: set[tuple[str, Literal["query", "form"]]] = set()
    has_global_dispatch = False
    body_start, body_end = definition_body
    for match in pattern.finditer(masked):
        opening_parenthesis = match.end() - 1
        prefix = masked[max(0, match.start() - 2) : match.start()]
        if prefix in {"->", "::"} or body_start < match.start() < body_end:
            continue
        # Exclude the named function declaration itself.
        declaration_prefix = masked[max(0, match.start() - 32) : match.start()]
        if re.search(r"\bfunction\s*(?:&\s*)?\Z", declaration_prefix, re.IGNORECASE):
            continue
        closing_parenthesis = _matching_delimiter(
            masked,
            opening_parenthesis,
            "(",
            ")",
            limit=min(len(masked), opening_parenthesis + _SSRF_MAX_CALL_CHARS),
        )
        if closing_parenthesis is None:
            continue
        arguments = _call_arguments(
            source,
            masked,
            opening_parenthesis,
            closing_parenthesis,
        )
        if arguments is None or parameter_index >= len(arguments):
            continue
        direct_sources = _literal_request_sources(arguments[parameter_index])
        if len(direct_sources) != 1:
            continue
        candidates.update(direct_sources)
        if _enclosing_php_function(masked, match.start()) is None:
            has_global_dispatch = True
    return frozenset(candidates), has_global_dispatch


def _brace_stack(masked: str, start: int, position: int) -> tuple[int, ...] | None:
    stack: list[int] = []
    for index in range(start, position):
        if masked[index] == "{":
            stack.append(index)
        elif masked[index] == "}":
            if not stack:
                return None
            stack.pop()
    return tuple(stack)


def _assignment_rhs(
    source: str,
    masked: str,
    start: int,
    limit: int,
) -> str | None:
    """Read one bounded assignment RHS through its top-level semicolon."""
    round_depth = square_depth = brace_depth = 0
    for index in range(start, limit):
        char = masked[index]
        if char == "(":
            round_depth += 1
        elif char == ")":
            if round_depth == 0:
                return None
            round_depth -= 1
        elif char == "[":
            square_depth += 1
        elif char == "]":
            if square_depth == 0:
                return None
            square_depth -= 1
        elif char == "{":
            brace_depth += 1
        elif char == "}":
            if brace_depth == 0:
                return None
            brace_depth -= 1
        elif char == ";" and not (round_depth or square_depth or brace_depth):
            value = source[start:index].strip()
            return value or None
    return None


def _infer_ssrf_destination_from_plugin_source(
    plugin_root: str | Path,
    hypothesis: Hypothesis,
) -> tuple[str, Literal["query", "form"]] | None:
    """Trace one cited HTTP sink back to one literal request input in plugin PHP."""
    source_file = _resolve_ssrf_source_file(plugin_root, hypothesis.file)
    if source_file is None:
        return None
    try:
        source = source_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    lines = source.splitlines()
    if not isinstance(hypothesis.line, int) or not 1 <= hypothesis.line <= len(lines):
        return None
    if "<<<" in source:
        # Heredoc/nowdoc requires a PHP lexer; do not guess structural scopes.
        return None

    masked = _mask_php_non_code(source)
    line_starts = _source_line_starts(source)
    anchor_start = line_starts[hypothesis.line - 1]
    anchor_end = (
        line_starts[hypothesis.line]
        if hypothesis.line < len(line_starts)
        else len(source)
    )
    function_range = _enclosing_php_function(masked, anchor_start)
    if function_range is None:
        return None
    function_start, function_end = function_range

    lower_line = max(1, hypothesis.line - _SSRF_SINK_ANCHOR_RADIUS_LINES)
    upper_line = min(len(lines), hypothesis.line + _SSRF_SINK_ANCHOR_RADIUS_LINES)
    search_start = max(function_start + 1, line_starts[lower_line - 1])
    search_end = min(
        function_end,
        line_starts[upper_line] if upper_line < len(line_starts) else len(source),
    )
    sink_calls: list[tuple[int, int, int, str]] = []
    for match in _SSRF_HTTP_SINK_RE.finditer(masked, search_start, search_end):
        opening_parenthesis = match.end() - 1
        closing_parenthesis = _matching_delimiter(
            masked,
            opening_parenthesis,
            "(",
            ")",
            limit=min(function_end, opening_parenthesis + _SSRF_MAX_CALL_CHARS),
        )
        if closing_parenthesis is None:
            continue
        start_line = _line_at_offset(line_starts, match.start())
        end_line = _line_at_offset(line_starts, closing_parenthesis)
        if match.start() <= anchor_end and closing_parenthesis >= anchor_start:
            distance = 0
        else:
            distance = min(
                abs(start_line - hypothesis.line),
                abs(end_line - hypothesis.line),
            )
        if distance > _SSRF_SINK_ANCHOR_RADIUS_LINES:
            continue
        argument = _first_call_argument(
            source,
            masked,
            opening_parenthesis,
            closing_parenthesis,
        )
        if argument is not None:
            sink_calls.append((distance, match.start(), closing_parenthesis, argument))
    if not sink_calls:
        return None
    nearest_distance = min(item[0] for item in sink_calls)
    nearest = [item for item in sink_calls if item[0] == nearest_distance]
    if len(nearest) != 1:
        return None
    _distance, sink_start, _sink_end, argument = nearest[0]

    direct_sources = _literal_request_sources(argument)
    if len(direct_sources) == 1:
        return next(iter(direct_sources))
    if direct_sources:
        return None

    variable_match = re.fullmatch(
        r"\s*\$(?P<variable>[A-Za-z_][A-Za-z0-9_]*)\s*",
        argument,
    )
    if variable_match is None:
        return None
    variable = variable_match.group("variable")
    lower_assignment_line = max(
        1,
        hypothesis.line - _SSRF_ASSIGNMENT_RADIUS_LINES,
    )
    assignment_start = max(function_start + 1, line_starts[lower_assignment_line - 1])
    assignment_pattern = re.compile(
        rf"(?:^|[;{{}}])(?P<spacing>\s*)(?P<lhs>\${re.escape(variable)})\s*=(?!=|>)",
        re.MULTILINE,
    )
    assignments = list(
        assignment_pattern.finditer(masked, assignment_start, sink_start)
    )
    if len(assignments) != 1:
        return None
    assignment = assignments[0]
    lhs_start = assignment.start("lhs")
    if _brace_stack(masked, function_start, lhs_start) != _brace_stack(
        masked,
        function_start,
        sink_start,
    ):
        return None
    rhs = _assignment_rhs(
        source,
        masked,
        assignment.end(),
        sink_start,
    )
    if rhs is None:
        return None
    assigned_sources = _literal_request_sources(rhs)
    if len(assigned_sources) != 1:
        return None
    return next(iter(assigned_sources))


def _infer_ssrf_destination_source_candidates(
    plugin_root: str | Path,
    hypothesis: Hypothesis,
) -> tuple[frozenset[tuple[str, Literal["query", "form"]]], bool]:
    """Return source-bound destinations, including direct helper call sites.

    The existing intraprocedural tracer remains authoritative when it resolves
    one input. The bounded interprocedural fallback handles a common direct PHP
    dispatcher shape: a URL wrapper receives one named function parameter, and
    same-file call sites pass literal ``$_GET``/``$_POST`` values into that exact
    parameter. No aliases, dynamic calls, methods, or cross-file flow are guessed.
    """
    direct = _infer_ssrf_destination_from_plugin_source(plugin_root, hypothesis)
    if direct is not None:
        return frozenset({direct}), False

    source_file = _resolve_ssrf_source_file(plugin_root, hypothesis.file)
    if source_file is None:
        return frozenset(), False
    try:
        source = source_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return frozenset(), False
    lines = source.splitlines()
    if (
        not isinstance(hypothesis.line, int)
        or not 1 <= hypothesis.line <= len(lines)
        or "<<<" in source
    ):
        return frozenset(), False

    masked = _mask_php_non_code(source)
    line_starts = _source_line_starts(source)
    anchor_start = line_starts[hypothesis.line - 1]
    anchor_end = (
        line_starts[hypothesis.line]
        if hypothesis.line < len(line_starts)
        else len(source)
    )
    function_range = _enclosing_php_function(masked, anchor_start)
    named_function = _enclosing_named_php_function(source, masked, anchor_start)
    if function_range is None or named_function is None:
        return frozenset(), False
    function_start, function_end = function_range

    lower_line = max(1, hypothesis.line - _SSRF_SINK_ANCHOR_RADIUS_LINES)
    upper_line = min(len(lines), hypothesis.line + _SSRF_SINK_ANCHOR_RADIUS_LINES)
    search_start = max(function_start + 1, line_starts[lower_line - 1])
    search_end = min(
        function_end,
        line_starts[upper_line] if upper_line < len(line_starts) else len(source),
    )
    sink_arguments: list[tuple[int, str]] = []
    for match in _SSRF_HTTP_SINK_RE.finditer(masked, search_start, search_end):
        opening_parenthesis = match.end() - 1
        closing_parenthesis = _matching_delimiter(
            masked,
            opening_parenthesis,
            "(",
            ")",
            limit=min(function_end, opening_parenthesis + _SSRF_MAX_CALL_CHARS),
        )
        if closing_parenthesis is None:
            continue
        start_line = _line_at_offset(line_starts, match.start())
        end_line = _line_at_offset(line_starts, closing_parenthesis)
        distance = (
            0
            if match.start() <= anchor_end and closing_parenthesis >= anchor_start
            else min(
                abs(start_line - hypothesis.line),
                abs(end_line - hypothesis.line),
            )
        )
        if distance > _SSRF_SINK_ANCHOR_RADIUS_LINES:
            continue
        argument = _first_call_argument(
            source,
            masked,
            opening_parenthesis,
            closing_parenthesis,
        )
        if argument is not None:
            sink_arguments.append((distance, argument))
    if not sink_arguments:
        return frozenset(), False
    nearest_distance = min(distance for distance, _argument in sink_arguments)
    nearest = [
        argument
        for distance, argument in sink_arguments
        if distance == nearest_distance
    ]
    if len(nearest) != 1:
        return frozenset(), False
    variable_match = re.fullmatch(
        r"\s*\$(?P<variable>[A-Za-z_][A-Za-z0-9_]*)\s*",
        nearest[0],
    )
    if variable_match is None:
        return frozenset(), False

    function_name, parameters, body_start, body_end = named_function
    parameter_names = tuple(_parameter_name(parameter) for parameter in parameters)
    variable = variable_match.group("variable")
    matching_indexes = [
        index
        for index, parameter in enumerate(parameter_names)
        if parameter == variable
    ]
    if len(matching_indexes) != 1:
        return frozenset(), False
    return _parameter_call_sources(
        source,
        masked,
        function_name=function_name,
        parameter_index=matching_indexes[0],
        definition_body=(body_start, body_end),
    )


def _direct_plugin_file_route(
    hypothesis: Hypothesis,
    plugin_root: str | Path,
    plugin_slug: str | None,
) -> str:
    """Derive one direct plugin-file route from a source-confined PHP citation."""
    if not plugin_slug:
        return ""
    try:
        slug = validate_plugin_slug(plugin_slug)
        root = Path(plugin_root).resolve(strict=True)
        source_file = _resolve_ssrf_source_file(root, hypothesis.file)
        if source_file is None:
            return ""
        relative = source_file.relative_to(root)
    except (OSError, ValueError):
        return ""
    if any(
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", part) is None
        for part in relative.parts
    ):
        return ""
    return "/wp-content/plugins/" + slug + "/" + "/".join(relative.parts)


def _expected_ssrf_http_transport(
    hypothesis: Hypothesis,
    plugin_root: str | Path,
    plugin_slug: str | None = None,
) -> dict[str, object]:
    """Bind SSRF verification to matching model and authoritative source inputs."""
    transport: dict[str, object] = dict(
        _parse_entry_point_transport(hypothesis.entry_point)
    )
    source_destinations, has_global_dispatch = (
        _infer_ssrf_destination_source_candidates(
            plugin_root,
            hypothesis,
        )
    )
    evidence_destinations = _infer_ssrf_destination_evidence_candidates(hypothesis)
    destinations = sorted(
        source_destinations & evidence_destinations,
        key=lambda item: (item[1] != "query", item[0], item[1]),
    )
    if len(destinations) == 1:
        destination = destinations[0]
        if not transport.get("method") and has_global_dispatch:
            transport["method"] = "GET" if destination[1] == "query" else "POST"
            transport["route"] = _direct_plugin_file_route(
                hypothesis,
                plugin_root,
                plugin_slug,
            )
        dispatch = transport.get("dispatch")
        if isinstance(dispatch, dict):
            dispatch = dict(dispatch)
            dispatch.pop(f"{destination[1]}:{destination[0]}", None)
            transport["dispatch"] = dispatch
        transport["destination_parameter"] = destination[0]
        transport["destination_location"] = destination[1]
        return transport

    if len(destinations) > 1 and has_global_dispatch:
        route = _direct_plugin_file_route(
            hypothesis,
            plugin_root,
            plugin_slug,
        )
        if route:
            alternatives: list[dict[str, object]] = [
                {
                    "method": "GET" if location == "query" else "POST",
                    "route": route,
                    "dispatch": {},
                    "destination_parameter": parameter,
                    "destination_location": location,
                }
                for parameter, location in destinations
            ]
            return {"alternatives": alternatives}

    # Preserve the parsed entry point on failure so diagnostics can distinguish
    # a missing source-bound destination from a missing HTTP route.
    source_destination = _infer_ssrf_destination_from_plugin_source(
        plugin_root,
        hypothesis,
    )
    evidence_destination = _infer_ssrf_destination_evidence(hypothesis)
    matched_destination = (
        source_destination
        if source_destination is not None and source_destination == evidence_destination
        else None
    )
    if matched_destination is not None:
        dispatch = transport.get("dispatch")
        if isinstance(dispatch, dict):
            dispatch = dict(dispatch)
            dispatch.pop(
                f"{matched_destination[1]}:{matched_destination[0]}",
                None,
            )
            transport["dispatch"] = dispatch
    transport["destination_parameter"] = (
        matched_destination[0] if matched_destination else ""
    )
    transport["destination_location"] = (
        matched_destination[1] if matched_destination else ""
    )
    return transport


async def _verify_one(
    hyp: Hypothesis,
    plugin_path: str,
    plugin_zip: str,
    plugin_slug: str,
    config: PipelineConfig,
    runtime: AgentRuntime,
    poc_dir: Path,
    developer: DeveloperAgent | None = None,
    # When provided, the caller owns sandbox boot and teardown.
    persistent_sb: SandboxManager | None = None,
) -> Finding | None:
    verify_cfg = config.verify

    poc_dir.mkdir(parents=True, exist_ok=True)
    # Drop the xss_check helper next to the PoC scripts so they can `from xss_check import ...`.
    atomic_write_text(poc_dir / "xss_check.py", _XSS_CHECK_SRC)
    # Drop the wp_login helper too — robust GET-then-POST flow with the
    # `wordpress_test_cookie` handled. Eliminates "admin login failed" false
    # negatives caused by PoC scripts skipping the GET prime step.
    atomic_write_text(poc_dir / "wp_login.py", _WP_LOGIN_SRC)
    atomic_write_text(poc_dir / "poc_result.py", _POC_RESULT_SRC)
    attempts: list[PoCAttempt] = []
    last_evidence: dict = {}
    expected_attacker_role = infer_attacker_role(hyp)
    expected_bug_class = hyp.bug_class.oracle_key
    ssrf_expected = expected_bug_class in {
        BugClass.SSRF.name,
        BugClass.SSRF.value,
    }
    ssrf_oracle_mode = _ssrf_oracle_mode(hyp) if ssrf_expected else "http"
    sandbox_ssrf_modes = (
        frozenset({ssrf_oracle_mode}) if ssrf_expected else frozenset()
    )
    code_slice: str | None = None
    readme: str | None = None
    if developer is not None:
        plugin_root = Path(plugin_path)
        code_slice = _build_setup_code_context(plugin_root, hyp)
        readme = _read_readme(plugin_root)
    setup_plan = SetupPlan()
    setup_exec_results: list[dict] = []
    setup_round_notes: list[str] = []
    automatic_followups_used = 0
    automatic_followup_cap = _SETUP_FOLLOWUP_CAP
    poc_requested_followups_used = 0
    poc_requested_followup_cap = _POC_REQUESTED_SETUP_FOLLOWUP_CAP

    def _checkpoint_attempts(
        status: Literal["in_progress", "not_confirmed", "confirmed"] = "in_progress",
    ) -> None:
        """Persist rejected attempts too, including the terminal validator reason."""
        atomic_write_json(
            poc_dir / "attempts.json",
            {
                "schema_version": 1,
                "hypothesis_id": hyp.id,
                "status": status,
                "attempts": [attempt.model_dump(mode="json") for attempt in attempts],
            },
        )

    # Establish a new-format checkpoint before setup, authoring, snapshotting, or
    # execution can be interrupted.  An empty in-progress attempt list is
    # intentionally non-terminal and will be retried by ``run()``.
    _checkpoint_attempts()

    def _checkpoint_setup_results() -> None:
        """Persist exact setup execution state for audit and interrupted runs."""
        followups_used = automatic_followups_used + poc_requested_followups_used
        followup_cap = automatic_followup_cap + poc_requested_followup_cap
        atomic_write_json(
            poc_dir / "setup_results.json",
            {
                # Retain aggregate fields for readers of older checkpoints.
                "followups_used": followups_used,
                "followup_cap": followup_cap,
                "automatic_followups_used": automatic_followups_used,
                "automatic_followup_cap": automatic_followup_cap,
                "poc_requested_followups_used": poc_requested_followups_used,
                "poc_requested_followup_cap": poc_requested_followup_cap,
                "proposed_commands": setup_plan.commands,
                "results": setup_exec_results,
            },
        )

    def _current_setup_summary() -> str | None:
        """Render canonical setup state from all results known at prompt time."""
        if not (setup_plan.rationale or setup_round_notes or setup_exec_results):
            return None
        reasons = [f"Initial plan: {setup_plan.rationale or '(none stated)'}"]
        reasons.extend(setup_round_notes)
        execution_summary = (
            _summarise_setup_results(setup_exec_results)
            or "(no setup commands were executed)"
        )
        return (
            "The runner configured the sandbox before this PoC attempt.\n"
            "Setup rationale history:\n- "
            + "\n- ".join(reasons)
            + "\nAuthoritative cumulative setup execution results:\n"
            + execution_summary
            + "\nResults are ordered oldest to newest. Use only state whose result "
            "is OK or OK WITH WARNINGS, and treat a newer self-verified result as "
            "canonical when it contradicts or supersedes an older value. FAILED "
            "or partial commands are not evidence that their requested state exists. "
            "A BLOCKED BEFORE EXECUTION command made no state change."
        )

    # Bound once the sandbox and developer are available.
    setup_callback_state: dict[str, Any] = {"sb": None}

    async def _request_setup_followup(
        sb_local: SandboxManager,
        *,
        last_iteration: int,
        last_stdout: str,
        last_stderr: str,
        last_error_log: str,
        schema_diagnostics: str = "",
        setup_execution_feedback: str = "",
        quota_kind: Literal["automatic", "poc_requested"] = "automatic",
    ) -> tuple[SetupPlan | None, list[tuple[SetupPlan, list[dict]]]]:
        """Request and apply bounded setup repairs, retrying atomic blocks directly."""
        nonlocal automatic_followups_used, poc_requested_followups_used

        if quota_kind == "poc_requested":
            quota_cap = poc_requested_followup_cap
        elif quota_kind == "automatic":
            quota_cap = automatic_followup_cap
        else:
            raise ValueError(f"unknown setup followup quota kind: {quota_kind}")

        def _quota_used() -> int:
            if quota_kind == "poc_requested":
                return poc_requested_followups_used
            return automatic_followups_used

        rounds: list[tuple[SetupPlan, list[dict]]] = []
        followup: SetupPlan | None = None
        feedback = setup_execution_feedback
        diagnostics = schema_diagnostics
        atomic_retries = 0
        while developer is not None and _quota_used() < quota_cap:
            # Count every developer request, including empty or errored responses.
            if quota_kind == "poc_requested":
                poc_requested_followups_used += 1
            else:
                automatic_followups_used += 1
            quota_used = _quota_used()
            try:
                followup = await developer.propose_setup_followup(
                    hypothesis=hyp,
                    prior_plan=setup_plan,
                    last_iteration=last_iteration,
                    last_stdout=last_stdout,
                    last_stderr=last_stderr,
                    last_error_log=last_error_log,
                    schema_diagnostics=diagnostics,
                    code_slice=code_slice,
                    setup_execution_feedback=feedback,
                    runtime=runtime,
                    plugin_root=plugin_path,
                )
            except Exception as exc:
                logger.warning("propose_setup_followup for %s failed: %s", hyp.id, exc)
                _checkpoint_setup_results()
                return None, rounds

            if not followup.commands:
                _checkpoint_setup_results()
                return followup, rounds

            logger.info(
                "verify: %s applying %d %s followup setup commands (round %d/%d)",
                hyp.id,
                len(followup.commands),
                quota_kind,
                quota_used,
                quota_cap,
            )
            results = await _run_setup_commands(
                sb_local,
                followup.commands,
                hypothesis=hyp,
                plugin_slug=plugin_slug,
            )
            setup_exec_results.extend(results)
            # Preserve proposed history, but execution status is carried separately.
            setup_plan.commands.extend(followup.commands)
            setup_round_notes.append(
                f"{quota_kind.replace('_', '-')} followup {quota_used}: "
                f"{followup.rationale or '(no rationale)'}"
            )
            rounds.append((followup, results))
            _checkpoint_setup_results()

            if not any(item.get("failed") for item in results):
                return followup, rounds

            # A mixed safe/forbidden argv is rejected atomically. Feed the exact
            # non-execution back once so a clean replacement can be issued without
            # spending a PoC iteration. Ordinary execution failures return to the
            # PoC loop instead of consuming the whole followup budget up front.
            blocked_before_execution = any(
                item.get("blocked_before_execution") is True for item in results
            )
            if (
                not blocked_before_execution
                or atomic_retries >= _ATOMIC_SETUP_RETRY_CAP
            ):
                return followup, rounds
            atomic_retries += 1

            latest_feedback = _summarise_setup_results(results)
            cumulative_feedback = _summarise_setup_results(setup_exec_results)
            feedback = (
                f"LATEST SETUP ROUND:\n{latest_feedback}\n\n"
                f"CUMULATIVE SETUP HISTORY:\n{cumulative_feedback}"
            )
            retry_diagnostics = await _collect_schema_diagnostics(
                sb_local, followup.commands
            )
            if retry_diagnostics:
                diagnostics = "\n".join(
                    part for part in (diagnostics, retry_diagnostics) if part
                )

        return followup, rounds

    async def _setup_callback(description: str) -> str:
        sb_local = setup_callback_state["sb"]
        if sb_local is None or developer is None:
            return "[request_additional_setup] sandbox or developer not yet ready"
        if poc_requested_followups_used >= poc_requested_followup_cap:
            return (
                "[request_additional_setup] PoC-requested setup followup limit reached "
                f"({poc_requested_followup_cap}/{poc_requested_followup_cap})"
            )

        followup, rounds = await _request_setup_followup(
            sb_local,
            last_iteration=0,
            last_stdout="",
            last_stderr="",
            last_error_log="",
            schema_diagnostics=(
                f"PoC author requested additional setup:\n{description}"
            ),
            setup_execution_feedback=_summarise_setup_results(setup_exec_results),
            quota_kind="poc_requested",
        )
        if not rounds:
            rationale = followup.rationale if followup else "none"
            return (
                "[request_additional_setup] developer returned no applicable commands "
                f"(rationale: {rationale!r})"
            )

        final_plan, final_results = rounds[-1]
        all_round_results = [item for _plan, results in rounds for item in results]
        result_summary = "\n".join(
            f"Round {round_number}:\n{_summarise_setup_results(results)}"
            for round_number, (_plan, results) in enumerate(rounds, start=1)
        )
        if any(item.get("failed") for item in final_results):
            applied = sum(
                1
                for item in all_round_results
                if item.get("executed") and not item.get("failed")
            )
            return (
                "[request_additional_setup] setup remains incomplete; "
                f"{applied} permitted commands were applied. "
                "Execution feedback is authoritative:\n"
                f"{result_summary}"
            )
        executed = sum(
            1
            for item in all_round_results
            if item.get("executed") and not item.get("failed")
        )
        return (
            f"[request_additional_setup] applied {executed} permitted commands. "
            f"Rationale: {final_plan.rationale or '(none)'}\n"
            f"Execution feedback:\n{result_summary}"
        )

    poc_author = PoCAuthorAgent(
        runtime,
        model=config.models.poc_author,
        plugin_root=plugin_path,
        setup_callback=_setup_callback,
    )

    # Every route type can depend on plugin-created objects, forms, pages, nonces,
    # or settings. Ask for legitimate setup even when the HTTP endpoint itself is
    # directly reachable.
    if developer is not None:
        try:
            setup_plan = await developer.propose_setup(
                hyp,
                plugin_slug=plugin_slug,
                code_slice=code_slice,
                readme_excerpt=readme,
            )
        except Exception as e:
            logger.warning("propose_setup for %s failed: %s", hyp.id, e)

    # persistent_sb is supplied when verify.run() reuses one sandbox.
    # In that mode we DO NOT enter a new SandboxManager context — the caller has already
    # booted, installed plugin, set up users, and called restore() to baseline state.
    # We just run the per-hypothesis logic against the existing sb.
    @asynccontextmanager
    async def _sb_ctx():
        if persistent_sb is not None:
            # Caller manages lifecycle — also already installed the plugin + test users
            # and applied snapshot/restore as needed. We only run the per-hypothesis
            # propose-setup commands.
            setup_exec_results.extend(
                await _run_setup_commands(
                    persistent_sb,
                    setup_plan.commands,
                    hypothesis=hyp,
                    plugin_slug=plugin_slug,
                ),
            )
            _checkpoint_setup_results()
            yield persistent_sb
            return
        async with SandboxManager(
            config.sandbox,
            boot_timeout_s=max(config.sandbox_timeout_seconds, 180),
            poc_timeout_s=config.sandbox_timeout_seconds,
            ssrf_oracle_modes=sandbox_ssrf_modes,
        ) as fresh_sb:
            await fresh_sb.install_plugin(plugin_zip, plugin_slug)
            await fresh_sb.setup_test_users()
            setup_exec_results.extend(
                await _run_setup_commands(
                    fresh_sb,
                    setup_plan.commands,
                    hypothesis=hyp,
                    plugin_slug=plugin_slug,
                ),
            )
            _checkpoint_setup_results()
            yield fresh_sb

    async with _sb_ctx() as sb:
        # Bind the live sandbox into the PoC author's setup callback.
        setup_callback_state["sb"] = sb

        async def _restore_attempt_state(snapshot: Path) -> None:
            await sb.restore(snapshot)
            if ssrf_oracle_mode == "local_resource":
                await sb.restart_wordpress_runtime()

        setup_failed = any(item.get("failed") for item in setup_exec_results)
        if setup_failed:
            if (
                developer is not None
                and automatic_followups_used < automatic_followup_cap
            ):
                diagnostics = await _collect_schema_diagnostics(sb, setup_plan.commands)
                _followup, _repair_rounds = await _request_setup_followup(
                    sb,
                    last_iteration=0,
                    last_stdout="",
                    last_stderr="",
                    last_error_log="",
                    schema_diagnostics=diagnostics,
                    setup_execution_feedback=_summarise_setup_results(
                        setup_exec_results
                    ),
                    quota_kind="automatic",
                )

        # Surface the credential table the sandbox provisioned. PoC author MUST
        # pick from this list rather than recalling credentials from system prompt.
        user_accounts = sb.baseline_user_accounts()
        role_account = _required_attacker_account(
            user_accounts,
            expected_attacker_role,
        )
        normalized_role = (
            normalize_attacker_role(role_account.get("role"))
            if role_account is not None
            else "unauthenticated"
        )
        expected_http_transport = (
            _expected_ssrf_http_transport(hyp, plugin_path, plugin_slug)
            if ssrf_expected
            else None
        )
        if ssrf_expected:
            author_user_accounts = [role_account] if role_account is not None else []
        else:
            author_user_accounts = user_accounts

        for iteration in range(1, config.verify_max_iterations + 1):
            # Each authored SSRF attempt receives fresh, short-lived capabilities.
            # The same prepared oracle remains authoritative for that attempt's
            # attack and clean-state confirmation executions; each execution
            # rotates its private response marker inside SandboxManager.
            if not ssrf_expected:
                ssrf_oracle = None
            elif ssrf_oracle_mode == "local_resource":
                ssrf_oracle = await sb.prepare_ssrf_local_resource_oracle()
            else:
                ssrf_oracle = await sb.prepare_ssrf_oracle()
            # Rebuild from the complete execution ledger immediately before each
            # author call. This includes setup requested by earlier PoC tool turns
            # and cannot drift from the checkpointed command results.
            setup_summary = _current_setup_summary()
            extra_ctx: dict = {
                "user_accounts": author_user_accounts,
                "attacker_role": normalized_role,
                "test_username": role_account["login"] if role_account else "",
                "test_password": role_account["password"] if role_account else "",
            }
            if ssrf_oracle is not None:
                extra_ctx["ssrf_oracle"] = ssrf_oracle
                extra_ctx["ssrf_http_transport"] = expected_http_transport
            if setup_summary:
                extra_ctx["setup_summary"] = setup_summary
            script = await poc_author.write(
                hypothesis=hyp,
                target_url=sb.target_url,
                previous_attempts=attempts,
                extra_context=extra_ctx or None,
            )
            script_path = poc_dir / f"iter_{iteration}.py"
            atomic_write_text(script_path, script)

            pre_attempt_snapshot: Path | None = None
            try:
                pre_attempt_snapshot = await sb.snapshot()
            except Exception as exc:
                reason = f"clean-state snapshot failed: {exc}"
                logger.warning("verify: %s %s", hyp.id, reason)
                attempts.append(
                    PoCAttempt(
                        iteration=iteration,
                        script_path=str(script_path),
                        result=PoCStatus.FAILED,
                        validation_reason=reason,
                    )
                )
                _checkpoint_attempts()
                raise RuntimeError(reason) from exc

            result = await sb.run_poc(
                str(script_path),
                expected_bug_class=expected_bug_class,
                expected_attacker_role=normalized_role,
                expected_http_transport=expected_http_transport,
            )
            attempt = PoCAttempt(
                iteration=iteration,
                phase="attack",
                script_path=str(script_path),
                result=PoCStatus.SUCCESS if result.success else PoCStatus.FAILED,
                http_status=result.http_status,
                response_snippet=(result.response or "")[:500] or None,
                timing_seconds=result.elapsed,
                error_log_snippet=(result.error_log or "")[:500] or None,
                developer_analysis=None,  # PoC author re-evaluates with consult_developer in next iter
                observation=result.observation,
                validation_reason=(
                    result.validation_reason
                    or ((result.error_log or "")[:1000] if not result.success else "")
                    or ("PoC execution failed" if not result.success else None)
                ),
            )
            attempts.append(attempt)
            _checkpoint_attempts()

            if result.success:
                forbidden_setup = any(
                    _setup_result_taints_confirmation(item)
                    for item in setup_exec_results
                )
                if forbidden_setup:
                    reason = (
                        "PoC returned SUCCESS, but verification rejected it because sandbox "
                        "setup crossed a protected verification boundary:\n"
                        f"{_summarise_forbidden_setup(setup_exec_results)}\n"
                        "A valid confirmation must preserve managed user authority and plugin "
                        "activation state, and must submit malicious values through a real "
                        "plugin/WordPress entry point reachable by the claimed attacker role."
                    )
                    attempt.result = PoCStatus.FAILED
                    attempt.validation_reason = reason[:1000]
                    attempt.developer_analysis = reason[:1000]
                    _checkpoint_attempts()
                    logger.warning(
                        "verify: %s rejected tainted setup confirmation", hyp.id
                    )
                    if pre_attempt_snapshot is not None:
                        await _restore_attempt_state(pre_attempt_snapshot)
                        shutil.rmtree(pre_attempt_snapshot, ignore_errors=True)
                    break
                # Re-run from the exact state that existed before the first
                # attempt. This prevents one-shot state mutation from being
                # mistaken for independent confirmation.
                await _restore_attempt_state(pre_attempt_snapshot)
                confirm = await sb.run_poc(
                    str(script_path),
                    expected_bug_class=expected_bug_class,
                    expected_attacker_role=normalized_role,
                    expected_http_transport=expected_http_transport,
                )
                confirmation_attempt = PoCAttempt(
                    iteration=iteration,
                    phase="confirmation",
                    script_path=str(script_path),
                    result=PoCStatus.SUCCESS if confirm.success else PoCStatus.FAILED,
                    http_status=confirm.http_status,
                    response_snippet=(confirm.response or "")[:500] or None,
                    timing_seconds=confirm.elapsed,
                    error_log_snippet=(confirm.error_log or "")[:500] or None,
                    observation=confirm.observation,
                    validation_reason=(
                        confirm.validation_reason
                        or (
                            (confirm.error_log or "")[:1000]
                            if not confirm.success
                            else ""
                        )
                        or (
                            "clean-state confirmation failed"
                            if not confirm.success
                            else None
                        )
                    ),
                )
                matching_confirmation = False
                confirmation_reason = "confirmation did not produce a valid observation"
                if result.observation is not None and confirm.observation is not None:
                    matching_confirmation, confirmation_reason = (
                        validate_confirmation_observations(
                            result.observation,
                            confirm.observation,
                        )
                    )
                if confirm.success and matching_confirmation:
                    attempts.append(confirmation_attempt)
                    _checkpoint_attempts()
                    last_evidence = {
                        "first_run": result.evidence,
                        "confirmation_run": confirm.evidence,
                        "clean_state_restored": True,
                    }
                    shutil.rmtree(pre_attempt_snapshot, ignore_errors=True)
                    if config.report.screenshot_capture:
                        screenshot_dir = poc_dir / "screenshots"
                        await verify_helpers.screenshot_url(
                            sb.target_url + "/wp-admin/",
                            screenshot_dir / f"{hyp.id}_admin.png",
                            timeout_s=verify_cfg.headless_browser_timeout_s,
                        )
                    break
                if confirm.success:
                    confirmation_attempt.result = PoCStatus.FAILED
                    confirmation_attempt.validation_reason = confirmation_reason
                elif not confirmation_attempt.validation_reason:
                    confirmation_attempt.validation_reason = (
                        "clean-state confirmation oracle did not reproduce"
                    )
                attempt.result = PoCStatus.FAILED
                attempt.validation_reason = "clean-state confirmation failed: " + (
                    confirmation_reason
                    if confirm.success
                    else (confirm.validation_reason or "oracle did not reproduce")
                )
                attempt.developer_analysis = attempt.validation_reason[:1000]
                attempts.append(confirmation_attempt)
                _checkpoint_attempts()
                result = confirm
                await _restore_attempt_state(pre_attempt_snapshot)
                shutil.rmtree(pre_attempt_snapshot, ignore_errors=True)
            else:
                if pre_attempt_snapshot is not None:
                    await _restore_attempt_state(pre_attempt_snapshot)
                    shutil.rmtree(pre_attempt_snapshot, ignore_errors=True)

            # Failed iteration — ask the developer if it looks setup-shaped, before next PoC try.
            if (
                developer is not None
                and automatic_followups_used < automatic_followup_cap
                and iteration
                < config.verify_max_iterations  # no point on the last iter
            ):
                diagnostics = await _collect_schema_diagnostics(sb, setup_plan.commands)
                followup, _followup_rounds = await _request_setup_followup(
                    sb,
                    last_iteration=iteration,
                    last_stdout=result.response or "",
                    last_stderr=result.error_log or "",
                    last_error_log=result.error_log or "",
                    schema_diagnostics=diagnostics,
                    setup_execution_feedback=_summarise_setup_results(
                        setup_exec_results
                    ),
                    quota_kind="automatic",
                )
                if followup is not None and not followup.commands:
                    # No setup change is needed, but a failed generated request is not proof
                    # that the source candidate is safe. Give the PoC author the diagnosis
                    # and continue within the configured iteration bound.
                    fc = followup.failure_class
                    stderr_blob = result.error_log or ""
                    poc_crashed = (
                        "Traceback (most recent call last)" in stderr_blob
                        or "JSONDecodeError" in stderr_blob
                        or "KeyError" in stderr_blob
                        or "IndexError" in stderr_blob
                        or "AttributeError" in stderr_blob
                    )
                    classification = (
                        "poc_code" if poc_crashed else (fc or "exploit_shape")
                    )
                    attempt.developer_analysis = (
                        f"{classification}: {followup.rationale or '(none)'}"
                    )[:1000]
                    _checkpoint_attempts()
                    logger.info(
                        "verify: %s iter %d failure classified as %s — continuing PoC "
                        "iteration (rationale: %s)",
                        hyp.id,
                        iteration,
                        classification,
                        (followup.rationale or "(none)")[:200],
                    )

        _checkpoint_attempts()

        # Collect optional diagnostics while the failed sandbox is still alive.
        any_confirmed = any(
            attempt.phase == "confirmation" and attempt.result == PoCStatus.SUCCESS
            for attempt in attempts
        )
        if not any_confirmed and verify_cfg.state_introspection_on_failure:
            try:
                await verify_helpers.dump_sandbox_state(sb, poc_dir / "state_dump")
            except Exception as e:
                logger.warning("verify: state dump for %s failed: %s", hyp.id, e)

        _checkpoint_setup_results()

    successful = [
        attempt for attempt in attempts if attempt.result == PoCStatus.SUCCESS
    ]
    confirmations = [
        attempt for attempt in successful if attempt.phase == "confirmation"
    ]
    if not confirmations:
        _checkpoint_attempts(status="not_confirmed")
        logger.info(
            "verify: %s NOT confirmed after %d iterations", hyp.id, len(attempts)
        )
        return None

    confirmed_observation = confirmations[-1].observation
    if confirmed_observation is None:
        raise RuntimeError("successful confirmation lacks a structured observation")
    verified_hypothesis = hyp.model_copy(deep=True)
    verified_hypothesis.security_outcome = SecurityOutcome(
        confidentiality=confirmed_observation.impact.confidentiality,
        integrity=confirmed_observation.impact.integrity,
        availability=confirmed_observation.impact.availability,
        description=confirmed_observation.impact.description,
    )
    finding = Finding(
        id=_next_finding_id(),
        hypothesis=verified_hypothesis,
        poc_status=PoCStatus.SUCCESS,
        poc_script_path=confirmations[-1].script_path,
        poc_attempts=attempts,
        evidence=last_evidence,
        confidence_runs=len(successful),
        verified_impact=confirmed_observation.impact.model_copy(deep=True),
        dedup_status=DedupStatus.NOT_CHECKED,
        dedup_matches=[],
    )

    _checkpoint_attempts(status="confirmed")

    return finding


def _new_verify_archive_dir(run_dir: Path) -> Path:
    return run_dir / "verify_archive" / uuid.uuid4().hex[:12]


def _archive_forced_verify_artifacts(
    run_dir: Path,
    verifications_dir: Path,
    findings_path: Path,
    complete_path: Path,
) -> Path | None:
    """Move prior verify outputs aside before an explicitly forced re-run."""
    existing = [
        path
        for path in (verifications_dir, findings_path, complete_path)
        if path.exists()
    ]
    if not existing:
        return None

    archive_dir = _new_verify_archive_dir(run_dir)
    archive_dir.mkdir(parents=True, exist_ok=False)
    for path in existing:
        shutil.move(str(path), str(archive_dir / path.name))
    return archive_dir


def _archive_hypothesis_artifacts(
    run_dir: Path,
    hyp_dir: Path,
    archive_dir: Path | None,
) -> tuple[Path | None, Path | None]:
    """Archive an incomplete candidate before retrying it in a clean directory."""
    if not hyp_dir.exists():
        return archive_dir, None
    if archive_dir is None:
        archive_dir = _new_verify_archive_dir(run_dir)
    target = archive_dir / "verifications" / hyp_dir.name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(hyp_dir), str(target))
    return archive_dir, target


def _open_cwe_manual_checkpoint_matches(
    hyp_dir: Path,
    hypothesis: Hypothesis,
) -> bool:
    """Return whether an open CWE already has a complete local manual handoff."""
    if hypothesis.bug_class.is_known:
        return False
    marker_path = hyp_dir / OPEN_CWE_MANUAL_REVIEW_FILENAME
    if not marker_path.exists():
        return False
    try:
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return False
    return (
        isinstance(marker, dict)
        and marker.get("schema_version") == 1
        and marker.get("status") == "manual_review"
        and marker.get("hypothesis_id") == hypothesis.id
        and marker.get("bug_class") == hypothesis.bug_class.value
        and marker.get("source") == _OPEN_CWE_MANUAL_REVIEW_SOURCE
        and not (hyp_dir / "error.log").exists()
        and not any(hyp_dir.glob("iter_*.py"))
        and (hyp_dir / "manual_scaffold" / "README.md").is_file()
        and (hyp_dir / "manual_scaffold" / "context.json").is_file()
    )


def _attempt_checkpoint_state(hyp_dir: Path) -> str | None:
    """Return a trusted attempt state, or ``incomplete`` for a bad checkpoint.

    ``None`` identifies historical verification directories that predate the
    checkpoint.  Their existing iteration-only resume behavior is preserved.
    """
    path = hyp_dir / "attempts.json"
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return "incomplete"
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        return "incomplete"
    if payload.get("hypothesis_id") != hyp_dir.name:
        return "incomplete"
    status = payload.get("status")
    if status not in {"in_progress", "not_confirmed", "confirmed"}:
        return "incomplete"
    attempts = payload.get("attempts")
    if not isinstance(attempts, list) or not attempts:
        return "incomplete"
    try:
        parsed_attempts = [PoCAttempt.model_validate(attempt) for attempt in attempts]
    except (TypeError, ValueError):
        return "incomplete"
    if status == "not_confirmed" and any(
        attempt.phase == "confirmation" and attempt.result == PoCStatus.SUCCESS
        for attempt in parsed_attempts
    ):
        # A reproduced clean-state confirmation cannot be reconciled with a
        # terminal negative.  Retry rather than silently discarding it.
        return "incomplete"
    return str(status)


async def run(
    triaged: TriagedArtifact,
    plugin_path: str,
    config: PipelineConfig,
    budget: BudgetTracker,
    runtime: AgentRuntime,
    runs_root: str = "runs",
    run_id: str = "",
    developer: DeveloperAgent | None = None,
    force: bool = False,
) -> list[Finding]:
    automatic_hypotheses = [
        hypothesis for hypothesis in triaged.accepted if hypothesis.bug_class.is_known
    ]
    plugin_zip = ""
    plugin_zip_staging: Path | None = None
    if automatic_hypotheses:
        plugin_zip, plugin_zip_staging = _zip_plugin(plugin_path, triaged.plugin_slug)
        logger.info("verify: zipped plugin to %s", plugin_zip)

    findings: list[Finding] = []
    run_dir = Path(runs_root) / run_id
    verifications_dir = Path(runs_root) / run_id / "verifications"
    findings_path = Path(runs_root) / run_id / "findings.jsonl"
    complete_path = run_dir / VERIFY_COMPLETE_FILENAME
    findings_path.parent.mkdir(parents=True, exist_ok=True)

    retry_archive_dir: Path | None = None
    if force:
        retry_archive_dir = _archive_forced_verify_artifacts(
            run_dir,
            verifications_dir,
            findings_path,
            complete_path,
        )
        if retry_archive_dir is not None:
            logger.info(
                "verify: archived prior forced-run artifacts to %s", retry_archive_dir
            )
            append_decision(
                run_dir,
                stage="verify",
                action="archive",
                result="forced_rerun",
                artifact=retry_archive_dir,
            )
    else:
        # A caller reached the stage because the prior pass was incomplete. Do not
        # leave a stale success marker behind if this retry fails.
        complete_path.unlink(missing_ok=True)

    # Per-hypothesis checkpoint: load any previously confirmed findings (so a
    # mid-list crash doesn't lose them). A clean iter_*.py checkpoint is a terminal
    # non-confirmation. error.log, or a directory without iterations, is incomplete
    # and must be retried.
    previously_confirmed: dict[str, Finding] = {}
    if not force and findings_path.exists() and findings_path.stat().st_size > 0:
        parsed, corrupt_count = read_jsonl_models(
            findings_path,
            Finding,
            corrupt_path=run_dir / "findings_corrupt.jsonl",
        )
        accepted_hypothesis_ids = {hypothesis.id for hypothesis in triaged.accepted}
        stale_findings = [
            finding
            for finding in parsed
            if finding.hypothesis.id not in accepted_hypothesis_ids
        ]
        if stale_findings:
            stale_path = run_dir / "findings_stale.jsonl"
            atomic_write_jsonl(stale_path, stale_findings)
            logger.warning(
                "verify: quarantined %d finding(s) outside the current triage set to %s",
                len(stale_findings),
                stale_path,
            )
            append_decision(
                run_dir,
                stage="verify",
                action="recover",
                result="stale_findings_quarantined",
                reason=(
                    f"{len(stale_findings)} finding(s) referenced hypotheses outside "
                    "the current accepted set"
                ),
                artifact=stale_path,
                details={
                    "hypothesis_ids": [
                        finding.hypothesis.id for finding in stale_findings
                    ]
                },
            )
        open_cwe_findings = [
            finding
            for finding in parsed
            if finding.hypothesis.id in accepted_hypothesis_ids
            and not finding.hypothesis.bug_class.is_known
        ]
        if open_cwe_findings:
            quarantine_path = run_dir / "findings_open_cwe_quarantined.jsonl"
            atomic_write_jsonl(quarantine_path, open_cwe_findings)
            logger.warning(
                "verify: quarantined %d prior open-CWE finding(s) without a reviewed "
                "automatic verification contract to %s",
                len(open_cwe_findings),
                quarantine_path,
            )
            append_decision(
                run_dir,
                stage="verify",
                action="recover",
                result="open_cwe_findings_quarantined",
                reason=(
                    f"{len(open_cwe_findings)} finding(s) used canonical unmapped "
                    "CWEs without a reviewed automatic verification contract"
                ),
                artifact=quarantine_path,
                details={
                    "hypothesis_ids": [
                        finding.hypothesis.id for finding in open_cwe_findings
                    ]
                },
            )
        for f in parsed:
            if f.hypothesis.id not in accepted_hypothesis_ids:
                continue
            if not f.hypothesis.bug_class.is_known:
                continue
            previously_confirmed[f.hypothesis.id] = f
        if corrupt_count:
            logger.warning(
                "verify: quarantined %d malformed findings.jsonl line(s) to %s",
                corrupt_count,
                run_dir / "findings_corrupt.jsonl",
            )
            append_decision(
                run_dir,
                stage="verify",
                action="recover",
                result="corrupt_findings_quarantined",
                reason=f"{corrupt_count} malformed findings.jsonl line(s)",
                artifact=run_dir / "findings_corrupt.jsonl",
            )
        if previously_confirmed:
            logger.info(
                "verify: resuming with %d previously confirmed findings",
                len(previously_confirmed),
            )
    findings.extend(previously_confirmed.values())

    # Open findings.jsonl in append mode after preserving prior content.
    # Re-write what we have so the file is the canonical source of truth.
    atomic_write_jsonl(findings_path, findings)

    unresolved_errors: list[tuple[str, str]] = []
    manual_review_hypothesis_ids: list[str] = []
    manual_queued = 0
    manual_already_queued = 0

    # Persistent path: boot one sandbox at scan level, snapshot baseline,
    # restore between hypotheses. Cuts ~80% of sandbox cost for multi-hypothesis runs.
    persistent_sb: SandboxManager | None = None
    persistent_snapshot: Path | None = None
    if config.verify.persistent_sandbox and automatic_hypotheses:
        try:
            persistent_sb = SandboxManager(
                config.sandbox,
                boot_timeout_s=max(config.sandbox_timeout_seconds, 180),
                poc_timeout_s=config.sandbox_timeout_seconds,
                ssrf_oracle_modes=_ssrf_oracle_modes_for_hypotheses(
                    automatic_hypotheses
                ),
            )
            await persistent_sb.boot()
            await persistent_sb.install_plugin(plugin_zip, triaged.plugin_slug)
            await persistent_sb.setup_test_users()
            persistent_snapshot = await persistent_sb.snapshot()
            logger.info(
                "verify: persistent sandbox booted (target=%s, snapshot=%s)",
                persistent_sb.target_url,
                persistent_snapshot,
            )
        except Exception as e:
            logger.warning(
                "verify: persistent sandbox boot failed: %s — falling back to per-hypothesis",
                e,
            )
            if persistent_sb is not None:
                try:
                    await persistent_sb.teardown()
                except Exception:
                    pass
            persistent_sb = None
            persistent_snapshot = None

    try:
        for hyp in triaged.accepted:
            if not hyp.bug_class.is_known:
                hyp_dir = verifications_dir / hyp.id
                checkpoint_matches = _open_cwe_manual_checkpoint_matches(hyp_dir, hyp)
                archived_path: Path | None = None
                if hyp_dir.exists() and not checkpoint_matches:
                    if (hyp_dir / "error.log").exists():
                        archive_reason = "previous_error_before_open_cwe_manual_review"
                    elif any(hyp_dir.glob("iter_*.py")):
                        archive_reason = (
                            "previous_automatic_attempt_before_open_cwe_manual_review"
                        )
                    else:
                        archive_reason = "incomplete_open_cwe_manual_review"
                    retry_archive_dir, archived_path = _archive_hypothesis_artifacts(
                        run_dir,
                        hyp_dir,
                        retry_archive_dir,
                    )
                    append_decision(
                        run_dir,
                        stage="verify",
                        action="archive",
                        result=archive_reason,
                        hypothesis_id=hyp.id,
                        artifact=archived_path,
                    )

                hyp_dir.mkdir(parents=True, exist_ok=True)
                reason = (
                    f"{hyp.bug_class.value} is a canonical unmapped CWE with no "
                    "reviewed automatic verification oracle. Automatic confirmation "
                    f"is disabled; use {OPEN_CWE_POC_TEMPLATE} as the fail-closed "
                    "starting point for manual verification."
                )
                verify_helpers.write_manual_scaffold(
                    hyp,
                    hyp_dir,
                    triaged.plugin_slug,
                    "",
                    handoff_reason=reason,
                )
                was_queued = verify_helpers.emit_to_manual_review_queue(
                    hyp,
                    run_dir,
                    reason=reason,
                    verifier_notes={
                        "source": _OPEN_CWE_MANUAL_REVIEW_SOURCE,
                        "manual_review": True,
                        "automatic_verification": False,
                        "poc_template": OPEN_CWE_POC_TEMPLATE,
                    },
                )
                atomic_write_json(
                    hyp_dir / OPEN_CWE_MANUAL_REVIEW_FILENAME,
                    {
                        "schema_version": 1,
                        "status": "manual_review",
                        "hypothesis_id": hyp.id,
                        "bug_class": hyp.bug_class.value,
                        "source": _OPEN_CWE_MANUAL_REVIEW_SOURCE,
                        "automatic_verification": False,
                        "poc_template": OPEN_CWE_POC_TEMPLATE,
                        "reason": reason,
                    },
                )
                manual_review_hypothesis_ids.append(hyp.id)
                if was_queued:
                    manual_queued += 1
                else:
                    manual_already_queued += 1
                append_decision(
                    run_dir,
                    stage="verify",
                    action="manual_review" if was_queued else "skip",
                    result=(
                        "open_cwe_manual_review_queued"
                        if was_queued
                        else "open_cwe_manual_review_already_queued"
                    ),
                    hypothesis_id=hyp.id,
                    reason=reason,
                    artifact=hyp_dir / "manual_scaffold",
                    details={
                        "automatic_verification": False,
                        "poc_template": OPEN_CWE_POC_TEMPLATE,
                        "prior_artifacts_archived": archived_path is not None,
                    },
                )
                continue
            if hyp.id in previously_confirmed:
                logger.info(
                    "verify: %s — skipping (already confirmed in prior run)", hyp.id
                )
                append_decision(
                    run_dir,
                    stage="verify",
                    action="skip",
                    result="previously_confirmed",
                    hypothesis_id=hyp.id,
                    artifact=findings_path,
                )
                continue
            hyp_dir = verifications_dir / hyp.id
            error_path = hyp_dir / "error.log"
            iter_files = sorted(hyp_dir.glob("iter_*.py")) if hyp_dir.exists() else []
            checkpoint_state = _attempt_checkpoint_state(hyp_dir)
            # Only a clean iteration checkpoint is a terminal non-confirmation.
            # Exceptions and non-terminal/corrupt checkpoints take precedence even
            # if one or more iteration scripts were written first.  Directories
            # without attempts.json predate the checkpoint and retain the legacy
            # iteration-only skip behavior.
            terminal_not_confirmed = checkpoint_state in {None, "not_confirmed"}
            if (
                hyp_dir.exists()
                and iter_files
                and not error_path.exists()
                and terminal_not_confirmed
            ):
                logger.info(
                    "verify: %s — skipping (already attempted, no confirm). "
                    "Use --from verify to retry.",
                    hyp.id,
                )
                append_decision(
                    run_dir,
                    stage="verify",
                    action="skip",
                    result="previously_attempted_not_confirmed",
                    hypothesis_id=hyp.id,
                    artifact=hyp_dir,
                )
                continue
            if hyp_dir.exists():
                retry_reason = (
                    "previous_error" if error_path.exists() else "incomplete_checkpoint"
                )
                retry_archive_dir, archived_path = _archive_hypothesis_artifacts(
                    run_dir,
                    hyp_dir,
                    retry_archive_dir,
                )
                logger.info(
                    "verify: %s — retrying %s checkpoint (archived to %s)",
                    hyp.id,
                    retry_reason,
                    archived_path,
                )
                append_decision(
                    run_dir,
                    stage="verify",
                    action="archive",
                    result=retry_reason,
                    hypothesis_id=hyp.id,
                    artifact=archived_path,
                )
            logger.info("verify: %s (%s)", hyp.id, hyp.bug_class.value)
            hyp_dir.mkdir(parents=True, exist_ok=True)

            # Restore baseline before each hypothesis to prevent state leakage.
            if persistent_sb is not None and persistent_snapshot is not None:
                try:
                    await persistent_sb.restore(persistent_snapshot)
                except Exception as e:
                    logger.warning(
                        "verify: persistent restore for %s failed: %s; "
                        "falling back to a fresh per-hypothesis sandbox",
                        hyp.id,
                        e,
                    )
                    try:
                        await persistent_sb.teardown()
                    finally:
                        shutil.rmtree(persistent_snapshot, ignore_errors=True)
                        persistent_sb = None
                        persistent_snapshot = None
            try:
                finding = await _verify_one(
                    hyp,
                    plugin_path,
                    plugin_zip,
                    triaged.plugin_slug,
                    config,
                    runtime,
                    poc_dir=hyp_dir,
                    developer=developer,
                    persistent_sb=persistent_sb,
                )
            except Exception as e:
                import traceback

                tb = traceback.format_exc()
                logger.exception("verify: hypothesis %s raised: %s", hyp.id, e)
                atomic_write_text(
                    hyp_dir / "error.log",
                    f"=== Exception during verify for {hyp.id} ===\n"
                    f"hypothesis: {hyp.bug_class.value} {hyp.file}:{hyp.line}\n"
                    f"sink: {hyp.sink}\n\n"
                    f"{tb}",
                )
                append_decision(
                    run_dir,
                    stage="verify",
                    action="error",
                    result="exception",
                    hypothesis_id=hyp.id,
                    reason=str(e),
                    artifact=hyp_dir / "error.log",
                )
                unresolved_errors.append((hyp.id, str(e)))
                continue
            # Detect silent failures — completed normally but no iter files were written.
            iter_files = sorted(hyp_dir.glob("iter_*.py"))
            if not iter_files:
                reason = "_verify_one returned without writing any PoC iterations"
                atomic_write_text(
                    hyp_dir / "error.log",
                    f"=== Silent failure for {hyp.id} ===\n"
                    f"_verify_one returned without raising an exception, but no iter files\n"
                    f"were written. This usually means SandboxManager.__aenter__() raised an\n"
                    f"exception that was caught silently OR propose_setup hung without raising,\n"
                    f"OR docker compose timed out internally.\n\n"
                    f"Inspect runs/{run_id}/trace.jsonl for poc_author entries (or absence) to\n"
                    f"diagnose. If `propose_setup for {hyp.id} failed` appears in the run logs\n"
                    f"that's the smoking gun.\n",
                )
                logger.warning(
                    "verify: hypothesis %s — no iter files written and no exception raised",
                    hyp.id,
                )
                append_decision(
                    run_dir,
                    stage="verify",
                    action="error",
                    result="silent_failure",
                    hypothesis_id=hyp.id,
                    reason=reason,
                    artifact=hyp_dir / "error.log",
                )
                unresolved_errors.append((hyp.id, reason))
                continue
            if finding is None:
                append_decision(
                    run_dir,
                    stage="verify",
                    action="reject",
                    result="not_confirmed",
                    hypothesis_id=hyp.id,
                    artifact=hyp_dir,
                )
                continue
            findings.append(finding)
            with findings_path.open("a") as output_file:
                output_file.write(finding.model_dump_json() + "\n")
            append_decision(
                run_dir,
                stage="verify",
                action="confirm",
                result=finding.poc_status.value,
                hypothesis_id=hyp.id,
                finding_id=finding.id,
                artifact=findings_path,
                details={"poc_script_path": finding.poc_script_path},
            )
    finally:
        # Tear down the persistent sandbox at end of scan.
        if persistent_sb is not None:
            try:
                await persistent_sb.teardown()
                logger.info("verify: persistent sandbox torn down")
            except Exception as e:
                logger.warning("verify: persistent sandbox teardown failed: %s", e)
        if persistent_snapshot is not None and persistent_snapshot.exists():
            try:
                shutil.rmtree(persistent_snapshot)
            except Exception:
                pass
        if plugin_zip_staging is not None:
            shutil.rmtree(plugin_zip_staging, ignore_errors=True)

    if unresolved_errors:
        raise VerifyStageError(unresolved_errors, findings)

    atomic_write_json(
        complete_path,
        {
            "status": "complete",
            "accepted_hypothesis_ids": [hyp.id for hyp in triaged.accepted],
            "finding_ids": [finding.id for finding in findings],
            "automatic_verification_hypothesis_ids": [
                hyp.id for hyp in automatic_hypotheses
            ],
            "manual_review_hypothesis_ids": manual_review_hypothesis_ids,
            "manual_review_queue": {
                "queued": manual_queued,
                "already_queued": manual_already_queued,
            },
            "submission_scope_enforced": triaged.submission_scope_enforced,
        },
    )
    logger.info("verify: %d findings confirmed -> %s", len(findings), findings_path)
    return findings
