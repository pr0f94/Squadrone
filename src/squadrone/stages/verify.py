"""Verify stage — sandbox boot + PoC iteration loop per accepted hypothesis."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import shutil
import tempfile
import uuid
from bisect import bisect_right
from contextlib import asynccontextmanager
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from importlib.resources import files as _pkg_files
from pathlib import Path, PurePosixPath
from typing import Any, Awaitable, Callable, Literal

from ..agents.developer import DeveloperAgent, RequestedSetupPlan, SetupPlan
from ..agents.poc_author import (
    PHP_OBJECT_INERT_IMPACT_DESCRIPTION,
    PoCAuthorAgent,
    _parse_entry_point_transport,
)
from ..agents.runtime import AgentRuntime
from ..poc_isolation import (
    EXECUTABLE_UPLOAD_ATTACK_FILENAME_ENV,
    EXECUTABLE_UPLOAD_CONTROL_FILENAME_ENV,
    EXECUTABLE_UPLOAD_PAYLOAD_ENV,
)
from ..schemas.config import PipelineConfig
from ..schemas.finding import DedupStatus, Finding, PoCAttempt, PoCStatus
from ..schemas.hypothesis import Hypothesis, SecurityOutcome, TriagedArtifact
from ..schemas.observation import CIAImpact, PoCObservation
from ..schemas.php_object_gadget import PhpObjectGadgetRecipe
from ..schemas.taxonomy import BugClass, OPEN_CWE_POC_TEMPLATE
from ..services.artifacts import (
    atomic_write_json,
    atomic_write_jsonl,
    atomic_write_text,
    read_jsonl_models,
)
from ..services.budget import BudgetTracker
from ..services.decision_ledger import append_decision
from ..services.diagnostics import bound_diagnostic
from ..services.quality_gate import (
    infer_attacker_role,
    validate_php_object_natural_finding_confirmation,
)
from ..services.php_object_oracle import PhpObjectCallsite, PhpObjectOracleSnapshot
from ..services.php_object_gadget_oracle import (
    PHP_OBJECT_GADGET_ORACLE_MODE,
    PHP_OBJECT_GADGET_ORACLE_SCHEMA_VERSION,
    PhpObjectGadgetOracleSnapshot,
    validate_php_object_gadget_snapshot_pair,
)
from ..services.roles import normalize_attacker_role
from ..services.setup_http import SetupHttpContext
from ..services.sandbox import (
    EXECUTABLE_UPLOAD_CHALLENGE_PARAMETER,
    EXECUTABLE_UPLOAD_RESPONSE_PREFIX,
    SandboxManager,
    SandboxRunResult,
    WORDPRESS_WEB_USER,
    php_include_private_marker_from_observation,
    redact_php_include_run_result,
    validate_confirmation_observations,
    validate_plugin_slug,
)
from ..services import verify_helpers
from .triage import validate_php_object_gadget_recipe_sources

logger = logging.getLogger(__name__)

VERIFY_COMPLETE_FILENAME = "verify_complete.json"
OPEN_CWE_MANUAL_REVIEW_FILENAME = "manual_review.json"
PHP_OBJECT_PRIMITIVE_CONFIRMATION_FILENAME = "primitive_confirmation.json"
PHP_OBJECT_NATURAL_CONFIRMATION_FILENAME = "natural_gadget_confirmation.json"
PHP_OBJECT_NATURAL_IMPACT_DESCRIPTION = (
    "PHP object injection deleted one verifier-created, non-executable regular "
    "file in the isolated sandbox temporary directory; the object-free control "
    "preserved the same file."
)
_OPEN_CWE_MANUAL_REVIEW_SOURCE = "verify_open_cwe"
_POC_RESULT_PREFIX = "SQUADRONE_RESULT="


def _strip_child_result_lines(value: str | None) -> str:
    """Remove machine self-reports from text after the runner rejected them."""
    if not value:
        return ""
    return "\n".join(
        line for line in value.splitlines() if _POC_RESULT_PREFIX not in line
    ).strip()


def _runner_failure_feedback(result: SandboxRunResult) -> str:
    """Render failure context without presenting a child claim as evidence."""
    if result.success:
        raise ValueError("runner failure feedback requires a failed result")
    lines = [
        "AUTHORITATIVE RUNNER VERDICT: FAILED",
        "AUTHORITATIVE VALIDATION REASON: "
        + (result.validation_reason or "runner rejected the execution"),
    ]
    if (
        result.evidence.get("php_object_oracle_error") == "transport_incomplete"
        and result.evidence.get("php_object_oracle_failure_reason")
        == "php_object_transport_incomplete"
    ):
        lines.append(
            "TRUSTED PHP OBJECT DIAGNOSTIC: expected attack/control transport "
            "did not complete; this was not classified as executable-surface drift."
        )
    if result.rejected_observation is not None:
        lines.extend(
            [
                "REJECTED CHILD OBSERVATION: the PoC emitted a machine self-report, "
                "but none of its success declarations are established measurements.",
                "REPORTED ORACLE TYPE (diagnostic only): "
                + result.rejected_observation.oracle,
                "OTHER CHILD OUTPUT: withheld because the runner rejected the "
                "observation; consult only the authoritative validation reason.",
            ]
        )
    else:
        remaining_output = _strip_child_result_lines(result.output)
        lines.append(
            "OTHER POC OUTPUT (diagnostic only):\n"
            + (
                bound_diagnostic(remaining_output, limit=2000)
                if remaining_output
                else "(none)"
            )
        )
    return "\n".join(lines)


def _attempt_response_snippet(result: SandboxRunResult) -> str | None:
    """Persist accepted output or an explicitly rejected failure summary."""
    if result.success:
        return (result.response or "")[:500] or None
    return bound_diagnostic(_runner_failure_feedback(result), limit=500)


def _attempt_error_log_snippet(result: SandboxRunResult) -> str | None:
    """Keep diagnostics but never persist a rejected machine-result line."""
    error_log = result.error_log or ""
    if not result.success:
        error_log = _strip_child_result_lines(error_log)
        return bound_diagnostic(error_log, limit=500) or None
    return error_log[:500] or None


def _runner_failure_error_feedback(result: SandboxRunResult) -> str:
    """Expose runtime errors only when no rejected success claim accompanied them."""
    if result.rejected_observation is not None:
        return ""
    return _strip_child_result_lines(result.error_log)


def _consume_php_include_live_observation(
    result: SandboxRunResult,
    *,
    php_include_expected: bool,
) -> PoCObservation | None:
    """Take the raw verifier observation and leave only persistence-safe fields."""
    if not php_include_expected:
        return result.observation
    trusted_observation = result.take_trusted_php_include_observation()
    live_observation = trusted_observation or result.observation
    private_marker = php_include_private_marker_from_observation(live_observation)
    redact_php_include_run_result(result, private_marker)
    return live_observation


_PHP_OBJECT_OBSERVATION_FIELDS = frozenset(
    {
        "observed",
        "instantiated",
        "effect",
        "attacker_user_id",
        "identity_verified",
        "request_fingerprint",
    }
)
_PHP_OBJECT_FINGERPRINT_FIELDS = frozenset(
    {"method", "route", "object_field", "object_location", "dispatch"}
)


def _bounded_php_object_observation(
    observation: PoCObservation | None,
) -> tuple[bool, str]:
    """Restrict the trusted canary to its measured object-lifecycle claim."""
    if observation is None or observation.oracle != "object_instantiation":
        return False, "trusted PHP object run lacks object_instantiation evidence"
    if (
        observation.impact.confidentiality != "none"
        or observation.impact.integrity != "low"
        or observation.impact.availability != "none"
        or observation.impact.description != PHP_OBJECT_INERT_IMPACT_DESCRIPTION
    ):
        return False, "trusted PHP object run exceeded the inert-canary impact bound"
    if set(observation.request) != {"method", "url"}:
        return False, "trusted PHP object request contains unsupported claims"
    if (
        set(observation.attack) != _PHP_OBJECT_OBSERVATION_FIELDS
        or set(observation.control) != _PHP_OBJECT_OBSERVATION_FIELDS
    ):
        return False, "trusted PHP object arms contain unsupported claims"
    if (
        observation.attack.get("observed") is not True
        or observation.control.get("observed") is not False
        or observation.attack.get("instantiated") is not True
        or observation.control.get("instantiated") is not False
        or observation.attack.get("effect") != "verifier_inert_canary_wakeup"
        or observation.control.get("effect") != "verifier_inert_canary_wakeup"
        or observation.attack.get("identity_verified") is not True
        or observation.control.get("identity_verified") is not True
        or observation.attack.get("attacker_user_id")
        != observation.control.get("attacker_user_id")
    ):
        return False, "trusted PHP object attack/control declaration is invalid"
    attack_fingerprint = observation.attack.get("request_fingerprint")
    control_fingerprint = observation.control.get("request_fingerprint")
    if (
        not isinstance(attack_fingerprint, dict)
        or not isinstance(control_fingerprint, dict)
        or set(attack_fingerprint) != _PHP_OBJECT_FINGERPRINT_FIELDS
        or set(control_fingerprint) != _PHP_OBJECT_FINGERPRINT_FIELDS
        or attack_fingerprint != control_fingerprint
    ):
        return False, "trusted PHP object request fingerprints are invalid"
    return True, "trusted PHP object claim is bounded to inert canary instantiation"


def _consume_php_object_snapshot(
    result: SandboxRunResult,
    *,
    php_object_expected: bool,
) -> PhpObjectOracleSnapshot | None:
    """Take parent-private object evidence without copying it into persistence."""
    if not php_object_expected:
        return None
    return result.take_trusted_php_object_snapshot()


def _validate_php_object_confirmation_snapshots(
    first: PhpObjectOracleSnapshot | None,
    confirmation: PhpObjectOracleSnapshot | None,
) -> tuple[bool, str]:
    """Bind two successful runs to stable tokens and fresh private generations."""
    if first is None or confirmation is None:
        return False, "clean replay lacks parent-attested PHP object evidence"
    first_execution = first.execution
    confirmation_execution = confirmation.execution
    if (
        first.schema_version != 1
        or confirmation.schema_version != 1
        or first.mode != "php_object"
        or confirmation.mode != "php_object"
        or first.generation_id_sha256 != first_execution.generation_id_sha256
        or confirmation.generation_id_sha256
        != confirmation_execution.generation_id_sha256
        or not first_execution.attack_receipt_matched
        or not confirmation_execution.attack_receipt_matched
        or not first_execution.control_receipt_absent
        or not confirmation_execution.control_receipt_absent
    ):
        return False, "clean replay contains an invalid PHP object attestation"
    stable_fields = (
        "class_name_sha256",
        "callsite_path_sha256",
        "callsite_start_line",
        "callsite_end_line",
        "callsite_source_sha256",
        "backtrace_limit",
        "canary_class_source_sha256",
        "canary_class_source_size_bytes",
        "attack_token_sha256",
        "control_token_sha256",
        "attack_payload_size_bytes",
        "control_payload_size_bytes",
    )
    if any(
        getattr(first_execution, field) != getattr(confirmation_execution, field)
        for field in stable_fields
    ):
        return False, "clean replay changed its canary identity or authored arm tokens"
    rotating_pairs = (
        (first.generation_id_sha256, confirmation.generation_id_sha256),
        (first_execution.proof_sha256, confirmation_execution.proof_sha256),
        (
            first_execution.attack_payload_sha256,
            confirmation_execution.attack_payload_sha256,
        ),
        (
            first_execution.control_payload_sha256,
            confirmation_execution.control_payload_sha256,
        ),
        (
            first_execution.expected_receipt_sha256,
            confirmation_execution.expected_receipt_sha256,
        ),
    )
    if any(left == right for left, right in rotating_pairs):
        return False, "clean replay reused private PHP object generation material"
    if (
        confirmation_execution.execution_started_monotonic_ns
        < first_execution.attested_monotonic_ns
    ):
        return False, "clean replay PHP object attestations are out of order"
    return True, "clean replay used stable arm tokens and fresh private object material"


def _php_object_natural_observation(
    snapshot: PhpObjectGadgetOracleSnapshot,
    *,
    attacker_role: str,
    target_url: str,
    transport: dict[str, object],
) -> PoCObservation:
    """Render one bounded parent-attested natural-gadget measurement."""
    if (
        snapshot.schema_version != PHP_OBJECT_GADGET_ORACLE_SCHEMA_VERSION
        or snapshot.mode != PHP_OBJECT_GADGET_ORACLE_MODE
        or snapshot.effect != "file_delete"
        or snapshot.effect_binding_kind != "direct_path"
        or snapshot.effect_attestation.attack_deleted_exact_target is not True
        or snapshot.effect_attestation.control_preserved_exact_target is not True
        or snapshot.effect_attestation.collateral_paths_unchanged is not True
    ):
        raise ValueError("invalid PHP object natural-gadget snapshot")
    method = transport.get("method")
    route = transport.get("route")
    if (
        not isinstance(method, str)
        or not method
        or not isinstance(route, str)
        or not route.startswith("/")
    ):
        raise ValueError("invalid PHP object natural-gadget transport")
    return PoCObservation(
        verdict="vulnerable",
        oracle="file_effect",
        attacker_role=attacker_role,
        request={
            "method": method,
            "url": target_url.rstrip("/") + route,
            "transport_contract_sha256": (
                snapshot.transport_attestation.transport_contract_sha256
            ),
        },
        attack={
            "observed": True,
            "effect": "verifier_owned_temporary_file_deleted",
            "target_path_sha256": snapshot.target_path_sha256,
            "target_content_sha256": snapshot.target_content_sha256,
            "source_recipe_sha256": snapshot.runtime_binding.recipe_sha256,
            "collateral_paths_unchanged": True,
        },
        control={
            "observed": False,
            "effect": "verifier_owned_temporary_file_deleted",
            "target_path_sha256": snapshot.target_path_sha256,
            "target_content_sha256": snapshot.target_content_sha256,
            "source_recipe_sha256": snapshot.runtime_binding.recipe_sha256,
            "target_preserved": True,
        },
        impact=CIAImpact(
            confidentiality="none",
            integrity="low",
            availability="none",
            description=PHP_OBJECT_NATURAL_IMPACT_DESCRIPTION,
        ),
    )


def _php_object_natural_confirmation_payload(
    hypothesis: Hypothesis,
    first: PhpObjectGadgetOracleSnapshot,
    confirmation: PhpObjectGadgetOracleSnapshot,
) -> dict[str, object]:
    """Build the persistence-safe promotion record for two natural executions."""
    if (
        first.effect_binding_kind != "direct_path"
        or confirmation.effect_binding_kind != "direct_path"
    ):
        raise ValueError(
            "only a direct-path natural gadget can promote a full CWE-502 finding"
        )
    accepted, reason = validate_php_object_gadget_snapshot_pair(first, confirmation)
    if not accepted:
        raise ValueError(reason)
    return {
        "schema_version": PHP_OBJECT_GADGET_ORACLE_SCHEMA_VERSION,
        "status": "confirmed",
        "proof_kind": "php_object_natural",
        "hypothesis_id": hypothesis.id,
        "bug_class": hypothesis.bug_class.value,
        "effect": "file_delete",
        "clean_state_executions": 2,
        "finding_promoted": True,
        "promotion_policy": "source_bound_natural_gadget_v1",
        "first_execution": first.as_dict(),
        "confirmation_execution": confirmation.as_dict(),
    }


@dataclass(frozen=True, slots=True)
class _PhpObjectNaturalReplay:
    first_result: SandboxRunResult
    first_snapshot: PhpObjectGadgetOracleSnapshot | None
    confirmation_result: SandboxRunResult | None
    confirmation_snapshot: PhpObjectGadgetOracleSnapshot | None
    confirmed: bool
    reason: str


def _attach_php_object_natural_observation(
    result: SandboxRunResult,
    snapshot: PhpObjectGadgetOracleSnapshot,
    *,
    attacker_role: str,
    target_url: str,
    transport: dict[str, object],
) -> None:
    """Attach only a parent-derived observation to one successful run result."""
    if not result.success or result.observation is not None:
        raise ValueError(
            "natural PHP object evidence requires a successful observation-free run"
        )
    _discard_ignored_php_object_child_report(result)
    observation = _php_object_natural_observation(
        snapshot,
        attacker_role=attacker_role,
        target_url=target_url,
        transport=transport,
    )
    result.observation = observation
    result.evidence["observation"] = observation.model_dump(mode="json")
    result.evidence["observation_disposition"] = "accepted_parent_attestation"


def _discard_ignored_php_object_child_report(result: SandboxRunResult) -> None:
    """Remove the reused inert template's stdout from natural-proof surfaces."""
    if not result.success:
        return
    result.output = ""
    result.response = None
    result.error_log = _strip_child_result_lines(result.error_log) or None
    if "stdout_tail" in result.evidence:
        result.evidence["stdout_tail"] = ""


def _php_object_natural_attempt(
    result: SandboxRunResult,
    *,
    iteration: int,
    phase: Literal["attack", "confirmation"],
    script_path: Path,
) -> PoCAttempt:
    """Convert one natural-gadget runner result into a bounded audit attempt."""
    _discard_ignored_php_object_child_report(result)
    return PoCAttempt(
        iteration=iteration,
        phase=phase,
        proof_kind="php_object_natural",
        script_path=str(script_path),
        result=PoCStatus.SUCCESS if result.success else PoCStatus.FAILED,
        http_status=result.http_status,
        response_snippet=_attempt_response_snippet(result),
        timing_seconds=result.elapsed,
        error_log_snippet=_attempt_error_log_snippet(result),
        observation=result.observation,
        rejected_observation=result.rejected_observation,
        validation_reason=(
            result.validation_reason
            or ((result.error_log or "")[:1000] if not result.success else "")
            or (
                "natural PHP object execution failed"
                if not result.success
                else None
            )
        ),
    )


async def _run_php_object_natural_replay(
    sb: SandboxManager,
    *,
    script_path: Path,
    recipe: PhpObjectGadgetRecipe,
    expected_bug_class: str,
    attacker_role: str,
    transport: dict[str, object],
    pre_attempt_snapshot: Path,
    restore_attempt_state: Callable[[Path], Awaitable[None]],
) -> _PhpObjectNaturalReplay:
    """Execute one source-bound gadget twice from the same clean outer state."""
    if recipe.effect_binding.kind != "direct_path":
        raise ValueError(
            "only direct-path PHP object recipes qualify for natural promotion"
        )

    first: SandboxRunResult | None = None
    first_snapshot: PhpObjectGadgetOracleSnapshot | None = None
    confirmation: SandboxRunResult | None = None
    confirmation_snapshot: PhpObjectGadgetOracleSnapshot | None = None
    await restore_attempt_state(pre_attempt_snapshot)
    try:
        await sb.prepare_php_object_gadget_oracle(recipe)
        first = await sb.run_poc(
            str(script_path),
            expected_bug_class=expected_bug_class,
            expected_attacker_role=attacker_role,
            expected_http_transport=transport,
            expected_php_object_gadget=True,
            expected_php_object_transport=transport,
        )
        first_snapshot = first.take_trusted_php_object_gadget_snapshot()
        if first.success:
            if first_snapshot is None:
                first.reject(
                    "trusted natural PHP object run lacks parent attestation"
                )
            else:
                _attach_php_object_natural_observation(
                    first,
                    first_snapshot,
                    attacker_role=attacker_role,
                    target_url=sb.target_url,
                    transport=transport,
                )
        if not first.success:
            return _PhpObjectNaturalReplay(
                first_result=first,
                first_snapshot=first_snapshot,
                confirmation_result=None,
                confirmation_snapshot=None,
                confirmed=False,
                reason=(
                    first.validation_reason
                    or "natural PHP object file effect did not reproduce"
                ),
            )

        await restore_attempt_state(pre_attempt_snapshot)
        confirmation = await sb.run_poc(
            str(script_path),
            expected_bug_class=expected_bug_class,
            expected_attacker_role=attacker_role,
            expected_http_transport=transport,
            expected_php_object_gadget=True,
            expected_php_object_transport=transport,
        )
        confirmation_snapshot = (
            confirmation.take_trusted_php_object_gadget_snapshot()
        )
        if confirmation.success:
            if confirmation_snapshot is None:
                confirmation.reject(
                    "trusted natural PHP object replay lacks parent attestation"
                )
            else:
                _attach_php_object_natural_observation(
                    confirmation,
                    confirmation_snapshot,
                    attacker_role=attacker_role,
                    target_url=sb.target_url,
                    transport=transport,
                )
        if not confirmation.success:
            return _PhpObjectNaturalReplay(
                first_result=first,
                first_snapshot=first_snapshot,
                confirmation_result=confirmation,
                confirmation_snapshot=confirmation_snapshot,
                confirmed=False,
                reason=(
                    confirmation.validation_reason
                    or "clean-state natural PHP object replay did not reproduce"
                ),
            )

        matching, reason = validate_php_object_gadget_snapshot_pair(
            first_snapshot,
            confirmation_snapshot,
        )
        if not matching:
            confirmation.reject(reason)
            return _PhpObjectNaturalReplay(
                first_result=first,
                first_snapshot=first_snapshot,
                confirmation_result=confirmation,
                confirmation_snapshot=confirmation_snapshot,
                confirmed=False,
                reason=reason,
            )
        return _PhpObjectNaturalReplay(
            first_result=first,
            first_snapshot=first_snapshot,
            confirmation_result=confirmation,
            confirmation_snapshot=confirmation_snapshot,
            confirmed=True,
            reason="two clean parent-attested direct-path gadget runs matched",
        )
    finally:
        await restore_attempt_state(pre_attempt_snapshot)


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

_WP_USER_SESSION_CLI_MUTATION_RE = re.compile(
    r"\buser\b.{0,1000}\bsession\b.{0,1000}\b(?:destroy|destroy-all)\b",
    re.IGNORECASE | re.DOTALL,
)

_PHP_AUTH_SESSION_MUTATION_RE = re.compile(
    r"\b(?:wp_generate_auth_cookie|wp_set_auth_cookie|wp_clear_auth_cookie|"
    r"wp_destroy_current_session|wp_destroy_other_sessions|"
    r"wp_destroy_all_sessions|wp_signon|wp_logout)\b",
    re.IGNORECASE,
)

_PHP_SESSION_TOKENS_CLASS_RE = re.compile(
    r"\bWP_(?:User_Meta_)?Session_Tokens\b",
    re.IGNORECASE,
)

_PHP_SESSION_TOKEN_MUTATOR_RE = re.compile(
    r"(?:(?:->|::)\s*|['\"])(?:create|update|destroy|destroy_others|"
    r"destroy_all|destroy_all_for_all_users)(?:\s*\(|['\"])",
    re.IGNORECASE,
)

_SESSION_TOKEN_STORAGE_KEY_RE = re.compile(
    r"(?<![A-Za-z0-9_])session_tokens(?![A-Za-z0-9_])",
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

_CANONICAL_URL_OPTION_KEYS = frozenset({"home", "siteurl"})
_CANONICAL_URL_CONFIG_KEYS = frozenset({"wp_home", "wp_siteurl"})

_PHP_CANONICAL_URL_OPTION_MUTATION_RE = re.compile(
    r"(?<![A-Za-z0-9_>:\\])\\?(?:add|update|delete)_option\s*\(\s*"
    r"['\"](?:home|siteurl)['\"]\s*(?:,|\))|"
    r"\bcall_user_func\s*\(\s*['\"](?:add|update|delete)_option['\"]\s*,\s*"
    r"['\"](?:home|siteurl)['\"]|"
    r"\bcall_user_func_array\s*\(\s*"
    r"['\"](?:add|update|delete)_option['\"]\s*,\s*"
    r"(?:array\s*\(\s*|\[\s*)['\"](?:home|siteurl)['\"]",
    re.IGNORECASE,
)

_EMBEDDED_WP_CLI_CANONICAL_URL_MUTATION_RE = re.compile(
    r"\bWP_CLI\s*::\s*runcommand\s*\(\s*['\"]\s*"
    r"(?!site\s+option\b)option\s+(?:(?:add|update|delete)\s+|patch\s+"
    r"(?:add|update|delete|insert)\s+)(?:home|siteurl)(?:\s|['\"]|$)",
    re.IGNORECASE,
)

_EMBEDDED_WP_CLI_CANONICAL_URL_CONFIG_MUTATION_RE = re.compile(
    r"\bWP_CLI\s*::\s*runcommand\s*\(\s*['\"]\s*config\s+"
    r"(?:set|delete)\s+(?:wp_home|wp_siteurl)(?:\s|['\"]|$)",
    re.IGNORECASE,
)

_WP_CONFIG_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])wp-config\.php\b",
    re.IGNORECASE,
)
_PHP_WP_CONFIG_DELETE_RE = re.compile(r"\b(?:unlink|rmdir)\s*\(", re.IGNORECASE)

_RAW_CANONICAL_URL_OPTION_ROW_RE = re.compile(
    r"(?:['\"]option_name['\"]\s*=>|\boption_name\b\s*=)\s*"
    r"['\"](?:home|siteurl)['\"]",
    re.IGNORECASE,
)

_WORDPRESS_OPTIONS_TABLE_RE = re.compile(
    r"\$wpdb\s*->\s*options\b|(?<![A-Za-z0-9_])`?wp_options`?(?![A-Za-z0-9_])",
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


def _setup_command_mutates_canonical_url(args: list[str]) -> bool:
    """Recognise writes to WordPress's runner-owned public URL options."""
    lowered = [str(token).casefold() for token in args]
    for option_index, token in enumerate(lowered):
        if token != "option" or (
            option_index > 0 and lowered[option_index - 1] == "site"
        ):
            continue
        positionals = [
            value for value in lowered[option_index + 1 :] if not value.startswith("-")
        ]
        if not positionals:
            continue
        action = positionals[0]
        if action in {"add", "update"} and len(positionals) >= 2:
            if positionals[1] in _CANONICAL_URL_OPTION_KEYS:
                return True
        elif action == "delete" and any(
            value in _CANONICAL_URL_OPTION_KEYS for value in positionals[1:]
        ):
            return True
        elif (
            action == "patch"
            and len(positionals) >= 3
            and positionals[1] in {"add", "update", "delete", "insert"}
            and positionals[2] in _CANONICAL_URL_OPTION_KEYS
        ):
            return True

    for config_index, token in enumerate(lowered):
        if token != "config":
            continue
        positionals = [
            value for value in lowered[config_index + 1 :] if not value.startswith("-")
        ]
        if (
            len(positionals) >= 2
            and positionals[0] in {"set", "delete"}
            and positionals[1] in _CANONICAL_URL_CONFIG_KEYS
        ):
            return True

    command = " ".join(args)
    if _PHP_CANONICAL_URL_OPTION_MUTATION_RE.search(command):
        return True
    if _EMBEDDED_WP_CLI_CANONICAL_URL_MUTATION_RE.search(command):
        return True
    if _EMBEDDED_WP_CLI_CANONICAL_URL_CONFIG_MUTATION_RE.search(command):
        return True
    if _WP_CONFIG_PATH_RE.search(command) and (
        _PHP_DIRECT_FILE_WRITE_RE.search(command)
        or _PHP_WP_CONFIG_DELETE_RE.search(command)
    ):
        return True
    return bool(
        _DIRECT_STORAGE_WRITE_RE.search(command)
        and _WORDPRESS_OPTIONS_TABLE_RE.search(command)
        and _RAW_CANONICAL_URL_OPTION_ROW_RE.search(command)
    )


def _setup_command_mutates_managed_context(args: list[str]) -> str | None:
    """Reject identity overrides and plugin lifecycle changes owned by the sandbox."""
    if _setup_command_mutates_canonical_url(args):
        return "setup command mutates WordPress home/siteurl managed by the sandbox"

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
    if _WP_USER_SESSION_CLI_MUTATION_RE.search(command):
        return "setup command mutates a managed user's authentication sessions"
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
    if _PHP_AUTH_SESSION_MUTATION_RE.search(command):
        return "setup command creates or mutates authentication cookies or sessions"
    if _PHP_SESSION_TOKENS_CLASS_RE.search(
        command
    ) and _PHP_SESSION_TOKEN_MUTATOR_RE.search(command):
        return "setup command mutates WordPress session-token credentials"
    if _APPLICATION_PASSWORD_STORAGE_KEY_RE.search(
        command
    ) and _setup_command_is_raw_state_write(args):
        return "setup command writes application-password credential storage directly"
    if _SESSION_TOKEN_STORAGE_KEY_RE.search(
        command
    ) and _setup_command_is_raw_state_write(args):
        return "setup command writes session-token credential storage directly"
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


_SETUP_SENSITIVE_KEY_RE = re.compile(
    r"(?:password|passwd|secret|token|nonce|cookie|session|authorization|"
    r"api[_-]?key|private[_-]?key|hash|receipt|proof)",
    re.IGNORECASE,
)
_SETUP_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)\b([a-z0-9_-]*(?:password|passwd|secret|token|nonce|cookie|session|"
    r"authorization|api[_-]?key|private[_-]?key|hash|receipt|proof)[a-z0-9_-]*)"
    r"(\s*(?:=|:)\s*|\s+)([^\s,;&|]+)"
)
_SETUP_SENSITIVE_HEADER_RE = re.compile(
    r"(?i)\b(authorization|proxy-authorization|cookie|set-cookie)\s*:\s*[^|]+"
)


def _redact_setup_output_value(value: object, *, key: str = "") -> object:
    """Retain setup evidence while withholding credentials and nonce material."""
    if key and _SETUP_SENSITIVE_KEY_RE.search(key):
        if isinstance(value, bool):
            return value
        if (
            isinstance(value, int)
            and not isinstance(value, bool)
            and re.search(r"(?:count|length|size)$", key, re.IGNORECASE)
        ):
            return value
        if value is None or value is False or value == "" or value == [] or value == {}:
            return "<redacted:absent>"
        return "<redacted:present>"
    if isinstance(value, dict):
        return {
            str(child_key): _redact_setup_output_value(
                child_value, key=str(child_key)
            )
            for child_key, child_value in value.items()
        }
    if isinstance(value, list):
        return [_redact_setup_output_value(item) for item in value[:20]]
    if isinstance(value, str):
        return _redact_setup_output_text(value)
    return value


def _redact_setup_output_text(value: str) -> str:
    """Best-effort redaction for non-JSON diagnostics before model exposure."""
    without_headers = _SETUP_SENSITIVE_HEADER_RE.sub(
        lambda match: f"{match.group(1)}: <redacted>", value
    )
    return _SETUP_SENSITIVE_ASSIGNMENT_RE.sub(
        lambda match: f"{match.group(1)}{match.group(2)}<redacted>",
        without_headers,
    )


def _bounded_setup_output(raw: object, *, limit: int = 500) -> str:
    """Prefer one structured result and keep setup feedback predictably bounded."""
    text = str(raw or "").strip()
    if not text:
        return ""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    for line in reversed(lines):
        try:
            parsed = json.loads(line)
        except (TypeError, ValueError):
            continue
        if isinstance(parsed, (dict, list)):
            redacted = _redact_setup_output_value(parsed)
            rendered = json.dumps(
                redacted,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            return rendered[:limit] + ("..." if len(rendered) > limit else "")
        if parsed is None or isinstance(parsed, (str, int, float, bool)):
            return "<non-object structured output omitted>"
    rendered = _redact_setup_output_text(" ".join(lines))
    return rendered[:limit] + ("..." if len(rendered) > limit else "")


def _bounded_setup_diagnostic(raw: object, *, limit: int = 360) -> str:
    """Surface stable errors before noisy bootstrap warnings, without secrets."""
    text = str(raw or "").strip()
    if not text:
        return ""
    lines = [" ".join(line.split()) for line in text.splitlines() if line.strip()]
    priority = [
        line
        for line in lines
        if line.startswith("Error:") or "setup postcondition failed" in line.lower()
    ]
    selected = priority or lines
    rendered = _redact_setup_output_text(" | ".join(selected[:3]))
    return rendered[:limit] + ("..." if len(rendered) > limit else "")


def _summarise_setup_command(args: object) -> str:
    """Return a bounded, non-secret command identity for prompt diagnostics."""
    if not isinstance(args, list) or not args:
        return "wp <command unavailable>"
    values = [str(arg) for arg in args]
    digest = hashlib.sha256(
        "\0".join(values).encode("utf-8", errors="replace")
    ).hexdigest()[:12]
    verb = " ".join(values[0].split())[:48] or "<empty verb>"
    if verb == "eval":
        php_chars = len(values[1]) if len(values) > 1 else 0
        return f"wp eval <PHP omitted; chars={php_chars}; sha256={digest}>"
    subcommand = ""
    if len(values) > 1:
        subcommand = " " + " ".join(values[1].split())[:48]
    omitted = max(len(values) - 2, 0)
    suffix = f" <{omitted} args omitted; sha256={digest}>" if omitted else ""
    return f"wp {verb}{subcommand}{suffix}"


def _summarise_setup_results(results: list[dict]) -> str:
    """Summarise results with outcome/evidence before bounded command identity."""
    lines: list[str] = []
    for index, item in enumerate(results, start=1):
        blocked = item.get("blocked_before_execution") is True
        rolled_back = item.get("setup_round_rolled_back") is True
        if rolled_back and blocked:
            status = "BLOCKED BEFORE EXECUTION — SETUP ROUND ROLLED BACK"
        elif rolled_back and item.get("failed"):
            status = "FAILED AFTER EXECUTION — ENTIRE SETUP ROUND ROLLED BACK"
        elif rolled_back:
            status = "NOT COMMITTED — SETUP ROUND ROLLED BACK"
        elif blocked:
            status = "BLOCKED BEFORE EXECUTION"
        elif item.get("failed") and item.get("executed", True) is not False:
            status = "FAILED AFTER EXECUTION — STATE MAY BE PARTIAL"
        elif item.get("failed"):
            status = "FAILED"
        elif item.get("advisory_bootstrap_warning"):
            status = (
                "OK WITH WARNINGS — COMMITTED / RETAINED"
                if item.get("setup_state_committed") is True
                else "OK WITH WARNINGS"
            )
        else:
            status = (
                "OK — COMMITTED / RETAINED"
                if item.get("setup_state_committed") is True
                else "OK"
            )
        output = _bounded_setup_output(item.get("output"))
        diagnostic = _bounded_setup_diagnostic(item.get("stderr"))
        lines.append(f"[{index}] {status}")
        if output:
            lines.append(f"  verified output: {output}")
        if diagnostic:
            label = "diagnostic" if item.get("failed") else "advisory"
            lines.append(f"  {label}: {diagnostic}")
        if blocked:
            lines.append(
                "  runner note: No part of this command ran. Submit a new command "
                "containing only permitted prerequisite operations."
            )
        lines.append(f"  command: {_summarise_setup_command(item.get('args'))}")
    return "\n".join(lines)


def _summarise_setup_state(
    results: list[dict],
    *,
    latest_round_results: list[dict] | None = None,
) -> str:
    """Describe retained setup separately from one transactional repair attempt."""
    if not results and not latest_round_results:
        return "(no setup commands were executed)"
    committed = [
        item for item in results if item.get("setup_state_committed") is True
    ]
    latest = list(latest_round_results or (results[-1:] if results else []))
    lines = [
        "RETAINED COMMITTED SETUP STATE "
        "(authoritative current baseline; results ordered oldest to newest):"
    ]
    if committed:
        lines.append(_summarise_setup_results(committed))
        lines.append(
            "For overlapping fields, treat a newer self-verified result as canonical. "
            "Preserve these established objects and repair them incrementally."
        )
    else:
        lines.append("(none established)")

    lines.append("LATEST SETUP ROUND (authoritative transactional outcome):")
    lines.append(_summarise_setup_results(latest) if latest else "(none)")
    lines.append(
        "FAILED or partial commands are not evidence that their attempted state "
        "exists."
    )
    if any(item.get("setup_round_rolled_back") is True for item in latest):
        lines.append(
            "STATE TRANSITION: Only the latest failed setup round shown above was "
            "rolled back. Its attempted mutations do not exist. Earlier committed "
            "setup state remains present; inspect and repair that retained state "
            "instead of recreating it."
        )
    elif latest and all(
        item.get("blocked_before_execution") is True for item in latest
    ):
        lines.append(
            "STATE TRANSITION: The latest round made no change. Earlier committed "
            "setup state remains present."
        )
    elif latest and all(
        item.get("setup_state_committed") is True for item in latest
    ):
        lines.append(
            "STATE TRANSITION: The latest round committed and is included in the "
            "retained baseline above."
        )
    rolled_back_count = sum(
        item.get("setup_round_rolled_back") is True for item in results
    )
    blocked_count = sum(
        item.get("blocked_before_execution") is True for item in results
    )
    lines.append(
        "CUMULATIVE HISTORY COUNTS: "
        f"committed={len(committed)}, rolled_back={rolled_back_count}, "
        f"blocked_before_execution={blocked_count}."
    )
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
            return frozenset(str(path) for path in value)
        if isinstance(value, (list, tuple, set, frozenset)):
            return frozenset(str(path) for path in value)
        return frozenset()

    if _normalised_paths(before.get("active_plugins")) != _normalised_paths(
        after.get("active_plugins")
    ) or _normalised_paths(before.get("active_sitewide_plugins")) != _normalised_paths(
        after.get("active_sitewide_plugins")
    ):
        return "generated setup changed managed plugin activation state"

    if before.get("canonical_urls") != after.get("canonical_urls"):
        return "generated setup changed WordPress home/siteurl"

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


def _setup_http_context_for_sandbox(sb: SandboxManager) -> SetupHttpContext:
    """Read the typed setup-only HTTP contract from a live sandbox."""
    context_factory = getattr(sb, "setup_http_context", None)
    if not callable(context_factory):
        raise RuntimeError("sandbox does not expose a setup HTTP context")
    context = context_factory()
    if not isinstance(context, SetupHttpContext):
        raise RuntimeError("sandbox returned an invalid setup HTTP context")
    return context


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

        if before_state is not None and callable(state_reader):
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


async def _run_setup_round_atomically(
    sb: SandboxManager,
    commands: list[list[str]],
    *,
    hypothesis: Hypothesis | None = None,
    plugin_slug: str | None = None,
) -> list[dict]:
    """Run one generated setup round and roll back every partial failure.

    A developer round can contain several commands, and a single ``wp eval`` may
    mutate state before its final postcondition fails. The pre-round snapshot makes
    the whole proposal transactional from the verifier's perspective.
    """
    if not commands:
        return []
    snapshot = await sb.snapshot()
    retain_snapshot_for_recovery = True

    async def _rollback() -> None:
        await sb.restore(snapshot)
        restart_runtime = getattr(sb, "restart_wordpress_runtime", None)
        if callable(restart_runtime):
            await restart_runtime()

    try:
        try:
            results = await _run_setup_commands(
                sb,
                commands,
                hypothesis=hypothesis,
                plugin_slug=plugin_slug,
            )
        except BaseException:
            await _rollback()
            retain_snapshot_for_recovery = False
            raise
        failed = any(item.get("failed") for item in results)
        any_executed = any(
            item.get("executed", True) is not False for item in results
        )
        rolled_back = failed and any_executed
        if rolled_back:
            await _rollback()
        retain_snapshot_for_recovery = False
        for item in results:
            item["setup_round_rolled_back"] = rolled_back
            item["setup_state_committed"] = not failed
        return results
    finally:
        # A failed restore leaves this as the only recovery copy. Retain it for
        # sandbox-level recovery/teardown instead of deleting evidence and state.
        if not retain_snapshot_for_recovery:
            shutil.rmtree(snapshot, ignore_errors=True)


_POC_CODE_FAILURE_MARKERS = (
    "Traceback (most recent call last)",
    "JSONDecodeError",
    "KeyError",
    "IndexError",
    "AttributeError",
)


def _poc_failure_looks_like_code_error(result: SandboxRunResult) -> bool:
    """Return whether trusted stderr shows the PoC itself crashed."""
    stderr = result.error_log or ""
    return any(marker in stderr for marker in _POC_CODE_FAILURE_MARKERS)


def _should_replay_poc_after_setup(
    result: SandboxRunResult,
    followup: SetupPlan | None,
    rounds: list[tuple[SetupPlan, list[dict]]],
    *,
    replaying_setup_repair: bool,
) -> bool:
    """Allow one exact replay only after a cleanly committed setup repair."""
    if (
        replaying_setup_repair
        or followup is None
        or followup.failure_class != "setup"
        or not followup.commands
        or not rounds
        or rounds[-1][0] is not followup
        or _poc_failure_looks_like_code_error(result)
    ):
        return False

    final_results = rounds[-1][1]
    reusable_oracle_state = (
        result.evidence.get("ssrf_oracle_error") in (None, "")
        and result.evidence.get("php_include_oracle_error") in (None, "")
        and result.evidence.get("php_include_oracle_cleanup_error") in (None, "")
        and result.evidence.get("php_object_oracle_error")
        in (None, "", "transport_incomplete")
    )
    return bool(final_results) and reusable_oracle_state and all(
        item.get("failed") is False
        and item.get("executed") is True
        and item.get("setup_state_committed") is True
        and item.get("setup_round_rolled_back") is False
        and item.get("blocked_before_execution") is False
        and not _setup_result_taints_confirmation(item)
        for item in final_results
    )


_IMPACT_LEVEL_RANK = {"none": 0, "low": 1, "high": 2}


def _has_full_compromise_target(outcome: SecurityOutcome) -> bool:
    """Return whether source review explicitly claimed high impact in every dimension."""
    return all(
        getattr(outcome, dimension) == "high"
        for dimension in ("confidentiality", "integrity", "availability")
    )


def _full_compromise_gaps(impact: CIAImpact) -> dict[str, str]:
    """Describe measured dimensions that remain below an explicit full-compromise target."""
    return {
        dimension: getattr(impact, dimension)
        for dimension in ("confidentiality", "integrity", "availability")
        if getattr(impact, dimension) != "high"
    }


def _confirmed_impact_vector(attempt: PoCAttempt) -> tuple[int, int, int]:
    """Return a fixed CIA vector for stable component-wise comparison."""
    if attempt.observation is None:
        return (-1, -1, -1)
    impact = attempt.observation.impact
    return (
        _IMPACT_LEVEL_RANK[impact.confidentiality],
        _IMPACT_LEVEL_RANK[impact.integrity],
        _IMPACT_LEVEL_RANK[impact.availability],
    )


def _confirmed_impact_dominates(
    candidate: PoCAttempt,
    incumbent: PoCAttempt,
) -> bool:
    """Return whether a confirmation improves impact without losing a dimension."""
    candidate_ranks = _confirmed_impact_vector(candidate)
    incumbent_ranks = _confirmed_impact_vector(incumbent)
    return all(
        candidate_rank >= incumbent_rank
        for candidate_rank, incumbent_rank in zip(
            candidate_ranks,
            incumbent_ranks,
            strict=True,
        )
    ) and any(
        candidate_rank > incumbent_rank
        for candidate_rank, incumbent_rank in zip(
            candidate_ranks,
            incumbent_ranks,
            strict=True,
        )
    )


def _select_strongest_confirmation(
    confirmations: list[PoCAttempt],
) -> PoCAttempt:
    """Select only monotonic improvements, retaining the first incomparable proof."""
    if not confirmations:
        raise ValueError("at least one confirmation is required")
    selected = confirmations[0]
    for candidate in confirmations[1:]:
        if _confirmed_impact_dominates(candidate, selected):
            selected = candidate
    return selected


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
        selected: set[int] = set()
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


def _mask_php_document_non_code(source: str) -> str | None:
    """Mask non-code in one complete PHP document while preserving offsets.

    Unlike ``_mask_php_non_code``, this parser starts outside PHP and handles
    document-only lexical forms.  It is intentionally separate because many
    callers pass isolated PHP expressions without opening tags.  Unsupported
    short tags and unterminated lexical states fail closed.
    """
    masked = list(source)
    state = "inline_html"
    heredoc_label = ""
    index = 0

    def mask_range(start: int, end: int) -> None:
        for position in range(start, end):
            if source[position] != "\n":
                masked[position] = " "

    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""

        if state == "inline_html":
            standard_tag = source[index : index + 5]
            standard_boundary = source[index + 5 : index + 6]
            if standard_tag.casefold() == "<?php" and (
                not standard_boundary or standard_boundary.isspace()
            ):
                mask_range(index, index + 5)
                index += 5
                state = "code"
                continue
            if source.startswith("<?=", index):
                mask_range(index, index + 3)
                index += 3
                state = "code"
                continue
            if source.startswith("<?", index):
                return None
            if char != "\n":
                masked[index] = " "
            index += 1
            continue

        if state == "code":
            if source.startswith("?>", index):
                mask_range(index, index + 2)
                index += 2
                state = "inline_html"
                continue
            if source.startswith("<<<", index):
                line_end = source.find("\n", index)
                if line_end < 0:
                    return None
                opener = source[index:line_end]
                opener_match = re.fullmatch(
                    r"<<<[ \t]*(?:(?P<quote>['\"])(?P<quoted>"
                    r"[A-Za-z_][A-Za-z0-9_]*)(?P=quote)|"
                    r"(?P<bare>[A-Za-z_][A-Za-z0-9_]*))[ \t]*",
                    opener,
                )
                if opener_match is None:
                    return None
                heredoc_label = (
                    opener_match.group("quoted") or opener_match.group("bare")
                )
                mask_range(index, line_end)
                index = line_end
                state = "heredoc"
                continue
            if char == "'":
                masked[index] = " "
                state = "single"
            elif char == '"':
                masked[index] = " "
                state = "double"
            elif char == "`":
                masked[index] = " "
                state = "backtick"
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
            index += 1
            continue

        if state in {"single", "double", "backtick"}:
            if char != "\n":
                masked[index] = " "
            if char == "\\" and following:
                if following != "\n":
                    masked[index + 1] = " "
                index += 2
                continue
            if (
                (state == "single" and char == "'")
                or (state == "double" and char == '"')
                or (state == "backtick" and char == "`")
            ):
                state = "code"
            index += 1
            continue

        if state == "line_comment":
            # A PHP closing tag terminates a // or # comment as well as the
            # surrounding PHP section.
            if source.startswith("?>", index):
                mask_range(index, index + 2)
                index += 2
                state = "inline_html"
                continue
            if char == "\n":
                state = "code"
            else:
                masked[index] = " "
            index += 1
            continue

        if state == "block_comment":
            if char != "\n":
                masked[index] = " "
            if char == "*" and following == "/":
                masked[index + 1] = " "
                index += 2
                state = "code"
            else:
                index += 1
            continue

        if state == "heredoc":
            if index == 0 or source[index - 1] == "\n":
                line_end = source.find("\n", index)
                if line_end < 0:
                    line_end = len(source)
                cursor = index
                while cursor < line_end and source[cursor] in " \t":
                    cursor += 1
                if source.startswith(heredoc_label, cursor):
                    label_end = cursor + len(heredoc_label)
                    boundary = source[label_end : label_end + 1]
                    if not boundary or not re.match(r"[A-Za-z0-9_]", boundary):
                        tail = source[label_end:line_end].lstrip(" \t")
                        if not tail or tail[0] in ";,)]}":
                            mask_range(index, label_end)
                            index = label_end
                            heredoc_label = ""
                            state = "code"
                            continue
            if char != "\n":
                masked[index] = " "
            index += 1
            continue

        return None

    if state in {"single", "double", "backtick", "block_comment", "heredoc"}:
        return None
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


_PHP_INCLUDE_CONSTRUCT_RE = re.compile(
    r"\b(?:include|include_once|require|require_once)\b\s*(?:\(|\s)",
    re.IGNORECASE,
)
_PHP_INCLUDE_VARIABLE_RE = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*")
_PHP_REQUEST_REFERENCE_RE = re.compile(
    r"\$_(?P<source>GET|POST|REQUEST)\s*\[\s*"
    r"(?P<quote>['\"])(?P<name>[A-Za-z_][A-Za-z0-9_.:-]{0,127})(?P=quote)\s*\]",
    re.IGNORECASE,
)
_PHP_DESCRIBED_ENTRY_RE = re.compile(
    r"\A(?P<head>.+?)\s+with\s+(?P<fields>[^\r\n]+)\Z",
    re.IGNORECASE,
)
_PHP_DESCRIBED_FIELD_RE = re.compile(
    r"\A(?P<name>[A-Za-z_][A-Za-z0-9_.:-]{0,127})=(?P<value>[^&]+)\Z"
)
_PHP_WORDPRESS_HOOK_RE = re.compile(
    r"\A(?:wp_ajax_(?:nopriv_)?|admin_post_(?:nopriv_)?)"
    r"[A-Za-z_][A-Za-z0-9_.:-]{0,127}\Z"
)
_PHP_INCLUDE_MAX_FILES = 4096
_PHP_INCLUDE_MAX_TOTAL_SOURCE_BYTES = 64 * 1024 * 1024


def _has_variable_php_include_operand(source_quote: str) -> bool:
    """Require one request-shaped variable inside the actual include operand."""
    masked = _mask_php_non_code(source_quote)
    matches = list(_PHP_INCLUDE_CONSTRUCT_RE.finditer(masked))
    if len(matches) != 1:
        return False
    match = matches[0]
    if match.group(0).rstrip().endswith("("):
        closing_parenthesis = _matching_delimiter(
            masked,
            match.end() - 1,
            "(",
            ")",
        )
        if closing_parenthesis is None:
            return False
        operand = masked[match.end() : closing_parenthesis]
        return bool(operand.strip() and _PHP_INCLUDE_VARIABLE_RE.search(operand))

    round_depth = 0
    square_depth = 0
    brace_depth = 0
    end = len(masked)
    for index in range(match.end(), len(masked)):
        char = masked[index]
        if char == "(":
            round_depth += 1
        elif char == ")":
            if round_depth == 0:
                return False
            round_depth -= 1
        elif char == "[":
            square_depth += 1
        elif char == "]":
            if square_depth == 0:
                return False
            square_depth -= 1
        elif char == "{":
            brace_depth += 1
        elif char == "}":
            if brace_depth == 0:
                return False
            brace_depth -= 1
        elif char == ";" and not (round_depth or square_depth or brace_depth):
            end = index
            break
    operand = masked[match.end() : end]
    return bool(operand.strip() and _PHP_INCLUDE_VARIABLE_RE.search(operand))


def _is_source_grounded_php_include_hypothesis(
    hypothesis: Hypothesis,
    plugin_root: str | Path,
) -> bool:
    """Enable the trusted canary only for an exact dynamic PHP include sink."""
    if hypothesis.bug_class != BugClass.PATH_TRAVERSAL:
        return False
    source_file = _resolve_ssrf_source_file(plugin_root, hypothesis.file)
    if source_file is None or not hypothesis.sink_code.strip():
        return False
    try:
        lines = source_file.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return False
    quote_lines = hypothesis.sink_code.strip("\r\n").splitlines()
    start = hypothesis.line - 1
    if start < 0 or start + len(quote_lines) > len(lines):
        return False
    if [line.strip() for line in quote_lines] != [
        line.strip() for line in lines[start : start + len(quote_lines)]
    ]:
        return False
    return _has_variable_php_include_operand(hypothesis.sink_code)


def _bounded_php_include_sources(
    plugin_root: str | Path,
) -> list[tuple[str, str]] | None:
    """Read a bounded, symlink-confined PHP corpus for literal route facts."""
    try:
        root = Path(plugin_root).resolve(strict=True)
    except OSError:
        return None
    if not root.is_dir():
        return None
    paths = sorted(root.rglob("*.php"))
    if len(paths) > _PHP_INCLUDE_MAX_FILES:
        return None
    total = 0
    sources: list[tuple[str, str]] = []
    for path in paths:
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(root)
            size = resolved.stat().st_size
        except (OSError, ValueError):
            return None
        if not resolved.is_file() or size > _SSRF_MAX_SOURCE_BYTES:
            return None
        total += size
        if total > _PHP_INCLUDE_MAX_TOTAL_SOURCE_BYTES:
            return None
        try:
            source = resolved.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        sources.append((source, _mask_php_non_code(source)))
    return sources


def _php_include_source_facts(
    plugin_root: str | Path,
    entry_head: str,
    hypothesis: Hypothesis,
    plugin_slug: str | None,
) -> dict[str, frozenset[Literal["query", "form"]]] | None:
    """Collect scoped literal request keys for one source-backed entry point."""
    sources = _bounded_php_include_sources(plugin_root)
    if sources is None:
        return None
    head = entry_head.strip()
    allowed_functions: set[str] | None = None
    if _PHP_WORDPRESS_HOOK_RE.fullmatch(head):
        callback_names: set[str] = set()
        add_action = re.compile(r"\badd_action\s*\(", re.IGNORECASE)
        quoted_identifier = re.compile(
            r"\A\s*(?P<quote>['\"])(?P<value>[A-Za-z_][A-Za-z0-9_]*)"
            r"(?P=quote)\s*\Z"
        )
        quoted_hook = re.compile(
            r"\A\s*(?P<quote>['\"])" + re.escape(head) + r"(?P=quote)\s*\Z",
            re.IGNORECASE,
        )
        array_callback = re.compile(
            r"\A\s*(?:array\s*\(|\[).*?(?P<quote>['\"])"
            r"(?P<value>[A-Za-z_][A-Za-z0-9_]*)(?P=quote)\s*(?:\)|\])\s*\Z",
            re.IGNORECASE | re.DOTALL,
        )
        for source, masked in sources:
            for registration in add_action.finditer(masked):
                opening_parenthesis = registration.end() - 1
                closing_parenthesis = _matching_delimiter(
                    masked,
                    opening_parenthesis,
                    "(",
                    ")",
                    limit=min(
                        len(masked),
                        opening_parenthesis + _SSRF_MAX_CALL_CHARS,
                    ),
                )
                if closing_parenthesis is None:
                    continue
                arguments = _call_arguments(
                    source,
                    masked,
                    opening_parenthesis,
                    closing_parenthesis,
                )
                if arguments is None or len(arguments) < 2:
                    continue
                if quoted_hook.fullmatch(arguments[0]) is None:
                    continue
                direct = quoted_identifier.fullmatch(arguments[1])
                array_value = array_callback.fullmatch(arguments[1])
                if direct is not None:
                    callback_names.add(direct.group("value").casefold())
                elif array_value is not None:
                    callback_names.add(array_value.group("value").casefold())
                elif (
                    re.fullmatch(
                        r"\s*\$[A-Za-z_][A-Za-z0-9_]*\s*",
                        arguments[1],
                    )
                    and len(arguments) >= 3
                ):
                    loader_callback = quoted_identifier.fullmatch(arguments[2])
                    if loader_callback is not None:
                        callback_names.add(loader_callback.group("value").casefold())

        defined_functions = {
            match.group("name").casefold()
            for _source, masked in sources
            for match in _SSRF_NAMED_FUNCTION_RE.finditer(masked)
        }
        callback_names &= defined_functions
        if not callback_names:
            return None

        described = _PHP_DESCRIBED_ENTRY_RE.fullmatch(hypothesis.entry_point.strip())
        described_handlers: set[str] = set()
        if described:
            for raw_field in described.group("fields").split("&"):
                field = _PHP_DESCRIBED_FIELD_RE.fullmatch(raw_field.strip())
                if field is None:
                    continue
                value = field.group("value").strip()
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
                    described_handlers.add(value.casefold())
        allowed_functions = callback_names | (described_handlers & defined_functions)
    else:
        parsed = _parse_entry_point_transport(head)
        route = str(parsed.get("route") or "")
        try:
            root = Path(plugin_root).resolve(strict=True)
        except OSError:
            return None
        # Exact direct plugin files are source-grounded by their route. Other
        # callback/REST descriptions need a structured hook and fail closed.
        if plugin_slug is None:
            return None
        direct_prefix = f"/wp-content/plugins/{plugin_slug}/"
        if not route.startswith(direct_prefix):
            return None
        relative = route.removeprefix(direct_prefix)
        if _resolve_ssrf_source_file(root, relative) is None:
            return None

    facts: dict[str, set[Literal["query", "form"]]] = {}
    for source, masked in sources:
        for match in _PHP_REQUEST_REFERENCE_RE.finditer(source):
            if masked[match.start() : match.start() + 2] != "$_":
                continue
            if allowed_functions is not None:
                enclosing = _enclosing_named_php_function(
                    source,
                    masked,
                    match.start(),
                )
                if (
                    enclosing is not None
                    and enclosing[0].casefold() not in allowed_functions
                ):
                    continue
            request_source = match.group("source").upper()
            options: tuple[Literal["query", "form"], ...]
            if request_source == "GET":
                options = ("query",)
            elif request_source == "POST":
                options = ("form",)
            else:
                options = ("query", "form")
            facts.setdefault(match.group("name"), set()).update(options)
    return {name: frozenset(options) for name, options in facts.items()}


def _php_request_parameter_locations(
    hypothesis: Hypothesis,
    source_facts: dict[str, frozenset[Literal["query", "form"]]],
) -> dict[str, frozenset[Literal["query", "form"]]]:
    """Map explicitly described PHP request inputs to bounded HTTP locations."""
    evidence = hypothesis.evidence_summary or {}
    values = [
        *hypothesis.taint_path,
        hypothesis.reasoning,
        hypothesis.preconditions,
        *(str(value) for value in evidence.values() if isinstance(value, str)),
    ]
    locations: dict[str, set[Literal["query", "form"]]] = {}
    for value in values:
        for match in _PHP_REQUEST_REFERENCE_RE.finditer(value):
            source = match.group("source").upper()
            options: tuple[Literal["query", "form"], ...]
            if source == "GET":
                options = ("query",)
            elif source == "POST":
                options = ("form",)
            else:
                options = ("query", "form")
            locations.setdefault(match.group("name"), set()).update(options)
    return {
        name: frozenset(found & set(source_facts.get(name, frozenset())))
        for name, found in locations.items()
        if found & set(source_facts.get(name, frozenset()))
    }


def _php_include_destination_parameter(hypothesis: Hypothesis) -> str:
    """Prefer one explicit placeholder, then the request input nearest the sink."""
    described = _PHP_DESCRIBED_ENTRY_RE.fullmatch(hypothesis.entry_point.strip())
    if described:
        placeholders: list[str] = []
        for raw_field in described.group("fields").split("&"):
            field = _PHP_DESCRIBED_FIELD_RE.fullmatch(raw_field.strip())
            if field and re.fullmatch(r"<[^<>]{1,80}>", field.group("value").strip()):
                placeholders.append(field.group("name"))
        if len(placeholders) == 1:
            return placeholders[0]

    for step in reversed(hypothesis.taint_path):
        names = {
            match.group("name") for match in _PHP_REQUEST_REFERENCE_RE.finditer(step)
        }
        if len(names) == 1:
            return next(iter(names))
    return ""


def _expected_php_include_http_transport(
    hypothesis: Hypothesis,
    plugin_root: str | Path,
    plugin_slug: str | None = None,
) -> dict[str, object] | None:
    """Derive bounded request variants from the accepted source-backed claim."""
    if plugin_slug is not None:
        try:
            plugin_slug = validate_plugin_slug(plugin_slug)
        except ValueError:
            return None
    if not _is_source_grounded_php_include_hypothesis(hypothesis, plugin_root):
        return None
    destination = _php_include_destination_parameter(hypothesis)
    if not destination:
        return None

    described = _PHP_DESCRIBED_ENTRY_RE.fullmatch(hypothesis.entry_point.strip())
    head = described.group("head").strip() if described else hypothesis.entry_point
    base = dict(_parse_entry_point_transport(head))
    if not base.get("method") or not base.get("route"):
        return None
    dispatch = base.get("dispatch")
    if not isinstance(dispatch, dict):
        return None
    source_facts = _php_include_source_facts(
        plugin_root,
        head,
        hypothesis,
        plugin_slug,
    )
    if source_facts is None:
        return None
    locations = _php_request_parameter_locations(hypothesis, source_facts)
    destination_locations = sorted(locations.get(destination, frozenset()))
    if not destination_locations:
        return None
    variants: list[dict[str, str]] = [dict(dispatch)]

    if described:
        described_fields: list[tuple[str, str]] = []
        for raw_field in described.group("fields").split("&"):
            field = _PHP_DESCRIBED_FIELD_RE.fullmatch(raw_field.strip())
            if field is None:
                return None
            name = field.group("name")
            value = field.group("value").strip()
            if name != destination:
                described_fields.append((name, value))
        if len(described_fields) > 6:
            return None
        for name, value in described_fields:
            field_locations = sorted(locations.get(name, frozenset()))
            if not field_locations:
                return None
            expanded: list[dict[str, str]] = []
            for current in variants:
                for location in field_locations:
                    key = f"{location}:{name}"
                    if key in current and current[key] != value:
                        continue
                    candidate = dict(current)
                    candidate[key] = value
                    expanded.append(candidate)
            if not expanded or len(expanded) > 4:
                return None
            variants = expanded

    alternatives: list[dict[str, object]] = []
    for destination_location in destination_locations:
        for current in variants:
            candidate_dispatch = dict(current)
            candidate_dispatch.pop(f"{destination_location}:{destination}", None)
            alternatives.append(
                {
                    "method": str(base["method"]),
                    "route": str(base["route"]),
                    "dispatch": candidate_dispatch,
                    "destination_parameter": destination,
                    "destination_location": destination_location,
                }
            )
    unique: list[dict[str, object]] = []
    seen: set[str] = set()
    for alternative in alternatives:
        key = json.dumps(alternative, sort_keys=True)
        if key not in seen:
            seen.add(key)
            unique.append(alternative)
    if not unique or len(unique) > 4:
        return None
    return unique[0] if len(unique) == 1 else {"alternatives": unique}


def _php_include_oracle_enabled_for_hypotheses(
    hypotheses: list[Hypothesis],
    plugin_root: str | Path,
    plugin_slug: str,
) -> bool:
    """Return whether this sandbox needs the additive PHP include capability."""
    return any(
        _expected_php_include_http_transport(
            hypothesis,
            plugin_root,
            plugin_slug,
        )
        is not None
        for hypothesis in hypotheses
    )


_PHP_OBJECT_SINK_RE = re.compile(
    r"\b(?P<name>unserialize|maybe_unserialize|update_metadata|get_metadata)\s*\(",
    re.IGNORECASE,
)
_PHP_OBJECT_NAMED_ARGUMENT_RE = re.compile(
    r"\A\s*[A-Za-z_][A-Za-z0-9_]*\s*:",
)
_PHP_OBJECT_DECIMAL_LITERAL_RE = re.compile(
    r"[+-]?(?:(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:e[+-]?[0-9]+)?)\Z",
    re.IGNORECASE,
)
_PHP_OBJECT_BASE_INTEGER_LITERAL_RE = re.compile(
    r"[+-]?(?:0[xX][0-9a-fA-F_]+|0[bB][01_]+|0[oO][0-7_]+)\Z"
)
_PHP_OBJECT_NAMESPACE_RE = re.compile(
    r"\bnamespace(?:\s+(?P<name>[A-Za-z_\x80-\uffff]"
    r"[A-Za-z0-9_\x80-\uffff\\]*))?\s*(?P<delimiter>[;{])",
    re.IGNORECASE,
)
_PHP_OBJECT_FUNCTION_IMPORT_RE = re.compile(
    r"\buse\s+function\s+(?P<body>[^;]{1,1000});",
    re.IGNORECASE,
)
_PHP_OBJECT_ARRAY_KEY_RE = re.compile(
    r"\$(?P<variable>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"\[\s*(?P<quote>['\"])(?P<name>[A-Za-z_][A-Za-z0-9_.:-]{0,127})"
    r"(?P=quote)\s*\]",
)
_PHP_OBJECT_LITERAL_SUBSCRIPT_RE = re.compile(
    r"\[\s*(?P<quote>['\"])(?P<name>[A-Za-z_][A-Za-z0-9_.:-]{0,127})"
    r"(?P=quote)\s*\]",
)
_PHP_OBJECT_EVIDENCE_FUNCTION_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:[A-Za-z_][A-Za-z0-9_\\]*::)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
)
_PHP_OBJECT_POST_FIELD_RE = re.compile(
    r"\bPOST\s+(?:form\s+|body\s+|field\s+|parameter\s+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_.:-]{0,127})\b",
    re.IGNORECASE,
)
_PHP_OBJECT_FIELD_POST_RE = re.compile(
    r"\b(?P<name>[A-Za-z_][A-Za-z0-9_.:-]{0,127})\s+"
    r"(?:POST|form|body)\s+(?:field|parameter)\b",
    re.IGNORECASE,
)
_PHP_OBJECT_FIELD_STOPWORDS = frozenset(
    {"body", "data", "field", "fields", "form", "parameter", "request"}
)
_PHP_OBJECT_MAX_DESCRIBED_DISPATCH_FIELDS = 8


def _php_object_is_direct_global_call(
    masked: str,
    call: re.Match[str],
    *,
    document_masked: str,
    document_call_start: int,
) -> bool:
    """Accept only an unambiguous call to WordPress's global function."""
    prefix = masked[: call.start()]
    root_qualified = False
    if call.start() > 0 and masked[call.start() - 1] == "\\":
        before_separator = masked[: call.start() - 1]
        if before_separator and (
            before_separator[-1].isalnum()
            or before_separator[-1] in {"_", "\\"}
        ):
            return False
        prefix = before_separator
        root_qualified = True
    if re.search(r"(?:->|::)\s*\Z", prefix) is not None:
        return False
    if re.search(
        r"\b(?:function\s*&?|new)\s*\Z",
        prefix,
        re.IGNORECASE,
    ) is not None:
        return False
    if root_qualified:
        return True
    if not _php_object_call_is_in_global_namespace(
        document_masked,
        document_call_start,
    ):
        return False
    for imported in _PHP_OBJECT_FUNCTION_IMPORT_RE.finditer(
        document_masked,
        0,
        document_call_start,
    ):
        body = imported.group("body").strip()
        if re.search(r"\bget_metadata\b", body, re.IGNORECASE) is None:
            continue
        if re.fullmatch(
            r"\\?get_metadata(?:\s+as\s+get_metadata)?",
            body,
            re.IGNORECASE,
        ) is None:
            return False
    return True


def _php_object_call_is_in_global_namespace(
    document_masked: str,
    call_start: int,
) -> bool:
    """Resolve the namespace declaration containing one source call."""
    declarations = [
        declaration
        for declaration in _PHP_OBJECT_NAMESPACE_RE.finditer(document_masked)
        if declaration.start() < call_start
    ]
    if not declarations:
        return True
    latest = declarations[-1]
    if latest.group("delimiter") == ";":
        return latest.group("name") is None
    opening_brace = latest.end() - 1
    closing_brace = _matching_delimiter(
        document_masked,
        opening_brace,
        "{",
        "}",
    )
    return (
        closing_brace is not None
        and opening_brace < call_start < closing_brace
        and latest.group("name") is None
    )


def _php_object_simple_string_literal(value: str) -> str | None:
    """Return an unescaped, non-interpolated PHP string literal's contents."""
    stripped = value.strip()
    if len(stripped) < 2 or stripped[0] not in {"'", '"'}:
        return None
    if stripped[-1] != stripped[0]:
        return None
    contents = stripped[1:-1]
    if "\\" in contents or (stripped[0] == '"' and "$" in contents):
        return None
    return contents


def _php_object_decimal_literal(value: str) -> Decimal | None:
    """Parse one PHP decimal code literal or numeric-string body."""
    stripped = value.strip()
    if _PHP_OBJECT_DECIMAL_LITERAL_RE.fullmatch(stripped) is not None:
        try:
            return Decimal(stripped)
        except InvalidOperation:
            return None
    return None


def _php_object_code_numeric_literal(value: str) -> Decimal | None:
    """Parse an unquoted PHP numeric code literal without string coercion."""
    stripped = value.strip()
    decimal = _php_object_decimal_literal(stripped)
    if decimal is not None:
        return decimal
    if _PHP_OBJECT_BASE_INTEGER_LITERAL_RE.fullmatch(stripped) is not None:
        sign = -1 if stripped.startswith("-") else 1
        unsigned = stripped.lstrip("+-").replace("_", "")
        try:
            return Decimal(sign * int(unsigned, 0))
        except ValueError:
            return None
    return None


def _php_object_is_quoted_string_syntax(value: str) -> bool:
    stripped = value.strip()
    return (
        len(stripped) >= 2
        and stripped[0] in {"'", '"'}
        and stripped[-1] == stripped[0]
    )


def _php_object_is_fixed_array_syntax(value: str) -> bool:
    compact = re.sub(r"\s+", "", value.strip()).casefold()
    return (
        compact.startswith("[")
        or compact.startswith("array(")
    )


def _php_object_interpolated_string(value: str) -> bool:
    stripped = value.strip()
    return (
        len(stripped) >= 2
        and stripped[0] == '"'
        and stripped[-1] == '"'
        and "$" in stripped[1:-1]
    )


def _php_object_metadata_identity_is_plausible(value: str) -> bool:
    """Require a possibly truthy metadata type/key without decoding PHP."""
    stripped = value.strip()
    folded = stripped.casefold()
    if not stripped or folded in {"true", "false", "null"}:
        return False
    if _php_object_is_fixed_array_syntax(stripped):
        return False
    if _php_object_is_quoted_string_syntax(stripped):
        string_value = _php_object_simple_string_literal(stripped)
        if string_value is not None:
            return string_value not in {"", "0"}
        return _php_object_interpolated_string(stripped)
    numeric = _php_object_code_numeric_literal(stripped)
    if numeric is not None:
        return numeric != 0
    return True


def _php_object_fixed_object_id_is_invalid(value: str) -> bool:
    """Mirror get_metadata()'s is_numeric/absint early-return for fixed IDs."""
    stripped = value.strip()
    folded = stripped.casefold()
    if not stripped or folded in {"true", "false", "null"}:
        return True
    if _php_object_is_fixed_array_syntax(stripped):
        return True
    if _php_object_is_quoted_string_syntax(stripped):
        string_value = _php_object_simple_string_literal(stripped)
        if string_value is None:
            return not _php_object_interpolated_string(stripped)
        numeric_string = _php_object_decimal_literal(string_value.strip())
        return numeric_string is None or abs(numeric_string) < 1
    numeric = _php_object_code_numeric_literal(stripped)
    if numeric is not None:
        return abs(numeric) < 1
    return False


def _php_object_metadata_read_arguments_are_plausible(
    arguments: tuple[str, ...],
) -> bool:
    """Validate the positional WordPress ``get_metadata`` call contract."""
    if len(arguments) not in {3, 4}:
        return False
    if any(
        argument.lstrip().startswith("...")
        or _PHP_OBJECT_NAMED_ARGUMENT_RE.match(argument) is not None
        for argument in arguments
    ):
        return False
    metadata_type, object_id, metadata_key = (
        argument.strip() for argument in arguments[:3]
    )
    return (
        _php_object_metadata_identity_is_plausible(metadata_type)
        and not _php_object_fixed_object_id_is_invalid(object_id)
        and _php_object_metadata_identity_is_plausible(metadata_key)
    )


def _php_object_source_quote_offset(
    source: str,
    *,
    line: int,
    source_quote: str,
) -> int | None:
    """Locate the already-validated exact source quote in normalized bytes."""
    normalized_source = source.replace("\r\n", "\n").replace("\r", "\n")
    quote = source_quote.replace("\r\n", "\n").replace("\r", "\n").strip()
    quote_lines = quote.splitlines()
    source_lines = normalized_source.splitlines(keepends=True)
    start = line - 1
    end = start + len(quote_lines)
    if not quote or line < 1 or end > len(source_lines):
        return None
    source_span = "".join(source_lines[start:end])
    matches = list(re.finditer(re.escape(quote), source_span))
    if len(matches) != 1 or "\n" in source_span[: matches[0].start()]:
        return None
    return sum(len(item) for item in source_lines[:start]) + matches[0].start()


def _php_object_source_expression_matches(
    source: str,
    *,
    line: int,
    source_quote: str,
) -> bool:
    """Bind one exact dangerous expression to its cited line.

    Specialist source grounding requires the dangerous expression, not the
    surrounding assignment or return statement.  Match that expression only
    inside the exact cited source-line span, reject ambiguous raw matches, and
    independently require the matched bytes to contain one real (unmasked)
    deserialization sink call.
    """
    normalized_source = source.replace("\r\n", "\n").replace("\r", "\n")
    normalized_quote = source_quote.replace("\r\n", "\n").replace("\r", "\n")
    framed_quote = normalized_quote.strip("\n")
    framed_lines = framed_quote.splitlines()
    if (
        not framed_lines
        or not framed_lines[0].strip()
        or not framed_lines[-1].strip()
    ):
        return False
    quote = framed_quote.strip()
    quote_lines = quote.splitlines()
    if not quote or not quote_lines or line < 1:
        return False

    source_lines = normalized_source.splitlines(keepends=True)
    start = line - 1
    end = start + len(quote_lines)
    if start < 0 or end > len(source_lines):
        return False
    source_span = "".join(source_lines[start:end])
    source_start = sum(len(source_line) for source_line in source_lines[:start])
    masked_source = _mask_php_document_non_code(normalized_source)
    if masked_source is None:
        return False
    masked_span = masked_source[source_start : source_start + len(source_span)]

    matches = list(re.finditer(re.escape(quote), source_span))
    if len(matches) != 1:
        return False
    match = matches[0]
    if "\n" in source_span[: match.start()]:
        return False
    calls = list(_PHP_OBJECT_SINK_RE.finditer(masked_span))
    if len(calls) != 1:
        return False
    call = calls[0]
    return (
        match.start() <= call.start()
        and call.end() <= match.end()
        and "\n" not in source_span[: call.start()]
    )


def _is_source_grounded_php_object_hypothesis(
    hypothesis: Hypothesis,
    plugin_root: str | Path,
) -> bool:
    """Require an exact plugin-local unrestricted-deserialization sink call."""
    if (
        hypothesis.bug_class != BugClass.PHP_OBJECT_INJECTION
        or (hypothesis.evidence_summary or {}).get("usable_gadget") is not True
    ):
        return False
    source_file = _resolve_ssrf_source_file(plugin_root, hypothesis.file)
    if source_file is None or not hypothesis.sink_code.strip():
        return False
    try:
        source = source_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    if not _php_object_source_expression_matches(
        source,
        line=hypothesis.line,
        source_quote=hypothesis.sink_code,
    ):
        return False

    source_quote = hypothesis.sink_code.replace("\r\n", "\n").replace("\r", "\n")
    source_quote = source_quote.strip()
    masked = _mask_php_non_code(source_quote)
    calls = list(_PHP_OBJECT_SINK_RE.finditer(masked))
    if len(calls) != 1:
        return False
    call = calls[0]
    if re.search(r"\bfunction\s*\Z", masked[: call.start()], re.IGNORECASE):
        return False
    opening_parenthesis = call.end() - 1
    closing_parenthesis = _matching_delimiter(
        masked,
        opening_parenthesis,
        "(",
        ")",
        limit=min(len(masked), opening_parenthesis + _SSRF_MAX_CALL_CHARS),
    )
    if closing_parenthesis is None:
        return False
    arguments = _call_arguments(
        source_quote,
        masked,
        opening_parenthesis,
        closing_parenthesis,
    )
    if arguments is None:
        return False
    sink_name = call.group("name").casefold()
    if sink_name == "get_metadata":
        # WordPress deserializes only a keyed metadata read. Keep the trusted
        # callsite bound to the direct core API rather than accepting arbitrary
        # object-specific get_meta() wrappers. Tuple/value provenance remains a
        # source-review responsibility, but clearly empty keys cannot reach the
        # implicit deserialization branch.
        normalized_source = source.replace("\r\n", "\n").replace("\r", "\n")
        document_masked = _mask_php_document_non_code(normalized_source)
        quote_offset = _php_object_source_quote_offset(
            normalized_source,
            line=hypothesis.line,
            source_quote=source_quote,
        )
        return bool(
            document_masked is not None
            and quote_offset is not None
            and _php_object_is_direct_global_call(
                masked,
                call,
                document_masked=document_masked,
                document_call_start=quote_offset + call.start(),
            )
            and _php_object_metadata_read_arguments_are_plausible(arguments)
        )
    value_index = 3 if sink_name == "update_metadata" else 0
    if len(arguments) <= value_index:
        return False
    value_argument = _mask_php_non_code(arguments[value_index])
    if _PHP_INCLUDE_VARIABLE_RE.search(value_argument) is None:
        return False
    if sink_name == "update_metadata" and len(arguments) >= 5:
        previous_value = arguments[4].strip().casefold()
        if (
            previous_value
            and previous_value not in {"''", '""', "null"}
            and (_PHP_INCLUDE_VARIABLE_RE.fullmatch(previous_value) is None)
        ):
            return False
    return True


def _expected_php_object_callsite(
    hypothesis: Hypothesis,
    plugin_root: str | Path,
) -> PhpObjectCallsite | None:
    """Bind the cited sink to one exact plugin-relative file and line range."""
    if not _is_source_grounded_php_object_hypothesis(hypothesis, plugin_root):
        return None
    source_file = _resolve_ssrf_source_file(plugin_root, hypothesis.file)
    if source_file is None:
        return None
    try:
        root = Path(plugin_root).resolve(strict=True)
        resolved = source_file.resolve(strict=True)
        relative_path = resolved.relative_to(root).as_posix()
        source_bytes = resolved.read_bytes()
    except (OSError, ValueError):
        return None
    quote_lines = hypothesis.sink_code.strip("\r\n").splitlines()
    if not quote_lines:
        return None
    try:
        return PhpObjectCallsite(
            relative_path=relative_path,
            start_line=hypothesis.line,
            end_line=hypothesis.line + len(quote_lines) - 1,
            source_sha256=hashlib.sha256(source_bytes).hexdigest(),
        )
    except ValueError:
        return None


def _php_object_entry_callbacks(
    sources: list[tuple[str, str]],
    hook: str,
) -> frozenset[str]:
    """Resolve one literal WordPress hook to one literal callback name."""
    if _PHP_WORDPRESS_HOOK_RE.fullmatch(hook) is None:
        return frozenset()
    quoted_hook = re.compile(
        r"\A\s*(?P<quote>['\"])" + re.escape(hook) + r"(?P=quote)\s*\Z",
        re.IGNORECASE,
    )
    quoted_callback = re.compile(
        r"\A\s*(?P<quote>['\"])(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
        r"(?P=quote)\s*\Z"
    )
    array_callback = re.compile(
        r"\A\s*(?:array\s*\(|\[).*?(?P<quote>['\"])"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?P=quote)\s*(?:\)|\])\s*\Z",
        re.IGNORECASE | re.DOTALL,
    )
    callbacks: set[str] = set()
    for source, masked in sources:
        for registration in re.finditer(r"\badd_action\s*\(", masked, re.IGNORECASE):
            opening_parenthesis = registration.end() - 1
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
            if arguments is None or len(arguments) < 2:
                continue
            if quoted_hook.fullmatch(arguments[0]) is None:
                continue
            callback = quoted_callback.fullmatch(arguments[1])
            array_value = array_callback.fullmatch(arguments[1])
            if callback is not None:
                callbacks.add(callback.group("name").casefold())
            elif array_value is not None:
                callbacks.add(array_value.group("name").casefold())
    defined = {
        match.group("name").casefold()
        for _source, masked in sources
        for match in _SSRF_NAMED_FUNCTION_RE.finditer(masked)
    }
    resolved = callbacks & defined
    return frozenset(resolved) if len(resolved) == 1 else frozenset()


def _php_object_function_spans(
    source: str,
    masked: str,
    names: frozenset[str] | set[str] | None,
) -> tuple[tuple[str, int, int], ...]:
    """Index selected named PHP function bodies once for bounded lookups."""
    spans: list[tuple[str, int, int]] = []
    for match in _SSRF_NAMED_FUNCTION_RE.finditer(masked):
        name = match.group("name").casefold()
        if names is not None and name not in names:
            continue
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
        terminator = re.search(r"[;{]", masked[closing_parenthesis + 1 :])
        if terminator is None:
            continue
        body_start = closing_parenthesis + 1 + terminator.start()
        if masked[body_start] != "{":
            continue
        body_end = _matching_delimiter(masked, body_start, "{", "}")
        if body_end is not None:
            spans.append((name, body_start, body_end))
    return tuple(spans)


def _php_object_enclosing_function_name(
    spans: tuple[tuple[str, int, int], ...],
    anchor: int,
) -> str | None:
    enclosing = [span for span in spans if span[1] < anchor <= span[2]]
    return max(enclosing, key=lambda item: item[1])[0] if enclosing else None


def _php_object_whole_post_aliases(
    sources: list[tuple[str, str]],
    callbacks: frozenset[str] | None,
) -> frozenset[str]:
    """Find callback-local aliases assigned the whole ``$_POST`` array."""
    aliases: set[str] = set()
    whole_post = re.compile(r"\$_POST\b(?!\s*\[)", re.IGNORECASE)
    assignment = re.compile(
        r"\$(?P<alias>[A-Za-z_][A-Za-z0-9_]*)\s*=",
        re.IGNORECASE,
    )
    for source, masked in sources:
        callback_spans = _php_object_function_spans(source, masked, callbacks)
        for post in whole_post.finditer(masked):
            enclosing_name = _php_object_enclosing_function_name(
                callback_spans,
                post.start(),
            )
            if callbacks is not None and (
                enclosing_name is None or enclosing_name not in callbacks
            ):
                continue
            enclosing_span = next(
                (
                    span
                    for span in callback_spans
                    if span[0] == enclosing_name and span[1] < post.start() <= span[2]
                ),
                None,
            )
            body_start = enclosing_span[1] if enclosing_span is not None else 0
            body_end = enclosing_span[2] if enclosing_span is not None else len(masked)
            statement_start = max(
                masked.rfind(";", body_start + 1, post.start()),
                masked.rfind("{", body_start, post.start()),
            )
            statement_end = masked.find(";", post.end(), body_end)
            if statement_end < 0:
                continue
            statement = masked[statement_start + 1 : statement_end]
            found = assignment.search(statement)
            if found is not None and found.start() < post.start() - statement_start:
                aliases.add(found.group("alias").casefold())
    return frozenset(aliases)


def _php_object_source_form_fields(
    sources: list[tuple[str, str]],
    callbacks: frozenset[str] | None,
    whole_post_aliases: frozenset[str],
    hypothesis: Hypothesis,
) -> frozenset[str]:
    """Collect literal form keys backed by direct or whole-POST source reads."""
    fields: set[str] = set()
    evidence_values = [
        *hypothesis.taint_path,
        hypothesis.reasoning,
        str((hypothesis.evidence_summary or {}).get("reachable_path") or ""),
    ]
    evidence_functions = {
        match.group("name").casefold()
        for value in evidence_values
        for match in _PHP_OBJECT_EVIDENCE_FUNCTION_RE.finditer(value)
    }
    for source, masked in sources:
        relevant_names = set(evidence_functions)
        if callbacks is not None:
            relevant_names.update(callbacks)
        relevant_spans = _php_object_function_spans(
            source,
            masked,
            relevant_names,
        )
        for match in _PHP_REQUEST_REFERENCE_RE.finditer(source):
            if masked[match.start() : match.start() + 2] != "$_":
                continue
            if match.group("source").upper() != "POST":
                continue
            enclosing_name = _php_object_enclosing_function_name(
                relevant_spans,
                match.start(),
            )
            if callbacks is None or (
                enclosing_name is not None and enclosing_name in callbacks
            ):
                fields.add(match.group("name"))
        if whole_post_aliases:
            for match in _PHP_OBJECT_ARRAY_KEY_RE.finditer(source):
                if masked[match.start()] != "$":
                    continue
                enclosing_name = _php_object_enclosing_function_name(
                    relevant_spans,
                    match.start(),
                )
                if match.group("variable").casefold() in whole_post_aliases and (
                    callbacks is None
                    or (enclosing_name is not None and enclosing_name in callbacks)
                ):
                    fields.add(match.group("name"))
            # Whole request arrays are frequently handed to DTOs or adapters.
            # Accept a downstream literal only inside a function explicitly
            # named by the reviewed taint path; an unrelated plugin-wide key is
            # not transport evidence.
            for match in _PHP_OBJECT_LITERAL_SUBSCRIPT_RE.finditer(source):
                if masked[match.start()] != "[":
                    continue
                enclosing_name = _php_object_enclosing_function_name(
                    relevant_spans,
                    match.start(),
                )
                if enclosing_name is not None and enclosing_name in evidence_functions:
                    fields.add(match.group("name"))
    return frozenset(fields)


def _php_object_candidate_fields(
    hypothesis: Hypothesis,
    *,
    whole_post_aliases: frozenset[str],
    dispatch_fields: frozenset[str],
) -> frozenset[str]:
    """Extract exactly described POST field candidates without guessing."""
    described = _PHP_DESCRIBED_ENTRY_RE.fullmatch(hypothesis.entry_point.strip())
    if described is not None:
        placeholders: set[str] = set()
        for raw_field in described.group("fields").split("&"):
            field = _PHP_DESCRIBED_FIELD_RE.fullmatch(raw_field.strip())
            if field is None:
                return frozenset()
            if re.fullmatch(r"<[^<>]{1,80}>", field.group("value").strip()):
                placeholders.add(field.group("name"))
        if placeholders:
            return frozenset(placeholders - set(dispatch_fields))

    def from_values(values: list[str]) -> set[str]:
        candidates: set[str] = set()
        for value in values:
            for match in _PHP_REQUEST_REFERENCE_RE.finditer(value):
                if match.group("source").upper() == "POST":
                    candidates.add(match.group("name"))
            for match in _PHP_OBJECT_ARRAY_KEY_RE.finditer(value):
                if match.group("variable").casefold() in whole_post_aliases:
                    candidates.add(match.group("name"))
            for pattern in (_PHP_OBJECT_POST_FIELD_RE, _PHP_OBJECT_FIELD_POST_RE):
                for match in pattern.finditer(value):
                    name = match.group("name")
                    if name.casefold() not in _PHP_OBJECT_FIELD_STOPWORDS:
                        candidates.add(name)
        return candidates - set(dispatch_fields)

    evidence_source = (hypothesis.evidence_summary or {}).get("source")
    if isinstance(evidence_source, str):
        evidence_candidates = from_values([evidence_source])
        if evidence_candidates:
            return frozenset(evidence_candidates)
    return frozenset(
        from_values(
            [
                *hypothesis.taint_path,
                hypothesis.reasoning,
                hypothesis.preconditions,
            ]
        )
    )


def _expected_php_object_http_transport(
    hypothesis: Hypothesis,
    plugin_root: str | Path,
    plugin_slug: str | None = None,
) -> dict[str, object] | None:
    """Derive one exact form rewrite policy from source and reviewed evidence."""
    if plugin_slug is not None:
        try:
            validate_plugin_slug(plugin_slug)
        except ValueError:
            return None
    if not _is_source_grounded_php_object_hypothesis(hypothesis, plugin_root):
        return None

    described = _PHP_DESCRIBED_ENTRY_RE.fullmatch(hypothesis.entry_point.strip())
    head = described.group("head").strip() if described else hypothesis.entry_point
    base = dict(_parse_entry_point_transport(head))
    if base.get("method") != "POST" or not base.get("route"):
        return None
    dispatch = base.get("dispatch")
    if not isinstance(dispatch, dict):
        return None
    if any(
        not isinstance(key, str)
        or not isinstance(value, str)
        or key.partition(":")[0] not in {"query", "form"}
        for key, value in dispatch.items()
    ):
        return None

    sources = _bounded_php_include_sources(plugin_root)
    if sources is None:
        return None
    callbacks: frozenset[str] | None
    if _PHP_WORDPRESS_HOOK_RE.fullmatch(head):
        callbacks = _php_object_entry_callbacks(sources, head)
        if not callbacks:
            return None
    else:
        if plugin_slug is None:
            return None
        direct_prefix = f"/wp-content/plugins/{plugin_slug}/"
        route = str(base["route"])
        if not route.startswith(direct_prefix):
            return None
        relative = route.removeprefix(direct_prefix)
        direct_file = _resolve_ssrf_source_file(plugin_root, relative)
        if direct_file is None:
            return None
        try:
            direct_source = direct_file.read_text(
                encoding="utf-8",
                errors="replace",
            )
        except OSError:
            return None
        sources = [(direct_source, _mask_php_non_code(direct_source))]
        callbacks = None
    whole_post_aliases = _php_object_whole_post_aliases(sources, callbacks)
    source_fields = _php_object_source_form_fields(
        sources,
        callbacks,
        whole_post_aliases,
        hypothesis,
    )
    dispatch_fields = frozenset(key.partition(":")[2] for key in dispatch)
    candidates = _php_object_candidate_fields(
        hypothesis,
        whole_post_aliases=whole_post_aliases,
        dispatch_fields=dispatch_fields,
    )
    if len(candidates) != 1:
        return None
    object_field = next(iter(candidates))
    if object_field not in source_fields:
        return None

    exact_dispatch = dict(dispatch)
    if described is not None:
        described_fields = []
        for raw_field in described.group("fields").split("&"):
            field = _PHP_DESCRIBED_FIELD_RE.fullmatch(raw_field.strip())
            if field is None:
                return None
            if field.group("name") != object_field:
                described_fields.append((field.group("name"), field.group("value")))
        if len(described_fields) > _PHP_OBJECT_MAX_DESCRIBED_DISPATCH_FIELDS:
            return None
        for name, value in described_fields:
            if name not in source_fields and name not in dispatch_fields:
                return None
            typed_name = f"form:{name}"
            existing = exact_dispatch.get(typed_name)
            if existing is not None and existing != value:
                return None
            exact_dispatch[typed_name] = value

    if f"form:{object_field}" in exact_dispatch:
        return None
    return {
        "method": "POST",
        "route": str(base["route"]),
        "dispatch": exact_dispatch,
        "object_field": object_field,
        "object_location": "form",
    }


def _php_object_oracle_enabled_for_hypotheses(
    hypotheses: list[Hypothesis],
    plugin_root: str | Path,
    plugin_slug: str,
) -> bool:
    return any(
        _expected_php_object_http_transport(
            hypothesis,
            plugin_root,
            plugin_slug,
        )
        is not None
        for hypothesis in hypotheses
    )


def _php_object_gadget_oracle_enabled_for_hypotheses(
    hypotheses: list[Hypothesis],
    plugin_root: str | Path,
    plugin_slug: str,
) -> bool:
    """Enable the natural-gadget surface only for a promotable typed recipe."""
    return any(
        hypothesis.bug_class == BugClass.PHP_OBJECT_INJECTION
        and hypothesis.php_object_gadget_recipe is not None
        and hypothesis.php_object_gadget_recipe.effect_binding.kind == "direct_path"
        and validate_php_object_gadget_recipe_sources(
            Path(plugin_root),
            hypothesis.php_object_gadget_recipe,
        )
        is None
        and _expected_php_object_http_transport(
            hypothesis,
            plugin_root,
            plugin_slug,
        )
        is not None
        and _expected_php_object_callsite(hypothesis, plugin_root) is not None
        for hypothesis in hypotheses
    )


def _php_object_gadget_directory_constants(
    recipe: PhpObjectGadgetRecipe,
) -> frozenset[str]:
    """Return only source-reviewed constants that must resolve to the tmpfs."""
    constants = {
        guarded.directory_constant for guarded in recipe.guarded_effect_anchors
    }
    if recipe.effect_binding.kind == "direct_path":
        local_path_check = recipe.effect_binding.local_path_check
        if local_path_check is not None:
            constants.add(local_path_check.directory_constant)
    else:
        constants.add(recipe.effect_binding.effect.directory_constant)
    return frozenset(constants)


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
    confirmed_evidence_by_script: dict[str, dict] = {}
    php_object_primitive_confirmation: dict[str, object] | None = None
    php_object_natural_confirmation: dict[str, object] | None = None
    php_object_natural_failure_reason = ""
    expected_attacker_role = infer_attacker_role(hyp)
    expected_bug_class = hyp.bug_class.oracle_key
    ssrf_expected = expected_bug_class in {
        BugClass.SSRF.name,
        BugClass.SSRF.value,
    }
    ssrf_oracle_mode = _ssrf_oracle_mode(hyp) if ssrf_expected else "http"
    sandbox_ssrf_modes = frozenset({ssrf_oracle_mode}) if ssrf_expected else frozenset()
    php_include_http_transport = _expected_php_include_http_transport(
        hyp,
        plugin_path,
        plugin_slug,
    )
    php_include_expected = php_include_http_transport is not None
    php_object_candidate = hyp.bug_class == BugClass.PHP_OBJECT_INJECTION
    if (
        php_object_candidate
        and (hyp.evidence_summary or {}).get("usable_gadget") is not True
    ):
        raise RuntimeError(
            "automatic CWE-502 verification requires the source reviewer to "
            "establish evidence_summary.usable_gadget=true exactly"
        )
    php_object_http_transport = (
        _expected_php_object_http_transport(hyp, plugin_path, plugin_slug)
        if php_object_candidate
        else None
    )
    php_object_callsite = (
        _expected_php_object_callsite(hyp, plugin_path)
        if php_object_candidate
        else None
    )
    if php_object_candidate and (
        php_object_http_transport is None or php_object_callsite is None
    ):
        raise RuntimeError(
            "trusted PHP object verification requires one unambiguous "
            "source-derived POST form transport and installed callsite binding"
        )
    php_object_expected = (
        php_object_http_transport is not None and php_object_callsite is not None
    )
    seek_full_compromise = _has_full_compromise_target(
        hyp.security_outcome
    ) and not (ssrf_expected or php_include_expected or php_object_expected)
    executable_upload_http_transport = _parse_entry_point_transport(hyp.entry_point)
    executable_upload_candidate = bool(
        seek_full_compromise
        and hyp.bug_class == BugClass.ARBITRARY_FILE_WRITE
    )
    if executable_upload_candidate and (
        executable_upload_http_transport.get("method") != "POST"
        or not executable_upload_http_transport.get("route")
    ):
        raise RuntimeError(
            "trusted executable-upload verification requires one unambiguous "
            "source-derived POST transport"
        )
    executable_upload_expected = executable_upload_candidate
    php_object_gadget_recipe = hyp.php_object_gadget_recipe
    if php_object_candidate and php_object_gadget_recipe is not None:
        gadget_source_error = validate_php_object_gadget_recipe_sources(
            Path(plugin_path),
            php_object_gadget_recipe,
        )
        if gadget_source_error is not None:
            raise RuntimeError(
                "trusted PHP object gadget recipe no longer matches installed "
                f"source: {gadget_source_error}"
            )
    php_object_natural_expected = bool(
        php_object_expected
        and php_object_gadget_recipe is not None
        and php_object_gadget_recipe.effect_binding.kind == "direct_path"
    )
    code_slice: str | None = None
    readme: str | None = None
    if developer is not None:
        plugin_root = Path(plugin_path)
        code_slice = _build_setup_code_context(plugin_root, hyp)
        readme = _read_readme(plugin_root)
    setup_plan = SetupPlan()
    setup_exec_results: list[dict] = []
    latest_setup_round_results: list[dict] = []
    setup_round_notes: list[str] = []
    automatic_followups_used = 0
    automatic_followup_cap = _SETUP_FOLLOWUP_CAP
    poc_requested_followups_used = 0
    poc_requested_followup_cap = _POC_REQUESTED_SETUP_FOLLOWUP_CAP

    def _checkpoint_attempts(
        status: Literal[
            "in_progress",
            "not_confirmed",
            "primitive_confirmed",
            "confirmed",
        ] = "in_progress",
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

    def _record_setup_round(results: list[dict]) -> None:
        """Append one atomic round while retaining its transactional boundary."""
        nonlocal latest_setup_round_results
        setup_exec_results.extend(results)
        if results:
            latest_setup_round_results = list(results)

    def _authoritative_setup_feedback() -> str:
        return _summarise_setup_state(
            setup_exec_results,
            latest_round_results=latest_setup_round_results,
        )

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
        execution_summary = _authoritative_setup_feedback()
        return (
            "The runner configured the sandbox before this PoC attempt.\n"
            "Setup rationale history:\n- "
            + "\n- ".join(reasons)
            + "\nAuthoritative setup state and latest round:\n"
            + execution_summary
            + "\nUse only RETAINED COMMITTED SETUP STATE as current state. A failed "
            "latest round is an atomic repair attempt whose mutations were removed; "
            "it does not erase earlier committed setup."
        )

    # Bound once the sandbox and developer are available.
    setup_callback_state: dict[str, Any] = {"sb": None, "error": None}

    async def _request_setup_followup(
        sb_local: SandboxManager,
        *,
        last_iteration: int,
        last_stdout: str,
        last_stderr: str,
        last_error_log: str,
        schema_diagnostics: str = "",
        setup_execution_feedback: str = "",
    ) -> tuple[SetupPlan | None, list[tuple[SetupPlan, list[dict]]]]:
        """Request and apply bounded setup repairs, retrying atomic blocks directly."""
        nonlocal automatic_followups_used

        rounds: list[tuple[SetupPlan, list[dict]]] = []
        followup: SetupPlan | None = None
        feedback = setup_execution_feedback
        diagnostics = schema_diagnostics
        atomic_retries = 0
        while developer is not None and automatic_followups_used < automatic_followup_cap:
            # Count every developer request, including empty or errored responses.
            automatic_followups_used += 1
            quota_used = automatic_followups_used
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
                    setup_http_context=_setup_http_context_for_sandbox(sb_local),
                )
            except Exception as exc:
                logger.warning("propose_setup_followup for %s failed: %s", hyp.id, exc)
                _checkpoint_setup_results()
                return None, rounds

            if not followup.commands:
                _checkpoint_setup_results()
                return followup, rounds

            logger.info(
                "verify: %s applying %d automatic followup setup commands "
                "(round %d/%d)",
                hyp.id,
                len(followup.commands),
                quota_used,
                automatic_followup_cap,
            )
            results = await _run_setup_round_atomically(
                sb_local,
                followup.commands,
                hypothesis=hyp,
                plugin_slug=plugin_slug,
            )
            _record_setup_round(results)
            # Preserve proposed history, but execution status is carried separately.
            setup_plan.commands.extend(followup.commands)
            setup_round_notes.append(
                f"automatic followup {quota_used}: "
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

            feedback = _authoritative_setup_feedback()
            retry_diagnostics = await _collect_schema_diagnostics(
                sb_local, followup.commands
            )
            if retry_diagnostics:
                diagnostics = "\n".join(
                    part for part in (diagnostics, retry_diagnostics) if part
                )

        return followup, rounds

    async def _request_poc_requested_setup(
        sb_local: SandboxManager,
        *,
        request_description: str,
    ) -> tuple[
        RequestedSetupPlan | None,
        list[tuple[RequestedSetupPlan, list[dict]]],
    ]:
        """Plan and apply bounded PoC-requested state without inventing a failure.

        The child description stays a separately labelled, untrusted planning
        input.  Safety checks, atomic execution, repair retries, checkpointing,
        and the dedicated PoC-requested quota remain runner-owned.
        """
        nonlocal poc_requested_followups_used

        rounds: list[tuple[RequestedSetupPlan, list[dict]]] = []
        requested_plan: RequestedSetupPlan | None = None
        feedback = _authoritative_setup_feedback()
        diagnostics = ""
        atomic_retries = 0
        while (
            developer is not None
            and poc_requested_followups_used < poc_requested_followup_cap
        ):
            # Count every planning request, including empty or errored responses.
            poc_requested_followups_used += 1
            quota_used = poc_requested_followups_used
            try:
                requested_plan = await developer.propose_requested_setup(
                    hypothesis=hyp,
                    prior_plan=setup_plan,
                    request_description=request_description,
                    schema_diagnostics=diagnostics,
                    code_slice=code_slice,
                    setup_execution_feedback=feedback,
                    runtime=runtime,
                    plugin_root=plugin_path,
                    setup_http_context=_setup_http_context_for_sandbox(sb_local),
                )
            except Exception as exc:
                logger.warning(
                    "propose_requested_setup for %s failed: %s", hyp.id, exc
                )
                _checkpoint_setup_results()
                return None, rounds

            if not requested_plan.commands:
                _checkpoint_setup_results()
                return requested_plan, rounds

            logger.info(
                "verify: %s applying %d poc_requested setup commands (round %d/%d)",
                hyp.id,
                len(requested_plan.commands),
                quota_used,
                poc_requested_followup_cap,
            )
            results = await _run_setup_round_atomically(
                sb_local,
                requested_plan.commands,
                hypothesis=hyp,
                plugin_slug=plugin_slug,
            )
            _record_setup_round(results)
            # Preserve proposed history; execution status is recorded separately.
            setup_plan.commands.extend(requested_plan.commands)
            setup_round_notes.append(
                f"poc-requested followup {quota_used}: "
                f"{requested_plan.rationale or '(no rationale)'}"
            )
            rounds.append((requested_plan, results))
            _checkpoint_setup_results()

            if not any(item.get("failed") for item in results):
                return requested_plan, rounds

            blocked_before_execution = any(
                item.get("blocked_before_execution") is True for item in results
            )
            if (
                not blocked_before_execution
                or atomic_retries >= _ATOMIC_SETUP_RETRY_CAP
            ):
                return requested_plan, rounds
            atomic_retries += 1

            feedback = _authoritative_setup_feedback()
            retry_diagnostics = await _collect_schema_diagnostics(
                sb_local, requested_plan.commands
            )
            if retry_diagnostics:
                diagnostics = "\n".join(
                    part for part in (diagnostics, retry_diagnostics) if part
                )

        return requested_plan, rounds

    async def _setup_callback(description: str) -> str:
        sb_local = setup_callback_state["sb"]
        if sb_local is None or developer is None:
            return "[request_additional_setup] sandbox or developer not yet ready"
        if poc_requested_followups_used >= poc_requested_followup_cap:
            return (
                "[request_additional_setup] PoC-requested setup followup limit reached "
                f"({poc_requested_followup_cap}/{poc_requested_followup_cap})"
            )

        try:
            followup, rounds = await _request_poc_requested_setup(
                sb_local,
                request_description=description,
            )
        except Exception as exc:
            # The agent runtime may turn tool exceptions into model-visible text.
            # Retain a runner-owned latch so a failed atomic rollback/restore can
            # never be mistaken for a harmless authoring failure.
            setup_callback_state["error"] = exc
            raise
        if not rounds:
            rationale = followup.rationale if followup else "none"
            return (
                "[request_additional_setup] developer returned no applicable commands "
                f"(rationale: {rationale!r}). No setup state changed.\n"
                f"{_authoritative_setup_feedback()}"
            )

        final_plan, final_results = rounds[-1]
        all_round_results = [item for _plan, results in rounds for item in results]
        if any(item.get("failed") for item in final_results):
            applied = sum(
                1
                for item in all_round_results
                if item.get("executed")
                and item.get("setup_state_committed") is True
            )
            return (
                "[request_additional_setup] setup remains incomplete; "
                f"{applied} permitted commands were committed. "
                "The latest failed repair round was rolled back without erasing "
                "earlier committed setup. Execution feedback is authoritative:\n"
                f"{_authoritative_setup_feedback()}"
            )
        executed = sum(
            1
            for item in all_round_results
            if item.get("executed") and item.get("setup_state_committed") is True
        )
        return (
            f"[request_additional_setup] applied {executed} permitted commands. "
            f"Rationale: {final_plan.rationale or '(none)'}\n"
            "Execution feedback:\n"
            f"{_authoritative_setup_feedback()}"
        )

    poc_author = PoCAuthorAgent(
        runtime,
        model=config.models.poc_author,
        plugin_root=plugin_path,
        setup_callback=_setup_callback,
    )

    initial_setup_requested = False

    async def _request_initial_setup(sb_local: SandboxManager) -> None:
        """Plan setup only after the live sandbox exposes its canonical Host."""
        nonlocal initial_setup_requested, setup_plan
        if developer is None or initial_setup_requested:
            return
        initial_setup_requested = True
        try:
            setup_plan = await developer.propose_setup(
                hyp,
                plugin_slug=plugin_slug,
                code_slice=code_slice,
                readme_excerpt=readme,
                setup_http_context=_setup_http_context_for_sandbox(sb_local),
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
            await _request_initial_setup(persistent_sb)
            _record_setup_round(
                await _run_setup_round_atomically(
                    persistent_sb,
                    setup_plan.commands,
                    hypothesis=hyp,
                    plugin_slug=plugin_slug,
                )
            )
            _checkpoint_setup_results()
            yield persistent_sb
            return
        async with SandboxManager(
            config.sandbox,
            boot_timeout_s=max(config.sandbox_timeout_seconds, 180),
            poc_timeout_s=config.sandbox_timeout_seconds,
            ssrf_oracle_modes=sandbox_ssrf_modes,
            php_include_oracle_enabled=php_include_expected,
            php_object_oracle_enabled=php_object_expected,
            php_object_gadget_oracle_enabled=php_object_natural_expected,
            php_object_gadget_directory_constants=(
                _php_object_gadget_directory_constants(php_object_gadget_recipe)
                if php_object_natural_expected
                and php_object_gadget_recipe is not None
                else frozenset()
            ),
        ) as fresh_sb:
            await fresh_sb.install_plugin(plugin_zip, plugin_slug)
            await fresh_sb.setup_test_users()
            await _request_initial_setup(fresh_sb)
            _record_setup_round(
                await _run_setup_round_atomically(
                    fresh_sb,
                    setup_plan.commands,
                    hypothesis=hyp,
                    plugin_slug=plugin_slug,
                )
            )
            _checkpoint_setup_results()
            yield fresh_sb

    async with _sb_ctx() as sb:
        # Bind the live sandbox into the PoC author's setup callback.
        setup_callback_state["sb"] = sb

        async def _restore_attempt_state(snapshot: Path) -> None:
            await sb.restore(snapshot)
            if (
                ssrf_oracle_mode == "local_resource"
                or php_include_expected
                or php_object_expected
            ):
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
                    setup_execution_feedback=_authoritative_setup_feedback(),
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
        expected_http_transport: dict[str, object] | None
        if ssrf_expected:
            expected_http_transport = _expected_ssrf_http_transport(
                hyp,
                plugin_path,
                plugin_slug,
            )
        elif php_include_expected:
            expected_http_transport = php_include_http_transport
        elif php_object_expected:
            expected_http_transport = php_object_http_transport
        elif executable_upload_expected:
            expected_http_transport = dict(executable_upload_http_transport)
        else:
            expected_http_transport = None
        if (
            ssrf_expected
            or php_include_expected
            or php_object_expected
            or executable_upload_expected
        ):
            author_user_accounts = [role_account] if role_account is not None else []
        else:
            author_user_accounts = user_accounts

        ssrf_oracle: dict[str, str] | None = None
        php_include_oracle: dict[str, str] | None = None
        php_object_oracle: dict[str, str] | None = None
        replay_script_after_setup: str | None = None
        verified_partial_proof: dict[str, object] | None = None
        for iteration in range(1, config.verify_max_iterations + 1):
            replay_script = replay_script_after_setup
            replay_script_after_setup = None
            replaying_setup_repair = replay_script is not None
            if replaying_setup_repair:
                # A committed setup-only repair changes the prerequisite state, not
                # the exploit shape. Reuse both the exact prior script and its
                # already-prepared verifier oracle once before permitting a rewrite.
                assert replay_script is not None
                script = replay_script
                logger.info(
                    "verify: %s iter %d replaying the prior PoC unchanged after "
                    "committed setup repair",
                    hyp.id,
                    iteration,
                )
            else:
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
                php_include_oracle = (
                    await sb.prepare_php_include_oracle()
                    if php_include_expected
                    else None
                )
                php_object_oracle = (
                    await sb.prepare_php_object_oracle(php_object_callsite)
                    if php_object_expected and php_object_callsite is not None
                    else None
                )
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
                if seek_full_compromise:
                    extra_ctx["verification_target"] = {
                        "confidentiality": "high",
                        "integrity": "high",
                        "availability": "high",
                        "description": hyp.security_outcome.description,
                        "proof_gap": str(
                            (hyp.evidence_summary or {}).get("proof_gaps") or ""
                        ),
                    }
                if executable_upload_expected:
                    extra_ctx["executable_upload_oracle"] = {
                        "mode": "post_upload_challenge_v1",
                        "payload_environment": EXECUTABLE_UPLOAD_PAYLOAD_ENV,
                        "attack_filename_environment": (
                            EXECUTABLE_UPLOAD_ATTACK_FILENAME_ENV
                        ),
                        "control_filename_environment": (
                            EXECUTABLE_UPLOAD_CONTROL_FILENAME_ENV
                        ),
                        "challenge_parameter": (
                            EXECUTABLE_UPLOAD_CHALLENGE_PARAMETER
                        ),
                        "response_prefix": EXECUTABLE_UPLOAD_RESPONSE_PREFIX,
                        "response_derivation": (
                            "implemented by the exact parent-generated PHP payload; "
                            "the child must not reconstruct or alter those bytes"
                        ),
                    }
                if verified_partial_proof is not None:
                    extra_ctx["verified_partial_proof"] = verified_partial_proof
                if ssrf_oracle is not None:
                    extra_ctx["ssrf_oracle"] = ssrf_oracle
                    extra_ctx["ssrf_http_transport"] = expected_http_transport
                if php_include_oracle is not None:
                    extra_ctx["php_include_oracle"] = php_include_oracle
                    extra_ctx["php_include_http_transport"] = expected_http_transport
                if php_object_oracle is not None:
                    extra_ctx["php_object_oracle"] = php_object_oracle
                    extra_ctx["php_object_http_transport"] = php_object_http_transport
                if setup_summary:
                    extra_ctx["setup_summary"] = setup_summary
                setup_callback_state["error"] = None
                try:
                    script = await poc_author.write(
                        hypothesis=hyp,
                        target_url=sb.target_url,
                        previous_attempts=attempts,
                        extra_context=extra_ctx or None,
                    )
                except Exception as exc:
                    callback_error = setup_callback_state.get("error")
                    if isinstance(callback_error, Exception):
                        raise RuntimeError(
                            "PoC-requested setup failed during authoring"
                        ) from callback_error
                    if verified_partial_proof is None:
                        raise
                    logger.warning(
                        "verify: %s could not author the optional full-compromise "
                        "refinement (%s); retaining the confirmed lower bound",
                        hyp.id,
                        exc,
                    )
                    break
                callback_error = setup_callback_state.get("error")
                if isinstance(callback_error, Exception):
                    raise RuntimeError(
                        "PoC-requested setup failed during authoring"
                    ) from callback_error
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
                        proof_kind=(
                            "php_object_primitive"
                            if php_object_expected
                            else "standard"
                        ),
                        script_path=str(script_path),
                        result=PoCStatus.FAILED,
                        validation_reason=reason,
                    )
                )
                _checkpoint_attempts()
                if verified_partial_proof is not None:
                    logger.warning(
                        "verify: %s could not snapshot the optional full-compromise "
                        "refinement; retaining the confirmed lower bound",
                        hyp.id,
                    )
                    break
                raise RuntimeError(reason) from exc

            result = await sb.run_poc(
                str(script_path),
                expected_bug_class=expected_bug_class,
                expected_attacker_role=normalized_role,
                expected_http_transport=expected_http_transport,
                expected_php_include=php_include_expected,
                expected_php_object=php_object_expected,
                expected_php_object_transport=php_object_http_transport,
                expected_executable_upload=executable_upload_expected,
            )
            first_php_object_snapshot = _consume_php_object_snapshot(
                result,
                php_object_expected=php_object_expected,
            )
            if result.success and php_object_expected:
                bounded, bounded_reason = _bounded_php_object_observation(
                    result.observation
                )
                if not bounded or first_php_object_snapshot is None:
                    result.reject(
                        bounded_reason
                        if not bounded
                        else "trusted PHP object run lacks parent attestation"
                    )
            live_result_observation = _consume_php_include_live_observation(
                result,
                php_include_expected=php_include_expected,
            )
            attempt = PoCAttempt(
                iteration=iteration,
                phase="attack",
                proof_kind=(
                    "php_object_primitive" if php_object_expected else "standard"
                ),
                script_path=str(script_path),
                result=PoCStatus.SUCCESS if result.success else PoCStatus.FAILED,
                http_status=result.http_status,
                response_snippet=_attempt_response_snippet(result),
                timing_seconds=result.elapsed,
                error_log_snippet=_attempt_error_log_snippet(result),
                developer_analysis=None,  # PoC author re-evaluates with consult_developer in next iter
                observation=result.observation,
                rejected_observation=result.rejected_observation,
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
                    result.reject(reason[:1000])
                    attempt.mark_failed(reason[:1000])
                    attempt.developer_analysis = reason[:1000]
                    _checkpoint_attempts()
                    logger.warning(
                        "verify: %s rejected tainted setup confirmation", hyp.id
                    )
                    if pre_attempt_snapshot is not None:
                        await _restore_attempt_state(pre_attempt_snapshot)
                        shutil.rmtree(pre_attempt_snapshot, ignore_errors=True)
                    live_result_observation = None
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
                    expected_php_include=php_include_expected,
                    expected_php_object=php_object_expected,
                    expected_php_object_transport=php_object_http_transport,
                    expected_executable_upload=executable_upload_expected,
                )
                confirmation_php_object_snapshot = _consume_php_object_snapshot(
                    confirm,
                    php_object_expected=php_object_expected,
                )
                if confirm.success and php_object_expected:
                    bounded, bounded_reason = _bounded_php_object_observation(
                        confirm.observation
                    )
                    if not bounded or confirmation_php_object_snapshot is None:
                        confirm.reject(
                            bounded_reason
                            if not bounded
                            else "trusted PHP object replay lacks parent attestation"
                        )
                live_confirmation_observation = _consume_php_include_live_observation(
                    confirm,
                    php_include_expected=php_include_expected,
                )
                confirmation_attempt = PoCAttempt(
                    iteration=iteration,
                    phase="confirmation",
                    proof_kind=(
                        "php_object_primitive"
                        if php_object_expected
                        else "standard"
                    ),
                    script_path=str(script_path),
                    result=PoCStatus.SUCCESS if confirm.success else PoCStatus.FAILED,
                    http_status=confirm.http_status,
                    response_snippet=_attempt_response_snippet(confirm),
                    timing_seconds=confirm.elapsed,
                    error_log_snippet=_attempt_error_log_snippet(confirm),
                    observation=confirm.observation,
                    rejected_observation=confirm.rejected_observation,
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
                if (
                    live_result_observation is not None
                    and live_confirmation_observation is not None
                ):
                    matching_confirmation, confirmation_reason = (
                        validate_confirmation_observations(
                            live_result_observation,
                            live_confirmation_observation,
                        )
                    )
                    if matching_confirmation and php_object_expected:
                        matching_confirmation, confirmation_reason = (
                            _validate_php_object_confirmation_snapshots(
                                first_php_object_snapshot,
                                confirmation_php_object_snapshot,
                            )
                        )
                live_result_observation = None
                live_confirmation_observation = None
                if confirm.success and matching_confirmation:
                    attempts.append(confirmation_attempt)
                    _checkpoint_attempts()
                    if php_object_expected:
                        primitive_evidence = {
                            "first_run": result.evidence,
                            "confirmation_run": confirm.evidence,
                            "clean_state_restored": True,
                        }
                        if (
                            not php_object_natural_expected
                            or php_object_gadget_recipe is None
                            or php_object_http_transport is None
                        ):
                            php_object_natural_failure_reason = (
                                "The verifier cannot reproduce a source-bound natural "
                                "gadget because the candidate has no validated "
                                "direct-path recipe; only the inert object-instantiation "
                                "primitive was reproduced."
                            )
                            last_evidence = primitive_evidence
                            shutil.rmtree(pre_attempt_snapshot, ignore_errors=True)
                            break

                        try:
                            natural_replay = await _run_php_object_natural_replay(
                                sb,
                                script_path=script_path,
                                recipe=php_object_gadget_recipe,
                                expected_bug_class=expected_bug_class,
                                attacker_role=normalized_role,
                                transport=php_object_http_transport,
                                pre_attempt_snapshot=pre_attempt_snapshot,
                                restore_attempt_state=_restore_attempt_state,
                            )
                        except Exception:
                            shutil.rmtree(pre_attempt_snapshot, ignore_errors=True)
                            raise

                        natural_first_attempt = _php_object_natural_attempt(
                            natural_replay.first_result,
                            iteration=iteration,
                            phase="attack",
                            script_path=script_path,
                        )
                        natural_confirmation_attempt = (
                            _php_object_natural_attempt(
                                natural_replay.confirmation_result,
                                iteration=iteration,
                                phase="confirmation",
                                script_path=script_path,
                            )
                            if natural_replay.confirmation_result is not None
                            else None
                        )
                        if not natural_replay.confirmed:
                            php_object_natural_failure_reason = (
                                natural_replay.reason[:1000]
                            )
                            attempts.append(natural_first_attempt)
                            if natural_confirmation_attempt is not None:
                                attempts.append(natural_confirmation_attempt)
                            last_evidence = primitive_evidence
                            _checkpoint_attempts()
                            shutil.rmtree(pre_attempt_snapshot, ignore_errors=True)
                            break

                        if (
                            natural_replay.first_snapshot is None
                            or natural_replay.confirmation_snapshot is None
                            or natural_replay.confirmation_result is None
                            or natural_confirmation_attempt is None
                        ):
                            shutil.rmtree(pre_attempt_snapshot, ignore_errors=True)
                            raise RuntimeError(
                                "confirmed natural PHP object replay lacks evidence"
                            )
                        attempts.extend(
                            [natural_first_attempt, natural_confirmation_attempt]
                        )
                        php_object_natural_confirmation = (
                            _php_object_natural_confirmation_payload(
                                hyp,
                                natural_replay.first_snapshot,
                                natural_replay.confirmation_snapshot,
                            )
                        )
                        last_evidence = {
                            "first_run": natural_replay.first_result.evidence,
                            "confirmation_run": (
                                natural_replay.confirmation_result.evidence
                            ),
                            "primitive_confirmation_runs": primitive_evidence,
                            "php_object_natural_confirmation": (
                                php_object_natural_confirmation
                            ),
                            "clean_state_restored": True,
                        }
                        _checkpoint_attempts()
                        shutil.rmtree(pre_attempt_snapshot, ignore_errors=True)
                        if config.report.screenshot_capture:
                            screenshot_dir = poc_dir / "screenshots"
                            await verify_helpers.screenshot_url(
                                sb.target_url + "/wp-admin/",
                                screenshot_dir / f"{hyp.id}_admin.png",
                                timeout_s=verify_cfg.headless_browser_timeout_s,
                            )
                        break

                    current_evidence = {
                        "first_run": result.evidence,
                        "confirmation_run": confirm.evidence,
                        "clean_state_restored": True,
                    }
                    confirmed_evidence_by_script[str(script_path)] = current_evidence
                    last_evidence = current_evidence
                    confirmed_observation = confirmation_attempt.observation
                    if confirmed_observation is None:
                        raise RuntimeError(
                            "successful confirmation lacks a structured observation"
                        )
                    full_compromise_gaps = (
                        _full_compromise_gaps(confirmed_observation.impact)
                        if seek_full_compromise
                        else {}
                    )
                    if (
                        full_compromise_gaps
                        and verified_partial_proof is None
                        and iteration < config.verify_max_iterations
                    ):
                        verified_partial_proof = {
                            "status": "confirmed_lower_bound",
                            "confirmation_iteration": iteration,
                            "oracle": confirmed_observation.oracle,
                            "verified_impact": confirmed_observation.impact.model_dump(
                                mode="json"
                            ),
                            "target_impact": {
                                "confidentiality": "high",
                                "integrity": "high",
                                "availability": "high",
                            },
                            "unmet_dimensions": full_compromise_gaps,
                        }
                        await _restore_attempt_state(pre_attempt_snapshot)
                        shutil.rmtree(pre_attempt_snapshot, ignore_errors=True)
                        logger.info(
                            "verify: %s iter %d confirmed a lower-bound %s proof; "
                            "retaining it and authoring one full-compromise refinement",
                            hyp.id,
                            iteration,
                            confirmed_observation.oracle,
                        )
                        continue
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
                    confirm.reject(confirmation_reason)
                    confirmation_attempt.mark_failed(confirmation_reason)
                elif not confirmation_attempt.validation_reason:
                    confirmation_attempt.validation_reason = (
                        "clean-state confirmation oracle did not reproduce"
                    )
                first_run_rejection = (
                    "clean-state confirmation failed: "
                    + (confirm.validation_reason or "oracle did not reproduce")
                )
                result.reject(first_run_rejection)
                attempt.mark_failed(first_run_rejection)
                attempt.developer_analysis = (attempt.validation_reason or "")[:1000]
                attempts.append(confirmation_attempt)
                _checkpoint_attempts()
                result = confirm
                await _restore_attempt_state(pre_attempt_snapshot)
                shutil.rmtree(pre_attempt_snapshot, ignore_errors=True)
            else:
                live_result_observation = None
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
                    last_stdout=_runner_failure_feedback(result),
                    last_stderr=_runner_failure_error_feedback(result),
                    last_error_log=_runner_failure_error_feedback(result),
                    schema_diagnostics=diagnostics,
                    setup_execution_feedback=_authoritative_setup_feedback(),
                )
                poc_crashed = _poc_failure_looks_like_code_error(result)
                if _should_replay_poc_after_setup(
                    result,
                    followup,
                    _followup_rounds,
                    replaying_setup_repair=replaying_setup_repair,
                ):
                    replay_script_after_setup = script
                    logger.info(
                        "verify: %s iter %d committed setup repair; scheduling one "
                        "unchanged PoC replay",
                        hyp.id,
                        iteration,
                    )
                elif followup is not None and not followup.commands:
                    # No setup change is needed, but a failed generated request is not proof
                    # that the source candidate is safe. Give the PoC author the diagnosis
                    # and continue within the configured iteration bound.
                    fc = followup.failure_class
                    classification = (
                        "poc_code" if poc_crashed else (fc or "exploit_shape")
                    )
                    if attempt.rejected_observation is not None:
                        attempt.developer_analysis = (
                            "UNTRUSTED DEVELOPER CLASSIFICATION ONLY; the runner "
                            "failure remains authoritative: "
                            f"classification={classification}; model rationale "
                            "withheld after rejected child observation"
                        )[:1000]
                    else:
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

            if (
                verified_partial_proof is not None
                and replay_script_after_setup is None
            ):
                logger.info(
                    "verify: %s full-compromise refinement did not confirm a "
                    "stronger proof; retaining the confirmed lower bound",
                    hyp.id,
                )
                break

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
    if php_object_expected:
        successful_primitive = [
            attempt
            for attempt in successful
            if attempt.proof_kind == "php_object_primitive"
        ]
        primitive_confirmations = [
            attempt
            for attempt in successful_primitive
            if attempt.phase == "confirmation"
        ]
        if not primitive_confirmations:
            _checkpoint_attempts(status="not_confirmed")
            logger.info(
                "verify: %s NOT confirmed after %d attempts",
                hyp.id,
                len(attempts),
            )
            return None
        primitive_observation = primitive_confirmations[-1].observation
        if primitive_observation is None:
            raise RuntimeError(
                "successful PHP object primitive confirmation lacks an observation"
            )
        successful_natural = [
            attempt
            for attempt in successful
            if attempt.proof_kind == "php_object_natural"
        ]
        confirmations = [
            attempt
            for attempt in successful_natural
            if attempt.phase == "confirmation"
        ]
        natural_promoted = php_object_natural_confirmation is not None
        proof_gap = (hyp.evidence_summary or {}).get("proof_gaps")
        unmet_requirement = (
            None
            if natural_promoted
            else (
                proof_gap.strip()
                if isinstance(proof_gap, str) and proof_gap.strip()
                else (
                    "Trusted reproduction of the source-reviewed natural gadget's "
                    "concrete side effect."
                )
            )
        )
        reason = (
            "Two clean trusted executions confirmed the PHP object-instantiation "
            "primitive, and two clean parent-attested executions reproduced the "
            "source-bound direct-path natural gadget."
            if natural_promoted
            else (
                php_object_natural_failure_reason
                or (
                    "Two clean trusted executions confirmed only the PHP object "
                    "instantiation primitive; the source-bound direct-path natural "
                    "gadget was not reproduced twice from clean state."
                )
            )
        )
        php_object_primitive_confirmation = {
            "schema_version": 1,
            "status": "primitive_confirmed",
            "hypothesis_id": hyp.id,
            "bug_class": hyp.bug_class.value,
            "finding_promoted": natural_promoted,
            "promotion_policy": (
                "source_bound_natural_gadget_v1" if natural_promoted else None
            ),
            "source_gadget_reviewed": True,
            "clean_state_executions": len(successful_primitive),
            "oracle_observation": primitive_observation.impact.model_dump(
                mode="json"
            ),
            "source_reviewed_outcome": hyp.security_outcome.model_dump(mode="json"),
            "unmet_proof_requirement": unmet_requirement,
            "reason": reason,
        }
        if not natural_promoted:
            atomic_write_json(
                poc_dir / PHP_OBJECT_PRIMITIVE_CONFIRMATION_FILENAME,
                php_object_primitive_confirmation,
            )
            _checkpoint_attempts(status="primitive_confirmed")
            logger.info("verify: %s primitive confirmed but not promoted", hyp.id)
            return None
        if not confirmations:
            raise RuntimeError(
                "natural PHP object confirmation artifact lacks a successful replay"
            )
    else:
        confirmations = [
            attempt for attempt in successful if attempt.phase == "confirmation"
        ]
        if not confirmations:
            _checkpoint_attempts(status="not_confirmed")
            logger.info(
                "verify: %s NOT confirmed after %d iterations", hyp.id, len(attempts)
            )
            return None

    selected_confirmation = (
        confirmations[-1]
        if php_object_expected
        else _select_strongest_confirmation(confirmations)
    )
    confirmed_observation = selected_confirmation.observation
    if confirmed_observation is None:
        raise RuntimeError("successful confirmation lacks a structured observation")
    if not php_object_expected:
        last_evidence = confirmed_evidence_by_script.get(
            selected_confirmation.script_path,
            last_evidence,
        )
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
        poc_script_path=selected_confirmation.script_path,
        poc_attempts=attempts,
        evidence=last_evidence,
        confidence_runs=2,
        verified_impact=confirmed_observation.impact.model_copy(deep=True),
        dedup_status=DedupStatus.NOT_CHECKED,
        dedup_matches=[],
    )

    if php_object_expected:
        accepted, reason = validate_php_object_natural_finding_confirmation(finding)
        if not accepted:
            raise RuntimeError(
                "constructed CWE-502 finding failed its promotion gate: " + reason
            )
        if (
            php_object_primitive_confirmation is None
            or php_object_natural_confirmation is None
        ):
            raise RuntimeError("confirmed CWE-502 finding lacks promotion artifacts")
        atomic_write_json(
            poc_dir / PHP_OBJECT_PRIMITIVE_CONFIRMATION_FILENAME,
            php_object_primitive_confirmation,
        )
        atomic_write_json(
            poc_dir / PHP_OBJECT_NATURAL_CONFIRMATION_FILENAME,
            php_object_natural_confirmation,
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
    if status not in {
        "in_progress",
        "not_confirmed",
        "primitive_confirmed",
        "confirmed",
    }:
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
    if status == "primitive_confirmed":
        successful_primitive = [
            attempt
            for attempt in parsed_attempts
            if attempt.result == PoCStatus.SUCCESS
            and attempt.proof_kind == "php_object_primitive"
        ]
        primitive_by_phase = {
            attempt.phase: attempt for attempt in successful_primitive
        }
        if (
            len(successful_primitive) != 2
            or set(primitive_by_phase) != {"attack", "confirmation"}
            or len({attempt.script_path for attempt in successful_primitive}) != 1
            or any(
                not _bounded_php_object_observation(attempt.observation)[0]
                for attempt in successful_primitive
            )
            or any(
                attempt.proof_kind == "standard" for attempt in parsed_attempts
            )
            or any(
                attempt.result == PoCStatus.SUCCESS
                and attempt.proof_kind == "php_object_natural"
                and attempt.phase == "confirmation"
                for attempt in parsed_attempts
            )
            or (hyp_dir / PHP_OBJECT_NATURAL_CONFIRMATION_FILENAME).exists()
        ):
            return "incomplete"
        primitive_confirmation_observation = primitive_by_phase[
            "confirmation"
        ].observation
        if primitive_confirmation_observation is None:
            return "incomplete"
        primitive_path = hyp_dir / PHP_OBJECT_PRIMITIVE_CONFIRMATION_FILENAME
        try:
            primitive = json.loads(primitive_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return "incomplete"
        if not (
            isinstance(primitive, dict)
            and primitive.get("schema_version") == 1
            and primitive.get("status") == "primitive_confirmed"
            and primitive.get("hypothesis_id") == hyp_dir.name
            and primitive.get("bug_class") == BugClass.PHP_OBJECT_INJECTION.value
            and primitive.get("finding_promoted") is False
            and primitive.get("promotion_policy") is None
            and primitive.get("source_gadget_reviewed") is True
            and type(primitive.get("clean_state_executions")) is int
            and primitive.get("clean_state_executions") == 2
            and primitive.get("oracle_observation")
            == primitive_confirmation_observation.impact.model_dump(
                mode="json"
            )
            and isinstance(primitive.get("reason"), str)
            and bool(primitive["reason"].strip())
        ):
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
        unproven_php_object_findings: list[Finding] = []
        for f in parsed:
            if f.hypothesis.id not in accepted_hypothesis_ids:
                continue
            if not f.hypothesis.bug_class.is_known:
                continue
            if f.hypothesis.bug_class == BugClass.PHP_OBJECT_INJECTION:
                accepted, _reason = (
                    validate_php_object_natural_finding_confirmation(f)
                )
                if not accepted:
                    unproven_php_object_findings.append(f)
                    continue
            previously_confirmed[f.hypothesis.id] = f
        if unproven_php_object_findings:
            quarantine_path = run_dir / "findings_php_object_unproven.jsonl"
            atomic_write_jsonl(quarantine_path, unproven_php_object_findings)
            logger.warning(
                "verify: quarantined %d prior CWE-502 finding(s) without a "
                "complete direct-path natural proof to %s",
                len(unproven_php_object_findings),
                quarantine_path,
            )
            append_decision(
                run_dir,
                stage="verify",
                action="recover",
                result="php_object_findings_quarantined",
                reason=(
                    f"{len(unproven_php_object_findings)} prior CWE-502 finding(s) "
                    "lacked the complete parent-attested direct-path proof"
                ),
                artifact=quarantine_path,
                details={
                    "hypothesis_ids": [
                        finding.hypothesis.id
                        for finding in unproven_php_object_findings
                    ]
                },
            )
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
    persistent_hypotheses = [
        hypothesis
        for hypothesis in automatic_hypotheses
        if not _php_object_gadget_oracle_enabled_for_hypotheses(
            [hypothesis],
            plugin_path,
            triaged.plugin_slug,
        )
    ]
    if config.verify.persistent_sandbox and persistent_hypotheses:
        try:
            persistent_sb = SandboxManager(
                config.sandbox,
                boot_timeout_s=max(config.sandbox_timeout_seconds, 180),
                poc_timeout_s=config.sandbox_timeout_seconds,
                ssrf_oracle_modes=_ssrf_oracle_modes_for_hypotheses(
                    persistent_hypotheses
                ),
                php_include_oracle_enabled=(
                    _php_include_oracle_enabled_for_hypotheses(
                        persistent_hypotheses,
                        plugin_path,
                        triaged.plugin_slug,
                    )
                ),
                php_object_oracle_enabled=(
                    _php_object_oracle_enabled_for_hypotheses(
                        persistent_hypotheses,
                        plugin_path,
                        triaged.plugin_slug,
                    )
                ),
                # Natural gadgets require an exact, recipe-specific constant set
                # and TMPDIR. Keep the ordinary shared sandbox unchanged; the
                # candidate loop gives each promotable recipe a fresh sandbox.
                php_object_gadget_oracle_enabled=False,
                php_object_gadget_directory_constants=frozenset(),
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
            terminal_not_confirmed = checkpoint_state in {
                None,
                "not_confirmed",
                "primitive_confirmed",
            }
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

            dedicated_natural_sandbox = (
                _php_object_gadget_oracle_enabled_for_hypotheses(
                    [hyp],
                    plugin_path,
                    triaged.plugin_slug,
                )
            )
            if dedicated_natural_sandbox:
                logger.info(
                    "verify: %s — using a dedicated recipe-bound natural-gadget "
                    "sandbox",
                    hyp.id,
                )

            # Restore baseline before each hypothesis to prevent state leakage.
            if (
                not dedicated_natural_sandbox
                and persistent_sb is not None
                and persistent_snapshot is not None
            ):
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
                    persistent_sb=(
                        None if dedicated_natural_sandbox else persistent_sb
                    ),
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
                primitive_confirmation = (
                    hyp_dir / PHP_OBJECT_PRIMITIVE_CONFIRMATION_FILENAME
                )
                primitive_confirmed = primitive_confirmation.is_file()
                append_decision(
                    run_dir,
                    stage="verify",
                    action="reject",
                    result=(
                        "primitive_confirmed_not_promoted"
                        if primitive_confirmed
                        else "not_confirmed"
                    ),
                    hypothesis_id=hyp.id,
                    artifact=(
                        primitive_confirmation if primitive_confirmed else hyp_dir
                    ),
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
