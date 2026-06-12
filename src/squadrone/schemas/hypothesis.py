"""Hypothesis + triage artifact schemas."""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Any

from pydantic import BeforeValidator

from ._base import JSONFileMixin


class BugClass(str, Enum):
    MISSING_CAP_CHECK = "CWE-862"
    MISSING_NONCE = "CWE-352"
    SQLI = "CWE-89"
    COMMAND_INJECTION = "CWE-78"
    PATH_TRAVERSAL = "CWE-22"
    ARBITRARY_FILE_WRITE = "CWE-434"
    SSRF = "CWE-918"
    XXE = "CWE-611"
    PHP_OBJECT_INJECTION = "CWE-502"
    XSS_REFLECTED = "CWE-79"
    XSS_STORED = "CWE-79"
    OPEN_REDIRECT = "CWE-601"
    IDOR = "CWE-639"
    WEAK_CRYPTO = "CWE-327"
    WEAK_PRNG = "CWE-338"
    MASS_ASSIGNMENT = "CWE-915"
    AUTH_BYPASS = "CWE-287"
    WEAK_PASSWORD_RECOVERY = "CWE-640"
    SESSION_FIXATION = "CWE-384"
    MISSING_RATE_LIMIT = "CWE-307"
    LOGIC_FLAW = "CWE-840"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


def _coerce_str(v: Any) -> Any:
    """LLMs sometimes return arrays where we ask for a single string — coerce."""
    if isinstance(v, list):
        return "; ".join(str(x) for x in v)
    return v


def _coerce_str_list(v: Any) -> Any:
    """Accept common scalar/list drift in model-produced path fields."""
    if isinstance(v, str):
        if "->" in v:
            return [part.strip() for part in v.split("->") if part.strip()]
        return [v]
    if isinstance(v, list):
        coerced: list[str] = []
        for item in v:
            if isinstance(item, str):
                coerced.append(item)
            elif isinstance(item, dict) and isinstance(item.get("step"), str):
                coerced.append(item["step"])
            else:
                coerced.append(str(item))
        return coerced
    return v


def _coerce_lower_str(v: Any) -> Any:
    if isinstance(v, str):
        return v.lower()
    return v


_StrLike = Annotated[str, BeforeValidator(_coerce_str)]
_StrListLike = Annotated[list[str], BeforeValidator(_coerce_str_list)]
_ConfidenceLike = Annotated[Confidence, BeforeValidator(_coerce_lower_str)]


class Hypothesis(JSONFileMixin):
    id: str
    specialist: str
    bug_class: BugClass
    entry_point: str
    file: str
    line: int
    sink: _StrLike
    sink_code: _StrLike = ""  # Verbatim source line(s) of the sink. Empty = legacy hypothesis.
    taint_path: _StrListLike
    reasoning: _StrLike
    confidence: _ConfidenceLike
    preconditions: _StrLike
    affected_versions: _StrLike
    # Populated by the triage stage. Empty for hypotheses produced before scope filtering ran;
    # may contain "wordfence", "patchstack", or both. Routing/report stages should respect this.
    bounty_programs: list[str] = []
    # Stage 3 opt-in additions (S3, S4, S5, S7). All None / empty when toggles off.
    taint_path_branches: list[list[str]] = []   # S3: alternate taint branches from same entry to sink
    exploit_classification: dict | None = None  # S4: {type, secondary_primitive_required?, config_required?, realistic_in_default_install?}
    bounty_fit: dict | None = None              # S5: {wordfence_tier, wordfence_install_floor_satisfied, patchstack_cvss_estimate, patchstack_floor_satisfied, realistic_payout_likelihood}
    requires_verification: bool = False         # S7: specialist self-flagged "claim I can't fully cite"
    # Populated by the optional chain stage (--chain). Empty when the stage didn't run.
    chains_with: list[str] = []                 # IDs of other hypotheses that combine with this one
    chain_impact: str | None = None             # human-readable combined impact (e.g. "Subscriber→RCE via auth-bypass + file-write")
    chain_severity_bump: str | None = None      # severity delta from chaining (e.g. "medium→critical")
    # Populated by optional quality gates. These fields are additive metadata only.
    evidence_summary: dict[str, Any] = {}        # source/sink/role/guard fields inferred for triage/reporting
    quality_gate: dict[str, Any] = {}            # rule decisions, warnings, and submit-worthiness notes
    derived_severity: dict[str, Any] = {}        # deterministic severity/CVSS approximation


class HypothesesArtifact(JSONFileMixin):
    plugin_slug: str
    hypotheses: list[Hypothesis]


class TriagedArtifact(JSONFileMixin):
    plugin_slug: str
    accepted: list[Hypothesis]
    rejected: list[dict]
    merged: list[dict]
    # Candidates that are source-grounded enough to preserve but not strong enough
    # for automatic verification/reporting. These are emitted to the manual queue.
    manual_review: list[dict] = []
    # T4: optional list of hypotheses where the critic suggests re-framing rather than accept/reject.
    # Each entry: {"hypothesis_id": str, "suggested_framing": str, "reason_original_rejected": str}
    request_reframing: list[dict] = []
