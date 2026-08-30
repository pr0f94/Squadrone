"""Finding artifact schema."""

from __future__ import annotations

from enum import Enum
from typing import Literal, Optional

from ._base import JSONFileMixin
from .hypothesis import Hypothesis
from .observation import CIAImpact, PoCObservation


class PoCStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    # Retained only so historical run artifacts can still be loaded. New
    # verification code never emits or accepts PARTIAL as a finding.
    PARTIAL = "partial"


class DedupStatus(str, Enum):
    NOT_CHECKED = "not_checked"
    NOVEL = "novel"
    POSSIBLY_KNOWN = "possibly_known"
    KNOWN_DUPE = "known_dupe"


class PoCAttempt(JSONFileMixin):
    iteration: int
    phase: Literal["attack", "confirmation"] = "attack"
    script_path: str
    result: PoCStatus
    http_status: Optional[int] = None
    response_snippet: Optional[str] = None
    timing_seconds: Optional[float] = None
    error_log_snippet: Optional[str] = None
    developer_analysis: Optional[str] = None
    observation: Optional[PoCObservation] = None
    validation_reason: Optional[str] = None


class Finding(JSONFileMixin):
    id: str
    hypothesis: Hypothesis
    poc_status: PoCStatus
    poc_script_path: str
    poc_attempts: list[PoCAttempt]
    evidence: dict
    confidence_runs: int
    dedup_status: DedupStatus
    dedup_matches: list[dict]
    # Authoritative CIA impact reproduced by the clean confirmation run.  This
    # is deliberately separate from the source-review hypothesis: static review
    # may identify a broader possible outcome than the sandbox actually proved.
    # Optional so historical finding artifacts remain readable.
    verified_impact: Optional[CIAImpact] = None
    cvss_estimate: Optional[str] = None
    cvss_vector: Optional[str] = None
    suggested_fix: Optional[str] = None
    # Structured next-action derived after deduplication.
    # One of: submit_as_novel | submit_as_regression_of_<CVE> | skip_exact_dupe_of_<CVE> |
    #          submit_with_dedup_rebuttal | None
    submission_recommendation: Optional[str] = None
    submission_recommendation_reason: Optional[str] = None
