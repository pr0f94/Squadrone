"""Finding artifact schema."""

from __future__ import annotations

from enum import Enum
from typing import Optional

from ._base import JSONFileMixin
from .hypothesis import Hypothesis


class PoCStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"


class DedupStatus(str, Enum):
    NOVEL = "novel"
    POSSIBLY_KNOWN = "possibly_known"
    KNOWN_DUPE = "known_dupe"


class PoCAttempt(JSONFileMixin):
    iteration: int
    script_path: str
    result: PoCStatus
    http_status: Optional[int] = None
    response_snippet: Optional[str] = None
    timing_seconds: Optional[float] = None
    error_log_snippet: Optional[str] = None
    developer_analysis: Optional[str] = None


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
    cvss_estimate: Optional[str] = None
    suggested_fix: Optional[str] = None
    # Structured next-action derived after deduplication.
    # One of: submit_as_novel | submit_as_regression_of_<CVE> | skip_exact_dupe_of_<CVE> |
    #          submit_with_dedup_rebuttal | None
    submission_recommendation: Optional[str] = None
    submission_recommendation_reason: Optional[str] = None
