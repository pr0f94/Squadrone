"""Finding artifact schema."""

from __future__ import annotations

from enum import Enum
from typing import Literal, Optional

from pydantic import model_validator

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


def _strip_rejected_result_lines(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    cleaned = "\n".join(
        line for line in value.splitlines() if "SQUADRONE_RESULT=" not in line
    ).strip()
    return cleaned or None


class PoCAttempt(JSONFileMixin):
    iteration: int
    phase: Literal["attack", "confirmation"] = "attack"
    # Distinguish ordinary family proofs from the two bounded phases used for
    # PHP object injection.  The default keeps historical artifacts readable.
    proof_kind: Literal[
        "standard",
        "php_object_primitive",
        "php_object_natural",
    ] = "standard"
    script_path: str
    result: PoCStatus
    http_status: Optional[int] = None
    response_snippet: Optional[str] = None
    timing_seconds: Optional[float] = None
    error_log_snippet: Optional[str] = None
    developer_analysis: Optional[str] = None
    # Only an observation accepted by the runner belongs in ``observation``.
    # Preserve a child's rejected self-report separately for debugging so a
    # failed trusted-oracle run cannot serialize ``verdict=vulnerable`` as if
    # it were established evidence.
    observation: Optional[PoCObservation] = None
    rejected_observation: Optional[PoCObservation] = None
    validation_reason: Optional[str] = None

    @model_validator(mode="after")
    def _separate_rejected_observation(self) -> "PoCAttempt":
        """Normalize new and historical attempts to runner-trust precedence."""
        if self.result == PoCStatus.SUCCESS:
            if self.rejected_observation is not None:
                raise ValueError(
                    "successful PoC attempt cannot contain a rejected observation"
                )
            return self

        if self.observation is not None:
            if (
                self.rejected_observation is not None
                and self.rejected_observation != self.observation
            ):
                raise ValueError(
                    "failed PoC attempt contains conflicting rejected observations"
                )
            self.rejected_observation = self.observation
            self.observation = None
        if self.rejected_observation is not None:
            # Snippets are already bounded before persistence and may begin in
            # the middle of a long machine-result line.  Once the parent has
            # rejected that result, no fragment of the child's claimed success
            # is useful enough to retain as if it were ordinary diagnostics.
            self.response_snippet = None
            self.error_log_snippet = None
            self.developer_analysis = None
        else:
            self.response_snippet = _strip_rejected_result_lines(self.response_snippet)
            self.error_log_snippet = _strip_rejected_result_lines(
                self.error_log_snippet
            )
        return self

    def mark_failed(self, validation_reason: str) -> None:
        """Apply an authoritative rejection after an initially accepted run."""
        self.result = PoCStatus.FAILED
        if self.observation is not None:
            self.rejected_observation = self.observation
            self.observation = None
        if self.rejected_observation is not None:
            self.response_snippet = None
            self.error_log_snippet = None
            self.developer_analysis = None
        else:
            self.response_snippet = _strip_rejected_result_lines(self.response_snippet)
            self.error_log_snippet = _strip_rejected_result_lines(
                self.error_log_snippet
            )
        self.validation_reason = validation_reason


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
