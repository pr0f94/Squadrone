"""Stage-7 report helpers."""

from __future__ import annotations

import logging

from ..schemas.finding import Finding

logger = logging.getLogger(__name__)


# ---------- R2: submission readiness gate -------------------------------------------

def check_submission_readiness(finding: Finding) -> tuple[bool, dict]:
    """Return (is_ready, checklist_dict). Each checklist entry is True/False/"N/A".

    Conservative — defaults to "N/A" for upstream-stage flags that may not have run
    when the corresponding toggle is off. Triage-stage / specialist-stage info that
    isn't on the Finding is treated as "N/A" rather than False (since absence ≠ failure).
    """
    h = finding.hypothesis
    checklist: dict = {
        "verifier_kept": True,  # by definition — the finding survived verifier+triage
        "triage_accepted": True,  # by definition
        "verify_poc_confirmed": finding.poc_status.value in ("success", "partial"),
        "dedup_classification_set": finding.dedup_status is not None,
        "specialist_self_classification_set": h.exploit_classification is not None,
        "cvss_estimate_set": finding.cvss_estimate is not None,
        "submission_recommendation_set": finding.submission_recommendation is not None,
    }
    # Determine "ready". Required for submission:
    # - PoC actually confirmed (not FP, not partial-only-with-no-evidence)
    # - dedup status resolved (any of NOVEL/POSSIBLY_KNOWN — KNOWN_DUPE never reaches here)
    is_ready = (
        checklist["verify_poc_confirmed"]
        and checklist["dedup_classification_set"]
    )
    return is_ready, checklist


def render_not_ready_md(finding: Finding, checklist: dict) -> str:
    """When R2 fails, emit a report_<id>_<program>_NOT_READY.md with what's missing."""
    h = finding.hypothesis
    lines = [
        f"# NOT READY for submission: {finding.id}",
        "",
        "This finding did not pass the submission_readiness_gate (R2). The polished",
        "report was NOT generated. Inspect the checklist below and rectify any item",
        "that should be ✓ but is ✗ before re-running with `squadrone scan --resume`.",
        "",
        f"- **bug class:** {h.bug_class.value}",
        f"- **file:** {h.file}:{h.line}",
        f"- **sink:** `{h.sink[:200]}`",
        f"- **dedup:** {finding.dedup_status.value}",
        f"- **submission_recommendation:** {finding.submission_recommendation or '(unset)'}",
        "",
        "## Readiness checklist",
        "",
    ]
    for k, v in checklist.items():
        glyph = "✓" if v is True else ("✗" if v is False else "N/A")
        lines.append(f"- {glyph} `{k}`")
    return "\n".join(lines) + "\n"
