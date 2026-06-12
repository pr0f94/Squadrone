"""Stage-7 report helpers.

R2 — submission_readiness_gate: structured pre-flight checklist
R4 — PoC bundling: copy report + exploit + payload + setup-script into one folder
R7 — machine-readable submission JSON: pre-filled form-field payload per program
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

from ..schemas.finding import Finding
from .artifacts import atomic_write_json, atomic_write_text

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
        "specialist_bounty_fit_set": h.bounty_fit is not None,
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


# ---------- R4: submission bundle ----------------------------------------------------

def write_submission_bundle(
    finding: Finding,
    plugin_slug: str,
    plugins_root: Path,
    report_md: str,
    program: str,
    *,
    submission_json: dict | None = None,
    payload_files: list[Path] | None = None,
    screenshot_dir: Path | None = None,
) -> Path:
    """Write a polished submission bundle to plugins/<slug>/submissions/<finding_id>/.

    The bundle directory is created/overwritten. Paths copied:
    - report.md (or <program>_report.md)
    - exploit.py — copied from finding.poc_script_path
    - payload files — copied verbatim
    - screenshots/ — copied from W2/R5 capture dir if present
    - submission.json — R7 machine-readable form payload
    """
    bundle = plugins_root / plugin_slug / "submissions" / finding.id
    bundle.mkdir(parents=True, exist_ok=True)

    # Report (one per program when called repeatedly)
    report_name = f"{program}_report.md" if program else "report.md"
    atomic_write_text(bundle / report_name, report_md)

    # PoC script
    if finding.poc_script_path:
        src = Path(finding.poc_script_path)
        if src.exists():
            shutil.copy2(src, bundle / "exploit.py")
        # Helper modules in the same dir (e.g. xss_check.py)
        if src.parent.exists():
            for sib in src.parent.iterdir():
                if sib.is_file() and sib.suffix == ".py" and sib.name != src.name:
                    shutil.copy2(sib, bundle / sib.name)

    # Payload files (free-form; caller supplies)
    if payload_files:
        for pf in payload_files:
            if pf.exists():
                shutil.copy2(pf, bundle / pf.name)

    # Screenshots from R5 capture
    if screenshot_dir and screenshot_dir.exists():
        target = bundle / "screenshots"
        target.mkdir(exist_ok=True)
        for img in screenshot_dir.iterdir():
            if img.is_file() and img.suffix.lower() in (".png", ".jpg", ".jpeg", ".webp", ".mp4", ".mov"):
                shutil.copy2(img, target / img.name)

    # Submission JSON
    if submission_json is not None:
        suffix = f"_{program}" if program else ""
        atomic_write_json(bundle / f"submission{suffix}.json", submission_json)

    logger.info("report: bundle written → %s", bundle)
    return bundle


# ---------- R7: machine-readable submission JSON ------------------------------------

def build_submission_json(finding: Finding, plugin_slug: str, plugin_version: str | None,
                          program: str) -> dict:
    """Pre-fill the submission form payload for the target program.

    Wordfence and Patchstack have somewhat different field names; this maps our
    Finding into each program's expected shape. The output is a best-effort skeleton
    a human (or future scripted submitter) can finalise.
    """
    h = finding.hypothesis
    common = {
        "plugin_slug": plugin_slug,
        "plugin_version_tested": plugin_version or "",
        "vulnerability_type_cwe": h.bug_class.value,
        "auth_level": _infer_auth_level(h),
        "title": _build_title(h, plugin_slug),
        "summary": h.reasoning[:500] if h.reasoning else "",
        "affected_versions_operator": "<=",
        "affected_versions_value": plugin_version or "",
        "code_references": [
            f"https://plugins.trac.wordpress.org/browser/{plugin_slug}/tags/{plugin_version}/{h.file}#L{h.line}"
        ] if plugin_version else [],
        "suggested_fix": finding.suggested_fix or "",
        "cvss_estimate": finding.cvss_estimate or "",
        "dedup_status": finding.dedup_status.value,
        "dedup_top_match": (finding.dedup_matches[0] if finding.dedup_matches else None),
        "submission_recommendation": finding.submission_recommendation,
    }
    if program == "patchstack":
        return {
            **common,
            "_program": "patchstack",
            "patchstack_cvss_floor_satisfied": (h.bounty_fit or {}).get("patchstack_floor_satisfied"),
        }
    # Default to wordfence
    return {
        **common,
        "_program": "wordfence",
        "wordfence_tier": (h.bounty_fit or {}).get("wordfence_tier"),
    }


def _infer_auth_level(h) -> str:
    """Best-effort inference from hypothesis fields. Kept here rather than on Hypothesis
    because we may want to refine the heuristic without bumping the schema."""
    pre = (h.preconditions or "").lower()
    if "unauthenticated" in pre or "unauth" in pre or "anonymous" in pre:
        return "Unauthenticated"
    if "subscriber" in pre:
        return "Subscriber"
    if "contributor" in pre:
        return "Contributor"
    if "author" in pre:
        return "Author"
    if "editor" in pre:
        return "Editor"
    if "admin" in pre:
        return "Admin"
    return "Unknown"


def _build_title(h, plugin_slug: str) -> str:
    bug_class_short = {
        "CWE-862": "Missing Authorization",
        "CWE-352": "Cross-Site Request Forgery",
        "CWE-89": "SQL Injection",
        "CWE-79": "Cross-Site Scripting",
        "CWE-22": "Path Traversal",
        "CWE-434": "Arbitrary File Upload",
        "CWE-918": "Server-Side Request Forgery",
        "CWE-502": "PHP Object Injection",
    }.get(h.bug_class.value, h.bug_class.value)
    return f"{plugin_slug}: {bug_class_short} via {h.entry_point or h.file}"
