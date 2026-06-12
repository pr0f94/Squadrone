"""Dedup stage — compare findings against Wordfence + WPScan vuln DBs."""

from __future__ import annotations

import logging
from pathlib import Path

from ..schemas.config import PipelineConfig
from ..schemas.finding import DedupStatus, Finding
from ..services import dedup_helpers
from ..services.decision_ledger import append_decision
from ..services.vuln_db import VulnDBClient, VulnMatch

logger = logging.getLogger(__name__)


def _classify_legacy(finding: Finding, known: list[VulnMatch]) -> tuple[DedupStatus, list[dict]]:
    """Original (pre-stage-6) classifier — uniform 1.0 scoring with title-substring strong-signal."""
    cwe = finding.hypothesis.bug_class.value
    matches: list[VulnMatch] = []
    strong = False
    sink = (finding.hypothesis.sink or "").lower()
    handler = (finding.hypothesis.entry_point or "").lower()
    for k in known:
        if not k.bug_class or k.bug_class != cwe:
            continue
        matches.append(k)
        title_l = (k.title or "").lower()
        if (sink and sink in title_l) or (handler and handler in title_l):
            strong = True

    if not matches:
        return DedupStatus.NOVEL, []
    match_dicts = [m.model_dump() for m in matches]
    return (DedupStatus.KNOWN_DUPE if strong else DedupStatus.POSSIBLY_KNOWN, match_dicts)


def _classify_scored(
    finding: Finding,
    known: list[VulnMatch],
    scanned_version: str,
) -> tuple[DedupStatus, list[dict]]:
    """D1: meaningful per-match similarity scoring, sorted high→low.

    Status thresholds:
    - top_score >= 0.95 → KNOWN_DUPE
    - any matches      → POSSIBLY_KNOWN
    - no matches       → NOVEL
    """
    cwe = finding.hypothesis.bug_class.value
    sink = finding.hypothesis.sink or ""
    handler = finding.hypothesis.entry_point or ""
    file_ = finding.hypothesis.file or ""

    scored: list[tuple[float, VulnMatch]] = []
    for k in known:
        if not k.bug_class or k.bug_class != cwe:
            continue
        s = dedup_helpers.score_match(k, cwe, sink, handler, file_, scanned_version)
        if s > 0:
            scored.append((s, k))

    if not scored:
        return DedupStatus.NOVEL, []

    scored.sort(key=lambda t: t[0], reverse=True)
    match_dicts: list[dict] = []
    for s, k in scored:
        d = k.model_dump()
        d["similarity_score"] = s  # override the static 1.0
        match_dicts.append(d)

    top = scored[0][0]
    if top >= 0.95:
        return DedupStatus.KNOWN_DUPE, match_dicts
    return DedupStatus.POSSIBLY_KNOWN, match_dicts


async def run(
    findings: list[Finding],
    plugin_slug: str,
    config: PipelineConfig,
    runs_root: str = "runs",
    run_id: str = "",
) -> list[Finding]:
    if not findings:
        logger.info("dedup: no findings to classify")
        return findings

    cfg = config.dedup

    db = VulnDBClient()
    known = await db.lookup_all(plugin_slug)
    logger.info("dedup: %d known vulns from DBs", len(known))

    # D5: parse plugins/<slug>/review.md once for all findings
    review_signals = (
        dedup_helpers.parse_review_md_signals(plugin_slug)
        if cfg.review_md_signal else {}
    )
    if review_signals:
        logger.info("dedup: D5 review.md loaded — fp_keywords=%d confirmed_keywords=%d",
                    len(review_signals.get("fp_keywords", set())),
                    len(review_signals.get("confirmed_keywords", set())))

    # Determine scanned plugin version (for D1 version-range alignment)
    scanned_version = ""
    try:
        from ..schemas.intake import IntakeArtifact
        intake_path = Path(runs_root) / run_id / "intake.json"
        if intake_path.exists():
            scanned_version = IntakeArtifact.from_json_file(str(intake_path)).plugin_version
    except Exception:
        pass

    for f in findings:
        if cfg.meaningful_scoring:
            status, matches = _classify_scored(f, known, scanned_version)
        else:
            status, matches = _classify_legacy(f, known)
        f.dedup_status = status
        f.dedup_matches = matches

        # D5: per-finding local review signal
        local_signal: str | None = None
        if cfg.review_md_signal and review_signals:
            local_signal = dedup_helpers.local_review_signal_for_finding(
                review_signals,
                finding_sink=f.hypothesis.sink or "",
                finding_file=f.hypothesis.file or "",
                finding_handler=f.hypothesis.entry_point or "",
            )
            if local_signal:
                logger.info("dedup: %s — D5 local signal: %s", f.id, local_signal)

        # D4: submission recommendation (combines D1 score + D5 signal)
        if cfg.submission_recommendation:
            rec, reason = dedup_helpers.derive_submission_recommendation(
                finding_dedup_status=status.value,
                scored_matches=matches,
                review_signal=local_signal,
            )
            f.submission_recommendation = rec
            f.submission_recommendation_reason = reason
            logger.info("dedup: %s — recommendation: %s", f.id, rec)

        logger.info("dedup: %s -> %s (matches=%d)", f.id, status.value, len(matches))
        append_decision(
            Path(runs_root) / run_id,
            stage="dedup",
            action="classify",
            result=status.value,
            hypothesis_id=f.hypothesis.id,
            finding_id=f.id,
            artifact=Path(runs_root) / run_id / "findings.jsonl",
            details={
                "matches": len(matches),
                "submission_recommendation": f.submission_recommendation,
                "submission_recommendation_reason": f.submission_recommendation_reason,
            },
        )

    findings_path = Path(runs_root) / run_id / "findings.jsonl"
    findings_path.parent.mkdir(parents=True, exist_ok=True)
    with findings_path.open("w") as fp:
        for x in findings:
            fp.write(x.model_dump_json() + "\n")
    return findings
