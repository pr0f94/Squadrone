"""Dedup stage — compare findings against Wordfence + WPScan vuln DBs."""

from __future__ import annotations

import logging
from pathlib import Path

from ..schemas.config import PipelineConfig
from ..schemas.finding import DedupStatus, Finding
from ..services import dedup_helpers
from ..services.artifacts import atomic_write_jsonl
from ..services.decision_ledger import append_decision
from ..services.vuln_db import VulnDBClient, VulnMatch

logger = logging.getLogger(__name__)


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

    db = VulnDBClient()
    known = await db.lookup_all(plugin_slug)
    logger.info("dedup: %d known vulns from DBs", len(known))

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
        status, matches = _classify_scored(f, known, scanned_version)
        f.dedup_status = status
        f.dedup_matches = matches

        rec, reason = dedup_helpers.derive_submission_recommendation(
            finding_dedup_status=status.value,
            scored_matches=matches,
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
    atomic_write_jsonl(findings_path, findings)
    return findings
