"""Dedup stage — compare findings against Wordfence + WPScan vuln DBs."""

from __future__ import annotations

import logging
from pathlib import Path

from ..schemas.config import PipelineConfig
from ..schemas.finding import DedupStatus, Finding
from ..services import dedup_helpers
from ..services.artifacts import atomic_write_jsonl
from ..services.decision_ledger import append_decision
from ..services.vuln_db import (
    VulnDBClient,
    VulnLookupResult,
    VulnMatch,
    VulnSourceResult,
    VulnSourceStatus,
)

logger = logging.getLogger(__name__)


class DedupSourceUnavailableError(RuntimeError):
    """The authoritative dedup source failed and no safe stored fallback exists."""

    def __init__(
        self,
        source: VulnSourceResult,
        finding_ids: list[str],
    ) -> None:
        self.source = source.source
        self.source_status = source.status
        self.source_error = source.status_reason
        self.finding_ids = finding_ids
        reason = source.status_reason or "no status detail"
        missing = ", ".join(finding_ids)
        super().__init__(
            f"authoritative vulnerability source {source.source} is {source.status.value} "
            f"({reason}); no reusable stored {source.source} matches for finding(s): {missing}"
        )


def _stored_wordfence_matches(finding: Finding) -> list[VulnMatch]:
    matches: list[VulnMatch] = []
    expected_cwe = finding.hypothesis.root_cause_cwe
    for raw_match in finding.dedup_matches:
        if str(raw_match.get("source") or "").lower() != "wordfence":
            continue
        try:
            match = VulnMatch.model_validate(raw_match)
        except Exception as exc:
            logger.warning(
                "dedup: ignoring malformed stored Wordfence match for %s: %s",
                finding.id,
                exc,
            )
            continue
        if match.bug_class == expected_cwe:
            matches.append(match)
    return matches


def _merge_known_matches(*batches: list[VulnMatch]) -> list[VulnMatch]:
    merged: dict[tuple[str, ...], VulnMatch] = {}
    for batch in batches:
        for match in batch:
            if match.cve_id:
                key = ("cve", match.cve_id)
            else:
                key = (
                    "anonymous",
                    match.source,
                    match.title,
                    match.affected_versions,
                    match.bug_class or "",
                )
            if key not in merged:
                merged[key] = match
    return list(merged.values())


def _source_status_details(lookup: VulnLookupResult) -> dict[str, dict[str, object]]:
    return {
        name: {
            "status": source.status.value,
            "matches": len(source.matches),
            "status_reason": source.status_reason,
        }
        for name, source in lookup.sources.items()
    }


def _classify_scored(
    finding: Finding,
    known: list[VulnMatch],
    scanned_version: str,
) -> tuple[DedupStatus, list[dict]]:
    """Calculate meaningful per-match similarity, sorted high to low.

    Status thresholds:
    - top_score >= 0.95 → KNOWN_DUPE
    - any matches      → POSSIBLY_KNOWN
    - no matches       → NOVEL
    """
    cwe = finding.hypothesis.root_cause_cwe
    sink = finding.hypothesis.sink or ""
    handler = finding.hypothesis.entry_point or ""
    file_ = finding.hypothesis.file or ""
    attacker_role = str(
        (finding.hypothesis.derived_severity or {}).get("attacker_role")
        or (finding.hypothesis.evidence_summary or {}).get("attacker_role")
        or ""
    )
    vulnerability_type = finding.hypothesis.vulnerability_type or ""

    scored: list[tuple[float, VulnMatch, bool]] = []
    for k in known:
        if not k.bug_class or k.bug_class != cwe:
            continue
        s = dedup_helpers.score_match(k, cwe, sink, handler, file_, scanned_version)
        if s > 0:
            semantic_match = dedup_helpers.is_exact_semantic_match(
                k,
                cwe,
                scanned_version,
                attacker_role,
                vulnerability_type,
            )
            scored.append((s, k, semantic_match))

    if not scored:
        return DedupStatus.NOVEL, []

    semantic_match_count = sum(1 for _, _, is_match in scored if is_match)
    has_unique_semantic_match = semantic_match_count == 1
    if has_unique_semantic_match:
        scored = [
            (1.0 if is_match else score, match, is_match)
            for score, match, is_match in scored
        ]

    scored.sort(
        key=lambda item: (item[0], has_unique_semantic_match and item[2]),
        reverse=True,
    )
    match_dicts: list[dict] = []
    for s, k, semantic_match in scored:
        d = k.model_dump()
        d["similarity_score"] = s  # override the static 1.0
        d["exact_semantic_match"] = has_unique_semantic_match and semantic_match
        if semantic_match:
            d["match_basis"] = [
                "affected_version",
                "attacker_role",
                "vulnerability_type",
            ]
            if not has_unique_semantic_match:
                d["semantic_match_ambiguous"] = True
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
    lookup = await db.lookup_all_with_status(plugin_slug)
    source_details = _source_status_details(lookup)
    for source_name, details in source_details.items():
        logger.info(
            "dedup: source=%s status=%s matches=%d reason=%s",
            source_name,
            details["status"],
            details["matches"],
            details["status_reason"] or "none",
        )

    wordfence = lookup.source("wordfence")
    reused_wordfence = wordfence.status is not VulnSourceStatus.AVAILABLE
    if reused_wordfence:
        stored_by_finding = [_stored_wordfence_matches(finding) for finding in findings]
        missing_finding_ids = [
            finding.id
            for finding, stored in zip(findings, stored_by_finding, strict=True)
            if not stored
        ]
        if missing_finding_ids:
            raise DedupSourceUnavailableError(wordfence, missing_finding_ids)
        known_by_finding = [
            _merge_known_matches(stored, lookup.matches)
            for stored in stored_by_finding
        ]
        logger.warning(
            "dedup: Wordfence is %s (%s); reusing %d stored Wordfence match(es) "
            "across %d finding(s)",
            wordfence.status.value,
            wordfence.status_reason or "no status detail",
            sum(len(stored) for stored in stored_by_finding),
            len(findings),
        )
    else:
        known_by_finding = [lookup.matches for _ in findings]

    logger.info("dedup: %d merged live known vulns from DBs", len(lookup.matches))

    # Determine the scanned plugin version for version-range alignment.
    scanned_version = ""
    try:
        from ..schemas.intake import IntakeArtifact
        intake_path = Path(runs_root) / run_id / "intake.json"
        if intake_path.exists():
            scanned_version = IntakeArtifact.from_json_file(str(intake_path)).plugin_version
    except Exception:
        pass

    planned: list[tuple[DedupStatus, list[dict], str, str]] = []
    for finding, known in zip(findings, known_by_finding, strict=True):
        status, matches = _classify_scored(finding, known, scanned_version)
        rec, reason = dedup_helpers.derive_submission_recommendation(
            finding_dedup_status=status.value,
            scored_matches=matches,
        )
        planned.append((status, matches, rec, reason))

    for f, (status, matches, rec, reason) in zip(findings, planned, strict=True):
        f.dedup_status = status
        f.dedup_matches = matches
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
                "source_status": source_details,
                "reused_stored_wordfence_matches": reused_wordfence,
            },
        )

    findings_path = Path(runs_root) / run_id / "findings.jsonl"
    atomic_write_jsonl(findings_path, findings)
    return findings
