"""Report stage — Reporter agent writes one markdown advisory per non-dupe finding."""

from __future__ import annotations

import logging
from pathlib import Path

from ..agents.claim_validator import ClaimValidator
from ..agents.reporter import ReporterAgent
from ..agents.runtime import AgentRuntime
from ..schemas.config import PipelineConfig
from ..schemas.finding import DedupStatus, Finding
from ..services import report_helpers
from ..services.budget import BudgetTracker
from ..services.decision_ledger import append_decision
from ..services.quality_gate import grade_finding_for_report

logger = logging.getLogger(__name__)


def _read_code_slice(plugin_root: Path, rel_file: str, line: int, ctx: int = 25) -> str | None:
    if not rel_file:
        return None
    candidate = plugin_root / rel_file
    if not candidate.is_file():
        for prefix in ("wp-content/plugins/" + plugin_root.name + "/", plugin_root.name + "/"):
            if rel_file.startswith(prefix):
                candidate = plugin_root / rel_file[len(prefix):]
                if candidate.is_file():
                    break
    if not candidate.is_file():
        return None
    try:
        text = candidate.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    lines = text.splitlines()
    start = max(0, line - 1 - ctx)
    end = min(len(lines), line - 1 + ctx)
    numbered = [f"{i+1:5}  {lines[i]}" for i in range(start, end)]
    return "\n".join(numbered)


async def run(
    findings: list[Finding],
    plugin_slug: str,
    config: PipelineConfig,
    budget: BudgetTracker,
    runtime: AgentRuntime,
    runs_root: str = "runs",
    run_id: str = "",
    plugin_path: str | None = None,
    plugin_version: str | None = None,
) -> list[str]:
    cfg = config.report
    reporter = ReporterAgent(runtime, model=config.models.reporter)
    claim_validator = ClaimValidator(runtime, model=config.models.reporter) if cfg.claim_validation_pass else None
    out_paths: list[str] = []
    run_dir = Path(runs_root) / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    plugin_root = Path(plugin_path) if plugin_path else None

    for f in findings:
        if f.dedup_status == DedupStatus.KNOWN_DUPE:
            logger.info("report: skipping %s (KNOWN_DUPE)", f.id)
            append_decision(
                run_dir,
                stage="report",
                action="skip",
                result="known_duplicate",
                hypothesis_id=f.hypothesis.id,
                finding_id=f.id,
                reason="dedup_status is known_dupe",
            )
            continue

        if config.quality.enabled and config.quality.report_grader:
            grade = grade_finding_for_report(
                f,
                require_evidence_schema=config.quality.require_evidence_schema,
                false_positive_rules=config.quality.false_positive_rules,
                recompute=config.quality.recompute_severity,
            )
            f.hypothesis.evidence_summary = grade.evidence
            f.hypothesis.derived_severity = grade.severity
            f.hypothesis.quality_gate = {
                "accepted": grade.accepted,
                "reason": grade.reason,
                "warnings": grade.warnings,
                "rules": grade.rules,
            }
            if f.cvss_estimate is None:
                f.cvss_estimate = str(grade.severity.get("cvss_estimate"))
            if not grade.accepted:
                programs = list(f.hypothesis.bounty_programs) or ["wordfence"]
                for program in programs:
                    blocked_path = run_dir / f"report_{f.id}_{program}_QUALITY_BLOCKED.md"
                    blocked_path.write_text(
                        f"# QUALITY GATE BLOCKED: {f.id} ({program})\n\n"
                        f"**Reason:** {grade.reason}\n\n"
                        f"**Derived severity:** {grade.severity}\n\n"
                        f"**Evidence summary:** {grade.evidence}\n\n"
                        f"**Warnings:** {grade.warnings or 'none'}\n\n"
                        "This confirmed finding was not converted into a submission draft because "
                        "the quality gate did not find enough submit-worthy impact."
                    )
                    out_paths.append(str(blocked_path))
                    logger.info("report: quality gate blocked %s (%s) — wrote %s", f.id, program, blocked_path)
                    append_decision(
                        run_dir,
                        stage="report",
                        action="block",
                        result="quality_gate_blocked",
                        hypothesis_id=f.hypothesis.id,
                        finding_id=f.id,
                        reason=grade.reason,
                        artifact=blocked_path,
                        details={"program": program, "rules": grade.rules, "warnings": grade.warnings},
                    )
                continue

        # R2: submission readiness gate — emit *_NOT_READY.md instead of polished report
        # if upstream prerequisites aren't satisfied.
        if cfg.submission_readiness_gate:
            is_ready, checklist = report_helpers.check_submission_readiness(f)
            if not is_ready:
                programs = list(f.hypothesis.bounty_programs) or ["wordfence"]
                for program in programs:
                    not_ready_path = run_dir / f"report_{f.id}_{program}_NOT_READY.md"
                    not_ready_path.write_text(report_helpers.render_not_ready_md(f, checklist))
                    out_paths.append(str(not_ready_path))
                    logger.info("report: NOT READY for %s (%s) — wrote %s", f.id, program, not_ready_path)
                    append_decision(
                        run_dir,
                        stage="report",
                        action="block",
                        result="not_ready",
                        hypothesis_id=f.hypothesis.id,
                        finding_id=f.id,
                        artifact=not_ready_path,
                        details={"program": program, "checklist": checklist},
                    )
                continue

        code_slice = None
        if plugin_root is not None:
            code_slice = _read_code_slice(plugin_root, f.hypothesis.file, f.hypothesis.line)

        # Generate one report per qualifying program. Default to wordfence for legacy
        # findings produced before scope-tagging was wired in (empty bounty_programs).
        programs = list(f.hypothesis.bounty_programs) or ["wordfence"]
        for program in programs:
            md = await reporter.write(
                f,
                plugin_slug=plugin_slug,
                plugin_version=plugin_version,
                code_slice=code_slice,
                program=program,
            )

            # R1: claim-validation pass before writing
            validation_summary = None
            if claim_validator is not None:
                evidence_summary = (
                    f"Hypothesis: {f.hypothesis.model_dump_json(indent=2)[:3000]}\n\n"
                    f"PoC evidence: {str(f.evidence)[:2000]}\n\n"
                    f"Dedup matches (top 3): "
                    f"{(f.dedup_matches[:3] if f.dedup_matches else 'none')}"
                )
                validation = await claim_validator.validate(md, evidence_summary)
                validation_summary = validation.summary
                blocking = [c for c in validation.unsupported_claims if c.severity == "blocking"]
                if blocking:
                    blocked_path = run_dir / f"report_{f.id}_{program}_CLAIM_VALIDATION_BLOCKED.md"
                    block_md = (
                        f"# CLAIM VALIDATION BLOCKED: {f.id} ({program})\n\n"
                        f"R1 found {len(blocking)} blocking unsupported claim(s) in the generated report.\n\n"
                        f"## Summary\n{validation_summary or '(none)'}\n\n"
                        f"## Blocking claims\n\n"
                        + "\n\n".join(
                            f"### Severity: {c.severity}\n> {c.quote}\n\n**Issue:** {c.issue}"
                            for c in blocking
                        )
                        + "\n\n## Original report\n\n"
                        + md
                    )
                    blocked_path.write_text(block_md)
                    out_paths.append(str(blocked_path))
                    logger.warning("report: %s (%s) — claim validation BLOCKED (%d blocking claims) — %s",
                                   f.id, program, len(blocking), blocked_path)
                    append_decision(
                        run_dir,
                        stage="report",
                        action="block",
                        result="claim_validation_blocked",
                        hypothesis_id=f.hypothesis.id,
                        finding_id=f.id,
                        reason=validation_summary,
                        artifact=blocked_path,
                        details={"program": program, "blocking_claims": len(blocking)},
                    )
                    continue

            out = run_dir / f"report_{f.id}_{program}.md"
            out.write_text(md)
            out_paths.append(str(out))
            logger.info("report: wrote %s (%d bytes, program=%s)", out, len(md), program)
            append_decision(
                run_dir,
                stage="report",
                action="write",
                result="report_written",
                hypothesis_id=f.hypothesis.id,
                finding_id=f.id,
                artifact=out,
                details={"program": program, "bytes": len(md)},
            )
            if validation_summary:
                logger.info("report: %s validator: %s", f.id, validation_summary)

            # R7: machine-readable submission JSON
            submission_json = None
            if cfg.submission_json:
                submission_json = report_helpers.build_submission_json(
                    f, plugin_slug, plugin_version, program,
                )

            # R4: bundle the report + PoC + screenshots + JSON into plugins/<slug>/submissions/<id>/
            if cfg.poc_bundling:
                # Discover screenshot dir from R5 (verifications/<id>/screenshots/)
                screenshot_dir = run_dir / "verifications" / f.id / "screenshots"
                report_helpers.write_submission_bundle(
                    finding=f,
                    plugin_slug=plugin_slug,
                    plugins_root=Path("plugins"),
                    report_md=md,
                    program=program,
                    submission_json=submission_json,
                    payload_files=None,
                    screenshot_dir=screenshot_dir if screenshot_dir.exists() else None,
                )
            elif cfg.submission_json and submission_json is not None:
                # JSON without bundling — drop it next to the report
                json_path = run_dir / f"report_{f.id}_{program}.submission.json"
                import json as _json
                json_path.write_text(_json.dumps(submission_json, indent=2))
                logger.info("report: submission JSON → %s", json_path)
    return out_paths
