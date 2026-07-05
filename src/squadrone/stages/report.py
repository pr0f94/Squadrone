"""Report stage — Reporter agent writes one markdown advisory per non-dupe finding."""

from __future__ import annotations

import logging
from pathlib import Path

from ..agents.reporter import ReporterAgent
from ..agents.runtime import AgentRuntime
from ..schemas.config import PipelineConfig
from ..schemas.finding import DedupStatus, Finding
from ..services.artifacts import atomic_write_text
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
    reporter = ReporterAgent(runtime, model=config.models.reporter)
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
                    atomic_write_text(
                        blocked_path,
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

        code_slice = None
        if plugin_root is not None:
            code_slice = _read_code_slice(plugin_root, f.hypothesis.file, f.hypothesis.line)

        # Generate one report per qualifying program. Default to Wordfence if
        # routing metadata is unexpectedly absent.
        programs = list(f.hypothesis.bounty_programs) or ["wordfence"]
        for program in programs:
            md = await reporter.write(
                f,
                plugin_slug=plugin_slug,
                plugin_version=plugin_version,
                code_slice=code_slice,
                program=program,
            )

            out = run_dir / f"report_{f.id}_{program}.md"
            atomic_write_text(out, md)
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
    return out_paths
