"""Triage stage — Critic narrows hypotheses, capped to max_hypotheses_to_verify."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from ..agents.critic import CriticAgent
from ..agents.runtime import AgentRuntime
from ..schemas.config import PipelineConfig
from ..schemas.hypothesis import Confidence, HypothesesArtifact, TriagedArtifact
from ..services.budget import BudgetTracker
from ..services.console_format import (
    format_triage_accept,
    format_triage_merge,
    format_triage_reject,
)
from ..services.artifacts import atomic_write_jsonl
from ..services.decision_ledger import append_decision
from ..services.quality_gate import apply_quality_gate
from .hypothesis import _build_code_slices

logger = logging.getLogger(__name__)

_CONF_RANK = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}


async def run(
    hypotheses: HypothesesArtifact,
    plugin_path: str,
    config: PipelineConfig,
    budget: BudgetTracker,
    runtime: AgentRuntime,
    recon=None,  # for code_slice rebuilding
    runs_root: str = "runs",
    run_id: str = "",
    apply_scope_filter: bool = True,
) -> TriagedArtifact:
    if recon is None:
        # Fallback: read recon.json from disk
        from ..schemas.recon import ReconArtifact
        recon = ReconArtifact.from_json_file(str(Path(runs_root) / run_id / "recon.json"))

    code_slices = _build_code_slices(recon, Path(plugin_path))

    critic = CriticAgent(runtime, model=config.models.critic)
    triaged = await critic.review(hypotheses, code_slices, apply_scope_filter=apply_scope_filter)
    for h in triaged.accepted:
        logger.info(format_triage_accept(h))
    for rejection in triaged.rejected:
        logger.info(format_triage_reject(rejection))
    for merge in triaged.merged:
        logger.info(format_triage_merge(merge))
    for item in triaged.manual_review:
        logger.info(
            "triage: manual review %s — %s",
            item.get("hypothesis_id"),
            item.get("reason"),
        )

    scope_rejects = sum(1 for r in triaged.rejected if (r.get("reason") or "").startswith("out_of_scope:"))
    if scope_rejects:
        logger.info("triage: %d hypotheses rejected as out-of-scope for Wordfence", scope_rejects)

    # Cap accepted at max_hypotheses_to_verify, highest confidence first
    cap = config.max_hypotheses_to_verify
    accepted_sorted = sorted(triaged.accepted, key=lambda h: _CONF_RANK.get(h.confidence, 99))
    if len(accepted_sorted) > cap:
        logger.info("triage: capping accepted from %d to %d", len(accepted_sorted), cap)
        run_dir = Path(runs_root) / run_id
        for h in accepted_sorted[cap:]:
            append_decision(
                run_dir,
                stage="triage",
                action="drop",
                result="capped_before_verification",
                hypothesis_id=h.id,
                reason=f"max_hypotheses_to_verify cap {cap}",
            )
        accepted_sorted = accepted_sorted[:cap]
    triaged.accepted = accepted_sorted

    run_dir = Path(runs_root) / run_id
    for h in triaged.accepted:
        append_decision(
            run_dir,
            stage="triage",
            action="accept",
            result="accepted",
            hypothesis_id=h.id,
            artifact=run_dir / "triaged.json",
        )
    for rejection in triaged.rejected:
        append_decision(
            run_dir,
            stage="triage",
            action="reject",
            result="rejected",
            hypothesis_id=str(rejection.get("hypothesis_id") or ""),
            reason=str(rejection.get("reason") or ""),
            artifact=run_dir / "triaged.json",
        )
    for item in triaged.manual_review:
        append_decision(
            run_dir,
            stage="triage",
            action="manual_review",
            result=str(item.get("source") or "manual_review"),
            hypothesis_id=str(item.get("hypothesis_id") or ""),
            reason=str(item.get("reason") or ""),
            artifact=run_dir / "triaged.json",
        )
    for merge in triaged.merged:
        append_decision(
            run_dir,
            stage="triage",
            action="merge",
            result="merged",
            hypothesis_id=str(merge.get("hypothesis_id") or merge.get("source_id") or ""),
            reason=str(merge.get("reason") or ""),
            artifact=run_dir / "triaged.json",
            details={"merge": merge},
        )

    if config.quality.enabled and config.quality.finding_grader:
        before = len(triaged.accepted)
        quality_path = run_dir / "quality_gate_triage.json"
        triaged = apply_quality_gate(
            triaged,
            require_evidence_schema=config.quality.require_evidence_schema,
            false_positive_rules=config.quality.false_positive_rules,
            recompute=config.quality.recompute_severity,
            reject_below_submit_bar=config.quality.reject_below_submit_bar,
            borderline_to_manual_review=config.quality.borderline_to_manual_review,
            pre_verification=True,
            artifact_path=quality_path,
        )
        if quality_path.exists():
            try:
                for decision in json.loads(quality_path.read_text()):
                    accepted = bool(decision.get("accepted"))
                    disposition = str(decision.get("disposition") or ("accepted" if accepted else "rejected"))
                    append_decision(
                        run_dir,
                        stage="quality_gate",
                        action="manual_review" if disposition == "manual_review" else "accept" if accepted else "reject",
                        result=disposition,
                        hypothesis_id=str(decision.get("hypothesis_id") or ""),
                        reason=str(decision.get("reason") or ""),
                        artifact=quality_path,
                        details={
                            "rules": decision.get("rules") or [],
                            "warnings": decision.get("warnings") or [],
                            "severity": decision.get("severity") or {},
                        },
                    )
            except Exception as exc:
                logger.warning("triage: failed to mirror quality gate decisions into ledger: %s", exc)
        logger.info("triage: quality gate accepted %d/%d", len(triaged.accepted), before)

    out_path = Path(runs_root) / run_id / "triaged.jsonl"
    atomic_write_jsonl(out_path, triaged.accepted)
    # Also write the full TriagedArtifact for posterity.
    triaged.to_json_file(str(out_path.with_suffix(".json")))
    logger.info("triage: accepted=%d rejected=%d merged=%d -> %s",
                len(triaged.accepted), len(triaged.rejected), len(triaged.merged), out_path)
    return triaged
