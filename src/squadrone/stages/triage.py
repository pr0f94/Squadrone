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
    format_triage_reframe,
    format_triage_reject,
)
from ..services.decision_ledger import append_decision
from ..services.quality_gate import apply_quality_gate
from .hypothesis import _build_code_slices

logger = logging.getLogger(__name__)

_CONF_RANK = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}


def _combine_vote_artifacts(votes: list[TriagedArtifact], original: HypothesesArtifact) -> TriagedArtifact:
    """Majority-vote multiple critic passes by hypothesis id.

    A hypothesis is accepted if more than half of vote artifacts accepted it. The
    first accepted object is retained so any bounty_programs from the critic carry
    forward. Rejections keep the most common-ish first reason for auditability.
    """
    if len(votes) == 1:
        return votes[0]
    threshold = len(votes) // 2 + 1
    by_id = {h.id: h for h in original.hypotheses}
    accepted_counts: dict[str, int] = {h.id: 0 for h in original.hypotheses}
    accepted_objects: dict[str, object] = {}
    rejection_reasons: dict[str, list[str]] = {h.id: [] for h in original.hypotheses}
    merged: list[dict] = []
    reframes: list[dict] = []
    for art in votes:
        accepted_ids = {h.id for h in art.accepted}
        for h in art.accepted:
            accepted_counts[h.id] = accepted_counts.get(h.id, 0) + 1
            accepted_objects.setdefault(h.id, h)
        for h_id in by_id:
            if h_id not in accepted_ids:
                reason = next(
                    (str(r.get("reason", "")) for r in art.rejected if r.get("hypothesis_id") == h_id),
                    "not accepted by critic vote",
                )
                rejection_reasons.setdefault(h_id, []).append(reason)
        merged.extend(art.merged)
        reframes.extend(art.request_reframing)

    accepted = []
    rejected = []
    manual_review = []
    for h_id, count in accepted_counts.items():
        if count >= threshold:
            accepted.append(accepted_objects.get(h_id, by_id[h_id]))
        elif count > 0:
            reasons = rejection_reasons.get(h_id) or ["critic vote split below acceptance threshold"]
            manual_review.append({
                "hypothesis_id": h_id,
                "reason": f"triage_votes: accepted {count}/{len(votes)}; split vote requires manual review — {reasons[0]}",
                "source": "triage_votes",
                "accepted_votes": count,
                "total_votes": len(votes),
                "hypothesis": by_id[h_id].model_dump(mode="json"),
            })
        else:
            reasons = rejection_reasons.get(h_id) or ["critic vote majority rejected"]
            rejected.append({
                "hypothesis_id": h_id,
                "reason": f"triage_votes: accepted {count}/{len(votes)}; majority rejected — {reasons[0]}",
            })
    return TriagedArtifact(
        plugin_slug=original.plugin_slug,
        accepted=accepted,
        rejected=rejected,
        merged=merged,
        manual_review=manual_review,
        request_reframing=reframes,
    )


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

    # Stage-4 toggles flow through the critic constructor. All default off so existing
    # callers see identical behaviour.
    triage_cfg = config.triage
    plugin_version_for_cache = ""
    try:
        from ..schemas.intake import IntakeArtifact
        intake_path = Path(runs_root) / run_id / "intake.json"
        if intake_path.exists():
            plugin_version_for_cache = IntakeArtifact.from_json_file(str(intake_path)).plugin_version
    except Exception:
        pass

    votes = max(1, triage_cfg.verifier_votes)
    vote_artifacts: list[TriagedArtifact] = []
    for vote_idx in range(votes):
        review_mode = "adversarial" if votes > 1 and vote_idx == votes - 1 else "standard"
        critic = CriticAgent(
            runtime,
            model=config.models.critic,
            inject_review_md=triage_cfg.inject_review_md,
            cluster_aware=triage_cfg.cluster_aware,
            allow_reframing=triage_cfg.allow_reframing,
            drift_logging=triage_cfg.drift_logging,
            cache_enabled=triage_cfg.cache_enabled and votes == 1,
            review_md_max_chars=triage_cfg.review_md_max_chars,
            plugin_version=plugin_version_for_cache,
            review_mode=review_mode,
        )
        if votes > 1:
            logger.info("triage: critic vote %d/%d (%s)", vote_idx + 1, votes, review_mode)
        vote_artifacts.append(await critic.review(hypotheses, code_slices, apply_scope_filter=apply_scope_filter))
    triaged = _combine_vote_artifacts(vote_artifacts, hypotheses)
    for h in triaged.accepted:
        logger.info(format_triage_accept(h))
    for rejection in triaged.rejected:
        logger.info(format_triage_reject(rejection))
    for merge in triaged.merged:
        logger.info(format_triage_merge(merge))
    for reframe in triaged.request_reframing:
        logger.info(format_triage_reframe(reframe))
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
                details={"votes": votes},
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
            details={"votes": votes},
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
            details={"votes": votes},
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
            details={"votes": votes},
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
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as f:
        for h in triaged.accepted:
            f.write(h.model_dump_json() + "\n")
    # Also write the full TriagedArtifact for posterity.
    triaged.to_json_file(str(out_path.with_suffix(".json")))
    logger.info("triage: accepted=%d rejected=%d merged=%d -> %s",
                len(triaged.accepted), len(triaged.rejected), len(triaged.merged), out_path)
    return triaged
