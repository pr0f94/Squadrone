"""Triage stage — Critic narrows hypotheses, capped to max_hypotheses_to_verify."""

from __future__ import annotations

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

    critic = CriticAgent(
        runtime,
        model=config.models.critic,
        inject_review_md=triage_cfg.inject_review_md,
        cluster_aware=triage_cfg.cluster_aware,
        allow_reframing=triage_cfg.allow_reframing,
        drift_logging=triage_cfg.drift_logging,
        cache_enabled=triage_cfg.cache_enabled,
        review_md_max_chars=triage_cfg.review_md_max_chars,
        plugin_version=plugin_version_for_cache,
    )
    triaged = await critic.review(hypotheses, code_slices, apply_scope_filter=apply_scope_filter)
    for h in triaged.accepted:
        logger.info(format_triage_accept(h))
    for rejection in triaged.rejected:
        logger.info(format_triage_reject(rejection))
    for merge in triaged.merged:
        logger.info(format_triage_merge(merge))
    for reframe in triaged.request_reframing:
        logger.info(format_triage_reframe(reframe))

    scope_rejects = sum(1 for r in triaged.rejected if (r.get("reason") or "").startswith("out_of_scope:"))
    if scope_rejects:
        logger.info("triage: %d hypotheses rejected as out-of-scope for Wordfence", scope_rejects)

    # Cap accepted at max_hypotheses_to_verify, highest confidence first
    cap = config.max_hypotheses_to_verify
    accepted_sorted = sorted(triaged.accepted, key=lambda h: _CONF_RANK.get(h.confidence, 99))
    if len(accepted_sorted) > cap:
        logger.info("triage: capping accepted from %d to %d", len(accepted_sorted), cap)
        accepted_sorted = accepted_sorted[:cap]
    triaged.accepted = accepted_sorted

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
