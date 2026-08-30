"""Triage stage — Critic narrows hypotheses, capped to max_hypotheses_to_verify."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from ..agents.critic import CriticAgent
from ..agents.hypothesis_verifier import validate_exact_sink_anchor
from ..agents.runtime import AgentRuntime
from ..schemas.config import PipelineConfig
from ..schemas.hypothesis import (
    HypothesesArtifact,
    Hypothesis,
    SourceAnchor,
    TriagedArtifact,
)
from ..services.budget import BudgetTracker
from ..services.console_format import (
    format_triage_accept,
    format_triage_merge,
    format_triage_reject,
)
from ..services.artifacts import atomic_write_jsonl
from ..services.decision_ledger import append_decision
from ..services.quality_gate import (
    apply_quality_gate,
    infer_attacker_role,
    rank_hypothesis,
)
from ..services.scope import preverification_programs
from .hypothesis import _build_code_slices

logger = logging.getLogger(__name__)

_MAX_SOURCE_ANCHOR_REPAIR_LINE_DRIFT = 15


def _apply_submission_scope(
    triaged: TriagedArtifact,
    run_dir: Path,
    *,
    enforce_submission_scope: bool,
) -> None:
    """Route candidates for delivery, optionally retaining local-only verification."""
    triaged.submission_scope_enforced = enforce_submission_scope
    scope_eligible = []
    for hypothesis in triaged.accepted:
        programs, reasons = preverification_programs(hypothesis)
        hypothesis.bounty_programs = programs
        if programs or not enforce_submission_scope:
            scope_eligible.append(hypothesis)
            if not programs:
                reason = "; ".join(
                    f"{program}: {detail}" for program, detail in reasons.items()
                )
                append_decision(
                    run_dir,
                    stage="scope",
                    action="retain",
                    result="local_verification_only",
                    hypothesis_id=hypothesis.id,
                    reason=reason,
                    details={"bounty_programs": []},
                )
            continue
        reason = "; ".join(
            f"{program}: {detail}" for program, detail in reasons.items()
        )
        triaged.deferred.append(
            {
                "hypothesis_id": hypothesis.id,
                "reason": "no current automatic CVE submission route: " + reason,
                "hypothesis": hypothesis.model_dump(mode="json"),
            }
        )
        append_decision(
            run_dir,
            stage="scope",
            action="defer",
            result="no_eligible_program",
            hypothesis_id=hypothesis.id,
            reason=reason,
        )
    triaged.accepted = scope_eligible


def _validate_critic_accounting(
    hypotheses: HypothesesArtifact,
    triaged: TriagedArtifact,
    *,
    plugin_path: str | None = None,
) -> None:
    """Fail rather than silently losing or duplicating a critic input."""
    expected = {hypothesis.id for hypothesis in hypotheses.hypotheses}
    if triaged.plugin_slug != hypotheses.plugin_slug:
        raise ValueError(
            f"critic returned plugin_slug {triaged.plugin_slug!r}; "
            f"expected {hypotheses.plugin_slug!r}"
        )

    accepted = {hypothesis.id for hypothesis in triaged.accepted}
    rejected = {str(item.get("hypothesis_id") or "") for item in triaged.rejected}
    merged = {
        str(item.get("merged_from_id") or item.get("source_id") or "")
        for item in triaged.merged
    }
    manual = {str(item.get("hypothesis_id") or "") for item in triaged.manual_review}
    groups = {
        "accepted": accepted,
        "rejected": rejected,
        "merged": merged,
        "manual_review": manual,
    }
    if any("" in values for values in groups.values()):
        raise ValueError("critic returned a disposition without a hypothesis_id")

    seen: dict[str, str] = {}
    for disposition, values in groups.items():
        for hypothesis_id in values:
            prior = seen.setdefault(hypothesis_id, disposition)
            if prior != disposition:
                raise ValueError(
                    f"critic assigned {hypothesis_id!r} to both {prior} and {disposition}"
                )

    unknown = set(seen) - expected
    missing = expected - set(seen)
    if unknown:
        raise ValueError(f"critic returned unknown hypothesis ids: {sorted(unknown)}")
    if missing:
        raise ValueError(f"critic omitted hypothesis ids: {sorted(missing)}")

    for item in triaged.merged:
        kept_id = str(item.get("kept_id") or "")
        if not kept_id or kept_id not in accepted:
            raise ValueError(
                "critic merge must reference a kept_id present in accepted"
            )
    for item in triaged.manual_review:
        hypothesis_id = str(item.get("hypothesis_id") or "")
        payload = item.get("hypothesis")
        try:
            manual_hypothesis = Hypothesis.model_validate(payload)
        except Exception as exc:
            raise ValueError(
                f"manual-review item {hypothesis_id!r} lacks a valid hypothesis payload"
            ) from exc
        if manual_hypothesis.id != hypothesis_id:
            raise ValueError(
                f"manual-review item id {hypothesis_id!r} does not match its payload"
            )

    input_by_id = {hypothesis.id: hypothesis for hypothesis in hypotheses.hypotheses}
    repairs_by_id = {}
    for repair in triaged.source_anchor_repairs:
        if repair.hypothesis_id in repairs_by_id:
            raise ValueError(
                f"critic returned duplicate source-anchor repairs for "
                f"{repair.hypothesis_id!r}"
            )
        if repair.hypothesis_id not in accepted:
            raise ValueError(
                "critic source-anchor repair must reference an accepted hypothesis"
            )
        repairs_by_id[repair.hypothesis_id] = repair

    def _anchor(hypothesis: Hypothesis) -> SourceAnchor:
        return SourceAnchor(
            file=hypothesis.file,
            line=hypothesis.line,
            sink=hypothesis.sink,
            sink_code=hypothesis.sink_code,
        )

    for accepted_hypothesis in triaged.accepted:
        original = input_by_id[accepted_hypothesis.id]
        original_anchor = _anchor(original)
        accepted_anchor = _anchor(accepted_hypothesis)
        anchor_changed = accepted_anchor != original_anchor
        repair = repairs_by_id.get(accepted_hypothesis.id)

        if anchor_changed and repair is None:
            raise ValueError(
                f"critic changed source anchor for {accepted_hypothesis.id!r} "
                "without source_anchor_repairs audit metadata"
            )
        if not anchor_changed and repair is not None:
            raise ValueError(
                f"critic returned a source-anchor repair for unchanged hypothesis "
                f"{accepted_hypothesis.id!r}"
            )
        if repair is not None:
            if (
                repair.original != original_anchor
                or repair.corrected != accepted_anchor
            ):
                raise ValueError(
                    f"critic source-anchor repair for {accepted_hypothesis.id!r} "
                    "does not match the input and accepted hypotheses"
                )
            if not repair.reason.strip():
                raise ValueError("critic source-anchor repair lacks a reason")
            if (
                accepted_hypothesis.file != original.file
                or abs(accepted_hypothesis.line - original.line)
                > _MAX_SOURCE_ANCHOR_REPAIR_LINE_DRIFT
            ):
                raise ValueError(
                    f"critic source-anchor repair for {accepted_hypothesis.id!r} "
                    "is not a same-file local correction"
                )

            invariant_pairs = {
                "specialist": (original.specialist, accepted_hypothesis.specialist),
                "bug_class": (original.bug_class, accepted_hypothesis.bug_class),
                "entry_point": (original.entry_point, accepted_hypothesis.entry_point),
                "preconditions": (
                    original.preconditions,
                    accepted_hypothesis.preconditions,
                ),
                "affected_versions": (
                    original.affected_versions,
                    accepted_hypothesis.affected_versions,
                ),
                "attacker_role": (
                    infer_attacker_role(original),
                    infer_attacker_role(accepted_hypothesis),
                ),
                "security_outcome": (
                    original.security_outcome.model_dump(mode="json"),
                    accepted_hypothesis.security_outcome.model_dump(mode="json"),
                ),
                "source": (
                    str((original.evidence_summary or {}).get("source") or ""),
                    str(
                        (accepted_hypothesis.evidence_summary or {}).get("source") or ""
                    ),
                ),
                "control": (
                    str((original.evidence_summary or {}).get("control") or ""),
                    str(
                        (accepted_hypothesis.evidence_summary or {}).get("control")
                        or ""
                    ),
                ),
                "boundary": (
                    str((original.evidence_summary or {}).get("boundary") or ""),
                    str(
                        (accepted_hypothesis.evidence_summary or {}).get("boundary")
                        or ""
                    ),
                ),
                "impact": (
                    str((original.evidence_summary or {}).get("impact") or ""),
                    str(
                        (accepted_hypothesis.evidence_summary or {}).get("impact") or ""
                    ),
                ),
            }
            changed_claim_fields = [
                name
                for name, values in invariant_pairs.items()
                if values[0] != values[1]
            ]
            if changed_claim_fields:
                raise ValueError(
                    f"critic source-anchor repair for {accepted_hypothesis.id!r} "
                    "changed claim fields: " + ", ".join(changed_claim_fields)
                )

            if original.sink_code != accepted_hypothesis.sink_code:
                if (
                    original.taint_path
                    and accepted_hypothesis.taint_path
                    and original.taint_path[-1] == accepted_hypothesis.taint_path[-1]
                ):
                    raise ValueError(
                        f"critic source-anchor repair for {accepted_hypothesis.id!r} "
                        "left the terminal taint path unchanged"
                    )
                original_evidence_sink = str(
                    (original.evidence_summary or {}).get("sink") or ""
                )
                accepted_evidence_sink = str(
                    (accepted_hypothesis.evidence_summary or {}).get("sink") or ""
                )
                if (
                    original_evidence_sink
                    and original_evidence_sink == accepted_evidence_sink
                ):
                    raise ValueError(
                        f"critic source-anchor repair for {accepted_hypothesis.id!r} "
                        "left evidence_summary.sink unchanged"
                    )

        if plugin_path:
            citation_error = validate_exact_sink_anchor(
                Path(plugin_path),
                accepted_hypothesis.file,
                accepted_hypothesis.line,
                accepted_hypothesis.sink_code,
            )
            if citation_error:
                raise ValueError(
                    f"critic accepted {accepted_hypothesis.id!r} with an invalid "
                    f"source anchor: {citation_error}"
                )


async def run(
    hypotheses: HypothesesArtifact,
    plugin_path: str,
    config: PipelineConfig,
    budget: BudgetTracker,
    runtime: AgentRuntime,
    runs_root: str = "runs",
    run_id: str = "",
    enforce_submission_scope: bool = True,
) -> TriagedArtifact:
    code_slices = _build_code_slices(hypotheses.hypotheses, Path(plugin_path))

    critic = CriticAgent(runtime, model=config.models.critic)
    triaged = await critic.review(
        hypotheses,
        code_slices,
        plugin_path=plugin_path,
    )
    _validate_critic_accounting(hypotheses, triaged, plugin_path=plugin_path)
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

    run_dir = Path(runs_root) / run_id
    for repair in triaged.source_anchor_repairs:
        append_decision(
            run_dir,
            stage="triage",
            action="repair_source_anchor",
            result="accepted",
            hypothesis_id=repair.hypothesis_id,
            reason=repair.reason,
            artifact=run_dir / "triaged.json",
            details={
                "original": repair.original.model_dump(mode="json"),
                "corrected": repair.corrected.model_dump(mode="json"),
            },
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
            hypothesis_id=str(
                merge.get("merged_from_id")
                or merge.get("hypothesis_id")
                or merge.get("source_id")
                or ""
            ),
            reason=str(merge.get("reason") or ""),
            artifact=run_dir / "triaged.json",
            details={"merge": merge},
        )

    before = len(triaged.accepted)
    quality_path = run_dir / "quality_gate_triage.json"
    triaged = apply_quality_gate(triaged, artifact_path=quality_path)
    if quality_path.exists():
        try:
            for decision in json.loads(quality_path.read_text()):
                accepted = bool(decision.get("accepted"))
                append_decision(
                    run_dir,
                    stage="quality_gate",
                    action="accept" if accepted else "reject",
                    result="accepted" if accepted else "rejected",
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
            logger.warning(
                "triage: failed to mirror quality gate decisions into ledger: %s", exc
            )
    logger.info("triage: quality gate accepted %d/%d", len(triaged.accepted), before)

    _apply_submission_scope(
        triaged,
        run_dir,
        enforce_submission_scope=enforce_submission_scope,
    )

    # Apply the sandbox budget only after source/evidence validation. Ranking is
    # based on demonstrated role reachability and CIA outcome, not model
    # confidence alone.
    cap = config.max_hypotheses_to_verify
    accepted_sorted = sorted(triaged.accepted, key=rank_hypothesis)
    if len(accepted_sorted) > cap:
        logger.info(
            "triage: selected %d/%d source-valid candidates for verification; deferred=%d",
            cap,
            len(accepted_sorted),
            len(accepted_sorted) - cap,
        )
        for hypothesis in accepted_sorted[cap:]:
            triaged.deferred.append(
                {
                    "hypothesis_id": hypothesis.id,
                    "reason": f"verification budget cap {cap}; ranked below selected candidates",
                    "hypothesis": hypothesis.model_dump(mode="json"),
                }
            )
            append_decision(
                run_dir,
                stage="triage",
                action="defer",
                result="verification_budget_cap",
                hypothesis_id=hypothesis.id,
                reason=f"max_hypotheses_to_verify cap {cap}",
            )
    triaged.accepted = accepted_sorted[:cap]

    for hypothesis in triaged.accepted:
        append_decision(
            run_dir,
            stage="triage",
            action="accept",
            result="selected_for_verification",
            hypothesis_id=hypothesis.id,
            artifact=run_dir / "triaged.json",
        )

    out_path = Path(runs_root) / run_id / "triaged.jsonl"
    atomic_write_jsonl(out_path, triaged.accepted)
    # Also write the full TriagedArtifact for posterity.
    triaged.to_json_file(str(out_path.with_suffix(".json")))
    logger.info(
        "triage: accepted=%d rejected=%d merged=%d deferred=%d -> %s",
        len(triaged.accepted),
        len(triaged.rejected),
        len(triaged.merged),
        len(triaged.deferred),
        out_path,
    )
    return triaged
