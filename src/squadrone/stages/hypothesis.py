"""Hypothesis stage — accountable review of the deterministic coverage ledger."""

from __future__ import annotations

import asyncio
from collections import Counter
import hashlib
import json
import logging
from pathlib import Path

from typing import Any

from ..agents.hypothesis_verifier import HypothesisVerifier
from ..agents._specialist_base import FocusedSpecialist, _compact_recon
from ..agents.runtime import AgentRuntime
from ..schemas.config import PipelineConfig
from ..schemas.hypothesis import (
    HypothesesArtifact,
    Hypothesis,
    SpecialistReviewArtifact,
)
from ..schemas.recon import CoverageDisposition, CoverageItem, ReconArtifact, ReviewArea
from ..schemas.taxonomy import get_known_cwe_profile
from ..services.artifacts import atomic_write_json, atomic_write_jsonl
from ..services.budget import BudgetTracker
from ..services.console_format import format_verifier_decision
from ..services.decision_ledger import append_decision


_VERIFIER_BATCH_SIZE = 3
# Specialists force-finalise after 20 tool calls. Keep enough headroom after
# reading every assigned target to trace alternate callers, controls, and impact.
_REVIEW_BATCH_MAX_ITEMS = 8
_REVIEW_BATCH_MAX_BYTES = 60_000
_REVIEW_BATCH_MAX_FILES = 6
_REVIEW_BATCH_ATTEMPTS = 2
_REVIEW_CHECKPOINT_VERSION = 3
_REVIEWABLE_SUPPORT = {"active", "partial", "review_only"}


def _batch_input_fingerprint(
    recon: ReconArtifact,
    targets: list[CoverageItem],
    reviewer: ReviewArea,
) -> str:
    """Digest every semantic input used to decide whether a batch is reusable."""
    payload = {
        "version": _REVIEW_CHECKPOINT_VERSION,
        "reviewer": reviewer,
        "targets": [target.model_dump(mode="json") for target in targets],
        "related_recon": _compact_recon(recon, targets),
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def _verify_hypotheses(
    verifier: HypothesisVerifier,
    hypotheses: list[Hypothesis],
    plugin_path: str,
) -> list[Any]:
    """Verify hypotheses in small batches and stop on transport failure."""
    verdicts: list[Any] = []
    for start in range(0, len(hypotheses), _VERIFIER_BATCH_SIZE):
        batch = hypotheses[start : start + _VERIFIER_BATCH_SIZE]
        verdicts.extend(
            await asyncio.gather(
                *(verifier.verify(hypothesis, plugin_path) for hypothesis in batch)
            )
        )
    return verdicts


# Group hypotheses by (file, line, bug_class) and keep the highest-confidence
# representative. This only merges exact-match keys.
def _pre_verifier_dedup(
    hypotheses: list[Hypothesis],
) -> tuple[list[Hypothesis], dict[str, str]]:
    """Return (deduped, merge_log: merged_id -> kept_id)."""
    by_key: dict[tuple, Hypothesis] = {}
    merge_log: dict[str, str] = {}
    conf_rank = {"high": 0, "medium": 1, "low": 2}
    for h in hypotheses:
        key = (h.file, h.line, h.bug_class.value)
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = h
            continue
        # Keep the higher-confidence one; if tied, keep the earlier one
        if conf_rank.get(h.confidence.value, 1) < conf_rank.get(
            existing.confidence.value, 1
        ):
            merge_log[existing.id] = h.id
            by_key[key] = h
        else:
            merge_log[h.id] = existing.id
    return list(by_key.values()), merge_log


def _build_review_batches(targets: list[CoverageItem]) -> list[list[CoverageItem]]:
    """Create deterministic source-local batches with bounded initial payloads."""
    ordered = sorted(
        targets, key=lambda item: (item.file, item.line, item.kind, item.id)
    )
    batches: list[list[CoverageItem]] = []
    current: list[CoverageItem] = []
    current_bytes = 0
    current_files: set[str] = set()
    for target in ordered:
        target_bytes = len(json.dumps(target.model_dump(mode="json"), default=str))
        if current and (
            len(current) >= _REVIEW_BATCH_MAX_ITEMS
            or current_bytes + target_bytes > _REVIEW_BATCH_MAX_BYTES
            or (
                target.file not in current_files
                and len(current_files) >= _REVIEW_BATCH_MAX_FILES
            )
        ):
            batches.append(current)
            current = []
            current_bytes = 0
            current_files = set()
        current.append(target)
        current_bytes += target_bytes
        current_files.add(target.file)
    if current:
        batches.append(current)
    return batches


def _reconcile_batch_coverage(
    result: SpecialistReviewArtifact,
    targets: list[CoverageItem],
    reviewer: ReviewArea,
) -> tuple[list[CoverageDisposition], list[CoverageItem], set[str]]:
    """Accept exactly one evidence-backed disposition for every assigned item."""
    target_by_id = {target.id: target for target in targets}
    by_id: dict[str, CoverageDisposition] = {}
    invalid_ids: set[str] = set()
    hypothesis_id_counts = Counter(hypothesis.id for hypothesis in result.hypotheses)
    result_hypothesis_ids = {
        hypothesis_id
        for hypothesis_id, count in hypothesis_id_counts.items()
        if count == 1
    }
    accepted_hypothesis_ids: set[str] = set()
    for disposition in result.coverage:
        if disposition.item_id not in target_by_id or disposition.reviewer != reviewer:
            continue
        if disposition.item_id in by_id:
            invalid_ids.add(disposition.item_id)
            continue
        target = target_by_id[disposition.item_id]
        target_location = f"{target.file}:{target.line}"
        candidate_links = set(disposition.hypothesis_ids)
        if (
            disposition.status == "unreviewed"
            or target_location not in disposition.evidence_locations
            or (
                disposition.status == "candidate"
                and (
                    not candidate_links
                    or not candidate_links.issubset(result_hypothesis_ids)
                )
            )
            or (disposition.status != "candidate" and bool(candidate_links))
        ):
            invalid_ids.add(disposition.item_id)
            continue
        by_id[disposition.item_id] = disposition
        accepted_hypothesis_ids.update(candidate_links)
    for item_id in invalid_ids:
        by_id.pop(item_id, None)
    unresolved = [target for target in targets if target.id not in by_id]
    return list(by_id.values()), unresolved, accepted_hypothesis_ids


def _canonicalize_batch_hypotheses(
    hypotheses: list[Hypothesis],
    reviewer: ReviewArea,
    batch_number: int,
    *,
    start_index: int = 1,
) -> dict[str, str]:
    """Assign stable IDs and canonical taxonomy ownership, returning the ID map."""
    prefixes = {
        "authorization_workflows": "authz",
        "injection_files": "inject",
        "xss_lifecycle": "xss",
        "authentication": "authn",
    }
    id_map: dict[str, str] = {}
    for index, hypothesis in enumerate(hypotheses, start_index):
        model_id = hypothesis.id
        hypothesis.id = f"{prefixes[reviewer]}-b{batch_number:03d}-{index:03d}"
        profile = get_known_cwe_profile(hypothesis.bug_class)
        hypothesis.specialist = (
            profile.reviewer
            if profile is not None
            and profile.reviewer is not None
            and profile.analysis_support in _REVIEWABLE_SUPPORT
            else reviewer
        )
        id_map[model_id] = hypothesis.id
    return id_map


logger = logging.getLogger(__name__)


def _build_specialists(runtime: AgentRuntime, model: str) -> list[Any]:
    return [
        FocusedSpecialist(
            runtime,
            model,
            name="authorization_workflows",
            prompt_path="specialists/authorization_workflows",
        ),
        FocusedSpecialist(
            runtime,
            model,
            name="injection_files",
            prompt_path="specialists/injection_files",
        ),
        FocusedSpecialist(
            runtime,
            model,
            name="xss_lifecycle",
            prompt_path="specialists/xss_lifecycle",
        ),
        FocusedSpecialist(
            runtime,
            model,
            name="authentication",
            prompt_path="specialists/authentication",
        ),
    ]


def _build_code_slices(
    hypotheses: list[Hypothesis], plugin_path: Path
) -> dict[str, str]:
    """Build line-numbered source windows around emitted hypotheses."""
    target_lines: dict[str, set[int]] = {}
    for hypothesis in hypotheses:
        if hypothesis.file:
            target_lines.setdefault(hypothesis.file, set()).add(hypothesis.line)
    slices: dict[str, str] = {}
    for rel, lines_of_interest in target_lines.items():
        full = (plugin_path / rel) if not Path(rel).is_absolute() else Path(rel)
        if not full.is_file():
            continue
        try:
            text = full.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        selected: set[int] = set()
        for line in lines_of_interest:
            selected.update(range(max(1, line - 30), min(len(lines), line + 30) + 1))
        rendered: list[str] = []
        previous = 0
        for line in sorted(selected):
            if previous and line > previous + 1:
                rendered.append("...")
            rendered.append(f"{line:5}  {lines[line - 1]}")
            previous = line
        slices[rel] = "\n".join(rendered)
    return slices


async def run(
    recon: ReconArtifact,
    plugin_path: str,
    config: PipelineConfig,
    budget: BudgetTracker,
    runtime: AgentRuntime,
    runs_root: str = "runs",
    run_id: str = "",
) -> HypothesesArtifact:
    model = config.models.specialists
    specialists = _build_specialists(runtime, model)

    # Reviewers run sequentially to avoid rate-limit bursts. Each reviewer gets
    # fresh, source-local batches rather than the complete recon artifact, and
    # every completed batch is checkpointed independently for resume.
    spec_dir = Path(runs_root) / run_id
    spec_dir.mkdir(parents=True, exist_ok=True)
    batch_root = spec_dir / "review_batches"
    merged: list[Hypothesis] = []
    coverage_dispositions: list[CoverageDisposition] = []
    for spec in specialists:
        spec_path = spec_dir / f"hypotheses_{spec.NAME}.jsonl"
        coverage_path = spec_dir / f"coverage_{spec.NAME}.json"
        targets = [
            item
            for item in (recon.coverage.items if recon.coverage else [])
            if spec.NAME in item.review_areas
        ]
        batches = _build_review_batches(targets)
        logger.info(
            "specialist %s: reviewing %d coverage items in %d bounded batches",
            spec.NAME,
            len(targets),
            len(batches),
        )
        specialist_hypotheses: list[Hypothesis] = []
        specialist_dispositions: list[CoverageDisposition] = []
        area_batch_dir = batch_root / spec.NAME
        area_batch_dir.mkdir(parents=True, exist_ok=True)

        for batch_number, batch_targets in enumerate(batches, 1):
            batch_id = f"b{batch_number:03d}"
            checkpoint = area_batch_dir / f"{batch_id}.json"
            target_ids = {target.id for target in batch_targets}
            input_fingerprint = _batch_input_fingerprint(
                recon,
                batch_targets,
                spec.NAME,
            )
            if checkpoint.exists():
                cached = SpecialistReviewArtifact.model_validate_json(
                    checkpoint.read_text()
                )
                cached_dispositions, cached_unresolved, cached_hypothesis_ids = (
                    _reconcile_batch_coverage(cached, batch_targets, spec.NAME)
                )
                cached_ids = {item.item_id for item in cached_dispositions}
                if (
                    cached.input_fingerprint == input_fingerprint
                    and not cached_unresolved
                    and cached_ids == target_ids
                    and cached_hypothesis_ids == {item.id for item in cached.hypotheses}
                ):
                    logger.info(
                        "specialist %s: loaded batch %d/%d checkpoint",
                        spec.NAME,
                        batch_number,
                        len(batches),
                    )
                    specialist_hypotheses.extend(cached.hypotheses)
                    specialist_dispositions.extend(cached.coverage)
                    continue

            unresolved = list(batch_targets)
            batch_hypotheses: list[Hypothesis] = []
            batch_dispositions: dict[str, CoverageDisposition] = {}
            for attempt in range(1, _REVIEW_BATCH_ATTEMPTS + 1):
                attempt_id = batch_id if attempt == 1 else f"{batch_id}-retry"
                priority_files = sorted({item.file for item in unresolved})
                logger.info(
                    "specialist %s: batch %d/%d attempt %d reviewing %d items across %d files",
                    spec.NAME,
                    batch_number,
                    len(batches),
                    attempt,
                    len(unresolved),
                    len(priority_files),
                )
                try:
                    result = await spec.analyze(
                        recon,
                        plugin_path=plugin_path,
                        priority_files=priority_files,
                        coverage_targets=unresolved,
                        batch_id=attempt_id,
                    )
                except Exception as exc:
                    logger.warning(
                        "specialist %s batch %s failed; aborting hypothesis stage: %s",
                        spec.NAME,
                        attempt_id,
                        exc,
                    )
                    raise
                accepted, unresolved, accepted_hypothesis_ids = (
                    _reconcile_batch_coverage(
                        result,
                        unresolved,
                        spec.NAME,
                    )
                )
                accepted_hypotheses = [
                    hypothesis
                    for hypothesis in result.hypotheses
                    if hypothesis.id in accepted_hypothesis_ids
                ]
                id_map = _canonicalize_batch_hypotheses(
                    accepted_hypotheses,
                    spec.NAME,
                    batch_number,
                    start_index=len(batch_hypotheses) + 1,
                )
                for disposition in accepted:
                    disposition.hypothesis_ids = [
                        id_map[hypothesis_id]
                        for hypothesis_id in disposition.hypothesis_ids
                    ]
                batch_dispositions.update({item.item_id: item for item in accepted})
                batch_hypotheses.extend(accepted_hypotheses)
                if not unresolved:
                    break

            if unresolved:
                unresolved_ids = ", ".join(item.id for item in unresolved)
                raise ValueError(
                    f"specialist {spec.NAME} batch {batch_id} left evidence-unreviewed "
                    f"coverage items after retry: {unresolved_ids}"
                )

            batch_result = SpecialistReviewArtifact(
                hypotheses=batch_hypotheses,
                coverage=[batch_dispositions[item.id] for item in batch_targets],
                input_fingerprint=input_fingerprint,
            )
            atomic_write_json(checkpoint, batch_result.model_dump(mode="json"))
            specialist_hypotheses.extend(batch_result.hypotheses)
            specialist_dispositions.extend(batch_result.coverage)

        # Aggregate compatibility artifacts remain convenient for users, while
        # review_batches/ contains the actual crash-safe checkpoints.
        atomic_write_jsonl(spec_path, specialist_hypotheses)
        atomic_write_json(
            coverage_path,
            [item.model_dump(mode="json") for item in specialist_dispositions],
        )
        coverage_dispositions.extend(specialist_dispositions)
        merged.extend(specialist_hypotheses)

    if recon.coverage is not None:
        recon.coverage.dispositions = coverage_dispositions
        coverage_path = spec_dir / "coverage.json"
        atomic_write_json(coverage_path, recon.coverage.model_dump(mode="json"))
        recon.to_json_file(str(spec_dir / "recon.json"))
        unresolved_count = sum(
            item.status == "unreviewed" for item in coverage_dispositions
        )
        logger.info(
            "hypothesis: coverage ledger recorded %d dispositions; unreviewed=%d -> %s",
            len(coverage_dispositions),
            unresolved_count,
            coverage_path,
        )

    # Merge exact duplicate candidates before paying for verification of each.
    pre_dedup_count = len(merged)
    if merged:
        merged, merge_log = _pre_verifier_dedup(merged)
        if merge_log:
            logger.info(
                "hypothesis: pre-verifier dedup merged %d -> %d (saved %d verifier calls)",
                pre_dedup_count,
                len(merged),
                pre_dedup_count - len(merged),
            )

    # Self-verification pass: cheap source-quote + guard check per hypothesis.
    # Drops hallucinated sinks and missed-guard claims before they reach triage/verify.
    verifier = HypothesisVerifier(
        runtime,
        model=config.models.hypothesis_verifier,
    )
    verdicts = await _verify_hypotheses(verifier, merged, plugin_path)

    kept: list = []
    drop_reasons: dict[str, str] = {}
    run_dir = Path(runs_root) / run_id

    for h, v in zip(merged, verdicts):
        if v.verdict == "keep":
            kept.append(h)
            append_decision(
                run_dir,
                stage="hypothesis_verifier",
                action="keep",
                result=v.verdict,
                hypothesis_id=h.id,
                reason=v.reason,
                details={"citation": v.citation} if v.citation else None,
            )
        elif v.verdict == "drop":
            drop_reasons[h.id] = v.reason
            logger.info(
                format_verifier_decision(h, v.verdict, v.reason, citation=v.citation)
            )
            append_decision(
                run_dir,
                stage="hypothesis_verifier",
                action="drop",
                result=v.verdict,
                hypothesis_id=h.id,
                reason=v.reason,
                artifact=run_dir / "hypothesis_verifier_drops.json",
                details={"citation": v.citation} if v.citation else None,
            )
        else:
            raise ValueError(
                f"verifier returned unknown verdict {v.verdict!r} for {h.id}"
            )

    if drop_reasons:
        verifier_path = run_dir / "hypothesis_verifier_drops.json"
        verifier_path.parent.mkdir(parents=True, exist_ok=True)
        drops_dump = {hid: {"reason": reason} for hid, reason in drop_reasons.items()}
        atomic_write_json(verifier_path, drops_dump)
        logger.info(
            "hypothesis: verifier dropped %d/%d -> %s",
            len(drop_reasons),
            len(merged),
            verifier_path,
        )
    artifact = HypothesesArtifact(plugin_slug=recon.plugin_slug, hypotheses=kept)
    out_path = Path(runs_root) / run_id / "hypotheses.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_jsonl(out_path, kept)
    logger.info(
        "hypothesis: wrote %d hypotheses to %s (verifier kept %d/%d)",
        len(kept),
        out_path,
        len(kept),
        len(merged),
    )
    return artifact
