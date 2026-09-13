"""Paired vulnerable/fixed benchmark runner for the complete scan pipeline."""

from __future__ import annotations

import json
import logging
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from pydantic import BaseModel

from squadrone.orchestrator import _resolve_run_dir, run_scan
from squadrone.schemas.finding import Finding, PoCStatus
from squadrone.schemas.hypothesis import Confidence, Hypothesis

logger = logging.getLogger(__name__)

_CONF_RANK = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}


class CorpusEntry(BaseModel):
    slug: str
    cve_id: str
    vulnerable_version: str
    fixed_version: str
    bug_class: str
    expected_file: str
    expected_function: str
    split: str = "train"
    notes: str = ""


class VariantResult(BaseModel):
    slug: str
    cve_id: str
    version: str
    expected_vulnerable: bool
    run_id: str
    status: str
    cost_usd: float
    duration_seconds: float
    candidate_rank: Optional[int]
    target_confirmed: bool
    target_finding_count: int
    finding_count: int
    hypothesis_count: int


class BenchmarkResult(BaseModel):
    corpus_path: str
    split: str
    pair_count: int
    scan_count: int
    variants: list[VariantResult]
    hypothesis_recall_at_1: float
    hypothesis_recall_at_3: float
    hypothesis_recall_at_10: float
    verified_recall: float
    target_confirmation_rate: float
    fixed_target_false_positive_rate: float
    paired_verified_precision: float
    cost_per_confirmed_target: float
    total_cost_usd: float
    per_bug_class: dict[str, dict]


def _matches(item: Finding | Hypothesis, entry: CorpusEntry) -> bool:
    hypothesis = item.hypothesis if isinstance(item, Finding) else item
    if hypothesis.root_cause_cwe != entry.bug_class:
        return False
    file_name = (hypothesis.file or "").lower()
    expected_function = entry.expected_function.lower()
    return (
        entry.expected_file.lower() in file_name
        or expected_function in (hypothesis.sink or "").lower()
        or expected_function in (hypothesis.entry_point or "").lower()
    )


def _load_jsonl(run_id: str, filename: str, model: type[BaseModel]) -> list:
    path = _resolve_run_dir(run_id) / filename
    if not path.exists():
        return []
    return [
        model.model_validate_json(line)
        for line in path.read_text().splitlines()
        if line.strip()
    ]


async def _run_variant(
    entry: CorpusEntry,
    version: str,
    expected_vulnerable: bool,
    config_path: str,
    budget: Optional[float],
) -> VariantResult:
    label = "vulnerable" if expected_vulnerable else "fixed"
    logger.info("benchmark: %s %s @ %s (%s)", entry.cve_id, entry.slug, version, label)
    started = time.time()
    try:
        scan = await run_scan(
            plugin_slug=entry.slug,
            config_path=config_path,
            budget_override=budget,
            version=version,
        )
    except Exception as exc:
        logger.exception("benchmark: scan crashed for %s@%s: %s", entry.slug, version, exc)
        return VariantResult(
            slug=entry.slug,
            cve_id=entry.cve_id,
            version=version,
            expected_vulnerable=expected_vulnerable,
            run_id="",
            status="crashed",
            cost_usd=0.0,
            duration_seconds=time.time() - started,
            candidate_rank=None,
            target_confirmed=False,
            target_finding_count=0,
            finding_count=0,
            hypothesis_count=0,
        )

    findings: list[Finding] = _load_jsonl(scan.run_id, "findings.jsonl", Finding)
    hypotheses: list[Hypothesis] = _load_jsonl(scan.run_id, "hypotheses.jsonl", Hypothesis)
    ranked = sorted(hypotheses, key=lambda item: (_CONF_RANK.get(item.confidence, 99), item.id))
    candidate_rank = next(
        (index for index, hypothesis in enumerate(ranked, 1) if _matches(hypothesis, entry)),
        None,
    )
    target_findings = [
        finding
        for finding in findings
        if finding.poc_status == PoCStatus.SUCCESS and _matches(finding, entry)
    ]
    return VariantResult(
        slug=entry.slug,
        cve_id=entry.cve_id,
        version=version,
        expected_vulnerable=expected_vulnerable,
        run_id=scan.run_id,
        status=scan.status,
        cost_usd=scan.cost_usd,
        duration_seconds=scan.duration_seconds,
        candidate_rank=candidate_rank,
        target_confirmed=bool(target_findings),
        target_finding_count=len(target_findings),
        finding_count=len(findings),
        hypothesis_count=len(hypotheses),
    )


def _compute_metrics(variants: list[VariantResult], corpus: list[CorpusEntry]) -> dict:
    vulnerable = [variant for variant in variants if variant.expected_vulnerable]
    fixed = [variant for variant in variants if not variant.expected_vulnerable]

    def hypothesis_recall_at(limit: int) -> float:
        if not vulnerable:
            return 0.0
        matched = sum(
            variant.candidate_rank is not None and variant.candidate_rank <= limit
            for variant in vulnerable
        )
        return matched / len(vulnerable)

    true_positives = sum(variant.target_finding_count for variant in vulnerable)
    false_positives = sum(variant.target_finding_count for variant in fixed)
    candidate_matches = sum(variant.candidate_rank is not None for variant in vulnerable)
    verified_pairs = sum(variant.target_confirmed for variant in vulnerable)
    total_cost = sum(variant.cost_usd for variant in variants)

    per_class: dict[str, dict] = defaultdict(
        lambda: {"pairs": 0, "candidate_matches": 0, "confirmed": 0, "fixed_false_positives": 0}
    )
    entries_by_key = {(entry.slug, entry.cve_id): entry for entry in corpus}
    for variant in variants:
        bug_class = entries_by_key[(variant.slug, variant.cve_id)].bug_class
        values = per_class[bug_class]
        if variant.expected_vulnerable:
            values["pairs"] += 1
            values["candidate_matches"] += int(variant.candidate_rank is not None)
            values["confirmed"] += int(variant.target_confirmed)
        else:
            values["fixed_false_positives"] += variant.target_finding_count
    per_bug_class = {
        bug_class: {
            **values,
            "hypothesis_recall": (
                values["candidate_matches"] / values["pairs"] if values["pairs"] else 0.0
            ),
            "verified_recall": values["confirmed"] / values["pairs"] if values["pairs"] else 0.0,
        }
        for bug_class, values in per_class.items()
    }

    return {
        "hypothesis_recall_at_1": hypothesis_recall_at(1),
        "hypothesis_recall_at_3": hypothesis_recall_at(3),
        "hypothesis_recall_at_10": hypothesis_recall_at(10),
        "verified_recall": verified_pairs / len(vulnerable) if vulnerable else 0.0,
        "target_confirmation_rate": verified_pairs / candidate_matches if candidate_matches else 0.0,
        "fixed_target_false_positive_rate": (
            sum(variant.target_confirmed for variant in fixed) / len(fixed) if fixed else 0.0
        ),
        "paired_verified_precision": (
            true_positives / (true_positives + false_positives)
            if true_positives + false_positives
            else 0.0
        ),
        "cost_per_confirmed_target": total_cost / true_positives if true_positives else 0.0,
        "total_cost_usd": total_cost,
        "per_bug_class": per_bug_class,
    }


async def run_benchmark(
    corpus_path: str,
    split: str = "train",
    config_path: str = "pipelines/chatgpt.yaml",
    budget_override: Optional[float] = None,
) -> BenchmarkResult:
    corpus_data = json.loads(Path(corpus_path).read_text())
    corpus = [CorpusEntry.model_validate(item) for item in corpus_data]
    selected = [entry for entry in corpus if entry.split == split]
    logger.info("benchmark: %d/%d pairs in split=%s", len(selected), len(corpus), split)

    variants: list[VariantResult] = []
    for entry in selected:
        variants.append(await _run_variant(
            entry, entry.vulnerable_version, True, config_path, budget_override,
        ))
        variants.append(await _run_variant(
            entry, entry.fixed_version, False, config_path, budget_override,
        ))

    result = BenchmarkResult(
        corpus_path=corpus_path,
        split=split,
        pair_count=len(selected),
        scan_count=len(variants),
        variants=variants,
        **_compute_metrics(variants, selected),
    )
    out_dir = Path("benchmarks/results")
    out_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = out_dir / f"{timestamp}.json"
    out_path.write_text(result.model_dump_json(indent=2))
    logger.info("benchmark: wrote %s", out_path)
    return result
