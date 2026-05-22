"""Benchmark runner — runs scans on the corpus and computes recall/precision/cost metrics."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from pydantic import BaseModel

from squadrone.orchestrator import _resolve_run_dir, run_scan
from squadrone.schemas.finding import DedupStatus, Finding, PoCStatus
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


class EntryResult(BaseModel):
    slug: str
    cve_id: str
    run_id: str
    status: str
    cost_usd: float
    duration_seconds: float
    matched_at_rank: Optional[int]      # 1-based; None = not found
    matched_via: Optional[str]          # "finding" | "hypothesis" | None
    poc_succeeded: bool
    finding_count: int
    hypothesis_count: int


class BenchmarkResult(BaseModel):
    corpus_path: str
    split: str
    entry_count: int
    entries: list[EntryResult]
    recall_at_1: float
    recall_at_3: float
    recall_at_10: float
    precision: float                    # findings matching corpus / total findings
    poc_success_rate: float             # findings with successful PoC / corpus matches
    cost_per_finding: float
    total_cost_usd: float
    per_bug_class: dict[str, dict]      # bug_class -> {recall, count}


def _matches(item: Finding | Hypothesis, entry: CorpusEntry) -> bool:
    """Match a finding or hypothesis against the corpus entry."""
    h = item.hypothesis if isinstance(item, Finding) else item
    if h.bug_class.value != entry.bug_class:
        return False
    file_l = (h.file or "").lower()
    fn_l = (h.sink or "").lower()
    handler_l = entry.expected_function.lower()
    return (
        entry.expected_file.lower() in file_l
        or handler_l in fn_l
        or handler_l in (item.hypothesis.entry_point if isinstance(item, Finding) else item.entry_point).lower()
    )


def _load_findings(run_id: str) -> list[Finding]:
    p = _resolve_run_dir(run_id) / "findings.jsonl"
    if not p.exists():
        return []
    out: list[Finding] = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if line:
            out.append(Finding.model_validate_json(line))
    return out


def _load_hypotheses(run_id: str) -> list[Hypothesis]:
    p = _resolve_run_dir(run_id) / "hypotheses.jsonl"
    if not p.exists():
        return []
    out: list[Hypothesis] = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if line:
            out.append(Hypothesis.model_validate_json(line))
    return out


async def _run_one(entry: CorpusEntry, config_path: str, budget: Optional[float], no_triage: bool = False, apply_scope_filter: bool = True) -> EntryResult:
    logger.info("benchmark: %s %s @ %s", entry.cve_id, entry.slug, entry.vulnerable_version)
    started = time.time()
    try:
        scan = await run_scan(
            plugin_slug=entry.slug,
            config_path=config_path,
            budget_override=budget,
            version=entry.vulnerable_version,
            no_triage=no_triage,
            apply_scope_filter=apply_scope_filter,
        )
    except Exception as e:
        logger.exception("benchmark: scan crashed for %s: %s", entry.slug, e)
        return EntryResult(
            slug=entry.slug, cve_id=entry.cve_id, run_id="",
            status="crashed", cost_usd=0.0,
            duration_seconds=time.time() - started,
            matched_at_rank=None, matched_via=None,
            poc_succeeded=False, finding_count=0, hypothesis_count=0,
        )

    findings = _load_findings(scan.run_id)
    hypotheses = _load_hypotheses(scan.run_id)

    # Try findings first (sorted by hypothesis confidence), then fall back to hypotheses.
    findings_sorted = sorted(findings, key=lambda f: _CONF_RANK.get(f.hypothesis.confidence, 99))
    matched_rank: Optional[int] = None
    matched_via: Optional[str] = None
    poc_ok = False
    for i, f in enumerate(findings_sorted, 1):
        if _matches(f, entry):
            matched_rank = i
            matched_via = "finding"
            poc_ok = f.poc_status == PoCStatus.SUCCESS
            break
    if matched_rank is None:
        hyps_sorted = sorted(hypotheses, key=lambda h: _CONF_RANK.get(h.confidence, 99))
        for i, h in enumerate(hyps_sorted, 1):
            if _matches(h, entry):
                matched_rank = i
                matched_via = "hypothesis"
                break

    return EntryResult(
        slug=entry.slug, cve_id=entry.cve_id, run_id=scan.run_id,
        status=scan.status, cost_usd=scan.cost_usd,
        duration_seconds=scan.duration_seconds,
        matched_at_rank=matched_rank, matched_via=matched_via,
        poc_succeeded=poc_ok,
        finding_count=len(findings), hypothesis_count=len(hypotheses),
    )


def _compute_metrics(entries: list[EntryResult], corpus: list[CorpusEntry]) -> dict:
    n = len(entries) or 1

    def recall_at(k: int) -> float:
        return sum(1 for e in entries if e.matched_at_rank is not None and e.matched_at_rank <= k) / n

    total_findings = sum(e.finding_count for e in entries)
    matched_count = sum(1 for e in entries if e.matched_at_rank is not None)
    precision = (matched_count / total_findings) if total_findings else 0.0
    poc_rate = (sum(1 for e in entries if e.poc_succeeded) / matched_count) if matched_count else 0.0
    total_cost = sum(e.cost_usd for e in entries)
    cost_per_finding = (total_cost / total_findings) if total_findings else 0.0

    per_bc: dict[str, dict] = defaultdict(lambda: {"count": 0, "matched": 0})
    by_slug = {c.slug: c for c in corpus}
    for e in entries:
        bc = by_slug[e.slug].bug_class
        per_bc[bc]["count"] += 1
        if e.matched_at_rank is not None:
            per_bc[bc]["matched"] += 1
    per_bug_class = {
        bc: {**v, "recall": (v["matched"] / v["count"]) if v["count"] else 0.0}
        for bc, v in per_bc.items()
    }

    return {
        "recall_at_1": recall_at(1),
        "recall_at_3": recall_at(3),
        "recall_at_10": recall_at(10),
        "precision": precision,
        "poc_success_rate": poc_rate,
        "cost_per_finding": cost_per_finding,
        "total_cost_usd": total_cost,
        "per_bug_class": per_bug_class,
    }


async def run_benchmark(
    corpus_path: str,
    split: str = "train",
    config_path: str = "pipelines/default.yaml",
    budget_override: Optional[float] = None,
    no_triage: bool = False,
    apply_scope_filter: bool = True,
) -> BenchmarkResult:
    corpus_data = json.loads(Path(corpus_path).read_text())
    corpus = [CorpusEntry.model_validate(e) for e in corpus_data]
    filtered = [c for c in corpus if c.split == split]
    logger.info("benchmark: %d/%d entries in split=%s", len(filtered), len(corpus), split)

    entries: list[EntryResult] = []
    for c in filtered:
        entries.append(await _run_one(c, config_path, budget_override, no_triage=no_triage, apply_scope_filter=apply_scope_filter))

    metrics = _compute_metrics(entries, filtered)
    result = BenchmarkResult(
        corpus_path=corpus_path,
        split=split,
        entry_count=len(filtered),
        entries=entries,
        **metrics,
    )

    out_dir = Path("benchmarks/results")
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = out_dir / f"{ts}.json"
    out_path.write_text(result.model_dump_json(indent=2))
    logger.info("benchmark: wrote %s", out_path)
    return result
