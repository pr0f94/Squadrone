from __future__ import annotations

from benchmarks.runner import CorpusEntry, VariantResult, _compute_metrics


def _corpus(slug: str, cve: str, bug_class: str) -> CorpusEntry:
    return CorpusEntry(
        slug=slug,
        cve_id=cve,
        vulnerable_version="1.0",
        fixed_version="1.1",
        bug_class=bug_class,
        expected_file="plugin.php",
        expected_function="handler",
    )


def _variant(
    slug: str,
    cve: str,
    *,
    vulnerable: bool,
    rank: int | None,
    confirmed: bool,
    target_count: int,
    cost: float = 1.0,
) -> VariantResult:
    return VariantResult(
        slug=slug,
        cve_id=cve,
        version="1.0" if vulnerable else "1.1",
        expected_vulnerable=vulnerable,
        run_id="run",
        status="complete",
        cost_usd=cost,
        duration_seconds=1.0,
        candidate_rank=rank,
        target_confirmed=confirmed,
        target_finding_count=target_count,
        finding_count=target_count,
        hypothesis_count=5,
    )


def test_metrics_separate_hypothesis_recall_from_clean_confirmation_and_fixed_fp():
    corpus = [
        _corpus("one", "CVE-1", "CWE-89"),
        _corpus("two", "CVE-2", "CWE-79"),
    ]
    variants = [
        _variant("one", "CVE-1", vulnerable=True, rank=1, confirmed=True, target_count=1),
        _variant("one", "CVE-1", vulnerable=False, rank=2, confirmed=True, target_count=1),
        _variant("two", "CVE-2", vulnerable=True, rank=4, confirmed=False, target_count=0),
        _variant("two", "CVE-2", vulnerable=False, rank=None, confirmed=False, target_count=0),
    ]

    metrics = _compute_metrics(variants, corpus)

    assert metrics["hypothesis_recall_at_1"] == 0.5
    assert metrics["hypothesis_recall_at_3"] == 0.5
    assert metrics["hypothesis_recall_at_10"] == 1.0
    assert metrics["verified_recall"] == 0.5
    assert metrics["target_confirmation_rate"] == 0.5
    assert metrics["fixed_target_false_positive_rate"] == 0.5
    assert metrics["paired_verified_precision"] == 0.5
    assert metrics["cost_per_confirmed_target"] == 4.0
