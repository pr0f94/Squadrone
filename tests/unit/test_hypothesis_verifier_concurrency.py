from __future__ import annotations

import asyncio

import pytest

from squadrone.agents.hypothesis_verifier import HypothesisVerifier, VerifierVerdict
from squadrone.schemas import BugClass, Confidence, Hypothesis
from squadrone.stages import hypothesis as hypothesis_stage


class _Hypothesis:
    def __init__(self, hypothesis_id: str) -> None:
        self.id = hypothesis_id


class _Verifier:
    def __init__(self, *, fail_on: str | None = None) -> None:
        self.active = 0
        self.max_active = 0
        self.fail_on = fail_on

    async def verify(self, hypothesis: _Hypothesis, plugin_path: str) -> str:
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        try:
            await asyncio.sleep(0)
            if hypothesis.id == self.fail_on:
                raise RuntimeError("upstream unavailable")
            return hypothesis.id
        finally:
            self.active -= 1


@pytest.mark.asyncio
async def test_verifier_requests_are_limited_to_small_batches():
    verifier = _Verifier()
    hypotheses = [_Hypothesis(f"h-{index}") for index in range(8)]

    verdicts = await hypothesis_stage._verify_hypotheses(
        verifier, hypotheses, "/plugin"
    )

    assert verdicts == [hypothesis.id for hypothesis in hypotheses]
    assert verifier.max_active == hypothesis_stage._VERIFIER_BATCH_SIZE


@pytest.mark.asyncio
async def test_verifier_transport_failure_aborts_instead_of_keeping_hypothesis():
    verifier = _Verifier(fail_on="h-1")
    hypotheses = [_Hypothesis("h-0"), _Hypothesis("h-1"), _Hypothesis("h-2")]

    with pytest.raises(RuntimeError, match="upstream unavailable"):
        await hypothesis_stage._verify_hypotheses(verifier, hypotheses, "/plugin")


@pytest.mark.asyncio
async def test_unreadable_citation_is_dropped_without_calling_model(tmp_path):
    verifier = HypothesisVerifier(runtime=object(), model="unused")  # type: ignore[arg-type]
    hypothesis = Hypothesis(
        id="h-missing",
        specialist="injection_files",
        bug_class=BugClass.SQLI,
        entry_point="wp_ajax_nopriv_demo",
        file="missing.php",
        line=10,
        sink="$wpdb->query",
        sink_code="$wpdb->query($_GET['id'])",
        taint_path=["$_GET['id']", "$wpdb->query"],
        reasoning="Unauthenticated SQL injection.",
        confidence=Confidence.HIGH,
        preconditions="unauthenticated",
        affected_versions="current",
    )

    verdict = await verifier.verify(hypothesis, str(tmp_path))

    assert verdict.verdict == "drop"
    assert "not source-grounded" in verdict.reason


@pytest.mark.asyncio
async def test_unique_adjacent_sink_quote_is_relocated_before_source_verification(
    tmp_path,
):
    (tmp_path / "demo.php").write_text(
        "<?php\nsafe_call();\n$wpdb->query($_GET['id']);\n"
    )

    class Runtime:
        def __init__(self) -> None:
            self.user_prompt = ""

        async def run(self, **kwargs):
            self.user_prompt = kwargs["messages"][-1]["content"]
            return type(
                "Result",
                (),
                {
                    "output": VerifierVerdict(
                        verdict="keep",
                        reason="the normalized citation matches the exact sink",
                    ),
                },
            )()

    runtime = Runtime()
    verifier = HypothesisVerifier(runtime=runtime, model="test")  # type: ignore[arg-type]
    hypothesis = Hypothesis(
        id="h-drift",
        specialist="injection_files",
        bug_class=BugClass.SQLI,
        entry_point="wp_ajax_nopriv_demo",
        file="demo.php",
        line=2,
        sink="$wpdb->query",
        sink_code="$wpdb->query($_GET['id']);",
        taint_path=["$_GET['id']", "$wpdb->query"],
        reasoning="Unauthenticated SQL injection.",
        confidence=Confidence.HIGH,
        preconditions="unauthenticated",
        affected_versions="current",
    )

    verdict = await verifier.verify(hypothesis, str(tmp_path))

    assert verdict.verdict == "keep"
    assert hypothesis.line == 3
    assert "around line 3" in runtime.user_prompt
    assert "normalized from demo.php:2 to demo.php:3" in (verdict.citation or "")


@pytest.mark.asyncio
async def test_sink_quote_outside_bounded_line_drift_is_dropped(tmp_path):
    (tmp_path / "demo.php").write_text(
        "<?php\n" + "safe_call();\n" * 15 + "$wpdb->query($_GET['id']);\n"
    )
    verifier = HypothesisVerifier(runtime=object(), model="unused")  # type: ignore[arg-type]
    hypothesis = Hypothesis(
        id="h-far-drift",
        specialist="injection_files",
        bug_class=BugClass.SQLI,
        entry_point="wp_ajax_nopriv_demo",
        file="demo.php",
        line=1,
        sink="$wpdb->query",
        sink_code="$wpdb->query($_GET['id']);",
        taint_path=["$_GET['id']", "$wpdb->query"],
        reasoning="Unauthenticated SQL injection.",
        confidence=Confidence.HIGH,
        preconditions="unauthenticated",
        affected_versions="current",
    )

    verdict = await verifier.verify(hypothesis, str(tmp_path))

    assert verdict.verdict == "drop"
    assert "within ±15 lines" in verdict.reason


@pytest.mark.asyncio
async def test_relocation_does_not_use_fuzzy_whitespace_matching(tmp_path):
    (tmp_path / "demo.php").write_text(
        "<?php\nsafe_call();\n$wpdb->query(  $_GET['id']  );\n"
    )
    verifier = HypothesisVerifier(runtime=object(), model="unused")  # type: ignore[arg-type]
    hypothesis = Hypothesis(
        id="h-fuzzy-drift",
        specialist="injection_files",
        bug_class=BugClass.SQLI,
        entry_point="wp_ajax_nopriv_demo",
        file="demo.php",
        line=2,
        sink="$wpdb->query",
        sink_code="$wpdb->query( $_GET['id'] );",
        taint_path=["$_GET['id']", "$wpdb->query"],
        reasoning="Unauthenticated SQL injection.",
        confidence=Confidence.HIGH,
        preconditions="unauthenticated",
        affected_versions="current",
    )

    verdict = await verifier.verify(hypothesis, str(tmp_path))

    assert verdict.verdict == "drop"
    assert "within ±15 lines" in verdict.reason


@pytest.mark.asyncio
async def test_ambiguous_nearby_sink_quotes_are_dropped(tmp_path):
    (tmp_path / "demo.php").write_text(
        "<?php\n$wpdb->query($_GET['id']);\nsafe_call();\n$wpdb->query($_GET['id']);\n"
    )
    verifier = HypothesisVerifier(runtime=object(), model="unused")  # type: ignore[arg-type]
    hypothesis = Hypothesis(
        id="h-ambiguous-drift",
        specialist="injection_files",
        bug_class=BugClass.SQLI,
        entry_point="wp_ajax_nopriv_demo",
        file="demo.php",
        line=3,
        sink="$wpdb->query",
        sink_code="$wpdb->query($_GET['id']);",
        taint_path=["$_GET['id']", "$wpdb->query"],
        reasoning="Unauthenticated SQL injection.",
        confidence=Confidence.HIGH,
        preconditions="unauthenticated",
        affected_versions="current",
    )

    verdict = await verifier.verify(hypothesis, str(tmp_path))

    assert verdict.verdict == "drop"
    assert "multiple nearby matches" in verdict.reason


@pytest.mark.asyncio
async def test_exact_sink_quote_reaches_source_verifier(tmp_path):
    (tmp_path / "demo.php").write_text("<?php\n$wpdb->query($_GET['id']);\n")

    class Runtime:
        def __init__(self) -> None:
            self.called = False

        async def run(self, **kwargs):
            self.called = True
            return type(
                "Result",
                (),
                {
                    "output": VerifierVerdict(
                        verdict="keep",
                        reason="citation matches and no local contradiction is visible",
                    ),
                },
            )()

    runtime = Runtime()
    verifier = HypothesisVerifier(runtime=runtime, model="test")  # type: ignore[arg-type]
    hypothesis = Hypothesis(
        id="h-exact",
        specialist="injection_files",
        bug_class=BugClass.SQLI,
        entry_point="wp_ajax_nopriv_demo",
        file="demo.php",
        line=2,
        sink="$wpdb->query",
        sink_code="$wpdb->query($_GET['id']);",
        taint_path=["$_GET['id']", "$wpdb->query"],
        reasoning="Unauthenticated SQL injection.",
        confidence=Confidence.HIGH,
        preconditions="unauthenticated",
        affected_versions="current",
    )

    verdict = await verifier.verify(hypothesis, str(tmp_path))

    assert runtime.called is True
    assert verdict.verdict == "keep"
