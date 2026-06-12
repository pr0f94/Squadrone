from __future__ import annotations

from squadrone.schemas import BugClass, Confidence, Hypothesis
from squadrone.services import verify_helpers


def _hypothesis() -> Hypothesis:
    return Hypothesis(
        id="xss-001",
        specialist="xss",
        bug_class=BugClass.XSS_STORED,
        entry_point="wp_ajax_demo",
        file="demo.php",
        line=22,
        sink="echo $value",
        taint_path=["$_POST['value']", "echo"],
        reasoning="Contributor input is rendered to an administrator.",
        confidence=Confidence.MEDIUM,
        preconditions="contributor",
        affected_versions="<=1.0",
    )


def test_manual_review_queue_dedupes_by_run_hypothesis_and_source(tmp_path, monkeypatch):
    queue_path = tmp_path / "manual.jsonl"
    monkeypatch.setattr(verify_helpers, "MANUAL_REVIEW_QUEUE", queue_path)
    hyp = _hypothesis()
    run_dir = tmp_path / "runs" / "abc123"

    verify_helpers.emit_to_manual_review_queue(
        hyp,
        run_dir,
        reason="needs manual review",
        verifier_notes={"source": "quality_gate"},
    )
    verify_helpers.emit_to_manual_review_queue(
        hyp,
        run_dir,
        reason="needs manual review again",
        verifier_notes={"source": "quality_gate"},
    )
    verify_helpers.emit_to_manual_review_queue(
        hyp,
        run_dir,
        reason="different source",
        verifier_notes={"source": "verify"},
    )

    lines = queue_path.read_text().splitlines()
    assert len(lines) == 2
