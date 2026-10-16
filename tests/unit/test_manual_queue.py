from __future__ import annotations

import json

from squadrone import orchestrator
from squadrone.schemas import BugClass, Confidence, Hypothesis, TriagedArtifact
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


def test_manual_review_queue_dedupes_only_the_same_claim_reason_and_source(
    tmp_path,
    monkeypatch,
):
    queue_path = tmp_path / "manual.jsonl"
    monkeypatch.setattr(verify_helpers, "MANUAL_REVIEW_QUEUE", queue_path)
    hyp = _hypothesis()
    run_dir = tmp_path / "runs" / "abc123"

    first = verify_helpers.emit_to_manual_review_queue(
        hyp,
        run_dir,
        reason="needs manual review",
        verifier_notes={"source": "quality_gate"},
    )
    second = verify_helpers.emit_to_manual_review_queue(
        hyp,
        run_dir,
        reason="needs manual review",
        verifier_notes={"source": "quality_gate"},
    )
    third = verify_helpers.emit_to_manual_review_queue(
        hyp,
        run_dir,
        reason="new source evidence needs manual review",
        verifier_notes={"source": "quality_gate"},
    )
    fourth = verify_helpers.emit_to_manual_review_queue(
        hyp,
        run_dir,
        reason="different source",
        verifier_notes={"source": "verify"},
    )

    assert first is True
    assert second is False
    assert third is True
    assert fourth is True
    rows = [json.loads(line) for line in queue_path.read_text().splitlines()]
    assert len(rows) == 3
    assert all(
        row["policy_version"]
        == verify_helpers.MANUAL_REVIEW_QUEUE_POLICY_VERSION
        for row in rows
    )
    assert len({row["fingerprint"] for row in rows}) == 3


def test_triage_manual_queue_refreshes_reused_id_when_claim_changes(
    tmp_path,
    monkeypatch,
) -> None:
    queue_path = tmp_path / "manual.jsonl"
    monkeypatch.setattr(verify_helpers, "MANUAL_REVIEW_QUEUE", queue_path)
    run_dir = tmp_path / "runs" / "abc123"
    run_dir.mkdir(parents=True)

    original = _hypothesis()
    first = TriagedArtifact(
        plugin_slug="demo",
        accepted=[],
        rejected=[],
        merged=[],
        manual_review=[
            {
                "hypothesis_id": original.id,
                "reason": "unsupported nested field",
                "source": "quality_gate",
                "hypothesis": original.model_dump(mode="json"),
            }
        ],
    )
    first_result = orchestrator._emit_triage_manual_review_queue(
        first,
        run_dir,
        "demo",
    )

    changed = original.model_copy(
        update={
            "file": "changed.php",
            "line": 91,
            "sink": "print $changed",
            "sink_code": "print $changed;",
        }
    )
    resumed = TriagedArtifact(
        plugin_slug="demo",
        accepted=[],
        rejected=[],
        merged=[],
        manual_review=[
            {
                "hypothesis_id": changed.id,
                "reason": "unsupported header field",
                "source": "quality_gate",
                "hypothesis": changed.model_dump(mode="json"),
            }
        ],
    )
    resumed_result = orchestrator._emit_triage_manual_review_queue(
        resumed,
        run_dir,
        "demo",
    )
    unchanged_result = orchestrator._emit_triage_manual_review_queue(
        resumed,
        run_dir,
        "demo",
    )

    assert first_result["manual_queued"] == 1
    assert resumed_result["manual_queued"] == 1
    assert unchanged_result["manual_queued"] == 0
    assert unchanged_result["already_queued"] == 1
    rows = [json.loads(line) for line in queue_path.read_text().splitlines()]
    assert len(rows) == 2
    assert rows[0]["fingerprint"] != rows[1]["fingerprint"]
    context_path = (
        run_dir
        / "verifications"
        / changed.id
        / "manual_scaffold"
        / "context.json"
    )
    context = json.loads(context_path.read_text())
    assert context["hypothesis"]["file"] == "changed.php"
    marker = json.loads((run_dir / "manual_review_queued.json").read_text())
    assert marker["policy_version"] == verify_helpers.MANUAL_REVIEW_QUEUE_POLICY_VERSION
    assert marker["fingerprints"][changed.id] == rows[1]["fingerprint"]
