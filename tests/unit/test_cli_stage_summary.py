from __future__ import annotations

from squadrone.cli import _stage_done_summary


def test_triage_summary_labels_manual_review_candidates():
    summary = _stage_done_summary(
        "triage",
        {
            "accepted": 1,
            "rejected": 3,
            "merged": 1,
            "manual_review_candidates": 1,
            "spent": 29.5516,
        },
    )

    assert "manual review candidates 1" in summary
    assert "manual review 1" not in summary


def test_manual_queue_summary_shows_new_and_existing_counts():
    summary = _stage_done_summary(
        "manual_queue",
        {
            "candidates": 2,
            "manual_queued": 1,
            "already_queued": 1,
            "unavailable": 0,
            "reason": "triage_or_quality_gate",
        },
    )

    assert summary == (
        "candidates 2 · manual queued 1 · already queued 1 · "
        "reason triage_or_quality_gate"
    )
