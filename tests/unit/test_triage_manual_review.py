from __future__ import annotations

from squadrone.schemas import BugClass, Confidence, Hypothesis, HypothesesArtifact, TriagedArtifact
from squadrone.stages.triage import _combine_vote_artifacts


def _hypothesis(hypothesis_id: str) -> Hypothesis:
    return Hypothesis(
        id=hypothesis_id,
        specialist="xss",
        bug_class=BugClass.XSS_STORED,
        entry_point="wp_ajax_demo",
        file="demo.php",
        line=10,
        sink="echo $value",
        sink_code="echo $value;",
        taint_path=["$_POST['value']", "echo"],
        reasoning="Subscriber input is stored and rendered to an administrator.",
        confidence=Confidence.MEDIUM,
        preconditions="subscriber",
        affected_versions="<=1.0",
    )


def test_split_triage_votes_route_to_manual_review():
    hyp = _hypothesis("xss-001")
    original = HypothesesArtifact(plugin_slug="demo", hypotheses=[hyp])
    votes = [
        TriagedArtifact(plugin_slug="demo", accepted=[hyp], rejected=[], merged=[]),
        TriagedArtifact(
            plugin_slug="demo",
            accepted=[],
            rejected=[{"hypothesis_id": hyp.id, "reason": "needs proof"}],
            merged=[],
        ),
        TriagedArtifact(
            plugin_slug="demo",
            accepted=[],
            rejected=[{"hypothesis_id": hyp.id, "reason": "impact unclear"}],
            merged=[],
        ),
    ]

    combined = _combine_vote_artifacts(votes, original)

    assert combined.accepted == []
    assert combined.rejected == []
    assert combined.manual_review[0]["hypothesis_id"] == "xss-001"
    assert combined.manual_review[0]["source"] == "triage_votes"
