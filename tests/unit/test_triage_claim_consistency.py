from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from squadrone.agents.critic import CriticAgent
from squadrone.agents.prompts_io import load_prompt
from squadrone.schemas.hypothesis import (
    HypothesesArtifact,
    Hypothesis,
    TriagedArtifact,
)
from squadrone.services.quality_gate import (
    apply_quality_gate,
    automatic_verifier_contract_violations,
    grade_hypothesis,
    infer_attacker_role,
)
from squadrone.stages.triage import _scanned_version, _validate_critic_accounting


def _candidate(**updates: Any) -> Hypothesis:
    values: dict[str, Any] = {
        "id": "review-1",
        "specialist": "authorization_workflows",
        "bug_class": "CWE-639",
        "entry_point": "wp_ajax_read_record",
        "file": "record.php",
        "line": 10,
        "sink": "get_post_meta",
        "sink_code": "get_post_meta($id, '_private', true);",
        "taint_path": ["$_GET['id']", "read_record", "get_post_meta"],
        "reasoning": "The selected record belongs to another account.",
        "confidence": "high",
        "preconditions": "Subscriber attacker can invoke the record-reading action.",
        "affected_versions": "2.0.3",
        "security_outcome": {
            "confidentiality": "high",
            "description": "Disclosure of another user's private record.",
        },
        "evidence_summary": {
            "attacker_role": "subscriber",
            "source": "$_GET['id']",
            "control": "No object ownership check in the record-reading callback.",
            "reachable_path": "wp_ajax_read_record -> read_record -> get_post_meta",
            "boundary": "A Subscriber reads another user's private record.",
        },
    }
    values.update(updates)
    return Hypothesis.model_validate(values)


@pytest.mark.parametrize(
    "incidental",
    [
        "An unauthenticated caller cannot reach the action.",
        "The victim is an Administrator who opens the output.",
        "The administrator enables the shipped feature.",
        "There is no proof that a Contributor is the caller.",
    ],
)
def test_missing_attacker_role_is_not_inferred_from_unrelated_text(
    incidental: str,
) -> None:
    hypothesis = _candidate(
        preconditions="A normal account is required.",
        reasoning=incidental,
        evidence_summary={
            "source": "$_GET['id']",
            "boundary": "Read another user's private record.",
        },
    )
    assert infer_attacker_role(hypothesis) == "unknown"
    assert "attacker_role_unresolved" in grade_hypothesis(hypothesis).rules


def test_precondition_role_is_inferred_without_scanning_victim_or_negated_roles() -> (
    None
):
    hypothesis = _candidate(
        preconditions="Subscriber attacker; an Administrator victim views the output.",
        reasoning="Unauthenticated requests are rejected.",
        evidence_summary={},
    )
    assert infer_attacker_role(hypothesis) == "subscriber"


def test_canonical_role_with_capability_annotation_is_not_false_manual() -> None:
    hypothesis = _candidate(
        preconditions="Attacker: Contributor (edit_posts on own draft).",
        evidence_summary={
            **_candidate().evidence_summary,
            "attacker_role": "Contributor (edit_posts on own draft)",
        },
    )
    assert grade_hypothesis(hypothesis, scanned_version="2.0.3").accepted


def test_nopriv_fallback_requires_a_hook_not_an_incidental_mention() -> None:
    hypothesis = _candidate(
        entry_point="No wp_ajax_nopriv_demo handler is registered",
        preconditions="Normal account setup is required.",
        evidence_summary={},
    )
    assert infer_attacker_role(hypothesis) == "unknown"
    hypothesis.entry_point = "wp_ajax_nopriv_demo"
    assert infer_attacker_role(hypothesis) == "unauthenticated"


def test_cross_field_role_conflict_is_retained_unchanged_for_manual_review() -> None:
    hypothesis = _candidate(
        preconditions=(
            "Default shipped configuration. Attacker can author post content "
            "containing raw block markup (an Editor with unfiltered_html on a "
            "default single-site install) and the post is publicly rendered."
        ),
        evidence_summary={
            **_candidate().evidence_summary,
            "attacker_role": "contributor",
        },
    )
    original = hypothesis.model_dump(mode="json")
    assert automatic_verifier_contract_violations(hypothesis) == [
        "attacker_role_preconditions_mismatch"
    ]
    result = apply_quality_gate(
        TriagedArtifact(
            plugin_slug="example", accepted=[hypothesis], rejected=[], merged=[]
        ),
        scanned_version="2.0.3",
    )
    assert result.accepted == []
    assert result.rejected == []
    assert result.manual_review[0]["rules"] == ["attacker_role_preconditions_mismatch"]
    assert result.manual_review[0]["hypothesis"] == original
    assert hypothesis.model_dump(mode="json") == original


def test_explicit_attacker_alternatives_do_not_conflict_with_a_member_role() -> None:
    hypothesis = _candidate(
        preconditions="Attacker is a Subscriber or Customer; Administrator is the victim.",
    )
    assert grade_hypothesis(hypothesis, scanned_version="2.0.3").accepted


def test_lowest_role_marker_is_not_overridden_by_a_later_editor_alternative() -> None:
    hypothesis = _candidate(
        preconditions=(
            "Shipped default configuration. Lowest role: Contributor saving its "
            "own draft and previewing that draft, or Author publishing its own "
            "post; an Editor with unfiltered_html can submit content directly."
        ),
        evidence_summary={
            **_candidate().evidence_summary,
            "attacker_role": "contributor",
        },
    )
    assert grade_hypothesis(hypothesis, scanned_version="2.0.3").accepted


@pytest.mark.parametrize("claim", ["2.0.3", "v2.0.3", "version 2.0.3", "2.0.3 only"])
def test_version_gate_accepts_the_inspected_version(claim: str) -> None:
    assert grade_hypothesis(
        _candidate(affected_versions=claim), scanned_version="2.0.3"
    ).accepted


@pytest.mark.parametrize(
    "claim",
    [
        "<=2.0.3",
        "2.0.3 and earlier versions in this source tree",
        "2.0.3 and all versions shipping this callback",
        "2.0.1-2.0.3",
        "2.0.4",
        "all versions",
    ],
)
def test_version_gate_does_not_rewrite_uninspected_version_claims(claim: str) -> None:
    hypothesis = _candidate(affected_versions=claim)
    original = hypothesis.model_dump(mode="json")
    result = apply_quality_gate(
        TriagedArtifact(
            plugin_slug="example", accepted=[hypothesis], rejected=[], merged=[]
        ),
        scanned_version="2.0.3",
    )
    assert not result.accepted
    assert not result.rejected
    assert result.manual_review[0]["rules"] == ["affected_versions_not_inspected"]
    assert result.manual_review[0]["hypothesis"] == original


def test_version_gate_fails_closed_when_active_scope_lacks_provenance() -> None:
    assert grade_hypothesis(_candidate(), scanned_version="").rules == [
        "affected_versions_not_inspected"
    ]


@pytest.mark.parametrize(
    "field", ["preconditions", "affected_versions", "attacker_role"]
)
def test_critic_cannot_launder_immutable_prerequisites_without_an_anchor_repair(
    field: str,
) -> None:
    original = _candidate()
    altered = original.model_copy(deep=True)
    if field == "attacker_role":
        altered.evidence_summary[field] = "editor"
    else:
        setattr(altered, field, "Changed claim")
    with pytest.raises(ValueError, match="changed verifier contract fields"):
        _validate_critic_accounting(
            HypothesesArtifact(plugin_slug="example", hypotheses=[original]),
            TriagedArtifact(
                plugin_slug="example", accepted=[altered], rejected=[], merged=[]
            ),
        )


def test_scanned_version_requires_matching_intake_provenance(tmp_path: Path) -> None:
    assert _scanned_version(tmp_path, "example") == ""
    intake = {
        "run_id": "test",
        "plugin_slug": "example",
        "plugin_version": "2.0.3",
        "source_path": "source",
        "file_count": 1,
        "total_lines": 1,
        "source_url": "fixture://source",
        "scanned_at": "2026-10-21T00:00:00Z",
    }
    (tmp_path / "intake.json").write_text(json.dumps(intake))
    assert _scanned_version(tmp_path, "example") == "2.0.3"
    with pytest.raises(ValueError, match="plugin_slug"):
        _scanned_version(tmp_path, "other")


@pytest.mark.asyncio
async def test_critic_receives_the_trusted_inspected_version() -> None:
    observed: dict[str, Any] = {}

    class Runtime:
        async def run(self, **kwargs: Any) -> Any:
            observed.update(kwargs)
            return SimpleNamespace(
                output=TriagedArtifact(
                    plugin_slug="example", accepted=[], rejected=[], merged=[]
                )
            )

    critic = CriticAgent(Runtime(), model="test")  # type: ignore[arg-type]
    await critic.review(
        HypothesesArtifact(plugin_slug="example", hypotheses=[_candidate()]),
        {},
        scanned_version="2.0.3",
    )
    payload = json.loads(observed["messages"][1]["content"])
    assert payload["review_scope"] == {
        "inspected_version": "2.0.3",
        "historical_versions_inspected": False,
    }


def test_critic_prompt_uses_qualified_core_facts_and_immutable_claims() -> None:
    prompt = load_prompt("critic")
    assert "grants `unfiltered_html` to Editor and Administrator" in prompt
    assert "not Author or Contributor" in prompt
    assert "non-super-admins on multisite" in prompt
    assert "blank or incomplete developer consultation is not evidence" in prompt
    assert "historical range remains unproven" in prompt
    assert "Never repair a role or version" in prompt
