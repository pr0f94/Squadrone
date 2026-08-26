from __future__ import annotations

import pytest

from squadrone.agents.reporter import ReporterAgent
from squadrone.schemas import (
    BugClass,
    Confidence,
    DedupStatus,
    Finding,
    Hypothesis,
    PoCAttempt,
    PoCStatus,
    SecurityOutcome,
    TriagedArtifact,
)
from squadrone.schemas.config import PipelineConfig
from squadrone.services.budget import BudgetTracker
from squadrone.services.quality_gate import (
    apply_quality_gate,
    grade_hypothesis,
    infer_attacker_role,
    recompute_severity,
    severity_from_finding,
)
from squadrone.stages import report as report_stage


def _hypothesis(**overrides) -> Hypothesis:
    data = {
        "id": "h-1",
        "specialist": "authorization_workflows",
        "bug_class": BugClass.IDOR,
        "entry_point": "wp_ajax_nopriv_demo",
        "file": "demo.php",
        "line": 10,
        "sink": "get_post_meta",
        "sink_code": "get_post_meta($_GET['id'], '_secret', true)",
        "taint_path": ["$_GET['id']", "demo", "get_post_meta"],
        "reasoning": "An unauthenticated caller reads another user's private secret.",
        "confidence": Confidence.HIGH,
        "preconditions": "unauthenticated attacker",
        "affected_versions": "<=1.0",
        "security_outcome": SecurityOutcome(
            confidentiality="high",
            description="Unauthenticated disclosure of another user's private secret.",
        ),
        "evidence_summary": {
            "attacker_role": "unauthenticated",
            "source": "$_GET['id']",
            "control": "missing object ownership check",
            "sink": "get_post_meta($id, '_secret', true)",
            "reachable_path": "wp_ajax_nopriv_demo -> demo -> get_post_meta",
            "boundary": "anonymous caller reads another user's private secret",
            "impact": "disclosure of another user's private secret",
            "counterevidence": "no capability or ownership guard in the complete handler",
            "proof_gaps": "runtime object setup only",
        },
    }
    data.update(overrides)
    return Hypothesis(**data)


def _confirmed_finding(*, dedup_status: DedupStatus = DedupStatus.NOVEL) -> Finding:
    hypothesis = _hypothesis(bug_class=BugClass.SQLI)
    observation = {
        "schema_version": 1,
        "verdict": "vulnerable",
        "oracle": "response_marker",
        "attacker_role": "unauthenticated",
        "request": {
            "method": "POST",
            "url": "http://localhost/wp-admin/admin-ajax.php",
        },
        "attack": {
            "observed": True,
            "marker": "private-marker",
            "marker_present": True,
        },
        "control": {"observed": False, "marker_present": False},
        "impact": {
            "confidentiality": "high",
            "integrity": "high",
            "availability": "high",
            "description": "Database compromise.",
        },
    }
    return Finding(
        id="f-1",
        hypothesis=hypothesis,
        poc_status=PoCStatus.SUCCESS,
        poc_script_path="poc.py",
        poc_attempts=[
            PoCAttempt(
                iteration=1,
                phase="attack",
                script_path="poc.py",
                result=PoCStatus.SUCCESS,
            ),
            PoCAttempt(
                iteration=1,
                phase="confirmation",
                script_path="poc.py",
                result=PoCStatus.SUCCESS,
            ),
        ],
        evidence={
            "clean_state_restored": True,
            "confirmation_run": {"observation": observation},
        },
        confidence_runs=2,
        dedup_status=dedup_status,
        dedup_matches=[],
    )


def test_quality_gate_accepts_source_grounded_cia_candidate_without_guessing_cvss():
    grade = grade_hypothesis(_hypothesis())

    assert grade.accepted is True
    assert grade.evidence["attacker_role"] == "unauthenticated"
    assert grade.severity["cvss_estimate"] is None
    assert grade.severity["rating"] == "unscored"


@pytest.mark.parametrize(
    ("supplied", "expected"),
    [
        ("unauthenticated_remote_attacker", "unauthenticated"),
        (
            "subscriber;_wp_ajax_mk_file_folder_manager_accepts_every_authenticated_role.",
            "subscriber",
        ),
        ("administrator", "administrator"),
        ("authenticated user", "unknown"),
    ],
)
def test_infer_attacker_role_canonicalizes_supplied_model_text(
    supplied: str,
    expected: str,
) -> None:
    hypothesis = _hypothesis(evidence_summary={"attacker_role": supplied})

    assert infer_attacker_role(hypothesis) == expected


def test_quality_gate_rejects_missing_concrete_cia_impact():
    hypothesis = _hypothesis(
        security_outcome=SecurityOutcome(),
        evidence_summary={
            "attacker_role": "subscriber",
            "source": "$_POST['dismiss']",
            "control": "missing nonce",
            "sink": "update_user_meta",
            "reachable_path": "wp_ajax_dismiss -> update_user_meta",
            "boundary": "subscriber changes a notice preference",
            "impact": "updates a dismiss notice flag",
            "counterevidence": "none",
            "proof_gaps": "none",
        },
        reasoning="Subscriber updates a dismiss notice flag.",
    )

    grade = grade_hypothesis(hypothesis)

    assert grade.accepted is False
    assert "missing_concrete_cia_impact" in grade.rules
    assert "cosmetic_or_no_security_impact" in grade.rules


def test_quality_gate_rejects_missing_security_boundary():
    evidence = dict(_hypothesis().evidence_summary)
    evidence["boundary"] = ""
    hypothesis = _hypothesis(evidence_summary=evidence)

    grade = grade_hypothesis(hypothesis)

    assert grade.accepted is False
    assert "missing_security_boundary" in grade.rules


def test_quality_gate_recognizes_public_upload_execution_impact():
    hypothesis = _hypothesis(
        bug_class=BugClass.ARBITRARY_FILE_WRITE,
        security_outcome=SecurityOutcome(
            description=(
                "The attacker can place arbitrary files, including PHP-named payloads, "
                "in public uploads and may obtain remote code execution where PHP "
                "execution is enabled there."
            ),
        ),
        evidence_summary={
            "attacker_role": "subscriber",
            "source": "Multipart data sent to a REST upload route",
            "control": "no file-type or extension validation",
            "sink": "copy($path, $destination)",
            "reachable_path": "rest_upload -> upload_file -> copy",
            "boundary": (
                "A Subscriber writes attacker-selected content and extension into "
                "the site's public uploads tree."
            ),
            "impact": "Arbitrary public file placement and possible code execution.",
            "counterevidence": "A separate upload route validates file types.",
            "proof_gaps": "Confirm whether PHP executes in uploads.",
        },
    )

    grade = grade_hypothesis(hypothesis)

    assert grade.accepted is True
    assert grade.evidence["has_security_boundary"] is True
    assert grade.evidence["impact_dimensions"]["integrity"] == "low"


def test_quality_gate_records_narrow_runtime_gap_as_warning():
    grade = grade_hypothesis(_hypothesis())

    assert grade.accepted is True
    assert "broad_or_vague_proof_gap" not in grade.warnings


def test_quality_gate_allows_intended_shipped_feature_enablement():
    hypothesis = _hypothesis(
        preconditions=(
            "The administrator enables the shipped Public API feature; "
            "its bearer token remains at the feature's default empty value."
        ),
    )

    grade = grade_hypothesis(hypothesis)

    assert grade.accepted is True
    assert "configuration_dependent" not in grade.rules


def test_quality_gate_rejects_unsafe_security_override():
    hypothesis = _hypothesis(
        preconditions="The administrator must disable authentication for the endpoint.",
    )

    grade = grade_hypothesis(hypothesis)

    assert grade.accepted is False
    assert "configuration_dependent" in grade.rules


def test_quality_gate_rejects_missing_preconditions_and_equivalent_evidence():
    evidence = dict(_hypothesis().evidence_summary)
    evidence["attacker_role"] = ""
    evidence["proof_gaps"] = ""
    hypothesis = _hypothesis(preconditions="", evidence_summary=evidence)

    grade = grade_hypothesis(hypothesis)

    assert grade.accepted is False
    assert "missing_preconditions" in grade.rules


def test_apply_quality_gate_moves_invalid_candidate_to_rejected():
    invalid = _hypothesis(
        id="h-2",
        sink_code="",
        security_outcome=SecurityOutcome(),
    )
    artifact = TriagedArtifact(
        plugin_slug="demo",
        accepted=[_hypothesis(), invalid],
        rejected=[],
        merged=[],
    )

    gated = apply_quality_gate(artifact)

    assert [hypothesis.id for hypothesis in gated.accepted] == ["h-1"]
    assert gated.rejected[0]["hypothesis_id"] == "h-2"


def test_recompute_severity_maps_owasp_without_pre_poc_score():
    severity = recompute_severity(_hypothesis(bug_class=BugClass.SQLI))

    assert severity["owasp_2021"] == "A03:2021-Injection"
    assert severity["cvss_estimate"] is None


def test_missing_authentication_for_critical_function_maps_to_owasp_a07():
    severity = recompute_severity(
        _hypothesis(
            bug_class=BugClass.MISSING_AUTH_CRITICAL_FUNCTION,
        )
    )

    assert (
        severity["owasp_2021"] == "A07:2021-Identification and Authentication Failures"
    )


def test_unmapped_cwe_does_not_inherit_an_owasp_category():
    severity = recompute_severity(_hypothesis(bug_class=BugClass("CWE-1234")))

    assert severity["owasp_2021"] == "Unmapped"


def test_confirmed_finding_gets_cvss31_score_and_vector():
    finding = _confirmed_finding()

    severity = severity_from_finding(finding)

    assert severity["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert severity["cvss_estimate"] == 9.8


def test_confirmed_severity_uses_canonical_descriptive_attacker_role():
    finding = _confirmed_finding()
    observation = finding.evidence["confirmation_run"]["observation"]
    observation["attacker_role"] = "unauthenticated_remote_attacker"

    severity = severity_from_finding(finding)

    assert severity["attacker_role"] == "unauthenticated"
    assert "/PR:N/" in severity["cvss_vector"]


def test_confirmed_severity_scores_unknown_role_conservatively():
    finding = _confirmed_finding()
    observation = finding.evidence["confirmation_run"]["observation"]
    observation["attacker_role"] = "authenticated user"

    severity = severity_from_finding(finding)

    assert severity["attacker_role"] == "unknown"
    assert "/PR:H/" in severity["cvss_vector"]


@pytest.mark.asyncio
async def test_report_stage_scores_confirmed_known_duplicate(tmp_path):
    finding = _confirmed_finding(dedup_status=DedupStatus.KNOWN_DUPE)

    reports = await report_stage.run(
        [finding],
        plugin_slug="demo",
        config=PipelineConfig.from_yaml("pipelines/test.yaml"),
        budget=BudgetTracker(1.0),
        runtime=object(),  # type: ignore[arg-type]
        runs_root=str(tmp_path),
        run_id="run",
    )

    assert reports == []
    assert finding.cvss_estimate == "9.8"
    assert finding.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


@pytest.mark.asyncio
async def test_reporter_receives_exact_confirmed_poc_script(tmp_path):
    finding = _confirmed_finding()
    script_path = tmp_path / "confirmed.py"
    script_path.write_text(
        "import requests\nrequests.post('http://localhost/target')\n"
    )
    finding.poc_script_path = str(script_path)

    class Runtime:
        def __init__(self) -> None:
            self.request: dict | None = None

        async def run(self, **kwargs):
            self.request = kwargs
            return type("Result", (), {"output": "report"})()

    runtime = Runtime()
    reporter = ReporterAgent(runtime=runtime, model="test-model")  # type: ignore[arg-type]

    report = await reporter.write(finding, plugin_slug="demo")

    assert report == "report"
    assert runtime.request is not None
    user_message = runtime.request["messages"][1]["content"]
    assert "VERIFIED_POC_SCRIPT" in user_message
    assert "requests.post('http://localhost/target')" in user_message
