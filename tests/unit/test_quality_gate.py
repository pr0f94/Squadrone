from __future__ import annotations

import pytest

from squadrone.agents.reporter import ReporterAgent
from squadrone.schemas import (
    BugClass,
    CIAImpact,
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
from squadrone.services import quality_gate as quality_gate_service
from squadrone.services.budget import BudgetTracker
from squadrone.services.quality_gate import (
    apply_quality_gate,
    grade_finding_for_report,
    grade_hypothesis,
    infer_attacker_role,
    reconcile_verified_impact,
    recompute_severity,
    severity_from_finding,
    validate_php_object_natural_finding_confirmation,
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


def _natural_cwe502_finding(
    *, effect_binding_kind: str = "direct_path"
) -> Finding:
    source = _hypothesis()
    hypothesis = _hypothesis(
        bug_class=BugClass.PHP_OBJECT_INJECTION,
        security_outcome=SecurityOutcome(
            integrity="low",
            description="Deletion of a verifier-owned temporary file.",
        ),
        evidence_summary={
            **source.evidence_summary,
            "usable_gadget": True,
            "impact": "Deletion of a verifier-owned temporary file.",
        },
    )
    target_path_sha256 = "11" * 32
    target_content_sha256 = "22" * 32
    recipe_sha256 = "33" * 32
    transport_sha256 = "44" * 32
    snapshot = {
        "effect_binding_kind": effect_binding_kind,
        "target_path_sha256": target_path_sha256,
        "target_content_sha256": target_content_sha256,
        "runtime_binding": {
            "effect_binding_kind": effect_binding_kind,
            "recipe_sha256": recipe_sha256,
        },
        "transport_attestation": {
            "transport_contract_sha256": transport_sha256,
            "actor_role": "unauthenticated",
        },
    }
    observation = {
        "schema_version": 1,
        "verdict": "vulnerable",
        "oracle": "file_effect",
        "attacker_role": "unauthenticated",
        "request": {
            "method": "POST",
            "url": "http://localhost/wp-admin/admin-ajax.php",
            "transport_contract_sha256": transport_sha256,
        },
        "attack": {
            "observed": True,
            "effect": "verifier_owned_temporary_file_deleted",
            "target_path_sha256": target_path_sha256,
            "target_content_sha256": target_content_sha256,
            "source_recipe_sha256": recipe_sha256,
            "collateral_paths_unchanged": True,
        },
        "control": {
            "observed": False,
            "effect": "verifier_owned_temporary_file_deleted",
            "target_path_sha256": target_path_sha256,
            "target_content_sha256": target_content_sha256,
            "source_recipe_sha256": recipe_sha256,
            "target_preserved": True,
        },
        "impact": {
            "confidentiality": "none",
            "integrity": "low",
            "availability": "none",
            "description": "Deletion of a verifier-owned temporary file.",
        },
    }
    fingerprint = {
        "method": "POST",
        "route": "/wp-admin/admin-ajax.php",
        "object_field": "company",
        "object_location": "form",
        "dispatch": {"form:action": "donate"},
    }
    primitive_observation = {
        "schema_version": 1,
        "verdict": "vulnerable",
        "oracle": "object_instantiation",
        "attacker_role": "unauthenticated",
        "request": {
            "method": "POST",
            "url": "http://localhost/wp-admin/admin-ajax.php",
        },
        "attack": {
            "observed": True,
            "instantiated": True,
            "effect": "verifier_inert_canary_wakeup",
            "attacker_user_id": 0,
            "identity_verified": True,
            "request_fingerprint": fingerprint,
        },
        "control": {
            "observed": False,
            "instantiated": False,
            "effect": "verifier_inert_canary_wakeup",
            "attacker_user_id": 0,
            "identity_verified": True,
            "request_fingerprint": fingerprint,
        },
        "impact": {
            "confidentiality": "none",
            "integrity": "low",
            "availability": "none",
            "description": "Verifier-owned inert object instantiation only.",
        },
    }
    script = "natural-poc.py"
    return Finding(
        id="f-natural",
        hypothesis=hypothesis,
        poc_status=PoCStatus.SUCCESS,
        poc_script_path=script,
        poc_attempts=[
            PoCAttempt(
                iteration=1,
                phase="attack",
                proof_kind="php_object_primitive",
                script_path=script,
                result=PoCStatus.SUCCESS,
                observation=primitive_observation,
            ),
            PoCAttempt(
                iteration=1,
                phase="confirmation",
                proof_kind="php_object_primitive",
                script_path=script,
                result=PoCStatus.SUCCESS,
                observation=primitive_observation,
            ),
            PoCAttempt(
                iteration=1,
                phase="attack",
                proof_kind="php_object_natural",
                script_path=script,
                result=PoCStatus.SUCCESS,
                observation=observation,
            ),
            PoCAttempt(
                iteration=1,
                phase="confirmation",
                proof_kind="php_object_natural",
                script_path=script,
                result=PoCStatus.SUCCESS,
                observation=observation,
            ),
        ],
        evidence={
            "clean_state_restored": True,
            "confirmation_run": {"observation": observation},
            "php_object_natural_confirmation": {
                "schema_version": 1,
                "status": "confirmed",
                "proof_kind": "php_object_natural",
                "hypothesis_id": hypothesis.id,
                "bug_class": "CWE-502",
                "effect": "file_delete",
                "clean_state_executions": 2,
                "finding_promoted": True,
                "promotion_policy": "source_bound_natural_gadget_v1",
                "first_execution": dict(snapshot),
                "confirmation_execution": dict(snapshot),
            },
        },
        confidence_runs=2,
        dedup_status=DedupStatus.NOVEL,
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


def test_quality_gate_preserves_structured_usable_gadget_evidence():
    evidence = dict(_hypothesis().evidence_summary)
    evidence["usable_gadget"] = False

    grade = grade_hypothesis(
        _hypothesis(
            bug_class=BugClass.PHP_OBJECT_INJECTION,
            evidence_summary=evidence,
        )
    )

    assert grade.evidence["usable_gadget"] is False


@pytest.mark.parametrize(
    "boundary",
    ["", "  ", "unknown", "not applicable", "security boundary"],
)
def test_quality_gate_rejects_missing_or_placeholder_security_boundary(boundary):
    evidence = dict(_hypothesis().evidence_summary)
    evidence["boundary"] = boundary
    hypothesis = _hypothesis(evidence_summary=evidence)

    grade = grade_hypothesis(hypothesis)

    assert grade.accepted is False
    assert "missing_security_boundary" in grade.rules


def test_quality_gate_accepts_descriptive_boundary_outside_closed_cwe_vocabulary():
    evidence = dict(_hypothesis().evidence_summary)
    evidence.update(
        {
            "boundary": (
                "A request crosses from one tenant workspace into a separate "
                "tenant workspace."
            ),
            "impact": "Records from a separate tenant become readable.",
        }
    )
    hypothesis = _hypothesis(
        security_outcome=SecurityOutcome(
            confidentiality="high",
            description="Records from a separate tenant become readable.",
        ),
        evidence_summary=evidence,
    )

    grade = grade_hypothesis(hypothesis)

    assert grade.accepted is True
    assert grade.evidence["has_security_boundary"] is True


def test_quality_gate_accepts_structured_ssrf_impact_without_keyword_allowlist():
    evidence = dict(_hypothesis().evidence_summary)
    evidence.update(
        {
            "attacker_role": "subscriber",
            "source": "REST query parameter get_content_url",
            "control": "No destination restriction is applied",
            "sink": "wp_remote_get($get_content_url)",
            "reachable_path": "REST route -> get_remote_content -> wp_remote_get",
            "boundary": (
                "An ordinary web user crosses from browser-visible resources into "
                "services reachable only from the application execution environment."
            ),
            "impact": (
                "The caller reads valid JSON returned by a service unavailable through "
                "the caller's own network path."
            ),
            "counterevidence": "The URL is syntax-validated but destinations are unrestricted",
            "proof_gaps": "runtime reachability confirmation only",
        }
    )
    hypothesis = _hypothesis(
        bug_class=BugClass.SSRF,
        entry_point="GET /wp-json/demo/v1/fetch",
        sink="wp_remote_get",
        sink_code="wp_remote_get($request->get_param('get_content_url'))",
        taint_path=["REST get_content_url", "get_remote_content", "wp_remote_get"],
        preconditions="authenticated Subscriber",
        security_outcome=SecurityOutcome(
            confidentiality="low",
            description=evidence["impact"],
        ),
        evidence_summary=evidence,
    )

    grade = grade_hypothesis(hypothesis)

    assert grade.accepted is True
    assert grade.evidence["impact_dimensions"]["confidentiality"] == "low"


def test_quality_gate_rejects_attacker_controlled_callback_as_security_boundary():
    evidence = dict(_hypothesis().evidence_summary)
    evidence.update(
        {
            "source": "REST query parameter target_url",
            "sink": "wp_remote_get($target_url)",
            "reachable_path": "REST route -> callback -> wp_remote_get",
            "boundary": "The server requests an attacker-controlled callback endpoint.",
            "impact": "The callback confirms that the server made an outbound request.",
        }
    )
    hypothesis = _hypothesis(
        bug_class=BugClass.SSRF,
        entry_point="GET /wp-json/demo/v1/callback",
        sink="wp_remote_get",
        sink_code="wp_remote_get($request->get_param('target_url'))",
        taint_path=["REST target_url", "callback", "wp_remote_get"],
        security_outcome=SecurityOutcome(
            confidentiality="low",
            description=evidence["impact"],
        ),
        evidence_summary=evidence,
    )

    grade = grade_hypothesis(hypothesis)

    assert grade.accepted is False
    assert "missing_security_boundary" in grade.rules


@pytest.mark.parametrize(
    "boundary",
    [
        "A registered user edits only their own profile.",
        "The caller changes an object that the caller owns.",
        "A registered user edits their profile.",
        "The request updates an account owned by the same caller.",
        "The newly created account belongs to the registrant.",
        "The caller changes their own object without authorization.",
        "Request input reaches the selected record.",
    ],
)
def test_quality_gate_rejects_own_object_or_flow_as_security_boundary(boundary):
    evidence = dict(_hypothesis().evidence_summary)
    evidence["boundary"] = boundary

    grade = grade_hypothesis(_hypothesis(evidence_summary=evidence))

    assert grade.accepted is False
    assert grade.evidence["has_security_boundary"] is False
    assert "missing_security_boundary" in grade.rules


def test_quality_gate_accepts_protected_attribute_boundary_on_own_object():
    hypothesis = _hypothesis(
        bug_class=BugClass.MASS_ASSIGNMENT,
        sink="attacker-selected user metadata write",
        sink_code="update_user_meta($user_id, $key, $value);",
        taint_path=[
            "$_POST['account_fields']",
            "update_profile",
            "update_user_meta",
        ],
        reasoning=(
            "A public registration path accepts an attacker-selected protected "
            "attribute without an allowed-key check."
        ),
        security_outcome=SecurityOutcome(
            integrity="high",
            description="The registrant gains administrative capabilities.",
        ),
        evidence_summary={
            "attacker_role": "unauthenticated",
            "source": "$_POST['account_fields']",
            "control": "no allowed-key check for protected attributes",
            "sink": "update_user_meta($user_id, $key, $value)",
            "reachable_path": (
                "public_registration -> update_profile -> update_user_meta"
            ),
            "boundary": (
                "An anonymous registrant assigns the administrator role and "
                "protected capabilities to their own newly created account."
            ),
            "impact": "The registrant gains administrative capabilities.",
            "counterevidence": "ordinary profile fields are intended to be writable",
            "proof_gaps": "runtime confirmation only",
        },
    )

    grade = grade_hypothesis(hypothesis)

    assert grade.accepted is True
    assert grade.evidence["has_security_boundary"] is True


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


def test_quality_gate_recognizes_browser_origin_as_xss_security_boundary():
    hypothesis = _hypothesis(
        bug_class=BugClass.XSS_REFLECTED,
        entry_point="wp_ajax_nopriv_render",
        sink="unescaped validation error in an HTML response",
        sink_code="echo '<p>' . $error . '</p>';",
        taint_path=["$_GET['value']", "validate", "echo HTML"],
        reasoning=(
            "An unauthenticated request injects script into a top-level HTML response."
        ),
        security_outcome=SecurityOutcome(
            confidentiality="high",
            integrity="high",
            description=(
                "Attacker-supplied JavaScript executes in the victim's site origin and "
                "can read same-origin data or perform authenticated actions."
            ),
        ),
        evidence_summary={
            "attacker_role": "unauthenticated",
            "source": "$_GET['value']",
            "control": "validation error retains the unescaped request value",
            "sink": "echo HTML",
            "reachable_path": "wp_ajax_nopriv_render -> validate -> echo HTML",
            "boundary": (
                "Unauthenticated request data reaches executable HTML in a victim's "
                "site origin."
            ),
            "impact": "Script runs with the victim's same-origin browser authority.",
            "counterevidence": "none",
            "proof_gaps": "browser execution only",
        },
    )

    grade = grade_hypothesis(hypothesis)

    assert grade.accepted is True
    assert grade.evidence["has_security_boundary"] is True


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


def test_cwe502_direct_natural_proof_unlocks_verified_impact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finding = _natural_cwe502_finding()
    calls: list[tuple[object, str | None]] = []

    def validate(payload: object, *, hypothesis_id: str | None = None):
        calls.append((payload, hypothesis_id))
        return True, "valid persisted proof"

    monkeypatch.setattr(
        quality_gate_service,
        "validate_persisted_php_object_gadget_confirmation",
        validate,
    )

    accepted, reason = validate_php_object_natural_finding_confirmation(finding)
    impact = reconcile_verified_impact(finding)
    grade = grade_finding_for_report(finding)

    assert accepted is True, reason
    assert calls and all(call[1] == finding.hypothesis.id for call in calls)
    assert impact == CIAImpact(
        integrity="low",
        description="Deletion of a verifier-owned temporary file.",
    )
    assert grade.accepted is True


def test_cwe502_without_persisted_natural_proof_has_no_verified_impact() -> None:
    finding = _natural_cwe502_finding()
    del finding.evidence["php_object_natural_confirmation"]

    assert reconcile_verified_impact(finding) is None
    grade = grade_finding_for_report(finding)
    assert grade.accepted is False
    assert "php_object_natural_confirmation_missing" in grade.rules


def test_cwe502_prefix_only_natural_proof_cannot_promote_full_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finding = _natural_cwe502_finding(
        effect_binding_kind="guarded_opaque_prefix"
    )
    monkeypatch.setattr(
        quality_gate_service,
        "validate_persisted_php_object_gadget_confirmation",
        lambda _payload, *, hypothesis_id=None: (True, "valid lower-tier proof"),
    )

    accepted, reason = validate_php_object_natural_finding_confirmation(finding)

    assert accepted is False
    assert "direct-path" in reason
    assert reconcile_verified_impact(finding) is None


def test_cwe502_natural_attempts_must_be_successful_paired_and_same_script(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finding = _natural_cwe502_finding()
    next(
        attempt
        for attempt in finding.poc_attempts
        if attempt.proof_kind == "php_object_natural"
        and attempt.phase == "confirmation"
    ).script_path = "different.py"
    monkeypatch.setattr(
        quality_gate_service,
        "validate_persisted_php_object_gadget_confirmation",
        lambda _payload, *, hypothesis_id=None: (True, "valid runtime proof"),
    )

    accepted, reason = validate_php_object_natural_finding_confirmation(finding)

    assert accepted is False
    assert "promoted script" in reason


def test_cwe502_requires_unambiguous_bounded_primitive_pair(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finding = _natural_cwe502_finding()
    primitive_confirmation = next(
        attempt
        for attempt in finding.poc_attempts
        if attempt.proof_kind == "php_object_primitive"
        and attempt.phase == "confirmation"
    )
    primitive_confirmation.observation = None
    monkeypatch.setattr(
        quality_gate_service,
        "validate_persisted_php_object_gadget_confirmation",
        lambda _payload, *, hypothesis_id=None: (True, "valid runtime proof"),
    )

    accepted, reason = validate_php_object_natural_finding_confirmation(finding)

    assert accepted is False
    assert "bounded to inert instantiation" in reason


def test_cwe502_observation_must_match_parent_snapshot_and_bounded_impact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finding = _natural_cwe502_finding()
    observation = finding.evidence["confirmation_run"]["observation"]
    observation["attack"]["target_path_sha256"] = "99" * 32
    observation["impact"]["integrity"] = "high"
    monkeypatch.setattr(
        quality_gate_service,
        "validate_persisted_php_object_gadget_confirmation",
        lambda _payload, *, hypothesis_id=None: (True, "valid runtime proof"),
    )

    accepted, reason = validate_php_object_natural_finding_confirmation(finding)

    assert accepted is False
    assert "parent-attested" in reason
    assert reconcile_verified_impact(finding) is None


def test_confirmed_impact_replaces_broader_source_only_cia_claim():
    finding = _confirmed_finding()
    finding.hypothesis.security_outcome = SecurityOutcome(
        integrity="high",
        availability="low",
        description="Source review predicted modification and disruption.",
    )
    observation = finding.evidence["confirmation_run"]["observation"]
    observation["impact"] = {
        "confidentiality": "none",
        "integrity": "high",
        "availability": "none",
        "description": "Clean replay measured modification only.",
    }

    verified = reconcile_verified_impact(finding)
    severity = severity_from_finding(finding)

    assert verified == CIAImpact(
        integrity="high",
        description="Clean replay measured modification only.",
    )
    assert finding.verified_impact == verified
    assert finding.hypothesis.security_outcome.availability == "none"
    assert finding.hypothesis.security_outcome.description == verified.description
    assert severity["impact_dimensions"]["availability"] == "none"
    assert severity["cvss_vector"].endswith("/C:N/I:H/A:N")


def test_report_gate_rejects_explicit_impact_that_conflicts_with_confirmation():
    finding = _confirmed_finding()
    finding.verified_impact = CIAImpact(
        integrity="high",
        availability="low",
        description="Claimed disruption.",
    )
    finding.evidence["confirmation_run"]["observation"]["impact"] = {
        "confidentiality": "none",
        "integrity": "high",
        "availability": "none",
        "description": "Measured modification only.",
    }

    grade = grade_finding_for_report(finding)

    assert grade.accepted is False
    assert "verified_impact_mismatch" in grade.rules


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
