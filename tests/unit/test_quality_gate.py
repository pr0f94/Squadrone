from __future__ import annotations

import json

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
    automatic_verifier_contract_violations,
    grade_finding_for_report,
    grade_hypothesis,
    infer_attacker_role,
    recompute_severity,
    reconcile_verified_impact,
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
        preconditions="Subscriber attacker uploads a file through the REST route.",
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


def test_second_order_sqli_requires_and_preserves_storage_evidence() -> None:
    evidence = dict(_hypothesis().evidence_summary)
    evidence.update(
        {
            "source": "POST form field sort_clause; plugin.php:10 — $_POST['sort_clause']",
            "control": "The final SQL construction has no placeholder or allowlist",
            "sink": "$wpdb->get_results($sql)",
            "reachable_path": (
                "low-privilege settings write -> option demo_sort -> scheduled report "
                "-> $wpdb->get_results"
            ),
            "boundary": (
                "A Subscriber controls SQL syntax executed later with the site's "
                "database privileges."
            ),
            "impact": "The attacker can extract protected database values.",
            "storage_writer": "POST /save -> update_option('demo_sort', $value)",
            "storage_identity": "option:demo_sort",
            "trigger": "GET /report -> get_option('demo_sort') -> query",
            "write_success_marker": "FILTER_WRITE_CONFIRMED_7D3A",
            "same_actor_lifecycle": True,
            "verification_oracle": "timing",
        }
    )
    hypothesis = _hypothesis(
        bug_class=BugClass.SQLI,
        specialist="injection_files",
        injection_order="second",
        storage_boundary="option",
        security_outcome=SecurityOutcome(
            confidentiality="high",
            description="The attacker can extract protected database values.",
        ),
        evidence_summary=evidence,
    )

    grade = grade_hypothesis(hypothesis)

    assert grade.accepted is True
    assert grade.evidence["storage_writer"] == evidence["storage_writer"]
    assert grade.evidence["storage_identity"] == "option:demo_sort"
    assert grade.evidence["trigger"] == evidence["trigger"]
    assert grade.evidence["write_success_marker"] == "FILTER_WRITE_CONFIRMED_7D3A"
    assert grade.evidence["verification_oracle"] == "timing"

    gated = apply_quality_gate(
        TriagedArtifact(
            plugin_slug="demo",
            accepted=[hypothesis],
            rejected=[],
            merged=[],
        )
    )
    resumed = TriagedArtifact.model_validate(gated.model_dump(mode="json"))
    assert resumed.accepted[0].evidence_summary["verification_oracle"] == "timing"
    assert automatic_verifier_contract_violations(resumed.accepted[0]) == []


def test_second_order_sqli_binds_storage_identity_to_declared_boundary() -> None:
    evidence = {
        **_hypothesis().evidence_summary,
        "source": "POST form field sort; plugin.php:10 — $_POST['sort']",
        "storage_writer": "POST /save -> update_option",
        "storage_identity": "metadata:post:7:demo_sort",
        "trigger": "GET /report",
        "write_success_marker": "FILTER_WRITE_CONFIRMED_7D3A",
        "same_actor_lifecycle": True,
        "verification_oracle": "timing",
    }
    hypothesis = _hypothesis(
        bug_class=BugClass.SQLI,
        specialist="injection_files",
        entry_point="POST /save",
        injection_order="second",
        storage_boundary="option",
        evidence_summary=evidence,
    )

    grade = grade_hypothesis(hypothesis)

    assert grade.accepted is False
    assert "second_order_sqli_storage_identity_invalid" in grade.rules


@pytest.mark.parametrize(
    ("storage_boundary", "storage_identity"),
    [
        ("option", "option:rapport_clé"),
        ("metadata", "metadata:post:7:rapport_clé"),
        ("transient", "transient:rapport:clé"),
        ("custom_table", "custom_table:wp_reports:id:7"),
        ("other", "other:queue:rapport_clé"),
    ],
)
def test_second_order_sqli_accepts_exact_storage_identity_prefixes(
    storage_boundary,
    storage_identity,
) -> None:
    evidence = {
        **_hypothesis().evidence_summary,
        "source": "POST form field sort; plugin.php:10 — $_POST['sort']",
        "storage_writer": "POST /save -> persistent writer",
        "storage_identity": storage_identity,
        "trigger": "GET /report",
        "write_success_marker": "FILTER_WRITE_CONFIRMED_7D3A",
        "same_actor_lifecycle": True,
        "verification_oracle": "timing",
    }
    hypothesis = _hypothesis(
        bug_class=BugClass.SQLI,
        specialist="injection_files",
        entry_point="POST /save",
        injection_order="second",
        storage_boundary=storage_boundary,
        evidence_summary=evidence,
    )

    grade = grade_hypothesis(hypothesis)

    assert "second_order_sqli_storage_identity_invalid" not in grade.rules


def test_second_order_sqli_fails_closed_without_storage_evidence() -> None:
    hypothesis = _hypothesis(
        bug_class=BugClass.SQLI,
        specialist="injection_files",
        injection_order="second",
        storage_boundary="custom_table",
    )

    grade = grade_hypothesis(hypothesis)

    assert grade.accepted is False
    assert "second_order_sqli_storage_evidence_missing" in grade.rules


@pytest.mark.parametrize("injection_order", [None, "direct"])
def test_non_second_order_hypothesis_rejects_reserved_storage_evidence(
    injection_order,
) -> None:
    evidence = {
        **_hypothesis().evidence_summary,
        "storage_writer": "POST /save -> update_option",
        "storage_identity": "option:demo_sort",
        "trigger": "GET /report",
        "write_success_marker": "FILTER_WRITE_CONFIRMED_7D3A",
        "same_actor_lifecycle": True,
        "verification_oracle": "timing",
    }
    hypothesis = _hypothesis(
        bug_class=BugClass.SQLI,
        specialist="injection_files",
        injection_order=injection_order,
        evidence_summary=evidence,
    )

    grade = grade_hypothesis(hypothesis)

    assert grade.accepted is False
    assert "second_order_sqli_evidence_inapplicable" in grade.rules
    assert "second_order_sqli_evidence_inapplicable" in (
        automatic_verifier_contract_violations(hypothesis)
    )


@pytest.mark.parametrize(
    ("entry_point", "trigger", "expected_rule"),
    [
        (
            "save_sort callback",
            "GET /report -> render_report -> query",
            "second_order_sqli_writer_transport_invalid",
        ),
        (
            "POST /wp-admin/admin-ajax.php?action=save_sort",
            "scheduled report job -> query",
            "second_order_sqli_trigger_transport_unsupported",
        ),
        (
            "POST /plugin//save?mode=sort",
            "GET /report -> render_report -> query",
            "second_order_sqli_writer_transport_invalid",
        ),
        (
            "POST /plugin/save?mode=sort&mode=other",
            "GET /report -> render_report -> query",
            "second_order_sqli_writer_transport_invalid",
        ),
    ],
)
def test_second_order_sqli_requires_machine_readable_writer_and_trigger_transports(
    entry_point: str,
    trigger: str,
    expected_rule: str,
) -> None:
    evidence = dict(_hypothesis().evidence_summary)
    evidence.update(
        {
            "storage_writer": "POST writer stores the source-proven sort value",
            "storage_identity": "option:demo_sort",
            "trigger": trigger,
            "write_success_marker": "FILTER_WRITE_CONFIRMED_7D3A",
            "same_actor_lifecycle": True,
            "verification_oracle": "timing",
        }
    )
    hypothesis = _hypothesis(
        bug_class=BugClass.SQLI,
        specialist="injection_files",
        entry_point=entry_point,
        injection_order="second",
        storage_boundary="option",
        evidence_summary=evidence,
    )

    grade = grade_hypothesis(hypothesis)

    assert grade.accepted is False
    assert expected_rule in grade.rules


def test_second_order_sqli_requires_one_exact_writer_wire_field() -> None:
    source = _hypothesis()
    evidence = {
        **source.evidence_summary,
        "source": "POST form field sort and POST form field mode",
        "storage_writer": "POST writer stores a source-proven value",
        "storage_identity": "option:demo_sort",
        "trigger": "GET /report -> render_report -> query",
        "write_success_marker": "FILTER_WRITE_CONFIRMED_7D3A",
        "same_actor_lifecycle": True,
        "verification_oracle": "timing",
    }
    hypothesis = _hypothesis(
        bug_class=BugClass.SQLI,
        specialist="injection_files",
        entry_point="POST /wp-admin/admin-ajax.php?action=save_sort",
        injection_order="second",
        storage_boundary="option",
        evidence_summary=evidence,
    )

    grade = grade_hypothesis(hypothesis)

    assert grade.accepted is False
    assert "second_order_sqli_writer_field_invalid" in grade.rules


@pytest.mark.parametrize(
    "marker",
    [
        None,
        "success",
        "aaaaaaaa",
        " confirmed-write",
        "confirmed-write ",
        "stored-✓-confirmed",
        "x" * 257,
    ],
)
def test_second_order_sqli_requires_a_specific_ascii_write_success_marker(
    marker,
) -> None:
    source = _hypothesis()
    evidence = {
        **source.evidence_summary,
        "source": "POST form field sort; plugin.php:10 — $_POST['sort']",
        "storage_writer": "POST writer stores a source-proven value",
        "storage_identity": "option:demo_sort",
        "trigger": "GET /report -> render_report -> query",
        "write_success_marker": marker,
        "same_actor_lifecycle": True,
        "verification_oracle": "timing",
    }
    hypothesis = _hypothesis(
        bug_class=BugClass.SQLI,
        specialist="injection_files",
        entry_point="POST /wp-admin/admin-ajax.php?action=save_sort",
        injection_order="second",
        storage_boundary="option",
        evidence_summary=evidence,
    )

    grade = grade_hypothesis(hypothesis)

    assert grade.accepted is False
    assert "second_order_sqli_write_success_marker_invalid" in grade.rules


def test_potential_rce_label_requires_and_preserves_execution_evidence() -> None:
    evidence = dict(_hypothesis().evidence_summary)
    hypothesis = _hypothesis(
        bug_class=BugClass.ARBITRARY_FILE_WRITE,
        specialist="injection_files",
        impact_labels=["potential_rce"],
        evidence_summary=evidence,
    )

    rejected = grade_hypothesis(hypothesis)
    assert rejected.accepted is False
    assert "potential_rce_execution_evidence_missing" in rejected.rules

    evidence.update(
        {
            "code_execution_path": (
                "upload route -> public .php destination -> HTTP execution"
            ),
            "code_execution_sink": "server executes uploads/proof.php",
        }
    )
    accepted = grade_hypothesis(
        hypothesis.model_copy(update={"evidence_summary": evidence})
    )

    assert accepted.accepted is True
    assert accepted.evidence["code_execution_path"] == evidence["code_execution_path"]
    assert accepted.evidence["code_execution_sink"] == evidence["code_execution_sink"]


@pytest.mark.parametrize(
    ("bug_class", "entry_point", "source", "expected_rule"),
    [
        (
            BugClass.COMMAND_INJECTION,
            "command callback",
            "POST form field command",
            "execution_transport_invalid",
        ),
        (
            BugClass.PHP_CODE_INJECTION,
            "POST /evaluate",
            "$_REQUEST['code']",
            "execution_source_field_invalid",
        ),
    ],
)
def test_execution_candidates_require_exact_http_transport_and_wire_field(
    bug_class,
    entry_point,
    source,
    expected_rule,
) -> None:
    evidence = {
        **_hypothesis().evidence_summary,
        "source": source,
    }
    hypothesis = _hypothesis(
        bug_class=bug_class,
        specialist="injection_files",
        entry_point=entry_point,
        evidence_summary=evidence,
    )

    grade = grade_hypothesis(hypothesis)

    assert grade.accepted is False
    assert expected_rule in grade.rules


def test_potential_rce_label_is_restricted_to_arbitrary_file_write() -> None:
    evidence = {
        **_hypothesis().evidence_summary,
        "code_execution_path": "request -> shell wrapper -> exec",
        "code_execution_sink": "exec($command)",
    }
    with pytest.raises(ValueError, match="exact CWE-434"):
        _hypothesis(
            bug_class=BugClass.COMMAND_INJECTION,
            specialist="injection_files",
            impact_labels=["potential_rce"],
            evidence_summary=evidence,
        )


def test_execution_evidence_requires_potential_rce_label() -> None:
    evidence = {
        **_hypothesis().evidence_summary,
        "code_execution_path": "upload -> executable destination -> HTTP request",
        "code_execution_sink": "server executes uploads/proof.php",
    }
    hypothesis = _hypothesis(
        bug_class=BugClass.ARBITRARY_FILE_WRITE,
        specialist="injection_files",
        evidence_summary=evidence,
    )

    grade = grade_hypothesis(hypothesis)

    assert grade.accepted is False
    assert "potential_rce_evidence_without_label" in grade.rules


def test_execution_evidence_without_label_routes_to_manual_review(tmp_path) -> None:
    evidence = {
        **_hypothesis().evidence_summary,
        "code_execution_path": "upload -> executable destination -> HTTP request",
        "code_execution_sink": "server executes uploads/proof.php",
    }
    hypothesis = _hypothesis(
        bug_class=BugClass.ARBITRARY_FILE_WRITE,
        specialist="injection_files",
        evidence_summary=evidence,
    )

    assert grade_hypothesis(hypothesis).rules == [
        "potential_rce_evidence_without_label"
    ]

    decision_path = tmp_path / "quality.json"
    gated = _apply_one(hypothesis, artifact_path=decision_path)

    assert gated.accepted == []
    assert gated.rejected == []
    assert gated.manual_review[0]["rules"] == [
        "potential_rce_evidence_without_label"
    ]
    assert json.loads(decision_path.read_text())[0]["disposition"] == "manual_review"


def test_quality_gate_preserves_canonical_ordered_verification_preflights() -> None:
    evidence = {
        **_hypothesis().evidence_summary,
        "verification_preflights": [
            "GET /wp-admin/admin.php?page=prepare&item=7",
            "HEAD /wp-json/example/v1/state?id=7",
        ],
    }
    hypothesis = _hypothesis(
        bug_class=BugClass.COMMAND_INJECTION,
        specialist="injection_files",
        evidence_summary=evidence,
    )

    grade = grade_hypothesis(hypothesis)

    assert grade.accepted is True
    assert grade.evidence["verification_preflights"] == evidence[
        "verification_preflights"
    ]


@pytest.mark.parametrize(
    "preflights",
    [
        [],
        ["POST /wp-admin/admin.php?page=prepare"],
        ["GET /prepare", "GET /prepare"],
        ["GET /prepare then visit the command route"],
        ["GET https://example.test/prepare"],
        ["GET /prepare?flag"],
        ["GET /prépare"],
        ["GET /prepare"] * 9,
        "GET /prepare",
    ],
)
def test_quality_gate_rejects_noncanonical_verification_preflights(
    preflights,
) -> None:
    evidence = {
        **_hypothesis().evidence_summary,
        "verification_preflights": preflights,
    }
    hypothesis = _hypothesis(
        bug_class=BugClass.COMMAND_INJECTION,
        specialist="injection_files",
        evidence_summary=evidence,
    )

    grade = grade_hypothesis(hypothesis)

    assert grade.accepted is False
    assert "verification_preflights_invalid" in grade.rules


def test_quality_gate_rejects_preflights_for_unrelated_bug_classes() -> None:
    evidence = {
        **_hypothesis().evidence_summary,
        "verification_preflights": ["GET /prepare"],
    }

    grade = grade_hypothesis(_hypothesis(evidence_summary=evidence))

    assert grade.accepted is False
    assert "verification_preflights_invalid" in grade.rules


def test_quality_gate_rejects_canonically_duplicate_preflights() -> None:
    evidence = {
        "attacker_role": "subscriber",
        "source": "POST form field command",
        "control": "No shell escaping",
        "reachable_path": "request -> system",
        "boundary": "A subscriber crosses the server command boundary.",
        "impact": "The subscriber can execute an operating-system command.",
        "verification_preflights": [
            "GET /prepare?a=1&b=2",
            "GET /prepare?b=2&a=1",
        ],
    }
    hypothesis = _hypothesis(
        bug_class=BugClass.COMMAND_INJECTION,
        evidence_summary=evidence,
    )

    grade = grade_hypothesis(hypothesis)

    assert "verification_preflights_invalid" in grade.rules


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


def _execution_candidate(
    *,
    source: object = "POST form field command; demo.php:10 — $_POST['command']",
    entry_point: str = "POST /execute",
    bug_class: BugClass = BugClass.COMMAND_INJECTION,
) -> Hypothesis:
    evidence = {**_hypothesis().evidence_summary, "source": source}
    return _hypothesis(
        bug_class=bug_class,
        specialist="injection_files",
        entry_point=entry_point,
        evidence_summary=evidence,
    )


def _second_order_candidate(
    *,
    source: object = "POST form field sort; demo.php:10 — $_POST['sort']",
    entry_point: str = "POST /save",
    trigger: object = "GET /report",
    same_actor: object = True,
    oracle: object = "timing",
) -> Hypothesis:
    evidence = {
        **_hypothesis().evidence_summary,
        "source": source,
        "storage_writer": "POST writer stores the source-proven sort value",
        "storage_identity": "option:demo_sort",
        "trigger": trigger,
        "write_success_marker": "FILTER_WRITE_CONFIRMED_7D3A",
        "same_actor_lifecycle": same_actor,
        "verification_oracle": oracle,
    }
    return _hypothesis(
        bug_class=BugClass.SQLI,
        specialist="injection_files",
        entry_point=entry_point,
        injection_order="second",
        storage_boundary="option",
        evidence_summary=evidence,
    )


def _apply_one(hypothesis: Hypothesis, *, artifact_path=None) -> TriagedArtifact:
    return apply_quality_gate(
        TriagedArtifact(
            plugin_slug="demo",
            accepted=[hypothesis],
            rejected=[],
            merged=[],
        ),
        artifact_path=artifact_path,
    )


_UNSUPPORTED_SOURCE_FIELDS = (
    "demo.php:10 — $_POST['settings']['sort']",
    "POST form field settings[sort]",
    "POST form field settings%5Bsort%5D",
    "JSON field settings.sort",
    "demo.php:10 — $_POST['settings.sort']",
    "demo.php:10 — $_POST['settings[sort]']",
    "demo.php:10 — $_POST['settings%5Bsort%5D']",
    "demo.php:10 — $_POST['settings'] /* reviewed chain */ ['sort']",
    "POST form field settings; demo.php:10 — $_POST['settings']['sort']",
    "request header X-Command; demo.php:10 — $_SERVER['HTTP_X_COMMAND']",
    "header parameter X-Command",
    "cookie command; demo.php:10 — $_COOKIE['command']",
    "cookie parameter command",
    "path parameter command",
    "multipart file field upload",
    "multipart form field upload",
    "raw request body",
    "raw body parameter command",
    "XML request body",
)


@pytest.mark.parametrize("source", _UNSUPPORTED_SOURCE_FIELDS)
@pytest.mark.parametrize(
    "bug_class",
    [BugClass.COMMAND_INJECTION, BugClass.PHP_CODE_INJECTION],
)
def test_quality_gate_routes_one_exact_unsupported_execution_field_to_manual(
    source: str,
    bug_class: BugClass,
    tmp_path,
) -> None:
    hypothesis = _execution_candidate(source=source, bug_class=bug_class)
    original_payload = hypothesis.model_dump(mode="json")
    decision_path = tmp_path / "quality.json"

    assert grade_hypothesis(hypothesis).rules == [
        "execution_source_field_unsupported"
    ]
    gated = _apply_one(hypothesis, artifact_path=decision_path)

    assert gated.accepted == []
    assert gated.rejected == []
    assert gated.manual_review[0]["rules"] == [
        "execution_source_field_unsupported"
    ]
    assert gated.manual_review[0]["hypothesis"] == original_payload
    assert json.loads(decision_path.read_text())[0]["disposition"] == "manual_review"


@pytest.mark.parametrize(
    "source",
    [
        "POST form field command and POST form field mode",
        "$_REQUEST['command']",
        "query or form parameter command",
        "",
    ],
)
def test_quality_gate_rejects_missing_or_ambiguous_execution_fields(
    source: object,
) -> None:
    hypothesis = _execution_candidate(source=source)

    grade = grade_hypothesis(hypothesis)
    gated = _apply_one(hypothesis)

    assert "execution_source_field_invalid" in grade.rules
    assert gated.manual_review == []
    assert gated.rejected[0]["hypothesis_id"] == hypothesis.id


def test_quality_gate_rejects_execution_field_dispatch_conflict() -> None:
    hypothesis = _execution_candidate(
        source="command query parameter",
        entry_point="POST /execute?command=fixed",
    )

    grade = grade_hypothesis(hypothesis)
    gated = _apply_one(hypothesis)

    assert grade.rules == ["execution_source_field_dispatch_conflict"]
    assert gated.manual_review == []
    assert gated.rejected[0]["hypothesis_id"] == hypothesis.id


@pytest.mark.parametrize("entry_point", ["command callback", "POST execute", ""])
def test_quality_gate_rejects_malformed_execution_transport(
    entry_point: str,
) -> None:
    hypothesis = _execution_candidate(entry_point=entry_point)

    grade = grade_hypothesis(hypothesis)
    gated = _apply_one(hypothesis)

    assert "execution_transport_invalid" in grade.rules
    assert gated.manual_review == []
    assert gated.rejected[0]["hypothesis_id"] == hypothesis.id


@pytest.mark.parametrize("source", _UNSUPPORTED_SOURCE_FIELDS)
def test_quality_gate_routes_exact_unsupported_second_order_writer_field_manual(
    source: str,
) -> None:
    hypothesis = _second_order_candidate(source=source)
    original_payload = hypothesis.model_dump(mode="json")

    assert grade_hypothesis(hypothesis).rules == [
        "second_order_sqli_writer_field_unsupported"
    ]
    gated = _apply_one(hypothesis)

    assert gated.rejected == []
    assert gated.manual_review[0]["hypothesis"] == original_payload
    assert gated.manual_review[0]["rules"] == [
        "second_order_sqli_writer_field_unsupported"
    ]


@pytest.mark.parametrize(
    ("updates", "rule"),
    [
        ({"same_actor_lifecycle": None}, "second_order_sqli_same_actor_invalid"),
        ({"same_actor_lifecycle": "false"}, "second_order_sqli_same_actor_invalid"),
        ({"verification_oracle": None}, "second_order_sqli_oracle_invalid"),
        ({"verification_oracle": "body_marker"}, "second_order_sqli_oracle_invalid"),
    ],
)
def test_quality_gate_rejects_missing_or_malformed_second_order_values(
    updates: dict[str, object],
    rule: str,
) -> None:
    hypothesis = _second_order_candidate()
    hypothesis.evidence_summary = {**hypothesis.evidence_summary, **updates}

    grade = grade_hypothesis(hypothesis)
    gated = _apply_one(hypothesis)

    assert rule in grade.rules
    assert gated.manual_review == []
    assert gated.rejected[0]["hypothesis_id"] == hypothesis.id


@pytest.mark.parametrize(
    ("same_actor", "oracle", "rule"),
    [
        (False, "timing", "second_order_sqli_different_actor_manual"),
        (True, "response_marker", "second_order_sqli_response_marker_manual"),
    ],
)
def test_quality_gate_routes_explicit_second_order_manual_contracts(
    same_actor: bool,
    oracle: str,
    rule: str,
) -> None:
    hypothesis = _second_order_candidate(same_actor=same_actor, oracle=oracle)
    original_payload = hypothesis.model_dump(mode="json")

    assert grade_hypothesis(hypothesis).rules == [rule]
    gated = _apply_one(hypothesis)

    assert gated.rejected == []
    assert gated.manual_review[0]["rules"] == [rule]
    assert gated.manual_review[0]["hypothesis"] == original_payload


@pytest.mark.parametrize(
    ("entry_point", "trigger", "rule"),
    [
        ("save sort callback", "GET /report", "second_order_sqli_writer_transport_invalid"),
        ("POST /save", "later report trigger", "second_order_sqli_trigger_transport_invalid"),
        ("POST /save", "run report command", "second_order_sqli_trigger_transport_invalid"),
        ("POST /save", None, "second_order_sqli_trigger_transport_invalid"),
    ],
)
def test_quality_gate_rejects_malformed_or_non_http_second_order_routes(
    entry_point: str,
    trigger: object,
    rule: str,
) -> None:
    hypothesis = _second_order_candidate(
        entry_point=entry_point,
        trigger=trigger,
    )

    grade = grade_hypothesis(hypothesis)
    gated = _apply_one(hypothesis)

    assert rule in grade.rules
    assert gated.manual_review == []
    assert gated.rejected[0]["hypothesis_id"] == hypothesis.id


def test_quality_gate_rejects_second_order_writer_dispatch_conflict() -> None:
    hypothesis = _second_order_candidate(
        source="sort query parameter",
        entry_point="POST /save?sort=fixed",
    )

    grade = grade_hypothesis(hypothesis)
    gated = _apply_one(hypothesis)

    assert grade.rules == ["second_order_sqli_writer_field_dispatch_conflict"]
    assert gated.manual_review == []
    assert gated.rejected[0]["hypothesis_id"] == hypothesis.id


def test_quality_gate_preserves_payload_for_multiple_explicit_manual_reasons() -> None:
    hypothesis = _second_order_candidate(
        same_actor=False,
        oracle="response_marker",
        trigger="scheduled report job -> query",
    )
    original_payload = hypothesis.model_dump(mode="json")
    expected_rules = {
        "second_order_sqli_different_actor_manual",
        "second_order_sqli_response_marker_manual",
        "second_order_sqli_trigger_transport_unsupported",
    }

    assert set(grade_hypothesis(hypothesis).rules) == expected_rules
    gated = _apply_one(hypothesis)

    assert gated.rejected == []
    assert set(gated.manual_review[0]["rules"]) == expected_rules
    assert gated.manual_review[0]["hypothesis"] == original_payload


@pytest.mark.parametrize(
    ("same_actor", "oracle", "trigger", "expected_rules"),
    [
        (
            True,
            "timing",
            "scheduled report job -> query",
            {"second_order_sqli_trigger_transport_unsupported"},
        ),
        (
            True,
            "timing",
            "CLI report command -> query",
            {"second_order_sqli_trigger_transport_unsupported"},
        ),
        (
            False,
            "response_marker",
            "GET /report",
            {
                "second_order_sqli_different_actor_manual",
                "second_order_sqli_response_marker_manual",
            },
        ),
        (
            False,
            "timing",
            "scheduled report job -> query",
            {
                "second_order_sqli_different_actor_manual",
                "second_order_sqli_trigger_transport_unsupported",
            },
        ),
        (
            True,
            "response_marker",
            "CLI report command -> query",
            {
                "second_order_sqli_response_marker_manual",
                "second_order_sqli_trigger_transport_unsupported",
            },
        ),
    ],
)
def test_quality_gate_routes_exact_non_http_trigger_manual_pairwise(
    same_actor: bool,
    oracle: str,
    trigger: str,
    expected_rules: set[str],
) -> None:
    hypothesis = _second_order_candidate(
        same_actor=same_actor,
        oracle=oracle,
        trigger=trigger,
    )
    original_payload = hypothesis.model_dump(mode="json")

    assert set(grade_hypothesis(hypothesis).rules) == expected_rules
    gated = _apply_one(hypothesis)

    assert gated.rejected == []
    assert set(gated.manual_review[0]["rules"]) == expected_rules
    assert gated.manual_review[0]["hypothesis"] == original_payload


@pytest.mark.parametrize(
    ("same_actor", "oracle", "trigger", "reject_rule"),
    [
        (None, "response_marker", "GET /report", "second_order_sqli_same_actor_invalid"),
        (False, None, "GET /report", "second_order_sqli_oracle_invalid"),
        (False, "timing", "later trigger", "second_order_sqli_trigger_transport_invalid"),
    ],
)
def test_quality_gate_does_not_manual_route_when_contract_is_also_invalid(
    same_actor: object,
    oracle: object,
    trigger: object,
    reject_rule: str,
) -> None:
    hypothesis = _second_order_candidate(
        same_actor=same_actor,
        oracle=oracle,
        trigger=trigger,
    )

    grade = grade_hypothesis(hypothesis)
    gated = _apply_one(hypothesis)

    assert reject_rule in grade.rules
    assert gated.manual_review == []
    assert gated.rejected[0]["hypothesis_id"] == hypothesis.id


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
        config=PipelineConfig.from_yaml("tests/fixtures/pipeline.yaml"),
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
