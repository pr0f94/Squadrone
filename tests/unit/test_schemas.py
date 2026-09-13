"""Smoke tests — every Pydantic schema instantiates with valid data and round-trips through JSON."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from squadrone.agents.prompts_io import load_prompt
from squadrone.schemas import (
    BugClass,
    CIAImpact,
    Confidence,
    DedupStatus,
    EntryPoint,
    Finding,
    Hypothesis,
    HypothesesArtifact,
    IntakeArtifact,
    PipelineConfig,
    PoCAttempt,
    PoCObservation,
    PoCStatus,
    ReconArtifact,
    Sink,
    StaticCallEdge,
    StaticCallback,
    TriagedArtifact,
)


def _hypothesis() -> Hypothesis:
    return Hypothesis(
        id="h-1",
        specialist="auth",
        bug_class=BugClass.MISSING_CAP_CHECK,
        entry_point="wp_ajax_demo",
        file="demo.php",
        line=10,
        sink="wp_delete_post",
        taint_path=["$_POST", "wp_delete_post"],
        reasoning="No cap check.",
        confidence=Confidence.HIGH,
        preconditions="any subscriber",
        affected_versions="<=1.0",
    )


def _finding() -> Finding:
    h = _hypothesis()
    return Finding(
        id="f-1",
        hypothesis=h,
        poc_status=PoCStatus.SUCCESS,
        poc_script_path="/tmp/p.py",
        poc_attempts=[
            PoCAttempt(iteration=1, script_path="/tmp/p.py", result=PoCStatus.SUCCESS)
        ],
        evidence={"deleted": 1},
        confidence_runs=1,
        dedup_status=DedupStatus.NOVEL,
        dedup_matches=[],
    )


def _reported_observation() -> PoCObservation:
    return PoCObservation(
        verdict="vulnerable",
        oracle="callback",
        attacker_role="unauthenticated",
        request={"method": "POST", "url": "http://localhost/test"},
        attack={"observed": True},
        control={"observed": False},
        impact=CIAImpact(integrity="low", description="Child-declared callback."),
    )


def test_failed_attempt_separates_rejected_child_observation() -> None:
    reported = _reported_observation()

    attempt = PoCAttempt(
        iteration=1,
        script_path="/tmp/p.py",
        result=PoCStatus.FAILED,
        observation=reported,
        validation_reason="parent callback receipt was absent",
    )

    assert attempt.observation is None
    assert attempt.rejected_observation == reported
    persisted = attempt.model_dump(mode="json")
    assert persisted["observation"] is None
    assert persisted["rejected_observation"]["verdict"] == "vulnerable"


def test_later_runner_rejection_moves_accepted_attempt_observation() -> None:
    reported = _reported_observation()
    attempt = PoCAttempt(
        iteration=1,
        script_path="/tmp/p.py",
        result=PoCStatus.SUCCESS,
        response_snippet='before\nSQUADRONE_RESULT={"verdict":"vulnerable"}\nafter',
        error_log_snippet='SQUADRONE_RESULT={"forged":"error"}',
        observation=reported,
    )

    attempt.mark_failed("clean-state control did not reproduce")

    assert attempt.result == PoCStatus.FAILED
    assert attempt.observation is None
    assert attempt.rejected_observation == reported
    assert attempt.response_snippet is None
    assert attempt.error_log_snippet is None
    assert attempt.validation_reason == "clean-state control did not reproduce"


def test_later_rejection_clears_truncated_success_fragments() -> None:
    reported = _reported_observation()
    attempt = PoCAttempt(
        iteration=1,
        script_path="/tmp/p.py",
        result=PoCStatus.SUCCESS,
        response_snippet='"verdict":"vulnerable","instantiated":true}',
        error_log_snippet='"effect":"canary instantiated"}',
        developer_analysis="the canary was proven",
        observation=reported,
    )

    attempt.mark_failed("trusted parent receipt was absent")

    assert attempt.response_snippet is None
    assert attempt.error_log_snippet is None
    assert attempt.developer_analysis is None


def test_intake_round_trip(tmp_path):
    a = IntakeArtifact(
        run_id="r1",
        plugin_slug="x",
        plugin_version="1.0",
        source_path="/tmp/x",
        file_count=1,
        total_lines=10,
        source_url="https://example/",
        scanned_at=datetime.now(timezone.utc),
    )
    p = tmp_path / "intake.json"
    a.to_json_file(str(p))
    assert IntakeArtifact.from_json_file(str(p)) == a


def test_intake_accepts_legacy_svn_url_field():
    artifact = IntakeArtifact.model_validate(
        {
            "run_id": "r1",
            "plugin_slug": "x",
            "plugin_version": "1.0",
            "source_path": "/tmp/x",
            "file_count": 1,
            "total_lines": 10,
            "svn_url": "https://plugins.svn.wordpress.org/x/tags/1.0",
            "scanned_at": datetime.now(timezone.utc),
        }
    )

    assert artifact.source_url.endswith("/x/tags/1.0")


def test_recon_round_trip(tmp_path):
    a = ReconArtifact(
        plugin_slug="x",
        entry_points=[
            EntryPoint(
                type="ajax_priv",
                name="wp_ajax_x",
                file="x.php",
                line=1,
                handler_function="x",
                requires_auth=True,
                has_nonce_check=False,
                has_capability_check=False,
                capability=None,
            )
        ],
        sinks=[
            Sink(
                type="db_query",
                function="wpdb->query",
                file="x.php",
                line=2,
                tainted_args=["a"],
            )
        ],
        entry_to_sink_paths={"wp_ajax_x": ["x.php:1->x.php:2"]},
        raw_grep_hits={"add_action": ["x.php:1"]},
        static_callbacks=[
            StaticCallback(
                type="ajax_priv",
                name="wp_ajax_x",
                file="x.php",
                line=1,
                handler_function="x",
                callback_kind="function",
                raw="add_action('wp_ajax_x', 'x')",
            )
        ],
        static_call_edges=[
            StaticCallEdge(
                caller="x",
                callee="helper",
                caller_file="x.php",
                caller_line=2,
                callee_file="x.php",
                callee_line=8,
                confidence="high",
            )
        ],
    )
    p = tmp_path / "recon.json"
    a.to_json_file(str(p))
    assert ReconArtifact.from_json_file(str(p)) == a


def test_hypothesis_artifacts():
    h = _hypothesis()
    ha = HypothesesArtifact(plugin_slug="x", hypotheses=[h])
    assert ha.hypotheses[0].bug_class == BugClass.MISSING_CAP_CHECK
    ta = TriagedArtifact(plugin_slug="x", accepted=[h], rejected=[], merged=[])
    assert ta.accepted == [h]
    assert ta.submission_scope_enforced is True

    local_only = ta.model_copy(update={"submission_scope_enforced": False})
    assert (
        TriagedArtifact.model_validate_json(
            local_only.model_dump_json()
        ).submission_scope_enforced
        is False
    )


def test_xss_taxonomy_keeps_stored_and_reflected_distinct():
    base = _hypothesis().model_dump(mode="json")
    stored = Hypothesis.model_validate(
        {
            **base,
            "bug_class": BugClass.XSS_STORED.value,
            "root_cause_cwe": "",
            "vulnerability_type": "",
        }
    )
    reflected = Hypothesis.model_validate(
        {
            **base,
            "bug_class": BugClass.XSS_REFLECTED.value,
            "root_cause_cwe": "",
            "vulnerability_type": "",
        }
    )

    assert stored.bug_class.value == "CWE-79:stored"
    assert reflected.bug_class.value == "CWE-79:reflected"
    assert stored.root_cause_cwe == reflected.root_cause_cwe == "CWE-79"
    assert stored.vulnerability_type != reflected.vulnerability_type


def test_authenticated_cwe306_history_is_preserved_on_deserialization():
    data = _hypothesis().model_dump(mode="json")
    data.update(
        {
            "bug_class": BugClass.MISSING_AUTH_CRITICAL_FUNCTION.value,
            "root_cause_cwe": BugClass.MISSING_AUTH_CRITICAL_FUNCTION.value,
            "vulnerability_type": "missing_authentication_for_critical_function",
            "evidence_summary": {"attacker_role": "authenticated Subscriber"},
        }
    )

    parsed = Hypothesis.model_validate(data)

    assert parsed.bug_class == BugClass.MISSING_AUTH_CRITICAL_FUNCTION
    assert parsed.root_cause_cwe == "CWE-306"
    assert parsed.vulnerability_type == "missing_authentication_for_critical_function"
    round_tripped = Hypothesis.model_validate_json(parsed.model_dump_json())
    assert round_tripped.bug_class == BugClass.MISSING_AUTH_CRITICAL_FUNCTION


def test_unauthenticated_cwe306_remains_missing_authentication():
    data = _hypothesis().model_dump(mode="json")
    data.update(
        {
            "bug_class": BugClass.MISSING_AUTH_CRITICAL_FUNCTION.value,
            "evidence_summary": {"attacker_role": "unauthenticated"},
        }
    )

    parsed = Hypothesis.model_validate(data)

    assert parsed.bug_class == BugClass.MISSING_AUTH_CRITICAL_FUNCTION
    assert parsed.root_cause_cwe == "CWE-306"
    assert (
        parsed.vulnerability_type
        == "missing_authentication_for_critical_function"
    )


def test_authorization_prompt_distinguishes_authentication_from_authorization():
    prompt = load_prompt("specialists/authorization_workflows")

    assert "Use CWE-306 only when" in prompt
    assert "lowest\ndemonstrated attacker is unauthenticated" in prompt
    assert "Use CWE-862 when WordPress authenticated" in prompt
    assert "including a Subscriber through `wp_ajax_*`" in prompt


def test_legacy_cwe79_artifact_is_upgraded_from_context():
    parsed = Hypothesis.model_validate(
        {
            **_hypothesis().model_dump(mode="json"),
            "bug_class": "CWE-79",
            "reasoning": "Stored payload reaches an administrator view.",
            "root_cause_cwe": "",
            "vulnerability_type": "",
        }
    )

    assert parsed.bug_class == BugClass.XSS_STORED
    assert parsed.root_cause_cwe == "CWE-79"


@pytest.mark.parametrize(
    ("label", "expected"),
    [
        ("CWE-862: Missing Authorization", BugClass.MISSING_CAP_CHECK),
        (
            "CWE-306: Missing Authentication for Critical Function",
            BugClass.MISSING_AUTH_CRITICAL_FUNCTION,
        ),
        ("CWE-639: Authorization Bypass Through User-Controlled Key", BugClass.IDOR),
        (
            "CWE-400: Uncontrolled Resource Consumption",
            BugClass.RESOURCE_EXHAUSTION,
        ),
        ("SQL Injection", BugClass.SQLI),
        ("Server-Side Request Forgery", BugClass.SSRF),
        (
            "Unrestricted Upload of File with Dangerous Type",
            BugClass.ARBITRARY_FILE_WRITE,
        ),
        ("Uncontrolled Resource Consumption", BugClass.RESOURCE_EXHAUSTION),
        ("CWE-79: Stored Cross-Site Scripting", BugClass.XSS_STORED),
        ("CWE-79: Reflected Cross-Site Scripting", BugClass.XSS_REFLECTED),
    ],
)
def test_descriptive_bug_class_labels_are_normalized(label, expected):
    parsed = Hypothesis.model_validate(
        {
            **_hypothesis().model_dump(mode="json"),
            "bug_class": label,
        }
    )

    assert parsed.bug_class == expected


def test_auxiliary_cwe_normalizes_unknown_descriptive_bug_class():
    parsed = Hypothesis.model_validate(
        {
            **_hypothesis().model_dump(mode="json"),
            "bug_class": "Dangerous upload primitive",
            "cwe": "CWE-434",
        }
    )

    assert parsed.bug_class == BugClass.ARBITRARY_FILE_WRITE


def test_valid_bug_class_wins_over_conflicting_auxiliary_cwe():
    parsed = Hypothesis.model_validate(
        {
            **_hypothesis().model_dump(mode="json"),
            "bug_class": "CWE-89",
            "cwe": "CWE-434",
        }
    )

    assert parsed.bug_class == BugClass.SQLI


def test_unmapped_cwe_label_is_preserved_and_round_trips() -> None:
    data = _hypothesis().model_dump(mode="json")
    data.update(
        {
            "bug_class": "CWE-1234: Future Weakness",
            "root_cause_cwe": "",
            "vulnerability_type": "",
        }
    )

    parsed = Hypothesis.model_validate(data)
    reparsed = Hypothesis.model_validate_json(parsed.model_dump_json())

    assert parsed.bug_class.value == "CWE-1234"
    assert parsed.bug_class.is_known is False
    assert parsed.root_cause_cwe == "CWE-1234"
    assert parsed.vulnerability_type == "unclassified_cwe"
    assert reparsed.bug_class.value == "CWE-1234"


@pytest.mark.parametrize(
    ("bug_class", "expected_root", "expected_type"),
    [
        ("CWE-89", "CWE-89", "sql_injection"),
        ("CWE-1234", "CWE-1234", "unclassified_cwe"),
    ],
)
def test_taxonomy_fields_override_contradictory_payload_metadata(
    bug_class: str,
    expected_root: str,
    expected_type: str,
) -> None:
    parsed = Hypothesis.model_validate(
        {
            **_hypothesis().model_dump(mode="json"),
            "bug_class": bug_class,
            "root_cause_cwe": "CWE-79",
            "vulnerability_type": "stored_cross_site_scripting",
        }
    )

    assert parsed.root_cause_cwe == expected_root
    assert parsed.vulnerability_type == expected_type


def test_hypothesis_normalization_remains_tolerant_of_lowercase_cwe_labels() -> None:
    parsed = Hypothesis.model_validate(
        {
            **_hypothesis().model_dump(mode="json"),
            "bug_class": "cwe-89",
        }
    )

    assert parsed.bug_class is BugClass.SQLI
    assert parsed.bug_class.is_known is True


@pytest.mark.parametrize("label", ["CWE-0", "CWE-01", "CWE-123 no colon"])
def test_malformed_cwe_labels_are_rejected(label):
    with pytest.raises(ValidationError):
        Hypothesis.model_validate(
            {
                **_hypothesis().model_dump(mode="json"),
                "bug_class": label,
            }
        )


def test_missing_model_preconditions_do_not_invalidate_whole_artifact():
    data = _hypothesis().model_dump(mode="json")
    data.pop("preconditions")

    parsed = Hypothesis.model_validate(data)

    assert parsed.preconditions == ""


def test_missing_model_confidence_defaults_conservatively_to_medium():
    data = _hypothesis().model_dump(mode="json")
    data.pop("confidence")

    parsed = Hypothesis.model_validate(data)

    assert parsed.confidence == Confidence.MEDIUM


def test_hypothesis_contract_aliases_are_normalized_without_overwriting_canonical_keys():
    data = _hypothesis().model_dump(mode="json")
    data.pop("id")
    data.pop("specialist")
    data.update(
        {
            "hypothesis_id": "alias-id",
            "reviewer": "injection_files",
            "confidence": "",
        }
    )

    parsed = Hypothesis.model_validate(data)
    canonical = Hypothesis.model_validate(
        {
            **data,
            "id": "canonical-id",
            "specialist": "authentication",
        }
    )

    assert (parsed.id, parsed.specialist, parsed.confidence) == (
        "alias-id",
        "injection_files",
        Confidence.MEDIUM,
    )
    assert (canonical.id, canonical.specialist) == ("canonical-id", "authentication")


def test_invalid_explicit_confidence_and_missing_substantive_fields_still_fail():
    with pytest.raises(ValidationError):
        Hypothesis.model_validate(
            {
                **_hypothesis().model_dump(mode="json"),
                "confidence": "certain",
            }
        )

    data = _hypothesis().model_dump(mode="json")
    data.pop("affected_versions")
    with pytest.raises(ValidationError):
        Hypothesis.model_validate(data)


def test_specialist_prompt_names_the_canonical_hypothesis_contract():
    prompt = load_prompt("specialists/_shared_rules")

    for field in ("id", "specialist", "bug_class", "confidence", "affected_versions"):
        assert f'"{field}"' in prompt
    assert "do not substitute `hypothesis_id`, `reviewer`" in prompt
    assert '"entry_point": "POST /origin-relative/path"' in prompt
    assert (
        '"source": "POST form field exact_name; relative/source-file:123 '
        "— $_POST['exact_name']\"" in prompt
    )


def test_finding_round_trip(tmp_path):
    f = _finding()
    p = tmp_path / "f.json"
    f.to_json_file(str(p))
    loaded = Finding.from_json_file(str(p))
    assert loaded == f
    assert loaded.poc_attempts[0].proof_kind == "standard"


def test_poc_attempt_proof_kind_is_closed_and_backward_compatible():
    historical = PoCAttempt.model_validate(
        {"iteration": 1, "script_path": "/tmp/p.py", "result": "failed"}
    )
    assert historical.proof_kind == "standard"

    natural = historical.model_copy(update={"proof_kind": "php_object_natural"})
    assert natural.proof_kind == "php_object_natural"

    with pytest.raises(ValidationError):
        PoCAttempt.model_validate(
            {
                "iteration": 1,
                "proof_kind": "model_claimed_gadget",
                "script_path": "/tmp/p.py",
                "result": "failed",
            }
        )


def test_invalid_data_raises():
    with pytest.raises(ValidationError):
        IntakeArtifact()  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        Hypothesis(  # type: ignore[call-arg]
            id="x",
            specialist="s",
            bug_class="not-a-cwe",
            entry_point="e",
            file="f",
            line=1,
            sink="s",
            taint_path=[],
            reasoning="r",
            confidence="maybe",
            preconditions="p",
            affected_versions="v",
        )
    with pytest.raises(ValidationError):
        PoCAttempt(iteration=1, script_path="/tmp", result="nope")  # type: ignore[arg-type]


def test_pipeline_config_loads():
    cfg = PipelineConfig.from_yaml("pipelines/chatgpt.yaml")
    assert cfg.cost_ceiling_usd > 0
    assert cfg.models.specialists
    assert cfg.hypothesis_review_areas == [
        "authorization_workflows",
        "injection_files",
        "xss_lifecycle",
        "authentication",
    ]
    assert cfg.hypothesis_review_item_types is None


@pytest.mark.parametrize(
    "review_areas",
    [
        [],
        ["injection_files", "injection_files"],
        ["not_a_review_area"],
    ],
)
def test_pipeline_config_rejects_invalid_hypothesis_review_areas(review_areas):
    payload = PipelineConfig.from_yaml("pipelines/chatgpt.yaml").model_dump()
    payload["hypothesis_review_areas"] = review_areas

    with pytest.raises(ValidationError):
        PipelineConfig.model_validate(payload)


@pytest.mark.parametrize(
    "item_types",
    [
        [],
        ["deserialization", "deserialization"],
        [""],
        ["   "],
    ],
)
def test_pipeline_config_rejects_invalid_hypothesis_review_item_types(item_types):
    payload = PipelineConfig.from_yaml("pipelines/chatgpt.yaml").model_dump()
    payload["hypothesis_review_item_types"] = item_types

    with pytest.raises(ValidationError):
        PipelineConfig.model_validate(payload)


def test_pipeline_llm_options_load():
    cfg = PipelineConfig.from_yaml("pipelines/chatgpt.yaml")
    assert cfg.llm_options_for_role("critic") == {"reasoning_effort": "medium"}
    assert cfg.llm_options_for_role("surveyor") == {"reasoning_effort": "medium"}


@pytest.mark.parametrize("role", ["developer_followup", "hypothesis_verifier"])
def test_pipeline_model_roles_have_no_provider_specific_fallback(role):
    payload = PipelineConfig.from_yaml("pipelines/chatgpt.yaml").model_dump()
    del payload["models"][role]

    with pytest.raises(ValidationError):
        PipelineConfig.model_validate(payload)


def test_hypothesis_coerces_list_to_str():
    """LLMs sometimes emit list[str] for fields we declared as str. Coerce."""
    h = Hypothesis.model_validate(
        {
            "id": "x",
            "specialist": "auth",
            "bug_class": "CWE-862",
            "entry_point": "wp_ajax_x",
            "file": "x.php",
            "line": 1,
            "sink": ["a", "b"],
            "taint_path": ["src", "sink"],
            "reasoning": ["one reason", "another"],
            "confidence": "high",
            "preconditions": ["a precondition", "another"],
            "affected_versions": ["<= 1.0", "and 2.0"],
        }
    )
    assert h.preconditions == "a precondition; another"
    assert h.reasoning == "one reason; another"
    assert h.sink == "a; b"


def test_hypothesis_preserves_structured_entry_and_sink_references():
    h = Hypothesis.model_validate(
        {
            **_hypothesis().model_dump(mode="json"),
            "entry_point": {
                "type": "direct_php",
                "name": "api/connector.php",
                "file": "api/connector.php",
                "line": 12,
            },
            "sink": {
                "type": "file_write",
                "function": "rename",
                "file": "src/files.php",
                "line": 81,
                "code": "rename($old, $new);",
            },
        }
    )

    assert h.entry_point == ("direct_php api/connector.php | api/connector.php:12")
    assert h.sink == ("file_write rename | src/files.php:81 | rename($old, $new);")


@pytest.mark.parametrize(
    "sink",
    [
        "src/files.php:81",
        {
            "type": "file_write",
            "function": "rename",
            "file": "src/files.php",
            "line": 81,
        },
    ],
)
def test_hypothesis_derives_omitted_location_from_explicit_sink(sink):
    data = _hypothesis().model_dump(mode="json")
    data.pop("file")
    data.pop("line")
    data["sink"] = sink

    h = Hypothesis.model_validate(data)

    assert h.file == "src/files.php"
    assert h.line == 81


def test_explicit_hypothesis_location_wins_over_sink_reference():
    h = Hypothesis.model_validate(
        {
            **_hypothesis().model_dump(mode="json"),
            "file": "reported.php",
            "line": 10,
            "sink": "different.php:99",
        }
    )

    assert (h.file, h.line) == ("reported.php", 10)


def test_hypothesis_coerces_scalar_taint_path_to_list():
    h = Hypothesis.model_validate(
        {
            "id": "x",
            "specialist": "auth",
            "bug_class": "CWE-862",
            "entry_point": "wp_ajax_x",
            "file": "x.php",
            "line": 1,
            "sink": "state change",
            "sink_code": "do_action();",
            "taint_path": "request -> handler -> sink",
            "reasoning": "Missing capability check.",
            "confidence": "medium",
            "preconditions": "unauthenticated attacker",
            "affected_versions": "current",
        }
    )

    assert h.taint_path == ["request", "handler", "sink"]


def test_hypothesis_coerces_step_object_taint_path_to_list():
    h = Hypothesis.model_validate(
        {
            "id": "auth-001",
            "specialist": "auth",
            "bug_class": "CWE-862",
            "entry_point": "ApplePay VALIDATE",
            "file": "modules/ppcp-applepay/src/Assets/ApplePayButton.php",
            "line": 85,
            "sink": "global Apple Pay payment settings update",
            "sink_code": "set_applepay_validated();",
            "taint_path": [
                {
                    "step": "wp_ajax_nopriv_ApplePay VALIDATE -> ApplePayButton::validate()"
                },
                {"step": "ApplePayButton::validate() accepts POST data"},
            ],
            "reasoning": "Missing capability check before saving global settings.",
            "confidence": "high",
            "preconditions": "unauthenticated user with valid checkout nonce",
            "affected_versions": "all currently shipped",
        }
    )

    assert h.taint_path == [
        "wp_ajax_nopriv_ApplePay VALIDATE -> ApplePayButton::validate()",
        "ApplePayButton::validate() accepts POST data",
    ]


def test_hypothesis_coerces_confidence_case():
    h = Hypothesis.model_validate(
        {
            "id": "authflow-001",
            "specialist": "auth_flow",
            "bug_class": "CWE-287",
            "entry_point": "rest_permission_callback",
            "file": "Auth.php",
            "line": 32,
            "sink": "token validation",
            "sink_code": "return true;",
            "taint_path": "request -> permission_callback",
            "reasoning": "Forged token accepted.",
            "confidence": "MEDIUM",
            "preconditions": "unauthenticated attacker",
            "affected_versions": "current",
        }
    )

    assert h.confidence == Confidence.MEDIUM


def test_strip_fences_handles_prose_and_embedded_json():
    """Runtime must extract JSON from various LLM response shapes."""
    import json as _json
    from squadrone.agents.runtime import _strip_fences

    assert _json.loads(_strip_fences("```json\n[1,2]\n```")) == [1, 2]
    assert _json.loads(_strip_fences("Here you go:\n```json\n[1,2]\n```")) == [1, 2]
    assert _json.loads(_strip_fences('Based on analysis:\n[{"a":1}]\nThanks.')) == [
        {"a": 1}
    ]
    assert _json.loads(_strip_fences('[{"x":"has [bracket]"}]')) == [
        {"x": "has [bracket]"}
    ]
    # Object containing nested array — must return the OBJECT, not the inner array
    out = _strip_fences(
        'Here is the recon: {"plugin_slug":"x","entry_points":[{"a":1}],"sinks":[]}'
    )
    parsed = _json.loads(out)
    assert isinstance(parsed, dict) and parsed["plugin_slug"] == "x"
