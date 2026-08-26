"""Smoke tests — every Pydantic schema instantiates with valid data and round-trips through JSON."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from squadrone.agents.prompts_io import load_prompt
from squadrone.schemas import (
    BugClass,
    Confidence,
    DedupStatus,
    EntryPoint,
    Finding,
    Hypothesis,
    HypothesesArtifact,
    IntakeArtifact,
    PipelineConfig,
    PoCAttempt,
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


def test_finding_round_trip(tmp_path):
    f = _finding()
    p = tmp_path / "f.json"
    f.to_json_file(str(p))
    assert Finding.from_json_file(str(p)) == f


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
    cfg = PipelineConfig.from_yaml("pipelines/default.yaml")
    assert cfg.cost_ceiling_usd > 0
    assert cfg.models.specialists
    assert "wordfence" in cfg.vuln_dbs.model_dump()


def test_pipeline_llm_options_load():
    cfg = PipelineConfig.from_yaml("pipelines/openai.yaml")
    assert cfg.llm_options_for_role("critic") == {
        "reasoning_effort": "high",
        "verbosity": "high",
    }
    assert cfg.llm_options_for_role("surveyor") == {
        "reasoning_effort": "high",
        "verbosity": "high",
    }


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
