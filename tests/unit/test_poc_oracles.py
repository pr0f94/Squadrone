from __future__ import annotations

import json

from squadrone.schemas import CIAImpact, PoCObservation
from squadrone.services.sandbox import (
    POC_RESULT_PREFIX,
    _parse_poc_observation,
    validate_confirmation_observations,
    validate_poc_observation,
)


def _observation(**overrides) -> PoCObservation:
    data = {
        "schema_version": 1,
        "verdict": "vulnerable",
        "oracle": "response_marker",
        "attacker_role": "unauthenticated",
        "request": {"method": "POST", "url": "http://localhost/endpoint"},
        "attack": {
            "observed": True,
            "marker": "private-marker",
            "marker_present": True,
        },
        "control": {"observed": False, "marker_present": False},
        "impact": CIAImpact(
            confidentiality="high",
            description="The response disclosed a private marker.",
        ),
    }
    data.update(overrides)
    return PoCObservation.model_validate(data)


def test_unstructured_success_text_is_not_proof():
    observation, reason = _parse_poc_observation("[+] SUCCESS: got HTTP 200\n")

    assert observation is None
    assert "missing final" in reason


def test_parser_uses_final_structured_result_line():
    expected = _observation()
    stdout = (
        "debug output\n"
        + POC_RESULT_PREFIX
        + json.dumps(expected.model_dump(mode="json"))
    )

    parsed, reason = _parse_poc_observation(stdout)

    assert reason == ""
    assert parsed == expected


def test_parser_rejects_multiple_structured_results():
    expected = _observation()
    result_line = POC_RESULT_PREFIX + json.dumps(expected.model_dump(mode="json"))

    parsed, reason = _parse_poc_observation(result_line + "\n" + result_line)

    assert parsed is None
    assert "more than one" in reason


def test_parser_rejects_output_after_structured_result():
    expected = _observation()
    stdout = (
        POC_RESULT_PREFIX
        + json.dumps(expected.model_dump(mode="json"))
        + "\nlate debug"
    )

    parsed, reason = _parse_poc_observation(stdout)

    assert parsed is None
    assert "final output line" in reason


def test_confirmation_must_reproduce_same_claim():
    first = _observation()
    confirmation = first.model_copy(deep=True)

    accepted, reason = validate_confirmation_observations(first, confirmation)

    assert accepted is True
    assert "reproduced" in reason


def test_confirmation_rejects_changed_role_or_impact():
    first = _observation()
    confirmation = _observation(
        attacker_role="subscriber",
        impact=CIAImpact(
            integrity="high",
            description="A different security effect was claimed.",
        ),
    )

    accepted, reason = validate_confirmation_observations(first, confirmation)

    assert accepted is False
    assert "attacker role" in reason


def test_confirmation_compares_canonicalized_attacker_roles():
    first = _observation(attacker_role="anonymous remote attacker")
    confirmation = _observation(attacker_role="unauthenticated")

    accepted, reason = validate_confirmation_observations(first, confirmation)

    assert accepted is True, reason


def test_confirmation_rejects_unrecognized_attacker_roles():
    first = _observation(attacker_role="authenticated user")
    confirmation = _observation(attacker_role="authenticated user")

    accepted, reason = validate_confirmation_observations(first, confirmation)

    assert accepted is False
    assert "unrecognized attacker role" in reason


def test_valid_timing_oracle_requires_repeatable_differential():
    observation = _observation(
        oracle="timing",
        attack={"observed": True, "samples_seconds": [5.1, 5.0, 5.2]},
        control={"observed": False, "samples_seconds": [0.2, 0.3, 0.2]},
        impact=CIAImpact(
            confidentiality="high", description="Boolean SQL result was inferred."
        ),
    )

    accepted, reason = validate_poc_observation(observation, expected_bug_class="SQLI")

    assert accepted is True
    assert "passed" in reason


def test_timing_oracle_rejects_small_or_single_sample_delta():
    observation = _observation(
        oracle="timing",
        attack={"observed": True, "samples_seconds": [1.0, 1.1, 1.2]},
        control={"observed": False, "samples_seconds": [0.8, 0.9, 0.9]},
    )

    accepted, reason = validate_poc_observation(observation, expected_bug_class="SQLI")

    assert accepted is False
    assert "too small" in reason


def test_callback_hit_without_sensitive_marker_is_only_an_ssrf_primitive():
    observation = _observation(
        oracle="callback",
        attack={"observed": True, "hit_count": 1},
        control={"observed": False, "hit_count": 0, "marker_present": False},
        impact=CIAImpact(
            confidentiality="high", description="Claimed internal disclosure."
        ),
    )

    accepted, reason = validate_poc_observation(observation, expected_bug_class="SSRF")

    assert accepted is False
    assert "sensitive marker" in reason


def test_cross_object_oracle_requires_distinct_nonempty_ids():
    observation = _observation(
        oracle="cross_object_access",
        attack={
            "observed": True,
            "attacker_user_id": "",
            "owner_user_id": "2",
            "secret_present": True,
        },
        control={"observed": False, "secret_present": False},
    )

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "identifiers" in reason


def test_file_oracle_requires_hex_sha256():
    observation = _observation(
        oracle="file_effect",
        attack={
            "observed": True,
            "exists": True,
            "path": "/tmp/marker",
            "marker_sha256": "z" * 64,
        },
        control={"observed": False, "exists": False},
        impact=CIAImpact(integrity="high", description="A protected file was written."),
    )

    accepted, reason = validate_poc_observation(
        observation,
        expected_bug_class="ARBITRARY_FILE_WRITE",
    )

    assert accepted is False
    assert "SHA-256" in reason


def test_file_oracle_accepts_measured_file_sha256_alias():
    observation = _observation(
        oracle="file_effect",
        attack={
            "observed": True,
            "exists": True,
            "path": "/wp-content/uploads/marker.php",
            "file_sha256": "a" * 64,
        },
        control={"observed": False, "exists": False},
        impact=CIAImpact(integrity="high", description="A protected file was written."),
    )

    accepted, reason = validate_poc_observation(
        observation,
        expected_bug_class="ARBITRARY_FILE_WRITE",
    )

    assert accepted is True, reason


def test_oracle_must_match_vulnerability_class():
    accepted, reason = validate_poc_observation(
        _observation(),
        expected_bug_class="XSS_STORED",
    )

    assert accepted is False
    assert "cannot prove" in reason


def test_missing_authentication_accepts_measured_response_marker_oracle():
    accepted, reason = validate_poc_observation(
        _observation(),
        expected_bug_class="MISSING_AUTH_CRITICAL_FUNCTION",
    )

    assert accepted is True, reason


def test_unmapped_cwe_has_no_automatic_oracle():
    accepted, reason = validate_poc_observation(
        _observation(),
        expected_bug_class="CWE-1234",
    )

    assert accepted is False
    assert "no automatic oracle" in reason


def test_observation_without_cia_impact_is_rejected():
    observation = _observation(impact=CIAImpact(description="No protected effect."))

    accepted, reason = validate_poc_observation(observation, expected_bug_class="SQLI")

    assert accepted is False
    assert "no confidentiality" in reason


def test_observation_must_use_source_reviewed_attacker_role():
    accepted, reason = validate_poc_observation(
        _observation(attacker_role="administrator"),
        expected_bug_class="SQLI",
        expected_attacker_role="unauthenticated",
    )

    assert accepted is False
    assert "source review requires" in reason


def test_observation_accepts_descriptive_equivalent_attacker_role():
    accepted, reason = validate_poc_observation(
        _observation(attacker_role="unauthenticated_remote_attacker"),
        expected_bug_class="SQLI",
        expected_attacker_role="unauthenticated",
    )

    assert accepted is True, reason


def test_observation_rejects_unrecognized_source_role():
    accepted, reason = validate_poc_observation(
        _observation(),
        expected_bug_class="SQLI",
        expected_attacker_role="authenticated user",
    )

    assert accepted is False
    assert "source review has an unrecognized" in reason


def test_observation_request_must_target_local_sandbox():
    observation = _observation(
        request={"method": "POST", "url": "https://example.com/endpoint"},
    )

    accepted, reason = validate_poc_observation(observation, expected_bug_class="SQLI")

    assert accepted is False
    assert "local sandbox" in reason
