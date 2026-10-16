from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass, replace
from urllib.parse import parse_qs, urlencode

import httpx
import pytest

from squadrone.poc_proxy import (
    ACTOR_RECEIPT_HEADER,
    PHP_INCLUDE_RECEIPT_HEADER,
    PocProxySupervisor,
    classify_request_sentinels,
)
from squadrone.schemas import CIAImpact, PoCObservation
from squadrone.schemas.taxonomy import BugClass
from squadrone.services import sandbox as sandbox_module
from squadrone.services.php_include_oracle import (
    PHP_INCLUDE_ORACLE_FILE_MODE,
    PhpIncludeHostFilesystemMeasurement,
    PhpIncludeOracle,
    PhpIncludeOracleSnapshot,
)
from squadrone.services.sandbox import (
    SandboxRunResult,
    execution_private_marker_from_observation,
    redact_execution_run_result,
    validate_confirmation_observations,
    validate_execution_response_marker_http_trace,
)

_TRACE_SALT = bytes.fromhex("31" * 32)
_TRACE_SECRET = bytes.fromhex("42" * 32)
_TRACE_TOKEN = "53" * 32
_TARGET = "http://localhost:8123"
_ROUTE = "/execute"
_HOST_DEVICE = 8_123_456_709_871
_HOST_INODE = 9_123_456_709_877
_TRANSPORT: dict[str, object] = {
    "method": "POST",
    "route": _ROUTE,
    "dispatch": {"form:action": "run"},
    "destination_parameter": "command",
    "destination_location": "form",
}


def _actor_receipt(record: dict[str, object]) -> str:
    payload = {
        "v": 2,
        "trace_token": _TRACE_TOKEN,
        "nonce": f"{int(record['sequence']) + 100:032x}",
        "request_nonce": record["request_nonce"],
        "request_digest": record["request_digest"],
        "user_id": 0,
        "roles": [],
        "method": record["method"],
        "path": record["path"],
    }
    encoded = (
        base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        )
        .decode("ascii")
        .rstrip("=")
    )
    signature = hmac.new(
        _TRACE_SECRET,
        encoded.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    return f"{encoded}.{signature}"


class _ExecutionProxy(PocProxySupervisor):
    def __init__(self, oracle: PhpIncludeOracle, bug_class: BugClass) -> None:
        super().__init__(
            _TARGET,
            trace_token=_TRACE_TOKEN,
            trace_salt=_TRACE_SALT,
            tracked_capabilities={
                "execution_attack_path": oracle.attack_basename.removesuffix(".php"),
                "execution_control_path": oracle.control_basename.removesuffix(".php"),
                "execution_marker": oracle.private_marker,
            },
            capture_php_include_receipt=True,
        )
        self.oracle = oracle
        self.bug_class = bug_class

    async def _forward(
        self,
        method: str,
        url: str,
        headers: list[tuple[str, str]],
        body: bytes,
        nonce: str,
        request_digest: str,
        record: dict[str, object],
        *,
        credential_free_headers: list[tuple[str, str]] | None = None,
    ) -> tuple[httpx.Response, bytes]:
        del method, url, headers, nonce, request_digest, credential_free_headers
        destination = parse_qs(body.decode("ascii"), strict_parsing=True)["command"][0]
        response_headers = [(ACTOR_RECEIPT_HEADER, _actor_receipt(record))]
        content = b"handled"
        if self.oracle.attack_path in destination:
            if self.bug_class == BugClass.COMMAND_INJECTION:
                content = ("result:" + self.oracle.private_marker).encode("ascii")
            else:
                response_headers.append(
                    (PHP_INCLUDE_RECEIPT_HEADER, self.oracle.private_marker)
                )
        else:
            assert self.oracle.control_path in destination
        response = httpx.Response(200, headers=response_headers, content=content)
        return response, response.content


async def _record_request(proxy: PocProxySupervisor, destination: str) -> None:
    body = urlencode({"action": "run", "command": destination}).encode("ascii")
    headers = [
        ("Host", "localhost:8123"),
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Accept", "*/*"),
    ]
    raw_headers = "\r\n".join(f"{name}: {value}" for name, value in headers)
    flags, categories = classify_request_sentinels(
        _ROUTE.encode("ascii"),
        raw_headers.encode("latin-1"),
        body,
    )
    response, response_body, status, detail = await proxy._execute_accepted_request(
        method="POST",
        url=f"{_TARGET}{_ROUTE}",
        path=_ROUTE,
        raw_target=_ROUTE,
        headers=headers,
        body=body,
        sentinel_flags=flags,
        sentinel_categories=categories,
    )
    assert response is not None, (status, detail)
    assert response_body == response.content


def _host_measurement(
    oracle: PhpIncludeOracle,
) -> PhpIncludeHostFilesystemMeasurement:
    return PhpIncludeHostFilesystemMeasurement(
        attack_content_sha256=hashlib.sha256(oracle.private_attack_content).hexdigest(),
        attack_content_size_bytes=len(oracle.private_attack_content),
        attack_owner_uid=os.geteuid(),
        attack_owner_gid=os.getegid(),
        attack_file_mode=PHP_INCLUDE_ORACLE_FILE_MODE,
        attack_link_count=1,
        attack_is_regular_file=True,
        attack_is_symlink=False,
        control_lstat_exists=False,
        attack_device=_HOST_DEVICE,
        attack_inode=_HOST_INODE,
        measured_monotonic_ns=time.monotonic_ns(),
    )


@dataclass(slots=True)
class _Case:
    bug_class: BugClass
    oracle: PhpIncludeOracle
    observation: PoCObservation
    records: list[dict[str, object]]
    snapshot: PhpIncludeOracleSnapshot
    marker: str
    generation_id: str
    attack_value: str
    control_value: str


async def _valid_case(
    bug_class: BugClass,
    *,
    oracle: PhpIncludeOracle | None = None,
) -> _Case:
    oracle = oracle or PhpIncludeOracle(execution_mode=True)
    generation_id = oracle.begin_generation()
    marker = oracle.private_marker
    content = oracle.private_attack_content
    content_sha256 = hashlib.sha256(content).hexdigest()
    provisioning_started = time.monotonic_ns()
    host_before = _host_measurement(oracle)
    provisioning_finished = time.monotonic_ns()
    provisioning = oracle.attest_provisioning(
        generation_id=generation_id,
        attack_resource_path=oracle.attack_path,
        control_resource_path=oracle.control_path,
        attack_content_sha256=content_sha256,
        attack_content_size_bytes=len(content),
        attack_owner_uid=33,
        attack_owner_gid=33,
        attack_file_mode=PHP_INCLUDE_ORACLE_FILE_MODE,
        attack_link_count=1,
        attack_is_regular_file=True,
        attack_is_symlink=False,
        control_lstat_exists=False,
        host_measurement=host_before,
        started_monotonic_ns=provisioning_started,
        finished_monotonic_ns=provisioning_finished,
    )
    if bug_class == BugClass.COMMAND_INJECTION:
        attack_value = f"php {oracle.attack_path}"
        control_value = f"php {oracle.control_path}"
    else:
        attack_value = f"include '{oracle.attack_path}';"
        control_value = f"include '{oracle.control_path}';"
    proxy = _ExecutionProxy(oracle, bug_class)
    execution_started = max(
        provisioning.filesystem.measured_monotonic_ns,
        time.monotonic_ns(),
    )
    await _record_request(proxy, control_value)
    await _record_request(proxy, attack_value)
    execution_finished = time.monotonic_ns()
    host_after = _host_measurement(oracle)
    after = time.monotonic_ns()
    snapshot = oracle.attest_verification(
        generation_id=generation_id,
        attack_resource_path=oracle.attack_path,
        control_resource_path=oracle.control_path,
        after_attack_content_sha256=content_sha256,
        after_attack_content_size_bytes=len(content),
        after_attack_owner_uid=33,
        after_attack_owner_gid=33,
        after_attack_file_mode=PHP_INCLUDE_ORACLE_FILE_MODE,
        after_attack_link_count=1,
        after_attack_is_regular_file=True,
        after_attack_is_symlink=False,
        after_control_lstat_exists=False,
        after_host_measurement=host_after,
        execution_started_monotonic_ns=execution_started,
        execution_finished_monotonic_ns=execution_finished,
        after_monotonic_ns=after,
    )
    observation = PoCObservation(
        verdict="vulnerable",
        oracle="response_marker",
        attacker_role="unauthenticated",
        request={"method": "POST", "url": f"{_TARGET}{_ROUTE}"},
        attack={
            "observed": True,
            "marker": marker,
            "marker_present": True,
            "execution_path": oracle.attack_path,
            "destination_value": attack_value,
        },
        control={
            "observed": False,
            "marker_present": False,
            "execution_path": oracle.control_path,
            "destination_value": control_value,
        },
        impact=CIAImpact(
            integrity="high",
            description="The parent-private execution canary ran.",
        ),
    )
    return _Case(
        bug_class=bug_class,
        oracle=oracle,
        observation=observation,
        records=proxy.records,
        snapshot=snapshot,
        marker=marker,
        generation_id=generation_id,
        attack_value=attack_value,
        control_value=control_value,
    )


def _validate(case: _Case) -> tuple[bool, str, dict]:
    return validate_execution_response_marker_http_trace(
        case.observation,
        case.records,
        trace_salt=_TRACE_SALT,
        target_url=_TARGET,
        receipt_secret=_TRACE_SECRET,
        trace_token=_TRACE_TOKEN,
        expected_http_transport=_TRANSPORT,
        expected_attacker_role="unauthenticated",
        expected_bug_class=case.bug_class.value,
        oracle_attack_path=case.oracle.attack_path,
        oracle_control_path=case.oracle.control_path,
        oracle_marker=case.marker,
        oracle_snapshot=case.snapshot,
        oracle_generation_id=case.generation_id,
    )


def _replace_response_body(record: dict[str, object], body: bytes) -> None:
    record["response_body_sha256"] = hashlib.sha256(body).hexdigest()
    record["response_body_length"] = len(body)
    record["response_body_b64"] = base64.b64encode(body).decode("ascii")
    record["response_body_tail_b64"] = ""
    record["response_body_truncated"] = False


def test_execution_oracle_preparation_has_no_private_generation_material() -> None:
    oracle = PhpIncludeOracle(execution_mode=True)

    public = oracle.public_context()

    assert set(public) == {
        "attack_path",
        "control_path",
        "attack_basename",
        "control_basename",
        "header_name",
    }
    assert "marker" not in repr(public).casefold()
    with pytest.raises(RuntimeError, match="generation"):
        _ = oracle.private_marker

    # SandboxManager begins the generation only inside run_poc, after the
    # already-authored script has been isolated.
    oracle.begin_generation()
    assert oracle.private_marker.startswith("SQUADRONE_PHP_INCLUDE_")


@pytest.mark.asyncio
async def test_execution_marker_is_privateattr_only_and_redacted_before_dump() -> None:
    case = await _valid_case(BugClass.COMMAND_INJECTION)
    marker = case.marker
    result = SandboxRunResult(
        success=True,
        output=f"stdout:{marker}",
        elapsed=0,
        response=f"response:{marker}",
        error_log=f"error:{marker}",
        evidence={
            "private": marker,
            "nested": {marker: [marker]},
        },
        observation=case.observation,
        validation_reason=f"accepted:{marker}",
    )
    result.retain_trusted_execution_observation(case.observation)

    redact_execution_run_result(result, marker)

    persisted = result.model_dump_json()
    assert marker not in persisted
    assert marker not in result.output
    assert marker not in (result.response or "")
    assert marker not in (result.error_log or "")
    assert marker not in result.validation_reason
    assert marker not in json.dumps(result.evidence, sort_keys=True)
    assert marker not in result.observation.model_dump_json()
    assert result.rejected_observation is None
    assert result.output == ""
    assert result.response is None
    assert result.error_log is None
    assert result.observation.impact.model_dump(mode="json") == {
        "confidentiality": "none",
        "integrity": "high",
        "availability": "none",
        "description": sandbox_module.EXECUTION_PARENT_IMPACT_DESCRIPTION,
    }
    assert (
        result.evidence["execution_marker_sha256"]
        == hashlib.sha256(marker.encode("ascii")).hexdigest()
    )
    assert result.evidence["execution_marker_redacted"] is True
    assert "php_include_marker_sha256" not in result.evidence
    assert "php_include_marker_redacted" not in result.evidence

    live = result.take_trusted_execution_observation()
    assert execution_private_marker_from_observation(live) == marker
    assert result.take_trusted_execution_observation() is None
    assert marker not in result.model_dump_json()

    rejected_result = SandboxRunResult(
        success=False,
        output=f"rejected stdout:{marker}",
        elapsed=0,
        error_log=f"rejected error:{marker}",
        evidence={"rejected_private": marker},
        observation=case.observation.model_copy(deep=True),
        validation_reason=f"rejected:{marker}",
    )
    redact_execution_run_result(rejected_result, marker)
    assert rejected_result.observation is None
    assert rejected_result.rejected_observation is None
    assert marker not in rejected_result.model_dump_json()


@pytest.mark.asyncio
async def test_execution_persistence_discards_encoded_and_split_child_channels() -> None:
    case = await _valid_case(BugClass.COMMAND_INJECTION)
    marker = case.marker
    encoded = base64.b64encode(marker.encode("ascii")).decode("ascii")
    hexed = marker.encode("ascii").hex()
    left, right = marker[: len(marker) // 2], marker[len(marker) // 2 :]
    child_observation = case.observation.model_copy(deep=True)
    child_observation.attack["encoded_note"] = encoded
    child_observation.control["split_note"] = [left, right]
    child_observation.impact.description = hexed
    promoted = sandbox_module._parent_execution_observation(child_observation)
    result = SandboxRunResult(
        success=True,
        output=hexed,
        elapsed=0,
        response=encoded,
        error_log=f"{left}\n{right}",
        evidence={
            "child_hex": hexed,
            "child_base64": encoded,
            "child_split": [left, right],
        },
        observation=child_observation,
        validation_reason=encoded,
    )
    result.retain_trusted_execution_observation(promoted)

    redact_execution_run_result(result, marker)

    persisted = result.model_dump_json()
    for forbidden in (marker, encoded, hexed, left, right):
        assert forbidden not in persisted
    assert result.output == ""
    assert result.response is None
    assert result.error_log is None
    assert result.rejected_observation is None
    assert result.observation is not None
    assert result.observation.impact.description == (
        sandbox_module.EXECUTION_PARENT_IMPACT_DESCRIPTION
    )
    live = result.take_trusted_execution_observation()
    assert live is promoted
    assert live.impact.description == sandbox_module.EXECUTION_PARENT_IMPACT_DESCRIPTION

    rejected = SandboxRunResult(
        success=False,
        output=encoded,
        elapsed=0,
        error_log=hexed,
        evidence={"child_split": [left, right]},
        observation=child_observation,
        validation_reason=left + right,
    )
    redact_execution_run_result(rejected, marker)
    rejected_dump = rejected.model_dump_json()
    for forbidden in (marker, encoded, hexed, left, right):
        assert forbidden not in rejected_dump
    assert rejected.observation is None
    assert rejected.rejected_observation is None


@pytest.mark.asyncio
async def test_execution_parent_promotion_discards_child_impact_and_extra_fields() -> None:
    case = await _valid_case(BugClass.PHP_CODE_INJECTION)
    child = case.observation.model_copy(deep=True)
    child.attack["child_claim"] = "full compromise"
    child.control["child_claim"] = "arbitrary"
    child.impact = CIAImpact(
        confidentiality="high",
        integrity="high",
        availability="high",
        description="Child-authored total compromise claim.",
    )

    promoted = sandbox_module._parent_execution_observation(child)

    assert set(promoted.attack) == {
        "observed",
        "marker",
        "marker_present",
        "execution_path",
        "destination_value",
    }
    assert set(promoted.control) == {
        "observed",
        "marker_present",
        "execution_path",
        "destination_value",
    }
    assert promoted.impact.model_dump(mode="json") == {
        "confidentiality": "none",
        "integrity": "high",
        "availability": "none",
        "description": sandbox_module.EXECUTION_PARENT_IMPACT_DESCRIPTION,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bug_class",
    [BugClass.COMMAND_INJECTION, BugClass.PHP_CODE_INJECTION],
)
async def test_private_execution_canary_accepts_fresh_parent_effect(
    bug_class: BugClass,
) -> None:
    case = await _valid_case(bug_class)

    accepted, reason, evidence = _validate(case)

    assert accepted is True, reason
    assert evidence["oracle"] == "execution_private_canary_parent_trace_v1"
    assert evidence["control"]["sequence"] == 1
    assert evidence["attack"]["sequence"] == 2
    assert evidence["transmitted_marker_absent"] is True
    assert case.marker.encode("ascii") not in case.oracle.private_attack_content


@pytest.mark.asyncio
async def test_model_authored_constant_cannot_confirm_execution() -> None:
    case = await _valid_case(BugClass.COMMAND_INJECTION)
    case.observation.attack["marker"] = "SQUADRONE_PHP_INCLUDE_" + "f" * 64

    accepted, reason, _evidence = _validate(case)

    assert accepted is False
    assert "private canary" in reason


@pytest.mark.asyncio
@pytest.mark.parametrize("source_body", [False, True])
async def test_php_reflection_or_split_canary_source_cannot_confirm_execution(
    source_body: bool,
) -> None:
    case = await _valid_case(BugClass.PHP_CODE_INJECTION)
    attack_record = case.records[1]
    attack_record["response_php_include_receipt"] = None
    body = (
        case.oracle.private_attack_content
        if source_body
        else case.marker.encode("ascii")
    )
    _replace_response_body(attack_record, body)

    accepted, reason, _evidence = _validate(case)

    assert case.marker.encode("ascii") not in case.oracle.private_attack_content
    assert accepted is False
    assert "evaluation" in reason


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bug_class",
    [BugClass.COMMAND_INJECTION, BugClass.PHP_CODE_INJECTION],
)
async def test_private_execution_canary_rejects_control_effect(
    bug_class: BugClass,
) -> None:
    case = await _valid_case(bug_class)
    control_record = case.records[0]
    if bug_class == BugClass.COMMAND_INJECTION:
        _replace_response_body(control_record, case.marker.encode("ascii"))
    else:
        control_record["response_php_include_receipt"] = case.marker

    accepted, reason, _evidence = _validate(case)

    assert accepted is False
    assert "control" in reason


@pytest.mark.asyncio
async def test_private_execution_canary_rejects_extra_proof_request() -> None:
    case = await _valid_case(BugClass.COMMAND_INJECTION)
    extra = copy.deepcopy(case.records[1])
    extra["sequence"] = 3
    case.records.append(extra)

    accepted, reason, _evidence = _validate(case)

    assert accepted is False
    assert "exactly one control and attack pair" in reason


@pytest.mark.asyncio
async def test_private_execution_canary_rejects_tampered_attestation() -> None:
    case = await _valid_case(BugClass.COMMAND_INJECTION)
    case.snapshot = replace(
        case.snapshot,
        provisioning=replace(case.snapshot.provisioning, marker_sha256="0" * 64),
    )

    accepted, reason, _evidence = _validate(case)

    assert accepted is False
    assert "attestation" in reason


@pytest.mark.asyncio
async def test_execution_confirmation_requires_fresh_private_marker() -> None:
    oracle = PhpIncludeOracle(execution_mode=True)
    first = await _valid_case(BugClass.COMMAND_INJECTION, oracle=oracle)
    confirmation = await _valid_case(BugClass.COMMAND_INJECTION, oracle=oracle)

    first_ok, first_reason, _ = _validate(first)
    confirmation_ok, confirmation_reason, _ = _validate(confirmation)
    fresh_ok, fresh_reason = validate_confirmation_observations(
        first.observation,
        confirmation.observation,
    )

    assert first_ok is True, first_reason
    assert confirmation_ok is True, confirmation_reason
    assert first.marker != confirmation.marker
    assert fresh_ok is True, fresh_reason

    replay = confirmation.observation.model_copy(deep=True)
    replay.attack["marker"] = first.marker
    replay_ok, replay_reason = validate_confirmation_observations(
        first.observation,
        replay,
    )
    assert replay_ok is False
    assert "fresh private execution marker" in replay_reason
