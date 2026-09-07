from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import pytest

from squadrone.poc_proxy import (
    ACTOR_RECEIPT_HEADER,
    PHP_INCLUDE_RECEIPT_HEADER,
    PocProxySupervisor,
    classify_request_sentinels,
)
from squadrone.schemas import CIAImpact, PoCObservation
from squadrone.services.php_include_oracle import (
    PHP_INCLUDE_ORACLE_FILE_MODE,
    PhpIncludeHostFilesystemMeasurement,
    PhpIncludeOracle,
    PhpIncludeOracleSnapshot,
)
from squadrone.services.sandbox import (
    validate_php_include_response_marker_http_trace,
)


_TRACE_SALT = bytes.fromhex("31" * 32)
_TRACE_SECRET = bytes.fromhex("42" * 32)
_TRACE_TOKEN = "53" * 32
_TARGET_URL = "http://localhost:8123"
_ROUTE = "/wp-admin/admin-ajax.php"
_HOST_DEVICE = 8_123_456_701_237
_HOST_INODE = 9_123_456_701_239
_EXPECTED_TRANSPORT: dict[str, object] = {
    "method": "POST",
    "route": _ROUTE,
    "dispatch": {
        "form:action": "example_dispatch",
        "form:function": "render_editor",
        "query:action": "add",
    },
    "destination_parameter": "source",
    "destination_location": "query",
}


def _actor_receipt(
    record: dict[str, object],
    *,
    actor_nonce: str | None = None,
) -> str:
    payload = {
        "v": 2,
        "trace_token": _TRACE_TOKEN,
        "nonce": actor_nonce or f"{int(record['sequence']) + 100:032x}",
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


class _InMemoryPhpIncludeProxy(PocProxySupervisor):
    def __init__(self, oracle: PhpIncludeOracle) -> None:
        super().__init__(
            _TARGET_URL,
            trace_token=_TRACE_TOKEN,
            trace_salt=_TRACE_SALT,
            tracked_capabilities={
                "php_include_attack_path": oracle.attack_basename.removesuffix(".php"),
                "php_include_control_path": oracle.control_basename.removesuffix(
                    ".php"
                ),
            },
            capture_php_include_receipt=True,
        )
        self.oracle = oracle

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
        del method, headers, body, nonce, request_digest, credential_free_headers
        destination = parse_qs(urlsplit(url).query, strict_parsing=True)["source"][0]
        response_headers = [(ACTOR_RECEIPT_HEADER, _actor_receipt(record))]
        if self.oracle.attack_basename.removesuffix(".php") in destination:
            response_headers.append(
                (PHP_INCLUDE_RECEIPT_HEADER, self.oracle.private_marker)
            )
        else:
            assert self.oracle.control_basename.removesuffix(".php") in destination
        response = httpx.Response(200, headers=response_headers, content=b"handled")
        return response, response.content


async def _record_request(proxy: PocProxySupervisor, destination: str) -> None:
    query = urlencode({"action": "add", "source": destination})
    url = f"{_TARGET_URL}{_ROUTE}?{query}"
    raw_target = f"{_ROUTE}?{query}"
    body = urlencode(
        {"action": "example_dispatch", "function": "render_editor"}
    ).encode("ascii")
    headers = [
        ("Host", "localhost:8123"),
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Accept", "*/*"),
    ]
    raw_headers = "\r\n".join(f"{name}: {value}" for name, value in headers)
    flags, categories = classify_request_sentinels(
        raw_target.encode("ascii"),
        raw_headers.encode("latin-1"),
        body,
    )
    response, response_body, status, detail = await proxy._execute_accepted_request(
        method="POST",
        url=url,
        path=_ROUTE,
        raw_target=raw_target,
        headers=headers,
        body=body,
        sentinel_flags=flags,
        sentinel_categories=categories,
    )
    assert response is not None, (status, detail)
    assert response_body == response.content


@dataclass(slots=True)
class _Case:
    observation: PoCObservation
    records: list[dict[str, object]]
    snapshot: PhpIncludeOracleSnapshot
    attack_path: str
    control_path: str
    marker: str
    generation_id: str


def _host_measurement(
    oracle: PhpIncludeOracle,
    *,
    measured_monotonic_ns: int | None = None,
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
        measured_monotonic_ns=(
            time.monotonic_ns()
            if measured_monotonic_ns is None
            else measured_monotonic_ns
        ),
    )


async def _valid_case() -> _Case:
    oracle = PhpIncludeOracle()
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
        attack_owner_uid=0,
        attack_owner_gid=0,
        attack_file_mode=PHP_INCLUDE_ORACLE_FILE_MODE,
        attack_link_count=1,
        attack_is_regular_file=True,
        attack_is_symlink=False,
        control_lstat_exists=False,
        host_measurement=host_before,
        started_monotonic_ns=provisioning_started,
        finished_monotonic_ns=provisioning_finished,
    )

    attack_stem = oracle.attack_basename.removesuffix(".php")
    control_stem = oracle.control_basename.removesuffix(".php")
    prefix = "../../../../../../var/lib/squadrone/php-include/"
    attack_value = prefix + attack_stem
    control_value = prefix + control_stem
    proxy = _InMemoryPhpIncludeProxy(oracle)
    execution_started = max(
        provisioning.filesystem.measured_monotonic_ns,
        time.monotonic_ns(),
    )
    await _record_request(proxy, attack_value)
    await _record_request(proxy, control_value)
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
    fingerprint = {**_EXPECTED_TRANSPORT, "csrf_fields": []}
    observation = PoCObservation(
        verdict="vulnerable",
        oracle="response_marker",
        attacker_role="unauthenticated",
        request={"method": "POST", "url": _TARGET_URL + _ROUTE},
        attack={
            "observed": True,
            "marker": marker,
            "marker_present": True,
            "include_path": oracle.attack_path,
            "destination_value": attack_value,
            "attacker_user_id": "anonymous",
            "identity_verified": True,
            "request_fingerprint": fingerprint,
        },
        control={
            "observed": False,
            "marker_present": False,
            "include_path": oracle.control_path,
            "destination_value": control_value,
            "attacker_user_id": "anonymous",
            "identity_verified": True,
            "request_fingerprint": copy.deepcopy(fingerprint),
        },
        impact=CIAImpact(
            confidentiality="low",
            description="The trusted PHP include canary executed.",
        ),
    )
    return _Case(
        observation=observation,
        records=proxy.records,
        snapshot=snapshot,
        attack_path=oracle.attack_path,
        control_path=oracle.control_path,
        marker=marker,
        generation_id=generation_id,
    )


def _validate(case: _Case) -> tuple[bool, str, dict]:
    return validate_php_include_response_marker_http_trace(
        case.observation,
        case.records,
        trace_salt=_TRACE_SALT,
        target_url=_TARGET_URL,
        receipt_secret=_TRACE_SECRET,
        trace_token=_TRACE_TOKEN,
        oracle_attack_path=case.attack_path,
        oracle_control_path=case.control_path,
        oracle_marker=case.marker,
        oracle_snapshot=case.snapshot,
        oracle_generation_id=case.generation_id,
        expected_http_transport=_EXPECTED_TRANSPORT,
    )


@pytest.mark.asyncio
async def test_php_include_trace_binds_receipt_paths_actor_and_absent_control() -> None:
    case = await _valid_case()

    accepted, reason, evidence = _validate(case)

    assert accepted is True, reason
    assert evidence["oracle"] == "php_include_response_marker"
    attestation = evidence["php_include_attestation"]
    assert attestation["control_lstat_exists"] is False
    assert attestation["host_owner_verified"] is True
    assert attestation["host_identity_stable"] is True
    assert len(attestation["host_identity_sha256"]) == 64
    assert attestation["host_identity_sha256"] == (
        case.snapshot.provisioning.host_filesystem.host_identity_sha256
    )
    assert "owner_uid" not in attestation
    assert "owner_gid" not in attestation
    assert not any(
        type(value) is int
        and value in {os.geteuid(), os.getegid(), _HOST_DEVICE, _HOST_INODE}
        for value in attestation.values()
    )
    assert case.records[0]["response_php_include_receipt"] == case.marker
    assert case.records[1]["response_php_include_receipt"] is None
    serialized_evidence = json.dumps(evidence, sort_keys=True)
    assert case.marker not in serialized_evidence
    assert case.attack_path not in serialized_evidence
    assert case.control_path not in serialized_evidence
    assert "response_php_include_receipt" not in serialized_evidence
    assert "attack_owner_uid" not in serialized_evidence
    assert "attack_owner_gid" not in serialized_evidence
    for private_host_value in (
        "owner_uid",
        "owner_gid",
        "attack_device",
        "attack_inode",
        "measured_monotonic_ns",
        str(_HOST_DEVICE),
        str(_HOST_INODE),
        case.generation_id,
    ):
        assert private_host_value not in serialized_evidence


@pytest.mark.asyncio
async def test_php_include_trace_accepts_container_owner_projection_drift() -> None:
    case = await _valid_case()

    assert case.snapshot.provisioning.filesystem.attack_owner_uid == 0
    assert case.snapshot.provisioning.filesystem.attack_owner_gid == 0
    assert case.snapshot.verification.after.attack_owner_uid == 33
    assert case.snapshot.verification.after.attack_owner_gid == 33

    accepted, reason, evidence = _validate(case)

    assert accepted is True, reason
    serialized_evidence = json.dumps(evidence, sort_keys=True)
    assert '"owner_uid"' not in serialized_evidence
    assert '"owner_gid"' not in serialized_evidence

    negative = await _valid_case()
    object.__setattr__(
        negative.snapshot.verification.after,
        "attack_owner_uid",
        -1,
    )
    accepted, reason, evidence = _validate(negative)
    assert accepted is False
    assert reason == "PHP include attestation is invalid or non-causal"
    assert evidence == {}


@pytest.mark.asyncio
async def test_php_include_trace_rejects_destination_drift_and_control_receipt() -> (
    None
):
    drift = await _valid_case()
    drift.observation.control["destination_value"] += "-different"
    accepted, reason, _evidence = _validate(drift)
    assert accepted is False
    assert "change more than the path token" in reason

    receipt = await _valid_case()
    receipt.records[1]["response_php_include_receipt"] = receipt.marker
    accepted, reason, _evidence = _validate(receipt)
    assert accepted is False
    assert "receipt appeared outside the attack arm" in reason


@pytest.mark.asyncio
async def test_php_include_trace_rejects_replayed_identity_and_untrusted_preproof() -> (
    None
):
    replay = await _valid_case()
    shared_nonce = "9" * 32
    replay.records[0]["response_actor_receipt"] = _actor_receipt(
        replay.records[0], actor_nonce=shared_nonce
    )
    replay.records[1]["response_actor_receipt"] = _actor_receipt(
        replay.records[1], actor_nonce=shared_nonce
    )
    accepted, reason, _evidence = _validate(replay)
    assert accepted is False
    assert "reused a signed request nonce" in reason

    preproof = await _valid_case()
    unrelated = copy.deepcopy(preproof.records[0])
    unrelated.update(
        {
            "sequence": 1,
            "path": "/wp-login.php",
            "fields": [],
            "parameter_shape": [],
            "response_actor_receipt": "malformed",
            "response_php_include_receipt": None,
        }
    )
    preproof.records[0]["sequence"] = 2
    preproof.records[1]["sequence"] = 3
    preproof.records.insert(0, unrelated)
    accepted, reason, _evidence = _validate(preproof)
    assert accepted is False
    assert "pre-proof actor receipt is untrusted" in reason


@pytest.mark.asyncio
async def test_php_include_trace_rejects_wrong_capability_field_and_changed_state() -> (
    None
):
    wrong_field = await _valid_case()
    attack_fields = wrong_field.records[0]["fields"]
    assert isinstance(attack_fields, list)
    source_field = next(field for field in attack_fields if field["name"] == "source")
    function_field = next(
        field for field in attack_fields if field["name"] == "function"
    )
    source_field["tracked_capabilities"] = []
    function_field["tracked_capabilities"] = ["php_include_attack_path"]
    accepted, reason, _evidence = _validate(wrong_field)
    assert accepted is False
    assert "outside its exact destination arm" in reason

    changed = await _valid_case()
    object.__setattr__(
        changed.snapshot.verification.after,
        "control_lstat_exists",
        True,
    )
    accepted, reason, _evidence = _validate(changed)
    assert accepted is False
    assert "attestation is invalid" in reason

    changed_host = await _valid_case()
    object.__setattr__(
        changed_host.snapshot.verification.host_after,
        "attack_owner_matches_verifier",
        False,
    )
    accepted, reason, _evidence = _validate(changed_host)
    assert accepted is False
    assert "attestation is invalid" in reason


@pytest.mark.parametrize(
    ("attribute_path", "value"),
    [
        (("generation_id",), 7),
        (("provisioning", "marker_sha256"), None),
        (("verification", "execution_started_monotonic_ns"), "1"),
        (("verification", "after", "attack_path_sha256"), b"0" * 64),
        (("verification", "after", "attack_owner_uid"), True),
        (("provisioning", "host_filesystem", "host_identity_sha256"), b"0" * 64),
        (
            ("verification", "host_after", "attack_owner_matches_verifier"),
            1,
        ),
        (("verification", "host_after", "attack_content_size_bytes"), "1"),
    ],
)
@pytest.mark.asyncio
async def test_php_include_trace_rejects_wrong_typed_snapshot_scalars(
    attribute_path: tuple[str, ...],
    value: object,
) -> None:
    case = await _valid_case()
    target: object = case.snapshot
    for attribute in attribute_path[:-1]:
        target = getattr(target, attribute)
    object.__setattr__(target, attribute_path[-1], value)

    accepted, reason, evidence = _validate(case)

    assert accepted is False
    assert reason == "PHP include attestation scalar shape is invalid"
    assert evidence == {}


@pytest.mark.asyncio
async def test_php_include_trace_rejects_wrong_host_attestation_type() -> None:
    case = await _valid_case()
    object.__setattr__(
        case.snapshot.verification,
        "host_after",
        case.snapshot.verification.after,
    )

    accepted, reason, evidence = _validate(case)

    assert accepted is False
    assert reason == "PHP include attestation shape is invalid"
    assert evidence == {}


@pytest.mark.parametrize(
    "attribute_path",
    [
        ("provisioning", "generation_id"),
        ("provisioning", "marker_sha256"),
        ("verification", "after", "attack_content_sha256"),
        ("verification", "host_after", "host_identity_sha256"),
    ],
)
@pytest.mark.asyncio
async def test_php_include_trace_rejects_non_ascii_attestation_digests(
    attribute_path: tuple[str, ...],
) -> None:
    case = await _valid_case()
    target: object = case.snapshot
    for attribute in attribute_path[:-1]:
        target = getattr(target, attribute)
    object.__setattr__(target, attribute_path[-1], "é" * 64)

    accepted, reason, evidence = _validate(case)

    assert accepted is False
    assert reason == "PHP include attestation is invalid or non-causal"
    assert evidence == {}


@pytest.mark.asyncio
async def test_php_include_trace_rejects_changed_host_identity_and_noncausal_time() -> (
    None
):
    changed_identity = await _valid_case()
    object.__setattr__(
        changed_identity.snapshot.verification.host_after,
        "host_identity_sha256",
        "f" * 64,
    )
    accepted, reason, evidence = _validate(changed_identity)
    assert accepted is False
    assert reason == "PHP include attestation is invalid or non-causal"
    assert evidence == {}

    late_host = await _valid_case()
    object.__setattr__(
        late_host.snapshot.verification.host_after,
        "measured_monotonic_ns",
        late_host.snapshot.verification.after.measured_monotonic_ns + 1,
    )
    accepted, reason, evidence = _validate(late_host)
    assert accepted is False
    assert reason == "PHP include attestation is invalid or non-causal"
    assert evidence == {}

    early_host = await _valid_case()
    object.__setattr__(
        early_host.snapshot.provisioning.host_filesystem,
        "measured_monotonic_ns",
        early_host.snapshot.provisioning.started_monotonic_ns - 1,
    )
    accepted, reason, evidence = _validate(early_host)
    assert accepted is False
    assert reason == "PHP include attestation is invalid or non-causal"
    assert evidence == {}

    host_after_container = await _valid_case()
    object.__setattr__(
        host_after_container.snapshot.provisioning.host_filesystem,
        "measured_monotonic_ns",
        host_after_container.snapshot.provisioning.filesystem.measured_monotonic_ns + 1,
    )
    accepted, reason, evidence = _validate(host_after_container)
    assert accepted is False
    assert reason == "PHP include attestation is invalid or non-causal"
    assert evidence == {}

    future_chain = await _valid_case()
    future_ns = time.monotonic_ns() + 10_000_000_000
    object.__setattr__(
        future_chain.snapshot.verification.host_after,
        "measured_monotonic_ns",
        future_ns,
    )
    object.__setattr__(
        future_chain.snapshot.verification.after,
        "measured_monotonic_ns",
        future_ns + 1,
    )
    accepted, reason, evidence = _validate(future_chain)
    assert accepted is False
    assert reason == "PHP include attestation is invalid or non-causal"
    assert evidence == {}


@pytest.mark.parametrize(
    ("attribute", "value"),
    [
        ("attack_content_sha256", "e" * 64),
        ("attack_content_size_bytes", 1),
        ("attack_file_mode", 0o400),
        ("attack_link_count", 2),
        ("attack_is_regular_file", False),
        ("attack_is_symlink", True),
        ("control_lstat_exists", True),
    ],
)
@pytest.mark.asyncio
async def test_php_include_trace_rejects_changed_safe_host_state(
    attribute: str,
    value: object,
) -> None:
    case = await _valid_case()
    object.__setattr__(case.snapshot.verification.host_after, attribute, value)

    accepted, reason, evidence = _validate(case)

    assert accepted is False
    assert reason == "PHP include attestation is invalid or non-causal"
    assert evidence == {}

    noncausal = await _valid_case()
    object.__setattr__(
        noncausal.snapshot.verification.host_after,
        "measured_monotonic_ns",
        noncausal.snapshot.verification.execution_finished_monotonic_ns - 1,
    )
    accepted, reason, evidence = _validate(noncausal)
    assert accepted is False
    assert reason == "PHP include attestation is invalid or non-causal"
    assert evidence == {}


@pytest.mark.asyncio
async def test_php_include_trace_rejects_snapshot_with_deleted_scalar() -> None:
    case = await _valid_case()
    object.__delattr__(
        case.snapshot.verification.after,
        "attack_content_sha256",
    )

    accepted, reason, evidence = _validate(case)

    assert accepted is False
    assert reason == "PHP include attestation scalar shape is invalid"
    assert evidence == {}
