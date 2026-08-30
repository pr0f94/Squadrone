from __future__ import annotations

import base64
import copy
import dataclasses
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import pytest

from squadrone.poc_proxy import (
    PocProxySupervisor,
    canonical_request_digest,
    classify_request_sentinels,
    trace_fields_from_wire,
)
from squadrone.schemas import CIAImpact, PoCObservation
from squadrone.services.sandbox import validate_ssrf_response_marker_http_trace
from squadrone.services.ssrf_oracle import (
    LOCAL_RESOURCE_SSRF_FILE_MODE,
    LOCAL_RESOURCE_SSRF_MODE,
    LocalResourceSsrfOracle,
    LocalResourceSsrfSnapshot,
)


_TRACE_SALT = bytes.fromhex("31" * 32)
_TRACE_SECRET = bytes.fromhex("42" * 32)
_TRACE_TOKEN = "53" * 32
_TARGET_URL = "http://localhost:8123"
_DIRECT_ROUTE = "/wp-content/plugins/example-plugin/direct-proxy.php"
_CAPABILITY_LABEL = "local_resource_path"
_EXPECTED_TRANSPORT: dict[str, object] = {
    "method": "GET",
    "route": _DIRECT_ROUTE,
    "dispatch": {},
    "destination_parameter": "url",
    "destination_location": "query",
}
_CREDENTIAL_FREE_HEADERS = [
    ("Accept", "*/*"),
    ("User-Agent", "Squadrone-Trusted-PoC/1"),
]


class _InMemoryResponseProxy(PocProxySupervisor):
    """Use the production proxy recorder without making a network request."""

    def __init__(self, oracle: LocalResourceSsrfOracle) -> None:
        super().__init__(
            _TARGET_URL,
            trace_token=_TRACE_TOKEN,
            trace_salt=_TRACE_SALT,
            tracked_capabilities={
                _CAPABILITY_LABEL: oracle.resource_path.rsplit("/", 1)[-1]
            },
            credential_free=True,
        )
        self._oracle = oracle
        self.forwarded_header_sets: list[list[tuple[str, str]] | None] = []

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
        del method, headers, body, nonce, request_digest, record
        self.forwarded_header_sets.append(credential_free_headers)
        destination = parse_qs(urlsplit(url).query, strict_parsing=True)["url"][0]
        if destination == self._oracle.attack_url:
            status = 200
            response_body = self._oracle.private_marker.encode("ascii")
        else:
            assert destination == self._oracle.control_url
            status = 404
            response_body = b"not-found"
        return httpx.Response(status, content=response_body), response_body


@dataclass(slots=True)
class _LocalResourceCase:
    observation: PoCObservation
    records: list[dict[str, object]]
    snapshot: LocalResourceSsrfSnapshot
    attack_url: str
    control_url: str
    marker: str
    generation_id: str
    resource_path: str
    forwarded_header_sets: list[list[tuple[str, str]] | None]


def _request_parts(destination: str) -> tuple[str, str]:
    raw_target = f"{_DIRECT_ROUTE}?{urlencode({'url': destination})}"
    return _TARGET_URL + raw_target, raw_target


async def _record_request(
    proxy: PocProxySupervisor,
    destination: str,
    *,
    headers: list[tuple[str, str]] | None = None,
) -> None:
    url, raw_target = _request_parts(destination)
    child_headers = headers or [
        ("Host", "localhost:8123"),
        ("Accept", "text/plain"),
        ("User-Agent", "untrusted-child"),
    ]
    raw_headers = "\r\n".join(f"{name}: {value}" for name, value in child_headers)
    sentinel_flags, sentinel_categories = classify_request_sentinels(
        raw_target.encode("ascii"),
        raw_headers.encode("latin-1"),
        b"",
    )
    response, response_body, status, detail = await proxy._execute_accepted_request(
        method="GET",
        url=url,
        path=_DIRECT_ROUTE,
        raw_target=raw_target,
        headers=child_headers,
        body=b"",
        sentinel_flags=sentinel_flags,
        sentinel_categories=sentinel_categories,
    )
    assert response is not None, (status, detail)
    assert response_body == response.content


async def _valid_case() -> _LocalResourceCase:
    oracle = LocalResourceSsrfOracle()
    generation_id = oracle.begin_generation()
    marker = oracle.private_marker
    marker_sha256 = hashlib.sha256(marker.encode("ascii")).hexdigest()

    provisioning_started = time.monotonic_ns()
    provisioning_finished = time.monotonic_ns()
    oracle.attest_provisioning(
        generation_id=generation_id,
        resource_path=oracle.resource_path,
        content_sha256=marker_sha256,
        content_size_bytes=len(marker.encode("ascii")),
        owner_uid=0,
        owner_gid=0,
        file_mode=LOCAL_RESOURCE_SSRF_FILE_MODE,
        link_count=1,
        is_regular_file=True,
        is_symlink=False,
        started_monotonic_ns=provisioning_started,
        finished_monotonic_ns=provisioning_finished,
    )

    proxy = _InMemoryResponseProxy(oracle)
    before_monotonic_ns = time.monotonic_ns()
    execution_started_monotonic_ns = time.monotonic_ns()
    await _record_request(proxy, oracle.attack_url)
    await _record_request(proxy, oracle.control_url)
    execution_finished_monotonic_ns = time.monotonic_ns()
    after_monotonic_ns = time.monotonic_ns()
    snapshot = oracle.attest_verification(
        generation_id=generation_id,
        resource_path=oracle.resource_path,
        before_sha256=marker_sha256,
        before_monotonic_ns=before_monotonic_ns,
        execution_started_monotonic_ns=execution_started_monotonic_ns,
        execution_finished_monotonic_ns=execution_finished_monotonic_ns,
        after_sha256=marker_sha256,
        after_monotonic_ns=after_monotonic_ns,
    )

    fingerprint = {
        "method": "GET",
        "route": _DIRECT_ROUTE,
        "destination_parameter": "url",
        "destination_location": "query",
        "dispatch": {},
        "csrf_fields": [],
    }
    observation = PoCObservation(
        verdict="vulnerable",
        oracle="response_marker",
        attacker_role="unauthenticated",
        request={"method": "GET", "url": _TARGET_URL + _DIRECT_ROUTE},
        attack={
            "observed": True,
            "marker": marker,
            "marker_present": True,
            "destination_url": oracle.attack_url,
            "attacker_user_id": "anonymous",
            "identity_verified": True,
            "request_fingerprint": fingerprint,
        },
        control={
            "observed": False,
            "marker_present": False,
            "destination_url": oracle.control_url,
            "attacker_user_id": "anonymous",
            "identity_verified": True,
            "request_fingerprint": copy.deepcopy(fingerprint),
        },
        impact=CIAImpact(
            confidentiality="low",
            description="An unauthenticated request disclosed the local canary.",
        ),
    )
    return _LocalResourceCase(
        observation=observation,
        records=proxy.records,
        snapshot=snapshot,
        attack_url=oracle.attack_url,
        control_url=oracle.control_url,
        marker=marker,
        generation_id=generation_id,
        resource_path=oracle.resource_path,
        forwarded_header_sets=proxy.forwarded_header_sets,
    )


def _validate(
    case: _LocalResourceCase,
    *,
    records: list[dict[str, object]] | None = None,
    snapshot: object | None = None,
    control_url: str | None = None,
) -> tuple[bool, str, dict]:
    return validate_ssrf_response_marker_http_trace(
        case.observation,
        case.records if records is None else records,
        trace_salt=_TRACE_SALT,
        target_url=_TARGET_URL,
        receipt_secret=_TRACE_SECRET,
        trace_token=_TRACE_TOKEN,
        oracle_attack_url=case.attack_url,
        oracle_control_url=case.control_url if control_url is None else control_url,
        oracle_marker=case.marker,
        oracle_snapshot=case.snapshot if snapshot is None else snapshot,
        oracle_generation_id=case.generation_id,
        expected_http_transport=_EXPECTED_TRANSPORT,
        oracle_mode=LOCAL_RESOURCE_SSRF_MODE,
    )


def _replace_response(record: dict[str, object], body: bytes) -> None:
    record["response_body_b64"] = base64.b64encode(body).decode("ascii")
    record["response_body_tail_b64"] = ""
    record["response_body_truncated"] = False
    record["response_body_length"] = len(body)
    record["response_body_sha256"] = hashlib.sha256(body).hexdigest()


def _set_query_fields(
    case: _LocalResourceCase,
    record: dict[str, object],
    pairs: list[tuple[str, str]],
) -> None:
    raw_target = f"{_DIRECT_ROUTE}?{urlencode(pairs)}"
    fields, shape, parse_error = trace_fields_from_wire(
        _TARGET_URL + raw_target,
        "",
        b"",
        _TRACE_SALT,
        tracked_capabilities={_CAPABILITY_LABEL: case.resource_path.rsplit("/", 1)[-1]},
    )
    assert parse_error is None
    record["fields"] = fields
    record["parameter_shape"] = shape
    record["request_digest"] = canonical_request_digest("GET", raw_target, b"")


def _signed_receipt(record: dict[str, object]) -> str:
    payload = {
        "v": 2,
        "trace_token": _TRACE_TOKEN,
        "nonce": "64" * 16,
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


def _unrelated_record(
    case: _LocalResourceCase,
    *,
    sequence: int,
    path: str,
    query_pairs: list[tuple[str, str]],
) -> dict[str, object]:
    record = copy.deepcopy(case.records[0])
    record["sequence"] = sequence
    record["request_nonce"] = f"{sequence + 100:064x}"
    record["path"] = path
    raw_target = path
    if query_pairs:
        raw_target += "?" + urlencode(query_pairs)
    fields, shape, parse_error = trace_fields_from_wire(
        _TARGET_URL + raw_target,
        "",
        b"",
        _TRACE_SALT,
        tracked_capabilities={_CAPABILITY_LABEL: case.resource_path.rsplit("/", 1)[-1]},
    )
    assert parse_error is None
    record["fields"] = fields
    record["parameter_shape"] = shape
    record["request_digest"] = canonical_request_digest("GET", raw_target, b"")
    record["request_tracked_capabilities_in_headers"] = []
    record["response_actor_receipt"] = None
    record["response_actor_receipt_truncated"] = False
    _replace_response(record, b"ordinary pre-proof response")
    return record


@pytest.mark.asyncio
async def test_local_resource_direct_trace_and_snapshot_are_fully_bound() -> None:
    case = await _valid_case()

    accepted, reason, evidence = _validate(case)

    assert accepted is True, reason
    assert case.forwarded_header_sets == [
        _CREDENTIAL_FREE_HEADERS,
        _CREDENTIAL_FREE_HEADERS,
    ]
    assert all(record["credential_free_transport"] is True for record in case.records)
    assert all(record["response_actor_receipt"] is None for record in case.records)
    assert [
        field["tracked_capabilities"]
        for record in case.records
        for field in record["fields"]
    ] == [[_CAPABILITY_LABEL], [_CAPABILITY_LABEL]]
    assert evidence["attack_request"]["actor_provenance"] == (
        "credential_free_transport"
    )
    assert evidence["control_request"]["actor_provenance"] == (
        "credential_free_transport"
    )
    assert evidence["local_resource_attestation"]["mode"] == (LOCAL_RESOURCE_SSRF_MODE)
    serialized = json.dumps(evidence, sort_keys=True)
    assert case.marker not in serialized
    assert case.resource_path not in serialized
    assert case.attack_url not in serialized
    assert case.generation_id not in serialized


@pytest.mark.asyncio
async def test_local_resource_rejects_marker_self_report_without_capture() -> None:
    case = await _valid_case()
    records = copy.deepcopy(case.records)
    _replace_response(records[0], b"ordinary response")

    accepted, reason, evidence = _validate(case, records=records)

    assert accepted is False
    assert "exactly one private marker" in reason
    assert evidence == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("location", ["extra_field", "header", "preproof"])
async def test_local_resource_rejects_path_capability_outside_destination(
    location: str,
) -> None:
    case = await _valid_case()
    records = copy.deepcopy(case.records)
    if location == "extra_field":
        _set_query_fields(
            case,
            records[0],
            [("url", case.attack_url), ("leak", case.resource_path)],
        )
        _set_query_fields(
            case,
            records[1],
            [("url", case.control_url), ("leak", case.resource_path)],
        )
    elif location == "header":
        records[0]["request_tracked_capabilities_in_headers"] = [_CAPABILITY_LABEL]
    else:
        preproof = _unrelated_record(
            case,
            sequence=1,
            path="/preproof.php",
            query_pairs=[("leak", case.resource_path)],
        )
        records[0]["sequence"] = 2
        records[1]["sequence"] = 3
        records = [preproof, *records]

    accepted, reason, evidence = _validate(case, records=records)

    assert accepted is False
    assert "path capability appears outside" in reason
    assert evidence == {}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("credential_free_transport", False),
        ("credential_free_transport", "true"),
        ("credential_free_transport", 1),
        ("response_actor_receipt_truncated", True),
    ],
)
async def test_local_resource_rejects_false_or_malformed_credential_free_proof(
    field: str,
    value: object,
) -> None:
    case = await _valid_case()
    records = copy.deepcopy(case.records)
    records[0][field] = value

    accepted, reason, evidence = _validate(case, records=records)

    assert accepted is False
    assert "no signed SSRF attack request" in reason
    assert evidence == {}


@pytest.mark.asyncio
async def test_local_resource_rejects_malformed_receipt_instead_of_fallback() -> None:
    case = await _valid_case()
    records = copy.deepcopy(case.records)
    records[0]["response_actor_receipt"] = "forged"

    accepted, reason, evidence = _validate(case, records=records)

    assert accepted is False
    assert "no signed SSRF attack request" in reason
    assert evidence == {}


@pytest.mark.asyncio
async def test_local_resource_rejects_mixed_signed_and_credential_free_actors() -> None:
    case = await _valid_case()
    records = copy.deepcopy(case.records)
    records[1]["response_actor_receipt"] = _signed_receipt(records[1])

    accepted, reason, evidence = _validate(case, records=records)

    assert accepted is False
    assert "actor provenance differs" in reason
    assert evidence == {}


@pytest.mark.asyncio
async def test_local_resource_rejects_extra_traffic_in_proof_window() -> None:
    case = await _valid_case()
    records = copy.deepcopy(case.records)
    extra = _unrelated_record(
        case,
        sequence=2,
        path="/unrelated.php",
        query_pairs=[("ordinary", "value")],
    )
    records[1]["sequence"] = 3
    records = [records[0], extra, records[1]]

    accepted, reason, evidence = _validate(case, records=records)

    assert accepted is False
    assert "extra traffic inside the proof window" in reason
    assert evidence == {}


@pytest.mark.asyncio
async def test_local_resource_rejects_undeclared_credential_free_fields() -> None:
    case = await _valid_case()
    records = copy.deepcopy(case.records)
    _set_query_fields(
        case,
        records[0],
        [("url", case.attack_url), ("stable", "same")],
    )
    _set_query_fields(
        case,
        records[1],
        [("url", case.control_url), ("stable", "same")],
    )

    accepted, reason, evidence = _validate(case, records=records)

    assert accepted is False
    assert "credential-free SSRF request contains undeclared fields" in reason
    assert evidence == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["scheme", "path"])
async def test_local_resource_rejects_changed_control_scheme_or_path(
    mutation: str,
) -> None:
    case = await _valid_case()
    parsed = urlsplit(case.control_url)
    if mutation == "scheme":
        changed_control = f"http://localhost{parsed.path}"
    else:
        changed_control = f"https://localhost{parsed.path}-changed"

    accepted, reason, evidence = _validate(case, control_url=changed_control)

    assert accepted is False
    assert "parent oracle contract is invalid" in reason
    assert evidence == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["type", "content_hash", "causal_start"])
async def test_local_resource_rejects_bad_snapshot(
    mutation: str,
) -> None:
    case = await _valid_case()
    if mutation == "type":
        snapshot: object = {"mode": LOCAL_RESOURCE_SSRF_MODE}
        expected = "invalid type"
    elif mutation == "content_hash":
        snapshot = dataclasses.replace(
            case.snapshot,
            provisioning=dataclasses.replace(
                case.snapshot.provisioning,
                content_sha256="0" * 64,
            ),
        )
        expected = "invalid or non-causal"
    else:
        attack_started = int(case.records[0]["upstream_started_monotonic_ns"])
        snapshot = dataclasses.replace(
            case.snapshot,
            verification=dataclasses.replace(
                case.snapshot.verification,
                execution_started_monotonic_ns=attack_started + 1,
            ),
        )
        expected = "invalid or non-causal"

    accepted, reason, evidence = _validate(case, snapshot=snapshot)

    assert accepted is False
    assert expected in reason
    assert evidence == {}


@pytest.mark.asyncio
async def test_local_resource_rejects_overlapping_parent_causal_intervals() -> None:
    case = await _valid_case()
    records = copy.deepcopy(case.records)
    control_started = int(records[1]["upstream_started_monotonic_ns"])
    records[0]["upstream_finished_monotonic_ns"] = control_started + 1

    accepted, reason, evidence = _validate(case, records=records)

    assert accepted is False
    assert "invalid or non-causal" in reason
    assert evidence == {}


@pytest.mark.parametrize("value", [None, 0, 1, "true", object()])
def test_proxy_rejects_non_boolean_credential_free_configuration(value: Any) -> None:
    with pytest.raises(ValueError, match="credential_free must be a boolean"):
        PocProxySupervisor(
            _TARGET_URL,
            trace_token=_TRACE_TOKEN,
            trace_salt=_TRACE_SALT,
            credential_free=value,
        )
