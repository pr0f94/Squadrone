from __future__ import annotations

import base64
import json
from collections.abc import Awaitable, Callable
from typing import Literal
from urllib.parse import urlencode

import httpx
import pytest

from squadrone.poc_proxy import ExecutableUploadPolicy, PocProxySupervisor


TARGET = "http://127.0.0.1:48080"
TRACE_SALT = bytes.fromhex("71" * 32)
TRACE_TOKEN = "parent-only-executable-upload-trace-token"
REQUEST_BINDING_SECRET = bytes.fromhex("82" * 32)
REST_ROUTE = "/mwai/v1/simpleFileUpload"
ATTACK_FILENAME = "squadrone-parent-wire.php"
CONTROL_FILENAME = "squadrone-parent-wire.txt"
PAYLOAD = (
    b"<?php echo hash('sha256', 'parent-executable-upload-wire-test'); ?>"
)

Arm = Literal["attack", "control"]
Phase = Literal["before", "after"]
Encoding = Literal["form", "json"]
Attestor = Callable[[Phase, Arm], Awaitable[object]]


class _Attestor:
    def __init__(self, fail_at: tuple[Phase, Arm] | None = None) -> None:
        self.fail_at = fail_at
        self.calls: list[tuple[Phase, Arm]] = []

    async def __call__(self, phase: Phase, arm: Arm) -> None:
        self.calls.append((phase, arm))
        if (phase, arm) == self.fail_at:
            raise RuntimeError("private attestation failure")


class _WireProxy(PocProxySupervisor):
    """Use the real listener/parser while keeping the upstream deterministic."""

    def __init__(
        self,
        *,
        policy: ExecutableUploadPolicy,
        attestor: Attestor,
        fail_upstream: bool = False,
    ) -> None:
        super().__init__(
            TARGET,
            trace_token=TRACE_TOKEN,
            trace_salt=TRACE_SALT,
            executable_upload_policy=policy,
            executable_upload_arm_attestor=attestor,
            request_binding_secret=REQUEST_BINDING_SECRET,
        )
        self.fail_upstream = fail_upstream
        self.forward_attempts: list[dict[str, object]] = []

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
        del headers, nonce, request_digest, credential_free_headers
        self.forward_attempts.append(
            {"method": method, "url": url, "body": body}
        )
        request = httpx.Request(method, url)
        if self.fail_upstream:
            raise httpx.ConnectError("synthetic upstream reset", request=request)
        response_body = json.dumps(
            {"success": True, "data": {"url": TARGET + "/uploads/result"}},
            separators=(",", ":"),
        ).encode("ascii")
        record["status_code"] = 200
        response = httpx.Response(
            200,
            content=response_body,
            headers={"Content-Type": "application/json"},
            request=request,
        )
        return response, response_body


def _policy(encoding: Encoding = "form") -> ExecutableUploadPolicy:
    return ExecutableUploadPolicy(
        method="POST",
        route_kind="wordpress_rest",
        route=REST_ROUTE,
        dispatch=(
            (encoding, "purpose", "files"),
            (encoding, "target", "uploads"),
        ),
        payload=PAYLOAD,
        attack_filename=ATTACK_FILENAME,
        control_filename=CONTROL_FILENAME,
    )


def _fields(filename: str) -> list[tuple[str, str]]:
    return [
        ("base64", base64.b64encode(PAYLOAD).decode("ascii")),
        ("filename", filename),
        ("purpose", "files"),
        ("target", "uploads"),
    ]


def _encoded_body(
    fields: list[tuple[str, str]],
    encoding: Encoding,
) -> tuple[bytes, str]:
    if encoding == "form":
        return urlencode(fields).encode("ascii"), "application/x-www-form-urlencoded"
    document = {name: value for name, value in fields}
    return (
        json.dumps(document, separators=(",", ":")).encode("ascii"),
        "application/json",
    )


async def _send(
    proxy: PocProxySupervisor,
    *,
    filename: str,
    encoding: Encoding = "form",
    method: str = "POST",
    path_and_query: str | None = None,
    fields: list[tuple[str, str]] | None = None,
) -> httpx.Response:
    body, content_type = _encoded_body(fields or _fields(filename), encoding)
    target = TARGET + (
        path_and_query
        if path_and_query is not None
        else f"/?rest_route={REST_ROUTE}"
    )
    async with httpx.AsyncClient(
        proxy=proxy.proxy_url,
        trust_env=False,
        follow_redirects=False,
    ) as client:
        return await client.request(
            method,
            target,
            content=body,
            headers={"Content-Type": content_type},
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("encoding", "path_and_query"),
    [
        ("form", f"/?rest_route={REST_ROUTE}"),
        ("json", f"/wp-json{REST_ROUTE}"),
    ],
)
async def test_ai_engine_like_base64_upload_arms_complete_over_wire(
    encoding: Encoding,
    path_and_query: str,
) -> None:
    attestor = _Attestor()
    proxy = _WireProxy(policy=_policy(encoding), attestor=attestor)

    async with proxy:
        attack = await _send(
            proxy,
            filename=ATTACK_FILENAME,
            encoding=encoding,
            path_and_query=path_and_query,
        )
        control = await _send(
            proxy,
            filename=CONTROL_FILENAME,
            encoding=encoding,
            path_and_query=path_and_query,
        )
        records = proxy.records

    assert attack.status_code == control.status_code == 200
    assert proxy.executable_upload_complete is True
    assert proxy.fatal_error is None
    assert attestor.calls == [
        ("before", "attack"),
        ("after", "attack"),
        ("before", "control"),
        ("after", "control"),
    ]
    assert [record["executable_upload_arm"] for record in records] == [
        "attack",
        "control",
    ]
    assert all(record["forward_state"] == "completed" for record in records)
    assert all(record["executable_upload_before_attested"] is True for record in records)
    assert all(record["executable_upload_after_attested"] is True for record in records)
    assert len(proxy.forward_attempts) == 2


@pytest.mark.asyncio
async def test_control_first_fails_before_upstream() -> None:
    attestor = _Attestor()
    proxy = _WireProxy(policy=_policy(), attestor=attestor)

    async with proxy:
        response = await _send(proxy, filename=CONTROL_FILENAME)
        records = proxy.records

    assert response.status_code == 403
    assert proxy.executable_upload_complete is False
    assert proxy.fatal_error == "executable_upload_arm_replayed_or_out_of_order"
    assert proxy.forward_attempts == []
    assert attestor.calls == []
    assert records[0]["forward_state"] == "failed"


@pytest.mark.asyncio
@pytest.mark.parametrize("replay", ["attack", "third"])
async def test_replay_or_third_upload_request_fails_closed(replay: str) -> None:
    attestor = _Attestor()
    proxy = _WireProxy(policy=_policy(), attestor=attestor)

    async with proxy:
        first = await _send(proxy, filename=ATTACK_FILENAME)
        if replay == "attack":
            rejected = await _send(proxy, filename=ATTACK_FILENAME)
        else:
            second = await _send(proxy, filename=CONTROL_FILENAME)
            assert second.status_code == 200
            rejected = await _send(proxy, filename=CONTROL_FILENAME)

    assert first.status_code == 200
    assert rejected.status_code == 403
    assert proxy.executable_upload_complete is False
    assert proxy.fatal_error == "executable_upload_arm_replayed_or_out_of_order"
    assert len(proxy.forward_attempts) == (1 if replay == "attack" else 2)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("case", "method", "path_and_query", "fields"),
    [
        ("wrong route", "POST", "/wp-json/mwai/v1/other", None),
        ("wrong method", "PUT", f"/?rest_route={REST_ROUTE}", None),
        ("extra query", "POST", f"/?rest_route={REST_ROUTE}&debug=1", None),
        (
            "dispatch collision",
            "POST",
            f"/?rest_route={REST_ROUTE}&purpose=files",
            None,
        ),
        (
            "wrong dispatch",
            "POST",
            f"/?rest_route={REST_ROUTE}",
            [
                ("base64", base64.b64encode(PAYLOAD).decode("ascii")),
                ("filename", ATTACK_FILENAME),
                ("purpose", "images"),
                ("target", "uploads"),
            ],
        ),
    ],
)
async def test_transport_mismatches_fail_before_upstream(
    case: str,
    method: str,
    path_and_query: str,
    fields: list[tuple[str, str]] | None,
) -> None:
    del case
    attestor = _Attestor()
    proxy = _WireProxy(policy=_policy(), attestor=attestor)

    async with proxy:
        response = await _send(
            proxy,
            filename=ATTACK_FILENAME,
            method=method,
            path_and_query=path_and_query,
            fields=fields,
        )

    assert response.status_code == 403
    assert proxy.fatal_error == "executable_upload_transport_mismatch"
    assert proxy.forward_attempts == []
    assert attestor.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("case", "fields", "expected_error"),
    [
        (
            "duplicate payload",
            [
                *_fields(ATTACK_FILENAME),
                ("base64", base64.b64encode(PAYLOAD).decode("ascii")),
            ],
            "executable_upload_payload_not_unique",
        ),
        (
            "duplicate filename",
            [*_fields(ATTACK_FILENAME), ("filename", ATTACK_FILENAME)],
            "executable_upload_filename_not_unique",
        ),
    ],
)
async def test_duplicate_payload_or_filename_fails_before_upstream(
    case: str,
    fields: list[tuple[str, str]],
    expected_error: str,
) -> None:
    del case
    attestor = _Attestor()
    proxy = _WireProxy(policy=_policy(), attestor=attestor)

    async with proxy:
        response = await _send(
            proxy,
            filename=ATTACK_FILENAME,
            fields=fields,
        )

    assert response.status_code == 403
    assert proxy.fatal_error == expected_error
    assert proxy.forward_attempts == []
    assert attestor.calls == []


@pytest.mark.asyncio
async def test_non_control_request_after_attack_fails_before_upstream() -> None:
    attestor = _Attestor()
    proxy = _WireProxy(policy=_policy(), attestor=attestor)

    async with proxy:
        attack = await _send(proxy, filename=ATTACK_FILENAME)
        unrelated = await _send(
            proxy,
            filename="unused.txt",
            fields=[("ping", "1")],
        )

    assert attack.status_code == 200
    assert unrelated.status_code == 403
    assert proxy.fatal_error == "executable_upload_unbound_or_out_of_order_request"
    assert len(proxy.forward_attempts) == 1
    assert attestor.calls == [("before", "attack"), ("after", "attack")]


@pytest.mark.asyncio
async def test_upstream_failure_latches_trace_after_before_attestation() -> None:
    attestor = _Attestor()
    proxy = _WireProxy(
        policy=_policy(),
        attestor=attestor,
        fail_upstream=True,
    )

    async with proxy:
        response = await _send(proxy, filename=ATTACK_FILENAME)
        records = proxy.records

    assert response.status_code == 502
    assert proxy.executable_upload_complete is False
    assert proxy.fatal_error == "upstream_reset"
    assert len(proxy.forward_attempts) == 1
    assert attestor.calls == [("before", "attack")]
    assert records[0]["executable_upload_before_attested"] is True
    assert "executable_upload_after_attested" not in records[0]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure", "expected_forward_attempts"),
    [
        (("before", "attack"), 0),
        (("after", "attack"), 1),
    ],
)
async def test_attestor_failure_latches_trace_at_exact_boundary(
    failure: tuple[Phase, Arm],
    expected_forward_attempts: int,
) -> None:
    attestor = _Attestor(fail_at=failure)
    proxy = _WireProxy(policy=_policy(), attestor=attestor)

    async with proxy:
        response = await _send(proxy, filename=ATTACK_FILENAME)
        records = proxy.records

    assert response.status_code == 502
    assert proxy.executable_upload_complete is False
    assert proxy.fatal_error == "executable_upload_attestation_failed"
    assert len(proxy.forward_attempts) == expected_forward_attempts
    assert attestor.calls[-1] == failure
    assert records[0]["forward_state"] == "failed"
    assert ("executable_upload_before_attested" in records[0]) is (
        failure[0] == "after"
    )
    assert "executable_upload_after_attested" not in records[0]
