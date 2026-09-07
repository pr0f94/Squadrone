from __future__ import annotations

import hashlib
import json

import httpx
import pytest

from squadrone.poc_proxy import (
    PHP_INCLUDE_RECEIPT_HEADER,
    PocProxySupervisor,
    canonical_request_digest,
    classify_request_sentinels,
)


_TARGET_ORIGIN = "http://localhost:8123"
_TARGET_PATH = "/wp-admin/admin-ajax.php"
_RECEIPT = "SQUADRONE_PHP_INCLUDE_" + "a" * 64
_OTHER_RECEIPT = "SQUADRONE_PHP_INCLUDE_" + "b" * 64


class _InMemoryResponseProxy(PocProxySupervisor):
    def __init__(
        self,
        response_headers: list[tuple[str, str]],
        *,
        capture_php_include_receipt: bool,
        max_trace_capture_bytes: int | None = None,
    ) -> None:
        kwargs: dict[str, object] = {}
        if max_trace_capture_bytes is not None:
            kwargs["max_trace_capture_bytes"] = max_trace_capture_bytes
        super().__init__(
            _TARGET_ORIGIN,
            trace_token="parent-only-token",
            trace_salt=bytes.fromhex("31" * 32),
            capture_php_include_receipt=capture_php_include_receipt,
            **kwargs,
        )
        self._response_headers = response_headers

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
        del (
            method,
            url,
            headers,
            body,
            nonce,
            request_digest,
            record,
            credential_free_headers,
        )
        response_body = b"upstream response"
        return (
            httpx.Response(
                202,
                headers=self._response_headers,
                content=response_body,
            ),
            response_body,
        )


class _MemoryWriter:
    def __init__(self) -> None:
        self.chunks: list[bytes] = []

    def writelines(self, chunks: list[bytes]) -> None:
        self.chunks.extend(chunks)

    def write(self, chunk: bytes) -> None:
        self.chunks.append(chunk)

    async def drain(self) -> None:
        return None

    @property
    def value(self) -> bytes:
        return b"".join(self.chunks)


async def _execute(
    proxy: PocProxySupervisor,
) -> tuple[httpx.Response | None, bytes, int, str]:
    raw_target = _TARGET_PATH + "?action=include"
    headers = [("Host", "localhost:8123"), ("Accept", "*/*")]
    raw_headers = "\r\n".join(f"{name}: {value}" for name, value in headers)
    sentinel_flags, sentinel_categories = classify_request_sentinels(
        raw_target.encode("ascii"),
        raw_headers.encode("ascii"),
        b"",
    )
    return await proxy._execute_accepted_request(
        method="GET",
        url=_TARGET_ORIGIN + raw_target,
        path=_TARGET_PATH,
        raw_target=raw_target,
        headers=headers,
        body=b"",
        sentinel_flags=sentinel_flags,
        sentinel_categories=sentinel_categories,
    )


@pytest.mark.asyncio
async def test_opt_in_captures_receipt_on_its_bound_response() -> None:
    proxy = _InMemoryResponseProxy(
        [
            (PHP_INCLUDE_RECEIPT_HEADER, _RECEIPT),
            ("X-Untrusted-Response", "must-not-enter-trace"),
        ],
        capture_php_include_receipt=True,
    )

    response, response_body, status, detail = await _execute(proxy)
    record = proxy.trace_records[0]

    assert response is not None
    assert response_body == b"upstream response"
    assert (status, detail) == (0, "")
    assert record["forward_state"] == "completed"
    assert record["request_digest"] == canonical_request_digest(
        "GET",
        _TARGET_PATH + "?action=include",
        b"",
    )
    assert record["status_code"] == 202
    assert record["response_body_sha256"] == hashlib.sha256(response_body).hexdigest()
    assert record["response_php_include_receipt"] == _RECEIPT
    assert "must-not-enter-trace" not in json.dumps(record)


@pytest.mark.asyncio
async def test_enabled_capture_allows_control_response_without_receipt() -> None:
    proxy = _InMemoryResponseProxy([], capture_php_include_receipt=True)

    response, _body, status, detail = await _execute(proxy)

    assert response is not None
    assert (status, detail) == (0, "")
    assert proxy.trace_records[0]["response_php_include_receipt"] is None


@pytest.mark.asyncio
async def test_disabled_capture_preserves_trace_and_strips_receipt() -> None:
    proxy = _InMemoryResponseProxy(
        [(PHP_INCLUDE_RECEIPT_HEADER, _RECEIPT)],
        capture_php_include_receipt=False,
    )

    response, response_body, status, detail = await _execute(proxy)
    record = proxy.trace_records[0]
    writer = _MemoryWriter()
    assert response is not None
    await proxy._send_response(writer, response, response_body)

    assert (status, detail) == (0, "")
    assert "response_php_include_receipt" not in record
    assert _RECEIPT not in json.dumps(record)
    assert (
        PHP_INCLUDE_RECEIPT_HEADER.casefold().encode("ascii")
        not in writer.value.lower()
    )
    assert _RECEIPT.encode("ascii") not in writer.value


@pytest.mark.asyncio
async def test_enabled_capture_returns_only_valid_receipt_naturally_to_child() -> None:
    proxy = _InMemoryResponseProxy(
        [
            (PHP_INCLUDE_RECEIPT_HEADER, _RECEIPT),
            ("X-Squadrone-Other-Private", "must-be-stripped"),
        ],
        capture_php_include_receipt=True,
    )

    response, response_body, status, detail = await _execute(proxy)
    writer = _MemoryWriter()
    assert response is not None
    await proxy._send_response(writer, response, response_body)

    assert (status, detail) == (0, "")
    assert PHP_INCLUDE_RECEIPT_HEADER.casefold().encode("ascii") in writer.value.lower()
    assert _RECEIPT.encode("ascii") in writer.value
    assert b"x-squadrone-other-private" not in writer.value.lower()
    assert b"must-be-stripped" not in writer.value


@pytest.mark.parametrize(
    ("response_headers", "expected_error"),
    [
        (
            [
                (PHP_INCLUDE_RECEIPT_HEADER, _RECEIPT),
                (PHP_INCLUDE_RECEIPT_HEADER, _OTHER_RECEIPT),
            ],
            "duplicate_php_include_receipt",
        ),
        (
            [(PHP_INCLUDE_RECEIPT_HEADER, "SQUADRONE_PHP_INCLUDE_not-hex")],
            "malformed_php_include_receipt",
        ),
        (
            [(PHP_INCLUDE_RECEIPT_HEADER, _RECEIPT.upper())],
            "malformed_php_include_receipt",
        ),
    ],
)
@pytest.mark.asyncio
async def test_duplicate_or_malformed_receipt_is_a_value_free_terminal_failure(
    response_headers: list[tuple[str, str]],
    expected_error: str,
) -> None:
    proxy = _InMemoryResponseProxy(
        response_headers,
        capture_php_include_receipt=True,
    )

    response, response_body, status, detail = await _execute(proxy)
    record = proxy.trace_records[0]

    assert response is None
    assert response_body == b""
    assert (status, detail) == (502, "trusted response header is invalid")
    assert record["forward_state"] == "failed"
    assert record["forward_error"] == expected_error
    assert record["terminal"] is True
    assert record["response_php_include_receipt"] is None
    assert proxy.fatal_error == expected_error
    assert proxy.rejection_counts == {expected_error: 1}
    serialized = json.dumps(record)
    assert all(value not in serialized for _name, value in response_headers)


@pytest.mark.asyncio
async def test_receipt_capture_counts_toward_the_trace_limit() -> None:
    proxy = _InMemoryResponseProxy(
        [(PHP_INCLUDE_RECEIPT_HEADER, _RECEIPT)],
        capture_php_include_receipt=True,
        max_trace_capture_bytes=1,
    )

    response, response_body, status, detail = await _execute(proxy)
    record = proxy.trace_records[0]

    assert response is None
    assert response_body == b""
    assert (status, detail) == (503, "PoC trace capture limit exceeded")
    assert record["response_capture_omitted"] is True
    assert record["response_php_include_receipt"] is None
    assert _RECEIPT not in json.dumps(record)


def test_capture_capability_requires_an_explicit_boolean() -> None:
    with pytest.raises(
        ValueError,
        match="capture_php_include_receipt must be a boolean",
    ):
        PocProxySupervisor(
            _TARGET_ORIGIN,
            trace_token="token",
            capture_php_include_receipt=1,  # type: ignore[arg-type]
        )
