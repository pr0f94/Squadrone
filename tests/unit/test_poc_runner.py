from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import socket
import sys
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator
from urllib.parse import urlsplit

import httpx
import pytest
import requests
import squadrone.poc_proxy as poc_proxy

from squadrone.poc_proxy import (
    ACTOR_RECEIPT_HEADER,
    MAX_REQUEST_BODY_BYTES,
    POC_PROXY_ENV,
    PRIVATE_TRACE_ENV_NAMES,
    REQUEST_DIGEST_HEADER,
    REQUEST_NONCE_HEADER,
    RESPONSE_BODY_CAPTURE_LIMIT,
    TRACE_FD_ENV,
    TRACE_ORIGIN_ENV,
    TRACE_SALT_ENV,
    TRACE_TOKEN_ENV,
    TRACE_TOKEN_HEADER,
    PocProxySupervisor,
    canonical_request_digest,
    classify_request_sentinels,
    minimal_poc_environment,
    normalize_trace_scalar,
    request_trace_fields,
    salted_headers_sha256,
    salted_scalar_sha256,
)


class _Upstream(ThreadingHTTPServer):
    observed: list[dict[str, object]]
    response_body: bytes
    status_code: int
    redirect_to: str | None
    set_cookie_once: bool
    content_encoding: str | None
    delay_by_path: dict[str, float]
    reset_paths: set[str]
    active_requests: int
    max_active_requests: int

    def __init__(self, server_address, handler_class):
        super().__init__(server_address, handler_class)
        self.observed = []
        self.response_body = b"owner-visible VICTIM-MARKER-101"
        self.status_code = 200
        self.redirect_to = None
        self.set_cookie_once = False
        self.content_encoding = None
        self.delay_by_path = {}
        self.reset_paths = set()
        self.active_requests = 0
        self.max_active_requests = 0
        self.observation_lock = threading.Lock()


class _UpstreamHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _respond(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        headers = {name.casefold(): value for name, value in self.headers.items()}
        with self.server.observation_lock:  # type: ignore[attr-defined]
            self.server.active_requests += 1  # type: ignore[attr-defined]
            self.server.max_active_requests = max(  # type: ignore[attr-defined]
                self.server.max_active_requests,  # type: ignore[attr-defined]
                self.server.active_requests,  # type: ignore[attr-defined]
            )
            observation_index = len(self.server.observed)  # type: ignore[attr-defined]
            self.server.observed.append(  # type: ignore[attr-defined]
                {
                    "method": self.command,
                    "path": self.path,
                    "headers": headers,
                    "body": body,
                }
            )
        try:
            delay = self.server.delay_by_path.get(self.path, 0)  # type: ignore[attr-defined]
            if delay:
                time.sleep(delay)
            if self.path in self.server.reset_paths:  # type: ignore[attr-defined]
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return

            redirect_to = self.server.redirect_to  # type: ignore[attr-defined]
            if redirect_to:
                self.send_response(302)
                self.send_header("Location", redirect_to)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

            response_body = self.server.response_body  # type: ignore[attr-defined]
            status_code = self.server.status_code  # type: ignore[attr-defined]
            nonce = headers.get(REQUEST_NONCE_HEADER.casefold(), "missing")
            digest = headers.get(REQUEST_DIGEST_HEADER.casefold(), "missing")
            self.send_response(status_code)
            self.send_header(ACTOR_RECEIPT_HEADER, f"signed:{nonce}:{digest}")
            self.send_header("X-Squadrone-Upstream-Private", "must-be-stripped")
            self.send_header("Content-Type", "application/octet-stream")
            if self.server.content_encoding:  # type: ignore[attr-defined]
                self.send_header(  # type: ignore[attr-defined]
                    "Content-Encoding",
                    self.server.content_encoding,  # type: ignore[attr-defined]
                )
            if self.server.set_cookie_once and observation_index == 0:  # type: ignore[attr-defined]
                self.send_header("Set-Cookie", "proxy_secret=must-not-leak; Path=/")
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            try:
                self.wfile.write(response_body)
            except (BrokenPipeError, ConnectionResetError):
                pass
        finally:
            with self.server.observation_lock:  # type: ignore[attr-defined]
                self.server.active_requests -= 1  # type: ignore[attr-defined]

    do_DELETE = _respond
    do_GET = _respond
    do_PATCH = _respond
    do_POST = _respond
    do_PUT = _respond

    def log_message(self, _format: str, *_args: object) -> None:
        return


@contextmanager
def _upstream() -> Iterator[tuple[_Upstream, str]]:
    server = _Upstream(("127.0.0.1", 0), _UpstreamHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield server, f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


async def _proxied_request(
    proxy_url: str,
    method: str,
    url: str,
    **kwargs: object,
) -> httpx.Response:
    async with httpx.AsyncClient(
        proxy=proxy_url,
        trust_env=False,
        follow_redirects=False,
    ) as client:
        return await client.request(method, url, **kwargs)


async def _raw_proxy_request(proxy_url: str, payload: bytes) -> bytes:
    parsed = urlsplit(proxy_url)
    reader, writer = await asyncio.open_connection(parsed.hostname, parsed.port)
    writer.write(payload)
    await writer.drain()
    response = await reader.read()
    writer.close()
    await writer.wait_closed()
    return response


def _field(record: dict[str, object], location: str, name: str) -> dict[str, object]:
    fields = record["fields"]
    assert isinstance(fields, list)
    matches = [
        item for item in fields if item["location"] == location and item["name"] == name
    ]
    assert len(matches) == 1
    return matches[0]


def test_scalar_and_request_digest_protocols_are_stable() -> None:
    salt = bytes.fromhex("11" * 32)

    assert normalize_trace_scalar(None) == "null"
    assert normalize_trace_scalar(True) == "true"
    assert normalize_trace_scalar(False) == "false"
    assert normalize_trace_scalar(101) == "101"
    assert normalize_trace_scalar(1.5) == "1.5"
    assert normalize_trace_scalar(b"caf\xc3\xa9") == "café"
    assert (
        salted_scalar_sha256("101", salt)
        == hashlib.sha256(salt + b"\0" + b"101").hexdigest()
    )


def test_header_digest_binds_sensitive_forwarded_values_but_not_proxy_headers() -> None:
    salt = bytes.fromhex("12" * 32)
    headers = [
        ("Host", "localhost:8100"),
        ("Cookie", "wordpress=private-cookie"),
        ("Authorization", "Bearer private-auth"),
        ("X-WP-Nonce", "private-nonce"),
        ("Accept-Encoding", "gzip"),
        (TRACE_TOKEN_HEADER, "child-spoof"),
        ("Connection", "close, X-Hop"),
        ("X-Hop", "ignored"),
    ]
    expected = salted_headers_sha256(headers, salt)

    equivalent = [
        ("x-wp-nonce", "private-nonce"),
        ("AUTHORIZATION", "Bearer private-auth"),
        ("cookie", "wordpress=private-cookie"),
        ("Host", "127.0.0.1:8100"),
        ("Accept-Encoding", "identity"),
        (TRACE_TOKEN_HEADER, "different-spoof"),
    ]
    assert salted_headers_sha256(equivalent, salt) == expected

    for name in ("Cookie", "Authorization", "X-WP-Nonce"):
        changed = [
            (header_name, "changed" if header_name == name else value)
            for header_name, value in headers
        ]
        assert salted_headers_sha256(changed, salt) != expected


def test_sentinel_classifier_detects_safe_reversible_encodings() -> None:
    flags, categories = classify_request_sentinels(
        b"/probe?value=SQUADRONE&#95;HTML",
        b"X-Probe: \\u0053\\u0051\\u0055\\u0041\\u0044"
        b"\\u0052\\u004f\\u004e\\u0045\\u005fESCAPED",
        b"5351554144524f4e455f484558",
    )

    assert flags == {
        "target": False,
        "target_encoded": True,
        "body": False,
        "body_encoded": True,
        "headers": False,
        "headers_encoded": True,
    }
    assert categories == ["body_encoded", "headers_encoded", "target_encoded"]

    canonical = b"SQUADRONE-REQUEST-V1\0POST\0/items?mode=edit\0object_id=101"
    assert (
        canonical_request_digest("post", "/items?mode=edit", b"object_id=101")
        == hashlib.sha256(canonical).hexdigest()
    )


def test_field_parser_hashes_values_and_marks_only_scalar_sentinels() -> None:
    salt = bytes.fromhex("22" * 32)
    prepared = requests.Request(
        "POST",
        "http://localhost:8100/items?context=edit",
        files={
            "upload": ("SQUADRONE_PRIVATE.txt", b"SQUADRONE_FILE_CONTENT"),
        },
        data={"marker": "SQUADRONE_ATTACK_123", "password": "raw-password"},
    ).prepare()

    fields, shape, error = request_trace_fields(prepared, salt)
    serialized = json.dumps({"fields": fields, "shape": shape})

    assert error is None
    assert (
        next(item for item in fields if item["name"] == "marker")[
            "contains_squadrone_sentinel"
        ]
        is True
    )
    assert (
        next(item for item in fields if item["name"] == "password")[
            "contains_squadrone_sentinel"
        ]
        is False
    )
    assert (
        next(item for item in fields if item["name"] == "upload")[
            "contains_squadrone_sentinel"
        ]
        is False
    )
    assert "raw-password" not in serialized
    assert "SQUADRONE_ATTACK_123" not in serialized
    assert "SQUADRONE_PRIVATE.txt" not in serialized
    assert "SQUADRONE_FILE_CONTENT" not in serialized


@pytest.mark.asyncio
async def test_proxy_classifies_raw_and_encoded_sentinels_without_values() -> None:
    encoded_header = base64.b64encode(b"user:SQUADRONE_HEADER_SECRET").decode()
    with _upstream() as (_upstream_server, origin):
        async with PocProxySupervisor(origin, trace_token="token") as proxy:
            encoded_response = await _proxied_request(
                proxy.proxy_url,
                "POST",
                origin + "/encoded?probe=SQUADRONE%5FTARGET_SECRET",
                content=b"marker=SQUADRONE%5FBODY_SECRET",
                headers={
                    "Authorization": "Basic " + encoded_header,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
            raw_response = await _proxied_request(
                proxy.proxy_url,
                "POST",
                origin + "/raw?probe=SQUADRONE_TARGET_SECRET",
                content=b"marker=SQUADRONE_BODY_SECRET",
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-Probe": "SQUADRONE_HEADER_SECRET",
                },
            )
            records = proxy.records

    assert encoded_response.status_code == raw_response.status_code == 200
    encoded_flags = records[0]["request_sentinel_flags"]
    assert encoded_flags == {
        "target": False,
        "target_encoded": True,
        "body": False,
        "body_encoded": True,
        "headers": False,
        "headers_encoded": True,
    }
    assert records[0]["request_sentinel_categories"] == [
        "body_encoded",
        "headers_encoded",
        "target_encoded",
    ]
    assert records[1]["request_sentinel_flags"] == {
        "target": True,
        "target_encoded": False,
        "body": True,
        "body_encoded": False,
        "headers": True,
        "headers_encoded": False,
    }
    assert _field(records[0], "query", "probe")["contains_squadrone_sentinel"] is True
    assert _field(records[0], "form", "marker")["contains_squadrone_sentinel"] is True
    serialized = json.dumps(records)
    for raw_value in (
        "SQUADRONE_TARGET_SECRET",
        "SQUADRONE_BODY_SECRET",
        "SQUADRONE_HEADER_SECRET",
        encoded_header,
    ):
        assert raw_value not in serialized


@pytest.mark.asyncio
async def test_proxy_records_wire_request_and_injects_fresh_bindings() -> None:
    salt = bytes.fromhex("33" * 32)
    token = "parent-only-trace-token"
    body = b"action=save&object_id=101&marker=SQUADRONE_ATTACK_101"
    with _upstream() as (upstream, origin):
        async with PocProxySupervisor(
            origin,
            trace_token=token,
            trace_salt=salt,
        ) as proxy:
            for _ in range(2):
                response = await _proxied_request(
                    proxy.proxy_url,
                    "POST",
                    origin + "/objects?route=calendar",
                    content=body,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Cookie": "session=raw-cookie",
                        "Authorization": "Bearer raw-auth",
                        TRACE_TOKEN_HEADER: "child-spoofed-token",
                        REQUEST_NONCE_HEADER: "child-spoofed-nonce",
                        REQUEST_DIGEST_HEADER: "child-spoofed-digest",
                    },
                )
                assert response.status_code == 200
                assert ACTOR_RECEIPT_HEADER not in response.headers
                assert not any(
                    name.casefold().startswith("x-squadrone-")
                    for name in response.headers
                )
            records = proxy.records

    assert len(records) == 2
    assert [record["sequence"] for record in records] == [1, 2]
    intervals = [
        (
            record["upstream_started_monotonic_ns"],
            record["upstream_finished_monotonic_ns"],
        )
        for record in records
    ]
    assert all(
        isinstance(started, int)
        and isinstance(finished, int)
        and 0 < started <= finished
        for started, finished in intervals
    )
    assert intervals[0][1] <= intervals[1][0]
    nonces = [str(record["request_nonce"]) for record in records]
    assert len(set(nonces)) == 2
    assert all(re.fullmatch(r"[0-9a-f]{64}", nonce) for nonce in nonces)
    expected_digest = canonical_request_digest(
        "POST",
        "/objects?route=calendar",
        body,
    )
    assert [record["request_digest"] for record in records] == [
        expected_digest,
        expected_digest,
    ]
    header_digests = [record["request_headers_sha256"] for record in records]
    assert header_digests[0] == header_digests[1]
    assert all(
        isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)
        for digest in header_digests
    )

    for index, observed in enumerate(upstream.observed):
        headers = observed["headers"]
        assert isinstance(headers, dict)
        assert headers[TRACE_TOKEN_HEADER.casefold()] == token
        assert headers[REQUEST_NONCE_HEADER.casefold()] == nonces[index]
        assert headers[REQUEST_DIGEST_HEADER.casefold()] == expected_digest
        assert headers["accept-encoding"] == "identity"
        assert records[index]["response_actor_receipt"] == (
            f"signed:{nonces[index]}:{expected_digest}"
        )

    record = records[0]
    assert record["method"] == "POST"
    assert record["path"] == "/objects"
    assert _field(record, "query", "route")["value_sha256"] == (
        salted_scalar_sha256("calendar", salt)
    )
    assert _field(record, "form", "object_id")["value_sha256"] == (
        salted_scalar_sha256("101", salt)
    )
    assert _field(record, "form", "marker")["contains_squadrone_sentinel"] is True
    serialized = json.dumps(records)
    for forbidden in (
        "raw-cookie",
        "raw-auth",
        token,
        "child-spoofed",
        "save",
        "SQUADRONE_ATTACK_101",
    ):
        assert forbidden not in serialized


@pytest.mark.asyncio
async def test_credential_free_proxy_keeps_parent_binding_headers_off_upstream() -> (
    None
):
    token = "parent-only-trace-token"
    with _upstream() as (upstream, origin):
        async with PocProxySupervisor(
            origin,
            trace_token=token,
            credential_free=True,
        ) as proxy:
            response = await _proxied_request(
                proxy.proxy_url,
                "GET",
                origin + "/direct-plugin.php?url=file%3A%2F%2Flocalhost%2Fopaque",
            )
            assert response.status_code == 200
            records = proxy.records

    assert len(upstream.observed) == 1
    headers = upstream.observed[0]["headers"]
    assert isinstance(headers, dict)
    assert headers["accept"] == "*/*"
    assert headers["user-agent"] == "Squadrone-Trusted-PoC/1"
    assert headers["accept-encoding"] == "identity"
    assert not any(name.startswith("x-squadrone-") for name in headers)
    assert len(records) == 1
    assert records[0]["credential_free_transport"] is True
    assert isinstance(records[0]["request_nonce"], str)
    assert isinstance(records[0]["request_digest"], str)


@pytest.mark.asyncio
async def test_proxy_does_not_share_upstream_cookie_state_between_requests() -> None:
    with _upstream() as (upstream, origin):
        upstream.set_cookie_once = True
        async with PocProxySupervisor(origin, trace_token="token") as proxy:
            first = await _proxied_request(
                proxy.proxy_url,
                "GET",
                origin + "/sets-cookie",
            )
            second = await _proxied_request(
                proxy.proxy_url,
                "GET",
                origin + "/must-be-stateless",
            )
            records = proxy.records

    assert first.status_code == second.status_code == 200
    assert "proxy_secret=must-not-leak" in first.headers["set-cookie"]
    second_headers = upstream.observed[1]["headers"]
    assert isinstance(second_headers, dict)
    assert "cookie" not in second_headers
    assert [record["forward_state"] for record in records] == [
        "completed",
        "completed",
    ]


@pytest.mark.asyncio
async def test_concurrent_clients_are_forwarded_serially_in_sequence_order() -> None:
    with _upstream() as (upstream, origin):
        upstream.delay_by_path["/first"] = 0.2
        async with PocProxySupervisor(origin, trace_token="token") as proxy:
            first_task = asyncio.create_task(
                _proxied_request(
                    proxy.proxy_url, "POST", origin + "/first", content=b"a=1"
                )
            )
            for _ in range(100):
                if upstream.observed:
                    break
                await asyncio.sleep(0.005)
            assert upstream.observed
            second_task = asyncio.create_task(
                _proxied_request(
                    proxy.proxy_url,
                    "POST",
                    origin + "/second",
                    content=b"b=2",
                )
            )
            first, second = await asyncio.gather(first_task, second_task)
            records = proxy.records

    assert first.status_code == second.status_code == 200
    assert upstream.max_active_requests == 1
    assert [item["path"] for item in upstream.observed] == ["/first", "/second"]
    assert [(record["sequence"], record["path"]) for record in records] == [
        (1, "/first"),
        (2, "/second"),
    ]


@pytest.mark.asyncio
async def test_mutating_upstream_reset_retains_terminal_failure_record() -> None:
    body = b"action=mutate&password=raw-secret"
    salt = bytes.fromhex("45" * 32)
    with _upstream() as (upstream, origin):
        upstream.reset_paths.add("/mutate?object_id=19")
        async with PocProxySupervisor(
            origin,
            trace_token="token",
            trace_salt=salt,
        ) as proxy:
            response = await _proxied_request(
                proxy.proxy_url,
                "POST",
                origin + "/mutate?object_id=19",
                content=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            records = proxy.records
            fatal_error = proxy.fatal_error

    assert response.status_code == 502
    assert len(upstream.observed) == 1
    assert len(records) == 1
    record = records[0]
    assert record["forward_state"] == "failed"
    assert record["forward_error"] == "upstream_reset"
    assert record["terminal"] is True
    assert record["method"] == "POST"
    assert record["path"] == "/mutate"
    assert record["request_digest"] == canonical_request_digest(
        "POST",
        "/mutate?object_id=19",
        body,
    )
    assert _field(record, "form", "action")["value_sha256"] == (
        salted_scalar_sha256("mutate", salt)
    )
    assert fatal_error == "upstream_reset"
    serialized = json.dumps(records)
    assert "raw-secret" not in serialized
    assert "mutate&password" not in serialized


@pytest.mark.asyncio
async def test_total_upstream_deadline_retains_timed_out_mutation() -> None:
    with _upstream() as (upstream, origin):
        upstream.delay_by_path["/slow-mutation"] = 0.15
        async with PocProxySupervisor(
            origin,
            trace_token="token",
            upstream_timeout=0.03,
        ) as proxy:
            response = await _proxied_request(
                proxy.proxy_url,
                "POST",
                origin + "/slow-mutation",
                content=b"action=mutate",
            )
            records = proxy.records

    assert response.status_code == 504
    assert len(upstream.observed) == 1
    assert records[0]["forward_error"] == "upstream_timeout"
    assert records[0]["terminal"] is True
    assert proxy.fatal_error == "upstream_timeout"


@pytest.mark.asyncio
async def test_cancelled_upstream_exchange_retains_terminal_record(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started = asyncio.Event()
    never = asyncio.Event()
    with _upstream() as (_upstream_server, origin):
        async with PocProxySupervisor(origin, trace_token="token") as proxy:

            async def hang_forward(*_args: object, **_kwargs: object) -> object:
                started.set()
                await never.wait()
                raise AssertionError("unreachable")

            monkeypatch.setattr(proxy, "_forward", hang_forward)
            client_task = asyncio.create_task(
                _proxied_request(
                    proxy.proxy_url,
                    "POST",
                    origin + "/cancelled-mutation",
                    content=b"action=mutate",
                )
            )
            await asyncio.wait_for(started.wait(), timeout=1)
            handler = next(iter(proxy._handler_tasks))
            handler.cancel()
            with pytest.raises(httpx.RemoteProtocolError):
                await client_task
            records = proxy.records

    assert records[0]["forward_error"] == "upstream_cancelled"
    assert records[0]["forward_state"] == "failed"
    assert proxy.fatal_error == "upstream_cancelled"


@pytest.mark.asyncio
async def test_close_cancels_active_and_queued_requests_without_draining(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started = asyncio.Event()
    never = asyncio.Event()
    forward_calls = 0
    with _upstream() as (upstream, origin):
        proxy = PocProxySupervisor(origin, trace_token="token")
        await proxy.start()

        async def hang_forward(*_args: object, **_kwargs: object) -> object:
            nonlocal forward_calls
            forward_calls += 1
            started.set()
            await never.wait()
            raise AssertionError("unreachable")

        monkeypatch.setattr(proxy, "_forward", hang_forward)
        first_task = asyncio.create_task(
            _proxied_request(
                proxy.proxy_url,
                "POST",
                origin + "/active-mutation",
                content=b"action=first",
            )
        )
        await asyncio.wait_for(started.wait(), timeout=1)
        second_task = asyncio.create_task(
            _proxied_request(
                proxy.proxy_url,
                "POST",
                origin + "/queued-mutation",
                content=b"action=second",
            )
        )
        for _ in range(100):
            if len(proxy._handler_tasks) >= 2:
                break
            await asyncio.sleep(0.005)
        assert len(proxy._handler_tasks) >= 2

        started_at = asyncio.get_running_loop().time()
        await proxy.close()
        elapsed = asyncio.get_running_loop().time() - started_at
        client_results = await asyncio.gather(
            first_task,
            second_task,
            return_exceptions=True,
        )
        records = proxy.records

    assert elapsed < 0.5
    assert forward_calls == 1
    assert upstream.observed == []
    assert all(isinstance(result, httpx.HTTPError) for result in client_results)
    assert len(records) == 2
    assert [record["path"] for record in records] == [
        "/active-mutation",
        "/queued-mutation",
    ]
    assert [record["forward_error"] for record in records] == [
        "upstream_cancelled",
        "queued_request_cancelled",
    ]
    assert proxy.fatal_error == "upstream_cancelled"


@pytest.mark.asyncio
async def test_runner_has_no_trace_secrets_and_hooks_cannot_change_record(
    tmp_path: Path,
) -> None:
    salt = bytes.fromhex("44" * 32)
    with _upstream() as (upstream, origin):
        upstream.status_code = 201
        upstream.response_body = b"upstream-body-before-hook"
        script = tmp_path / "proof.py"
        script.write_text(
            "\n".join(
                (
                    "import json",
                    "import os",
                    "import requests",
                    f"private = {sorted(PRIVATE_TRACE_ENV_NAMES)!r}",
                    "def rewrite(response, *args, **kwargs):",
                    "    response.status_code = 599",
                    "    response._content = b'forged-by-hook'",
                    "    response.headers['X-Squadrone-Actor-Receipt'] = 'forged'",
                    "    return response",
                    "session = requests.Session()",
                    "session.hooks['response'].append(rewrite)",
                    f"response = session.get({origin!r} + '/hooked?object_id=9', timeout=5)",
                    "print(json.dumps({'status': response.status_code,",
                    "    'body': response.text,",
                    "    'private_absent': all(name not in os.environ for name in private),",
                    "    'parent_secret_absent': 'SQUADRONE_TEST_PARENT_SECRET' not in os.environ,",
                    f"    'proxy_control_absent': {POC_PROXY_ENV!r} not in os.environ}}))",
                )
            ),
            encoding="utf-8",
        )
        async with PocProxySupervisor(
            origin,
            trace_token="parent-secret-token",
            trace_salt=salt,
        ) as proxy:
            base_env = os.environ.copy()
            base_env.update(
                {
                    "SQUADRONE_TEST_PARENT_SECRET": "must-not-cross-boundary",
                    TRACE_FD_ENV: "91",
                    TRACE_SALT_ENV: "old-salt",
                    TRACE_TOKEN_ENV: "old-token",
                    TRACE_ORIGIN_ENV: "old-origin",
                }
            )
            process = await asyncio.create_subprocess_exec(
                sys.executable,
                "-m",
                "squadrone.poc_runner",
                str(script),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=proxy.child_environment(base_env),
            )
            stdout, stderr = await process.communicate()
            records = proxy.records

    assert process.returncode == 0, stderr.decode()
    output = json.loads(stdout)
    assert output == {
        "status": 599,
        "body": "forged-by-hook",
        "private_absent": True,
        "parent_secret_absent": True,
        "proxy_control_absent": True,
    }
    assert len(records) == 1
    record = records[0]
    assert record["status_code"] == 201
    assert base64.b64decode(str(record["response_body_b64"])) == (
        b"upstream-body-before-hook"
    )
    assert (
        record["response_body_sha256"]
        == hashlib.sha256(b"upstream-body-before-hook").hexdigest()
    )
    assert record["response_actor_receipt"] != "forged"


@pytest.mark.asyncio
async def test_proxy_rejects_cross_origin_connect_and_chunked_requests() -> None:
    with _upstream() as (allowed, allowed_origin):
        with _upstream() as (other, other_origin):
            async with PocProxySupervisor(
                allowed_origin,
                trace_token="token",
            ) as proxy:
                cross_origin = await _proxied_request(
                    proxy.proxy_url,
                    "GET",
                    other_origin + "/must-not-arrive",
                )
                assert cross_origin.status_code == 403

                parsed_proxy = urlsplit(proxy.proxy_url)
                reader, writer = await asyncio.open_connection(
                    parsed_proxy.hostname,
                    parsed_proxy.port,
                )
                writer.write(
                    b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
                )
                await writer.drain()
                connect_response = await reader.read()
                writer.close()
                await writer.wait_closed()

                allowed_host = urlsplit(allowed_origin).netloc.encode("ascii")
                reader, writer = await asyncio.open_connection(
                    parsed_proxy.hostname,
                    parsed_proxy.port,
                )
                writer.write(
                    b"POST "
                    + allowed_origin.encode("ascii")
                    + b"/chunked HTTP/1.1\r\nHost: "
                    + allowed_host
                    + b"\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
                )
                await writer.drain()
                chunked_response = await reader.read()
                writer.close()
                await writer.wait_closed()
                records = proxy.records

    assert b" 405 " in connect_response.split(b"\r\n", 1)[0]
    assert b" 501 " in chunked_response.split(b"\r\n", 1)[0]
    assert other.observed == []
    assert allowed.observed == []
    assert [record["forward_error"] for record in records] == [
        "target_origin_not_allowed",
        "connect_not_supported",
        "unsupported_transfer_encoding",
    ]
    assert proxy.fatal_error == "target_origin_not_allowed"


@pytest.mark.parametrize(
    ("extra_headers", "expected_status", "expected_error"),
    [
        (
            b"Content-Type: application/json\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n",
            400,
            "ambiguous_content_type",
        ),
        (
            b"X-HTTP-Method-Override: SQUADRONE_OVERRIDE\r\n",
            400,
            "behavior_changing_header",
        ),
        (
            b"X-Original-URL: /hidden-route\r\n",
            400,
            "behavior_changing_header",
        ),
        (
            b"Content-Encoding: gzip\r\n",
            415,
            "unsupported_request_content_encoding",
        ),
    ],
)
@pytest.mark.asyncio
async def test_proxy_rejects_ambiguous_request_semantics_with_terminal_record(
    extra_headers: bytes,
    expected_status: int,
    expected_error: str,
) -> None:
    with _upstream() as (upstream, origin):
        async with PocProxySupervisor(origin, trace_token="token") as proxy:
            authority = urlsplit(origin).netloc.encode("ascii")
            response = await _raw_proxy_request(
                proxy.proxy_url,
                b"POST "
                + origin.encode("ascii")
                + b"/ambiguous HTTP/1.1\r\nHost: "
                + authority
                + b"\r\nContent-Length: 0\r\n"
                + extra_headers
                + b"\r\n",
            )
            records = proxy.records

    assert f" {expected_status} ".encode() in response.split(b"\r\n", 1)[0]
    assert upstream.observed == []
    assert len(records) == 1
    assert records[0]["record_type"] == "terminal_error"
    assert records[0]["forward_error"] == expected_error
    assert records[0]["forward_state"] == "failed"
    assert records[0]["terminal"] is True
    assert set(records[0]["request_sentinel_flags"]) == {
        "target",
        "target_encoded",
        "body",
        "body_encoded",
        "headers",
        "headers_encoded",
    }
    assert proxy.fatal_error == expected_error
    assert proxy.rejection_counts[expected_error] == 1
    if expected_error == "behavior_changing_header" and b"SQUADRONE_" in extra_headers:
        assert records[0]["request_sentinel_flags"]["headers"] is True
        assert "SQUADRONE_OVERRIDE" not in json.dumps(records)


@pytest.mark.parametrize(
    "raw_target",
    [
        b"http://[invalid/",
        b"//[invalid",
        b"http://127.0.0.1:not-a-port/path",
    ],
)
@pytest.mark.asyncio
async def test_malformed_targets_are_terminal_rejections(raw_target: bytes) -> None:
    with _upstream() as (upstream, origin):
        async with PocProxySupervisor(origin, trace_token="token") as proxy:
            authority = urlsplit(origin).netloc.encode("ascii")
            response = await _raw_proxy_request(
                proxy.proxy_url,
                b"GET " + raw_target + b" HTTP/1.1\r\nHost: " + authority + b"\r\n\r\n",
            )
            records = proxy.records
            fatal_error = proxy.fatal_error

    assert b" 400 " in response.split(b"\r\n", 1)[0]
    assert upstream.observed == []
    assert len(records) == 1
    assert records[0]["record_type"] == "terminal_error"
    assert records[0]["forward_error"] == "invalid_request_target"
    assert records[0]["forward_state"] == "failed"
    assert records[0]["terminal"] is True
    assert fatal_error == "invalid_request_target"


@pytest.mark.asyncio
async def test_unexpected_request_exception_is_value_free_terminal_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with _upstream() as (upstream, origin):
        async with PocProxySupervisor(origin, trace_token="token") as proxy:

            def fail_parse(_raw_head: bytes) -> None:
                raise RuntimeError("SQUADRONE_RAW_SECRET")

            monkeypatch.setattr(proxy, "_parse_request", fail_parse)
            authority = urlsplit(origin).netloc.encode("ascii")
            response = await _raw_proxy_request(
                proxy.proxy_url,
                b"GET "
                + origin.encode("ascii")
                + b"/unexpected HTTP/1.1\r\nHost: "
                + authority
                + b"\r\n\r\n",
            )
            records = proxy.records
            fatal_error = proxy.fatal_error

    assert b" 502 " in response.split(b"\r\n", 1)[0]
    assert upstream.observed == []
    assert len(records) == 1
    assert records[0]["record_type"] == "terminal_error"
    assert records[0]["forward_error"] == "unexpected_request_error"
    assert records[0]["forward_state"] == "failed"
    assert records[0]["terminal"] is True
    assert fatal_error == "unexpected_request_error"
    assert "SQUADRONE_RAW_SECRET" not in json.dumps(records)


@pytest.mark.asyncio
async def test_oversized_declared_body_is_terminal_before_buffering() -> None:
    with _upstream() as (upstream, origin):
        async with PocProxySupervisor(origin, trace_token="token") as proxy:
            authority = urlsplit(origin).netloc.encode("ascii")
            response = await _raw_proxy_request(
                proxy.proxy_url,
                b"POST "
                + origin.encode("ascii")
                + b"/too-large HTTP/1.1\r\nHost: "
                + authority
                + b"\r\nContent-Length: "
                + str(MAX_REQUEST_BODY_BYTES + 1).encode("ascii")
                + b"\r\n\r\n",
            )
            records = proxy.records

    assert b" 413 " in response.split(b"\r\n", 1)[0]
    assert upstream.observed == []
    assert records[0]["forward_error"] == "request_body_too_large"
    assert proxy.fatal_error == "request_body_too_large"


@pytest.mark.asyncio
async def test_partial_body_read_deadline_records_encoded_sentinel_and_fails() -> None:
    with _upstream() as (upstream, origin):
        async with PocProxySupervisor(
            origin,
            trace_token="token",
            request_read_timeout=0.05,
        ) as proxy:
            parsed_proxy = urlsplit(proxy.proxy_url)
            reader, writer = await asyncio.open_connection(
                parsed_proxy.hostname,
                parsed_proxy.port,
            )
            authority = urlsplit(origin).netloc.encode("ascii")
            writer.write(
                b"POST "
                + origin.encode("ascii")
                + b"/slow-body HTTP/1.1\r\nHost: "
                + authority
                + b"\r\nContent-Type: application/x-www-form-urlencoded"
                + b"\r\nContent-Length: 100\r\n\r\n"
                + b"marker=SQUADRONE%5FPARTIAL"
            )
            await writer.drain()
            response = await asyncio.wait_for(reader.read(), timeout=1)
            writer.close()
            await writer.wait_closed()
            records = proxy.records

    assert b" 408 " in response.split(b"\r\n", 1)[0]
    assert upstream.observed == []
    assert records[0]["forward_error"] == "request_read_timeout"
    assert records[0]["request_sentinel_flags"]["body"] is False
    assert records[0]["request_sentinel_flags"]["body_encoded"] is True
    assert records[0]["request_sentinel_categories"] == ["body_encoded"]
    assert proxy.fatal_error == "request_read_timeout"
    assert "SQUADRONE_PARTIAL" not in json.dumps(records)


@pytest.mark.asyncio
async def test_handler_limit_rejects_extra_connection_without_body_buffering() -> None:
    with _upstream() as (upstream, origin):
        proxy = PocProxySupervisor(
            origin,
            trace_token="token",
            max_concurrent_handlers=1,
            request_read_timeout=5,
        )
        await proxy.start()
        parsed_proxy = urlsplit(proxy.proxy_url)
        first_reader, first_writer = await asyncio.open_connection(
            parsed_proxy.hostname,
            parsed_proxy.port,
        )
        del first_reader
        first_writer.write(b"POST /held HTTP/1.1\r\nHost:")
        await first_writer.drain()
        for _ in range(100):
            if proxy._active_handlers == 1:
                break
            await asyncio.sleep(0.005)
        assert proxy._active_handlers == 1

        second_reader, second_writer = await asyncio.open_connection(
            parsed_proxy.hostname,
            parsed_proxy.port,
        )
        second_response = await asyncio.wait_for(second_reader.read(), timeout=1)
        second_writer.close()
        await second_writer.wait_closed()
        await proxy.close()
        first_writer.close()
        await first_writer.wait_closed()
        records = proxy.records

    assert b" 503 " in second_response.split(b"\r\n", 1)[0]
    assert upstream.observed == []
    assert [record["forward_error"] for record in records] == [
        "handler_limit_exceeded",
        "request_read_cancelled",
    ]
    assert proxy.fatal_error == "handler_limit_exceeded"
    assert proxy.rejection_counts == {
        "handler_limit_exceeded": 1,
        "request_read_cancelled": 1,
    }


@pytest.mark.asyncio
async def test_trace_construction_error_is_retained_and_not_forwarded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_trace(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("raw-secret-must-not-be-recorded")

    monkeypatch.setattr(poc_proxy, "trace_fields_from_wire", fail_trace)
    with _upstream() as (upstream, origin):
        async with PocProxySupervisor(origin, trace_token="token") as proxy:
            response = await _proxied_request(
                proxy.proxy_url,
                "POST",
                origin + "/would-mutate",
                content=b"secret=raw-secret",
            )
            records = proxy.records
            fatal_error = proxy.fatal_error

    assert response.status_code == 502
    assert upstream.observed == []
    assert records[0]["forward_error"] == "trace_construction_error"
    assert records[0]["forward_state"] == "failed"
    assert fatal_error == "trace_construction_error"
    assert "raw-secret" not in json.dumps(records)


@pytest.mark.asyncio
async def test_non_identity_response_encoding_is_terminal_and_not_returned() -> None:
    with _upstream() as (upstream, origin):
        upstream.content_encoding = "gzip"
        async with PocProxySupervisor(origin, trace_token="token") as proxy:
            response = await _proxied_request(
                proxy.proxy_url,
                "GET",
                origin + "/compressed",
            )
            records = proxy.records

    assert response.status_code == 502
    assert len(upstream.observed) == 1
    assert records[0]["status_code"] == 200
    assert records[0]["forward_error"] == "unsupported_content_encoding"
    assert proxy.fatal_error == "unsupported_content_encoding"


@pytest.mark.asyncio
async def test_record_limit_uses_reserved_terminal_slot_and_latches_fatal() -> None:
    with _upstream() as (upstream, origin):
        async with PocProxySupervisor(
            origin,
            trace_token="token",
            max_trace_records=2,
        ) as proxy:
            first = await _proxied_request(
                proxy.proxy_url,
                "GET",
                origin + "/first",
            )
            overflow = await _proxied_request(
                proxy.proxy_url,
                "POST",
                origin + "/must-not-mutate",
                content=b"action=delete",
            )
            records = proxy.records
            fatal_error = proxy.fatal_error

    assert first.status_code == 200
    assert overflow.status_code == 503
    assert [record["record_type"] for record in records] == [
        "request",
        "terminal_error",
    ]
    assert records[-1]["forward_error"] == "trace_record_limit_exceeded"
    assert records[-1]["path"] == "/must-not-mutate"
    assert fatal_error == "trace_record_limit_exceeded"
    assert [item["path"] for item in upstream.observed] == ["/first"]


@pytest.mark.asyncio
async def test_capture_limit_retains_hash_and_terminal_failure() -> None:
    with _upstream() as (upstream, origin):
        upstream.response_body = b"response-too-large-for-trace-budget"
        async with PocProxySupervisor(
            origin,
            trace_token="token",
            max_trace_capture_bytes=1,
        ) as proxy:
            response = await _proxied_request(
                proxy.proxy_url,
                "POST",
                origin + "/mutated-before-response",
                content=b"action=save",
            )
            records = proxy.records

    assert response.status_code == 503
    record = records[0]
    assert record["status_code"] == 200
    assert (
        record["response_body_sha256"]
        == hashlib.sha256(upstream.response_body).hexdigest()
    )
    assert record["response_capture_omitted"] is True
    assert record["forward_error"] == "trace_capture_limit_exceeded"
    assert proxy.fatal_error == "trace_capture_limit_exceeded"


@pytest.mark.asyncio
async def test_metadata_limit_collapses_record_and_rejects_before_forward() -> None:
    with _upstream() as (upstream, origin):
        async with PocProxySupervisor(
            origin,
            trace_token="token",
            max_trace_metadata_bytes=1,
        ) as proxy:
            response = await _proxied_request(
                proxy.proxy_url,
                "POST",
                origin + "/metadata-overflow",
                content=b"secret=raw-value",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            records = proxy.records

    assert response.status_code == 503
    assert upstream.observed == []
    assert records[0]["fields"] == []
    assert records[0]["parameter_shape"] == []
    assert records[0]["request_metadata_omitted"] is True
    assert records[0]["forward_error"] == "trace_metadata_limit_exceeded"
    assert proxy.fatal_error == "trace_metadata_limit_exceeded"
    assert "raw-value" not in json.dumps(records)


@pytest.mark.asyncio
async def test_response_capture_is_bounded_but_hashes_complete_body() -> None:
    body = b"H" * (RESPONSE_BODY_CAPTURE_LIMIT // 2 + 17)
    body += b"M" * RESPONSE_BODY_CAPTURE_LIMIT
    body += b"T" * (RESPONSE_BODY_CAPTURE_LIMIT // 2 + 19)
    with _upstream() as (upstream, origin):
        upstream.response_body = body
        async with PocProxySupervisor(origin, trace_token="token") as proxy:
            response = await _proxied_request(
                proxy.proxy_url,
                "GET",
                origin + "/large",
            )
            records = proxy.records

    assert response.content == body
    record = records[0]
    half = RESPONSE_BODY_CAPTURE_LIMIT // 2
    assert record["response_body_sha256"] == hashlib.sha256(body).hexdigest()
    assert record["response_body_length"] == len(body)
    assert record["response_body_truncated"] is True
    assert base64.b64decode(str(record["response_body_b64"])) == body[:half]
    assert base64.b64decode(str(record["response_body_tail_b64"])) == body[-half:]


def test_minimal_child_environment_drops_parent_credentials() -> None:
    environment = minimal_poc_environment(
        "http://127.0.0.1:8123",
        {
            "PATH": "/bin",
            "LANG": "C.UTF-8",
            "OPENAI_API_KEY": "must-not-cross-boundary",
            TRACE_TOKEN_ENV: "old-token",
        },
    )

    assert environment["PATH"] == "/bin"
    assert environment["HTTP_PROXY"] == "http://127.0.0.1:8123"
    assert environment[POC_PROXY_ENV] == "http://127.0.0.1:8123"
    assert "OPENAI_API_KEY" not in environment
    assert TRACE_TOKEN_ENV not in environment
