from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import re
import time
from dataclasses import FrozenInstanceError
from urllib.parse import urlsplit

import pytest

from squadrone.services.ssrf_oracle import (
    ALLOWED_ORACLE_METHODS,
    LOCAL_RESOURCE_SSRF_DIRECTORY,
    LOCAL_RESOURCE_SSRF_FILE_MODE,
    LOCAL_RESOURCE_SSRF_MODE,
    SSRF_ATTACK_URL_ENV,
    SSRF_CONTROL_URL_ENV,
    LocalResourceSsrfOracle,
    SsrfOracleServer,
)


def _target_and_authority(url: str) -> tuple[str, str]:
    parsed = urlsplit(url)
    assert parsed.scheme == "http"
    assert parsed.hostname == "host.docker.internal"
    assert parsed.port is not None
    target = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    return target, parsed.netloc


def _request_bytes(
    url: str,
    *,
    method: str = "GET",
    version: str = "HTTP/1.1",
    body: bytes = b"",
    header_lines: tuple[bytes, ...] = (),
    add_content_length: bool = True,
) -> bytes:
    target, authority = _target_and_authority(url)
    lines = [
        f"{method} {target} {version}".encode(),
        f"Host: {authority}".encode(),
        *header_lines,
    ]
    if add_content_length and body:
        lines.append(f"Content-Length: {len(body)}".encode())
    return b"\r\n".join(lines) + b"\r\n\r\n" + body


async def _exchange(port: int, request: bytes) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(request)
        await writer.drain()
        return await asyncio.wait_for(reader.read(), timeout=2)
    finally:
        writer.close()


def _response(raw: bytes) -> tuple[int, dict[str, object]]:
    head, separator, body = raw.partition(b"\r\n\r\n")
    assert separator
    status = int(head.split(b"\r\n", 1)[0].split(b" ")[1])
    return status, json.loads(body)


def _attest_local_resource_provisioning(
    oracle: LocalResourceSsrfOracle,
) -> tuple[str, int]:
    marker_sha256 = hashlib.sha256(oracle.private_marker.encode("ascii")).hexdigest()
    started_ns = time.monotonic_ns()
    finished_ns = time.monotonic_ns()
    oracle.attest_provisioning(
        generation_id=oracle.generation_id,
        resource_path=oracle.resource_path,
        content_sha256=marker_sha256,
        content_size_bytes=len(oracle.private_marker.encode("ascii")),
        owner_uid=0,
        owner_gid=0,
        file_mode=LOCAL_RESOURCE_SSRF_FILE_MODE,
        link_count=1,
        is_regular_file=True,
        is_symlink=False,
        started_monotonic_ns=started_ns,
        finished_monotonic_ns=finished_ns,
    )
    return marker_sha256, finished_ns


def _attest_local_resource_verification(
    oracle: LocalResourceSsrfOracle,
    marker_sha256: str,
    provisioned_ns: int,
):
    before_ns = max(provisioned_ns, time.monotonic_ns())
    execution_started_ns = time.monotonic_ns()
    execution_finished_ns = time.monotonic_ns()
    after_ns = time.monotonic_ns()
    return oracle.attest_verification(
        generation_id=oracle.generation_id,
        resource_path=oracle.resource_path,
        before_sha256=marker_sha256,
        before_monotonic_ns=before_ns,
        execution_started_monotonic_ns=execution_started_ns,
        execution_finished_monotonic_ns=execution_finished_ns,
        after_sha256=marker_sha256,
        after_monotonic_ns=after_ns,
    )


def test_local_resource_urls_are_opaque_stable_and_same_path() -> None:
    oracle = LocalResourceSsrfOracle()
    attack = urlsplit(oracle.attack_url)
    control = urlsplit(oracle.control_url)

    assert attack.scheme == "file"
    assert control.scheme == "https"
    assert attack.hostname == control.hostname == "localhost"
    assert attack.path == control.path == oracle.resource_path
    assert attack.path.startswith(f"{LOCAL_RESOURCE_SSRF_DIRECTORY}/")
    assert re.fullmatch(r"[0-9a-f]{64}", attack.path.rsplit("/", 1)[1])
    assert not attack.query and not attack.fragment
    assert not control.query and not control.fragment
    assert oracle.public_context() == {
        "mode": LOCAL_RESOURCE_SSRF_MODE,
        "attack_url": oracle.attack_url,
        "control_url": oracle.control_url,
    }
    with pytest.raises(RuntimeError, match="generation is not started"):
        _ = oracle.private_marker
    with pytest.raises(RuntimeError, match="generation is not started"):
        _ = oracle.generation_id


def test_local_resource_generation_rotates_private_values_not_urls() -> None:
    oracle = LocalResourceSsrfOracle()
    public_context = oracle.public_context()

    first_generation = oracle.begin_generation()
    first_marker = oracle.private_marker
    second_generation = oracle.begin_generation()
    second_marker = oracle.private_marker

    assert oracle.public_context() == public_context
    assert first_generation != second_generation
    assert first_marker != second_marker
    assert re.fullmatch(r"[0-9a-f]{64}", second_generation)
    assert re.fullmatch(r"SQUADRONE_SSRF_[0-9a-f]{64}", second_marker)
    serialized = json.dumps(oracle.public_context(), sort_keys=True)
    assert first_generation not in serialized
    assert second_generation not in serialized
    assert first_marker not in serialized
    assert second_marker not in serialized


def test_local_resource_completed_generation_rotates_cleanly() -> None:
    oracle = LocalResourceSsrfOracle()
    public_context = oracle.public_context()
    first_generation = oracle.begin_generation()
    first_marker = oracle.private_marker
    marker_sha256, provisioned_ns = _attest_local_resource_provisioning(oracle)
    _attest_local_resource_verification(oracle, marker_sha256, provisioned_ns)

    second_generation = oracle.begin_generation()

    assert oracle.public_context() == public_context
    assert second_generation != first_generation
    assert oracle.private_marker != first_marker
    with pytest.raises(RuntimeError, match="incomplete or unverified"):
        oracle.snapshot()


def test_local_resource_public_contract_fails_closed_if_state_is_corrupted() -> None:
    oracle = LocalResourceSsrfOracle()
    object.__setattr__(oracle, "_resource_path", "/tmp/not-the-issued-path")

    with pytest.raises(RuntimeError, match="public URL state is invalid"):
        oracle.public_context()
    with pytest.raises(RuntimeError, match="public URL state is invalid"):
        oracle.begin_generation()


def test_local_resource_exact_attestations_are_immutable_and_marker_free() -> None:
    oracle = LocalResourceSsrfOracle()
    generation_id = oracle.begin_generation()
    marker = oracle.private_marker
    marker_sha256, provisioned_ns = _attest_local_resource_provisioning(oracle)
    snapshot = _attest_local_resource_verification(
        oracle, marker_sha256, provisioned_ns
    )

    assert snapshot is not oracle.snapshot()
    assert snapshot == oracle.snapshot()
    assert snapshot.schema_version == 1
    assert snapshot.mode == LOCAL_RESOURCE_SSRF_MODE
    assert snapshot.generation_id == generation_id
    assert snapshot.provisioning.marker_sha256 == marker_sha256
    assert snapshot.provisioning.content_sha256 == marker_sha256
    assert snapshot.provisioning.owner_uid == 0
    assert snapshot.provisioning.owner_gid == 0
    assert snapshot.provisioning.file_mode == 0o444
    assert snapshot.provisioning.link_count == 1
    assert snapshot.provisioning.is_regular_file is True
    assert snapshot.provisioning.is_symlink is False
    assert (
        snapshot.provisioning.finished_monotonic_ns
        <= snapshot.verification.before_monotonic_ns
        <= snapshot.verification.execution_started_monotonic_ns
        <= snapshot.verification.execution_finished_monotonic_ns
        <= snapshot.verification.after_monotonic_ns
    )
    serialized = json.dumps(snapshot.as_dict(), sort_keys=True)
    assert marker not in serialized
    assert oracle.resource_path not in serialized
    with pytest.raises(FrozenInstanceError):
        snapshot.provisioning.owner_uid = 1  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        snapshot.verification.after_sha256 = "0" * 64  # type: ignore[misc]


@pytest.mark.parametrize(
    ("override", "value"),
    [
        ("generation_id", "0" * 64),
        ("resource_path", "/var/lib/squadrone/ssrf/" + "0" * 64),
        ("content_sha256", "0" * 64),
        ("content_size_bytes", 0),
        ("owner_uid", True),
        ("owner_gid", 1),
        ("file_mode", 0o644),
        ("link_count", 2),
        ("is_regular_file", False),
        ("is_symlink", True),
        ("started_monotonic_ns", 0),
    ],
)
def test_local_resource_provisioning_rejects_inexact_state(
    override: str,
    value: object,
) -> None:
    oracle = LocalResourceSsrfOracle()
    oracle.begin_generation()
    marker_sha256 = hashlib.sha256(oracle.private_marker.encode("ascii")).hexdigest()
    values: dict[str, object] = {
        "generation_id": oracle.generation_id,
        "resource_path": oracle.resource_path,
        "content_sha256": marker_sha256,
        "content_size_bytes": len(oracle.private_marker.encode("ascii")),
        "owner_uid": 0,
        "owner_gid": 0,
        "file_mode": LOCAL_RESOURCE_SSRF_FILE_MODE,
        "link_count": 1,
        "is_regular_file": True,
        "is_symlink": False,
        "started_monotonic_ns": time.monotonic_ns(),
        "finished_monotonic_ns": time.monotonic_ns(),
    }
    values[override] = value

    with pytest.raises(ValueError, match="provisioning attestation"):
        oracle.attest_provisioning(**values)  # type: ignore[arg-type]
    with pytest.raises(RuntimeError, match="incomplete or unverified"):
        oracle.snapshot()


@pytest.mark.parametrize(
    ("override", "value"),
    [
        ("generation_id", "0" * 64),
        ("resource_path", "/var/lib/squadrone/ssrf/" + "0" * 64),
        ("before_sha256", "0" * 64),
        ("after_sha256", "0" * 64),
        ("after_monotonic_ns", 1),
    ],
)
def test_local_resource_verification_rejects_changed_or_unbounded_state(
    override: str,
    value: object,
) -> None:
    oracle = LocalResourceSsrfOracle()
    oracle.begin_generation()
    marker_sha256, provisioned_ns = _attest_local_resource_provisioning(oracle)
    before_ns = max(provisioned_ns, time.monotonic_ns())
    values: dict[str, object] = {
        "generation_id": oracle.generation_id,
        "resource_path": oracle.resource_path,
        "before_sha256": marker_sha256,
        "before_monotonic_ns": before_ns,
        "execution_started_monotonic_ns": time.monotonic_ns(),
        "execution_finished_monotonic_ns": time.monotonic_ns(),
        "after_sha256": marker_sha256,
        "after_monotonic_ns": time.monotonic_ns(),
    }
    values[override] = value

    with pytest.raises(ValueError, match="verification attestation"):
        oracle.attest_verification(**values)  # type: ignore[arg-type]
    with pytest.raises(RuntimeError, match="incomplete or unverified"):
        oracle.snapshot()
    with pytest.raises(RuntimeError, match="unfinished"):
        oracle.begin_generation()


def test_local_resource_attestation_state_is_single_use_and_fail_closed() -> None:
    oracle = LocalResourceSsrfOracle()
    oracle.begin_generation()
    with pytest.raises(RuntimeError, match="not provisioned"):
        oracle.attest_verification(
            generation_id=oracle.generation_id,
            resource_path=oracle.resource_path,
            before_sha256="0" * 64,
            before_monotonic_ns=1,
            execution_started_monotonic_ns=1,
            execution_finished_monotonic_ns=1,
            after_sha256="0" * 64,
            after_monotonic_ns=1,
        )

    marker_sha256, provisioned_ns = _attest_local_resource_provisioning(oracle)
    with pytest.raises(RuntimeError, match="already attested"):
        _attest_local_resource_provisioning(oracle)
    snapshot = _attest_local_resource_verification(
        oracle, marker_sha256, provisioned_ns
    )
    with pytest.raises(RuntimeError, match="already verified"):
        _attest_local_resource_verification(oracle, marker_sha256, provisioned_ns)

    object.__setattr__(snapshot.provisioning, "marker_sha256", "0" * 64)
    with pytest.raises(RuntimeError, match="provisioning state is malformed"):
        oracle.snapshot()
    with pytest.raises(RuntimeError, match="provisioning state is malformed"):
        oracle.begin_generation()


@pytest.mark.asyncio
async def test_attack_control_and_readiness_are_parent_measured() -> None:
    async with SsrfOracleServer() as oracle:
        assert oracle.is_running is True
        assert oracle.listen_host == "0.0.0.0"
        assert 1024 <= oracle.port <= 65535

        readiness_status, readiness_body = _response(
            await _exchange(
                oracle.port,
                _request_bytes(oracle.readiness_url),
            )
        )
        assert readiness_status == 200
        assert readiness_body == {"ready": True, "schema_version": 1}
        assert (await oracle.snapshot()).hits == ()

        attack_status, attack_body = _response(
            await _exchange(
                oracle.port,
                _request_bytes(
                    oracle.attack_url,
                    method="POST",
                    body=b'{"probe":true}',
                ),
            )
        )
        control_status, control_body = _response(
            await _exchange(
                oracle.port,
                _request_bytes(
                    oracle.control_url,
                    method="POST",
                    body=b'{"probe":true}',
                ),
            )
        )

        assert attack_status == 200
        assert attack_body == {
            "marker": oracle.private_marker,
            "schema_version": 1,
        }
        assert control_status == 404
        assert control_body == {"error": "not_found", "schema_version": 1}
        assert oracle.private_marker not in json.dumps(control_body)

        snapshot = await oracle.snapshot()
        assert snapshot.schema_version == 1
        assert snapshot.generation_id == oracle.generation_id
        assert snapshot.overflow is False
        assert [hit.sequence for hit in snapshot.hits] == [1, 2]
        assert [hit.arm for hit in snapshot.hits] == ["attack", "control"]
        assert [hit.method for hit in snapshot.hits] == ["POST", "POST"]
        assert [hit.status_code for hit in snapshot.hits] == [200, 404]
        assert (
            snapshot.hits[0].marker_sha256
            == hashlib.sha256(oracle.private_marker.encode()).hexdigest()
        )
        assert snapshot.hits[1].marker_sha256 is None
        assert all(
            hit.received_monotonic_ns <= hit.responded_monotonic_ns
            for hit in snapshot.hits
        )


@pytest.mark.asyncio
async def test_public_environment_exposes_only_expiring_destination_urls() -> None:
    instances: list[tuple[dict[str, str], str, str, str]] = []
    for _ in range(2):
        async with SsrfOracleServer() as oracle:
            environment = oracle.public_environment()
            serialized = json.dumps(environment, sort_keys=True)
            readiness_capability = urlsplit(oracle.readiness_url).path.rsplit("/", 1)[1]

            assert set(environment) == {
                SSRF_ATTACK_URL_ENV,
                SSRF_CONTROL_URL_ENV,
            }
            assert environment[SSRF_ATTACK_URL_ENV] == oracle.attack_url
            assert environment[SSRF_CONTROL_URL_ENV] == oracle.control_url
            assert oracle.private_marker not in serialized
            assert oracle.generation_id not in serialized
            assert readiness_capability not in serialized
            instances.append(
                (
                    environment,
                    oracle.private_marker,
                    oracle.generation_id,
                    readiness_capability,
                )
            )

    first, second = instances
    assert first[0] != second[0]
    assert first[1] != second[1]
    assert first[2] != second[2]
    assert first[3] != second[3]


@pytest.mark.asyncio
async def test_generation_rotation_retains_urls_and_clears_private_proof_state() -> (
    None
):
    async with SsrfOracleServer(max_hits=2) as oracle:
        environment = oracle.public_environment()
        first_marker = oracle.private_marker
        first_generation = oracle.generation_id
        await _exchange(oracle.port, _request_bytes(oracle.attack_url))
        await _exchange(oracle.port, _request_bytes(oracle.control_url))
        await _exchange(oracle.port, _request_bytes(oracle.attack_url))
        before = await oracle.snapshot()
        assert before.overflow is True
        assert len(before.hits) == 2

        returned_generation = await oracle.begin_generation()
        after = await oracle.snapshot()

        assert oracle.public_environment() == environment
        assert oracle.private_marker != first_marker
        assert oracle.generation_id != first_generation
        assert returned_generation == oracle.generation_id
        assert after.generation_id == oracle.generation_id
        assert after.overflow is False
        assert after.hits == ()
        assert first_marker not in json.dumps(after.as_dict(), sort_keys=True)

        status, body = _response(
            await _exchange(oracle.port, _request_bytes(oracle.attack_url))
        )
        assert status == 200
        assert body["marker"] == oracle.private_marker
        assert body["marker"] != first_marker


@pytest.mark.asyncio
async def test_generation_rotation_rejects_an_active_connection() -> None:
    async with SsrfOracleServer(request_timeout_s=10) as oracle:
        reader, writer = await asyncio.open_connection("127.0.0.1", oracle.port)
        writer.write(b"GET /partial HTTP/1.1\r\n")
        await writer.drain()
        for _ in range(100):
            if oracle._active_handlers == 1:
                break
            await asyncio.sleep(0)
        assert oracle._active_handlers == 1

        with pytest.raises(RuntimeError, match="active handlers"):
            await oracle.begin_generation()

        writer.close()
        with contextlib.suppress(ConnectionResetError):
            await writer.wait_closed()
        with contextlib.suppress(ConnectionResetError):
            await reader.read()


@pytest.mark.asyncio
async def test_known_capabilities_record_duplicate_and_reordered_hits_exactly() -> None:
    async with SsrfOracleServer() as oracle:
        for url in (oracle.control_url, oracle.attack_url, oracle.attack_url):
            await _exchange(oracle.port, _request_bytes(url))

        snapshot = await oracle.snapshot()

    assert snapshot.overflow is False
    assert [hit.sequence for hit in snapshot.hits] == [1, 2, 3]
    assert [hit.arm for hit in snapshot.hits] == ["control", "attack", "attack"]


@pytest.mark.asyncio
async def test_hit_storage_is_bounded_and_latches_overflow() -> None:
    async with SsrfOracleServer(max_hits=2) as oracle:
        responses = [
            await _exchange(oracle.port, _request_bytes(url))
            for url in (oracle.attack_url, oracle.control_url, oracle.attack_url)
        ]
        snapshot = await oracle.snapshot()

    assert [_response(raw)[0] for raw in responses] == [200, 404, 200]
    assert snapshot.overflow is True
    assert len(snapshot.hits) == 2
    assert [hit.arm for hit in snapshot.hits] == ["attack", "control"]


@pytest.mark.asyncio
async def test_unknown_or_ambiguous_requests_are_marker_free_and_unlogged() -> None:
    async with SsrfOracleServer() as oracle:
        attack_target, authority = _target_and_authority(oracle.attack_url)
        unknown_url = oracle.attack_url.rsplit("/", 1)[0] + "/" + ("f" * 64)
        cases = [
            _request_bytes(unknown_url),
            _request_bytes(oracle.attack_url + "?extra=1"),
            (f"GET {attack_target} HTTP/1.1\r\nHost: wrong.invalid\r\n\r\n").encode(),
            (
                f"GET {attack_target} HTTP/1.1\r\n"
                f"Host: {authority}\r\n"
                f"Host: {authority}\r\n\r\n"
            ).encode(),
            (
                f"POST {attack_target} HTTP/1.1\r\n"
                f"Host: {authority}\r\n"
                "Content-Length: 0\r\n"
                "Content-Length: 0\r\n\r\n"
            ).encode(),
            (
                f"POST {attack_target} HTTP/1.1\r\n"
                f"Host: {authority}\r\n"
                "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
            ).encode(),
            (f"HEAD {attack_target} HTTP/1.1\r\nHost: {authority}\r\n\r\n").encode(),
            (f"GET {attack_target} HTTP/2.0\r\nHost: {authority}\r\n\r\n").encode(),
        ]

        responses = [await _exchange(oracle.port, request) for request in cases]
        snapshot = await oracle.snapshot()

    assert snapshot.hits == ()
    assert snapshot.overflow is False
    assert all(oracle.private_marker.encode() not in raw for raw in responses)
    assert [_response(raw)[0] for raw in responses] == [
        404,
        404,
        400,
        400,
        400,
        400,
        405,
        400,
    ]


@pytest.mark.asyncio
async def test_body_ceiling_and_request_timeout_fail_closed() -> None:
    async with SsrfOracleServer(
        max_body_bytes=8,
        request_timeout_s=0.05,
    ) as oracle:
        target, authority = _target_and_authority(oracle.attack_url)
        oversized = (
            f"POST {target} HTTP/1.1\r\nHost: {authority}\r\nContent-Length: 9\r\n\r\n"
        ).encode()
        oversized_response = await _exchange(oracle.port, oversized)

        reader, writer = await asyncio.open_connection("127.0.0.1", oracle.port)
        try:
            writer.write(f"GET {target} HTTP/1.1\r\n".encode())
            await writer.drain()
            timeout_response = await asyncio.wait_for(reader.read(), timeout=1)
        finally:
            writer.close()
            await writer.wait_closed()

        snapshot = await oracle.snapshot()

    assert _response(oversized_response)[0] == 413
    assert _response(timeout_response)[0] == 408
    assert oracle.private_marker.encode() not in oversized_response
    assert oracle.private_marker.encode() not in timeout_response
    assert snapshot.hits == ()


@pytest.mark.asyncio
async def test_header_ceiling_fails_closed_without_recording() -> None:
    async with SsrfOracleServer(max_header_bytes=1024) as oracle:
        target, authority = _target_and_authority(oracle.attack_url)
        oversized = (
            f"GET {target} HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            "X-Fill: " + ("a" * 1024) + "\r\n\r\n"
        ).encode()
        try:
            response = await _exchange(oracle.port, oversized)
        except ConnectionResetError:
            response = b""
        snapshot = await oracle.snapshot()

    if response:
        assert _response(response)[0] == 431
        assert oracle.private_marker.encode() not in response
    assert snapshot.hits == ()
    assert snapshot.overflow is False


@pytest.mark.asyncio
async def test_concurrency_limit_rejects_without_recording() -> None:
    async with SsrfOracleServer(
        max_concurrent_handlers=1,
        request_timeout_s=10,
    ) as oracle:
        first_reader, first_writer = await asyncio.open_connection(
            "127.0.0.1", oracle.port
        )
        first_writer.write(b"GET /partial HTTP/1.1\r\n")
        await first_writer.drain()
        for _ in range(100):
            if oracle._active_handlers == 1:
                break
            await asyncio.sleep(0)
        assert oracle._active_handlers == 1

        try:
            overloaded = await _exchange(
                oracle.port,
                _request_bytes(oracle.attack_url),
            )
        except ConnectionResetError:
            overloaded = b""
        if overloaded:
            assert _response(overloaded)[0] == 503
            assert oracle.private_marker.encode() not in overloaded
        assert (await oracle.snapshot()).hits == ()

        first_writer.close()
        with contextlib.suppress(ConnectionResetError):
            await first_writer.wait_closed()
        with contextlib.suppress(ConnectionResetError):
            await first_reader.read()


@pytest.mark.asyncio
@pytest.mark.parametrize("method", sorted(ALLOWED_ORACLE_METHODS))
async def test_allowlisted_non_head_methods_can_reach_the_oracle(method: str) -> None:
    async with SsrfOracleServer() as oracle:
        status, body = _response(
            await _exchange(
                oracle.port,
                _request_bytes(oracle.attack_url, method=method),
            )
        )
        snapshot = await oracle.snapshot()

    assert status == 200
    assert body["marker"] == oracle.private_marker
    assert len(snapshot.hits) == 1
    assert snapshot.hits[0].method == method


@pytest.mark.asyncio
@pytest.mark.parametrize("version", ["HTTP/1.0", "HTTP/1.1"])
async def test_http_10_and_11_are_accepted_with_the_exact_host(version: str) -> None:
    async with SsrfOracleServer() as oracle:
        status, body = _response(
            await _exchange(
                oracle.port,
                _request_bytes(oracle.attack_url, version=version),
            )
        )
        snapshot = await oracle.snapshot()

    assert status == 200
    assert body["marker"] == oracle.private_marker
    assert len(snapshot.hits) == 1


@pytest.mark.asyncio
async def test_context_shutdown_closes_clients_listener_and_prevents_restart() -> None:
    oracle = SsrfOracleServer(request_timeout_s=10)
    await oracle.start()
    port = oracle.port
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"GET /partial HTTP/1.1\r\n")
    await writer.drain()

    await oracle.close()

    assert oracle.is_running is False
    try:
        assert await asyncio.wait_for(reader.read(), timeout=1) == b""
    except ConnectionResetError:
        pass
    writer.close()
    with contextlib.suppress(ConnectionResetError):
        await writer.wait_closed()
    with pytest.raises(OSError):
        await asyncio.open_connection("127.0.0.1", port)
    with pytest.raises(RuntimeError, match="single-use"):
        await oracle.start()
