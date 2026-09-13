from __future__ import annotations

import base64
import asyncio
import contextlib
import hashlib
import hmac
import json
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

import squadrone.services.sandbox as sandbox_module
from squadrone.poc_proxy import normalize_trace_origin, salted_scalar_sha256
from squadrone.schemas.config import SandboxConfig
from squadrone.schemas.observation import CIAImpact, PoCObservation
from squadrone.services.sandbox import (
    EXECUTABLE_UPLOAD_CHALLENGE_PARAMETER,
    EXECUTABLE_UPLOAD_RESPONSE_PREFIX,
    POC_RESULT_PREFIX,
    SandboxManager,
)


TARGET = "http://127.0.0.1:48080"
REQUEST_URL = f"{TARGET}/?rest_route=/mwai/v1/simpleFileUpload"
ATTACK_URL = f"{TARGET}/wp-content/uploads/2026/09/attack.php"
CONTROL_URL = f"{TARGET}/wp-content/uploads/2026/09/control.txt"
TRACE_SALT = b"trace-salt-for-upload-tests-0001"
RECEIPT_SECRET = b"receipt-secret-for-upload-tests"
TRACE_TOKEN = "trace-token-for-upload-tests"
CHALLENGE = "a" * 64
EXPECTED_TRANSPORT: dict[str, object] = {
    "method": "POST",
    "route": "/wp-json/mwai/v1/simpleFileUpload",
    "dispatch": {},
}


def _generation() -> sandbox_module._ExecutableUploadGeneration:
    return sandbox_module._new_executable_upload_generation()


def _candidate(
    *,
    attacker_role: str = "subscriber",
    attack_url: object = ATTACK_URL,
    control_url: object = CONTROL_URL,
) -> PoCObservation:
    return PoCObservation(
        verdict="not_vulnerable",
        oracle="response_marker",
        attacker_role=attacker_role,
        request={"method": "POST", "url": REQUEST_URL},
        attack={
            "observed": False,
            "marker_present": False,
            "uploaded_url": attack_url,
        },
        control={
            "observed": False,
            "marker_present": False,
            "uploaded_url": control_url,
        },
        impact=CIAImpact(
            description="Execution is intentionally deferred to the parent oracle."
        ),
    )


def _file_effect_observation() -> PoCObservation:
    return PoCObservation(
        verdict="vulnerable",
        oracle="file_effect",
        attacker_role="unauthenticated",
        request={"method": "POST", "url": f"{TARGET}/upload"},
        attack={
            "observed": True,
            "path": ATTACK_URL,
            "before_exists": False,
            "after_exists": True,
            "after_sha256": "a" * 64,
        },
        control={
            "observed": False,
            "path": CONTROL_URL,
            "before_exists": False,
            "after_exists": False,
        },
        impact=CIAImpact(
            integrity="high",
            description="The upload created an attack-only file.",
        ),
    )


def _scalar_field(location: str, name: str, value: str) -> dict[str, object]:
    return {
        "location": location,
        "name": name,
        "kind": "scalar",
        "value_sha256": salted_scalar_sha256(value, TRACE_SALT),
        "contains_squadrone_sentinel": "SQUADRONE_" in value,
    }


def _response_capture(url: str) -> dict[str, object]:
    # WordPress commonly escapes forward slashes in REST JSON. The parent must
    # decode the document and compare the string leaf, not search raw bytes.
    body = json.dumps(
        {"success": True, "data": {"url": url}},
        separators=(",", ":"),
    ).replace("/", "\\/").encode()
    return {
        "response_body_b64": base64.b64encode(body).decode("ascii"),
        "response_body_tail_b64": "",
        "response_body_truncated": False,
        "response_body_length": len(body),
        "response_body_sha256": hashlib.sha256(body).hexdigest(),
        "response_capture_omitted": None,
    }


def _sign_record(
    record: dict[str, object],
    *,
    user_id: int = 2,
    roles: tuple[str, ...] = ("subscriber",),
) -> None:
    sequence = int(record["sequence"])
    payload = {
        "v": 2,
        "trace_token": TRACE_TOKEN,
        "nonce": f"{sequence + 100:032x}",
        "request_nonce": record["request_nonce"],
        "request_digest": record["request_digest"],
        "user_id": user_id,
        "roles": sorted(roles),
        "method": record["method"],
        "path": record["path"],
    }
    encoded = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    ).decode("ascii").rstrip("=")
    signature = hmac.new(
        RECEIPT_SECRET,
        encoded.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    record["response_actor_receipt"] = f"{encoded}.{signature}"
    record["response_actor_receipt_truncated"] = False


def _trace_record(
    *,
    sequence: int,
    filename: str,
    uploaded_url: str,
    generation: sandbox_module._ExecutableUploadGeneration,
    user_id: int = 2,
    roles: tuple[str, ...] = ("subscriber",),
    purpose: str = "files",
) -> dict[str, object]:
    fields = [
        _scalar_field("query", "rest_route", "/mwai/v1/simpleFileUpload"),
        _scalar_field("form", "base64", generation.payload_b64),
        _scalar_field("form", "filename", filename),
        _scalar_field("form", "purpose", purpose),
        _scalar_field("form", "target", "uploads"),
    ]
    parameter_shape = [
        {
            "location": field["location"],
            "name": field["name"],
            "kind": field["kind"],
            "count": 1,
        }
        for field in fields
    ]
    record: dict[str, object] = {
        "trace_version": 1,
        "record_type": "request",
        "sequence": sequence,
        "request_nonce": f"{sequence:064x}",
        "request_digest": f"{sequence + 10:064x}",
        "method": "POST",
        "origin": normalize_trace_origin(TARGET),
        "path": "/",
        "fields": fields,
        "parameter_shape": parameter_shape,
        "status_code": 200,
        "forward_state": "completed",
        "forward_error": None,
        "terminal": False,
        "request_body_parse_error": None,
        "request_metadata_omitted": None,
        **_response_capture(uploaded_url),
    }
    _sign_record(record, user_id=user_id, roles=roles)
    return record


def _trace_pair(
    generation: sandbox_module._ExecutableUploadGeneration,
    *,
    roles: tuple[str, ...] = ("subscriber",),
) -> list[dict[str, object]]:
    return [
        _trace_record(
            sequence=1,
            filename=generation.attack_filename,
            uploaded_url=ATTACK_URL,
            generation=generation,
            roles=roles,
        ),
        _trace_record(
            sequence=2,
            filename=generation.control_filename,
            uploaded_url=CONTROL_URL,
            generation=generation,
            roles=roles,
        ),
    ]


def _prepare_candidate(
    generation: sandbox_module._ExecutableUploadGeneration,
    *,
    observation: PoCObservation | None = None,
    records: list[dict[str, object]] | None = None,
) -> tuple[sandbox_module._ExecutableUploadTraceBinding | None, str]:
    return sandbox_module._prepare_executable_upload_candidate(
        observation or _candidate(),
        trace_records=records or _trace_pair(generation),
        trace_salt=TRACE_SALT,
        target_url=TARGET,
        expected_http_transport=EXPECTED_TRANSPORT,
        expected_attacker_role="subscriber",
        receipt_secret=RECEIPT_SECRET,
        trace_token=TRACE_TOKEN,
        generation=generation,
    )


def _filesystem_entry(
    generation: sandbox_module._ExecutableUploadGeneration,
    *,
    kind: str = "f",
    inode: int,
    links: int = 1,
    size: int | None = None,
    digest: str | None = None,
) -> sandbox_module._ExecutableUploadFilesystemEntry:
    resolved_size = len(generation.payload) if size is None else size
    resolved_digest = (
        generation.payload_sha256
        if digest is None and kind == "f" and resolved_size == len(generation.payload)
        else digest
    )
    return sandbox_module._ExecutableUploadFilesystemEntry(
        kind=kind,
        inode=inode,
        mode=0o100644 if kind == "f" else 0o120777,
        links=links,
        uid=82,
        gid=82,
        size=resolved_size,
        sha256=resolved_digest,
    )


def _filesystem_snapshot(
    label: str,
    entries: dict[str, sandbox_module._ExecutableUploadFilesystemEntry],
) -> sandbox_module._ExecutableUploadFilesystemSnapshot:
    return sandbox_module._ExecutableUploadFilesystemSnapshot(
        root="directory",
        entries=dict(entries),
        manifest_sha256=hashlib.sha256(label.encode("ascii")).hexdigest(),
    )


def _valid_filesystem_transitions(
    generation: sandbox_module._ExecutableUploadGeneration,
) -> dict[
    tuple[str, str],
    sandbox_module._ExecutableUploadFilesystemSnapshot,
]:
    attack_path = "2026/09/attack.php"
    control_path = "2026/09/control.txt"
    attack = _filesystem_entry(generation, inode=101)
    control = _filesystem_entry(generation, inode=102)
    return {
        ("before", "attack"): _filesystem_snapshot("s0", {}),
        ("after", "attack"): _filesystem_snapshot(
            "s1",
            {attack_path: attack},
        ),
        ("before", "control"): _filesystem_snapshot(
            "s2",
            {attack_path: attack},
        ),
        ("after", "control"): _filesystem_snapshot(
            "s3",
            {attack_path: attack, control_path: control},
        ),
    }


def test_neutral_candidate_is_bound_to_signed_parent_trace() -> None:
    generation = _generation()

    binding, reason = _prepare_candidate(generation)

    assert binding is not None, reason
    assert reason == "executable-upload candidate is bound to two signed upload requests"
    assert binding.attacker_role == "subscriber"
    assert binding.attacker_user_id == 2
    assert binding.attack_url == ATTACK_URL
    assert binding.control_url == CONTROL_URL
    assert binding.attack_sequence == 1
    assert binding.control_sequence == 2
    assert binding.evidence["payload_sha256"] == generation.payload_sha256
    assert binding.evidence["attack"]["actor_roles"] == ["subscriber"]
    assert generation.generation not in json.dumps(binding.evidence)


@pytest.mark.parametrize(
    ("case", "reason_fragment"),
    [
        ("child_verdict", "defer the vulnerable verdict"),
        ("child_identity_claim", "must contain only"),
        ("wrong_role", "wrong attacker role"),
        ("wrong_route", "changed the source-derived transport"),
        ("unsigned_actor", "actor receipt"),
        ("elevated_actor", "only the expected privileges"),
        ("different_fields", "changed fields beyond the filename"),
        ("extra_mutation", "additional mutating HTTP request"),
        ("unbound_response", "did not uniquely bind the attack response"),
    ],
)
def test_neutral_candidate_rejects_untrusted_or_ambiguous_handoffs(
    case: str,
    reason_fragment: str,
) -> None:
    generation = _generation()
    observation = _candidate()
    records = _trace_pair(generation)

    if case == "child_verdict":
        observation.verdict = "vulnerable"
    elif case == "child_identity_claim":
        observation.attack["identity_verified"] = True
    elif case == "wrong_role":
        observation.attacker_role = "administrator"
    elif case == "wrong_route":
        observation.request["url"] = f"{TARGET}/wp-admin/admin-ajax.php"
    elif case == "unsigned_actor":
        records[0]["response_actor_receipt"] = None
    elif case == "elevated_actor":
        _sign_record(records[0], roles=("administrator", "subscriber"))
    elif case == "different_fields":
        fields = records[1]["fields"]
        assert isinstance(fields, list)
        for field in fields:
            assert isinstance(field, dict)
            if field["name"] == "purpose":
                field["value_sha256"] = salted_scalar_sha256("vision", TRACE_SALT)
    elif case == "extra_mutation":
        records.append(
            {
                "method": "POST",
                "path": "/wp-admin/admin-ajax.php",
                "sequence": 3,
                "forward_state": "completed",
                "forward_error": None,
            }
        )
    elif case == "unbound_response":
        records[0].update(_response_capture(f"{TARGET}/wp-content/uploads/other.php"))
    else:  # pragma: no cover - parametrization is exhaustive
        raise AssertionError(case)

    binding, reason = _prepare_candidate(
        generation,
        observation=observation,
        records=records,
    )

    assert binding is None
    assert reason_fragment in reason


def test_parent_builds_final_observation_without_child_claims() -> None:
    generation = _generation()
    binding, reason = _prepare_candidate(generation)
    assert binding is not None, reason
    marker = EXECUTABLE_UPLOAD_RESPONSE_PREFIX + "c" * 64

    observation = sandbox_module._parent_executable_upload_observation(
        binding,
        generation=generation,
        response_marker=marker,
    )

    assert observation.verdict == "vulnerable"
    assert observation.attack["marker"] == marker
    assert observation.attack["identity_verified"] is True
    assert observation.attack["attacker_user_id"] == 2
    assert observation.control["attacker_user_id"] == 2
    assert observation.attack["payload_sha256"] == generation.payload_sha256
    assert observation.impact == CIAImpact(
        confidentiality="high",
        integrity="high",
        availability="high",
        description=sandbox_module.EXECUTABLE_UPLOAD_IMPACT_DESCRIPTION,
    )
    accepted, validation_reason = sandbox_module.validate_poc_observation(
        observation,
        expected_bug_class="ARBITRARY_FILE_WRITE",
        expected_attacker_role="subscriber",
    )
    assert accepted is True, validation_reason


class _StreamResponse:
    def __init__(self, status_code: int, chunks: list[bytes]) -> None:
        self.status_code = status_code
        self._chunks = chunks

    async def __aenter__(self) -> _StreamResponse:
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def aiter_bytes(self):  # type: ignore[no-untyped-def]
        for chunk in self._chunks:
            yield chunk


class _Client:
    responses: dict[str, tuple[int, list[bytes]]] = {}
    constructor_kwargs: dict[str, object] = {}
    requests: list[
        tuple[str, str, dict[str, str], dict[str, str]]
    ] = []

    def __init__(self, **kwargs: object) -> None:
        type(self).constructor_kwargs = kwargs

    async def __aenter__(self) -> _Client:
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    def stream(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str],
        headers: dict[str, str],
    ) -> _StreamResponse:
        type(self).requests.append((method, url, params, headers))
        status, chunks = type(self).responses[url]
        return _StreamResponse(status, chunks)


def _install_http_client(
    monkeypatch: pytest.MonkeyPatch,
    *,
    attack_chunks: list[bytes],
    control_chunks: list[bytes],
    attack_status: int = 200,
    control_status: int = 200,
) -> None:
    _Client.responses = {
        ATTACK_URL: (attack_status, attack_chunks),
        CONTROL_URL: (control_status, control_chunks),
    }
    _Client.constructor_kwargs = {}
    _Client.requests = []
    monkeypatch.setattr(sandbox_module.httpx, "AsyncClient", _Client)
    monkeypatch.setattr(sandbox_module.secrets, "token_hex", lambda _size: CHALLENGE)


def _execution_body(
    generation: sandbox_module._ExecutableUploadGeneration,
) -> bytes:
    digest = hashlib.sha256(
        f"{generation.generation}:{CHALLENGE}".encode("ascii")
    ).hexdigest()
    return (EXECUTABLE_UPLOAD_RESPONSE_PREFIX + digest).encode("ascii")


@pytest.mark.asyncio
async def test_parent_attests_fresh_challenge_and_exact_inert_control_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generation = _generation()
    binding, reason = _prepare_candidate(generation)
    assert binding is not None, reason
    expected = _execution_body(generation)
    _install_http_client(
        monkeypatch,
        attack_chunks=[expected],
        control_chunks=[generation.payload],
    )

    accepted, reason, evidence = (
        await sandbox_module._attest_executable_upload_response_marker(
            binding,
            target_url=TARGET,
            generation=generation,
        )
    )

    assert accepted is True, reason
    assert reason == "parent executable-upload challenge attestation passed"
    assert _Client.constructor_kwargs["follow_redirects"] is False
    assert _Client.constructor_kwargs["trust_env"] is False
    assert _Client.requests == [
        (
            "GET",
            ATTACK_URL,
            {EXECUTABLE_UPLOAD_CHALLENGE_PARAMETER: CHALLENGE},
            {"Accept-Encoding": "identity"},
        ),
        (
            "GET",
            CONTROL_URL,
            {EXECUTABLE_UPLOAD_CHALLENGE_PARAMETER: CHALLENGE},
            {"Accept-Encoding": "identity"},
        ),
    ]
    assert evidence["response_marker"] == expected.decode("ascii")
    assert evidence["payload_sha256"] == generation.payload_sha256
    assert evidence["control"] == {
        "path": "/wp-content/uploads/2026/09/control.txt",
        "status_code": 200,
        "response_complete": True,
        "response_size_bytes": len(generation.payload),
        "response_sha256": generation.payload_sha256,
    }
    serialized = json.dumps(evidence)
    assert CHALLENGE not in serialized
    assert generation.generation not in serialized


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("case", "reason_fragment"),
    [
        ("attack_status", "attack challenge did not execute"),
        ("stale_generation", "attack challenge did not execute"),
        ("changed_control", "control did not preserve the exact inert bytes"),
        ("overflowed_control", "control did not preserve the exact inert bytes"),
    ],
)
async def test_parent_probe_rejects_nonexact_attack_or_control(
    monkeypatch: pytest.MonkeyPatch,
    case: str,
    reason_fragment: str,
) -> None:
    generation = _generation()
    binding, reason = _prepare_candidate(generation)
    assert binding is not None, reason
    attack_status = 200
    attack_body = _execution_body(generation)
    control_chunks = [generation.payload]
    if case == "attack_status":
        attack_status = 302
    elif case == "stale_generation":
        stale = _generation()
        attack_body = _execution_body(stale)
    elif case == "changed_control":
        control_chunks = [generation.payload + b"x"]
    elif case == "overflowed_control":
        control_chunks = [generation.payload, b"x" * 5000]
    else:  # pragma: no cover - parametrization is exhaustive
        raise AssertionError(case)
    _install_http_client(
        monkeypatch,
        attack_chunks=[attack_body],
        control_chunks=control_chunks,
        attack_status=attack_status,
    )

    accepted, reason, evidence = (
        await sandbox_module._attest_executable_upload_response_marker(
            binding,
            target_url=TARGET,
            generation=generation,
        )
    )

    assert accepted is False
    assert reason_fragment in reason
    assert evidence["oracle"] == "executable_upload_response_marker"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("attack_url", "control_url", "reason_fragment"),
    [
        (
            "http://user:pass@127.0.0.1:48080/wp-content/uploads/a.php",
            CONTROL_URL,
            "credentials",
        ),
        (f"{ATTACK_URL}?existing=1", CONTROL_URL, "query or fragment"),
        (f"{ATTACK_URL}#fragment", CONTROL_URL, "query or fragment"),
        (
            "http://localhost:48080/wp-content/uploads/a.php",
            CONTROL_URL,
            "exact sandbox origin",
        ),
        (
            f"{TARGET}/wp-content/plugins/a.php",
            CONTROL_URL,
            "beneath /wp-content/uploads/",
        ),
        (
            f"{TARGET}/wp-content/uploads/a.txt",
            CONTROL_URL,
            ".php",
        ),
        (
            f"{TARGET}/wp-content/uploads/%61ttack.php",
            CONTROL_URL,
            "canonical .php",
        ),
        (
            ATTACK_URL,
            f"{TARGET}/wp-content/uploads/control.php",
            ".txt",
        ),
    ],
)
async def test_executable_upload_urls_fail_closed_before_http(
    monkeypatch: pytest.MonkeyPatch,
    attack_url: str,
    control_url: str,
    reason_fragment: str,
) -> None:
    generation = _generation()
    binding, reason = _prepare_candidate(generation)
    assert binding is not None, reason
    binding = replace(binding, attack_url=attack_url, control_url=control_url)

    def forbidden_client(**_kwargs: object) -> None:
        raise AssertionError("invalid URLs must not start parent HTTP")

    monkeypatch.setattr(sandbox_module.httpx, "AsyncClient", forbidden_client)

    accepted, reason, evidence = (
        await sandbox_module._attest_executable_upload_response_marker(
            binding,
            target_url=TARGET,
            generation=generation,
        )
    )

    assert accepted is False
    assert reason_fragment in reason
    assert evidence == {}


@pytest.mark.asyncio
async def test_filesystem_snapshot_parses_one_bounded_portable_manifest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generation = _generation()
    document = {
        "version": 1,
        "root": "directory",
        "entries": [
            {
                "path": "2026/09/attack.php",
                "kind": "f",
                "inode": 101,
                "mode": 0o100640,
                "links": 1,
                "uid": 82,
                "gid": 82,
                "size": len(generation.payload),
                "sha256": generation.payload_sha256,
            },
            {
                "path": "2026/09/nested",
                "kind": "d",
                "inode": 102,
                "mode": 0o40750,
                "links": 2,
                "uid": 1001,
                "gid": 1001,
                "size": 4096,
                "sha256": None,
            },
        ],
    }
    rendered = json.dumps(document, separators=(",", ":"))
    calls: list[tuple[str, ...]] = []

    async def fake_run(
        *command: str,
        cwd: str | None = None,
        check: bool = True,
    ) -> tuple[int, str, str]:
        del cwd
        calls.append(command)
        assert check is False
        return 0, rendered, ""

    monkeypatch.setattr(sandbox_module, "_run", fake_run)

    snapshot = await sandbox_module._snapshot_executable_upload_filesystem(
        container_name="wordpress-test",
        generation=generation,
    )

    assert snapshot.root == "directory"
    assert snapshot.entries["2026/09/attack.php"].uid == 82
    assert snapshot.entries["2026/09/nested"].uid == 1001
    assert snapshot.entries["2026/09/nested"].sha256 is None
    assert snapshot.manifest_sha256 == hashlib.sha256(rendered.encode()).hexdigest()
    assert calls == [
        (
            "docker",
            "exec",
            "wordpress-test",
            "timeout",
            "--signal=TERM",
            "--kill-after=1",
            "13s",
            "php",
            "-r",
            sandbox_module._EXECUTABLE_UPLOAD_SNAPSHOT_SCRIPT,
            "--",
            str(len(generation.payload)),
        )
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    [
        "command_failed",
        "empty_output",
        "malformed_json",
        "output_bound",
        "entry_bound",
        "absent_root_with_entry",
        "duplicate_path",
        "noncanonical_path",
        "negative_metadata",
        "missing_exact_file_digest",
        "digest_on_nonfile",
        "unexpected_field",
    ],
)
async def test_filesystem_snapshot_rejects_malformed_or_unbounded_manifest(
    monkeypatch: pytest.MonkeyPatch,
    case: str,
) -> None:
    generation = _generation()
    entry: dict[str, object] = {
        "path": "2026/09/attack.php",
        "kind": "f",
        "inode": 101,
        "mode": 0o100644,
        "links": 1,
        "uid": 33,
        "gid": 33,
        "size": len(generation.payload),
        "sha256": generation.payload_sha256,
    }
    document: dict[str, object] = {
        "version": 1,
        "root": "directory",
        "entries": [entry],
    }
    return_code = 0
    output = ""
    if case == "command_failed":
        return_code = 2
    elif case == "empty_output":
        pass
    elif case == "malformed_json":
        output = "{not-json"
    elif case == "output_bound":
        output = json.dumps(document, separators=(",", ":"))
        monkeypatch.setattr(
            sandbox_module,
            "_EXECUTABLE_UPLOAD_SNAPSHOT_MAX_BYTES",
            len(output.encode()) - 1,
        )
    elif case == "entry_bound":
        output = json.dumps(document, separators=(",", ":"))
        monkeypatch.setattr(
            sandbox_module,
            "_EXECUTABLE_UPLOAD_SNAPSHOT_MAX_ENTRIES",
            0,
        )
    else:
        mutated = deepcopy(document)
        mutated_entries = mutated["entries"]
        assert isinstance(mutated_entries, list)
        mutated_entry = mutated_entries[0]
        assert isinstance(mutated_entry, dict)
        if case == "absent_root_with_entry":
            mutated["root"] = "absent"
        elif case == "duplicate_path":
            mutated_entries.append(deepcopy(mutated_entry))
        elif case == "noncanonical_path":
            mutated_entry["path"] = "2026/09/../escape.php"
        elif case == "negative_metadata":
            mutated_entry["inode"] = -1
        elif case == "missing_exact_file_digest":
            mutated_entry["sha256"] = None
        elif case == "digest_on_nonfile":
            mutated_entry["kind"] = "l"
        elif case == "unexpected_field":
            mutated_entry["owner"] = "www-data"
        else:  # pragma: no cover - parametrization is exhaustive
            raise AssertionError(case)
        output = json.dumps(mutated, separators=(",", ":"))

    async def fake_run(
        *_command: str,
        cwd: str | None = None,
        check: bool = True,
    ) -> tuple[int, str, str]:
        del cwd, check
        return return_code, output, "snapshot_failed"

    monkeypatch.setattr(sandbox_module, "_run", fake_run)

    with pytest.raises(RuntimeError, match="snapshot"):
        await sandbox_module._snapshot_executable_upload_filesystem(
            container_name="wordpress-test",
            generation=generation,
        )


@pytest.mark.asyncio
async def test_filesystem_snapshot_timeout_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generation = _generation()

    async def fake_run(
        *_command: str,
        cwd: str | None = None,
        check: bool = True,
    ) -> tuple[int, str, str]:
        del cwd, check
        raise TimeoutError

    monkeypatch.setattr(sandbox_module, "_run", fake_run)

    with pytest.raises(RuntimeError, match="timed out"):
        await sandbox_module._snapshot_executable_upload_filesystem(
            container_name="wordpress-test",
            generation=generation,
        )


@pytest.mark.asyncio
async def test_run_terminates_and_reaps_subprocess_when_cancelled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    blocked = asyncio.Event()

    class Process:
        returncode: int | None = None
        terminated = False
        waited = False

        async def communicate(self) -> tuple[bytes, bytes]:
            await blocked.wait()
            return b"", b""

        def terminate(self) -> None:
            self.terminated = True
            self.returncode = -15

        def kill(self) -> None:
            raise AssertionError("terminate should be sufficient")

        async def wait(self) -> int:
            self.waited = True
            assert self.returncode is not None
            return self.returncode

    process = Process()

    async def create(*_command: str, **_kwargs: object) -> Process:
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create)
    task = asyncio.create_task(sandbox_module._run("synthetic-command"))
    await asyncio.sleep(0)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task
    assert process.terminated is True
    assert process.waited is True


def test_filesystem_snapshot_transitions_bind_exact_s0_s1_s2_s3() -> None:
    generation = _generation()
    binding, reason = _prepare_candidate(generation)
    assert binding is not None, reason
    snapshots = _valid_filesystem_transitions(generation)

    accepted, reason, evidence = (
        sandbox_module._validate_executable_upload_snapshot_transitions(
            binding,
            generation=generation,
            snapshots=snapshots,  # type: ignore[arg-type]
        )
    )

    assert accepted is True, reason
    assert reason == "executable-upload arm snapshot transitions passed"
    assert evidence["attack_path"] == "2026/09/attack.php"
    assert evidence["control_path"] == "2026/09/control.txt"
    assert evidence["payload_sha256"] == generation.payload_sha256
    assert evidence["before_attack"]["entry_count"] == 0
    assert evidence["after_control"]["entry_count"] == 2


def test_filesystem_snapshot_transitions_reject_stale_attack() -> None:
    generation = _generation()
    binding, reason = _prepare_candidate(generation)
    assert binding is not None, reason
    snapshots = _valid_filesystem_transitions(generation)
    snapshots[("before", "attack")] = _filesystem_snapshot(
        "stale-s0",
        {"2026/09/attack.php": _filesystem_entry(generation, inode=99)},
    )

    accepted, reason, _evidence = (
        sandbox_module._validate_executable_upload_snapshot_transitions(
            binding,
            generation=generation,
            snapshots=snapshots,  # type: ignore[arg-type]
        )
    )

    assert accepted is False
    assert reason == "attack upload was not a fresh exact file"


def test_filesystem_snapshot_transitions_reject_control_created_by_attack() -> None:
    generation = _generation()
    binding, reason = _prepare_candidate(generation)
    assert binding is not None, reason
    snapshots = _valid_filesystem_transitions(generation)
    attack = snapshots[("after", "attack")].entries["2026/09/attack.php"]
    snapshots[("after", "attack")] = _filesystem_snapshot(
        "early-control-s1",
        {
            "2026/09/attack.php": attack,
            "2026/09/control.txt": _filesystem_entry(generation, inode=102),
        },
    )

    accepted, reason, _evidence = (
        sandbox_module._validate_executable_upload_snapshot_transitions(
            binding,
            generation=generation,
            snapshots=snapshots,  # type: ignore[arg-type]
        )
    )

    assert accepted is False
    assert reason == "control upload was not a fresh exact file"


@pytest.mark.parametrize("arm", ["attack", "control"])
@pytest.mark.parametrize("case", ["digest", "symlink", "link_count"])
def test_filesystem_snapshot_transitions_reject_nonexact_artifact(
    arm: str,
    case: str,
) -> None:
    generation = _generation()
    binding, reason = _prepare_candidate(generation)
    assert binding is not None, reason
    snapshots = _valid_filesystem_transitions(generation)
    snapshot_key = ("after", arm)
    path = (
        "2026/09/attack.php" if arm == "attack" else "2026/09/control.txt"
    )
    snapshot = snapshots[snapshot_key]
    entry = snapshot.entries[path]
    if case == "digest":
        bad_digest = (
            "0" * 64 if generation.payload_sha256 != "0" * 64 else "1" * 64
        )
        replacement = replace(entry, sha256=bad_digest)
    elif case == "symlink":
        replacement = replace(entry, kind="l", mode=0o120777, sha256=None)
    elif case == "link_count":
        replacement = replace(entry, links=2)
    else:  # pragma: no cover - parametrization is exhaustive
        raise AssertionError(case)
    changed_entries = dict(snapshot.entries)
    changed_entries[path] = replacement
    snapshots[snapshot_key] = _filesystem_snapshot(
        f"{arm}-{case}",
        changed_entries,
    )

    accepted, reason, _evidence = (
        sandbox_module._validate_executable_upload_snapshot_transitions(
            binding,
            generation=generation,
            snapshots=snapshots,  # type: ignore[arg-type]
        )
    )

    assert accepted is False
    assert reason == f"{arm} upload was not a fresh exact file"


def test_filesystem_snapshot_transitions_reject_attack_changed_before_control() -> None:
    generation = _generation()
    binding, reason = _prepare_candidate(generation)
    assert binding is not None, reason
    snapshots = _valid_filesystem_transitions(generation)
    attack = snapshots[("after", "attack")].entries["2026/09/attack.php"]
    snapshots[("before", "control")] = _filesystem_snapshot(
        "changed-s2",
        {"2026/09/attack.php": replace(attack, inode=attack.inode + 1)},
    )

    accepted, reason, _evidence = (
        sandbox_module._validate_executable_upload_snapshot_transitions(
            binding,
            generation=generation,
            snapshots=snapshots,  # type: ignore[arg-type]
        )
    )

    assert accepted is False
    assert reason == "control upload was not a fresh exact file"


@pytest.mark.parametrize("case", ["missing", "out_of_order"])
def test_filesystem_snapshot_transitions_require_all_four_ordered_edges(
    case: str,
) -> None:
    generation = _generation()
    binding, reason = _prepare_candidate(generation)
    assert binding is not None, reason
    snapshots = _valid_filesystem_transitions(generation)
    if case == "missing":
        snapshots.pop(("before", "control"))
    elif case == "out_of_order":
        snapshots = {
            ("after", "attack"): snapshots[("after", "attack")],
            ("before", "attack"): snapshots[("before", "attack")],
            ("before", "control"): snapshots[("before", "control")],
            ("after", "control"): snapshots[("after", "control")],
        }
    else:  # pragma: no cover - parametrization is exhaustive
        raise AssertionError(case)

    accepted, reason, evidence = (
        sandbox_module._validate_executable_upload_snapshot_transitions(
            binding,
            generation=generation,
            snapshots=snapshots,  # type: ignore[arg-type]
        )
    )

    assert accepted is False
    assert reason == "executable-upload arm snapshots are incomplete"
    assert evidence


@pytest.mark.asyncio
async def test_parent_measures_exact_regular_files_from_bounded_manifest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generation = _generation()
    binding, reason = _prepare_candidate(generation)
    assert binding is not None, reason
    calls: list[tuple[str, ...]] = []
    document = {
        "version": 1,
        "root": "directory",
        "entries": [
            {
                "path": "2026/09/attack.php",
                "kind": "f",
                "inode": 101,
                "mode": 0o100644,
                "links": 1,
                "uid": 33,
                "gid": 33,
                "size": len(generation.payload),
                "sha256": generation.payload_sha256,
            },
            {
                "path": "2026/09/control.txt",
                "kind": "f",
                "inode": 102,
                "mode": 0o100644,
                "links": 1,
                "uid": 33,
                "gid": 33,
                "size": len(generation.payload),
                "sha256": generation.payload_sha256,
            },
        ],
    }

    async def fake_run(
        *command: str,
        cwd: str | None = None,
        check: bool = True,
    ) -> tuple[int, str, str]:
        del cwd, check
        calls.append(command)
        assert command[3:7] == (
            "timeout",
            "--signal=TERM",
            "--kill-after=1",
            "13s",
        )
        assert command[7:9] == ("php", "-r")
        return 0, json.dumps(document, separators=(",", ":")), ""

    monkeypatch.setattr(sandbox_module, "_run", fake_run)

    accepted, reason, evidence = (
        await sandbox_module._attest_executable_upload_filesystem(
            binding,
            container_name="wordpress-test",
            generation=generation,
        )
    )

    assert accepted is True, reason
    assert reason == "parent executable-upload filesystem attestation passed"
    assert evidence["attack"]["inode"] == 101
    assert evidence["control"]["inode"] == 102
    assert evidence["attack"]["sha256"] == generation.payload_sha256
    assert len(calls) == 1
    assert sandbox_module._EXECUTABLE_UPLOAD_SNAPSHOT_SCRIPT in calls[0]


@pytest.mark.asyncio
async def test_parent_filesystem_attestation_rejects_digest_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    generation = _generation()
    binding, reason = _prepare_candidate(generation)
    assert binding is not None, reason

    document = {
        "version": 1,
        "root": "directory",
        "entries": [
            {
                "path": "2026/09/attack.php",
                "kind": "f",
                "inode": 101,
                "mode": 0o100644,
                "links": 1,
                "uid": 33,
                "gid": 33,
                "size": len(generation.payload),
                "sha256": "f" * 64,
            },
            {
                "path": "2026/09/control.txt",
                "kind": "f",
                "inode": 102,
                "mode": 0o100644,
                "links": 1,
                "uid": 33,
                "gid": 33,
                "size": len(generation.payload),
                "sha256": generation.payload_sha256,
            },
        ],
    }

    async def fake_run(
        *command: str,
        cwd: str | None = None,
        check: bool = True,
    ) -> tuple[int, str, str]:
        del command, cwd, check
        return 0, json.dumps(document, separators=(",", ":")), ""

    monkeypatch.setattr(sandbox_module, "_run", fake_run)

    accepted, reason, evidence = (
        await sandbox_module._attest_executable_upload_filesystem(
            binding,
            container_name="wordpress-test",
            generation=generation,
        )
    )

    assert accepted is False
    assert reason == "parent executable-upload attack filesystem metadata mismatch"
    assert evidence == {}


class _Process:
    pid = 999_999
    returncode = 0

    async def wait(self) -> int:
        return 0


def _manager(tmp_path: Path) -> SandboxManager:
    manager = SandboxManager(
        SandboxConfig(
            wordpress_image="unused",
            db_image="unused",
            wp_admin_user="admin",
            wp_admin_pass="password",
            wp_admin_email="admin@example.test",
        ),
        poc_timeout_s=1,
    )
    manager.target_url = TARGET
    manager.workdir = tmp_path
    return manager


def _install_child(
    monkeypatch: pytest.MonkeyPatch,
    observation: PoCObservation,
) -> None:
    stdout = (
        POC_RESULT_PREFIX
        + json.dumps(observation.model_dump(mode="json"), separators=(",", ":"))
        + "\n"
    ).encode()

    async def create(*_command: str, **_kwargs: Any) -> _Process:
        return _Process()

    async def communicate(_process: _Process) -> tuple[bytes, bytes]:
        return stdout, b""

    async def kill(_process: _Process) -> None:
        return None

    monkeypatch.setattr(sandbox_module.asyncio, "create_subprocess_exec", create)
    monkeypatch.setattr(sandbox_module, "_communicate_poc_bounded", communicate)
    monkeypatch.setattr(sandbox_module, "_kill_poc_process_group", kill)


@pytest.mark.asyncio
async def test_file_effect_bypasses_executable_upload_promotion(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _install_child(monkeypatch, _file_effect_observation())

    class Proxy:
        proxy_url = "http://127.0.0.1:43123"
        records: list[dict[str, object]] = []
        trace_salt = TRACE_SALT
        fatal_error = ""
        rejection_counts: dict[str, int] = {}

        async def __aenter__(self) -> Proxy:
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

    monkeypatch.setattr(
        sandbox_module,
        "PocProxySupervisor",
        lambda *_args, **_kwargs: Proxy(),
    )

    class Isolation:
        cwd = tmp_path
        runner_path = tmp_path / "runner.py"
        script_path = tmp_path / "poc.py"

        def python_command(self, *_paths: Path) -> tuple[str, ...]:
            return ("isolated-python",)

        def child_environment(self, _proxy_url: str) -> dict[str, str]:
            return {}

    @contextlib.contextmanager
    def prepare(*_args: object, **_kwargs: object):  # type: ignore[no-untyped-def]
        yield Isolation()

    monkeypatch.setattr(sandbox_module, "prepare_poc_isolation", prepare)

    def forbidden_candidate(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("file_effect must not enter executable-upload promotion")

    async def forbidden_attestation(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("file_effect must not invoke executable-upload attestation")

    monkeypatch.setattr(
        sandbox_module,
        "_prepare_executable_upload_candidate",
        forbidden_candidate,
    )
    monkeypatch.setattr(
        sandbox_module,
        "_attest_executable_upload_filesystem",
        forbidden_attestation,
    )
    monkeypatch.setattr(
        sandbox_module,
        "_attest_executable_upload_response_marker",
        forbidden_attestation,
    )

    result = await _manager(tmp_path).run_poc(
        "/generated/poc.py",
        expected_bug_class="ARBITRARY_FILE_WRITE",
        expected_attacker_role="unauthenticated",
        expected_http_transport={
            "method": "POST",
            "route": "/upload",
            "dispatch": {},
        },
        expected_executable_upload=True,
    )

    assert result.success is True, result.validation_reason
    assert result.observation is not None
    assert result.observation.oracle == "file_effect"
    assert result.evidence["executable_upload_parent_promoted"] is False
    assert result.evidence["http_trace_binding"] is None


@pytest.mark.asyncio
async def test_expected_executable_upload_requires_boolean(tmp_path: Path) -> None:
    with pytest.raises(
        ValueError, match="expected_executable_upload must be a boolean"
    ):
        await _manager(tmp_path)._run_poc_locked(  # type: ignore[arg-type]
            "/generated/poc.py",
            expected_executable_upload="yes",  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
async def test_expected_executable_upload_requires_exact_cwe_434(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        ValueError, match="expected_executable_upload requires exact CWE-434 mode"
    ):
        await _manager(tmp_path)._run_poc_locked(
            "/generated/poc.py",
            expected_bug_class="SQLI",
            expected_executable_upload=True,
        )


@pytest.mark.asyncio
async def test_expected_executable_upload_requires_source_transport(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        ValueError, match="expected_executable_upload requires one exact source transport"
    ):
        await _manager(tmp_path)._run_poc_locked(
            "/generated/poc.py",
            expected_bug_class="ARBITRARY_FILE_WRITE",
            expected_executable_upload=True,
        )


@pytest.mark.asyncio
async def test_expected_executable_upload_is_mutually_exclusive(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        ValueError, match="trusted HTTP oracle modes are mutually exclusive"
    ):
        await _manager(tmp_path)._run_poc_locked(
            "/generated/poc.py",
            expected_bug_class="ARBITRARY_FILE_WRITE",
            expected_http_transport=EXPECTED_TRANSPORT,
            expected_php_include=True,
            expected_executable_upload=True,
        )
