"""Parent-owned HTTP and local-resource oracles for trusted SSRF verification.

The generated PoC receives only verifier-issued destination URLs. Response
markers and generation identities remain private to the parent. Network-fetch
proofs also retain a parent-only readiness capability and hit ledger. Local-file
scheme-bypass proofs use an opaque, read-only target-local canary outside the web
root and parent-attested before/after state.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import json
import re
import secrets
import socket
import time
from dataclasses import dataclass
from http import HTTPStatus
from typing import Final, Literal
from urllib.parse import urlsplit


SSRF_ATTACK_URL_ENV = "SQUADRONE_SSRF_ATTACK_URL"
SSRF_CONTROL_URL_ENV = "SQUADRONE_SSRF_CONTROL_URL"

DEFAULT_ADVERTISED_HOST = "host.docker.internal"
DEFAULT_LISTEN_HOST = "0.0.0.0"
DEFAULT_MAX_HEADER_BYTES = 16 * 1024
DEFAULT_MAX_BODY_BYTES = 1024 * 1024
DEFAULT_MAX_HITS = 64
DEFAULT_MAX_CONCURRENT_HANDLERS = 8
DEFAULT_REQUEST_TIMEOUT_S = 5.0
DEFAULT_WRITE_TIMEOUT_S = 5.0

LOCAL_RESOURCE_SSRF_MODE: Final[Literal["local_resource"]] = "local_resource"
LOCAL_RESOURCE_SSRF_DIRECTORY = "/var/lib/squadrone/ssrf"
LOCAL_RESOURCE_SSRF_FILE_MODE = 0o444

ALLOWED_ORACLE_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})

_TOKEN_RE = re.compile(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")
_CONTENT_LENGTH_RE = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_CAPABILITY_RE = re.compile(r"[0-9a-f]{64}\Z")
_MARKER_RE = re.compile(r"SQUADRONE_SSRF_[0-9a-f]{64}\Z")
_ORACLE_PATH_PREFIX = "/_squadrone/ssrf/"
_READ_CHUNK_LIMIT = 64 * 1024


@dataclass(frozen=True, slots=True)
class SsrfOracleHit:
    """One accepted capability request measured by the parent process."""

    schema_version: int
    sequence: int
    arm: Literal["attack", "control"]
    method: str
    received_monotonic_ns: int
    responded_monotonic_ns: int
    status_code: int
    marker_sha256: str | None

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "sequence": self.sequence,
            "arm": self.arm,
            "method": self.method,
            "received_monotonic_ns": self.received_monotonic_ns,
            "responded_monotonic_ns": self.responded_monotonic_ns,
            "status_code": self.status_code,
            "marker_sha256": self.marker_sha256,
        }


@dataclass(frozen=True, slots=True)
class SsrfOracleSnapshot:
    """Immutable verifier evidence; it never contains a live capability."""

    schema_version: int
    generation_id: str
    overflow: bool
    hits: tuple[SsrfOracleHit, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "generation_id": self.generation_id,
            "overflow": self.overflow,
            "hits": [hit.as_dict() for hit in self.hits],
        }


@dataclass(frozen=True, slots=True)
class LocalResourceSsrfProvisioningAttestation:
    """Immutable parent evidence for one provisioned local canary.

    Only hashes are retained.  In particular, this object never contains the
    canary marker that a child must recover through the vulnerable sink.
    """

    schema_version: int
    generation_id: str
    resource_path_sha256: str
    marker_sha256: str
    content_sha256: str
    content_size_bytes: int
    owner_uid: int
    owner_gid: int
    file_mode: int
    link_count: int
    is_regular_file: bool
    is_symlink: bool
    started_monotonic_ns: int
    finished_monotonic_ns: int

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "generation_id": self.generation_id,
            "resource_path_sha256": self.resource_path_sha256,
            "marker_sha256": self.marker_sha256,
            "content_sha256": self.content_sha256,
            "content_size_bytes": self.content_size_bytes,
            "owner_uid": self.owner_uid,
            "owner_gid": self.owner_gid,
            "file_mode": self.file_mode,
            "link_count": self.link_count,
            "is_regular_file": self.is_regular_file,
            "is_symlink": self.is_symlink,
            "started_monotonic_ns": self.started_monotonic_ns,
            "finished_monotonic_ns": self.finished_monotonic_ns,
        }


@dataclass(frozen=True, slots=True)
class LocalResourceSsrfVerificationAttestation:
    """Immutable evidence that the exact canary bounded one execution."""

    schema_version: int
    generation_id: str
    resource_path_sha256: str
    before_sha256: str
    before_monotonic_ns: int
    execution_started_monotonic_ns: int
    execution_finished_monotonic_ns: int
    after_sha256: str
    after_monotonic_ns: int

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "generation_id": self.generation_id,
            "resource_path_sha256": self.resource_path_sha256,
            "before_sha256": self.before_sha256,
            "before_monotonic_ns": self.before_monotonic_ns,
            "execution_started_monotonic_ns": (self.execution_started_monotonic_ns),
            "execution_finished_monotonic_ns": (self.execution_finished_monotonic_ns),
            "after_sha256": self.after_sha256,
            "after_monotonic_ns": self.after_monotonic_ns,
        }


@dataclass(frozen=True, slots=True)
class LocalResourceSsrfSnapshot:
    """Complete parent-only evidence for one local-resource execution."""

    schema_version: int
    mode: Literal["local_resource"]
    generation_id: str
    provisioning: LocalResourceSsrfProvisioningAttestation
    verification: LocalResourceSsrfVerificationAttestation

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "mode": self.mode,
            "generation_id": self.generation_id,
            "provisioning": self.provisioning.as_dict(),
            "verification": self.verification.as_dict(),
        }


class LocalResourceSsrfOracle:
    """Parent-owned oracle state for ``file://`` local-resource SSRF.

    The opaque resource path and its two URLs are stable for the lifetime of an
    instance.  ``begin_generation`` rotates the private marker and generation
    for every child execution.  The caller is responsible for provisioning the
    canary inside the sandbox as root and reporting the resulting measurements
    through the two attestation methods.
    """

    def __init__(self) -> None:
        self._issued_private_values: set[str] = set()
        self._resource_capability = self._fresh_hex()
        self._resource_path = (
            f"{LOCAL_RESOURCE_SSRF_DIRECTORY}/{self._resource_capability}"
        )
        self._resource_path_sha256 = _sha256_ascii(self._resource_path)
        self._marker = ""
        self._marker_sha256 = ""
        self._generation_id = ""
        self._generation_started_monotonic_ns = 0
        self._provisioning: LocalResourceSsrfProvisioningAttestation | None = None
        self._verification: LocalResourceSsrfVerificationAttestation | None = None
        self._validate_public_contract()

    @property
    def resource_path(self) -> str:
        """Return the parent-only absolute path that must be provisioned."""
        self._validate_public_contract()
        return self._resource_path

    @property
    def private_marker(self) -> str:
        if not self._generation_id:
            raise RuntimeError("local-resource SSRF generation is not started")
        return self._marker

    @property
    def generation_id(self) -> str:
        if not self._generation_id:
            raise RuntimeError("local-resource SSRF generation is not started")
        return self._generation_id

    @property
    def attack_url(self) -> str:
        self._validate_public_contract()
        return f"file://localhost{self._resource_path}"

    @property
    def control_url(self) -> str:
        self._validate_public_contract()
        return f"https://localhost{self._resource_path}"

    def public_context(self) -> dict[str, str]:
        """Return the complete and only local-resource child-facing context."""
        return {
            "mode": LOCAL_RESOURCE_SSRF_MODE,
            "attack_url": self.attack_url,
            "control_url": self.control_url,
        }

    def begin_generation(self) -> str:
        """Start a fresh execution while retaining the opaque destination URLs."""
        self._validate_public_contract()
        if self._verification is not None and self._provisioning is None:
            raise RuntimeError("local-resource SSRF attestation state is invalid")
        if self._provisioning is not None:
            if self._verification is None:
                raise RuntimeError(
                    "cannot rotate an unfinished local-resource SSRF generation"
                )
            self._validated_snapshot()

        marker = "SQUADRONE_SSRF_" + self._fresh_hex()
        generation_id = self._fresh_hex()
        if (
            _MARKER_RE.fullmatch(marker) is None
            or _CAPABILITY_RE.fullmatch(generation_id) is None
        ):
            raise RuntimeError("failed to generate private local-resource values")
        self._marker = marker
        self._marker_sha256 = _sha256_ascii(marker)
        self._generation_id = generation_id
        self._generation_started_monotonic_ns = time.monotonic_ns()
        self._provisioning = None
        self._verification = None
        return generation_id

    def attest_provisioning(
        self,
        *,
        generation_id: str,
        resource_path: str,
        content_sha256: str,
        content_size_bytes: int,
        owner_uid: int,
        owner_gid: int,
        file_mode: int,
        link_count: int,
        is_regular_file: bool,
        is_symlink: bool,
        started_monotonic_ns: int,
        finished_monotonic_ns: int,
    ) -> LocalResourceSsrfProvisioningAttestation:
        """Bind exact, root-owned provisioning measurements to this generation."""
        self._require_active_generation()
        if self._provisioning is not None:
            raise RuntimeError("local-resource SSRF canary is already attested")
        now_ns = time.monotonic_ns()
        if (
            type(generation_id) is not str
            or _CAPABILITY_RE.fullmatch(generation_id) is None
            or not hmac.compare_digest(generation_id, self._generation_id)
            or type(resource_path) is not str
            or not hmac.compare_digest(resource_path, self._resource_path)
            or not _is_sha256(content_sha256)
            or not hmac.compare_digest(content_sha256, self._marker_sha256)
            or type(content_size_bytes) is not int
            or content_size_bytes != len(self._marker.encode("ascii"))
            or type(owner_uid) is not int
            or owner_uid != 0
            or type(owner_gid) is not int
            or owner_gid != 0
            or type(file_mode) is not int
            or file_mode != LOCAL_RESOURCE_SSRF_FILE_MODE
            or type(link_count) is not int
            or link_count != 1
            or is_regular_file is not True
            or is_symlink is not False
            or not _is_monotonic_ns(started_monotonic_ns)
            or not _is_monotonic_ns(finished_monotonic_ns)
            or started_monotonic_ns < self._generation_started_monotonic_ns
            or finished_monotonic_ns < started_monotonic_ns
            or finished_monotonic_ns > now_ns
        ):
            raise ValueError("invalid local-resource SSRF provisioning attestation")

        attestation = LocalResourceSsrfProvisioningAttestation(
            schema_version=1,
            generation_id=self._generation_id,
            resource_path_sha256=self._resource_path_sha256,
            marker_sha256=self._marker_sha256,
            content_sha256=content_sha256,
            content_size_bytes=content_size_bytes,
            owner_uid=owner_uid,
            owner_gid=owner_gid,
            file_mode=file_mode,
            link_count=link_count,
            is_regular_file=is_regular_file,
            is_symlink=is_symlink,
            started_monotonic_ns=started_monotonic_ns,
            finished_monotonic_ns=finished_monotonic_ns,
        )
        self._validate_provisioning(attestation)
        self._provisioning = attestation
        return attestation

    def attest_verification(
        self,
        *,
        generation_id: str,
        resource_path: str,
        before_sha256: str,
        before_monotonic_ns: int,
        execution_started_monotonic_ns: int,
        execution_finished_monotonic_ns: int,
        after_sha256: str,
        after_monotonic_ns: int,
    ) -> LocalResourceSsrfSnapshot:
        """Finalize evidence that the immutable canary bounded one execution."""
        self._require_active_generation()
        if self._provisioning is None:
            raise RuntimeError("local-resource SSRF canary is not provisioned")
        if self._verification is not None:
            raise RuntimeError("local-resource SSRF generation is already verified")
        self._validate_provisioning(self._provisioning)
        now_ns = time.monotonic_ns()
        if (
            type(generation_id) is not str
            or _CAPABILITY_RE.fullmatch(generation_id) is None
            or not hmac.compare_digest(generation_id, self._generation_id)
            or type(resource_path) is not str
            or not hmac.compare_digest(resource_path, self._resource_path)
            or not _is_sha256(before_sha256)
            or not hmac.compare_digest(before_sha256, self._marker_sha256)
            or not _is_sha256(after_sha256)
            or not hmac.compare_digest(after_sha256, self._marker_sha256)
            or not _is_monotonic_ns(before_monotonic_ns)
            or not _is_monotonic_ns(execution_started_monotonic_ns)
            or not _is_monotonic_ns(execution_finished_monotonic_ns)
            or not _is_monotonic_ns(after_monotonic_ns)
            or before_monotonic_ns < self._provisioning.finished_monotonic_ns
            or execution_started_monotonic_ns < before_monotonic_ns
            or execution_finished_monotonic_ns < execution_started_monotonic_ns
            or after_monotonic_ns < execution_finished_monotonic_ns
            or after_monotonic_ns > now_ns
        ):
            raise ValueError("invalid local-resource SSRF verification attestation")

        verification = LocalResourceSsrfVerificationAttestation(
            schema_version=1,
            generation_id=self._generation_id,
            resource_path_sha256=self._resource_path_sha256,
            before_sha256=before_sha256,
            before_monotonic_ns=before_monotonic_ns,
            execution_started_monotonic_ns=execution_started_monotonic_ns,
            execution_finished_monotonic_ns=execution_finished_monotonic_ns,
            after_sha256=after_sha256,
            after_monotonic_ns=after_monotonic_ns,
        )
        self._validate_verification(verification, self._provisioning)
        self._verification = verification
        return self._validated_snapshot()

    def snapshot(self) -> LocalResourceSsrfSnapshot:
        """Return complete evidence, failing closed until verification finishes."""
        return self._validated_snapshot()

    def _fresh_hex(self) -> str:
        while True:
            value = secrets.token_hex(32)
            if value not in self._issued_private_values:
                self._issued_private_values.add(value)
                return value

    def _require_active_generation(self) -> None:
        self._validate_public_contract()
        if (
            _CAPABILITY_RE.fullmatch(self._generation_id) is None
            or _MARKER_RE.fullmatch(self._marker) is None
            or not _is_sha256(self._marker_sha256)
            or not hmac.compare_digest(self._marker_sha256, _sha256_ascii(self._marker))
            or not _is_monotonic_ns(self._generation_started_monotonic_ns)
        ):
            raise RuntimeError("local-resource SSRF generation state is invalid")

    def _validate_public_contract(self) -> None:
        expected_path = f"{LOCAL_RESOURCE_SSRF_DIRECTORY}/{self._resource_capability}"
        attack = urlsplit(f"file://localhost{self._resource_path}")
        control = urlsplit(f"https://localhost{self._resource_path}")
        if (
            _CAPABILITY_RE.fullmatch(self._resource_capability) is None
            or self._resource_path != expected_path
            or self._resource_path_sha256 != _sha256_ascii(expected_path)
            or attack.scheme != "file"
            or control.scheme != "https"
            or attack.netloc != "localhost"
            or control.netloc != attack.netloc
            or attack.path != expected_path
            or control.path != attack.path
            or attack.query
            or control.query
            or attack.fragment
            or control.fragment
        ):
            raise RuntimeError("local-resource SSRF public URL state is invalid")

    def _validate_provisioning(
        self,
        value: object,
    ) -> None:
        self._require_active_generation()
        if type(value) is not LocalResourceSsrfProvisioningAttestation or (
            type(value.schema_version) is not int
            or value.schema_version != 1
            or type(value.generation_id) is not str
            or not hmac.compare_digest(value.generation_id, self._generation_id)
            or not _is_sha256(value.resource_path_sha256)
            or not hmac.compare_digest(
                value.resource_path_sha256, self._resource_path_sha256
            )
            or not _is_sha256(value.marker_sha256)
            or not hmac.compare_digest(value.marker_sha256, self._marker_sha256)
            or not _is_sha256(value.content_sha256)
            or not hmac.compare_digest(value.content_sha256, self._marker_sha256)
            or type(value.content_size_bytes) is not int
            or value.content_size_bytes != len(self._marker.encode("ascii"))
            or type(value.owner_uid) is not int
            or value.owner_uid != 0
            or type(value.owner_gid) is not int
            or value.owner_gid != 0
            or type(value.file_mode) is not int
            or value.file_mode != LOCAL_RESOURCE_SSRF_FILE_MODE
            or type(value.link_count) is not int
            or value.link_count != 1
            or value.is_regular_file is not True
            or value.is_symlink is not False
            or not _is_monotonic_ns(value.started_monotonic_ns)
            or value.started_monotonic_ns < self._generation_started_monotonic_ns
            or not _is_monotonic_ns(value.finished_monotonic_ns)
            or value.finished_monotonic_ns < value.started_monotonic_ns
            or value.finished_monotonic_ns > time.monotonic_ns()
        ):
            raise RuntimeError("local-resource SSRF provisioning state is malformed")

    def _validate_verification(
        self,
        value: object,
        provisioning: LocalResourceSsrfProvisioningAttestation,
    ) -> None:
        if type(value) is not LocalResourceSsrfVerificationAttestation or (
            type(value.schema_version) is not int
            or value.schema_version != 1
            or type(value.generation_id) is not str
            or not hmac.compare_digest(value.generation_id, self._generation_id)
            or not _is_sha256(value.resource_path_sha256)
            or not hmac.compare_digest(
                value.resource_path_sha256, self._resource_path_sha256
            )
            or not _is_sha256(value.before_sha256)
            or not hmac.compare_digest(value.before_sha256, self._marker_sha256)
            or not _is_sha256(value.after_sha256)
            or not hmac.compare_digest(value.after_sha256, self._marker_sha256)
            or not _is_monotonic_ns(value.before_monotonic_ns)
            or value.before_monotonic_ns < provisioning.finished_monotonic_ns
            or not _is_monotonic_ns(value.execution_started_monotonic_ns)
            or value.execution_started_monotonic_ns < value.before_monotonic_ns
            or not _is_monotonic_ns(value.execution_finished_monotonic_ns)
            or value.execution_finished_monotonic_ns
            < value.execution_started_monotonic_ns
            or not _is_monotonic_ns(value.after_monotonic_ns)
            or value.after_monotonic_ns < value.execution_finished_monotonic_ns
            or value.after_monotonic_ns > time.monotonic_ns()
        ):
            raise RuntimeError("local-resource SSRF verification state is malformed")

    def _validated_snapshot(self) -> LocalResourceSsrfSnapshot:
        if self._provisioning is None or self._verification is None:
            raise RuntimeError(
                "local-resource SSRF evidence is incomplete or unverified"
            )
        self._validate_provisioning(self._provisioning)
        self._validate_verification(self._verification, self._provisioning)
        return LocalResourceSsrfSnapshot(
            schema_version=1,
            mode=LOCAL_RESOURCE_SSRF_MODE,
            generation_id=self._generation_id,
            provisioning=self._provisioning,
            verification=self._verification,
        )


def _sha256_ascii(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _is_sha256(value: object) -> bool:
    return type(value) is str and _CAPABILITY_RE.fullmatch(value) is not None


def _is_monotonic_ns(value: object) -> bool:
    return type(value) is int and value > 0


@dataclass(frozen=True, slots=True)
class _ParsedRequest:
    method: str
    target: str
    body: bytes


class _RequestRejected(Exception):
    def __init__(self, status_code: int):
        super().__init__(str(status_code))
        self.status_code = status_code


class SsrfOracleServer:
    """Strict, short-lived SSRF oracle owned by the verifier parent.

    Instances are deliberately single-use.  Starting a new instance generates
    independent attack, control, readiness, marker, and generation values.
    """

    def __init__(
        self,
        *,
        advertised_host: str = DEFAULT_ADVERTISED_HOST,
        listen_host: str = DEFAULT_LISTEN_HOST,
        max_header_bytes: int = DEFAULT_MAX_HEADER_BYTES,
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
        max_hits: int = DEFAULT_MAX_HITS,
        max_concurrent_handlers: int = DEFAULT_MAX_CONCURRENT_HANDLERS,
        request_timeout_s: float = DEFAULT_REQUEST_TIMEOUT_S,
        write_timeout_s: float = DEFAULT_WRITE_TIMEOUT_S,
    ) -> None:
        if advertised_host != DEFAULT_ADVERTISED_HOST:
            raise ValueError("SSRF oracle must advertise host.docker.internal")
        if listen_host != DEFAULT_LISTEN_HOST:
            raise ValueError("SSRF oracle must bind the IPv4 wildcard host")
        if max_header_bytes < 1024:
            raise ValueError("max_header_bytes must be at least 1024")
        if max_body_bytes < 0:
            raise ValueError("max_body_bytes cannot be negative")
        if max_hits < 2:
            raise ValueError("max_hits must allow the attack and control arms")
        if max_concurrent_handlers < 1:
            raise ValueError("max_concurrent_handlers must be positive")
        if request_timeout_s <= 0 or write_timeout_s <= 0:
            raise ValueError("oracle timeouts must be positive")

        self.advertised_host = advertised_host
        self.listen_host = listen_host
        self.max_header_bytes = max_header_bytes
        self.max_body_bytes = max_body_bytes
        self.max_hits = max_hits
        self.max_concurrent_handlers = max_concurrent_handlers
        self.request_timeout_s = request_timeout_s
        self.write_timeout_s = write_timeout_s

        self._issued_private_values: set[str] = set()
        self._attack_capability = self._fresh_hex()
        self._control_capability = self._fresh_hex()
        self._readiness_capability = self._fresh_hex()
        self._marker = ""
        self._generation_id = ""
        self._marker_sha256 = ""
        self._rotate_private_generation()

        self._server: asyncio.AbstractServer | None = None
        self._port: int | None = None
        self._started_once = False
        self._closing = False
        self._generation_rotating = False
        self._active_handlers = 0
        self._state_lock = asyncio.Lock()
        self._hit_lock = asyncio.Lock()
        self._handler_tasks: set[asyncio.Task[None]] = set()
        self._writers: set[asyncio.StreamWriter] = set()
        self._hits: list[SsrfOracleHit] = []
        self._overflow = False

    @property
    def is_running(self) -> bool:
        return self._server is not None and not self._closing

    @property
    def port(self) -> int:
        if self._port is None:
            raise RuntimeError("SSRF oracle is not started")
        return self._port

    @property
    def generation_id(self) -> str:
        return self._generation_id

    @property
    def private_marker(self) -> str:
        return self._marker

    @property
    def attack_url(self) -> str:
        return self._url_for(self._attack_capability)

    @property
    def control_url(self) -> str:
        return self._url_for(self._control_capability)

    @property
    def readiness_url(self) -> str:
        """Return the parent-only URL used for a container reachability probe."""
        return self._url_for(self._readiness_capability)

    def public_environment(self) -> dict[str, str]:
        """Return exactly the two expiring values safe for the isolated child."""
        return {
            SSRF_ATTACK_URL_ENV: self.attack_url,
            SSRF_CONTROL_URL_ENV: self.control_url,
        }

    def _fresh_hex(self) -> str:
        while True:
            value = secrets.token_hex(32)
            if value not in self._issued_private_values:
                self._issued_private_values.add(value)
                return value

    def _rotate_private_generation(self) -> None:
        marker = "SQUADRONE_SSRF_" + self._fresh_hex()
        generation_id = self._fresh_hex()
        if (
            _MARKER_RE.fullmatch(marker) is None
            or _CAPABILITY_RE.fullmatch(generation_id) is None
        ):
            raise RuntimeError("failed to generate private SSRF oracle values")
        self._marker = marker
        self._generation_id = generation_id
        self._marker_sha256 = hashlib.sha256(marker.encode("ascii")).hexdigest()

    def _url_for(self, capability: str) -> str:
        if _CAPABILITY_RE.fullmatch(capability) is None:
            raise RuntimeError("invalid internal SSRF capability")
        return f"http://{self.advertised_host}:{self.port}{_ORACLE_PATH_PREFIX}{capability}"

    async def start(self) -> SsrfOracleServer:
        if self._started_once:
            raise RuntimeError("SSRF oracle instances are single-use")
        self._started_once = True
        self._closing = False
        server = await asyncio.start_server(
            self._accept,
            host=self.listen_host,
            port=0,
            family=socket.AF_INET,
            backlog=self.max_concurrent_handlers,
            limit=self.max_header_bytes + 4,
            reuse_address=False,
            reuse_port=False,
            start_serving=True,
        )
        sockets = tuple(server.sockets or ())
        if len(sockets) != 1:
            server.close()
            await server.wait_closed()
            raise RuntimeError("SSRF oracle did not receive one IPv4 listener")
        port = int(sockets[0].getsockname()[1])
        if not 1024 <= port <= 65535:
            server.close()
            await server.wait_closed()
            raise RuntimeError("SSRF oracle did not receive a high host port")
        self._port = port
        self._server = server
        return self

    async def close(self) -> None:
        self._closing = True
        server, self._server = self._server, None
        if server is not None:
            server.close()

        current = asyncio.current_task()
        pending = [task for task in self._handler_tasks if task is not current]
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        self._handler_tasks.clear()

        writers = tuple(self._writers)
        for writer in writers:
            writer.close()
        if writers:
            await asyncio.gather(
                *(writer.wait_closed() for writer in writers),
                return_exceptions=True,
            )
        self._writers.clear()
        if server is not None:
            await server.wait_closed()

    async def begin_generation(self) -> str:
        """Rotate private proof state while retaining the two public URLs.

        Rotation never waits for an in-flight request: the caller must first
        quiesce the child/proxy request path.  New connections are rejected for
        the short interval in which the private generation and ledger change.
        """
        async with self._state_lock:
            if not self.is_running:
                raise RuntimeError("SSRF oracle must be running to rotate generation")
            if self._active_handlers:
                raise RuntimeError(
                    "SSRF oracle generation cannot rotate with active handlers"
                )
            self._generation_rotating = True
        try:
            async with self._hit_lock:
                self._rotate_private_generation()
                self._hits.clear()
                self._overflow = False
                return self._generation_id
        finally:
            async with self._state_lock:
                self._generation_rotating = False

    async def snapshot(self) -> SsrfOracleSnapshot:
        async with self._hit_lock:
            return SsrfOracleSnapshot(
                schema_version=1,
                generation_id=self._generation_id,
                overflow=self._overflow,
                hits=tuple(self._hits),
            )

    async def __aenter__(self) -> SsrfOracleServer:
        return await self.start()

    async def __aexit__(self, *_exc_info: object) -> None:
        await self.close()

    async def _accept(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._handler_tasks.add(task)
        self._writers.add(writer)
        admitted = False
        try:
            async with self._state_lock:
                if (
                    not self._closing
                    and not self._generation_rotating
                    and (self._active_handlers < self.max_concurrent_handlers)
                ):
                    self._active_handlers += 1
                    admitted = True
            if not admitted:
                await self._write_static_error(writer, HTTPStatus.SERVICE_UNAVAILABLE)
                return
            await self._serve_one(reader, writer)
        except asyncio.CancelledError:
            raise
        except Exception:
            # No parser or socket exception text is returned or retained because
            # it may contain attacker-controlled bytes or a live capability.
            with contextlib.suppress(Exception):
                await self._write_static_error(writer, HTTPStatus.BAD_REQUEST)
        finally:
            if admitted:
                async with self._state_lock:
                    self._active_handlers -= 1
            self._writers.discard(writer)
            writer.close()
            with contextlib.suppress(ConnectionError, RuntimeError, TimeoutError):
                await asyncio.wait_for(writer.wait_closed(), timeout=0.25)
            if task is not None:
                self._handler_tasks.discard(task)

    async def _serve_one(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            async with asyncio.timeout(self.request_timeout_s):
                request = await self._read_request(reader)
        except TimeoutError:
            await self._write_static_error(writer, HTTPStatus.REQUEST_TIMEOUT)
            return
        except asyncio.LimitOverrunError:
            await self._write_static_error(
                writer, HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE
            )
            return
        except asyncio.IncompleteReadError:
            await self._write_static_error(writer, HTTPStatus.BAD_REQUEST)
            return
        except _RequestRejected as exc:
            await self._write_static_error(writer, exc.status_code)
            return

        attack_target = _ORACLE_PATH_PREFIX + self._attack_capability
        control_target = _ORACLE_PATH_PREFIX + self._control_capability
        readiness_target = _ORACLE_PATH_PREFIX + self._readiness_capability

        if hmac.compare_digest(request.target, readiness_target):
            if request.method != "GET" or request.body:
                await self._write_static_error(writer, HTTPStatus.NOT_FOUND)
                return
            await self._write_json(
                writer,
                HTTPStatus.OK,
                {"schema_version": 1, "ready": True},
            )
            return

        arm: Literal["attack", "control"] | None = None
        if hmac.compare_digest(request.target, attack_target):
            arm = "attack"
        elif hmac.compare_digest(request.target, control_target):
            arm = "control"
        if arm is None:
            await self._write_static_error(writer, HTTPStatus.NOT_FOUND)
            return

        received_ns = time.monotonic_ns()
        status = HTTPStatus.OK if arm == "attack" else HTTPStatus.NOT_FOUND
        payload: dict[str, object]
        if arm == "attack":
            payload = {"schema_version": 1, "marker": self._marker}
        else:
            payload = {"schema_version": 1, "error": "not_found"}

        async with self._hit_lock:
            try:
                responded_ns = await self._write_json(writer, status, payload)
            except Exception:
                self._overflow = True
                raise
            if len(self._hits) >= self.max_hits:
                self._overflow = True
                return
            self._hits.append(
                SsrfOracleHit(
                    schema_version=1,
                    sequence=len(self._hits) + 1,
                    arm=arm,
                    method=request.method,
                    received_monotonic_ns=received_ns,
                    responded_monotonic_ns=responded_ns,
                    status_code=int(status),
                    marker_sha256=(self._marker_sha256 if arm == "attack" else None),
                )
            )

    async def _read_request(self, reader: asyncio.StreamReader) -> _ParsedRequest:
        raw_head = await reader.readuntil(b"\r\n\r\n")
        if len(raw_head) > self.max_header_bytes:
            raise _RequestRejected(HTTPStatus.REQUEST_HEADER_FIELDS_TOO_LARGE)
        without_crlf = raw_head.replace(b"\r\n", b"")
        if b"\r" in without_crlf or b"\n" in without_crlf:
            raise _RequestRejected(HTTPStatus.BAD_REQUEST)

        lines = raw_head[:-4].split(b"\r\n")
        if not lines:
            raise _RequestRejected(HTTPStatus.BAD_REQUEST)
        request_parts = lines[0].split(b" ")
        if len(request_parts) != 3 or any(not part for part in request_parts):
            raise _RequestRejected(HTTPStatus.BAD_REQUEST)
        method_raw, target_raw, version = request_parts
        if (
            version not in {b"HTTP/1.0", b"HTTP/1.1"}
            or _TOKEN_RE.fullmatch(method_raw) is None
        ):
            raise _RequestRejected(HTTPStatus.BAD_REQUEST)
        try:
            method = method_raw.decode("ascii")
            target = target_raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise _RequestRejected(HTTPStatus.BAD_REQUEST) from exc
        if method != method.upper() or method not in ALLOWED_ORACLE_METHODS:
            raise _RequestRejected(HTTPStatus.METHOD_NOT_ALLOWED)
        if (
            not target.startswith("/")
            or target.startswith("//")
            or len(target_raw) > self.max_header_bytes // 2
        ):
            raise _RequestRejected(HTTPStatus.BAD_REQUEST)

        headers: dict[str, list[str]] = {}
        for raw_line in lines[1:]:
            if not raw_line or raw_line[:1] in {b" ", b"\t"}:
                raise _RequestRejected(HTTPStatus.BAD_REQUEST)
            raw_name, separator, raw_value = raw_line.partition(b":")
            if not separator or _TOKEN_RE.fullmatch(raw_name) is None:
                raise _RequestRejected(HTTPStatus.BAD_REQUEST)
            raw_value = raw_value.strip(b" \t")
            if any(byte < 0x20 or byte > 0x7E for byte in raw_value):
                raise _RequestRejected(HTTPStatus.BAD_REQUEST)
            try:
                name = raw_name.decode("ascii").casefold()
                value = raw_value.decode("ascii")
            except UnicodeDecodeError as exc:
                raise _RequestRejected(HTTPStatus.BAD_REQUEST) from exc
            headers.setdefault(name, []).append(value)

        authority = f"{self.advertised_host}:{self.port}"
        host_values = headers.get("host", [])
        if len(host_values) != 1 or not hmac.compare_digest(
            host_values[0].casefold(), authority.casefold()
        ):
            raise _RequestRejected(HTTPStatus.BAD_REQUEST)
        if "transfer-encoding" in headers or "expect" in headers:
            raise _RequestRejected(HTTPStatus.BAD_REQUEST)

        length_values = headers.get("content-length", [])
        if len(length_values) > 1:
            raise _RequestRejected(HTTPStatus.BAD_REQUEST)
        content_length = 0
        if length_values:
            supplied_length = length_values[0]
            if _CONTENT_LENGTH_RE.fullmatch(supplied_length) is None:
                raise _RequestRejected(HTTPStatus.BAD_REQUEST)
            content_length = int(supplied_length)
            if content_length > self.max_body_bytes:
                raise _RequestRejected(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)

        chunks: list[bytes] = []
        remaining = content_length
        while remaining:
            chunk = await reader.readexactly(min(remaining, _READ_CHUNK_LIMIT))
            chunks.append(chunk)
            remaining -= len(chunk)
        return _ParsedRequest(method=method, target=target, body=b"".join(chunks))

    async def _write_static_error(
        self,
        writer: asyncio.StreamWriter,
        status: int | HTTPStatus,
    ) -> int:
        return await self._write_json(
            writer,
            status,
            {"schema_version": 1, "error": "not_found"},
        )

    async def _write_json(
        self,
        writer: asyncio.StreamWriter,
        status: int | HTTPStatus,
        payload: dict[str, object],
    ) -> int:
        normalized_status = HTTPStatus(int(status))
        body = json.dumps(
            payload,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        head = (
            f"HTTP/1.1 {int(normalized_status)} {normalized_status.phrase}\r\n"
            "Content-Type: application/json; charset=utf-8\r\n"
            "Cache-Control: no-store\r\n"
            "X-Content-Type-Options: nosniff\r\n"
            "Connection: close\r\n"
            f"Content-Length: {len(body)}\r\n"
            "\r\n"
        ).encode("ascii")
        writer.write(head + body)
        async with asyncio.timeout(self.write_timeout_s):
            await writer.drain()
        return time.monotonic_ns()


__all__ = [
    "ALLOWED_ORACLE_METHODS",
    "LOCAL_RESOURCE_SSRF_DIRECTORY",
    "LOCAL_RESOURCE_SSRF_FILE_MODE",
    "LOCAL_RESOURCE_SSRF_MODE",
    "SSRF_ATTACK_URL_ENV",
    "SSRF_CONTROL_URL_ENV",
    "LocalResourceSsrfOracle",
    "LocalResourceSsrfProvisioningAttestation",
    "LocalResourceSsrfSnapshot",
    "LocalResourceSsrfVerificationAttestation",
    "SsrfOracleHit",
    "SsrfOracleServer",
    "SsrfOracleSnapshot",
]
