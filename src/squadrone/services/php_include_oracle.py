"""Parent-owned state for trusted PHP local-file-include verification.

The generated PoC receives two stable opaque PHP paths and a fixed receipt
header name.  Only the attack path is provisioned.  Its fresh marker and exact
PHP contents remain private to the verifier parent, while the sibling control
path must remain absent.  Immutable attestations bind both facts before and
after one child execution.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import time
from dataclasses import dataclass
from typing import Final, Literal, TypeGuard


PHP_INCLUDE_ORACLE_MODE: Final[Literal["php_include"]] = "php_include"
PHP_INCLUDE_ORACLE_DIRECTORY: Final = "/var/lib/squadrone/php-include"
PHP_INCLUDE_ORACLE_FILE_MODE: Final = 0o444
PHP_INCLUDE_ORACLE_HEADER_NAME: Final = "X-Squadrone-PHP-Include-Receipt"

_CAPABILITY_RE = re.compile(r"[0-9a-f]{64}\Z")
_BASENAME_RE = re.compile(r"[0-9a-f]{64}\.php\Z")
_MARKER_RE = re.compile(r"SQUADRONE_PHP_INCLUDE_[0-9a-f]{64}\Z")

_ATTESTATION_PHASES = frozenset({"provisioning", "verification"})
_ATTESTATION_FIELDS = frozenset(
    {
        "after_monotonic_ns",
        "attack_content_sha256",
        "attack_content_size_bytes",
        "attack_file_mode",
        "attack_is_regular_file",
        "attack_is_symlink",
        "attack_link_count",
        "attack_owner_gid",
        "attack_owner_uid",
        "attack_resource_path",
        "control_lstat_exists",
        "control_resource_path",
        "execution_finished_monotonic_ns",
        "execution_started_monotonic_ns",
        "finished_monotonic_ns",
        "generation_id",
        "host_attack_content_sha256",
        "host_attack_content_size_bytes",
        "host_attack_device",
        "host_attack_file_mode",
        "host_attack_inode",
        "host_attack_is_regular_file",
        "host_attack_is_symlink",
        "host_attack_link_count",
        "host_attack_owner",
        "host_control_lstat_exists",
        "host_identity_sha256",
        "host_measured_monotonic_ns",
        "host_measurement",
        "measured_monotonic_ns",
        "started_monotonic_ns",
    }
)
_ATTESTATION_CATEGORIES = frozenset(
    {
        "future",
        "invalid_shape",
        "mismatch",
        "out_of_order",
        "unsafe_state",
    }
)


class PhpIncludeAttestationError(ValueError):
    """Expose one fixed, secret-free rejected attestation invariant.

    The exception deliberately carries no observed or expected value. Callers
    may persist ``reason`` because every possible value comes from closed
    field/category allowlists.
    """

    def __init__(self, phase: str, field: str, category: str) -> None:
        if (
            phase not in _ATTESTATION_PHASES
            or field not in _ATTESTATION_FIELDS
            or category not in _ATTESTATION_CATEGORIES
        ):
            raise ValueError("invalid PHP include attestation error category")
        self.phase = phase
        self.field = field
        self.category = category
        self.reason = f"{field}_{category}"
        super().__init__(f"invalid PHP include {phase} attestation")


@dataclass(frozen=True, slots=True, repr=False)
class PhpIncludeHostFilesystemMeasurement:
    """Raw parent-only host measurement; never serialize this object."""

    attack_content_sha256: str
    attack_content_size_bytes: int
    attack_owner_uid: int
    attack_owner_gid: int
    attack_file_mode: int
    attack_link_count: int
    attack_is_regular_file: bool
    attack_is_symlink: bool
    control_lstat_exists: bool
    attack_device: int
    attack_inode: int
    measured_monotonic_ns: int

    def __repr__(self) -> str:
        return "PhpIncludeHostFilesystemMeasurement(<redacted>)"


@dataclass(frozen=True, slots=True)
class PhpIncludeHostFilesystemAttestation:
    """Sanitized host authority for one exact parent-owned canary inode."""

    schema_version: int
    host_identity_sha256: str
    attack_content_sha256: str
    attack_content_size_bytes: int
    attack_owner_matches_verifier: bool
    attack_file_mode: int
    attack_link_count: int
    attack_is_regular_file: bool
    attack_is_symlink: bool
    control_lstat_exists: bool
    measured_monotonic_ns: int

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "host_identity_sha256": self.host_identity_sha256,
            "attack_content_sha256": self.attack_content_sha256,
            "attack_content_size_bytes": self.attack_content_size_bytes,
            "attack_owner_matches_verifier": self.attack_owner_matches_verifier,
            "attack_file_mode": self.attack_file_mode,
            "attack_link_count": self.attack_link_count,
            "attack_is_regular_file": self.attack_is_regular_file,
            "attack_is_symlink": self.attack_is_symlink,
            "control_lstat_exists": self.control_lstat_exists,
            "measured_monotonic_ns": self.measured_monotonic_ns,
        }


@dataclass(frozen=True, slots=True)
class PhpIncludeFilesystemAttestation:
    """Exact digest and metadata state for both oracle paths at one instant."""

    schema_version: int
    attack_path_sha256: str
    control_path_sha256: str
    attack_content_sha256: str
    attack_content_size_bytes: int
    attack_owner_uid: int
    attack_owner_gid: int
    attack_file_mode: int
    attack_link_count: int
    attack_is_regular_file: bool
    attack_is_symlink: bool
    control_lstat_exists: bool
    measured_monotonic_ns: int

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "attack_path_sha256": self.attack_path_sha256,
            "control_path_sha256": self.control_path_sha256,
            "attack_content_sha256": self.attack_content_sha256,
            "attack_content_size_bytes": self.attack_content_size_bytes,
            "attack_owner_uid": self.attack_owner_uid,
            "attack_owner_gid": self.attack_owner_gid,
            "attack_file_mode": self.attack_file_mode,
            "attack_link_count": self.attack_link_count,
            "attack_is_regular_file": self.attack_is_regular_file,
            "attack_is_symlink": self.attack_is_symlink,
            "control_lstat_exists": self.control_lstat_exists,
            "measured_monotonic_ns": self.measured_monotonic_ns,
        }


@dataclass(frozen=True, slots=True)
class PhpIncludeProvisioningAttestation:
    """Immutable parent evidence for one provisioned attack canary."""

    schema_version: int
    generation_id: str
    attack_basename_sha256: str
    control_basename_sha256: str
    header_name_sha256: str
    marker_sha256: str
    started_monotonic_ns: int
    filesystem: PhpIncludeFilesystemAttestation
    host_filesystem: PhpIncludeHostFilesystemAttestation

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "generation_id": self.generation_id,
            "attack_basename_sha256": self.attack_basename_sha256,
            "control_basename_sha256": self.control_basename_sha256,
            "header_name_sha256": self.header_name_sha256,
            "marker_sha256": self.marker_sha256,
            "started_monotonic_ns": self.started_monotonic_ns,
            "filesystem": self.filesystem.as_dict(),
            "host_filesystem": self.host_filesystem.as_dict(),
        }


@dataclass(frozen=True, slots=True)
class PhpIncludeVerificationAttestation:
    """Immutable evidence that exact oracle state bounded one execution."""

    schema_version: int
    generation_id: str
    before: PhpIncludeFilesystemAttestation
    host_before: PhpIncludeHostFilesystemAttestation
    execution_started_monotonic_ns: int
    execution_finished_monotonic_ns: int
    after: PhpIncludeFilesystemAttestation
    host_after: PhpIncludeHostFilesystemAttestation

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "generation_id": self.generation_id,
            "before": self.before.as_dict(),
            "host_before": self.host_before.as_dict(),
            "execution_started_monotonic_ns": self.execution_started_monotonic_ns,
            "execution_finished_monotonic_ns": self.execution_finished_monotonic_ns,
            "after": self.after.as_dict(),
            "host_after": self.host_after.as_dict(),
        }


@dataclass(frozen=True, slots=True)
class PhpIncludeOracleSnapshot:
    """Complete marker-free parent evidence for one verified generation."""

    schema_version: int
    mode: Literal["php_include"]
    generation_id: str
    provisioning: PhpIncludeProvisioningAttestation
    verification: PhpIncludeVerificationAttestation

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "mode": self.mode,
            "generation_id": self.generation_id,
            "provisioning": self.provisioning.as_dict(),
            "verification": self.verification.as_dict(),
        }


class PhpIncludeOracle:
    """Single-generation state machine for a trusted PHP include canary.

    The two public paths remain stable for the lifetime of the instance.
    ``begin_generation`` rotates only the private marker and canary contents,
    and cannot rotate again until the begun generation has been provisioned and
    verified.  Callers provision the attack file through the trusted parent,
    leave the control sibling absent, and report both host-authoritative and
    container-view measurements through the attestation methods.
    """

    def __init__(self) -> None:
        self._issued_private_values: set[str] = set()
        self._host_identity_hmac_key = secrets.token_bytes(32)
        self._verifier_owner_uid = _effective_owner_id("uid")
        self._verifier_owner_gid = _effective_owner_id("gid")
        self._attack_capability = self._fresh_hex()
        self._control_capability = self._fresh_hex()
        self._attack_basename = f"{self._attack_capability}.php"
        self._control_basename = f"{self._control_capability}.php"
        self._attack_path = f"{PHP_INCLUDE_ORACLE_DIRECTORY}/{self._attack_basename}"
        self._control_path = f"{PHP_INCLUDE_ORACLE_DIRECTORY}/{self._control_basename}"
        self._attack_path_sha256 = _sha256_ascii(self._attack_path)
        self._control_path_sha256 = _sha256_ascii(self._control_path)
        self._attack_basename_sha256 = _sha256_ascii(self._attack_basename)
        self._control_basename_sha256 = _sha256_ascii(self._control_basename)
        self._header_name_sha256 = _sha256_ascii(PHP_INCLUDE_ORACLE_HEADER_NAME)
        self._generation_id = ""
        self._marker = ""
        self._marker_sha256 = ""
        self._attack_content = b""
        self._attack_content_sha256 = ""
        self._generation_started_monotonic_ns = 0
        self._host_identity_sha256 = ""
        self._provisioning: PhpIncludeProvisioningAttestation | None = None
        self._verification: PhpIncludeVerificationAttestation | None = None
        self._validate_public_contract()

    @property
    def attack_basename(self) -> str:
        self._validate_public_contract()
        return self._attack_basename

    @property
    def control_basename(self) -> str:
        self._validate_public_contract()
        return self._control_basename

    @property
    def attack_path(self) -> str:
        self._validate_public_contract()
        return self._attack_path

    @property
    def control_path(self) -> str:
        self._validate_public_contract()
        return self._control_path

    @property
    def header_name(self) -> str:
        self._validate_public_contract()
        return PHP_INCLUDE_ORACLE_HEADER_NAME

    @property
    def generation_id(self) -> str:
        self._require_active_generation()
        return self._generation_id

    @property
    def private_marker(self) -> str:
        self._require_active_generation()
        return self._marker

    @property
    def private_attack_content(self) -> bytes:
        """Return the exact parent-only PHP canary bytes for provisioning."""
        self._require_active_generation()
        return self._attack_content

    def public_context(self) -> dict[str, str]:
        """Return the complete and only child-facing PHP include context."""
        self._validate_public_contract()
        return {
            "attack_path": self._attack_path,
            "control_path": self._control_path,
            "attack_basename": self._attack_basename,
            "control_basename": self._control_basename,
            "header_name": PHP_INCLUDE_ORACLE_HEADER_NAME,
        }

    def begin_generation(self) -> str:
        """Begin one fresh provision-and-verify lifecycle."""
        self._validate_public_contract()
        if type(self._generation_id) is not str:
            raise RuntimeError("PHP include oracle lifecycle state is invalid")
        if self._generation_id:
            if self._provisioning is None or self._verification is None:
                raise RuntimeError(
                    "cannot rotate an unfinished PHP include oracle generation"
                )
            self._validated_snapshot()
        elif self._provisioning is not None or self._verification is not None:
            raise RuntimeError("PHP include oracle lifecycle state is invalid")

        marker = "SQUADRONE_PHP_INCLUDE_" + self._fresh_hex()
        generation_id = self._fresh_hex()
        if (
            _MARKER_RE.fullmatch(marker) is None
            or _CAPABILITY_RE.fullmatch(generation_id) is None
        ):
            raise RuntimeError("failed to generate private PHP include values")
        attack_content = _render_attack_canary(marker)
        self._marker = marker
        self._marker_sha256 = _sha256_ascii(marker)
        self._attack_content = attack_content
        self._attack_content_sha256 = hashlib.sha256(attack_content).hexdigest()
        self._generation_id = generation_id
        self._generation_started_monotonic_ns = time.monotonic_ns()
        self._host_identity_sha256 = ""
        self._provisioning = None
        self._verification = None
        return generation_id

    def attest_provisioning(
        self,
        *,
        generation_id: str,
        attack_resource_path: str,
        control_resource_path: str,
        attack_content_sha256: str,
        attack_content_size_bytes: int,
        attack_owner_uid: int,
        attack_owner_gid: int,
        attack_file_mode: int,
        attack_link_count: int,
        attack_is_regular_file: bool,
        attack_is_symlink: bool,
        control_lstat_exists: bool,
        host_measurement: PhpIncludeHostFilesystemMeasurement,
        started_monotonic_ns: int,
        finished_monotonic_ns: int,
    ) -> PhpIncludeProvisioningAttestation:
        """Bind exact verifier-owned provisioning and control nonexistence."""
        self._require_active_generation()
        if self._provisioning is not None:
            raise RuntimeError("PHP include oracle canary is already attested")
        phase = "provisioning"
        self._validate_generation_and_paths(
            generation_id,
            attack_resource_path,
            control_resource_path,
            phase=phase,
        )
        self._validated_monotonic_ns(
            started_monotonic_ns, phase, "started_monotonic_ns"
        )
        self._validated_monotonic_ns(
            finished_monotonic_ns,
            phase,
            "finished_monotonic_ns",
        )
        if started_monotonic_ns < self._generation_started_monotonic_ns:
            raise PhpIncludeAttestationError(
                phase,
                "started_monotonic_ns",
                "out_of_order",
            )
        if finished_monotonic_ns < started_monotonic_ns:
            raise PhpIncludeAttestationError(
                phase,
                "finished_monotonic_ns",
                "out_of_order",
            )
        if finished_monotonic_ns > time.monotonic_ns():
            raise PhpIncludeAttestationError(
                phase,
                "finished_monotonic_ns",
                "future",
            )

        filesystem = self._new_filesystem_attestation(
            attack_content_sha256=attack_content_sha256,
            attack_content_size_bytes=attack_content_size_bytes,
            attack_owner_uid=attack_owner_uid,
            attack_owner_gid=attack_owner_gid,
            attack_file_mode=attack_file_mode,
            attack_link_count=attack_link_count,
            attack_is_regular_file=attack_is_regular_file,
            attack_is_symlink=attack_is_symlink,
            control_lstat_exists=control_lstat_exists,
            measured_monotonic_ns=finished_monotonic_ns,
            phase=phase,
        )
        host_filesystem = self._new_host_filesystem_attestation(
            host_measurement,
            phase=phase,
        )
        if host_filesystem.measured_monotonic_ns < started_monotonic_ns:
            raise PhpIncludeAttestationError(
                phase,
                "host_measured_monotonic_ns",
                "out_of_order",
            )
        if host_filesystem.measured_monotonic_ns > finished_monotonic_ns:
            raise PhpIncludeAttestationError(
                phase,
                "host_measured_monotonic_ns",
                "out_of_order",
            )
        attestation = PhpIncludeProvisioningAttestation(
            schema_version=1,
            generation_id=self._generation_id,
            attack_basename_sha256=self._attack_basename_sha256,
            control_basename_sha256=self._control_basename_sha256,
            header_name_sha256=self._header_name_sha256,
            marker_sha256=self._marker_sha256,
            started_monotonic_ns=started_monotonic_ns,
            filesystem=filesystem,
            host_filesystem=host_filesystem,
        )
        self._validate_provisioning(
            attestation,
            expected_host_identity_sha256=host_filesystem.host_identity_sha256,
        )
        self._host_identity_sha256 = host_filesystem.host_identity_sha256
        self._provisioning = attestation
        return attestation

    def attest_verification(
        self,
        *,
        generation_id: str,
        attack_resource_path: str,
        control_resource_path: str,
        after_attack_content_sha256: str,
        after_attack_content_size_bytes: int,
        after_attack_owner_uid: int,
        after_attack_owner_gid: int,
        after_attack_file_mode: int,
        after_attack_link_count: int,
        after_attack_is_regular_file: bool,
        after_attack_is_symlink: bool,
        after_control_lstat_exists: bool,
        after_host_measurement: PhpIncludeHostFilesystemMeasurement,
        execution_started_monotonic_ns: int,
        execution_finished_monotonic_ns: int,
        after_monotonic_ns: int,
    ) -> PhpIncludeOracleSnapshot:
        """Finalize evidence that exact oracle state bounded one execution."""
        self._require_active_generation()
        if self._provisioning is None:
            raise RuntimeError("PHP include oracle canary is not provisioned")
        if self._verification is not None:
            raise RuntimeError("PHP include oracle generation is already verified")
        self._validate_provisioning(self._provisioning)
        phase = "verification"
        self._validate_generation_and_paths(
            generation_id,
            attack_resource_path,
            control_resource_path,
            phase=phase,
        )
        self._validated_monotonic_ns(
            execution_started_monotonic_ns,
            phase,
            "execution_started_monotonic_ns",
        )
        self._validated_monotonic_ns(
            execution_finished_monotonic_ns,
            phase,
            "execution_finished_monotonic_ns",
        )
        self._validated_monotonic_ns(
            after_monotonic_ns,
            phase,
            "after_monotonic_ns",
        )
        if (
            execution_started_monotonic_ns
            < self._provisioning.filesystem.measured_monotonic_ns
        ):
            raise PhpIncludeAttestationError(
                phase,
                "execution_started_monotonic_ns",
                "out_of_order",
            )
        if execution_finished_monotonic_ns < execution_started_monotonic_ns:
            raise PhpIncludeAttestationError(
                phase,
                "execution_finished_monotonic_ns",
                "out_of_order",
            )
        if after_monotonic_ns < execution_finished_monotonic_ns:
            raise PhpIncludeAttestationError(
                phase,
                "after_monotonic_ns",
                "out_of_order",
            )
        if after_monotonic_ns > time.monotonic_ns():
            raise PhpIncludeAttestationError(
                phase,
                "after_monotonic_ns",
                "future",
            )

        after = self._new_filesystem_attestation(
            attack_content_sha256=after_attack_content_sha256,
            attack_content_size_bytes=after_attack_content_size_bytes,
            attack_owner_uid=after_attack_owner_uid,
            attack_owner_gid=after_attack_owner_gid,
            attack_file_mode=after_attack_file_mode,
            attack_link_count=after_attack_link_count,
            attack_is_regular_file=after_attack_is_regular_file,
            attack_is_symlink=after_attack_is_symlink,
            control_lstat_exists=after_control_lstat_exists,
            measured_monotonic_ns=after_monotonic_ns,
            phase=phase,
        )
        host_after = self._new_host_filesystem_attestation(
            after_host_measurement,
            phase=phase,
            expected_identity_sha256=self._host_identity_sha256,
        )
        if host_after.measured_monotonic_ns < execution_finished_monotonic_ns:
            raise PhpIncludeAttestationError(
                phase,
                "host_measured_monotonic_ns",
                "out_of_order",
            )
        if host_after.measured_monotonic_ns > after_monotonic_ns:
            raise PhpIncludeAttestationError(
                phase,
                "host_measured_monotonic_ns",
                "out_of_order",
            )
        verification = PhpIncludeVerificationAttestation(
            schema_version=1,
            generation_id=self._generation_id,
            before=self._provisioning.filesystem,
            host_before=self._provisioning.host_filesystem,
            execution_started_monotonic_ns=execution_started_monotonic_ns,
            execution_finished_monotonic_ns=execution_finished_monotonic_ns,
            after=after,
            host_after=host_after,
        )
        self._validate_verification(verification, self._provisioning)
        self._verification = verification
        return self._validated_snapshot()

    def snapshot(self) -> PhpIncludeOracleSnapshot:
        """Return complete evidence, failing closed until verification finishes."""
        return self._validated_snapshot()

    def _fresh_hex(self) -> str:
        while True:
            value = secrets.token_hex(32)
            if value not in self._issued_private_values:
                self._issued_private_values.add(value)
                return value

    def _validate_generation_and_paths(
        self,
        generation_id: object,
        attack_resource_path: object,
        control_resource_path: object,
        *,
        phase: str,
    ) -> None:
        if (
            type(generation_id) is not str
            or _CAPABILITY_RE.fullmatch(generation_id) is None
        ):
            raise PhpIncludeAttestationError(phase, "generation_id", "invalid_shape")
        if not hmac.compare_digest(generation_id, self._generation_id):
            raise PhpIncludeAttestationError(phase, "generation_id", "mismatch")
        if type(attack_resource_path) is not str:
            raise PhpIncludeAttestationError(
                phase,
                "attack_resource_path",
                "invalid_shape",
            )
        if not hmac.compare_digest(attack_resource_path, self._attack_path):
            raise PhpIncludeAttestationError(
                phase,
                "attack_resource_path",
                "mismatch",
            )
        if type(control_resource_path) is not str:
            raise PhpIncludeAttestationError(
                phase,
                "control_resource_path",
                "invalid_shape",
            )
        if not hmac.compare_digest(control_resource_path, self._control_path):
            raise PhpIncludeAttestationError(
                phase,
                "control_resource_path",
                "mismatch",
            )

    @staticmethod
    def _validated_monotonic_ns(value: object, phase: str, field: str) -> int:
        if not _is_monotonic_ns(value):
            raise PhpIncludeAttestationError(phase, field, "invalid_shape")
        return value

    def _new_filesystem_attestation(
        self,
        *,
        attack_content_sha256: object,
        attack_content_size_bytes: object,
        attack_owner_uid: object,
        attack_owner_gid: object,
        attack_file_mode: object,
        attack_link_count: object,
        attack_is_regular_file: object,
        attack_is_symlink: object,
        control_lstat_exists: object,
        measured_monotonic_ns: object,
        phase: str,
    ) -> PhpIncludeFilesystemAttestation:
        if not _is_sha256(attack_content_sha256):
            raise PhpIncludeAttestationError(
                phase,
                "attack_content_sha256",
                "invalid_shape",
            )
        if not hmac.compare_digest(
            attack_content_sha256,
            self._attack_content_sha256,
        ):
            raise PhpIncludeAttestationError(
                phase,
                "attack_content_sha256",
                "mismatch",
            )
        content_size_bytes = self._validated_exact_int(
            attack_content_size_bytes,
            len(self._attack_content),
            phase,
            "attack_content_size_bytes",
        )
        owner_uid = self._validated_nonnegative_int(
            attack_owner_uid,
            phase,
            "attack_owner_uid",
        )
        owner_gid = self._validated_nonnegative_int(
            attack_owner_gid,
            phase,
            "attack_owner_gid",
        )
        file_mode = self._validated_exact_int(
            attack_file_mode,
            PHP_INCLUDE_ORACLE_FILE_MODE,
            phase,
            "attack_file_mode",
        )
        link_count = self._validated_exact_int(
            attack_link_count,
            1,
            phase,
            "attack_link_count",
        )
        self._validate_safe_bool(
            attack_is_regular_file,
            True,
            phase,
            "attack_is_regular_file",
        )
        self._validate_safe_bool(
            attack_is_symlink,
            False,
            phase,
            "attack_is_symlink",
        )
        self._validate_safe_bool(
            control_lstat_exists,
            False,
            phase,
            "control_lstat_exists",
        )
        measurement_ns = self._validated_monotonic_ns(
            measured_monotonic_ns,
            phase,
            "measured_monotonic_ns",
        )
        return PhpIncludeFilesystemAttestation(
            schema_version=1,
            attack_path_sha256=self._attack_path_sha256,
            control_path_sha256=self._control_path_sha256,
            attack_content_sha256=attack_content_sha256,
            attack_content_size_bytes=content_size_bytes,
            attack_owner_uid=owner_uid,
            attack_owner_gid=owner_gid,
            attack_file_mode=file_mode,
            attack_link_count=link_count,
            attack_is_regular_file=True,
            attack_is_symlink=False,
            control_lstat_exists=False,
            measured_monotonic_ns=measurement_ns,
        )

    def _new_host_filesystem_attestation(
        self,
        measurement: object,
        *,
        phase: str,
        expected_identity_sha256: str | None = None,
    ) -> PhpIncludeHostFilesystemAttestation:
        """Validate raw host authority and return only safe, opaque evidence."""
        if type(measurement) is not PhpIncludeHostFilesystemMeasurement:
            raise PhpIncludeAttestationError(
                phase,
                "host_measurement",
                "invalid_shape",
            )
        if not _is_sha256(measurement.attack_content_sha256):
            raise PhpIncludeAttestationError(
                phase,
                "host_attack_content_sha256",
                "invalid_shape",
            )
        if not hmac.compare_digest(
            measurement.attack_content_sha256,
            self._attack_content_sha256,
        ):
            raise PhpIncludeAttestationError(
                phase,
                "host_attack_content_sha256",
                "mismatch",
            )
        content_size_bytes = self._validated_exact_int(
            measurement.attack_content_size_bytes,
            len(self._attack_content),
            phase,
            "host_attack_content_size_bytes",
        )
        self._validated_host_owner(measurement, phase=phase)
        file_mode = self._validated_exact_int(
            measurement.attack_file_mode,
            PHP_INCLUDE_ORACLE_FILE_MODE,
            phase,
            "host_attack_file_mode",
        )
        link_count = self._validated_exact_int(
            measurement.attack_link_count,
            1,
            phase,
            "host_attack_link_count",
        )
        self._validate_safe_bool(
            measurement.attack_is_regular_file,
            True,
            phase,
            "host_attack_is_regular_file",
        )
        self._validate_safe_bool(
            measurement.attack_is_symlink,
            False,
            phase,
            "host_attack_is_symlink",
        )
        self._validate_safe_bool(
            measurement.control_lstat_exists,
            False,
            phase,
            "host_control_lstat_exists",
        )
        device = self._validated_nonnegative_int(
            measurement.attack_device,
            phase,
            "host_attack_device",
        )
        inode = self._validated_positive_int(
            measurement.attack_inode,
            phase,
            "host_attack_inode",
        )
        measurement_ns = self._validated_monotonic_ns(
            measurement.measured_monotonic_ns,
            phase,
            "host_measured_monotonic_ns",
        )
        if measurement_ns > time.monotonic_ns():
            raise PhpIncludeAttestationError(
                phase,
                "host_measured_monotonic_ns",
                "future",
            )
        identity_sha256 = self._host_identity_digest(device=device, inode=inode)
        if expected_identity_sha256 is not None:
            if not _is_sha256(expected_identity_sha256):
                raise RuntimeError("PHP include host identity state is malformed")
            if not hmac.compare_digest(identity_sha256, expected_identity_sha256):
                raise PhpIncludeAttestationError(
                    phase,
                    "host_identity_sha256",
                    "mismatch",
                )
        return PhpIncludeHostFilesystemAttestation(
            schema_version=1,
            host_identity_sha256=identity_sha256,
            attack_content_sha256=measurement.attack_content_sha256,
            attack_content_size_bytes=content_size_bytes,
            attack_owner_matches_verifier=True,
            attack_file_mode=file_mode,
            attack_link_count=link_count,
            attack_is_regular_file=True,
            attack_is_symlink=False,
            control_lstat_exists=False,
            measured_monotonic_ns=measurement_ns,
        )

    def _validated_host_owner(
        self,
        measurement: PhpIncludeHostFilesystemMeasurement,
        *,
        phase: str,
    ) -> None:
        uid = measurement.attack_owner_uid
        gid = measurement.attack_owner_gid
        if type(uid) is not int or type(gid) is not int or uid < 0 or gid < 0:
            raise PhpIncludeAttestationError(
                phase,
                "host_attack_owner",
                "invalid_shape",
            )
        if uid != self._verifier_owner_uid or gid != self._verifier_owner_gid:
            raise PhpIncludeAttestationError(
                phase,
                "host_attack_owner",
                "mismatch",
            )

    def _host_identity_digest(self, *, device: int, inode: int) -> str:
        identity = "\x00".join(
            (
                "squadrone-php-include-host-identity-v1",
                self._generation_id,
                self._attack_path_sha256,
                self._control_path_sha256,
                str(device),
                str(inode),
            )
        ).encode("ascii")
        return hmac.new(
            self._host_identity_hmac_key,
            identity,
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def _validated_exact_int(
        value: object,
        expected: int,
        phase: str,
        field: str,
    ) -> int:
        if type(value) is not int:
            raise PhpIncludeAttestationError(phase, field, "invalid_shape")
        if value != expected:
            raise PhpIncludeAttestationError(phase, field, "mismatch")
        return value

    @staticmethod
    def _validated_nonnegative_int(
        value: object,
        phase: str,
        field: str,
    ) -> int:
        if type(value) is not int or value < 0:
            raise PhpIncludeAttestationError(phase, field, "invalid_shape")
        return value

    @staticmethod
    def _validated_positive_int(
        value: object,
        phase: str,
        field: str,
    ) -> int:
        if type(value) is not int or value < 1:
            raise PhpIncludeAttestationError(phase, field, "invalid_shape")
        return value

    @staticmethod
    def _validate_safe_bool(
        value: object,
        expected: bool,
        phase: str,
        field: str,
    ) -> None:
        if type(value) is not bool:
            raise PhpIncludeAttestationError(phase, field, "invalid_shape")
        if value is not expected:
            raise PhpIncludeAttestationError(phase, field, "unsafe_state")

    def _require_active_generation(self) -> None:
        self._validate_public_contract()
        if (
            type(self._generation_id) is not str
            or _CAPABILITY_RE.fullmatch(self._generation_id) is None
            or type(self._marker) is not str
            or _MARKER_RE.fullmatch(self._marker) is None
            or not _is_sha256(self._marker_sha256)
            or not hmac.compare_digest(self._marker_sha256, _sha256_ascii(self._marker))
            or type(self._attack_content) is not bytes
            or not self._attack_content
            or not hmac.compare_digest(
                self._attack_content, _render_attack_canary(self._marker)
            )
            or not _is_sha256(self._attack_content_sha256)
            or not hmac.compare_digest(
                self._attack_content_sha256,
                hashlib.sha256(self._attack_content).hexdigest(),
            )
            or not _is_monotonic_ns(self._generation_started_monotonic_ns)
            or type(self._host_identity_sha256) is not str
            or (
                bool(self._host_identity_sha256)
                and not _is_sha256(self._host_identity_sha256)
            )
        ):
            raise RuntimeError("PHP include oracle generation state is invalid")

    def _validate_public_contract(self) -> None:
        expected_attack_basename = f"{self._attack_capability}.php"
        expected_control_basename = f"{self._control_capability}.php"
        expected_attack_path = (
            f"{PHP_INCLUDE_ORACLE_DIRECTORY}/{expected_attack_basename}"
        )
        expected_control_path = (
            f"{PHP_INCLUDE_ORACLE_DIRECTORY}/{expected_control_basename}"
        )
        if (
            type(self._host_identity_hmac_key) is not bytes
            or len(self._host_identity_hmac_key) != 32
            or type(self._verifier_owner_uid) is not int
            or self._verifier_owner_uid < 0
            or type(self._verifier_owner_gid) is not int
            or self._verifier_owner_gid < 0
            or type(self._attack_capability) is not str
            or _CAPABILITY_RE.fullmatch(self._attack_capability) is None
            or type(self._control_capability) is not str
            or _CAPABILITY_RE.fullmatch(self._control_capability) is None
            or hmac.compare_digest(self._attack_capability, self._control_capability)
            or type(self._attack_basename) is not str
            or _BASENAME_RE.fullmatch(self._attack_basename) is None
            or type(self._control_basename) is not str
            or _BASENAME_RE.fullmatch(self._control_basename) is None
            or type(self._attack_path) is not str
            or type(self._control_path) is not str
            or self._attack_basename != expected_attack_basename
            or self._control_basename != expected_control_basename
            or self._attack_path != expected_attack_path
            or self._control_path != expected_control_path
            or hmac.compare_digest(self._attack_path, self._control_path)
            or not _is_sha256(self._attack_path_sha256)
            or not hmac.compare_digest(
                self._attack_path_sha256, _sha256_ascii(expected_attack_path)
            )
            or not _is_sha256(self._control_path_sha256)
            or not hmac.compare_digest(
                self._control_path_sha256, _sha256_ascii(expected_control_path)
            )
            or not _is_sha256(self._attack_basename_sha256)
            or not hmac.compare_digest(
                self._attack_basename_sha256,
                _sha256_ascii(expected_attack_basename),
            )
            or not _is_sha256(self._control_basename_sha256)
            or not hmac.compare_digest(
                self._control_basename_sha256,
                _sha256_ascii(expected_control_basename),
            )
            or not _is_sha256(self._header_name_sha256)
            or not hmac.compare_digest(
                self._header_name_sha256,
                _sha256_ascii(PHP_INCLUDE_ORACLE_HEADER_NAME),
            )
        ):
            raise RuntimeError("PHP include oracle public path state is invalid")

    def _validate_filesystem(
        self,
        value: object,
        *,
        malformed_message: str,
    ) -> None:
        self._require_active_generation()
        if type(value) is not PhpIncludeFilesystemAttestation or (
            type(value.schema_version) is not int
            or value.schema_version != 1
            or not _is_sha256(value.attack_path_sha256)
            or not hmac.compare_digest(
                value.attack_path_sha256, self._attack_path_sha256
            )
            or not _is_sha256(value.control_path_sha256)
            or not hmac.compare_digest(
                value.control_path_sha256, self._control_path_sha256
            )
            or not _is_sha256(value.attack_content_sha256)
            or not hmac.compare_digest(
                value.attack_content_sha256, self._attack_content_sha256
            )
            or type(value.attack_content_size_bytes) is not int
            or value.attack_content_size_bytes != len(self._attack_content)
            or type(value.attack_owner_uid) is not int
            or value.attack_owner_uid < 0
            or type(value.attack_owner_gid) is not int
            or value.attack_owner_gid < 0
            or type(value.attack_file_mode) is not int
            or value.attack_file_mode != PHP_INCLUDE_ORACLE_FILE_MODE
            or type(value.attack_link_count) is not int
            or value.attack_link_count != 1
            or value.attack_is_regular_file is not True
            or value.attack_is_symlink is not False
            or value.control_lstat_exists is not False
            or not _is_monotonic_ns(value.measured_monotonic_ns)
            or value.measured_monotonic_ns > time.monotonic_ns()
        ):
            raise RuntimeError(malformed_message)

    def _validate_host_filesystem(
        self,
        value: object,
        *,
        expected_identity_sha256: str,
        malformed_message: str,
    ) -> None:
        self._require_active_generation()
        if type(value) is not PhpIncludeHostFilesystemAttestation or (
            type(value.schema_version) is not int
            or value.schema_version != 1
            or not _is_sha256(expected_identity_sha256)
            or not _is_sha256(value.host_identity_sha256)
            or not hmac.compare_digest(
                value.host_identity_sha256,
                expected_identity_sha256,
            )
            or not _is_sha256(value.attack_content_sha256)
            or not hmac.compare_digest(
                value.attack_content_sha256,
                self._attack_content_sha256,
            )
            or type(value.attack_content_size_bytes) is not int
            or value.attack_content_size_bytes != len(self._attack_content)
            or value.attack_owner_matches_verifier is not True
            or type(value.attack_file_mode) is not int
            or value.attack_file_mode != PHP_INCLUDE_ORACLE_FILE_MODE
            or type(value.attack_link_count) is not int
            or value.attack_link_count != 1
            or value.attack_is_regular_file is not True
            or value.attack_is_symlink is not False
            or value.control_lstat_exists is not False
            or not _is_monotonic_ns(value.measured_monotonic_ns)
            or value.measured_monotonic_ns > time.monotonic_ns()
        ):
            raise RuntimeError(malformed_message)

    def _validate_provisioning(
        self,
        value: object,
        *,
        expected_host_identity_sha256: str | None = None,
    ) -> None:
        self._require_active_generation()
        host_identity_sha256 = (
            self._host_identity_sha256
            if expected_host_identity_sha256 is None
            else expected_host_identity_sha256
        )
        if type(value) is not PhpIncludeProvisioningAttestation or (
            type(value.schema_version) is not int
            or value.schema_version != 1
            or type(value.generation_id) is not str
            or not hmac.compare_digest(value.generation_id, self._generation_id)
            or not _is_sha256(value.attack_basename_sha256)
            or not hmac.compare_digest(
                value.attack_basename_sha256, self._attack_basename_sha256
            )
            or not _is_sha256(value.control_basename_sha256)
            or not hmac.compare_digest(
                value.control_basename_sha256, self._control_basename_sha256
            )
            or not _is_sha256(value.header_name_sha256)
            or not hmac.compare_digest(
                value.header_name_sha256, self._header_name_sha256
            )
            or not _is_sha256(value.marker_sha256)
            or not hmac.compare_digest(value.marker_sha256, self._marker_sha256)
            or not _is_monotonic_ns(value.started_monotonic_ns)
            or value.started_monotonic_ns < self._generation_started_monotonic_ns
        ):
            raise RuntimeError("PHP include provisioning state is malformed")
        self._validate_filesystem(
            value.filesystem,
            malformed_message="PHP include provisioning state is malformed",
        )
        self._validate_host_filesystem(
            value.host_filesystem,
            expected_identity_sha256=host_identity_sha256,
            malformed_message="PHP include provisioning state is malformed",
        )
        if (
            value.filesystem.measured_monotonic_ns < value.started_monotonic_ns
            or value.host_filesystem.measured_monotonic_ns < value.started_monotonic_ns
            or value.host_filesystem.measured_monotonic_ns
            > value.filesystem.measured_monotonic_ns
        ):
            raise RuntimeError("PHP include provisioning state is malformed")

    def _validate_verification(
        self,
        value: object,
        provisioning: PhpIncludeProvisioningAttestation,
    ) -> None:
        self._validate_provisioning(provisioning)
        if type(value) is not PhpIncludeVerificationAttestation or (
            type(value.schema_version) is not int
            or value.schema_version != 1
            or type(value.generation_id) is not str
            or not hmac.compare_digest(value.generation_id, self._generation_id)
            or value.before != provisioning.filesystem
            or value.host_before != provisioning.host_filesystem
            or not _is_monotonic_ns(value.execution_started_monotonic_ns)
            or value.execution_started_monotonic_ns
            < provisioning.filesystem.measured_monotonic_ns
            or value.execution_started_monotonic_ns
            < provisioning.host_filesystem.measured_monotonic_ns
            or not _is_monotonic_ns(value.execution_finished_monotonic_ns)
            or value.execution_finished_monotonic_ns
            < value.execution_started_monotonic_ns
        ):
            raise RuntimeError("PHP include verification state is malformed")
        self._validate_filesystem(
            value.before,
            malformed_message="PHP include verification state is malformed",
        )
        self._validate_filesystem(
            value.after,
            malformed_message="PHP include verification state is malformed",
        )
        self._validate_host_filesystem(
            value.host_before,
            expected_identity_sha256=self._host_identity_sha256,
            malformed_message="PHP include verification state is malformed",
        )
        self._validate_host_filesystem(
            value.host_after,
            expected_identity_sha256=self._host_identity_sha256,
            malformed_message="PHP include verification state is malformed",
        )
        if (
            value.after.measured_monotonic_ns < value.execution_finished_monotonic_ns
            or value.host_after.measured_monotonic_ns
            < value.execution_finished_monotonic_ns
            or value.host_after.measured_monotonic_ns
            > value.after.measured_monotonic_ns
        ):
            raise RuntimeError("PHP include verification state is malformed")

    def _validated_snapshot(self) -> PhpIncludeOracleSnapshot:
        if self._provisioning is None or self._verification is None:
            raise RuntimeError(
                "PHP include oracle evidence is incomplete or unverified"
            )
        self._validate_provisioning(self._provisioning)
        self._validate_verification(self._verification, self._provisioning)
        return PhpIncludeOracleSnapshot(
            schema_version=1,
            mode=PHP_INCLUDE_ORACLE_MODE,
            generation_id=self._generation_id,
            provisioning=self._provisioning,
            verification=self._verification,
        )


def _render_attack_canary(marker: str) -> bytes:
    if _MARKER_RE.fullmatch(marker) is None:
        raise RuntimeError("invalid private PHP include marker")
    return (
        f"<?php\nheader('{PHP_INCLUDE_ORACLE_HEADER_NAME}: {marker}');\nreturn;\n"
    ).encode("ascii")


def _sha256_ascii(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _is_sha256(value: object) -> TypeGuard[str]:
    return type(value) is str and _CAPABILITY_RE.fullmatch(value) is not None


def _is_monotonic_ns(value: object) -> TypeGuard[int]:
    return type(value) is int and value > 0


def _effective_owner_id(kind: Literal["uid", "gid"]) -> int:
    getter_name = "geteuid" if kind == "uid" else "getegid"
    fallback_name = "getuid" if kind == "uid" else "getgid"
    getter = getattr(os, getter_name, None) or getattr(os, fallback_name, None)
    if getter is None:
        raise RuntimeError("PHP include host owner identity is unavailable")
    value = getter()
    if type(value) is not int or value < 0:
        raise RuntimeError("PHP include host owner identity is invalid")
    return value


__all__ = [
    "PHP_INCLUDE_ORACLE_DIRECTORY",
    "PHP_INCLUDE_ORACLE_FILE_MODE",
    "PHP_INCLUDE_ORACLE_HEADER_NAME",
    "PHP_INCLUDE_ORACLE_MODE",
    "PhpIncludeAttestationError",
    "PhpIncludeFilesystemAttestation",
    "PhpIncludeHostFilesystemAttestation",
    "PhpIncludeHostFilesystemMeasurement",
    "PhpIncludeOracle",
    "PhpIncludeOracleSnapshot",
    "PhpIncludeProvisioningAttestation",
    "PhpIncludeVerificationAttestation",
]
