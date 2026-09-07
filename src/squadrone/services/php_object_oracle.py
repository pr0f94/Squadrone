"""Parent-owned state for trusted PHP object-instantiation verification.

The generated PoC receives only two attempt-scoped, opaque arm tokens.  The
verifier parent resolves those tokens to an exact serialized canary object and
a benign serialized-array control that rotate for each execution.  The
canary's ``__wakeup`` method has no external side effects: it validates a
generation proof and stores a one-shot receipt in PHP process memory for
trusted integration code to consume.

Raw payloads, tokens, proofs, receipt secrets, and receipts are deliberately
kept out of immutable snapshots.  A snapshot contains only hashes, sizes,
closed booleans, and monotonic execution bounds.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import time
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Final, Literal, TypeGuard


PHP_OBJECT_ORACLE_MODE: Final[Literal["php_object"]] = "php_object"
PHP_OBJECT_ORACLE_SCHEMA_VERSION: Final = 1

_CLASS_PREFIX = "SquadroneObjectCanary_"
_CLASS_RE = re.compile(r"SquadroneObjectCanary_[0-9a-f]{32}\Z")
_HEX_64_RE = re.compile(r"[0-9a-f]{64}\Z")
_TOKEN_RE = re.compile(r"sqpobjt1\.[0-9a-f]{64}\Z")
_RECEIPT_RE = re.compile(r"sqpobj1\.[0-9a-f]{64}\.[0-9a-f]{64}\Z")
_PROOF_DOMAIN = b"squadrone-php-object-proof-v1\x00"
_RECEIPT_DOMAIN = b"squadrone-php-object-receipt-v1\x00"
_SECRET_SIZE_BYTES = 32
_BACKTRACE_LIMIT = 64
_MAX_CALLSITE_LINE = 10_000_000
_MAX_CALLSITE_SPAN = 128

_ATTESTATION_FIELDS = frozenset(
    {
        "attack_receipt",
        "attack_token",
        "attested_monotonic_ns",
        "control_receipt",
        "control_token",
        "execution_finished_monotonic_ns",
        "execution_started_monotonic_ns",
        "generation_id",
    }
)
_ATTESTATION_CATEGORIES = frozenset(
    {"future", "invalid_shape", "mismatch", "out_of_order", "unsafe_state"}
)


class PhpObjectAttestationError(ValueError):
    """Secret-free failure for one rejected object-oracle attestation."""

    def __init__(self, field: str, category: str) -> None:
        if field not in _ATTESTATION_FIELDS or category not in _ATTESTATION_CATEGORIES:
            raise ValueError("invalid PHP object attestation error category")
        self.field = field
        self.category = category
        self.reason = f"{field}_{category}"
        super().__init__("invalid PHP object execution attestation")


@dataclass(frozen=True, slots=True, repr=False)
class PhpObjectCallsite:
    """Verifier-derived plugin-relative source identity for sandbox mapping."""

    relative_path: str
    start_line: int
    end_line: int
    source_sha256: str

    def __post_init__(self) -> None:
        if not _is_relative_php_path(self.relative_path):
            raise ValueError("invalid PHP object callsite relative path")
        if not _is_callsite_range(self.start_line, self.end_line):
            raise ValueError("invalid PHP object callsite line range")
        if not _is_hex_64(self.source_sha256):
            raise ValueError("invalid PHP object callsite source digest")

    def __repr__(self) -> str:
        return "PhpObjectCallsite(<redacted>)"


@dataclass(frozen=True, slots=True)
class PhpObjectExecutionAttestation:
    """Sanitized immutable evidence for one attack/control execution."""

    schema_version: int
    generation_id_sha256: str
    class_name_sha256: str
    callsite_path_sha256: str
    callsite_start_line: int
    callsite_end_line: int
    callsite_source_sha256: str
    backtrace_limit: int
    canary_class_source_sha256: str
    canary_class_source_size_bytes: int
    attack_token_sha256: str
    control_token_sha256: str
    attack_payload_sha256: str
    control_payload_sha256: str
    attack_payload_size_bytes: int
    control_payload_size_bytes: int
    proof_sha256: str
    expected_receipt_sha256: str
    execution_started_monotonic_ns: int
    execution_finished_monotonic_ns: int
    attested_monotonic_ns: int
    attack_receipt_matched: bool
    control_receipt_absent: bool

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "generation_id_sha256": self.generation_id_sha256,
            "class_name_sha256": self.class_name_sha256,
            "callsite_path_sha256": self.callsite_path_sha256,
            "callsite_start_line": self.callsite_start_line,
            "callsite_end_line": self.callsite_end_line,
            "callsite_source_sha256": self.callsite_source_sha256,
            "backtrace_limit": self.backtrace_limit,
            "canary_class_source_sha256": self.canary_class_source_sha256,
            "canary_class_source_size_bytes": self.canary_class_source_size_bytes,
            "attack_token_sha256": self.attack_token_sha256,
            "control_token_sha256": self.control_token_sha256,
            "attack_payload_sha256": self.attack_payload_sha256,
            "control_payload_sha256": self.control_payload_sha256,
            "attack_payload_size_bytes": self.attack_payload_size_bytes,
            "control_payload_size_bytes": self.control_payload_size_bytes,
            "proof_sha256": self.proof_sha256,
            "expected_receipt_sha256": self.expected_receipt_sha256,
            "execution_started_monotonic_ns": (self.execution_started_monotonic_ns),
            "execution_finished_monotonic_ns": (self.execution_finished_monotonic_ns),
            "attested_monotonic_ns": self.attested_monotonic_ns,
            "attack_receipt_matched": self.attack_receipt_matched,
            "control_receipt_absent": self.control_receipt_absent,
        }


@dataclass(frozen=True, slots=True)
class PhpObjectOracleSnapshot:
    """Complete sanitized evidence for one verified oracle generation."""

    schema_version: int
    mode: Literal["php_object"]
    generation_id_sha256: str
    execution: PhpObjectExecutionAttestation

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "mode": self.mode,
            "generation_id_sha256": self.generation_id_sha256,
            "execution": self.execution.as_dict(),
        }


class PhpObjectOracle:
    """Attempt-scoped state machine for a harmless PHP object canary.

    A class identity and receipt secret belong to one sandbox-scoped oracle
    instance.  Its model-facing arm tokens remain stable while a script is
    authored once and executed more than once.  ``begin_generation`` rotates
    the private generation, proof, serialized values, and expected receipt for
    every child execution.  Rotation fails closed until the current generation
    has a successful attack receipt and an absent control receipt.

    ``private_canary_class_source`` is trusted setup material, not model-facing
    context.  Its final class mutates only a private static PHP variable.
    """

    def __init__(
        self,
        *,
        callsite_path: str,
        callsite_start_line: int,
        callsite_end_line: int,
        callsite_source_sha256: str,
        class_name: str | None = None,
        receipt_secret: bytes | None = None,
    ) -> None:
        if not _is_absolute_callsite_path(callsite_path):
            raise ValueError("invalid PHP object installed callsite path")
        if not _is_callsite_range(callsite_start_line, callsite_end_line):
            raise ValueError("invalid PHP object callsite line range")
        if not _is_hex_64(callsite_source_sha256):
            raise ValueError("invalid PHP object callsite source digest")
        if class_name is None:
            class_name = _CLASS_PREFIX + secrets.token_hex(16)
        if not _is_class_name(class_name):
            raise ValueError("invalid PHP object canary class name")
        if receipt_secret is None:
            receipt_secret = secrets.token_bytes(_SECRET_SIZE_BYTES)
        if type(receipt_secret) is not bytes or len(receipt_secret) != 32:
            raise ValueError("PHP object receipt secret must be exactly 32 bytes")

        self._callsite_path = callsite_path
        self._callsite_path_sha256 = _sha256_ascii(callsite_path)
        self._callsite_start_line = callsite_start_line
        self._callsite_end_line = callsite_end_line
        self._callsite_source_sha256 = callsite_source_sha256
        self._class_name = class_name
        self._receipt_secret = bytes(receipt_secret)
        self._class_name_sha256 = _sha256_ascii(class_name)
        self._canary_class_source = _render_canary_class(
            class_name,
            self._receipt_secret,
            callsite_path,
            callsite_start_line,
            callsite_end_line,
            callsite_source_sha256,
        )
        self._canary_class_source_sha256 = _sha256_bytes(self._canary_class_source)
        self._issued_private_values: set[str] = set()
        self._attack_token = "sqpobjt1." + self._fresh_hex()
        self._control_token = "sqpobjt1." + self._fresh_hex()
        self._attack_token_sha256 = _sha256_ascii(self._attack_token)
        self._control_token_sha256 = _sha256_ascii(self._control_token)

        self._generation_id = ""
        self._generation_id_sha256 = ""
        self._proof = ""
        self._expected_receipt = ""
        self._attack_payload = b""
        self._control_payload = b""
        self._generation_started_monotonic_ns = 0
        self._proof_sha256 = ""
        self._expected_receipt_sha256 = ""
        self._attack_payload_sha256 = ""
        self._control_payload_sha256 = ""
        self._execution: PhpObjectExecutionAttestation | None = None
        self._validate_state()

    def __repr__(self) -> str:
        return "PhpObjectOracle(<redacted>)"

    @property
    def generation_id(self) -> str:
        self._require_active_generation()
        return self._generation_id

    @property
    def private_class_name(self) -> str:
        """Return the verifier-only class identity installed in the sandbox."""
        self._validate_state()
        return self._class_name

    @property
    def private_canary_class_source(self) -> bytes:
        """Return the exact verifier-only, in-memory-only PHP class source."""
        self._validate_state()
        return self._canary_class_source

    @property
    def private_receipt_secret(self) -> bytes:
        """Return the sandbox-scoped HMAC secret for trusted setup code."""
        self._validate_state()
        return self._receipt_secret

    @property
    def private_callsite_path(self) -> str:
        """Return the exact installed path bound into the inert canary."""
        self._validate_state()
        return self._callsite_path

    @property
    def private_proof(self) -> str:
        self._require_active_generation()
        return self._proof

    @property
    def private_expected_receipt(self) -> str:
        self._require_active_generation()
        return self._expected_receipt

    @property
    def private_marker(self) -> str:
        """Alias for the private one-generation receipt marker."""
        return self.private_expected_receipt

    @property
    def private_attack_payload(self) -> bytes:
        self._require_active_generation()
        return self._attack_payload

    @property
    def private_control_payload(self) -> bytes:
        self._require_active_generation()
        return self._control_payload

    def private_redaction_values(self) -> tuple[str, ...]:
        """Return bounded sensitive strings that must never be persisted.

        Callers can capture this tuple before execution and recursively scrub
        reflected payloads or setup material from transport/debug evidence. It
        includes the model-visible tokens so they do not survive in evidence.
        Every value is ASCII and the tuple has a fixed upper bound.
        """
        self._require_active_generation()
        values = (
            self._callsite_path,
            self._class_name,
            self._canary_class_source.decode("ascii"),
            self._receipt_secret.hex(),
            self._attack_token,
            self._control_token,
            self._proof,
            self._expected_receipt,
            self._attack_payload.decode("ascii"),
            self._control_payload.decode("ascii"),
        )
        if len(values) != 10 or any(not value or len(value) > 4096 for value in values):
            raise RuntimeError("PHP object oracle private material is invalid")
        return values

    def public_context(self) -> dict[str, str]:
        """Return the stable attempt tokens safe for the once-authored PoC."""
        self._validate_state()
        return {
            "mode": PHP_OBJECT_ORACLE_MODE,
            "attack_token": self._attack_token,
            "control_token": self._control_token,
        }

    def begin_generation(self) -> str:
        """Begin one fresh attack/control execution lifecycle."""
        self._validate_state()
        if self._generation_id:
            if self._execution is None:
                raise RuntimeError(
                    "cannot rotate an unfinished PHP object oracle generation"
                )
            self._validated_snapshot()

        generation_id = self._fresh_hex()
        proof = _proof_for(
            self._receipt_secret,
            self._class_name,
            generation_id,
            self._callsite_path_sha256,
            self._callsite_start_line,
            self._callsite_end_line,
            self._callsite_source_sha256,
        )
        expected_receipt = _receipt_for(
            self._receipt_secret,
            self._class_name,
            generation_id,
            proof,
            self._callsite_path_sha256,
            self._callsite_start_line,
            self._callsite_end_line,
            self._callsite_source_sha256,
        )
        attack_payload = _serialize_canary_object(
            self._class_name,
            generation_id,
            proof,
        )
        control_payload = _serialize_control_array(generation_id, proof)

        self._generation_id = generation_id
        self._generation_id_sha256 = _sha256_ascii(generation_id)
        self._proof = proof
        self._expected_receipt = expected_receipt
        self._attack_payload = attack_payload
        self._control_payload = control_payload
        self._generation_started_monotonic_ns = time.monotonic_ns()
        self._proof_sha256 = _sha256_ascii(proof)
        self._expected_receipt_sha256 = _sha256_ascii(expected_receipt)
        self._attack_payload_sha256 = _sha256_bytes(attack_payload)
        self._control_payload_sha256 = _sha256_bytes(control_payload)
        self._execution = None
        self._require_active_generation()
        return generation_id

    def resolve_payload(self, *, generation_id: str, token: str) -> bytes:
        """Resolve one exact current-generation token for trusted transport."""
        self._require_active_generation()
        if self._execution is not None:
            raise ValueError("PHP object payload generation is finalized")
        if not _is_hex_64(generation_id) or not hmac.compare_digest(
            generation_id,
            self._generation_id,
        ):
            raise ValueError("invalid PHP object payload generation")
        if type(token) is not str or _TOKEN_RE.fullmatch(token) is None:
            raise ValueError("invalid PHP object arm token")
        is_attack = hmac.compare_digest(token, self._attack_token)
        is_control = hmac.compare_digest(token, self._control_token)
        if is_attack == is_control:
            raise ValueError("invalid PHP object arm token")
        return self._attack_payload if is_attack else self._control_payload

    def abort_generation(self, *, generation_id: str) -> None:
        """Invalidate one unfinished generation after cancellation or failure."""
        self._require_active_generation()
        if self._execution is not None:
            raise RuntimeError("cannot abort a verified PHP object generation")
        if not _is_hex_64(generation_id) or not hmac.compare_digest(
            generation_id,
            self._generation_id,
        ):
            raise ValueError("invalid PHP object abort generation")
        self._clear_generation()
        self._validate_state()

    def attest_execution(
        self,
        *,
        generation_id: str,
        attack_token: str,
        control_token: str,
        attack_receipt: str,
        control_receipt: str | None,
        execution_started_monotonic_ns: int,
        execution_finished_monotonic_ns: int,
        attested_monotonic_ns: int,
    ) -> PhpObjectOracleSnapshot:
        """Finalize a receipt-positive attack and receipt-negative control."""
        self._require_active_generation()
        if self._execution is not None:
            raise RuntimeError("PHP object oracle generation is already verified")

        self._validate_attested_identity(
            generation_id=generation_id,
            attack_token=attack_token,
            control_token=control_token,
        )
        if (
            type(attack_receipt) is not str
            or _RECEIPT_RE.fullmatch(attack_receipt) is None
        ):
            raise PhpObjectAttestationError("attack_receipt", "invalid_shape")
        if not hmac.compare_digest(attack_receipt, self._expected_receipt):
            raise PhpObjectAttestationError("attack_receipt", "mismatch")
        if control_receipt is not None:
            raise PhpObjectAttestationError("control_receipt", "unsafe_state")

        self._validate_attested_times(
            execution_started_monotonic_ns=execution_started_monotonic_ns,
            execution_finished_monotonic_ns=execution_finished_monotonic_ns,
            attested_monotonic_ns=attested_monotonic_ns,
        )
        execution = PhpObjectExecutionAttestation(
            schema_version=PHP_OBJECT_ORACLE_SCHEMA_VERSION,
            generation_id_sha256=self._generation_id_sha256,
            class_name_sha256=self._class_name_sha256,
            callsite_path_sha256=self._callsite_path_sha256,
            callsite_start_line=self._callsite_start_line,
            callsite_end_line=self._callsite_end_line,
            callsite_source_sha256=self._callsite_source_sha256,
            backtrace_limit=_BACKTRACE_LIMIT,
            canary_class_source_sha256=self._canary_class_source_sha256,
            canary_class_source_size_bytes=len(self._canary_class_source),
            attack_token_sha256=self._attack_token_sha256,
            control_token_sha256=self._control_token_sha256,
            attack_payload_sha256=self._attack_payload_sha256,
            control_payload_sha256=self._control_payload_sha256,
            attack_payload_size_bytes=len(self._attack_payload),
            control_payload_size_bytes=len(self._control_payload),
            proof_sha256=self._proof_sha256,
            expected_receipt_sha256=self._expected_receipt_sha256,
            execution_started_monotonic_ns=execution_started_monotonic_ns,
            execution_finished_monotonic_ns=execution_finished_monotonic_ns,
            attested_monotonic_ns=attested_monotonic_ns,
            attack_receipt_matched=True,
            control_receipt_absent=True,
        )
        self._validate_execution(execution)
        self._execution = execution
        return self._validated_snapshot()

    def snapshot(self) -> PhpObjectOracleSnapshot:
        """Return evidence, failing closed until verification succeeds."""
        return self._validated_snapshot()

    def _fresh_hex(self) -> str:
        while True:
            value = secrets.token_hex(32)
            if value not in self._issued_private_values:
                self._issued_private_values.add(value)
                return value

    def _clear_generation(self) -> None:
        self._generation_id = ""
        self._generation_id_sha256 = ""
        self._proof = ""
        self._expected_receipt = ""
        self._attack_payload = b""
        self._control_payload = b""
        self._generation_started_monotonic_ns = 0
        self._proof_sha256 = ""
        self._expected_receipt_sha256 = ""
        self._attack_payload_sha256 = ""
        self._control_payload_sha256 = ""
        self._execution = None

    def _validate_state(self) -> None:
        self._validate_static_contract()
        if type(self._generation_id) is not str:
            raise RuntimeError("PHP object oracle lifecycle state is invalid")
        if not self._generation_id:
            if (
                self._generation_id_sha256 != ""
                or self._proof != ""
                or self._expected_receipt != ""
                or self._attack_payload != b""
                or self._control_payload != b""
                or self._generation_started_monotonic_ns != 0
                or self._proof_sha256 != ""
                or self._expected_receipt_sha256 != ""
                or self._attack_payload_sha256 != ""
                or self._control_payload_sha256 != ""
                or self._execution is not None
            ):
                raise RuntimeError("PHP object oracle lifecycle state is invalid")
            return
        self._validate_active_fields()
        if self._execution is not None:
            self._validate_execution(self._execution)

    def _validate_static_contract(self) -> None:
        if (
            not _is_absolute_callsite_path(self._callsite_path)
            or self._callsite_path_sha256 != _sha256_ascii(self._callsite_path)
            or not _is_callsite_range(
                self._callsite_start_line,
                self._callsite_end_line,
            )
            or not _is_hex_64(self._callsite_source_sha256)
            or not _is_class_name(self._class_name)
            or type(self._receipt_secret) is not bytes
            or len(self._receipt_secret) != _SECRET_SIZE_BYTES
            or self._class_name_sha256 != _sha256_ascii(self._class_name)
            or type(self._issued_private_values) is not set
            or not all(_is_hex_64(value) for value in self._issued_private_values)
            or type(self._attack_token) is not str
            or _TOKEN_RE.fullmatch(self._attack_token) is None
            or type(self._control_token) is not str
            or _TOKEN_RE.fullmatch(self._control_token) is None
            or hmac.compare_digest(self._attack_token, self._control_token)
            or self._attack_token.removeprefix("sqpobjt1.")
            not in self._issued_private_values
            or self._control_token.removeprefix("sqpobjt1.")
            not in self._issued_private_values
            or self._attack_token_sha256 != _sha256_ascii(self._attack_token)
            or self._control_token_sha256 != _sha256_ascii(self._control_token)
        ):
            raise RuntimeError("PHP object oracle static state is invalid")
        expected_source = _render_canary_class(
            self._class_name,
            self._receipt_secret,
            self._callsite_path,
            self._callsite_start_line,
            self._callsite_end_line,
            self._callsite_source_sha256,
        )
        if (
            type(self._canary_class_source) is not bytes
            or not hmac.compare_digest(self._canary_class_source, expected_source)
            or self._canary_class_source_sha256 != _sha256_bytes(expected_source)
        ):
            raise RuntimeError("PHP object oracle static state is invalid")

    def _validate_active_fields(self) -> None:
        if (
            not _is_hex_64(self._generation_id)
            or self._generation_id_sha256 != _sha256_ascii(self._generation_id)
            or not _is_hex_64(self._proof)
            or not _is_receipt(self._expected_receipt)
            or type(self._attack_payload) is not bytes
            or type(self._control_payload) is not bytes
            or not _is_monotonic_ns(self._generation_started_monotonic_ns)
            or self._generation_started_monotonic_ns > time.monotonic_ns()
        ):
            raise RuntimeError("PHP object oracle generation state is invalid")

        expected_proof = _proof_for(
            self._receipt_secret,
            self._class_name,
            self._generation_id,
            self._callsite_path_sha256,
            self._callsite_start_line,
            self._callsite_end_line,
            self._callsite_source_sha256,
        )
        expected_receipt = _receipt_for(
            self._receipt_secret,
            self._class_name,
            self._generation_id,
            expected_proof,
            self._callsite_path_sha256,
            self._callsite_start_line,
            self._callsite_end_line,
            self._callsite_source_sha256,
        )
        expected_attack = _serialize_canary_object(
            self._class_name,
            self._generation_id,
            expected_proof,
        )
        expected_control = _serialize_control_array(
            self._generation_id,
            expected_proof,
        )
        issued_values = {
            self._generation_id,
        }
        if (
            not issued_values.issubset(self._issued_private_values)
            or not hmac.compare_digest(self._proof, expected_proof)
            or not hmac.compare_digest(self._expected_receipt, expected_receipt)
            or not hmac.compare_digest(self._attack_payload, expected_attack)
            or not hmac.compare_digest(self._control_payload, expected_control)
            or b"O:" in self._control_payload
            or b"C:" in self._control_payload
            or self._proof_sha256 != _sha256_ascii(self._proof)
            or self._expected_receipt_sha256 != _sha256_ascii(self._expected_receipt)
            or self._attack_payload_sha256 != _sha256_bytes(self._attack_payload)
            or self._control_payload_sha256 != _sha256_bytes(self._control_payload)
        ):
            raise RuntimeError("PHP object oracle generation state is invalid")

    def _require_active_generation(self) -> None:
        self._validate_state()
        if not self._generation_id:
            raise RuntimeError("PHP object oracle generation is not started")

    def _validate_attested_identity(
        self,
        *,
        generation_id: object,
        attack_token: object,
        control_token: object,
    ) -> None:
        if not _is_hex_64(generation_id):
            raise PhpObjectAttestationError("generation_id", "invalid_shape")
        if not hmac.compare_digest(generation_id, self._generation_id):
            raise PhpObjectAttestationError("generation_id", "mismatch")
        for field, value, expected in (
            ("attack_token", attack_token, self._attack_token),
            ("control_token", control_token, self._control_token),
        ):
            if type(value) is not str or _TOKEN_RE.fullmatch(value) is None:
                raise PhpObjectAttestationError(field, "invalid_shape")
            if not hmac.compare_digest(value, expected):
                raise PhpObjectAttestationError(field, "mismatch")

    def _validate_attested_times(
        self,
        *,
        execution_started_monotonic_ns: object,
        execution_finished_monotonic_ns: object,
        attested_monotonic_ns: object,
    ) -> None:
        started_ns = self._validated_attested_monotonic_ns(
            execution_started_monotonic_ns,
            "execution_started_monotonic_ns",
        )
        finished_ns = self._validated_attested_monotonic_ns(
            execution_finished_monotonic_ns,
            "execution_finished_monotonic_ns",
        )
        attested_ns = self._validated_attested_monotonic_ns(
            attested_monotonic_ns,
            "attested_monotonic_ns",
        )
        if started_ns < self._generation_started_monotonic_ns:
            raise PhpObjectAttestationError(
                "execution_started_monotonic_ns",
                "out_of_order",
            )
        if finished_ns < started_ns:
            raise PhpObjectAttestationError(
                "execution_finished_monotonic_ns",
                "out_of_order",
            )
        if attested_ns < finished_ns:
            raise PhpObjectAttestationError(
                "attested_monotonic_ns",
                "out_of_order",
            )
        if attested_ns > time.monotonic_ns():
            raise PhpObjectAttestationError("attested_monotonic_ns", "future")

    @staticmethod
    def _validated_attested_monotonic_ns(value: object, field: str) -> int:
        if not _is_monotonic_ns(value):
            raise PhpObjectAttestationError(field, "invalid_shape")
        return value

    def _validate_execution(self, value: object) -> None:
        self._validate_active_fields()
        if type(value) is not PhpObjectExecutionAttestation or (
            type(value.schema_version) is not int
            or value.schema_version != PHP_OBJECT_ORACLE_SCHEMA_VERSION
            or value.generation_id_sha256 != self._generation_id_sha256
            or value.class_name_sha256 != self._class_name_sha256
            or value.callsite_path_sha256 != self._callsite_path_sha256
            or value.callsite_start_line != self._callsite_start_line
            or value.callsite_end_line != self._callsite_end_line
            or value.callsite_source_sha256 != self._callsite_source_sha256
            or value.backtrace_limit != _BACKTRACE_LIMIT
            or value.canary_class_source_sha256 != self._canary_class_source_sha256
            or type(value.canary_class_source_size_bytes) is not int
            or value.canary_class_source_size_bytes != len(self._canary_class_source)
            or value.attack_token_sha256 != self._attack_token_sha256
            or value.control_token_sha256 != self._control_token_sha256
            or value.attack_payload_sha256 != self._attack_payload_sha256
            or value.control_payload_sha256 != self._control_payload_sha256
            or type(value.attack_payload_size_bytes) is not int
            or value.attack_payload_size_bytes != len(self._attack_payload)
            or type(value.control_payload_size_bytes) is not int
            or value.control_payload_size_bytes != len(self._control_payload)
            or value.proof_sha256 != self._proof_sha256
            or value.expected_receipt_sha256 != self._expected_receipt_sha256
            or not _is_monotonic_ns(value.execution_started_monotonic_ns)
            or value.execution_started_monotonic_ns
            < self._generation_started_monotonic_ns
            or not _is_monotonic_ns(value.execution_finished_monotonic_ns)
            or value.execution_finished_monotonic_ns
            < value.execution_started_monotonic_ns
            or not _is_monotonic_ns(value.attested_monotonic_ns)
            or value.attested_monotonic_ns < value.execution_finished_monotonic_ns
            or value.attested_monotonic_ns > time.monotonic_ns()
            or value.attack_receipt_matched is not True
            or value.control_receipt_absent is not True
        ):
            raise RuntimeError("PHP object execution state is malformed")

    def _validated_snapshot(self) -> PhpObjectOracleSnapshot:
        self._validate_state()
        if self._execution is None:
            raise RuntimeError("PHP object oracle evidence is incomplete or unverified")
        self._validate_execution(self._execution)
        return PhpObjectOracleSnapshot(
            schema_version=PHP_OBJECT_ORACLE_SCHEMA_VERSION,
            mode=PHP_OBJECT_ORACLE_MODE,
            generation_id_sha256=self._generation_id_sha256,
            execution=self._execution,
        )


def _serialize_canary_object(
    class_name: str,
    generation_id: str,
    proof: str,
) -> bytes:
    if (
        not _is_class_name(class_name)
        or not _is_hex_64(generation_id)
        or not _is_hex_64(proof)
    ):
        raise RuntimeError("invalid PHP object canary serialization input")
    value = (
        f'O:{len(class_name)}:"{class_name}":2:{{'
        f's:13:"\x00*\x00generation";s:64:"{generation_id}";'
        f's:8:"\x00*\x00proof";s:64:"{proof}";'
        "}"
    ).encode("ascii")
    if len(value) > 512:
        raise RuntimeError("PHP object canary payload exceeds its fixed bound")
    return value


def _serialize_control_array(generation_id: str, proof: str) -> bytes:
    if not _is_hex_64(generation_id) or not _is_hex_64(proof):
        raise RuntimeError("invalid PHP object control serialization input")
    value = (
        "a:2:{"
        f's:13:"\x00*\x00generation";s:64:"{generation_id}";'
        f's:8:"\x00*\x00proof";s:64:"{proof}";'
        "}"
    ).encode("ascii")
    if len(value) > 256 or b"O:" in value or b"C:" in value:
        raise RuntimeError("PHP object control payload is unsafe")
    return value


def _proof_for(
    secret: bytes,
    class_name: str,
    generation_id: str,
    callsite_path_sha256: str,
    callsite_start_line: int,
    callsite_end_line: int,
    callsite_source_sha256: str,
) -> str:
    if (
        type(secret) is not bytes
        or len(secret) != _SECRET_SIZE_BYTES
        or not _is_class_name(class_name)
        or not _is_hex_64(generation_id)
        or not _is_hex_64(callsite_path_sha256)
        or not _is_callsite_range(callsite_start_line, callsite_end_line)
        or not _is_hex_64(callsite_source_sha256)
    ):
        raise RuntimeError("invalid PHP object proof input")
    message = (
        _PROOF_DOMAIN
        + class_name.encode("ascii")
        + b"\x00"
        + generation_id.encode("ascii")
        + b"\x00"
        + _callsite_binding_bytes(
            callsite_path_sha256,
            callsite_start_line,
            callsite_end_line,
            callsite_source_sha256,
        )
    )
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def _receipt_for(
    secret: bytes,
    class_name: str,
    generation_id: str,
    proof: str,
    callsite_path_sha256: str,
    callsite_start_line: int,
    callsite_end_line: int,
    callsite_source_sha256: str,
) -> str:
    if (
        not _is_hex_64(proof)
        or not _is_hex_64(callsite_path_sha256)
        or not _is_callsite_range(callsite_start_line, callsite_end_line)
        or not _is_hex_64(callsite_source_sha256)
    ):
        raise RuntimeError("invalid PHP object receipt input")
    message = (
        _RECEIPT_DOMAIN
        + class_name.encode("ascii")
        + b"\x00"
        + generation_id.encode("ascii")
        + b"\x00"
        + proof.encode("ascii")
        + b"\x00"
        + _callsite_binding_bytes(
            callsite_path_sha256,
            callsite_start_line,
            callsite_end_line,
            callsite_source_sha256,
        )
    )
    mac = hmac.new(secret, message, hashlib.sha256).hexdigest()
    return f"sqpobj1.{generation_id}.{mac}"


def _render_canary_class(
    class_name: str,
    secret: bytes,
    callsite_path: str,
    callsite_start_line: int,
    callsite_end_line: int,
    callsite_source_sha256: str,
) -> bytes:
    if (
        not _is_class_name(class_name)
        or (type(secret) is not bytes or len(secret) != _SECRET_SIZE_BYTES)
        or not _is_absolute_callsite_path(callsite_path)
        or not _is_callsite_range(
            callsite_start_line,
            callsite_end_line,
        )
        or not _is_hex_64(callsite_source_sha256)
    ):
        raise RuntimeError("invalid PHP object canary class input")
    secret_hex = secret.hex()
    callsite_path_sha256 = _sha256_ascii(callsite_path)
    callsite_binding = _callsite_binding_text(
        callsite_path_sha256,
        callsite_start_line,
        callsite_end_line,
        callsite_source_sha256,
    )
    source = f"""<?php
final class {class_name}
{{
    protected $generation = '';
    protected $proof = '';
    private static $receipt = null;

    public function __wakeup()
    {{
        if (!is_string($this->generation) || !is_string($this->proof)) {{
            return;
        }}
        if (preg_match('/\\A[0-9a-f]{{64}}\\z/D', $this->generation) !== 1) {{
            return;
        }}
        if (preg_match('/\\A[0-9a-f]{{64}}\\z/D', $this->proof) !== 1) {{
            return;
        }}
        $callsiteMatched = false;
        $frames = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, {_BACKTRACE_LIMIT});
        foreach ($frames as $frame) {{
            if (!is_array($frame)
                || !isset($frame['file'], $frame['line'])
                || !is_string($frame['file'])
                || !is_int($frame['line'])
                || $frame['line'] < {callsite_start_line}
                || $frame['line'] > {callsite_end_line}
                || !hash_equals('{callsite_path_sha256}', hash('sha256', $frame['file']))) {{
                continue;
            }}
            $runtimeSourceHash = hash_file('sha256', $frame['file']);
            if (is_string($runtimeSourceHash)
                && hash_equals('{callsite_source_sha256}', $runtimeSourceHash)) {{
                $callsiteMatched = true;
                break;
            }}
        }}
        if (!$callsiteMatched) {{
            return;
        }}
        $secret = hex2bin('{secret_hex}');
        if ($secret === false) {{
            return;
        }}
        $proofMessage = "squadrone-php-object-proof-v1\\0"
            . __CLASS__ . "\\0" . $this->generation
            . "\\0" . "{callsite_binding}";
        $expectedProof = hash_hmac('sha256', $proofMessage, $secret);
        if (!hash_equals($expectedProof, $this->proof)) {{
            return;
        }}
        $receiptMessage = "squadrone-php-object-receipt-v1\\0"
            . __CLASS__ . "\\0" . $this->generation . "\\0" . $this->proof
            . "\\0" . "{callsite_binding}";
        $receiptMac = hash_hmac('sha256', $receiptMessage, $secret);
        self::$receipt = 'sqpobj1.' . $this->generation . '.' . $receiptMac;
    }}

    public static function consumeReceipt()
    {{
        $receipt = self::$receipt;
        self::$receipt = null;
        return $receipt;
    }}

    public static function resetReceipt()
    {{
        self::$receipt = null;
    }}
}}
""".encode("ascii")
    if len(source) > 4096:
        raise RuntimeError("PHP object canary class exceeds its fixed bound")
    return source


def _sha256_ascii(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _callsite_binding_bytes(
    path_sha256: str,
    start_line: int,
    end_line: int,
    source_sha256: str,
) -> bytes:
    if (
        not _is_hex_64(path_sha256)
        or not _is_callsite_range(start_line, end_line)
        or not _is_hex_64(source_sha256)
    ):
        raise RuntimeError("invalid PHP object callsite binding")
    return (
        path_sha256.encode("ascii")
        + b"\x00"
        + str(start_line).encode("ascii")
        + b"\x00"
        + str(end_line).encode("ascii")
        + b"\x00"
        + source_sha256.encode("ascii")
    )


def _callsite_binding_text(
    path_sha256: str,
    start_line: int,
    end_line: int,
    source_sha256: str,
) -> str:
    return (
        _callsite_binding_bytes(
            path_sha256,
            start_line,
            end_line,
            source_sha256,
        )
        .decode("ascii")
        .replace("\x00", r"\0")
    )


def _is_relative_php_path(value: object) -> TypeGuard[str]:
    if type(value) is not str or not value or len(value) > 1024:
        return False
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        return False
    path = PurePosixPath(value)
    return (
        not path.is_absolute()
        and path.as_posix() == value
        and path.suffix.casefold() == ".php"
        and all(part not in {"", ".", ".."} for part in path.parts)
        and "\\" not in value
        and all(32 <= ord(character) <= 126 for character in value)
    )


def _is_absolute_callsite_path(value: object) -> TypeGuard[str]:
    if type(value) is not str or not value.startswith("/") or len(value) > 2048:
        return False
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        return False
    path = PurePosixPath(value)
    return (
        path.is_absolute()
        and path.as_posix() == value
        and path.suffix.casefold() == ".php"
        and all(part not in {"", ".", ".."} for part in path.parts)
        and "\\" not in value
        and all(32 <= ord(character) <= 126 for character in value)
    )


def _is_callsite_range(start_line: object, end_line: object) -> bool:
    return (
        type(start_line) is int
        and type(end_line) is int
        and 1 <= start_line <= end_line <= _MAX_CALLSITE_LINE
        and end_line - start_line < _MAX_CALLSITE_SPAN
    )


def _is_class_name(value: object) -> TypeGuard[str]:
    return type(value) is str and _CLASS_RE.fullmatch(value) is not None


def _is_hex_64(value: object) -> TypeGuard[str]:
    return type(value) is str and _HEX_64_RE.fullmatch(value) is not None


def _is_receipt(value: object) -> TypeGuard[str]:
    return type(value) is str and _RECEIPT_RE.fullmatch(value) is not None


def _is_monotonic_ns(value: object) -> TypeGuard[int]:
    return type(value) is int and value > 0


__all__ = [
    "PHP_OBJECT_ORACLE_MODE",
    "PHP_OBJECT_ORACLE_SCHEMA_VERSION",
    "PhpObjectAttestationError",
    "PhpObjectCallsite",
    "PhpObjectExecutionAttestation",
    "PhpObjectOracle",
    "PhpObjectOracleSnapshot",
]
