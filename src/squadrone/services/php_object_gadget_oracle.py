"""Parent-owned natural PHP-object file-delete oracle.

The model-authored PoC continues to carry only the two opaque arm tokens issued
for the inert object-instantiation proof.  This oracle resolves those same
tokens to a parent-built, source-reviewed gadget serialization and an
object-free array control.  PHP is never asked to serialize or instantiate the
reviewed object graph.

The only external value admitted to the graph is an attempt-scoped path inside
Squadrone's container-only tmpfs.  A second closed placeholder can supply one
parent-derived opaque generation identifier to guards such as cache prefixes.
Neither private value is serialized into result artifacts.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Literal, TypeGuard, cast

from .php_object_oracle import PhpObjectOracleSnapshot

if TYPE_CHECKING:
    from ..schemas.php_object_gadget import (
        PhpObjectGadgetMapEntry,
        PhpObjectGadgetRecipe,
        PhpObjectGadgetValue,
    )


PHP_OBJECT_GADGET_ORACLE_MODE: Final[Literal["php_object_gadget_file_delete"]] = (
    "php_object_gadget_file_delete"
)
PHP_OBJECT_GADGET_ORACLE_SCHEMA_VERSION: Final = 1
PHP_OBJECT_GADGET_DIRECTORY: Final = "/var/lib/squadrone/php-object-gadget"

_TOKEN_RE = re.compile(r"sqpobjt1\.[0-9a-f]{64}\Z")
_HEX_64_RE = re.compile(r"[0-9a-f]{64}\Z")
_CLASS_RE = re.compile(
    r"(?:[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*\\)*"
    r"[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*\Z"
)
_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_TARGET_RE = re.compile(
    re.escape(PHP_OBJECT_GADGET_DIRECTORY) + r"/squadrone-[0-9a-f]{64}\Z"
)
_OPAQUE_ID_RE = re.compile(r"squadrone-[0-9a-f]{64}\Z")
_PROOF_DOMAIN = b"squadrone-php-object-gadget-proof-v1\x00"
_MAX_SERIALIZED_BYTES = 64 * 1024
_MAX_POC_BUNDLE_SOURCE_FILES = 32
_FORBIDDEN_CONTROL_MARKERS: Final = (b"O:", b"C:", b"E:", b"R:", b"r:")


@dataclass(frozen=True, slots=True)
class PhpObjectGadgetRuntimeBinding:
    """Sanitized installed-source and Reflection binding established at prepare."""

    schema_version: int
    mode: Literal["php_object_gadget_file_delete"]
    effect: Literal["file_delete"]
    effect_binding_kind: Literal["direct_path", "guarded_opaque_prefix"]
    recipe_sha256: str
    source_inventory_sha256: str
    reflection_sha256: str
    source_file_count: int
    source_anchor_count: int
    property_count: int
    all_effect_sinks_accounted: bool

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != PHP_OBJECT_GADGET_ORACLE_SCHEMA_VERSION
            or self.mode != PHP_OBJECT_GADGET_ORACLE_MODE
            or self.effect != "file_delete"
            or self.effect_binding_kind not in {"direct_path", "guarded_opaque_prefix"}
            or not _is_hex_64(self.recipe_sha256)
            or not _is_hex_64(self.source_inventory_sha256)
            or not _is_hex_64(self.reflection_sha256)
            or type(self.source_file_count) is not int
            or not 1 <= self.source_file_count <= 64
            or type(self.source_anchor_count) is not int
            or not 3 <= self.source_anchor_count <= 256
            or type(self.property_count) is not int
            or not 1 <= self.property_count <= 32
            or self.all_effect_sinks_accounted is not True
        ):
            raise ValueError("invalid PHP object gadget runtime binding")

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "mode": self.mode,
            "effect": self.effect,
            "effect_binding_kind": self.effect_binding_kind,
            "recipe_sha256": self.recipe_sha256,
            "source_inventory_sha256": self.source_inventory_sha256,
            "reflection_sha256": self.reflection_sha256,
            "source_file_count": self.source_file_count,
            "source_anchor_count": self.source_anchor_count,
            "property_count": self.property_count,
            "all_effect_sinks_accounted": self.all_effect_sinks_accounted,
        }


@dataclass(frozen=True, slots=True)
class PhpObjectGadgetFileMeasurement:
    """Value-free measurement of the dedicated tmpfs and one target path."""

    target_path_sha256: str
    target_exists: bool
    target_regular: bool
    target_symlink: bool
    target_content_sha256: str | None
    target_size_bytes: int | None
    target_uid: int | None
    target_gid: int | None
    target_mode: int | None
    target_inode: int | None
    target_link_count: int | None
    directory_entry_count: int
    directory_inventory_sha256: str
    directory_uid: int
    directory_gid: int
    directory_mode: int
    directory_is_tmpfs: bool

    def __post_init__(self) -> None:
        optional_ints = (
            self.target_size_bytes,
            self.target_uid,
            self.target_gid,
            self.target_mode,
            self.target_inode,
            self.target_link_count,
        )
        if (
            not _is_hex_64(self.target_path_sha256)
            or type(self.target_exists) is not bool
            or type(self.target_regular) is not bool
            or type(self.target_symlink) is not bool
            or type(self.directory_entry_count) is not int
            or not 0 <= self.directory_entry_count <= 1024
            or not _is_hex_64(self.directory_inventory_sha256)
            or type(self.directory_uid) is not int
            or self.directory_uid != 0
            or type(self.directory_gid) is not int
            or self.directory_gid != 33
            or type(self.directory_mode) is not int
            or self.directory_mode != 0o770
            or self.directory_is_tmpfs is not True
            or any(
                value is not None and type(value) is not int for value in optional_ints
            )
        ):
            raise ValueError("invalid PHP object gadget file measurement")
        if self.target_exists:
            if (
                self.target_regular is not True
                or self.target_symlink is not False
                or not _is_hex_64(self.target_content_sha256)
                or self.target_size_bytes is None
                or self.target_size_bytes < 1
                or self.target_uid is None
                or self.target_uid < 1
                or self.target_gid is None
                or self.target_gid < 0
                or self.target_mode != 0o600
                or self.target_inode is None
                or self.target_inode < 1
                or self.target_link_count != 1
            ):
                raise ValueError("unsafe PHP object gadget target measurement")
        elif (
            self.target_regular
            or self.target_symlink
            or self.target_content_sha256 is not None
            or any(value is not None for value in optional_ints)
        ):
            raise ValueError("inconsistent absent gadget target measurement")

    def as_dict(self) -> dict[str, object]:
        return {
            "target_path_sha256": self.target_path_sha256,
            "target_exists": self.target_exists,
            "target_regular": self.target_regular,
            "target_symlink": self.target_symlink,
            "target_content_sha256": self.target_content_sha256,
            "target_size_bytes": self.target_size_bytes,
            "target_uid": self.target_uid,
            "target_gid": self.target_gid,
            "target_mode": self.target_mode,
            "target_inode": self.target_inode,
            "target_link_count": self.target_link_count,
            "directory_entry_count": self.directory_entry_count,
            "directory_inventory_sha256": self.directory_inventory_sha256,
            "directory_uid": self.directory_uid,
            "directory_gid": self.directory_gid,
            "directory_mode": self.directory_mode,
            "directory_is_tmpfs": self.directory_is_tmpfs,
        }


@dataclass(frozen=True, slots=True)
class PhpObjectGadgetTransportAttestation:
    """Sanitized actor, script, policy, trace, and surface binding."""

    schema_version: int
    mode: Literal["php_object_gadget_file_delete"]
    effect: Literal["file_delete"]
    effect_binding_kind: Literal["direct_path", "guarded_opaque_prefix"]
    script_sha256: str
    poc_bundle_manifest_sha256: str
    poc_bundle_source_file_count: int
    transport_contract_sha256: str
    trace_binding_sha256: str
    actor_identity_sha256: str
    actor_role: str
    attack_payload_sha256: str
    control_payload_sha256: str
    attack_payload_size_bytes: int
    control_payload_size_bytes: int
    attack_sequence: int
    control_sequence: int
    attack_status_code: int
    control_status_code: int
    attack_control_envelopes_equal: bool
    rewritten_payloads_differ: bool
    ephemeral_path_capability_exact: bool
    executable_surface_bound: bool

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != PHP_OBJECT_GADGET_ORACLE_SCHEMA_VERSION
            or self.mode != PHP_OBJECT_GADGET_ORACLE_MODE
            or self.effect != "file_delete"
            or self.effect_binding_kind not in {"direct_path", "guarded_opaque_prefix"}
            or not _is_hex_64(self.script_sha256)
            or not _is_hex_64(self.poc_bundle_manifest_sha256)
            or type(self.poc_bundle_source_file_count) is not int
            or not 1
            <= self.poc_bundle_source_file_count
            <= _MAX_POC_BUNDLE_SOURCE_FILES
            or not _is_hex_64(self.transport_contract_sha256)
            or not _is_hex_64(self.trace_binding_sha256)
            or not _is_hex_64(self.actor_identity_sha256)
            or not _is_hex_64(self.attack_payload_sha256)
            or not _is_hex_64(self.control_payload_sha256)
            or hmac.compare_digest(
                self.attack_payload_sha256,
                self.control_payload_sha256,
            )
            or type(self.attack_payload_size_bytes) is not int
            or not 1 <= self.attack_payload_size_bytes <= _MAX_SERIALIZED_BYTES
            or type(self.control_payload_size_bytes) is not int
            or not 1 <= self.control_payload_size_bytes <= _MAX_SERIALIZED_BYTES
            or type(self.actor_role) is not str
            or not self.actor_role
            or len(self.actor_role) > 64
            or type(self.attack_sequence) is not int
            or type(self.control_sequence) is not int
            or not 1 <= self.attack_sequence < self.control_sequence
            or type(self.attack_status_code) is not int
            or not 100 <= self.attack_status_code <= 599
            or type(self.control_status_code) is not int
            or not 100 <= self.control_status_code <= 599
            or self.attack_control_envelopes_equal is not True
            or self.rewritten_payloads_differ is not True
            or self.ephemeral_path_capability_exact is not True
            or self.executable_surface_bound is not True
        ):
            raise ValueError("invalid PHP object gadget transport attestation")

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "mode": self.mode,
            "effect": self.effect,
            "effect_binding_kind": self.effect_binding_kind,
            "script_sha256": self.script_sha256,
            "poc_bundle_manifest_sha256": self.poc_bundle_manifest_sha256,
            "poc_bundle_source_file_count": self.poc_bundle_source_file_count,
            "transport_contract_sha256": self.transport_contract_sha256,
            "trace_binding_sha256": self.trace_binding_sha256,
            "actor_identity_sha256": self.actor_identity_sha256,
            "actor_role": self.actor_role,
            "attack_payload_sha256": self.attack_payload_sha256,
            "control_payload_sha256": self.control_payload_sha256,
            "attack_payload_size_bytes": self.attack_payload_size_bytes,
            "control_payload_size_bytes": self.control_payload_size_bytes,
            "attack_sequence": self.attack_sequence,
            "control_sequence": self.control_sequence,
            "attack_status_code": self.attack_status_code,
            "control_status_code": self.control_status_code,
            "attack_control_envelopes_equal": (self.attack_control_envelopes_equal),
            "rewritten_payloads_differ": self.rewritten_payloads_differ,
            "ephemeral_path_capability_exact": (self.ephemeral_path_capability_exact),
            "executable_surface_bound": self.executable_surface_bound,
        }


@dataclass(frozen=True, slots=True)
class PhpObjectGadgetEffectAttestation:
    """Exact attack deletion and same-state control preservation evidence."""

    schema_version: int
    mode: Literal["php_object_gadget_file_delete"]
    effect: Literal["file_delete"]
    effect_binding_kind: Literal["direct_path", "guarded_opaque_prefix"]
    attack_before: PhpObjectGadgetFileMeasurement
    attack_after: PhpObjectGadgetFileMeasurement
    control_before: PhpObjectGadgetFileMeasurement
    control_after: PhpObjectGadgetFileMeasurement
    state_restored_before_control: bool
    runtime_restarted_before_control: bool
    state_restored_after_control: bool
    runtime_restarted_after_control: bool
    attack_deleted_exact_target: bool
    control_preserved_exact_target: bool
    collateral_paths_unchanged: bool

    def __post_init__(self) -> None:
        before = self.attack_before
        attack_after = self.attack_after
        control_before = self.control_before
        control_after = self.control_after
        stable_fields = (
            "target_path_sha256",
            "target_content_sha256",
            "target_size_bytes",
            "target_uid",
            "target_gid",
            "target_mode",
            "target_link_count",
            "directory_entry_count",
            "directory_inventory_sha256",
            "directory_uid",
            "directory_gid",
            "directory_mode",
        )
        same_logical_start = all(
            getattr(before, field) == getattr(control_before, field)
            for field in stable_fields
        )
        exact_control = control_before == control_after
        if (
            type(self.schema_version) is not int
            or self.schema_version != PHP_OBJECT_GADGET_ORACLE_SCHEMA_VERSION
            or self.mode != PHP_OBJECT_GADGET_ORACLE_MODE
            or self.effect != "file_delete"
            or self.effect_binding_kind not in {"direct_path", "guarded_opaque_prefix"}
            or before.target_exists is not True
            or before.directory_entry_count != 1
            or attack_after.target_exists is not False
            or attack_after.directory_entry_count != 0
            or control_before.target_exists is not True
            or control_before.directory_entry_count != 1
            or not same_logical_start
            or not exact_control
            or self.state_restored_before_control is not True
            or self.runtime_restarted_before_control is not True
            or self.state_restored_after_control is not True
            or self.runtime_restarted_after_control is not True
            or self.attack_deleted_exact_target is not True
            or self.control_preserved_exact_target is not True
            or self.collateral_paths_unchanged is not True
        ):
            raise ValueError("invalid PHP object gadget effect attestation")

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "mode": self.mode,
            "effect": self.effect,
            "effect_binding_kind": self.effect_binding_kind,
            "attack_before": self.attack_before.as_dict(),
            "attack_after": self.attack_after.as_dict(),
            "control_before": self.control_before.as_dict(),
            "control_after": self.control_after.as_dict(),
            "state_restored_before_control": self.state_restored_before_control,
            "runtime_restarted_before_control": (self.runtime_restarted_before_control),
            "state_restored_after_control": self.state_restored_after_control,
            "runtime_restarted_after_control": self.runtime_restarted_after_control,
            "attack_deleted_exact_target": self.attack_deleted_exact_target,
            "control_preserved_exact_target": self.control_preserved_exact_target,
            "collateral_paths_unchanged": self.collateral_paths_unchanged,
        }


@dataclass(frozen=True, slots=True)
class PhpObjectGadgetOracleSnapshot:
    """Complete persistence-safe natural gadget proof for one execution."""

    schema_version: int
    mode: Literal["php_object_gadget_file_delete"]
    effect: Literal["file_delete"]
    effect_binding_kind: Literal["direct_path", "guarded_opaque_prefix"]
    generation_id_sha256: str
    generation_proof_sha256: str
    target_path_sha256: str
    target_content_sha256: str
    opaque_generation_id_sha256: str | None
    attack_token_sha256: str
    control_token_sha256: str
    attack_payload_sha256: str
    control_payload_sha256: str
    attack_payload_size_bytes: int
    control_payload_size_bytes: int
    primitive_binding_sha256: str
    callsite_path_sha256: str
    callsite_source_sha256: str
    runtime_binding: PhpObjectGadgetRuntimeBinding
    effect_attestation: PhpObjectGadgetEffectAttestation
    transport_attestation: PhpObjectGadgetTransportAttestation

    def __post_init__(self) -> None:
        runtime = self.runtime_binding
        effect = self.effect_attestation
        transport = self.transport_attestation
        measurements = (
            (
                effect.attack_before,
                effect.attack_after,
                effect.control_before,
                effect.control_after,
            )
            if type(effect) is PhpObjectGadgetEffectAttestation
            else ()
        )
        if (
            type(self.schema_version) is not int
            or self.schema_version != PHP_OBJECT_GADGET_ORACLE_SCHEMA_VERSION
            or self.mode != PHP_OBJECT_GADGET_ORACLE_MODE
            or self.effect != "file_delete"
            or self.effect_binding_kind not in {"direct_path", "guarded_opaque_prefix"}
            or not all(
                _is_hex_64(value)
                for value in (
                    self.generation_id_sha256,
                    self.generation_proof_sha256,
                    self.target_path_sha256,
                    self.target_content_sha256,
                    self.attack_token_sha256,
                    self.control_token_sha256,
                    self.attack_payload_sha256,
                    self.control_payload_sha256,
                    self.primitive_binding_sha256,
                    self.callsite_path_sha256,
                    self.callsite_source_sha256,
                )
            )
            or (
                self.opaque_generation_id_sha256 is not None
                and not _is_hex_64(self.opaque_generation_id_sha256)
            )
            or hmac.compare_digest(
                self.attack_token_sha256,
                self.control_token_sha256,
            )
            or hmac.compare_digest(
                self.attack_payload_sha256,
                self.control_payload_sha256,
            )
            or type(self.attack_payload_size_bytes) is not int
            or not 1 <= self.attack_payload_size_bytes <= _MAX_SERIALIZED_BYTES
            or type(self.control_payload_size_bytes) is not int
            or not 1 <= self.control_payload_size_bytes <= _MAX_SERIALIZED_BYTES
            or type(runtime) is not PhpObjectGadgetRuntimeBinding
            or type(effect) is not PhpObjectGadgetEffectAttestation
            or type(transport) is not PhpObjectGadgetTransportAttestation
            or runtime.schema_version != self.schema_version
            or runtime.mode != self.mode
            or runtime.effect != self.effect
            or runtime.effect_binding_kind != self.effect_binding_kind
            or effect.schema_version != self.schema_version
            or effect.mode != self.mode
            or effect.effect != self.effect
            or effect.effect_binding_kind != self.effect_binding_kind
            or transport.schema_version != self.schema_version
            or transport.mode != self.mode
            or transport.effect != self.effect
            or transport.effect_binding_kind != self.effect_binding_kind
            or transport.attack_payload_sha256 != self.attack_payload_sha256
            or transport.control_payload_sha256 != self.control_payload_sha256
            or transport.attack_payload_size_bytes != self.attack_payload_size_bytes
            or transport.control_payload_size_bytes != self.control_payload_size_bytes
            or len(measurements) != 4
            or any(
                measurement.target_path_sha256 != self.target_path_sha256
                for measurement in measurements
            )
            or effect.attack_before.target_content_sha256 != self.target_content_sha256
            or effect.control_before.target_content_sha256 != self.target_content_sha256
            or effect.control_after.target_content_sha256 != self.target_content_sha256
        ):
            raise ValueError("invalid PHP object gadget oracle snapshot binding")

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "mode": self.mode,
            "effect": self.effect,
            "effect_binding_kind": self.effect_binding_kind,
            "generation_id_sha256": self.generation_id_sha256,
            "generation_proof_sha256": self.generation_proof_sha256,
            "target_path_sha256": self.target_path_sha256,
            "target_content_sha256": self.target_content_sha256,
            "opaque_generation_id_sha256": self.opaque_generation_id_sha256,
            "attack_token_sha256": self.attack_token_sha256,
            "control_token_sha256": self.control_token_sha256,
            "attack_payload_sha256": self.attack_payload_sha256,
            "control_payload_sha256": self.control_payload_sha256,
            "attack_payload_size_bytes": self.attack_payload_size_bytes,
            "control_payload_size_bytes": self.control_payload_size_bytes,
            "primitive_binding_sha256": self.primitive_binding_sha256,
            "callsite_path_sha256": self.callsite_path_sha256,
            "callsite_source_sha256": self.callsite_source_sha256,
            "runtime_binding": self.runtime_binding.as_dict(),
            "effect_attestation": self.effect_attestation.as_dict(),
            "transport_attestation": self.transport_attestation.as_dict(),
        }


class PhpObjectGadgetOracle:
    """Closed state machine for one source-reviewed natural file-delete gadget."""

    def __init__(
        self,
        *,
        recipe: "PhpObjectGadgetRecipe",
        primitive_snapshot: PhpObjectOracleSnapshot,
        attack_token: str,
        control_token: str,
        runtime_binding: PhpObjectGadgetRuntimeBinding,
        receipt_secret: bytes | None = None,
    ) -> None:
        recipe_type = _recipe_model_type()
        if type(recipe) is not recipe_type:
            raise ValueError("PHP object gadget recipe has an invalid type")
        canonical_recipe = _canonical_recipe_bytes(recipe)
        recipe_sha256 = hashlib.sha256(canonical_recipe).hexdigest()
        if not hmac.compare_digest(recipe_sha256, runtime_binding.recipe_sha256):
            raise ValueError("PHP object gadget runtime binding changed")
        if type(primitive_snapshot) is not PhpObjectOracleSnapshot:
            raise ValueError("PHP object primitive snapshot has an invalid type")
        if (
            not _is_token(attack_token)
            or not _is_token(control_token)
            or hmac.compare_digest(attack_token, control_token)
            or primitive_snapshot.execution.attack_token_sha256
            != _sha256_ascii(attack_token)
            or primitive_snapshot.execution.control_token_sha256
            != _sha256_ascii(control_token)
        ):
            raise ValueError("PHP object gadget tokens do not bind to the primitive")
        if receipt_secret is None:
            receipt_secret = secrets.token_bytes(32)
        if type(receipt_secret) is not bytes or len(receipt_secret) != 32:
            raise ValueError("PHP object gadget proof secret must be 32 bytes")

        self._recipe = recipe
        self._canonical_recipe = canonical_recipe
        self._primitive_snapshot = primitive_snapshot
        self._attack_token = attack_token
        self._control_token = control_token
        self._runtime_binding = runtime_binding
        self._receipt_secret = bytes(receipt_secret)
        self._issued: set[str] = set()
        self._generation_id = ""
        self._generation_proof = ""
        self._target_path = ""
        self._target_content = b""
        self._opaque_generation_id: str | None = None
        self._attack_payload = b""
        self._control_payload = b""
        self._generation_started_monotonic_ns = 0
        self._effect_attestation: PhpObjectGadgetEffectAttestation | None = None
        self._snapshot: PhpObjectGadgetOracleSnapshot | None = None

    def __repr__(self) -> str:
        return "PhpObjectGadgetOracle(<redacted>)"

    def public_context(self) -> dict[str, str]:
        return {
            "mode": PHP_OBJECT_GADGET_ORACLE_MODE,
            "attack_token": self._attack_token,
            "control_token": self._control_token,
        }

    @property
    def generation_id(self) -> str:
        self._require_generation()
        return self._generation_id

    @property
    def private_target_path(self) -> str:
        self._require_generation()
        return self._target_path

    @property
    def private_target_content(self) -> bytes:
        self._require_generation()
        return self._target_content

    @property
    def private_attack_payload(self) -> bytes:
        self._require_generation()
        return self._attack_payload

    @property
    def private_control_payload(self) -> bytes:
        self._require_generation()
        return self._control_payload

    @property
    def runtime_binding(self) -> PhpObjectGadgetRuntimeBinding:
        return self._runtime_binding

    @property
    def recipe(self) -> "PhpObjectGadgetRecipe":
        return self._recipe

    @property
    def uses_ephemeral_path_capability(self) -> bool:
        return _count_value_kind(self._recipe, "capability") == 1

    def begin_generation(self) -> str:
        if self._generation_id:
            if self._snapshot is None:
                raise RuntimeError("cannot rotate an unfinished gadget generation")
            self._clear_generation()
        generation_id = self._fresh_hex()
        opaque_needed = _count_value_kind(self._recipe, "opaque_generation_id")
        opaque_generation_id = (
            "squadrone-" + self._fresh_hex() if opaque_needed == 1 else None
        )
        effect_binding = self._recipe.effect_binding
        if effect_binding.kind == "guarded_opaque_prefix":
            if opaque_generation_id is None:
                raise RuntimeError("guarded gadget target lacks its opaque identifier")
            guarded = effect_binding.effect
            target_basename = (
                guarded.basename_prefix
                + opaque_generation_id
                + guarded.basename_suffix
                + self._fresh_hex()
            )
        else:
            target_basename = "squadrone-" + self._fresh_hex()
        target_path = f"{PHP_OBJECT_GADGET_DIRECTORY}/{target_basename}"
        target_content = ("SQUADRONE_PHP_OBJECT_GADGET_" + self._fresh_hex()).encode(
            "ascii"
        )
        generation_proof = hmac.new(
            self._receipt_secret,
            _PROOF_DOMAIN
            + generation_id.encode("ascii")
            + b"\x00"
            + target_path.encode("ascii")
            + b"\x00"
            + target_content,
            hashlib.sha256,
        ).hexdigest()
        attack_payload = _serialize_gadget_object(
            self._recipe,
            ephemeral_file_path=target_path,
            opaque_generation_id=opaque_generation_id,
        )
        control_payload = _serialize_object_free_control(
            self._recipe,
            ephemeral_file_path=target_path,
            opaque_generation_id=opaque_generation_id,
        )
        if (
            not _is_recipe_target_path(
                self._recipe,
                target_path,
                opaque_generation_id,
            )
            or len(attack_payload) > _MAX_SERIALIZED_BYTES
            or len(control_payload) > _MAX_SERIALIZED_BYTES
            or b"O:" not in attack_payload
            or any(marker in control_payload for marker in _FORBIDDEN_CONTROL_MARKERS)
            or (
                self.uses_ephemeral_path_capability
                and (
                    attack_payload.count(target_path.encode("ascii")) != 1
                    or control_payload.count(target_path.encode("ascii")) != 1
                )
            )
            or (
                not self.uses_ephemeral_path_capability
                and (
                    target_path.encode("ascii") in attack_payload
                    or target_path.encode("ascii") in control_payload
                )
            )
            or (
                opaque_generation_id is not None
                and (
                    attack_payload.count(opaque_generation_id.encode("ascii")) != 1
                    or control_payload.count(opaque_generation_id.encode("ascii")) != 1
                )
            )
        ):
            raise RuntimeError("unsafe PHP object gadget serialization")
        self._generation_id = generation_id
        self._generation_proof = generation_proof
        self._target_path = target_path
        self._target_content = target_content
        self._opaque_generation_id = opaque_generation_id
        self._attack_payload = attack_payload
        self._control_payload = control_payload
        self._generation_started_monotonic_ns = time.monotonic_ns()
        self._effect_attestation = None
        self._snapshot = None
        return generation_id

    def resolve_payload(self, *, generation_id: str, token: str) -> bytes:
        self._require_generation()
        if self._snapshot is not None:
            raise ValueError("PHP object gadget generation is finalized")
        if not _is_hex_64(generation_id) or not hmac.compare_digest(
            generation_id, self._generation_id
        ):
            raise ValueError("invalid PHP object gadget generation")
        if not _is_token(token):
            raise ValueError("invalid PHP object gadget token")
        is_attack = hmac.compare_digest(token, self._attack_token)
        is_control = hmac.compare_digest(token, self._control_token)
        if is_attack == is_control:
            raise ValueError("invalid PHP object gadget token")
        return self._attack_payload if is_attack else self._control_payload

    def private_redaction_values(self) -> tuple[str, ...]:
        self._require_generation()
        values = [
            self._generation_id,
            self._generation_proof,
            self._target_path,
            self._target_content.decode("ascii"),
            self._attack_token,
            self._control_token,
            self._attack_payload.decode("ascii"),
            self._control_payload.decode("ascii"),
            self._receipt_secret.hex(),
        ]
        if self._opaque_generation_id is not None:
            values.append(self._opaque_generation_id)
        if len(values) > 10 or any(
            not value or len(value) > _MAX_SERIALIZED_BYTES for value in values
        ):
            raise RuntimeError("invalid PHP object gadget redaction material")
        return tuple(values)

    def attest_effect(
        self,
        *,
        attack_before: PhpObjectGadgetFileMeasurement,
        attack_after: PhpObjectGadgetFileMeasurement,
        control_before: PhpObjectGadgetFileMeasurement,
        control_after: PhpObjectGadgetFileMeasurement,
        state_restored_before_control: bool,
        runtime_restarted_before_control: bool,
        state_restored_after_control: bool,
        runtime_restarted_after_control: bool,
    ) -> PhpObjectGadgetEffectAttestation:
        self._require_generation()
        if self._effect_attestation is not None:
            raise RuntimeError("PHP object gadget effect is already attested")
        expected_path_hash = _sha256_ascii(self._target_path)
        if any(
            measurement.target_path_sha256 != expected_path_hash
            for measurement in (
                attack_before,
                attack_after,
                control_before,
                control_after,
            )
        ):
            raise ValueError("PHP object gadget effect target changed")
        effect = PhpObjectGadgetEffectAttestation(
            schema_version=PHP_OBJECT_GADGET_ORACLE_SCHEMA_VERSION,
            mode=PHP_OBJECT_GADGET_ORACLE_MODE,
            effect="file_delete",
            effect_binding_kind=self._runtime_binding.effect_binding_kind,
            attack_before=attack_before,
            attack_after=attack_after,
            control_before=control_before,
            control_after=control_after,
            state_restored_before_control=state_restored_before_control,
            runtime_restarted_before_control=runtime_restarted_before_control,
            state_restored_after_control=state_restored_after_control,
            runtime_restarted_after_control=runtime_restarted_after_control,
            attack_deleted_exact_target=True,
            control_preserved_exact_target=True,
            collateral_paths_unchanged=True,
        )
        self._effect_attestation = effect
        return effect

    def attest_execution(
        self,
        *,
        generation_id: str,
        attack_token: str,
        control_token: str,
        execution_started_monotonic_ns: int,
        execution_finished_monotonic_ns: int,
        attested_monotonic_ns: int,
        runtime_binding: PhpObjectGadgetRuntimeBinding,
        transport_attestation: PhpObjectGadgetTransportAttestation,
    ) -> PhpObjectGadgetOracleSnapshot:
        self._require_generation()
        if self._snapshot is not None or self._effect_attestation is None:
            raise RuntimeError("PHP object gadget evidence is incomplete")
        if (
            not hmac.compare_digest(generation_id, self._generation_id)
            or not hmac.compare_digest(attack_token, self._attack_token)
            or not hmac.compare_digest(control_token, self._control_token)
            or runtime_binding != self._runtime_binding
            or type(execution_started_monotonic_ns) is not int
            or type(execution_finished_monotonic_ns) is not int
            or type(attested_monotonic_ns) is not int
            or execution_started_monotonic_ns < self._generation_started_monotonic_ns
            or execution_finished_monotonic_ns < execution_started_monotonic_ns
            or attested_monotonic_ns < execution_finished_monotonic_ns
            or attested_monotonic_ns > time.monotonic_ns()
        ):
            raise ValueError("invalid PHP object gadget execution attestation")
        primitive = self._primitive_snapshot.execution
        primitive_binding = hashlib.sha256(
            json.dumps(
                self._primitive_snapshot.as_dict(),
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
        ).hexdigest()
        snapshot = PhpObjectGadgetOracleSnapshot(
            schema_version=PHP_OBJECT_GADGET_ORACLE_SCHEMA_VERSION,
            mode=PHP_OBJECT_GADGET_ORACLE_MODE,
            effect="file_delete",
            effect_binding_kind=self._runtime_binding.effect_binding_kind,
            generation_id_sha256=_sha256_ascii(self._generation_id),
            generation_proof_sha256=_sha256_ascii(self._generation_proof),
            target_path_sha256=_sha256_ascii(self._target_path),
            target_content_sha256=hashlib.sha256(self._target_content).hexdigest(),
            opaque_generation_id_sha256=(
                _sha256_ascii(self._opaque_generation_id)
                if self._opaque_generation_id is not None
                else None
            ),
            attack_token_sha256=_sha256_ascii(self._attack_token),
            control_token_sha256=_sha256_ascii(self._control_token),
            attack_payload_sha256=hashlib.sha256(self._attack_payload).hexdigest(),
            control_payload_sha256=hashlib.sha256(self._control_payload).hexdigest(),
            attack_payload_size_bytes=len(self._attack_payload),
            control_payload_size_bytes=len(self._control_payload),
            primitive_binding_sha256=primitive_binding,
            callsite_path_sha256=primitive.callsite_path_sha256,
            callsite_source_sha256=primitive.callsite_source_sha256,
            runtime_binding=self._runtime_binding,
            effect_attestation=self._effect_attestation,
            transport_attestation=transport_attestation,
        )
        self._snapshot = snapshot
        return snapshot

    def snapshot(self) -> PhpObjectGadgetOracleSnapshot:
        if self._snapshot is None:
            raise RuntimeError("PHP object gadget evidence is incomplete or unverified")
        return self._snapshot

    def abort_generation(self, *, generation_id: str) -> None:
        self._require_generation()
        if self._snapshot is not None:
            raise RuntimeError("cannot abort a verified PHP object gadget generation")
        if not _is_hex_64(generation_id) or not hmac.compare_digest(
            generation_id, self._generation_id
        ):
            raise ValueError("invalid PHP object gadget abort generation")
        self._clear_generation()

    def _require_generation(self) -> None:
        if not self._generation_id:
            raise RuntimeError("PHP object gadget generation is not started")

    def _clear_generation(self) -> None:
        self._generation_id = ""
        self._generation_proof = ""
        self._target_path = ""
        self._target_content = b""
        self._opaque_generation_id = None
        self._attack_payload = b""
        self._control_payload = b""
        self._generation_started_monotonic_ns = 0
        self._effect_attestation = None
        self._snapshot = None

    def _fresh_hex(self) -> str:
        while True:
            value = secrets.token_hex(32)
            if value not in self._issued:
                self._issued.add(value)
                return value


def validate_php_object_gadget_snapshot_pair(
    first: object,
    second: object,
) -> tuple[bool, str]:
    """Require stable reviewed identities and fresh execution capabilities."""
    if (
        type(first) is not PhpObjectGadgetOracleSnapshot
        or type(second) is not PhpObjectGadgetOracleSnapshot
    ):
        return False, "PHP object gadget replay snapshots have invalid types"
    stable = (
        "schema_version",
        "mode",
        "effect",
        "effect_binding_kind",
        "attack_token_sha256",
        "control_token_sha256",
        "primitive_binding_sha256",
        "callsite_path_sha256",
        "callsite_source_sha256",
        "runtime_binding",
        "attack_payload_size_bytes",
        "control_payload_size_bytes",
    )
    if any(getattr(first, field) != getattr(second, field) for field in stable):
        return False, "PHP object gadget replay changed a reviewed source identity"
    first_transport = first.transport_attestation
    second_transport = second.transport_attestation
    stable_transport = (
        "script_sha256",
        "poc_bundle_manifest_sha256",
        "poc_bundle_source_file_count",
        "transport_contract_sha256",
        "actor_identity_sha256",
        "actor_role",
        "attack_control_envelopes_equal",
        "rewritten_payloads_differ",
        "ephemeral_path_capability_exact",
        "executable_surface_bound",
    )
    if any(
        getattr(first_transport, field) != getattr(second_transport, field)
        for field in stable_transport
    ):
        return False, "PHP object gadget replay changed script, actor, or transport"
    if hmac.compare_digest(
        first_transport.trace_binding_sha256,
        second_transport.trace_binding_sha256,
    ):
        return False, "PHP object gadget replay reused its private trace binding"
    fresh = (
        "generation_id_sha256",
        "generation_proof_sha256",
        "target_path_sha256",
        "target_content_sha256",
        "attack_payload_sha256",
        "control_payload_sha256",
    )
    if any(getattr(first, field) == getattr(second, field) for field in fresh):
        return False, "PHP object gadget replay reused private generation material"
    if (first.opaque_generation_id_sha256 is None) != (
        second.opaque_generation_id_sha256 is None
    ):
        return False, "PHP object gadget replay changed its opaque-ID contract"
    if (
        first.opaque_generation_id_sha256 is not None
        and first.opaque_generation_id_sha256 == second.opaque_generation_id_sha256
    ):
        return False, "PHP object gadget replay reused its opaque generation ID"
    return True, "PHP object gadget file-delete replay identities are valid"


def php_object_gadget_snapshot_from_dict(
    payload: object,
) -> PhpObjectGadgetOracleSnapshot:
    """Strictly restore one persistence-safe snapshot without type coercion."""
    try:
        snapshot = _exact_dict(
            payload,
            {
                "schema_version",
                "mode",
                "effect",
                "effect_binding_kind",
                "generation_id_sha256",
                "generation_proof_sha256",
                "target_path_sha256",
                "target_content_sha256",
                "opaque_generation_id_sha256",
                "attack_token_sha256",
                "control_token_sha256",
                "attack_payload_sha256",
                "control_payload_sha256",
                "attack_payload_size_bytes",
                "control_payload_size_bytes",
                "primitive_binding_sha256",
                "callsite_path_sha256",
                "callsite_source_sha256",
                "runtime_binding",
                "effect_attestation",
                "transport_attestation",
            },
        )
        runtime_payload = _exact_dict(
            snapshot["runtime_binding"],
            {
                "schema_version",
                "mode",
                "effect",
                "effect_binding_kind",
                "recipe_sha256",
                "source_inventory_sha256",
                "reflection_sha256",
                "source_file_count",
                "source_anchor_count",
                "property_count",
                "all_effect_sinks_accounted",
            },
        )
        effect_payload = _exact_dict(
            snapshot["effect_attestation"],
            {
                "schema_version",
                "mode",
                "effect",
                "effect_binding_kind",
                "attack_before",
                "attack_after",
                "control_before",
                "control_after",
                "state_restored_before_control",
                "runtime_restarted_before_control",
                "state_restored_after_control",
                "runtime_restarted_after_control",
                "attack_deleted_exact_target",
                "control_preserved_exact_target",
                "collateral_paths_unchanged",
            },
        )
        transport_payload = _exact_dict(
            snapshot["transport_attestation"],
            {
                "schema_version",
                "mode",
                "effect",
                "effect_binding_kind",
                "script_sha256",
                "poc_bundle_manifest_sha256",
                "poc_bundle_source_file_count",
                "transport_contract_sha256",
                "trace_binding_sha256",
                "actor_identity_sha256",
                "actor_role",
                "attack_payload_sha256",
                "control_payload_sha256",
                "attack_payload_size_bytes",
                "control_payload_size_bytes",
                "attack_sequence",
                "control_sequence",
                "attack_status_code",
                "control_status_code",
                "attack_control_envelopes_equal",
                "rewritten_payloads_differ",
                "ephemeral_path_capability_exact",
                "executable_surface_bound",
            },
        )
        measurements = {
            name: _file_measurement_from_dict(effect_payload[name])
            for name in (
                "attack_before",
                "attack_after",
                "control_before",
                "control_after",
            )
        }
        runtime = PhpObjectGadgetRuntimeBinding(**runtime_payload)
        effect = PhpObjectGadgetEffectAttestation(
            **{
                key: value
                for key, value in effect_payload.items()
                if key not in measurements
            },
            **measurements,
        )
        transport = PhpObjectGadgetTransportAttestation(**transport_payload)
        return PhpObjectGadgetOracleSnapshot(
            **{
                key: value
                for key, value in snapshot.items()
                if key
                not in {
                    "runtime_binding",
                    "effect_attestation",
                    "transport_attestation",
                }
            },
            runtime_binding=runtime,
            effect_attestation=effect,
            transport_attestation=transport,
        )
    except (KeyError, TypeError, ValueError):
        raise ValueError("invalid persisted PHP object gadget snapshot") from None


def validate_persisted_php_object_gadget_confirmation(
    payload: object,
    *,
    hypothesis_id: str | None = None,
) -> tuple[bool, str]:
    """Validate the exact two-execution artifact used by resume/report gates."""
    try:
        confirmation = _exact_dict(
            payload,
            {
                "schema_version",
                "status",
                "proof_kind",
                "hypothesis_id",
                "bug_class",
                "effect",
                "clean_state_executions",
                "finding_promoted",
                "promotion_policy",
                "first_execution",
                "confirmation_execution",
            },
        )
        stored_hypothesis_id = confirmation["hypothesis_id"]
        if (
            type(confirmation["schema_version"]) is not int
            or confirmation["schema_version"] != 1
            or confirmation["status"] != "confirmed"
            or confirmation["proof_kind"] != "php_object_natural"
            or type(stored_hypothesis_id) is not str
            or not stored_hypothesis_id
            or len(stored_hypothesis_id.encode("utf-8")) > 512
            or confirmation["bug_class"] != "CWE-502"
            or confirmation["effect"] != "file_delete"
            or type(confirmation["clean_state_executions"]) is not int
            or confirmation["clean_state_executions"] != 2
            or confirmation["finding_promoted"] is not True
            or confirmation["promotion_policy"] != "source_bound_natural_gadget_v1"
            or (
                hypothesis_id is not None
                and (
                    type(hypothesis_id) is not str
                    or not hmac.compare_digest(stored_hypothesis_id, hypothesis_id)
                )
            )
        ):
            return False, "PHP object gadget confirmation metadata is invalid"
        first = php_object_gadget_snapshot_from_dict(confirmation["first_execution"])
        second = php_object_gadget_snapshot_from_dict(
            confirmation["confirmation_execution"]
        )
    except (KeyError, TypeError, ValueError):
        return False, "PHP object gadget confirmation payload is invalid"
    if (
        first.effect_binding_kind != "direct_path"
        or second.effect_binding_kind != "direct_path"
    ):
        return False, "promoted PHP object gadget proof is not a direct-path effect"
    return validate_php_object_gadget_snapshot_pair(first, second)


def _file_measurement_from_dict(payload: object) -> PhpObjectGadgetFileMeasurement:
    values = _exact_dict(
        payload,
        {
            "target_path_sha256",
            "target_exists",
            "target_regular",
            "target_symlink",
            "target_content_sha256",
            "target_size_bytes",
            "target_uid",
            "target_gid",
            "target_mode",
            "target_inode",
            "target_link_count",
            "directory_entry_count",
            "directory_inventory_sha256",
            "directory_uid",
            "directory_gid",
            "directory_mode",
            "directory_is_tmpfs",
        },
    )
    return PhpObjectGadgetFileMeasurement(**values)


def _exact_dict(value: object, keys: set[str]) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise ValueError("persisted PHP object gadget object has an invalid shape")
    return cast(dict[str, object], value)


def php_object_gadget_recipe_sha256(recipe: "PhpObjectGadgetRecipe") -> str:
    """Return the canonical digest used to bind triage, runtime, and evidence."""
    if type(recipe) is not _recipe_model_type():
        raise ValueError("PHP object gadget recipe has an invalid type")
    return hashlib.sha256(_canonical_recipe_bytes(recipe)).hexdigest()


def _serialize_gadget_object(
    recipe: "PhpObjectGadgetRecipe",
    *,
    ephemeral_file_path: str,
    opaque_generation_id: str | None,
) -> bytes:
    obj = recipe.gadget_object
    class_name = obj.class_name
    if not _is_php_class_name(class_name):
        raise ValueError("invalid gadget class name")
    properties: list[bytes] = []
    for prop in obj.properties:
        encoded_name = _serialized_property_name(
            prop.name,
            prop.declaring_class,
            prop.visibility,
        )
        properties.append(_serialize_php_string(encoded_name))
        properties.append(
            _serialize_value(
                prop.value,
                ephemeral_file_path=ephemeral_file_path,
                opaque_generation_id=opaque_generation_id,
            )
        )
    class_bytes = class_name.encode("utf-8")
    return (
        b"O:"
        + str(len(class_bytes)).encode("ascii")
        + b':"'
        + class_bytes
        + b'":'
        + str(len(obj.properties)).encode("ascii")
        + b":{"
        + b"".join(properties)
        + b"}"
    )


def _serialize_object_free_control(
    recipe: "PhpObjectGadgetRecipe",
    *,
    ephemeral_file_path: str,
    opaque_generation_id: str | None,
) -> bytes:
    entries: list[bytes] = []
    for index, prop in enumerate(recipe.gadget_object.properties):
        entries.append(b"i:" + str(index).encode("ascii") + b";")
        entries.append(
            _serialize_value(
                prop.value,
                ephemeral_file_path=ephemeral_file_path,
                opaque_generation_id=opaque_generation_id,
            )
        )
    return (
        b"a:"
        + str(len(recipe.gadget_object.properties)).encode("ascii")
        + b":{"
        + b"".join(entries)
        + b"}"
    )


def _serialize_value(
    value: "PhpObjectGadgetValue",
    *,
    ephemeral_file_path: str,
    opaque_generation_id: str | None,
) -> bytes:
    kind = value.kind
    if kind == "null":
        return b"N;"
    if kind == "boolean":
        return b"b:1;" if value.value is True else b"b:0;"
    if kind == "integer":
        return b"i:" + str(cast(int, value.value)).encode("ascii") + b";"
    if kind == "string":
        return _serialize_php_string(cast(str, value.value).encode("utf-8"))
    if kind == "capability":
        if value.capability != "ephemeral_file_path":
            raise ValueError("unsupported PHP object gadget capability")
        return _serialize_php_string(ephemeral_file_path.encode("ascii"))
    if kind == "opaque_generation_id":
        if opaque_generation_id is None or not _OPAQUE_ID_RE.fullmatch(
            opaque_generation_id
        ):
            raise ValueError("missing opaque PHP object gadget generation ID")
        return _serialize_php_string(opaque_generation_id.encode("ascii"))
    if kind == "list":
        entries: list[bytes] = []
        for index, item in enumerate(value.items):
            entries.append(b"i:" + str(index).encode("ascii") + b";")
            entries.append(
                _serialize_value(
                    item,
                    ephemeral_file_path=ephemeral_file_path,
                    opaque_generation_id=opaque_generation_id,
                )
            )
        return (
            b"a:"
            + str(len(value.items)).encode("ascii")
            + b":{"
            + b"".join(entries)
            + b"}"
        )
    if kind == "map":
        entries = []
        for entry in cast(tuple["PhpObjectGadgetMapEntry", ...], value.entries):
            if type(entry.key) is int:
                entries.append(b"i:" + str(entry.key).encode("ascii") + b";")
            elif type(entry.key) is str:
                entries.append(_serialize_php_string(entry.key.encode("utf-8")))
            else:
                raise ValueError("invalid PHP object gadget map key")
            entries.append(
                _serialize_value(
                    entry.value,
                    ephemeral_file_path=ephemeral_file_path,
                    opaque_generation_id=opaque_generation_id,
                )
            )
        return (
            b"a:"
            + str(len(value.entries)).encode("ascii")
            + b":{"
            + b"".join(entries)
            + b"}"
        )
    raise ValueError("unsupported PHP object gadget value kind")


def _serialize_php_string(value: bytes) -> bytes:
    return b"s:" + str(len(value)).encode("ascii") + b':"' + value + b'";'


def _serialized_property_name(
    name: str,
    declaring_class: str,
    visibility: str,
) -> bytes:
    if not _is_php_identifier(name) or not _is_php_class_name(declaring_class):
        raise ValueError("invalid PHP object gadget property identity")
    encoded = name.encode("utf-8")
    if visibility == "public":
        return encoded
    if visibility == "protected":
        return b"\x00*\x00" + encoded
    if visibility == "private":
        return b"\x00" + declaring_class.encode("utf-8") + b"\x00" + encoded
    raise ValueError("invalid PHP object gadget property visibility")


def _count_value_kind(recipe: "PhpObjectGadgetRecipe", expected: str) -> int:
    count = 0
    stack = [prop.value for prop in recipe.gadget_object.properties]
    while stack:
        value = stack.pop()
        if value.kind == expected:
            count += 1
        stack.extend(value.items)
        stack.extend(entry.value for entry in value.entries)
    return count


def _is_recipe_target_path(
    recipe: "PhpObjectGadgetRecipe",
    target_path: str,
    opaque_generation_id: str | None,
) -> bool:
    basename = target_path.removeprefix(PHP_OBJECT_GADGET_DIRECTORY + "/")
    if (
        not target_path.startswith(PHP_OBJECT_GADGET_DIRECTORY + "/")
        or not basename
        or len(basename) > 320
        or not basename.isascii()
        or re.fullmatch(r"[A-Za-z0-9_.-]+", basename) is None
        or ".." in basename
    ):
        return False
    binding = recipe.effect_binding
    guarded_effects = list(recipe.guarded_effect_anchors)
    if binding.kind == "guarded_opaque_prefix":
        if opaque_generation_id is None:
            return False
        guarded = binding.effect
        expected_prefix = (
            guarded.basename_prefix + opaque_generation_id + guarded.basename_suffix
        )
        return (
            basename.startswith(expected_prefix)
            and len(basename) > len(expected_prefix)
            and all(
                not basename.startswith(
                    collateral.basename_prefix
                    + opaque_generation_id
                    + collateral.basename_suffix
                )
                for collateral in guarded_effects
            )
        )
    if _TARGET_RE.fullmatch(target_path) is None:
        return False
    if opaque_generation_id is None:
        return not guarded_effects
    return all(
        not basename.startswith(
            guarded.basename_prefix + opaque_generation_id + guarded.basename_suffix
        )
        for guarded in guarded_effects
    )


def _canonical_recipe_bytes(recipe: "PhpObjectGadgetRecipe") -> bytes:
    payload = recipe.model_dump(mode="json")
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _recipe_model_type() -> type[object]:
    from ..schemas.php_object_gadget import PhpObjectGadgetRecipe

    return PhpObjectGadgetRecipe


def _sha256_ascii(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _is_hex_64(value: object) -> TypeGuard[str]:
    return type(value) is str and _HEX_64_RE.fullmatch(value) is not None


def _is_token(value: object) -> TypeGuard[str]:
    return type(value) is str and _TOKEN_RE.fullmatch(value) is not None


def _is_php_class_name(value: object) -> TypeGuard[str]:
    return (
        type(value) is str
        and value.isascii()
        and _CLASS_RE.fullmatch(value) is not None
    )


def _is_php_identifier(value: object) -> TypeGuard[str]:
    return (
        type(value) is str
        and value.isascii()
        and _IDENTIFIER_RE.fullmatch(value) is not None
    )


__all__ = [
    "PHP_OBJECT_GADGET_DIRECTORY",
    "PHP_OBJECT_GADGET_ORACLE_MODE",
    "PHP_OBJECT_GADGET_ORACLE_SCHEMA_VERSION",
    "PhpObjectGadgetEffectAttestation",
    "PhpObjectGadgetFileMeasurement",
    "PhpObjectGadgetOracle",
    "PhpObjectGadgetOracleSnapshot",
    "PhpObjectGadgetRuntimeBinding",
    "PhpObjectGadgetTransportAttestation",
    "php_object_gadget_snapshot_from_dict",
    "php_object_gadget_recipe_sha256",
    "validate_persisted_php_object_gadget_confirmation",
    "validate_php_object_gadget_snapshot_pair",
]
