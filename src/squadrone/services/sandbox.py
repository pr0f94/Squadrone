"""SandboxManager — async context manager that boots an isolated WP+DB sandbox."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import posixpath
import re
import secrets
import signal
import shutil
import socket
import statistics
import sys
import tempfile
import time
import uuid
from pathlib import Path, PurePosixPath
from typing import Literal, Optional, cast
from urllib.parse import unquote, urlparse, urlsplit

import httpx
from jinja2 import Template
from pydantic import BaseModel, Field, ValidationError

from ..poc_isolation import (
    CROSS_OBJECT_HTTP_CAPABILITY,
    prepare_poc_isolation,
)
from ..poc_proxy import (
    PocProxySupervisor,
    normalize_trace_origin,
    salted_scalar_sha256,
)
from ..schemas.config import SandboxConfig
from ..schemas.observation import PoCObservation
from ..schemas.taxonomy import (
    BugClass,
    KNOWN_CWE_REGISTRY,
    get_known_cwe_profile,
)
from .roles import UNKNOWN_ATTACKER_ROLE, normalize_attacker_role
from .ssrf_oracle import (
    ALLOWED_ORACLE_METHODS,
    LOCAL_RESOURCE_SSRF_DIRECTORY,
    LOCAL_RESOURCE_SSRF_MODE,
    LocalResourceSsrfOracle,
    LocalResourceSsrfProvisioningAttestation,
    LocalResourceSsrfSnapshot,
    LocalResourceSsrfVerificationAttestation,
    SsrfOracleHit,
    SsrfOracleServer,
    SsrfOracleSnapshot,
)
from .wp_cli import WPCli

logger = logging.getLogger(__name__)

_PORT_MIN = 8100
_PORT_MAX = 8200
_PROJECT_PREFIX = "squadrone"
_DOCKER_DIR = Path(__file__).resolve().parents[3] / "docker"
_ACTOR_RECEIPT_TEMPLATE = _DOCKER_DIR / "squadrone-actor-receipt.php.j2"
_PORT_ALLOC_LOCK = asyncio.Lock()
_PLUGIN_SLUG_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,199}\Z")
_SHA256_RE = re.compile(r"[0-9a-fA-F]{64}\Z")
_SSRF_ORACLE_MODES = frozenset({"http", "local_resource"})
WORDPRESS_WEB_USER = "www-data"
_POC_OUTPUT_LIMIT_BYTES = 4 * 1024 * 1024
_POC_OUTPUT_READ_BYTES = 64 * 1024
_POC_COMPATIBILITY_ENV_NAMES = frozenset(
    {
        "APPDATA",
        "HOME",
        "LANG",
        "LC_ALL",
        "LOCALAPPDATA",
        "PATH",
        "PLAYWRIGHT_BROWSERS_PATH",
        "PLAYWRIGHT_NODEJS_PATH",
        "REQUESTS_CA_BUNDLE",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "TZ",
        "USERPROFILE",
        "VIRTUAL_ENV",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "__PYVENV_LAUNCHER__",
    }
)


def validate_plugin_slug(plugin_slug: str) -> str:
    """Return a slug that is safe to use as one plugin-directory component."""
    if not isinstance(plugin_slug, str) or not _PLUGIN_SLUG_RE.fullmatch(plugin_slug):
        raise ValueError(
            "plugin slug must contain only lowercase ASCII letters, digits, "
            "hyphens, and underscores, and must start with a letter or digit"
        )
    return plugin_slug


class SandboxRunResult(BaseModel):
    success: bool
    output: str
    elapsed: float
    http_status: Optional[int] = None
    response: Optional[str] = None
    error_log: Optional[str] = None
    evidence: dict = Field(default_factory=dict)
    observation: Optional[PoCObservation] = None
    validation_reason: str = ""


POC_RESULT_PREFIX = "SQUADRONE_RESULT="

_CROSS_OBJECT_ACCESS_TYPES = frozenset({"read", "write"})
_CROSS_OBJECT_CONTROL_BASES = frozenset(
    {"attacker_owned", "public", "authorized_actor"}
)
_CROSS_OBJECT_WRITE_EFFECTS = frozenset({"modify", "delete"})
_CROSS_OBJECT_PROVENANCE_TYPES = frozenset(
    {"setup_id", "create_response", "unique_lookup"}
)
_CROSS_OBJECT_OBJECT_LOCATIONS = frozenset(
    {"query", "form", "json", "multipart", "path"}
)
_CROSS_OBJECT_PROTECTION_SCOPES = frozenset({"object", "owner_filtered_collection"})
_CROSS_OBJECT_FIELD_LOCATIONS = frozenset({"query", "form", "json", "multipart"})
_CROSS_OBJECT_REQUEST_FIELDS = (
    "method",
    "route",
    "object_parameter",
    "object_type",
    "object_location",
)
_CROSS_OBJECT_SHARED_ROUTES = frozenset(
    {
        "/",
        "/wp-admin/admin.php",
        "/wp-admin/admin-ajax.php",
        "/wp-admin/admin-post.php",
    }
)
_CROSS_OBJECT_MARKER_PLACEHOLDERS = frozenset(
    {
        "attack-marker",
        "attack_marker",
        "control-marker",
        "control_marker",
        "marker",
        "placeholder",
        "replace-me",
        "replace_with_marker",
        "test-marker",
        "test_marker",
    }
)
_CROSS_OBJECT_SENTINEL_PREFIX = "SQUADRONE_"
_CROSS_OBJECT_SENTINEL_RE = re.compile(r"SQUADRONE_[A-Za-z0-9_.:-]{2,246}\Z")
_CROSS_OBJECT_REQUEST_SENTINEL_FLAGS = frozenset(
    {
        "target",
        "target_encoded",
        "body",
        "body_encoded",
        "headers",
        "headers_encoded",
    }
)
_CROSS_OBJECT_VALUE_TEMPLATE_TOKEN = "{object_id}"
_SSRF_ORACLE_HOST = "host.docker.internal"
_SSRF_ORACLE_PATH_PREFIX = "/_squadrone/ssrf/"
_SSRF_REQUEST_LOCATIONS = frozenset({"query", "form", "json", "multipart"})
_SSRF_REQUEST_FIELDS = (
    "method",
    "route",
    "destination_parameter",
    "destination_location",
)

_ALLOWED_ORACLES: dict[str, set[str]] = {
    bug_class.name: set(profile.allowed_oracles)
    for bug_class, profile in KNOWN_CWE_REGISTRY.items()
    if profile.allowed_oracles
}


def _allowed_oracles_for(expected_bug_class: str | None) -> set[str] | None:
    """Resolve an exact reviewed policy; open and invalid CWEs stay fail-closed."""
    if not expected_bug_class:
        return None
    declared = _ALLOWED_ORACLES.get(expected_bug_class)
    if declared is not None:
        return set(declared)
    try:
        bug_class = BugClass(expected_bug_class)
    except (TypeError, ValueError):
        return None
    profile = get_known_cwe_profile(bug_class)
    if profile is None:
        return None
    return set(profile.allowed_oracles)


def _requires_cross_object_isolation(expected_bug_class: str | None) -> bool:
    """Return whether this hypothesis can emit the trusted cross-object oracle."""
    return "cross_object_access" in (_allowed_oracles_for(expected_bug_class) or set())


def _is_ssrf_bug_class(expected_bug_class: str | None) -> bool:
    """Return whether an exact known SSRF identifier was supplied."""
    return expected_bug_class in {BugClass.SSRF.name, BugClass.SSRF.value}


def _requires_trusted_http_isolation(expected_bug_class: str | None) -> bool:
    """Route trace-bound HTTP proofs through the existing strict boundary."""
    return _is_ssrf_bug_class(expected_bug_class) or _requires_cross_object_isolation(
        expected_bug_class
    )


def _poc_protected_paths(workdir: Path | None) -> tuple[Path, ...]:
    """Return known host credential/state locations layered over default-deny."""
    project_root = Path(__file__).resolve().parents[3]
    user_home = Path.home()
    candidates: list[Path] = [
        project_root / ".env",
        project_root / ".env.local",
        project_root / ".env.paypal",
        user_home / ".ssh",
        user_home / ".aws",
        user_home / ".docker",
        user_home / ".kube",
        user_home / ".config" / "gcloud",
        user_home / "Library" / "Keychains",
    ]
    if workdir is not None:
        candidates.append(workdir)
    return tuple(dict.fromkeys(path.absolute() for path in candidates))


def _compatibility_poc_environment() -> dict[str, str]:
    """Retain browser/runtime paths without exposing parent service credentials."""
    environment = {
        name: os.environ[name]
        for name in _POC_COMPATIBILITY_ENV_NAMES
        if name in os.environ
    }
    environment.setdefault("HOME", os.fspath(Path.home()))
    environment.setdefault("PATH", os.defpath)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    local_hosts = "localhost,127.0.0.1,::1,host.docker.internal"
    environment["NO_PROXY"] = local_hosts
    environment["no_proxy"] = local_hosts
    return environment


def _parse_poc_observation(stdout: str) -> tuple[PoCObservation | None, str]:
    nonempty_lines = [line for line in stdout.splitlines() if line.strip()]
    payload_lines = [
        line for line in nonempty_lines if line.startswith(POC_RESULT_PREFIX)
    ]
    if not payload_lines:
        return None, f"missing final {POC_RESULT_PREFIX}<json> observation"
    if len(payload_lines) != 1:
        return None, "PoC emitted more than one structured result observation"
    payload_line = payload_lines[0]
    if nonempty_lines[-1] != payload_line:
        return None, "structured result observation is not the final output line"
    raw = payload_line[len(POC_RESULT_PREFIX) :].strip()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, f"invalid observation JSON: {exc}"
    try:
        return PoCObservation.model_validate(payload), ""
    except ValidationError as exc:
        return None, f"observation schema validation failed: {exc}"


def _claim_identifier(value: object) -> str:
    """Normalize an identifier without accepting booleans as IDs.

    Decimal representations are canonicalized so that, for example, ``2`` and
    ``"02"`` cannot be presented as different principals or objects.
    """
    if isinstance(value, bool) or not isinstance(value, str | int):
        return ""
    identifier = str(value).strip()
    if re.fullmatch(r"\+?[0-9]+", identifier):
        digits = identifier.lstrip("+").lstrip("0")
        return digits or "0"
    return identifier


def _wp_user_identifier(value: object) -> str:
    """Return one canonical positive WordPress user ID, or an empty string."""
    identifier = _claim_identifier(value)
    if not re.fullmatch(r"[1-9][0-9]*", identifier):
        return ""
    return identifier


def _claim_role(value: object) -> str:
    """Canonicalize known roles while keeping stable custom owner-role labels."""
    raw = str(value or "").strip()
    canonical = normalize_attacker_role(raw)
    return raw.casefold() if canonical == UNKNOWN_ATTACKER_ROLE else canonical


def _state_contains_marker(state: object, marker: str) -> bool:
    """Recompute marker presence from the emitted state instead of trusting a flag."""
    try:
        rendered = json.dumps(state, sort_keys=True, default=str)
    except (TypeError, ValueError):
        rendered = str(state)
    return marker in rendered


def _cross_object_write_marker_transition(
    arm: dict, *, state: Literal["before", "after"]
) -> tuple[bool | None, str]:
    """Read one write-marker flag without breaking historical PoC artifacts.

    The original field names are ambiguous beside ``baseline_marker``.  New PoCs
    use ``write_marker_present_before``/``write_marker_present_after``; legacy
    names remain accepted only when they agree with the canonical value.
    """
    canonical_key = f"write_marker_present_{state}"
    legacy_key = f"{state}_marker_present"
    canonical_present = canonical_key in arm
    legacy_present = legacy_key in arm
    if not canonical_present and not legacy_present:
        return None, (
            f"requires {canonical_key} (legacy {legacy_key} is also accepted)"
        )

    canonical = arm.get(canonical_key)
    legacy = arm.get(legacy_key)
    if canonical_present and not isinstance(canonical, bool):
        return None, f"{canonical_key} must be a boolean"
    if legacy_present and not isinstance(legacy, bool):
        return None, f"{legacy_key} must be a boolean"
    if canonical_present and legacy_present and canonical is not legacy:
        return None, f"{canonical_key} conflicts with legacy {legacy_key}"
    return (canonical if canonical_present else legacy), ""


def _normalize_request_path(value: str) -> str:
    """Return a decoded, slash-normalized absolute HTTP path."""
    decoded = unquote(value.strip()).replace("\\", "/")
    if not decoded.startswith("/"):
        return ""
    return posixpath.normpath(re.sub(r"/+", "/", decoded))


def _cross_object_dispatch_signature(
    value: object,
) -> tuple[tuple[str, str], ...] | None:
    """Canonicalize stable dispatcher fields such as AJAX action or admin tab."""
    if value is None:
        return ()
    if not isinstance(value, dict):
        return None
    normalized: list[tuple[str, str]] = []
    for raw_key, raw_value in value.items():
        if not isinstance(raw_key, str) or not isinstance(raw_value, str):
            return None
        location, separator, name = raw_key.strip().partition(":")
        expected = raw_value.strip()
        if (
            not separator
            or location not in _CROSS_OBJECT_FIELD_LOCATIONS
            or not name.strip()
            or not expected
        ):
            return None
        normalized.append((f"{location}:{name.strip()}", expected))
    if len({key for key, _value in normalized}) != len(normalized):
        return None
    return tuple(sorted(normalized))


def _cross_object_field_spec(value: object) -> tuple[str, str] | None:
    """Parse one typed request-field declaration such as ``form:title``."""
    if not isinstance(value, str):
        return None
    location, separator, name = value.strip().partition(":")
    if (
        not separator
        or location not in _CROSS_OBJECT_FIELD_LOCATIONS
        or not name.strip()
        or name != name.strip()
    ):
        return None
    return location, name


def _cross_object_typed_fields(
    value: dict,
    *,
    object_location: str,
    object_parameter: str,
) -> tuple[object, ...] | None:
    """Validate explicitly allowed attack/control value differences."""
    marker_raw = value.get("marker_field")
    owner_raw = value.get("owner_field")
    marker_field = (
        ()
        if marker_raw is None or marker_raw == ""
        else _cross_object_field_spec(marker_raw)
    )
    owner_field = (
        ()
        if owner_raw is None or owner_raw == ""
        else _cross_object_field_spec(owner_raw)
    )
    if marker_field is None or owner_field is None:
        return None

    csrf_raw = value.get("csrf_fields", [])
    if not isinstance(csrf_raw, list):
        return None
    csrf_fields: list[tuple[str, str]] = []
    for raw in csrf_raw:
        parsed = _cross_object_field_spec(raw)
        if parsed is None:
            return None
        csrf_fields.append(parsed)
    if len(set(csrf_fields)) != len(csrf_fields):
        return None

    declared = [
        item
        for item in (marker_field, owner_field, *csrf_fields)
        if isinstance(item, tuple) and item
    ]
    if len(set(declared)) != len(declared):
        return None
    object_field = (
        (object_location, object_parameter) if object_location != "path" else None
    )
    if object_field is not None and object_field in declared:
        return None

    dispatch = _cross_object_dispatch_signature(value.get("dispatch"))
    if dispatch is None:
        return None
    dispatch_fields = {tuple(str(key).split(":", 1)) for key, _expected in dispatch}
    if any(item in dispatch_fields for item in declared):
        return None

    raw_template = value.get("object_value_template")
    if raw_template is None or raw_template == "":
        object_value_template = ""
    elif (
        isinstance(raw_template, str)
        and raw_template == raw_template.strip()
        and raw_template.count(_CROSS_OBJECT_VALUE_TEMPLATE_TOKEN) == 1
        and not re.search(
            r"[{}]",
            raw_template.replace(_CROSS_OBJECT_VALUE_TEMPLATE_TOKEN, ""),
        )
        and len(raw_template) <= 2048
        and object_location != "path"
    ):
        object_value_template = raw_template
    else:
        return None

    return (
        dispatch,
        object_value_template,
        marker_field,
        owner_field,
        tuple(sorted(csrf_fields)),
    )


def _cross_object_request_signature(value: object) -> tuple[object, ...] | None:
    """Canonicalize the request identity shared by both oracle arms."""
    if not isinstance(value, dict):
        return None
    normalized: list[str] = []
    for field in _CROSS_OBJECT_REQUEST_FIELDS:
        raw = value.get(field)
        if not isinstance(raw, str) or not raw.strip():
            return None
        item = raw.strip()
        normalized.append(item.upper() if field == "method" else item)

    route = _normalize_request_path(normalized[1])
    if not route or urlparse(normalized[1]).query or urlparse(normalized[1]).fragment:
        return None
    normalized[1] = route
    object_parameter = normalized[2]
    object_type = normalized[3]
    object_location = normalized[4].casefold()
    if object_type.casefold().startswith("replace-"):
        return None
    if object_location not in _CROSS_OBJECT_OBJECT_LOCATIONS:
        return None
    placeholder = "{" + object_parameter + "}"
    if object_location == "path":
        if route.count(placeholder) != 1:
            return None
    elif "{" in route or "}" in route:
        return None

    typed = _cross_object_typed_fields(
        value,
        object_location=object_location,
        object_parameter=object_parameter,
    )
    if typed is None:
        return None
    dispatch, object_value_template, marker_field, owner_field, csrf_fields = typed
    if (
        route in _CROSS_OBJECT_SHARED_ROUTES
        and not dispatch
        and not (
            object_value_template
            and object_value_template != _CROSS_OBJECT_VALUE_TEMPLATE_TOKEN
        )
    ):
        return None
    normalized[4] = object_location
    return (
        *normalized,
        dispatch,
        object_value_template,
        marker_field,
        owner_field,
        csrf_fields,
    )


def _cross_object_probe_request_signature(value: object) -> tuple[object, ...] | None:
    """Canonicalize a protection/read probe, with optional object selection."""
    if not isinstance(value, dict):
        return None
    scope = str(value.get("scope") or "").strip().casefold()
    if scope and scope not in _CROSS_OBJECT_PROTECTION_SCOPES:
        return None
    object_fields = {
        "object_parameter",
        "object_type",
        "object_location",
    }
    present = {
        field
        for field in object_fields
        if value.get(field) is not None and value.get(field) != ""
    }
    if scope == "object" and present != object_fields:
        return None
    if scope == "owner_filtered_collection" and present:
        return None
    if present:
        if present != object_fields:
            return None
        return _cross_object_request_signature(value)

    method = value.get("method")
    route_value = value.get("route")
    if (
        not isinstance(method, str)
        or not method.strip()
        or not isinstance(route_value, str)
        or not route_value.strip()
    ):
        return None
    route = _normalize_request_path(route_value)
    if not route or urlparse(route_value).query or urlparse(route_value).fragment:
        return None
    dispatch = _cross_object_dispatch_signature(value.get("dispatch"))
    if dispatch is None or (route in _CROSS_OBJECT_SHARED_ROUTES and not dispatch):
        return None
    csrf_raw = value.get("csrf_fields", [])
    if not isinstance(csrf_raw, list):
        return None
    csrf_fields: list[tuple[str, str]] = []
    for raw in csrf_raw:
        parsed = _cross_object_field_spec(raw)
        if parsed is None:
            return None
        csrf_fields.append(parsed)
    if len(set(csrf_fields)) != len(csrf_fields):
        return None
    dispatch_fields = {tuple(str(key).split(":", 1)) for key, _expected in dispatch}
    if any(field in dispatch_fields for field in csrf_fields):
        return None
    return (
        method.strip().upper(),
        route,
        "",
        "",
        "",
        dispatch,
        "",
        (),
        (),
        tuple(sorted(csrf_fields)),
    )


def _valid_cross_object_marker(value: object) -> bool:
    """Reject placeholders and low-information values masquerading as sentinels."""
    if not isinstance(value, str) or value != value.strip():
        return False
    if (
        not 12 <= len(value) <= 256
        or not value.isascii()
        or not value.isprintable()
        or _CROSS_OBJECT_SENTINEL_RE.fullmatch(value) is None
    ):
        return False
    folded = value.casefold()
    if folded in _CROSS_OBJECT_MARKER_PLACEHOLDERS:
        return False
    alphanumeric = [character.casefold() for character in value if character.isalnum()]
    return (
        any(character.isalpha() for character in value)
        and any(character.isdigit() for character in value)
        and len(set(alphanumeric)) >= 6
    )


def _decode_actor_receipt(
    record: dict,
    *,
    receipt_secret: bytes,
    trace_token: str,
) -> tuple[dict | None, str]:
    """Verify one server-signed WordPress actor identity receipt."""
    receipt = record.get("response_actor_receipt")
    if record.get("response_actor_receipt_truncated") is True:
        return None, "HTTP trace actor receipt was truncated"
    if not isinstance(receipt, str) or not receipt:
        return None, "HTTP trace response lacks a server-signed actor receipt"
    encoded, separator, signature = receipt.partition(".")
    if (
        not separator
        or not encoded
        or not encoded.isascii()
        or _SHA256_RE.fullmatch(signature) is None
        or len(encoded) > 8192
    ):
        return None, "HTTP trace actor receipt has an invalid envelope"
    expected_signature = hmac.new(
        receipt_secret,
        encoded.encode("ascii", errors="strict"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(signature.casefold(), expected_signature):
        return None, "HTTP trace actor receipt signature is invalid"
    try:
        padding = "=" * (-len(encoded) % 4)
        payload = json.loads(base64.urlsafe_b64decode(encoded + padding))
    except (ValueError, TypeError, UnicodeDecodeError):
        return None, "HTTP trace actor receipt payload is invalid"
    required_keys = {
        "v",
        "trace_token",
        "nonce",
        "request_nonce",
        "request_digest",
        "user_id",
        "roles",
        "method",
        "path",
    }
    if not isinstance(payload, dict) or set(payload) != required_keys:
        return None, "HTTP trace actor receipt payload has an invalid shape"
    if payload.get("v") != 2:
        return None, "HTTP trace actor receipt version is unsupported"
    payload_token = payload.get("trace_token")
    if not isinstance(payload_token, str) or not hmac.compare_digest(
        payload_token, trace_token
    ):
        return None, "HTTP trace actor receipt belongs to a different sandbox"
    nonce = payload.get("nonce")
    if not isinstance(nonce, str) or re.fullmatch(r"[0-9a-f]{32}", nonce) is None:
        return None, "HTTP trace actor receipt nonce is invalid"
    request_nonce = payload.get("request_nonce")
    record_nonce = record.get("request_nonce")
    if (
        not isinstance(request_nonce, str)
        or re.fullmatch(r"[0-9a-f]{64}", request_nonce) is None
        or not isinstance(record_nonce, str)
        or not hmac.compare_digest(request_nonce, record_nonce)
    ):
        return None, "HTTP trace actor receipt request nonce does not match"
    request_digest = payload.get("request_digest")
    record_digest = record.get("request_digest")
    if (
        not isinstance(request_digest, str)
        or _SHA256_RE.fullmatch(request_digest) is None
        or request_digest != request_digest.casefold()
        or not isinstance(record_digest, str)
        or not hmac.compare_digest(request_digest, record_digest)
    ):
        return None, "HTTP trace actor receipt request digest does not match"
    user_id = payload.get("user_id")
    if isinstance(user_id, bool) or not isinstance(user_id, int) or user_id < 0:
        return None, "HTTP trace actor receipt user_id is invalid"
    roles = payload.get("roles")
    if (
        not isinstance(roles, list)
        or any(
            not isinstance(role, str) or not role.strip() or role != role.strip()
            for role in roles
        )
        or roles != sorted(set(roles))
        or (user_id == 0 and roles)
    ):
        return None, "HTTP trace actor receipt roles are invalid"
    receipt_method = payload.get("method")
    receipt_path = payload.get("path")
    if (
        not isinstance(receipt_method, str)
        or receipt_method.upper() != str(record.get("method") or "").upper()
        or not isinstance(receipt_path, str)
        or _normalize_request_path(receipt_path)
        != _normalize_request_path(str(record.get("path") or ""))
    ):
        return None, "HTTP trace actor receipt does not match its request"
    return payload, ""


def _trace_body_parts(record: dict) -> tuple[bytes, bytes, bool] | None:
    """Decode the bounded response capture retained only for live validation."""
    if (
        record.get("record_type") != "request"
        or record.get("forward_state") != "completed"
        or record.get("forward_error") is not None
        or record.get("terminal") is not False
        or record.get("request_body_parse_error") is not None
        or record.get("request_metadata_omitted") is not None
        or record.get("response_capture_omitted") is not None
    ):
        return None
    head = record.get("response_body_b64")
    tail = record.get("response_body_tail_b64")
    truncated = record.get("response_body_truncated")
    length = record.get("response_body_length")
    digest = record.get("response_body_sha256")
    if (
        not isinstance(head, str)
        or not isinstance(tail, str)
        or not isinstance(truncated, bool)
        or not isinstance(length, int)
        or isinstance(length, bool)
        or length < 0
        or not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
    ):
        return None
    try:
        head_bytes = base64.b64decode(head, validate=True)
        tail_bytes = base64.b64decode(tail, validate=True)
    except (ValueError, TypeError):
        return None
    if truncated:
        if not tail_bytes or length <= len(head_bytes) + len(tail_bytes):
            return None
    elif (
        tail_bytes
        or len(head_bytes) != length
        or hashlib.sha256(head_bytes).hexdigest() != digest
    ):
        return None
    return head_bytes, tail_bytes, truncated


def _trace_marker_state(record: dict, marker: str) -> bool | None:
    """Return measured marker presence, or None when a truncated middle is unknown."""
    parts = _trace_body_parts(record)
    if parts is None:
        return None
    head, tail, truncated = parts
    encoded_marker = marker.encode("utf-8")
    if encoded_marker in head or encoded_marker in tail:
        return True
    return None if truncated else False


def _trace_field_digests(record: dict, location: str, name: str) -> list[str] | None:
    fields = record.get("fields")
    if not isinstance(fields, list):
        return None
    matches: list[str] = []
    for field in fields:
        if not isinstance(field, dict):
            return None
        if (
            field.get("location") not in _CROSS_OBJECT_FIELD_LOCATIONS
            or not isinstance(field.get("name"), str)
            or not field.get("name")
            or field.get("kind") not in {"scalar", "file"}
            or not isinstance(field.get("value_sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", field["value_sha256"]) is None
            or not isinstance(field.get("contains_squadrone_sentinel"), bool)
        ):
            return None
        if field.get("location") == location and field.get("name") == name:
            digest = field.get("value_sha256")
            if field.get("kind") != "scalar" or not isinstance(digest, str):
                return None
            matches.append(digest)
    return matches


def _trace_field_signature(record: dict) -> tuple[tuple[object, ...], ...] | None:
    """Return every hashed request field after validating the record shape."""
    fields = record.get("fields")
    if not isinstance(fields, list):
        return None
    normalized: list[tuple[object, ...]] = []
    for field in fields:
        if not isinstance(field, dict):
            return None
        location = field.get("location")
        name = field.get("name")
        kind = field.get("kind")
        digest = field.get("value_sha256")
        has_sentinel = field.get("contains_squadrone_sentinel")
        if (
            location not in _CROSS_OBJECT_FIELD_LOCATIONS
            or not isinstance(name, str)
            or not name
            or kind not in {"scalar", "file"}
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or not isinstance(has_sentinel, bool)
            or (kind == "file" and has_sentinel)
        ):
            return None
        normalized.append((location, name, kind, digest, has_sentinel))
    return tuple(sorted(normalized))


def _trace_tracked_capability_fields(
    record: dict,
    *,
    allowed_labels: frozenset[str],
) -> tuple[tuple[str, str, str], ...] | None:
    """Return value-free tracked-capability locations from a supervised request."""
    fields = record.get("fields")
    header_labels = record.get("request_tracked_capabilities_in_headers")
    if (
        not isinstance(fields, list)
        or not isinstance(header_labels, list)
        or any(not isinstance(label, str) for label in header_labels)
        or header_labels != sorted(set(header_labels))
        or not set(header_labels) <= allowed_labels
    ):
        return None
    occurrences: list[tuple[str, str, str]] = [
        ("header", "*", label) for label in header_labels
    ]
    for field in fields:
        if not isinstance(field, dict):
            return None
        labels = field.get("tracked_capabilities")
        if (
            not isinstance(labels, list)
            or any(not isinstance(label, str) for label in labels)
            or labels != sorted(set(labels))
            or not set(labels) <= allowed_labels
        ):
            return None
        location = field.get("location")
        name = field.get("name")
        if not isinstance(location, str) or not isinstance(name, str):
            return None
        occurrences.extend((location, name, label) for label in labels)
    return tuple(sorted(occurrences))


def _trace_parameter_shape(record: dict) -> tuple[tuple[object, ...], ...] | None:
    raw_shape = record.get("parameter_shape")
    if not isinstance(raw_shape, list):
        return None
    normalized: list[tuple[object, ...]] = []
    for item in raw_shape:
        if not isinstance(item, dict):
            return None
        location = item.get("location")
        name = item.get("name")
        kind = item.get("kind")
        count = item.get("count")
        if (
            location not in _CROSS_OBJECT_FIELD_LOCATIONS
            or not isinstance(name, str)
            or not name
            or kind not in {"scalar", "file"}
            or not isinstance(count, int)
            or isinstance(count, bool)
            or count < 1
        ):
            return None
        normalized.append((location, name, kind, count))
    return tuple(sorted(normalized))


def _trace_request_sentinel_categories(record: dict) -> frozenset[str] | None:
    """Validate the proxy's fixed, value-free raw-wire sentinel classification."""
    flags = record.get("request_sentinel_flags")
    categories = record.get("request_sentinel_categories")
    if (
        not isinstance(flags, dict)
        or set(flags) != _CROSS_OBJECT_REQUEST_SENTINEL_FLAGS
        or any(not isinstance(value, bool) for value in flags.values())
        or not isinstance(categories, list)
        or any(not isinstance(value, str) for value in categories)
    ):
        return None
    expected = sorted(name for name, present in flags.items() if present)
    if categories != expected:
        return None
    return frozenset(categories)


def _receipt_has_expected_role(payload: dict, expected_role: str) -> bool:
    canonical = normalize_attacker_role(expected_role)
    roles = {
        normalize_attacker_role(role)
        for role in payload.get("roles", [])
        if isinstance(role, str)
    }
    roles.discard(UNKNOWN_ATTACKER_ROLE)
    if canonical == "unauthenticated":
        return payload.get("user_id") == 0 and not roles
    if canonical == "low_priv":
        return bool(
            roles
            & {
                "subscriber",
                "customer",
                "contributor",
                "author",
                "low_priv",
            }
        )
    return canonical != UNKNOWN_ATTACKER_ROLE and canonical in roles


def _receipt_has_only_expected_privileges(payload: dict, expected_role: str) -> bool:
    """Reject an SSRF proof actor carrying any undeclared elevated role."""
    canonical = normalize_attacker_role(expected_role)
    roles = {
        normalize_attacker_role(role)
        for role in payload.get("roles", [])
        if isinstance(role, str)
    }
    if UNKNOWN_ATTACKER_ROLE in roles:
        return False
    user_id = payload.get("user_id")
    if canonical == "unauthenticated":
        return user_id == 0 and not roles
    if not isinstance(user_id, int) or isinstance(user_id, bool) or user_id < 1:
        return False
    low_privilege_roles = {
        "subscriber",
        "customer",
        "contributor",
        "author",
        "low_priv",
    }
    if canonical == "low_priv":
        return bool(roles) and roles <= low_privilege_roles
    return canonical != UNKNOWN_ATTACKER_ROLE and roles == {canonical}


def _resolved_trace_path(
    request_signature: tuple[object, ...], object_id: str | None
) -> str:
    route = str(request_signature[1])
    if request_signature[4] == "path":
        if object_id is None:
            return ""
        route = route.replace(
            "{" + str(request_signature[2]) + "}",
            object_id,
        )
    return _normalize_request_path(route)


def _trace_request_binding(
    record: dict,
    request_signature: tuple[object, ...],
    *,
    object_id: str | None,
    expected_user_id: int,
    expected_role: str | None,
    trace_salt: bytes,
    target_origin: str,
    receipt_secret: bytes,
    trace_token: str,
    allow_credential_free_unauthenticated: bool = False,
) -> dict | None:
    """Return trusted request/actor metadata when one trace record matches."""
    sequence = record.get("sequence")
    status = record.get("status_code")
    if (
        record.get("trace_version") != 1
        or record.get("record_type") != "request"
        or record.get("forward_state") != "completed"
        or record.get("forward_error") is not None
        or record.get("terminal") is not False
        or record.get("request_body_parse_error") is not None
        or record.get("request_metadata_omitted") is not None
        or record.get("response_capture_omitted") is not None
        or not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or sequence < 1
        or not isinstance(status, int)
        or isinstance(status, bool)
        or not 100 <= status <= 599
        or record.get("origin") != target_origin
        or str(record.get("method") or "").upper() != request_signature[0]
        or _normalize_request_path(str(record.get("path") or ""))
        != _resolved_trace_path(request_signature, object_id)
    ):
        return None

    object_location = str(request_signature[4])
    if object_location and object_location != "path":
        if object_id is None:
            return None
        object_digests = _trace_field_digests(
            record,
            object_location,
            str(request_signature[2]),
        )
        object_value_template = str(request_signature[6])
        expected_object_value = (
            object_value_template.replace(
                _CROSS_OBJECT_VALUE_TEMPLATE_TOKEN,
                object_id,
            )
            if object_value_template
            else object_id
        )
        if object_digests != [salted_scalar_sha256(expected_object_value, trace_salt)]:
            return None

    dispatch = request_signature[5]
    if not isinstance(dispatch, tuple):
        return None
    for key, expected_value in dispatch:
        location, name = str(key).split(":", 1)
        digests = _trace_field_digests(record, location, name)
        if digests != [salted_scalar_sha256(expected_value, trace_salt)]:
            return None

    actor, _reason = _decode_actor_receipt(
        record,
        receipt_secret=receipt_secret,
        trace_token=trace_token,
    )
    if actor is None:
        if not (
            allow_credential_free_unauthenticated
            and expected_user_id == 0
            and normalize_attacker_role(expected_role or "") == "unauthenticated"
            and record.get("response_actor_receipt") is None
            and record.get("response_actor_receipt_truncated") is False
            and record.get("credential_free_transport") is True
        ):
            return None
        actor = {
            "user_id": 0,
            "roles": [],
            "provenance": "credential_free_transport",
        }
    else:
        actor = dict(actor)
        actor["provenance"] = "signed_receipt"
        if actor.get("user_id") != expected_user_id:
            return None
        if expected_role is not None and not _receipt_has_expected_role(
            actor, expected_role
        ):
            return None
    shape = _trace_parameter_shape(record)
    field_signature = _trace_field_signature(record)
    if shape is None or field_signature is None:
        return None
    measured_shape = tuple(
        sorted(
            (
                location,
                name,
                kind,
                sum(
                    1
                    for candidate in field_signature
                    if candidate[:3] == (location, name, kind)
                ),
            )
            for location, name, kind in {tuple(field[:3]) for field in field_signature}
        )
    )
    if shape != measured_shape:
        return None
    sentinel_categories = _trace_request_sentinel_categories(record)
    if sentinel_categories is None:
        return None
    return {
        "record": record,
        "sequence": sequence,
        "status_code": status,
        "actor": actor,
        "parameter_shape": shape,
        "field_signature": field_signature,
        "request_sentinel_categories": sentinel_categories,
    }


def _matching_trace_requests(
    trace_records: list[dict],
    request_signature: tuple[object, ...],
    **kwargs: object,
) -> list[dict]:
    matches: list[dict] = []
    for record in trace_records:
        if not isinstance(record, dict):
            continue
        binding = _trace_request_binding(record, request_signature, **kwargs)
        if binding is not None:
            matches.append(binding)
    return matches


def _sanitized_trace_binding(binding: dict) -> dict:
    actor = binding["actor"]
    record = binding["record"]
    return {
        "sequence": binding["sequence"],
        "method": record.get("method"),
        "origin": record.get("origin"),
        "path": record.get("path"),
        "status_code": binding["status_code"],
        "actor_user_id": actor.get("user_id"),
        "actor_roles": actor.get("roles"),
        "actor_provenance": actor.get("provenance"),
        "response_body_sha256": record.get("response_body_sha256"),
    }


def _cross_object_provenance_signature(arm: dict) -> tuple[str, object]:
    """Return the normalized object-resolution claim for replay matching."""
    provenance = str(arm.get("object_provenance") or "").strip().casefold()
    match_count = arm.get("match_count") if provenance == "unique_lookup" else None
    return provenance, match_count


def _cross_object_confirmation_signature(observation: PoCObservation) -> tuple:
    """Return the security-claim identity that a clean replay must preserve."""
    attack = observation.attack
    control = observation.control
    access_type = str(attack.get("access_type") or "").strip().casefold()
    signature: list[object] = [
        access_type,
        str(control.get("access_type") or "").strip().casefold(),
        str(control.get("control_basis") or "").strip().casefold(),
        _cross_object_request_signature(attack.get("request_fingerprint")),
        _cross_object_request_signature(control.get("request_fingerprint")),
        attack.get("authorization_expected"),
        str(attack.get("protection_basis") or "").strip(),
        attack.get("protection_observed"),
        str(attack.get("protection_visible_marker") or ""),
        attack.get("owner_verified"),
        _cross_object_probe_request_signature(
            attack.get("protection_request_fingerprint")
        ),
        control.get("authorization_expected"),
    ]
    for arm in (attack, control):
        signature.extend((arm.get("identity_verified"), arm.get("owner_verified")))
        signature.extend(
            _claim_identifier(arm.get(field))
            for field in (
                "attacker_user_id",
                "owner_user_id",
                "object_id",
            )
        )
        signature.append(str(arm.get("marker") or ""))
        signature.append(_cross_object_provenance_signature(arm))
    if access_type == "write":
        for arm in (attack, control):
            signature.extend(
                (
                    str(arm.get("write_effect") or "").strip().casefold(),
                    str(arm.get("baseline_marker") or ""),
                    _cross_object_request_signature(
                        arm.get("observer_request_fingerprint")
                    ),
                    _claim_identifier(arm.get("observer_user_id")),
                    _claim_role(arm.get("observer_role")),
                )
            )
    elif access_type == "read":
        signature.append(
            _cross_object_request_signature(attack.get("owner_request_fingerprint"))
        )
    if str(control.get("control_basis") or "").strip().casefold() == "authorized_actor":
        signature.append(_claim_role(control.get("actor_role")))
    if (
        access_type == "write"
        and str(attack.get("write_effect") or "").strip().casefold() == "delete"
        and observation.impact.availability != "none"
    ):
        probe = attack.get("availability_probe")
        if isinstance(probe, dict):
            before = probe.get("before")
            after = probe.get("after")
            signature.extend(
                (
                    _cross_object_request_signature(probe.get("request_fingerprint")),
                    _claim_identifier(probe.get("object_id")),
                    str(probe.get("object_type") or "").strip(),
                    str(probe.get("marker") or ""),
                    _wp_user_identifier(probe.get("observer_user_id")),
                    _claim_role(probe.get("observer_role")),
                    probe.get("identity_verified"),
                    probe.get("authorization_expected"),
                    before.get("status_code") if isinstance(before, dict) else None,
                    before.get("usable") if isinstance(before, dict) else None,
                    after.get("status_code") if isinstance(after, dict) else None,
                    after.get("usable") if isinstance(after, dict) else None,
                )
            )
    return tuple(signature)


def _ssrf_confirmation_signature(observation: PoCObservation) -> tuple | None:
    """Return the replay-stable SSRF claim already bound by each parent run."""
    if observation.oracle != "response_marker":
        return None
    attack = observation.attack
    control = observation.control
    attack_request = _ssrf_request_signature(attack.get("request_fingerprint"))
    control_request = _ssrf_request_signature(control.get("request_fingerprint"))
    attack_actor = _trace_claimed_user_id(
        attack.get("attacker_user_id"), observation.attacker_role
    )
    control_actor = _trace_claimed_user_id(
        control.get("attacker_user_id"), observation.attacker_role
    )
    if attack_request is None or control_request is None:
        return None
    if attack_actor is None or control_actor is None:
        return None
    attack_destination = attack.get("destination_url")
    control_destination = control.get("destination_url")
    if not all(
        isinstance(value, str) and bool(value)
        for value in (attack_destination, control_destination)
    ):
        return None
    return (
        attack_request,
        control_request,
        attack_destination,
        control_destination,
        attack_actor,
        control_actor,
        attack.get("identity_verified"),
        control.get("identity_verified"),
    )


def validate_confirmation_observations(
    first: PoCObservation,
    confirmation: PoCObservation,
) -> tuple[bool, str]:
    """Require the clean rerun to prove the same security claim."""
    if first.oracle != confirmation.oracle:
        return False, "confirmation used a different oracle"
    first_role = normalize_attacker_role(first.attacker_role)
    confirmation_role = normalize_attacker_role(confirmation.attacker_role)
    if UNKNOWN_ATTACKER_ROLE in {first_role, confirmation_role}:
        return False, "confirmation used an unrecognized attacker role"
    if first_role != confirmation_role:
        return False, "confirmation used a different attacker role"
    first_method = str(first.request.get("method") or "").strip().upper()
    confirmation_method = str(confirmation.request.get("method") or "").strip().upper()
    if first_method != confirmation_method:
        return False, "confirmation used a different request method"
    first_url = str(first.request.get("url") or "").strip()
    confirmation_url = str(confirmation.request.get("url") or "").strip()
    if first_url != confirmation_url:
        return False, "confirmation targeted a different request URL"
    first_impact = first.impact.model_dump(exclude={"description"})
    confirmation_impact = confirmation.impact.model_dump(exclude={"description"})
    if first_impact != confirmation_impact:
        return False, "confirmation reported different CIA impact dimensions"
    if first.oracle == "cross_object_access" and (
        _cross_object_confirmation_signature(first)
        != _cross_object_confirmation_signature(confirmation)
    ):
        return False, (
            "confirmation changed cross-object request, policy, provenance, access "
            "type, control basis, actors, owners, object IDs, markers, or observers"
        )
    first_ssrf = first.oracle == "response_marker" and (
        "destination_url" in first.attack or "destination_url" in first.control
    )
    confirmation_ssrf = confirmation.oracle == "response_marker" and (
        "destination_url" in confirmation.attack
        or "destination_url" in confirmation.control
    )
    if first_ssrf or confirmation_ssrf:
        first_signature = _ssrf_confirmation_signature(first)
        confirmation_signature = _ssrf_confirmation_signature(confirmation)
        if (
            first_signature is None
            or confirmation_signature is None
            or first_signature != confirmation_signature
        ):
            return False, (
                "confirmation changed the SSRF request fingerprint, destinations, "
                "actors, or identity verification"
            )
        first_marker = first.attack.get("marker")
        confirmation_marker = confirmation.attack.get("marker")
        if (
            not isinstance(first_marker, str)
            or re.fullmatch(r"SQUADRONE_SSRF_[0-9a-f]{64}", first_marker) is None
            or not isinstance(confirmation_marker, str)
            or re.fullmatch(r"SQUADRONE_SSRF_[0-9a-f]{64}", confirmation_marker) is None
            or hmac.compare_digest(first_marker, confirmation_marker)
        ):
            return False, (
                "confirmation did not disclose a fresh private SSRF response marker"
            )
    return True, "clean rerun reproduced the same oracle, role, request, and CIA impact"


def _number_list(value: object) -> list[float]:
    if not isinstance(value, list):
        return []
    out: list[float] = []
    for item in value:
        if isinstance(item, int | float) and not isinstance(item, bool):
            out.append(float(item))
    return out


def _normalize_file_effect_path(path: str) -> str:
    """Canonicalize an observed file location for attack/control comparison."""
    raw_path = path.strip()
    if not raw_path:
        return ""
    parsed = urlparse(raw_path)
    observed_path = parsed.path or "/"
    decoded_path = unquote(observed_path).replace("\\", "/")
    return posixpath.normpath(re.sub(r"/+", "/", decoded_path))


def _validate_cross_object_observation(
    observation: PoCObservation,
) -> tuple[bool, str]:
    """Validate a measured foreign-object effect and its functional control."""
    attack = observation.attack
    control = observation.control

    attack_access = str(attack.get("access_type") or "").strip().casefold()
    control_access = str(control.get("access_type") or "").strip().casefold()
    if attack_access not in _CROSS_OBJECT_ACCESS_TYPES:
        return False, "cross-object oracle requires attack.access_type read or write"
    if control_access != attack_access:
        return False, "cross-object attack/control access_type values do not match"

    attack_request = _cross_object_request_signature(attack.get("request_fingerprint"))
    control_request = _cross_object_request_signature(
        control.get("request_fingerprint")
    )
    if attack_request is None or control_request is None:
        return False, (
            "cross-object attack/control require request_fingerprint with nonempty "
            "method, route, object_parameter, object_type, object_location, and "
            "stable dispatch fields for shared WordPress endpoints; any differing "
            "marker, owner, CSRF, or embedded object values must use typed fields"
        )
    if attack_request != control_request:
        return (
            False,
            "cross-object attack/control request_fingerprint values do not match",
        )
    top_level_method = str(observation.request.get("method") or "").strip().upper()
    if attack_request[0] != top_level_method:
        return False, (
            "cross-object request_fingerprint method does not match request.method"
        )
    protection_request = _cross_object_probe_request_signature(
        attack.get("protection_request_fingerprint")
    )
    if protection_request is None:
        return False, (
            "cross-object attack requires a valid protection_request_fingerprint "
            "for the measured denied or owner-filtered path"
        )
    if protection_request[2] and protection_request[3] != attack_request[3]:
        return False, (
            "cross-object protection fingerprint uses a different object_type"
        )

    if attack.get("authorization_expected") is not False:
        return False, "cross-object attack must record authorization_expected=false"
    protection_basis = attack.get("protection_basis")
    if not isinstance(protection_basis, str) or len(protection_basis.strip()) < 8:
        return False, (
            "cross-object attack requires a concrete protection_basis of at least "
            "8 characters"
        )
    if attack.get("protection_observed") is not True:
        return False, "cross-object attack must record protection_observed=true"
    if control.get("authorization_expected") is not True:
        return False, "cross-object control must record authorization_expected=true"

    for arm_name, arm in (("attack", attack), ("control", control)):
        if arm.get("identity_verified") is not True:
            return False, (
                f"cross-object {arm_name} must record identity_verified=true"
            )
        if arm.get("owner_verified") is not True:
            return False, f"cross-object {arm_name} must record owner_verified=true"
        provenance = str(arm.get("object_provenance") or "").strip().casefold()
        if provenance not in _CROSS_OBJECT_PROVENANCE_TYPES:
            return False, (
                f"cross-object {arm_name} requires object_provenance setup_id, "
                "create_response, or unique_lookup"
            )
        match_count = arm.get("match_count")
        if provenance == "unique_lookup" and (
            not isinstance(match_count, int)
            or isinstance(match_count, bool)
            or match_count != 1
        ):
            return False, (
                f"cross-object {arm_name} unique_lookup requires match_count=1"
            )

    attacker_role = normalize_attacker_role(observation.attacker_role)
    attack_attacker_claim = _claim_identifier(attack.get("attacker_user_id"))
    if attacker_role == "unauthenticated":
        if attack_attacker_claim != "anonymous":
            return False, (
                "unauthenticated cross-object attack requires the canonical "
                "attacker_user_id anonymous"
            )
        attack_attacker = "anonymous"
    else:
        attack_attacker = _wp_user_identifier(attack.get("attacker_user_id"))
        if not attack_attacker:
            return False, (
                "authenticated cross-object attack requires a positive numeric "
                "WordPress attacker_user_id"
            )

    attack_owner = _wp_user_identifier(attack.get("owner_user_id"))
    control_owner = _wp_user_identifier(control.get("owner_user_id"))
    if not attack_owner or not control_owner:
        return False, (
            "cross-object attack/control owners require positive numeric WordPress "
            "user IDs"
        )
    attack_object = _claim_identifier(attack.get("object_id"))
    control_object = _claim_identifier(control.get("object_id"))
    if not attack_object or not control_object:
        return False, "cross-object oracle lacks attack/control object identifiers"
    if any(
        _CROSS_OBJECT_SENTINEL_PREFIX.casefold() in identifier.casefold()
        for identifier in (attack_object, control_object)
    ):
        return False, "cross-object object identifiers cannot contain proof sentinels"
    if attack_attacker == attack_owner:
        return False, "cross-object attack used the object's owner as attacker"
    if attack_object == control_object:
        return False, "cross-object attack/control used the same object identifier"
    request_url_path = _normalize_request_path(
        urlparse(str(observation.request["url"])).path
    )
    fingerprint_path = str(attack_request[1])
    if str(attack_request[4]) == "path":
        fingerprint_path = fingerprint_path.replace(
            "{" + str(attack_request[2]) + "}", attack_object
        )
        fingerprint_path = _normalize_request_path(fingerprint_path)
    if request_url_path != fingerprint_path:
        return False, (
            "cross-object request_fingerprint route does not match request.url"
        )

    control_basis = str(control.get("control_basis") or "").strip().casefold()
    if control_basis not in _CROSS_OBJECT_CONTROL_BASES:
        return False, (
            "cross-object control requires control_basis attacker_owned, public, "
            "or authorized_actor"
        )
    if control_basis == "attacker_owned":
        if attacker_role == "unauthenticated":
            return (
                False,
                "an unauthenticated actor cannot use an attacker-owned control",
            )
        control_attacker = _wp_user_identifier(control.get("attacker_user_id"))
        if not control_attacker:
            return False, (
                "attacker-owned control requires a positive numeric WordPress "
                "attacker_user_id"
            )
        if control_attacker != attack_attacker:
            return False, "attacker-owned control changed the attack actor"
        if control_owner != attack_attacker:
            return False, "attacker-owned control object is not owned by the attacker"
    elif control_basis == "public":
        if attack_access != "read":
            return False, "public cross-object controls are valid only for reads"
        control_attacker_claim = _claim_identifier(control.get("attacker_user_id"))
        if attacker_role == "unauthenticated":
            control_attacker = control_attacker_claim
        else:
            control_attacker = _wp_user_identifier(control.get("attacker_user_id"))
            if not control_attacker:
                return False, (
                    "authenticated public control requires a positive numeric "
                    "WordPress attacker_user_id"
                )
        if control_attacker != attack_attacker:
            return False, "public control changed the attack actor"
        if control.get("publicly_authorized") is not True:
            return False, "public control lacks publicly_authorized=true"
    else:
        control_attacker = _wp_user_identifier(control.get("attacker_user_id"))
        if not control_attacker:
            return False, (
                "authorized-actor control requires a positive numeric WordPress "
                "attacker_user_id"
            )
        if control_attacker != control_owner:
            return False, "authorized-actor control was not performed by its owner"
        control_actor_role = normalize_attacker_role(control.get("actor_role"))
        if control_actor_role in {UNKNOWN_ATTACKER_ROLE, "unauthenticated"}:
            return False, "authorized-actor control lacks a recognized actor_role"

    attack_marker = attack.get("marker")
    control_marker = control.get("marker")
    if not _valid_cross_object_marker(attack_marker):
        return False, "cross-object attack.marker is not a strong unique sentinel"
    if not _valid_cross_object_marker(control_marker):
        return False, "cross-object control.marker is not a strong unique sentinel"
    folded_attack_marker = attack_marker.casefold()
    folded_control_marker = control_marker.casefold()
    if (
        folded_attack_marker in folded_control_marker
        or folded_control_marker in folded_attack_marker
    ):
        return False, (
            "cross-object attack/control markers must be distinct and must not "
            "contain one another"
        )
    if control.get("attack_marker_present") is not False:
        return False, "cross-object control also contains the attack marker"
    if control.get("legitimate_access_succeeded") is not True:
        return False, "cross-object functional control did not succeed"

    confidentiality = observation.impact.confidentiality
    integrity = observation.impact.integrity
    availability = observation.impact.availability
    if attack_access == "read":
        owner_request = _cross_object_request_signature(
            attack.get("owner_request_fingerprint")
        )
        if owner_request is None:
            return False, (
                "cross-object read requires an object-bound owner_request_fingerprint"
            )
        if owner_request[3] != attack_request[3]:
            return False, (
                "cross-object owner fingerprint uses a different object_type"
            )
        if not protection_request[2]:
            visible_marker = attack.get("protection_visible_marker")
            if visible_marker != control_marker:
                return False, (
                    "owner-filtered read protection must name the control marker as "
                    "protection_visible_marker"
                )
        for arm_name, arm in (("attack", attack), ("control", control)):
            if arm.get("marker_present") is not True:
                return False, (
                    f"cross-object read {arm_name} did not observe its own marker"
                )
            if "observed_value" not in arm or not _state_contains_marker(
                arm.get("observed_value"), str(arm.get("marker") or "")
            ):
                return False, (
                    f"cross-object read {arm_name} observed_value does not contain "
                    "its marker"
                )
        if _state_contains_marker(control.get("observed_value"), attack_marker):
            return False, (
                "cross-object read control observed_value contains the attack marker"
            )
        if confidentiality == "none":
            return False, "cross-object read requires measured confidentiality impact"
        if integrity != "none" or availability != "none":
            return False, (
                "cross-object read cannot claim unmeasured integrity or availability"
            )
        return True, "cross-object read measurements passed"

    attack_effect = str(attack.get("write_effect") or "").strip().casefold()
    control_effect = str(control.get("write_effect") or "").strip().casefold()
    if attack_effect not in _CROSS_OBJECT_WRITE_EFFECTS:
        return False, "cross-object write requires write_effect modify or delete"
    if control_effect != attack_effect:
        return False, "cross-object attack/control write_effect values do not match"
    if confidentiality != "none" or integrity == "none":
        return False, (
            "cross-object write requires measured integrity without unmeasured "
            "confidentiality"
        )
    if not protection_request[2]:
        expected_visible_marker = (
            control.get("baseline_marker")
            if attack_effect == "modify"
            else control_marker
        )
        if attack.get("protection_visible_marker") != expected_visible_marker:
            return False, (
                "owner-filtered write protection must name the accessible control "
                "state as protection_visible_marker"
            )

    for arm_name, arm, arm_attacker, arm_owner in (
        ("attack", attack, attack_attacker, attack_owner),
        ("control", control, control_attacker, control_owner),
    ):
        observer_request = _cross_object_request_signature(
            arm.get("observer_request_fingerprint")
        )
        if observer_request is None or observer_request == attack_request:
            return False, (
                f"cross-object {arm_name} write requires a distinct, object-bound "
                "observer_request_fingerprint"
            )
        if observer_request[3] != attack_request[3]:
            return False, (
                f"cross-object {arm_name} observer fingerprint uses a different "
                "object_type"
            )
        if (
            "before" not in arm
            or "after" not in arm
            or arm.get("before") == arm.get("after")
        ):
            return False, (
                f"cross-object {arm_name} write lacks a measured before/after change"
            )
        observer_id = _claim_identifier(arm.get("observer_user_id"))
        observer_role_claim = arm.get("observer_role")
        if (
            not observer_id
            or not isinstance(observer_role_claim, str)
            or not observer_role_claim.strip()
        ):
            return False, (f"cross-object {arm_name} write lacks an owner observer")
        observer_id = _wp_user_identifier(arm.get("observer_user_id"))
        if not observer_id:
            return False, (
                f"cross-object {arm_name} observer requires a positive numeric "
                "WordPress user ID"
            )
        if arm_name == "attack" and observer_id == arm_attacker:
            return (
                False,
                "foreign write was observed only through the attacker identity",
            )
        if observer_id != arm_owner:
            return False, (
                f"cross-object {arm_name} write observer is not the claimed owner"
            )

    for state_name in ("before", "after"):
        if _state_contains_marker(control.get(state_name), attack_marker):
            return False, (
                "cross-object control state contains the attack marker in its "
                f"{state_name} measurement"
            )

    if attack_effect == "modify":
        for arm_name, arm in (("attack", attack), ("control", control)):
            baseline_marker = arm.get("baseline_marker")
            if not _valid_cross_object_marker(baseline_marker):
                return False, (
                    f"cross-object {arm_name} baseline_marker is not a strong "
                    "unique sentinel"
                )
            if baseline_marker.casefold() in {
                folded_attack_marker,
                folded_control_marker,
            }:
                return False, (
                    f"cross-object {arm_name} baseline_marker is not distinct "
                    "from the write markers"
                )
            if not _state_contains_marker(arm.get("before"), baseline_marker):
                return False, (
                    f"cross-object {arm_name} before state lacks its baseline_marker"
                )
            marker_before, transition_reason = _cross_object_write_marker_transition(
                arm, state="before"
            )
            if marker_before is None:
                return False, (f"cross-object {arm_name} {transition_reason}")
            marker_after, transition_reason = _cross_object_write_marker_transition(
                arm, state="after"
            )
            if marker_after is None:
                return False, f"cross-object {arm_name} {transition_reason}"
            if marker_before is not False:
                return False, (
                    f"cross-object {arm_name} write_marker_present_before must be "
                    "false for a modification; it refers to arm.marker, not "
                    "baseline_marker"
                )
            if marker_after is not True:
                return False, (
                    f"cross-object {arm_name} write_marker_present_after must be "
                    "true for a modification; it refers to arm.marker"
                )
            marker = str(arm.get("marker") or "")
            if _state_contains_marker(arm.get("before"), marker):
                return False, (
                    f"cross-object {arm_name} before state already contains its marker"
                )
            if not _state_contains_marker(arm.get("after"), marker):
                return False, (
                    f"cross-object {arm_name} after state does not contain its marker"
                )
        if availability != "none":
            return False, (
                "cross-object modification cannot claim unmeasured availability"
            )
    else:
        for arm_name, arm in (("attack", attack), ("control", control)):
            marker_before, transition_reason = _cross_object_write_marker_transition(
                arm, state="before"
            )
            if marker_before is None:
                return False, f"cross-object {arm_name} {transition_reason}"
            marker_after, transition_reason = _cross_object_write_marker_transition(
                arm, state="after"
            )
            if marker_after is None:
                return False, f"cross-object {arm_name} {transition_reason}"
            if marker_before is not True:
                return False, (
                    f"cross-object {arm_name} write_marker_present_before must be "
                    "true for a deletion"
                )
            if marker_after is not False:
                return False, (
                    f"cross-object {arm_name} write_marker_present_after must be "
                    "false for a deletion"
                )
            marker = str(arm.get("marker") or "")
            if not _state_contains_marker(arm.get("before"), marker):
                return False, (
                    f"cross-object {arm_name} pre-delete state lacks its marker"
                )
            if _state_contains_marker(arm.get("after"), marker):
                return False, (
                    f"cross-object {arm_name} post-delete state retains its marker"
                )
            if (
                arm.get("before_exists") is not True
                or arm.get("after_exists") is not False
            ):
                return False, (
                    f"cross-object {arm_name} delete lacks an exists-to-absent transition"
                )
        if availability != "none":
            if availability != "low":
                return False, (
                    "a single cross-object delete can claim at most low availability"
                )
            probe = attack.get("availability_probe")
            if not isinstance(probe, dict):
                return False, (
                    "cross-object delete availability requires a separate nested "
                    "availability_probe"
                )
            probe_object = _claim_identifier(probe.get("object_id"))
            probe_type = str(probe.get("object_type") or "").strip()
            probe_marker = probe.get("marker")
            probe_request = _cross_object_request_signature(
                probe.get("request_fingerprint")
            )
            attack_observer_request = _cross_object_request_signature(
                attack.get("observer_request_fingerprint")
            )
            if probe_object != attack_object or probe_type != str(attack_request[3]):
                return False, (
                    "cross-object availability_probe does not bind the deleted "
                    "object ID and type"
                )
            if probe_marker != attack_marker:
                return False, (
                    "cross-object availability_probe marker does not match the "
                    "deleted object marker"
                )
            if probe_request is None or probe_request in {
                attack_request,
                attack_observer_request,
            }:
                return False, (
                    "cross-object availability_probe requires a distinct valid "
                    "authorized-read request_fingerprint"
                )
            probe_observer = _wp_user_identifier(probe.get("observer_user_id"))
            probe_role = _claim_role(probe.get("observer_role"))
            if (
                probe_observer != _wp_user_identifier(attack.get("observer_user_id"))
                or probe_role != _claim_role(attack.get("observer_role"))
                or probe.get("identity_verified") is not True
                or probe.get("authorization_expected") is not True
            ):
                return False, (
                    "cross-object availability_probe lacks the same verified, "
                    "authorized owner observer"
                )
            if probe_observer == attack_attacker:
                return False, (
                    "cross-object availability_probe used the attacker as observer"
                )
            before_probe = probe.get("before")
            after_probe = probe.get("after")
            if not isinstance(before_probe, dict) or not isinstance(after_probe, dict):
                return False, (
                    "cross-object availability_probe requires raw before/after records"
                )
            before_status = before_probe.get("status_code")
            after_status = after_probe.get("status_code")
            if (
                not isinstance(before_status, int)
                or isinstance(before_status, bool)
                or not 200 <= before_status < 300
                or not isinstance(after_status, int)
                or isinstance(after_status, bool)
                or not 100 <= after_status <= 599
            ):
                return False, (
                    "cross-object availability_probe has invalid measured HTTP statuses"
                )
            if (
                before_probe.get("usable") is not True
                or after_probe.get("usable") is not False
            ):
                return False, (
                    "cross-object availability_probe does not show usable=true "
                    "to usable=false"
                )
            if before_probe.get("observed_value") == after_probe.get("observed_value"):
                return False, (
                    "cross-object availability_probe before/after values did not change"
                )
            if not _state_contains_marker(
                before_probe.get("observed_value"), attack_marker
            ) or _state_contains_marker(
                after_probe.get("observed_value"), attack_marker
            ):
                return False, (
                    "cross-object availability_probe does not measure the marker "
                    "present before and absent after"
                )

    return True, "cross-object write measurements passed"


def _trace_claimed_user_id(value: object, role: str) -> int | None:
    if normalize_attacker_role(role) == "unauthenticated":
        return 0 if _claim_identifier(value) == "anonymous" else None
    identifier = _wp_user_identifier(value)
    return int(identifier) if identifier else None


def _one_trace_match(matches: list[dict], label: str) -> tuple[dict | None, str]:
    if not matches:
        return None, f"HTTP trace has no signed {label} request"
    if len(matches) != 1:
        return None, f"HTTP trace has ambiguous duplicate {label} requests"
    return matches[0], ""


def _filter_trace_marker(
    matches: list[dict], marker: str, expected: bool
) -> list[dict]:
    return [
        binding
        for binding in matches
        if _trace_marker_state(binding["record"], marker) is expected
    ]


def _binding_fields_for(
    binding: dict,
    field_spec: tuple[str, str],
) -> list[tuple[object, ...]]:
    return [field for field in binding["field_signature"] if field[:2] == field_spec]


def _binding_has_request_sentinel(binding: dict) -> bool:
    return bool(binding["request_sentinel_categories"]) or any(
        field[4] is True for field in binding["field_signature"]
    )


def _record_has_request_sentinel(record: dict) -> bool:
    categories = _trace_request_sentinel_categories(record)
    fields = _trace_field_signature(record)
    if categories is None or fields is None:
        return True
    return bool(categories) or any(field[4] is True for field in fields)


def _cross_object_main_value_contract(
    attack_binding: dict,
    control_binding: dict,
    request_signature: tuple[object, ...],
    *,
    access_type: str,
    write_effect: str,
    attack_marker: str,
    control_marker: str,
    attack_owner_id: str,
    control_owner_id: str,
    trace_salt: bytes,
) -> tuple[bool, str]:
    """Require identical real request values except declared typed differences."""
    attack_fields = tuple(attack_binding["field_signature"])
    control_fields = tuple(control_binding["field_signature"])
    if any(field[2] == "file" for field in (*attack_fields, *control_fields)):
        return False, "cross-object proof does not accept unbound multipart file values"

    object_field = (
        (str(request_signature[4]), str(request_signature[2]))
        if request_signature[4] != "path"
        else None
    )
    marker_field = cast(tuple[str, str] | None, request_signature[7] or None)
    owner_field = cast(tuple[str, str] | None, request_signature[8] or None)
    csrf_fields = set(cast(tuple[tuple[str, str], ...], request_signature[9]))
    ignored_fields = {
        field
        for field in (object_field, marker_field, owner_field, *csrf_fields)
        if field is not None
    }

    def require_scalar(
        binding: dict,
        spec: tuple[str, str],
        expected_value: str | None,
        *,
        sentinel: bool,
    ) -> bool:
        fields = _binding_fields_for(binding, spec)
        if len(fields) != 1 or fields[0][2] != "scalar":
            return False
        if fields[0][4] is not sentinel:
            return False
        return expected_value is None or fields[0][3] == salted_scalar_sha256(
            expected_value,
            trace_salt,
        )

    if access_type == "write" and write_effect == "modify":
        if marker_field is None:
            return False, "cross-object modification requires marker_field"
        if not require_scalar(
            attack_binding,
            marker_field,
            attack_marker,
            sentinel=True,
        ) or not require_scalar(
            control_binding,
            marker_field,
            control_marker,
            sentinel=True,
        ):
            return False, "cross-object write marker_field is not bound to its marker"
    elif marker_field is not None:
        return False, "cross-object read/delete must not declare marker_field"

    allowed_wire_sentinel_categories: set[str] = set()
    if marker_field:
        if marker_field[0] == "query":
            allowed_wire_sentinel_categories.update({"target", "target_encoded"})
        else:
            allowed_wire_sentinel_categories.update({"body", "body_encoded"})
    for arm_name, binding in (
        ("attack", attack_binding),
        ("control", control_binding),
    ):
        sentinel_categories = cast(
            frozenset[str], binding["request_sentinel_categories"]
        )
        unexpected_categories = (
            set(sentinel_categories) - allowed_wire_sentinel_categories
        )
        if unexpected_categories:
            return False, (
                f"cross-object {arm_name} request carries an undeclared raw-wire "
                "sentinel"
            )

    if object_field is not None:
        for binding in (attack_binding, control_binding):
            object_fields = _binding_fields_for(binding, object_field)
            if (
                len(object_fields) != 1
                or object_fields[0][2] != "scalar"
                or object_fields[0][4] is not False
            ):
                return False, "cross-object object selector contains a sentinel"

    if owner_field is not None:
        if not require_scalar(
            attack_binding,
            owner_field,
            attack_owner_id,
            sentinel=False,
        ) or not require_scalar(
            control_binding,
            owner_field,
            control_owner_id,
            sentinel=False,
        ):
            return False, "cross-object owner_field is not bound to the claimed owner"

    for csrf_field in csrf_fields:
        if not require_scalar(
            attack_binding,
            csrf_field,
            None,
            sentinel=False,
        ) or not require_scalar(
            control_binding,
            csrf_field,
            None,
            sentinel=False,
        ):
            return False, "cross-object csrf_fields are missing or contain sentinels"

    attack_stable = tuple(
        field for field in attack_fields if field[:2] not in ignored_fields
    )
    control_stable = tuple(
        field for field in control_fields if field[:2] not in ignored_fields
    )
    if any(field[4] is True for field in (*attack_stable, *control_stable)):
        return False, "cross-object request contains an undeclared sentinel field"
    if attack_stable != control_stable:
        return False, ("cross-object attack/control changed undeclared request values")
    return True, "cross-object request values passed"


def _validate_cross_object_trace_sequence(
    trace_records: list[dict],
    ordered_bindings: list[tuple[str, dict]],
    *,
    target_origin: str,
) -> tuple[bool, str]:
    """Require one exact, uninterrupted causal proof sequence."""
    sequences = [binding["sequence"] for _label, binding in ordered_bindings]
    if sequences != sorted(sequences) or len(sequences) != len(set(sequences)):
        labels = " -> ".join(label for label, _binding in ordered_bindings)
        return False, f"cross-object HTTP trace order must be {labels}"
    expected = set(sequences)
    first, last = sequences[0], sequences[-1]
    observed: list[int] = []
    for record in trace_records:
        sequence = record.get("sequence")
        if (
            record.get("origin") == target_origin
            and isinstance(sequence, int)
            and not isinstance(sequence, bool)
            and first <= sequence <= last
        ):
            observed.append(sequence)
    if sorted(observed) != sorted(expected):
        return False, (
            "cross-object HTTP trace contains unclassified traffic inside the "
            "causal proof window"
        )

    actors = [binding["actor"] for _label, binding in ordered_bindings]
    receipt_nonces = [actor.get("nonce") for actor in actors]
    request_nonces = [actor.get("request_nonce") for actor in actors]
    if len(set(receipt_nonces)) != len(receipt_nonces):
        return False, "cross-object HTTP trace reused a signed actor receipt nonce"
    if len(set(request_nonces)) != len(request_nonces):
        return False, "cross-object HTTP trace reused a parent request nonce"
    return True, "cross-object causal trace sequence passed"


def validate_cross_object_http_trace(
    observation: PoCObservation,
    trace_records: list[dict],
    *,
    trace_salt: bytes,
    target_url: str,
    receipt_secret: bytes,
    trace_token: str,
    trace_error: str = "",
) -> tuple[bool, str, dict]:
    """Bind a cross-object claim to runner-observed HTTP and WP identities."""
    if trace_error:
        return False, f"cross-object HTTP trace failed: {trace_error}", {}
    attack = observation.attack
    control = observation.control
    attack_request = _cross_object_request_signature(attack.get("request_fingerprint"))
    control_request = _cross_object_request_signature(
        control.get("request_fingerprint")
    )
    if attack_request is None or control_request is None:
        return False, "cross-object HTTP trace received invalid fingerprints", {}

    target_origin = normalize_trace_origin(target_url)
    if not target_origin:
        return False, "cross-object HTTP trace target origin is invalid", {}
    if (
        normalize_trace_origin(str(observation.request.get("url") or ""))
        != target_origin
    ):
        return (
            False,
            ("cross-object reported request origin does not match the sandbox"),
            {},
        )
    target_records = [
        record
        for record in trace_records
        if isinstance(record, dict) and record.get("origin") == target_origin
    ]
    if len(target_records) != len(trace_records):
        return False, "cross-object HTTP trace contains an invalid-origin record", {}
    sequences = [record.get("sequence") for record in target_records]
    if sequences != list(range(1, len(target_records) + 1)):
        return False, "cross-object HTTP trace sequence is incomplete or unordered", {}
    if any(
        record.get("trace_version") != 1
        or record.get("record_type") != "request"
        or record.get("forward_state") != "completed"
        or record.get("forward_error") is not None
        or record.get("terminal") is not False
        or record.get("request_body_parse_error") is not None
        or record.get("request_metadata_omitted") is not None
        or record.get("response_capture_omitted") is not None
        for record in target_records
    ):
        return (
            False,
            "cross-object HTTP trace contains incomplete, opaque, or omitted evidence",
            {},
        )
    if any(
        _trace_request_sentinel_categories(record) is None for record in target_records
    ):
        return False, "cross-object HTTP trace has invalid sentinel metadata", {}
    request_nonces = [record.get("request_nonce") for record in target_records]
    if any(
        not isinstance(nonce, str) or re.fullmatch(r"[0-9a-f]{64}", nonce) is None
        for nonce in request_nonces
    ) or len(set(request_nonces)) != len(request_nonces):
        return False, "cross-object HTTP trace request nonces are invalid or reused", {}
    attack_user_id = _trace_claimed_user_id(
        attack.get("attacker_user_id"), observation.attacker_role
    )
    if attack_user_id is None:
        return False, "cross-object HTTP trace attacker identity is invalid", {}

    control_basis = str(control.get("control_basis") or "").strip().casefold()
    if control_basis == "authorized_actor":
        control_role = str(control.get("actor_role") or "")
    else:
        control_role = observation.attacker_role
    control_user_id = _trace_claimed_user_id(
        control.get("attacker_user_id"), control_role
    )
    if control_user_id is None:
        return False, "cross-object HTTP trace control identity is invalid", {}

    common = {
        "trace_salt": trace_salt,
        "target_origin": target_origin,
        "receipt_secret": receipt_secret,
        "trace_token": trace_token,
    }
    attack_matches = _matching_trace_requests(
        trace_records,
        attack_request,
        object_id=_claim_identifier(attack.get("object_id")),
        expected_user_id=attack_user_id,
        expected_role=observation.attacker_role,
        **common,
    )
    control_matches = _matching_trace_requests(
        trace_records,
        control_request,
        object_id=_claim_identifier(control.get("object_id")),
        expected_user_id=control_user_id,
        expected_role=control_role,
        **common,
    )
    attack_binding, reason = _one_trace_match(attack_matches, "attack")
    if attack_binding is None:
        return False, reason, {}
    control_binding, reason = _one_trace_match(control_matches, "control")
    if control_binding is None:
        return False, reason, {}
    if attack_binding["sequence"] == control_binding["sequence"]:
        return False, "one HTTP request cannot satisfy both cross-object arms", {}
    if attack_binding["parameter_shape"] != control_binding["parameter_shape"]:
        return (
            False,
            ("cross-object attack/control used different actual parameter shapes"),
            {},
        )
    access_type = str(attack.get("access_type") or "").strip().casefold()
    attack_marker = str(attack.get("marker") or "")
    control_marker = str(control.get("marker") or "")
    write_effect = str(attack.get("write_effect") or "").strip().casefold()
    sentinel_allowed_sequences = (
        {attack_binding["sequence"], control_binding["sequence"]}
        if access_type == "write" and write_effect == "modify"
        else set()
    )
    if any(
        _record_has_request_sentinel(record)
        and record.get("sequence") not in sentinel_allowed_sequences
        for record in target_records
    ):
        return (
            False,
            "cross-object HTTP trace has a sentinel-bearing request outside the "
            "declared mutation arms",
            {},
        )
    values_ok, values_reason = _cross_object_main_value_contract(
        attack_binding,
        control_binding,
        attack_request,
        access_type=access_type,
        write_effect=write_effect,
        attack_marker=attack_marker,
        control_marker=control_marker,
        attack_owner_id=_wp_user_identifier(attack.get("owner_user_id")),
        control_owner_id=_wp_user_identifier(control.get("owner_user_id")),
        trace_salt=trace_salt,
    )
    if not values_ok:
        return False, values_reason, {}
    evidence: dict[str, object] = {
        "attack_request": _sanitized_trace_binding(attack_binding),
        "control_request": _sanitized_trace_binding(control_binding),
    }

    protection_request = _cross_object_probe_request_signature(
        attack.get("protection_request_fingerprint")
    )
    if protection_request is None:
        return False, "cross-object protection trace fingerprint is invalid", {}
    protection_marker = (
        str(attack.get("baseline_marker") or "")
        if access_type == "write"
        and str(attack.get("write_effect") or "").strip().casefold() == "modify"
        else attack_marker
    )
    protection_object_id = (
        _claim_identifier(attack.get("object_id")) if protection_request[2] else None
    )
    protection_matches = _matching_trace_requests(
        trace_records,
        protection_request,
        object_id=protection_object_id,
        expected_user_id=attack_user_id,
        expected_role=observation.attacker_role,
        **common,
    )
    protection_matches = [
        binding
        for binding in protection_matches
        if binding["sequence"] < attack_binding["sequence"]
        and _trace_marker_state(binding["record"], protection_marker) is False
    ]
    if protection_request[2]:
        protection_matches = [
            binding
            for binding in protection_matches
            if binding["status_code"] in {401, 403, 404}
        ]
    else:
        visible_marker = str(attack.get("protection_visible_marker") or "")
        protection_matches = [
            binding
            for binding in protection_matches
            if 200 <= binding["status_code"] < 300
            and _trace_marker_state(binding["record"], visible_marker) is True
        ]
    protection_matches = [
        binding
        for binding in protection_matches
        if not _binding_has_request_sentinel(binding)
    ]
    protection_binding, reason = _one_trace_match(
        protection_matches, "pre-attack protection-policy"
    )
    if protection_binding is None:
        return False, reason, {}
    evidence["protection_request"] = _sanitized_trace_binding(protection_binding)

    if access_type == "read":
        if (
            not 200 <= attack_binding["status_code"] < 300
            or not 200 <= control_binding["status_code"] < 300
        ):
            return False, "cross-object read requests were not successful", {}
        if _binding_has_request_sentinel(
            attack_binding
        ) or _binding_has_request_sentinel(control_binding):
            return (
                False,
                ("cross-object read request carried a sentinel and could reflect it"),
                {},
            )
        if _trace_marker_state(attack_binding["record"], attack_marker) is not True:
            return False, "HTTP trace attack response lacks the foreign marker", {}
        if _trace_marker_state(control_binding["record"], control_marker) is not True:
            return False, "HTTP trace control response lacks its own marker", {}
        if _trace_marker_state(control_binding["record"], attack_marker) is not False:
            return (
                False,
                ("HTTP trace control response does not prove the attack marker absent"),
                {},
            )

        owner_request = _cross_object_request_signature(
            attack.get("owner_request_fingerprint")
        )
        owner_id = _wp_user_identifier(attack.get("owner_user_id"))
        if owner_request is None or not owner_id:
            return False, "cross-object owner HTTP trace evidence is invalid", {}
        owner_matches = _matching_trace_requests(
            trace_records,
            owner_request,
            object_id=_claim_identifier(attack.get("object_id")),
            expected_user_id=int(owner_id),
            expected_role=None,
            **common,
        )
        owner_matches = [
            binding
            for binding in owner_matches
            if binding["sequence"] < attack_binding["sequence"]
            and 200 <= binding["status_code"] < 300
            and not _binding_has_request_sentinel(binding)
            and _trace_marker_state(binding["record"], attack_marker) is True
        ]
        owner_binding, reason = _one_trace_match(
            owner_matches, "foreign-object owner observation"
        )
        if owner_binding is None:
            return False, reason, {}
        evidence["owner_request"] = _sanitized_trace_binding(owner_binding)
        sequence_ok, sequence_reason = _validate_cross_object_trace_sequence(
            trace_records,
            [
                ("protection", protection_binding),
                ("owner observation", owner_binding),
                ("foreign read", attack_binding),
                ("control read", control_binding),
            ],
            target_origin=target_origin,
        )
        if not sequence_ok:
            return False, sequence_reason, {}
        return True, "cross-object HTTP read trace and identities passed", evidence

    if (
        not 200 <= attack_binding["status_code"] < 400
        or not 200 <= control_binding["status_code"] < 400
    ):
        return False, "cross-object write requests were not accepted", {}
    main_bindings = {"attack": attack_binding, "control": control_binding}
    write_state_bindings: dict[str, dict[str, dict]] = {}
    for arm_name, arm in (("attack", attack), ("control", control)):
        main_binding = main_bindings[arm_name]
        observer_request = _cross_object_request_signature(
            arm.get("observer_request_fingerprint")
        )
        observer_id = _wp_user_identifier(arm.get("observer_user_id"))
        owner_id = _wp_user_identifier(arm.get("owner_user_id"))
        if observer_request is None or not observer_id or not owner_id:
            return False, f"cross-object {arm_name} observer trace is invalid", {}
        observer_matches = _matching_trace_requests(
            trace_records,
            observer_request,
            object_id=_claim_identifier(arm.get("object_id")),
            expected_user_id=int(observer_id),
            expected_role=None,
            **common,
        )
        observer_is_owner = observer_id == owner_id
        if not observer_is_owner:
            return (
                False,
                (
                    f"cross-object {arm_name} write lacks a server-verified "
                    "owner observer"
                ),
                {},
            )
        observer_matches = [
            binding
            for binding in observer_matches
            if not _binding_has_request_sentinel(binding)
        ]

        write_effect = str(arm.get("write_effect") or "").strip().casefold()
        marker = str(arm.get("marker") or "")
        if write_effect == "modify":
            baseline_marker = str(arm.get("baseline_marker") or "")
            before_matches = [
                binding
                for binding in observer_matches
                if binding["sequence"] < main_binding["sequence"]
                and _trace_marker_state(binding["record"], baseline_marker) is True
                and _trace_marker_state(binding["record"], marker) is False
            ]
        else:
            before_matches = [
                binding
                for binding in observer_matches
                if binding["sequence"] < main_binding["sequence"]
                and _trace_marker_state(binding["record"], marker) is True
            ]
        after_matches = [
            binding
            for binding in observer_matches
            if binding["sequence"] > main_binding["sequence"]
            and _trace_marker_state(binding["record"], marker)
            is (write_effect == "modify")
        ]
        if arm_name == "control":
            before_matches = _filter_trace_marker(before_matches, attack_marker, False)
            after_matches = _filter_trace_marker(after_matches, attack_marker, False)
        before_binding, reason = _one_trace_match(
            before_matches, f"{arm_name} owner before-state"
        )
        if before_binding is None:
            return False, reason, {}
        after_binding, reason = _one_trace_match(
            after_matches, f"{arm_name} owner after-state"
        )
        if after_binding is None:
            return False, reason, {}
        if not 200 <= before_binding["status_code"] < 300:
            return (
                False,
                (f"cross-object {arm_name} before-state request was not successful"),
                {},
            )
        if write_effect == "modify":
            after_status_ok = 200 <= after_binding["status_code"] < 300
        else:
            after_status_ok = 200 <= after_binding[
                "status_code"
            ] < 300 or after_binding["status_code"] in {404, 410}
        if not after_status_ok:
            return (
                False,
                (f"cross-object {arm_name} after-state request was not conclusive"),
                {},
            )
        evidence[f"{arm_name}_before"] = _sanitized_trace_binding(before_binding)
        evidence[f"{arm_name}_after"] = _sanitized_trace_binding(after_binding)
        write_state_bindings[arm_name] = {
            "before": before_binding,
            "after": after_binding,
        }

    availability_state_bindings: dict[str, dict] | None = None
    if observation.impact.availability != "none":
        probe = attack.get("availability_probe")
        if not isinstance(probe, dict):
            return False, "cross-object availability trace probe is missing", {}
        probe_request = _cross_object_request_signature(
            probe.get("request_fingerprint")
        )
        probe_observer = _wp_user_identifier(probe.get("observer_user_id"))
        if probe_request is None or not probe_observer:
            return False, "cross-object availability trace probe is invalid", {}
        probe_matches = _matching_trace_requests(
            trace_records,
            probe_request,
            object_id=_claim_identifier(probe.get("object_id")),
            expected_user_id=int(probe_observer),
            expected_role=None,
            **common,
        )
        probe_matches = [
            binding
            for binding in probe_matches
            if not _binding_has_request_sentinel(binding)
        ]
        probe_before = probe["before"]
        probe_after = probe["after"]
        availability_before = [
            binding
            for binding in probe_matches
            if binding["sequence"] < attack_binding["sequence"]
            and binding["status_code"] == probe_before["status_code"]
            and _trace_marker_state(binding["record"], attack_marker) is True
        ]
        availability_after = [
            binding
            for binding in probe_matches
            if binding["sequence"] > attack_binding["sequence"]
            and binding["status_code"] == probe_after["status_code"]
            and _trace_marker_state(binding["record"], attack_marker) is False
        ]
        before_binding, reason = _one_trace_match(
            availability_before, "availability before-state"
        )
        if before_binding is None:
            return False, reason, {}
        after_binding, reason = _one_trace_match(
            availability_after, "availability after-state"
        )
        if after_binding is None:
            return False, reason, {}
        if not (
            200 <= before_binding["status_code"] < 300
            and (
                200 <= after_binding["status_code"] < 300
                or after_binding["status_code"] in {404, 410}
            )
        ):
            return False, "availability trace statuses are not conclusive", {}
        evidence["availability_before"] = _sanitized_trace_binding(before_binding)
        evidence["availability_after"] = _sanitized_trace_binding(after_binding)
        availability_state_bindings = {
            "before": before_binding,
            "after": after_binding,
        }

    attack_states = write_state_bindings["attack"]
    control_states = write_state_bindings["control"]
    ordered_bindings: list[tuple[str, dict]] = [
        ("protection", protection_binding),
        ("foreign before", attack_states["before"]),
    ]
    if availability_state_bindings is not None:
        ordered_bindings.append(
            ("availability before", availability_state_bindings["before"])
        )
    ordered_bindings.extend(
        [
            ("foreign mutation", attack_binding),
            ("foreign after", attack_states["after"]),
        ]
    )
    if availability_state_bindings is not None:
        ordered_bindings.append(
            ("availability after", availability_state_bindings["after"])
        )
    ordered_bindings.extend(
        [
            ("control before", control_states["before"]),
            ("control mutation", control_binding),
            ("control after", control_states["after"]),
        ]
    )
    sequence_ok, sequence_reason = _validate_cross_object_trace_sequence(
        trace_records,
        ordered_bindings,
        target_origin=target_origin,
    )
    if not sequence_ok:
        return False, sequence_reason, {}

    return True, "cross-object HTTP write trace and identities passed", evidence


def _ssrf_request_signature(value: object) -> tuple[object, ...] | None:
    """Canonicalize the real plugin request used by both SSRF oracle arms."""
    if not isinstance(value, dict):
        return None
    normalized: list[str] = []
    for field in _SSRF_REQUEST_FIELDS:
        raw = value.get(field)
        if not isinstance(raw, str) or not raw.strip():
            return None
        item = raw.strip()
        normalized.append(item.upper() if field == "method" else item)

    method, route_value, destination_parameter, destination_location = normalized
    if (
        re.fullmatch(r"[A-Z]+", method) is None
        or len(method) > 32
        or destination_parameter != destination_parameter.strip()
    ):
        return None
    route = _normalize_request_path(route_value)
    parsed_route = urlparse(route_value)
    if not route or parsed_route.query or parsed_route.fragment:
        return None
    location = destination_location.casefold()
    if location not in _SSRF_REQUEST_LOCATIONS:
        return None

    dispatch = _cross_object_dispatch_signature(value.get("dispatch"))
    if dispatch is None:
        return None
    destination_field = (location, destination_parameter)
    dispatch_fields = {tuple(str(key).split(":", 1)) for key, _expected in dispatch}
    if destination_field in dispatch_fields:
        return None

    csrf_raw = value.get("csrf_fields", [])
    if not isinstance(csrf_raw, list):
        return None
    csrf_fields: list[tuple[str, str]] = []
    for raw in csrf_raw:
        parsed = _cross_object_field_spec(raw)
        if parsed is None or parsed == destination_field:
            return None
        csrf_fields.append(parsed)
    if len(set(csrf_fields)) != len(csrf_fields) or any(
        field in dispatch_fields for field in csrf_fields
    ):
        return None
    if route in _CROSS_OBJECT_SHARED_ROUTES and not dispatch:
        return None
    return (
        method,
        route,
        destination_parameter,
        location,
        dispatch,
        tuple(sorted(csrf_fields)),
    )


def _ssrf_trace_signature(signature: tuple[object, ...]) -> tuple[object, ...]:
    """Adapt an SSRF fingerprint to the shared trusted trace matcher."""
    method, route, parameter, location, dispatch, csrf_fields = signature
    return (
        method,
        route,
        parameter,
        "ssrf_destination",
        location,
        dispatch,
        "",
        (),
        (),
        csrf_fields,
    )


def _canonical_rest_route(value: object) -> str:
    """Return one unambiguous WordPress REST route, or an empty string."""
    if not isinstance(value, str) or not value or value != value.strip():
        return ""
    decoded = unquote(value).replace("\\", "/")
    if (
        not decoded.startswith("/")
        or decoded.startswith("//")
        or "?" in decoded
        or "#" in decoded
    ):
        return ""
    normalized = _normalize_request_path(decoded)
    return normalized if normalized not in {"", "/"} else ""


def _canonical_http_transport(
    method: object,
    route_value: object,
    dispatch_value: object,
) -> tuple[str, str, str, tuple[tuple[str, str], ...]] | None:
    """Canonicalize exact HTTP transport, including WP REST permalink aliases."""
    if (
        not isinstance(method, str)
        or not isinstance(route_value, str)
        or not method.strip()
        or not route_value.strip()
    ):
        return None
    normalized_method = method.strip().upper()
    if (
        re.fullmatch(r"[A-Z]+", normalized_method) is None
        or len(normalized_method) > 32
    ):
        return None
    route = _normalize_request_path(route_value)
    parsed_route = urlparse(route_value)
    if not route or parsed_route.query or parsed_route.fragment:
        return None
    dispatch = _cross_object_dispatch_signature(dispatch_value)
    if dispatch is None:
        return None

    rest_dispatch = [
        (key, value) for key, value in dispatch if key == "query:rest_route"
    ]
    remaining_dispatch = tuple(
        (key, value) for key, value in dispatch if key != "query:rest_route"
    )
    if route.startswith("/wp-json/"):
        if rest_dispatch:
            return None
        rest_route = _canonical_rest_route(route.removeprefix("/wp-json"))
        if not rest_route:
            return None
        return normalized_method, "wordpress_rest", rest_route, remaining_dispatch
    if route == "/" and rest_dispatch:
        if len(rest_dispatch) != 1:
            return None
        rest_route = _canonical_rest_route(rest_dispatch[0][1])
        if not rest_route:
            return None
        return normalized_method, "wordpress_rest", rest_route, remaining_dispatch
    if rest_dispatch:
        return None
    return normalized_method, "path", route, remaining_dispatch


def _expected_http_transport_signature(
    value: object,
) -> tuple[str, str, str, tuple[tuple[str, str], ...], str, str] | None:
    """Validate the parent-derived hypothesis transport without guessing."""
    required_keys = {
        "method",
        "route",
        "dispatch",
        "destination_parameter",
        "destination_location",
    }
    if not isinstance(value, dict) or set(value) != required_keys:
        return None
    destination_parameter = value.get("destination_parameter")
    destination_location = value.get("destination_location")
    if (
        not isinstance(destination_parameter, str)
        or not destination_parameter
        or destination_parameter != destination_parameter.strip()
        or not isinstance(destination_location, str)
        or destination_location not in _SSRF_REQUEST_LOCATIONS
    ):
        return None
    transport = _canonical_http_transport(
        value.get("method"),
        value.get("route"),
        value.get("dispatch"),
    )
    if transport is None:
        return None
    return (*transport, destination_parameter, destination_location)


def _expected_http_transport_signatures(
    value: object,
) -> frozenset[tuple[str, str, str, tuple[tuple[str, str], ...], str, str]]:
    """Validate one source-bound transport or a bounded set of direct routes."""
    direct = _expected_http_transport_signature(value)
    if direct is not None:
        return frozenset({direct})
    if not isinstance(value, dict) or set(value) != {"alternatives"}:
        return frozenset()
    alternatives = value.get("alternatives")
    if not isinstance(alternatives, list) or not 1 <= len(alternatives) <= 4:
        return frozenset()
    signatures: list[tuple[str, str, str, tuple[tuple[str, str], ...], str, str]] = []
    for alternative in alternatives:
        signature = _expected_http_transport_signature(alternative)
        if signature is None:
            return frozenset()
        signatures.append(signature)
    if len(set(signatures)) != len(signatures):
        return frozenset()
    return frozenset(signatures)


def _allows_credential_free_direct_ssrf(
    expected_http_transport: object,
    expected_attacker_role: str | None,
) -> bool:
    """Gate receipt-free identity proof to source-bound direct PHP endpoints."""
    if normalize_attacker_role(expected_attacker_role or "") != "unauthenticated":
        return False
    signatures = _expected_http_transport_signatures(expected_http_transport)
    return bool(signatures) and all(
        signature[1] == "path"
        and re.fullmatch(
            r"/wp-content/plugins/[a-z0-9][a-z0-9_-]{0,199}/"
            r"(?:[A-Za-z0-9][A-Za-z0-9_.-]*/)*"
            r"[A-Za-z0-9][A-Za-z0-9_.-]*\.php",
            signature[2],
        )
        is not None
        for signature in signatures
    )


def _valid_ssrf_oracle_url(value: str) -> bool:
    """Validate one opaque parent-oracle URL advertised to the WordPress host."""
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except (TypeError, ValueError):
        return False
    return bool(
        parsed.scheme == "http"
        and parsed.hostname == _SSRF_ORACLE_HOST
        and isinstance(port, int)
        and 1024 <= port <= 65535
        and parsed.username is None
        and parsed.password is None
        and parsed.path.startswith(_SSRF_ORACLE_PATH_PREFIX)
        and re.fullmatch(
            r"[0-9a-f]{64}",
            parsed.path.removeprefix(_SSRF_ORACLE_PATH_PREFIX),
        )
        is not None
        and not parsed.query
        and not parsed.fragment
    )


def _valid_ssrf_local_oracle_pair(attack_url: str, control_url: str) -> bool:
    """Validate a scheme-only pair for one protected target-local path."""
    try:
        attack = urlsplit(attack_url)
        control = urlsplit(control_url)
        attack_port = attack.port
        control_port = control.port
    except (TypeError, ValueError):
        return False
    return bool(
        attack.scheme == "file"
        and control.scheme == "https"
        and attack.hostname == "localhost"
        and control.hostname == "localhost"
        and attack_port is None
        and control_port is None
        and attack.username is None
        and attack.password is None
        and control.username is None
        and control.password is None
        and attack.path == control.path
        and re.fullmatch(
            re.escape(LOCAL_RESOURCE_SSRF_DIRECTORY) + r"/[0-9a-f]{64}",
            attack.path,
        )
        is not None
        and not attack.query
        and not attack.fragment
        and not control.query
        and not control.fragment
    )


def _validate_ssrf_local_resource_snapshot(
    snapshot: object,
    *,
    marker: str,
    expected_generation_id: str,
    resource_path: str,
    attack_record: dict,
    control_record: dict,
) -> tuple[bool, str, dict[str, object]]:
    """Bind a frozen local-canary attestation to the two outer requests."""
    if type(snapshot) is not LocalResourceSsrfSnapshot:
        return False, "local-resource SSRF snapshot has an invalid type", {}
    provisioning = snapshot.provisioning
    verification = snapshot.verification
    if (
        type(provisioning) is not LocalResourceSsrfProvisioningAttestation
        or type(verification) is not LocalResourceSsrfVerificationAttestation
        or not isinstance(expected_generation_id, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_generation_id) is None
        or any(
            not isinstance(value, str)
            for value in (
                snapshot.generation_id,
                provisioning.generation_id,
                provisioning.resource_path_sha256,
                provisioning.marker_sha256,
                provisioning.content_sha256,
                verification.generation_id,
                verification.resource_path_sha256,
                verification.before_sha256,
                verification.after_sha256,
            )
        )
        or any(
            re.fullmatch(r"[0-9a-f]{64}", value) is None
            for value in (
                snapshot.generation_id,
                provisioning.generation_id,
                provisioning.resource_path_sha256,
                provisioning.marker_sha256,
                provisioning.content_sha256,
                verification.generation_id,
                verification.resource_path_sha256,
                verification.before_sha256,
                verification.after_sha256,
            )
        )
        or any(
            type(value) is not int
            for value in (
                provisioning.schema_version,
                provisioning.content_size_bytes,
                provisioning.owner_uid,
                provisioning.owner_gid,
                provisioning.file_mode,
                provisioning.link_count,
                provisioning.started_monotonic_ns,
                provisioning.finished_monotonic_ns,
                verification.schema_version,
                verification.before_monotonic_ns,
                verification.execution_started_monotonic_ns,
                verification.execution_finished_monotonic_ns,
                verification.after_monotonic_ns,
            )
        )
    ):
        return False, "local-resource SSRF attestation shape is invalid", {}
    marker_sha256 = hashlib.sha256(marker.encode("ascii")).hexdigest()
    resource_sha256 = hashlib.sha256(resource_path.encode("ascii")).hexdigest()
    attack_interval = _ssrf_upstream_interval(attack_record)
    control_interval = _ssrf_upstream_interval(control_record)
    if attack_interval is None or control_interval is None:
        return False, "local-resource SSRF parent intervals are invalid", {}
    if (
        type(snapshot.schema_version) is not int
        or snapshot.schema_version != 1
        or snapshot.mode != LOCAL_RESOURCE_SSRF_MODE
        or not isinstance(snapshot.generation_id, str)
        or not hmac.compare_digest(snapshot.generation_id, expected_generation_id)
        or provisioning.schema_version != 1
        or verification.schema_version != 1
        or not hmac.compare_digest(
            provisioning.generation_id,
            expected_generation_id,
        )
        or not hmac.compare_digest(
            verification.generation_id,
            expected_generation_id,
        )
        or not hmac.compare_digest(
            provisioning.resource_path_sha256,
            resource_sha256,
        )
        or not hmac.compare_digest(
            verification.resource_path_sha256,
            resource_sha256,
        )
        or not hmac.compare_digest(provisioning.marker_sha256, marker_sha256)
        or not hmac.compare_digest(provisioning.content_sha256, marker_sha256)
        or provisioning.content_size_bytes != len(marker.encode("ascii"))
        or provisioning.owner_uid != 0
        or provisioning.owner_gid != 0
        or provisioning.file_mode != 0o444
        or provisioning.link_count != 1
        or provisioning.is_regular_file is not True
        or provisioning.is_symlink is not False
        or not hmac.compare_digest(verification.before_sha256, marker_sha256)
        or not hmac.compare_digest(verification.after_sha256, marker_sha256)
        or provisioning.started_monotonic_ns < 1
        or provisioning.finished_monotonic_ns < provisioning.started_monotonic_ns
        or verification.before_monotonic_ns < provisioning.finished_monotonic_ns
        or verification.execution_started_monotonic_ns
        < verification.before_monotonic_ns
        or attack_interval[0] < verification.execution_started_monotonic_ns
        or attack_interval[1] > control_interval[0]
        or control_interval[1] > verification.execution_finished_monotonic_ns
        or verification.execution_finished_monotonic_ns
        < verification.execution_started_monotonic_ns
        or verification.after_monotonic_ns
        < verification.execution_finished_monotonic_ns
    ):
        return False, "local-resource SSRF attestation is invalid or non-causal", {}
    return (
        True,
        "local-resource SSRF canary attestation passed",
        {
            "mode": LOCAL_RESOURCE_SSRF_MODE,
            "generation_id_sha256": hashlib.sha256(
                expected_generation_id.encode("ascii")
            ).hexdigest(),
            "resource_path_sha256": resource_sha256,
            "marker_sha256": marker_sha256,
            "file_mode": provisioning.file_mode,
            "owner_uid": provisioning.owner_uid,
            "owner_gid": provisioning.owner_gid,
        },
    )


def _ssrf_upstream_interval(record: dict) -> tuple[int, int] | None:
    started = record.get("upstream_started_monotonic_ns")
    finished = record.get("upstream_finished_monotonic_ns")
    if (
        not isinstance(started, int)
        or isinstance(started, bool)
        or started < 1
        or not isinstance(finished, int)
        or isinstance(finished, bool)
        or finished < started
    ):
        return None
    return started, finished


def _validate_ssrf_oracle_snapshot(
    snapshot: object,
    *,
    marker: str,
    expected_generation_id: str,
    attack_record: dict,
    control_record: dict,
) -> tuple[bool, str, list[dict[str, object]]]:
    """Validate immutable parent evidence and bind it to outer proxy intervals."""
    if type(snapshot) is not SsrfOracleSnapshot:
        return False, "SSRF oracle snapshot has an invalid type", []
    if (
        type(snapshot.schema_version) is not int
        or snapshot.schema_version != 1
        or snapshot.overflow is not False
        or not isinstance(snapshot.generation_id, str)
        or re.fullmatch(r"[0-9a-f]{64}", snapshot.generation_id) is None
        or not isinstance(expected_generation_id, str)
        or re.fullmatch(r"[0-9a-f]{64}", expected_generation_id) is None
        or not hmac.compare_digest(snapshot.generation_id, expected_generation_id)
        or not isinstance(snapshot.hits, tuple)
    ):
        return False, "SSRF oracle snapshot generation or bounds are invalid", []
    if len(snapshot.hits) != 2:
        return False, "SSRF oracle snapshot requires exactly two inner hits", []

    attack_interval = _ssrf_upstream_interval(attack_record)
    control_interval = _ssrf_upstream_interval(control_record)
    if (
        attack_interval is None
        or control_interval is None
        or attack_interval[1] > control_interval[0]
    ):
        return False, "SSRF parent proxy intervals are malformed or overlap", []

    marker_sha256 = hashlib.sha256(marker.encode("ascii")).hexdigest()
    expected = (
        (1, "attack", 200, marker_sha256, attack_interval),
        (2, "control", 404, None, control_interval),
    )
    sanitized: list[dict[str, object]] = []
    inner_method = ""
    for hit, expected_hit in zip(snapshot.hits, expected, strict=True):
        sequence, arm, status_code, expected_hash, interval = expected_hit
        if type(hit) is not SsrfOracleHit:
            return False, "SSRF oracle snapshot contains a malformed hit", []
        if (
            type(hit.schema_version) is not int
            or hit.schema_version != 1
            or type(hit.sequence) is not int
            or hit.sequence != sequence
            or hit.arm != arm
            or not isinstance(hit.method, str)
            or hit.method not in ALLOWED_ORACLE_METHODS
            or type(hit.status_code) is not int
            or hit.status_code != status_code
            or hit.marker_sha256 != expected_hash
            or type(hit.received_monotonic_ns) is not int
            or hit.received_monotonic_ns < interval[0]
            or type(hit.responded_monotonic_ns) is not int
            or hit.responded_monotonic_ns < hit.received_monotonic_ns
            or hit.responded_monotonic_ns > interval[1]
        ):
            return False, "SSRF oracle hit is invalid or outside its parent request", []
        if not inner_method:
            inner_method = hit.method
        elif hit.method != inner_method:
            return False, "SSRF oracle attack/control inner methods differ", []
        sanitized.append(
            {
                "sequence": hit.sequence,
                "arm": hit.arm,
                "method": hit.method,
                "status_code": hit.status_code,
                "marker_sha256": hit.marker_sha256,
            }
        )
    return True, "SSRF oracle snapshot and causal intervals passed", sanitized


def _ssrf_request_values_match(
    attack_binding: dict,
    control_binding: dict,
    signature: tuple[object, ...],
    *,
    attack_url: str,
    control_url: str,
    trace_salt: bytes,
) -> tuple[bool, str]:
    """Bind the two exact destinations and reject all other request drift."""
    attack_fields = tuple(attack_binding["field_signature"])
    control_fields = tuple(control_binding["field_signature"])
    if any(field[2] == "file" for field in (*attack_fields, *control_fields)):
        return False, "SSRF response-marker proof does not accept file request values"
    if any(field[4] is True for field in (*attack_fields, *control_fields)):
        return False, "SSRF request contains a response-marker sentinel"
    if (
        attack_binding["request_sentinel_categories"]
        or control_binding["request_sentinel_categories"]
    ):
        return False, "SSRF request carries a raw or encoded response-marker sentinel"

    destination_field = (str(signature[3]), str(signature[2]))
    csrf_fields = set(cast(tuple[tuple[str, str], ...], signature[5]))

    def require_destination(binding: dict, expected_url: str) -> bool:
        fields = _binding_fields_for(binding, destination_field)
        return bool(
            len(fields) == 1
            and fields[0][2] == "scalar"
            and fields[0][4] is False
            and fields[0][3] == salted_scalar_sha256(expected_url, trace_salt)
        )

    if not require_destination(attack_binding, attack_url) or not require_destination(
        control_binding, control_url
    ):
        return False, "SSRF destination field is not bound to its exact oracle URL"

    for csrf_field in csrf_fields:
        for binding in (attack_binding, control_binding):
            fields = _binding_fields_for(binding, csrf_field)
            if (
                len(fields) != 1
                or fields[0][2] != "scalar"
                or fields[0][4] is not False
            ):
                return (
                    False,
                    "SSRF csrf_fields are missing, duplicated, or sentinel-bearing",
                )

    # CSRF/nonces are behavior-bearing child input too. They may be declared so
    # their shape is checked explicitly, but their values must remain equal.
    ignored = {destination_field}
    attack_stable = tuple(field for field in attack_fields if field[:2] not in ignored)
    control_stable = tuple(
        field for field in control_fields if field[:2] not in ignored
    )
    if attack_stable != control_stable:
        return False, "SSRF attack/control changed undeclared request values"
    return True, "SSRF request values passed"


def validate_ssrf_response_marker_http_trace(
    observation: PoCObservation,
    trace_records: list[dict],
    *,
    trace_salt: bytes,
    target_url: str,
    receipt_secret: bytes,
    trace_token: str,
    oracle_attack_url: str,
    oracle_control_url: str,
    oracle_marker: str,
    oracle_snapshot: object,
    oracle_generation_id: str,
    expected_http_transport: dict[str, object] | None = None,
    trace_error: str = "",
    oracle_mode: Literal["http", "local_resource"] = "http",
) -> tuple[bool, str, dict]:
    """Bind one SSRF disclosure claim to both outer and inner trusted evidence."""
    if trace_error:
        return False, f"SSRF HTTP trace failed: {trace_error}", {}
    if re.fullmatch(r"SQUADRONE_SSRF_[0-9a-f]{64}", oracle_marker) is None:
        return False, "SSRF parent oracle contract is invalid", {}
    if oracle_mode == "http":
        attack_oracle = urlsplit(oracle_attack_url)
        control_oracle = urlsplit(oracle_control_url)
        valid_oracle_pair = bool(
            _valid_ssrf_oracle_url(oracle_attack_url)
            and _valid_ssrf_oracle_url(oracle_control_url)
            and oracle_attack_url != oracle_control_url
            and attack_oracle.scheme == control_oracle.scheme
            and attack_oracle.hostname == control_oracle.hostname
            and attack_oracle.port == control_oracle.port
        )
    elif oracle_mode == LOCAL_RESOURCE_SSRF_MODE:
        valid_oracle_pair = _valid_ssrf_local_oracle_pair(
            oracle_attack_url,
            oracle_control_url,
        )
    else:
        valid_oracle_pair = False
    if not valid_oracle_pair:
        return False, "SSRF parent oracle contract is invalid", {}

    attack = observation.attack
    control = observation.control
    marker = attack.get("marker")
    if not isinstance(marker, str) or not hmac.compare_digest(marker, oracle_marker):
        return (
            False,
            "SSRF response marker does not match the private oracle marker",
            {},
        )
    if observation.impact.confidentiality != "low":
        return False, "SSRF response-marker evidence requires confidentiality=low", {}
    if (
        observation.impact.integrity != "none"
        or observation.impact.availability != "none"
    ):
        return False, "SSRF response-marker evidence proves confidentiality only", {}
    if (
        attack.get("identity_verified") is not True
        or control.get("identity_verified") is not True
    ):
        return False, "SSRF response-marker proof lacks verified arm identities", {}
    if attack.get("destination_url") != oracle_attack_url:
        return False, "SSRF attack destination does not match the parent oracle", {}
    if control.get("destination_url") != oracle_control_url:
        return False, "SSRF control destination does not match the parent oracle", {}

    attack_signature = _ssrf_request_signature(attack.get("request_fingerprint"))
    control_signature = _ssrf_request_signature(control.get("request_fingerprint"))
    if attack_signature is None or control_signature is None:
        return False, "SSRF response-marker request fingerprint is invalid", {}
    if attack_signature != control_signature:
        return False, "SSRF attack/control request fingerprints differ", {}
    method, route = str(attack_signature[0]), str(attack_signature[1])
    expected_transports = _expected_http_transport_signatures(expected_http_transport)
    if not expected_transports:
        return False, "SSRF hypothesis HTTP transport is missing or invalid", {}
    observed_transport = _canonical_http_transport(
        attack_signature[0],
        attack_signature[1],
        dict(cast(tuple[tuple[str, str], ...], attack_signature[4])),
    )
    if (
        observed_transport is None
        or (
            *observed_transport,
            str(attack_signature[2]),
            str(attack_signature[3]),
        )
        not in expected_transports
    ):
        return (
            False,
            "SSRF request transport does not match the hypothesis entry point",
            {},
        )

    request_method = str(observation.request.get("method") or "").strip().upper()
    request_url = str(observation.request.get("url") or "").strip()
    target_origin = normalize_trace_origin(target_url)
    if (
        not target_origin
        or normalize_trace_origin(request_url) != target_origin
        or request_method != method
        or _normalize_request_path(urlsplit(request_url).path) != route
        or urlsplit(request_url).query
        or urlsplit(request_url).fragment
    ):
        return (
            False,
            "SSRF reported request does not match its fingerprint or sandbox",
            {},
        )

    attack_user_id = _trace_claimed_user_id(
        attack.get("attacker_user_id"), observation.attacker_role
    )
    control_user_id = _trace_claimed_user_id(
        control.get("attacker_user_id"), observation.attacker_role
    )
    if attack_user_id is None or attack_user_id != control_user_id:
        return False, "SSRF attack/control actor identity is invalid or changed", {}

    target_records = [
        record
        for record in trace_records
        if isinstance(record, dict) and record.get("origin") == target_origin
    ]
    if len(target_records) != len(trace_records):
        return False, "SSRF HTTP trace contains an invalid-origin record", {}
    sequences = [record.get("sequence") for record in target_records]
    if sequences != list(range(1, len(target_records) + 1)):
        return False, "SSRF HTTP trace sequence is incomplete or unordered", {}
    if any(_record_has_request_sentinel(record) for record in target_records):
        return False, "SSRF HTTP trace contains a sentinel-bearing child request", {}

    common = {
        "trace_salt": trace_salt,
        "target_origin": target_origin,
        "receipt_secret": receipt_secret,
        "trace_token": trace_token,
    }
    trace_signature = _ssrf_trace_signature(attack_signature)
    attack_matches = _matching_trace_requests(
        trace_records,
        trace_signature,
        object_id=oracle_attack_url,
        expected_user_id=attack_user_id,
        expected_role=observation.attacker_role,
        allow_credential_free_unauthenticated=(oracle_mode == LOCAL_RESOURCE_SSRF_MODE),
        **common,
    )
    control_matches = _matching_trace_requests(
        trace_records,
        trace_signature,
        object_id=oracle_control_url,
        expected_user_id=control_user_id,
        expected_role=observation.attacker_role,
        allow_credential_free_unauthenticated=(oracle_mode == LOCAL_RESOURCE_SSRF_MODE),
        **common,
    )
    attack_binding, reason = _one_trace_match(attack_matches, "SSRF attack")
    if attack_binding is None:
        return False, reason, {}
    control_binding, reason = _one_trace_match(control_matches, "SSRF control")
    if control_binding is None:
        return False, reason, {}
    if attack_binding["sequence"] >= control_binding["sequence"]:
        return False, "SSRF attack request must precede its control", {}
    causal_sequences = {
        record.get("sequence")
        for record in target_records
        if attack_binding["sequence"]
        <= int(record.get("sequence") or 0)
        <= control_binding["sequence"]
    }
    if causal_sequences != {
        attack_binding["sequence"],
        control_binding["sequence"],
    }:
        return (
            False,
            "SSRF HTTP trace contains extra traffic inside the proof window",
            {},
        )
    if attack_binding["parameter_shape"] != control_binding["parameter_shape"]:
        return False, "SSRF attack/control parameter shapes differ", {}
    if attack_binding["actor"].get("user_id") != control_binding["actor"].get(
        "user_id"
    ) or attack_binding["actor"].get("roles") != control_binding["actor"].get("roles"):
        return False, "SSRF signed attack/control actors differ", {}
    attack_actor_provenance = attack_binding["actor"].get("provenance")
    control_actor_provenance = control_binding["actor"].get("provenance")
    if (
        attack_actor_provenance not in {"signed_receipt", "credential_free_transport"}
        or attack_actor_provenance != control_actor_provenance
    ):
        return False, "SSRF attack/control actor provenance differs", {}
    if not _receipt_has_only_expected_privileges(
        attack_binding["actor"], observation.attacker_role
    ) or not _receipt_has_only_expected_privileges(
        control_binding["actor"], observation.attacker_role
    ):
        return (
            False,
            "SSRF signed actor carries privileges outside the expected role",
            {},
        )

    if oracle_mode == LOCAL_RESOURCE_SSRF_MODE:
        label = "local_resource_path"
        path_capability_occurrences: list[tuple[int, str, str, str]] = []
        for record in target_records:
            tracked = _trace_tracked_capability_fields(
                record,
                allowed_labels=frozenset({label}),
            )
            if tracked is None:
                return False, "local-resource capability trace is malformed", {}
            sequence = int(record.get("sequence") or 0)
            path_capability_occurrences.extend(
                (sequence, location, name, tracked_label)
                for location, name, tracked_label in tracked
            )
        destination_location = str(attack_signature[3])
        destination_parameter = str(attack_signature[2])
        expected_occurrences = [
            (
                attack_binding["sequence"],
                destination_location,
                destination_parameter,
                label,
            ),
            (
                control_binding["sequence"],
                destination_location,
                destination_parameter,
                label,
            ),
        ]
        if path_capability_occurrences != expected_occurrences:
            return (
                False,
                (
                    "local-resource path capability appears outside the exact "
                    "attack/control destination fields"
                ),
                {},
            )

    if attack_actor_provenance == "credential_free_transport":
        if (
            oracle_mode != LOCAL_RESOURCE_SSRF_MODE
            or len(target_records) != 2
            or [record.get("sequence") for record in target_records] != [1, 2]
            or cast(tuple[tuple[str, str], ...], attack_signature[5])
        ):
            return False, "credential-free SSRF proof contains undeclared traffic", {}
        expected_fields = {
            (str(attack_signature[3]), str(attack_signature[2])),
            *(
                tuple(str(key).split(":", 1))
                for key, _value in cast(
                    tuple[tuple[str, str], ...],
                    attack_signature[4],
                )
            ),
        }
        for binding in (attack_binding, control_binding):
            fields = tuple(binding["field_signature"])
            observed_fields = [(str(field[0]), str(field[1])) for field in fields]
            if (
                len(fields) != len(expected_fields)
                or len(observed_fields) != len(set(observed_fields))
                or set(observed_fields) != expected_fields
                or any(field[2] != "scalar" for field in fields)
            ):
                return (
                    False,
                    ("credential-free SSRF request contains undeclared fields"),
                    {},
                )

    for record in target_records:
        if int(record.get("sequence") or 0) >= attack_binding["sequence"]:
            break
        if record.get("response_actor_receipt") is None:
            continue
        preproof_actor, _actor_reason = _decode_actor_receipt(
            record,
            receipt_secret=receipt_secret,
            trace_token=trace_token,
        )
        if preproof_actor is None:
            return False, "SSRF pre-proof actor receipt is malformed or untrusted", {}
        if preproof_actor.get("user_id") == 0 and not preproof_actor.get("roles"):
            continue
        if preproof_actor.get(
            "user_id"
        ) != attack_user_id or not _receipt_has_only_expected_privileges(
            preproof_actor, observation.attacker_role
        ):
            return (
                False,
                (
                    "SSRF pre-proof traffic used an actor with privileges outside "
                    "the expected role"
                ),
                {},
            )
    if attack_actor_provenance == "signed_receipt":
        if attack_binding["actor"].get("nonce") == control_binding["actor"].get(
            "nonce"
        ) or attack_binding["actor"].get("request_nonce") == control_binding[
            "actor"
        ].get("request_nonce"):
            return False, "SSRF HTTP trace reused a signed request nonce", {}
    else:
        attack_nonce = attack_binding["record"].get("request_nonce")
        control_nonce = control_binding["record"].get("request_nonce")
        attack_digest = attack_binding["record"].get("request_digest")
        control_digest = control_binding["record"].get("request_digest")
        if (
            not isinstance(attack_nonce, str)
            or re.fullmatch(r"[0-9a-f]{64}", attack_nonce) is None
            or not isinstance(control_nonce, str)
            or re.fullmatch(r"[0-9a-f]{64}", control_nonce) is None
            or hmac.compare_digest(attack_nonce, control_nonce)
            or not isinstance(attack_digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", attack_digest) is None
            or not isinstance(control_digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", control_digest) is None
            or hmac.compare_digest(attack_digest, control_digest)
        ):
            return False, "credential-free SSRF request binding is invalid", {}

    attack_header_digest = attack_binding["record"].get("request_headers_sha256")
    control_header_digest = control_binding["record"].get("request_headers_sha256")
    if (
        not isinstance(attack_header_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", attack_header_digest) is None
        or not isinstance(control_header_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", control_header_digest) is None
        or not hmac.compare_digest(attack_header_digest, control_header_digest)
    ):
        return (
            False,
            "SSRF attack/control child request headers differ or are unbound",
            {},
        )

    destination_field = (str(attack_signature[3]), str(attack_signature[2]))
    attack_destination_digest = salted_scalar_sha256(oracle_attack_url, trace_salt)
    control_destination_digest = salted_scalar_sha256(oracle_control_url, trace_salt)
    capability_occurrences: dict[str, list[tuple[object, ...]]] = {
        attack_destination_digest: [],
        control_destination_digest: [],
    }
    for record in target_records:
        record_fields = _trace_field_signature(record)
        if record_fields is None:
            return False, "SSRF HTTP trace contains malformed request fields", {}
        for field in record_fields:
            digest = str(field[3])
            if digest in capability_occurrences:
                capability_occurrences[digest].append(
                    (record.get("sequence"), *field[:3])
                )
    expected_attack_occurrence = [
        (attack_binding["sequence"], *destination_field, "scalar")
    ]
    expected_control_occurrence = [
        (control_binding["sequence"], *destination_field, "scalar")
    ]
    if (
        capability_occurrences[attack_destination_digest] != expected_attack_occurrence
        or capability_occurrences[control_destination_digest]
        != expected_control_occurrence
    ):
        return (
            False,
            (
                "SSRF oracle capabilities appear outside their exact matched "
                "attack/control destination fields"
            ),
            {},
        )

    values_ok, values_reason = _ssrf_request_values_match(
        attack_binding,
        control_binding,
        attack_signature,
        attack_url=oracle_attack_url,
        control_url=oracle_control_url,
        trace_salt=trace_salt,
    )
    if not values_ok:
        return False, values_reason, {}

    attack_parts = _trace_body_parts(attack_binding["record"])
    control_parts = _trace_body_parts(control_binding["record"])
    if attack_parts is None or control_parts is None:
        return False, "SSRF response capture is incomplete or malformed", {}
    if attack_parts[2] or control_parts[2]:
        return (
            False,
            "SSRF response-marker proof requires complete response captures",
            {},
        )
    marker_bytes = oracle_marker.encode("utf-8")
    if attack_parts[0].count(marker_bytes) != 1:
        return (
            False,
            "SSRF attack response does not contain exactly one private marker",
            {},
        )
    if marker_bytes in control_parts[0]:
        return False, "SSRF control response contains the private marker", {}

    sanitized_oracle: list[dict[str, object]] | dict[str, object]
    if oracle_mode == "http":
        snapshot_ok, snapshot_reason, sanitized_oracle = _validate_ssrf_oracle_snapshot(
            oracle_snapshot,
            marker=oracle_marker,
            expected_generation_id=oracle_generation_id,
            attack_record=attack_binding["record"],
            control_record=control_binding["record"],
        )
        oracle_evidence_key = "inner_hits"
        success_reason = (
            "SSRF response marker, HTTP trace, actors, and inner hits passed"
        )
    else:
        snapshot_ok, snapshot_reason, sanitized_oracle = (
            _validate_ssrf_local_resource_snapshot(
                oracle_snapshot,
                marker=oracle_marker,
                expected_generation_id=oracle_generation_id,
                resource_path=urlsplit(oracle_attack_url).path,
                attack_record=attack_binding["record"],
                control_record=control_binding["record"],
            )
        )
        oracle_evidence_key = "local_resource_attestation"
        success_reason = (
            "SSRF local-resource marker, HTTP trace, actor, and attestation passed"
        )
    if not snapshot_ok:
        return False, snapshot_reason, {}
    evidence = {
        "oracle": "ssrf_response_marker",
        "destination_field": {
            "location": attack_signature[3],
            "name": attack_signature[2],
        },
        "attack_request": _sanitized_trace_binding(attack_binding),
        "control_request": _sanitized_trace_binding(control_binding),
        oracle_evidence_key: sanitized_oracle,
    }
    return True, success_reason, evidence


def validate_poc_observation(
    observation: PoCObservation,
    expected_bug_class: str | None = None,
    expected_attacker_role: str | None = None,
) -> tuple[bool, str]:
    """Validate measurements without trusting a model-authored success string."""
    if observation.verdict != "vulnerable":
        return False, "PoC reported not_vulnerable"
    if not observation.attacker_role.strip():
        return False, "attacker_role is empty"
    if not str(observation.request.get("method") or "").strip():
        return False, "request.method is missing"
    request_url = str(observation.request.get("url") or "").strip()
    if not request_url:
        return False, "request.url is missing"
    if urlparse(request_url).hostname not in {"localhost", "127.0.0.1", "::1"}:
        return False, "request.url is not a local sandbox target"
    if expected_attacker_role:
        observed_role = normalize_attacker_role(observation.attacker_role)
        required_role = normalize_attacker_role(expected_attacker_role)
        if required_role == UNKNOWN_ATTACKER_ROLE:
            return False, "source review has an unrecognized attacker role"
        if observed_role == UNKNOWN_ATTACKER_ROLE:
            return False, "PoC reported an unrecognized attacker role"
        if observed_role != required_role:
            return False, (
                f"PoC used attacker role {observation.attacker_role!r}; "
                f"source review requires {expected_attacker_role!r}"
            )
    if not observation.impact.description.strip():
        return False, "impact.description is empty"
    if {
        observation.impact.confidentiality,
        observation.impact.integrity,
        observation.impact.availability,
    } == {"none"}:
        return (
            False,
            "no confidentiality, integrity, or availability impact was observed",
        )

    if expected_bug_class:
        if (
            _is_ssrf_bug_class(expected_bug_class)
            and observation.oracle != "response_marker"
        ):
            return False, "SSRF automatic verification requires trusted response_marker"
        allowed = _allowed_oracles_for(expected_bug_class)
        if not allowed:
            return False, f"no automatic oracle is defined for {expected_bug_class}"
        if observation.oracle not in allowed:
            return False, (
                f"oracle {observation.oracle!r} cannot prove {expected_bug_class}; "
                f"expected one of {sorted(allowed)}"
            )

    attack = observation.attack
    control = observation.control
    if attack.get("observed") is not True:
        return False, "attack observation did not record observed=true"
    if control.get("observed") is not False:
        return False, "negative control did not record observed=false"

    oracle = observation.oracle
    if oracle == "timing":
        attack_samples = _number_list(attack.get("samples_seconds"))
        control_samples = _number_list(control.get("samples_seconds"))
        if len(attack_samples) < 3 or len(control_samples) < 3:
            return (
                False,
                "timing oracle requires at least three attack and three control samples",
            )
        attack_median = statistics.median(attack_samples)
        control_median = statistics.median(control_samples)
        if attack_median - control_median < 3.0 or attack_median < max(
            2.0, control_median * 2.0
        ):
            return False, (
                "timing differential is too small "
                f"(attack median={attack_median:.2f}s, control median={control_median:.2f}s)"
            )
    elif oracle == "response_marker":
        marker = str(attack.get("marker") or "")
        if len(marker) < 8:
            return (
                False,
                "response-marker oracle requires attack.marker to contain the unique "
                "response marker (at least 8 characters)",
            )
        if attack.get("marker_present") is not True:
            return False, "response-marker oracle requires attack.marker_present=true"
        if control.get("marker_present") is not False:
            return False, "negative-control response also contains the marker"
    elif oracle == "state_change":
        if (
            "before" not in attack
            or "after" not in attack
            or attack.get("before") == attack.get("after")
        ):
            return False, "state-change oracle does not show a before/after difference"
        if control.get("before") != control.get("after"):
            return False, "negative control also changed state"
    elif oracle == "authorization":
        if attack.get("allowed") is not True or control.get("allowed") is not False:
            return (
                False,
                "authorization oracle does not show attack allowed and control denied",
            )
        if not str(attack.get("privileged_effect") or "").strip():
            return False, "authorization oracle lacks the privileged effect"
    elif oracle == "cross_object_access":
        accepted, reason = _validate_cross_object_observation(observation)
        if not accepted:
            return False, reason
    elif oracle == "callback":
        if (
            int(attack.get("hit_count") or 0) < 1
            or int(control.get("hit_count") or 0) != 0
        ):
            return (
                False,
                "callback oracle did not observe attack-only server-side callbacks",
            )
        marker = str(attack.get("marker") or "")
        if len(marker) < 8 or attack.get("marker_present") is not True:
            return False, "callback oracle did not capture a unique sensitive marker"
        if control.get("marker_present") is not False:
            return False, "negative-control callback also captured the sensitive marker"
    elif oracle == "browser_execution":
        if attack.get("executed") is not True or control.get("executed") is not False:
            return (
                False,
                "browser oracle did not observe attack-only JavaScript execution",
            )
    elif oracle == "file_effect":
        path = str(attack.get("path") or "")
        control_path = str(control.get("path") or "")
        attack_before_exists = attack.get("before_exists")
        attack_after_exists = attack.get("after_exists")
        control_before_exists = control.get("before_exists")
        control_after_exists = control.get("after_exists")
        attack_before_hash = str(attack.get("before_sha256") or "")
        attack_after_hash = str(
            attack.get("after_sha256")
            or attack.get("marker_sha256")
            or attack.get("file_sha256")
            or ""
        )
        control_before_hash = str(control.get("before_sha256") or "")
        control_after_hash = str(
            control.get("after_sha256")
            or control.get("marker_sha256")
            or control.get("file_sha256")
            or ""
        )
        normalized_path = _normalize_file_effect_path(path)
        normalized_control_path = _normalize_file_effect_path(control_path)
        if not normalized_path or not normalized_control_path:
            return False, "file oracle lacks measured attack/control paths"
        if normalized_path == normalized_control_path:
            return (
                False,
                "file oracle requires distinct normalized attack/control paths",
            )
        if not isinstance(attack_before_exists, bool) or not isinstance(
            attack_after_exists, bool
        ):
            return False, (
                "file oracle requires boolean attack.before_exists and "
                "attack.after_exists measurements"
            )
        if not isinstance(control_before_exists, bool) or not isinstance(
            control_after_exists, bool
        ):
            return False, (
                "file oracle requires boolean control.before_exists and "
                "control.after_exists measurements"
            )
        if (
            attack_after_exists is not True
            or _SHA256_RE.fullmatch(attack_after_hash) is None
        ):
            return False, (
                "file oracle requires an existing attack after-state with a measured "
                "64-character SHA-256"
            )

        created = attack_before_exists is False and attack_after_exists is True
        overwritten = (
            attack_before_exists is True
            and attack_after_exists is True
            and _SHA256_RE.fullmatch(attack_before_hash) is not None
            and attack_before_hash.lower() != attack_after_hash.lower()
        )
        if not created and not overwritten:
            return False, (
                "file oracle does not prove creation or overwrite: the attack file "
                "must be absent before and present after, or its SHA-256 must change"
            )

        control_absent_unchanged = (
            control_before_exists is False and control_after_exists is False
        )
        control_file_unchanged = (
            control_before_exists is True
            and control_after_exists is True
            and _SHA256_RE.fullmatch(control_before_hash) is not None
            and _SHA256_RE.fullmatch(control_after_hash) is not None
            and control_before_hash.lower() == control_after_hash.lower()
        )
        if not control_absent_unchanged and not control_file_unchanged:
            return False, (
                "negative control changed file existence or SHA-256, or lacks "
                "comparable before/after measurements"
            )

    return True, "structured attack observation passed its independent oracle"


def _alloc_port() -> int:
    for port in range(_PORT_MIN, _PORT_MAX + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError(f"no free port in {_PORT_MIN}-{_PORT_MAX}")


async def _run(
    *cmd: str, cwd: Optional[str] = None, check: bool = True
) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=cwd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    out = stdout.decode("utf-8", errors="replace")
    err = stderr.decode("utf-8", errors="replace")
    if check and proc.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} exited {proc.returncode}: {err.strip()}")
    return proc.returncode or 0, out, err


async def _read_poc_output(
    stream: asyncio.StreamReader | None,
    *,
    label: str,
) -> bytes:
    """Read one model-authored output stream without unbounded parent memory."""
    if stream is None:
        return b""
    chunks: list[bytes] = []
    consumed = 0
    while True:
        chunk = await stream.read(_POC_OUTPUT_READ_BYTES)
        if not chunk:
            return b"".join(chunks)
        consumed += len(chunk)
        if consumed > _POC_OUTPUT_LIMIT_BYTES:
            raise RuntimeError(f"PoC {label} exceeded {_POC_OUTPUT_LIMIT_BYTES} bytes")
        chunks.append(chunk)


async def _communicate_poc_bounded(
    proc: asyncio.subprocess.Process,
) -> tuple[bytes, bytes]:
    """Drain stdout and stderr concurrently under fixed byte ceilings."""
    stdout_task = asyncio.create_task(_read_poc_output(proc.stdout, label="stdout"))
    stderr_task = asyncio.create_task(_read_poc_output(proc.stderr, label="stderr"))
    try:
        stdout, stderr = await asyncio.gather(stdout_task, stderr_task)
        await proc.wait()
        return stdout, stderr
    finally:
        for task in (stdout_task, stderr_task):
            if not task.done():
                task.cancel()
        await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)


async def _kill_poc_process_group(proc: asyncio.subprocess.Process) -> None:
    """Stop the isolated process session before releasing its sandbox bundle."""
    # The session leader may exit after spawning a detached-stdio descendant.
    # The process group remains authoritative even after that leader has been
    # reaped, so always signal the group before considering cleanup complete.
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    await proc.wait()


async def _probe_ssrf_oracle_readiness(
    container_name: str,
    readiness_url: str,
) -> None:
    """Require an exact oracle readiness response from inside WordPress.

    The private readiness capability is supplied over stdin instead of the
    process command line.  Both the PHP stream and the parent subprocess have
    short deadlines, and the response shape is exact rather than truthy.
    """
    php = (
        "$url=stream_get_contents(STDIN);"
        "if(!is_string($url)||strlen($url)>512){exit(70);}"
        "$ctx=stream_context_create(['http'=>["
        "'method'=>'GET','timeout'=>3.0,'ignore_errors'=>false,"
        "'follow_location'=>0,'max_redirects'=>0]]);"
        "$data=@file_get_contents($url,false,$ctx);"
        "$status=$http_response_header[0]??'';"
        "if(!is_string($data)||!preg_match('/^HTTP\\/[0-9.]+ 200(?: |$)/',$status))"
        "{exit(71);}fwrite(STDOUT,$data);"
    )
    proc = await asyncio.create_subprocess_exec(
        "docker",
        "exec",
        "-i",
        container_name,
        "php",
        "-r",
        php,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(readiness_url.encode("ascii")),
            timeout=6.0,
        )
    except BaseException:
        if proc.returncode is None:
            proc.kill()
        await proc.wait()
        raise
    if proc.returncode != 0 or stderr or len(stdout) > 256:
        raise RuntimeError("SSRF oracle readiness probe failed")
    try:
        payload = json.loads(stdout.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("SSRF oracle readiness response is malformed") from exc
    if type(payload) is not dict or payload != {
        "schema_version": 1,
        "ready": True,
    }:
        raise RuntimeError("SSRF oracle readiness response is invalid")


def _local_resource_host_path(
    host_directory: Path,
    oracle: LocalResourceSsrfOracle,
) -> Path:
    """Resolve the opaque container resource to one file in the private mount."""
    container_directory = PurePosixPath(LOCAL_RESOURCE_SSRF_DIRECTORY)
    resource_path = PurePosixPath(oracle.resource_path)
    try:
        relative = resource_path.relative_to(container_directory)
    except ValueError as exc:
        raise RuntimeError("local-resource SSRF path escaped its mount") from exc
    if len(relative.parts) != 1 or re.fullmatch(r"[0-9a-f]{64}", relative.name) is None:
        raise RuntimeError("local-resource SSRF path is malformed")
    root = host_directory.resolve(strict=True)
    target = (root / relative.name).resolve()
    if target.parent != root:
        raise RuntimeError("local-resource SSRF host path escaped its mount")
    return target


def _provision_ssrf_local_resource(
    host_directory: Path,
    oracle: LocalResourceSsrfOracle,
) -> Path:
    """Atomically rotate a private canary in the parent-owned bind mount."""
    target = _local_resource_host_path(host_directory, oracle)
    marker = oracle.private_marker.encode("ascii", errors="strict")
    fd, temporary_name = tempfile.mkstemp(
        prefix=".squadrone-ssrf-",
        dir=os.fspath(target.parent),
    )
    temporary = Path(temporary_name)
    try:
        view = memoryview(marker)
        while view:
            written = os.write(fd, view)
            if written < 1:
                raise RuntimeError("failed to write local-resource SSRF canary")
            view = view[written:]
        os.fsync(fd)
        os.fchmod(fd, 0o444)
        os.close(fd)
        fd = -1
        os.replace(temporary, target)
    finally:
        if fd >= 0:
            os.close(fd)
        temporary.unlink(missing_ok=True)
    return target


async def _inspect_ssrf_local_resource(
    container_name: str,
    resource_path: str,
) -> dict[str, object]:
    """Measure the mounted canary from inside WordPress without reading its bytes."""
    php = (
        "$p=stream_get_contents(STDIN);"
        "if(!is_string($p)||strlen($p)>256||"
        "!preg_match('#^/var/lib/squadrone/ssrf/[0-9a-f]{64}$#D',$p)){exit(70);}"
        "$s=@lstat($p);$r=@realpath($p);$h=@hash_file('sha256',$p);"
        "if(!is_array($s)||!is_string($r)||!is_string($h)){exit(71);}"
        "$o=['resource_path'=>$r,'content_sha256'=>$h,"
        "'content_size_bytes'=>(int)$s['size'],'owner_uid'=>(int)$s['uid'],"
        "'owner_gid'=>(int)$s['gid'],'file_mode'=>((int)$s['mode']&0777),"
        "'link_count'=>(int)$s['nlink'],'is_regular_file'=>is_file($p),"
        "'is_symlink'=>is_link($p)];"
        "fwrite(STDOUT,json_encode($o,JSON_UNESCAPED_SLASHES));"
    )
    proc = await asyncio.create_subprocess_exec(
        "docker",
        "exec",
        "-i",
        container_name,
        "php",
        "-r",
        php,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(resource_path.encode("ascii", errors="strict")),
            timeout=6.0,
        )
    except BaseException:
        if proc.returncode is None:
            proc.kill()
        await proc.wait()
        raise
    if proc.returncode != 0 or stderr or not stdout or len(stdout) > 2048:
        raise RuntimeError("local-resource SSRF canary inspection failed")
    try:
        payload = json.loads(stdout.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("local-resource SSRF inspection is malformed") from exc
    required = {
        "resource_path",
        "content_sha256",
        "content_size_bytes",
        "owner_uid",
        "owner_gid",
        "file_mode",
        "link_count",
        "is_regular_file",
        "is_symlink",
    }
    if not isinstance(payload, dict) or set(payload) != required:
        raise RuntimeError("local-resource SSRF inspection has an invalid shape")
    if (
        not isinstance(payload["resource_path"], str)
        or re.fullmatch(
            re.escape(LOCAL_RESOURCE_SSRF_DIRECTORY) + r"/[0-9a-f]{64}",
            payload["resource_path"],
        )
        is None
        or not isinstance(payload["content_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", payload["content_sha256"]) is None
        or any(
            type(payload[key]) is not int
            for key in (
                "content_size_bytes",
                "owner_uid",
                "owner_gid",
                "file_mode",
                "link_count",
            )
        )
        or type(payload["is_regular_file"]) is not bool
        or type(payload["is_symlink"]) is not bool
    ):
        raise RuntimeError("local-resource SSRF inspection values are invalid")
    return payload


def _accepted_ssrf_bind_sources(
    expected_source: str,
    *,
    platform: str | None = None,
) -> frozenset[str]:
    """Return exact host-source spellings Docker may report for one resolved path."""
    accepted = {expected_source}
    runtime_platform = sys.platform if platform is None else platform
    if runtime_platform == "darwin":
        if expected_source.startswith("/private/"):
            accepted.add(expected_source.removeprefix("/private"))
        accepted.update(f"/host_mnt{source}" for source in tuple(accepted))
    return frozenset(accepted)


async def _probe_ssrf_local_mount(
    container_name: str,
    host_directory: Path,
) -> None:
    """Require exactly one read-only bind mount at the protected container path."""
    _code, stdout, stderr = await _run(
        "docker",
        "inspect",
        "--format",
        "{{json .Mounts}}",
        container_name,
    )
    if stderr or len(stdout) > 64 * 1024:
        raise RuntimeError("local-resource SSRF mount inspection failed")
    try:
        mounts = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("local-resource SSRF mount inspection is malformed") from exc
    expected_source = os.fspath(host_directory.resolve(strict=True))
    matches = [
        mount
        for mount in mounts
        if isinstance(mount, dict)
        and mount.get("Destination") == LOCAL_RESOURCE_SSRF_DIRECTORY
    ]
    if len(matches) != 1:
        raise RuntimeError("local-resource SSRF mount is missing or ambiguous")
    mount = matches[0]
    observed_source = mount.get("Source")
    # Docker Desktop may report either the macOS /private alias or the
    # corresponding Linux-VM /host_mnt source. Accept only exact spellings
    # derived from the already-resolved parent directory.
    accepted_sources = _accepted_ssrf_bind_sources(expected_source)
    if (
        mount.get("Type") != "bind"
        or mount.get("RW") is not False
        or not isinstance(observed_source, str)
        or observed_source not in accepted_sources
    ):
        raise RuntimeError(
            "local-resource SSRF mount is not the expected read-only bind"
        )


class SandboxManager:
    """Boots a fresh WordPress + MariaDB stack and tears it down on exit."""

    def __init__(
        self,
        config: SandboxConfig,
        boot_timeout_s: int = 60,
        poc_timeout_s: int = 120,
        *,
        ssrf_oracle_modes: frozenset[Literal["http", "local_resource"]] = frozenset(),
    ):
        unknown_ssrf_modes = set(ssrf_oracle_modes).difference(_SSRF_ORACLE_MODES)
        if unknown_ssrf_modes:
            raise ValueError("sandbox received an unsupported SSRF oracle mode")
        self.config = config
        self.boot_timeout_s = boot_timeout_s
        self.poc_timeout_s = poc_timeout_s
        self.port: int = 0
        self.project: str = ""
        self.workdir: Optional[Path] = None
        self.container_name: str = ""
        self.target_url: str = ""
        self.wp_cli: Optional[WPCli] = None
        self._trace_token = secrets.token_hex(32)
        self._receipt_secret = secrets.token_bytes(32)
        self._ssrf_oracle_modes = frozenset(ssrf_oracle_modes)
        self._ssrf_oracle: SsrfOracleServer | None = None
        self._ssrf_local_oracle: LocalResourceSsrfOracle | None = None
        self._ssrf_local_host_dir: Path | None = None
        self._ssrf_operation_lock = asyncio.Lock()
        self._booted = False
        self._baseline_accounts: list[dict] | None = None
        self._pre_plugin_role_capabilities: dict[str, frozenset[str]] | None = None
        self._baseline_passwords = {
            login: secrets.token_urlsafe(32) for login, _role in self.BASELINE_USERS
        }

    # ── lifecycle ────────────────────────────────────────────────

    async def __aenter__(self) -> "SandboxManager":
        try:
            await self.boot()
        except BaseException:
            await self.teardown()
            raise
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.teardown()

    async def prepare_ssrf_oracle(self) -> dict[str, str]:
        """Start one fresh parent oracle and verify container reachability."""
        async with self._ssrf_operation_lock:
            return await self._prepare_ssrf_oracle_locked()

    async def _prepare_ssrf_oracle_locked(self) -> dict[str, str]:
        """Prepare an oracle while excluding runs and lifecycle mutation."""
        if "http" not in self._ssrf_oracle_modes:
            raise RuntimeError("HTTP SSRF oracle was not enabled for this sandbox")
        previous, self._ssrf_oracle = self._ssrf_oracle, None
        if previous is not None:
            await previous.close()
        self._clear_ssrf_local_oracle_locked()
        if not self._booted or not self.container_name:
            raise RuntimeError("sandbox is unavailable for SSRF oracle preparation")

        oracle = SsrfOracleServer()
        try:
            await oracle.start()
            await _probe_ssrf_oracle_readiness(
                self.container_name,
                oracle.readiness_url,
            )
            attack_url = oracle.attack_url
            control_url = oracle.control_url
            if (
                not oracle.is_running
                or not _valid_ssrf_oracle_url(attack_url)
                or not _valid_ssrf_oracle_url(control_url)
                or attack_url == control_url
            ):
                raise RuntimeError("SSRF oracle produced invalid public URLs")
        except BaseException as exc:
            await oracle.close()
            if isinstance(exc, asyncio.CancelledError):
                raise
            raise RuntimeError("failed to prepare the SSRF oracle") from exc
        self._ssrf_oracle = oracle
        return {"attack_url": attack_url, "control_url": control_url}

    async def prepare_ssrf_local_resource_oracle(self) -> dict[str, str]:
        """Prepare a fresh protected-file oracle for scheme-bypass verification."""
        async with self._ssrf_operation_lock:
            if "local_resource" not in self._ssrf_oracle_modes:
                raise RuntimeError(
                    "local-resource SSRF oracle was not enabled for this sandbox"
                )
            previous, self._ssrf_oracle = self._ssrf_oracle, None
            if previous is not None:
                await previous.close()
            self._clear_ssrf_local_oracle_locked()
            if (
                not self._booted
                or not self.container_name
                or self._ssrf_local_host_dir is None
            ):
                raise RuntimeError(
                    "sandbox is unavailable for local-resource SSRF preparation"
                )
            await _probe_ssrf_local_mount(
                self.container_name,
                self._ssrf_local_host_dir,
            )
            oracle = LocalResourceSsrfOracle()
            self._ssrf_local_oracle = oracle
            return oracle.public_context()

    def _clear_ssrf_local_oracle_locked(self) -> None:
        oracle, self._ssrf_local_oracle = self._ssrf_local_oracle, None
        if oracle is None or self._ssrf_local_host_dir is None:
            return
        try:
            _local_resource_host_path(
                self._ssrf_local_host_dir,
                oracle,
            ).unlink(missing_ok=True)
        except (OSError, RuntimeError):
            logger.warning("failed to remove local-resource SSRF canary")

    async def boot(self) -> None:
        if self._booted:
            return
        self._baseline_accounts = None
        self._pre_plugin_role_capabilities = None
        async with _PORT_ALLOC_LOCK:
            self.port = _alloc_port()
            self.project = f"{_PROJECT_PREFIX}-{uuid.uuid4().hex[:8]}"
            self.container_name = f"{self.project}-wordpress-1"
            self.target_url = f"http://localhost:{self.port}"
            self.workdir = Path(tempfile.mkdtemp(prefix=f"{self.project}-"))
            if "local_resource" in self._ssrf_oracle_modes:
                self._ssrf_local_host_dir = self.workdir / "ssrf-local-resource"
                self._ssrf_local_host_dir.mkdir(mode=0o755)
                self._ssrf_local_host_dir.chmod(0o755)
            else:
                self._ssrf_local_host_dir = None

            template = Template((_DOCKER_DIR / "docker-compose.yml.j2").read_text())
            rendered = template.render(
                port=self.port,
                wp_url=self.target_url,
                wp_title="Squadrone Sandbox",
                wp_admin_user=self.config.wp_admin_user,
                wp_admin_pass=self.config.wp_admin_pass,
                wp_admin_email=self.config.wp_admin_email,
                enable_http_ssrf="http" in self._ssrf_oracle_modes,
                enable_local_resource_ssrf=(
                    "local_resource" in self._ssrf_oracle_modes
                ),
                ssrf_local_host_dir=(
                    os.fspath(self._ssrf_local_host_dir)
                    if self._ssrf_local_host_dir is not None
                    else ""
                ),
            )
            (self.workdir / "docker-compose.yml").write_text(rendered)
            shutil.copy(_DOCKER_DIR / "wp-init.sh", self.workdir / "wp-init.sh")
            (self.workdir / "wp-init.sh").chmod(0o755)

            logger.info("sandbox boot project=%s port=%d", self.project, self.port)
            await _run(
                "docker",
                "compose",
                "-p",
                self.project,
                "up",
                "-d",
                cwd=str(self.workdir),
            )

        await self._wait_for_wordpress()
        self.wp_cli = WPCli(self.container_name)
        # wp-init.sh may not have completed `wp core install` by the time the port answers;
        # ensure it has, then we are ready.
        await self._ensure_wp_installed()
        await self._install_actor_receipt_plugin()
        await self._ensure_wp_upload_path()
        self._booted = True

    async def teardown(self) -> None:
        async with self._ssrf_operation_lock:
            await self._teardown_locked()

    async def _teardown_locked(self) -> None:
        oracle, self._ssrf_oracle = self._ssrf_oracle, None
        try:
            if oracle is not None:
                await oracle.close()
            self._clear_ssrf_local_oracle_locked()
        finally:
            try:
                if self.project:
                    logger.info("sandbox teardown project=%s", self.project)
                    await _run(
                        "docker",
                        "compose",
                        "-p",
                        self.project,
                        "down",
                        "-v",
                        cwd=str(self.workdir) if self.workdir else None,
                        check=False,
                    )
            finally:
                if self.workdir and self.workdir.exists():
                    shutil.rmtree(self.workdir, ignore_errors=True)
                self._booted = False
                self._ssrf_local_host_dir = None
                self._baseline_accounts = None
                self._pre_plugin_role_capabilities = None

    # ── snapshot + restore ──────────────────────────────────────────────────

    @property
    def db_container_name(self) -> str:
        return f"{self.project}-db-1"

    async def snapshot(self) -> Path:
        """Capture DB + wp-content to a temp directory. Returns the snapshot path.

        Capturing all of wp-content prevents a failed or successful PoC from
        contaminating a later attempt through files outside uploads.
        """
        if not self._booted:
            raise RuntimeError("snapshot called before sandbox booted")
        snap_dir = Path(tempfile.mkdtemp(prefix=f"{self.project}-snap-"))
        # DB dump
        rc, dump, err = await _run(
            "docker",
            "exec",
            self.db_container_name,
            "mariadb-dump",
            "-uwpuser",
            "-pwppass",
            "--add-drop-database",
            "--databases",
            "wordpress",
            check=False,
        )
        if rc != 0 or not dump.strip():
            shutil.rmtree(snap_dir, ignore_errors=True)
            raise RuntimeError(
                f"snapshot database dump failed (rc={rc}): {err.strip()[:200]}"
            )
        (snap_dir / "db.sql").write_text(dump)
        # Full wp-content archive, including the installed plugin and uploads.
        await _run(
            "docker",
            "exec",
            self.container_name,
            "sh",
            "-c",
            "mkdir -p /var/www/html/wp-content && "
            "tar czf /tmp/squadrone_wp_content.tar.gz -C /var/www/html wp-content",
        )
        await _run(
            "docker",
            "cp",
            f"{self.container_name}:/tmp/squadrone_wp_content.tar.gz",
            str(snap_dir / "wp-content.tar.gz"),
        )
        content_tar = snap_dir / "wp-content.tar.gz"
        if not content_tar.exists() or content_tar.stat().st_size == 0:
            shutil.rmtree(snap_dir, ignore_errors=True)
            raise RuntimeError("snapshot wp-content archive is missing or empty")
        logger.info("sandbox snapshot → %s (db=%d bytes)", snap_dir, len(dump))
        return snap_dir

    async def restore(self, snap_dir: Path) -> None:
        """Restore DB and all of wp-content from a previous snapshot."""
        if not self._booted:
            raise RuntimeError("restore called before sandbox booted")
        db_sql_path = snap_dir / "db.sql"
        if not db_sql_path.exists() or db_sql_path.stat().st_size == 0:
            raise RuntimeError(f"restore snapshot has no database dump: {snap_dir}")
        sql_bytes = db_sql_path.read_bytes()
        proc = await asyncio.create_subprocess_exec(
            "docker",
            "exec",
            "-i",
            self.db_container_name,
            "mariadb",
            "-uwpuser",
            "-pwppass",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _stdout, _stderr = await proc.communicate(sql_bytes)
        if proc.returncode != 0:
            raise RuntimeError(
                "restore database import failed: "
                + (_stderr.decode(errors="replace") or "")[:200]
            )

        content_tar = snap_dir / "wp-content.tar.gz"
        if not content_tar.exists() or content_tar.stat().st_size == 0:
            raise RuntimeError(
                f"restore snapshot has no wp-content archive: {snap_dir}"
            )
        await _run(
            "docker",
            "cp",
            str(content_tar),
            f"{self.container_name}:/tmp/squadrone_wp_content.tar.gz",
        )
        await _run(
            "docker",
            "exec",
            self.container_name,
            "sh",
            "-c",
            "rm -rf /var/www/html/wp-content && "
            "tar xzf /tmp/squadrone_wp_content.tar.gz -C /var/www/html",
        )
        logger.info("sandbox restore from %s — done", snap_dir)

    async def restart_wordpress_runtime(self) -> None:
        """Kill request workers and require the restored WordPress runtime to return."""
        if not self._booted or not self.container_name:
            raise RuntimeError("runtime restart called before sandbox booted")
        await _run("docker", "restart", self.container_name)
        await self._wait_for_wordpress()
        if self._ssrf_local_host_dir is not None:
            await _probe_ssrf_local_mount(
                self.container_name,
                self._ssrf_local_host_dir,
            )

    # ── helpers ─────────────────────────────────────────────────

    async def _wait_for_wordpress(self) -> None:
        """Wait for Apache to answer (any HTTP status) — pre-install it returns 302."""
        deadline = time.time() + self.boot_timeout_s
        url = f"{self.target_url}/wp-login.php"
        async with httpx.AsyncClient(timeout=5.0) as client:
            while time.time() < deadline:
                try:
                    r = await client.get(url)
                    if r.status_code in (200, 302):
                        return
                except (httpx.HTTPError, OSError):
                    pass
                await asyncio.sleep(2)
        raise RuntimeError(
            f"WordPress not reachable at {url} within {self.boot_timeout_s}s"
        )

    async def _ensure_wp_installed(self) -> None:
        """Make sure wp-cli is installed and `wp core install` has been run."""
        # 1. Install wp-cli inside container if missing.
        rc, _, _ = await _run(
            "docker",
            "exec",
            self.container_name,
            "sh",
            "-c",
            "command -v wp >/dev/null 2>&1",
            check=False,
        )
        if rc != 0:
            await _run(
                "docker",
                "exec",
                self.container_name,
                "sh",
                "-c",
                "curl -sSLo /usr/local/bin/wp "
                "https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar "
                "&& chmod +x /usr/local/bin/wp",
            )

        # The compose dependency starts WordPress only after MariaDB is healthy.
        # Do not use `wp db check` here: it shells out to `mysqlcheck`, which the
        # official WordPress image does not provide and would consume the entire
        # boot timeout even when the database is healthy.

        # 2. Run wp core install if not already installed.
        rc, _, _ = await _run(
            "docker",
            "exec",
            self.container_name,
            "wp",
            "--allow-root",
            "core",
            "is-installed",
            check=False,
        )
        if rc != 0:
            await _run(
                "docker",
                "exec",
                "--user",
                WORDPRESS_WEB_USER,
                self.container_name,
                "wp",
                "core",
                "install",
                f"--url={self.target_url}",
                "--title=Squadrone Sandbox",
                f"--admin_user={self.config.wp_admin_user}",
                f"--admin_password={self.config.wp_admin_pass}",
                f"--admin_email={self.config.wp_admin_email}",
                "--skip-email",
            )

    async def _ensure_wp_upload_path(self) -> None:
        """Create and validate WordPress's current upload path as the web identity.

        A fresh site has not necessarily handled a media upload yet. Establishing
        this ordinary WordPress prerequisite prevents plugin file operations from
        failing only because the disposable baseline lacks its dated uploads
        directory. No permissions or ownership are changed: an image that already
        contains an unwritable path fails closed instead of being broadened.
        """
        assert self.wp_cli is not None
        php = (
            "$upload = wp_upload_dir(); $path = $upload['path'] ?? ''; "
            "if (!$path || !wp_mkdir_p($path) || !is_writable($path)) { "
            "WP_CLI::error('WordPress upload path is not writable by the web user.'); "
            "} echo $path;"
        )
        rc, out, err = await self.wp_cli._exec_result(
            "eval", php, user=WORDPRESS_WEB_USER
        )
        if rc != 0:
            raise RuntimeError(
                "failed to prepare WordPress upload path as web user: "
                + (err or out).strip()[:300]
            )
        logger.info(
            "sandbox upload path ready as %s: %s", WORDPRESS_WEB_USER, out.strip()
        )

    async def _install_actor_receipt_plugin(self) -> None:
        """Install the verifier-owned MU-plugin that signs observed WP identities."""
        if self.workdir is None:
            raise RuntimeError("sandbox workdir is unavailable for actor receipt setup")
        if not _ACTOR_RECEIPT_TEMPLATE.is_file():
            raise RuntimeError(
                f"actor receipt template is missing: {_ACTOR_RECEIPT_TEMPLATE}"
            )
        rendered = Template(_ACTOR_RECEIPT_TEMPLATE.read_text()).render(
            trace_token=self._trace_token,
            receipt_secret=self._receipt_secret.hex(),
        )
        local_path = self.workdir / "squadrone-actor-receipt.php"
        local_path.write_text(rendered)
        destination_dir = "/var/www/html/wp-content/mu-plugins"
        destination = f"{destination_dir}/squadrone-actor-receipt.php"
        await _run(
            "docker",
            "exec",
            self.container_name,
            "mkdir",
            "-p",
            destination_dir,
        )
        await _run(
            "docker",
            "cp",
            str(local_path),
            f"{self.container_name}:{destination}",
        )
        rc, _out, err = await _run(
            "docker",
            "exec",
            self.container_name,
            "php",
            "-l",
            destination,
            check=False,
        )
        if rc != 0:
            raise RuntimeError(
                "sandbox actor receipt plugin failed PHP lint: " + err.strip()[:300]
            )

    # ── operations ──────────────────────────────────────────────

    async def install_plugin(self, zip_path: str, plugin_slug: str) -> None:
        """Install one scanned plugin with production-like filesystem ownership.

        Run extraction as the WordPress web-service operating-system identity and
        select the configured WordPress administrator for activation hooks. This
        matches a dashboard install without broadening package modes, while giving
        activation-created files the identity that later HTTP requests use.
        """
        assert self.wp_cli is not None
        slug = validate_plugin_slug(plugin_slug)
        if self._pre_plugin_role_capabilities is None:
            captured_roles = await self.wp_cli.role_capabilities()
            required_core_roles = {
                "administrator",
                "editor",
                "author",
                "contributor",
                "subscriber",
            }
            if (
                not required_core_roles.issubset(captured_roles)
                or "manage_options"
                not in captured_roles.get("administrator", frozenset())
                or "read" not in captured_roles.get("subscriber", frozenset())
            ):
                raise RuntimeError(
                    "pre-plugin WordPress role capability ceiling is incomplete"
                )
            self._pre_plugin_role_capabilities = captured_roles
        dest = f"/tmp/squadrone-{slug}.zip"
        await _run("docker", "cp", zip_path, f"{self.container_name}:{dest}")
        await self.wp_cli.install_plugin(
            dest,
            user=WORDPRESS_WEB_USER,
            wp_user=self.config.wp_admin_email,
        )
        await self._fire_admin_init()

    async def _fire_admin_init(self) -> bool:
        """Trigger admin_init in a real admin context after plugin activation.

        Many plugins (events-manager, woocommerce, et al.) defer their dbDelta()
        table creation to admin_init rather than the activation hook itself —
        because WP_ADMIN must be defined during WP bootstrap (not after), this
        cannot be faked via `wp eval do_action('admin_init')`. Log in with the
        configured sandbox administrator and visit /wp-admin/ once, which gives a
        real authenticated admin request lifecycle.
        """
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=20.0) as client:
                login_url = f"{self.target_url}/wp-login.php"
                admin_url = f"{self.target_url}/wp-admin/"
                prime = await client.get(login_url)
                if prime.status_code != 200:
                    raise RuntimeError(f"login prime returned HTTP {prime.status_code}")
                login = await client.post(
                    login_url,
                    data={
                        "log": self.config.wp_admin_user,
                        "pwd": self.config.wp_admin_pass,
                        "wp-submit": "Log In",
                        "redirect_to": admin_url,
                        "testcookie": "1",
                    },
                )
                has_auth_cookie = any(
                    str(cookie.name).startswith("wordpress_logged_in_")
                    for cookie in client.cookies.jar
                )
                if login.status_code >= 400 or not has_auth_cookie:
                    raise RuntimeError(
                        "configured administrator login did not establish an "
                        "authenticated WordPress session"
                    )
                probe = await client.get(admin_url)
                if probe.status_code >= 400:
                    raise RuntimeError(
                        f"authenticated wp-admin request returned HTTP {probe.status_code}"
                    )
                logger.info(
                    "post-install admin_init: authenticated GET /wp-admin/ -> %d",
                    probe.status_code,
                )
                return True
        except Exception as e:
            logger.warning("post-install admin_init dispatch failed: %s", e)
            return False

    # Baseline non-admin accounts cover every core WordPress role that can act as
    # an authenticated attacker, plus optional roles commonly registered by an
    # installed plugin. Every non-admin role is optional at sandbox setup time:
    # verify.py rejects only the hypothesis whose required attacker role is absent.
    # Credentials are published only after WP-CLI has reconciled and authenticated
    # them; the configured administrator remains mandatory for trusted controls.
    BASELINE_USERS: list[tuple[str, str]] = [
        ("subscriber_user", "subscriber"),
        ("customer_user", "customer"),
        ("contributor_user", "contributor"),
        ("author_user", "author"),
        ("editor_user", "editor"),
    ]

    async def setup_test_users(self) -> None:
        self._baseline_accounts = None
        if self.wp_cli is None:
            raise RuntimeError("cannot provision sandbox users before WP-CLI is ready")
        if self._pre_plugin_role_capabilities is None:
            raise RuntimeError(
                "cannot provision sandbox users before the pre-plugin role ceiling "
                "has been captured"
            )

        core_capability_universe = frozenset().union(
            *self._pre_plugin_role_capabilities.values()
        )

        def forbidden_core_capabilities(role: str) -> list[str]:
            baseline_role = "subscriber" if role == "customer" else role
            allowed = self._pre_plugin_role_capabilities.get(
                baseline_role,
                frozenset(),
            )
            return sorted(core_capability_universe - allowed)

        expected_accounts = [
            {
                "login": self.config.wp_admin_user,
                "password": self.config.wp_admin_pass,
                "role": "administrator",
                "email": self.config.wp_admin_email,
                "forbidden_core_caps": forbidden_core_capabilities("administrator"),
                "required": True,
            },
            *[
                {
                    "login": login,
                    "password": self._baseline_passwords[login],
                    "role": role,
                    "email": f"{login}@test.local",
                    "forbidden_core_caps": forbidden_core_capabilities(role),
                    "required": False,
                }
                for login, role in self.BASELINE_USERS
            ],
        ]
        expected_logins = [str(account["login"]) for account in expected_accounts]
        if len({login.casefold() for login in expected_logins}) != len(expected_logins):
            raise RuntimeError(
                "sandbox baseline account logins must be case-insensitively unique"
            )

        reconciliation_spec = [
            {
                "login": str(account["login"]),
                "password": str(account["password"]),
                "role": str(account["role"]),
                "email": str(account["email"]),
                "forbidden_core_caps": list(account["forbidden_core_caps"]),
            }
            for account in expected_accounts
        ]
        try:
            state = await self.wp_cli.reconcile_users(reconciliation_spec)
        except Exception as exc:
            raise RuntimeError(
                "failed to reconcile sandbox baseline accounts: " + str(exc)[:300]
            ) from exc

        expected_roles = {str(account["role"]) for account in expected_accounts}
        roles = state.get("roles") if isinstance(state, dict) else None
        users = state.get("users") if isinstance(state, dict) else None
        if (
            not isinstance(roles, dict)
            or set(roles) != expected_roles
            or not all(isinstance(available, bool) for available in roles.values())
            or not isinstance(users, dict)
            or set(users) != set(expected_logins)
        ):
            raise RuntimeError(
                "sandbox baseline account inspection returned an invalid shape"
            )

        verified_accounts: list[dict] = []
        for expected in expected_accounts:
            login = str(expected["login"])
            role = str(expected["role"])
            required = expected["required"] is True
            inspected = users[login]
            reason = ""
            if roles[role] is not True:
                reason = "role is not registered"
            elif inspected is None:
                reason = "user is missing"
            elif not isinstance(inspected, dict):
                reason = "user inspection has an invalid shape"
            else:
                user_id = inspected.get("id")
                actual_login = inspected.get("login")
                actual_roles = inspected.get("roles")
                authenticated = inspected.get("authenticated")
                caps = inspected.get("caps")
                allcaps = inspected.get("allcaps")
                privileged_caps = inspected.get("privileged_caps")
                unexpected_core_caps = inspected.get("unexpected_effective_core_caps")
                unexpected_caps = inspected.get("unexpected_individual_caps")
                network_super_admin = inspected.get("network_super_admin")
                authority_exceeds = inspected.get("authority_exceeds_baseline")
                if (
                    isinstance(user_id, bool)
                    or not isinstance(user_id, int)
                    or user_id <= 0
                ):
                    reason = "user ID is not a positive integer"
                elif actual_login != login:
                    reason = f"inspected login is {actual_login!r}"
                elif actual_roles != [role]:
                    reason = f"inspected roles are {actual_roles!r}"
                elif authenticated is not True:
                    reason = "reconciled credentials did not authenticate"
                elif (
                    not isinstance(caps, dict)
                    or not all(
                        isinstance(capability, str) and isinstance(granted, bool)
                        for capability, granted in caps.items()
                    )
                    or not isinstance(allcaps, list)
                    or not all(isinstance(capability, str) for capability in allcaps)
                    or not isinstance(privileged_caps, list)
                    or not all(
                        isinstance(capability, str) for capability in privileged_caps
                    )
                    or not isinstance(unexpected_core_caps, list)
                    or not all(
                        isinstance(capability, str)
                        for capability in unexpected_core_caps
                    )
                    or not isinstance(unexpected_caps, list)
                    or not all(
                        isinstance(capability, str) for capability in unexpected_caps
                    )
                    or not isinstance(network_super_admin, bool)
                    or not isinstance(authority_exceeds, bool)
                ):
                    reason = "authority inspection has an invalid shape"
                elif authority_exceeds is not bool(
                    unexpected_core_caps
                    or network_super_admin
                    or (
                        role != "administrator" and (unexpected_caps or privileged_caps)
                    )
                ):
                    reason = "authority inspection is internally inconsistent"
                elif authority_exceeds:
                    excess = {
                        *unexpected_core_caps,
                        *(["network_super_admin"] if network_super_admin else []),
                    }
                    if role != "administrator":
                        excess.update(privileged_caps)
                        excess.update(unexpected_caps)
                    reason = (
                        "effective authority exceeds the intended role baseline"
                        + (f": {', '.join(sorted(excess))}" if excess else "")
                    )
                else:
                    verified_accounts.append(
                        {
                            "id": user_id,
                            "login": actual_login,
                            "password": expected["password"],
                            "role": actual_roles[0],
                        }
                    )
                    continue

            description = f"{login}/{role}: {reason}"
            if required:
                raise RuntimeError(
                    "required sandbox baseline account failed inspection: "
                    + description
                )
            logger.info("omitting optional sandbox baseline account %s", description)

        # Publish atomically only after every required identity has passed.
        self._baseline_accounts = verified_accounts

    def baseline_user_accounts(self) -> list[dict]:
        """Return the inspected credential table provisioned for this sandbox.

        Used by verify.py to surface a structured `user_accounts` block to the
        PoC author so it picks credentials from a known table instead of
        recalling them from the system prompt (which can drift).
        """
        if self._baseline_accounts is None:
            raise RuntimeError(
                "sandbox baseline accounts are unavailable until setup_test_users "
                "completes successfully"
            )
        return [dict(account) for account in self._baseline_accounts]

    def baseline_admin_user_id(self) -> int:
        """Return the stable numeric identity used for trusted WP-CLI controls."""
        administrators = [
            account
            for account in self.baseline_user_accounts()
            if normalize_attacker_role(account.get("role")) == "administrator"
        ]
        if len(administrators) != 1:
            raise RuntimeError(
                "verified sandbox manifest does not contain exactly one administrator"
            )
        return int(administrators[0]["id"])

    async def capture_setup_security_state(self, plugin_slug: str) -> dict:
        """Capture managed identities, elevated users, and active plugin state.

        Generated setup is intentionally allowed to create ordinary plugin objects,
        options, and pages. It must not, however, change the authority of the
        verifier's provisioned administrator/attacker/control accounts, create a new
        elevated identity, or alter which plugins are active. The verify stage
        compares this compact snapshot around every setup command so indirect
        PHP/SQL forms cannot bypass the lexical preflight.
        """
        assert self.wp_cli is not None
        slug = validate_plugin_slug(plugin_slug)
        protected_accounts = {
            str(account["login"]): int(account["id"])
            for account in self.baseline_user_accounts()
        }
        encoded_accounts = base64.b64encode(
            json.dumps(protected_accounts, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")
        elevated_php = ", ".join(
            json.dumps(capability) for capability in WPCli.ELEVATED_CAPABILITIES
        )
        php = (
            f"$expected = json_decode(base64_decode('{encoded_accounts}'), true); "
            f"$privileged_caps = [{elevated_php}]; "
            "$users = []; foreach ((array) $expected as $login => $expected_id) { "
            "$user = get_user_by('login', $login); "
            "if (!$user) { $users[$login] = null; continue; } "
            "$roles = array_values((array) $user->roles); sort($roles); "
            "$caps = []; foreach ((array) $user->caps as $cap => $granted) { "
            "$caps[(string) $cap] = (bool) $granted; } ksort($caps); "
            "$allcaps = array_keys(array_filter((array) $user->allcaps)); "
            "sort($allcaps); $granted_privileged = []; "
            "foreach ($privileged_caps as $cap) { "
            "if ($user->has_cap($cap)) { $granted_privileged[] = $cap; } } "
            "sort($granted_privileged); $credential_state = ["
            "'password_hash' => (string) $user->user_pass, "
            "'activation_key' => (string) $user->user_activation_key, "
            "'application_passwords' => get_user_meta($user->ID, "
            "'_application_passwords', true), "
            "'session_tokens' => get_user_meta($user->ID, 'session_tokens', true)]; "
            "$credential_fingerprint = hash_hmac('sha256', "
            "serialize($credential_state), wp_salt('auth')); "
            "$users[$login] = ['id' => (int) $user->ID, "
            "'login' => (string) $user->user_login, 'roles' => $roles, "
            "'caps' => $caps, 'allcaps' => $allcaps, "
            "'privileged_caps' => $granted_privileged, "
            "'network_super_admin' => is_multisite() && is_super_admin($user->ID), "
            "'credential_fingerprint' => $credential_fingerprint]; } "
            "$privileged = []; foreach (get_users(['fields' => 'all']) as $candidate) { "
            "$granted = []; foreach ($privileged_caps as $cap) { "
            "if ($candidate->has_cap($cap)) { $granted[] = $cap; } } "
            "$roles = array_values((array) $candidate->roles); sort($roles); "
            "$super_admin = is_super_admin($candidate->ID); "
            "if ($super_admin || in_array('administrator', $roles, true) || $granted) { "
            "sort($granted); $privileged[$candidate->user_login] = ["
            "'id' => (int) $candidate->ID, 'roles' => $roles, 'caps' => $granted, "
            "'super_admin' => $super_admin]; } } ksort($privileged); "
            "$active = array_values((array) get_option('active_plugins', [])); "
            "sort($active); $network = array_keys((array) "
            "get_site_option('active_sitewide_plugins', [])); sort($network); "
            "echo 'SQUADRONE_SETUP_SECURITY_STATE=' . wp_json_encode(["
            "'users' => $users, 'active_plugins' => $active, "
            "'active_sitewide_plugins' => $network, "
            "'privileged_users' => $privileged]);"
        )
        rc, out, err = await self.wp_cli._exec_result(
            "eval",
            php,
            user=WORDPRESS_WEB_USER,
            wp_user=str(self.baseline_admin_user_id()),
        )
        if rc != 0:
            raise RuntimeError(
                "managed setup-state query failed: " + (err or out).strip()[:300]
            )
        prefix = "SQUADRONE_SETUP_SECURITY_STATE="
        payload_line = next(
            (line for line in reversed(out.splitlines()) if line.startswith(prefix)),
            "",
        )
        if not payload_line:
            raise RuntimeError("managed setup-state query returned no structured state")
        try:
            state = json.loads(payload_line.removeprefix(prefix))
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "managed setup-state query returned invalid JSON"
            ) from exc
        if (
            not isinstance(state, dict)
            or not isinstance(state.get("users"), dict)
            or not isinstance(state.get("privileged_users"), dict)
            or set(state["users"]) != set(protected_accounts)
        ):
            raise RuntimeError("managed setup-state query returned an invalid shape")

        for login, expected_id in protected_accounts.items():
            user = state["users"].get(login)
            if (
                not isinstance(user, dict)
                or user.get("id") != expected_id
                or user.get("login") != login
                or not isinstance(user.get("roles"), list)
                or not all(isinstance(role, str) for role in user["roles"])
                or not isinstance(user.get("caps"), dict)
                or not all(
                    isinstance(capability, str) and isinstance(granted, bool)
                    for capability, granted in user["caps"].items()
                )
                or not isinstance(user.get("allcaps"), list)
                or not all(
                    isinstance(capability, str) for capability in user["allcaps"]
                )
                or not isinstance(user.get("privileged_caps"), list)
                or not all(
                    isinstance(capability, str)
                    for capability in user["privileged_caps"]
                )
                or not isinstance(user.get("network_super_admin"), bool)
                or not isinstance(user.get("credential_fingerprint"), str)
                or _SHA256_RE.fullmatch(user["credential_fingerprint"]) is None
            ):
                raise RuntimeError(
                    "managed setup-state query returned invalid identity, "
                    f"credential, or authority evidence for {login!r}"
                )

        if any(
            not isinstance(user, dict)
            or isinstance(user.get("id"), bool)
            or not isinstance(user.get("id"), int)
            or user["id"] <= 0
            or not isinstance(user.get("roles"), list)
            or not all(isinstance(role, str) for role in user["roles"])
            or not isinstance(user.get("caps"), list)
            or not all(isinstance(capability, str) for capability in user["caps"])
            or not isinstance(user.get("super_admin"), bool)
            for user in state["privileged_users"].values()
        ):
            raise RuntimeError(
                "managed setup-state query returned invalid elevated-user evidence"
            )

        for key in ("active_plugins", "active_sitewide_plugins"):
            paths = state.get(key)
            if not isinstance(paths, list):
                raise RuntimeError(
                    "managed setup-state query returned an invalid shape"
                )
            state[key] = sorted({str(path) for path in paths})

        active_paths = {
            str(path)
            for key in ("active_plugins", "active_sitewide_plugins")
            for path in (state.get(key) or [])
        }
        state["target_plugin_active"] = any(
            path == f"{slug}.php" or path.startswith(f"{slug}/")
            for path in active_paths
        )
        return state

    async def run_poc(
        self,
        script_path: str,
        *,
        expected_bug_class: str | None = None,
        expected_attacker_role: str | None = None,
        expected_http_transport: dict[str, object] | None = None,
    ) -> SandboxRunResult:
        async with self._ssrf_operation_lock:
            return await self._run_poc_locked(
                script_path,
                expected_bug_class=expected_bug_class,
                expected_attacker_role=expected_attacker_role,
                expected_http_transport=expected_http_transport,
            )

    async def _run_poc_locked(
        self,
        script_path: str,
        *,
        expected_bug_class: str | None = None,
        expected_attacker_role: str | None = None,
        expected_http_transport: dict[str, object] | None = None,
    ) -> SandboxRunResult:
        start = time.time()
        trace_records: list[dict] = []
        trace_error = ""
        rejection_counts: dict[str, int] = {}
        ssrf_expected = _is_ssrf_bug_class(expected_bug_class)
        strict_isolation = _requires_trusted_http_isolation(expected_bug_class)
        isolation_capability = (
            CROSS_OBJECT_HTTP_CAPABILITY if strict_isolation else "compatibility"
        )
        proc: asyncio.subprocess.Process | None = None
        stdout = b""
        stderr = b""
        timed_out = False
        trace_salt = b""
        oracle_service: SsrfOracleServer | None = None
        local_oracle: LocalResourceSsrfOracle | None = None
        oracle_mode = ""
        oracle_snapshot: object = None
        oracle_generation_id = ""
        oracle_marker = ""
        oracle_attack_url = ""
        oracle_control_url = ""
        oracle_error = ""
        local_before_sha256 = ""
        local_before_monotonic_ns = 0
        execution_started_monotonic_ns = 0
        execution_finished_monotonic_ns = 0
        credential_free_direct = False
        tracked_capabilities: dict[str, str] = {}
        execution_error: Exception | None = None

        async def execute_child(
            command: tuple[str, ...],
            *,
            cwd: Path | None,
            environment: dict[str, str],
        ) -> tuple[bytes, bytes]:
            nonlocal proc
            proc = await asyncio.create_subprocess_exec(
                *command,
                cwd=os.fspath(cwd) if cwd is not None else None,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=environment,
                start_new_session=True,
            )
            try:
                return await asyncio.wait_for(
                    _communicate_poc_bounded(proc),
                    timeout=self.poc_timeout_s,
                )
            finally:
                await _kill_poc_process_group(proc)

        if ssrf_expected:
            oracle_service = self._ssrf_oracle
            local_oracle = self._ssrf_local_oracle
            if (oracle_service is None) == (local_oracle is None):
                return SandboxRunResult(
                    success=False,
                    output="",
                    elapsed=time.time() - start,
                    error_log="PoC exec failed: SSRF oracle is not prepared",
                    validation_reason="SSRF oracle is not prepared",
                    evidence={
                        "http_trace_records": 0,
                        "http_trace_error": None,
                        "http_trace_rejections": {},
                        "ssrf_oracle_error": "unprepared",
                        "poc_isolation": isolation_capability,
                    },
                )
            try:
                if oracle_service is not None:
                    oracle_mode = "http"
                    if not oracle_service.is_running:
                        raise RuntimeError("HTTP SSRF oracle is stopped")
                    previous_generation = oracle_service.generation_id
                    previous_marker = oracle_service.private_marker
                    oracle_attack_url = oracle_service.attack_url
                    oracle_control_url = oracle_service.control_url
                    oracle_generation_id = await oracle_service.begin_generation()
                    oracle_marker = oracle_service.private_marker
                    if (
                        self._ssrf_oracle is not oracle_service
                        or not oracle_service.is_running
                        or re.fullmatch(r"[0-9a-f]{64}", oracle_generation_id) is None
                        or not hmac.compare_digest(
                            oracle_generation_id, oracle_service.generation_id
                        )
                        or hmac.compare_digest(
                            oracle_generation_id,
                            previous_generation,
                        )
                        or re.fullmatch(r"SQUADRONE_SSRF_[0-9a-f]{64}", oracle_marker)
                        is None
                        or hmac.compare_digest(oracle_marker, previous_marker)
                        or oracle_service.attack_url != oracle_attack_url
                        or oracle_service.control_url != oracle_control_url
                        or not _valid_ssrf_oracle_url(oracle_attack_url)
                        or not _valid_ssrf_oracle_url(oracle_control_url)
                        or oracle_attack_url == oracle_control_url
                    ):
                        raise RuntimeError("invalid HTTP SSRF oracle generation")
                else:
                    if (
                        local_oracle is None
                        or self._ssrf_local_oracle is not local_oracle
                        or self._ssrf_local_host_dir is None
                    ):
                        raise RuntimeError("local-resource SSRF oracle was replaced")
                    oracle_mode = LOCAL_RESOURCE_SSRF_MODE
                    oracle_attack_url = local_oracle.attack_url
                    oracle_control_url = local_oracle.control_url
                    oracle_generation_id = local_oracle.begin_generation()
                    oracle_marker = local_oracle.private_marker
                    provisioning_started = time.monotonic_ns()
                    _provision_ssrf_local_resource(
                        self._ssrf_local_host_dir,
                        local_oracle,
                    )
                    measured = await _inspect_ssrf_local_resource(
                        self.container_name,
                        local_oracle.resource_path,
                    )
                    provisioning_finished = time.monotonic_ns()
                    local_oracle.attest_provisioning(
                        generation_id=oracle_generation_id,
                        resource_path=cast(str, measured["resource_path"]),
                        content_sha256=cast(str, measured["content_sha256"]),
                        content_size_bytes=cast(
                            int,
                            measured["content_size_bytes"],
                        ),
                        owner_uid=cast(int, measured["owner_uid"]),
                        owner_gid=cast(int, measured["owner_gid"]),
                        file_mode=cast(int, measured["file_mode"]),
                        link_count=cast(int, measured["link_count"]),
                        is_regular_file=cast(
                            bool,
                            measured["is_regular_file"],
                        ),
                        is_symlink=cast(bool, measured["is_symlink"]),
                        started_monotonic_ns=provisioning_started,
                        finished_monotonic_ns=provisioning_finished,
                    )
                    local_before_sha256 = cast(str, measured["content_sha256"])
                    local_before_monotonic_ns = provisioning_finished
                    credential_free_direct = _allows_credential_free_direct_ssrf(
                        expected_http_transport,
                        expected_attacker_role,
                    )
                    tracked_capabilities = {
                        "local_resource_path": PurePosixPath(
                            local_oracle.resource_path
                        ).name,
                    }
                    if (
                        local_oracle.public_context().get("mode") != oracle_mode
                        or re.fullmatch(r"[0-9a-f]{64}", oracle_generation_id) is None
                        or re.fullmatch(r"SQUADRONE_SSRF_[0-9a-f]{64}", oracle_marker)
                        is None
                    ):
                        raise RuntimeError(
                            "invalid local-resource SSRF oracle generation"
                        )
            except Exception:
                return SandboxRunResult(
                    success=False,
                    output="",
                    elapsed=time.time() - start,
                    error_log="PoC exec failed: SSRF oracle generation failed",
                    validation_reason="SSRF oracle generation failed",
                    evidence={
                        "http_trace_records": 0,
                        "http_trace_error": None,
                        "http_trace_rejections": {},
                        "ssrf_oracle_error": "generation_failed",
                        "poc_isolation": isolation_capability,
                    },
                )

        try:
            if strict_isolation:
                if credential_free_direct:
                    proxy = PocProxySupervisor(
                        self.target_url,
                        trace_token=self._trace_token,
                        tracked_capabilities=tracked_capabilities,
                        credential_free=True,
                    )
                elif tracked_capabilities:
                    proxy = PocProxySupervisor(
                        self.target_url,
                        trace_token=self._trace_token,
                        tracked_capabilities=tracked_capabilities,
                    )
                else:
                    proxy = PocProxySupervisor(
                        self.target_url,
                        trace_token=self._trace_token,
                    )
                async with proxy:
                    try:
                        proxy_port = urlsplit(proxy.proxy_url).port
                        if proxy_port is None:
                            raise RuntimeError("PoC proxy did not expose a valid port")
                        with prepare_poc_isolation(
                            script_path,
                            proxy_port=proxy_port,
                            protected_paths=_poc_protected_paths(self.workdir),
                            capability=CROSS_OBJECT_HTTP_CAPABILITY,
                        ) as isolation:
                            execution_started_monotonic_ns = time.monotonic_ns()
                            try:
                                stdout, stderr = await execute_child(
                                    isolation.python_command(
                                        isolation.runner_path,
                                        isolation.script_path,
                                    ),
                                    cwd=isolation.cwd,
                                    environment=isolation.child_environment(
                                        proxy.proxy_url
                                    ),
                                )
                            finally:
                                execution_finished_monotonic_ns = time.monotonic_ns()
                    except TimeoutError:
                        timed_out = True
                trace_records = proxy.records
                trace_salt = proxy.trace_salt
                trace_error = proxy.fatal_error or ""
                rejection_counts = proxy.rejection_counts
            else:
                try:
                    stdout, stderr = await execute_child(
                        (sys.executable, script_path),
                        cwd=None,
                        environment=_compatibility_poc_environment(),
                    )
                except TimeoutError:
                    timed_out = True
        except Exception as e:
            execution_error = e

        if ssrf_expected:
            try:
                if oracle_mode == "http":
                    if (
                        self._ssrf_oracle is not oracle_service
                        or oracle_service is None
                    ):
                        raise RuntimeError("HTTP SSRF oracle was replaced")
                    if not oracle_service.is_running:
                        raise RuntimeError("HTTP SSRF oracle stopped")
                    oracle_snapshot = await oracle_service.snapshot()
                elif oracle_mode == LOCAL_RESOURCE_SSRF_MODE:
                    if (
                        self._ssrf_local_oracle is not local_oracle
                        or local_oracle is None
                        or execution_started_monotonic_ns < 1
                        or execution_finished_monotonic_ns
                        < execution_started_monotonic_ns
                    ):
                        raise RuntimeError("local-resource SSRF oracle was replaced")
                    measured_after = await _inspect_ssrf_local_resource(
                        self.container_name,
                        local_oracle.resource_path,
                    )
                    after_monotonic_ns = time.monotonic_ns()
                    oracle_snapshot = local_oracle.attest_verification(
                        generation_id=oracle_generation_id,
                        resource_path=cast(str, measured_after["resource_path"]),
                        before_sha256=local_before_sha256,
                        before_monotonic_ns=local_before_monotonic_ns,
                        execution_started_monotonic_ns=(execution_started_monotonic_ns),
                        execution_finished_monotonic_ns=(
                            execution_finished_monotonic_ns
                        ),
                        after_sha256=cast(
                            str,
                            measured_after["content_sha256"],
                        ),
                        after_monotonic_ns=after_monotonic_ns,
                    )
                else:
                    raise RuntimeError("SSRF oracle mode is missing")
            except Exception:
                oracle_error = "snapshot_failed"

        if execution_error is not None:
            return SandboxRunResult(
                success=False,
                output="",
                elapsed=time.time() - start,
                error_log=f"PoC exec failed: {execution_error}",
                validation_reason="PoC execution failed",
                evidence={
                    "http_trace_records": len(trace_records),
                    "http_trace_error": trace_error or None,
                    "http_trace_rejections": rejection_counts,
                    "ssrf_oracle_error": oracle_error or None,
                    "poc_isolation": isolation_capability,
                },
            )
        if timed_out:
            return SandboxRunResult(
                success=False,
                output="",
                elapsed=time.time() - start,
                error_log=f"PoC timed out after {self.poc_timeout_s}s",
                validation_reason="PoC execution timed out",
                evidence={
                    "http_trace_records": len(trace_records),
                    "http_trace_error": trace_error or None,
                    "http_trace_rejections": rejection_counts,
                    "ssrf_oracle_error": oracle_error or None,
                    "poc_isolation": isolation_capability,
                },
            )

        elapsed = time.time() - start
        out = stdout.decode("utf-8", errors="replace")
        err = stderr.decode("utf-8", errors="replace")
        observation, parse_reason = _parse_poc_observation(out)
        trace_evidence: dict = {}
        if proc is None:
            success = False
            validation_reason = "PoC process did not start"
        elif trace_error:
            success = False
            validation_reason = f"PoC HTTP supervision failed: {trace_error}"
        elif ssrf_expected and oracle_error:
            success = False
            validation_reason = f"SSRF oracle snapshot failed: {oracle_error}"
        elif proc.returncode != 0:
            success = False
            validation_reason = f"PoC process exited {proc.returncode}"
        elif observation is None:
            success = False
            validation_reason = parse_reason
        else:
            success, validation_reason = validate_poc_observation(
                observation,
                expected_bug_class=expected_bug_class,
                expected_attacker_role=expected_attacker_role,
            )
            if success and ssrf_expected and observation.oracle != "response_marker":
                success = False
                validation_reason = (
                    "SSRF automatic verification requires the trusted "
                    "response_marker boundary"
                )
            if success and ssrf_expected and observation.oracle == "response_marker":
                if not strict_isolation:
                    success = False
                    validation_reason = (
                        "SSRF response-marker proof requires the strict parent-proxy "
                        "isolation boundary"
                    )
                else:
                    success, validation_reason, trace_evidence = (
                        validate_ssrf_response_marker_http_trace(
                            observation,
                            trace_records,
                            trace_salt=trace_salt,
                            target_url=self.target_url,
                            receipt_secret=self._receipt_secret,
                            trace_token=self._trace_token,
                            oracle_attack_url=oracle_attack_url,
                            oracle_control_url=oracle_control_url,
                            oracle_marker=oracle_marker,
                            oracle_snapshot=oracle_snapshot,
                            oracle_generation_id=oracle_generation_id,
                            expected_http_transport=expected_http_transport,
                            trace_error=trace_error,
                            oracle_mode=cast(
                                Literal["http", "local_resource"],
                                oracle_mode,
                            ),
                        )
                    )
            if success and observation.oracle == "cross_object_access":
                if not strict_isolation:
                    success = False
                    validation_reason = (
                        "cross-object proof requires the strict parent-proxy "
                        "isolation boundary"
                    )
                else:
                    success, validation_reason, trace_evidence = (
                        validate_cross_object_http_trace(
                            observation,
                            trace_records,
                            trace_salt=trace_salt,
                            target_url=self.target_url,
                            receipt_secret=self._receipt_secret,
                            trace_token=self._trace_token,
                            trace_error=trace_error,
                        )
                    )

        http_status = None
        m = re.search(r"\bstatus[=:]\s*(\d{3})\b", out, re.IGNORECASE)
        if m:
            http_status = int(m.group(1))

        wp_error_log = ""
        if self.wp_cli is not None:
            try:
                wp_error_log = await self.wp_cli.get_error_log()
            except Exception:
                pass

        error_log = err
        if wp_error_log:
            error_log = (error_log + "\n--- wp debug.log ---\n" + wp_error_log).strip()

        return SandboxRunResult(
            success=success,
            output=out,
            elapsed=elapsed,
            http_status=http_status,
            response=out[-2000:] if out else None,
            error_log=error_log or None,
            observation=observation,
            validation_reason=validation_reason,
            evidence={
                "observation": observation.model_dump(mode="json")
                if observation
                else None,
                "validation_reason": validation_reason,
                "stdout_tail": out[-500:],
                "returncode": proc.returncode if proc is not None else None,
                "http_trace_records": len(trace_records),
                "http_trace_error": trace_error or None,
                "http_trace_rejections": rejection_counts,
                "http_trace_binding": trace_evidence or None,
                "ssrf_oracle_error": oracle_error or None,
                "poc_isolation": isolation_capability,
            },
        )
