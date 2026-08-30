"""Parent-owned HTTP trace proxy for generated proof-of-concept scripts.

The proxy is the trust boundary for PoC HTTP evidence. A child process only
receives the loopback proxy URL; the trace salt and sandbox trace token remain
in the parent process. Requests are parsed and observed before forwarding, and
upstream responses are recorded before bytes are returned to model-authored
code.

Only request parameter names, shapes, and salted value digests are retained.
Cookies, authorization values, injected trace credentials, and raw request
parameter values are never included in a record.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import copy
import hashlib
import html
import json
import math
import os
import re
import secrets
import time
from collections import Counter
from collections.abc import Iterable, Mapping, MutableMapping
from email import policy
from email.parser import BytesParser
from http import HTTPStatus
from typing import Any
from urllib.parse import parse_qsl, unquote_to_bytes, urlsplit

import httpx


TRACE_TOKEN_HEADER = "X-Squadrone-Trace-Token"
REQUEST_NONCE_HEADER = "X-Squadrone-Request-Nonce"
REQUEST_DIGEST_HEADER = "X-Squadrone-Request-Digest"
ACTOR_RECEIPT_HEADER = "X-Squadrone-Actor-Receipt"
TRACE_VERSION = 1

POC_PROXY_ENV = "SQUADRONE_HTTP_PROXY"

# Names used by the old in-child recorder. They remain available so callers
# can explicitly scrub stale environments during a rolling upgrade.
TRACE_FD_ENV = "SQUADRONE_HTTP_TRACE_FD"
TRACE_SALT_ENV = "SQUADRONE_HTTP_TRACE_SALT"
TRACE_TOKEN_ENV = "SQUADRONE_HTTP_TRACE_TOKEN"
TRACE_ORIGIN_ENV = "SQUADRONE_HTTP_TRACE_ORIGIN"
PRIVATE_TRACE_ENV_NAMES = frozenset(
    {TRACE_FD_ENV, TRACE_SALT_ENV, TRACE_TOKEN_ENV, TRACE_ORIGIN_ENV}
)

# The complete response is hashed, while only this much of its head/tail is
# retained. The absolute limits bound parent memory on untrusted input.
RESPONSE_BODY_CAPTURE_LIMIT = 512 * 1024
ACTOR_RECEIPT_LIMIT = 8192
MAX_REQUEST_HEADER_BYTES = 64 * 1024
MAX_REQUEST_BODY_BYTES = 16 * 1024 * 1024
MAX_RESPONSE_BODY_BYTES = 64 * 1024 * 1024
MAX_TRACE_RECORDS = 10_000
MAX_TRACE_CAPTURE_BYTES = 64 * 1024 * 1024
MAX_TRACE_METADATA_BYTES = 64 * 1024 * 1024
MAX_TRACE_FIELDS = 2_048
MAX_TRACE_FIELD_NAME_BYTES = 1_024
MAX_TRACE_FIELD_NAMES_BYTES = 64 * 1024
MAX_REQUEST_TARGET_BYTES = 8_192
MAX_REQUEST_METHOD_BYTES = 32
MAX_CONCURRENT_HANDLERS = 4
REQUEST_READ_TIMEOUT = 10.0
_READ_CHUNK_BYTES = 64 * 1024

_SQUADRONE_SENTINEL = b"SQUADRONE_"
_SENTINEL_FLAG_NAMES = (
    "target",
    "target_encoded",
    "body",
    "body_encoded",
    "headers",
    "headers_encoded",
)
_BASE64_CANDIDATE_RE = re.compile(
    rb"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{12,}={0,2}(?![A-Za-z0-9+/_-])"
)
_HEX_CANDIDATE_RE = re.compile(rb"(?<![0-9A-Fa-f])[0-9A-Fa-f]{20,}(?![0-9A-Fa-f])")
_BACKSLASH_ESCAPE_RE = re.compile(rb"\\(?:u([0-9A-Fa-f]{4})|x([0-9A-Fa-f]{2}))")
_ROUTING_OVERRIDE_HEADERS = frozenset(
    {
        "forwarded",
        "x-envoy-original-path",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-method",
        "x-forwarded-port",
        "x-forwarded-prefix",
        "x-forwarded-proto",
        "x-http-method",
        "x-http-method-override",
        "x-method-override",
        "x-original-host",
        "x-original-method",
        "x-original-uri",
        "x-original-url",
        "x-real-ip",
        "x-rewrite-url",
        "x-script-name",
    }
)
_CREDENTIAL_FREE_RAW_HEADERS = frozenset(
    {
        "accept",
        "accept-encoding",
        "connection",
        "content-length",
        "content-type",
        "host",
        "proxy-connection",
        "user-agent",
    }
)
_CREDENTIAL_FREE_CONTENT_TYPE = "application/x-www-form-urlencoded"
_TRACKED_CAPABILITY_LABEL_RE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")

_TOKEN_RE = re.compile(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")
_HOP_BY_HOP_HEADERS = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)
_PROXY_ENV_NAMES = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
)
_MINIMAL_ENV_NAMES = frozenset(
    {
        "LANG",
        "LC_ALL",
        "PATH",
        "PYTHONHOME",
        "PYTHONPATH",
        "SSL_CERT_DIR",
        "SSL_CERT_FILE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "VIRTUAL_ENV",
    }
)


def _empty_sentinel_flags() -> dict[str, bool]:
    return {name: False for name in _SENTINEL_FLAG_NAMES}


def _contains_encoded_sentinel(data: bytes) -> bool:
    """Detect common reversible encodings without retaining decoded material."""
    current = data
    for _ in range(3):
        decoded = unquote_to_bytes(current)
        if decoded == current:
            break
        if _SQUADRONE_SENTINEL in decoded:
            return True
        current = decoded

    def replace_escape(match: re.Match[bytes]) -> bytes:
        encoded = match.group(1) or match.group(2)
        codepoint = int(encoded, 16)
        return chr(codepoint).encode("utf-8")

    if b"\\" in data:
        unescaped = _BACKSLASH_ESCAPE_RE.sub(replace_escape, data)
        if unescaped != data and _SQUADRONE_SENTINEL in unescaped:
            return True

    if b"&" in data:
        try:
            unescaped_html = html.unescape(data.decode("ascii")).encode("utf-8")
        except UnicodeError:
            pass
        else:
            if unescaped_html != data and _SQUADRONE_SENTINEL in unescaped_html:
                return True

    decoded_budget = MAX_REQUEST_BODY_BYTES
    candidate_count = 0
    for match in _BASE64_CANDIDATE_RE.finditer(data):
        candidate_count += 1
        if candidate_count > 4_096:
            break
        candidate = match.group(0)
        if len(candidate) > decoded_budget * 2:
            break
        padding = b"=" * (-len(candidate) % 4)
        try:
            decoded = base64.b64decode(
                candidate + padding,
                altchars=b"-_",
                validate=True,
            )
        except (binascii.Error, ValueError):
            continue
        decoded_budget -= len(decoded)
        if _SQUADRONE_SENTINEL in decoded:
            return True
        if decoded_budget <= 0:
            break

    decoded_budget = MAX_REQUEST_BODY_BYTES
    candidate_count = 0
    for match in _HEX_CANDIDATE_RE.finditer(data):
        candidate_count += 1
        if candidate_count > 4_096:
            break
        candidate = match.group(0)
        if len(candidate) % 2 or len(candidate) > decoded_budget * 2:
            continue
        try:
            decoded = bytes.fromhex(candidate.decode("ascii"))
        except ValueError:
            continue
        decoded_budget -= len(decoded)
        if _SQUADRONE_SENTINEL in decoded:
            return True
        if decoded_budget <= 0:
            break
    return False


def _text_contains_tracked_capability(value: str, capability: str) -> bool:
    """Detect one opaque capability in raw or repeatedly URL-decoded text."""
    current = value
    for _ in range(4):
        if capability in current:
            return True
        decoded = unquote_to_bytes(current).decode("utf-8", errors="replace")
        if decoded == current:
            return False
        current = decoded
    return capability in current


def classify_request_sentinels(
    raw_target: bytes,
    raw_headers: bytes,
    body: bytes,
) -> tuple[dict[str, bool], list[str]]:
    """Return fixed, value-free sentinel location flags and true categories."""
    material = {
        "target": raw_target,
        "body": body,
        "headers": raw_headers,
    }
    flags = _empty_sentinel_flags()
    for location, value in material.items():
        flags[location] = _SQUADRONE_SENTINEL in value
        flags[f"{location}_encoded"] = _contains_encoded_sentinel(value)
    categories = sorted(name for name, present in flags.items() if present)
    return flags, categories


def normalize_trace_scalar(value: object) -> str:
    """Return the stable text representation used for trace value digests."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite floats are not trace scalars")
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    raise TypeError(f"unsupported trace scalar type: {type(value).__name__}")


def salted_scalar_sha256(value: object, salt: bytes) -> str:
    """Hash one scalar according to the public trace protocol."""
    canonical = normalize_trace_scalar(value).encode("utf-8")
    return hashlib.sha256(salt + b"\0" + canonical).hexdigest()


def _forwarded_child_headers(
    headers: Iterable[tuple[str, str]],
) -> list[tuple[str, str]]:
    """Return exactly the child-controlled headers that reach WordPress."""
    materialized = list(headers)
    connection_tokens: set[str] = set()
    for name, value in materialized:
        if name.casefold() == "connection":
            connection_tokens.update(
                part.strip().casefold() for part in value.split(",")
            )
    blocked = (
        _HOP_BY_HOP_HEADERS
        | frozenset(token for token in connection_tokens if token)
        | {"host", "content-length", "accept-encoding"}
    )
    return [
        (name, value)
        for name, value in materialized
        if name.casefold() not in blocked
        and not name.casefold().startswith("x-squadrone-")
    ]


def _credential_free_headers(
    headers: Iterable[tuple[str, str]],
    body: bytes,
) -> list[tuple[str, str]] | None:
    """Return parent-owned minimal headers, or reject a credential-capable shape."""
    materialized = list(headers)
    normalized_names = [name.casefold().replace("_", "-") for name, _ in materialized]
    if any(
        name not in _CREDENTIAL_FREE_RAW_HEADERS for name in normalized_names
    ) or len(normalized_names) != len(set(normalized_names)):
        return None
    content_types = [
        value.strip().casefold()
        for name, value in materialized
        if name.casefold().replace("_", "-") == "content-type"
    ]
    if body:
        if content_types != [_CREDENTIAL_FREE_CONTENT_TYPE]:
            return None
    elif content_types:
        return None
    sanitized = [
        ("Accept", "*/*"),
        ("User-Agent", "Squadrone-Trusted-PoC/1"),
    ]
    if body:
        sanitized.append(("Content-Type", _CREDENTIAL_FREE_CONTENT_TYPE))
    return sanitized


def salted_headers_sha256(
    headers: Iterable[tuple[str, str]],
    salt: bytes,
) -> str:
    """Hash canonical child-controlled headers without retaining their values."""
    grouped: dict[str, list[str]] = {}
    for name, value in _forwarded_child_headers(headers):
        grouped.setdefault(name.casefold(), []).append(value)
    canonical = sorted(grouped.items())
    encoded = json.dumps(
        canonical,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(salt + b"\0SQUADRONE-HEADERS-V1\0" + encoded).hexdigest()


def canonical_request_digest(
    method: str,
    raw_path_and_query: str,
    body: bytes,
) -> str:
    """Hash the exact request binding echoed by the sandbox actor receipt.

    Canonical bytes are ``b"SQUADRONE-REQUEST-V1\\0" + METHOD_ASCII_UPPER +
    b"\\0" + origin-form-target + b"\\0" + body``. The target starts with
    ``/`` and includes the exact raw query when present. The result is lowercase
    hexadecimal SHA-256.
    """
    normalized_method = method.upper().encode("ascii", errors="strict")
    raw_target = raw_path_and_query.encode("ascii", errors="strict")
    if not raw_path_and_query.startswith("/"):
        raise ValueError("canonical request target must use origin form")
    return hashlib.sha256(
        b"SQUADRONE-REQUEST-V1\0"
        + normalized_method
        + b"\0"
        + raw_target
        + b"\0"
        + body
    ).hexdigest()


def normalize_trace_origin(url: str) -> str:
    """Return a scheme/host/effective-port origin suitable for exact matching."""
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.casefold()
        host = (parsed.hostname or "").casefold()
        port = parsed.port
    except (TypeError, ValueError):
        return ""
    if not scheme or not host:
        return ""
    if port is None:
        if scheme == "http":
            port = 80
        elif scheme == "https":
            port = 443
        else:
            return ""
    rendered_host = f"[{host}]" if ":" in host else host
    return f"{scheme}://{rendered_host}:{port}"


def _body_bytes(body: object) -> bytes | None:
    if body is None:
        return b""
    if isinstance(body, bytes):
        return body
    if isinstance(body, bytearray):
        return bytes(body)
    if isinstance(body, memoryview):
        return body.tobytes()
    if isinstance(body, str):
        return body.encode("utf-8")
    return None


def _json_scalar_fields(value: object, name: str = "") -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for raw_key, child in value.items():
            key = str(raw_key)
            child_name = f"{name}.{key}" if name else key
            yield from _json_scalar_fields(child, child_name)
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            if isinstance(child, (dict, list)):
                child_name = f"{name}[{index}]" if name else f"[{index}]"
                yield from _json_scalar_fields(child, child_name)
            else:
                yield name or "$", child
        return
    yield name or "$", value


def _multipart_fields(
    content_type: str,
    body: bytes,
) -> Iterable[tuple[str, object, str]]:
    try:
        raw_prefix = (
            f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode(
                "ascii", errors="strict"
            )
        )
    except UnicodeEncodeError:
        return
    message = BytesParser(policy=policy.default).parsebytes(raw_prefix + body)
    if not message.is_multipart():
        return
    for part in message.iter_parts():
        name = part.get_param("name", header="content-disposition")
        if not isinstance(name, str) or not name:
            continue
        filename = part.get_filename()
        if filename is not None:
            # Hash the filename, but never retain it or the file contents.
            yield name, filename, "file"
            continue
        decoded_payload = part.get_payload(decode=True)
        if decoded_payload is None:
            payload = b""
        elif isinstance(decoded_payload, bytes):
            payload = decoded_payload
        else:
            payload = str(decoded_payload).encode("utf-8", errors="replace")
        charset = part.get_content_charset() or "utf-8"
        try:
            value = payload.decode(charset, errors="strict")
        except LookupError:
            value = payload.decode("utf-8", errors="strict")
        yield name, value, "scalar"


def trace_fields_from_wire(
    url: str,
    content_type: str,
    body: bytes,
    salt: bytes,
    *,
    tracked_capabilities: Mapping[str, str] | None = None,
) -> tuple[list[dict[str, object]], list[dict[str, object]], str | None]:
    """Extract value digests and a value-free shape from one wire request."""
    extracted: list[tuple[str, str, object, str]] = []
    parsed_url = urlsplit(url)
    parse_error: str | None = None
    try:
        query_pairs = parse_qsl(
            parsed_url.query,
            keep_blank_values=True,
            strict_parsing=False,
            encoding="utf-8",
            errors="strict",
            max_num_fields=10_000,
        )
        extracted.extend(
            ("query", name, value, "scalar") for name, value in query_pairs
        )
    except (UnicodeError, ValueError):
        parse_error = "malformed_query"

    media_type = content_type.partition(";")[0].strip().casefold()
    if body:
        try:
            if media_type == "application/x-www-form-urlencoded":
                pairs = parse_qsl(
                    body.decode("utf-8", errors="strict"),
                    keep_blank_values=True,
                    strict_parsing=False,
                    encoding="utf-8",
                    errors="strict",
                    max_num_fields=10_000,
                )
                extracted.extend(
                    ("form", name, value, "scalar") for name, value in pairs
                )
            elif media_type == "application/json" or media_type.endswith("+json"):
                decoded = json.loads(body.decode("utf-8"))
                extracted.extend(
                    ("json", name, value, "scalar")
                    for name, value in _json_scalar_fields(decoded)
                )
            elif media_type == "multipart/form-data":
                extracted.extend(
                    ("multipart", name, value, kind)
                    for name, value, kind in _multipart_fields(content_type, body)
                )
            else:
                parse_error = "unsupported_body_content_type"
        except (UnicodeError, ValueError, TypeError):
            parse_error = "malformed_request_body"

    fields: list[dict[str, object]] = []
    retained_name_bytes = 0
    for location, name, value, kind in extracted:
        encoded_name = name.encode("utf-8", errors="replace")
        if (
            len(fields) >= MAX_TRACE_FIELDS
            or len(encoded_name) > MAX_TRACE_FIELD_NAME_BYTES
            or retained_name_bytes + len(encoded_name) > MAX_TRACE_FIELD_NAMES_BYTES
        ):
            parse_error = "trace_field_limits_exceeded"
            continue
        try:
            canonical_value = normalize_trace_scalar(value)
            digest = hashlib.sha256(
                salt + b"\0" + canonical_value.encode("utf-8")
            ).hexdigest()
        except (TypeError, ValueError):
            parse_error = "malformed_request_body"
            continue
        field: dict[str, object] = {
            "location": location,
            "name": name,
            "kind": kind,
            "value_sha256": digest,
            "contains_squadrone_sentinel": (
                kind != "file" and "SQUADRONE_" in canonical_value
            ),
        }
        if tracked_capabilities:
            field["tracked_capabilities"] = sorted(
                label
                for label, capability in tracked_capabilities.items()
                if _text_contains_tracked_capability(name, capability)
                or (
                    kind != "file"
                    and _text_contains_tracked_capability(
                        canonical_value,
                        capability,
                    )
                )
            )
        fields.append(field)
        retained_name_bytes += len(encoded_name)
    fields.sort(
        key=lambda item: (
            item["location"],
            item["name"],
            item["kind"],
            item["value_sha256"],
        )
    )
    counts = Counter((item["location"], item["name"], item["kind"]) for item in fields)
    shape = [
        {
            "location": location,
            "name": name,
            "kind": kind,
            "count": count,
        }
        for (location, name, kind), count in sorted(counts.items())
    ]
    return fields, shape, parse_error


def request_trace_fields(
    request: object,
    salt: bytes,
) -> tuple[list[dict[str, object]], list[dict[str, object]], str | None]:
    """Compatibility helper for prepared ``requests`` or ``httpx`` requests."""
    url = str(getattr(request, "url", "") or "")
    headers = getattr(request, "headers", {})
    content_type = str(headers.get("Content-Type", "") or "")
    body_value = getattr(request, "body", None)
    if not hasattr(request, "body"):
        try:
            body_value = getattr(request, "content", b"")
        except httpx.RequestNotRead:
            body_value = None
    body = _body_bytes(body_value)
    if body is None:
        fields, shape, _ = trace_fields_from_wire(url, content_type, b"", salt)
        return fields, shape, "unsupported_streaming_body"
    return trace_fields_from_wire(url, content_type, body, salt)


def configure_proxy_environment(
    environment: MutableMapping[str, str],
    proxy_url: str,
) -> None:
    """Force proxy-aware HTTP clients through ``proxy_url`` in-place."""
    normalized = _validated_proxy_url(proxy_url)
    for name in PRIVATE_TRACE_ENV_NAMES:
        environment.pop(name, None)
    environment.pop("NO_PROXY", None)
    environment.pop("no_proxy", None)
    for name in _PROXY_ENV_NAMES:
        environment[name] = normalized


def build_poc_environment(
    proxy_url: str,
    base_environment: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return a copied child environment with only the proxy control value added."""
    environment = dict(os.environ if base_environment is None else base_environment)
    configure_proxy_environment(environment, proxy_url)
    environment[POC_PROXY_ENV] = _validated_proxy_url(proxy_url)
    return environment


def minimal_poc_environment(
    proxy_url: str,
    source_environment: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build a small child environment without unrelated parent credentials."""
    source = os.environ if source_environment is None else source_environment
    base = {name: source[name] for name in _MINIMAL_ENV_NAMES if name in source}
    return build_poc_environment(proxy_url, base)


def _validated_proxy_url(proxy_url: str) -> str:
    parsed = urlsplit(proxy_url)
    if (
        parsed.scheme.casefold() != "http"
        or parsed.hostname not in {"127.0.0.1", "::1", "localhost"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError("PoC proxy must be an HTTP loopback origin")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("PoC proxy has an invalid port") from exc
    if port is None or not (1 <= port <= 65535):
        raise ValueError("PoC proxy must include a valid port")
    hostname = str(parsed.hostname)
    host = f"[{hostname}]" if ":" in hostname else hostname
    return f"http://{host}:{port}"


class _ProxyRequestError(Exception):
    def __init__(self, status: int, detail: str, category: str = "invalid_request"):
        super().__init__(detail)
        self.status = status
        self.detail = detail
        self.category = category


class _UpstreamBodyTooLarge(Exception):
    pass


class _UnsupportedContentEncoding(Exception):
    pass


class PocProxySupervisor:
    """Async parent-owned, exact-origin HTTP forward proxy and trace recorder."""

    def __init__(
        self,
        target_url: str,
        *,
        trace_token: str,
        trace_salt: bytes | None = None,
        listen_host: str = "127.0.0.1",
        listen_port: int = 0,
        upstream_timeout: float = 30.0,
        max_trace_records: int = MAX_TRACE_RECORDS,
        max_trace_capture_bytes: int = MAX_TRACE_CAPTURE_BYTES,
        max_trace_metadata_bytes: int = MAX_TRACE_METADATA_BYTES,
        max_concurrent_handlers: int = MAX_CONCURRENT_HANDLERS,
        request_read_timeout: float = REQUEST_READ_TIMEOUT,
        tracked_capabilities: Mapping[str, str] | None = None,
        credential_free: bool = False,
    ) -> None:
        target_origin = normalize_trace_origin(target_url)
        if not target_origin or not target_origin.startswith("http://"):
            raise ValueError("PoC proxy target must have a valid HTTP origin")
        if not isinstance(trace_token, str) or not trace_token:
            raise ValueError("PoC proxy trace token must be non-empty")
        salt = secrets.token_bytes(32) if trace_salt is None else bytes(trace_salt)
        if len(salt) < 16:
            raise ValueError("PoC proxy trace salt must contain at least 16 bytes")
        if listen_host not in {"127.0.0.1", "::1", "localhost"}:
            raise ValueError("PoC proxy must listen on loopback")
        if upstream_timeout <= 0:
            raise ValueError("PoC proxy upstream timeout must be positive")
        if max_trace_records < 2:
            raise ValueError("PoC proxy must allow at least two trace records")
        if max_trace_capture_bytes < 0:
            raise ValueError("PoC proxy trace capture limit cannot be negative")
        if max_trace_metadata_bytes < 0:
            raise ValueError("PoC proxy trace metadata limit cannot be negative")
        if max_concurrent_handlers < 1:
            raise ValueError("PoC proxy handler limit must be positive")
        if request_read_timeout <= 0:
            raise ValueError("PoC proxy request read timeout must be positive")
        if not isinstance(credential_free, bool):
            raise ValueError("credential_free must be a boolean")
        capabilities = dict(tracked_capabilities or {})
        if (
            len(capabilities) > 8
            or any(
                not isinstance(label, str)
                or _TRACKED_CAPABILITY_LABEL_RE.fullmatch(label) is None
                or not isinstance(capability, str)
                or not 16 <= len(capability) <= 256
                or not capability.isascii()
                or not capability.isprintable()
                for label, capability in capabilities.items()
            )
            or len(set(capabilities.values())) != len(capabilities)
        ):
            raise ValueError("tracked capabilities are malformed or ambiguous")

        self.target_origin = target_origin
        self.trace_salt = salt
        self._trace_token = trace_token
        self._listen_host = listen_host
        self._listen_port = listen_port
        self._upstream_timeout = upstream_timeout
        self._max_trace_records = max_trace_records
        self._max_trace_capture_bytes = max_trace_capture_bytes
        self._max_trace_metadata_bytes = max_trace_metadata_bytes
        self._max_concurrent_handlers = max_concurrent_handlers
        self._request_read_timeout = request_read_timeout
        self._tracked_capabilities = capabilities
        self._credential_free = credential_free
        self._server: asyncio.AbstractServer | None = None
        self._proxy_url = ""
        self._records: list[dict[str, object]] = []
        self._next_sequence = 0
        self._trace_capture_bytes = 0
        self._trace_metadata_bytes = 0
        self._fatal_error: str | None = None
        self._fatal_sequence: int | None = None
        self._closing = False
        self._active_handlers = 0
        self._rejection_counts: dict[str, int] = {}
        self._forward_lock = asyncio.Lock()
        self._handler_tasks: set[asyncio.Task[None]] = set()
        self._writers: set[asyncio.StreamWriter] = set()

    @property
    def proxy_url(self) -> str:
        if not self._proxy_url:
            raise RuntimeError("PoC proxy is not running")
        return self._proxy_url

    @property
    def records(self) -> list[dict[str, object]]:
        """Return pending, completed, and failed records in execution order."""

        def sequence(record: dict[str, object]) -> int:
            value = record.get("sequence")
            return value if isinstance(value, int) else 0

        ordered = sorted(self._records, key=sequence)
        return copy.deepcopy(ordered)

    @property
    def trace_records(self) -> list[dict[str, object]]:
        """Alias used by sandbox integrations."""
        return self.records

    @property
    def fatal_error(self) -> str | None:
        """Return the latched reason that makes the complete trace unusable."""
        return self._fatal_error

    @property
    def rejection_counts(self) -> dict[str, int]:
        """Return stable, value-free categories for rejected request attempts."""
        return dict(self._rejection_counts)

    def child_environment(
        self,
        base_environment: Mapping[str, str] | None = None,
        *,
        minimal: bool = True,
    ) -> dict[str, str]:
        if minimal:
            return minimal_poc_environment(self.proxy_url, base_environment)
        return build_poc_environment(self.proxy_url, base_environment)

    async def start(self) -> PocProxySupervisor:
        if self._server is not None:
            raise RuntimeError("PoC proxy is already running")
        if self._fatal_error is not None:
            raise RuntimeError("a failed PoC proxy supervisor cannot be restarted")
        self._closing = False
        self._server = await asyncio.start_server(
            self._accept,
            self._listen_host,
            self._listen_port,
            limit=MAX_REQUEST_HEADER_BYTES + 4,
        )
        socket = self._server.sockets[0]
        host, port = socket.getsockname()[:2]
        rendered_host = f"[{host}]" if ":" in host else host
        self._proxy_url = f"http://{rendered_host}:{port}"
        return self

    async def close(self) -> None:
        self._closing = True
        server, self._server = self._server, None
        if server is not None:
            server.close()
        current = asyncio.current_task()
        pending = [task for task in self._handler_tasks if task is not current]
        # Closing is a cancellation barrier, not a queue drain. In particular,
        # requests waiting for the serialization lock must never run after the
        # child process has terminated.
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        self._handler_tasks.clear()
        if server is not None:
            await server.wait_closed()
        writers = tuple(self._writers)
        for writer in writers:
            writer.close()
        if writers:
            await asyncio.gather(
                *(writer.wait_closed() for writer in writers),
                return_exceptions=True,
            )
        self._proxy_url = ""

    async def __aenter__(self) -> PocProxySupervisor:
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
            if self._closing:
                self._record_rejection("proxy_closing")
                await self._send_error(writer, 503, "PoC proxy is closing")
                return
            if self._active_handlers >= self._max_concurrent_handlers:
                self._record_rejection("handler_limit_exceeded")
                await self._send_error(writer, 503, "PoC proxy is at capacity")
                return
            self._active_handlers += 1
            admitted = True
            await self._serve_one(reader, writer)
        except Exception:
            # This is the final request-processing safety boundary. Individual
            # parsing and forwarding paths use more specific categories, but an
            # unforeseen exception must still make the trace durably unusable.
            # Never retain the exception text: it may contain request material.
            self._record_rejection("unexpected_request_error")
            try:
                await self._send_error(writer, 502, "proxy request processing failed")
            except Exception:
                pass
        finally:
            if admitted:
                self._active_handlers -= 1
            self._writers.discard(writer)
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=0.25)
            except (ConnectionError, RuntimeError, TimeoutError):
                pass
            if task is not None:
                self._handler_tasks.discard(task)

    async def _serve_one(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        header_buffer = bytearray()
        body_buffer = bytearray()
        raw_head = b""
        try:
            async with asyncio.timeout(self._request_read_timeout):
                raw_head, body_prefix = await self._read_request_head(
                    reader,
                    header_buffer,
                )
                body_buffer.extend(body_prefix)
                method, url, path, raw_target, headers, content_length = (
                    self._parse_request(raw_head)
                )
                if len(body_buffer) > content_length:
                    del body_buffer[content_length:]
                await self._read_request_body(
                    reader,
                    body_buffer,
                    content_length,
                )
        except TimeoutError:
            flags, categories = self._classify_partial_request(
                raw_head or bytes(header_buffer),
                bytes(body_buffer),
            )
            self._record_rejection(
                "request_read_timeout",
                sentinel_flags=flags,
                sentinel_categories=categories,
            )
            await self._send_error(writer, 408, "proxy request read timed out")
            return
        except asyncio.CancelledError:
            flags, categories = self._classify_partial_request(
                raw_head or bytes(header_buffer),
                bytes(body_buffer),
            )
            self._record_rejection(
                "request_read_cancelled",
                sentinel_flags=flags,
                sentinel_categories=categories,
            )
            raise
        except _ProxyRequestError as exc:
            flags, categories = self._classify_partial_request(
                raw_head or bytes(header_buffer),
                bytes(body_buffer),
            )
            self._record_rejection(
                exc.category,
                sentinel_flags=flags,
                sentinel_categories=categories,
            )
            await self._send_error(writer, exc.status, exc.detail)
            return
        try:
            raw_target_bytes, raw_headers = self._sentinel_wire_parts(raw_head)
            sentinel_flags, sentinel_categories = classify_request_sentinels(
                raw_target_bytes,
                raw_headers,
                bytes(body_buffer),
            )
        except Exception:
            self._record_rejection("sentinel_classification_error")
            await self._send_error(writer, 502, "request classification failed")
            return
        body = bytes(body_buffer)

        execution_started = False
        try:
            async with self._forward_lock:
                execution_started = True
                (
                    response,
                    response_body,
                    error_status,
                    error_detail,
                ) = await self._execute_accepted_request(
                    method=method,
                    url=url,
                    path=path,
                    raw_target=raw_target,
                    headers=headers,
                    body=body,
                    sentinel_flags=sentinel_flags,
                    sentinel_categories=sentinel_categories,
                )
        except asyncio.CancelledError:
            if not execution_started:
                self._record_rejection(
                    "queued_request_cancelled",
                    method=method,
                    path=path,
                    request_digest=canonical_request_digest(
                        method,
                        raw_target,
                        body,
                    ),
                    sentinel_flags=sentinel_flags,
                    sentinel_categories=sentinel_categories,
                )
            # _execute_accepted_request marks an already-forwarding record.
            raise
        if response is None:
            await self._send_error(writer, error_status, error_detail)
            return
        await self._send_response(writer, response, response_body)

    @staticmethod
    async def _read_request_head(
        reader: asyncio.StreamReader,
        buffer: bytearray,
    ) -> tuple[bytes, bytes]:
        delimiter = b"\r\n\r\n"
        while True:
            boundary = buffer.find(delimiter)
            if boundary >= 0:
                head_end = boundary + len(delimiter)
                if head_end > MAX_REQUEST_HEADER_BYTES:
                    raise _ProxyRequestError(
                        431,
                        "proxy request headers too large",
                        "request_headers_too_large",
                    )
                return bytes(buffer[:head_end]), bytes(buffer[head_end:])
            if len(buffer) >= MAX_REQUEST_HEADER_BYTES:
                raise _ProxyRequestError(
                    431,
                    "proxy request headers too large",
                    "request_headers_too_large",
                )
            chunk = await reader.read(
                min(4_096, MAX_REQUEST_HEADER_BYTES - len(buffer))
            )
            if not chunk:
                raise _ProxyRequestError(
                    400,
                    "incomplete proxy request headers",
                    "incomplete_request_headers",
                )
            buffer.extend(chunk)

    @staticmethod
    async def _read_request_body(
        reader: asyncio.StreamReader,
        buffer: bytearray,
        content_length: int,
    ) -> None:
        while len(buffer) < content_length:
            chunk = await reader.read(
                min(_READ_CHUNK_BYTES, content_length - len(buffer))
            )
            if not chunk:
                raise _ProxyRequestError(
                    400,
                    "incomplete proxy request body",
                    "incomplete_request_body",
                )
            buffer.extend(chunk)

    @staticmethod
    def _sentinel_wire_parts(raw_head: bytes) -> tuple[bytes, bytes]:
        lines = raw_head.removesuffix(b"\r\n\r\n").split(b"\r\n")
        request_parts = lines[0].split(b" ") if lines else []
        raw_target = request_parts[1] if len(request_parts) >= 2 else b""
        raw_headers = b"\r\n".join(lines[1:])
        return raw_target, raw_headers

    def _classify_partial_request(
        self,
        raw_head: bytes,
        partial_body: bytes,
    ) -> tuple[dict[str, bool], list[str]]:
        try:
            raw_target, raw_headers = self._sentinel_wire_parts(raw_head)
            return classify_request_sentinels(
                raw_target,
                raw_headers,
                partial_body,
            )
        except Exception:
            return _empty_sentinel_flags(), []

    async def _execute_accepted_request(
        self,
        *,
        method: str,
        url: str,
        path: str,
        raw_target: str,
        headers: list[tuple[str, str]],
        body: bytes,
        sentinel_flags: dict[str, bool],
        sentinel_categories: list[str],
    ) -> tuple[httpx.Response | None, bytes, int, str]:
        """Trace and execute one request while the serialization lock is held."""
        if self._closing:
            self._record_rejection(
                "proxy_closing",
                sentinel_flags=sentinel_flags,
                sentinel_categories=sentinel_categories,
            )
            return None, b"", 503, "PoC proxy is closing"
        if self._fatal_error is not None:
            self._record_rejection(
                "trace_already_failed",
                sentinel_flags=sentinel_flags,
                sentinel_categories=sentinel_categories,
            )
            return None, b"", 503, "PoC trace is no longer usable"

        if len(self._records) >= self._max_trace_records - 1:
            self._record_rejection(
                "trace_record_limit_exceeded",
                method=method,
                path=path,
                request_digest=canonical_request_digest(method, raw_target, body),
                sentinel_flags=sentinel_flags,
                sentinel_categories=sentinel_categories,
            )
            return None, b"", 503, "PoC trace record limit exceeded"

        self._next_sequence += 1
        sequence = self._next_sequence
        # A 256-bit, lowercase hexadecimal challenge is unique to this request.
        nonce = secrets.token_hex(32)
        record = self._pending_record(
            sequence=sequence,
            nonce=nonce,
            method=method,
            path=path,
            sentinel_flags=sentinel_flags,
            sentinel_categories=sentinel_categories,
        )
        # Appending the bounded shell happens before digest/field construction
        # and, critically, before an upstream request can have a side effect.
        self._records.append(record)
        credential_free_headers: list[tuple[str, str]] | None = None
        if self._credential_free:
            credential_free_headers = _credential_free_headers(headers, body)
            record["credential_free_transport"] = credential_free_headers is not None
            if credential_free_headers is None:
                self._fail_record(record, "credential_capable_request")
                return None, b"", 403, "credential-capable request is not allowed"
        if self._tracked_capabilities:
            rendered_headers = "\n".join(f"{name}:{value}" for name, value in headers)
            record["request_tracked_capabilities_in_headers"] = sorted(
                label
                for label, capability in self._tracked_capabilities.items()
                if _text_contains_tracked_capability(rendered_headers, capability)
            )
        try:
            request_digest = canonical_request_digest(method, raw_target, body)
            record["request_digest"] = request_digest
            record["request_headers_sha256"] = salted_headers_sha256(
                credential_free_headers
                if credential_free_headers is not None
                else headers,
                self.trace_salt,
            )
            content_type = next(
                (value for name, value in headers if name.casefold() == "content-type"),
                "",
            )
            fields, shape, parse_error = trace_fields_from_wire(
                url,
                content_type,
                body,
                self.trace_salt,
                tracked_capabilities=self._tracked_capabilities,
            )
            record["fields"] = fields
            record["parameter_shape"] = shape
            if parse_error is not None:
                record["request_body_parse_error"] = parse_error
        except Exception:
            self._fail_record(record, "trace_construction_error")
            return None, b"", 502, "request trace construction failed"

        try:
            metadata_size = self._record_metadata_size(record)
        except Exception:
            self._fail_record(record, "trace_construction_error")
            return None, b"", 502, "request trace construction failed"
        if self._trace_metadata_bytes + metadata_size > self._max_trace_metadata_bytes:
            record["fields"] = []
            record["parameter_shape"] = []
            record.pop("request_body_parse_error", None)
            record["request_metadata_omitted"] = True
            self._fail_record(record, "trace_metadata_limit_exceeded")
            return None, b"", 503, "PoC trace metadata limit exceeded"
        self._trace_metadata_bytes += metadata_size

        try:
            async with asyncio.timeout(self._upstream_timeout):
                record["upstream_started_monotonic_ns"] = time.monotonic_ns()
                response, response_body = await self._forward(
                    method,
                    url,
                    headers,
                    body,
                    nonce,
                    request_digest,
                    record,
                    credential_free_headers=credential_free_headers,
                )
                record["upstream_finished_monotonic_ns"] = time.monotonic_ns()
        except TimeoutError:
            self._fail_record(record, "upstream_timeout")
            return None, b"", 504, "upstream request timed out"
        except httpx.TimeoutException:
            self._fail_record(record, "upstream_timeout")
            return None, b"", 504, "upstream request timed out"
        except _UpstreamBodyTooLarge:
            self._fail_record(record, "upstream_response_too_large")
            return None, b"", 502, "upstream response too large"
        except _UnsupportedContentEncoding:
            self._fail_record(record, "unsupported_content_encoding")
            return None, b"", 502, "upstream content encoding is unsupported"
        except (httpx.HTTPError, OSError):
            self._fail_record(record, "upstream_reset")
            return None, b"", 502, "upstream request failed"
        except asyncio.CancelledError:
            self._fail_record(record, "upstream_cancelled")
            raise
        except Exception:
            self._fail_record(record, "upstream_reset")
            return None, b"", 502, "upstream request failed"

        try:
            capture_fits = self._populate_response_trace(
                record,
                response,
                response_body,
            )
        except Exception:
            self._fail_record(record, "trace_construction_error")
            return None, b"", 502, "response trace construction failed"
        if not capture_fits:
            self._fail_record(record, "trace_capture_limit_exceeded")
            return None, b"", 503, "PoC trace capture limit exceeded"

        # Commit completion before model-authored code receives status, headers,
        # or body and can run a response hook.
        record["forward_state"] = "completed"
        return response, response_body, 0, ""

    def _parse_request(
        self,
        raw_head: bytes,
    ) -> tuple[str, str, str, str, list[tuple[str, str]], int]:
        if len(raw_head) > MAX_REQUEST_HEADER_BYTES:
            raise _ProxyRequestError(431, "proxy request headers too large")
        lines = raw_head[:-4].split(b"\r\n")
        if not lines or not lines[0]:
            raise _ProxyRequestError(400, "malformed proxy request")
        request_parts = lines[0].split(b" ")
        if len(request_parts) != 3 or any(not part for part in request_parts):
            raise _ProxyRequestError(400, "malformed proxy request line")
        raw_method, raw_target, version = request_parts
        if not _TOKEN_RE.fullmatch(raw_method):
            raise _ProxyRequestError(400, "invalid proxy request method")
        if len(raw_method) > MAX_REQUEST_METHOD_BYTES:
            raise _ProxyRequestError(400, "proxy request method is too long")
        if len(raw_target) > MAX_REQUEST_TARGET_BYTES:
            raise _ProxyRequestError(414, "proxy request target is too long")
        method = raw_method.decode("ascii").upper()
        if method == "CONNECT":
            raise _ProxyRequestError(
                405,
                "CONNECT is not supported",
                "connect_not_supported",
            )
        if version not in {b"HTTP/1.0", b"HTTP/1.1"}:
            raise _ProxyRequestError(505, "unsupported HTTP version")
        try:
            target = raw_target.decode("ascii")
        except UnicodeDecodeError as exc:
            raise _ProxyRequestError(400, "invalid proxy request target") from exc
        if any(ord(char) < 0x21 or ord(char) == 0x7F for char in target):
            raise _ProxyRequestError(400, "invalid proxy request target")

        headers: list[tuple[str, str]] = []
        for raw_line in lines[1:]:
            if not raw_line or raw_line[:1] in {b" ", b"\t"} or b":" not in raw_line:
                raise _ProxyRequestError(400, "malformed proxy request header")
            raw_name, raw_value = raw_line.split(b":", 1)
            if not _TOKEN_RE.fullmatch(raw_name):
                raise _ProxyRequestError(400, "invalid proxy request header name")
            if (
                any(byte < 0x20 and byte != 0x09 for byte in raw_value)
                or b"\x7f" in raw_value
            ):
                raise _ProxyRequestError(400, "invalid proxy request header value")
            headers.append(
                (
                    raw_name.decode("ascii"),
                    raw_value.strip(b" \t").decode("latin-1"),
                )
            )

        lower_headers: dict[str, list[str]] = {}
        for name, value in headers:
            lower_headers.setdefault(name.casefold(), []).append(value)
        semantic_header_names = {name.replace("_", "-") for name in lower_headers}
        if _ROUTING_OVERRIDE_HEADERS.intersection(semantic_header_names):
            raise _ProxyRequestError(
                400,
                "routing and method override headers are not supported",
                "behavior_changing_header",
            )
        content_types = lower_headers.get("content-type", [])
        if len(content_types) > 1 or (content_types and "," in content_types[0]):
            raise _ProxyRequestError(
                400,
                "ambiguous Content-Type headers are not supported",
                "ambiguous_content_type",
            )
        content_encodings = lower_headers.get("content-encoding", [])
        if len(content_encodings) > 1 or (
            content_encodings
            and content_encodings[0].strip().casefold() not in {"", "identity"}
        ):
            raise _ProxyRequestError(
                415,
                "request content encoding is not supported",
                "unsupported_request_content_encoding",
            )
        if "transfer-encoding" in lower_headers:
            raise _ProxyRequestError(
                501,
                "chunked request bodies are not supported",
                "unsupported_transfer_encoding",
            )
        if "expect" in lower_headers:
            raise _ProxyRequestError(417, "request expectations are not supported")
        content_lengths = lower_headers.get("content-length", [])
        if len(content_lengths) > 1:
            raise _ProxyRequestError(400, "ambiguous proxy request length")
        if content_lengths:
            if not content_lengths[0].isdigit():
                raise _ProxyRequestError(400, "invalid proxy request length")
            content_length = int(content_lengths[0])
        else:
            content_length = 0
        if content_length > MAX_REQUEST_BODY_BYTES:
            raise _ProxyRequestError(
                413,
                "proxy request body too large",
                "request_body_too_large",
            )

        host_values = lower_headers.get("host", [])
        if len(host_values) != 1:
            raise _ProxyRequestError(400, "proxy request requires one Host header")
        host_origin = self._host_origin(host_values[0])
        try:
            parsed = urlsplit(target)
        except ValueError as exc:
            raise _ProxyRequestError(
                400,
                "invalid proxy request target",
                "invalid_request_target",
            ) from exc
        if parsed.scheme or parsed.netloc:
            if (
                parsed.scheme.casefold() != "http"
                or parsed.username is not None
                or parsed.password is not None
                or parsed.fragment
            ):
                raise _ProxyRequestError(
                    403,
                    "proxy target origin is not allowed",
                    "target_origin_not_allowed",
                )
            request_origin = normalize_trace_origin(target)
            if not request_origin:
                raise _ProxyRequestError(
                    400,
                    "invalid proxy request target",
                    "invalid_request_target",
                )
            path_and_query = parsed.path or "/"
            if parsed.query:
                path_and_query += "?" + parsed.query
        else:
            if not target.startswith("/") or "#" in target:
                raise _ProxyRequestError(400, "proxy requires an absolute HTTP target")
            request_origin = host_origin
            path_and_query = target
        if request_origin != self.target_origin or host_origin != self.target_origin:
            raise _ProxyRequestError(
                403,
                "proxy target origin is not allowed",
                "target_origin_not_allowed",
            )

        url = self.target_origin + path_and_query
        path = parsed.path or "/"
        return method, url, path, path_and_query, headers, content_length

    @staticmethod
    def _host_origin(host: str) -> str:
        if any(char in host for char in "/?#@"):
            return ""
        return normalize_trace_origin("http://" + host)

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
        forwarded = (
            list(credential_free_headers)
            if credential_free_headers is not None
            else _forwarded_child_headers(headers)
        )
        forwarded.append(("Accept-Encoding", "identity"))
        if credential_free_headers is None:
            forwarded.extend(
                [
                    (TRACE_TOKEN_HEADER, self._trace_token),
                    (REQUEST_NONCE_HEADER, nonce),
                    (REQUEST_DIGEST_HEADER, request_digest),
                ]
            )
        # One client per request gives each exchange a fresh cookie jar and
        # connection pool. No Set-Cookie state can cross child requests.
        async with httpx.AsyncClient(
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(self._upstream_timeout),
        ) as client:
            async with client.stream(
                method,
                url,
                headers=forwarded,
                content=body,
                follow_redirects=False,
            ) as response:
                record["status_code"] = response.status_code
                content_encoding = response.headers.get("Content-Encoding", "")
                if content_encoding.strip().casefold() not in {"", "identity"}:
                    raise _UnsupportedContentEncoding
                declared_length = response.headers.get("Content-Length")
                if declared_length and declared_length.isdigit():
                    if int(declared_length) > MAX_RESPONSE_BODY_BYTES:
                        raise _UpstreamBodyTooLarge
                chunks: list[bytes] = []
                length = 0
                async for chunk in response.aiter_raw():
                    length += len(chunk)
                    if length > MAX_RESPONSE_BODY_BYTES:
                        raise _UpstreamBodyTooLarge
                    chunks.append(chunk)
                response_body = b"".join(chunks)
        return response, response_body

    def _pending_record(
        self,
        *,
        sequence: int,
        nonce: str,
        method: str,
        path: str,
        sentinel_flags: Mapping[str, bool] | None = None,
        sentinel_categories: Iterable[str] | None = None,
    ) -> dict[str, object]:
        """Return a bounded record shell containing no raw request values."""
        supplied_flags = sentinel_flags or {}
        normalized_flags = {
            name: bool(supplied_flags.get(name, False)) for name in _SENTINEL_FLAG_NAMES
        }
        normalized_categories = sorted(
            name for name, present in normalized_flags.items() if present
        )
        # Categories are always derived from the fixed flag shape. Accepting the
        # argument makes the call site explicit while preventing divergence.
        del sentinel_categories
        return {
            "trace_version": TRACE_VERSION,
            "record_type": "request",
            "sequence": sequence,
            "request_nonce": nonce,
            "request_digest": None,
            "request_headers_sha256": None,
            "upstream_started_monotonic_ns": None,
            "upstream_finished_monotonic_ns": None,
            "method": method,
            "origin": self.target_origin,
            "path": path,
            "fields": [],
            "parameter_shape": [],
            "request_sentinel_flags": normalized_flags,
            "request_sentinel_categories": normalized_categories,
            "status_code": None,
            "response_body_sha256": None,
            "response_body_length": None,
            "response_body_b64": "",
            "response_body_tail_b64": "",
            "response_body_truncated": False,
            "response_actor_receipt": None,
            "response_actor_receipt_truncated": False,
            "forward_state": "pending",
            "forward_error": None,
            "terminal": False,
        }

    @staticmethod
    def _record_metadata_size(record: dict[str, object]) -> int:
        """Return exact compact-JSON bytes before any response capture is added."""
        return len(
            json.dumps(
                record,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        )

    def _populate_response_trace(
        self,
        record: dict[str, object],
        response: httpx.Response,
        response_body: bytes,
    ) -> bool:
        """Add bounded upstream evidence, returning false on aggregate overflow."""
        truncated = len(response_body) > RESPONSE_BODY_CAPTURE_LIMIT
        if truncated:
            half = RESPONSE_BODY_CAPTURE_LIMIT // 2
            body_head = response_body[:half]
            body_tail = response_body[-half:]
        else:
            body_head = response_body
            body_tail = b""
        encoded_head = base64.b64encode(body_head).decode("ascii")
        encoded_tail = base64.b64encode(body_tail).decode("ascii")

        receipt = response.headers.get(ACTOR_RECEIPT_HEADER)
        receipt_text = str(receipt) if receipt is not None else None
        receipt_truncated = bool(
            receipt_text is not None and len(receipt_text) > ACTOR_RECEIPT_LIMIT
        )
        if receipt_truncated and receipt_text is not None:
            receipt_text = receipt_text[:ACTOR_RECEIPT_LIMIT]

        record.update(
            {
                "status_code": response.status_code,
                "response_body_sha256": hashlib.sha256(response_body).hexdigest(),
                "response_body_length": len(response_body),
            }
        )
        capture_size = len(encoded_head) + len(encoded_tail)
        if receipt_text is not None:
            capture_size += len(receipt_text.encode("utf-8", errors="replace"))
        if self._trace_capture_bytes + capture_size > self._max_trace_capture_bytes:
            record["response_capture_omitted"] = True
            return False

        record.update(
            {
                "response_body_b64": encoded_head,
                "response_body_tail_b64": encoded_tail,
                "response_body_truncated": truncated,
                "response_actor_receipt": receipt_text,
                "response_actor_receipt_truncated": receipt_truncated,
            }
        )
        self._trace_capture_bytes += capture_size
        return True

    def _fail_record(self, record: dict[str, object], error: str) -> None:
        """Make a pending request a durable terminal failure without error text."""
        record["forward_state"] = "failed"
        record["forward_error"] = error
        record["terminal"] = True
        self._increment_rejection(error)
        sequence = record.get("sequence")
        if not isinstance(sequence, int) or isinstance(sequence, bool):
            sequence = self._next_sequence + 1
        if self._fatal_sequence is None or sequence < self._fatal_sequence:
            self._fatal_error = error
            self._fatal_sequence = sequence

    def _increment_rejection(self, error: str) -> None:
        count = self._rejection_counts.get(error, 0)
        self._rejection_counts[error] = min(count + 1, 2**31 - 1)

    def _record_rejection(
        self,
        error: str,
        *,
        method: str = "",
        path: str = "/",
        request_digest: str | None = None,
        sentinel_flags: Mapping[str, bool] | None = None,
        sentinel_categories: Iterable[str] | None = None,
    ) -> None:
        """Append one bounded rejection or account it in an existing terminal."""
        if len(self._records) < self._max_trace_records:
            self._append_terminal_record(
                error,
                method=method,
                path=path,
                request_digest=request_digest,
                sentinel_flags=sentinel_flags,
                sentinel_categories=sentinel_categories,
            )
            return

        self._increment_rejection(error)
        if self._fatal_error is None:
            self._fatal_error = "trace_record_limit_exceeded"
            self._fatal_sequence = self._next_sequence + 1
        if self._records:
            terminal = self._records[-1]
            terminal["rejection_overflow"] = True
            count = terminal.get("additional_rejected_attempts", 0)
            if not isinstance(count, int) or isinstance(count, bool):
                count = 0
            terminal["additional_rejected_attempts"] = min(count + 1, 2**31 - 1)
            supplied_flags = sentinel_flags or {}
            prior_flags = terminal.get("overflow_request_sentinel_flags")
            if not isinstance(prior_flags, dict):
                prior_flags = _empty_sentinel_flags()
            aggregate_flags = {
                name: bool(prior_flags.get(name, False))
                or bool(supplied_flags.get(name, False))
                for name in _SENTINEL_FLAG_NAMES
            }
            terminal["overflow_request_sentinel_flags"] = aggregate_flags
            terminal["overflow_request_sentinel_categories"] = sorted(
                name for name, present in aggregate_flags.items() if present
            )

    def _append_terminal_record(
        self,
        error: str,
        *,
        method: str,
        path: str,
        request_digest: str | None,
        sentinel_flags: Mapping[str, bool] | None = None,
        sentinel_categories: Iterable[str] | None = None,
    ) -> None:
        """Reserve the last slot for an explicit trace-overflow sentinel."""
        self._next_sequence += 1
        record = self._pending_record(
            sequence=self._next_sequence,
            nonce="",
            method=method,
            path=path,
            sentinel_flags=sentinel_flags,
            sentinel_categories=sentinel_categories,
        )
        record["record_type"] = "terminal_error"
        record["request_digest"] = request_digest
        self._fail_record(record, error)
        self._records.append(record)

    async def _send_response(
        self,
        writer: asyncio.StreamWriter,
        response: httpx.Response,
        body: bytes,
    ) -> None:
        reason = response.reason_phrase
        if not reason:
            try:
                reason = HTTPStatus(response.status_code).phrase
            except ValueError:
                reason = "Upstream Response"
        response_headers = list(response.headers.multi_items())
        connection_tokens = self._connection_tokens(response_headers)
        blocked = _HOP_BY_HOP_HEADERS | connection_tokens | {"content-length"}
        kept_headers = [
            (name, value)
            for name, value in response_headers
            if name.casefold() not in blocked
            and not name.casefold().startswith("x-squadrone-")
        ]
        kept_headers.extend(
            [("Content-Length", str(len(body))), ("Connection", "close")]
        )
        head = [f"HTTP/1.1 {response.status_code} {reason}\r\n".encode("latin-1")]
        head.extend(
            f"{name}: {value}\r\n".encode("latin-1") for name, value in kept_headers
        )
        head.append(b"\r\n")
        writer.writelines(head)
        writer.write(body)
        await writer.drain()

    @staticmethod
    def _connection_tokens(headers: Iterable[tuple[str, str]]) -> frozenset[str]:
        tokens: set[str] = set()
        for name, value in headers:
            if name.casefold() == "connection":
                tokens.update(part.strip().casefold() for part in value.split(","))
        return frozenset(token for token in tokens if token)

    @staticmethod
    async def _send_error(
        writer: asyncio.StreamWriter,
        status: int,
        detail: str,
    ) -> None:
        try:
            phrase = HTTPStatus(status).phrase
        except ValueError:
            phrase = "Proxy Error"
        body = f"{status} {detail}\n".encode("utf-8")
        writer.write(
            f"HTTP/1.1 {status} {phrase}\r\n".encode("ascii")
            + b"Content-Type: text/plain; charset=utf-8\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"Connection: close\r\n\r\n"
            + body
        )
        try:
            await writer.drain()
        except ConnectionError:
            pass


# Readable aliases for integrations and older naming drafts.
PocHttpTraceProxy = PocProxySupervisor
TRACE_NONCE_HEADER = REQUEST_NONCE_HEADER
