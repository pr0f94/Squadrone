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
import shutil
import signal
import socket
import stat
import statistics
import sys
import tempfile
import time
import uuid
from collections import Counter
from dataclasses import dataclass
from importlib.resources import files as _package_files
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Optional, cast
from urllib.parse import parse_qsl, quote, quote_plus, unquote, urlparse, urlsplit

import httpx
from jinja2 import Template
from pydantic import BaseModel, Field, PrivateAttr, ValidationError, model_validator

from ..poc_isolation import (
    CROSS_OBJECT_HTTP_CAPABILITY,
    DEFAULT_MAX_BUNDLE_FILES,
    EXECUTABLE_UPLOAD_ATTACK_FILENAME_ENV,
    EXECUTABLE_UPLOAD_CONTROL_FILENAME_ENV,
    EXECUTABLE_UPLOAD_PAYLOAD_ENV,
    prepare_poc_isolation,
)
from ..poc_proxy import (
    PHP_INCLUDE_RECEIPT_HEADER,
    ExecutableUploadPolicy,
    PhpObjectRewritePolicy,
    PocProxySupervisor,
    normalize_trace_origin,
    salted_file_content_sha256,
    salted_scalar_sha256,
)
from ..schemas.config import SandboxConfig
from ..schemas.observation import CIAImpact, PoCObservation
from ..schemas.php_object_gadget import (
    PhpObjectGadgetDirectPathEffectBinding,
    PhpObjectGadgetRecipe,
    PhpObjectGadgetSourceAnchor,
)
from ..schemas.taxonomy import (
    KNOWN_CWE_REGISTRY,
    BugClass,
    get_known_cwe_profile,
)
from .php_include_oracle import (
    PHP_INCLUDE_ORACLE_DIRECTORY,
    PHP_INCLUDE_ORACLE_FILE_MODE,
    PHP_INCLUDE_ORACLE_HEADER_NAME,
    PHP_INCLUDE_ORACLE_MODE,
    PhpIncludeAttestationError,
    PhpIncludeFilesystemAttestation,
    PhpIncludeHostFilesystemAttestation,
    PhpIncludeHostFilesystemMeasurement,
    PhpIncludeOracle,
    PhpIncludeOracleSnapshot,
    PhpIncludeProvisioningAttestation,
    PhpIncludeVerificationAttestation,
)
from .php_object_gadget_oracle import (
    PHP_OBJECT_GADGET_DIRECTORY,
    PHP_OBJECT_GADGET_ORACLE_MODE,
    PHP_OBJECT_GADGET_ORACLE_SCHEMA_VERSION,
    PhpObjectGadgetFileMeasurement,
    PhpObjectGadgetOracle,
    PhpObjectGadgetOracleSnapshot,
    PhpObjectGadgetRuntimeBinding,
    PhpObjectGadgetTransportAttestation,
    php_object_gadget_recipe_sha256,
)
from .php_object_oracle import (
    PhpObjectCallsite,
    PhpObjectOracle,
    PhpObjectOracleSnapshot,
)
from .roles import UNKNOWN_ATTACKER_ROLE, normalize_attacker_role
from .setup_http import SetupHttpContext
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
_DOCKER_DIR = _package_files("squadrone.docker")
_SANDBOX_DATABASE_NAME = "wordpress"
_SANDBOX_DATABASE_USER = "wpuser"
_SANDBOX_DATABASE_PASSWORD = "wppass"
_SANDBOX_MARIADB_CLIENT_AUTH = (
    f"-u{_SANDBOX_DATABASE_USER}",
    f"-p{_SANDBOX_DATABASE_PASSWORD}",
)
_ACTOR_RECEIPT_TEMPLATE = _DOCKER_DIR / "squadrone-actor-receipt.php.j2"
_ACTOR_RECEIPT_BASENAME = "squadrone-actor-receipt.php"
_MU_PLUGIN_DIRECTORY = "/var/www/html/wp-content/mu-plugins"
_PHP_OBJECT_CANARY_CLASS_RE = re.compile(r"SquadroneObjectCanary_([0-9a-f]{32})\Z")
_PHP_OBJECT_CANARY_BASENAME_PREFIX = "squadrone-object-canary-"
_PHP_OBJECT_REDACTED_VALUE = "<redacted>"
_PHP_OBJECT_OBSERVATION_FIELDS = frozenset(
    {
        "observed",
        "instantiated",
        "effect",
        "attacker_user_id",
        "identity_verified",
        "request_fingerprint",
    }
)
_PHP_OBJECT_FINGERPRINT_FIELDS = frozenset(
    {"method", "route", "object_field", "object_location", "dispatch"}
)
_PHP_OBJECT_SURFACE_MANIFEST_PREFIX = "/tmp/squadrone-object-surfaces-"
_PHP_OBJECT_SURFACE_MANIFEST_RE = re.compile(
    r"/tmp/squadrone-object-surfaces-[0-9a-f]{32}\.json\Z"
)
_CONTAINER_SNAPSHOT_ARCHIVE_RE = re.compile(
    r"/tmp/squadrone-wordpress-root-[0-9a-f]{32}\.tar\.gz\Z"
)
_PHP_OBJECT_SURFACE_ATTESTATION_ORDER = (
    ("before", "attack"),
    ("after", "attack"),
    ("before", "control"),
    ("after", "control"),
)
_PHP_OBJECT_RECEIPT_DIAGNOSTIC_MAX_CHARS = 320
_PHP_OBJECT_RECEIPT_REJECTION_SPECS = {
    "missing_php_object_receipt": (
        "Trusted parent PHP object diagnostic: attack policy accepted; attack "
        "payload privately rewritten; upstream response received; required attack "
        "receipt missing; instantiation/control remain unestablished.",
        "attack",
        "accepted",
        "privately_rewritten",
        "missing",
    ),
    "malformed_php_object_receipt": (
        "Trusted parent PHP object diagnostic: attack policy accepted; attack "
        "payload privately rewritten; upstream response received; attack receipt "
        "malformed; instantiation/control remain unestablished.",
        "attack",
        "accepted",
        "privately_rewritten",
        "malformed",
    ),
    "mismatched_php_object_receipt": (
        "Trusted parent PHP object diagnostic: attack policy accepted; attack "
        "payload privately rewritten; upstream response received; attack receipt "
        "mismatched; instantiation/control remain unestablished.",
        "attack",
        "accepted",
        "privately_rewritten",
        "mismatched",
    ),
    "control_php_object_receipt_present": (
        "Trusted parent PHP object diagnostic: control policy accepted; control "
        "payload privately rewritten; upstream response received; control receipt "
        "present where absence was required; instantiation/control remain "
        "unestablished.",
        "control",
        "accepted",
        "privately_rewritten",
        "control_present",
    ),
    "duplicate_php_object_receipt": (
        "Trusted parent PHP object diagnostic: upstream response received; duplicate "
        "PHP object receipt headers present; instantiation/control remain "
        "unestablished.",
        "unestablished",
        "unestablished",
        "unestablished",
        "duplicate",
    ),
    "unexpected_php_object_receipt": (
        "Trusted parent PHP object diagnostic: upstream response received; unexpected "
        "PHP object receipt present; instantiation/control remain unestablished.",
        "unestablished",
        "unestablished",
        "unestablished",
        "unexpected",
    ),
}
_PHP_OBJECT_GADGET_FORBIDDEN_DIRECTORY_CONSTANTS = frozenset(
    {
        "ABSPATH",
        "AUTH_KEY",
        "AUTH_SALT",
        "COOKIEHASH",
        "DB_CHARSET",
        "DB_COLLATE",
        "DB_HOST",
        "DB_NAME",
        "DB_PASSWORD",
        "DB_USER",
        "DISALLOW_FILE_EDIT",
        "DISALLOW_FILE_MODS",
        "DOMAIN_CURRENT_SITE",
        "FORCE_SSL_ADMIN",
        "LOGGED_IN_KEY",
        "LOGGED_IN_SALT",
        "MULTISITE",
        "NONCE_KEY",
        "NONCE_SALT",
        "PATH_CURRENT_SITE",
        "SECURE_AUTH_KEY",
        "SECURE_AUTH_SALT",
        "SUBDOMAIN_INSTALL",
        "WP_ACCESSIBLE_HOSTS",
        "WP_ALLOW_MULTISITE",
        "WP_CACHE",
        "WP_CONTENT_DIR",
        "WP_CONTENT_URL",
        "WP_DEBUG",
        "WP_DEBUG_DISPLAY",
        "WP_DEBUG_LOG",
        "WP_ENVIRONMENT_TYPE",
        "WP_HOME",
        "WP_HTTP_BLOCK_EXTERNAL",
        "WP_MAX_MEMORY_LIMIT",
        "WP_MEMORY_LIMIT",
        "WP_PLUGIN_DIR",
        "WP_PLUGIN_URL",
        "WP_SITEURL",
        "WP_TEMP_DIR",
        "WPMU_PLUGIN_DIR",
        "WPMU_PLUGIN_URL",
    }
)
_PHP_OBJECT_GADGET_UNLINK_CALL_RE = re.compile(
    r"(?<![A-Za-z0-9_\\>:@])@?\\?unlink\s*\(",
    re.IGNORECASE,
)
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


def _fresh_container_snapshot_archive_path() -> str:
    path = f"/tmp/squadrone-wordpress-root-{secrets.token_hex(16)}.tar.gz"
    if _CONTAINER_SNAPSHOT_ARCHIVE_RE.fullmatch(path) is None:
        raise RuntimeError("invalid container snapshot archive identity")
    return path


async def _remove_container_snapshot_archive(
    container_name: str,
    archive_path: str,
) -> None:
    if (
        not container_name
        or _CONTAINER_SNAPSHOT_ARCHIVE_RE.fullmatch(archive_path) is None
    ):
        raise RuntimeError("invalid container snapshot cleanup target")
    rc, _stdout, _stderr = await _run(
        "docker",
        "exec",
        "--user",
        "root",
        container_name,
        "rm",
        "-f",
        "--",
        archive_path,
        check=False,
    )
    if rc != 0:
        raise RuntimeError("failed to remove private container snapshot archive")


@dataclass(frozen=True, slots=True)
class _PhpObjectSurfaceFreeze:
    """Opaque handle for one root-owned executable-surface freeze."""

    manifest_path: str
    entry_count: int
    original_sha256: str
    frozen_sha256: str
    manifest_sha256: str


POC_RESULT_PREFIX = "SQUADRONE_RESULT="


def _strip_rejected_poc_result_lines(value: str | None) -> str | None:
    """Remove child machine-result lines after parent validation rejects them."""
    if value is None:
        return None
    return "\n".join(
        line for line in value.splitlines() if POC_RESULT_PREFIX not in line
    ).strip()


def strip_php_object_gadget_child_claims(result: SandboxRunResult) -> None:
    """Remove every child machine claim from a natural-gadget run artifact."""
    result.observation = None
    result.rejected_observation = None
    result.output = _strip_rejected_poc_result_lines(result.output) or ""
    # Derive the response tail again from the cleaned full output.  Sanitizing the
    # old tail in isolation is unsafe because a long machine-result line can be
    # truncated before its prefix and leave a JSON fragment behind.
    result.response = result.output[-2000:] if result.output else None
    result.error_log = _strip_rejected_poc_result_lines(result.error_log) or None
    result.evidence["observation"] = None
    result.evidence["rejected_observation"] = None
    result.evidence["observation_disposition"] = "parent_attestation_only"
    result.evidence["stdout_tail"] = result.output[-500:]


class SandboxRunResult(BaseModel):
    success: bool
    output: str
    elapsed: float
    http_status: Optional[int] = None
    response: Optional[str] = None
    error_log: Optional[str] = None
    evidence: dict = Field(default_factory=dict)
    # The runner, not the child process, decides whether an emitted observation
    # is evidence. A rejected child self-report remains available only under an
    # explicitly non-authoritative field for bounded retry diagnostics.
    observation: Optional[PoCObservation] = None
    rejected_observation: Optional[PoCObservation] = None
    validation_reason: str = ""

    _trusted_php_include_observation: Optional[PoCObservation] = PrivateAttr(
        default=None
    )
    _trusted_php_object_snapshot: Optional[PhpObjectOracleSnapshot] = PrivateAttr(
        default=None
    )
    _trusted_php_object_gadget_snapshot: Optional[PhpObjectGadgetOracleSnapshot] = (
        PrivateAttr(default=None)
    )

    @model_validator(mode="after")
    def _separate_rejected_observation(self) -> "SandboxRunResult":
        """Prevent a failed runner verdict from carrying accepted evidence."""
        if self.success:
            if self.rejected_observation is not None:
                raise ValueError(
                    "successful sandbox run cannot contain a rejected observation"
                )
            return self

        self._normalize_rejection()
        return self

    def _normalize_rejection(self) -> None:
        self._reject_child_observation()
        self.output = _strip_rejected_poc_result_lines(self.output) or ""
        # ``response`` is a tail slice in the real runner, so it may start in
        # the middle of an overlong SQUADRONE_RESULT line and no longer carry
        # the prefix needed for safe line filtering.  The full output above is
        # the only source from which bounded diagnostics may be derived.
        self.response = (
            None
            if self.rejected_observation is not None
            else _strip_rejected_poc_result_lines(self.response) or None
        )
        self.error_log = _strip_rejected_poc_result_lines(self.error_log) or None
        self.evidence["stdout_tail"] = self.output[-500:]
        self.evidence["observation"] = None
        self.evidence["rejected_observation"] = (
            self.rejected_observation.model_dump(mode="json")
            if self.rejected_observation is not None
            else None
        )
        self.evidence["observation_disposition"] = (
            "rejected" if self.rejected_observation is not None else "absent"
        )
        if self.validation_reason:
            self.evidence["validation_reason"] = self.validation_reason

    def _reject_child_observation(self) -> None:
        if self.observation is None:
            return
        if (
            self.rejected_observation is not None
            and self.rejected_observation != self.observation
        ):
            raise ValueError("sandbox run contains conflicting rejected observations")
        self.rejected_observation = self.observation
        self.observation = None

    def reject(self, validation_reason: str) -> None:
        """Make a later parent-side validation failure authoritative."""
        self.success = False
        self.validation_reason = validation_reason
        self._normalize_rejection()

    def retain_trusted_php_include_observation(
        self,
        observation: PoCObservation | None,
    ) -> None:
        """Keep one raw PHP marker only in this non-serializing memory slot."""
        self._trusted_php_include_observation = observation

    def take_trusted_php_include_observation(self) -> PoCObservation | None:
        """Return and forget the raw PHP observation after confirmation binding."""
        observation = self._trusted_php_include_observation
        self._trusted_php_include_observation = None
        return observation

    def retain_trusted_php_object_snapshot(
        self,
        snapshot: PhpObjectOracleSnapshot | None,
    ) -> None:
        """Keep trusted object-canary evidence outside every serialized field."""
        self._trusted_php_object_snapshot = snapshot

    def take_trusted_php_object_snapshot(self) -> PhpObjectOracleSnapshot | None:
        """Return and forget one parent-attested PHP-object snapshot."""
        snapshot = self._trusted_php_object_snapshot
        self._trusted_php_object_snapshot = None
        return snapshot

    def retain_trusted_php_object_gadget_snapshot(
        self,
        snapshot: PhpObjectGadgetOracleSnapshot | None,
    ) -> None:
        """Keep natural gadget evidence only in a non-serializing memory slot."""
        self._trusted_php_object_gadget_snapshot = snapshot

    def take_trusted_php_object_gadget_snapshot(
        self,
    ) -> PhpObjectGadgetOracleSnapshot | None:
        """Return and forget one parent-attested natural gadget snapshot."""
        snapshot = self._trusted_php_object_gadget_snapshot
        self._trusted_php_object_gadget_snapshot = None
        return snapshot


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
_SSRF_ORACLE_HOST = "squadrone-ssrf-relay.internal"
_SSRF_ORACLE_PATH_PREFIX = "/_squadrone/ssrf/"
_SSRF_RELAY_GATEWAY_HOST = "squadrone.host.internal"
_SSRF_RELAY_CONFIG_BASENAME = "squadrone-ssrf-relay.conf"
_SSRF_RELAY_CONTAINER_CONFIG = (
    f"/etc/apache2/conf-enabled/{_SSRF_RELAY_CONFIG_BASENAME}"
)
_SSRF_RELAY_CONTAINER_STAGING_CONFIG = (
    f"/etc/apache2/conf-enabled/.{_SSRF_RELAY_CONFIG_BASENAME}.new"
)
_SSRF_READINESS_MAX_ATTEMPTS = 8
_SSRF_READINESS_RETRY_DELAY_S = 0.2
_SSRF_REQUEST_LOCATIONS = frozenset({"query", "form", "json", "multipart"})
_SSRF_REQUEST_FIELDS = (
    "method",
    "route",
    "destination_parameter",
    "destination_location",
)
_PHP_INCLUDE_MARKER_RE = re.compile(r"SQUADRONE_PHP_INCLUDE_[0-9a-f]{64}\Z")
_PHP_INCLUDE_REDACTED_MARKER = "<redacted>"

EXECUTABLE_UPLOAD_CHALLENGE_PARAMETER = "squadrone_challenge"
EXECUTABLE_UPLOAD_RESPONSE_PREFIX = "SQUADRONE_UPLOAD_EXEC_V1:"
EXECUTABLE_UPLOAD_IMPACT_DESCRIPTION = (
    "The parent issued a fresh post-upload challenge after the PoC exited and "
    "measured attack-only PHP execution from the public uploads directory, "
    "establishing arbitrary server-side code execution in the sandbox."
)
_EXECUTABLE_UPLOAD_PATH_PREFIX = "/wp-content/uploads/"
_EXECUTABLE_UPLOAD_MAX_URL_BYTES = 8192
_EXECUTABLE_UPLOAD_MAX_RESPONSE_BYTES = 4096
_EXECUTABLE_UPLOAD_PROBE_TIMEOUT_SECONDS = 15.0
_EXECUTABLE_UPLOAD_SNAPSHOT_ROOT = "/var/www/html/wp-content/uploads"
_EXECUTABLE_UPLOAD_SNAPSHOT_MAX_BYTES = 4 * 1024 * 1024
_EXECUTABLE_UPLOAD_SNAPSHOT_MAX_ENTRIES = 20_000
_EXECUTABLE_UPLOAD_SNAPSHOT_MAX_PATH_BYTES = 4096
_EXECUTABLE_UPLOAD_SNAPSHOT_TIMEOUT_SECONDS = 15.0
_EXECUTABLE_UPLOAD_SNAPSHOT_INNER_TIMEOUT_SECONDS = 13
_EXECUTABLE_UPLOAD_SNAPSHOT_SCRIPT = r"""
$root = '/var/www/html/wp-content/uploads';
$expected_size = isset($argv[1]) ? (int) $argv[1] : -1;
$max_entries = 20000;
$max_path_bytes = 4096;
$max_output_bytes = 4194304;
$result = array('version' => 1, 'root' => 'absent', 'entries' => array());
try {
    if (is_link($root) || (file_exists($root) && ! is_dir($root))) {
        throw new RuntimeException('invalid_root');
    }
    if (is_dir($root)) {
        $result['root'] = 'directory';
        $flags = FilesystemIterator::SKIP_DOTS;
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($root, $flags),
            RecursiveIteratorIterator::SELF_FIRST
        );
        foreach ($iterator as $info) {
            if (count($result['entries']) >= $max_entries) {
                throw new RuntimeException('entry_limit');
            }
            $path = $info->getPathname();
            $relative = substr($path, strlen($root) + 1);
            if (! is_string($relative) || $relative === ''
                || strlen($relative) > $max_path_bytes) {
                throw new RuntimeException('path_limit');
            }
            $before = lstat($path);
            if (! is_array($before)) {
                throw new RuntimeException('lstat_failed');
            }
            if (is_link($path)) {
                $kind = 'l';
            } elseif (is_dir($path)) {
                $kind = 'd';
            } elseif (is_file($path)) {
                $kind = 'f';
            } else {
                $kind = 'o';
            }
            $digest = null;
            if ($kind === 'f' && (int) $before['size'] === $expected_size) {
                $digest = hash_file('sha256', $path);
                clearstatcache(true, $path);
                $after = lstat($path);
                foreach (array('ino', 'mode', 'nlink', 'uid', 'gid', 'size', 'mtime', 'ctime') as $key) {
                    if (! is_array($after) || $before[$key] !== $after[$key]) {
                        throw new RuntimeException('unstable_file');
                    }
                }
                if (! is_string($digest) || preg_match('/\A[0-9a-f]{64}\z/D', $digest) !== 1) {
                    throw new RuntimeException('hash_failed');
                }
            }
            $result['entries'][] = array(
                'path' => $relative,
                'kind' => $kind,
                'inode' => (int) $before['ino'],
                'mode' => (int) $before['mode'],
                'links' => (int) $before['nlink'],
                'uid' => (int) $before['uid'],
                'gid' => (int) $before['gid'],
                'size' => (int) $before['size'],
                'sha256' => $digest,
            );
        }
    }
    usort($result['entries'], static function ($left, $right) {
        return strcmp($left['path'], $right['path']);
    });
    $encoded = json_encode($result, JSON_UNESCAPED_SLASHES);
    if (! is_string($encoded) || strlen($encoded) > $max_output_bytes) {
        throw new RuntimeException('output_limit');
    }
    echo $encoded;
} catch (Throwable $ignored) {
    fwrite(STDERR, "snapshot_failed\n");
    exit(2);
}
""".strip()
_EXECUTABLE_UPLOAD_ATTESTATION_ORDER: tuple[
    tuple[Literal["before", "after"], Literal["attack", "control"]], ...
] = (
    ("before", "attack"),
    ("after", "attack"),
    ("before", "control"),
    ("after", "control"),
)
_EXECUTABLE_UPLOAD_CANDIDATE_ARM_KEYS = frozenset(
    {"observed", "marker_present", "uploaded_url"}
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


def _requires_php_object_isolation(expected_bug_class: str | None) -> bool:
    """Return whether this hypothesis can emit the trusted object oracle."""
    return "object_instantiation" in (_allowed_oracles_for(expected_bug_class) or set())


def _is_ssrf_bug_class(expected_bug_class: str | None) -> bool:
    """Return whether an exact known SSRF identifier was supplied."""
    return expected_bug_class in {BugClass.SSRF.name, BugClass.SSRF.value}


def _requires_trusted_http_isolation(expected_bug_class: str | None) -> bool:
    """Route trace-bound HTTP proofs through the existing strict boundary."""
    return (
        _is_ssrf_bug_class(expected_bug_class)
        or _requires_cross_object_isolation(expected_bug_class)
        or _requires_php_object_isolation(expected_bug_class)
    )


def php_object_rewrite_policy_from_transport(
    transport: dict[str, object] | None,
) -> PhpObjectRewritePolicy | None:
    """Build one exact, source-reviewed object destination policy."""
    if not isinstance(transport, dict):
        return None
    method = transport.get("method")
    route = transport.get("route")
    object_location = transport.get("object_location")
    object_field = transport.get("object_field")
    dispatch_value = transport.get("dispatch", {})
    if (
        not isinstance(method, str)
        or method != method.strip().upper()
        or not isinstance(route, str)
        or route != route.strip()
        or _normalize_request_path(route) != route
        or not isinstance(object_location, str)
        or not isinstance(object_field, str)
        or not isinstance(dispatch_value, dict)
    ):
        return None
    dispatch: list[tuple[str, str, str]] = []
    for raw_key, raw_value in dispatch_value.items():
        if not isinstance(raw_key, str) or not isinstance(raw_value, str):
            return None
        location, separator, field = raw_key.partition(":")
        if not separator or not location or not field:
            return None
        dispatch.append((location, field, raw_value))
    try:
        return PhpObjectRewritePolicy(
            method=method,
            path=route,
            object_location=object_location,
            object_field=object_field,
            dispatch=tuple(sorted(dispatch)),
        )
    except (UnicodeError, ValueError):
        return None


def _trusted_php_object_receipt_rejection_diagnostic(
    trace_error: str,
) -> tuple[str, dict[str, str]] | None:
    """Project a proxy receipt failure into bounded parent-owned vocabulary."""
    spec = _PHP_OBJECT_RECEIPT_REJECTION_SPECS.get(trace_error)
    if spec is None:
        return None
    reason, arm, policy_acceptance, payload_rewrite, receipt_outcome = spec
    if len(reason) > _PHP_OBJECT_RECEIPT_DIAGNOSTIC_MAX_CHARS:
        raise RuntimeError("PHP object receipt diagnostic exceeds its fixed bound")
    return (
        reason,
        {
            "source": "trusted_parent_proxy",
            "arm": arm,
            "policy_acceptance": policy_acceptance,
            "payload_rewrite": payload_rewrite,
            "upstream_response": "received",
            "receipt_outcome": receipt_outcome,
            "instantiation": "unestablished",
            "control": "unestablished",
        },
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
    local_hosts = "localhost,127.0.0.1,::1,host.docker.internal,squadrone-ssrf-relay.internal"
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


def php_include_private_marker_from_observation(
    observation: PoCObservation | None,
) -> str | None:
    """Return a PHP-include marker without matching other response oracles."""
    if observation is None or observation.oracle != "response_marker":
        return None
    if not (
        isinstance(observation.attack.get("include_path"), str)
        and isinstance(observation.control.get("include_path"), str)
    ):
        return None
    marker = observation.attack.get("marker")
    if not isinstance(marker, str) or _PHP_INCLUDE_MARKER_RE.fullmatch(marker) is None:
        return None
    return marker


def redact_php_include_private_marker(value: Any, private_marker: str) -> Any:
    """Return a persistence-safe copy with one verifier marker removed.

    This helper is deliberately marker-specific.  It does not rewrite public
    include paths or affect the response markers used by other oracle families.
    """
    if _PHP_INCLUDE_MARKER_RE.fullmatch(private_marker) is None:
        return value
    if isinstance(value, str):
        return value.replace(private_marker, _PHP_INCLUDE_REDACTED_MARKER)
    if isinstance(value, dict):
        return {
            redact_php_include_private_marker(
                key, private_marker
            ): redact_php_include_private_marker(item, private_marker)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [
            redact_php_include_private_marker(item, private_marker) for item in value
        ]
    if isinstance(value, tuple):
        return tuple(
            redact_php_include_private_marker(item, private_marker) for item in value
        )
    return value


def redact_php_include_observation(
    observation: PoCObservation | None,
    private_marker: str | None = None,
) -> PoCObservation | None:
    """Project an observation for persistence without its private marker."""
    if observation is None:
        return None
    marker = private_marker or php_include_private_marker_from_observation(observation)
    if marker is None or _PHP_INCLUDE_MARKER_RE.fullmatch(marker) is None:
        return observation.model_copy(deep=True)
    payload = redact_php_include_private_marker(
        observation.model_dump(mode="python"),
        marker,
    )
    if not isinstance(payload, dict):  # Defensive: model_dump is always a mapping.
        return observation.model_copy(deep=True)
    attack = payload.get("attack")
    if isinstance(attack, dict):
        attack["marker_sha256"] = hashlib.sha256(marker.encode("ascii")).hexdigest()
        attack["marker_redacted"] = True
    return PoCObservation.model_validate(payload)


def redact_php_include_run_result(
    result: SandboxRunResult,
    private_marker: str | None,
) -> None:
    """Remove a PHP verifier marker from every serializing result field in place."""
    if (
        private_marker is None
        or _PHP_INCLUDE_MARKER_RE.fullmatch(private_marker) is None
    ):
        return
    result.output = cast(
        str,
        redact_php_include_private_marker(result.output, private_marker),
    )
    result.response = cast(
        str | None,
        redact_php_include_private_marker(result.response, private_marker),
    )
    result.error_log = cast(
        str | None,
        redact_php_include_private_marker(result.error_log, private_marker),
    )
    result.validation_reason = cast(
        str,
        redact_php_include_private_marker(result.validation_reason, private_marker),
    )
    result.evidence = cast(
        dict,
        redact_php_include_private_marker(result.evidence, private_marker),
    )
    result.observation = redact_php_include_observation(
        result.observation,
        private_marker,
    )
    result.rejected_observation = redact_php_include_observation(
        result.rejected_observation,
        private_marker,
    )
    result.evidence["php_include_marker_sha256"] = hashlib.sha256(
        private_marker.encode("ascii")
    ).hexdigest()
    result.evidence["php_include_marker_redacted"] = True


def php_object_private_redaction_values(
    oracle: PhpObjectOracle,
) -> tuple[str, ...]:
    """Return bounded raw and transport spellings of all object-oracle secrets."""
    public = oracle.public_context()
    base_values = [
        oracle.private_callsite_path,
        oracle.private_class_name,
        oracle.private_canary_class_source.decode("ascii"),
        oracle.private_receipt_secret.hex(),
        public["attack_token"],
        public["control_token"],
    ]
    try:
        base_values = list(oracle.private_redaction_values())
    except RuntimeError:
        # A prepared oracle has no generation material until run_poc starts.
        pass

    expanded: set[str] = set()
    for value in base_values:
        if not value:
            continue
        raw = value.encode("ascii")
        expanded.update(
            {
                value,
                quote(value, safe=""),
                quote_plus(value, safe=""),
                base64.b64encode(raw).decode("ascii"),
                base64.urlsafe_b64encode(raw).decode("ascii"),
                raw.hex(),
            }
        )
    if len(expanded) > 64 or any(len(value) > 32768 for value in expanded):
        raise RuntimeError("PHP object oracle redaction material is invalid")
    return tuple(sorted(expanded, key=lambda value: (-len(value), value)))


def php_object_gadget_private_redaction_values(
    oracle: PhpObjectGadgetOracle,
    primitive: PhpObjectOracle,
    actor_receipt_secret: bytes | None = None,
) -> tuple[str, ...]:
    """Expand both natural and reused primitive secrets for output scrubbing."""
    if actor_receipt_secret is not None and (
        type(actor_receipt_secret) is not bytes or len(actor_receipt_secret) != 32
    ):
        raise ValueError("actor receipt redaction secret must be 32 bytes")
    expanded = set(php_object_private_redaction_values(primitive))
    private_values = oracle.private_redaction_values()
    if actor_receipt_secret is not None:
        private_values = (*private_values, actor_receipt_secret.hex())
    for value in private_values:
        if not value:
            continue
        raw = value.encode("ascii")
        expanded.update(
            {
                value,
                quote(value, safe=""),
                quote_plus(value, safe=""),
                base64.b64encode(raw).decode("ascii"),
                base64.urlsafe_b64encode(raw).decode("ascii"),
                raw.hex(),
            }
        )
    if len(expanded) > 128 or any(len(value) > 256 * 1024 for value in expanded):
        raise RuntimeError("PHP object gadget redaction material is invalid")
    return tuple(sorted(expanded, key=lambda value: (-len(value), value)))


def redact_php_object_private_values(
    value: Any,
    private_values: tuple[str, ...],
) -> Any:
    """Return a recursive persistence-safe copy without object-oracle material."""
    if isinstance(value, str):
        for private_value in private_values:
            value = value.replace(private_value, _PHP_OBJECT_REDACTED_VALUE)
        return value
    if isinstance(value, dict):
        return {
            redact_php_object_private_values(key, private_values): (
                redact_php_object_private_values(item, private_values)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [
            redact_php_object_private_values(item, private_values) for item in value
        ]
    if isinstance(value, tuple):
        return tuple(
            redact_php_object_private_values(item, private_values) for item in value
        )
    return value


def redact_php_object_run_result(
    result: SandboxRunResult,
    private_values: tuple[str, ...],
) -> None:
    """Remove object-oracle material from every serializing result field in place."""
    result.output = cast(
        str,
        redact_php_object_private_values(result.output, private_values),
    )
    result.response = cast(
        str | None,
        redact_php_object_private_values(result.response, private_values),
    )
    result.error_log = cast(
        str | None,
        redact_php_object_private_values(result.error_log, private_values),
    )
    result.validation_reason = cast(
        str,
        redact_php_object_private_values(result.validation_reason, private_values),
    )
    result.evidence = cast(
        dict,
        redact_php_object_private_values(result.evidence, private_values),
    )
    if result.observation is not None:
        payload = redact_php_object_private_values(
            result.observation.model_dump(mode="python"),
            private_values,
        )
        if isinstance(payload, dict):
            result.observation = PoCObservation.model_validate(payload)
    if result.rejected_observation is not None:
        payload = redact_php_object_private_values(
            result.rejected_observation.model_dump(mode="python"),
            private_values,
        )
        if isinstance(payload, dict):
            result.rejected_observation = PoCObservation.model_validate(payload)
    result.evidence["php_object_private_values_redacted"] = True


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


def _php_include_confirmation_signature(
    observation: PoCObservation,
) -> tuple | None:
    """Return the replay-stable include claim bound by each parent run."""
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
    values = (
        attack.get("include_path"),
        control.get("include_path"),
        attack.get("destination_value"),
        control.get("destination_value"),
    )
    if (
        attack_request is None
        or control_request is None
        or attack_actor is None
        or control_actor is None
        or any(not isinstance(value, str) or not value for value in values)
    ):
        return None
    return (
        attack_request,
        control_request,
        *values,
        attack_actor,
        control_actor,
        attack.get("identity_verified"),
        control.get("identity_verified"),
    )


def _executable_upload_confirmation_signature(
    observation: PoCObservation,
) -> tuple[object, ...] | None:
    """Return replay-stable facts from one parent-promoted upload proof."""
    attack = observation.attack
    control = observation.control
    if (
        observation.oracle != "response_marker"
        or attack.get("parent_attestation") != "executable_upload_v1"
        or control.get("parent_attestation") != "executable_upload_v1"
        or attack.get("identity_verified") is not True
        or control.get("identity_verified") is not True
        or attack.get("attacker_user_id") != control.get("attacker_user_id")
        or attack.get("request_fingerprint") != control.get("request_fingerprint")
    ):
        return None
    fingerprint = attack.get("request_fingerprint")
    if not isinstance(fingerprint, dict):
        return None
    return (
        json.dumps(fingerprint, sort_keys=True, separators=(",", ":")),
        _claim_identifier(attack.get("attacker_user_id")),
        normalize_attacker_role(observation.attacker_role),
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
    first_php_include = first.oracle == "response_marker" and (
        "include_path" in first.attack or "include_path" in first.control
    )
    confirmation_php_include = confirmation.oracle == "response_marker" and (
        "include_path" in confirmation.attack or "include_path" in confirmation.control
    )
    if first_php_include or confirmation_php_include:
        first_signature = _php_include_confirmation_signature(first)
        confirmation_signature = _php_include_confirmation_signature(confirmation)
        if (
            first_signature is None
            or confirmation_signature is None
            or first_signature != confirmation_signature
        ):
            return False, (
                "confirmation changed the PHP include request fingerprint, paths, "
                "destination values, actors, or identity verification"
            )
        first_marker = first.attack.get("marker")
        confirmation_marker = confirmation.attack.get("marker")
        if (
            not isinstance(first_marker, str)
            or _PHP_INCLUDE_MARKER_RE.fullmatch(first_marker) is None
            or not isinstance(confirmation_marker, str)
            or _PHP_INCLUDE_MARKER_RE.fullmatch(confirmation_marker) is None
            or hmac.compare_digest(first_marker, confirmation_marker)
        ):
            return False, (
                "confirmation did not disclose a fresh private PHP include marker"
            )
    first_executable_upload = _executable_upload_confirmation_signature(first)
    confirmation_executable_upload = _executable_upload_confirmation_signature(
        confirmation
    )
    if first_executable_upload is not None or confirmation_executable_upload is not None:
        if (
            first_executable_upload is None
            or confirmation_executable_upload is None
            or first_executable_upload != confirmation_executable_upload
        ):
            return False, (
                "confirmation changed the parent-attested executable-upload "
                "transport or actor"
            )
        first_payload = first.attack.get("payload_sha256")
        confirmation_payload = confirmation.attack.get("payload_sha256")
        first_marker = first.attack.get("marker")
        confirmation_marker = confirmation.attack.get("marker")
        if (
            not isinstance(first_payload, str)
            or _SHA256_RE.fullmatch(first_payload) is None
            or not isinstance(confirmation_payload, str)
            or _SHA256_RE.fullmatch(confirmation_payload) is None
            or hmac.compare_digest(first_payload, confirmation_payload)
            or not isinstance(first_marker, str)
            or not isinstance(confirmation_marker, str)
            or hmac.compare_digest(first_marker, confirmation_marker)
        ):
            return False, (
                "confirmation did not use a fresh parent executable-upload "
                "payload and challenge"
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


def _validated_executable_upload_url(
    value: object,
    *,
    target_url: str,
    expected_suffix: Literal[".php", ".txt"],
) -> tuple[str, str] | tuple[None, str]:
    """Return one canonical same-origin URL beneath the public uploads tree."""
    if not isinstance(value, str) or not value or value != value.strip():
        return None, "executable-upload oracle requires a nonempty absolute URL"
    if (
        not value.isascii()
        or not value.isprintable()
        or len(value.encode("ascii")) > _EXECUTABLE_UPLOAD_MAX_URL_BYTES
    ):
        return None, "executable-upload oracle URL exceeds the parent limit"
    try:
        parsed = urlsplit(value)
        username = parsed.username
        password = parsed.password
    except (TypeError, ValueError):
        return None, "executable-upload oracle URL is malformed"
    if username is not None or password is not None:
        return None, "executable-upload oracle URL must not contain credentials"
    if parsed.query or parsed.fragment:
        return None, "executable-upload oracle URL must not contain query or fragment"
    target_origin = normalize_trace_origin(target_url)
    if not target_origin or normalize_trace_origin(value) != target_origin:
        return None, "executable-upload oracle URL is outside the exact sandbox origin"
    path = parsed.path
    if (
        not path.startswith(_EXECUTABLE_UPLOAD_PATH_PREFIX)
        or not path.endswith(expected_suffix)
        or "%" in path
        or "\\" in path
        or "//" in path
        or posixpath.normpath(path) != path
        or any(part in {"", ".", ".."} for part in path.split("/")[1:])
    ):
        return None, (
            "executable-upload oracle URL must identify one canonical "
            f"{expected_suffix} file beneath /wp-content/uploads/"
        )
    return value, path


@dataclass(frozen=True, slots=True)
class _ExecutableUploadGeneration:
    generation: str
    payload: bytes
    payload_b64: str
    payload_sha256: str
    attack_filename: str
    control_filename: str


@dataclass(frozen=True, slots=True)
class _ExecutableUploadFilesystemEntry:
    kind: str
    inode: int
    mode: int
    links: int
    uid: int
    gid: int
    size: int
    sha256: str | None


@dataclass(frozen=True, slots=True)
class _ExecutableUploadFilesystemSnapshot:
    root: Literal["absent", "directory"]
    entries: dict[str, _ExecutableUploadFilesystemEntry]
    manifest_sha256: str

    def evidence(self) -> dict[str, object]:
        return {
            "root": self.root,
            "entry_count": len(self.entries),
            "manifest_sha256": self.manifest_sha256,
        }


def _new_executable_upload_generation() -> _ExecutableUploadGeneration:
    """Create exact per-execution bytes that cannot exist in a stale baseline."""
    generation = secrets.token_hex(32)
    if re.fullmatch(r"[0-9a-f]{64}", generation) is None:
        raise RuntimeError("parent executable-upload generation failed")
    payload = (
        "<?php $c=isset($_GET['"
        + EXECUTABLE_UPLOAD_CHALLENGE_PARAMETER
        + "'])?(string)$_GET['"
        + EXECUTABLE_UPLOAD_CHALLENGE_PARAMETER
        + "']:'';echo '"
        + EXECUTABLE_UPLOAD_RESPONSE_PREFIX
        + "'.hash('sha256','"
        + generation
        + ":'.$c);"
    ).encode("ascii")
    stem = f"squadrone-exec-{generation[:32]}"
    return _ExecutableUploadGeneration(
        generation=generation,
        payload=payload,
        payload_b64=base64.b64encode(payload).decode("ascii"),
        payload_sha256=hashlib.sha256(payload).hexdigest(),
        attack_filename=f"{stem}.php",
        control_filename=f"{stem}.txt",
    )


async def _snapshot_executable_upload_filesystem(
    *,
    container_name: str,
    generation: _ExecutableUploadGeneration,
) -> _ExecutableUploadFilesystemSnapshot:
    """Capture one bounded, no-symlink uploads manifest inside WordPress."""
    if not container_name:
        raise RuntimeError("executable-upload container is unavailable")
    try:
        async with asyncio.timeout(_EXECUTABLE_UPLOAD_SNAPSHOT_TIMEOUT_SECONDS):
            rc, output, _error = await _run(
                "docker",
                "exec",
                container_name,
                "timeout",
                "--signal=TERM",
                "--kill-after=1",
                f"{_EXECUTABLE_UPLOAD_SNAPSHOT_INNER_TIMEOUT_SECONDS}s",
                "php",
                "-r",
                _EXECUTABLE_UPLOAD_SNAPSHOT_SCRIPT,
                "--",
                str(len(generation.payload)),
                check=False,
            )
    except TimeoutError as exc:
        raise RuntimeError("executable-upload filesystem snapshot timed out") from exc
    encoded = output.encode("utf-8", errors="strict")
    if rc != 0 or not encoded or len(encoded) > _EXECUTABLE_UPLOAD_SNAPSHOT_MAX_BYTES:
        raise RuntimeError("executable-upload filesystem snapshot failed")
    try:
        document = json.loads(output)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("executable-upload filesystem snapshot is malformed") from exc
    if (
        not isinstance(document, dict)
        or set(document) != {"version", "root", "entries"}
        or document.get("version") != 1
        or document.get("root") not in {"absent", "directory"}
        or not isinstance(document.get("entries"), list)
        or len(document["entries"]) > _EXECUTABLE_UPLOAD_SNAPSHOT_MAX_ENTRIES
        or (document.get("root") == "absent" and document["entries"])
    ):
        raise RuntimeError("executable-upload filesystem snapshot is malformed")
    entries: dict[str, _ExecutableUploadFilesystemEntry] = {}
    required = {
        "path",
        "kind",
        "inode",
        "mode",
        "links",
        "uid",
        "gid",
        "size",
        "sha256",
    }
    for item in document["entries"]:
        if not isinstance(item, dict) or set(item) != required:
            raise RuntimeError("executable-upload snapshot entry is malformed")
        path = item.get("path")
        kind = item.get("kind")
        digest = item.get("sha256")
        numeric = [
            item.get("inode"),
            item.get("mode"),
            item.get("links"),
            item.get("uid"),
            item.get("gid"),
            item.get("size"),
        ]
        if (
            not isinstance(path, str)
            or not path
            or path.startswith("/")
            or "\\" in path
            or path != posixpath.normpath(path)
            or any(part in {"", ".", ".."} for part in path.split("/"))
            or len(path.encode("utf-8")) > _EXECUTABLE_UPLOAD_SNAPSHOT_MAX_PATH_BYTES
            or path in entries
            or kind not in {"f", "d", "l", "o"}
            or any(
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
                for value in numeric
            )
            or (
                digest is not None
                and (
                    not isinstance(digest, str)
                    or _SHA256_RE.fullmatch(digest) is None
                )
            )
            or (kind != "f" and digest is not None)
            or (
                kind == "f"
                and item.get("size") == len(generation.payload)
                and digest is None
            )
        ):
            raise RuntimeError("executable-upload snapshot entry is malformed")
        entries[path] = _ExecutableUploadFilesystemEntry(
            kind=cast(str, kind),
            inode=cast(int, item["inode"]),
            mode=cast(int, item["mode"]),
            links=cast(int, item["links"]),
            uid=cast(int, item["uid"]),
            gid=cast(int, item["gid"]),
            size=cast(int, item["size"]),
            sha256=cast(str | None, digest),
        )
    return _ExecutableUploadFilesystemSnapshot(
        root=cast(Literal["absent", "directory"], document["root"]),
        entries=entries,
        manifest_sha256=hashlib.sha256(encoded).hexdigest(),
    )


def _executable_upload_relative_path(url: str) -> str:
    path = urlsplit(url).path
    if not path.startswith(_EXECUTABLE_UPLOAD_PATH_PREFIX):
        return ""
    relative = path.removeprefix(_EXECUTABLE_UPLOAD_PATH_PREFIX)
    if (
        not relative
        or relative != posixpath.normpath(relative)
        or any(part in {"", ".", ".."} for part in relative.split("/"))
    ):
        return ""
    return relative


def _validate_executable_upload_snapshot_transitions(
    binding: _ExecutableUploadTraceBinding,
    *,
    generation: _ExecutableUploadGeneration,
    snapshots: dict[
        tuple[Literal["before", "after"], Literal["attack", "control"]],
        _ExecutableUploadFilesystemSnapshot,
    ],
) -> tuple[bool, str, dict[str, object]]:
    """Bind each returned URL to the exact file introduced by its request."""
    order = _EXECUTABLE_UPLOAD_ATTESTATION_ORDER
    evidence: dict[str, object] = {}
    for phase, arm in order:
        snapshot = snapshots.get((phase, arm))
        if snapshot is not None:
            evidence[f"{phase}_{arm}"] = snapshot.evidence()
    if tuple(snapshots) != order:
        return False, "executable-upload arm snapshots are incomplete", evidence
    attack_path = _executable_upload_relative_path(binding.attack_url)
    control_path = _executable_upload_relative_path(binding.control_url)
    if not attack_path or not control_path or attack_path == control_path:
        return False, "executable-upload snapshot paths are invalid", evidence
    before_attack = snapshots[("before", "attack")]
    after_attack = snapshots[("after", "attack")]
    before_control = snapshots[("before", "control")]
    after_control = snapshots[("after", "control")]
    attack_after = after_attack.entries.get(attack_path)
    control_after = after_control.entries.get(control_path)
    if (
        attack_path in before_attack.entries
        or control_path in before_attack.entries
        or attack_after is None
        or attack_after.kind != "f"
        or attack_after.links != 1
        or attack_after.size != len(generation.payload)
        or attack_after.sha256 != generation.payload_sha256
    ):
        return False, "attack upload was not a fresh exact file", evidence
    if (
        before_control.entries.get(attack_path) != attack_after
        or control_path in after_attack.entries
        or control_path in before_control.entries
        or control_after is None
        or control_after.kind != "f"
        or control_after.links != 1
        or control_after.size != len(generation.payload)
        or control_after.sha256 != generation.payload_sha256
    ):
        return False, "control upload was not a fresh exact file", evidence
    if after_control.entries.get(attack_path) != attack_after:
        return False, "control request changed the attack upload", evidence
    evidence["attack_path"] = attack_path
    evidence["control_path"] = control_path
    evidence["payload_sha256"] = generation.payload_sha256
    return True, "executable-upload arm snapshot transitions passed", evidence


@dataclass(frozen=True, slots=True)
class _ExecutableUploadTraceBinding:
    request_url: str
    attacker_role: str
    attacker_user_id: int
    attack_url: str
    control_url: str
    attack_status_code: int
    control_status_code: int
    attack_sequence: int
    control_sequence: int
    request_fingerprint: dict[str, object]
    evidence: dict[str, object]


@dataclass(frozen=True, slots=True)
class _ExecutableUploadProbeResponse:
    status_code: int
    body: bytes
    overflow: bool


async def _read_executable_upload_probe(
    client: httpx.AsyncClient,
    url: str,
    challenge: str,
) -> _ExecutableUploadProbeResponse:
    """Read one parent probe response with a fixed in-memory bound."""
    payload = bytearray()
    overflow = False
    async with client.stream(
        "GET",
        url,
        params={EXECUTABLE_UPLOAD_CHALLENGE_PARAMETER: challenge},
        headers={"Accept-Encoding": "identity"},
    ) as response:
        async for chunk in response.aiter_bytes():
            remaining = _EXECUTABLE_UPLOAD_MAX_RESPONSE_BYTES - len(payload)
            if len(chunk) > remaining:
                payload.extend(chunk[:remaining])
                overflow = True
                break
            payload.extend(chunk)
    return _ExecutableUploadProbeResponse(
        status_code=response.status_code,
        body=bytes(payload),
        overflow=overflow,
    )


def _executable_upload_probe_evidence(
    response: _ExecutableUploadProbeResponse,
    *,
    normalized_path: str,
) -> dict[str, object]:
    """Return bounded, value-free evidence for one parent-owned probe."""
    return {
        "path": normalized_path,
        "status_code": response.status_code,
        "response_complete": not response.overflow,
        "response_size_bytes": len(response.body) if not response.overflow else None,
        "response_sha256": (
            hashlib.sha256(response.body).hexdigest() if not response.overflow else None
        ),
    }


async def _attest_executable_upload_response_marker(
    binding: _ExecutableUploadTraceBinding,
    *,
    target_url: str,
    generation: _ExecutableUploadGeneration,
) -> tuple[bool, str, dict[str, object]]:
    """Prove exact uploaded bytes with a fresh post-process parent challenge."""
    attack_url, attack_value = _validated_executable_upload_url(
        binding.attack_url,
        target_url=target_url,
        expected_suffix=".php",
    )
    if attack_url is None:
        return False, f"attack {attack_value}", {}
    control_url, control_value = _validated_executable_upload_url(
        binding.control_url,
        target_url=target_url,
        expected_suffix=".txt",
    )
    if control_url is None:
        return False, f"control {control_value}", {}
    attack_path = attack_value
    control_path = control_value
    if attack_path == control_path:
        return (
            False,
            "executable-upload oracle requires distinct normalized attack/control paths",
            {},
        )

    challenge = secrets.token_hex(32)
    if re.fullmatch(r"[0-9a-f]{64}", challenge) is None:
        return False, "parent executable-upload challenge generation failed", {}
    challenge_digest = hashlib.sha256(challenge.encode("ascii")).hexdigest()
    execution_digest = hashlib.sha256(
        f"{generation.generation}:{challenge}".encode("ascii")
    ).hexdigest()
    expected_body = (
        EXECUTABLE_UPLOAD_RESPONSE_PREFIX + execution_digest
    ).encode("ascii")
    try:
        async with httpx.AsyncClient(
            follow_redirects=False,
            trust_env=False,
            timeout=_EXECUTABLE_UPLOAD_PROBE_TIMEOUT_SECONDS,
        ) as client:
            attack_response = await _read_executable_upload_probe(
                client,
                attack_url,
                challenge,
            )
            control_response = await _read_executable_upload_probe(
                client,
                control_url,
                challenge,
            )
    except (httpx.HTTPError, OSError):
        return False, "parent executable-upload HTTP probe failed", {}

    evidence: dict[str, object] = {
        "oracle": "executable_upload_response_marker",
        "challenge_sha256": challenge_digest,
        "payload_sha256": generation.payload_sha256,
        "response_marker": expected_body.decode("ascii"),
        "attack": _executable_upload_probe_evidence(
            attack_response,
            normalized_path=attack_path,
        ),
        "control": _executable_upload_probe_evidence(
            control_response,
            normalized_path=control_path,
        ),
    }
    if (
        attack_response.status_code != 200
        or attack_response.overflow
        or not hmac.compare_digest(attack_response.body, expected_body)
    ):
        return (
            False,
            "parent executable-upload attack challenge did not execute",
            evidence,
        )
    if (
        control_response.status_code != 200
        or control_response.overflow
        or not hmac.compare_digest(control_response.body, generation.payload)
    ):
        return (
            False,
            "parent executable-upload control did not preserve the exact inert bytes",
            evidence,
        )
    return True, "parent executable-upload challenge attestation passed", evidence


def _candidate_request_transport(
    request: object,
    *,
    target_url: str,
) -> tuple[
    tuple[str, str, str, tuple[tuple[str, str], ...]] | None,
    str,
    str,
]:
    """Canonicalize the child's inert request pointer without trusting it."""
    if not isinstance(request, dict) or set(request) != {"method", "url"}:
        return None, "", "candidate request must contain only method and url"
    method = request.get("method")
    value = request.get("url")
    if not isinstance(method, str) or not isinstance(value, str):
        return None, "", "candidate request method and url must be strings"
    if method != "POST":
        return None, "", "candidate request method must be exact POST"
    try:
        parsed = urlsplit(value)
        pairs = parse_qsl(
            parsed.query,
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=64,
        )
    except (TypeError, ValueError):
        return None, "", "candidate request URL is malformed"
    raw_path = parsed.path or "/"
    normalized_path = _normalize_request_path(raw_path)
    if (
        value != value.strip()
        or not value.isascii()
        or len(value.encode("ascii")) > _EXECUTABLE_UPLOAD_MAX_URL_BYTES
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or raw_path != normalized_path
        or "%" in raw_path
        or "\\" in raw_path
        or "//" in raw_path
        or re.search(r"%(?![0-9A-Fa-f]{2})", parsed.query) is not None
        or normalize_trace_origin(value) != normalize_trace_origin(target_url)
        or len({name for name, _item in pairs}) != len(pairs)
        or any(not name or not item for name, item in pairs)
    ):
        return None, "", "candidate request URL is not an exact sandbox URL"
    dispatch = {f"query:{name}": item for name, item in pairs}
    signature = _canonical_http_transport(method, raw_path, dispatch)
    if signature is None:
        return None, "", "candidate request transport is malformed"
    return signature, value, ""


def _expected_executable_upload_transport(
    value: object,
) -> tuple[str, str, str, tuple[tuple[str, str], ...]] | None:
    """Accept only one source-derived method, route, and dispatch contract."""
    if not isinstance(value, dict) or set(value) != {"method", "route", "dispatch"}:
        return None
    signature = _canonical_http_transport(
        value.get("method"),
        value.get("route"),
        value.get("dispatch"),
    )
    if (
        signature is None
        or signature[0] != "POST"
        or (
            signature[1] == "path"
            and signature[2] in _CROSS_OBJECT_SHARED_ROUTES
            and not signature[3]
        )
    ):
        return None
    return signature


def _executable_upload_policy(
    value: object,
    generation: _ExecutableUploadGeneration,
) -> ExecutableUploadPolicy | None:
    """Build the proxy-private policy from one canonical source transport."""
    signature = _expected_executable_upload_transport(value)
    if signature is None:
        return None
    method, route_kind, route, dispatch = signature
    policy_dispatch: list[tuple[str, str, str]] = []
    for key, expected in dispatch:
        location, separator, name = key.partition(":")
        if not separator:
            return None
        policy_dispatch.append((location, name, expected))
    try:
        return ExecutableUploadPolicy(
            method=method,
            route_kind=cast(Literal["path", "wordpress_rest"], route_kind),
            route=route,
            dispatch=tuple(policy_dispatch),
            payload=generation.payload,
            attack_filename=generation.attack_filename,
            control_filename=generation.control_filename,
        )
    except ValueError:
        return None


def _candidate_matches_executable_upload_transport(
    candidate: tuple[str, str, str, tuple[tuple[str, str], ...]],
    expected: tuple[str, str, str, tuple[tuple[str, str], ...]],
) -> bool:
    """Compare only the method/route/query facts representable in a URL."""
    if candidate[:3] != expected[:3]:
        return False
    expected_query_dispatch = tuple(
        (key, value)
        for key, value in expected[3]
        if key.startswith("query:")
    )
    return candidate[3] == expected_query_dispatch


def _trace_matches_executable_upload_transport(
    record: dict,
    signature: tuple[str, str, str, tuple[tuple[str, str], ...]],
    *,
    trace_salt: bytes,
    target_url: str,
) -> bool:
    """Bind one completed proxy record to the parent-derived upload route."""
    method, route_kind, route_value, dispatch = signature
    if (
        record.get("trace_version") != 1
        or record.get("record_type") != "request"
        or record.get("forward_state") != "completed"
        or record.get("forward_error") is not None
        or record.get("terminal") is not False
        or record.get("request_body_parse_error") is not None
        or record.get("request_metadata_omitted") is not None
        or record.get("response_capture_omitted") is not None
        or record.get("origin") != normalize_trace_origin(target_url)
        or str(record.get("method") or "").upper() != method
    ):
        return False
    raw_path = str(record.get("path") or "")
    path = _normalize_request_path(raw_path)
    if (
        raw_path != path
        or "%" in raw_path
        or "\\" in raw_path
        or "//" in raw_path
    ):
        return False
    rest_alias = False
    if route_kind == "wordpress_rest":
        direct_path = "/wp-json" + route_value
        rest_digests = _trace_field_digests(record, "query", "rest_route")
        if path == direct_path:
            if rest_digests != []:
                return False
        elif path == "/":
            rest_alias = True
            if rest_digests != [salted_scalar_sha256(route_value, trace_salt)]:
                return False
        else:
            return False
    elif route_kind == "path":
        if path != route_value:
            return False
    else:
        return False
    fields = record.get("fields")
    if not isinstance(fields, list):
        return False
    allowed_query_names = {
        key.split(":", 1)[1]
        for key, _expected in dispatch
        if key.startswith("query:")
    }
    if rest_alias:
        allowed_query_names.add("rest_route")
    if any(
        isinstance(field, dict)
        and field.get("location") == "query"
        and field.get("name") not in allowed_query_names
        for field in fields
    ):
        return False
    def dispatch_locations(location: str) -> tuple[str, ...]:
        return ("form", "multipart") if location == "form" else (location,)

    if not all(
        [
            digest
            for wire_location in dispatch_locations(key.split(":", 1)[0])
            for digest in _trace_field_digests(
                record,
                wire_location,
                key.split(":", 1)[1],
            )
        ]
        == [salted_scalar_sha256(expected, trace_salt)]
        for key, expected in dispatch
    ):
        return False
    expected_identities = {
        (wire_location, key.split(":", 1)[1])
        for key, _expected in dispatch
        for wire_location in dispatch_locations(key.split(":", 1)[0])
    }
    dispatch_names = {key.split(":", 1)[1] for key, _expected in dispatch}
    return all(
        not _trace_field_digests(record, location, name)
        for name in dispatch_names
        for location in _CROSS_OBJECT_FIELD_LOCATIONS
        if (location, name) not in expected_identities
    )


def _trace_json_contains_exact_string(record: dict, expected: str) -> bool:
    """Find one exact JSON string leaf in a complete parent-captured response."""
    parts = _trace_body_parts(record)
    if parts is None:
        return False
    head, tail, truncated = parts
    if truncated or tail:
        return False
    try:
        document = json.loads(head.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, ValueError, TypeError):
        return False
    stack = [document]
    visited = 0
    matches = 0
    while stack:
        visited += 1
        if visited > 10_000:
            return False
        item = stack.pop()
        if isinstance(item, str):
            matches += int(item == expected)
        elif isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return matches == 1


def _executable_upload_trace_fields(
    record: dict,
) -> tuple[tuple[object, ...], ...] | None:
    """Return a fully validated digest-only request-field signature."""
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
        value_sha256 = field.get("value_sha256")
        content_sha256 = field.get("content_sha256")
        if (
            location not in _CROSS_OBJECT_FIELD_LOCATIONS
            or not isinstance(name, str)
            or not name
            or kind not in {"scalar", "file"}
            or not isinstance(value_sha256, str)
            or _SHA256_RE.fullmatch(value_sha256) is None
            or (
                kind == "file"
                and (
                    not isinstance(content_sha256, str)
                    or _SHA256_RE.fullmatch(content_sha256) is None
                )
            )
            or (kind == "scalar" and content_sha256 is not None)
        ):
            return None
        normalized.append(
            (location, name, kind, value_sha256, content_sha256 or "")
        )
    return tuple(sorted(normalized))


def _upload_payload_fields(
    fields: tuple[tuple[object, ...], ...],
    *,
    generation: _ExecutableUploadGeneration,
    trace_salt: bytes,
) -> tuple[tuple[object, ...], ...]:
    raw_payload = generation.payload.decode("ascii")
    scalar_digests = {
        salted_scalar_sha256(generation.payload_b64, trace_salt),
        salted_scalar_sha256(raw_payload, trace_salt),
    }
    return tuple(
        field
        for field in fields
        if (
            field[2] == "scalar"
            and field[3] in scalar_digests
            or field[2] == "file"
            and field[4]
            == salted_file_content_sha256(generation.payload, trace_salt)
        )
    )


def _upload_filename_fields(
    fields: tuple[tuple[object, ...], ...],
    *,
    filename: str,
    trace_salt: bytes,
) -> tuple[tuple[object, ...], ...]:
    filename_digest = salted_scalar_sha256(filename, trace_salt)
    return tuple(field for field in fields if field[3] == filename_digest)


def _parent_actor_from_upload_record(
    record: dict,
    *,
    expected_attacker_role: str,
    receipt_secret: bytes,
    trace_token: str,
) -> tuple[dict | None, str]:
    actor, reason = _decode_actor_receipt(
        record,
        receipt_secret=receipt_secret,
        trace_token=trace_token,
    )
    if actor is None:
        return None, reason
    if not _receipt_has_only_expected_privileges(actor, expected_attacker_role):
        return None, "upload trace actor did not have only the expected privileges"
    return actor, ""


def _prepare_executable_upload_candidate(
    observation: PoCObservation,
    *,
    trace_records: list[dict],
    trace_salt: bytes,
    target_url: str,
    expected_http_transport: dict[str, object] | None,
    expected_attacker_role: str | None,
    receipt_secret: bytes,
    trace_token: str,
    generation: _ExecutableUploadGeneration,
) -> tuple[_ExecutableUploadTraceBinding | None, str]:
    """Bind a claim-free child handoff to parent-owned upload trace facts."""
    if (
        len(trace_salt) < 16
        or len(receipt_secret) < 16
        or not trace_token
        or normalize_attacker_role(expected_attacker_role) == UNKNOWN_ATTACKER_ROLE
    ):
        return None, "executable-upload parent trace context is unavailable"
    if observation.oracle != "response_marker":
        return None, "executable-upload candidate requires response_marker"
    if observation.verdict != "not_vulnerable":
        return None, (
            "executable-upload candidate must defer the vulnerable verdict to the "
            "parent challenge"
        )
    if any(
        getattr(observation.impact, dimension) != "none"
        for dimension in ("confidentiality", "integrity", "availability")
    ):
        return None, (
            "executable-upload candidate must defer CIA impact to the parent challenge"
        )
    if normalize_attacker_role(observation.attacker_role) != normalize_attacker_role(
        expected_attacker_role
    ):
        return None, "executable-upload candidate used the wrong attacker role"
    for arm_name, arm in (("attack", observation.attack), ("control", observation.control)):
        if set(arm) != _EXECUTABLE_UPLOAD_CANDIDATE_ARM_KEYS:
            return None, (
                f"executable-upload {arm_name} candidate must contain only "
                "observed, marker_present, and uploaded_url"
            )
        if arm.get("observed") is not False or arm.get("marker_present") is not False:
            return None, (
                "executable-upload candidate must leave both proof arms unobserved"
            )

    expected_transport = _expected_executable_upload_transport(expected_http_transport)
    if expected_transport is None:
        return None, "executable-upload source transport is unavailable"
    candidate_transport, request_url, request_error = _candidate_request_transport(
        observation.request,
        target_url=target_url,
    )
    if candidate_transport is None:
        return None, request_error
    if not _candidate_matches_executable_upload_transport(
        candidate_transport,
        expected_transport,
    ):
        return None, "executable-upload candidate changed the source-derived transport"

    attack_url, attack_path = _validated_executable_upload_url(
        observation.attack.get("uploaded_url"),
        target_url=target_url,
        expected_suffix=".php",
    )
    if attack_url is None:
        return None, f"attack {attack_path}"
    control_url, control_path = _validated_executable_upload_url(
        observation.control.get("uploaded_url"),
        target_url=target_url,
        expected_suffix=".txt",
    )
    if control_url is None:
        return None, f"control {control_path}"
    if attack_path == control_path:
        return None, "executable-upload candidate returned one path for both arms"

    payload_records: list[
        tuple[dict, tuple[tuple[object, ...], ...], tuple[tuple[object, ...], ...]]
    ] = []
    for record in trace_records:
        if not isinstance(record, dict):
            return None, "executable-upload HTTP trace contains a malformed record"
        fields = _executable_upload_trace_fields(record)
        if fields is None:
            continue
        payload_fields = _upload_payload_fields(
            fields,
            generation=generation,
            trace_salt=trace_salt,
        )
        if not payload_fields:
            continue
        if len(payload_fields) != 1:
            return None, "executable-upload request has an ambiguous payload carrier"
        if not _trace_matches_executable_upload_transport(
            record,
            expected_transport,
            trace_salt=trace_salt,
            target_url=target_url,
        ):
            return None, "exact executable-upload payload used an unexpected transport"
        payload_records.append((record, fields, payload_fields))
    if len(payload_records) != 2:
        return None, "executable-upload proof requires exactly two payload requests"

    matched: dict[
        str,
        tuple[dict, tuple[tuple[object, ...], ...], dict],
    ] = {}
    for label, filename, uploaded_url in (
        ("attack", generation.attack_filename, attack_url),
        ("control", generation.control_filename, control_url),
    ):
        candidates: list[tuple[dict, tuple[tuple[object, ...], ...], dict]] = []
        for record, fields, _payload_fields in payload_records:
            filename_fields = _upload_filename_fields(
                fields,
                filename=filename,
                trace_salt=trace_salt,
            )
            if len(filename_fields) != 1:
                continue
            status = record.get("status_code")
            if (
                not isinstance(status, int)
                or isinstance(status, bool)
                or not 200 <= status < 300
                or not _trace_json_contains_exact_string(record, uploaded_url)
            ):
                continue
            actor, actor_reason = _parent_actor_from_upload_record(
                record,
                expected_attacker_role=expected_attacker_role or "",
                receipt_secret=receipt_secret,
                trace_token=trace_token,
            )
            if actor is None:
                return None, f"{label} {actor_reason}"
            candidates.append((record, fields, actor))
        if len(candidates) != 1:
            return None, (
                f"executable-upload trace did not uniquely bind the {label} response"
            )
        matched[label] = candidates[0]

    attack_record, attack_fields, attack_actor = matched["attack"]
    control_record, control_fields, control_actor = matched["control"]
    if attack_record is control_record:
        return None, "one executable-upload request matched both proof arms"
    attack_sequence = attack_record.get("sequence")
    control_sequence = control_record.get("sequence")
    if (
        not isinstance(attack_sequence, int)
        or isinstance(attack_sequence, bool)
        or not isinstance(control_sequence, int)
        or isinstance(control_sequence, bool)
        or control_sequence != attack_sequence + 1
    ):
        return None, "executable-upload attack/control request order changed"
    if attack_actor.get("user_id") != control_actor.get("user_id"):
        return None, "executable-upload arms used different signed actors"
    for field_name in ("request_nonce", "request_digest"):
        attack_value = attack_record.get(field_name)
        control_value = control_record.get(field_name)
        if (
            not isinstance(attack_value, str)
            or _SHA256_RE.fullmatch(attack_value) is None
            or not isinstance(control_value, str)
            or _SHA256_RE.fullmatch(control_value) is None
            or hmac.compare_digest(attack_value, control_value)
        ):
            return None, (
                "executable-upload arms lack distinct parent request bindings"
            )

    login_records = 0
    for record in trace_records:
        if not isinstance(record, dict):
            return None, "executable-upload HTTP trace contains a malformed record"
        method = str(record.get("method") or "").upper()
        if method not in {"POST", "PUT", "PATCH", "DELETE"}:
            continue
        if record is attack_record or record is control_record:
            continue
        if (
            method == "POST"
            and _normalize_request_path(str(record.get("path") or ""))
            == "/wp-login.php"
            and isinstance(record.get("sequence"), int)
            and not isinstance(record.get("sequence"), bool)
            and cast(int, record["sequence"]) < attack_sequence
            and record.get("forward_state") == "completed"
            and record.get("forward_error") is None
        ):
            login_records += 1
            continue
        return None, (
            "executable-upload proof used an additional mutating HTTP request"
        )
    if login_records > 1 or (
        normalize_attacker_role(expected_attacker_role) == "unauthenticated"
        and login_records
    ):
        return None, "executable-upload proof used an unexpected login sequence"

    attack_filename_fields = set(
        _upload_filename_fields(
            attack_fields,
            filename=generation.attack_filename,
            trace_salt=trace_salt,
        )
    )
    control_filename_fields = set(
        _upload_filename_fields(
            control_fields,
            filename=generation.control_filename,
            trace_salt=trace_salt,
        )
    )
    if (
        tuple(field for field in attack_fields if field not in attack_filename_fields)
        != tuple(field for field in control_fields if field not in control_filename_fields)
        or _trace_parameter_shape(attack_record) != _trace_parameter_shape(control_record)
    ):
        return None, "executable-upload arms changed fields beyond the filename"

    actor_id = attack_actor.get("user_id")
    if not isinstance(actor_id, int) or isinstance(actor_id, bool) or actor_id < 0:
        return None, "executable-upload trace actor is malformed"
    request_fingerprint: dict[str, object] = {
        "method": expected_transport[0],
        "route_kind": expected_transport[1],
        "route": expected_transport[2],
        "dispatch": dict(expected_transport[3]),
    }
    evidence: dict[str, object] = {
        "oracle": "executable_upload_http_trace",
        "payload_sha256": generation.payload_sha256,
        "request_fingerprint": request_fingerprint,
        "attack": {
            "sequence": attack_sequence,
            "path": attack_record.get("path"),
            "status_code": attack_record.get("status_code"),
            "actor_user_id": actor_id,
            "actor_roles": attack_actor.get("roles"),
            "uploaded_path": attack_path,
        },
        "control": {
            "sequence": control_sequence,
            "path": control_record.get("path"),
            "status_code": control_record.get("status_code"),
            "actor_user_id": actor_id,
            "actor_roles": control_actor.get("roles"),
            "uploaded_path": control_path,
        },
    }
    return (
        _ExecutableUploadTraceBinding(
            request_url=request_url,
            attacker_role=normalize_attacker_role(expected_attacker_role),
            attacker_user_id=actor_id,
            attack_url=attack_url,
            control_url=control_url,
            attack_status_code=cast(int, attack_record["status_code"]),
            control_status_code=cast(int, control_record["status_code"]),
            attack_sequence=attack_sequence,
            control_sequence=control_sequence,
            request_fingerprint=request_fingerprint,
            evidence=evidence,
        ),
        "executable-upload candidate is bound to two signed upload requests",
    )


def _parent_executable_upload_observation(
    binding: _ExecutableUploadTraceBinding,
    *,
    generation: _ExecutableUploadGeneration,
    response_marker: str,
) -> PoCObservation:
    """Construct the final observation exclusively from parent-validated facts."""
    actor: int | str = binding.attacker_user_id
    if binding.attacker_role == "unauthenticated":
        actor = "anonymous"
    common = {
        "attacker_user_id": actor,
        "identity_verified": True,
        "upload_accepted": True,
        "payload_sha256": generation.payload_sha256,
        "parent_attestation": "executable_upload_v1",
        "request_fingerprint": binding.request_fingerprint,
    }
    return PoCObservation(
        verdict="vulnerable",
        oracle="response_marker",
        attacker_role=binding.attacker_role,
        request={"method": "POST", "url": binding.request_url},
        attack={
            **common,
            "observed": True,
            "marker": response_marker,
            "marker_present": True,
            "uploaded_url": binding.attack_url,
            "status_code": binding.attack_status_code,
            "upload_filename": generation.attack_filename,
        },
        control={
            **common,
            "observed": False,
            "marker_present": False,
            "uploaded_url": binding.control_url,
            "status_code": binding.control_status_code,
            "upload_filename": generation.control_filename,
        },
        impact=CIAImpact(
            confidentiality="high",
            integrity="high",
            availability="high",
            description=EXECUTABLE_UPLOAD_IMPACT_DESCRIPTION,
        ),
    )


async def _attest_executable_upload_filesystem(
    binding: _ExecutableUploadTraceBinding,
    *,
    container_name: str,
    generation: _ExecutableUploadGeneration,
) -> tuple[bool, str, dict[str, object]]:
    """Re-measure the two exact files through the bounded PHP manifest."""
    try:
        snapshot = await _snapshot_executable_upload_filesystem(
            container_name=container_name,
            generation=generation,
        )
    except RuntimeError:
        return False, "parent executable-upload filesystem is unavailable", {}
    measurements: dict[str, object] = {}
    for label, url in (("attack", binding.attack_url), ("control", binding.control_url)):
        path = _executable_upload_relative_path(url)
        entry = snapshot.entries.get(path)
        if (
            not path
            or entry is None
            or entry.kind != "f"
            or entry.links != 1
            or entry.size != len(generation.payload)
            or entry.sha256 != generation.payload_sha256
        ):
            return (
                False,
                f"parent executable-upload {label} filesystem metadata mismatch",
                measurements,
            )
        measurements[label] = {
            "path": urlsplit(url).path,
            "file_type": "regular",
            "link_count": entry.links,
            "owner_uid": entry.uid,
            "owner_gid": entry.gid,
            "mode": entry.mode,
            "size_bytes": entry.size,
            "sha256": entry.sha256,
            "inode": entry.inode,
        }
    return True, "parent executable-upload filesystem attestation passed", measurements


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


def _ssrf_relay_apache_config(port: int) -> str:
    """Build one literal, fixed-path relay to a validated parent oracle port."""
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError("SSRF relay port must be a high TCP port")
    upstream = f"http://{_SSRF_RELAY_GATEWAY_HOST}:{port}{_SSRF_ORACLE_PATH_PREFIX}"
    return "\n".join(
        (
            f"Listen {port}",
            f"<VirtualHost *:{port}>",
            f"    ServerName {_SSRF_ORACLE_HOST}",
            "    ProxyRequests Off",
            "    ProxyPreserveHost On",
            "    ProxyAddHeaders Off",
            "    ProxyPassInterpolateEnv Off",
            "    ProxyPassInherit Off",
            "    UseCanonicalName Off",
            "    AllowEncodedSlashes NoDecode",
            '    <Location "/">',
            "        Require all denied",
            "    </Location>",
            f'    <Location "{_SSRF_ORACLE_PATH_PREFIX}">',
            "        Require all granted",
            "    </Location>",
            f'    ProxyPass "{_SSRF_ORACLE_PATH_PREFIX}" "{upstream}" nocanon',
            f'    ProxyPassReverse "{_SSRF_ORACLE_PATH_PREFIX}" "{upstream}"',
            "</VirtualHost>",
            "",
        )
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


def _php_include_attestation_scalar_shape_is_valid(
    snapshot: PhpIncludeOracleSnapshot,
    provisioning: PhpIncludeProvisioningAttestation,
    verification: PhpIncludeVerificationAttestation,
    filesystems: tuple[
        PhpIncludeFilesystemAttestation,
        PhpIncludeFilesystemAttestation,
        PhpIncludeFilesystemAttestation,
    ],
    host_filesystems: tuple[
        PhpIncludeHostFilesystemAttestation,
        PhpIncludeHostFilesystemAttestation,
        PhpIncludeHostFilesystemAttestation,
    ],
) -> bool:
    """Reject object-level attestation corruption before typed comparisons."""
    try:
        string_values = (
            snapshot.mode,
            snapshot.generation_id,
            provisioning.generation_id,
            provisioning.attack_basename_sha256,
            provisioning.control_basename_sha256,
            provisioning.header_name_sha256,
            provisioning.marker_sha256,
            verification.generation_id,
            *(
                value
                for filesystem in filesystems
                for value in (
                    filesystem.attack_path_sha256,
                    filesystem.control_path_sha256,
                    filesystem.attack_content_sha256,
                )
            ),
            *(
                value
                for filesystem in host_filesystems
                for value in (
                    filesystem.host_identity_sha256,
                    filesystem.attack_content_sha256,
                )
            ),
        )
        integer_values = (
            snapshot.schema_version,
            provisioning.schema_version,
            provisioning.started_monotonic_ns,
            verification.schema_version,
            verification.execution_started_monotonic_ns,
            verification.execution_finished_monotonic_ns,
            *(
                value
                for filesystem in filesystems
                for value in (
                    filesystem.schema_version,
                    filesystem.attack_content_size_bytes,
                    filesystem.attack_owner_uid,
                    filesystem.attack_owner_gid,
                    filesystem.attack_file_mode,
                    filesystem.attack_link_count,
                    filesystem.measured_monotonic_ns,
                )
            ),
            *(
                value
                for filesystem in host_filesystems
                for value in (
                    filesystem.schema_version,
                    filesystem.attack_content_size_bytes,
                    filesystem.attack_file_mode,
                    filesystem.attack_link_count,
                    filesystem.measured_monotonic_ns,
                )
            ),
        )
        boolean_values = (
            *(
                value
                for filesystem in filesystems
                for value in (
                    filesystem.attack_is_regular_file,
                    filesystem.attack_is_symlink,
                    filesystem.control_lstat_exists,
                )
            ),
            *(
                value
                for filesystem in host_filesystems
                for value in (
                    filesystem.attack_owner_matches_verifier,
                    filesystem.attack_is_regular_file,
                    filesystem.attack_is_symlink,
                    filesystem.control_lstat_exists,
                )
            ),
        )
    except AttributeError:
        return False
    return (
        all(type(value) is str for value in string_values)
        and all(type(value) is int for value in integer_values)
        and all(type(value) is bool for value in boolean_values)
    )


def _validate_php_include_oracle_snapshot(
    snapshot: object,
    *,
    marker: str,
    expected_generation_id: str,
    attack_path: str,
    control_path: str,
    attack_record: dict,
    control_record: dict,
) -> tuple[bool, str, dict[str, object]]:
    """Bind immutable canary state to the two supervised HTTP requests."""
    if type(snapshot) is not PhpIncludeOracleSnapshot:
        return False, "PHP include snapshot has an invalid type", {}
    try:
        provisioning = snapshot.provisioning
        verification = snapshot.verification
        provisioning_filesystem = provisioning.filesystem
        provisioning_host_filesystem = provisioning.host_filesystem
        verification_before = verification.before
        verification_host_before = verification.host_before
        verification_after = verification.after
        verification_host_after = verification.host_after
    except AttributeError:
        return False, "PHP include attestation shape is invalid", {}
    if (
        type(provisioning) is not PhpIncludeProvisioningAttestation
        or type(verification) is not PhpIncludeVerificationAttestation
        or type(provisioning_filesystem) is not PhpIncludeFilesystemAttestation
        or type(verification_before) is not PhpIncludeFilesystemAttestation
        or type(verification_after) is not PhpIncludeFilesystemAttestation
        or type(provisioning_host_filesystem) is not PhpIncludeHostFilesystemAttestation
        or type(verification_host_before) is not PhpIncludeHostFilesystemAttestation
        or type(verification_host_after) is not PhpIncludeHostFilesystemAttestation
    ):
        return False, "PHP include attestation shape is invalid", {}

    attack_interval = _ssrf_upstream_interval(attack_record)
    control_interval = _ssrf_upstream_interval(control_record)
    if attack_interval is None or control_interval is None:
        return False, "PHP include parent intervals are invalid", {}
    if (
        type(marker) is not str
        or _PHP_INCLUDE_MARKER_RE.fullmatch(marker) is None
        or type(expected_generation_id) is not str
        or re.fullmatch(r"[0-9a-f]{64}", expected_generation_id) is None
        or type(attack_path) is not str
        or type(control_path) is not str
    ):
        return False, "PHP include oracle values are invalid", {}
    try:
        marker_bytes = marker.encode("ascii", errors="strict")
        attack_bytes = attack_path.encode("ascii", errors="strict")
        control_bytes = control_path.encode("ascii", errors="strict")
    except UnicodeEncodeError:
        return False, "PHP include oracle values are invalid", {}
    expected_content = (
        f"<?php\nheader('{PHP_INCLUDE_ORACLE_HEADER_NAME}: {marker}');\nreturn;\n"
    ).encode("ascii")
    marker_sha256 = hashlib.sha256(marker_bytes).hexdigest()
    attack_path_sha256 = hashlib.sha256(attack_bytes).hexdigest()
    control_path_sha256 = hashlib.sha256(control_bytes).hexdigest()
    attack_basename_sha256 = hashlib.sha256(
        PurePosixPath(attack_path).name.encode("ascii")
    ).hexdigest()
    control_basename_sha256 = hashlib.sha256(
        PurePosixPath(control_path).name.encode("ascii")
    ).hexdigest()
    header_sha256 = hashlib.sha256(
        PHP_INCLUDE_ORACLE_HEADER_NAME.encode("ascii")
    ).hexdigest()
    content_sha256 = hashlib.sha256(expected_content).hexdigest()
    filesystems = (
        provisioning_filesystem,
        verification_before,
        verification_after,
    )
    host_filesystems = (
        provisioning_host_filesystem,
        verification_host_before,
        verification_host_after,
    )
    if not _php_include_attestation_scalar_shape_is_valid(
        snapshot,
        provisioning,
        verification,
        filesystems,
        host_filesystems,
    ):
        return False, "PHP include attestation scalar shape is invalid", {}
    now_monotonic_ns = time.monotonic_ns()
    stable_filesystem_fields = {
        "schema_version",
        "attack_path_sha256",
        "control_path_sha256",
        "attack_content_sha256",
        "attack_content_size_bytes",
        "attack_file_mode",
        "attack_link_count",
        "attack_is_regular_file",
        "attack_is_symlink",
        "control_lstat_exists",
    }
    stable_host_filesystem_fields = {
        "schema_version",
        "host_identity_sha256",
        "attack_content_sha256",
        "attack_content_size_bytes",
        "attack_owner_matches_verifier",
        "attack_file_mode",
        "attack_link_count",
        "attack_is_regular_file",
        "attack_is_symlink",
        "control_lstat_exists",
    }
    try:
        stable_states = [
            {
                key: value
                for key, value in filesystem.as_dict().items()
                if key in stable_filesystem_fields
            }
            for filesystem in filesystems
        ]
        stable_host_states = [
            {
                key: value
                for key, value in filesystem.as_dict().items()
                if key in stable_host_filesystem_fields
            }
            for filesystem in host_filesystems
        ]
    except AttributeError:
        return False, "PHP include attestation scalar shape is invalid", {}
    if (
        PHP_INCLUDE_RECEIPT_HEADER != PHP_INCLUDE_ORACLE_HEADER_NAME
        or snapshot.schema_version != 1
        or snapshot.mode != PHP_INCLUDE_ORACLE_MODE
        or re.fullmatch(r"[0-9a-f]{64}", snapshot.generation_id) is None
        or not hmac.compare_digest(snapshot.generation_id, expected_generation_id)
        or provisioning.schema_version != 1
        or re.fullmatch(r"[0-9a-f]{64}", provisioning.generation_id) is None
        or not hmac.compare_digest(provisioning.generation_id, expected_generation_id)
        or verification.schema_version != 1
        or re.fullmatch(r"[0-9a-f]{64}", verification.generation_id) is None
        or not hmac.compare_digest(verification.generation_id, expected_generation_id)
        or re.fullmatch(r"[0-9a-f]{64}", provisioning.attack_basename_sha256) is None
        or not hmac.compare_digest(
            provisioning.attack_basename_sha256, attack_basename_sha256
        )
        or re.fullmatch(r"[0-9a-f]{64}", provisioning.control_basename_sha256) is None
        or not hmac.compare_digest(
            provisioning.control_basename_sha256, control_basename_sha256
        )
        or re.fullmatch(r"[0-9a-f]{64}", provisioning.header_name_sha256) is None
        or not hmac.compare_digest(provisioning.header_name_sha256, header_sha256)
        or re.fullmatch(r"[0-9a-f]{64}", provisioning.marker_sha256) is None
        or not hmac.compare_digest(provisioning.marker_sha256, marker_sha256)
        or verification.before != provisioning.filesystem
        or verification.host_before != provisioning.host_filesystem
        or stable_states[0] != stable_states[1]
        or stable_states[1] != stable_states[2]
        or stable_host_states[0] != stable_host_states[1]
        or stable_host_states[1] != stable_host_states[2]
        or any(
            filesystem.schema_version != 1
            or re.fullmatch(r"[0-9a-f]{64}", filesystem.attack_path_sha256) is None
            or not hmac.compare_digest(
                filesystem.attack_path_sha256, attack_path_sha256
            )
            or re.fullmatch(r"[0-9a-f]{64}", filesystem.control_path_sha256) is None
            or not hmac.compare_digest(
                filesystem.control_path_sha256, control_path_sha256
            )
            or re.fullmatch(r"[0-9a-f]{64}", filesystem.attack_content_sha256) is None
            or not hmac.compare_digest(filesystem.attack_content_sha256, content_sha256)
            or filesystem.attack_content_size_bytes != len(expected_content)
            or filesystem.attack_owner_uid < 0
            or filesystem.attack_owner_gid < 0
            or filesystem.attack_file_mode != PHP_INCLUDE_ORACLE_FILE_MODE
            or filesystem.attack_link_count != 1
            or filesystem.attack_is_regular_file is not True
            or filesystem.attack_is_symlink is not False
            or filesystem.control_lstat_exists is not False
            or filesystem.measured_monotonic_ns < 1
            or filesystem.measured_monotonic_ns > now_monotonic_ns
            for filesystem in filesystems
        )
        or any(
            filesystem.schema_version != 1
            or re.fullmatch(r"[0-9a-f]{64}", filesystem.host_identity_sha256) is None
            or not hmac.compare_digest(
                filesystem.host_identity_sha256,
                provisioning_host_filesystem.host_identity_sha256,
            )
            or re.fullmatch(r"[0-9a-f]{64}", filesystem.attack_content_sha256) is None
            or not hmac.compare_digest(
                filesystem.attack_content_sha256,
                content_sha256,
            )
            or filesystem.attack_content_size_bytes != len(expected_content)
            or filesystem.attack_owner_matches_verifier is not True
            or filesystem.attack_file_mode != PHP_INCLUDE_ORACLE_FILE_MODE
            or filesystem.attack_link_count != 1
            or filesystem.attack_is_regular_file is not True
            or filesystem.attack_is_symlink is not False
            or filesystem.control_lstat_exists is not False
            or filesystem.measured_monotonic_ns < 1
            or filesystem.measured_monotonic_ns > now_monotonic_ns
            for filesystem in host_filesystems
        )
        or any(
            not hmac.compare_digest(
                filesystem.attack_content_sha256,
                host_filesystem.attack_content_sha256,
            )
            or filesystem.attack_content_size_bytes
            != host_filesystem.attack_content_size_bytes
            or filesystem.attack_file_mode != host_filesystem.attack_file_mode
            or filesystem.attack_link_count != host_filesystem.attack_link_count
            or filesystem.attack_is_regular_file
            is not host_filesystem.attack_is_regular_file
            or filesystem.attack_is_symlink is not host_filesystem.attack_is_symlink
            or filesystem.control_lstat_exists
            is not host_filesystem.control_lstat_exists
            for filesystem, host_filesystem in zip(filesystems, host_filesystems)
        )
        or provisioning.started_monotonic_ns < 1
        or provisioning.started_monotonic_ns > now_monotonic_ns
        or provisioning.filesystem.measured_monotonic_ns
        < provisioning.started_monotonic_ns
        or provisioning.host_filesystem.measured_monotonic_ns
        < provisioning.started_monotonic_ns
        or provisioning.host_filesystem.measured_monotonic_ns
        > provisioning.filesystem.measured_monotonic_ns
        or verification.execution_started_monotonic_ns
        < provisioning.filesystem.measured_monotonic_ns
        or verification.execution_started_monotonic_ns
        < provisioning.host_filesystem.measured_monotonic_ns
        or verification.execution_started_monotonic_ns > now_monotonic_ns
        or attack_interval[0] < verification.execution_started_monotonic_ns
        or attack_interval[1] > control_interval[0]
        or control_interval[1] > verification.execution_finished_monotonic_ns
        or verification.execution_finished_monotonic_ns
        < verification.execution_started_monotonic_ns
        or verification.execution_finished_monotonic_ns > now_monotonic_ns
        or control_interval[1] > now_monotonic_ns
        or verification.after.measured_monotonic_ns
        < verification.execution_finished_monotonic_ns
        or verification.host_after.measured_monotonic_ns
        < verification.execution_finished_monotonic_ns
        or verification.host_after.measured_monotonic_ns
        > verification.after.measured_monotonic_ns
    ):
        return False, "PHP include attestation is invalid or non-causal", {}
    return (
        True,
        "PHP include canary attestation passed",
        {
            "mode": PHP_INCLUDE_ORACLE_MODE,
            "generation_id_sha256": hashlib.sha256(
                expected_generation_id.encode("ascii")
            ).hexdigest(),
            "attack_path_sha256": attack_path_sha256,
            "control_path_sha256": control_path_sha256,
            "marker_sha256": marker_sha256,
            "file_mode": provisioning.host_filesystem.attack_file_mode,
            "host_identity_sha256": (provisioning.host_filesystem.host_identity_sha256),
            "host_identity_stable": True,
            "host_owner_verified": True,
            "control_lstat_exists": False,
        },
    )


def validate_php_include_response_marker_http_trace(
    observation: PoCObservation,
    trace_records: list[dict],
    *,
    trace_salt: bytes,
    target_url: str,
    receipt_secret: bytes,
    trace_token: str,
    oracle_attack_path: str,
    oracle_control_path: str,
    oracle_marker: str,
    oracle_snapshot: object,
    oracle_generation_id: str,
    expected_http_transport: dict[str, object] | None = None,
    trace_error: str = "",
) -> tuple[bool, str, dict]:
    """Prove one request-selected PHP include using a private parent canary."""
    if trace_error:
        return False, f"PHP include HTTP trace failed: {trace_error}", {}
    if (
        type(oracle_marker) is not str
        or _PHP_INCLUDE_MARKER_RE.fullmatch(oracle_marker) is None
        or type(oracle_attack_path) is not str
        or re.fullmatch(
            re.escape(PHP_INCLUDE_ORACLE_DIRECTORY) + r"/[0-9a-f]{64}\.php",
            oracle_attack_path,
        )
        is None
        or type(oracle_control_path) is not str
        or re.fullmatch(
            re.escape(PHP_INCLUDE_ORACLE_DIRECTORY) + r"/[0-9a-f]{64}\.php",
            oracle_control_path,
        )
        is None
        or hmac.compare_digest(oracle_attack_path, oracle_control_path)
    ):
        return False, "PHP include parent oracle contract is invalid", {}

    attack = observation.attack
    control = observation.control
    marker = attack.get("marker")
    if not isinstance(marker, str) or not hmac.compare_digest(marker, oracle_marker):
        return False, "PHP include marker does not match the private canary", {}
    if observation.impact.confidentiality != "low":
        return False, "PHP include canary evidence requires confidentiality=low", {}
    if (
        observation.impact.integrity != "none"
        or observation.impact.availability != "none"
    ):
        return False, "PHP include canary proves confidentiality only", {}
    if (
        attack.get("identity_verified") is not True
        or control.get("identity_verified") is not True
    ):
        return False, "PHP include proof lacks verified arm identities", {}
    if attack.get("include_path") != oracle_attack_path:
        return False, "PHP include attack path does not match the parent canary", {}
    if control.get("include_path") != oracle_control_path:
        return False, "PHP include control path does not match the absent sibling", {}
    attack_value = attack.get("destination_value")
    control_value = control.get("destination_value")
    if (
        not isinstance(attack_value, str)
        or not attack_value
        or not isinstance(control_value, str)
        or not control_value
        or hmac.compare_digest(attack_value, control_value)
    ):
        return False, "PHP include destination values are missing or identical", {}
    attack_stem = PurePosixPath(oracle_attack_path).stem
    control_stem = PurePosixPath(oracle_control_path).stem
    if (
        attack_value.count(attack_stem) != 1
        or control_value.count(control_stem) != 1
        or control_stem in attack_value
        or attack_stem in control_value
        or attack_value.replace(attack_stem, "{php_include_path}")
        != control_value.replace(control_stem, "{php_include_path}")
    ):
        return (
            False,
            "PHP include attack/control destinations change more than the path token",
            {},
        )

    attack_signature = _ssrf_request_signature(attack.get("request_fingerprint"))
    control_signature = _ssrf_request_signature(control.get("request_fingerprint"))
    if attack_signature is None or control_signature is None:
        return False, "PHP include request fingerprint is invalid", {}
    if attack_signature != control_signature:
        return False, "PHP include attack/control request fingerprints differ", {}
    expected_transports = _expected_http_transport_signatures(expected_http_transport)
    if not expected_transports:
        return False, "PHP include hypothesis HTTP transport is missing or invalid", {}
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
            "PHP include request transport does not match the hypothesis entry point",
            {},
        )

    method, route = str(attack_signature[0]), str(attack_signature[1])
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
            "PHP include reported request does not match its fingerprint or sandbox",
            {},
        )
    attack_user_id = _trace_claimed_user_id(
        attack.get("attacker_user_id"), observation.attacker_role
    )
    control_user_id = _trace_claimed_user_id(
        control.get("attacker_user_id"), observation.attacker_role
    )
    if attack_user_id is None or attack_user_id != control_user_id:
        return False, "PHP include attack/control actor is invalid or changed", {}

    target_records = [
        record
        for record in trace_records
        if isinstance(record, dict) and record.get("origin") == target_origin
    ]
    if len(target_records) != len(trace_records):
        return False, "PHP include HTTP trace contains an invalid-origin record", {}
    if [record.get("sequence") for record in target_records] != list(
        range(1, len(target_records) + 1)
    ):
        return False, "PHP include HTTP trace is incomplete or unordered", {}
    if any(_record_has_request_sentinel(record) for record in target_records):
        return False, "PHP include HTTP trace contains a sentinel-bearing request", {}

    common = {
        "trace_salt": trace_salt,
        "target_origin": target_origin,
        "receipt_secret": receipt_secret,
        "trace_token": trace_token,
    }
    trace_signature = _ssrf_trace_signature(attack_signature)
    allow_credential_free = _allows_credential_free_direct_ssrf(
        expected_http_transport,
        observation.attacker_role,
    )
    attack_matches = _matching_trace_requests(
        trace_records,
        trace_signature,
        object_id=attack_value,
        expected_user_id=attack_user_id,
        expected_role=observation.attacker_role,
        allow_credential_free_unauthenticated=allow_credential_free,
        **common,
    )
    control_matches = _matching_trace_requests(
        trace_records,
        trace_signature,
        object_id=control_value,
        expected_user_id=control_user_id,
        expected_role=observation.attacker_role,
        allow_credential_free_unauthenticated=allow_credential_free,
        **common,
    )
    attack_binding, reason = _one_trace_match(attack_matches, "PHP include attack")
    if attack_binding is None:
        return False, reason, {}
    control_binding, reason = _one_trace_match(control_matches, "PHP include control")
    if control_binding is None:
        return False, reason, {}
    if attack_binding["sequence"] >= control_binding["sequence"]:
        return False, "PHP include attack request must precede its control", {}
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
    } or control_binding["sequence"] != len(target_records):
        return False, "PHP include proof contains extra causal target traffic", {}
    if attack_binding["parameter_shape"] != control_binding["parameter_shape"]:
        return False, "PHP include attack/control parameter shapes differ", {}
    if attack_binding["actor"].get("user_id") != control_binding["actor"].get(
        "user_id"
    ) or attack_binding["actor"].get("roles") != control_binding["actor"].get("roles"):
        return False, "PHP include signed attack/control actors differ", {}
    attack_provenance = attack_binding["actor"].get("provenance")
    control_provenance = control_binding["actor"].get("provenance")
    if (
        attack_provenance not in {"signed_receipt", "credential_free_transport"}
        or attack_provenance != control_provenance
        or not _receipt_has_only_expected_privileges(
            attack_binding["actor"], observation.attacker_role
        )
        or not _receipt_has_only_expected_privileges(
            control_binding["actor"], observation.attacker_role
        )
    ):
        return False, "PHP include actors exceed or change the expected role", {}

    if attack_provenance == "credential_free_transport":
        if (
            not allow_credential_free
            or len(target_records) != 2
            or [record.get("sequence") for record in target_records] != [1, 2]
            or cast(tuple[tuple[str, str], ...], attack_signature[5])
        ):
            return False, "credential-free PHP include proof has extra traffic", {}
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
                    "credential-free PHP include request contains undeclared fields",
                    {},
                )

    for record in target_records:
        sequence = int(record.get("sequence") or 0)
        if "response_php_include_receipt" not in record:
            return False, "PHP include receipt trace field is missing", {}
        if (
            sequence != attack_binding["sequence"]
            and record.get("response_php_include_receipt") is not None
        ):
            return False, "PHP include receipt appeared outside the attack arm", {}
        if sequence >= attack_binding["sequence"]:
            continue
        if record.get("response_actor_receipt") is None:
            continue
        preproof_actor, _actor_reason = _decode_actor_receipt(
            record,
            receipt_secret=receipt_secret,
            trace_token=trace_token,
        )
        if preproof_actor is None:
            return False, "PHP include pre-proof actor receipt is untrusted", {}
        if preproof_actor.get("user_id") == 0 and not preproof_actor.get("roles"):
            continue
        if preproof_actor.get(
            "user_id"
        ) != attack_user_id or not _receipt_has_only_expected_privileges(
            preproof_actor,
            observation.attacker_role,
        ):
            return False, "PHP include pre-proof traffic used an elevated actor", {}

    if attack_provenance == "signed_receipt":
        if attack_binding["actor"].get("nonce") == control_binding["actor"].get(
            "nonce"
        ) or attack_binding["actor"].get("request_nonce") == control_binding[
            "actor"
        ].get("request_nonce"):
            return False, "PHP include HTTP trace reused a signed request nonce", {}
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
            return False, "credential-free PHP include binding is invalid", {}

    labels = frozenset({"php_include_attack_path", "php_include_control_path"})
    occurrences: list[tuple[int, str, str, str]] = []
    for record in target_records:
        tracked = _trace_tracked_capability_fields(
            record,
            allowed_labels=labels,
        )
        if tracked is None:
            return False, "PHP include capability trace is malformed", {}
        sequence = int(record.get("sequence") or 0)
        occurrences.extend(
            (sequence, location, name, label) for location, name, label in tracked
        )
    destination_location = str(attack_signature[3])
    destination_parameter = str(attack_signature[2])
    expected_occurrences = [
        (
            attack_binding["sequence"],
            destination_location,
            destination_parameter,
            "php_include_attack_path",
        ),
        (
            control_binding["sequence"],
            destination_location,
            destination_parameter,
            "php_include_control_path",
        ),
    ]
    if occurrences != expected_occurrences:
        return (
            False,
            "PHP include path capability appears outside its exact destination arm",
            {},
        )

    values_ok, values_reason = _ssrf_request_values_match(
        attack_binding,
        control_binding,
        attack_signature,
        attack_url=attack_value,
        control_url=control_value,
        trace_salt=trace_salt,
    )
    if not values_ok:
        return False, values_reason.replace("SSRF", "PHP include"), {}
    attack_header_digest = attack_binding["record"].get("request_headers_sha256")
    control_header_digest = control_binding["record"].get("request_headers_sha256")
    if (
        not isinstance(attack_header_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", attack_header_digest) is None
        or not isinstance(control_header_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", control_header_digest) is None
        or not hmac.compare_digest(attack_header_digest, control_header_digest)
    ):
        return False, "PHP include attack/control request headers differ", {}
    if attack_binding["record"].get("response_php_include_receipt") != oracle_marker:
        return False, "PHP include attack response lacks the private receipt", {}
    if control_binding["record"].get("response_php_include_receipt") is not None:
        return False, "PHP include control response contains a receipt", {}

    snapshot_ok, snapshot_reason, snapshot_evidence = (
        _validate_php_include_oracle_snapshot(
            oracle_snapshot,
            marker=oracle_marker,
            expected_generation_id=oracle_generation_id,
            attack_path=oracle_attack_path,
            control_path=oracle_control_path,
            attack_record=attack_binding["record"],
            control_record=control_binding["record"],
        )
    )
    if not snapshot_ok:
        return False, snapshot_reason, {}
    return (
        True,
        "PHP include receipt, HTTP trace, actor, control, and attestation passed",
        {
            "oracle": "php_include_response_marker",
            "destination_field": {
                "location": destination_location,
                "name": destination_parameter,
            },
            "attack_request": _sanitized_trace_binding(attack_binding),
            "control_request": _sanitized_trace_binding(control_binding),
            "php_include_attestation": snapshot_evidence,
        },
    )


def _php_object_request_signature(value: object) -> tuple[object, ...] | None:
    """Canonicalize the model-visible request identity for both oracle arms."""
    if not isinstance(value, dict) or set(value) != _PHP_OBJECT_FINGERPRINT_FIELDS:
        return None
    method = value.get("method")
    route_value = value.get("route")
    object_field = value.get("object_field")
    object_location = value.get("object_location")
    if (
        not isinstance(method, str)
        or not method.strip()
        or not isinstance(route_value, str)
        or not route_value.strip()
        or not isinstance(object_field, str)
        or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", object_field) is None
        or object_location != "form"
    ):
        return None
    route = _normalize_request_path(route_value)
    if (
        not route
        or route != route_value
        or urlparse(route_value).query
        or urlparse(route_value).fragment
    ):
        return None
    dispatch = _cross_object_dispatch_signature(value.get("dispatch"))
    if dispatch is None:
        return None
    if any(key == f"form:{object_field}" for key, _expected in dispatch):
        return None
    return method.strip().upper(), route, object_field, "form", dispatch


def _validate_php_object_observation(
    observation: PoCObservation,
) -> tuple[bool, str]:
    """Validate only the inert object-instantiation primitive claimed by a PoC."""
    attack = observation.attack
    control = observation.control
    if set(observation.request) != {"method", "url"}:
        return False, "object request contains unsupported claims"
    if (
        set(attack) != _PHP_OBJECT_OBSERVATION_FIELDS
        or set(control) != _PHP_OBJECT_OBSERVATION_FIELDS
    ):
        return False, "object attack/control contains unsupported claims"
    if attack.get("instantiated") is not True:
        return False, "object attack did not report instantiated=true"
    if control.get("instantiated") is not False:
        return False, "object control did not report instantiated=false"
    if (
        attack.get("effect") != "verifier_inert_canary_wakeup"
        or control.get("effect") != "verifier_inert_canary_wakeup"
    ):
        return False, "object attack/control effect exceeds the inert canary"
    if (
        attack.get("identity_verified") is not True
        or control.get("identity_verified") is not True
    ):
        return False, "object attack/control identity is not verified"
    attack_actor = _trace_claimed_user_id(
        attack.get("attacker_user_id"), observation.attacker_role
    )
    control_actor = _trace_claimed_user_id(
        control.get("attacker_user_id"), observation.attacker_role
    )
    if attack_actor is None or control_actor is None or attack_actor != control_actor:
        return False, "object attack/control actor is invalid or changed"
    attack_request = _php_object_request_signature(attack.get("request_fingerprint"))
    control_request = _php_object_request_signature(control.get("request_fingerprint"))
    if attack_request is None or control_request is None:
        return False, "object attack/control request fingerprint is invalid"
    if attack_request != control_request:
        return False, "object attack/control request fingerprints differ"
    top_level_method = str(observation.request.get("method") or "").strip().upper()
    top_level_path = _normalize_request_path(
        urlparse(str(observation.request.get("url") or "")).path
    )
    if attack_request[0] != top_level_method or attack_request[1] != top_level_path:
        return False, "object request fingerprint does not match request"
    if (
        observation.impact.confidentiality != "none"
        or observation.impact.integrity != "low"
        or observation.impact.availability != "none"
    ):
        return False, (
            "the inert object canary proves only integrity=low object lifecycle "
            "invocation"
        )
    return True, "object-instantiation observation shape passed"


def validate_php_object_http_trace(
    observation: PoCObservation,
    trace_records: list[dict],
    *,
    target_url: str,
    receipt_secret: bytes,
    trace_token: str,
    policy: PhpObjectRewritePolicy,
    snapshot: PhpObjectOracleSnapshot,
    expected_attacker_role: str,
    trace_error: str,
) -> tuple[bool, str, dict]:
    """Bind the model claim to two parent-rewritten, server-signed requests."""
    if trace_error:
        return False, "PHP object HTTP trace is incomplete", {}
    signature = _php_object_request_signature(
        observation.attack.get("request_fingerprint")
    )
    control_signature = _php_object_request_signature(
        observation.control.get("request_fingerprint")
    )
    expected_dispatch = tuple(
        sorted(
            (f"{location}:{field}", expected)
            for location, field, expected in policy.dispatch
        )
    )
    expected_signature = (
        policy.method,
        policy.path,
        policy.object_field,
        policy.object_location,
        expected_dispatch,
    )
    if signature != expected_signature or control_signature != expected_signature:
        return False, "PHP object claim does not match its reviewed transport", {}

    expected_user_id = _trace_claimed_user_id(
        observation.attack.get("attacker_user_id"),
        expected_attacker_role,
    )
    control_user_id = _trace_claimed_user_id(
        observation.control.get("attacker_user_id"),
        expected_attacker_role,
    )
    if (
        expected_user_id is None
        or control_user_id is None
        or expected_user_id != control_user_id
    ):
        return False, "PHP object claimed actor is invalid or changed", {}

    arm_records: dict[str, list[dict]] = {"attack": [], "control": []}
    for record in trace_records:
        if not isinstance(record, dict):
            continue
        arm = record.get("php_object_arm")
        if arm in arm_records:
            arm_records[cast(str, arm)].append(record)
    if any(len(records) != 1 for records in arm_records.values()):
        return False, "PHP object trace has missing or duplicate oracle arms", {}

    target_origin = normalize_trace_origin(target_url)
    actors: dict[str, dict] = {}
    envelopes: dict[str, str] = {}
    rewritten: dict[str, str] = {}
    sequences: dict[str, int] = {}
    statuses: dict[str, int] = {}
    for arm in ("attack", "control"):
        record = arm_records[arm][0]
        sequence = record.get("sequence")
        status = record.get("status_code")
        envelope = record.get("php_object_original_envelope_sha256")
        rewritten_digest = record.get("php_object_rewritten_body_sha256")
        if (
            record.get("trace_version") != 1
            or record.get("record_type") != "request"
            or record.get("forward_state") != "completed"
            or record.get("forward_error") is not None
            or record.get("terminal") is not False
            or record.get("origin") != target_origin
            or str(record.get("method") or "").upper() != policy.method
            or _normalize_request_path(str(record.get("path") or "")) != policy.path
            or not isinstance(sequence, int)
            or isinstance(sequence, bool)
            or sequence < 1
            or not isinstance(status, int)
            or isinstance(status, bool)
            or not 100 <= status <= 599
            or not isinstance(envelope, str)
            or _SHA256_RE.fullmatch(envelope) is None
            or not isinstance(rewritten_digest, str)
            or _SHA256_RE.fullmatch(rewritten_digest) is None
        ):
            return False, f"PHP object {arm} trace record is malformed", {}
        actor, _reason = _decode_actor_receipt(
            record,
            receipt_secret=receipt_secret,
            trace_token=trace_token,
        )
        if (
            actor is None
            or actor.get("user_id") != expected_user_id
            or not _receipt_has_only_expected_privileges(actor, expected_attacker_role)
        ):
            return False, f"PHP object {arm} actor receipt is untrusted", {}
        actors[arm] = actor
        envelopes[arm] = envelope
        rewritten[arm] = rewritten_digest
        sequences[arm] = sequence
        statuses[arm] = status

    if actors["attack"].get("roles") != actors["control"].get("roles"):
        return False, "PHP object attack/control signed actors differ", {}
    if actors["attack"].get("nonce") == actors["control"].get("nonce") or actors[
        "attack"
    ].get("request_nonce") == actors["control"].get("request_nonce"):
        return False, "PHP object attack/control actor receipts were reused", {}
    if sequences["attack"] >= sequences["control"]:
        return False, "PHP object attack/control request order is invalid", {}
    if envelopes["attack"] != envelopes["control"]:
        return False, "PHP object attack/control envelopes differ", {}
    if rewritten["attack"] == rewritten["control"]:
        return False, "PHP object attack/control rewritten bodies are identical", {}

    attack_record = arm_records["attack"][0]
    control_record = arm_records["control"][0]
    expected_receipt_sha256 = snapshot.execution.expected_receipt_sha256
    if (
        attack_record.get("response_php_object_receipt_present") is not True
        or attack_record.get("response_php_object_receipt_sha256")
        != expected_receipt_sha256
        or control_record.get("response_php_object_receipt_present") is not False
        or control_record.get("response_php_object_receipt_sha256") is not None
        or snapshot.execution.attack_receipt_matched is not True
        or snapshot.execution.control_receipt_absent is not True
    ):
        return False, "PHP object trusted receipt differential is invalid", {}

    return (
        True,
        "PHP object receipt, HTTP trace, actor, control, and attestation passed",
        {
            "oracle": "object_instantiation",
            "attack_request": {
                "sequence": sequences["attack"],
                "method": policy.method,
                "path": policy.path,
                "status_code": statuses["attack"],
                "actor_user_id": expected_user_id,
                "actor_roles": actors["attack"].get("roles"),
            },
            "control_request": {
                "sequence": sequences["control"],
                "method": policy.method,
                "path": policy.path,
                "status_code": statuses["control"],
                "actor_user_id": expected_user_id,
                "actor_roles": actors["control"].get("roles"),
            },
        },
    )


def validate_php_object_gadget_http_trace(
    trace_records: list[dict],
    *,
    target_url: str,
    receipt_secret: bytes,
    trace_token: str,
    policy: PhpObjectRewritePolicy,
    oracle: PhpObjectGadgetOracle,
    script_sha256: str,
    poc_bundle_manifest_sha256: str,
    poc_bundle_source_file_count: int,
    expected_attacker_role: str,
    surface_attestations: tuple[tuple[str, str], ...],
    trace_error: str,
) -> tuple[bool, str, PhpObjectGadgetTransportAttestation | None, dict]:
    """Bind an unauthenticated natural effect to two credential-free HTTP arms.

    Actor identity is derived only from the parent proxy's removal of every
    credential-capable header.  Natural promotion deliberately does not decode
    or trust the in-process actor receipt, whose signing code shares the target
    PHP runtime with the plugin under test.
    """
    if trace_error or len(trace_records) not in {2, 3}:
        return False, "PHP object gadget HTTP trace is incomplete", None, {}
    if (
        _SHA256_RE.fullmatch(script_sha256) is None
        or _SHA256_RE.fullmatch(poc_bundle_manifest_sha256) is None
        or type(poc_bundle_source_file_count) is not int
        or not 1 <= poc_bundle_source_file_count <= DEFAULT_MAX_BUNDLE_FILES
    ):
        return False, "PHP object gadget PoC bundle identity is invalid", None, {}
    if surface_attestations != _PHP_OBJECT_SURFACE_ATTESTATION_ORDER:
        return False, "PHP object gadget surface binding is incomplete", None, {}
    normalized_attacker_role = normalize_attacker_role(expected_attacker_role)
    if normalized_attacker_role != "unauthenticated":
        return (
            False,
            "PHP object gadget natural proof requires an unauthenticated actor",
            None,
            {},
        )

    target_origin = normalize_trace_origin(target_url)
    generation_sha256 = hashlib.sha256(oracle.generation_id.encode("ascii")).hexdigest()
    if any(type(record) is not dict for record in trace_records):
        return False, "PHP object gadget trace record is malformed", None, {}
    sequences_in_order = [record.get("sequence") for record in trace_records]
    if sequences_in_order != list(range(1, len(trace_records) + 1)):
        return False, "PHP object gadget HTTP trace is incomplete", None, {}
    arm_trace_records = trace_records[-2:]
    if [record.get("php_object_arm") for record in arm_trace_records] != [
        "attack",
        "control",
    ]:
        return False, "PHP object gadget HTTP trace is incomplete", None, {}
    arm_records = {
        "attack": arm_trace_records[0],
        "control": arm_trace_records[1],
    }

    if len(trace_records) == 3:
        preflight = trace_records[0]
        preflight_status = preflight.get("status_code")
        preflight_fields = preflight.get("fields")
        if (
            preflight.get("trace_version") != 1
            or preflight.get("record_type") != "request"
            or preflight.get("forward_state") != "completed"
            or preflight.get("forward_error") is not None
            or preflight.get("terminal") is not False
            or preflight.get("origin") != target_origin
            or preflight.get("method") != "GET"
            or preflight.get("php_object_arm") is not None
            or preflight.get("php_object_generation_sha256") != generation_sha256
            or type(preflight_status) is not int
            or not 100 <= preflight_status <= 599
            or 300 <= preflight_status <= 399
            or preflight.get("php_object_original_envelope_sha256") is not None
            or preflight.get("php_object_rewritten_body_sha256") is not None
            or preflight.get("credential_free_transport") is not True
            or preflight.get("response_php_object_receipt_present") is not False
            or preflight.get("response_php_object_receipt_sha256") is not None
            or not isinstance(preflight_fields, list)
            or "request_body_parse_error" in preflight
            or preflight.get("request_metadata_omitted") is True
            or preflight.get("request_tracked_capabilities_in_headers") != []
        ):
            return False, "PHP object gadget preflight is malformed", None, {}
        preflight_shape_counts: Counter[tuple[str, str, str]] = Counter()
        for field in preflight_fields:
            if (
                type(field) is not dict
                or set(field)
                != {
                    "location",
                    "name",
                    "kind",
                    "value_sha256",
                    "contains_squadrone_sentinel",
                    "tracked_capabilities",
                }
                or field.get("location") != "query"
                or not isinstance(field.get("name"), str)
                or field.get("kind") != "scalar"
                or not isinstance(field.get("value_sha256"), str)
                or _SHA256_RE.fullmatch(cast(str, field["value_sha256"])) is None
                or type(field.get("contains_squadrone_sentinel")) is not bool
                or field.get("tracked_capabilities") != []
            ):
                return False, "PHP object gadget preflight is malformed", None, {}
            preflight_shape_counts[("query", cast(str, field["name"]), "scalar")] += 1
        expected_preflight_shape = [
            {
                "location": location,
                "name": name,
                "kind": kind,
                "count": count,
            }
            for (location, name, kind), count in sorted(preflight_shape_counts.items())
        ]
        if preflight.get("parameter_shape") != expected_preflight_shape:
            return False, "PHP object gadget preflight is malformed", None, {}

    actors: dict[str, dict] = {}
    envelopes: dict[str, str] = {}
    rewritten: dict[str, str] = {}
    sequences: dict[str, int] = {}
    statuses: dict[str, int] = {}
    parameter_shapes: dict[str, list[dict[str, object]]] = {}
    field_signatures: dict[str, list[tuple[object, ...]]] = {}
    trace_identities: list[dict[str, object]] = []
    required_field_identities = {
        (policy.object_location, policy.object_field),
        *((location, name) for location, name, _value in policy.dispatch),
    }
    declared_query_identities = {
        (location, name)
        for location, name, _value in policy.dispatch
        if location == "query"
    }
    for arm in ("attack", "control"):
        record = arm_records[arm]
        sequence = record.get("sequence")
        status = record.get("status_code")
        envelope = record.get("php_object_original_envelope_sha256")
        rewritten_digest = record.get("php_object_rewritten_body_sha256")
        request_nonce = record.get("request_nonce")
        request_digest = record.get("request_digest")
        if (
            record.get("trace_version") != 1
            or record.get("record_type") != "request"
            or record.get("forward_state") != "completed"
            or record.get("forward_error") is not None
            or record.get("terminal") is not False
            or record.get("origin") != target_origin
            or record.get("method") != policy.method
            or _normalize_request_path(str(record.get("path") or "")) != policy.path
            or record.get("php_object_generation_sha256") != generation_sha256
            or type(sequence) is not int
            or sequence < 1
            or type(status) is not int
            or not 100 <= status <= 599
            or not isinstance(envelope, str)
            or _SHA256_RE.fullmatch(envelope) is None
            or not isinstance(rewritten_digest, str)
            or _SHA256_RE.fullmatch(rewritten_digest) is None
            or not isinstance(request_nonce, str)
            or _SHA256_RE.fullmatch(request_nonce) is None
            or not isinstance(request_digest, str)
            or _SHA256_RE.fullmatch(request_digest) is None
            or record.get("credential_free_transport") is not True
            or record.get("response_php_object_receipt_present") is not False
            or record.get("response_php_object_receipt_sha256") is not None
        ):
            return False, f"PHP object gadget {arm} trace is malformed", None, {}
        actor = {
            "user_id": 0,
            "roles": [],
            "nonce": request_nonce,
            "request_nonce": request_nonce,
            "provenance": "credential_free_transport",
        }

        capability_fields = []
        fields = record.get("fields")
        if not isinstance(fields, list):
            return False, f"PHP object gadget {arm} fields are malformed", None, {}
        observed_field_identities: list[tuple[str, str]] = []
        arm_field_signatures: list[tuple[object, ...]] = []
        for field in fields:
            if (
                type(field) is not dict
                or set(field)
                != {
                    "location",
                    "name",
                    "kind",
                    "value_sha256",
                    "contains_squadrone_sentinel",
                    "tracked_capabilities",
                }
                or field.get("location") not in {"query", "form"}
                or not isinstance(field.get("name"), str)
                or field.get("kind") != "scalar"
                or not isinstance(field.get("value_sha256"), str)
                or _SHA256_RE.fullmatch(cast(str, field["value_sha256"])) is None
                or type(field.get("contains_squadrone_sentinel")) is not bool
            ):
                return False, f"PHP object gadget {arm} fields are malformed", None, {}
            observed_field_identities.append(
                (cast(str, field["location"]), cast(str, field["name"]))
            )
            identity = observed_field_identities[-1]
            if identity[0] == "query" and identity not in declared_query_identities:
                return (
                    False,
                    f"PHP object gadget {arm} has an undeclared query field",
                    None,
                    {},
                )
            labels = field.get("tracked_capabilities", [])
            if not isinstance(labels, list) or any(
                type(label) is not str for label in labels
            ):
                return (
                    False,
                    f"PHP object gadget {arm} capability trace is invalid",
                    None,
                    {},
                )
            if "ephemeral_file_path" in labels:
                capability_fields.append(field)
            if any(label != "ephemeral_file_path" for label in labels):
                return (
                    False,
                    f"PHP object gadget {arm} has an unknown capability",
                    None,
                    {},
                )
            if labels and identity != (policy.object_location, policy.object_field):
                return (
                    False,
                    f"PHP object gadget {arm} path escaped its field",
                    None,
                    {},
                )
            if identity != (policy.object_location, policy.object_field):
                arm_field_signatures.append(
                    (
                        field["location"],
                        field["name"],
                        field["kind"],
                        field["value_sha256"],
                        field["contains_squadrone_sentinel"],
                        tuple(cast(list[str], labels)),
                    )
                )
        parameter_shape = record.get("parameter_shape")
        shape_counts = Counter(observed_field_identities)
        expected_parameter_shape: list[dict[str, object]] = [
            {
                "location": location,
                "name": name,
                "kind": "scalar",
                "count": count,
            }
            for (location, name), count in sorted(shape_counts.items())
        ]
        if (
            any(
                observed_field_identities.count(identity) != 1
                for identity in required_field_identities
            )
            or parameter_shape != expected_parameter_shape
            or "request_body_parse_error" in record
            or record.get("request_metadata_omitted") is True
        ):
            return (
                False,
                f"PHP object gadget {arm} request field shape is not exact",
                None,
                {},
            )
        if oracle.uses_ephemeral_path_capability:
            if (
                len(capability_fields) != 1
                or capability_fields[0].get("location") != "form"
                or capability_fields[0].get("name") != policy.object_field
                or capability_fields[0].get("tracked_capabilities")
                != ["ephemeral_file_path"]
                or record.get("request_tracked_capabilities_in_headers") != []
            ):
                return (
                    False,
                    f"PHP object gadget {arm} path escaped its field",
                    None,
                    {},
                )
        elif capability_fields or record.get(
            "request_tracked_capabilities_in_headers", []
        ):
            return False, f"PHP object gadget {arm} has an unexpected path", None, {}

        actors[arm] = actor
        envelopes[arm] = cast(str, envelope)
        rewritten[arm] = cast(str, rewritten_digest)
        sequences[arm] = sequence
        statuses[arm] = status
        parameter_shapes[arm] = expected_parameter_shape
        field_signatures[arm] = sorted(arm_field_signatures)
        trace_identities.append(
            {
                "arm": arm,
                "sequence": sequence,
                "request_nonce": record.get("request_nonce"),
                "request_digest": record.get("request_digest"),
                "rewritten_body_sha256": rewritten_digest,
                "actor_nonce": actor.get("nonce"),
            }
        )

    if (
        actors["attack"].get("user_id") != actors["control"].get("user_id")
        or actors["attack"].get("roles") != actors["control"].get("roles")
        or actors["attack"].get("nonce") == actors["control"].get("nonce")
        or actors["attack"].get("request_nonce")
        == actors["control"].get("request_nonce")
        or sequences["control"] != sequences["attack"] + 1
        or envelopes["attack"] != envelopes["control"]
        or rewritten["attack"] == rewritten["control"]
        or parameter_shapes["attack"] != parameter_shapes["control"]
        or field_signatures["attack"] != field_signatures["control"]
    ):
        return False, "PHP object gadget attack/control binding is invalid", None, {}

    actor_identity = {
        "user_id": actors["attack"].get("user_id"),
        "roles": actors["attack"].get("roles"),
    }
    actor_identity_sha256 = hashlib.sha256(
        json.dumps(
            actor_identity,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    transport_contract_sha256 = hashlib.sha256(
        json.dumps(
            {
                "method": policy.method,
                "path": policy.path,
                "object_location": policy.object_location,
                "object_field": policy.object_field,
                "dispatch": policy.dispatch,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()
    trace_binding_sha256 = hashlib.sha256(
        json.dumps(
            trace_identities,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()
    transport = PhpObjectGadgetTransportAttestation(
        schema_version=PHP_OBJECT_GADGET_ORACLE_SCHEMA_VERSION,
        mode=PHP_OBJECT_GADGET_ORACLE_MODE,
        effect="file_delete",
        effect_binding_kind=oracle.runtime_binding.effect_binding_kind,
        script_sha256=script_sha256,
        poc_bundle_manifest_sha256=poc_bundle_manifest_sha256,
        poc_bundle_source_file_count=poc_bundle_source_file_count,
        transport_contract_sha256=transport_contract_sha256,
        trace_binding_sha256=trace_binding_sha256,
        actor_identity_sha256=actor_identity_sha256,
        actor_role=normalized_attacker_role,
        attack_payload_sha256=hashlib.sha256(oracle.private_attack_payload).hexdigest(),
        control_payload_sha256=hashlib.sha256(
            oracle.private_control_payload
        ).hexdigest(),
        attack_payload_size_bytes=len(oracle.private_attack_payload),
        control_payload_size_bytes=len(oracle.private_control_payload),
        attack_sequence=sequences["attack"],
        control_sequence=sequences["control"],
        attack_status_code=statuses["attack"],
        control_status_code=statuses["control"],
        attack_control_envelopes_equal=True,
        rewritten_payloads_differ=True,
        ephemeral_path_capability_exact=True,
        executable_surface_bound=True,
    )
    return (
        True,
        "PHP object gadget HTTP, actor, transport, and surface binding passed",
        transport,
        {
            "oracle": "php_object_gadget_file_delete",
            "poc_bundle_manifest_sha256": poc_bundle_manifest_sha256,
            "poc_bundle_source_file_count": poc_bundle_source_file_count,
            "transport_contract_sha256": transport_contract_sha256,
            "actor_identity_sha256": actor_identity_sha256,
        },
    )


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
    elif oracle == "object_instantiation":
        accepted, reason = _validate_php_object_observation(observation)
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
        if (
            observation.impact.confidentiality != "none"
            or observation.impact.availability != "none"
        ):
            return False, (
                "file-effect oracle proves only file creation or overwrite integrity; "
                "confidentiality and availability require separate measured oracles"
            )
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
    try:
        stdout, stderr = await proc.communicate()
    except BaseException:
        if proc.returncode is None:
            try:
                proc.terminate()
            except ProcessLookupError:
                pass
            try:
                async with asyncio.timeout(2.0):
                    await proc.wait()
            except TimeoutError:
                if proc.returncode is None:
                    try:
                        proc.kill()
                    except ProcessLookupError:
                        pass
                await proc.wait()
        raise
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
    for attempt in range(_SSRF_READINESS_MAX_ATTEMPTS):
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
        # apache2ctl's graceful reload may return just before the new listener
        # accepts connections.  PHP exit 71 with no output is the exact
        # transport-not-ready signal; retry only that bounded startup race.
        transport_not_ready = proc.returncode == 71 and not stdout and not stderr
        if transport_not_ready and attempt + 1 < _SSRF_READINESS_MAX_ATTEMPTS:
            await asyncio.sleep(_SSRF_READINESS_RETRY_DELAY_S)
            continue
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
        return


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


def _php_include_resource_basename(resource_path: str) -> str:
    """Return one validated opaque PHP oracle basename."""
    container_directory = PurePosixPath(PHP_INCLUDE_ORACLE_DIRECTORY)
    path = PurePosixPath(resource_path)
    try:
        relative = path.relative_to(container_directory)
    except ValueError as exc:
        raise RuntimeError("PHP include path escaped its mount") from exc
    if (
        len(relative.parts) != 1
        or re.fullmatch(r"[0-9a-f]{64}\.php", relative.name) is None
    ):
        raise RuntimeError("PHP include path is malformed")
    return relative.name


def _php_include_host_path(host_directory: Path, resource_path: str) -> Path:
    """Resolve one opaque PHP oracle path inside its private host mount."""
    basename = _php_include_resource_basename(resource_path)
    root = host_directory.resolve(strict=True)
    # The basename parser has already excluded traversal.  Do not resolve the
    # leaf: provisioning and cleanup must replace/unlink an exact-path symlink,
    # never follow it to an attacker-selected target.
    target = root / basename
    if target.parent != root:
        raise RuntimeError("PHP include host path escaped its mount")
    return target


def _provision_php_include_oracle(
    host_directory: Path,
    oracle: PhpIncludeOracle,
) -> Path:
    """Atomically install one read-only attack canary; control stays absent."""
    attack = _php_include_host_path(host_directory, oracle.attack_path)
    control = _php_include_host_path(host_directory, oracle.control_path)
    if control.exists() or control.is_symlink():
        raise RuntimeError("PHP include control path unexpectedly exists")
    content = oracle.private_attack_content
    fd, temporary_name = tempfile.mkstemp(
        prefix=".squadrone-php-include-",
        dir=os.fspath(attack.parent),
    )
    temporary = Path(temporary_name)
    try:
        view = memoryview(content)
        while view:
            written = os.write(fd, view)
            if written < 1:
                raise RuntimeError("failed to write PHP include canary")
            view = view[written:]
        os.fsync(fd)
        os.fchmod(fd, PHP_INCLUDE_ORACLE_FILE_MODE)
        os.close(fd)
        fd = -1
        os.replace(temporary, attack)
    finally:
        if fd >= 0:
            os.close(fd)
        temporary.unlink(missing_ok=True)
    return attack


def _remove_php_include_canary(
    host_directory: Path | None,
    oracle: PhpIncludeOracle | None,
) -> None:
    """Remove only the exact issued attack canary from the private mount."""
    if host_directory is None or oracle is None:
        return
    _php_include_host_path(host_directory, oracle.attack_path).unlink(missing_ok=True)


_PHP_INCLUDE_HOST_READ_CHUNK_BYTES = 64 * 1024
_PHP_INCLUDE_HOST_MAX_CONTENT_BYTES = 4 * 1024


def _php_include_host_stat_signature(metadata: os.stat_result) -> tuple[int, ...]:
    """Return fields that must not change around one streamed host read."""
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _php_include_host_directory_signature(
    metadata: os.stat_result,
) -> tuple[int, ...]:
    """Bind the open directory descriptor to the supplied private host path."""
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _php_include_lstat_at(
    directory_fd: int,
    basename: str,
) -> os.stat_result | None:
    """Perform one no-follow lookup relative to the already-open directory."""
    try:
        return os.stat(
            basename,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return None


def _measure_php_include_host_filesystem(
    host_directory: Path,
    attack_path: str,
    control_path: str,
) -> PhpIncludeHostFilesystemMeasurement:
    """Measure the parent-owned canary without following or racing path links."""
    try:
        return _measure_php_include_host_filesystem_checked(
            host_directory,
            attack_path,
            control_path,
        )
    except Exception:
        # Path names, host identities, and low-level errors are deliberately not
        # propagated into logs or persisted run evidence.
        raise RuntimeError("PHP include host measurement failed") from None


def _measure_php_include_host_filesystem_checked(
    host_directory: Path,
    attack_path: str,
    control_path: str,
) -> PhpIncludeHostFilesystemMeasurement:
    """Implement the no-follow host measurement behind a value-free boundary."""
    attack_basename = _php_include_resource_basename(attack_path)
    control_basename = _php_include_resource_basename(control_path)
    if attack_basename == control_basename:
        raise RuntimeError("invalid PHP include host measurement contract")

    required_flags = tuple(
        getattr(os, name, 0) for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")
    )
    if any(type(flag) is not int or flag == 0 for flag in required_flags):
        raise RuntimeError("unsupported PHP include host measurement platform")
    if (
        os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.stat not in os.supports_follow_symlinks
    ):
        raise RuntimeError("unsupported PHP include host measurement platform")

    get_effective_uid = getattr(os, "geteuid", None)
    get_effective_gid = getattr(os, "getegid", None)
    if not callable(get_effective_uid) or not callable(get_effective_gid):
        raise RuntimeError("unsupported PHP include host measurement platform")
    verifier_uid = get_effective_uid()
    verifier_gid = get_effective_gid()
    if (
        type(verifier_uid) is not int
        or verifier_uid < 0
        or type(verifier_gid) is not int
        or verifier_gid < 0
    ):
        raise RuntimeError("invalid PHP include verifier identity")

    directory_flags = (
        os.O_RDONLY | required_flags[0] | required_flags[1] | required_flags[2]
    )
    directory_path_before = os.stat(host_directory, follow_symlinks=False)
    directory_fd = os.open(os.fspath(host_directory), directory_flags)
    try:
        os.set_inheritable(directory_fd, False)
        directory_fd_before = os.fstat(directory_fd)
        directory_signature = _php_include_host_directory_signature(directory_fd_before)
        if (
            _php_include_host_directory_signature(directory_path_before)
            != directory_signature
            or not stat.S_ISDIR(directory_fd_before.st_mode)
            or directory_fd_before.st_uid != verifier_uid
            or directory_fd_before.st_gid != verifier_gid
            or stat.S_IMODE(directory_fd_before.st_mode) & 0o022
            or os.get_inheritable(directory_fd)
        ):
            raise RuntimeError("unsafe PHP include host directory")

        control_before = _php_include_lstat_at(directory_fd, control_basename)
        attack_path_before = _php_include_lstat_at(directory_fd, attack_basename)
        if attack_path_before is None:
            raise RuntimeError("missing PHP include attack canary")

        file_flags = os.O_RDONLY | required_flags[1] | required_flags[2]
        file_flags |= getattr(os, "O_NONBLOCK", 0)
        attack_fd = os.open(attack_basename, file_flags, dir_fd=directory_fd)
        try:
            os.set_inheritable(attack_fd, False)
            attack_fd_before = os.fstat(attack_fd)
            attack_signature = _php_include_host_stat_signature(attack_fd_before)
            if (
                _php_include_host_stat_signature(attack_path_before) != attack_signature
                or not stat.S_ISREG(attack_path_before.st_mode)
                or stat.S_ISLNK(attack_path_before.st_mode)
                or attack_fd_before.st_uid != verifier_uid
                or attack_fd_before.st_gid != verifier_gid
                or stat.S_IMODE(attack_fd_before.st_mode)
                != PHP_INCLUDE_ORACLE_FILE_MODE
                or attack_fd_before.st_nlink != 1
                or attack_fd_before.st_size < 1
                or attack_fd_before.st_size > _PHP_INCLUDE_HOST_MAX_CONTENT_BYTES
                or attack_fd_before.st_dev < 0
                or attack_fd_before.st_ino <= 0
                or os.get_inheritable(attack_fd)
            ):
                raise RuntimeError("unsafe PHP include attack canary")

            digest = hashlib.sha256()
            content_size = 0
            while True:
                chunk = os.read(attack_fd, _PHP_INCLUDE_HOST_READ_CHUNK_BYTES)
                if not chunk:
                    break
                content_size += len(chunk)
                if content_size > _PHP_INCLUDE_HOST_MAX_CONTENT_BYTES:
                    raise RuntimeError("oversized PHP include attack canary")
                digest.update(chunk)
            attack_fd_after = os.fstat(attack_fd)
        finally:
            os.close(attack_fd)

        attack_path_after = _php_include_lstat_at(directory_fd, attack_basename)
        control_after = _php_include_lstat_at(directory_fd, control_basename)
        directory_fd_after = os.fstat(directory_fd)
        directory_path_after = os.stat(host_directory, follow_symlinks=False)
        if (
            attack_path_after is None
            or _php_include_host_stat_signature(attack_fd_after) != attack_signature
            or _php_include_host_stat_signature(attack_path_after) != attack_signature
            or content_size != attack_fd_after.st_size
            or _php_include_host_directory_signature(directory_fd_after)
            != directory_signature
            or _php_include_host_directory_signature(directory_path_after)
            != directory_signature
        ):
            raise RuntimeError("raced PHP include host measurement")

        return PhpIncludeHostFilesystemMeasurement(
            attack_content_sha256=digest.hexdigest(),
            attack_content_size_bytes=content_size,
            attack_owner_uid=attack_fd_after.st_uid,
            attack_owner_gid=attack_fd_after.st_gid,
            attack_file_mode=stat.S_IMODE(attack_fd_after.st_mode),
            attack_link_count=attack_fd_after.st_nlink,
            attack_is_regular_file=stat.S_ISREG(attack_fd_after.st_mode),
            attack_is_symlink=stat.S_ISLNK(attack_path_after.st_mode),
            control_lstat_exists=control_before is not None
            or control_after is not None,
            attack_device=attack_fd_after.st_dev,
            attack_inode=attack_fd_after.st_ino,
            measured_monotonic_ns=time.monotonic_ns(),
        )
    finally:
        os.close(directory_fd)


_PHP_INCLUDE_INSPECTION_FAILURES = frozenset(
    {
        "communication_failed",
        "contract_rejected",
        "empty_output",
        "invalid_shape",
        "invalid_values",
        "launch_failed",
        "malformed_output",
        "oversized_output",
        "process_failed",
        "resource_unavailable",
        "stderr_output",
        "timeout",
        "unexpected_failure",
    }
)
_PHP_INCLUDE_RETRIABLE_INSPECTION_FAILURES = frozenset(
    {
        "communication_failed",
        "empty_output",
        "launch_failed",
        "resource_unavailable",
        "timeout",
    }
)
_PHP_INCLUDE_INSPECTION_RETRY_DELAY_S = 0.025
_PHP_INCLUDE_INSPECTOR_REAP_TIMEOUT_S = 0.25


class _PhpIncludeInspectionError(RuntimeError):
    """Carry one fixed, value-free inspection category to the parent."""

    def __init__(self, reason: str, *, retries: int = 0) -> None:
        if reason not in _PHP_INCLUDE_INSPECTION_FAILURES:
            raise ValueError("invalid PHP include inspection failure category")
        if type(retries) is not int or retries not in {0, 1}:
            raise ValueError("invalid PHP include inspection retry count")
        self.reason = reason
        self.retries = retries
        super().__init__("PHP include canary inspection failed")


def _consume_php_include_inspector_wait(task: asyncio.Task[int]) -> None:
    """Retrieve a detached inspector-wait result without surfacing its details."""
    try:
        task.result()
    except BaseException:
        pass


async def _terminate_and_reap_php_include_inspector(
    proc: asyncio.subprocess.Process,
) -> None:
    """Bound best-effort reaping; suppress operations, not task cancellation."""
    if proc.returncode is None:
        try:
            proc.kill()
        except asyncio.CancelledError:
            raise
        except BaseException:
            try:
                proc.terminate()
            except asyncio.CancelledError:
                raise
            except BaseException:
                pass
    try:
        wait_task = asyncio.ensure_future(proc.wait())
    except asyncio.CancelledError:
        raise
    except BaseException:
        return
    wait_task.add_done_callback(_consume_php_include_inspector_wait)
    try:
        done, _pending = await asyncio.wait(
            {wait_task},
            timeout=_PHP_INCLUDE_INSPECTOR_REAP_TIMEOUT_S,
        )
    except asyncio.CancelledError:
        wait_task.cancel()
        raise
    except BaseException:
        wait_task.cancel()
        return
    if wait_task not in done:
        if proc.returncode is None:
            try:
                proc.kill()
            except asyncio.CancelledError:
                wait_task.cancel()
                raise
            except BaseException:
                pass
        wait_task.cancel()


async def _inspect_php_include_oracle(
    container_name: str,
    attack_path: str,
    control_path: str,
) -> dict[str, object]:
    """Measure both mounted oracle paths without returning canary contents."""
    php = (
        "$j=stream_get_contents(STDIN);$v=json_decode($j,true);"
        "if(!is_array($v)||array_keys($v)!==['attack','control']){exit(70);}"
        "$a=$v['attack'];$c=$v['control'];"
        "$re='#^/var/lib/squadrone/php-include/[0-9a-f]{64}\\.php$#D';"
        "if(!is_string($a)||!is_string($c)||$a===$c||"
        "!preg_match($re,$a)||!preg_match($re,$c)){exit(71);}"
        "$s=@lstat($a);$r=@realpath($a);$h=@hash_file('sha256',$a);"
        "$cs=@lstat($c);"
        "if(!is_array($s)||!is_string($r)||!is_string($h)){exit(72);}"
        "$o=['attack_resource_path'=>$r,'control_resource_path'=>$c,"
        "'attack_content_sha256'=>$h,'attack_content_size_bytes'=>(int)$s['size'],"
        "'attack_owner_uid'=>(int)$s['uid'],'attack_owner_gid'=>(int)$s['gid'],"
        "'attack_file_mode'=>((int)$s['mode']&0777),"
        "'attack_link_count'=>(int)$s['nlink'],"
        "'attack_is_regular_file'=>is_file($a),"
        "'attack_is_symlink'=>is_link($a),"
        "'control_lstat_exists'=>is_array($cs)];"
        "fwrite(STDOUT,json_encode($o,JSON_UNESCAPED_SLASHES));"
    )
    try:
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
    except Exception as exc:
        raise _PhpIncludeInspectionError("launch_failed") from exc
    payload_bytes = json.dumps(
        {"attack": attack_path, "control": control_path},
        separators=(",", ":"),
    ).encode("ascii")
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(payload_bytes),
            timeout=6.0,
        )
    except TimeoutError as exc:
        try:
            await _terminate_and_reap_php_include_inspector(proc)
        except asyncio.CancelledError:
            raise
        except BaseException:
            pass
        raise _PhpIncludeInspectionError("timeout") from exc
    except BaseException as exc:
        if not isinstance(exc, Exception):
            try:
                await _terminate_and_reap_php_include_inspector(proc)
            except BaseException:
                pass
            raise
        try:
            await _terminate_and_reap_php_include_inspector(proc)
        except asyncio.CancelledError:
            raise
        except BaseException:
            pass
        raise _PhpIncludeInspectionError("communication_failed") from exc
    if proc.returncode in {70, 71}:
        raise _PhpIncludeInspectionError("contract_rejected")
    if proc.returncode == 72:
        raise _PhpIncludeInspectionError("resource_unavailable")
    if proc.returncode != 0:
        raise _PhpIncludeInspectionError("process_failed")
    if stderr:
        raise _PhpIncludeInspectionError("stderr_output")
    if not stdout:
        raise _PhpIncludeInspectionError("empty_output")
    if len(stdout) > 4096:
        raise _PhpIncludeInspectionError("oversized_output")
    try:
        payload = json.loads(stdout.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _PhpIncludeInspectionError("malformed_output") from exc
    required = {
        "attack_resource_path",
        "control_resource_path",
        "attack_content_sha256",
        "attack_content_size_bytes",
        "attack_owner_uid",
        "attack_owner_gid",
        "attack_file_mode",
        "attack_link_count",
        "attack_is_regular_file",
        "attack_is_symlink",
        "control_lstat_exists",
    }
    if not isinstance(payload, dict) or set(payload) != required:
        raise _PhpIncludeInspectionError("invalid_shape")
    if (
        payload["attack_resource_path"] != attack_path
        or payload["control_resource_path"] != control_path
        or not isinstance(payload["attack_content_sha256"], str)
        or re.fullmatch(r"[0-9a-f]{64}", payload["attack_content_sha256"]) is None
        or any(
            type(payload[key]) is not int
            for key in (
                "attack_content_size_bytes",
                "attack_owner_uid",
                "attack_owner_gid",
                "attack_file_mode",
                "attack_link_count",
            )
        )
        or type(payload["attack_is_regular_file"]) is not bool
        or type(payload["attack_is_symlink"]) is not bool
        or type(payload["control_lstat_exists"]) is not bool
    ):
        raise _PhpIncludeInspectionError("invalid_values")
    return payload


async def _inspect_php_include_oracle_bounded_retry(
    container_name: str,
    attack_path: str,
    control_path: str,
) -> tuple[dict[str, object], int]:
    """Retry one transport-like failure; never retry rejected state evidence."""
    try:
        return (
            await _inspect_php_include_oracle(
                container_name,
                attack_path,
                control_path,
            ),
            0,
        )
    except _PhpIncludeInspectionError as exc:
        if exc.reason not in _PHP_INCLUDE_RETRIABLE_INSPECTION_FAILURES:
            raise
        logger.warning(
            "retrying PHP include oracle inspection after %s",
            exc.reason,
        )
    await asyncio.sleep(_PHP_INCLUDE_INSPECTION_RETRY_DELAY_S)
    try:
        measured = await _inspect_php_include_oracle(
            container_name,
            attack_path,
            control_path,
        )
    except _PhpIncludeInspectionError as exc:
        raise _PhpIncludeInspectionError(exc.reason, retries=1) from exc
    except Exception as exc:
        raise _PhpIncludeInspectionError(
            "unexpected_failure",
            retries=1,
        ) from exc
    return measured, 1


async def _probe_php_include_mount(
    container_name: str,
    host_directory: Path,
) -> None:
    """Require the exact verifier-owned directory as a read-only bind mount."""
    _code, stdout, stderr = await _run(
        "docker",
        "inspect",
        "--format",
        "{{json .Mounts}}",
        container_name,
    )
    if stderr or len(stdout) > 64 * 1024:
        raise RuntimeError("PHP include mount inspection failed")
    try:
        mounts = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("PHP include mount inspection is malformed") from exc
    expected_source = os.fspath(host_directory.resolve(strict=True))
    matches = [
        mount
        for mount in mounts
        if isinstance(mount, dict)
        and mount.get("Destination") == PHP_INCLUDE_ORACLE_DIRECTORY
    ]
    if len(matches) != 1:
        raise RuntimeError("PHP include mount is missing or ambiguous")
    mount = matches[0]
    observed_source = mount.get("Source")
    if (
        mount.get("Type") != "bind"
        or mount.get("RW") is not False
        or not isinstance(observed_source, str)
        or observed_source not in _accepted_ssrf_bind_sources(expected_source)
    ):
        raise RuntimeError("PHP include mount is not the expected read-only bind")


_PHP_OBJECT_CALLSITE_INSPECT_SCRIPT = r"""
$path = isset($argv[1]) && is_string($argv[1]) ? $argv[1] : '';
try {
    if (
        $path === ''
        || strlen($path) > 2048
        || strpos($path, '/var/www/html/wp-content/plugins/') !== 0
        || @realpath($path) !== $path
        || is_link($path)
    ) {
        throw new RuntimeException('path');
    }
    $metadata = @lstat($path);
    if (
        ! is_array($metadata)
        || ((((int) $metadata['mode']) & 0170000) !== 0100000)
        || (int) $metadata['nlink'] !== 1
        || (int) $metadata['size'] < 1
        || (int) $metadata['size'] > 33554432
    ) {
        throw new RuntimeException('metadata');
    }
    $source = @file_get_contents($path);
    $digest = is_string($source) ? hash('sha256', $source) : false;
    if (
        ! is_string($source)
        || strlen($source) !== (int) $metadata['size']
        || ! is_string($digest)
        || strlen($digest) !== 64
    ) {
        throw new RuntimeException('source');
    }
    $line_count = substr_count($source, "\n");
    if ($source !== '' && substr($source, -1) !== "\n") {
        ++$line_count;
    }
    $output = json_encode(
        array(
            'source_sha256' => $digest,
            'source_size_bytes' => strlen($source),
            'line_count' => $line_count,
        ),
        JSON_UNESCAPED_SLASHES
    );
    if (! is_string($output) || $output === '') {
        throw new RuntimeException('json');
    }
    fwrite(STDOUT, $output);
    exit(0);
} catch (Throwable $error) {
    fwrite(STDERR, 'callsite_inspection_failed');
    exit(70);
}
"""


_PHP_OBJECT_GADGET_FILESYSTEM_SCRIPT = r"""
function sq_fail() { fwrite(STDERR, 'gadget_filesystem_failed'); exit(70); }
function sq_remove_tree($path, $root) {
    if (strpos($path, $root . '/') !== 0) { throw new RuntimeException('path'); }
    $metadata = @lstat($path);
    if (! is_array($metadata)) { return; }
    $kind = ((int) $metadata['mode']) & 0170000;
    if ($kind === 0040000 && ! is_link($path)) {
        $children = @scandir($path, SCANDIR_SORT_ASCENDING);
        if (! is_array($children)) { throw new RuntimeException('scan'); }
        foreach ($children as $name) {
            if ($name !== '.' && $name !== '..') { sq_remove_tree($path . '/' . $name, $root); }
        }
        if (! @rmdir($path)) { throw new RuntimeException('rmdir'); }
        return;
    }
    if (! @unlink($path)) { throw new RuntimeException('unlink'); }
}
try {
    $operation = isset($argv[1]) ? $argv[1] : '';
    $target = isset($argv[2]) ? $argv[2] : '';
    $content = isset($argv[3]) ? base64_decode($argv[3], true) : false;
    $require_empty = isset($argv[4]) && $argv[4] === '1';
    $root = '/var/lib/squadrone/php-object-gadget';
    $root_metadata = @lstat($root);
    if (@realpath($root) !== $root || is_link($root) || ! is_dir($root)
        || ! is_array($root_metadata)
        || ((((int) $root_metadata['mode']) & 0170000) !== 0040000)
        || (((int) $root_metadata['mode']) & 07777) !== 0770
        || (int) $root_metadata['uid'] !== 0
        || (int) $root_metadata['gid'] !== 33) {
        throw new RuntimeException('root');
    }
    $children = @scandir($root, SCANDIR_SORT_ASCENDING);
    if (! is_array($children)) { throw new RuntimeException('scan'); }
    $children = array_values(array_diff($children, array('.', '..')));
    if (count($children) > 1024) { throw new RuntimeException('entries'); }
    if ($operation === 'cleanup') {
        if ($require_empty && count($children) !== 0) { throw new RuntimeException('not_empty'); }
        foreach ($children as $name) { sq_remove_tree($root . '/' . $name, $root); }
        $result = array('operation' => 'cleanup', 'directory_entry_count' => 0);
    } elseif ($operation === 'provision') {
        if (count($children) !== 0 || ! is_string($content)) { throw new RuntimeException('state'); }
        if (! preg_match('#\A/var/lib/squadrone/php-object-gadget/[A-Za-z0-9_.-]{1,320}\z#D', $target)
            || strpos(basename($target), '..') !== false) {
            throw new RuntimeException('target');
        }
        $handle = @fopen($target, 'x+b');
        if (! is_resource($handle)) { throw new RuntimeException('create'); }
        $written = @fwrite($handle, $content);
        $flushed = @fflush($handle);
        @fclose($handle);
        if ($written !== strlen($content) || ! $flushed || ! @chmod($target, 0600)
            || ! @chown($target, 'www-data') || ! @chgrp($target, 'www-data')) {
            throw new RuntimeException('protect');
        }
        clearstatcache(true, $target);
        $metadata = @lstat($target);
        if (! is_array($metadata) || (int) $metadata['nlink'] !== 1) {
            throw new RuntimeException('metadata');
        }
        $result = array('operation' => 'provision', 'directory_entry_count' => 1);
    } elseif ($operation === 'measure') {
        if ($target === '' || dirname($target) !== $root) { throw new RuntimeException('target'); }
        $inventory = array();
        foreach ($children as $name) {
            $path = $root . '/' . $name;
            $metadata = @lstat($path);
            if (! is_array($metadata)) { throw new RuntimeException('lstat'); }
            $kind = ((int) $metadata['mode']) & 0170000;
            $digest = $kind === 0100000 ? @hash_file('sha256', $path) : null;
            $inventory[] = array(
                'name' => $name,
                'kind' => $kind,
                'mode' => ((int) $metadata['mode']) & 07777,
                'uid' => (int) $metadata['uid'],
                'gid' => (int) $metadata['gid'],
                'nlink' => (int) $metadata['nlink'],
                'size' => (int) $metadata['size'],
                'sha256' => $digest,
            );
        }
        $metadata = @lstat($target);
        $exists = is_array($metadata);
        $kind = $exists ? (((int) $metadata['mode']) & 0170000) : 0;
        $result = array(
            'operation' => 'measure',
            'target_path_sha256' => hash('sha256', $target),
            'target_exists' => $exists,
            'target_regular' => $exists && $kind === 0100000,
            'target_symlink' => $exists && is_link($target),
            'target_content_sha256' => $exists && $kind === 0100000 ? @hash_file('sha256', $target) : null,
            'target_size_bytes' => $exists ? (int) $metadata['size'] : null,
            'target_uid' => $exists ? (int) $metadata['uid'] : null,
            'target_gid' => $exists ? (int) $metadata['gid'] : null,
            'target_mode' => $exists ? (((int) $metadata['mode']) & 07777) : null,
            'target_inode' => $exists ? (int) $metadata['ino'] : null,
            'target_link_count' => $exists ? (int) $metadata['nlink'] : null,
            'directory_entry_count' => count($children),
            'directory_inventory_sha256' => hash('sha256', json_encode($inventory, JSON_UNESCAPED_SLASHES)),
            'directory_uid' => (int) $root_metadata['uid'],
            'directory_gid' => (int) $root_metadata['gid'],
            'directory_mode' => ((int) $root_metadata['mode']) & 07777,
        );
    } else { throw new RuntimeException('operation'); }
    $encoded = json_encode($result, JSON_UNESCAPED_SLASHES);
    if (! is_string($encoded) || strlen($encoded) > 8192) { throw new RuntimeException('json'); }
    fwrite(STDOUT, $encoded);
    exit(0);
} catch (Throwable $error) { sq_fail(); }
"""


_PHP_OBJECT_GADGET_SOURCE_SCRIPT = r"""
function sq_source_fail() { fwrite(STDERR, 'gadget_source_failed'); exit(70); }
function sq_source_lines($value) {
    return explode("\n", str_replace(array("\r\n", "\r"), "\n", $value));
}
function sq_source_anchors($value, &$anchors) {
    if (! is_array($value)) { return; }
    if (isset($value['file'], $value['line'], $value['source_code'])
        && is_string($value['file']) && is_int($value['line'])
        && is_string($value['source_code'])) {
        $anchors[] = $value;
    }
    foreach ($value as $child) { sq_source_anchors($child, $anchors); }
}
try {
    $slug = isset($argv[1]) ? $argv[1] : '';
    $decoded = isset($argv[2]) ? base64_decode($argv[2], true) : false;
    $recipe = is_string($decoded) ? json_decode($decoded, true) : null;
    $root = '/var/www/html/wp-content/plugins/' . $slug;
    if (! preg_match('/\A[a-z0-9][a-z0-9_-]{0,199}\z/D', $slug)
        || ! is_array($recipe) || @realpath($root) !== $root || is_link($root)) {
        throw new RuntimeException('input');
    }
    $anchors = array(); sq_source_anchors($recipe, $anchors);
    if (count($anchors) < 3 || count($anchors) > 256) {
        throw new RuntimeException('anchors');
    }
    $files = array();
    foreach ($anchors as $anchor) {
        $relative = $anchor['file']; $path = $root . '/' . $relative;
        $real = @realpath($path); $metadata = @lstat($path);
        if (! is_string($real) || $real !== $path || strpos($real, $root . '/') !== 0
            || is_link($path) || ! is_array($metadata)
            || ((((int) $metadata['mode']) & 0170000) !== 0100000)
            || (int) $metadata['nlink'] !== 1 || (int) $metadata['size'] < 1
            || (int) $metadata['size'] > 33554432) {
            throw new RuntimeException('source_file');
        }
        $source = @file_get_contents($path);
        if (! is_string($source) || strlen($source) !== (int) $metadata['size']) {
            throw new RuntimeException('source_read');
        }
        $source_lines = sq_source_lines($source);
        $quote_lines = sq_source_lines($anchor['source_code']);
        $offset = $anchor['line'] - 1;
        if ($offset < 0 || $offset + count($quote_lines) > count($source_lines)) {
            throw new RuntimeException('source_range');
        }
        foreach ($quote_lines as $index => $quote) {
            if (trim($source_lines[$offset + $index]) !== trim($quote)) {
                throw new RuntimeException('source_quote');
            }
        }
        $files[$relative] = hash('sha256', $source);
    }
    ksort($files, SORT_STRING);
    if (count($files) < 1 || count($files) > 64) {
        throw new RuntimeException('files');
    }
    $result = array(
        'source_inventory_sha256' => hash(
            'sha256',
            json_encode($files, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
        ),
        'source_file_count' => count($files),
        'source_anchor_count' => count($anchors),
    );
    $encoded = json_encode($result, JSON_UNESCAPED_SLASHES);
    if (! is_string($encoded) || strlen($encoded) > 1024) {
        throw new RuntimeException('json');
    }
    fwrite(STDOUT, $encoded); exit(0);
} catch (Throwable $error) { sq_source_fail(); }
"""


_PHP_OBJECT_GADGET_RUNTIME_SCRIPT = r"""
function sq_runtime_fail() { fwrite(STDERR, 'gadget_runtime_failed'); exit(70); }
function sq_lines($value) {
    return explode("\n", str_replace(array("\r\n", "\r"), "\n", $value));
}
function sq_collect_anchors($value, &$anchors, &$constants) {
    if (! is_array($value)) { return; }
    if (isset($value['file'], $value['line'], $value['source_code'])
        && is_string($value['file']) && is_int($value['line']) && is_string($value['source_code'])) {
        $anchors[] = $value;
    }
    if (isset($value['directory_constant']) && is_string($value['directory_constant'])) {
        $constants[$value['directory_constant']] = true;
    }
    foreach ($value as $child) { sq_collect_anchors($child, $anchors, $constants); }
}
function sq_method_identity($method) {
    $file = $method->getFileName();
    return array(
        'name' => $method->getName(),
        'declaring_class' => $method->getDeclaringClass()->getName(),
        'file' => is_string($file) ? $file : '',
        'start' => $method->getStartLine(),
        'end' => $method->getEndLine(),
        'static' => $method->isStatic(),
        'public' => $method->isPublic(),
    );
}
function sq_require_trait_free_hierarchy($class) {
    $current = $class;
    while ($current) {
        if ($current->isTrait() || count($current->getTraitNames()) !== 0) {
            throw new RuntimeException('trait');
        }
        $current = $current->getParentClass();
    }
}
function sq_attest_static_array_markers($class, $source, $opaque_properties, &$identities) {
    foreach (sq_lines($source) as $line) {
        $broad_count = preg_match_all(
            '/\b(?:self|static)::\$[A-Za-z_][A-Za-z0-9_]*\s*\[[^\]\r\n]+\]\s*=\s*true\s*;/i',
            $line,
            $broad_matches
        );
        if ($broad_count === false) { throw new RuntimeException('static_marker_parse'); }
        if ($broad_count === 0) { continue; }
        $match = array();
        if ($broad_count !== 1 || preg_match(
            '/\A\s*self::\$([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*\$this\s*->\s*'
            . '([A-Za-z_][A-Za-z0-9_]*)\s*\]\s*=\s*true\s*;\s*\z/i',
            $line,
            $match
        ) !== 1) {
            throw new RuntimeException('static_marker_shape');
        }
        $name = $match[1]; $opaque_property = $match[2];
        if (! isset($opaque_properties[$opaque_property]) || ! $class->hasProperty($name)) {
            throw new RuntimeException('static_marker_missing');
        }
        $property = $class->getProperty($name);
        $declaring = $property->getDeclaringClass();
        $defaults = $declaring->getDefaultProperties();
        if ($declaring->getName() !== $class->getName() || ! $property->isStatic()
            || ! array_key_exists($name, $defaults)
            || ! is_array($defaults[$name]) || ! is_array($property->getValue())) {
            throw new RuntimeException('static_marker_type');
        }
        $identity = array(
            'name' => $name,
            'opaque_property' => $opaque_property,
            'declaring_class' => $declaring->getName(),
            'native_array' => true,
        );
        $identity_key = $name . "\0" . $opaque_property;
        if (isset($identities[$identity_key])) {
            throw new RuntimeException('static_marker_duplicate');
        }
        $identities[$identity_key] = $identity;
    }
}
try {
    $slug = isset($argv[1]) ? $argv[1] : '';
    $decoded = isset($argv[2]) ? base64_decode($argv[2], true) : false;
    $recipe = is_string($decoded) ? json_decode($decoded, true) : null;
    $root = '/var/www/html/wp-content/plugins/' . $slug;
    if (! preg_match('/\A[a-z0-9][a-z0-9_-]{0,199}\z/D', $slug)
        || ! is_array($recipe) || @realpath($root) !== $root || is_link($root)) {
        throw new RuntimeException('input');
    }
    $anchors = array(); $constants = array();
    sq_collect_anchors($recipe, $anchors, $constants);
    if (count($anchors) < 3 || count($anchors) > 256) { throw new RuntimeException('anchors'); }
    $files = array();
    foreach ($anchors as $anchor) {
        $relative = $anchor['file'];
        $path = $root . '/' . $relative;
        $real = @realpath($path);
        $metadata = @lstat($path);
        if (! is_string($real) || $real !== $path || strpos($real, $root . '/') !== 0
            || is_link($path) || ! is_array($metadata)
            || ((((int) $metadata['mode']) & 0170000) !== 0100000)
            || (int) $metadata['nlink'] !== 1 || (int) $metadata['size'] < 1
            || (int) $metadata['size'] > 33554432) {
            throw new RuntimeException('source_file');
        }
        $source = @file_get_contents($path);
        if (! is_string($source) || strlen($source) !== (int) $metadata['size']) {
            throw new RuntimeException('source_read');
        }
        $source_lines = sq_lines($source); $quote_lines = sq_lines($anchor['source_code']);
        $offset = $anchor['line'] - 1;
        if ($offset < 0 || $offset + count($quote_lines) > count($source_lines)) {
            throw new RuntimeException('source_range');
        }
        foreach ($quote_lines as $index => $quote) {
            if (trim($source_lines[$offset + $index]) !== trim($quote)) {
                throw new RuntimeException('source_quote');
            }
        }
        $files[$relative] = hash('sha256', $source);
    }
    ksort($files, SORT_STRING);
    if (count($files) < 1 || count($files) > 64) { throw new RuntimeException('files'); }
    $source_inventory = hash('sha256', json_encode($files, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));

    ob_start(); require '/var/www/html/wp-load.php'; ob_end_clean();
    if (sys_get_temp_dir() !== '/var/lib/squadrone/php-object-gadget') {
        throw new RuntimeException('tmpdir');
    }
    foreach (array_keys($constants) as $constant_name) {
        if (! defined($constant_name)
            || constant($constant_name) !== '/var/lib/squadrone/php-object-gadget/') {
            throw new RuntimeException('constant');
        }
    }

    $object = $recipe['gadget_object']; $class_name = $object['class_name'];
    if (! is_string($class_name) || ! class_exists($class_name, true)) {
        throw new RuntimeException('class');
    }
    $class = new ReflectionClass($class_name);
    $class_file = $class->getFileName();
    $class_expected_file = $root . '/' . $object['class_anchor']['file'];
    if ($class->getName() !== $class_name || ! is_string($class_file)
        || @realpath($class_file) !== $class_expected_file || $class->isInternal()
        || $class->getStartLine() !== $object['class_anchor']['line']
        || $class->isInterface() || $class->isTrait()
        || (method_exists($class, 'isEnum') && $class->isEnum())
        || count($class->getTraitNames()) !== 0
        || $class->implementsInterface('Serializable')) {
        throw new RuntimeException('class_identity');
    }
    $ancestor = $class->getParentClass();
    while ($ancestor) {
        if (count($ancestor->getTraitNames()) !== 0) {
            throw new RuntimeException('ancestor_trait');
        }
        $ancestor = $ancestor->getParentClass();
    }
    $trigger_name = $object['trigger'];
    foreach ($class->getMethods() as $candidate_method) {
        $candidate_name = strtolower($candidate_method->getName());
        if (strpos($candidate_name, '__') === 0
            && $candidate_name !== '__construct'
            && $candidate_name !== strtolower($trigger_name)) {
            throw new RuntimeException('magic');
        }
    }
    if (! $class->hasMethod($trigger_name)) { throw new RuntimeException('trigger'); }
    $trigger = $class->getMethod($trigger_name);
    $trigger_anchor = $object['trigger_anchor'];
    $trigger_file = $root . '/' . $trigger_anchor['file'];
    $trigger_line_count = count(sq_lines($trigger_anchor['source_code']));
    if ($trigger->getName() !== $trigger_name
        || $trigger->getDeclaringClass()->getName() !== $object['trigger_declaring_class']
        || @realpath($trigger->getFileName()) !== $trigger_file
        || $trigger->getStartLine() !== $trigger_anchor['line']
        || $trigger->getEndLine() !== $trigger_anchor['line'] + $trigger_line_count - 1) {
        throw new RuntimeException('trigger_identity');
    }

    $opaque_properties = array();
    foreach ($object['properties'] as $property) {
        if (isset($property['value']['kind'])
            && $property['value']['kind'] === 'opaque_generation_id') {
            $opaque_properties[$property['name']] = true;
        }
    }
    $reflection = array(
        'class' => array(
            'name' => $class->getName(), 'file' => $class_file,
            'start' => $class->getStartLine(), 'end' => $class->getEndLine(),
            'parent' => ($class->getParentClass() ? $class->getParentClass()->getName() : null),
        ),
        'trigger' => sq_method_identity($trigger), 'properties' => array(),
        'helpers' => array(), 'static_array_markers' => array(),
    );
    sq_attest_static_array_markers(
        $class,
        $trigger_anchor['source_code'],
        $opaque_properties,
        $reflection['static_array_markers']
    );
    foreach ($object['properties'] as $property) {
        $declaring = $property['declaring_class']; $name = $property['name'];
        if (! class_exists($declaring, true)) { throw new RuntimeException('property_class'); }
        $declaring_class = new ReflectionClass($declaring);
        if ($declaring_class->getName() !== $declaring
            || ($declaring !== $class_name && ! is_subclass_of($class_name, $declaring, true))
            || ! $declaring_class->hasProperty($name)) {
            throw new RuntimeException('property_missing');
        }
        $reflected = $declaring_class->getProperty($name);
        $visibility = $reflected->isPrivate() ? 'private' : ($reflected->isProtected() ? 'protected' : 'public');
        if ($reflected->getDeclaringClass()->getName() !== $declaring
            || $visibility !== $property['visibility'] || $reflected->isStatic()) {
            throw new RuntimeException('property_identity');
        }
        $declaring_file = $declaring_class->getFileName();
        $declaring_real = is_string($declaring_file) ? @realpath($declaring_file) : false;
        $declaring_metadata = is_string($declaring_real) ? @lstat($declaring_real) : false;
        $declaring_digest = is_string($declaring_real) ? @hash_file('sha256', $declaring_real) : false;
        if (! is_string($declaring_real) || strpos($declaring_real, $root . '/') !== 0
            || is_link($declaring_real) || ! is_array($declaring_metadata)
            || ((((int) $declaring_metadata['mode']) & 0170000) !== 0100000)
            || (int) $declaring_metadata['nlink'] !== 1
            || ! is_string($declaring_digest) || strlen($declaring_digest) !== 64) {
            throw new RuntimeException('property_source');
        }
        $defaults = $declaring_class->getDefaultProperties();
        $default_present = array_key_exists($name, $defaults);
        $default_json = $default_present ? json_encode($defaults[$name], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) : '';
        if ($default_present && ! is_string($default_json)) { throw new RuntimeException('property_default'); }
        $type = $reflected->getType();
        if ($type instanceof ReflectionUnionType || $type instanceof ReflectionIntersectionType) {
            throw new RuntimeException('property_type');
        }
        $reflection['properties'][] = array(
            'name' => $name, 'declaring_class' => $declaring, 'visibility' => $visibility,
            'type' => $type ? (string) $type : '', 'default_present' => $default_present,
            'default_sha256' => hash('sha256', $default_json), 'file' => $declaring_real,
            'source_sha256' => $declaring_digest,
        );
    }
    foreach ($recipe['helper_anchors'] as $helper) {
        $symbol = $helper['symbol']; $anchor = $helper['anchor'];
        if (strpos($symbol, '::') !== false) {
            list($helper_class, $helper_method) = explode('::', $symbol, 2);
            if (! class_exists($helper_class, true)) { throw new RuntimeException('helper_class'); }
            $reflected = new ReflectionMethod($helper_class, $helper_method);
            if ($reflected->getName() !== $helper_method
                || $reflected->getDeclaringClass()->getName() !== $helper_class) {
                throw new RuntimeException('helper_declaring');
            }
            sq_require_trait_free_hierarchy($reflected->getDeclaringClass());
            $identity = sq_method_identity($reflected);
            $namespace = $reflected->getDeclaringClass()->getNamespaceName();
            sq_attest_static_array_markers(
                $class,
                $anchor['source_code'],
                $opaque_properties,
                $reflection['static_array_markers']
            );
        } else {
            if (! function_exists($symbol)) { throw new RuntimeException('helper_function'); }
            $reflected = new ReflectionFunction($symbol);
            if ($reflected->getName() !== $symbol) {
                throw new RuntimeException('helper_function_identity');
            }
            $file = $reflected->getFileName();
            $identity = array('name' => $reflected->getName(), 'declaring_class' => '',
                'file' => is_string($file) ? $file : '', 'start' => $reflected->getStartLine(),
                'end' => $reflected->getEndLine(), 'static' => false, 'public' => true);
            $namespace = $reflected->getNamespaceName();
        }
        $expected_file = $root . '/' . $anchor['file'];
        $line_count = count(sq_lines($anchor['source_code']));
        if (@realpath($identity['file']) !== $expected_file
            || $identity['start'] !== $anchor['line']
            || $identity['end'] !== $anchor['line'] + $line_count - 1) {
            throw new RuntimeException('helper_identity');
        }
        if ($namespace !== '' && (function_exists($namespace . '\\unlink')
            || function_exists($namespace . '\\file_exists')
            || function_exists($namespace . '\\strpos')
            || function_exists($namespace . '\\preg_match'))) {
            throw new RuntimeException('builtin_shadow');
        }
        $reflection['helpers'][] = $identity;
    }
    $namespace = $class->getNamespaceName();
    if ($namespace !== '' && (function_exists($namespace . '\\unlink')
        || function_exists($namespace . '\\file_exists')
        || function_exists($namespace . '\\strpos')
        || function_exists($namespace . '\\preg_match'))) {
        throw new RuntimeException('builtin_shadow');
    }
    ksort($reflection['static_array_markers'], SORT_STRING);
    $reflection['static_array_markers'] = array_values($reflection['static_array_markers']);
    $reflection_sha256 = hash('sha256', json_encode($reflection, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    $result = array(
        'source_inventory_sha256' => $source_inventory,
        'reflection_sha256' => $reflection_sha256,
        'source_file_count' => count($files),
        'source_anchor_count' => count($anchors),
        'property_count' => count($object['properties']),
    );
    $encoded = json_encode($result, JSON_UNESCAPED_SLASHES);
    if (! is_string($encoded) || strlen($encoded) > 4096) { throw new RuntimeException('json'); }
    fwrite(STDOUT, $encoded); exit(0);
} catch (Throwable $error) { if (ob_get_level()) { ob_end_clean(); } sq_runtime_fail(); }
"""


async def _inspect_php_object_gadget_runtime(
    container_name: str,
    plugin_slug: str,
    recipe: PhpObjectGadgetRecipe,
) -> dict[str, object]:
    encoded_recipe = base64.b64encode(recipe.model_dump_json().encode("utf-8")).decode(
        "ascii"
    )
    if len(encoded_recipe) > 512 * 1024:
        raise RuntimeError("PHP object gadget runtime recipe is too large")
    trusted_source_before = await _inspect_php_object_gadget_source(
        container_name,
        plugin_slug,
        encoded_recipe,
    )
    try:
        rc, stdout, _stderr = await _run(
            "docker",
            "exec",
            "--user",
            WORDPRESS_WEB_USER,
            container_name,
            "php",
            "-r",
            _PHP_OBJECT_GADGET_RUNTIME_SCRIPT,
            plugin_slug,
            encoded_recipe,
            check=False,
        )
    finally:
        trusted_source_after = await _inspect_php_object_gadget_source(
            container_name,
            plugin_slug,
            encoded_recipe,
        )
    if trusted_source_before != trusted_source_after:
        raise RuntimeError("PHP object gadget source changed during runtime inspection")
    try:
        payload = json.loads(stdout) if len(stdout) <= 4096 else None
    except (json.JSONDecodeError, TypeError, ValueError):
        payload = None
    if (
        rc != 0
        or type(payload) is not dict
        or any(
            payload.get(key) != trusted_source_before[key]
            for key in (
                "source_inventory_sha256",
                "source_file_count",
                "source_anchor_count",
            )
        )
    ):
        raise RuntimeError("PHP object gadget runtime attestation failed")
    return cast(dict[str, object], payload)


async def _inspect_php_object_gadget_source(
    container_name: str,
    plugin_slug: str,
    encoded_recipe: str,
) -> dict[str, object]:
    """Measure reviewed source in a root-owned process that never loads the plugin."""
    rc, stdout, _stderr = await _run(
        "docker",
        "exec",
        "--user",
        "root",
        container_name,
        "php",
        "-r",
        _PHP_OBJECT_GADGET_SOURCE_SCRIPT,
        plugin_slug,
        encoded_recipe,
        check=False,
    )
    try:
        payload = json.loads(stdout) if len(stdout) <= 1024 else None
    except (json.JSONDecodeError, TypeError, ValueError):
        payload = None
    required = {
        "source_inventory_sha256",
        "source_file_count",
        "source_anchor_count",
    }
    if (
        rc != 0
        or type(payload) is not dict
        or set(payload) != required
        or not isinstance(payload.get("source_inventory_sha256"), str)
        or _SHA256_RE.fullmatch(cast(str, payload["source_inventory_sha256"])) is None
        or type(payload.get("source_file_count")) is not int
        or not 1 <= cast(int, payload["source_file_count"]) <= 64
        or type(payload.get("source_anchor_count")) is not int
        or not 3 <= cast(int, payload["source_anchor_count"]) <= 256
    ):
        raise RuntimeError("PHP object gadget trusted source inspection failed")
    return cast(dict[str, object], payload)


def _validate_php_object_gadget_runtime_payload(
    payload: object,
    *,
    recipe: PhpObjectGadgetRecipe,
    effect_binding_kind: object,
) -> PhpObjectGadgetRuntimeBinding:
    required = {
        "source_inventory_sha256",
        "reflection_sha256",
        "source_file_count",
        "source_anchor_count",
        "property_count",
    }
    if (
        type(payload) is not dict
        or set(payload) != required
        or effect_binding_kind not in {"direct_path", "guarded_opaque_prefix"}
        or not _php_object_gadget_effect_sinks_accounted(recipe)
    ):
        raise RuntimeError("PHP object gadget runtime attestation is malformed")
    values = cast(dict[str, object], payload)
    try:
        return PhpObjectGadgetRuntimeBinding(
            schema_version=PHP_OBJECT_GADGET_ORACLE_SCHEMA_VERSION,
            mode=PHP_OBJECT_GADGET_ORACLE_MODE,
            effect="file_delete",
            effect_binding_kind=cast(
                Literal["direct_path", "guarded_opaque_prefix"],
                effect_binding_kind,
            ),
            recipe_sha256=php_object_gadget_recipe_sha256(recipe),
            source_inventory_sha256=cast(str, values["source_inventory_sha256"]),
            reflection_sha256=cast(str, values["reflection_sha256"]),
            source_file_count=cast(int, values["source_file_count"]),
            source_anchor_count=cast(int, values["source_anchor_count"]),
            property_count=cast(int, values["property_count"]),
            all_effect_sinks_accounted=True,
        )
    except (TypeError, ValueError):
        raise RuntimeError("PHP object gadget runtime attestation is unsafe") from None


def _php_object_gadget_recipe_directory_constants(
    recipe: PhpObjectGadgetRecipe,
) -> tuple[str, ...]:
    """Return the exact reviewed constants that must map to the private tmpfs."""
    constants = {
        guarded.directory_constant for guarded in recipe.guarded_effect_anchors
    }
    binding = recipe.effect_binding
    if isinstance(binding, PhpObjectGadgetDirectPathEffectBinding):
        if binding.local_path_check is not None:
            constants.add(binding.local_path_check.directory_constant)
    else:
        constants.add(binding.effect.directory_constant)
    return tuple(sorted(constants))


def _php_object_gadget_effect_sinks_accounted(
    recipe: PhpObjectGadgetRecipe,
) -> bool:
    """Require every builtin unlink in a complete reviewed body to be declared."""

    def lines(anchor: PhpObjectGadgetSourceAnchor) -> list[str]:
        return anchor.source_code.splitlines() or [anchor.source_code]

    def identity(anchor: PhpObjectGadgetSourceAnchor) -> tuple[str, int, str] | None:
        anchor_lines = lines(anchor)
        if (
            len(anchor_lines) != 1
            or len(_PHP_OBJECT_GADGET_UNLINK_CALL_RE.findall(anchor_lines[0])) != 1
        ):
            return None
        return (anchor.file, anchor.line, anchor_lines[0].strip())

    def contains(
        parent: PhpObjectGadgetSourceAnchor,
        child: PhpObjectGadgetSourceAnchor,
    ) -> bool:
        if parent.file != child.file or child.line < parent.line:
            return False
        parent_lines = lines(parent)
        child_lines = lines(child)
        offset = child.line - parent.line
        return offset + len(child_lines) <= len(parent_lines) and [
            line.strip() for line in parent_lines[offset : offset + len(child_lines)]
        ] == [line.strip() for line in child_lines]

    bodies = (
        recipe.gadget_object.trigger_anchor,
        *(helper.anchor for helper in recipe.helper_anchors),
    )
    binding = recipe.effect_binding
    declared_anchors: tuple[PhpObjectGadgetSourceAnchor, ...]
    if isinstance(binding, PhpObjectGadgetDirectPathEffectBinding):
        declared_anchors = (
            binding.effect_anchor,
            *(guarded.anchor for guarded in recipe.guarded_effect_anchors),
        )
    else:
        declared_anchors = (
            binding.effect.anchor,
            *(guarded.anchor for guarded in recipe.guarded_effect_anchors),
        )

    declared: set[tuple[str, int, str]] = set()
    for anchor in declared_anchors:
        sink = identity(anchor)
        if sink is None or sum(contains(body, anchor) for body in bodies) != 1:
            return False
        declared.add(sink)
    if len(declared) != len(declared_anchors):
        return False

    observed: set[tuple[str, int, str]] = set()
    for body in bodies:
        for offset, source_line in enumerate(lines(body)):
            count = len(_PHP_OBJECT_GADGET_UNLINK_CALL_RE.findall(source_line))
            if count > 1:
                return False
            if count == 1:
                sink = (body.file, body.line + offset, source_line.strip())
                if sink in observed:
                    return False
                observed.add(sink)
    return observed == declared


async def _php_object_gadget_filesystem_operation(
    container_name: str,
    *,
    operation: Literal["cleanup", "provision", "measure"],
    target_path: str,
    content: bytes,
    require_empty: bool,
) -> dict[str, object]:
    rc, filesystem_type, _stderr = await _run(
        "docker",
        "exec",
        "--user",
        "root",
        container_name,
        "stat",
        "-f",
        "-c",
        "%T",
        PHP_OBJECT_GADGET_DIRECTORY,
        check=False,
    )
    if rc != 0 or filesystem_type.strip() != "tmpfs":
        raise RuntimeError("PHP object gadget directory is not its dedicated tmpfs")
    rc, stdout, _stderr = await _run(
        "docker",
        "exec",
        "--user",
        "root",
        container_name,
        "php",
        "-r",
        _PHP_OBJECT_GADGET_FILESYSTEM_SCRIPT,
        operation,
        target_path,
        base64.b64encode(content).decode("ascii"),
        "1" if require_empty else "0",
        check=False,
    )
    try:
        payload = json.loads(stdout) if len(stdout) <= 8192 else None
    except (json.JSONDecodeError, TypeError, ValueError):
        payload = None
    if rc != 0 or type(payload) is not dict:
        raise RuntimeError("PHP object gadget filesystem operation failed")
    return cast(dict[str, object], payload)


def _validate_php_object_gadget_measurement_payload(
    payload: object,
    *,
    target_path: str,
) -> PhpObjectGadgetFileMeasurement:
    required = {
        "operation",
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
    }
    if type(payload) is not dict or set(payload) != required:
        raise RuntimeError("PHP object gadget measurement has an invalid shape")
    values = cast(dict[str, object], payload)
    if (
        values["operation"] != "measure"
        or values["target_path_sha256"]
        != hashlib.sha256(target_path.encode("ascii")).hexdigest()
    ):
        raise RuntimeError("PHP object gadget measurement changed its target")
    try:
        return PhpObjectGadgetFileMeasurement(
            **{key: value for key, value in values.items() if key != "operation"},
            directory_is_tmpfs=True,
        )
    except (TypeError, ValueError):
        raise RuntimeError("PHP object gadget measurement is unsafe") from None


_PHP_OBJECT_SURFACE_GUARD_SCRIPT = r"""
function sq_guard_fail($reason) {
    fwrite(STDERR, "surface_guard_" . $reason);
    exit(70);
}

function sq_guard_json($value) {
    $encoded = json_encode($value, JSON_UNESCAPED_SLASHES);
    if (! is_string($encoded) || $encoded === '') {
        throw new RuntimeException('json');
    }
    return $encoded;
}

function sq_guard_collect($slug) {
    $root = '/var/www/html';
    $content = $root . '/wp-content';
    $plugins = $content . '/plugins';
    $themes = $content . '/themes';
    $mu_plugins = $content . '/mu-plugins';
    $target = $plugins . '/' . $slug;
    $target_stat = @lstat($target);
    if (
        ! is_array($target_stat)
        || (((int) $target_stat['mode']) & 0170000) !== 0040000
        || is_link($target)
    ) {
        throw new RuntimeException('target');
    }

    // Root and wp-content entry sets protect config/drop-in and directory
    // replacement. Plugins, themes, and MU-plugins are protected recursively.
    $scopes = array(
        array($root, 1),
        array($content, 1),
        array($root . '/wp-admin', -1),
        array($root . '/wp-includes', -1),
        array($plugins, -1),
        array($themes, -1),
        array($mu_plugins, -1),
    );
    $entries = array();
    $seen = array();
    foreach ($scopes as $scope) {
        $stack = array(array($scope[0], 0));
        while ($stack) {
            $current = array_pop($stack);
            $path = $current[0];
            $depth = $current[1];
            if (
                ! is_string($path)
                || strlen($path) > 8192
                || ($path !== $root && strpos($path, $root . '/') !== 0)
            ) {
                throw new RuntimeException('path');
            }
            $metadata = @lstat($path);
            if (! is_array($metadata) || is_link($path)) {
                throw new RuntimeException('link');
            }
            $kind_bits = ((int) $metadata['mode']) & 0170000;
            if ($kind_bits === 0040000) {
                $kind = 'd';
            } elseif ($kind_bits === 0100000) {
                $kind = 'f';
                if ((int) $metadata['nlink'] !== 1) {
                    throw new RuntimeException('hardlink');
                }
            } else {
                throw new RuntimeException('special');
            }

            if (! isset($seen[$path])) {
                $seen[$path] = true;
                $digest = '';
                $size = 0;
                if ($kind === 'f') {
                    $digest = @hash_file('sha256', $path);
                    if (! is_string($digest) || strlen($digest) !== 64) {
                        throw new RuntimeException('hash');
                    }
                    $size = (int) $metadata['size'];
                    if ($size < 0) {
                        throw new RuntimeException('size');
                    }
                }
                $entries[] = array(
                    'path' => $path,
                    'kind' => $kind,
                    'mode' => ((int) $metadata['mode']) & 07777,
                    'uid' => (int) $metadata['uid'],
                    'gid' => (int) $metadata['gid'],
                    'nlink' => (int) $metadata['nlink'],
                    'size' => $size,
                    'sha256' => $digest,
                );
                if (count($entries) > 30000) {
                    throw new RuntimeException('entries');
                }
            }

            if ($kind === 'd' && ($scope[1] < 0 || $depth < $scope[1])) {
                $children = @scandir($path, SCANDIR_SORT_ASCENDING);
                if (! is_array($children)) {
                    throw new RuntimeException('scan');
                }
                for ($index = count($children) - 1; $index >= 0; --$index) {
                    $name = $children[$index];
                    if ($name === '.' || $name === '..') {
                        continue;
                    }
                    if (! is_string($name) || preg_match('//u', $name) !== 1) {
                        throw new RuntimeException('name');
                    }
                    $stack[] = array($path . '/' . $name, $depth + 1);
                }
            }
        }
    }
    usort(
        $entries,
        static function ($left, $right) {
            return strcmp($left['path'], $right['path']);
        }
    );
    return $entries;
}

function sq_guard_expected_frozen($entries) {
    $expected = array();
    foreach ($entries as $entry) {
        $entry['mode'] = ((int) $entry['mode']) & ~0222;
        $entry['uid'] = 0;
        $entry['gid'] = 0;
        $expected[] = $entry;
    }
    return $expected;
}

function sq_guard_restore_modes($entries) {
    $restored = true;
    for ($index = count($entries) - 1; $index >= 0; --$index) {
        $entry = $entries[$index];
        if (
            ! is_array($entry)
            || array_keys($entry) !== array(
                'path', 'kind', 'mode', 'uid', 'gid', 'nlink', 'size', 'sha256'
            )
            || ! is_string($entry['path'])
            || ! is_string($entry['kind'])
            || ! is_int($entry['mode'])
            || ! is_int($entry['uid'])
            || ! is_int($entry['gid'])
        ) {
            $restored = false;
            continue;
        }
        $metadata = @lstat($entry['path']);
        if (! is_array($metadata) || is_link($entry['path'])) {
            $restored = false;
            continue;
        }
        $kind_bits = ((int) $metadata['mode']) & 0170000;
        $actual_kind = $kind_bits === 0040000 ? 'd' : (
            $kind_bits === 0100000 ? 'f' : ''
        );
        if ($actual_kind !== $entry['kind']) {
            $restored = false;
            continue;
        }
        if (
            ! @chown($entry['path'], $entry['uid'])
            || ! @chgrp($entry['path'], $entry['gid'])
            || ! @chmod($entry['path'], $entry['mode'])
        ) {
            $restored = false;
        }
    }
    return $restored;
}

function sq_guard_read_manifest($manifest, $slug) {
    $metadata = @lstat($manifest);
    if (
        ! is_array($metadata)
        || is_link($manifest)
        || ((((int) $metadata['mode']) & 0170000) !== 0100000)
        || (((int) $metadata['mode']) & 0777) !== 0600
        || (int) $metadata['uid'] !== 0
        || (int) $metadata['nlink'] !== 1
        || (int) $metadata['size'] <= 0
        || (int) $metadata['size'] > 16777216
    ) {
        throw new RuntimeException('manifest_stat');
    }
    $raw = @file_get_contents($manifest);
    if (! is_string($raw) || $raw === '') {
        throw new RuntimeException('manifest_read');
    }
    $decoded = json_decode($raw, true);
    if (
        ! is_array($decoded)
        || array_keys($decoded) !== array('schema', 'slug', 'entries')
        || $decoded['schema'] !== 1
        || $decoded['slug'] !== $slug
        || ! is_array($decoded['entries'])
        || count($decoded['entries']) < 1
        || count($decoded['entries']) > 30000
    ) {
        throw new RuntimeException('manifest_shape');
    }
    return array($raw, $decoded['entries']);
}

$operation = isset($argv[1]) && is_string($argv[1]) ? $argv[1] : '';
$slug = isset($argv[2]) && is_string($argv[2]) ? $argv[2] : '';
$manifest = isset($argv[3]) && is_string($argv[3]) ? $argv[3] : '';
if (
    preg_match('/\A[a-z0-9][a-z0-9_-]{0,199}\z/D', $slug) !== 1
    || preg_match(
        '/\A\/tmp\/squadrone-object-surfaces-[0-9a-f]{32}\.json\z/D',
        $manifest
    ) !== 1
) {
    sq_guard_fail('arguments');
}

try {
    if ($operation === 'freeze') {
        if (@lstat($manifest) !== false) {
            throw new RuntimeException('manifest_collision');
        }
        $original = sq_guard_collect($slug);
        $manifest_value = array(
            'schema' => 1,
            'slug' => $slug,
            'entries' => $original,
        );
        $manifest_json = sq_guard_json($manifest_value);
        $handle = @fopen($manifest, 'x');
        if ($handle === false) {
            throw new RuntimeException('manifest_create');
        }
        $manifest_owned = true;
        try {
            $offset = 0;
            $length = strlen($manifest_json);
            while ($offset < $length) {
                $written = fwrite($handle, substr($manifest_json, $offset));
                if (! is_int($written) || $written <= 0) {
                    throw new RuntimeException('manifest_write');
                }
                $offset += $written;
            }
            if (! fflush($handle)) {
                throw new RuntimeException('manifest_flush');
            }
        } finally {
            fclose($handle);
        }
        if (! @chmod($manifest, 0600)) {
            throw new RuntimeException('manifest_mode');
        }
        foreach ($original as $entry) {
            if (
                ! @chown($entry['path'], 0)
                || ! @chgrp($entry['path'], 0)
                || ! @chmod($entry['path'], ((int) $entry['mode']) & ~0222)
            ) {
                throw new RuntimeException('freeze_mode');
            }
        }
        $frozen = sq_guard_collect($slug);
        $expected_frozen = sq_guard_expected_frozen($original);
        if ($frozen !== $expected_frozen) {
            throw new RuntimeException('freeze_drift');
        }
        $output = array(
            'operation' => 'freeze',
            'entry_count' => count($original),
            'original_sha256' => hash('sha256', sq_guard_json($original)),
            'frozen_sha256' => hash('sha256', sq_guard_json($frozen)),
            'manifest_sha256' => hash('sha256', $manifest_json),
        );
        fwrite(STDOUT, sq_guard_json($output));
        exit(0);
    }

    list($manifest_json, $original) = sq_guard_read_manifest($manifest, $slug);
    $expected_frozen = sq_guard_expected_frozen($original);
    $current = sq_guard_collect($slug);
    $drifted = $current !== $expected_frozen;
    if ($operation === 'attest') {
        if ($drifted) {
            throw new RuntimeException('attestation_drift');
        }
        $output = array(
            'operation' => 'attest',
            'entry_count' => count($original),
            'original_sha256' => hash('sha256', sq_guard_json($original)),
            'frozen_sha256' => hash('sha256', sq_guard_json($current)),
            'manifest_sha256' => hash('sha256', $manifest_json),
        );
        fwrite(STDOUT, sq_guard_json($output));
        exit(0);
    }
    if ($operation !== 'restore') {
        throw new RuntimeException('operation');
    }

    $modes_restored = sq_guard_restore_modes($original);
    $restored = false;
    try {
        $after = sq_guard_collect($slug);
        $restored = $modes_restored && $after === $original;
    } catch (Throwable $ignored) {
        $restored = false;
    }
    $unlinked = @unlink($manifest) && @lstat($manifest) === false;
    $output = array(
        'operation' => 'restore',
        'entry_count' => count($original),
        'original_sha256' => hash('sha256', sq_guard_json($original)),
        'drift_before_restore' => $drifted,
        'restored' => $restored,
        'manifest_removed' => $unlinked,
    );
    fwrite(STDOUT, sq_guard_json($output));
    exit(($drifted || ! $restored || ! $unlinked) ? 71 : 0);
} catch (Throwable $error) {
    if (
        isset($operation)
        && $operation === 'freeze'
        && isset($original)
        && is_array($original)
    ) {
        sq_guard_restore_modes($original);
    }
    if (isset($manifest_owned) && $manifest_owned === true) {
        @unlink($manifest);
    }
    sq_guard_fail('failed');
}
"""


def _validate_php_object_surface_summary(
    value: object,
    *,
    operation: Literal["freeze", "attest"],
) -> dict[str, object]:
    """Validate one compact, secret-free response from the root guard."""
    required = {
        "operation",
        "entry_count",
        "original_sha256",
        "frozen_sha256",
        "manifest_sha256",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise RuntimeError("PHP object executable-surface guard returned invalid data")
    entry_count = value.get("entry_count")
    if (
        value.get("operation") != operation
        or type(entry_count) is not int
        or not 1 <= entry_count <= 30000
        or any(
            not isinstance(value.get(field), str)
            or _SHA256_RE.fullmatch(cast(str, value.get(field))) is None
            for field in (
                "original_sha256",
                "frozen_sha256",
                "manifest_sha256",
            )
        )
    ):
        raise RuntimeError("PHP object executable-surface guard returned invalid data")
    return value


class SandboxManager:
    """Boots a fresh WordPress + MariaDB stack and tears it down on exit."""

    # A trusted ingress publishes WordPress's port 80 on a dynamic host port for
    # PoCs. WP-CLI setup runs inside WordPress, so its HTTP postconditions must use
    # the fixed container-local listener instead of ``target_url``.
    INTERNAL_WORDPRESS_ORIGIN = "http://127.0.0.1:80"

    def setup_http_context(self) -> SetupHttpContext:
        """Return the container connect address and WordPress's canonical Host.

        The host-facing URL is deliberately reduced to its HTTP authority so setup
        code cannot accidentally use a host-published port as an in-container
        destination.
        """
        if not self.target_url:
            raise RuntimeError("sandbox target URL is unavailable for setup HTTP")
        return SetupHttpContext.from_wordpress_origins(
            internal_connect_origin=self.INTERNAL_WORDPRESS_ORIGIN,
            canonical_wordpress_origin=self.target_url,
        )

    def __init__(
        self,
        config: SandboxConfig,
        boot_timeout_s: int = 60,
        poc_timeout_s: int = 120,
        *,
        ssrf_oracle_modes: frozenset[Literal["http", "local_resource"]] = frozenset(),
        php_include_oracle_enabled: bool = False,
        php_object_oracle_enabled: bool = False,
        php_object_gadget_oracle_enabled: bool = False,
        php_object_gadget_directory_constants: frozenset[str] = frozenset(),
    ):
        unknown_ssrf_modes = set(ssrf_oracle_modes).difference(_SSRF_ORACLE_MODES)
        if unknown_ssrf_modes:
            raise ValueError("sandbox received an unsupported SSRF oracle mode")
        if not isinstance(php_include_oracle_enabled, bool):
            raise ValueError("PHP include oracle flag must be a boolean")
        if not isinstance(php_object_oracle_enabled, bool):
            raise ValueError("PHP object oracle flag must be a boolean")
        if not isinstance(php_object_gadget_oracle_enabled, bool):
            raise ValueError("PHP object gadget oracle flag must be a boolean")
        if (
            type(php_object_gadget_directory_constants) is not frozenset
            or len(php_object_gadget_directory_constants) > 17
            or any(
                type(name) is not str
                or re.fullmatch(r"[A-Z_][A-Z0-9_]{0,127}", name) is None
                or name in _PHP_OBJECT_GADGET_FORBIDDEN_DIRECTORY_CONSTANTS
                for name in php_object_gadget_directory_constants
            )
        ):
            raise ValueError(
                "PHP object gadget directory constants must be a bounded "
                "frozenset of uppercase identifiers"
            )
        if php_object_gadget_oracle_enabled and not php_object_oracle_enabled:
            raise ValueError(
                "PHP object gadget oracle requires the primitive object oracle"
            )
        if php_object_gadget_directory_constants and not (
            php_object_gadget_oracle_enabled
        ):
            raise ValueError(
                "PHP object gadget directory constants require the gadget oracle"
            )
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
        self._ssrf_relay_port: int | None = None
        self._ssrf_local_oracle: LocalResourceSsrfOracle | None = None
        self._ssrf_local_host_dir: Path | None = None
        self._php_include_oracle_enabled = php_include_oracle_enabled
        self._php_include_oracle: PhpIncludeOracle | None = None
        self._php_include_host_dir: Path | None = None
        self._php_object_oracle_enabled = php_object_oracle_enabled
        self._php_object_oracle: PhpObjectOracle | None = None
        self._php_object_gadget_oracle_enabled = php_object_gadget_oracle_enabled
        self._php_object_gadget_directory_constants = tuple(
            sorted(php_object_gadget_directory_constants)
        )
        self._php_object_gadget_oracle: PhpObjectGadgetOracle | None = None
        self._php_object_callsite: PhpObjectCallsite | None = None
        self._installed_plugin_slug: str | None = None
        self._php_object_surface_poisoned = False
        # Snapshot archives can contain wp-config.php and therefore remain
        # sandbox-owned sensitive state even when a caller is interrupted before
        # its normal rmtree. Track every completed snapshot so teardown is the
        # final cleanup boundary, including snapshots intentionally retained after
        # a failed restore for in-lifetime recovery.
        self._snapshot_dirs: set[Path] = set()
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

    async def _stop_ingress_after_relay_failure(self) -> None:
        """Make a relay mutation failure terminal without restoring target egress."""
        self._booted = False
        try:
            await _run(
                "docker",
                "stop",
                "--time",
                "5",
                self.ingress_container_name,
                check=False,
            )
        except BaseException:
            logger.warning("failed to stop ingress after an SSRF relay failure")

    async def _disable_ssrf_relay_locked(self) -> None:
        """Remove the one fixed relay listener before its host port can be reused."""
        if self._ssrf_relay_port is None:
            return
        try:
            await _run(
                "docker",
                "exec",
                self.ingress_container_name,
                "rm",
                "-f",
                "--",
                _SSRF_RELAY_CONTAINER_CONFIG,
                _SSRF_RELAY_CONTAINER_STAGING_CONFIG,
            )
            await _run(
                "docker",
                "exec",
                self.ingress_container_name,
                "apache2ctl",
                "configtest",
            )
            await _run(
                "docker",
                "exec",
                self.ingress_container_name,
                "apache2ctl",
                "-k",
                "graceful",
            )
        except BaseException:
            await self._stop_ingress_after_relay_failure()
            raise
        self._ssrf_relay_port = None

    async def _configure_ssrf_relay_locked(self, port: int) -> None:
        """Atomically install one literal port-and-path Apache relay."""
        if (
            "http" not in self._ssrf_oracle_modes
            or not self._booted
            or not self.project
            or self.workdir is None
            or self._ssrf_relay_port is not None
        ):
            raise RuntimeError("sandbox SSRF relay is unavailable")
        config = _ssrf_relay_apache_config(port)
        local_path = self.workdir / _SSRF_RELAY_CONFIG_BASENAME
        local_path.write_text(config)
        local_path.chmod(0o600)
        self._ssrf_relay_port = port
        try:
            await _run(
                "docker",
                "cp",
                os.fspath(local_path),
                f"{self.ingress_container_name}:{_SSRF_RELAY_CONTAINER_STAGING_CONFIG}",
            )
            await _run(
                "docker",
                "exec",
                self.ingress_container_name,
                "chown",
                "root:root",
                _SSRF_RELAY_CONTAINER_STAGING_CONFIG,
            )
            await _run(
                "docker",
                "exec",
                self.ingress_container_name,
                "chmod",
                "0600",
                _SSRF_RELAY_CONTAINER_STAGING_CONFIG,
            )
            await _run(
                "docker",
                "exec",
                self.ingress_container_name,
                "mv",
                "-f",
                "--",
                _SSRF_RELAY_CONTAINER_STAGING_CONFIG,
                _SSRF_RELAY_CONTAINER_CONFIG,
            )
            await _run(
                "docker",
                "exec",
                self.ingress_container_name,
                "apache2ctl",
                "configtest",
            )
            await _run(
                "docker",
                "exec",
                self.ingress_container_name,
                "apache2ctl",
                "-k",
                "graceful",
            )
        finally:
            local_path.unlink(missing_ok=True)

    async def _retire_ssrf_oracle_locked(self) -> None:
        """Remove a relay before closing the parent listener behind its port."""
        previous, self._ssrf_oracle = self._ssrf_oracle, None
        try:
            await self._disable_ssrf_relay_locked()
        finally:
            if previous is not None:
                await previous.close()

    async def _prepare_ssrf_oracle_locked(self) -> dict[str, str]:
        """Prepare an oracle while excluding runs and lifecycle mutation."""
        if "http" not in self._ssrf_oracle_modes:
            raise RuntimeError("HTTP SSRF oracle was not enabled for this sandbox")
        await self._retire_ssrf_oracle_locked()
        self._clear_ssrf_local_oracle_locked()
        if not self._booted or not self.container_name:
            raise RuntimeError("sandbox is unavailable for SSRF oracle preparation")

        oracle = SsrfOracleServer()
        try:
            await oracle.start()
            attack_url = oracle.attack_url
            control_url = oracle.control_url
            readiness_url = oracle.readiness_url
            oracle_urls = (attack_url, control_url, readiness_url)
            if (
                not oracle.is_running
                or type(oracle.port) is not int
                or not all(_valid_ssrf_oracle_url(url) for url in oracle_urls)
                or any(urlsplit(url).port != oracle.port for url in oracle_urls)
                or len(set(oracle_urls)) != len(oracle_urls)
            ):
                raise RuntimeError("SSRF oracle produced invalid public URLs")
            await self._configure_ssrf_relay_locked(oracle.port)
            await _probe_ssrf_oracle_readiness(
                self.container_name,
                readiness_url,
            )
        except BaseException as exc:
            try:
                await self._disable_ssrf_relay_locked()
            finally:
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
            await self._retire_ssrf_oracle_locked()
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

    async def prepare_php_include_oracle(self) -> dict[str, str]:
        """Create stable opaque paths for one authored PHP include attempt."""
        async with self._ssrf_operation_lock:
            if not self._php_include_oracle_enabled:
                raise RuntimeError(
                    "PHP include oracle was not enabled for this sandbox"
                )
            self._clear_php_include_oracle_locked()
            if (
                not self._booted
                or not self.container_name
                or self._php_include_host_dir is None
            ):
                raise RuntimeError(
                    "sandbox is unavailable for PHP include oracle preparation"
                )
            await _probe_php_include_mount(
                self.container_name,
                self._php_include_host_dir,
            )
            oracle = PhpIncludeOracle()
            self._php_include_oracle = oracle
            return oracle.public_context()

    def _clear_php_include_oracle_locked(self) -> None:
        oracle = self._php_include_oracle
        if oracle is None:
            return
        if self._php_include_host_dir is None:
            raise RuntimeError(
                "cannot clear the PHP include oracle without its host directory"
            )
        try:
            _remove_php_include_canary(self._php_include_host_dir, oracle)
        except (OSError, RuntimeError) as exc:
            logger.warning("failed to remove PHP include canary")
            # Retain the exact oracle/path capability.  Preparation must fail
            # and retry this removal instead of orphaning an executable sibling
            # and issuing a new path into the same persistent mount.
            raise RuntimeError("failed to clear the PHP include oracle") from exc
        self._php_include_oracle = None

    async def prepare_php_object_oracle(
        self,
        callsite: PhpObjectCallsite,
    ) -> dict[str, str]:
        """Install one verifier-owned inert class and return opaque arm tokens."""
        async with self._ssrf_operation_lock:
            if not self._php_object_oracle_enabled:
                raise RuntimeError("PHP object oracle was not enabled for this sandbox")
            await self._clear_php_object_oracle_locked()
            if not self._booted or not self.container_name:
                raise RuntimeError(
                    "sandbox is unavailable for PHP object oracle preparation"
                )

            callsite_path = await self._attest_php_object_callsite(callsite)
            oracle = PhpObjectOracle(
                callsite_path=callsite_path,
                callsite_start_line=callsite.start_line,
                callsite_end_line=callsite.end_line,
                callsite_source_sha256=callsite.source_sha256,
            )
            self._php_object_oracle = oracle
            self._php_object_callsite = callsite
            try:
                await self._install_php_object_oracle_plugin(oracle)
            except BaseException as exc:
                cleanup_failed = False
                try:
                    await self._remove_php_object_oracle_plugin(oracle)
                    await self._install_actor_receipt_plugin()
                except Exception:
                    cleanup_failed = True
                    logger.warning("failed to clean a rejected PHP object oracle")
                if not cleanup_failed:
                    self._php_object_oracle = None
                    self._php_object_callsite = None
                if not isinstance(exc, Exception):
                    raise
                raise RuntimeError("failed to prepare the PHP object oracle") from None
            return oracle.public_context()

    async def _clear_php_object_oracle_locked(self) -> None:
        """Remove only the exact issued class and detach its receipt bridge."""
        oracle = self._php_object_oracle
        if oracle is None:
            self._php_object_gadget_oracle = None
            self._php_object_callsite = None
            return
        try:
            generation_id = oracle.generation_id
        except RuntimeError:
            generation_id = ""
        if generation_id:
            try:
                oracle.snapshot()
            except RuntimeError:
                oracle.abort_generation(generation_id=generation_id)
        try:
            await self._remove_php_object_oracle_plugin(oracle)
            await self._install_actor_receipt_plugin()
        except Exception:
            logger.warning("failed to clear PHP object oracle")
            raise RuntimeError("failed to clear the PHP object oracle") from None
        self._php_object_oracle = None
        self._php_object_gadget_oracle = None
        self._php_object_callsite = None

    async def prepare_php_object_gadget_oracle(
        self,
        recipe: PhpObjectGadgetRecipe,
    ) -> dict[str, str]:
        """Bind one typed natural gadget to the completed inert primitive."""
        async with self._ssrf_operation_lock:
            if not self._php_object_gadget_oracle_enabled:
                raise RuntimeError(
                    "PHP object gadget oracle was not enabled for this sandbox"
                )
            if type(recipe) is not PhpObjectGadgetRecipe:
                raise ValueError("PHP object gadget recipe has an invalid type")
            primitive = self._php_object_oracle
            callsite = self._php_object_callsite
            if (
                not self._booted
                or not self.container_name
                or primitive is None
                or callsite is None
                or self._installed_plugin_slug is None
            ):
                raise RuntimeError(
                    "sandbox primitive is unavailable for gadget preparation"
                )
            primitive_snapshot = primitive.snapshot()
            await self._attest_php_object_oracle_plugin(primitive)
            callsite_path = await self._attest_php_object_callsite(callsite)
            if not hmac.compare_digest(callsite_path, primitive.private_callsite_path):
                raise RuntimeError("PHP object primitive callsite mapping changed")
            runtime_binding = await self._attest_php_object_gadget_recipe(recipe)
            context = primitive.public_context()
            gadget = PhpObjectGadgetOracle(
                recipe=recipe,
                primitive_snapshot=primitive_snapshot,
                attack_token=context["attack_token"],
                control_token=context["control_token"],
                runtime_binding=runtime_binding,
            )
            if (
                gadget.public_context()["attack_token"] != context["attack_token"]
                or gadget.public_context()["control_token"] != context["control_token"]
            ):
                raise RuntimeError("PHP object gadget changed the authored arm tokens")
            self._php_object_gadget_oracle = gadget
            return gadget.public_context()

    async def boot(self) -> None:
        if self._booted:
            return
        if self.project:
            raise RuntimeError("sandbox has incomplete cleanup from a previous boot")
        try:
            await self._boot_once()
        except BaseException:
            try:
                await self.teardown()
            except BaseException:
                logger.warning("failed to clean a partially booted sandbox")
            raise

    async def _boot_once(self) -> None:
        self._baseline_accounts = None
        self._pre_plugin_role_capabilities = None
        self._installed_plugin_slug = None
        self._php_object_surface_poisoned = False
        self._php_object_callsite = None
        self._php_object_gadget_oracle = None
        self._ssrf_relay_port = None
        self.wp_cli = None
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
            if self._php_include_oracle_enabled:
                self._php_include_host_dir = self.workdir / "php-include"
                self._php_include_host_dir.mkdir(mode=0o755)
                self._php_include_host_dir.chmod(0o755)
            else:
                self._php_include_host_dir = None

            template = Template((_DOCKER_DIR / "docker-compose.yml.j2").read_text())
            rendered = template.render(
                wordpress_image=self.config.wordpress_image,
                db_image=self.config.db_image,
                port=self.port,
                wp_url=self.target_url,
                wp_title="Squadrone Sandbox",
                wp_admin_user=self.config.wp_admin_user,
                wp_admin_pass=self.config.wp_admin_pass,
                wp_admin_email=self.config.wp_admin_email,
                database_name=_SANDBOX_DATABASE_NAME,
                database_user=_SANDBOX_DATABASE_USER,
                database_password=_SANDBOX_DATABASE_PASSWORD,
                enable_http_ssrf="http" in self._ssrf_oracle_modes,
                enable_local_resource_ssrf=(
                    "local_resource" in self._ssrf_oracle_modes
                ),
                ssrf_local_host_dir=(
                    os.fspath(self._ssrf_local_host_dir)
                    if self._ssrf_local_host_dir is not None
                    else ""
                ),
                enable_php_include_oracle=self._php_include_oracle_enabled,
                enable_php_object_gadget_oracle=(
                    self._php_object_gadget_oracle_enabled
                ),
                php_object_gadget_directory_constants=(
                    self._php_object_gadget_directory_constants
                ),
                php_include_host_dir=(
                    os.fspath(self._php_include_host_dir)
                    if self._php_include_host_dir is not None
                    else ""
                ),
                bootstrap_network_name=self.bootstrap_network_name,
            )
            (self.workdir / "docker-compose.yml").write_text(rendered)
            wp_init_path = self.workdir / "wp-init.sh"
            wp_init_path.write_bytes((_DOCKER_DIR / "wp-init.sh").read_bytes())
            wp_init_path.chmod(0o755)

            logger.info("sandbox boot project=%s port=%d", self.project, self.port)
            await _run(
                "docker",
                "network",
                "create",
                "--driver",
                "bridge",
                self.bootstrap_network_name,
            )
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
        # wp-init.sh may not have completed `wp core install` by the time the port answers;
        # ensure it has, then we are ready.
        await self._ensure_wp_installed()
        await self._seal_runtime_network()
        # The host reaches WordPress only through the fixed-target ingress service.
        # Re-probe after removing bootstrap egress before exposing any sandbox API.
        await self._wait_for_wordpress()
        self.wp_cli = WPCli(self.container_name)
        await self._install_actor_receipt_plugin()
        await self._ensure_wp_upload_path()
        self._booted = True

    async def teardown(self) -> None:
        async with self._ssrf_operation_lock:
            await self._teardown_locked()

    async def _teardown_locked(self) -> None:
        project = self.project
        container_name = self.container_name
        workdir = self.workdir
        bootstrap_network_name = self.bootstrap_network_name if project else ""
        docker_cleanup_complete = not project
        oracle, self._ssrf_oracle = self._ssrf_oracle, None
        try:
            try:
                await self._disable_ssrf_relay_locked()
            finally:
                if oracle is not None:
                    await oracle.close()
            self._clear_ssrf_local_oracle_locked()
            self._clear_php_include_oracle_locked()
            await self._clear_php_object_oracle_locked()
        finally:
            try:
                try:
                    if project and container_name:
                        await _run(
                            "docker",
                            "network",
                            "disconnect",
                            "--force",
                            bootstrap_network_name,
                            container_name,
                            check=False,
                        )
                finally:
                    try:
                        try:
                            await self._remove_actor_receipt_plugin()
                        except Exception:
                            logger.warning(
                                "failed to remove sandbox actor receipt plugin"
                            )
                    finally:
                        if project:
                            logger.info("sandbox teardown project=%s", project)
                            try:
                                rc, _out, _err = await _run(
                                    "docker",
                                    "compose",
                                    "-p",
                                    project,
                                    "down",
                                    "-v",
                                    cwd=str(workdir) if workdir else None,
                                    check=False,
                                )
                                if rc != 0:
                                    raise RuntimeError(
                                        "sandbox Docker Compose cleanup failed"
                                    )
                            finally:
                                try:
                                    await _run(
                                        "docker",
                                        "network",
                                        "rm",
                                        bootstrap_network_name,
                                        check=False,
                                    )
                                finally:
                                    rc, output, _error = await _run(
                                        "docker",
                                        "network",
                                        "ls",
                                        "--filter",
                                        f"name=^{bootstrap_network_name}$",
                                        "--format",
                                        "{{.Name}}",
                                        check=False,
                                    )
                                    if rc != 0 or output.strip():
                                        raise RuntimeError(
                                            "sandbox bootstrap network cleanup failed"
                                        )
                            docker_cleanup_complete = True
            finally:
                if docker_cleanup_complete and workdir and workdir.exists():
                    shutil.rmtree(workdir, ignore_errors=True)
                for snapshot_dir in self._snapshot_dirs:
                    shutil.rmtree(snapshot_dir, ignore_errors=True)
                self._snapshot_dirs.clear()
                self._booted = False
                self._ssrf_local_host_dir = None
                self._php_object_oracle = None
                self._php_object_gadget_oracle = None
                self._php_object_callsite = None
                self._installed_plugin_slug = None
                self._php_object_surface_poisoned = False
                self.wp_cli = None
                if docker_cleanup_complete:
                    self._ssrf_relay_port = None
                    self.port = 0
                    self.project = ""
                    self.workdir = None
                    self.container_name = ""
                    self.target_url = ""
                if (
                    self._php_include_oracle is None
                    or self._php_include_host_dir is None
                    or not self._php_include_host_dir.exists()
                ):
                    self._php_include_oracle = None
                    self._php_include_host_dir = None
                self._baseline_accounts = None
                self._pre_plugin_role_capabilities = None

    # ── snapshot + restore ──────────────────────────────────────────────────

    @property
    def db_container_name(self) -> str:
        return f"{self.project}-db-1"

    @property
    def ingress_container_name(self) -> str:
        return f"{self.project}-ingress-1"

    @property
    def internal_network_name(self) -> str:
        return f"{self.project}_default"

    @property
    def ingress_network_name(self) -> str:
        return f"{self.project}_ingress"

    @property
    def bootstrap_network_name(self) -> str:
        return f"{self.project}-bootstrap"

    async def snapshot(self) -> Path:
        """Capture the DB and complete WordPress volume to a temp directory.

        Setup and PoC code can mutate root-level WordPress files such as
        ``.htaccess`` or create new entries beside ``wp-content``. Archiving the
        complete ``/var/www/html`` volume makes those changes recoverable too;
        trusted oracle mounts live under ``/var/lib/squadrone`` and remain outside
        this snapshot by design.
        """
        if not self._booted:
            raise RuntimeError("snapshot called before sandbox booted")
        snap_dir = Path(tempfile.mkdtemp(prefix=f"{self.project}-snap-"))
        try:
            # DB dump
            rc, dump, err = await _run(
                "docker",
                "exec",
                self.db_container_name,
                "mariadb-dump",
                *_SANDBOX_MARIADB_CLIENT_AUTH,
                "--add-drop-database",
                "--databases",
                _SANDBOX_DATABASE_NAME,
                check=False,
            )
            if rc != 0 or not dump.strip():
                raise RuntimeError(
                    f"snapshot database dump failed (rc={rc}): {err.strip()[:200]}"
                )
            database_archive = snap_dir / "db.sql"
            database_archive.write_text(dump)
            database_archive.chmod(0o600)
            # Complete named WordPress volume, including hidden/root-level entries,
            # core, wp-config.php, the installed plugin, and uploads. ``-C ... .`` is
            # intentional: archiving ``*`` would silently omit files such as .htaccess.
            container_archive = _fresh_container_snapshot_archive_path()
            try:
                await _run(
                    "docker",
                    "exec",
                    "--user",
                    "root",
                    self.container_name,
                    "sh",
                    "-c",
                    'set -eu; archive=$1; umask 077; rm -f -- "$archive"; '
                    "test -f /var/www/html/wp-config.php; "
                    "test -d /var/www/html/wp-content; "
                    'tar czf "$archive" -C /var/www/html .; '
                    'chown 0:0 "$archive"; chmod 0600 "$archive"; '
                    'test -f "$archive"; test ! -L "$archive"',
                    "squadrone-snapshot",
                    container_archive,
                )
                await _run(
                    "docker",
                    "cp",
                    f"{self.container_name}:{container_archive}",
                    str(snap_dir / "wordpress-root.tar.gz"),
                )
            finally:
                await _remove_container_snapshot_archive(
                    self.container_name,
                    container_archive,
                )
            root_tar = snap_dir / "wordpress-root.tar.gz"
            root_stat = root_tar.lstat() if root_tar.exists() else None
            if (
                root_stat is None
                or not stat.S_ISREG(root_stat.st_mode)
                or stat.S_ISLNK(root_stat.st_mode)
                or root_stat.st_nlink != 1
                or root_stat.st_size == 0
            ):
                raise RuntimeError(
                    "snapshot WordPress root archive is missing or empty"
                )
            root_tar.chmod(0o600)
        except BaseException:
            shutil.rmtree(snap_dir, ignore_errors=True)
            raise
        self._snapshot_dirs.add(snap_dir)
        logger.info("sandbox snapshot → %s (db=%d bytes)", snap_dir, len(dump))
        return snap_dir

    async def restore(self, snap_dir: Path) -> None:
        """Restore the DB and complete ``/var/www/html`` volume from a snapshot."""
        if not self._booted:
            raise RuntimeError("restore called before sandbox booted")
        db_sql_path = snap_dir / "db.sql"
        try:
            db_stat = db_sql_path.lstat()
        except OSError:
            db_stat = None
        if (
            db_stat is None
            or not stat.S_ISREG(db_stat.st_mode)
            or stat.S_ISLNK(db_stat.st_mode)
            or db_stat.st_nlink != 1
            or db_stat.st_size == 0
        ):
            raise RuntimeError(f"restore snapshot has no database dump: {snap_dir}")
        root_tar = snap_dir / "wordpress-root.tar.gz"
        try:
            root_stat = root_tar.lstat()
        except OSError:
            root_stat = None
        if (
            root_stat is None
            or not stat.S_ISREG(root_stat.st_mode)
            or stat.S_ISLNK(root_stat.st_mode)
            or root_stat.st_nlink != 1
            or root_stat.st_size == 0
        ):
            raise RuntimeError(
                f"restore snapshot has no WordPress root archive: {snap_dir}"
            )
        sql_bytes = db_sql_path.read_bytes()
        container_archive = _fresh_container_snapshot_archive_path()
        # Stage and validate the trusted archive before changing either restored
        # surface. A corrupt archive therefore cannot leave a restored database
        # paired with the previous webroot. The random root-only staging file is
        # removed on every exit before untrusted code can run again.
        try:
            await _run(
                "docker",
                "cp",
                str(root_tar),
                f"{self.container_name}:{container_archive}",
            )
            await _run(
                "docker",
                "exec",
                "--user",
                "root",
                self.container_name,
                "sh",
                "-c",
                'set -eu; archive=$1; chown 0:0 "$archive"; '
                'chmod 0600 "$archive"; test -f "$archive"; '
                'test ! -L "$archive"; tar tzf "$archive" >/dev/null',
                "squadrone-restore",
                container_archive,
            )
            proc = await asyncio.create_subprocess_exec(
                "docker",
                "exec",
                "-i",
                self.db_container_name,
                "mariadb",
                *_SANDBOX_MARIADB_CLIENT_AUTH,
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

            await _run(
                "docker",
                "exec",
                "--user",
                "root",
                self.container_name,
                "sh",
                "-c",
                "set -eu; archive=$1; "
                "find /var/www/html -mindepth 1 -maxdepth 1 "
                "-exec rm -rf -- {} +; "
                'tar xzf "$archive" -C /var/www/html; '
                "test -f /var/www/html/wp-config.php; "
                "test -d /var/www/html/wp-content",
                "squadrone-restore",
                container_archive,
            )
        finally:
            await _remove_container_snapshot_archive(
                self.container_name,
                container_archive,
            )
        self._php_object_surface_poisoned = False
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
        if self._php_include_host_dir is not None:
            await _probe_php_include_mount(
                self.container_name,
                self._php_include_host_dir,
            )

    # ── helpers ─────────────────────────────────────────────────

    async def _inspect_network_internal(self, network_name: str) -> bool:
        rc, output, _error = await _run(
            "docker",
            "network",
            "inspect",
            "--format",
            "{{json .Internal}}",
            network_name,
            check=False,
        )
        if rc != 0:
            raise RuntimeError("sandbox network inspection failed")
        try:
            value = json.loads(output.strip())
        except (TypeError, ValueError) as exc:
            raise RuntimeError("sandbox network inspection was malformed") from exc
        if type(value) is not bool:
            raise RuntimeError("sandbox network inspection was malformed")
        return value

    async def _inspect_container_network_settings(
        self,
        container_name: str,
    ) -> tuple[frozenset[str], dict[str, object]]:
        rc, output, _error = await _run(
            "docker",
            "inspect",
            "--format",
            "{{json .NetworkSettings}}",
            container_name,
            check=False,
        )
        if rc != 0:
            raise RuntimeError("sandbox container network inspection failed")
        try:
            value = json.loads(output.strip())
        except (TypeError, ValueError) as exc:
            raise RuntimeError(
                "sandbox container network inspection was malformed"
            ) from exc
        if type(value) is not dict:
            raise RuntimeError("sandbox container network inspection was malformed")
        networks = value.get("Networks")
        ports = value.get("Ports")
        if (
            type(networks) is not dict
            or not all(
                type(name) is str and type(details) is dict
                for name, details in networks.items()
            )
            or type(ports) is not dict
            or not all(type(name) is str for name in ports)
        ):
            raise RuntimeError("sandbox container network inspection was malformed")
        return frozenset(networks), cast(dict[str, object], ports)

    async def _inspect_container_network_mode(self, container_name: str) -> str:
        """Read Docker's persisted primary network used for later restarts."""
        rc, output, _error = await _run(
            "docker",
            "inspect",
            "--format",
            "{{json .HostConfig.NetworkMode}}",
            container_name,
            check=False,
        )
        if rc != 0:
            raise RuntimeError("sandbox persistent network mode inspection failed")
        try:
            value = json.loads(output.strip())
        except (TypeError, ValueError) as exc:
            raise RuntimeError(
                "sandbox persistent network mode inspection was malformed"
            ) from exc
        if type(value) is not str or not value:
            raise RuntimeError(
                "sandbox persistent network mode inspection was malformed"
            )
        return value

    @staticmethod
    def _published_port_bindings(
        ports: dict[str, object],
    ) -> tuple[tuple[str, str, str], ...]:
        published: list[tuple[str, str, str]] = []
        for container_port, raw_bindings in ports.items():
            if raw_bindings is None:
                continue
            if type(raw_bindings) is not list:
                raise RuntimeError("sandbox published-port inspection was malformed")
            for raw_binding in raw_bindings:
                if (
                    type(raw_binding) is not dict
                    or set(raw_binding) != {"HostIp", "HostPort"}
                    or type(raw_binding.get("HostIp")) is not str
                    or type(raw_binding.get("HostPort")) is not str
                ):
                    raise RuntimeError(
                        "sandbox published-port inspection was malformed"
                    )
                published.append(
                    (
                        container_port,
                        cast(str, raw_binding["HostIp"]),
                        cast(str, raw_binding["HostPort"]),
                    )
                )
        return tuple(sorted(published))

    async def _seal_runtime_network(self) -> None:
        """Remove bootstrap egress and attest the exact verifier topology."""
        if (
            not self.project.startswith(f"{_PROJECT_PREFIX}-")
            or self.container_name != f"{self.project}-wordpress-1"
            or self.port < _PORT_MIN
            or self.port > _PORT_MAX
        ):
            raise RuntimeError("sandbox network identity is unavailable")

        await _run(
            "docker",
            "network",
            "disconnect",
            self.bootstrap_network_name,
            self.container_name,
        )
        await _run("docker", "network", "rm", self.bootstrap_network_name)

        internal_is_internal = await self._inspect_network_internal(
            self.internal_network_name
        )
        ingress_is_internal = await self._inspect_network_internal(
            self.ingress_network_name
        )
        if not internal_is_internal or ingress_is_internal:
            raise RuntimeError("sandbox network isolation attestation failed")

        expected_internal = frozenset({self.internal_network_name})
        wordpress_network_mode = await self._inspect_container_network_mode(
            self.container_name
        )
        wordpress_networks, wordpress_ports = (
            await self._inspect_container_network_settings(self.container_name)
        )
        database_networks, database_ports = (
            await self._inspect_container_network_settings(self.db_container_name)
        )
        ingress_networks, ingress_ports = (
            await self._inspect_container_network_settings(self.ingress_container_name)
        )
        if (
            wordpress_networks != expected_internal
            or database_networks != expected_internal
            or ingress_networks
            != frozenset({self.internal_network_name, self.ingress_network_name})
        ):
            raise RuntimeError("sandbox container network topology attestation failed")

        if wordpress_network_mode != self.internal_network_name:
            raise RuntimeError("sandbox persistent network mode attestation failed")

        if (
            self._published_port_bindings(wordpress_ports)
            or self._published_port_bindings(database_ports)
            or self._published_port_bindings(ingress_ports)
            != (("80/tcp", "127.0.0.1", str(self.port)),)
        ):
            raise RuntimeError("sandbox published-port topology attestation failed")

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

    async def _install_actor_receipt_plugin(
        self,
        php_object_canary_class: str = "",
    ) -> None:
        """Install and protect the verifier-owned actor-receipt MU-plugin.

        WordPress plugins may legitimately create sibling MU-plugin files as the
        managed web identity. Give that identity directory-level creation
        rights through its primary group. Sticky directory semantics and protected
        ownership/mode metadata prevent direct replacement or unlinking of
        Squadrone's root-owned receipt entry within that directory.
        """
        if self.workdir is None:
            raise RuntimeError("sandbox workdir is unavailable for actor receipt setup")
        if not _ACTOR_RECEIPT_TEMPLATE.is_file():
            raise RuntimeError(
                f"actor receipt template is missing: {_ACTOR_RECEIPT_TEMPLATE}"
            )
        if php_object_canary_class and (
            _PHP_OBJECT_CANARY_CLASS_RE.fullmatch(php_object_canary_class) is None
        ):
            raise RuntimeError("invalid PHP object canary class for receipt bridge")
        rendered = Template(_ACTOR_RECEIPT_TEMPLATE.read_text()).render(
            trace_token=self._trace_token,
            receipt_secret=self._receipt_secret.hex(),
            php_object_canary_class=php_object_canary_class,
        )
        local_path = self.workdir / _ACTOR_RECEIPT_BASENAME
        local_path.write_text(rendered)
        destination_dir = _MU_PLUGIN_DIRECTORY
        destination = f"{destination_dir}/{_ACTOR_RECEIPT_BASENAME}"
        rc, uid, err = await _run(
            "docker",
            "exec",
            self.container_name,
            "id",
            "-u",
            WORDPRESS_WEB_USER,
            check=False,
        )
        normalized_uid = uid.strip()
        if rc != 0 or not normalized_uid.isdecimal() or normalized_uid == "0":
            detail = (err or uid).strip()[:200]
            raise RuntimeError(
                "sandbox WordPress web identity must resolve to a non-root UID"
                + (f": {detail}" if detail else "")
            )
        rc, gid, err = await _run(
            "docker",
            "exec",
            self.container_name,
            "id",
            "-g",
            WORDPRESS_WEB_USER,
            check=False,
        )
        web_gid = gid.strip()
        if rc != 0 or not web_gid.isdecimal():
            detail = (err or gid).strip()[:200]
            raise RuntimeError(
                "sandbox WordPress web identity has no safe primary group"
                + (f": {detail}" if detail else "")
            )
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
            "exec",
            self.container_name,
            "chown",
            f"root:{web_gid}",
            destination_dir,
        )
        await _run(
            "docker",
            "exec",
            self.container_name,
            "chmod",
            "1775",
            destination_dir,
        )
        await _run(
            "docker",
            "cp",
            str(local_path),
            f"{self.container_name}:{destination}",
        )
        await _run(
            "docker",
            "exec",
            self.container_name,
            "chown",
            "root:root",
            destination,
        )
        await _run(
            "docker",
            "exec",
            self.container_name,
            "chmod",
            "0444",
            destination,
        )
        rc, metadata, err = await _run(
            "docker",
            "exec",
            self.container_name,
            "stat",
            "-c",
            "%u:%g:%a",
            destination_dir,
            destination,
            check=False,
        )
        expected_metadata = [
            f"0:{web_gid}:1775",
            "0:0:444",
        ]
        if rc != 0 or metadata.splitlines() != expected_metadata:
            detail = (err or metadata).strip()[:300]
            raise RuntimeError(
                "sandbox actor receipt filesystem protections are invalid"
                + (f": {detail}" if detail else "")
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

    async def _install_php_object_oracle_plugin(
        self,
        oracle: PhpObjectOracle,
    ) -> None:
        """Install and attest one exact verifier-owned inert canary class."""
        if self.workdir is None or self.wp_cli is None:
            raise RuntimeError("sandbox is unavailable for PHP object setup")
        class_name = oracle.private_class_name
        match = _PHP_OBJECT_CANARY_CLASS_RE.fullmatch(class_name)
        if match is None:
            raise RuntimeError("invalid PHP object canary class")
        basename = f"{_PHP_OBJECT_CANARY_BASENAME_PREFIX}{match.group(1)}.php"
        destination = f"{_MU_PLUGIN_DIRECTORY}/{basename}"
        class_literal = json.dumps(class_name)
        collision_check = (
            f"$name = {class_literal}; "
            "if (class_exists($name, false) || interface_exists($name, false) "
            "|| trait_exists($name, false) || (function_exists('enum_exists') "
            "&& enum_exists($name, false))) { "
            "WP_CLI::error('PHP object canary class collision.'); }"
        )
        rc, out, err = await self.wp_cli._exec_result("eval", collision_check)
        if rc != 0:
            raise RuntimeError("PHP object canary class collision check failed")

        for file_test in ("-e", "-L"):
            rc, _out, err = await _run(
                "docker",
                "exec",
                self.container_name,
                "test",
                "!",
                file_test,
                destination,
                check=False,
            )
            if rc != 0:
                raise RuntimeError("PHP object canary destination already exists")

        source = oracle.private_canary_class_source
        expected_sha256 = hashlib.sha256(source).hexdigest()
        local_path = self.workdir / basename
        local_path.write_bytes(source)
        try:
            rc, _out, _err = await _run(
                "docker",
                "cp",
                str(local_path),
                f"{self.container_name}:{destination}",
                check=False,
            )
            if rc != 0:
                raise RuntimeError("failed to copy PHP object canary")
        finally:
            local_path.unlink(missing_ok=True)
        rc, _out, _err = await _run(
            "docker",
            "exec",
            self.container_name,
            "chown",
            "root:root",
            destination,
            check=False,
        )
        if rc != 0:
            raise RuntimeError("failed to protect PHP object canary ownership")
        rc, _out, _err = await _run(
            "docker",
            "exec",
            self.container_name,
            "chmod",
            "0444",
            destination,
            check=False,
        )
        if rc != 0:
            raise RuntimeError("failed to protect PHP object canary mode")
        rc, metadata, err = await _run(
            "docker",
            "exec",
            self.container_name,
            "stat",
            "-c",
            "%u:%g:%a:%s",
            destination,
            check=False,
        )
        if rc != 0 or metadata.strip() != f"0:0:444:{len(source)}":
            raise RuntimeError("PHP object canary filesystem protections are invalid")
        rc, digest, err = await _run(
            "docker",
            "exec",
            self.container_name,
            "sha256sum",
            destination,
            check=False,
        )
        if rc != 0 or digest.split(maxsplit=1)[0] != expected_sha256:
            raise RuntimeError("PHP object canary source attestation failed")
        rc, out, err = await _run(
            "docker",
            "exec",
            self.container_name,
            "php",
            "-l",
            destination,
            check=False,
        )
        if rc != 0:
            raise RuntimeError("PHP object canary failed PHP lint")

        await self._install_actor_receipt_plugin(class_name)
        await self._attest_php_object_oracle_plugin(oracle)

    async def _attest_php_object_callsite(
        self,
        callsite: PhpObjectCallsite,
    ) -> str:
        """Map and hash one verifier-derived source span inside the target plugin."""
        if (
            type(callsite) is not PhpObjectCallsite
            or not self.container_name
            or self._installed_plugin_slug is None
        ):
            raise RuntimeError("PHP object callsite is unavailable")
        slug = validate_plugin_slug(self._installed_plugin_slug)
        relative = PurePosixPath(callsite.relative_path)
        if (
            relative.is_absolute()
            or relative.as_posix() != callsite.relative_path
            or relative.suffix.casefold() != ".php"
            or any(part in {"", ".", ".."} for part in relative.parts)
            or "\\" in callsite.relative_path
            or any(
                ord(character) < 32 or ord(character) > 126
                for character in callsite.relative_path
            )
        ):
            raise RuntimeError("PHP object callsite path is invalid")
        plugin_root = PurePosixPath(f"/var/www/html/wp-content/plugins/{slug}")
        callsite_path = (plugin_root / relative).as_posix()
        if not callsite_path.startswith(plugin_root.as_posix() + "/"):
            raise RuntimeError("PHP object callsite path escapes the target plugin")
        rc, stdout, _stderr = await _run(
            "docker",
            "exec",
            "--user",
            "root",
            self.container_name,
            "php",
            "-r",
            _PHP_OBJECT_CALLSITE_INSPECT_SCRIPT,
            callsite_path,
            check=False,
        )
        try:
            payload = json.loads(stdout) if len(stdout) <= 1024 else None
        except (json.JSONDecodeError, TypeError, ValueError):
            payload = None
        if (
            rc != 0
            or not isinstance(payload, dict)
            or set(payload) != {"source_sha256", "source_size_bytes", "line_count"}
            or payload.get("source_sha256") != callsite.source_sha256
            or type(payload.get("source_size_bytes")) is not int
            or cast(int, payload.get("source_size_bytes")) < 1
            or type(payload.get("line_count")) is not int
            or cast(int, payload.get("line_count")) < callsite.end_line
        ):
            raise RuntimeError("PHP object callsite source attestation failed")
        return callsite_path

    async def _freeze_php_object_executable_surfaces(
        self,
    ) -> _PhpObjectSurfaceFreeze:
        """Make WordPress executable surfaces immutable for one object proof."""
        if (
            self._php_object_surface_poisoned
            or not self.container_name
            or self._installed_plugin_slug is None
        ):
            raise RuntimeError("PHP object executable surfaces are unavailable")
        slug = validate_plugin_slug(self._installed_plugin_slug)
        manifest_path = (
            _PHP_OBJECT_SURFACE_MANIFEST_PREFIX + secrets.token_hex(16) + ".json"
        )
        rc, stdout, _stderr = await _run(
            "docker",
            "exec",
            "--user",
            "root",
            self.container_name,
            "php",
            "-r",
            _PHP_OBJECT_SURFACE_GUARD_SCRIPT,
            "freeze",
            slug,
            manifest_path,
            check=False,
        )
        try:
            payload = json.loads(stdout) if len(stdout) <= 4096 else None
            summary = _validate_php_object_surface_summary(
                payload,
                operation="freeze",
            )
        except (json.JSONDecodeError, RuntimeError, TypeError, ValueError):
            self._php_object_surface_poisoned = True
            raise RuntimeError(
                "failed to freeze PHP object executable surfaces"
            ) from None
        if rc != 0:
            self._php_object_surface_poisoned = True
            raise RuntimeError("failed to freeze PHP object executable surfaces")
        return _PhpObjectSurfaceFreeze(
            manifest_path=manifest_path,
            entry_count=cast(int, summary["entry_count"]),
            original_sha256=cast(str, summary["original_sha256"]),
            frozen_sha256=cast(str, summary["frozen_sha256"]),
            manifest_sha256=cast(str, summary["manifest_sha256"]),
        )

    async def _attest_php_object_executable_surfaces(
        self,
        frozen: _PhpObjectSurfaceFreeze,
    ) -> None:
        """Recompute the exact frozen inventory without exposing its paths."""
        if (
            self._php_object_surface_poisoned
            or self._installed_plugin_slug is None
            or _PHP_OBJECT_SURFACE_MANIFEST_RE.fullmatch(frozen.manifest_path) is None
        ):
            raise RuntimeError("PHP object executable-surface attestation failed")
        rc, stdout, _stderr = await _run(
            "docker",
            "exec",
            "--user",
            "root",
            self.container_name,
            "php",
            "-r",
            _PHP_OBJECT_SURFACE_GUARD_SCRIPT,
            "attest",
            validate_plugin_slug(self._installed_plugin_slug),
            frozen.manifest_path,
            check=False,
        )
        try:
            payload = json.loads(stdout) if len(stdout) <= 4096 else None
            summary = _validate_php_object_surface_summary(
                payload,
                operation="attest",
            )
        except (json.JSONDecodeError, RuntimeError, TypeError, ValueError):
            raise RuntimeError(
                "PHP object executable-surface attestation failed"
            ) from None
        if (
            rc != 0
            or summary["entry_count"] != frozen.entry_count
            or summary["original_sha256"] != frozen.original_sha256
            or summary["frozen_sha256"] != frozen.frozen_sha256
            or summary["manifest_sha256"] != frozen.manifest_sha256
        ):
            raise RuntimeError("PHP object executable-surface attestation failed")

    async def _restore_php_object_executable_surfaces(
        self,
        frozen: _PhpObjectSurfaceFreeze,
    ) -> None:
        """Restore exact pre-proof modes and reject any transient surface drift."""
        if (
            self._installed_plugin_slug is None
            or _PHP_OBJECT_SURFACE_MANIFEST_RE.fullmatch(frozen.manifest_path) is None
        ):
            self._php_object_surface_poisoned = True
            raise RuntimeError("PHP object executable-surface restoration failed")
        rc, stdout, _stderr = await _run(
            "docker",
            "exec",
            "--user",
            "root",
            self.container_name,
            "php",
            "-r",
            _PHP_OBJECT_SURFACE_GUARD_SCRIPT,
            "restore",
            validate_plugin_slug(self._installed_plugin_slug),
            frozen.manifest_path,
            check=False,
        )
        try:
            payload = json.loads(stdout) if len(stdout) <= 4096 else None
        except (json.JSONDecodeError, TypeError, ValueError):
            payload = None
        valid_shape = (
            isinstance(payload, dict)
            and set(payload)
            == {
                "operation",
                "entry_count",
                "original_sha256",
                "drift_before_restore",
                "restored",
                "manifest_removed",
            }
            and payload.get("operation") == "restore"
            and payload.get("entry_count") == frozen.entry_count
            and payload.get("original_sha256") == frozen.original_sha256
            and type(payload.get("drift_before_restore")) is bool
            and type(payload.get("restored")) is bool
            and type(payload.get("manifest_removed")) is bool
        )
        if not valid_shape:
            self._php_object_surface_poisoned = True
            raise RuntimeError("PHP object executable-surface restoration failed")
        assert isinstance(payload, dict)
        restored = payload["restored"] is True
        manifest_removed = payload["manifest_removed"] is True
        drifted = payload["drift_before_restore"] is True
        if not restored or not manifest_removed:
            self._php_object_surface_poisoned = True
            raise RuntimeError("PHP object executable-surface restoration failed")
        if rc != 0 or drifted:
            raise RuntimeError("PHP object executable-surface drift was detected")

    async def _attest_php_object_oracle_plugin(
        self,
        oracle: PhpObjectOracle,
    ) -> None:
        """Reprove exact immutable MU files before each object execution."""
        if self.wp_cli is None:
            raise RuntimeError("sandbox is unavailable for PHP object attestation")
        class_name = oracle.private_class_name
        match = _PHP_OBJECT_CANARY_CLASS_RE.fullmatch(class_name)
        if match is None:
            raise RuntimeError("invalid PHP object canary attestation identity")
        basename = f"{_PHP_OBJECT_CANARY_BASENAME_PREFIX}{match.group(1)}.php"
        canary_destination = f"{_MU_PLUGIN_DIRECTORY}/{basename}"
        actor_destination = f"{_MU_PLUGIN_DIRECTORY}/{_ACTOR_RECEIPT_BASENAME}"
        actor_source = (
            Template(_ACTOR_RECEIPT_TEMPLATE.read_text())
            .render(
                trace_token=self._trace_token,
                receipt_secret=self._receipt_secret.hex(),
                php_object_canary_class=class_name,
            )
            .encode()
        )
        canary_source = oracle.private_canary_class_source

        rc, web_gid, err = await _run(
            "docker",
            "exec",
            self.container_name,
            "id",
            "-g",
            WORDPRESS_WEB_USER,
            check=False,
        )
        normalized_gid = web_gid.strip()
        if rc != 0 or not normalized_gid.isdecimal():
            raise RuntimeError("PHP object MU-plugin group attestation failed")
        rc, metadata, err = await _run(
            "docker",
            "exec",
            self.container_name,
            "stat",
            "-c",
            "%u:%g:%a:%s",
            _MU_PLUGIN_DIRECTORY,
            actor_destination,
            canary_destination,
            check=False,
        )
        expected_file_metadata = [
            f"0:0:444:{len(actor_source)}",
            f"0:0:444:{len(canary_source)}",
        ]
        observed_metadata = metadata.splitlines()
        # Directory size is filesystem-specific.  Keep the exact protection
        # fields while accepting only a positive decimal size in that slot.
        directory_fields = observed_metadata[0].split(":") if observed_metadata else []
        if (
            rc != 0
            or len(observed_metadata) != 3
            or len(directory_fields) != 4
            or directory_fields[:3] != ["0", normalized_gid, "1775"]
            or not directory_fields[3].isdecimal()
            or int(directory_fields[3]) <= 0
            or observed_metadata[1:] != expected_file_metadata
        ):
            raise RuntimeError("PHP object MU-plugin filesystem attestation failed")

        rc, digests, err = await _run(
            "docker",
            "exec",
            self.container_name,
            "sha256sum",
            actor_destination,
            canary_destination,
            check=False,
        )
        digest_lines = digests.splitlines()
        observed_digests = [
            line.split(maxsplit=1)[0] for line in digest_lines if line.strip()
        ]
        expected_digests = [
            hashlib.sha256(actor_source).hexdigest(),
            hashlib.sha256(canary_source).hexdigest(),
        ]
        if rc != 0 or observed_digests != expected_digests:
            raise RuntimeError("PHP object MU-plugin source attestation failed")

        class_literal = json.dumps(class_name)
        loaded_check = (
            f"$name = {class_literal}; "
            "if (!class_exists($name, false) "
            "|| !is_callable(array($name, 'consumeReceipt')) "
            "|| !is_callable(array($name, 'resetReceipt'))) { "
            "WP_CLI::error('PHP object canary did not load exactly.'); }"
        )
        rc, out, err = await self.wp_cli._exec_result("eval", loaded_check)
        if rc != 0:
            raise RuntimeError("PHP object canary runtime attestation failed")

    async def _attest_php_object_gadget_recipe(
        self,
        recipe: PhpObjectGadgetRecipe,
    ) -> PhpObjectGadgetRuntimeBinding:
        """Bind exact installed source and Reflection metadata without an object."""
        if (
            type(recipe) is not PhpObjectGadgetRecipe
            or not self.container_name
            or self._installed_plugin_slug is None
        ):
            raise RuntimeError("PHP object gadget source is unavailable")
        if _php_object_gadget_recipe_directory_constants(recipe) != (
            self._php_object_gadget_directory_constants
        ):
            raise RuntimeError(
                "PHP object gadget directory-constant configuration changed"
            )
        payload = await _inspect_php_object_gadget_runtime(
            self.container_name,
            validate_plugin_slug(self._installed_plugin_slug),
            recipe,
        )
        effect_binding = getattr(recipe, "effect_binding", None)
        effect_binding_kind = getattr(effect_binding, "kind", "direct_path")
        return _validate_php_object_gadget_runtime_payload(
            payload,
            recipe=recipe,
            effect_binding_kind=effect_binding_kind,
        )

    async def _cleanup_php_object_gadget_directory(
        self,
        *,
        require_empty: bool,
    ) -> None:
        if not self.container_name:
            raise RuntimeError("PHP object gadget tmpfs is unavailable")
        payload = await _php_object_gadget_filesystem_operation(
            self.container_name,
            operation="cleanup",
            target_path="",
            content=b"",
            require_empty=require_empty,
        )
        if payload != {"operation": "cleanup", "directory_entry_count": 0}:
            raise RuntimeError("PHP object gadget tmpfs cleanup failed")

    async def _provision_php_object_gadget_target(
        self,
        oracle: PhpObjectGadgetOracle,
    ) -> None:
        payload = await _php_object_gadget_filesystem_operation(
            self.container_name,
            operation="provision",
            target_path=oracle.private_target_path,
            content=oracle.private_target_content,
            require_empty=True,
        )
        if payload != {"operation": "provision", "directory_entry_count": 1}:
            raise RuntimeError("PHP object gadget target provisioning failed")

    async def _measure_php_object_gadget_target(
        self,
        oracle: PhpObjectGadgetOracle,
    ) -> PhpObjectGadgetFileMeasurement:
        payload = await _php_object_gadget_filesystem_operation(
            self.container_name,
            operation="measure",
            target_path=oracle.private_target_path,
            content=b"",
            require_empty=False,
        )
        return _validate_php_object_gadget_measurement_payload(
            payload,
            target_path=oracle.private_target_path,
        )

    async def _restore_php_object_gadget_clean_state(
        self,
        snapshot_dir: Path,
        oracle: PhpObjectGadgetOracle,
        *,
        require_empty_tmpfs: bool,
    ) -> None:
        """Apply the identical restore/restart/runtime sequence for each arm."""
        await self.restore(snapshot_dir)
        await self.restart_wordpress_runtime()
        if (
            await self._attest_php_object_gadget_recipe(oracle.recipe)
            != oracle.runtime_binding
        ):
            raise RuntimeError("PHP object gadget runtime binding changed")
        await self._cleanup_php_object_gadget_directory(
            require_empty=require_empty_tmpfs
        )

    async def _recover_and_discard_php_object_gadget_snapshot(
        self,
        snapshot_dir: Path,
        oracle: PhpObjectGadgetOracle,
    ) -> None:
        """Discard a sensitive snapshot only after complete clean-state recovery."""
        await self._restore_php_object_gadget_clean_state(
            snapshot_dir,
            oracle,
            require_empty_tmpfs=False,
        )
        self._discard_php_object_gadget_snapshot(snapshot_dir)

    def _discard_php_object_gadget_snapshot(self, snapshot_dir: Path) -> None:
        if snapshot_dir not in self._snapshot_dirs:
            raise RuntimeError("PHP object gadget snapshot identity changed")
        shutil.rmtree(snapshot_dir, ignore_errors=False)
        self._snapshot_dirs.remove(snapshot_dir)

    async def _remove_php_object_oracle_plugin(
        self,
        oracle: PhpObjectOracle,
    ) -> None:
        """Remove only the random canary file derived from this exact oracle."""
        if not self.container_name:
            return
        match = _PHP_OBJECT_CANARY_CLASS_RE.fullmatch(oracle.private_class_name)
        if match is None:
            raise RuntimeError("invalid PHP object canary cleanup identity")
        basename = f"{_PHP_OBJECT_CANARY_BASENAME_PREFIX}{match.group(1)}.php"
        destination = f"{_MU_PLUGIN_DIRECTORY}/{basename}"
        rc, _out, _err = await _run(
            "docker",
            "exec",
            self.container_name,
            "test",
            "!",
            "-L",
            destination,
            check=False,
        )
        if rc != 0:
            raise RuntimeError("refusing to remove a PHP object canary symlink")
        rc, digest, err = await _run(
            "docker",
            "exec",
            self.container_name,
            "sha256sum",
            destination,
            check=False,
        )
        if rc != 0:
            rc, _out, _err = await _run(
                "docker",
                "exec",
                self.container_name,
                "test",
                "!",
                "-e",
                destination,
                check=False,
            )
            if rc == 0:
                return
            raise RuntimeError("cannot attest PHP object canary before cleanup")
        expected_digest = hashlib.sha256(oracle.private_canary_class_source).hexdigest()
        if digest.split(maxsplit=1)[0] != expected_digest:
            raise RuntimeError("refusing to remove an unrecognized canary collision")
        rc, _out, err = await _run(
            "docker",
            "exec",
            self.container_name,
            "rm",
            "-f",
            "--",
            destination,
            check=False,
        )
        if rc != 0:
            raise RuntimeError("failed to remove PHP object canary")
        for file_test in ("-e", "-L"):
            rc, _out, _err = await _run(
                "docker",
                "exec",
                self.container_name,
                "test",
                "!",
                file_test,
                destination,
                check=False,
            )
            if rc != 0:
                raise RuntimeError("PHP object canary cleanup attestation failed")

    async def _remove_actor_receipt_plugin(self) -> None:
        """Remove the one fixed verifier-owned receipt bridge during teardown."""
        if not self.container_name:
            return
        destination = f"{_MU_PLUGIN_DIRECTORY}/{_ACTOR_RECEIPT_BASENAME}"
        await _run(
            "docker",
            "exec",
            self.container_name,
            "rm",
            "-f",
            "--",
            destination,
            check=False,
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
        self._installed_plugin_slug = slug
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
            "$canonical_urls = ['home' => (string) get_option('home', ''), "
            "'siteurl' => (string) get_option('siteurl', '')]; "
            "echo 'SQUADRONE_SETUP_SECURITY_STATE=' . wp_json_encode(["
            "'users' => $users, 'active_plugins' => $active, "
            "'active_sitewide_plugins' => $network, "
            "'privileged_users' => $privileged, "
            "'canonical_urls' => $canonical_urls]);"
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
            or not isinstance(state.get("canonical_urls"), dict)
            or set(state["canonical_urls"]) != {"home", "siteurl"}
            or not all(
                isinstance(value, str) and value
                for value in state["canonical_urls"].values()
            )
            or set(state["users"]) != set(protected_accounts)
        ):
            raise RuntimeError("managed setup-state query returned an invalid shape")

        expected_url = self.target_url.rstrip("/")
        if not expected_url or any(
            value.rstrip("/") != expected_url
            for value in state["canonical_urls"].values()
        ):
            raise RuntimeError(
                "managed setup-state WordPress home/siteurl do not match "
                "the sandbox target URL"
            )

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
        expected_php_include: bool = False,
        expected_php_object: bool = False,
        expected_php_object_gadget: bool = False,
        expected_php_object_transport: dict[str, object] | None = None,
        expected_executable_upload: bool = False,
    ) -> SandboxRunResult:
        async with self._ssrf_operation_lock:
            return await self._run_poc_locked(
                script_path,
                expected_bug_class=expected_bug_class,
                expected_attacker_role=expected_attacker_role,
                expected_http_transport=expected_http_transport,
                expected_php_include=expected_php_include,
                expected_php_object=expected_php_object,
                expected_php_object_gadget=expected_php_object_gadget,
                expected_php_object_transport=expected_php_object_transport,
                expected_executable_upload=expected_executable_upload,
            )

    async def _run_poc_locked(
        self,
        script_path: str,
        *,
        expected_bug_class: str | None = None,
        expected_attacker_role: str | None = None,
        expected_http_transport: dict[str, object] | None = None,
        expected_php_include: bool = False,
        expected_php_object: bool = False,
        expected_php_object_gadget: bool = False,
        expected_php_object_transport: dict[str, object] | None = None,
        expected_executable_upload: bool = False,
    ) -> SandboxRunResult:
        start = time.time()
        trace_records: list[dict] = []
        trace_error = ""
        rejection_counts: dict[str, int] = {}
        ssrf_expected = _is_ssrf_bug_class(expected_bug_class)
        php_include_expected = expected_php_include is True
        php_object_expected = expected_php_object is True
        php_object_gadget_expected = expected_php_object_gadget is True
        strict_isolation = (
            _requires_trusted_http_isolation(expected_bug_class)
            or php_include_expected
            or php_object_expected
            or php_object_gadget_expected
            or expected_executable_upload
        )
        isolation_capability = (
            CROSS_OBJECT_HTTP_CAPABILITY if strict_isolation else "compatibility"
        )
        proc: asyncio.subprocess.Process | None = None
        proxy: PocProxySupervisor | None = None
        stdout = b""
        stderr = b""
        timed_out = False
        trace_salt = b""
        oracle_service: SsrfOracleServer | None = None
        local_oracle: LocalResourceSsrfOracle | None = None
        php_include_oracle: PhpIncludeOracle | None = None
        oracle_mode = ""
        oracle_snapshot: object = None
        oracle_generation_id = ""
        oracle_marker = ""
        oracle_attack_url = ""
        oracle_control_url = ""
        oracle_error = ""
        php_include_snapshot: object = None
        php_include_generation_id = ""
        php_include_marker = ""
        php_include_attack_path = ""
        php_include_control_path = ""
        php_include_error = ""
        php_include_failure_reason = ""
        php_include_cleanup_error = ""
        php_include_inspection_retries = 0
        php_include_before: dict[str, object] | None = None
        php_include_host_before: PhpIncludeHostFilesystemMeasurement | None = None
        php_object_oracle: PhpObjectOracle | None = None
        php_object_policy: PhpObjectRewritePolicy | None = None
        php_object_snapshot: PhpObjectOracleSnapshot | None = None
        php_object_generation_id = ""
        php_object_error = ""
        php_object_failure_reason = ""
        php_object_private_values: tuple[str, ...] = ()
        php_object_surface_freeze: _PhpObjectSurfaceFreeze | None = None
        php_object_surface_attestations: list[tuple[str, str]] = []
        php_object_surface_error = ""
        php_object_gadget_oracle: PhpObjectGadgetOracle | None = None
        php_object_gadget_snapshot: PhpObjectGadgetOracleSnapshot | None = None
        php_object_gadget_arm_attestations: list[tuple[str, str]] = []
        php_object_gadget_effect_measurements: dict[
            tuple[str, str], PhpObjectGadgetFileMeasurement
        ] = {}
        php_object_gadget_state_snapshot: Path | None = None
        php_object_gadget_error = ""
        php_object_gadget_script_sha256 = ""
        php_object_gadget_bundle_manifest_sha256 = ""
        php_object_gadget_bundle_source_file_count = 0
        local_before_sha256 = ""
        local_before_monotonic_ns = 0
        execution_started_monotonic_ns = 0
        execution_finished_monotonic_ns = 0
        credential_free_direct = False
        tracked_capabilities: dict[str, str] = {}
        execution_error: Exception | None = None
        executable_upload_generation: _ExecutableUploadGeneration | None = None
        executable_upload_proxy_policy: ExecutableUploadPolicy | None = None
        executable_upload_snapshots: dict[
            tuple[Literal["before", "after"], Literal["attack", "control"]],
            _ExecutableUploadFilesystemSnapshot,
        ] = {}
        executable_upload_promoted = False

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

        if not isinstance(expected_php_include, bool):
            raise ValueError("expected_php_include must be a boolean")
        if not isinstance(expected_php_object, bool):
            raise ValueError("expected_php_object must be a boolean")
        if not isinstance(expected_php_object_gadget, bool):
            raise ValueError("expected_php_object_gadget must be a boolean")
        if not isinstance(expected_executable_upload, bool):
            raise ValueError("expected_executable_upload must be a boolean")
        if expected_executable_upload and expected_bug_class not in {
            BugClass.ARBITRARY_FILE_WRITE.name,
            BugClass.ARBITRARY_FILE_WRITE.value,
        }:
            raise ValueError("expected_executable_upload requires exact CWE-434 mode")
        enabled_trusted_modes = sum(
            (
                ssrf_expected,
                php_include_expected,
                php_object_expected,
                php_object_gadget_expected,
                expected_executable_upload,
            )
        )
        if enabled_trusted_modes > 1:
            raise ValueError("trusted HTTP oracle modes are mutually exclusive")
        if expected_executable_upload and _expected_executable_upload_transport(
            expected_http_transport
        ) is None:
            raise ValueError(
                "expected_executable_upload requires one exact source transport"
            )
        if expected_executable_upload:
            executable_upload_generation = _new_executable_upload_generation()
            executable_upload_proxy_policy = _executable_upload_policy(
                expected_http_transport,
                executable_upload_generation,
            )
            if executable_upload_proxy_policy is None:
                raise ValueError(
                    "expected_executable_upload requires a valid proxy policy"
                )
        if (
            not (php_object_expected or php_object_gadget_expected)
            and expected_php_object_transport is not None
        ):
            raise ValueError("expected_php_object_transport requires a PHP object mode")
        if (
            php_object_gadget_expected
            and normalize_attacker_role(expected_attacker_role) != "unauthenticated"
        ):
            return SandboxRunResult(
                success=False,
                output="",
                elapsed=time.time() - start,
                error_log=(
                    "PoC exec failed: natural PHP object gadget proof requires "
                    "an unauthenticated transport"
                ),
                validation_reason=(
                    "PHP object natural gadget promotion is limited to the exact "
                    "unauthenticated attacker role"
                ),
                evidence={
                    "http_trace_records": 0,
                    "http_trace_error": None,
                    "http_trace_rejections": {},
                    "php_object_oracle_error": "authenticated_transport_rejected",
                    "php_object_oracle_failure_reason": (
                        "php_object_gadget_requires_unauthenticated_transport"
                    ),
                    "poc_isolation": isolation_capability,
                },
            )

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

        if php_include_expected:
            php_include_oracle = self._php_include_oracle
            if (
                not self._php_include_oracle_enabled
                or php_include_oracle is None
                or self._php_include_host_dir is None
            ):
                return SandboxRunResult(
                    success=False,
                    output="",
                    elapsed=time.time() - start,
                    error_log="PoC exec failed: PHP include oracle is not prepared",
                    validation_reason="PHP include oracle is not prepared",
                    evidence={
                        "http_trace_records": 0,
                        "http_trace_error": None,
                        "http_trace_rejections": {},
                        "php_include_oracle_error": "unprepared",
                        "php_include_oracle_failure_reason": "unprepared",
                        "php_include_oracle_cleanup_error": None,
                        "php_include_oracle_inspection_retries": 0,
                        "poc_isolation": isolation_capability,
                    },
                )
            php_include_stage = "generation_begin"
            try:
                php_include_attack_path = php_include_oracle.attack_path
                php_include_control_path = php_include_oracle.control_path
                php_include_generation_id = php_include_oracle.begin_generation()
                php_include_marker = php_include_oracle.private_marker
                provisioning_started = time.monotonic_ns()
                php_include_stage = "provisioning_write"
                _provision_php_include_oracle(
                    self._php_include_host_dir,
                    php_include_oracle,
                )
                php_include_stage = "provisioning_host_measurement"
                php_include_host_before = _measure_php_include_host_filesystem(
                    self._php_include_host_dir,
                    php_include_attack_path,
                    php_include_control_path,
                )
                php_include_stage = "provisioning_inspection"
                (
                    php_include_before,
                    inspection_retries,
                ) = await _inspect_php_include_oracle_bounded_retry(
                    self.container_name,
                    php_include_attack_path,
                    php_include_control_path,
                )
                php_include_inspection_retries += inspection_retries
                provisioning_finished = time.monotonic_ns()
                php_include_stage = "provisioning_attestation"
                php_include_oracle.attest_provisioning(
                    generation_id=php_include_generation_id,
                    attack_resource_path=cast(
                        str,
                        php_include_before["attack_resource_path"],
                    ),
                    control_resource_path=cast(
                        str,
                        php_include_before["control_resource_path"],
                    ),
                    attack_content_sha256=cast(
                        str,
                        php_include_before["attack_content_sha256"],
                    ),
                    attack_content_size_bytes=cast(
                        int,
                        php_include_before["attack_content_size_bytes"],
                    ),
                    attack_owner_uid=cast(
                        int,
                        php_include_before["attack_owner_uid"],
                    ),
                    attack_owner_gid=cast(
                        int,
                        php_include_before["attack_owner_gid"],
                    ),
                    attack_file_mode=cast(
                        int,
                        php_include_before["attack_file_mode"],
                    ),
                    attack_link_count=cast(
                        int,
                        php_include_before["attack_link_count"],
                    ),
                    attack_is_regular_file=cast(
                        bool,
                        php_include_before["attack_is_regular_file"],
                    ),
                    attack_is_symlink=cast(
                        bool,
                        php_include_before["attack_is_symlink"],
                    ),
                    control_lstat_exists=cast(
                        bool,
                        php_include_before["control_lstat_exists"],
                    ),
                    host_measurement=php_include_host_before,
                    started_monotonic_ns=provisioning_started,
                    finished_monotonic_ns=provisioning_finished,
                )
                credential_free_direct = _allows_credential_free_direct_ssrf(
                    expected_http_transport,
                    expected_attacker_role,
                )
                tracked_capabilities = {
                    "php_include_attack_path": PurePosixPath(
                        php_include_attack_path
                    ).stem,
                    "php_include_control_path": PurePosixPath(
                        php_include_control_path
                    ).stem,
                }
                php_include_stage = "public_contract"
                public_context = php_include_oracle.public_context()
                if (
                    self._php_include_oracle is not php_include_oracle
                    or public_context.get("attack_path") != php_include_attack_path
                    or public_context.get("control_path") != php_include_control_path
                    or re.fullmatch(r"[0-9a-f]{64}", php_include_generation_id) is None
                    or _PHP_INCLUDE_MARKER_RE.fullmatch(php_include_marker) is None
                ):
                    raise RuntimeError("invalid PHP include oracle generation")
            except BaseException as exc:
                if isinstance(exc, _PhpIncludeInspectionError):
                    php_include_inspection_retries += exc.retries
                    php_include_failure_reason = f"{php_include_stage}_{exc.reason}"
                elif isinstance(exc, PhpIncludeAttestationError):
                    php_include_failure_reason = f"{php_include_stage}_{exc.reason}"
                else:
                    php_include_failure_reason = f"{php_include_stage}_failed"
                logger.warning(
                    "PHP include oracle generation failed: %s",
                    php_include_failure_reason,
                )
                try:
                    _remove_php_include_canary(
                        self._php_include_host_dir,
                        php_include_oracle,
                    )
                except Exception:
                    php_include_cleanup_error = "cleanup_failed"
                    logger.warning("failed to clean a rejected PHP include canary")
                if not isinstance(exc, Exception):
                    raise
                return SandboxRunResult(
                    success=False,
                    output="",
                    elapsed=time.time() - start,
                    error_log="PoC exec failed: PHP include oracle generation failed",
                    validation_reason=(
                        "PHP include oracle generation failed "
                        f"({php_include_failure_reason})"
                    ),
                    evidence={
                        "http_trace_records": 0,
                        "http_trace_error": None,
                        "http_trace_rejections": {},
                        "php_include_oracle_error": "generation_failed",
                        "php_include_oracle_failure_reason": (
                            php_include_failure_reason
                        ),
                        "php_include_oracle_cleanup_error": (
                            php_include_cleanup_error or None
                        ),
                        "php_include_oracle_inspection_retries": (
                            php_include_inspection_retries
                        ),
                        "poc_isolation": isolation_capability,
                    },
                )

        if php_object_gadget_expected:
            php_object_gadget_oracle = self._php_object_gadget_oracle
            php_object_policy = php_object_rewrite_policy_from_transport(
                expected_php_object_transport
            )
            if (
                not self._php_object_gadget_oracle_enabled
                or php_object_gadget_oracle is None
                or php_object_policy is None
                or self._php_object_oracle is None
                or self._php_object_callsite is None
            ):
                return SandboxRunResult(
                    success=False,
                    output="",
                    elapsed=time.time() - start,
                    error_log="PoC exec failed: PHP object gadget oracle is not prepared",
                    validation_reason=(
                        "PHP object gadget oracle or source-reviewed transport "
                        "is not prepared"
                    ),
                    evidence={
                        "http_trace_records": 0,
                        "http_trace_error": None,
                        "http_trace_rejections": {},
                        "php_object_oracle_error": "unprepared",
                        "php_object_oracle_failure_reason": (
                            "php_object_gadget_unprepared"
                        ),
                        "poc_isolation": isolation_capability,
                    },
                )
            php_object_stage = "gadget_source_attestation"
            try:
                primitive = self._php_object_oracle
                callsite = self._php_object_callsite
                await self._attest_php_object_oracle_plugin(primitive)
                await self._attest_php_object_callsite(callsite)
                runtime_binding = await self._attest_php_object_gadget_recipe(
                    php_object_gadget_oracle.recipe
                )
                if runtime_binding != php_object_gadget_oracle.runtime_binding:
                    raise RuntimeError("PHP object gadget runtime binding changed")
                php_object_stage = "generation"
                php_object_generation_id = php_object_gadget_oracle.begin_generation()
                php_object_private_values = php_object_gadget_private_redaction_values(
                    php_object_gadget_oracle,
                    primitive,
                    self._receipt_secret,
                )
                php_object_stage = "surface_freeze"
                php_object_surface_freeze = (
                    await self._freeze_php_object_executable_surfaces()
                )
            except BaseException as exc:
                php_object_failure_reason = f"{php_object_stage}_failed"
                if php_object_generation_id:
                    try:
                        php_object_gadget_oracle.abort_generation(
                            generation_id=php_object_generation_id
                        )
                    except Exception:
                        php_object_failure_reason = "generation_abort_failed"
                if php_object_surface_freeze is not None:
                    try:
                        await self._restore_php_object_executable_surfaces(
                            php_object_surface_freeze
                        )
                    except Exception:
                        php_object_failure_reason = "surface_restoration_failed"
                    php_object_surface_freeze = None
                if not isinstance(exc, Exception):
                    raise
                failed = SandboxRunResult(
                    success=False,
                    output="",
                    elapsed=time.time() - start,
                    error_log="PoC exec failed: PHP object gadget generation failed",
                    validation_reason=(
                        "PHP object gadget generation failed "
                        f"({php_object_failure_reason})"
                    ),
                    evidence={
                        "http_trace_records": 0,
                        "http_trace_error": None,
                        "http_trace_rejections": {},
                        "php_object_oracle_error": "generation_failed",
                        "php_object_oracle_failure_reason": (php_object_failure_reason),
                        "poc_isolation": isolation_capability,
                    },
                )
                if php_object_private_values:
                    redact_php_object_run_result(
                        failed,
                        php_object_private_values,
                    )
                return failed

        if php_object_expected:
            php_object_oracle = self._php_object_oracle
            php_object_policy = php_object_rewrite_policy_from_transport(
                expected_php_object_transport
            )
            if (
                not self._php_object_oracle_enabled
                or php_object_oracle is None
                or php_object_policy is None
            ):
                unprepared = SandboxRunResult(
                    success=False,
                    output="",
                    elapsed=time.time() - start,
                    error_log="PoC exec failed: PHP object oracle is not prepared",
                    validation_reason=(
                        "PHP object oracle or source-reviewed transport is not prepared"
                    ),
                    evidence={
                        "http_trace_records": 0,
                        "http_trace_error": None,
                        "http_trace_rejections": {},
                        "php_object_oracle_error": "unprepared",
                        "php_object_oracle_failure_reason": "unprepared",
                        "poc_isolation": isolation_capability,
                    },
                )
                if php_object_oracle is not None:
                    redact_php_object_run_result(
                        unprepared,
                        php_object_private_redaction_values(php_object_oracle),
                    )
                return unprepared
            php_object_stage = "callsite_attestation"
            try:
                callsite = self._php_object_callsite
                if callsite is None:
                    raise RuntimeError("PHP object callsite is not prepared")
                callsite_path = await self._attest_php_object_callsite(callsite)
                if not hmac.compare_digest(
                    callsite_path,
                    php_object_oracle.private_callsite_path,
                ):
                    raise RuntimeError("PHP object callsite mapping changed")
                php_object_stage = "oracle_attestation"
                await self._attest_php_object_oracle_plugin(php_object_oracle)
                php_object_stage = "generation"
                php_object_generation_id = php_object_oracle.begin_generation()
                php_object_private_values = php_object_private_redaction_values(
                    php_object_oracle
                )
                if (
                    self._php_object_oracle is not php_object_oracle
                    or php_object_generation_id != php_object_oracle.generation_id
                    or re.fullmatch(r"[0-9a-f]{64}", php_object_generation_id) is None
                    or not strict_isolation
                    or credential_free_direct
                ):
                    raise RuntimeError("invalid PHP object oracle generation")
                php_object_stage = "surface_freeze"
                php_object_surface_freeze = (
                    await self._freeze_php_object_executable_surfaces()
                )
                php_object_stage = "frozen_callsite_attestation"
                frozen_callsite_path = await self._attest_php_object_callsite(callsite)
                if not hmac.compare_digest(callsite_path, frozen_callsite_path):
                    raise RuntimeError("PHP object callsite changed during freeze")
            except BaseException as exc:
                php_object_failure_reason = f"{php_object_stage}_failed"
                if php_object_generation_id:
                    try:
                        php_object_oracle.abort_generation(
                            generation_id=php_object_generation_id
                        )
                    except Exception:
                        php_object_failure_reason = "generation_abort_failed"
                if php_object_surface_freeze is not None:
                    try:
                        await self._restore_php_object_executable_surfaces(
                            php_object_surface_freeze
                        )
                    except Exception:
                        php_object_failure_reason = "surface_restoration_failed"
                    php_object_surface_freeze = None
                if php_object_stage == "frozen_callsite_attestation":
                    self._php_object_surface_poisoned = True
                if not php_object_private_values:
                    php_object_private_values = php_object_private_redaction_values(
                        php_object_oracle
                    )
                if not isinstance(exc, Exception):
                    raise
                failed = SandboxRunResult(
                    success=False,
                    output="",
                    elapsed=time.time() - start,
                    error_log="PoC exec failed: PHP object oracle generation failed",
                    validation_reason=(
                        "PHP object oracle generation failed "
                        f"({php_object_failure_reason})"
                    ),
                    evidence={
                        "http_trace_records": 0,
                        "http_trace_error": None,
                        "http_trace_rejections": {},
                        "php_object_oracle_error": "generation_failed",
                        "php_object_oracle_failure_reason": (php_object_failure_reason),
                        "poc_isolation": isolation_capability,
                    },
                )
                redact_php_object_run_result(failed, php_object_private_values)
                return failed

        async def attest_php_object_surface(
            phase: Literal["before", "after"],
            arm: Literal["attack", "control"],
        ) -> None:
            """Bind proxy arm boundaries to the exact root-owned freeze."""
            nonlocal php_object_surface_error
            frozen = php_object_surface_freeze
            current = (phase, arm)
            if frozen is None:
                raise RuntimeError("PHP object executable surface is not frozen")
            try:
                await self._attest_php_object_executable_surfaces(frozen)
            except Exception:
                php_object_surface_error = "attestation_failed"
                raise
            php_object_surface_attestations.append(current)

        async def attest_php_object_gadget_arm(
            phase: Literal["before", "after"],
            arm: Literal["attack", "control"],
        ) -> None:
            """Provision/measure each arm around one identical restored state."""
            nonlocal php_object_gadget_state_snapshot
            oracle = php_object_gadget_oracle
            if oracle is None:
                raise RuntimeError("PHP object gadget oracle is unavailable")
            current = (phase, arm)
            expected = _PHP_OBJECT_SURFACE_ATTESTATION_ORDER[
                len(php_object_gadget_arm_attestations)
            ]
            if current != expected:
                raise RuntimeError("PHP object gadget arm order changed")
            if current == ("before", "attack"):
                if php_object_gadget_state_snapshot is not None:
                    raise RuntimeError("PHP object gadget state snapshot was reused")
                php_object_gadget_state_snapshot = await self.snapshot()
                # Start both arms from the exact archived application state and
                # run the same restart + runtime-attestation sequence.  Taking
                # the archive before this common setup avoids giving the attack
                # arm a warmer/differently bootstrapped state than the control.
                await self._restore_php_object_gadget_clean_state(
                    php_object_gadget_state_snapshot,
                    oracle,
                    require_empty_tmpfs=True,
                )
                await self._provision_php_object_gadget_target(oracle)
            elif current == ("after", "attack"):
                pass
            elif current == ("before", "control"):
                snapshot_dir = php_object_gadget_state_snapshot
                if snapshot_dir is None:
                    raise RuntimeError("PHP object gadget state snapshot is missing")
                await self._restore_php_object_gadget_clean_state(
                    snapshot_dir,
                    oracle,
                    require_empty_tmpfs=True,
                )
                await self._provision_php_object_gadget_target(oracle)
            elif current != ("after", "control"):
                raise RuntimeError("invalid PHP object gadget arm boundary")

            measurement = await self._measure_php_object_gadget_target(oracle)
            php_object_gadget_effect_measurements[current] = measurement

            if current == ("after", "control"):
                snapshot_dir = php_object_gadget_state_snapshot
                if snapshot_dir is None:
                    raise RuntimeError("PHP object gadget state snapshot is missing")
                await self._restore_php_object_gadget_clean_state(
                    snapshot_dir,
                    oracle,
                    require_empty_tmpfs=False,
                )
                oracle.attest_effect(
                    attack_before=php_object_gadget_effect_measurements[
                        ("before", "attack")
                    ],
                    attack_after=php_object_gadget_effect_measurements[
                        ("after", "attack")
                    ],
                    control_before=php_object_gadget_effect_measurements[
                        ("before", "control")
                    ],
                    control_after=measurement,
                    state_restored_before_control=True,
                    runtime_restarted_before_control=True,
                    state_restored_after_control=True,
                    runtime_restarted_after_control=True,
                )
                self._discard_php_object_gadget_snapshot(snapshot_dir)
                php_object_gadget_state_snapshot = None
            php_object_gadget_arm_attestations.append(current)

        async def attest_executable_upload_arm(
            phase: Literal["before", "after"],
            arm: Literal["attack", "control"],
        ) -> None:
            """Capture the uploads namespace at each serialized request edge."""
            generation = executable_upload_generation
            if generation is None:
                raise RuntimeError("executable-upload generation is unavailable")
            current = (phase, arm)
            index = len(executable_upload_snapshots)
            if (
                index >= len(_EXECUTABLE_UPLOAD_ATTESTATION_ORDER)
                or current != _EXECUTABLE_UPLOAD_ATTESTATION_ORDER[index]
                or current in executable_upload_snapshots
            ):
                raise RuntimeError("executable-upload arm boundary order changed")
            executable_upload_snapshots[current] = (
                await _snapshot_executable_upload_filesystem(
                    container_name=self.container_name,
                    generation=generation,
                )
            )

        try:
            if strict_isolation:
                if expected_executable_upload:
                    if executable_upload_proxy_policy is None:
                        raise RuntimeError(
                            "executable-upload proxy policy is unavailable"
                        )
                    proxy = PocProxySupervisor(
                        self.target_url,
                        trace_token=self._trace_token,
                        executable_upload_policy=executable_upload_proxy_policy,
                        executable_upload_arm_attestor=(
                            attest_executable_upload_arm
                        ),
                        request_binding_secret=self._receipt_secret,
                    )
                elif php_object_gadget_expected:
                    proxy = PocProxySupervisor(
                        self.target_url,
                        trace_token=self._trace_token,
                        php_object_gadget_oracle=php_object_gadget_oracle,
                        php_object_policy=php_object_policy,
                        php_object_surface_attestor=attest_php_object_surface,
                        php_object_gadget_arm_attestor=(attest_php_object_gadget_arm),
                        credential_free=True,
                    )
                elif php_object_expected:
                    proxy = PocProxySupervisor(
                        self.target_url,
                        trace_token=self._trace_token,
                        php_object_oracle=php_object_oracle,
                        php_object_policy=php_object_policy,
                        php_object_surface_attestor=attest_php_object_surface,
                    )
                elif php_include_expected:
                    proxy = PocProxySupervisor(
                        self.target_url,
                        trace_token=self._trace_token,
                        tracked_capabilities=tracked_capabilities,
                        credential_free=credential_free_direct,
                        capture_php_include_receipt=True,
                    )
                elif credential_free_direct:
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
                            if php_object_gadget_expected:
                                # This is the executable identity: hash the safely
                                # copied main script, all sibling helpers, and the
                                # trusted bootstrap inside the private bundle at
                                # the last parent-owned boundary before launch.
                                bundle_manifest = isolation.attest_bundle()
                                php_object_gadget_script_sha256 = (
                                    bundle_manifest.script_sha256
                                )
                                php_object_gadget_bundle_manifest_sha256 = (
                                    bundle_manifest.manifest_sha256
                                )
                                php_object_gadget_bundle_source_file_count = (
                                    bundle_manifest.source_file_count
                                )
                            execution_started_monotonic_ns = time.monotonic_ns()
                            try:
                                child_environment = isolation.child_environment(
                                    proxy.proxy_url
                                )
                                if executable_upload_generation is not None:
                                    child_environment.update(
                                        {
                                            EXECUTABLE_UPLOAD_PAYLOAD_ENV: (
                                                executable_upload_generation.payload_b64
                                            ),
                                            EXECUTABLE_UPLOAD_ATTACK_FILENAME_ENV: (
                                                executable_upload_generation.attack_filename
                                            ),
                                            EXECUTABLE_UPLOAD_CONTROL_FILENAME_ENV: (
                                                executable_upload_generation.control_filename
                                            ),
                                        }
                                    )
                                stdout, stderr = await execute_child(
                                    isolation.python_command(
                                        isolation.runner_path,
                                        isolation.script_path,
                                    ),
                                    cwd=isolation.cwd,
                                    environment=child_environment,
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
        except BaseException as exc:
            if isinstance(exc, Exception):
                execution_error = exc
            else:
                if php_include_expected:
                    try:
                        _remove_php_include_canary(
                            self._php_include_host_dir,
                            php_include_oracle,
                        )
                    except Exception:
                        logger.warning("failed to clean a cancelled PHP include canary")
                if php_object_expected and php_object_generation_id:
                    try:
                        cast(PhpObjectOracle, php_object_oracle).abort_generation(
                            generation_id=php_object_generation_id
                        )
                    except Exception:
                        logger.warning(
                            "failed to abort a cancelled PHP object generation"
                        )
                if php_object_gadget_expected and php_object_generation_id:
                    try:
                        cast(
                            PhpObjectGadgetOracle,
                            php_object_gadget_oracle,
                        ).abort_generation(generation_id=php_object_generation_id)
                    except Exception:
                        logger.warning(
                            "failed to abort a cancelled PHP object gadget generation"
                        )
                raise
        finally:
            if php_object_gadget_expected:
                try:
                    if php_object_gadget_state_snapshot is not None:
                        recovery_oracle = cast(
                            PhpObjectGadgetOracle,
                            php_object_gadget_oracle,
                        )
                        await self._recover_and_discard_php_object_gadget_snapshot(
                            php_object_gadget_state_snapshot,
                            recovery_oracle,
                        )
                        php_object_gadget_state_snapshot = None
                    else:
                        await self._cleanup_php_object_gadget_directory(
                            require_empty=False
                        )
                except Exception:
                    php_object_gadget_error = "state_restoration_failed"
            if php_object_surface_freeze is not None:
                try:
                    try:
                        await self._attest_php_object_executable_surfaces(
                            php_object_surface_freeze
                        )
                    except Exception:
                        php_object_surface_error = "attestation_failed"
                finally:
                    try:
                        await self._restore_php_object_executable_surfaces(
                            php_object_surface_freeze
                        )
                    except Exception:
                        if not php_object_surface_error:
                            php_object_surface_error = "restoration_failed"

        if php_object_expected:
            transport_complete = (
                tuple(php_object_surface_attestations)
                == _PHP_OBJECT_SURFACE_ATTESTATION_ORDER
                and proxy is not None
                and php_object_oracle is not None
                and proxy.php_object_complete
            )
            if php_object_surface_error:
                php_object_error = f"surface_{php_object_surface_error}"
                php_object_failure_reason = php_object_error
            elif not transport_complete:
                # A child can fail during login or rendered-form preflight before
                # either trusted arm reaches the proxy.  Missing arm callbacks are
                # a transport diagnostic, not evidence that the frozen executable
                # surface drifted.  The final root-owned surface check above remains
                # authoritative for that separate integrity property.
                php_object_error = "transport_incomplete"
                php_object_failure_reason = "php_object_transport_incomplete"
            else:
                trusted_proxy = cast(PocProxySupervisor, proxy)
                trusted_php_object_oracle = cast(
                    PhpObjectOracle,
                    php_object_oracle,
                )
                try:
                    private_observation = trusted_proxy.take_php_object_observation()
                    if private_observation is None:
                        raise RuntimeError("PHP object receipt observation is missing")
                    php_object_snapshot = trusted_php_object_oracle.attest_execution(
                        generation_id=private_observation.generation_id,
                        attack_token=private_observation.attack_token,
                        control_token=private_observation.control_token,
                        attack_receipt=private_observation.attack_receipt,
                        control_receipt=private_observation.control_receipt,
                        execution_started_monotonic_ns=(
                            private_observation.execution_started_monotonic_ns
                        ),
                        execution_finished_monotonic_ns=(
                            private_observation.execution_finished_monotonic_ns
                        ),
                        attested_monotonic_ns=time.monotonic_ns(),
                    )
                except Exception:
                    php_object_error = "attestation_failed"
                    php_object_failure_reason = "execution_attestation_failed"
            if php_object_error:
                if php_object_oracle is not None and php_object_generation_id:
                    try:
                        php_object_oracle.abort_generation(
                            generation_id=php_object_generation_id
                        )
                    except Exception:
                        php_object_failure_reason = "generation_abort_failed"

        if php_object_gadget_expected:
            transport_complete = (
                tuple(php_object_surface_attestations)
                == _PHP_OBJECT_SURFACE_ATTESTATION_ORDER
                and tuple(php_object_gadget_arm_attestations)
                == _PHP_OBJECT_SURFACE_ATTESTATION_ORDER
                and proxy is not None
                and php_object_gadget_oracle is not None
                and proxy.php_object_gadget_complete
            )
            if php_object_surface_error:
                php_object_gadget_error = f"surface_{php_object_surface_error}"
            elif php_object_gadget_error:
                pass
            elif trace_error == "php_object_gadget_attestation_failed":
                php_object_gadget_error = "attestation_failed"
            elif not transport_complete:
                php_object_gadget_error = "transport_incomplete"
            else:
                trusted_proxy = cast(PocProxySupervisor, proxy)
                trusted_oracle = cast(
                    PhpObjectGadgetOracle,
                    php_object_gadget_oracle,
                )
                try:
                    private_observation = (
                        trusted_proxy.take_php_object_gadget_observation()
                    )
                    if private_observation is None:
                        raise RuntimeError("PHP object gadget timing is missing")
                    (
                        trace_ok,
                        trace_reason,
                        transport_attestation,
                        trace_evidence,
                    ) = validate_php_object_gadget_http_trace(
                        trace_records,
                        target_url=self.target_url,
                        receipt_secret=self._receipt_secret,
                        trace_token=self._trace_token,
                        policy=cast(PhpObjectRewritePolicy, php_object_policy),
                        oracle=trusted_oracle,
                        script_sha256=php_object_gadget_script_sha256,
                        poc_bundle_manifest_sha256=(
                            php_object_gadget_bundle_manifest_sha256
                        ),
                        poc_bundle_source_file_count=(
                            php_object_gadget_bundle_source_file_count
                        ),
                        expected_attacker_role=(expected_attacker_role or ""),
                        surface_attestations=tuple(php_object_surface_attestations),
                        trace_error=trace_error,
                    )
                    if not trace_ok or transport_attestation is None:
                        raise RuntimeError(trace_reason)
                    php_object_gadget_snapshot = trusted_oracle.attest_execution(
                        generation_id=private_observation.generation_id,
                        attack_token=private_observation.attack_token,
                        control_token=private_observation.control_token,
                        execution_started_monotonic_ns=(
                            private_observation.execution_started_monotonic_ns
                        ),
                        execution_finished_monotonic_ns=(
                            private_observation.execution_finished_monotonic_ns
                        ),
                        attested_monotonic_ns=time.monotonic_ns(),
                        runtime_binding=trusted_oracle.runtime_binding,
                        transport_attestation=transport_attestation,
                    )
                except Exception:
                    php_object_gadget_error = "execution_attestation_failed"
            if php_object_gadget_error:
                php_object_error = php_object_gadget_error
                php_object_failure_reason = (
                    "php_object_gadget_" + php_object_gadget_error
                )
                if php_object_gadget_oracle is not None and php_object_generation_id:
                    try:
                        php_object_gadget_oracle.abort_generation(
                            generation_id=php_object_generation_id
                        )
                    except Exception:
                        php_object_failure_reason = "generation_abort_failed"

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

        if php_include_expected:
            php_include_stage = "post_execution_state"
            try:
                php_include_host_directory = self._php_include_host_dir
                if (
                    self._php_include_oracle is not php_include_oracle
                    or php_include_oracle is None
                    or php_include_before is None
                    or php_include_host_before is None
                    or php_include_host_directory is None
                    or execution_started_monotonic_ns < 1
                    or execution_finished_monotonic_ns < execution_started_monotonic_ns
                ):
                    raise RuntimeError("PHP include oracle was replaced")
                php_include_stage = "post_execution_host_measurement"
                php_include_host_after = _measure_php_include_host_filesystem(
                    php_include_host_directory,
                    php_include_attack_path,
                    php_include_control_path,
                )
                php_include_stage = "post_execution_inspection"
                (
                    measured_after,
                    inspection_retries,
                ) = await _inspect_php_include_oracle_bounded_retry(
                    self.container_name,
                    php_include_attack_path,
                    php_include_control_path,
                )
                php_include_inspection_retries += inspection_retries
                after_monotonic_ns = time.monotonic_ns()
                php_include_stage = "verification_attestation"
                php_include_snapshot = php_include_oracle.attest_verification(
                    generation_id=php_include_generation_id,
                    attack_resource_path=cast(
                        str,
                        measured_after["attack_resource_path"],
                    ),
                    control_resource_path=cast(
                        str,
                        measured_after["control_resource_path"],
                    ),
                    after_attack_content_sha256=cast(
                        str,
                        measured_after["attack_content_sha256"],
                    ),
                    after_attack_content_size_bytes=cast(
                        int,
                        measured_after["attack_content_size_bytes"],
                    ),
                    after_attack_owner_uid=cast(
                        int,
                        measured_after["attack_owner_uid"],
                    ),
                    after_attack_owner_gid=cast(
                        int,
                        measured_after["attack_owner_gid"],
                    ),
                    after_attack_file_mode=cast(
                        int,
                        measured_after["attack_file_mode"],
                    ),
                    after_attack_link_count=cast(
                        int,
                        measured_after["attack_link_count"],
                    ),
                    after_attack_is_regular_file=cast(
                        bool,
                        measured_after["attack_is_regular_file"],
                    ),
                    after_attack_is_symlink=cast(
                        bool,
                        measured_after["attack_is_symlink"],
                    ),
                    after_control_lstat_exists=cast(
                        bool,
                        measured_after["control_lstat_exists"],
                    ),
                    after_host_measurement=php_include_host_after,
                    execution_started_monotonic_ns=execution_started_monotonic_ns,
                    execution_finished_monotonic_ns=execution_finished_monotonic_ns,
                    after_monotonic_ns=after_monotonic_ns,
                )
            except Exception as exc:
                php_include_error = "snapshot_failed"
                if isinstance(exc, _PhpIncludeInspectionError):
                    php_include_inspection_retries += exc.retries
                    php_include_failure_reason = f"{php_include_stage}_{exc.reason}"
                elif isinstance(exc, PhpIncludeAttestationError):
                    php_include_failure_reason = f"{php_include_stage}_{exc.reason}"
                else:
                    php_include_failure_reason = f"{php_include_stage}_failed"
                logger.warning(
                    "PHP include oracle snapshot failed: %s",
                    php_include_failure_reason,
                )
            finally:
                try:
                    _remove_php_include_canary(
                        self._php_include_host_dir,
                        php_include_oracle,
                    )
                except (OSError, RuntimeError):
                    php_include_cleanup_error = "cleanup_failed"
                    logger.warning("failed to clean a completed PHP include canary")
                    if not php_include_error:
                        php_include_error = "cleanup_failed"
                        php_include_failure_reason = "cleanup_failed"

        php_object_receipt_diagnostic = (
            _trusted_php_object_receipt_rejection_diagnostic(trace_error)
            if (
                php_object_expected
                and not php_object_gadget_expected
                and php_object_error == "transport_incomplete"
            )
            else None
        )

        if execution_error is not None:
            failed_result = SandboxRunResult(
                success=False,
                output="",
                elapsed=time.time() - start,
                error_log=f"PoC exec failed: {execution_error}",
                validation_reason=(
                    php_object_receipt_diagnostic[0]
                    if php_object_receipt_diagnostic is not None
                    else "PoC execution failed"
                ),
                evidence={
                    "http_trace_records": len(trace_records),
                    "http_trace_error": trace_error or None,
                    "http_trace_rejections": rejection_counts,
                    "ssrf_oracle_error": oracle_error or None,
                    "php_include_oracle_error": php_include_error or None,
                    "php_include_oracle_failure_reason": (
                        php_include_failure_reason or None
                    ),
                    "php_include_oracle_cleanup_error": (
                        php_include_cleanup_error or None
                    ),
                    "php_include_oracle_inspection_retries": (
                        php_include_inspection_retries
                    ),
                    "php_object_oracle_error": php_object_error or None,
                    "php_object_oracle_failure_reason": (
                        php_object_failure_reason or None
                    ),
                    "poc_isolation": isolation_capability,
                },
            )
            if php_object_receipt_diagnostic is not None:
                failed_result.evidence["php_object_trusted_parent_diagnostic"] = (
                    php_object_receipt_diagnostic[1]
                )
            if php_include_expected:
                redact_php_include_run_result(failed_result, php_include_marker)
            if php_object_expected or php_object_gadget_expected:
                redact_php_object_run_result(
                    failed_result,
                    php_object_private_values,
                )
            return failed_result
        if timed_out:
            timed_out_result = SandboxRunResult(
                success=False,
                output="",
                elapsed=time.time() - start,
                error_log=f"PoC timed out after {self.poc_timeout_s}s",
                validation_reason=(
                    php_object_receipt_diagnostic[0]
                    if php_object_receipt_diagnostic is not None
                    else "PoC execution timed out"
                ),
                evidence={
                    "http_trace_records": len(trace_records),
                    "http_trace_error": trace_error or None,
                    "http_trace_rejections": rejection_counts,
                    "ssrf_oracle_error": oracle_error or None,
                    "php_include_oracle_error": php_include_error or None,
                    "php_include_oracle_failure_reason": (
                        php_include_failure_reason or None
                    ),
                    "php_include_oracle_cleanup_error": (
                        php_include_cleanup_error or None
                    ),
                    "php_include_oracle_inspection_retries": (
                        php_include_inspection_retries
                    ),
                    "php_object_oracle_error": php_object_error or None,
                    "php_object_oracle_failure_reason": (
                        php_object_failure_reason or None
                    ),
                    "poc_isolation": isolation_capability,
                },
            )
            if php_object_receipt_diagnostic is not None:
                timed_out_result.evidence["php_object_trusted_parent_diagnostic"] = (
                    php_object_receipt_diagnostic[1]
                )
            if php_include_expected:
                redact_php_include_run_result(timed_out_result, php_include_marker)
            if php_object_expected or php_object_gadget_expected:
                redact_php_object_run_result(
                    timed_out_result,
                    php_object_private_values,
                )
            return timed_out_result

        elapsed = time.time() - start
        out = stdout.decode("utf-8", errors="replace")
        err = stderr.decode("utf-8", errors="replace")
        observation, parse_reason = _parse_poc_observation(out)
        if php_object_gadget_expected:
            # Natural evidence is exclusively the non-serializing parent snapshot.
            # The reused child may still emit its old inert-canary report; it is
            # neither accepted nor retained as rejected natural evidence.
            observation = None
            parse_reason = "child report intentionally ignored for natural gadget"
        trace_evidence: dict = {}
        probe_evidence: dict[str, object] = {}
        if proc is None:
            success = False
            validation_reason = "PoC process did not start"
        elif php_object_receipt_diagnostic is not None:
            success = False
            validation_reason = php_object_receipt_diagnostic[0]
        elif trace_error and not (
            (php_object_gadget_expected and php_object_error)
            or (
                php_object_expected
                and php_object_error
                and php_object_error != "transport_incomplete"
            )
        ):
            success = False
            validation_reason = f"PoC HTTP supervision failed: {trace_error}"
        elif ssrf_expected and oracle_error:
            success = False
            validation_reason = f"SSRF oracle snapshot failed: {oracle_error}"
        elif php_include_expected and php_include_error:
            success = False
            php_include_failure_details = (
                [php_include_failure_reason] if php_include_failure_reason else []
            )
            if (
                php_include_cleanup_error
                and php_include_cleanup_error != php_include_failure_reason
            ):
                php_include_failure_details.append(php_include_cleanup_error)
            php_include_failure_suffix = (
                " (" + "; ".join(php_include_failure_details) + ")"
                if php_include_failure_details
                else ""
            )
            validation_reason = (
                f"PHP include oracle snapshot failed: {php_include_error}"
                f"{php_include_failure_suffix}"
            )
        elif (
            php_object_expected
            and php_object_error == "transport_incomplete"
            and proc.returncode != 0
        ):
            success = False
            validation_reason = (
                f"PoC process exited {proc.returncode} before PHP object "
                "transport completed"
            )
        elif php_object_expected and php_object_error:
            success = False
            if php_object_error == "transport_incomplete":
                validation_reason = "PHP object attack/control transport incomplete"
            elif php_object_error == "surface_attestation_failed":
                validation_reason = "PHP object executable-surface attestation failed"
            elif php_object_error == "surface_restoration_failed":
                validation_reason = "PHP object executable-surface restoration failed"
            else:
                validation_reason = "PHP object oracle attestation failed" + (
                    f" ({php_object_failure_reason})"
                    if php_object_failure_reason
                    else ""
                )
        elif php_object_gadget_expected and php_object_error:
            success = False
            validation_reason = "PHP object gadget oracle attestation failed" + (
                f" ({php_object_failure_reason})" if php_object_failure_reason else ""
            )
        elif proc.returncode != 0:
            success = False
            validation_reason = f"PoC process exited {proc.returncode}"
        elif php_object_gadget_expected:
            success = php_object_gadget_snapshot is not None
            validation_reason = (
                "PHP object natural file-delete proof passed"
                if success
                else "PHP object natural gadget snapshot is missing"
            )
        elif observation is None:
            success = False
            validation_reason = parse_reason
        else:
            if expected_executable_upload and observation.oracle == "response_marker":
                generation = executable_upload_generation
                if generation is None:
                    raise RuntimeError(
                        "executable-upload generation disappeared before validation"
                    )
                if (
                    proxy is None
                    or not proxy.executable_upload_complete
                    or trace_error
                ):
                    binding = None
                    validation_reason = (
                        "executable-upload proxy did not complete both attested arms"
                    )
                else:
                    binding, validation_reason = (
                        _prepare_executable_upload_candidate(
                            observation,
                            trace_records=trace_records,
                            trace_salt=trace_salt,
                            target_url=self.target_url,
                            expected_http_transport=expected_http_transport,
                            expected_attacker_role=expected_attacker_role,
                            receipt_secret=self._receipt_secret,
                            trace_token=self._trace_token,
                            generation=generation,
                        )
                    )
                success = binding is not None
                if binding is not None:
                    trace_evidence = {
                        "oracle": "executable_upload_parent_attestation",
                        "upload_trace": binding.evidence,
                    }
                    (
                        success,
                        validation_reason,
                        snapshot_evidence,
                    ) = _validate_executable_upload_snapshot_transitions(
                        binding,
                        generation=generation,
                        snapshots=executable_upload_snapshots,
                    )
                    trace_evidence["arm_filesystem"] = snapshot_evidence
                if success and binding is not None:
                    (
                        success,
                        validation_reason,
                        filesystem_evidence,
                    ) = await _attest_executable_upload_filesystem(
                        binding,
                        container_name=self.container_name,
                        generation=generation,
                    )
                    trace_evidence["filesystem"] = filesystem_evidence
                if success and binding is not None:
                    (
                        success,
                        validation_reason,
                        probe_evidence,
                    ) = await _attest_executable_upload_response_marker(
                        binding,
                        target_url=self.target_url,
                        generation=generation,
                    )
                    trace_evidence["post_exit_probe"] = probe_evidence
                if success and binding is not None:
                    (
                        success,
                        validation_reason,
                        filesystem_after_evidence,
                    ) = await _attest_executable_upload_filesystem(
                        binding,
                        container_name=self.container_name,
                        generation=generation,
                    )
                    trace_evidence["filesystem_after_probe"] = (
                        filesystem_after_evidence
                    )
                    if success and filesystem_after_evidence != filesystem_evidence:
                        success = False
                        validation_reason = (
                            "parent executable-upload files changed during probing"
                        )
                if success and binding is not None:
                    response_marker = probe_evidence.get("response_marker")
                    if (
                        not isinstance(response_marker, str)
                        or re.fullmatch(
                            re.escape(EXECUTABLE_UPLOAD_RESPONSE_PREFIX)
                            + r"[0-9a-f]{64}",
                            response_marker,
                        )
                        is None
                    ):
                        raise RuntimeError(
                            "parent executable-upload response marker is malformed"
                        )
                    observation = _parent_executable_upload_observation(
                        binding,
                        generation=generation,
                        response_marker=response_marker,
                    )
                    success, validation_reason = validate_poc_observation(
                        observation,
                        expected_bug_class=expected_bug_class,
                        expected_attacker_role=expected_attacker_role,
                    )
                    executable_upload_promoted = success
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
            if (
                success
                and php_include_expected
                and observation.oracle != "response_marker"
            ):
                success = False
                validation_reason = (
                    "PHP include automatic verification requires the trusted "
                    "response_marker boundary"
                )
            if (
                success
                and php_include_expected
                and observation.oracle == "response_marker"
            ):
                if not strict_isolation:
                    success = False
                    validation_reason = (
                        "PHP include proof requires the strict parent-proxy "
                        "isolation boundary"
                    )
                else:
                    success, validation_reason, trace_evidence = (
                        validate_php_include_response_marker_http_trace(
                            observation,
                            trace_records,
                            trace_salt=trace_salt,
                            target_url=self.target_url,
                            receipt_secret=self._receipt_secret,
                            trace_token=self._trace_token,
                            oracle_attack_path=php_include_attack_path,
                            oracle_control_path=php_include_control_path,
                            oracle_marker=php_include_marker,
                            oracle_snapshot=php_include_snapshot,
                            oracle_generation_id=php_include_generation_id,
                            expected_http_transport=expected_http_transport,
                            trace_error=trace_error,
                        )
                    )
            if (
                success
                and php_object_expected
                and observation.oracle != "object_instantiation"
            ):
                success = False
                validation_reason = (
                    "PHP object automatic verification requires the trusted "
                    "object_instantiation boundary"
                )
            if success and observation.oracle == "object_instantiation":
                if not php_object_expected:
                    success = False
                    validation_reason = (
                        "object-instantiation proof requires an explicitly prepared "
                        "trusted PHP object oracle"
                    )
                elif (
                    not strict_isolation
                    or php_object_policy is None
                    or php_object_snapshot is None
                ):
                    success = False
                    validation_reason = (
                        "PHP object proof requires the strict parent-proxy isolation "
                        "and trusted receipt attestation"
                    )
                else:
                    success, validation_reason, trace_evidence = (
                        validate_php_object_http_trace(
                            observation,
                            trace_records,
                            target_url=self.target_url,
                            receipt_secret=self._receipt_secret,
                            trace_token=self._trace_token,
                            policy=php_object_policy,
                            snapshot=php_object_snapshot,
                            expected_attacker_role=(expected_attacker_role or ""),
                            trace_error=trace_error,
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

        run_result = SandboxRunResult(
            success=success,
            output=out,
            elapsed=elapsed,
            http_status=http_status,
            response=out[-2000:] if out else None,
            error_log=error_log or None,
            observation=observation if success else None,
            rejected_observation=observation if not success else None,
            validation_reason=validation_reason,
            evidence={
                "observation": observation.model_dump(mode="json")
                if success and observation
                else None,
                "rejected_observation": observation.model_dump(mode="json")
                if not success and observation
                else None,
                "observation_disposition": (
                    "parent_promoted"
                    if success and observation and executable_upload_promoted
                    else "accepted"
                    if success and observation
                    else "rejected"
                    if observation
                    else "absent"
                ),
                "validation_reason": validation_reason,
                "stdout_tail": out[-500:],
                "returncode": proc.returncode if proc is not None else None,
                "http_trace_records": len(trace_records),
                "http_trace_error": trace_error or None,
                "http_trace_rejections": rejection_counts,
                "http_trace_binding": trace_evidence or None,
                "executable_upload_parent_promoted": executable_upload_promoted,
                "ssrf_oracle_error": oracle_error or None,
                "php_include_oracle_error": php_include_error or None,
                "php_include_oracle_failure_reason": (
                    php_include_failure_reason or None
                ),
                "php_include_oracle_cleanup_error": (php_include_cleanup_error or None),
                "php_include_oracle_inspection_retries": (
                    php_include_inspection_retries
                ),
                "php_object_oracle_error": php_object_error or None,
                "php_object_oracle_failure_reason": (php_object_failure_reason or None),
                "poc_isolation": isolation_capability,
            },
        )
        if executable_upload_promoted:
            run_result.output = _strip_rejected_poc_result_lines(run_result.output) or ""
            run_result.response = (
                run_result.output[-2000:] if run_result.output else None
            )
            run_result.error_log = (
                _strip_rejected_poc_result_lines(run_result.error_log) or None
            )
            run_result.evidence["stdout_tail"] = run_result.output[-500:]
        if php_object_receipt_diagnostic is not None:
            run_result.evidence["php_object_trusted_parent_diagnostic"] = (
                php_object_receipt_diagnostic[1]
            )
        if php_include_expected:
            if success and observation is not None:
                run_result.retain_trusted_php_include_observation(observation)
            redact_php_include_run_result(run_result, php_include_marker)
        if php_object_expected:
            if success and php_object_snapshot is not None:
                run_result.retain_trusted_php_object_snapshot(php_object_snapshot)
            redact_php_object_run_result(run_result, php_object_private_values)
        if php_object_gadget_expected:
            strip_php_object_gadget_child_claims(run_result)
            if success and php_object_gadget_snapshot is not None:
                run_result.retain_trusted_php_object_gadget_snapshot(
                    php_object_gadget_snapshot
                )
            redact_php_object_run_result(run_result, php_object_private_values)
        return run_result
