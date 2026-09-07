"""Fail-closed macOS isolation for model-authored PoC subprocesses.

The generated program is copied into a small, bounded bundle before launch.
On macOS the bundle can then be executed under Seatbelt with filesystem writes
limited to that bundle and network access limited to one parent-owned loopback
proxy port.  There is deliberately no unsandboxed fallback.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import ssl
import stat
import subprocess
import sys
import tempfile
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit


DEFAULT_SANDBOX_EXEC = Path("/usr/bin/sandbox-exec")
DEFAULT_MAX_BUNDLE_FILES = 32
DEFAULT_MAX_FILE_BYTES = 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 4 * 1024 * 1024
CROSS_OBJECT_HTTP_CAPABILITY = "cross_object_http"
EXECUTABLE_UPLOAD_PAYLOAD_ENV = "SQUADRONE_EXEC_UPLOAD_PAYLOAD_B64"
EXECUTABLE_UPLOAD_ATTACK_FILENAME_ENV = (
    "SQUADRONE_EXEC_UPLOAD_ATTACK_FILENAME"
)
EXECUTABLE_UPLOAD_CONTROL_FILENAME_ENV = (
    "SQUADRONE_EXEC_UPLOAD_CONTROL_FILENAME"
)
_COPY_CHUNK_BYTES = 64 * 1024
_RUNNER_NAME = "_squadrone_poc_bootstrap.py"
_PROFILE_NAME = "seatbelt.sb"
_BUNDLE_MANIFEST_SCHEMA_VERSION = 1
_LOCALE_ENV_NAMES = ("LANG", "LC_ALL")
_SAFE_LOCALE_RE = re.compile(r"[A-Za-z0-9_.@-]{1,128}\Z")
_SYSTEM_READ_ROOTS = (
    "/System/Library",
    "/System/Volumes/Preboot/Cryptexes/OS/System/Library",
    "/System/Volumes/Preboot/Cryptexes/OS/usr/lib",
    "/usr/lib",
    "/usr/share/zoneinfo",
    "/Library/Apple/System/Library",
    "/private/var/db/timezone",
)
_SYSTEM_READ_FILES = (
    "/",
    "/dev/null",
    "/dev/random",
    "/dev/urandom",
    "/private/etc/hosts",
    "/private/etc/localtime",
)
_BOOTSTRAP_SOURCE = b'''"""Trusted launcher for one isolated generated PoC."""
import os
import runpy
import sys
from pathlib import Path
from urllib.parse import urlsplit

PROXY_ENV = "SQUADRONE_HTTP_PROXY"
PRIVATE_NAMES = {
    "SQUADRONE_HTTP_TRACE_FD",
    "SQUADRONE_HTTP_TRACE_ORIGIN",
    "SQUADRONE_HTTP_TRACE_SALT",
    "SQUADRONE_HTTP_TRACE_TOKEN",
}
PROXY_NAMES = (
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
    "http_proxy", "https_proxy", "all_proxy",
)
PRESERVED_NAMES = {
    PROXY_ENV,
    "SQUADRONE_EXEC_UPLOAD_PAYLOAD_B64",
    "SQUADRONE_EXEC_UPLOAD_ATTACK_FILENAME",
    "SQUADRONE_EXEC_UPLOAD_CONTROL_FILENAME",
    "HOME", "LANG", "LC_ALL", "PATH", "PYTHONDONTWRITEBYTECODE",
    "TEMP", "TMP", "TMPDIR", "XDG_CACHE_HOME", "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "SSL_CERT_DIR", "SSL_CERT_FILE", "VIRTUAL_ENV", "__PYVENV_LAUNCHER__",
}

for name in tuple(os.environ):
    if name not in PRESERVED_NAMES:
        os.environ.pop(name, None)
for name in PRIVATE_NAMES:
    os.environ.pop(name, None)
proxy_url = os.environ.pop(PROXY_ENV, "")
parsed = urlsplit(proxy_url)
try:
    proxy_port = parsed.port
except ValueError:
    proxy_port = None
if (
    parsed.scheme.casefold() != "http"
    or parsed.hostname not in {"127.0.0.1", "::1", "localhost"}
    or proxy_port is None
    or not 1 <= proxy_port <= 65535
    or parsed.username is not None
    or parsed.password is not None
    or parsed.path not in {"", "/"}
    or parsed.query
    or parsed.fragment
):
    raise RuntimeError("invalid isolated PoC proxy URL")
for name in ("NO_PROXY", "no_proxy"):
    os.environ.pop(name, None)
for name in PROXY_NAMES:
    os.environ[name] = proxy_url
if len(sys.argv) < 2:
    raise SystemExit("usage: bootstrap.py SCRIPT.py [ARG ...]")
script_path = Path(sys.argv[1])
bundle_path = Path(__file__).parent
if (
    not script_path.is_absolute()
    or script_path.parent != bundle_path
    or not script_path.is_file()
    or script_path.is_symlink()
):
    raise SystemExit("isolated PoC must be a regular file in the bundle")
sys.path.insert(0, str(script_path.parent))
sys.argv = [str(script_path), *sys.argv[2:]]
runpy.run_path(str(script_path), run_name="__main__")
'''


class PoCIsolationError(RuntimeError):
    """Base class for errors that must prevent a PoC from running."""


class PoCIsolationUnavailable(PoCIsolationError):
    """Raised when the required operating-system isolation is unavailable."""


class PoCBundleRejected(PoCIsolationError):
    """Raised when a generated program cannot be copied safely and boundedly."""


@dataclass(frozen=True, slots=True)
class PoCBundleManifestFile:
    """One content-addressed Python source in an isolated PoC bundle."""

    name: str
    role: Literal["entrypoint", "helper", "trusted_bootstrap"]
    size_bytes: int
    sha256: str

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "role": self.role,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
        }


@dataclass(frozen=True, slots=True)
class PoCBundleManifest:
    """Canonical identity of the exact isolated Python bundle to execute."""

    schema_version: int
    entrypoint: str
    files: tuple[PoCBundleManifestFile, ...]
    manifest_sha256: str
    source_file_count: int

    @property
    def script_sha256(self) -> str:
        """Return the main-script digest committed by this manifest."""
        for entry in self.files:
            if entry.role == "entrypoint":
                return entry.sha256
        raise PoCBundleRejected("isolated PoC manifest has no entrypoint")

    def canonical_bytes(self) -> bytes:
        """Return the bytes whose SHA-256 is ``manifest_sha256``."""
        return _canonical_bundle_manifest_bytes(
            schema_version=self.schema_version,
            entrypoint=self.entrypoint,
            files=self.files,
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "entrypoint": self.entrypoint,
            "files": [entry.as_dict() for entry in self.files],
            "manifest_sha256": self.manifest_sha256,
            "source_file_count": self.source_file_count,
        }


@dataclass(frozen=True, slots=True)
class PoCIsolationLaunch:
    """Prepared Seatbelt launch parameters valid for one context lifetime."""

    command_prefix: tuple[str, ...]
    cwd: Path
    script_path: Path
    runner_path: Path
    python_executable: Path
    profile_path: Path
    bundle_files: tuple[Path, ...]
    proxy_port: int
    capability: str = CROSS_OBJECT_HTTP_CAPABILITY
    max_files: int = DEFAULT_MAX_BUNDLE_FILES
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES

    def command(self, *arguments: str | os.PathLike[str]) -> tuple[str, ...]:
        """Return a complete argv without invoking a shell."""
        return (*self.command_prefix, *(os.fspath(argument) for argument in arguments))

    def python_command(self, *arguments: str | os.PathLike[str]) -> tuple[str, ...]:
        """Return isolated-mode argv for the one permitted Python runtime."""
        return self.command(self.python_executable, "-I", *arguments)

    def child_environment(self, proxy_url: str) -> dict[str, str]:
        """Return a minimal environment bound to this isolation's proxy."""
        normalized_proxy = _validated_proxy_url(
            proxy_url, expected_port=self.proxy_port
        )
        environment = {
            "SQUADRONE_HTTP_PROXY": normalized_proxy,
            "HOME": os.fspath(self.cwd),
            "TEMP": os.fspath(self.cwd),
            "TMP": os.fspath(self.cwd),
            "TMPDIR": os.fspath(self.cwd),
            "XDG_CACHE_HOME": os.fspath(self.cwd),
            "XDG_CONFIG_HOME": os.fspath(self.cwd),
            "XDG_DATA_HOME": os.fspath(self.cwd),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PATH": os.defpath,
        }
        for name in _LOCALE_ENV_NAMES:
            value = os.environ.get(name, "")
            if _SAFE_LOCALE_RE.fullmatch(value):
                environment[name] = value
        if sys.prefix != sys.base_prefix:
            environment["VIRTUAL_ENV"] = os.fspath(Path(sys.prefix).resolve())
            environment["__PYVENV_LAUNCHER__"] = os.fspath(
                _absolute_without_following(sys.executable)
            )
        verify_paths = ssl.get_default_verify_paths()
        if verify_paths.cafile and Path(verify_paths.cafile).is_file():
            environment["SSL_CERT_FILE"] = verify_paths.cafile
        if verify_paths.capath and Path(verify_paths.capath).is_dir():
            environment["SSL_CERT_DIR"] = verify_paths.capath
        return environment

    def attest_bundle(self) -> PoCBundleManifest:
        """Read and identify every Python source in this prepared bundle."""
        return attest_poc_isolation_bundle(self)


def seatbelt_unavailability_reason(
    sandbox_exec: str | os.PathLike[str] = DEFAULT_SANDBOX_EXEC,
) -> str | None:
    """Return why Seatbelt cannot be used, or ``None`` when it is launchable."""
    if sys.platform != "darwin":
        return f"macOS Seatbelt is required (current platform: {sys.platform})"
    executable = Path(sandbox_exec)
    try:
        metadata = executable.stat()
    except OSError as exc:
        return f"macOS Seatbelt launcher is unavailable: {exc}"
    if not stat.S_ISREG(metadata.st_mode) or not os.access(executable, os.X_OK):
        return f"macOS Seatbelt launcher is not an executable file: {executable}"
    return None


def require_seatbelt(
    sandbox_exec: str | os.PathLike[str] = DEFAULT_SANDBOX_EXEC,
) -> Path:
    """Return the resolved launcher path, raising instead of falling back."""
    reason = seatbelt_unavailability_reason(sandbox_exec)
    if reason is not None:
        raise PoCIsolationUnavailable(reason)
    return Path(sandbox_exec).resolve(strict=True)


def _current_python_runtime() -> Path:
    """Resolve the actual current interpreter without its spawning shim."""
    base_executable = Path(
        getattr(sys, "_base_executable", None) or sys.executable
    ).resolve(strict=True)
    framework_root = base_executable.parent.parent
    app_runtime = (
        framework_root / "Resources" / "Python.app" / "Contents" / "MacOS" / "Python"
    )
    runtime = app_runtime if app_runtime.is_file() else base_executable
    try:
        metadata = runtime.stat()
    except OSError as exc:
        raise PoCIsolationUnavailable(
            f"current Python runtime is unavailable: {exc}"
        ) from exc
    if not stat.S_ISREG(metadata.st_mode) or not os.access(runtime, os.X_OK):
        raise PoCIsolationUnavailable(
            f"current Python runtime is not executable: {runtime}"
        )
    return runtime.resolve(strict=True)


def _validated_proxy_url(proxy_url: str, *, expected_port: int) -> str:
    try:
        parsed = urlsplit(proxy_url)
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise ValueError("PoC proxy URL is invalid") from exc
    if (
        parsed.scheme.casefold() != "http"
        or parsed.hostname not in {"127.0.0.1", "::1", "localhost"}
        or port != expected_port
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("PoC proxy URL must match the isolated loopback proxy port")
    hostname = str(parsed.hostname)
    rendered_host = f"[{hostname}]" if ":" in hostname else hostname
    return f"http://{rendered_host}:{port}"


def _runtime_dependency_files(runtime_roots: Iterable[Path]) -> tuple[Path, ...]:
    """Discover non-Python dylibs needed by this runtime's extension modules."""
    otool = Path("/usr/bin/otool")
    if not otool.is_file():
        raise PoCIsolationUnavailable(
            "cannot discover current Python runtime dependencies: /usr/bin/otool is unavailable"
        )
    candidates: list[Path] = []
    for root in runtime_roots:
        if root.is_file() and root.suffix in {"", ".dylib", ".so"}:
            candidates.append(root)
            continue
        if not root.is_dir():
            continue
        candidates.extend(path for path in root.rglob("*.so") if path.is_file())
    # A compromised or malformed runtime must not turn dependency discovery
    # into an unbounded filesystem walk or argv.
    candidates = list(dict.fromkeys(candidates))
    if len(candidates) > 1024:
        raise PoCIsolationUnavailable(
            "current Python runtime has too many extension modules to isolate safely"
        )

    dependencies: list[Path] = []
    for start in range(0, len(candidates), 128):
        command = [os.fspath(otool), "-L"]
        command.extend(os.fspath(path) for path in candidates[start : start + 128])
        try:
            result = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise PoCIsolationUnavailable(
                f"cannot discover current Python runtime dependencies: {exc}"
            ) from exc
        if result.returncode != 0:
            raise PoCIsolationUnavailable(
                "cannot discover current Python runtime dependencies with otool"
            )
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if not stripped.startswith("/"):
                continue
            dependency = Path(stripped.split(" (compatibility version", 1)[0])
            if dependency.is_file():
                dependencies.extend(_path_spellings(dependency))
    return tuple(dict.fromkeys(dependencies))


def _validate_positive_bound(name: str, value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _validate_proxy_port(proxy_port: int) -> int:
    if (
        not isinstance(proxy_port, int)
        or isinstance(proxy_port, bool)
        or not 1 <= proxy_port <= 65535
    ):
        raise ValueError("proxy_port must be an integer from 1 through 65535")
    return proxy_port


def _absolute_without_following(path: str | os.PathLike[str]) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _python_sources(script_path: Path) -> tuple[Path, ...]:
    if script_path.suffix.casefold() != ".py":
        raise PoCBundleRejected("the generated PoC must be a Python source file")
    try:
        entries = tuple(os.scandir(script_path.parent))
    except OSError as exc:
        raise PoCBundleRejected(
            f"cannot inspect the PoC source directory: {exc}"
        ) from exc

    sources: list[Path] = []
    for entry in entries:
        if Path(entry.name).suffix.casefold() != ".py":
            continue
        source = script_path.parent / entry.name
        try:
            metadata = entry.stat(follow_symlinks=False)
        except OSError as exc:
            raise PoCBundleRejected(
                f"cannot inspect Python helper {entry.name!r}: {exc}"
            ) from exc
        if entry.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise PoCBundleRejected(
                f"Python helper must be a regular non-symlink file: {entry.name!r}"
            )
        sources.append(source)

    if script_path not in sources:
        raise PoCBundleRejected("the generated PoC is not a regular directory entry")
    return tuple(sorted(sources, key=lambda path: path.name))


def _read_regular_bounded(path: Path, max_bytes: int) -> bytes:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise PoCBundleRejected(
            f"cannot safely open Python source {path.name!r}: {exc}"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise PoCBundleRejected(
                f"Python source must remain a regular file: {path.name!r}"
            )
        if metadata.st_size > max_bytes:
            raise PoCBundleRejected(
                f"Python source exceeds the {max_bytes}-byte per-file limit: {path.name!r}"
            )
        chunks: list[bytes] = []
        consumed = 0
        while True:
            chunk = os.read(
                descriptor, min(_COPY_CHUNK_BYTES, max_bytes + 1 - consumed)
            )
            if not chunk:
                break
            chunks.append(chunk)
            consumed += len(chunk)
            if consumed > max_bytes:
                raise PoCBundleRejected(
                    f"Python source exceeds the {max_bytes}-byte per-file limit: {path.name!r}"
                )
        return b"".join(chunks)
    except OSError as exc:
        raise PoCBundleRejected(
            f"cannot read Python source {path.name!r}: {exc}"
        ) from exc
    finally:
        os.close(descriptor)


def _load_bounded_bundle(
    script_path: str | os.PathLike[str],
    *,
    max_files: int,
    max_file_bytes: int,
    max_total_bytes: int,
) -> tuple[Path, tuple[tuple[str, bytes], ...]]:
    source_script = _absolute_without_following(script_path)
    sources = _python_sources(source_script)
    if len(sources) > max_files:
        raise PoCBundleRejected(
            f"PoC bundle has {len(sources)} Python files; limit is {max_files}"
        )

    loaded: list[tuple[str, bytes]] = []
    total = 0
    for source in sources:
        content = _read_regular_bounded(source, max_file_bytes)
        total += len(content)
        if total > max_total_bytes:
            raise PoCBundleRejected(
                f"PoC bundle exceeds the {max_total_bytes}-byte total limit"
            )
        loaded.append((source.name, content))
    return source_script, tuple(loaded)


def _canonical_bundle_manifest_bytes(
    *,
    schema_version: int,
    entrypoint: str,
    files: tuple[PoCBundleManifestFile, ...],
) -> bytes:
    payload = {
        "schema_version": schema_version,
        "entrypoint": entrypoint,
        "files": [entry.as_dict() for entry in files],
    }
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def attest_poc_isolation_bundle(
    launch: PoCIsolationLaunch,
) -> PoCBundleManifest:
    """Content-address the exact copied Python sources before child launch.

    The source directory is no longer authoritative once isolation preparation
    starts.  This function opens the copied main script, every copied helper,
    and the trusted bootstrap without following symlinks, then commits their
    names, roles, lengths, and bytes to one canonical manifest.  Callers should
    invoke it immediately before starting the isolated process.
    """
    if type(launch) is not PoCIsolationLaunch:
        raise PoCBundleRejected("invalid prepared PoC isolation handle")
    file_limit = _validate_positive_bound("max_files", launch.max_files)
    per_file_limit = _validate_positive_bound("max_file_bytes", launch.max_file_bytes)
    total_limit = _validate_positive_bound("max_total_bytes", launch.max_total_bytes)
    bundle_dir = _absolute_without_following(launch.cwd)
    try:
        bundle_metadata = bundle_dir.lstat()
    except OSError as exc:
        raise PoCBundleRejected(f"cannot inspect isolated PoC bundle: {exc}") from exc
    if (
        not stat.S_ISDIR(bundle_metadata.st_mode)
        or stat.S_ISLNK(bundle_metadata.st_mode)
        or not launch.cwd.is_absolute()
        or launch.cwd != bundle_dir
    ):
        raise PoCBundleRejected("isolated PoC bundle is not a stable directory")

    source_paths = tuple(launch.bundle_files)
    if not 1 <= len(source_paths) <= file_limit:
        raise PoCBundleRejected("isolated PoC source inventory is out of bounds")
    if any(
        not path.is_absolute()
        or path.parent != bundle_dir
        or path.name != os.path.basename(path.name)
        or path.suffix.casefold() != ".py"
        or path.name == _RUNNER_NAME
        for path in source_paths
    ):
        raise PoCBundleRejected("isolated PoC source inventory escaped its bundle")
    source_names = tuple(path.name for path in source_paths)
    if len(set(source_names)) != len(source_names):
        raise PoCBundleRejected("isolated PoC source inventory is ambiguous")

    script_path = launch.script_path
    runner_path = launch.runner_path
    if (
        not script_path.is_absolute()
        or script_path.parent != bundle_dir
        or script_path not in source_paths
        or not runner_path.is_absolute()
        or runner_path != bundle_dir / _RUNNER_NAME
    ):
        raise PoCBundleRejected("isolated PoC entrypoint or bootstrap is invalid")

    try:
        python_entries = tuple(
            entry
            for entry in os.scandir(bundle_dir)
            if Path(entry.name).suffix.casefold() == ".py"
        )
    except OSError as exc:
        raise PoCBundleRejected(
            f"cannot inspect isolated PoC Python inventory: {exc}"
        ) from exc
    expected_python_names = {*source_names, _RUNNER_NAME}
    if {entry.name for entry in python_entries} != expected_python_names:
        raise PoCBundleRejected("isolated PoC Python inventory changed")
    for entry in python_entries:
        try:
            metadata = entry.stat(follow_symlinks=False)
        except OSError as exc:
            raise PoCBundleRejected(
                f"cannot inspect isolated Python source {entry.name!r}: {exc}"
            ) from exc
        if entry.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise PoCBundleRejected(
                f"isolated Python source is not a regular file: {entry.name!r}"
            )

    entries: list[PoCBundleManifestFile] = []
    source_total = 0
    for path in (*source_paths, runner_path):
        content = _read_regular_bounded(path, per_file_limit)
        if path == runner_path:
            if content != _BOOTSTRAP_SOURCE:
                raise PoCBundleRejected("isolated PoC bootstrap identity changed")
            role: Literal["entrypoint", "helper", "trusted_bootstrap"] = (
                "trusted_bootstrap"
            )
        else:
            source_total += len(content)
            if source_total > total_limit:
                raise PoCBundleRejected(
                    f"isolated PoC bundle exceeds the {total_limit}-byte total limit"
                )
            role = "entrypoint" if path == script_path else "helper"
        entries.append(
            PoCBundleManifestFile(
                name=path.name,
                role=role,
                size_bytes=len(content),
                sha256=hashlib.sha256(content).hexdigest(),
            )
        )
    ordered = tuple(sorted(entries, key=lambda entry: entry.name))
    if sum(entry.role == "entrypoint" for entry in ordered) != 1:
        raise PoCBundleRejected("isolated PoC manifest entrypoint is ambiguous")
    canonical = _canonical_bundle_manifest_bytes(
        schema_version=_BUNDLE_MANIFEST_SCHEMA_VERSION,
        entrypoint=script_path.name,
        files=ordered,
    )
    return PoCBundleManifest(
        schema_version=_BUNDLE_MANIFEST_SCHEMA_VERSION,
        entrypoint=script_path.name,
        files=ordered,
        manifest_sha256=hashlib.sha256(canonical).hexdigest(),
        source_file_count=len(source_paths),
    )


def _seatbelt_string(value: str) -> str:
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError("Seatbelt paths cannot contain control characters")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _path_spellings(path: str | os.PathLike[str]) -> tuple[Path, ...]:
    absolute = _absolute_without_following(path)
    resolved = absolute.resolve(strict=False)
    return tuple(dict.fromkeys((absolute, resolved)))


def _existing_read_paths(
    paths: Iterable[str | os.PathLike[str]],
    *,
    required: bool,
) -> tuple[Path, ...]:
    entries: list[Path] = []
    for supplied in paths:
        spellings = _path_spellings(supplied)
        if required and not any(path.exists() for path in spellings):
            raise PoCIsolationUnavailable(
                f"required PoC runtime read path is unavailable: {supplied}"
            )
        entries.extend(path for path in spellings if path.exists())
    return tuple(dict.fromkeys(entries))


def _automatic_runtime_read_paths(python_runtime: Path) -> tuple[Path, ...]:
    roots = _existing_read_paths(
        (sys.prefix, sys.base_prefix, python_runtime),
        required=True,
    )
    system_paths = _existing_read_paths(
        (*_SYSTEM_READ_ROOTS, *_SYSTEM_READ_FILES),
        required=False,
    )
    verify_paths = ssl.get_default_verify_paths()
    certificates = _existing_read_paths(
        tuple(
            path
            for path in (verify_paths.cafile, verify_paths.capath)
            if path is not None
        ),
        required=False,
    )
    dependencies = _runtime_dependency_files(roots)
    return tuple(dict.fromkeys((*roots, *system_paths, *certificates, *dependencies)))


def _file_read_rules(paths: Iterable[Path]) -> list[str]:
    rules: list[str] = []
    for path in paths:
        quoted_path = _seatbelt_string(os.fspath(path))
        rules.append(f"(allow file-read* (literal {quoted_path}))")
        if path.is_dir() and path != Path("/"):
            rules.append(f"(allow file-read* (subpath {quoted_path}))")
    return rules


def render_seatbelt_profile(
    *,
    writable_root: str | os.PathLike[str],
    proxy_port: int,
    protected_paths: Iterable[str | os.PathLike[str]],
    python_executable: str | os.PathLike[str] | None = None,
    runtime_read_roots: Iterable[str | os.PathLike[str]] = (),
) -> str:
    """Render a default-deny profile for one bundle and one proxy port."""
    port = _validate_proxy_port(proxy_port)
    writable = Path(writable_root).resolve(strict=True)
    if not writable.is_dir():
        raise ValueError("writable_root must be an existing directory")
    python_runtime = (
        _current_python_runtime()
        if python_executable is None
        else Path(python_executable).resolve(strict=True)
    )
    runtime_paths = _automatic_runtime_read_paths(python_runtime)
    explicit_paths = _existing_read_paths(runtime_read_roots, required=True)
    readable_paths = tuple(
        dict.fromkeys((*_path_spellings(writable), *runtime_paths, *explicit_paths))
    )

    protected: list[Path] = []
    for supplied_path in protected_paths:
        protected.extend(_path_spellings(supplied_path))
    protected = list(dict.fromkeys(protected))

    quoted_writable = _seatbelt_string(os.fspath(writable))
    lines = [
        "(version 1)",
        "(deny default)",
        "(deny process-fork)",
        "(deny process-info*)",
        *_file_read_rules(readable_paths),
        f"(allow process-exec (literal {_seatbelt_string(os.fspath(python_runtime))}))",
        f"(allow file-write* (literal {quoted_writable}))",
        f"(allow file-write* (subpath {quoted_writable}))",
        f'(allow network-outbound (remote tcp "localhost:{port}"))',
    ]
    for path in protected:
        quoted_path = _seatbelt_string(os.fspath(path))
        lines.append(f"(deny file-read* (literal {quoted_path}))")
        lines.append(f"(deny file-read* (subpath {quoted_path}))")
    return "\n".join(lines) + "\n"


@contextlib.contextmanager
def prepare_poc_isolation(
    script_path: str | os.PathLike[str],
    *,
    proxy_port: int,
    protected_paths: Iterable[str | os.PathLike[str]],
    sandbox_exec: str | os.PathLike[str] = DEFAULT_SANDBOX_EXEC,
    temp_parent: str | os.PathLike[str] | None = None,
    runtime_read_roots: Iterable[str | os.PathLike[str]] = (),
    capability: str = CROSS_OBJECT_HTTP_CAPABILITY,
    max_files: int = DEFAULT_MAX_BUNDLE_FILES,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
) -> Iterator[PoCIsolationLaunch]:
    """Prepare a bounded PoC bundle and yield fail-closed launch parameters.

    ``protected_paths`` should include the WordPress sandbox work directory and
    every host-side credential file that the parent knows about.  The caller
    must keep this context open until the subprocess and all descendants have
    exited.  This strict capability intentionally excludes browser processes
    and inbound callback listeners; those need separate explicit profiles.
    """
    if capability != CROSS_OBJECT_HTTP_CAPABILITY:
        raise PoCIsolationUnavailable(
            "the strict PoC profile supports only requests-based cross-object "
            "HTTP; browser and callback/listener capabilities require separate "
            "explicit isolation profiles"
        )
    port = _validate_proxy_port(proxy_port)
    file_limit = _validate_positive_bound("max_files", max_files)
    per_file_limit = _validate_positive_bound("max_file_bytes", max_file_bytes)
    total_limit = _validate_positive_bound("max_total_bytes", max_total_bytes)
    source_script, loaded = _load_bounded_bundle(
        script_path,
        max_files=file_limit,
        max_file_bytes=per_file_limit,
        max_total_bytes=total_limit,
    )
    if any(name == _RUNNER_NAME for name, _content in loaded):
        raise PoCBundleRejected(f"PoC bundle uses reserved filename: {_RUNNER_NAME}")
    launcher = require_seatbelt(sandbox_exec)
    python_runtime = _current_python_runtime()

    with tempfile.TemporaryDirectory(
        prefix="squadrone-poc-", dir=temp_parent
    ) as raw_dir:
        bundle_dir = Path(raw_dir).resolve(strict=True)
        copied_files: list[Path] = []
        for name, content in loaded:
            destination = bundle_dir / name
            with destination.open("xb") as output:
                output.write(content)
            destination.chmod(0o600)
            copied_files.append(destination)

        isolated_script = bundle_dir / source_script.name
        if isolated_script not in copied_files:
            raise PoCBundleRejected("the generated PoC was not copied into its bundle")

        runner_path = bundle_dir / _RUNNER_NAME
        with runner_path.open("xb") as output:
            output.write(_BOOTSTRAP_SOURCE)
        runner_path.chmod(0o500)

        profile = render_seatbelt_profile(
            writable_root=bundle_dir,
            proxy_port=port,
            protected_paths=(
                *protected_paths,
                *(source_script.parent / name for name, _content in loaded),
            ),
            python_executable=python_runtime,
            runtime_read_roots=runtime_read_roots,
        )
        profile_path = bundle_dir / _PROFILE_NAME
        with profile_path.open("x", encoding="utf-8") as output:
            output.write(profile)
        profile_path.chmod(0o600)

        yield PoCIsolationLaunch(
            command_prefix=(os.fspath(launcher), "-f", os.fspath(profile_path)),
            cwd=bundle_dir,
            script_path=isolated_script,
            runner_path=runner_path,
            python_executable=python_runtime,
            profile_path=profile_path,
            bundle_files=tuple(copied_files),
            proxy_port=port,
            capability=capability,
            max_files=file_limit,
            max_file_bytes=per_file_limit,
            max_total_bytes=total_limit,
        )
