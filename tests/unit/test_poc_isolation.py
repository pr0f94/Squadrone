from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from squadrone.poc_isolation import (
    CROSS_OBJECT_HTTP_CAPABILITY,
    DEFAULT_SANDBOX_EXEC,
    PoCBundleRejected,
    PoCIsolationLaunch,
    PoCIsolationUnavailable,
    prepare_poc_isolation,
    require_seatbelt,
    seatbelt_unavailability_reason,
)


_PROBE = """\
import errno
import os
import pathlib
import socket
import subprocess
import sys

operation = sys.argv[1]
target = sys.argv[2]
try:
    if operation == "connect":
        connection = socket.create_connection(("127.0.0.1", int(target)), 1)
        connection.close()
    elif operation == "connect-unix":
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.connect(target)
        connection.close()
    elif operation == "read":
        pathlib.Path(target).read_bytes()
    elif operation == "write":
        pathlib.Path(target).write_text("written", encoding="utf-8")
    elif operation == "fork":
        child = os.fork()
        if child == 0:
            os._exit(0)
        os.waitpid(child, 0)
        raise SystemExit(91)
    elif operation == "spawn":
        subprocess.run([target, "-I", "-c", "print('spawned')"], check=True)
        raise SystemExit(92)
    elif operation == "inspect-parent":
        import ctypes
        libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        buffer = ctypes.create_string_buffer(4096)
        if libproc.proc_pidpath(os.getppid(), buffer, len(buffer)) > 0:
            raise SystemExit(93)
        raise OSError(ctypes.get_errno(), "process inspection denied")
    elif operation == "requests":
        import requests
        response = requests.get(target, timeout=2)
        if response.status_code != 204:
            raise SystemExit(94)
    elif operation == "runtime":
        if pathlib.Path(sys.executable) != pathlib.Path(target) or not sys.flags.isolated:
            raise SystemExit(95)
    else:
        raise RuntimeError(f"unknown operation: {operation}")
except OSError as exc:
    if exc.errno in {errno.EPERM, errno.EACCES}:
        print("seatbelt-denied")
        raise SystemExit(23)
    raise
print("allowed")
"""


def _make_probe(tmp_path: Path) -> Path:
    script = tmp_path / "probe.py"
    script.write_text(_PROBE, encoding="utf-8")
    return script


def _seatbelt_is_available() -> bool:
    return seatbelt_unavailability_reason() is None


requires_seatbelt = pytest.mark.skipif(
    not _seatbelt_is_available(),
    reason="macOS sandbox-exec is unavailable",
)


def _run_probe(
    launch: PoCIsolationLaunch,
    operation: str,
    target: str | os.PathLike[str],
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        launch.python_command(
            launch.runner_path,
            launch.script_path,
            operation,
            target,
        ),
        cwd=launch.cwd,
        env=launch.child_environment(f"http://127.0.0.1:{launch.proxy_port}"),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


def test_seatbelt_requirement_fails_closed_off_macos(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    with pytest.raises(PoCIsolationUnavailable, match="macOS Seatbelt is required"):
        require_seatbelt()


def test_bundle_copies_main_and_regular_python_helpers(tmp_path: Path) -> None:
    script = _make_probe(tmp_path)
    helper = tmp_path / "helper.py"
    helper.write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "ignored.txt").write_text("not copied", encoding="utf-8")

    if not _seatbelt_is_available():
        pytest.skip("macOS sandbox-exec is unavailable")
    with prepare_poc_isolation(
        script,
        proxy_port=54321,
        protected_paths=[tmp_path],
    ) as launch:
        assert {path.name for path in launch.bundle_files} == {"helper.py", "probe.py"}
        assert launch.script_path.read_text(encoding="utf-8") == _PROBE
        assert not (launch.cwd / "ignored.txt").exists()
        assert launch.command_prefix == (
            os.fspath(DEFAULT_SANDBOX_EXEC),
            "-f",
            os.fspath(launch.profile_path),
        )
        profile = launch.profile_path.read_text(encoding="utf-8")
        assert "(allow file-read*)" not in profile
        assert "(allow process*)" not in profile
        assert "(deny process-fork)" in profile
        assert launch.python_command(launch.runner_path)[-2:] == (
            "-I",
            os.fspath(launch.runner_path),
        )
        assert launch.capability == CROSS_OBJECT_HTTP_CAPABILITY
        child_environment = launch.child_environment("http://127.0.0.1:54321")
        assert child_environment["HOME"] == os.fspath(launch.cwd)
        assert child_environment["XDG_CONFIG_HOME"] == os.fspath(launch.cwd)
        assert "PYTHONPATH" not in child_environment
        with pytest.raises(ValueError, match="must match"):
            launch.child_environment("http://127.0.0.1:54322")


@pytest.mark.parametrize("bad_helper_kind", ["symlink", "directory"])
def test_bundle_rejects_nonregular_python_helpers(
    tmp_path: Path,
    bad_helper_kind: str,
) -> None:
    script = _make_probe(tmp_path)
    helper = tmp_path / "unsafe.py"
    if bad_helper_kind == "symlink":
        helper.symlink_to(script)
    else:
        helper.mkdir()

    with pytest.raises(PoCBundleRejected, match="regular non-symlink"):
        with prepare_poc_isolation(
            script,
            proxy_port=54321,
            protected_paths=[tmp_path],
        ):
            pass


def test_bundle_enforces_file_count_and_byte_bounds(tmp_path: Path) -> None:
    script = _make_probe(tmp_path)
    (tmp_path / "one.py").write_text("1", encoding="utf-8")
    (tmp_path / "two.py").write_text("2", encoding="utf-8")

    with pytest.raises(PoCBundleRejected, match="3 Python files; limit is 2"):
        with prepare_poc_isolation(
            script,
            proxy_port=54321,
            protected_paths=[tmp_path],
            max_files=2,
        ):
            pass

    (tmp_path / "one.py").unlink()
    (tmp_path / "two.py").unlink()
    with pytest.raises(PoCBundleRejected, match="per-file limit"):
        with prepare_poc_isolation(
            script,
            proxy_port=54321,
            protected_paths=[tmp_path],
            max_file_bytes=8,
        ):
            pass

    helper = tmp_path / "helper.py"
    helper.write_text("abcdefgh", encoding="utf-8")
    with pytest.raises(PoCBundleRejected, match="total limit"):
        with prepare_poc_isolation(
            script,
            proxy_port=54321,
            protected_paths=[tmp_path],
            max_file_bytes=len(_PROBE.encode()) + 1,
            max_total_bytes=len(_PROBE.encode()) + 4,
        ):
            pass


@requires_seatbelt
def test_seatbelt_allows_only_the_proxy_loopback_port(tmp_path: Path) -> None:
    script = _make_probe(tmp_path)
    with socket.socket() as proxy_listener, socket.socket() as other_listener:
        proxy_listener.bind(("127.0.0.1", 0))
        proxy_listener.listen()
        other_listener.bind(("127.0.0.1", 0))
        other_listener.listen()
        proxy_port = proxy_listener.getsockname()[1]
        other_port = other_listener.getsockname()[1]

        with prepare_poc_isolation(
            script,
            proxy_port=proxy_port,
            protected_paths=[tmp_path],
        ) as launch:
            allowed = _run_probe(launch, "connect", str(proxy_port))
            denied = _run_probe(launch, "connect", str(other_port))

    assert allowed.returncode == 0, allowed.stderr
    assert allowed.stdout.strip() == "allowed"
    assert denied.returncode == 23, denied.stderr
    assert denied.stdout.strip() == "seatbelt-denied"


@requires_seatbelt
def test_seatbelt_denies_unix_socket_connections(tmp_path: Path) -> None:
    script = _make_probe(tmp_path)

    with prepare_poc_isolation(
        script,
        proxy_port=54321,
        protected_paths=[tmp_path],
    ) as launch:
        socket_path = launch.cwd / "docker.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(os.fspath(socket_path))
            listener.listen()
            denied = _run_probe(launch, "connect-unix", socket_path)

    assert denied.returncode == 23, denied.stderr
    assert denied.stdout.strip() == "seatbelt-denied"


@requires_seatbelt
def test_seatbelt_denies_reads_of_protected_paths(tmp_path: Path) -> None:
    script = _make_probe(tmp_path)
    protected = tmp_path / "secret.txt"
    protected.write_text("do-not-read", encoding="utf-8")

    with prepare_poc_isolation(
        script,
        proxy_port=54321,
        protected_paths=[protected],
    ) as launch:
        result = _run_probe(launch, "read", protected)

    assert result.returncode == 23, result.stderr
    assert result.stdout.strip() == "seatbelt-denied"


@requires_seatbelt
def test_seatbelt_denies_unlisted_workspace_credentials(tmp_path: Path) -> None:
    script = _make_probe(tmp_path)
    credential = tmp_path / ".env"
    credential.write_text("API_KEY=must-not-leak", encoding="utf-8")

    with prepare_poc_isolation(
        script,
        proxy_port=54321,
        protected_paths=[],
    ) as launch:
        result = _run_probe(launch, "read", credential)

    assert result.returncode == 23, result.stderr
    assert result.stdout.strip() == "seatbelt-denied"


@requires_seatbelt
def test_seatbelt_allows_an_explicit_bounded_read_root(tmp_path: Path) -> None:
    script = _make_probe(tmp_path)
    readable_root = tmp_path / "public-fixture"
    readable_root.mkdir()
    fixture = readable_root / "value.txt"
    fixture.write_text("benign", encoding="utf-8")

    with prepare_poc_isolation(
        script,
        proxy_port=54321,
        protected_paths=[],
        runtime_read_roots=[readable_root],
    ) as launch:
        result = _run_probe(launch, "read", fixture)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "allowed"


@requires_seatbelt
@pytest.mark.parametrize("operation", ["fork", "spawn"])
def test_seatbelt_denies_child_processes(
    tmp_path: Path,
    operation: str,
) -> None:
    script = _make_probe(tmp_path)

    with prepare_poc_isolation(
        script,
        proxy_port=54321,
        protected_paths=[],
    ) as launch:
        target = launch.python_executable if operation == "spawn" else "unused"
        result = _run_probe(launch, operation, target)

    assert result.returncode == 23, result.stderr
    assert result.stdout.strip() == "seatbelt-denied"


@requires_seatbelt
def test_seatbelt_denies_parent_process_inspection(tmp_path: Path) -> None:
    script = _make_probe(tmp_path)

    with prepare_poc_isolation(
        script,
        proxy_port=54321,
        protected_paths=[],
    ) as launch:
        result = _run_probe(launch, "inspect-parent", "unused")

    assert result.returncode == 23, result.stderr
    assert result.stdout.strip() == "seatbelt-denied"


@requires_seatbelt
def test_runner_uses_the_exact_current_runtime_in_isolated_mode(
    tmp_path: Path,
) -> None:
    script = _make_probe(tmp_path)

    with prepare_poc_isolation(
        script,
        proxy_port=54321,
        protected_paths=[],
    ) as launch:
        result = _run_probe(launch, "runtime", os.path.abspath(sys.executable))

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "allowed"


@requires_seatbelt
def test_requests_runs_through_the_only_allowed_proxy(tmp_path: Path) -> None:
    script = _make_probe(tmp_path)
    received = bytearray()

    with socket.socket() as proxy_listener:
        proxy_listener.bind(("127.0.0.1", 0))
        proxy_listener.listen()
        proxy_port = proxy_listener.getsockname()[1]

        def serve_one_request() -> None:
            connection, _address = proxy_listener.accept()
            with connection:
                while b"\r\n\r\n" not in received:
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    received.extend(chunk)
                connection.sendall(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )

        server = threading.Thread(target=serve_one_request, daemon=True)
        server.start()
        with prepare_poc_isolation(
            script,
            proxy_port=proxy_port,
            protected_paths=[],
        ) as launch:
            result = _run_probe(
                launch,
                "requests",
                "http://192.0.2.123/proxy-proof",
            )
        server.join(timeout=2)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "allowed"
    assert received.startswith(b"GET http://192.0.2.123/proxy-proof HTTP/1.1\r\n")


def test_non_http_capabilities_fail_closed(tmp_path: Path) -> None:
    script = _make_probe(tmp_path)
    with pytest.raises(PoCIsolationUnavailable, match="browser and callback"):
        with prepare_poc_isolation(
            script,
            proxy_port=54321,
            protected_paths=[],
            capability="browser_execution",
        ):
            pass


@requires_seatbelt
def test_seatbelt_allows_writes_only_inside_bundle(tmp_path: Path) -> None:
    script = _make_probe(tmp_path)
    outside = tmp_path / "outside.txt"

    with prepare_poc_isolation(
        script,
        proxy_port=54321,
        protected_paths=[tmp_path],
    ) as launch:
        inside = launch.cwd / "inside.txt"
        outside_result = _run_probe(launch, "write", outside)
        inside_result = _run_probe(launch, "write", inside)
        assert inside.read_text(encoding="utf-8") == "written"

    assert outside_result.returncode == 23, outside_result.stderr
    assert outside_result.stdout.strip() == "seatbelt-denied"
    assert not outside.exists()
    assert inside_result.returncode == 0, inside_result.stderr
    assert inside_result.stdout.strip() == "allowed"
