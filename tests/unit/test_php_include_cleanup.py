from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

import squadrone.services.sandbox as sandbox_module
from squadrone.schemas import SandboxConfig
from squadrone.services.php_include_oracle import (
    PhpIncludeHostFilesystemMeasurement,
    PhpIncludeOracle,
)
from squadrone.services.sandbox import POC_RESULT_PREFIX, SandboxManager


def _manager(tmp_path: Path) -> tuple[SandboxManager, PhpIncludeOracle, Path]:
    manager = SandboxManager(
        SandboxConfig(
            wordpress_image="wordpress:latest",
            db_image="mariadb:10.11",
            wp_admin_user="admin",
            wp_admin_pass="password",
            wp_admin_email="admin@example.test",
            wp_url="http://localhost:8080",
        ),
        php_include_oracle_enabled=True,
    )
    host_directory = tmp_path / "php-include"
    host_directory.mkdir(mode=0o755)
    oracle = PhpIncludeOracle()
    manager._booted = True
    manager.workdir = tmp_path
    manager.container_name = "test-project-wordpress-1"
    manager.target_url = "http://localhost:8123"
    manager._php_include_host_dir = host_directory
    manager._php_include_oracle = oracle
    return manager, oracle, host_directory


def _measurement(
    host_directory: Path,
    attack_path: str,
    control_path: str,
) -> dict[str, object]:
    attack = sandbox_module._php_include_host_path(host_directory, attack_path)
    control = sandbox_module._php_include_host_path(host_directory, control_path)
    metadata = attack.lstat()
    return {
        "attack_resource_path": attack_path,
        "control_resource_path": control_path,
        "attack_content_sha256": hashlib.sha256(attack.read_bytes()).hexdigest(),
        "attack_content_size_bytes": metadata.st_size,
        # The production inspection is container-side, where the trusted bind
        # is required to present this verifier file as root-owned.
        "attack_owner_uid": 0,
        "attack_owner_gid": 0,
        "attack_file_mode": stat.S_IMODE(metadata.st_mode),
        "attack_link_count": metadata.st_nlink,
        "attack_is_regular_file": attack.is_file(),
        "attack_is_symlink": attack.is_symlink(),
        "control_lstat_exists": control.exists() or control.is_symlink(),
    }


def _inspection_payload(attack_path: str, control_path: str) -> bytes:
    return json.dumps(
        {
            "attack_resource_path": attack_path,
            "control_resource_path": control_path,
            "attack_content_sha256": "a" * 64,
            "attack_content_size_bytes": 128,
            "attack_owner_uid": 0,
            "attack_owner_gid": 0,
            "attack_file_mode": 0o444,
            "attack_link_count": 1,
            "attack_is_regular_file": True,
            "attack_is_symlink": False,
            "control_lstat_exists": False,
        },
        separators=(",", ":"),
    ).encode("ascii")


def _install_completed_php_include_child(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    observation = {
        "verdict": "vulnerable",
        "oracle": "response_marker",
        "attacker_role": "unauthenticated",
        "request": {"method": "POST", "url": "http://localhost:8123/proof"},
        "attack": {
            "observed": True,
            "marker": "SQUADRONE_PHP_INCLUDE_" + "a" * 64,
            "marker_present": True,
        },
        "control": {"observed": False, "marker_present": False},
        "impact": {
            "confidentiality": "low",
            "integrity": "none",
            "availability": "none",
            "description": "A trusted canary was observed.",
        },
    }
    stdout = (
        POC_RESULT_PREFIX + json.dumps(observation, separators=(",", ":")) + "\n"
    ).encode()

    class Process:
        pid = 999_999
        returncode = 0

        async def wait(self) -> int:
            return self.returncode

    class Isolation:
        cwd = tmp_path
        runner_path = tmp_path / "runner.py"
        script_path = tmp_path / "poc.py"

        def python_command(self, *_paths: Path) -> tuple[str, ...]:
            return ("python", "poc.py")

        def child_environment(self, _proxy_url: str) -> dict[str, str]:
            return {}

    class Proxy:
        proxy_url = "http://127.0.0.1:43123"
        records: list[dict[str, object]] = []
        trace_salt = b"s" * 32
        fatal_error = None
        rejection_counts: dict[str, int] = {}

        def __init__(self, *_args: object, **kwargs: object) -> None:
            assert kwargs.get("capture_php_include_receipt") is True

        async def __aenter__(self):  # type: ignore[no-untyped-def]
            return self

        async def __aexit__(self, *_exc_info: object) -> None:
            return None

    async def create(*_args: object, **_kwargs: object) -> Process:
        return Process()

    async def communicate(_process: Process) -> tuple[bytes, bytes]:
        return stdout, b""

    async def kill(_process: Process) -> None:
        return None

    @contextlib.contextmanager
    def prepare(*_args: object, **_kwargs: object):  # type: ignore[no-untyped-def]
        yield Isolation()

    monkeypatch.setattr(sandbox_module, "PocProxySupervisor", Proxy)
    monkeypatch.setattr(sandbox_module, "prepare_poc_isolation", prepare)
    monkeypatch.setattr(sandbox_module.asyncio, "create_subprocess_exec", create)
    monkeypatch.setattr(sandbox_module, "_communicate_poc_bounded", communicate)
    monkeypatch.setattr(sandbox_module, "_kill_poc_process_group", kill)


@pytest.mark.asyncio
async def test_php_include_manager_repeats_complete_generations_without_state_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager, oracle, host_directory = _manager(tmp_path)
    _install_completed_php_include_child(monkeypatch, tmp_path)
    inspections = 0

    async def inspect(
        _container_name: str,
        attack_path: str,
        control_path: str,
    ) -> dict[str, object]:
        nonlocal inspections
        inspections += 1
        measurement = _measurement(host_directory, attack_path, control_path)
        if inspections % 2 == 0:
            # Docker Desktop may project the same read-only host inode as the
            # Apache identity after the request.  Host ownership is authoritative.
            measurement["attack_owner_uid"] = 33
            measurement["attack_owner_gid"] = 33
        return measurement

    def stop_before_trace(*_args: object, **_kwargs: object) -> tuple[bool, str]:
        return False, "stop after the lifecycle boundary"

    monkeypatch.setattr(sandbox_module, "_inspect_php_include_oracle", inspect)
    monkeypatch.setattr(
        sandbox_module,
        "validate_poc_observation",
        stop_before_trace,
    )

    generations: set[str] = set()
    markers: set[str] = set()
    for _iteration in range(12):
        result = await manager.run_poc(
            "/generated/poc.py",
            expected_php_include=True,
        )
        generations.add(oracle.generation_id)
        markers.add(oracle.private_marker)
        assert result.validation_reason == "stop after the lifecycle boundary"
        assert result.evidence["php_include_oracle_error"] is None
        assert result.evidence["php_include_oracle_failure_reason"] is None
        assert result.evidence["php_include_oracle_cleanup_error"] is None
        assert result.evidence["php_include_oracle_inspection_retries"] == 0
        assert list(host_directory.iterdir()) == []

    assert len(generations) == 12
    assert len(markers) == 12
    assert inspections == 24


@pytest.mark.asyncio
@pytest.mark.parametrize("trace_success", [True, False])
async def test_php_include_result_redacts_marker_after_trusted_validation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    trace_success: bool,
) -> None:
    manager, oracle, host_directory = _manager(tmp_path)
    _install_completed_php_include_child(monkeypatch, tmp_path)

    async def communicate(_process: object) -> tuple[bytes, bytes]:
        observation = {
            "verdict": "vulnerable",
            "oracle": "response_marker",
            "attacker_role": "unauthenticated",
            "request": {"method": "POST", "url": "http://localhost:8123/proof"},
            "attack": {
                "observed": True,
                "marker": oracle.private_marker,
                "marker_present": True,
                "include_path": oracle.attack_path,
            },
            "control": {
                "observed": False,
                "marker_present": False,
                "include_path": oracle.control_path,
            },
            "impact": {
                "confidentiality": "low",
                "integrity": "none",
                "availability": "none",
                "description": f"trusted receipt {oracle.private_marker}",
            },
        }
        stdout = (
            f"private stdout {oracle.private_marker}\n"
            + POC_RESULT_PREFIX
            + json.dumps(observation, separators=(",", ":"))
            + "\n"
        ).encode()
        return stdout, f"private stderr {oracle.private_marker}".encode()

    async def inspect(
        _container_name: str,
        attack_path: str,
        control_path: str,
    ) -> dict[str, object]:
        return _measurement(host_directory, attack_path, control_path)

    captured_markers: list[str] = []

    def validate_observation(*_args: object, **_kwargs: object) -> tuple[bool, str]:
        return True, "generic observation accepted"

    def validate_trace(
        observation: object,
        *_args: object,
        **_kwargs: object,
    ) -> tuple[bool, str, dict[str, object]]:
        marker = observation.attack["marker"]  # type: ignore[attr-defined]
        assert marker == oracle.private_marker
        captured_markers.append(marker)
        return (
            trace_success,
            f"trusted trace accepted {marker}",
            {"trusted_marker_echo": marker, "attack_path": oracle.attack_path},
        )

    class WPCLI:
        async def get_error_log(self) -> str:
            return f"private WordPress log {oracle.private_marker}"

    manager.wp_cli = WPCLI()  # type: ignore[assignment]
    monkeypatch.setattr(sandbox_module, "_communicate_poc_bounded", communicate)
    monkeypatch.setattr(sandbox_module, "_inspect_php_include_oracle", inspect)
    monkeypatch.setattr(
        sandbox_module, "validate_poc_observation", validate_observation
    )
    monkeypatch.setattr(
        sandbox_module,
        "validate_php_include_response_marker_http_trace",
        validate_trace,
    )
    caplog.set_level("DEBUG")

    result = await manager.run_poc(
        "/generated/poc.py",
        expected_php_include=True,
    )
    private_marker = oracle.private_marker
    serialized_result = result.model_dump_json()

    assert result.success is trace_success
    assert captured_markers == [private_marker]
    assert private_marker not in serialized_result
    assert private_marker not in caplog.text
    assert "<redacted>" in serialized_result
    assert (
        hashlib.sha256(private_marker.encode("ascii")).hexdigest() in serialized_result
    )
    assert oracle.attack_path in serialized_result
    assert oracle.control_path in serialized_result
    if trace_success:
        assert result.observation is not None
        assert result.observation.attack["marker"] == "<redacted>"
        assert result.rejected_observation is None
    else:
        assert result.observation is None
        assert result.rejected_observation is not None
        assert result.rejected_observation.attack["marker"] == "<redacted>"
    live_observation = result.take_trusted_php_include_observation()
    if trace_success:
        assert live_observation is not None
        assert live_observation.attack["marker"] == private_marker
    else:
        assert live_observation is None
    assert result.take_trusted_php_include_observation() is None
    assert list(host_directory.iterdir()) == []


def test_php_include_host_measurement_binds_exact_parent_owned_inode(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _manager_instance, oracle, host_directory = _manager(tmp_path)
    oracle.begin_generation()
    attack = sandbox_module._provision_php_include_oracle(host_directory, oracle)
    observed_inheritable: list[bool] = []
    real_get_inheritable = os.get_inheritable

    def get_inheritable(fd: int) -> bool:
        inheritable = real_get_inheritable(fd)
        observed_inheritable.append(inheritable)
        return inheritable

    monkeypatch.setattr(sandbox_module.os, "get_inheritable", get_inheritable)

    measurement = sandbox_module._measure_php_include_host_filesystem(
        host_directory,
        oracle.attack_path,
        oracle.control_path,
    )
    metadata = attack.lstat()

    assert (
        measurement.attack_content_sha256
        == hashlib.sha256(oracle.private_attack_content).hexdigest()
    )
    assert measurement.attack_content_size_bytes == len(oracle.private_attack_content)
    assert measurement.attack_owner_uid == os.geteuid()
    assert measurement.attack_owner_gid == os.getegid()
    assert measurement.attack_file_mode == 0o444
    assert measurement.attack_link_count == 1
    assert measurement.attack_is_regular_file is True
    assert measurement.attack_is_symlink is False
    assert measurement.control_lstat_exists is False
    assert measurement.attack_device == metadata.st_dev
    assert measurement.attack_inode == metadata.st_ino
    assert measurement.measured_monotonic_ns > 0
    assert observed_inheritable == [False, False]
    assert repr(measurement) == "PhpIncludeHostFilesystemMeasurement(<redacted>)"


def test_php_include_host_measurement_rejects_path_replacement_during_hash(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _manager_instance, oracle, host_directory = _manager(tmp_path)
    oracle.begin_generation()
    attack = sandbox_module._provision_php_include_oracle(host_directory, oracle)
    real_read = os.read
    replaced = False

    def read_and_replace(fd: int, size: int) -> bytes:
        nonlocal replaced
        chunk = real_read(fd, size)
        if chunk and not replaced:
            replaced = True
            replacement = host_directory / ".replacement"
            replacement.write_bytes(oracle.private_attack_content)
            replacement.chmod(0o444)
            replacement.replace(attack)
        return chunk

    monkeypatch.setattr(sandbox_module.os, "read", read_and_replace)

    with pytest.raises(RuntimeError) as caught:
        sandbox_module._measure_php_include_host_filesystem(
            host_directory,
            oracle.attack_path,
            oracle.control_path,
        )

    assert str(caught.value) == "PHP include host measurement failed"
    assert caught.value.__cause__ is None
    assert replaced is True


def test_php_include_exact_path_operations_do_not_follow_symlink(
    tmp_path: Path,
) -> None:
    _manager_instance, oracle, host_directory = _manager(tmp_path)
    oracle.begin_generation()
    attack = sandbox_module._php_include_host_path(
        host_directory,
        oracle.attack_path,
    )
    outside = tmp_path / "outside.php"
    private_outside_content = b"outside must survive"
    outside.write_bytes(private_outside_content)
    attack.symlink_to(outside)

    provisioned = sandbox_module._provision_php_include_oracle(
        host_directory,
        oracle,
    )

    assert provisioned == attack
    assert provisioned.is_file()
    assert not provisioned.is_symlink()
    assert provisioned.read_bytes() == oracle.private_attack_content
    assert outside.read_bytes() == private_outside_content

    provisioned.unlink()
    attack.symlink_to(outside)
    sandbox_module._remove_php_include_canary(host_directory, oracle)

    assert not attack.exists()
    assert not attack.is_symlink()
    assert outside.read_bytes() == private_outside_content


@pytest.mark.asyncio
async def test_post_execution_host_measurement_failure_is_value_free(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager, oracle, host_directory = _manager(tmp_path)
    _install_completed_php_include_child(monkeypatch, tmp_path)
    real_measure = sandbox_module._measure_php_include_host_filesystem
    measurements = 0
    private_uid_text = f"private-uid={os.geteuid()}"

    def measure(
        requested_directory: Path,
        attack_path: str,
        control_path: str,
    ) -> PhpIncludeHostFilesystemMeasurement:
        nonlocal measurements
        measurements += 1
        if measurements == 2:
            raise RuntimeError(
                f"{private_uid_text} {requested_directory} {oracle.private_marker}"
            )
        return real_measure(requested_directory, attack_path, control_path)

    async def inspect(
        _container_name: str,
        attack_path: str,
        control_path: str,
    ) -> dict[str, object]:
        return _measurement(host_directory, attack_path, control_path)

    monkeypatch.setattr(
        sandbox_module,
        "_measure_php_include_host_filesystem",
        measure,
    )
    monkeypatch.setattr(sandbox_module, "_inspect_php_include_oracle", inspect)
    caplog.set_level("WARNING")

    result = await manager.run_poc(
        "/generated/poc.py",
        expected_php_include=True,
    )

    reason = "post_execution_host_measurement_failed"
    persisted_surfaces = "\n".join(
        (
            result.validation_reason or "",
            json.dumps(result.evidence, sort_keys=True),
            caplog.text,
        )
    )
    assert result.evidence["php_include_oracle_error"] == "snapshot_failed"
    assert result.evidence["php_include_oracle_failure_reason"] == reason
    assert reason in persisted_surfaces
    assert private_uid_text not in persisted_surfaces
    assert os.fspath(host_directory) not in persisted_surfaces
    assert oracle.private_marker not in persisted_surfaces
    assert list(host_directory.iterdir()) == []


@pytest.mark.asyncio
async def test_php_include_inspection_retries_one_empty_output_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = {"measured": True}
    calls = 0

    async def inspect(*_args: object) -> dict[str, object]:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise sandbox_module._PhpIncludeInspectionError("empty_output")
        return expected

    monkeypatch.setattr(sandbox_module, "_inspect_php_include_oracle", inspect)

    measured, retries = await sandbox_module._inspect_php_include_oracle_bounded_retry(
        "wordpress-test",
        "/var/lib/squadrone/php-include/" + "a" * 64 + ".php",
        "/var/lib/squadrone/php-include/" + "b" * 64 + ".php",
    )

    assert measured is expected
    assert retries == 1
    assert calls == 2


@pytest.mark.asyncio
async def test_php_include_inspection_retry_still_rejects_invalid_measurement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    async def inspect(*_args: object) -> dict[str, object]:
        nonlocal calls
        calls += 1
        reason = "empty_output" if calls == 1 else "invalid_values"
        raise sandbox_module._PhpIncludeInspectionError(reason)

    monkeypatch.setattr(sandbox_module, "_inspect_php_include_oracle", inspect)

    with pytest.raises(sandbox_module._PhpIncludeInspectionError) as caught:
        await sandbox_module._inspect_php_include_oracle_bounded_retry(
            "wordpress-test",
            "/var/lib/squadrone/php-include/" + "a" * 64 + ".php",
            "/var/lib/squadrone/php-include/" + "b" * 64 + ".php",
        )

    assert caught.value.reason == "invalid_values"
    assert caught.value.retries == 1
    assert calls == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("returncode", "reason"),
    [
        (70, "contract_rejected"),
        (71, "contract_rejected"),
        (1, "process_failed"),
    ],
)
async def test_php_include_inspection_does_not_retry_contract_or_unknown_exit(
    monkeypatch: pytest.MonkeyPatch,
    returncode: int,
    reason: str,
) -> None:
    launches = 0

    class Process:
        def __init__(self) -> None:
            self.returncode = returncode

        async def communicate(self, _payload: bytes) -> tuple[bytes, bytes]:
            return b"", b""

    async def create(*_args: object, **_kwargs: object) -> Process:
        nonlocal launches
        launches += 1
        return Process()

    monkeypatch.setattr(sandbox_module.asyncio, "create_subprocess_exec", create)

    with pytest.raises(sandbox_module._PhpIncludeInspectionError) as caught:
        await sandbox_module._inspect_php_include_oracle_bounded_retry(
            "wordpress-test",
            "/var/lib/squadrone/php-include/" + "a" * 64 + ".php",
            "/var/lib/squadrone/php-include/" + "b" * 64 + ".php",
        )

    assert caught.value.reason == reason
    assert caught.value.retries == 0
    assert launches == 1


@pytest.mark.asyncio
async def test_php_include_inspection_retries_exit_72_then_requires_exact_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attack_path = "/var/lib/squadrone/php-include/" + "a" * 64 + ".php"
    control_path = "/var/lib/squadrone/php-include/" + "b" * 64 + ".php"
    processes = [
        (72, b"", b""),
        (0, _inspection_payload(attack_path, control_path), b""),
    ]
    launches = 0
    real_sleep = asyncio.sleep
    delays: list[float] = []

    class Process:
        def __init__(self, result: tuple[int, bytes, bytes]) -> None:
            self.returncode, self.stdout, self.stderr = result

        async def communicate(self, _payload: bytes) -> tuple[bytes, bytes]:
            return self.stdout, self.stderr

    async def create(*_args: object, **_kwargs: object) -> Process:
        nonlocal launches
        process = Process(processes[launches])
        launches += 1
        return process

    async def sleep(delay: float) -> None:
        delays.append(delay)
        await real_sleep(0)

    monkeypatch.setattr(sandbox_module.asyncio, "create_subprocess_exec", create)
    monkeypatch.setattr(sandbox_module.asyncio, "sleep", sleep)

    measured, retries = await sandbox_module._inspect_php_include_oracle_bounded_retry(
        "wordpress-test",
        attack_path,
        control_path,
    )

    assert measured["attack_resource_path"] == attack_path
    assert measured["control_resource_path"] == control_path
    assert retries == 1
    assert launches == 2
    assert delays == [sandbox_module._PHP_INCLUDE_INSPECTION_RETRY_DELAY_S]


@pytest.mark.asyncio
async def test_inspector_cancellation_survives_kill_and_wait_failures(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    cancellation = asyncio.CancelledError("original cancellation")
    calls: list[str] = []

    class Process:
        returncode = None

        async def communicate(self, _payload: bytes) -> tuple[bytes, bytes]:
            raise cancellation

        def kill(self) -> None:
            calls.append("kill")
            raise RuntimeError("private kill failure")

        def terminate(self) -> None:
            calls.append("terminate")
            raise RuntimeError("private terminate failure")

        async def wait(self) -> int:
            calls.append("wait")
            raise RuntimeError("private wait failure")

    async def create(*_args: object, **_kwargs: object) -> Process:
        return Process()

    monkeypatch.setattr(sandbox_module.asyncio, "create_subprocess_exec", create)
    caplog.set_level("WARNING")

    with pytest.raises(asyncio.CancelledError) as caught:
        await sandbox_module._inspect_php_include_oracle(
            "wordpress-test",
            "/var/lib/squadrone/php-include/" + "a" * 64 + ".php",
            "/var/lib/squadrone/php-include/" + "b" * 64 + ".php",
        )

    assert caught.value is cancellation
    assert calls == ["kill", "terminate", "wait"]
    assert "private" not in caplog.text


@pytest.mark.asyncio
async def test_inspector_cancellation_bounds_a_hung_reap_and_cancels_wait_task(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cancellation = asyncio.CancelledError("original cancellation")
    never = asyncio.Event()
    wait_cancelled = asyncio.Event()
    kill_calls = 0

    class Process:
        returncode = None

        async def communicate(self, _payload: bytes) -> tuple[bytes, bytes]:
            raise cancellation

        def kill(self) -> None:
            nonlocal kill_calls
            kill_calls += 1

        async def wait(self) -> int:
            try:
                await never.wait()
            finally:
                wait_cancelled.set()
            return 0

    async def create(*_args: object, **_kwargs: object) -> Process:
        return Process()

    monkeypatch.setattr(sandbox_module.asyncio, "create_subprocess_exec", create)
    monkeypatch.setattr(
        sandbox_module,
        "_PHP_INCLUDE_INSPECTOR_REAP_TIMEOUT_S",
        0.001,
    )
    started = asyncio.get_running_loop().time()

    with pytest.raises(asyncio.CancelledError) as caught:
        await sandbox_module._inspect_php_include_oracle(
            "wordpress-test",
            "/var/lib/squadrone/php-include/" + "a" * 64 + ".php",
            "/var/lib/squadrone/php-include/" + "b" * 64 + ".php",
        )
    await asyncio.sleep(0)

    assert caught.value is cancellation
    assert asyncio.get_running_loop().time() - started < 0.2
    assert kill_calls == 2
    assert wait_cancelled.is_set()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "communication_error",
    [
        TimeoutError("original timeout"),
        RuntimeError("original communication failure"),
    ],
    ids=["timeout", "ordinary-error"],
)
async def test_new_cancellation_during_inspector_reap_is_not_reclassified(
    monkeypatch: pytest.MonkeyPatch,
    communication_error: Exception,
) -> None:
    wait_started = asyncio.Event()
    wait_cancelled = asyncio.Event()
    never = asyncio.Event()

    class Process:
        returncode = None

        async def communicate(self, _payload: bytes) -> tuple[bytes, bytes]:
            raise communication_error

        def kill(self) -> None:
            return None

        async def wait(self) -> int:
            wait_started.set()
            try:
                await never.wait()
            finally:
                wait_cancelled.set()
            return 0

    async def create(*_args: object, **_kwargs: object) -> Process:
        return Process()

    monkeypatch.setattr(sandbox_module.asyncio, "create_subprocess_exec", create)
    monkeypatch.setattr(
        sandbox_module,
        "_PHP_INCLUDE_INSPECTOR_REAP_TIMEOUT_S",
        5.0,
    )
    inspection = asyncio.create_task(
        sandbox_module._inspect_php_include_oracle(
            "wordpress-test",
            "/var/lib/squadrone/php-include/" + "a" * 64 + ".php",
            "/var/lib/squadrone/php-include/" + "b" * 64 + ".php",
        )
    )
    await asyncio.wait_for(wait_started.wait(), timeout=0.2)
    inspection.cancel("new cancellation during reap")

    with pytest.raises(asyncio.CancelledError) as caught:
        await inspection
    await asyncio.sleep(0)

    assert str(caught.value) == "new cancellation during reap"
    assert wait_cancelled.is_set()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reason",
    [
        "contract_rejected",
        "invalid_shape",
        "invalid_values",
        "malformed_output",
        "oversized_output",
        "process_failed",
        "stderr_output",
        "unexpected_failure",
    ],
)
async def test_php_include_inspection_never_retries_rejected_evidence(
    monkeypatch: pytest.MonkeyPatch,
    reason: str,
) -> None:
    calls = 0

    async def inspect(*_args: object) -> dict[str, object]:
        nonlocal calls
        calls += 1
        raise sandbox_module._PhpIncludeInspectionError(reason)

    monkeypatch.setattr(sandbox_module, "_inspect_php_include_oracle", inspect)

    with pytest.raises(sandbox_module._PhpIncludeInspectionError) as caught:
        await sandbox_module._inspect_php_include_oracle_bounded_retry(
            "wordpress-test",
            "/var/lib/squadrone/php-include/" + "a" * 64 + ".php",
            "/var/lib/squadrone/php-include/" + "b" * 64 + ".php",
        )

    assert caught.value.reason == reason
    assert calls == 1


@pytest.mark.asyncio
async def test_snapshot_failure_retains_sanitized_stage_without_private_values(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager, oracle, host_directory = _manager(tmp_path)
    _install_completed_php_include_child(monkeypatch, tmp_path)
    inspections = 0

    async def inspect(
        _container_name: str,
        attack_path: str,
        control_path: str,
    ) -> dict[str, object]:
        nonlocal inspections
        inspections += 1
        if inspections == 2:
            raise RuntimeError(
                f"private failure {oracle.private_marker} {oracle.attack_path}"
            )
        return _measurement(host_directory, attack_path, control_path)

    monkeypatch.setattr(sandbox_module, "_inspect_php_include_oracle", inspect)
    caplog.set_level("WARNING")

    result = await manager.run_poc(
        "/generated/poc.py",
        expected_php_include=True,
    )

    serialized_evidence = json.dumps(result.evidence, sort_keys=True)
    assert result.validation_reason == (
        "PHP include oracle snapshot failed: snapshot_failed "
        "(post_execution_inspection_failed)"
    )
    assert result.evidence["php_include_oracle_error"] == "snapshot_failed"
    assert result.evidence["php_include_oracle_failure_reason"] == (
        "post_execution_inspection_failed"
    )
    assert result.evidence["php_include_oracle_cleanup_error"] is None
    assert oracle.private_marker not in serialized_evidence
    assert oracle.attack_path not in serialized_evidence
    assert oracle.private_marker not in caplog.text
    assert oracle.attack_path not in caplog.text
    assert "post_execution_inspection_failed" in caplog.text
    assert list(host_directory.iterdir()) == []


@pytest.mark.asyncio
async def test_provisioning_attestation_retains_reason_without_private_values(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager, oracle, host_directory = _manager(tmp_path)
    private_observed_digest = "deadc0de" * 8

    async def inspect(
        _container_name: str,
        attack_path: str,
        control_path: str,
    ) -> dict[str, object]:
        measurement = _measurement(host_directory, attack_path, control_path)
        assert measurement["attack_content_sha256"] != private_observed_digest
        measurement["attack_content_sha256"] = private_observed_digest
        return measurement

    monkeypatch.setattr(sandbox_module, "_inspect_php_include_oracle", inspect)
    caplog.set_level("WARNING")

    result = await manager.run_poc(
        "/generated/poc.py",
        expected_php_include=True,
    )

    reason = "provisioning_attestation_attack_content_sha256_mismatch"
    assert (
        result.validation_reason == f"PHP include oracle generation failed ({reason})"
    )
    assert result.evidence["php_include_oracle_error"] == "generation_failed"
    assert result.evidence["php_include_oracle_failure_reason"] == reason
    assert result.evidence["php_include_oracle_cleanup_error"] is None
    persisted_surfaces = "\n".join(
        (
            result.validation_reason or "",
            json.dumps(result.evidence, sort_keys=True),
            caplog.text,
        )
    )
    assert reason in persisted_surfaces
    for private_value in (
        private_observed_digest,
        oracle.private_marker,
        oracle.attack_path,
        oracle.control_path,
        "invalid PHP include provisioning attestation",
    ):
        assert private_value not in persisted_surfaces
    assert list(host_directory.iterdir()) == []


@pytest.mark.asyncio
async def test_verification_attestation_retains_reason_without_private_values(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager, oracle, host_directory = _manager(tmp_path)
    _install_completed_php_include_child(monkeypatch, tmp_path)
    private_observed_digest = "badc0ffe" * 8
    inspections = 0

    async def inspect(
        _container_name: str,
        attack_path: str,
        control_path: str,
    ) -> dict[str, object]:
        nonlocal inspections
        inspections += 1
        measurement = _measurement(host_directory, attack_path, control_path)
        if inspections == 2:
            assert measurement["attack_content_sha256"] != private_observed_digest
            measurement["attack_content_sha256"] = private_observed_digest
        return measurement

    monkeypatch.setattr(sandbox_module, "_inspect_php_include_oracle", inspect)
    caplog.set_level("WARNING")

    result = await manager.run_poc(
        "/generated/poc.py",
        expected_php_include=True,
    )

    reason = "verification_attestation_attack_content_sha256_mismatch"
    assert result.validation_reason == (
        f"PHP include oracle snapshot failed: snapshot_failed ({reason})"
    )
    assert result.evidence["php_include_oracle_error"] == "snapshot_failed"
    assert result.evidence["php_include_oracle_failure_reason"] == reason
    assert result.evidence["php_include_oracle_cleanup_error"] is None
    persisted_surfaces = "\n".join(
        (
            result.validation_reason or "",
            json.dumps(result.evidence, sort_keys=True),
            caplog.text,
        )
    )
    assert reason in persisted_surfaces
    for private_value in (
        private_observed_digest,
        oracle.private_marker,
        oracle.attack_path,
        oracle.control_path,
        "invalid PHP include verification attestation",
    ):
        assert private_value not in persisted_surfaces
    assert list(host_directory.iterdir()) == []


@pytest.mark.asyncio
async def test_unexpected_second_inspection_failure_retains_retry_telemetry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    manager, oracle, host_directory = _manager(tmp_path)
    _install_completed_php_include_child(monkeypatch, tmp_path)
    inspections = 0

    async def inspect(
        _container_name: str,
        attack_path: str,
        control_path: str,
    ) -> dict[str, object]:
        nonlocal inspections
        inspections += 1
        if inspections == 2:
            raise sandbox_module._PhpIncludeInspectionError("empty_output")
        if inspections == 3:
            raise RuntimeError(
                f"private retry failure {oracle.private_marker} {oracle.attack_path}"
            )
        return _measurement(host_directory, attack_path, control_path)

    monkeypatch.setattr(sandbox_module, "_inspect_php_include_oracle", inspect)
    caplog.set_level("WARNING")

    result = await manager.run_poc(
        "/generated/poc.py",
        expected_php_include=True,
    )

    serialized_evidence = json.dumps(result.evidence, sort_keys=True)
    assert result.evidence["php_include_oracle_error"] == "snapshot_failed"
    assert result.evidence["php_include_oracle_failure_reason"] == (
        "post_execution_inspection_unexpected_failure"
    )
    assert result.evidence["php_include_oracle_inspection_retries"] == 1
    assert "post_execution_inspection_unexpected_failure" in (
        result.validation_reason or ""
    )
    assert oracle.private_marker not in serialized_evidence
    assert oracle.attack_path not in serialized_evidence
    assert oracle.private_marker not in caplog.text
    assert oracle.attack_path not in caplog.text
    assert list(host_directory.iterdir()) == []


@pytest.mark.asyncio
async def test_snapshot_and_cleanup_failures_preserve_primary_category(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager, _oracle, host_directory = _manager(tmp_path)
    _install_completed_php_include_child(monkeypatch, tmp_path)
    inspections = 0

    async def inspect(
        _container_name: str,
        attack_path: str,
        control_path: str,
    ) -> dict[str, object]:
        nonlocal inspections
        inspections += 1
        if inspections == 2:
            raise sandbox_module._PhpIncludeInspectionError("invalid_values")
        return _measurement(host_directory, attack_path, control_path)

    def fail_cleanup(*_args: object) -> None:
        raise OSError("private cleanup failure")

    monkeypatch.setattr(sandbox_module, "_inspect_php_include_oracle", inspect)
    monkeypatch.setattr(sandbox_module, "_remove_php_include_canary", fail_cleanup)

    result = await manager.run_poc(
        "/generated/poc.py",
        expected_php_include=True,
    )

    assert result.evidence["php_include_oracle_error"] == "snapshot_failed"
    assert result.evidence["php_include_oracle_failure_reason"] == (
        "post_execution_inspection_invalid_values"
    )
    assert result.evidence["php_include_oracle_cleanup_error"] == "cleanup_failed"
    assert result.evidence["php_include_oracle_inspection_retries"] == 0


@pytest.mark.asyncio
async def test_failed_clear_poison_blocks_prepare_and_retries_exact_canary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager, stale_oracle, host_directory = _manager(tmp_path)
    stale_oracle.begin_generation()
    stale_attack = sandbox_module._provision_php_include_oracle(
        host_directory,
        stale_oracle,
    )
    real_remove = sandbox_module._remove_php_include_canary
    remove_attempts = 0

    def flaky_remove(
        requested_directory: Path | None,
        requested_oracle: PhpIncludeOracle | None,
    ) -> None:
        nonlocal remove_attempts
        remove_attempts += 1
        assert requested_directory == host_directory
        assert requested_oracle is stale_oracle
        if remove_attempts == 1:
            raise OSError("transient cleanup failure")
        real_remove(requested_directory, requested_oracle)

    async def probe(_container_name: str, _host_directory: Path) -> None:
        return None

    monkeypatch.setattr(
        sandbox_module,
        "_remove_php_include_canary",
        flaky_remove,
    )
    monkeypatch.setattr(sandbox_module, "_probe_php_include_mount", probe)

    with pytest.raises(RuntimeError, match="failed to clear"):
        await manager.prepare_php_include_oracle()

    assert manager._php_include_oracle is stale_oracle
    assert stale_attack.is_file()
    assert remove_attempts == 1

    context = await manager.prepare_php_include_oracle()

    assert remove_attempts == 2
    assert not stale_attack.exists()
    assert manager._php_include_oracle is not stale_oracle
    assert context == manager._php_include_oracle.public_context()


@pytest.mark.asyncio
async def test_generation_cancellation_removes_provisioned_php_canary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager, oracle, host_directory = _manager(tmp_path)
    cancellation = asyncio.CancelledError("cancelled during inspection")

    async def cancel_inspection(
        _container_name: str,
        attack_path: str,
        _control_path: str,
    ) -> dict[str, object]:
        attack = sandbox_module._php_include_host_path(host_directory, attack_path)
        assert attack.is_file()
        raise cancellation

    monkeypatch.setattr(
        sandbox_module,
        "_inspect_php_include_oracle",
        cancel_inspection,
    )

    with pytest.raises(asyncio.CancelledError) as caught:
        await manager.run_poc("/generated/poc.py", expected_php_include=True)

    assert caught.value is cancellation
    assert manager._php_include_oracle is oracle
    assert list(host_directory.iterdir()) == []


@pytest.mark.asyncio
async def test_execution_cancellation_removes_provisioned_php_canary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager, oracle, host_directory = _manager(tmp_path)
    cancellation = asyncio.CancelledError("cancelled entering proxy")

    async def inspect(
        _container_name: str,
        attack_path: str,
        control_path: str,
    ) -> dict[str, object]:
        return _measurement(host_directory, attack_path, control_path)

    class CancellingProxy:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            assert _kwargs.get("capture_php_include_receipt") is True

        async def __aenter__(self):  # type: ignore[no-untyped-def]
            attack = sandbox_module._php_include_host_path(
                host_directory,
                oracle.attack_path,
            )
            assert attack.is_file()
            raise cancellation

        async def __aexit__(self, *_exc_info: object) -> None:
            return None

    monkeypatch.setattr(sandbox_module, "_inspect_php_include_oracle", inspect)
    monkeypatch.setattr(sandbox_module, "PocProxySupervisor", CancellingProxy)

    with pytest.raises(asyncio.CancelledError) as caught:
        await manager.run_poc("/generated/poc.py", expected_php_include=True)

    assert caught.value is cancellation
    assert list(host_directory.iterdir()) == []


@pytest.mark.asyncio
async def test_cleanup_failure_does_not_mask_execution_cancellation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager, oracle, host_directory = _manager(tmp_path)
    cancellation = asyncio.CancelledError("primary cancellation")

    async def inspect(
        _container_name: str,
        attack_path: str,
        control_path: str,
    ) -> dict[str, object]:
        return _measurement(host_directory, attack_path, control_path)

    class CancellingProxy:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            return None

        async def __aenter__(self):  # type: ignore[no-untyped-def]
            raise cancellation

        async def __aexit__(self, *_exc_info: object) -> None:
            return None

    def fail_cleanup(
        _host_directory: Path | None,
        _oracle: PhpIncludeOracle | None,
    ) -> None:
        raise RuntimeError("secondary cleanup failure")

    monkeypatch.setattr(sandbox_module, "_inspect_php_include_oracle", inspect)
    monkeypatch.setattr(sandbox_module, "PocProxySupervisor", CancellingProxy)
    monkeypatch.setattr(
        sandbox_module,
        "_remove_php_include_canary",
        fail_cleanup,
    )

    with pytest.raises(asyncio.CancelledError) as caught:
        await manager.run_poc("/generated/poc.py", expected_php_include=True)

    assert caught.value is cancellation
    assert sandbox_module._php_include_host_path(
        host_directory,
        oracle.attack_path,
    ).is_file()
