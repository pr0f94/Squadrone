from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import signal
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest

import squadrone.services.sandbox as sandbox_module
from squadrone.poc_isolation import (
    CROSS_OBJECT_HTTP_CAPABILITY,
    PoCIsolationLaunch,
    seatbelt_unavailability_reason,
)
from squadrone.poc_proxy import (
    POC_PROXY_ENV,
    PRIVATE_TRACE_ENV_NAMES,
    PocProxySupervisor,
    build_poc_environment,
    minimal_poc_environment,
)
from squadrone.schemas.config import SandboxConfig
from squadrone.schemas.observation import CIAImpact, PoCObservation
from squadrone.schemas.taxonomy import KNOWN_CWE_REGISTRY
from squadrone.services.sandbox import POC_RESULT_PREFIX, SandboxManager
from squadrone.services.ssrf_oracle import SsrfOracleHit, SsrfOracleSnapshot


_CROSS_OBJECT_CAPABLE_CLASSES = tuple(
    sorted(
        bug_class.name
        for bug_class, profile in KNOWN_CWE_REGISTRY.items()
        if "cross_object_access" in profile.allowed_oracles
    )
)


class _ProcessStub:
    def __init__(self, returncode: int | None = 0) -> None:
        self.pid = 999_999
        self.returncode = returncode

    async def wait(self) -> int:
        assert self.returncode is not None
        return self.returncode


class _ProxyStub:
    def __init__(
        self,
        *,
        fatal_error: str | None = None,
        events: list[str] | None = None,
    ) -> None:
        self.proxy_url = "http://127.0.0.1:43123"
        self.records: list[dict[str, object]] = []
        self.trace_salt = b"s" * 32
        self.fatal_error = fatal_error
        self.rejection_counts: dict[str, int] = {}
        self.events = events
        self.child_environment_calls = 0
        self.constructor_args: tuple[str, str] | None = None

    async def __aenter__(self) -> _ProxyStub:
        if self.events is not None:
            self.events.append("proxy_enter")
        return self

    async def __aexit__(self, *_args: object) -> None:
        if self.events is not None:
            self.events.append("proxy_exit")

    def child_environment(
        self,
        base_environment: dict[str, str] | None = None,
        *,
        minimal: bool = True,
    ) -> dict[str, str]:
        self.child_environment_calls += 1
        if minimal:
            return minimal_poc_environment(self.proxy_url, base_environment)
        return build_poc_environment(self.proxy_url, base_environment)


def _manager(
    tmp_path: Path,
    *,
    poc_timeout_s: float = 1,
    ssrf_oracle_modes: frozenset[str] = frozenset(),
) -> SandboxManager:
    manager = SandboxManager(
        SandboxConfig(
            wordpress_image="unused",
            db_image="unused",
            wp_admin_user="admin",
            wp_admin_pass="password",
            wp_admin_email="admin@example.test",
            wp_url="http://unused.test",
        ),
        poc_timeout_s=poc_timeout_s,  # type: ignore[arg-type]
        ssrf_oracle_modes=ssrf_oracle_modes,  # type: ignore[arg-type]
    )
    manager.target_url = "http://127.0.0.1:48080"
    manager.workdir = tmp_path / "wordpress-state"
    manager.workdir.mkdir()
    manager._trace_token = "parent-only-trace-token-9b4dcdf0"
    return manager


def _response_marker_observation(target_url: str) -> PoCObservation:
    return PoCObservation(
        verdict="vulnerable",
        oracle="response_marker",
        attacker_role="unauthenticated",
        request={"method": "GET", "url": f"{target_url}/proof"},
        attack={
            "observed": True,
            "marker": "private-marker-9174",
            "marker_present": True,
        },
        control={"observed": False, "marker_present": False},
        impact=CIAImpact(
            confidentiality="high",
            description="The response disclosed the private test marker.",
        ),
    )


def _cross_object_observation() -> PoCObservation:
    return PoCObservation(
        verdict="vulnerable",
        oracle="cross_object_access",
        attacker_role="subscriber",
        request={},
        attack={},
        control={},
        impact=CIAImpact(
            confidentiality="high",
            description="A foreign object was returned.",
        ),
    )


class _OracleStub:
    def __init__(
        self,
        *,
        port: int = 49152,
        events: list[str] | None = None,
        fail_generation: bool = False,
        fail_snapshot: bool = False,
    ) -> None:
        self.attack_url = (
            f"http://host.docker.internal:{port}/_squadrone/ssrf/" + "a" * 64
        )
        self.control_url = (
            f"http://host.docker.internal:{port}/_squadrone/ssrf/" + "b" * 64
        )
        self.readiness_url = (
            f"http://host.docker.internal:{port}/_squadrone/ssrf/" + "c" * 64
        )
        self.generation_id = "d" * 64
        self.private_marker = "SQUADRONE_SSRF_" + "e" * 64
        self.is_running = False
        self.events = events
        self.fail_generation = fail_generation
        self.fail_snapshot = fail_snapshot
        self.start_calls = 0
        self.close_calls = 0
        self.begin_calls = 0
        self.snapshot_calls = 0

    async def start(self) -> _OracleStub:
        self.start_calls += 1
        self.is_running = True
        if self.events is not None:
            self.events.append("oracle_start")
        return self

    async def close(self) -> None:
        self.close_calls += 1
        self.is_running = False
        if self.events is not None:
            self.events.append("oracle_close")

    async def begin_generation(self) -> str:
        self.begin_calls += 1
        if self.events is not None:
            self.events.append("oracle_begin")
        if self.fail_generation:
            raise RuntimeError("private generation detail")
        self.generation_id = f"{self.begin_calls:064x}"
        self.private_marker = "SQUADRONE_SSRF_" + f"{self.begin_calls + 8:064x}"
        return self.generation_id

    async def snapshot(self) -> SsrfOracleSnapshot:
        self.snapshot_calls += 1
        if self.events is not None:
            self.events.append("oracle_snapshot")
        if self.fail_snapshot:
            raise RuntimeError("private snapshot detail")
        return SsrfOracleSnapshot(
            schema_version=1,
            generation_id=self.generation_id,
            overflow=False,
            hits=(
                SsrfOracleHit(
                    schema_version=1,
                    sequence=1,
                    arm="attack",
                    method="GET",
                    received_monotonic_ns=100,
                    responded_monotonic_ns=200,
                    status_code=200,
                    marker_sha256=hashlib.sha256(
                        self.private_marker.encode()
                    ).hexdigest(),
                ),
                SsrfOracleHit(
                    schema_version=1,
                    sequence=2,
                    arm="control",
                    method="GET",
                    received_monotonic_ns=300,
                    responded_monotonic_ns=400,
                    status_code=404,
                    marker_sha256=None,
                ),
            ),
        )


def _install_prepared_oracle(
    manager: SandboxManager,
    *,
    events: list[str] | None = None,
    fail_generation: bool = False,
    fail_snapshot: bool = False,
) -> _OracleStub:
    oracle = _OracleStub(
        events=events,
        fail_generation=fail_generation,
        fail_snapshot=fail_snapshot,
    )
    oracle.is_running = True
    manager._ssrf_oracle = oracle  # type: ignore[assignment]
    return oracle


def _stdout_for(observation: PoCObservation) -> bytes:
    payload = json.dumps(observation.model_dump(mode="json"), separators=(",", ":"))
    return f"{POC_RESULT_PREFIX}{payload}\n".encode()


@pytest.mark.asyncio
async def test_prepare_ssrf_oracle_rotates_service_and_returns_only_destinations(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager = _manager(tmp_path, ssrf_oracle_modes=frozenset({"http"}))
    manager._booted = True
    manager.container_name = "wordpress-test"
    old = _OracleStub(port=49151)
    old.is_running = True
    manager._ssrf_oracle = old  # type: ignore[assignment]
    fresh = _OracleStub(port=49152)
    probes: list[tuple[str, str]] = []

    async def probe(container_name: str, readiness_url: str) -> None:
        probes.append((container_name, readiness_url))

    monkeypatch.setattr(sandbox_module, "SsrfOracleServer", lambda: fresh)
    monkeypatch.setattr(sandbox_module, "_probe_ssrf_oracle_readiness", probe)

    context = await manager.prepare_ssrf_oracle()

    assert set(context) == {"attack_url", "control_url"}
    assert context == {
        "attack_url": fresh.attack_url,
        "control_url": fresh.control_url,
    }
    assert old.close_calls == 1
    assert fresh.start_calls == 1
    assert probes == [("wordpress-test", fresh.readiness_url)]
    assert manager._ssrf_oracle is fresh
    serialized = json.dumps(context)
    assert fresh.private_marker not in serialized
    assert fresh.generation_id not in serialized
    assert fresh.readiness_url not in serialized


@pytest.mark.asyncio
async def test_prepare_ssrf_oracle_failure_closes_new_service(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager = _manager(tmp_path, ssrf_oracle_modes=frozenset({"http"}))
    manager._booted = True
    manager.container_name = "wordpress-test"
    fresh = _OracleStub()

    async def fail_probe(_container_name: str, _readiness_url: str) -> None:
        raise RuntimeError("private readiness failure")

    monkeypatch.setattr(sandbox_module, "SsrfOracleServer", lambda: fresh)
    monkeypatch.setattr(sandbox_module, "_probe_ssrf_oracle_readiness", fail_probe)

    with pytest.raises(RuntimeError, match="failed to prepare the SSRF oracle") as exc:
        await manager.prepare_ssrf_oracle()

    assert "private readiness failure" not in str(exc.value)
    assert fresh.close_calls == 1
    assert manager._ssrf_oracle is None


@pytest.mark.asyncio
async def test_readiness_probe_uses_stdin_and_requires_exact_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    readiness_url = "http://host.docker.internal:49152/_squadrone/ssrf/" + "f" * 64
    commands: list[tuple[str, ...]] = []
    supplied: list[bytes] = []

    class ReadinessProcess:
        returncode = 0

        async def communicate(self, payload: bytes) -> tuple[bytes, bytes]:
            supplied.append(payload)
            return b'{"ready":true,"schema_version":1}', b""

        def kill(self) -> None:
            raise AssertionError("successful readiness process must not be killed")

        async def wait(self) -> int:
            return self.returncode

    async def create(*command: str, **_kwargs: object) -> ReadinessProcess:
        commands.append(command)
        return ReadinessProcess()

    monkeypatch.setattr(sandbox_module.asyncio, "create_subprocess_exec", create)

    await sandbox_module._probe_ssrf_oracle_readiness(
        "wordpress-test",
        readiness_url,
    )

    assert supplied == [readiness_url.encode("ascii")]
    assert len(commands) == 1
    assert readiness_url not in commands[0]


@pytest.mark.asyncio
async def test_readiness_probe_rejects_extra_json_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ReadinessProcess:
        returncode = 0

        async def communicate(self, _payload: bytes) -> tuple[bytes, bytes]:
            return b'{"ready":true,"schema_version":1,"extra":true}', b""

        def kill(self) -> None:
            raise AssertionError("completed readiness process must not be killed")

        async def wait(self) -> int:
            return self.returncode

    async def create(*_command: str, **_kwargs: object) -> ReadinessProcess:
        return ReadinessProcess()

    monkeypatch.setattr(sandbox_module.asyncio, "create_subprocess_exec", create)

    with pytest.raises(RuntimeError, match="readiness response is invalid"):
        await sandbox_module._probe_ssrf_oracle_readiness(
            "wordpress-test",
            "http://host.docker.internal:49152/_squadrone/ssrf/" + "f" * 64,
        )


@pytest.mark.asyncio
async def test_teardown_always_closes_prepared_ssrf_oracle(tmp_path: Path) -> None:
    manager = _manager(tmp_path)
    oracle = _install_prepared_oracle(manager)
    manager.project = ""

    await manager.teardown()

    assert oracle.close_calls == 1
    assert manager._ssrf_oracle is None


@pytest.mark.asyncio
async def test_teardown_waits_for_an_in_flight_poc_run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager = _manager(tmp_path)
    oracle = _install_prepared_oracle(manager)
    entered = asyncio.Event()
    release = asyncio.Event()

    async def blocked_run(*_args: object, **_kwargs: object):  # type: ignore[no-untyped-def]
        entered.set()
        await release.wait()
        return sandbox_module.SandboxRunResult(
            success=False,
            output="",
            elapsed=0,
        )

    monkeypatch.setattr(manager, "_run_poc_locked", blocked_run)
    run_task = asyncio.create_task(manager.run_poc("/generated/poc.py"))
    await entered.wait()
    teardown_task = asyncio.create_task(manager.teardown())
    await asyncio.sleep(0)

    assert oracle.close_calls == 0

    release.set()
    await run_task
    await teardown_task
    assert oracle.close_calls == 1


def _install_proxy_stub(
    monkeypatch: pytest.MonkeyPatch,
    proxy: _ProxyStub,
) -> None:
    def factory(target_url: str, *, trace_token: str) -> _ProxyStub:
        proxy.constructor_args = (target_url, trace_token)
        return proxy

    monkeypatch.setattr(sandbox_module, "PocProxySupervisor", factory)


def _install_completed_child(
    monkeypatch: pytest.MonkeyPatch,
    stdout: bytes,
) -> tuple[_ProcessStub, list[tuple[tuple[str, ...], dict[str, Any]]]]:
    process = _ProcessStub()
    launches: list[tuple[tuple[str, ...], dict[str, Any]]] = []

    async def create(*command: str, **kwargs: Any) -> _ProcessStub:
        launches.append((command, kwargs))
        return process

    async def communicate(_process: _ProcessStub) -> tuple[bytes, bytes]:
        return stdout, b""

    monkeypatch.setattr(sandbox_module.asyncio, "create_subprocess_exec", create)
    monkeypatch.setattr(sandbox_module, "_communicate_poc_bounded", communicate)
    return process, launches


def _fake_launch(tmp_path: Path) -> PoCIsolationLaunch:
    bundle = tmp_path / "isolated-bundle"
    bundle.mkdir(exist_ok=True)
    return PoCIsolationLaunch(
        command_prefix=(
            "/usr/bin/sandbox-exec",
            "-f",
            os.fspath(bundle / "seatbelt.sb"),
        ),
        cwd=bundle,
        script_path=bundle / "poc.py",
        runner_path=bundle / "_squadrone_poc_bootstrap.py",
        python_executable=Path(sys.executable),
        profile_path=bundle / "seatbelt.sb",
        bundle_files=(bundle / "poc.py",),
        proxy_port=43123,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("bug_class", _CROSS_OBJECT_CAPABLE_CLASSES)
async def test_cross_object_capable_classes_use_strict_seatbelt_bootstrap(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    bug_class: str,
) -> None:
    assert "IDOR" in _CROSS_OBJECT_CAPABLE_CLASSES
    manager = _manager(tmp_path)
    proxy = _ProxyStub()
    _install_proxy_stub(monkeypatch, proxy)
    _process, launches = _install_completed_child(
        monkeypatch,
        _stdout_for(_response_marker_observation(manager.target_url)),
    )
    for name in PRIVATE_TRACE_ENV_NAMES:
        monkeypatch.setenv(name, f"must-not-leak-{name}")

    launch = _fake_launch(tmp_path)
    prepare_calls: list[tuple[str, dict[str, object]]] = []

    @contextlib.contextmanager
    def prepare(script_path: str, **kwargs: object):  # type: ignore[no-untyped-def]
        prepare_calls.append((script_path, kwargs))
        yield launch

    monkeypatch.setattr(sandbox_module, "prepare_poc_isolation", prepare)

    result = await manager.run_poc("/generated/poc.py", expected_bug_class=bug_class)

    assert len(prepare_calls) == 1
    script_path, prepare_kwargs = prepare_calls[0]
    assert script_path == "/generated/poc.py"
    assert prepare_kwargs["proxy_port"] == 43123
    assert prepare_kwargs["capability"] == CROSS_OBJECT_HTTP_CAPABILITY
    assert manager.workdir in prepare_kwargs["protected_paths"]
    assert len(launches) == 1
    command, kwargs = launches[0]
    assert command == launch.python_command(launch.runner_path, launch.script_path)
    assert kwargs["cwd"] == os.fspath(launch.cwd)
    assert kwargs["start_new_session"] is True
    assert "pass_fds" not in kwargs
    environment = kwargs["env"]
    assert environment[POC_PROXY_ENV] == proxy.proxy_url
    assert PRIVATE_TRACE_ENV_NAMES.isdisjoint(environment)
    assert manager._trace_token not in environment.values()
    assert proxy.trace_salt.hex() not in environment.values()
    assert proxy.child_environment_calls == 0
    assert proxy.constructor_args == (manager.target_url, manager._trace_token)
    assert result.evidence["poc_isolation"] == CROSS_OBJECT_HTTP_CAPABILITY


@pytest.mark.asyncio
async def test_ssrf_uses_strict_proxy_and_collects_fresh_oracle_snapshot(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    manager = _manager(tmp_path)
    oracle = _install_prepared_oracle(manager, events=events)
    proxy = _ProxyStub(events=events)
    _install_proxy_stub(monkeypatch, proxy)
    _process, launches = _install_completed_child(
        monkeypatch,
        _stdout_for(_response_marker_observation(manager.target_url)),
    )
    launch = _fake_launch(tmp_path)

    @contextlib.contextmanager
    def prepare(script_path: str, **kwargs: object):  # type: ignore[no-untyped-def]
        events.append("isolation_enter")
        assert script_path == "/generated/ssrf.py"
        assert kwargs["capability"] == CROSS_OBJECT_HTTP_CAPABILITY
        try:
            yield launch
        finally:
            events.append("isolation_exit")

    def accept_observation(*_args: object, **_kwargs: object) -> tuple[bool, str]:
        return True, "base oracle passed"

    def accept_trace(*_args: object, **_kwargs: object) -> tuple[bool, str, dict]:
        events.append("trace_validate")
        assert _kwargs["expected_http_transport"] == {
            "method": "GET",
            "route": "/wp-json/example/v1/proxy",
            "dispatch": {},
            "destination_parameter": "url",
            "destination_location": "query",
        }
        assert _kwargs["oracle_attack_url"] == oracle.attack_url
        assert _kwargs["oracle_control_url"] == oracle.control_url
        assert _kwargs["oracle_marker"] == oracle.private_marker
        assert _kwargs["oracle_generation_id"] == oracle.generation_id
        assert _kwargs["oracle_snapshot"].generation_id == oracle.generation_id
        return True, "trusted SSRF trace passed", {"trusted": True}

    monkeypatch.setattr(sandbox_module, "prepare_poc_isolation", prepare)
    monkeypatch.setattr(sandbox_module, "validate_poc_observation", accept_observation)
    monkeypatch.setattr(
        sandbox_module,
        "validate_ssrf_response_marker_http_trace",
        accept_trace,
    )

    result = await manager.run_poc(
        "/generated/ssrf.py",
        expected_bug_class="SSRF",
        expected_http_transport={
            "method": "GET",
            "route": "/wp-json/example/v1/proxy",
            "dispatch": {},
            "destination_parameter": "url",
            "destination_location": "query",
        },
    )

    assert result.success is True, result.validation_reason
    assert len(launches) == 1
    assert result.evidence["poc_isolation"] == CROSS_OBJECT_HTTP_CAPABILITY
    assert result.evidence["http_trace_binding"] == {"trusted": True}
    assert events.index("oracle_begin") < events.index("proxy_enter")
    assert events.index("proxy_exit") < events.index("oracle_snapshot")
    assert events.index("oracle_snapshot") < events.index("trace_validate")


@pytest.mark.asyncio
async def test_ssrf_runs_rotate_private_marker_but_keep_public_destinations(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager = _manager(tmp_path)
    oracle = _install_prepared_oracle(manager)
    proxy = _ProxyStub()
    _install_proxy_stub(monkeypatch, proxy)
    _install_completed_child(
        monkeypatch,
        _stdout_for(_response_marker_observation(manager.target_url)),
    )
    launch = _fake_launch(tmp_path)

    @contextlib.contextmanager
    def prepare(*_args: object, **_kwargs: object):  # type: ignore[no-untyped-def]
        yield launch

    captured: list[tuple[str, str, str, str]] = []

    def accept_base(*_args: object, **_kwargs: object) -> tuple[bool, str]:
        return True, "base oracle passed"

    def accept_trace(*_args: object, **kwargs: object) -> tuple[bool, str, dict]:
        captured.append(
            (
                str(kwargs["oracle_attack_url"]),
                str(kwargs["oracle_control_url"]),
                str(kwargs["oracle_marker"]),
                str(kwargs["oracle_generation_id"]),
            )
        )
        return True, "trusted SSRF trace passed", {"trusted": True}

    monkeypatch.setattr(sandbox_module, "prepare_poc_isolation", prepare)
    monkeypatch.setattr(sandbox_module, "validate_poc_observation", accept_base)
    monkeypatch.setattr(
        sandbox_module,
        "validate_ssrf_response_marker_http_trace",
        accept_trace,
    )

    first = await manager.run_poc("/generated/ssrf.py", expected_bug_class="SSRF")
    second = await manager.run_poc("/generated/ssrf.py", expected_bug_class="SSRF")

    assert first.success is True
    assert second.success is True
    assert len(captured) == 2
    assert captured[0][:2] == captured[1][:2]
    assert captured[0][2] != captured[1][2]
    assert captured[0][3] != captured[1][3]
    assert oracle.begin_calls == 2
    assert oracle.snapshot_calls == 2


@pytest.mark.asyncio
async def test_ssrf_rejects_non_response_marker_even_if_base_validator_accepts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager = _manager(tmp_path)
    oracle = _install_prepared_oracle(manager)
    proxy = _ProxyStub()
    _install_proxy_stub(monkeypatch, proxy)
    observation = PoCObservation(
        verdict="vulnerable",
        oracle="callback",
        attacker_role="unauthenticated",
        request={"method": "GET", "url": f"{manager.target_url}/proof"},
        attack={
            "observed": True,
            "hit_count": 1,
            "marker": "claimed-marker",
            "marker_present": True,
        },
        control={"observed": False, "hit_count": 0, "marker_present": False},
        impact=CIAImpact(
            confidentiality="low",
            description="A callback was claimed.",
        ),
    )
    _install_completed_child(monkeypatch, _stdout_for(observation))
    launch = _fake_launch(tmp_path)

    @contextlib.contextmanager
    def prepare(*_args: object, **_kwargs: object):  # type: ignore[no-untyped-def]
        yield launch

    def accept_base(*_args: object, **_kwargs: object) -> tuple[bool, str]:
        return True, "incorrectly accepted by generic validation"

    def forbid_trace(*_args: object, **_kwargs: object) -> tuple[bool, str, dict]:
        raise AssertionError(
            "a non-response-marker SSRF must not reach trace validation"
        )

    monkeypatch.setattr(sandbox_module, "prepare_poc_isolation", prepare)
    monkeypatch.setattr(sandbox_module, "validate_poc_observation", accept_base)
    monkeypatch.setattr(
        sandbox_module,
        "validate_ssrf_response_marker_http_trace",
        forbid_trace,
    )

    result = await manager.run_poc(
        "/generated/ssrf.py",
        expected_bug_class="SSRF",
    )

    assert result.success is False
    assert "trusted response_marker boundary" in result.validation_reason
    assert oracle.begin_calls == 1
    assert oracle.snapshot_calls == 1


@pytest.mark.asyncio
async def test_unprepared_ssrf_oracle_prevents_child_launch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager = _manager(tmp_path)
    launches: list[str] = []

    async def forbidden_create(*_args: object, **_kwargs: object) -> None:
        launches.append("child")
        raise AssertionError("child must not launch without a prepared oracle")

    monkeypatch.setattr(
        sandbox_module.asyncio, "create_subprocess_exec", forbidden_create
    )

    result = await manager.run_poc(
        "/generated/ssrf.py",
        expected_bug_class="SSRF",
    )

    assert result.success is False
    assert result.validation_reason == "SSRF oracle is not prepared"
    assert launches == []
    assert result.evidence["ssrf_oracle_error"] == "unprepared"


@pytest.mark.asyncio
async def test_ssrf_oracle_generation_failure_prevents_child_launch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager = _manager(tmp_path)
    _install_prepared_oracle(manager, fail_generation=True)
    launches: list[str] = []

    async def forbidden_create(*_args: object, **_kwargs: object) -> None:
        launches.append("child")
        raise AssertionError("child must not launch after generation failure")

    monkeypatch.setattr(
        sandbox_module.asyncio, "create_subprocess_exec", forbidden_create
    )

    result = await manager.run_poc(
        "/generated/ssrf.py",
        expected_bug_class="SSRF",
    )

    assert result.success is False
    assert result.validation_reason == "SSRF oracle generation failed"
    assert launches == []
    assert "private generation detail" not in (result.error_log or "")
    assert result.evidence["ssrf_oracle_error"] == "generation_failed"


@pytest.mark.asyncio
async def test_ssrf_oracle_snapshot_failure_rejects_completed_child(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager = _manager(tmp_path)
    oracle = _install_prepared_oracle(manager, fail_snapshot=True)
    proxy = _ProxyStub()
    _install_proxy_stub(monkeypatch, proxy)
    _install_completed_child(
        monkeypatch,
        _stdout_for(_response_marker_observation(manager.target_url)),
    )
    launch = _fake_launch(tmp_path)

    @contextlib.contextmanager
    def prepare(*_args: object, **_kwargs: object):  # type: ignore[no-untyped-def]
        yield launch

    monkeypatch.setattr(sandbox_module, "prepare_poc_isolation", prepare)

    result = await manager.run_poc(
        "/generated/ssrf.py",
        expected_bug_class="SSRF",
    )

    assert result.success is False
    assert "SSRF oracle snapshot failed" in result.validation_reason
    assert "private snapshot detail" not in (result.error_log or "")
    assert result.evidence["ssrf_oracle_error"] == "snapshot_failed"
    assert oracle.begin_calls == 1
    assert oracle.snapshot_calls == 1


@pytest.mark.asyncio
async def test_non_cross_object_class_keeps_compatibility_runner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager = _manager(tmp_path)
    oracle = _install_prepared_oracle(manager)
    proxy = _ProxyStub()
    _process, launches = _install_completed_child(
        monkeypatch,
        _stdout_for(_response_marker_observation(manager.target_url)),
    )
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", "/runtime/browsers")
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-leak-service-credential")
    for name in PRIVATE_TRACE_ENV_NAMES:
        monkeypatch.setenv(name, f"must-not-leak-{name}")

    def forbidden_proxy(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("compatibility execution must not start the strict proxy")

    def forbidden_isolation(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("compatibility execution must not prepare Seatbelt")

    monkeypatch.setattr(sandbox_module, "PocProxySupervisor", forbidden_proxy)
    monkeypatch.setattr(
        sandbox_module,
        "prepare_poc_isolation",
        forbidden_isolation,
    )

    result = await manager.run_poc("/generated/poc.py", expected_bug_class="SQLI")

    assert result.success is True, result.validation_reason
    assert result.evidence["poc_isolation"] == "compatibility"
    assert len(launches) == 1
    command, kwargs = launches[0]
    assert command == (sys.executable, "/generated/poc.py")
    assert kwargs["cwd"] is None
    assert kwargs["start_new_session"] is True
    assert "pass_fds" not in kwargs
    environment = kwargs["env"]
    assert environment["PLAYWRIGHT_BROWSERS_PATH"] == "/runtime/browsers"
    assert "OPENAI_API_KEY" not in environment
    assert POC_PROXY_ENV not in environment
    assert PRIVATE_TRACE_ENV_NAMES.isdisjoint(environment)
    assert manager._trace_token not in environment.values()
    assert proxy.trace_salt.hex() not in environment.values()
    assert environment["NO_PROXY"] == "localhost,127.0.0.1,::1,host.docker.internal"
    assert oracle.begin_calls == 0
    assert oracle.snapshot_calls == 0


@pytest.mark.asyncio
async def test_proxy_fatal_error_fails_otherwise_valid_run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager = _manager(tmp_path)
    proxy = _ProxyStub(fatal_error="upstream_response_too_large")
    _install_proxy_stub(monkeypatch, proxy)
    _install_completed_child(
        monkeypatch,
        _stdout_for(_response_marker_observation(manager.target_url)),
    )
    launch = _fake_launch(tmp_path)

    @contextlib.contextmanager
    def prepare(*_args: object, **_kwargs: object):  # type: ignore[no-untyped-def]
        yield launch

    monkeypatch.setattr(sandbox_module, "prepare_poc_isolation", prepare)

    result = await manager.run_poc(
        "/generated/poc.py",
        expected_bug_class="MISSING_CAP_CHECK",
    )

    assert result.success is False
    assert result.validation_reason == (
        "PoC HTTP supervision failed: upstream_response_too_large"
    )
    assert result.evidence["http_trace_error"] == "upstream_response_too_large"


@pytest.mark.asyncio
async def test_malformed_proxy_target_latches_a_terminal_fatal_record() -> None:
    proxy = PocProxySupervisor(
        "http://127.0.0.1:48080",
        trace_token="parent-only-trace-token",
    )

    async with proxy:
        proxy_port = urlsplit(proxy.proxy_url).port
        assert proxy_port is not None
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
        writer.write(
            b"GET http://[invalid/ HTTP/1.1\r\n"
            b"Host: 127.0.0.1:48080\r\nConnection: close\r\n\r\n"
        )
        await writer.drain()
        response = await asyncio.wait_for(reader.read(), timeout=2)
        writer.close()
        await writer.wait_closed()

    assert response.startswith(b"HTTP/1.1 400")
    assert proxy.fatal_error == "invalid_request_target"
    assert proxy.rejection_counts == {"invalid_request_target": 1}
    assert len(proxy.records) == 1
    assert proxy.records[0]["record_type"] == "terminal_error"
    assert proxy.records[0]["forward_state"] == "failed"


@pytest.mark.asyncio
async def test_timeout_kills_process_before_isolation_and_proxy_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    events: list[str] = []
    manager = _manager(tmp_path, poc_timeout_s=0.01)
    proxy = _ProxyStub(events=events)
    _install_proxy_stub(monkeypatch, proxy)
    process = _ProcessStub(returncode=None)

    async def create(*_command: str, **_kwargs: object) -> _ProcessStub:
        return process

    async def communicate(_process: _ProcessStub) -> tuple[bytes, bytes]:
        try:
            await asyncio.Event().wait()
        finally:
            events.append("communicate_cancelled")
        raise AssertionError("unreachable")

    async def kill(killed: _ProcessStub) -> None:
        events.append("kill")
        killed.returncode = -9

    monkeypatch.setattr(sandbox_module.asyncio, "create_subprocess_exec", create)
    monkeypatch.setattr(sandbox_module, "_communicate_poc_bounded", communicate)
    monkeypatch.setattr(sandbox_module, "_kill_poc_process_group", kill)
    launch = _fake_launch(tmp_path)

    @contextlib.contextmanager
    def prepare(*_args: object, **_kwargs: object):  # type: ignore[no-untyped-def]
        events.append("isolation_enter")
        try:
            yield launch
        finally:
            events.append("isolation_exit")

    monkeypatch.setattr(sandbox_module, "prepare_poc_isolation", prepare)

    result = await manager.run_poc("/generated/poc.py", expected_bug_class="IDOR")

    assert result.success is False
    assert result.validation_reason == "PoC execution timed out"
    assert result.error_log == "PoC timed out after 0.01s"
    assert process.returncode == -9
    assert events.index("communicate_cancelled") < events.index("kill")
    assert events.index("kill") < events.index("isolation_exit")
    assert events.index("isolation_exit") < events.index("proxy_exit")
    assert result.evidence["poc_isolation"] == CROSS_OBJECT_HTTP_CAPABILITY


@pytest.mark.asyncio
async def test_process_group_cleanup_kills_descendant_after_leader_exits() -> None:
    source = """\
import subprocess
import sys

child = subprocess.Popen(
    [sys.executable, "-c", "import time; time.sleep(30)"],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    close_fds=True,
)
print(child.pid, flush=True)
"""
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        source,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    stdout, stderr = await sandbox_module._communicate_poc_bounded(process)
    assert process.returncode == 0, stderr.decode(errors="replace")
    child_pid = int(stdout.strip())

    try:
        os.kill(child_pid, 0)
        await sandbox_module._kill_poc_process_group(process)
        for _ in range(200):
            try:
                os.kill(child_pid, 0)
            except ProcessLookupError:
                break
            await asyncio.sleep(0.01)
        else:
            pytest.fail("PoC descendant survived process-group cleanup")
    finally:
        try:
            os.kill(child_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


@pytest.mark.asyncio
async def test_cross_object_oracle_cannot_pass_without_strict_isolation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager = _manager(tmp_path)
    proxy = _ProxyStub()
    _install_proxy_stub(monkeypatch, proxy)
    _install_completed_child(monkeypatch, _stdout_for(_cross_object_observation()))
    monkeypatch.setattr(
        sandbox_module,
        "validate_poc_observation",
        lambda *_args, **_kwargs: (True, "oracle passed"),
    )

    def forbidden_trace_validation(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("unisolated cross-object trace must not be validated")

    monkeypatch.setattr(
        sandbox_module,
        "validate_cross_object_http_trace",
        forbidden_trace_validation,
    )

    result = await manager.run_poc("/generated/poc.py")

    assert result.success is False
    assert result.validation_reason == (
        "cross-object proof requires the strict parent-proxy isolation boundary"
    )
    assert result.evidence["poc_isolation"] == "compatibility"


@pytest.mark.asyncio
@pytest.mark.skipif(
    seatbelt_unavailability_reason() is not None,
    reason="macOS sandbox-exec is unavailable",
)
async def test_real_local_http_request_runs_through_seatbelt_and_parent_proxy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    received_heads: list[bytes] = []

    async def serve(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
            received_heads.append(head)
            body = b"private-marker-9174"
            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                + f"Content-Length: {len(body)}\r\n".encode()
                + b"Content-Type: text/plain\r\nConnection: close\r\n\r\n"
                + body
            )
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(serve, "127.0.0.1", 0)
    upstream_port = server.sockets[0].getsockname()[1]
    manager = _manager(tmp_path, poc_timeout_s=20)
    manager.target_url = f"http://127.0.0.1:{upstream_port}"
    for name in PRIVATE_TRACE_ENV_NAMES:
        monkeypatch.setenv(name, f"must-not-leak-{name}")
    trace_read_fd, trace_write_fd = os.pipe()
    os.set_inheritable(trace_read_fd, True)
    trace_fd_stat = os.fstat(trace_read_fd)

    source_dir = tmp_path / "source"
    source_dir.mkdir()
    script = source_dir / "poc.py"
    observation = _response_marker_observation(manager.target_url)
    source = f"""\
import json
import os
import requests

private_names = {sorted(PRIVATE_TRACE_ENV_NAMES)!r}
leaked = sorted(name for name in private_names if name in os.environ)
try:
    fd_stat = os.fstat({trace_read_fd})
    inherited_trace_fd = (fd_stat.st_dev, fd_stat.st_ino) == {
        (
            trace_fd_stat.st_dev,
            trace_fd_stat.st_ino,
        )!r
    }
except OSError:
    inherited_trace_fd = False
response = requests.get({manager.target_url!r} + "/proof", timeout=5)
response.raise_for_status()
assert "private-marker-9174" in response.text
print("private_trace_env=" + json.dumps(leaked))
print("inherited_trace_fd=" + json.dumps(inherited_trace_fd))
payload = {observation.model_dump(mode="json")!r}
print({POC_RESULT_PREFIX!r} + json.dumps(payload, separators=(",", ":")))
"""
    script.write_text(source, encoding="utf-8")

    try:
        result = await manager.run_poc(
            os.fspath(script),
            expected_bug_class="MISSING_CAP_CHECK",
        )
    finally:
        server.close()
        await server.wait_closed()
        os.close(trace_read_fd)
        os.close(trace_write_fd)

    assert result.success is True, (result.validation_reason, result.error_log)
    assert result.evidence["poc_isolation"] == CROSS_OBJECT_HTTP_CAPABILITY
    assert result.evidence["http_trace_records"] == 1
    assert "private_trace_env=[]" in result.output
    assert "inherited_trace_fd=false" in result.output
    assert len(received_heads) == 1
    received_head = received_heads[0].lower()
    assert b"x-squadrone-trace-token:" in received_head
    assert manager._trace_token.encode() in received_head
