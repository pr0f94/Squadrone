from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import json
import time
from pathlib import Path
from urllib.parse import parse_qs, quote, urlencode

import httpx
import pytest

import squadrone.services.sandbox as sandbox_module
from squadrone.poc_proxy import (
    ACTOR_RECEIPT_HEADER,
    PHP_OBJECT_RECEIPT_HEADER,
    PhpObjectProxyObservation,
    PhpObjectRewritePolicy,
    PocProxySupervisor,
    classify_request_sentinels,
)
from squadrone.schemas import CIAImpact, PoCObservation, SandboxConfig
from squadrone.services.php_object_oracle import PhpObjectCallsite, PhpObjectOracle
from squadrone.services.sandbox import (
    POC_RESULT_PREFIX,
    SandboxManager,
    SandboxRunResult,
    php_object_private_redaction_values,
    php_object_rewrite_policy_from_transport,
    redact_php_object_run_result,
    validate_php_object_http_trace,
    validate_poc_observation,
)


_CLASS_NAME = "SquadroneObjectCanary_0123456789abcdef0123456789abcdef"
_TRACE_TOKEN = "53" * 32
_TRACE_SECRET = bytes.fromhex("42" * 32)
_TRACE_SALT = bytes.fromhex("31" * 32)
_TARGET_URL = "http://localhost:8123"
_ROUTE = "/wp-admin/admin-ajax.php"
_PLUGIN_SLUG = "example-plugin"
_CALLSITE_RELATIVE_PATH = "includes/process-submission.php"
_CALLSITE_PATH = (
    f"/var/www/html/wp-content/plugins/{_PLUGIN_SLUG}/{_CALLSITE_RELATIVE_PATH}"
)
_CALLSITE_SOURCE_SHA256 = "7a" * 32


def _callsite() -> PhpObjectCallsite:
    return PhpObjectCallsite(
        relative_path=_CALLSITE_RELATIVE_PATH,
        start_line=40,
        end_line=44,
        source_sha256=_CALLSITE_SOURCE_SHA256,
    )


def _oracle() -> PhpObjectOracle:
    return PhpObjectOracle(
        callsite_path=_CALLSITE_PATH,
        callsite_start_line=40,
        callsite_end_line=44,
        callsite_source_sha256=_CALLSITE_SOURCE_SHA256,
        class_name=_CLASS_NAME,
        receipt_secret=bytes.fromhex("24" * 32),
    )


def _manager(*, enabled: bool = False) -> SandboxManager:
    manager = SandboxManager(
        SandboxConfig(
            wordpress_image="wordpress:latest",
            db_image="mariadb:10.11",
            wp_admin_user="admin",
            wp_admin_pass="password",
            wp_admin_email="admin@example.test",
        ),
        php_object_oracle_enabled=enabled,
    )
    manager.container_name = "test-project-wordpress-1"
    manager._installed_plugin_slug = _PLUGIN_SLUG
    return manager


def _verified_snapshot(oracle: PhpObjectOracle):
    generation_id = oracle.begin_generation()
    context = oracle.public_context()
    started = time.monotonic_ns()
    finished = time.monotonic_ns()
    return oracle.attest_execution(
        generation_id=generation_id,
        attack_token=context["attack_token"],
        control_token=context["control_token"],
        attack_receipt=oracle.private_expected_receipt,
        control_receipt=None,
        execution_started_monotonic_ns=started,
        execution_finished_monotonic_ns=finished,
        attested_monotonic_ns=time.monotonic_ns(),
    )


def _observation(
    *,
    attacker_role: str = "unauthenticated",
    attacker_user_id: str = "anonymous",
) -> PoCObservation:
    fingerprint = {
        "method": "POST",
        "route": _ROUTE,
        "object_field": "serialized_payload",
        "object_location": "form",
        "dispatch": {"form:action": "process_submission"},
    }
    return PoCObservation(
        verdict="vulnerable",
        oracle="object_instantiation",
        attacker_role=attacker_role,
        request={"method": "POST", "url": f"{_TARGET_URL}{_ROUTE}"},
        attack={
            "observed": True,
            "instantiated": True,
            "effect": "verifier_inert_canary_wakeup",
            "attacker_user_id": attacker_user_id,
            "identity_verified": True,
            "request_fingerprint": fingerprint,
        },
        control={
            "observed": False,
            "instantiated": False,
            "effect": "verifier_inert_canary_wakeup",
            "attacker_user_id": attacker_user_id,
            "identity_verified": True,
            "request_fingerprint": fingerprint,
        },
        impact=CIAImpact(
            confidentiality="none",
            integrity="low",
            availability="none",
            description=(
                "A verifier-owned inert canary object was instantiated and its "
                "__wakeup method ran; no natural gadget or external side effect "
                "was exercised."
            ),
        ),
    )


async def _accept_surface_attestation(
    _phase: str,
    _arm: str,
) -> None:
    return None


async def _run_stubbed_php_object_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    callbacks: tuple[tuple[str, str], ...] = (),
    returncode: int = 0,
    fatal_error: str | None = None,
    stdout: bytes = b"",
    stderr: bytes = b"",
    executable_surface_drift: bool = False,
) -> SandboxRunResult:
    """Exercise runner finalization without sockets, containers, or child code."""
    oracle = _oracle()
    manager = _manager(enabled=True)
    manager._booted = True
    manager.workdir = tmp_path
    manager.target_url = _TARGET_URL
    manager._php_object_oracle = oracle
    manager._php_object_callsite = _callsite()

    class Process:
        pid = 999_999

        def __init__(self) -> None:
            self.returncode = returncode

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
        rejection_counts: dict[str, int] = {}
        php_object_complete = (
            callbacks == sandbox_module._PHP_OBJECT_SURFACE_ATTESTATION_ORDER
        )

        def __init__(self, *_args: object, **kwargs: object) -> None:
            self.fatal_error = fatal_error
            self._surface_attestor = kwargs["php_object_surface_attestor"]

        async def __aenter__(self):  # type: ignore[no-untyped-def]
            for phase, arm in callbacks:
                await self._surface_attestor(phase, arm)
            return self

        async def __aexit__(self, *_exc_info: object) -> None:
            return None

        def take_php_object_observation(self) -> None:
            return None

    async def create(*_args: object, **_kwargs: object) -> Process:
        return Process()

    async def communicate(_process: Process) -> tuple[bytes, bytes]:
        return stdout, stderr

    async def kill(_process: Process) -> None:
        return None

    async def attest_oracle(_oracle_value: PhpObjectOracle) -> None:
        return None

    async def attest_callsite(_value: PhpObjectCallsite) -> str:
        return _CALLSITE_PATH

    frozen = sandbox_module._PhpObjectSurfaceFreeze(
        manifest_path=(
            "/tmp/squadrone-object-surfaces-"
            "0123456789abcdef0123456789abcdef.json"
        ),
        entry_count=3,
        original_sha256="1" * 64,
        frozen_sha256="2" * 64,
        manifest_sha256="3" * 64,
    )

    async def freeze_surfaces():  # type: ignore[no-untyped-def]
        return frozen

    surface_attestation_count = 0

    async def attest_surfaces(_value):  # type: ignore[no-untyped-def]
        nonlocal surface_attestation_count
        surface_attestation_count += 1
        if (
            executable_surface_drift
            and surface_attestation_count > len(callbacks)
        ):
            raise RuntimeError("private executable-surface drift detail")

    async def restore_surfaces(_value):  # type: ignore[no-untyped-def]
        return None

    @contextlib.contextmanager
    def prepare(*_args: object, **_kwargs: object):  # type: ignore[no-untyped-def]
        yield Isolation()

    monkeypatch.setattr(sandbox_module, "PocProxySupervisor", Proxy)
    monkeypatch.setattr(sandbox_module, "prepare_poc_isolation", prepare)
    monkeypatch.setattr(sandbox_module.asyncio, "create_subprocess_exec", create)
    monkeypatch.setattr(sandbox_module, "_communicate_poc_bounded", communicate)
    monkeypatch.setattr(sandbox_module, "_kill_poc_process_group", kill)
    monkeypatch.setattr(manager, "_attest_php_object_oracle_plugin", attest_oracle)
    monkeypatch.setattr(manager, "_attest_php_object_callsite", attest_callsite)
    monkeypatch.setattr(
        manager,
        "_freeze_php_object_executable_surfaces",
        freeze_surfaces,
    )
    monkeypatch.setattr(
        manager,
        "_attest_php_object_executable_surfaces",
        attest_surfaces,
    )
    monkeypatch.setattr(
        manager,
        "_restore_php_object_executable_surfaces",
        restore_surfaces,
    )
    transport: dict[str, object] = {
        "method": "POST",
        "route": _ROUTE,
        "object_location": "form",
        "object_field": "serialized_payload",
        "dispatch": {"form:action": "process_submission"},
    }
    return await manager.run_poc(
        "/generated/poc.py",
        expected_bug_class="CWE-502",
        expected_attacker_role="unauthenticated",
        expected_php_object=True,
        expected_php_object_transport=transport,
    )


def test_result_keeps_object_snapshot_in_a_take_once_private_slot() -> None:
    snapshot = _verified_snapshot(_oracle())
    result = SandboxRunResult(success=True, output="", elapsed=0.1)

    result.retain_trusted_php_object_snapshot(snapshot)

    assert "trusted_php_object" not in result.model_dump_json()
    assert result.take_trusted_php_object_snapshot() == snapshot
    assert result.take_trusted_php_object_snapshot() is None


def test_object_redaction_removes_raw_and_transport_encoded_private_values() -> None:
    oracle = _oracle()
    oracle.begin_generation()
    private_values = php_object_private_redaction_values(oracle)
    raw_payload = oracle.private_attack_payload.decode("ascii")
    reflected = "|".join(
        (
            oracle.private_class_name,
            raw_payload,
            quote(raw_payload, safe=""),
            base64.b64encode(raw_payload.encode("ascii")).decode("ascii"),
            raw_payload.encode("ascii").hex(),
        )
    )
    result = SandboxRunResult(
        success=False,
        output=reflected,
        elapsed=0.1,
        response=reflected,
        error_log=reflected,
        evidence={"nested": [reflected]},
        validation_reason=reflected,
    )

    redact_php_object_run_result(result, private_values)

    rendered = result.model_dump_json()
    assert _CLASS_NAME not in rendered
    assert raw_payload not in rendered
    assert quote(raw_payload, safe="") not in rendered
    assert oracle.private_receipt_secret.hex() not in rendered
    assert "<redacted>" in rendered
    assert result.evidence["php_object_private_values_redacted"] is True


@pytest.mark.asyncio
async def test_incomplete_object_callbacks_are_transport_not_surface_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    result = await _run_stubbed_php_object_failure(monkeypatch, tmp_path)

    assert result.success is False
    assert result.validation_reason == "PHP object attack/control transport incomplete"
    assert result.evidence["php_object_oracle_error"] == "transport_incomplete"
    assert (
        result.evidence["php_object_oracle_failure_reason"]
        == "php_object_transport_incomplete"
    )
    assert "surface" not in result.validation_reason.casefold()
    assert "surface" not in json.dumps(result.evidence).casefold()


@pytest.mark.asyncio
async def test_object_preflight_runtime_failure_outranks_incomplete_transport(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    result = await _run_stubbed_php_object_failure(
        monkeypatch,
        tmp_path,
        returncode=1,
        stderr=(
            b"Traceback (most recent call last):\n"
            b"RuntimeError: rendered form bootstrap failed\n"
        ),
    )

    assert result.success is False
    assert result.validation_reason == (
        "PoC process exited 1 before PHP object transport completed"
    )
    assert result.evidence["php_object_oracle_error"] == "transport_incomplete"
    assert "rendered form bootstrap failed" in (result.error_log or "")
    assert "surface_attestation_failed" not in result.model_dump_json()


@pytest.mark.asyncio
async def test_incomplete_object_callbacks_preserve_proxy_transport_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    child_observation = POC_RESULT_PREFIX + _observation().model_dump_json()
    result = await _run_stubbed_php_object_failure(
        monkeypatch,
        tmp_path,
        callbacks=(("before", "attack"),),
        fatal_error="missing_php_object_receipt",
        stdout=child_observation.encode("utf-8"),
    )

    assert result.success is False
    assert result.validation_reason == (
        "Trusted parent PHP object diagnostic: attack policy accepted; attack "
        "payload privately rewritten; upstream response received; required attack "
        "receipt missing; instantiation/control remain unestablished."
    )
    assert result.observation is None
    assert result.rejected_observation == _observation()
    assert child_observation not in result.output
    assert result.evidence["validation_reason"] == result.validation_reason
    assert result.evidence["php_object_trusted_parent_diagnostic"] == {
        "source": "trusted_parent_proxy",
        "arm": "attack",
        "policy_acceptance": "accepted",
        "payload_rewrite": "privately_rewritten",
        "upstream_response": "received",
        "receipt_outcome": "missing",
        "instantiation": "unestablished",
        "control": "unestablished",
    }
    assert result.evidence["php_object_oracle_error"] == "transport_incomplete"
    assert (
        result.evidence["php_object_oracle_failure_reason"]
        == "php_object_transport_incomplete"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("fatal_error", "receipt_outcome"),
    [
        ("malformed_php_object_receipt", "malformed"),
        ("mismatched_php_object_receipt", "mismatched"),
    ],
)
async def test_attack_receipt_failures_use_only_trusted_bounded_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    fatal_error: str,
    receipt_outcome: str,
) -> None:
    child_text = "raw child stdout/header/body/private text"
    result = await _run_stubbed_php_object_failure(
        monkeypatch,
        tmp_path,
        callbacks=(("before", "attack"),),
        fatal_error=fatal_error,
        stdout=child_text.encode("utf-8"),
        stderr=b"raw child stderr/private text",
    )

    diagnostic = result.evidence["php_object_trusted_parent_diagnostic"]
    authoritative = result.validation_reason + json.dumps(diagnostic, sort_keys=True)
    assert diagnostic["arm"] == "attack"
    assert diagnostic["policy_acceptance"] == "accepted"
    assert diagnostic["payload_rewrite"] == "privately_rewritten"
    assert diagnostic["upstream_response"] == "received"
    assert diagnostic["receipt_outcome"] == receipt_outcome
    assert diagnostic["instantiation"] == "unestablished"
    assert diagnostic["control"] == "unestablished"
    assert child_text not in authoritative
    assert "raw child stderr" not in authoritative
    assert len(result.validation_reason) <= (
        sandbox_module._PHP_OBJECT_RECEIPT_DIAGNOSTIC_MAX_CHARS
    )


@pytest.mark.parametrize(
    ("fatal_error", "receipt_outcome"),
    [
        ("duplicate_php_object_receipt", "duplicate"),
        ("unexpected_php_object_receipt", "unexpected"),
    ],
)
def test_ambiguous_receipt_failures_do_not_claim_policy_or_rewrite(
    fatal_error: str,
    receipt_outcome: str,
) -> None:
    diagnostic = sandbox_module._trusted_php_object_receipt_rejection_diagnostic(
        fatal_error
    )

    assert diagnostic is not None
    reason, evidence = diagnostic
    assert "policy accepted" not in reason
    assert "privately rewritten" not in reason
    assert evidence["arm"] == "unestablished"
    assert evidence["policy_acceptance"] == "unestablished"
    assert evidence["payload_rewrite"] == "unestablished"
    assert evidence["receipt_outcome"] == receipt_outcome


def test_receipt_diagnostic_rejects_unlisted_error_text() -> None:
    private_text = "missing_php_object_receipt:raw-private-receipt"

    assert (
        sandbox_module._trusted_php_object_receipt_rejection_diagnostic(private_text)
        is None
    )
    assert (
        sandbox_module._trusted_php_object_receipt_rejection_diagnostic(
            "natural_gadget_php_object_receipt_present"
        )
        is None
    )


def test_control_receipt_diagnostic_reports_only_parent_guaranteed_facts() -> None:
    diagnostic = sandbox_module._trusted_php_object_receipt_rejection_diagnostic(
        "control_php_object_receipt_present"
    )

    assert diagnostic is not None
    reason, evidence = diagnostic
    assert "control policy accepted" in reason
    assert "control payload privately rewritten" in reason
    assert evidence == {
        "source": "trusted_parent_proxy",
        "arm": "control",
        "policy_acceptance": "accepted",
        "payload_rewrite": "privately_rewritten",
        "upstream_response": "received",
        "receipt_outcome": "control_present",
        "instantiation": "unestablished",
        "control": "unestablished",
    }


@pytest.mark.asyncio
async def test_actual_object_surface_drift_keeps_surface_failure_class(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    result = await _run_stubbed_php_object_failure(
        monkeypatch,
        tmp_path,
        executable_surface_drift=True,
    )

    assert result.success is False
    assert result.validation_reason == (
        "PHP object executable-surface attestation failed"
    )
    assert (
        result.evidence["php_object_oracle_error"]
        == "surface_attestation_failed"
    )
    assert (
        result.evidence["php_object_oracle_failure_reason"]
        == "surface_attestation_failed"
    )
    assert "private executable-surface drift detail" not in result.model_dump_json()


@pytest.mark.asyncio
async def test_surface_drift_outranks_simultaneous_receipt_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    result = await _run_stubbed_php_object_failure(
        monkeypatch,
        tmp_path,
        callbacks=(("before", "attack"),),
        fatal_error="missing_php_object_receipt",
        executable_surface_drift=True,
    )

    assert result.success is False
    assert result.validation_reason == (
        "PHP object executable-surface attestation failed"
    )
    assert result.evidence["php_object_oracle_error"] == "surface_attestation_failed"
    assert (
        result.evidence["php_object_oracle_failure_reason"]
        == "surface_attestation_failed"
    )
    assert "php_object_trusted_parent_diagnostic" not in result.evidence


def test_transport_policy_is_exact_and_rejects_non_form_or_ambiguous_fields() -> None:
    transport: dict[str, object] = {
        "method": "POST",
        "route": _ROUTE,
        "object_location": "form",
        "object_field": "serialized_payload",
        "dispatch": {"form:action": "process_submission"},
    }

    policy = php_object_rewrite_policy_from_transport(transport)

    assert policy == PhpObjectRewritePolicy(
        method="POST",
        path=_ROUTE,
        object_location="form",
        object_field="serialized_payload",
        dispatch=(("form", "action", "process_submission"),),
    )
    assert php_object_rewrite_policy_from_transport(
        {**transport, "object_location": "json"}
    ) is None
    assert php_object_rewrite_policy_from_transport(
        {
            **transport,
            "dispatch": {"form:serialized_payload": "collision"},
        }
    ) is None


@pytest.mark.asyncio
async def test_prepare_requires_enablement_and_installs_one_private_oracle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    disabled = _manager()
    disabled._booted = True
    with pytest.raises(RuntimeError, match="was not enabled"):
        await disabled.prepare_php_object_oracle(_callsite())

    manager = _manager(enabled=True)
    manager._booted = True
    installed: list[PhpObjectOracle] = []

    async def fake_install(oracle: PhpObjectOracle) -> None:
        installed.append(oracle)

    async def fake_callsite(_value: PhpObjectCallsite) -> str:
        return _CALLSITE_PATH

    monkeypatch.setattr(manager, "_install_php_object_oracle_plugin", fake_install)
    monkeypatch.setattr(manager, "_attest_php_object_callsite", fake_callsite)

    context = await manager.prepare_php_object_oracle(_callsite())

    assert context == installed[0].public_context()
    assert context["mode"] == "php_object"
    assert manager._php_object_oracle is installed[0]
    assert manager._php_object_callsite == _callsite()


@pytest.mark.asyncio
async def test_callsite_is_mapped_and_attested_inside_the_installed_plugin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _manager(enabled=True)
    observed_paths: list[str] = []

    async def fake_run(*args: str, **_kwargs: object):
        observed_paths.append(args[-1])
        return (
            0,
            json.dumps(
                {
                    "source_sha256": _CALLSITE_SOURCE_SHA256,
                    "source_size_bytes": 512,
                    "line_count": 80,
                }
            ),
            "",
        )

    monkeypatch.setattr(sandbox_module, "_run", fake_run)

    mapped = await manager._attest_php_object_callsite(_callsite())

    assert mapped == _CALLSITE_PATH
    assert observed_paths == [_CALLSITE_PATH]


@pytest.mark.asyncio
async def test_surface_guard_rejects_preflight_drift_and_still_restores_modes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _manager(enabled=True)
    operations: list[str] = []
    digest_values = {
        "entry_count": 12,
        "original_sha256": "1" * 64,
        "frozen_sha256": "2" * 64,
        "manifest_sha256": "3" * 64,
    }

    async def fake_run(*args: str, **_kwargs: object):
        operation = args[-3]
        operations.append(operation)
        assert args[-2] == _PLUGIN_SLUG
        assert sandbox_module._PHP_OBJECT_SURFACE_MANIFEST_RE.fullmatch(args[-1])
        if operation == "freeze":
            return 0, json.dumps({"operation": operation, **digest_values}), ""
        if operation == "attest":
            return 70, "", "surface_guard_failed"
        if operation == "restore":
            return (
                71,
                json.dumps(
                    {
                        "operation": "restore",
                        "entry_count": digest_values["entry_count"],
                        "original_sha256": digest_values["original_sha256"],
                        "drift_before_restore": True,
                        "restored": True,
                        "manifest_removed": True,
                    }
                ),
                "",
            )
        raise AssertionError(operation)

    monkeypatch.setattr(sandbox_module, "_run", fake_run)

    frozen = await manager._freeze_php_object_executable_surfaces()
    with pytest.raises(RuntimeError, match="attestation failed"):
        await manager._attest_php_object_executable_surfaces(frozen)
    with pytest.raises(RuntimeError, match="drift was detected"):
        await manager._restore_php_object_executable_surfaces(frozen)

    assert operations == ["freeze", "attest", "restore"]
    assert manager._php_object_surface_poisoned is False
    assert "hardlink" in sandbox_module._PHP_OBJECT_SURFACE_GUARD_SCRIPT
    assert "mu-plugins" in sandbox_module._PHP_OBJECT_SURFACE_GUARD_SCRIPT
    assert "themes" in sandbox_module._PHP_OBJECT_SURFACE_GUARD_SCRIPT


def test_surface_guard_takes_web_owned_entries_away_from_chmod_and_restores_owner() -> None:
    script = sandbox_module._PHP_OBJECT_SURFACE_GUARD_SCRIPT

    assert "@chown($entry['path'], 0)" in script
    assert "@chgrp($entry['path'], 0)" in script
    assert "@chown($entry['path'], $entry['uid'])" in script
    assert "@chgrp($entry['path'], $entry['gid'])" in script
    assert "$entry['uid'] = 0" in script
    assert "$entry['gid'] = 0" in script
    assert "$root . '/wp-admin'" in script
    assert "$root . '/wp-includes'" in script


@pytest.mark.asyncio
async def test_canary_install_is_collision_checked_root_owned_exact_and_linted(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    oracle = _oracle()
    source = oracle.private_canary_class_source
    expected_digest = hashlib.sha256(source).hexdigest()
    calls: list[tuple[str, ...]] = []
    actor_classes: list[str] = []

    class FakeWPCli:
        async def _exec_result(self, *args: str, **_kwargs: object):
            assert args[0] == "eval"
            assert _CLASS_NAME in args[1]
            return 0, "", ""

    async def fake_run(*args: str, **_kwargs: object):
        calls.append(args)
        if args[3:5] == ("test", "!"):
            return 0, "", ""
        if args[3:6] == ("stat", "-c", "%u:%g:%a:%s"):
            return 0, f"0:0:444:{len(source)}\n", ""
        if args[3] == "sha256sum":
            return 0, f"{expected_digest}  canary.php\n", ""
        return 0, "", ""

    async def fake_actor(class_name: str = "") -> None:
        actor_classes.append(class_name)

    async def fake_attest(_oracle_value: PhpObjectOracle) -> None:
        return None

    manager = _manager(enabled=True)
    manager.workdir = tmp_path
    manager.wp_cli = FakeWPCli()  # type: ignore[assignment]
    monkeypatch.setattr(sandbox_module, "_run", fake_run)
    monkeypatch.setattr(manager, "_install_actor_receipt_plugin", fake_actor)
    monkeypatch.setattr(manager, "_attest_php_object_oracle_plugin", fake_attest)

    await manager._install_php_object_oracle_plugin(oracle)

    destination = (
        "/var/www/html/wp-content/mu-plugins/"
        "squadrone-object-canary-0123456789abcdef0123456789abcdef.php"
    )
    assert actor_classes == [_CLASS_NAME]
    assert not (tmp_path / Path(destination).name).exists()
    assert (
        "docker",
        "exec",
        manager.container_name,
        "test",
        "!",
        "-e",
        destination,
    ) in calls
    assert (
        "docker",
        "exec",
        manager.container_name,
        "test",
        "!",
        "-L",
        destination,
    ) in calls
    assert (
        "docker",
        "exec",
        manager.container_name,
        "chown",
        "root:root",
        destination,
    ) in calls
    assert (
        "docker",
        "exec",
        manager.container_name,
        "chmod",
        "0444",
        destination,
    ) in calls
    assert (
        "docker",
        "exec",
        manager.container_name,
        "php",
        "-l",
        destination,
    ) in calls


@pytest.mark.asyncio
async def test_canary_attestation_rechecks_both_exact_mu_plugin_sources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    oracle = _oracle()
    manager = _manager(enabled=True)
    canary_source = oracle.private_canary_class_source
    actor_source = sandbox_module.Template(
        sandbox_module._ACTOR_RECEIPT_TEMPLATE.read_text()
    ).render(
        trace_token=manager._trace_token,
        receipt_secret=manager._receipt_secret.hex(),
        php_object_canary_class=_CLASS_NAME,
    ).encode()
    wp_evals: list[str] = []

    class FakeWPCli:
        async def _exec_result(self, *args: str, **_kwargs: object):
            wp_evals.append(args[1])
            return 0, "", ""

    async def fake_run(*args: str, **_kwargs: object):
        if args[3:] == ("id", "-g", "www-data"):
            return 0, "82\n", ""
        if args[3:6] == ("stat", "-c", "%u:%g:%a:%s"):
            return (
                0,
                "0:82:1775:4096\n"
                f"0:0:444:{len(actor_source)}\n"
                f"0:0:444:{len(canary_source)}\n",
                "",
            )
        if args[3] == "sha256sum":
            return (
                0,
                f"{hashlib.sha256(actor_source).hexdigest()}  actor.php\n"
                f"{hashlib.sha256(canary_source).hexdigest()}  canary.php\n",
                "",
            )
        raise AssertionError(args)

    manager.wp_cli = FakeWPCli()  # type: ignore[assignment]
    monkeypatch.setattr(sandbox_module, "_run", fake_run)

    await manager._attest_php_object_oracle_plugin(oracle)

    assert len(wp_evals) == 1
    assert _CLASS_NAME in wp_evals[0]
    assert "consumeReceipt" in wp_evals[0]
    assert "resetReceipt" in wp_evals[0]


@pytest.mark.asyncio
async def test_cleanup_refuses_to_delete_an_unrecognized_collision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []

    async def fake_run(*args: str, **_kwargs: object):
        calls.append(args)
        if len(args) > 6 and args[3:6] == ("test", "!", "-L"):
            return 0, "", ""
        if args[3] == "sha256sum":
            return 0, ("0" * 64) + "  collision.php\n", ""
        return 0, "", ""

    manager = _manager(enabled=True)
    monkeypatch.setattr(sandbox_module, "_run", fake_run)

    with pytest.raises(RuntimeError, match="unrecognized canary collision"):
        await manager._remove_php_object_oracle_plugin(_oracle())

    assert not any(len(call) > 3 and call[3] == "rm" for call in calls)


def _actor_receipt(
    record: dict[str, object],
    *,
    user_id: int,
    roles: list[str],
) -> str:
    sequence = record["sequence"]
    assert isinstance(sequence, int) and not isinstance(sequence, bool)
    payload = {
        "v": 2,
        "trace_token": _TRACE_TOKEN,
        "nonce": f"{sequence + 100:032x}",
        "request_nonce": record["request_nonce"],
        "request_digest": record["request_digest"],
        "user_id": user_id,
        "roles": roles,
        "method": record["method"],
        "path": record["path"],
    }
    encoded = (
        base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        )
        .decode("ascii")
        .rstrip("=")
    )
    signature = hmac.new(
        _TRACE_SECRET,
        encoded.encode("ascii"),
        hashlib.sha256,
    ).hexdigest()
    return f"{encoded}.{signature}"


class _InMemoryObjectProxy(PocProxySupervisor):
    def __init__(
        self,
        oracle: PhpObjectOracle,
        policy: PhpObjectRewritePolicy,
        *,
        user_id: int,
        roles: list[str],
    ) -> None:
        super().__init__(
            _TARGET_URL,
            trace_token=_TRACE_TOKEN,
            trace_salt=_TRACE_SALT,
            php_object_oracle=oracle,
            php_object_policy=policy,
            php_object_surface_attestor=_accept_surface_attestation,
        )
        self.oracle = oracle
        self.user_id = user_id
        self.roles = roles

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
        del method, url, headers, nonce, request_digest, credential_free_headers
        payload = parse_qs(body.decode("ascii"), strict_parsing=True)[
            "serialized_payload"
        ][0]
        response_headers = [
            (
                ACTOR_RECEIPT_HEADER,
                _actor_receipt(
                    record,
                    user_id=self.user_id,
                    roles=self.roles,
                ),
            )
        ]
        if payload.startswith("O:"):
            response_headers.append(
                (PHP_OBJECT_RECEIPT_HEADER, self.oracle.private_expected_receipt)
            )
        response = httpx.Response(200, headers=response_headers, content=b"handled")
        return response, response.content


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("attacker_role", "attacker_user_id", "user_id", "roles"),
    [
        ("unauthenticated", "anonymous", 0, []),
        ("subscriber", "17", 17, ["subscriber"]),
    ],
)
async def test_object_trace_binds_parent_rewrite_receipt_actor_and_control(
    attacker_role: str,
    attacker_user_id: str,
    user_id: int,
    roles: list[str],
) -> None:
    oracle = _oracle()
    generation_id = oracle.begin_generation()
    policy = PhpObjectRewritePolicy(
        method="POST",
        path=_ROUTE,
        object_location="form",
        object_field="serialized_payload",
        dispatch=(("form", "action", "process_submission"),),
    )
    proxy = _InMemoryObjectProxy(
        oracle,
        policy,
        user_id=user_id,
        roles=roles,
    )
    headers = [
        ("Host", "localhost:8123"),
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Accept", "*/*"),
    ]
    raw_headers = "\r\n".join(f"{name}: {value}" for name, value in headers)
    for token in (
        oracle.public_context()["attack_token"],
        oracle.public_context()["control_token"],
    ):
        body = urlencode(
            {"action": "process_submission", "serialized_payload": token}
        ).encode("ascii")
        flags, categories = classify_request_sentinels(
            _ROUTE.encode("ascii"), raw_headers.encode("latin-1"), body
        )
        response, _body, status, detail = await proxy._execute_accepted_request(
            method="POST",
            url=f"{_TARGET_URL}{_ROUTE}",
            path=_ROUTE,
            raw_target=_ROUTE,
            headers=headers,
            body=body,
            sentinel_flags=flags,
            sentinel_categories=categories,
        )
        assert response is not None
        assert status == 0
        assert detail == ""

    private = proxy.take_php_object_observation()
    assert private is not None
    snapshot = oracle.attest_execution(
        generation_id=generation_id,
        attack_token=private.attack_token,
        control_token=private.control_token,
        attack_receipt=private.attack_receipt,
        control_receipt=private.control_receipt,
        execution_started_monotonic_ns=private.execution_started_monotonic_ns,
        execution_finished_monotonic_ns=private.execution_finished_monotonic_ns,
        attested_monotonic_ns=time.monotonic_ns(),
    )

    accepted, reason, evidence = validate_php_object_http_trace(
        _observation(
            attacker_role=attacker_role,
            attacker_user_id=attacker_user_id,
        ),
        proxy.records,
        target_url=_TARGET_URL,
        receipt_secret=_TRACE_SECRET,
        trace_token=_TRACE_TOKEN,
        policy=policy,
        snapshot=snapshot,
        expected_attacker_role=attacker_role,
        trace_error="",
    )

    assert accepted is True, reason
    assert evidence["oracle"] == "object_instantiation"
    serialized = json.dumps(evidence, sort_keys=True)
    assert _CLASS_NAME not in serialized
    assert oracle.private_expected_receipt not in serialized
    assert oracle.public_context()["attack_token"] not in serialized


def test_object_observation_rejects_claims_beyond_the_inert_integrity_primitive() -> None:
    observation = _observation()

    accepted, reason = validate_poc_observation(
        observation,
        expected_bug_class="CWE-502",
        expected_attacker_role="unauthenticated",
    )
    assert accepted is True, reason

    overstated = observation.model_copy(deep=True)
    overstated.impact.availability = "low"
    accepted, reason = validate_poc_observation(
        overstated,
        expected_bug_class="CWE-502",
        expected_attacker_role="unauthenticated",
    )
    assert accepted is False
    assert "proves only integrity=low" in reason


@pytest.mark.asyncio
async def test_run_poc_rotates_private_generations_under_strict_isolation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    oracle = _oracle()
    manager = _manager(enabled=True)
    manager._booted = True
    manager.workdir = tmp_path
    manager.target_url = _TARGET_URL
    manager._php_object_oracle = oracle
    manager._php_object_callsite = _callsite()
    observed_constructor_options: list[dict[str, object]] = []
    surface_events: list[str] = []

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
        php_object_complete = True

        def __init__(self, *_args: object, **kwargs: object) -> None:
            observed_constructor_options.append(kwargs)
            assert kwargs.get("php_object_oracle") is oracle
            assert isinstance(
                kwargs.get("php_object_policy"), PhpObjectRewritePolicy
            )
            assert kwargs.get("credential_free", False) is False
            self._surface_attestor = kwargs.get("php_object_surface_attestor")
            assert callable(self._surface_attestor)
            self._taken = False

        async def __aenter__(self):  # type: ignore[no-untyped-def]
            for phase, arm in sandbox_module._PHP_OBJECT_SURFACE_ATTESTATION_ORDER:
                await self._surface_attestor(phase, arm)
            return self

        async def __aexit__(self, *_exc_info: object) -> None:
            return None

        def take_php_object_observation(self) -> PhpObjectProxyObservation | None:
            if self._taken:
                return None
            self._taken = True
            context = oracle.public_context()
            now = time.monotonic_ns()
            return PhpObjectProxyObservation(
                generation_id=oracle.generation_id,
                attack_token=context["attack_token"],
                control_token=context["control_token"],
                attack_receipt=oracle.private_expected_receipt,
                control_receipt=None,
                execution_started_monotonic_ns=now,
                execution_finished_monotonic_ns=time.monotonic_ns(),
            )

    async def create(*_args: object, **_kwargs: object) -> Process:
        return Process()

    async def communicate(_process: Process) -> tuple[bytes, bytes]:
        observation = _observation().model_dump(mode="json")
        output = (
            oracle.private_attack_payload.decode("ascii")
            + "\n"
            + POC_RESULT_PREFIX
            + json.dumps(observation, separators=(",", ":"))
            + "\n"
        )
        return output.encode(), b""

    async def kill(_process: Process) -> None:
        return None

    async def attest(_oracle_value: PhpObjectOracle) -> None:
        return None

    async def attest_callsite(_value: PhpObjectCallsite) -> str:
        return _CALLSITE_PATH

    frozen = sandbox_module._PhpObjectSurfaceFreeze(
        manifest_path=(
            "/tmp/squadrone-object-surfaces-"
            "0123456789abcdef0123456789abcdef.json"
        ),
        entry_count=3,
        original_sha256="1" * 64,
        frozen_sha256="2" * 64,
        manifest_sha256="3" * 64,
    )

    async def freeze_surfaces():  # type: ignore[no-untyped-def]
        surface_events.append("freeze")
        return frozen

    async def attest_surfaces(_value):  # type: ignore[no-untyped-def]
        surface_events.append("attest")

    async def restore_surfaces(_value):  # type: ignore[no-untyped-def]
        surface_events.append("restore")

    @contextlib.contextmanager
    def prepare(*_args: object, **_kwargs: object):  # type: ignore[no-untyped-def]
        yield Isolation()

    monkeypatch.setattr(sandbox_module, "PocProxySupervisor", Proxy)
    monkeypatch.setattr(sandbox_module, "prepare_poc_isolation", prepare)
    monkeypatch.setattr(sandbox_module.asyncio, "create_subprocess_exec", create)
    monkeypatch.setattr(sandbox_module, "_communicate_poc_bounded", communicate)
    monkeypatch.setattr(sandbox_module, "_kill_poc_process_group", kill)
    monkeypatch.setattr(manager, "_attest_php_object_oracle_plugin", attest)
    monkeypatch.setattr(manager, "_attest_php_object_callsite", attest_callsite)
    monkeypatch.setattr(
        manager,
        "_freeze_php_object_executable_surfaces",
        freeze_surfaces,
    )
    monkeypatch.setattr(
        manager,
        "_attest_php_object_executable_surfaces",
        attest_surfaces,
    )
    monkeypatch.setattr(
        manager,
        "_restore_php_object_executable_surfaces",
        restore_surfaces,
    )
    monkeypatch.setattr(
        sandbox_module,
        "validate_php_object_http_trace",
        lambda *_args, **_kwargs: (True, "trusted object trace passed", {}),
    )
    transport: dict[str, object] = {
        "method": "POST",
        "route": _ROUTE,
        "object_location": "form",
        "object_field": "serialized_payload",
        "dispatch": {"form:action": "process_submission"},
    }

    first_result = await manager.run_poc(
        "/generated/poc.py",
        expected_bug_class="CWE-502",
        expected_attacker_role="unauthenticated",
        expected_php_object=True,
        expected_php_object_transport=transport,
    )
    first_snapshot = first_result.take_trusted_php_object_snapshot()
    second_result = await manager.run_poc(
        "/generated/poc.py",
        expected_bug_class="CWE-502",
        expected_attacker_role="unauthenticated",
        expected_php_object=True,
        expected_php_object_transport=transport,
    )
    second_snapshot = second_result.take_trusted_php_object_snapshot()

    assert first_result.success is True
    assert second_result.success is True
    assert "php_object_trusted_parent_diagnostic" not in first_result.evidence
    assert "php_object_trusted_parent_diagnostic" not in second_result.evidence
    assert first_snapshot is not None
    assert second_snapshot is not None
    assert (
        first_snapshot.generation_id_sha256
        != second_snapshot.generation_id_sha256
    )
    assert (
        first_snapshot.execution.attack_token_sha256
        == second_snapshot.execution.attack_token_sha256
    )
    assert (
        first_snapshot.execution.attack_payload_sha256
        != second_snapshot.execution.attack_payload_sha256
    )
    assert _CLASS_NAME not in first_result.model_dump_json()
    assert oracle.private_attack_payload.decode("ascii") not in (
        second_result.model_dump_json()
    )
    assert len(observed_constructor_options) == 2
    assert surface_events.count("freeze") == 2
    assert surface_events.count("attest") == 10
    assert surface_events.count("restore") == 2
