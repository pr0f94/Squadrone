from __future__ import annotations

import hashlib
import json
from importlib.resources import files
from pathlib import Path

import pytest
from jinja2 import Template

import squadrone.services.sandbox as sandbox_module
from squadrone.schemas.config import SandboxConfig
from squadrone.schemas.observation import CIAImpact, PoCObservation
from squadrone.schemas.php_object_gadget import (
    PhpObjectGadgetDirectPathEffectBinding,
    PhpObjectGadgetObject,
    PhpObjectGadgetProperty,
    PhpObjectGadgetRecipe,
    PhpObjectGadgetSourceAnchor,
    PhpObjectGadgetValue,
)
from squadrone.services.php_object_gadget_oracle import (
    PhpObjectGadgetOracleSnapshot,
)
from squadrone.services.sandbox import (
    _PHP_OBJECT_GADGET_RUNTIME_SCRIPT,
    SandboxManager,
    SandboxRunResult,
    _inspect_php_object_gadget_runtime,
    _validate_php_object_gadget_measurement_payload,
    _validate_php_object_gadget_runtime_payload,
    php_object_gadget_private_redaction_values,
    strip_php_object_gadget_child_claims,
)


def _recipe() -> PhpObjectGadgetRecipe:
    effect = PhpObjectGadgetSourceAnchor(
        file="gadget.php",
        line=4,
        source_code="unlink($this->path);",
    )
    return PhpObjectGadgetRecipe(
        gadget_object=PhpObjectGadgetObject(
            class_name="ReviewedGadget",
            class_anchor=PhpObjectGadgetSourceAnchor(
                file="gadget.php",
                line=1,
                source_code="class ReviewedGadget",
            ),
            trigger="__destruct",
            trigger_declaring_class="ReviewedGadget",
            trigger_anchor=PhpObjectGadgetSourceAnchor(
                file="gadget.php",
                line=3,
                source_code="function __destruct() {\n    unlink($this->path);\n}",
            ),
            properties=(
                PhpObjectGadgetProperty(
                    name="path",
                    declaring_class="ReviewedGadget",
                    visibility="public",
                    value=PhpObjectGadgetValue(
                        kind="capability",
                        capability="ephemeral_file_path",
                    ),
                ),
            ),
        ),
        effect_binding=PhpObjectGadgetDirectPathEffectBinding(
            effect_property="path",
            access="property",
            effect_anchor=effect,
        ),
    )


def _config() -> SandboxConfig:
    return SandboxConfig(
        wordpress_image="wordpress:latest",
        db_image="mariadb:10.11",
        wp_admin_user="admin",
        wp_admin_pass="password",
        wp_admin_email="admin@example.test",
        database_name="wordpress",
        database_user="wpuser",
        database_password="wppass",
    )


def _render_compose(
    *,
    enabled: bool,
    constants: tuple[str, ...] = (),
) -> str:
    source = (files("squadrone.docker") / "docker-compose.yml.j2").read_text()
    return Template(source).render(
        port=8123,
        wp_url="http://localhost:8123",
        wp_title="test",
        wp_admin_user="admin",
        wp_admin_pass="password",
        wp_admin_email="admin@example.test",
        enable_http_ssrf=False,
        enable_local_resource_ssrf=False,
        enable_php_include_oracle=False,
        enable_php_object_gadget_oracle=enabled,
        php_object_gadget_directory_constants=constants,
        bootstrap_network_name="squadrone-test-bootstrap",
    )


def test_gadget_tmpfs_and_generic_constant_overrides_are_conditional() -> None:
    constants = ("CACHE_ROOT", "K_PATH_CACHE")
    disabled = _render_compose(enabled=False, constants=constants)
    enabled = _render_compose(enabled=True, constants=constants)

    assert "/var/lib/squadrone/php-object-gadget" not in disabled
    assert "K_PATH_CACHE" not in disabled
    assert "CACHE_ROOT" not in disabled
    assert 'TMPDIR: "/var/lib/squadrone/php-object-gadget"' in enabled
    assert "tmpfs:" in enabled
    assert "define('K_PATH_CACHE'" in enabled
    assert "define('CACHE_ROOT'" in enabled


def test_gadget_directory_constants_are_strict_constructor_input() -> None:
    for invalid_constants in (
        frozenset({"cache_root"}),
        frozenset({"ABSPATH"}),
    ):
        with pytest.raises(ValueError, match="bounded frozenset"):
            SandboxManager(
                _config(),
                php_object_oracle_enabled=True,
                php_object_gadget_oracle_enabled=True,
                php_object_gadget_directory_constants=invalid_constants,
            )
    with pytest.raises(ValueError, match="require the gadget oracle"):
        SandboxManager(
            _config(),
            php_object_gadget_directory_constants=frozenset({"CACHE_ROOT"}),
        )

    boundary = frozenset(f"CACHE_ROOT_{index}" for index in range(17))
    manager = SandboxManager(
        _config(),
        php_object_oracle_enabled=True,
        php_object_gadget_oracle_enabled=True,
        php_object_gadget_directory_constants=boundary,
    )
    assert manager._php_object_gadget_directory_constants == tuple(sorted(boundary))
    with pytest.raises(ValueError, match="bounded frozenset"):
        SandboxManager(
            _config(),
            php_object_oracle_enabled=True,
            php_object_gadget_oracle_enabled=True,
            php_object_gadget_directory_constants=frozenset(
                f"CACHE_ROOT_{index}" for index in range(18)
            ),
        )


def test_gadget_flag_requires_the_inert_primitive_flag() -> None:
    with pytest.raises(ValueError, match="requires the primitive"):
        SandboxManager(_config(), php_object_gadget_oracle_enabled=True)


def test_runtime_payload_is_exact_and_binds_the_typed_recipe() -> None:
    recipe = _recipe()
    payload = {
        "source_inventory_sha256": "11" * 32,
        "reflection_sha256": "22" * 32,
        "source_file_count": 1,
        "source_anchor_count": 3,
        "property_count": 1,
    }
    binding = _validate_php_object_gadget_runtime_payload(
        payload,
        recipe=recipe,
        effect_binding_kind="direct_path",
    )

    assert binding.effect_binding_kind == "direct_path"
    payload["unexpected"] = True
    with pytest.raises(RuntimeError, match="malformed"):
        _validate_php_object_gadget_runtime_payload(
            payload,
            recipe=recipe,
            effect_binding_kind="direct_path",
        )


@pytest.mark.parametrize("mutation", ["detached", "extra_sink"])
def test_runtime_payload_rejects_unaccounted_or_detached_unlink(
    mutation: str,
) -> None:
    recipe = _recipe()
    if mutation == "detached":
        detached = recipe.effect_binding.effect_anchor.model_copy(
            update={"line": 40}
        )
        binding = recipe.effect_binding.model_copy(
            update={"effect_anchor": detached}
        )
        recipe = recipe.model_copy(update={"effect_binding": binding})
    else:
        trigger = recipe.gadget_object.trigger_anchor.model_copy(
            update={
                "source_code": (
                    "function __destruct() {\n"
                    "    unlink($this->path);\n"
                    "    unlink($this->unreviewed);\n"
                    "}"
                )
            }
        )
        gadget = recipe.gadget_object.model_copy(update={"trigger_anchor": trigger})
        recipe = recipe.model_copy(update={"gadget_object": gadget})
    payload = {
        "source_inventory_sha256": "11" * 32,
        "reflection_sha256": "22" * 32,
        "source_file_count": 1,
        "source_anchor_count": 3,
        "property_count": 1,
    }

    with pytest.raises(RuntimeError, match="malformed"):
        _validate_php_object_gadget_runtime_payload(
            payload,
            recipe=recipe,
            effect_binding_kind="direct_path",
        )


def _measurement_payload() -> tuple[dict[str, object], str]:
    target = "/var/lib/squadrone/php-object-gadget/squadrone-" + "a" * 64
    return (
        {
            "operation": "measure",
            "target_path_sha256": hashlib.sha256(target.encode("ascii")).hexdigest(),
            "target_exists": True,
            "target_regular": True,
            "target_symlink": False,
            "target_content_sha256": "33" * 32,
            "target_size_bytes": 32,
            "target_uid": 33,
            "target_gid": 33,
            "target_mode": 0o600,
            "target_inode": 123,
            "target_link_count": 1,
            "directory_entry_count": 1,
            "directory_inventory_sha256": "44" * 32,
            "directory_uid": 0,
            "directory_gid": 33,
            "directory_mode": 0o770,
        },
        target,
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("target_symlink", True),
        ("target_link_count", 2),
        ("target_mode", 0o644),
        ("directory_uid", 33),
        ("directory_gid", 0),
        ("directory_mode", 0o777),
    ),
)
def test_target_measurement_rejects_symlink_hardlink_and_mode_drift(
    field: str,
    value: object,
) -> None:
    payload, target = _measurement_payload()
    payload[field] = value

    with pytest.raises(RuntimeError, match="unsafe"):
        _validate_php_object_gadget_measurement_payload(
            payload,
            target_path=target,
        )


def test_natural_snapshot_slot_is_take_once_and_nonserializing() -> None:
    result = SandboxRunResult(success=True, output="", elapsed=0)
    placeholder = object()
    result.retain_trusted_php_object_gadget_snapshot(
        placeholder  # type: ignore[arg-type]
    )

    assert "trusted_php_object_gadget" not in result.model_dump_json()
    assert result.take_trusted_php_object_gadget_snapshot() is placeholder
    assert result.take_trusted_php_object_gadget_snapshot() is None


def test_snapshot_slot_annotation_is_the_typed_snapshot() -> None:
    annotations = (
        SandboxRunResult.take_trusted_php_object_gadget_snapshot.__annotations__
    )
    assert "PhpObjectGadgetOracleSnapshot" in str(annotations["return"])
    assert PhpObjectGadgetOracleSnapshot.__name__ in str(annotations["return"])


def test_natural_result_strips_reused_child_object_claim_from_every_surface() -> None:
    observation = PoCObservation(
        verdict="vulnerable",
        oracle="object_instantiation",
        attacker_role="subscriber",
        request={},
        attack={"marker": "stale-child-claim"},
        control={},
        impact=CIAImpact(integrity="low"),
    )
    machine_line = "SQUADRONE_RESULT=" + observation.model_dump_json()
    result = SandboxRunResult(
        success=True,
        output=f"ordinary diagnostic\n{machine_line}\nfinished",
        # Model the real response tail starting in the middle of an overlong
        # machine line, where the identifying prefix is no longer present.
        response=machine_line[-40:],
        error_log=f"warning\n{machine_line}\nwarning two",
        elapsed=0,
        observation=observation,
        evidence={
            "observation": observation.model_dump(mode="json"),
            "rejected_observation": None,
            "observation_disposition": "accepted",
            "stdout_tail": machine_line,
        },
    )

    strip_php_object_gadget_child_claims(result)

    assert result.observation is None
    assert result.rejected_observation is None
    assert result.output == "ordinary diagnostic\nfinished"
    assert result.response == result.output
    assert result.error_log == "warning\nwarning two"
    assert result.evidence["observation"] is None
    assert result.evidence["rejected_observation"] is None
    assert result.evidence["observation_disposition"] == "parent_attestation_only"
    assert result.evidence["stdout_tail"] == result.output
    serialized = result.model_dump_json()
    assert "SQUADRONE_RESULT" not in serialized
    assert "object_instantiation" not in serialized
    assert "stale-child-claim" not in serialized


@pytest.mark.asyncio
async def test_clean_state_sequence_is_identical_for_attack_and_control(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager = SandboxManager(
        _config(),
        php_object_oracle_enabled=True,
        php_object_gadget_oracle_enabled=True,
    )
    events: list[str] = []
    runtime_binding = object()

    class FakeOracle:
        recipe = _recipe()

        @property
        def runtime_binding(self) -> object:
            return runtime_binding

    async def restore(snapshot_dir: Path) -> None:
        assert snapshot_dir == tmp_path
        events.append("restore")

    async def restart() -> None:
        events.append("restart")

    async def attest(recipe: PhpObjectGadgetRecipe) -> object:
        assert recipe is FakeOracle.recipe
        events.append("attest")
        return runtime_binding

    async def cleanup(*, require_empty: bool) -> None:
        assert require_empty is True
        events.append("cleanup")

    monkeypatch.setattr(manager, "restore", restore)
    monkeypatch.setattr(manager, "restart_wordpress_runtime", restart)
    monkeypatch.setattr(manager, "_attest_php_object_gadget_recipe", attest)
    monkeypatch.setattr(manager, "_cleanup_php_object_gadget_directory", cleanup)

    oracle = FakeOracle()
    await manager._restore_php_object_gadget_clean_state(  # type: ignore[arg-type]
        tmp_path,
        oracle,
        require_empty_tmpfs=True,
    )
    await manager._restore_php_object_gadget_clean_state(  # type: ignore[arg-type]
        tmp_path,
        oracle,
        require_empty_tmpfs=True,
    )

    assert events == ["restore", "restart", "attest", "cleanup"] * 2


@pytest.mark.asyncio
async def test_failed_recovery_retains_sensitive_snapshot_for_teardown(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager = SandboxManager(
        _config(),
        php_object_oracle_enabled=True,
        php_object_gadget_oracle_enabled=True,
    )
    snapshot_dir = tmp_path / "retained"
    snapshot_dir.mkdir()
    manager._snapshot_dirs.add(snapshot_dir)
    discarded = False

    class FakeOracle:
        recipe = _recipe()
        runtime_binding = object()

    async def fail_restore(_snapshot_dir: Path) -> None:
        raise RuntimeError("restore failed")

    def discard(_snapshot_dir: Path) -> None:
        nonlocal discarded
        discarded = True

    monkeypatch.setattr(manager, "restore", fail_restore)
    monkeypatch.setattr(manager, "_discard_php_object_gadget_snapshot", discard)

    with pytest.raises(RuntimeError, match="restore failed"):
        await manager._recover_and_discard_php_object_gadget_snapshot(  # type: ignore[arg-type]
            snapshot_dir,
            FakeOracle(),
        )

    assert discarded is False
    assert snapshot_dir in manager._snapshot_dirs
    assert snapshot_dir.is_dir()


@pytest.mark.asyncio
async def test_recipe_constant_set_must_exactly_match_its_dedicated_sandbox() -> None:
    manager = SandboxManager(
        _config(),
        php_object_oracle_enabled=True,
        php_object_gadget_oracle_enabled=True,
        php_object_gadget_directory_constants=frozenset({"CACHE_ROOT"}),
    )
    manager.container_name = "sandbox-wordpress-1"
    manager._installed_plugin_slug = "example-plugin"

    with pytest.raises(RuntimeError, match="constant configuration changed"):
        await manager._attest_php_object_gadget_recipe(_recipe())


@pytest.mark.asyncio
async def test_runtime_inspection_uses_root_source_bookends_and_web_actor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = {
        "source_inventory_sha256": "11" * 32,
        "source_file_count": 1,
        "source_anchor_count": 3,
    }
    runtime = {
        **source,
        "reflection_sha256": "22" * 32,
        "property_count": 1,
    }
    responses = [source, runtime, source]
    calls: list[tuple[str, ...]] = []

    async def fake_run(*args: str, **_kwargs: object) -> tuple[int, str, str]:
        calls.append(args)
        return 0, json.dumps(responses.pop(0)), ""

    monkeypatch.setattr(sandbox_module, "_run", fake_run)

    observed = await _inspect_php_object_gadget_runtime(
        "sandbox-wordpress-1",
        "example-plugin",
        _recipe(),
    )

    assert observed == runtime
    assert [call[3] for call in calls] == ["root", "www-data", "root"]


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["runtime", "after"])
async def test_runtime_inspection_rejects_source_identity_drift(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    source = {
        "source_inventory_sha256": "11" * 32,
        "source_file_count": 1,
        "source_anchor_count": 3,
    }
    runtime = {
        **source,
        "reflection_sha256": "22" * 32,
        "property_count": 1,
    }
    after = dict(source)
    if mutation == "runtime":
        runtime["source_inventory_sha256"] = "33" * 32
    else:
        after["source_inventory_sha256"] = "44" * 32
    responses = [source, runtime, after]

    async def fake_run(*_args: str, **_kwargs: object) -> tuple[int, str, str]:
        return 0, json.dumps(responses.pop(0)), ""

    monkeypatch.setattr(sandbox_module, "_run", fake_run)

    with pytest.raises(RuntimeError, match="source changed|attestation failed"):
        await _inspect_php_object_gadget_runtime(
            "sandbox-wordpress-1",
            "example-plugin",
            _recipe(),
        )


def test_runtime_rejects_all_unreviewed_magic_and_binds_static_marker_pair() -> None:
    script = _PHP_OBJECT_GADGET_RUNTIME_SCRIPT

    assert "$candidate_name !== '__construct'" in script
    assert "$candidate_name !== strtolower($trigger_name)" in script
    assert "throw new RuntimeException('magic')" in script
    assert "self::\\$([A-Za-z_][A-Za-z0-9_]*)" in script
    assert "\\$this\\s*->\\s*'" in script
    assert "opaque_property" in script
    assert "$declaring->getName() !== $class->getName()" in script
    assert "! is_array($defaults[$name])" in script
    assert "! is_array($property->getValue())" in script


@pytest.mark.asyncio
async def test_authenticated_natural_gadget_run_fails_before_execution() -> None:
    manager = SandboxManager(
        _config(),
        php_object_oracle_enabled=True,
        php_object_gadget_oracle_enabled=True,
    )

    result = await manager.run_poc(
        "/does/not/exist.py",
        expected_bug_class="CWE-502",
        expected_attacker_role="subscriber",
        expected_php_object_gadget=True,
        expected_php_object_transport={},
    )

    assert result.success is False
    assert "limited to the exact unauthenticated" in result.validation_reason
    assert result.evidence["php_object_oracle_error"] == (
        "authenticated_transport_rejected"
    )


def test_natural_redaction_includes_in_process_actor_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = bytes.fromhex("42" * 32)

    class FakeOracle:
        @staticmethod
        def private_redaction_values() -> tuple[str, ...]:
            return ("private-oracle-value",)

    monkeypatch.setattr(
        sandbox_module,
        "php_object_private_redaction_values",
        lambda _primitive: (),
    )

    values = php_object_gadget_private_redaction_values(  # type: ignore[arg-type]
        FakeOracle(),
        object(),
        secret,
    )

    assert secret.hex() in values
    assert "private-oracle-value" in values
