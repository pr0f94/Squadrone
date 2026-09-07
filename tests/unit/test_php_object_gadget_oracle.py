from __future__ import annotations

import hashlib
import json
import time
from dataclasses import replace

import pytest

from squadrone.schemas.php_object_gadget import (
    PhpObjectGadgetDirectPathEffectBinding,
    PhpObjectGadgetObject,
    PhpObjectGadgetProperty,
    PhpObjectGadgetRecipe,
    PhpObjectGadgetSourceAnchor,
    PhpObjectGadgetValue,
)
from squadrone.services.php_object_gadget_oracle import (
    PHP_OBJECT_GADGET_ORACLE_SCHEMA_VERSION,
    PhpObjectGadgetFileMeasurement,
    PhpObjectGadgetOracle,
    PhpObjectGadgetRuntimeBinding,
    PhpObjectGadgetTransportAttestation,
    php_object_gadget_snapshot_from_dict,
    php_object_gadget_recipe_sha256,
    validate_persisted_php_object_gadget_confirmation,
    validate_php_object_gadget_snapshot_pair,
)
from squadrone.services.php_object_oracle import (
    PhpObjectOracle,
    PhpObjectOracleSnapshot,
)


def _recipe() -> PhpObjectGadgetRecipe:
    return PhpObjectGadgetRecipe(
        gadget_object=PhpObjectGadgetObject(
            class_name="ReviewedFileGadget",
            class_anchor=PhpObjectGadgetSourceAnchor(
                file="includes/gadget.php",
                line=3,
                source_code="class ReviewedFileGadget",
            ),
            trigger="__destruct",
            trigger_declaring_class="ReviewedFileGadget",
            trigger_anchor=PhpObjectGadgetSourceAnchor(
                file="includes/gadget.php",
                line=8,
                source_code=(
                    "public function __destruct() {\n    unlink($this->path);\n}"
                ),
            ),
            properties=(
                PhpObjectGadgetProperty(
                    name="path",
                    declaring_class="ReviewedFileGadget",
                    visibility="protected",
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
            effect_anchor=PhpObjectGadgetSourceAnchor(
                file="includes/gadget.php",
                line=9,
                source_code="unlink($this->path);",
            ),
        ),
    )


def _primitive() -> tuple[PhpObjectOracleSnapshot, str, str]:
    oracle = PhpObjectOracle(
        callsite_path=("/var/www/html/wp-content/plugins/example/includes/storage.php"),
        callsite_start_line=40,
        callsite_end_line=44,
        callsite_source_sha256="7a" * 32,
        class_name="SquadroneObjectCanary_0123456789abcdef0123456789abcdef",
        receipt_secret=bytes.fromhex("24" * 32),
    )
    generation = oracle.begin_generation()
    context = oracle.public_context()
    started = time.monotonic_ns()
    snapshot = oracle.attest_execution(
        generation_id=generation,
        attack_token=context["attack_token"],
        control_token=context["control_token"],
        attack_receipt=oracle.private_expected_receipt,
        control_receipt=None,
        execution_started_monotonic_ns=started,
        execution_finished_monotonic_ns=time.monotonic_ns(),
        attested_monotonic_ns=time.monotonic_ns(),
    )
    return snapshot, context["attack_token"], context["control_token"]


def _binding(recipe: PhpObjectGadgetRecipe) -> PhpObjectGadgetRuntimeBinding:
    return PhpObjectGadgetRuntimeBinding(
        schema_version=PHP_OBJECT_GADGET_ORACLE_SCHEMA_VERSION,
        mode="php_object_gadget_file_delete",
        effect="file_delete",
        effect_binding_kind="direct_path",
        recipe_sha256=php_object_gadget_recipe_sha256(recipe),
        source_inventory_sha256="11" * 32,
        reflection_sha256="22" * 32,
        source_file_count=1,
        source_anchor_count=4,
        property_count=1,
        all_effect_sinks_accounted=True,
    )


def _oracle() -> PhpObjectGadgetOracle:
    recipe = _recipe()
    primitive, attack_token, control_token = _primitive()
    return PhpObjectGadgetOracle(
        recipe=recipe,
        primitive_snapshot=primitive,
        attack_token=attack_token,
        control_token=control_token,
        runtime_binding=_binding(recipe),
        receipt_secret=bytes.fromhex("42" * 32),
    )


def _measurement(
    oracle: PhpObjectGadgetOracle,
    *,
    exists: bool,
    inode: int = 700,
) -> PhpObjectGadgetFileMeasurement:
    content_hash = hashlib.sha256(oracle.private_target_content).hexdigest()
    return PhpObjectGadgetFileMeasurement(
        target_path_sha256=hashlib.sha256(
            oracle.private_target_path.encode("ascii")
        ).hexdigest(),
        target_exists=exists,
        target_regular=exists,
        target_symlink=False,
        target_content_sha256=content_hash if exists else None,
        target_size_bytes=len(oracle.private_target_content) if exists else None,
        target_uid=33 if exists else None,
        target_gid=33 if exists else None,
        target_mode=0o600 if exists else None,
        target_inode=inode if exists else None,
        target_link_count=1 if exists else None,
        directory_entry_count=1 if exists else 0,
        directory_inventory_sha256=("33" * 32 if exists else "44" * 32),
        directory_uid=0,
        directory_gid=33,
        directory_mode=0o770,
        directory_is_tmpfs=True,
    )


def _finalize(oracle: PhpObjectGadgetOracle):  # type: ignore[no-untyped-def]
    generation = oracle.begin_generation()
    attack_before = _measurement(oracle, exists=True, inode=700)
    attack_after = _measurement(oracle, exists=False)
    control_before = _measurement(oracle, exists=True, inode=701)
    control_after = control_before
    oracle.attest_effect(
        attack_before=attack_before,
        attack_after=attack_after,
        control_before=control_before,
        control_after=control_after,
        state_restored_before_control=True,
        runtime_restarted_before_control=True,
        state_restored_after_control=True,
        runtime_restarted_after_control=True,
    )
    context = oracle.public_context()
    now = time.monotonic_ns()
    transport = PhpObjectGadgetTransportAttestation(
        schema_version=PHP_OBJECT_GADGET_ORACLE_SCHEMA_VERSION,
        mode="php_object_gadget_file_delete",
        effect="file_delete",
        effect_binding_kind="direct_path",
        script_sha256="55" * 32,
        poc_bundle_manifest_sha256="56" * 32,
        poc_bundle_source_file_count=2,
        transport_contract_sha256="66" * 32,
        trace_binding_sha256=hashlib.sha256(
            oracle.generation_id.encode("ascii")
        ).hexdigest(),
        actor_identity_sha256="88" * 32,
        actor_role="unauthenticated",
        attack_payload_sha256=hashlib.sha256(oracle.private_attack_payload).hexdigest(),
        control_payload_sha256=hashlib.sha256(
            oracle.private_control_payload
        ).hexdigest(),
        attack_payload_size_bytes=len(oracle.private_attack_payload),
        control_payload_size_bytes=len(oracle.private_control_payload),
        attack_sequence=1,
        control_sequence=2,
        attack_status_code=200,
        control_status_code=200,
        attack_control_envelopes_equal=True,
        rewritten_payloads_differ=True,
        ephemeral_path_capability_exact=True,
        executable_surface_bound=True,
    )
    return oracle.attest_execution(
        generation_id=generation,
        attack_token=context["attack_token"],
        control_token=context["control_token"],
        execution_started_monotonic_ns=now,
        execution_finished_monotonic_ns=time.monotonic_ns(),
        attested_monotonic_ns=time.monotonic_ns(),
        runtime_binding=oracle.runtime_binding,
        transport_attestation=transport,
    )


def test_parent_builds_object_payload_and_object_free_control_with_same_tokens() -> (
    None
):
    oracle = _oracle()
    context = oracle.public_context()
    generation = oracle.begin_generation()

    attack = oracle.resolve_payload(
        generation_id=generation,
        token=context["attack_token"],
    )
    control = oracle.resolve_payload(
        generation_id=generation,
        token=context["control_token"],
    )

    assert attack.startswith(b'O:18:"ReviewedFileGadget":1:{')
    assert b's:7:"\x00*\x00path";' in attack
    assert attack.count(oracle.private_target_path.encode("ascii")) == 1
    assert control.startswith(b"a:1:{")
    assert all(marker not in control for marker in (b"O:", b"C:", b"E:", b"R:", b"r:"))
    assert control.count(oracle.private_target_path.encode("ascii")) == 1
    assert context == oracle.public_context()


def test_snapshot_is_sanitized_and_replay_requires_fresh_private_material() -> None:
    first_oracle = _oracle()
    first = _finalize(first_oracle)
    second = _finalize(first_oracle)

    accepted, reason = validate_php_object_gadget_snapshot_pair(first, second)

    assert accepted is True, reason
    rendered = json.dumps(first.as_dict(), sort_keys=True)
    for private in first_oracle.private_redaction_values():
        assert private not in rendered
    assert first.generation_id_sha256 != second.generation_id_sha256
    assert first.target_path_sha256 != second.target_path_sha256
    assert first.attack_token_sha256 == second.attack_token_sha256


def test_snapshot_rejects_nested_payload_binding_drift() -> None:
    snapshot = _finalize(_oracle())
    changed_transport = replace(
        snapshot.transport_attestation,
        attack_payload_sha256="99" * 32,
    )

    with pytest.raises(ValueError, match="snapshot binding"):
        replace(snapshot, transport_attestation=changed_transport)


def test_replay_pair_rejects_isolated_poc_helper_identity_drift() -> None:
    oracle = _oracle()
    first = _finalize(oracle)
    second = _finalize(oracle)
    changed_transport = replace(
        second.transport_attestation,
        poc_bundle_manifest_sha256="ab" * 32,
    )
    second = replace(second, transport_attestation=changed_transport)

    accepted, reason = validate_php_object_gadget_snapshot_pair(first, second)

    assert accepted is False
    assert "changed script, actor, or transport" in reason


def test_persisted_confirmation_is_strict_and_revalidates_replay() -> None:
    oracle = _oracle()
    first = _finalize(oracle)
    second = _finalize(oracle)
    payload = {
        "schema_version": 1,
        "status": "confirmed",
        "proof_kind": "php_object_natural",
        "hypothesis_id": "hyp-php-object",
        "bug_class": "CWE-502",
        "effect": "file_delete",
        "clean_state_executions": 2,
        "finding_promoted": True,
        "promotion_policy": "source_bound_natural_gadget_v1",
        "first_execution": first.as_dict(),
        "confirmation_execution": second.as_dict(),
    }

    restored = php_object_gadget_snapshot_from_dict(first.as_dict())
    assert restored == first
    assert validate_persisted_php_object_gadget_confirmation(
        payload,
        hypothesis_id="hyp-php-object",
    )[0]

    incomplete_bundle_binding = json.loads(json.dumps(payload))
    incomplete_bundle_binding["first_execution"]["transport_attestation"].pop(
        "poc_bundle_manifest_sha256"
    )
    assert not validate_persisted_php_object_gadget_confirmation(
        incomplete_bundle_binding
    )[0]

    lower_tier = json.loads(json.dumps(payload))
    for execution_name in ("first_execution", "confirmation_execution"):
        execution = lower_tier[execution_name]
        execution["effect_binding_kind"] = "guarded_opaque_prefix"
        execution["runtime_binding"]["effect_binding_kind"] = "guarded_opaque_prefix"
        execution["effect_attestation"]["effect_binding_kind"] = "guarded_opaque_prefix"
        execution["transport_attestation"]["effect_binding_kind"] = (
            "guarded_opaque_prefix"
        )
    accepted, reason = validate_persisted_php_object_gadget_confirmation(lower_tier)
    assert accepted is False
    assert "not a direct-path effect" in reason

    payload["legacy_partial_marker"] = True
    assert not validate_persisted_php_object_gadget_confirmation(payload)[0]


def test_replay_pair_rejects_reused_snapshot_and_trace_identity() -> None:
    snapshot = _finalize(_oracle())

    accepted, reason = validate_php_object_gadget_snapshot_pair(snapshot, snapshot)

    assert accepted is False
    assert "trace binding" in reason


def test_object_free_control_uses_one_array_count_and_forbids_reference_markers() -> (
    None
):
    recipe = _recipe()
    extra = PhpObjectGadgetProperty(
        name="enabled",
        declaring_class="ReviewedFileGadget",
        visibility="public",
        value=PhpObjectGadgetValue(kind="boolean", value=True),
    )
    gadget_object = recipe.gadget_object.model_copy(
        update={"properties": (*recipe.gadget_object.properties, extra)}
    )
    recipe = recipe.model_copy(update={"gadget_object": gadget_object})
    primitive, attack_token, control_token = _primitive()
    oracle = PhpObjectGadgetOracle(
        recipe=recipe,
        primitive_snapshot=primitive,
        attack_token=attack_token,
        control_token=control_token,
        runtime_binding=_binding(recipe),
    )
    generation = oracle.begin_generation()
    control = oracle.resolve_payload(
        generation_id=generation,
        token=control_token,
    )

    assert control.startswith(b"a:2:{")
    assert not control.startswith(b"a:22:{")
    assert all(marker not in control for marker in (b"O:", b"C:", b"E:", b"R:", b"r:"))


def test_unicode_source_quotes_hash_as_utf8_but_unicode_runtime_ids_fail_closed() -> (
    None
):
    recipe = _recipe()
    unicode_anchor = PhpObjectGadgetSourceAnchor(
        file="includes/gadget.php",
        line=3,
        source_code="class ReviewedFileGadget // café",
    )
    recipe_with_unicode_source = recipe.model_copy(
        update={
            "gadget_object": recipe.gadget_object.model_copy(
                update={"class_anchor": unicode_anchor}
            )
        }
    )
    assert len(php_object_gadget_recipe_sha256(recipe_with_unicode_source)) == 64

    unsafe_object = recipe.gadget_object.model_copy(
        update={"class_name": "RéviewedFileGadget"}
    )
    unsafe_recipe = recipe.model_copy(update={"gadget_object": unsafe_object})
    primitive, attack_token, control_token = _primitive()
    oracle = PhpObjectGadgetOracle(
        recipe=unsafe_recipe,
        primitive_snapshot=primitive,
        attack_token=attack_token,
        control_token=control_token,
        runtime_binding=_binding(unsafe_recipe),
    )
    with pytest.raises(ValueError, match="class name"):
        oracle.begin_generation()


def test_collateral_directory_entry_fails_closed() -> None:
    oracle = _oracle()
    oracle.begin_generation()
    attack_before = _measurement(oracle, exists=True)
    attack_after = _measurement(oracle, exists=False)
    object.__setattr__(attack_after, "directory_entry_count", 1)

    with pytest.raises(ValueError, match="effect attestation"):
        oracle.attest_effect(
            attack_before=attack_before,
            attack_after=attack_after,
            control_before=_measurement(oracle, exists=True, inode=701),
            control_after=_measurement(oracle, exists=True, inode=701),
            state_restored_before_control=True,
            runtime_restarted_before_control=True,
            state_restored_after_control=True,
            runtime_restarted_after_control=True,
        )


def test_control_target_mutation_fails_closed() -> None:
    oracle = _oracle()
    oracle.begin_generation()
    control_before = _measurement(oracle, exists=True, inode=701)
    control_after = _measurement(oracle, exists=True, inode=702)

    with pytest.raises(ValueError, match="effect attestation"):
        oracle.attest_effect(
            attack_before=_measurement(oracle, exists=True),
            attack_after=_measurement(oracle, exists=False),
            control_before=control_before,
            control_after=control_after,
            state_restored_before_control=True,
            runtime_restarted_before_control=True,
            state_restored_after_control=True,
            runtime_restarted_after_control=True,
        )


def test_runtime_binding_must_match_the_exact_typed_recipe() -> None:
    recipe = _recipe()
    primitive, attack_token, control_token = _primitive()
    binding = _binding(recipe)
    object.__setattr__(binding, "recipe_sha256", "99" * 32)

    with pytest.raises(ValueError, match="binding changed"):
        PhpObjectGadgetOracle(
            recipe=recipe,
            primitive_snapshot=primitive,
            attack_token=attack_token,
            control_token=control_token,
            runtime_binding=binding,
        )
