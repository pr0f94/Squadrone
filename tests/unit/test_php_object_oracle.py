from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from dataclasses import FrozenInstanceError, asdict
from typing import Any

import pytest

from squadrone.services.php_object_oracle import (
    PHP_OBJECT_ORACLE_MODE,
    PHP_OBJECT_ORACLE_SCHEMA_VERSION,
    PhpObjectAttestationError,
    PhpObjectCallsite,
    PhpObjectOracle,
)


_CLASS_NAME = "SquadroneObjectCanary_" + "a" * 32
_SECRET = bytes.fromhex("11" * 32)
_CALLSITE_PATH = "/var/www/html/wp-content/plugins/generic/includes/storage.php"
_CALLSITE_SOURCE_SHA256 = "22" * 32
_CALLSITE_ARGS: dict[str, Any] = {
    "callsite_path": _CALLSITE_PATH,
    "callsite_start_line": 40,
    "callsite_end_line": 42,
    "callsite_source_sha256": _CALLSITE_SOURCE_SHA256,
}


def _oracle() -> PhpObjectOracle:
    return PhpObjectOracle(
        **_CALLSITE_ARGS,
        class_name=_CLASS_NAME,
        receipt_secret=_SECRET,
    )


def _attest(oracle: PhpObjectOracle):
    context = oracle.public_context()
    started_ns = time.monotonic_ns()
    finished_ns = time.monotonic_ns()
    attested_ns = time.monotonic_ns()
    return oracle.attest_execution(
        generation_id=oracle.generation_id,
        attack_token=context["attack_token"],
        control_token=context["control_token"],
        attack_receipt=oracle.private_expected_receipt,
        control_receipt=None,
        execution_started_monotonic_ns=started_ns,
        execution_finished_monotonic_ns=finished_ns,
        attested_monotonic_ns=attested_ns,
    )


def _attestation_values(oracle: PhpObjectOracle) -> dict[str, object]:
    context = oracle.public_context()
    return {
        "generation_id": oracle.generation_id,
        "attack_token": context["attack_token"],
        "control_token": context["control_token"],
        "attack_receipt": oracle.private_expected_receipt,
        "control_receipt": None,
        "execution_started_monotonic_ns": time.monotonic_ns(),
        "execution_finished_monotonic_ns": time.monotonic_ns(),
        "attested_monotonic_ns": time.monotonic_ns(),
    }


def test_constructor_accepts_only_scoped_class_identity_and_fixed_secret() -> None:
    oracle = _oracle()

    assert oracle.private_class_name == _CLASS_NAME
    assert oracle.private_receipt_secret == _SECRET
    assert repr(oracle) == "PhpObjectOracle(<redacted>)"

    for bad_name in (
        "stdClass",
        "SquadroneObjectCanary_" + "A" * 32,
        "SquadroneObjectCanary_" + "a" * 31,
        "SquadroneObjectCanary_" + "a" * 33,
        "SquadroneObjectCanary_../../Other",
        "",
    ):
        with pytest.raises(ValueError, match="class name"):
            PhpObjectOracle(
                **_CALLSITE_ARGS,
                class_name=bad_name,
                receipt_secret=_SECRET,
            )
    for bad_secret in (b"", b"x" * 31, b"x" * 33, bytearray(b"x" * 32)):
        with pytest.raises(ValueError, match="exactly 32 bytes"):
            PhpObjectOracle(
                **_CALLSITE_ARGS,
                class_name=_CLASS_NAME,
                receipt_secret=bad_secret,  # type: ignore[arg-type]
            )


@pytest.mark.parametrize(
    "relative_path",
    [
        "/absolute.php",
        "../escape.php",
        "includes/../escape.php",
        "includes//storage.php",
        "includes\\storage.php",
        "includes/storage.txt",
        "includes/sto\nrage.php",
        "",
    ],
)
def test_callsite_descriptor_rejects_untrusted_relative_paths(
    relative_path: str,
) -> None:
    with pytest.raises(ValueError, match="relative path"):
        PhpObjectCallsite(
            relative_path=relative_path,
            start_line=40,
            end_line=42,
            source_sha256=_CALLSITE_SOURCE_SHA256,
        )


def test_callsite_descriptor_is_redacted_and_line_range_is_bounded() -> None:
    callsite = PhpObjectCallsite(
        relative_path="includes/storage.php",
        start_line=40,
        end_line=42,
        source_sha256=_CALLSITE_SOURCE_SHA256,
    )

    assert repr(callsite) == "PhpObjectCallsite(<redacted>)"
    for start_line, end_line in ((0, 1), (42, 40), (1, 129), (1, 10_000_001)):
        with pytest.raises(ValueError, match="line range"):
            PhpObjectCallsite(
                relative_path="includes/storage.php",
                start_line=start_line,
                end_line=end_line,
                source_sha256=_CALLSITE_SOURCE_SHA256,
            )
    with pytest.raises(ValueError, match="source digest"):
        PhpObjectCallsite(
            relative_path="includes/storage.php",
            start_line=40,
            end_line=42,
            source_sha256="not-a-digest",
        )


@pytest.mark.parametrize(
    "installed_path",
    [
        "relative/storage.php",
        "/var/www/html/../escape.php",
        "/var/www/html/includes//storage.php",
        "/var/www/html/includes/storage.txt",
        "/var/www/html/includes/sto\nrage.php",
    ],
)
def test_oracle_rejects_noncanonical_installed_callsite_paths(
    installed_path: str,
) -> None:
    with pytest.raises(ValueError, match="installed callsite path"):
        PhpObjectOracle(
            **{**_CALLSITE_ARGS, "callsite_path": installed_path},
            class_name=_CLASS_NAME,
            receipt_secret=_SECRET,
        )


def test_default_identity_secret_and_generations_are_safe_shapes() -> None:
    first = PhpObjectOracle(**_CALLSITE_ARGS)
    second = PhpObjectOracle(**_CALLSITE_ARGS)

    assert re.fullmatch(r"SquadroneObjectCanary_[0-9a-f]{32}", first.private_class_name)
    assert len(first.private_receipt_secret) == 32
    assert first.private_class_name != second.private_class_name
    assert first.private_receipt_secret != second.private_receipt_secret
    generation_id = first.begin_generation()
    assert re.fullmatch(r"[0-9a-f]{64}", generation_id)


def test_attempt_exposes_only_stable_non_serialized_arm_tokens() -> None:
    oracle = _oracle()
    context = oracle.public_context()
    with pytest.raises(RuntimeError, match="generation is not started"):
        _ = oracle.private_attack_payload
    with pytest.raises(RuntimeError, match="generation is not started"):
        _ = oracle.private_marker

    generation_id = oracle.begin_generation()

    assert context == {
        "mode": PHP_OBJECT_ORACLE_MODE,
        "attack_token": context["attack_token"],
        "control_token": context["control_token"],
    }
    assert re.fullmatch(r"sqpobjt1\.[0-9a-f]{64}", context["attack_token"])
    assert re.fullmatch(r"sqpobjt1\.[0-9a-f]{64}", context["control_token"])
    assert context["attack_token"] != context["control_token"]
    assert oracle.public_context() == context
    serialized_context = json.dumps(context, sort_keys=True)
    assert generation_id not in serialized_context
    assert oracle.private_class_name not in serialized_context
    assert oracle.private_proof not in serialized_context
    assert oracle.private_expected_receipt not in serialized_context
    assert "SQUADRONE_" not in serialized_context
    assert "O:" not in serialized_context
    assert "C:" not in serialized_context


def test_exact_attack_object_and_same_shaped_benign_control_are_deterministic() -> None:
    oracle = _oracle()
    generation_id = oracle.begin_generation()
    proof = oracle.private_proof

    expected_attack = (
        f'O:{len(_CLASS_NAME)}:"{_CLASS_NAME}":2:{{'
        f's:13:"\x00*\x00generation";s:64:"{generation_id}";'
        f's:8:"\x00*\x00proof";s:64:"{proof}";'
        "}"
    ).encode("ascii")
    expected_control = (
        "a:2:{"
        f's:13:"\x00*\x00generation";s:64:"{generation_id}";'
        f's:8:"\x00*\x00proof";s:64:"{proof}";'
        "}"
    ).encode("ascii")

    assert oracle.private_attack_payload == expected_attack
    assert oracle.private_control_payload == expected_control
    assert oracle.private_attack_payload.startswith(b"O:")
    assert oracle.private_attack_payload.count(b"\x00*\x00") == 2
    assert oracle.private_control_payload.count(b"\x00*\x00") == 2
    assert b"O:" not in oracle.private_control_payload
    assert b"C:" not in oracle.private_control_payload
    assert len(oracle.private_attack_payload) <= 512
    assert len(oracle.private_control_payload) <= 256
    oracle.private_attack_payload.decode("ascii")
    oracle.private_control_payload.decode("ascii")


def test_proof_and_receipt_are_domain_separated_hmacs() -> None:
    oracle = _oracle()
    generation_id = oracle.begin_generation()
    callsite_binding = (
        hashlib.sha256(_CALLSITE_PATH.encode("ascii")).hexdigest().encode("ascii")
        + b"\x00"
        + b"40"
        + b"\x00"
        + b"42"
        + b"\x00"
        + _CALLSITE_SOURCE_SHA256.encode("ascii")
    )
    proof_message = (
        b"squadrone-php-object-proof-v1\x00"
        + _CLASS_NAME.encode("ascii")
        + b"\x00"
        + generation_id.encode("ascii")
        + b"\x00"
        + callsite_binding
    )
    expected_proof = hmac.new(_SECRET, proof_message, hashlib.sha256).hexdigest()
    receipt_message = (
        b"squadrone-php-object-receipt-v1\x00"
        + _CLASS_NAME.encode("ascii")
        + b"\x00"
        + generation_id.encode("ascii")
        + b"\x00"
        + expected_proof.encode("ascii")
        + b"\x00"
        + callsite_binding
    )
    expected_mac = hmac.new(_SECRET, receipt_message, hashlib.sha256).hexdigest()

    assert oracle.private_proof == expected_proof
    assert oracle.private_expected_receipt == (
        f"sqpobj1.{generation_id}.{expected_mac}"
    )
    assert oracle.private_marker == oracle.private_expected_receipt


@pytest.mark.parametrize(
    "changed_callsite",
    [
        {
            "callsite_path": (
                "/var/www/html/wp-content/plugins/generic/includes/other.php"
            )
        },
        {"callsite_start_line": 41, "callsite_end_line": 43},
        {"callsite_source_sha256": "33" * 32},
    ],
)
def test_private_proof_and_receipt_are_bound_to_exact_runtime_callsite(
    monkeypatch: pytest.MonkeyPatch,
    changed_callsite: dict[str, Any],
) -> None:
    issued_hex = iter(["a" * 64, "b" * 64, "c" * 64] * 2)
    monkeypatch.setattr(
        "squadrone.services.php_object_oracle.secrets.token_hex",
        lambda _size: next(issued_hex),
    )
    expected = _oracle()
    expected_generation = expected.begin_generation()
    changed = PhpObjectOracle(
        **{**_CALLSITE_ARGS, **changed_callsite},
        class_name=_CLASS_NAME,
        receipt_secret=_SECRET,
    )
    changed_generation = changed.begin_generation()

    assert changed_generation == expected_generation
    assert changed.public_context() == expected.public_context()
    assert changed.private_proof != expected.private_proof
    assert changed.private_expected_receipt != expected.private_expected_receipt
    assert changed.private_canary_class_source != expected.private_canary_class_source


def test_final_canary_class_is_bounded_and_has_only_in_memory_effect() -> None:
    source = _oracle().private_canary_class_source
    decoded = source.decode("ascii")

    assert len(source) <= 4096
    assert decoded.startswith(f"<?php\nfinal class {_CLASS_NAME}\n")
    assert "protected $generation = '';" in decoded
    assert "protected $proof = '';" in decoded
    assert "public function __wakeup()" in decoded
    assert "private static $receipt = null;" in decoded
    assert "public static function consumeReceipt()" in decoded
    assert "public static function resetReceipt()" in decoded
    assert "hash_hmac('sha256'" in decoded
    assert "hash_equals(" in decoded
    assert "debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 64)" in decoded
    assert "$frame['line'] < 40" in decoded
    assert "$frame['line'] > 42" in decoded
    assert "hash_file('sha256', $frame['file'])" in decoded
    assert hashlib.sha256(_CALLSITE_PATH.encode("ascii")).hexdigest() in decoded
    assert _CALLSITE_SOURCE_SHA256 in decoded
    assert _CALLSITE_PATH not in decoded
    for external_effect in (
        "file_put_contents",
        "fopen(",
        "unlink(",
        "curl_",
        "fsockopen(",
        "shell_exec(",
        "system(",
        "exec(",
        "header(",
    ):
        assert external_effect not in decoded


def test_unrelated_same_request_deserializer_cannot_set_the_private_receipt() -> None:
    decoded = _oracle().private_canary_class_source.decode("ascii")

    scan = decoded.index("$frames = debug_backtrace(")
    exact_path = decoded.index("hash('sha256', $frame['file'])", scan)
    exact_source = decoded.index("hash_file('sha256', $frame['file'])", exact_path)
    required_gate = decoded.index("if (!$callsiteMatched)", exact_source)
    proof_check = decoded.index("$expectedProof = hash_hmac(", required_gate)
    receipt_write = decoded.index("self::$receipt =", proof_check)

    assert (
        scan < exact_path < exact_source < required_gate < proof_check < receipt_write
    )


def test_token_resolution_is_exact_current_generation_and_constant_shape() -> None:
    oracle = _oracle()
    first_generation = oracle.begin_generation()
    first_context = oracle.public_context()

    assert (
        oracle.resolve_payload(
            generation_id=first_generation,
            token=first_context["attack_token"],
        )
        == oracle.private_attack_payload
    )
    assert (
        oracle.resolve_payload(
            generation_id=first_generation,
            token=first_context["control_token"],
        )
        == oracle.private_control_payload
    )
    with pytest.raises(ValueError, match="arm token"):
        oracle.resolve_payload(
            generation_id=first_generation,
            token="sqpobjt1." + "0" * 64,
        )
    with pytest.raises(ValueError, match="arm token"):
        oracle.resolve_payload(
            generation_id=first_generation,
            token=b"not-a-string",  # type: ignore[arg-type]
        )

    _attest(oracle)
    assert oracle.public_context() == first_context
    with pytest.raises(ValueError, match="generation is finalized"):
        oracle.resolve_payload(
            generation_id=first_generation,
            token=first_context["attack_token"],
        )
    second_generation = oracle.begin_generation()
    with pytest.raises(ValueError, match="payload generation"):
        oracle.resolve_payload(
            generation_id=first_generation,
            token=first_context["attack_token"],
        )
    assert second_generation != first_generation


def test_abort_invalidates_unfinished_private_material_and_allows_fresh_start() -> None:
    oracle = _oracle()
    first_generation = oracle.begin_generation()
    first_context = oracle.public_context()
    first_payload = oracle.private_attack_payload

    with pytest.raises(ValueError, match="abort generation"):
        oracle.abort_generation(generation_id="0" * 64)
    assert oracle.generation_id == first_generation
    oracle.abort_generation(generation_id=first_generation)

    assert oracle.public_context() == first_context
    with pytest.raises(RuntimeError, match="generation is not started"):
        _ = oracle.private_attack_payload
    second_generation = oracle.begin_generation()
    assert second_generation != first_generation
    assert oracle.public_context() == first_context
    assert oracle.private_attack_payload != first_payload


def test_verified_generation_cannot_be_aborted() -> None:
    oracle = _oracle()
    generation_id = oracle.begin_generation()
    _attest(oracle)

    with pytest.raises(RuntimeError, match="cannot abort a verified"):
        oracle.abort_generation(generation_id=generation_id)


def test_unfinished_generation_cannot_rotate_and_completed_one_rotates_fresh() -> None:
    oracle = _oracle()
    stable_class_source = oracle.private_canary_class_source
    stable_secret = oracle.private_receipt_secret
    first_generation = oracle.begin_generation()
    first_context = oracle.public_context()
    first_attack = oracle.private_attack_payload
    first_control = oracle.private_control_payload
    first_proof = oracle.private_proof
    first_receipt = oracle.private_expected_receipt

    with pytest.raises(RuntimeError, match="cannot rotate an unfinished"):
        oracle.begin_generation()
    _attest(oracle)
    second_generation = oracle.begin_generation()

    assert second_generation != first_generation
    assert oracle.public_context() == first_context
    assert oracle.private_attack_payload != first_attack
    assert oracle.private_control_payload != first_control
    assert oracle.private_proof != first_proof
    assert oracle.private_expected_receipt != first_receipt
    assert oracle.private_canary_class_source == stable_class_source
    assert oracle.private_receipt_secret == stable_secret
    with pytest.raises(RuntimeError, match="incomplete or unverified"):
        oracle.snapshot()


def test_two_executions_keep_tokens_but_rotate_all_private_generation_evidence() -> (
    None
):
    oracle = _oracle()
    context = oracle.public_context()
    first_generation = oracle.begin_generation()
    first_proof = oracle.private_proof
    first_attack_payload = oracle.private_attack_payload
    first_control_payload = oracle.private_control_payload
    first_receipt = oracle.private_expected_receipt
    first_snapshot = _attest(oracle)

    second_generation = oracle.begin_generation()
    second_proof = oracle.private_proof
    second_attack_payload = oracle.private_attack_payload
    second_control_payload = oracle.private_control_payload
    second_receipt = oracle.private_expected_receipt
    second_snapshot = _attest(oracle)

    assert oracle.public_context() == context
    assert second_generation != first_generation
    assert hashlib.sha256(second_generation.encode("ascii")).hexdigest() != (
        hashlib.sha256(first_generation.encode("ascii")).hexdigest()
    )
    assert second_proof != first_proof
    assert second_attack_payload != first_attack_payload
    assert second_control_payload != first_control_payload
    assert second_receipt != first_receipt
    assert (
        second_snapshot.execution.attack_token_sha256
        == first_snapshot.execution.attack_token_sha256
    )
    assert (
        second_snapshot.execution.control_token_sha256
        == first_snapshot.execution.control_token_sha256
    )
    assert (
        second_snapshot.execution.proof_sha256 != first_snapshot.execution.proof_sha256
    )
    assert (
        second_snapshot.execution.attack_payload_sha256
        != first_snapshot.execution.attack_payload_sha256
    )
    assert (
        second_snapshot.execution.control_payload_sha256
        != first_snapshot.execution.control_payload_sha256
    )
    assert (
        second_snapshot.execution.expected_receipt_sha256
        != first_snapshot.execution.expected_receipt_sha256
    )


def test_success_snapshot_is_immutable_exact_and_contains_only_sanitized_values() -> (
    None
):
    oracle = _oracle()
    generation_id = oracle.begin_generation()
    context = oracle.public_context()
    attack_payload = oracle.private_attack_payload
    control_payload = oracle.private_control_payload
    proof = oracle.private_proof
    receipt = oracle.private_expected_receipt
    class_source = oracle.private_canary_class_source
    redaction_values = oracle.private_redaction_values()
    snapshot = _attest(oracle)

    assert snapshot is not oracle.snapshot()
    assert snapshot == oracle.snapshot()
    assert snapshot.schema_version == PHP_OBJECT_ORACLE_SCHEMA_VERSION
    assert snapshot.mode == PHP_OBJECT_ORACLE_MODE
    assert (
        snapshot.generation_id_sha256
        == hashlib.sha256(generation_id.encode("ascii")).hexdigest()
    )
    assert snapshot.execution.generation_id_sha256 == snapshot.generation_id_sha256
    assert (
        snapshot.execution.callsite_path_sha256
        == hashlib.sha256(_CALLSITE_PATH.encode("ascii")).hexdigest()
    )
    assert snapshot.execution.callsite_start_line == 40
    assert snapshot.execution.callsite_end_line == 42
    assert snapshot.execution.callsite_source_sha256 == _CALLSITE_SOURCE_SHA256
    assert snapshot.execution.backtrace_limit == 64
    assert (
        snapshot.execution.attack_token_sha256
        == hashlib.sha256(context["attack_token"].encode("ascii")).hexdigest()
    )
    assert (
        snapshot.execution.control_token_sha256
        == hashlib.sha256(context["control_token"].encode("ascii")).hexdigest()
    )
    assert (
        snapshot.execution.attack_payload_sha256
        == hashlib.sha256(attack_payload).hexdigest()
    )
    assert (
        snapshot.execution.control_payload_sha256
        == hashlib.sha256(control_payload).hexdigest()
    )
    assert (
        snapshot.execution.class_name_sha256
        == hashlib.sha256(_CLASS_NAME.encode("ascii")).hexdigest()
    )
    assert (
        snapshot.execution.canary_class_source_sha256
        == hashlib.sha256(class_source).hexdigest()
    )
    assert (
        snapshot.execution.proof_sha256
        == hashlib.sha256(proof.encode("ascii")).hexdigest()
    )
    assert (
        snapshot.execution.expected_receipt_sha256
        == hashlib.sha256(receipt.encode("ascii")).hexdigest()
    )
    assert snapshot.execution.attack_receipt_matched is True
    assert snapshot.execution.control_receipt_absent is True

    serialized = json.dumps(snapshot.as_dict(), sort_keys=True)
    dataclass_serialized = json.dumps(asdict(snapshot), sort_keys=True)
    for private_value in (
        context["attack_token"],
        context["control_token"],
        attack_payload.decode("ascii"),
        control_payload.decode("ascii"),
        _CLASS_NAME,
        _SECRET.hex(),
        proof,
        receipt,
        class_source.decode("ascii"),
        _CALLSITE_PATH,
        generation_id,
    ):
        assert private_value not in serialized
        assert private_value not in dataclass_serialized
    assert len(redaction_values) == 10
    assert len(set(redaction_values)) == len(redaction_values)
    assert context["attack_token"] in redaction_values
    assert _CALLSITE_PATH in redaction_values
    assert attack_payload.decode("ascii") in redaction_values
    assert proof in redaction_values
    assert receipt in redaction_values
    assert oracle.private_redaction_values() == redaction_values
    with pytest.raises(FrozenInstanceError):
        snapshot.execution.attack_receipt_matched = False  # type: ignore[misc]


def test_attestation_error_taxonomy_is_closed_and_never_echoes_values() -> None:
    error = PhpObjectAttestationError("attack_receipt", "mismatch")

    assert str(error) == "invalid PHP object execution attestation"
    assert error.args == ("invalid PHP object execution attestation",)
    assert vars(error) == {
        "field": "attack_receipt",
        "category": "mismatch",
        "reason": "attack_receipt_mismatch",
    }
    with pytest.raises(ValueError, match="error category"):
        PhpObjectAttestationError("attacker-value", "mismatch")
    with pytest.raises(ValueError, match="error category"):
        PhpObjectAttestationError("attack_receipt", "dynamic-value")


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("generation_id", "0" * 64, "generation_id_mismatch"),
        ("generation_id", b"not-text", "generation_id_invalid_shape"),
        ("attack_token", "sqpobjt1." + "0" * 64, "attack_token_mismatch"),
        ("attack_token", "bad", "attack_token_invalid_shape"),
        ("control_token", "sqpobjt1." + "0" * 64, "control_token_mismatch"),
        ("control_token", None, "control_token_invalid_shape"),
        (
            "attack_receipt",
            "sqpobj1." + "0" * 64 + "." + "0" * 64,
            "attack_receipt_mismatch",
        ),
        ("attack_receipt", "bad", "attack_receipt_invalid_shape"),
        ("control_receipt", "unexpected", "control_receipt_unsafe_state"),
        (
            "execution_started_monotonic_ns",
            True,
            "execution_started_monotonic_ns_invalid_shape",
        ),
        (
            "execution_finished_monotonic_ns",
            0,
            "execution_finished_monotonic_ns_invalid_shape",
        ),
        ("attested_monotonic_ns", 0, "attested_monotonic_ns_invalid_shape"),
    ],
)
def test_attestation_rejects_inexact_identity_receipts_and_shapes(
    field: str,
    value: object,
    reason: str,
) -> None:
    oracle = _oracle()
    oracle.begin_generation()
    values = _attestation_values(oracle)
    values[field] = value

    with pytest.raises(PhpObjectAttestationError) as caught:
        oracle.attest_execution(**values)  # type: ignore[arg-type]
    assert caught.value.reason == reason
    assert str(value) not in str(caught.value)
    with pytest.raises(RuntimeError, match="incomplete or unverified"):
        oracle.snapshot()


def test_attestation_rejects_out_of_order_and_future_bounds() -> None:
    oracle = _oracle()
    oracle.begin_generation()
    values = _attestation_values(oracle)
    started_ns = values["execution_started_monotonic_ns"]
    assert type(started_ns) is int

    values["execution_finished_monotonic_ns"] = started_ns - 1
    with pytest.raises(PhpObjectAttestationError) as out_of_order:
        oracle.attest_execution(**values)  # type: ignore[arg-type]
    assert out_of_order.value.reason == ("execution_finished_monotonic_ns_out_of_order")

    values = _attestation_values(oracle)
    values["attested_monotonic_ns"] = time.monotonic_ns() + 10_000_000_000
    with pytest.raises(PhpObjectAttestationError) as future:
        oracle.attest_execution(**values)  # type: ignore[arg-type]
    assert future.value.reason == "attested_monotonic_ns_future"


def test_failed_attestation_is_non_mutating_and_success_is_single_use() -> None:
    oracle = _oracle()
    oracle.begin_generation()
    valid_values = _attestation_values(oracle)
    invalid_values = dict(valid_values)
    invalid_values["attack_receipt"] = "sqpobj1." + "0" * 64 + "." + "0" * 64
    with pytest.raises(PhpObjectAttestationError):
        oracle.attest_execution(**invalid_values)  # type: ignore[arg-type]

    snapshot = oracle.attest_execution(**valid_values)  # type: ignore[arg-type]
    assert snapshot.execution.attack_receipt_matched is True
    with pytest.raises(RuntimeError, match="already verified"):
        oracle.attest_execution(**valid_values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("attribute", "value", "message"),
    [
        (
            "_callsite_path",
            "/var/www/html/wp-content/plugins/other.php",
            "static state is invalid",
        ),
        ("_callsite_start_line", 0, "static state is invalid"),
        ("_callsite_source_sha256", "0" * 64, "static state is invalid"),
        ("_class_name", "stdClass", "static state is invalid"),
        ("_receipt_secret", b"short", "static state is invalid"),
        ("_canary_class_source", b"<?php // changed", "static state is invalid"),
        ("_issued_private_values", [], "static state is invalid"),
        ("_attack_token", "sqpobjt1." + "0" * 64, "static state is invalid"),
        ("_control_token", "not-a-token", "static state is invalid"),
        ("_attack_token_sha256", "0" * 64, "static state is invalid"),
    ],
)
def test_static_corruption_fails_closed(
    attribute: str,
    value: object,
    message: str,
) -> None:
    oracle = _oracle()
    object.__setattr__(oracle, attribute, value)

    with pytest.raises(RuntimeError, match=message):
        oracle.begin_generation()
    with pytest.raises(RuntimeError, match=message):
        _ = oracle.private_canary_class_source


@pytest.mark.parametrize(
    ("attribute", "value"),
    [
        ("_generation_id_sha256", "0" * 64),
        ("_proof", "0" * 64),
        ("_expected_receipt", "sqpobj1." + "0" * 64 + "." + "0" * 64),
        ("_attack_payload", b'O:8:"stdClass":0:{}'),
        ("_control_payload", b'O:8:"stdClass":0:{}'),
        ("_attack_payload_sha256", "0" * 64),
        ("_generation_started_monotonic_ns", 0),
    ],
)
def test_generation_corruption_fails_closed(attribute: str, value: object) -> None:
    oracle = _oracle()
    oracle.begin_generation()
    object.__setattr__(oracle, attribute, value)

    with pytest.raises(RuntimeError, match="generation state is invalid"):
        oracle.public_context()
    with pytest.raises(RuntimeError, match="generation state is invalid"):
        oracle.resolve_payload(generation_id="0" * 64, token="sqpobjt1." + "0" * 64)


def test_inactive_partial_lifecycle_and_completed_snapshot_corruption_fail_closed() -> (
    None
):
    inactive = _oracle()
    object.__setattr__(inactive, "_proof", "0" * 64)
    with pytest.raises(RuntimeError, match="lifecycle state is invalid"):
        inactive.begin_generation()

    complete = _oracle()
    complete.begin_generation()
    snapshot = _attest(complete)
    object.__setattr__(snapshot.execution, "attack_payload_sha256", "0" * 64)
    with pytest.raises(RuntimeError, match="execution state is malformed"):
        complete.snapshot()
    with pytest.raises(RuntimeError, match="execution state is malformed"):
        complete.begin_generation()
