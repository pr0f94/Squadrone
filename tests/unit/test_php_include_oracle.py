from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import FrozenInstanceError, asdict

import pytest

from squadrone.poc_proxy import PHP_INCLUDE_RECEIPT_HEADER
from squadrone.services.php_include_oracle import (
    PHP_INCLUDE_ORACLE_DIRECTORY,
    PHP_INCLUDE_ORACLE_FILE_MODE,
    PHP_INCLUDE_ORACLE_HEADER_NAME,
    PHP_INCLUDE_ORACLE_MODE,
    PhpIncludeAttestationError,
    PhpIncludeHostFilesystemMeasurement,
    PhpIncludeOracle,
)


_HOST_DEVICE = 812_345_670_123
_HOST_INODE = 912_345_670_123


def _content_sha256(oracle: PhpIncludeOracle) -> str:
    return hashlib.sha256(oracle.private_attack_content).hexdigest()


def _host_measurement(
    oracle: PhpIncludeOracle,
    *,
    measured_monotonic_ns: int | None = None,
    overrides: dict[str, object] | None = None,
) -> PhpIncludeHostFilesystemMeasurement:
    values: dict[str, object] = {
        "attack_content_sha256": _content_sha256(oracle),
        "attack_content_size_bytes": len(oracle.private_attack_content),
        "attack_owner_uid": os.geteuid(),
        "attack_owner_gid": os.getegid(),
        "attack_file_mode": PHP_INCLUDE_ORACLE_FILE_MODE,
        "attack_link_count": 1,
        "attack_is_regular_file": True,
        "attack_is_symlink": False,
        "control_lstat_exists": False,
        "attack_device": _HOST_DEVICE,
        "attack_inode": _HOST_INODE,
        "measured_monotonic_ns": (
            time.monotonic_ns()
            if measured_monotonic_ns is None
            else measured_monotonic_ns
        ),
    }
    if overrides is not None:
        values.update(overrides)
    return PhpIncludeHostFilesystemMeasurement(**values)  # type: ignore[arg-type]


def _provision(
    oracle: PhpIncludeOracle,
    *,
    container_owner_uid: int = 0,
    container_owner_gid: int = 0,
):
    started_ns = time.monotonic_ns()
    host_measurement = _host_measurement(oracle)
    finished_ns = time.monotonic_ns()
    return oracle.attest_provisioning(
        generation_id=oracle.generation_id,
        attack_resource_path=oracle.attack_path,
        control_resource_path=oracle.control_path,
        attack_content_sha256=_content_sha256(oracle),
        attack_content_size_bytes=len(oracle.private_attack_content),
        attack_owner_uid=container_owner_uid,
        attack_owner_gid=container_owner_gid,
        attack_file_mode=PHP_INCLUDE_ORACLE_FILE_MODE,
        attack_link_count=1,
        attack_is_regular_file=True,
        attack_is_symlink=False,
        control_lstat_exists=False,
        host_measurement=host_measurement,
        started_monotonic_ns=started_ns,
        finished_monotonic_ns=finished_ns,
    )


def _verify(
    oracle: PhpIncludeOracle,
    provisioned_ns: int,
    *,
    container_owner_uid: int = 33,
    container_owner_gid: int = 33,
):
    execution_started_ns = max(provisioned_ns, time.monotonic_ns())
    execution_finished_ns = time.monotonic_ns()
    after_host_measurement = _host_measurement(oracle)
    after_ns = time.monotonic_ns()
    return oracle.attest_verification(
        generation_id=oracle.generation_id,
        attack_resource_path=oracle.attack_path,
        control_resource_path=oracle.control_path,
        after_attack_content_sha256=_content_sha256(oracle),
        after_attack_content_size_bytes=len(oracle.private_attack_content),
        after_attack_owner_uid=container_owner_uid,
        after_attack_owner_gid=container_owner_gid,
        after_attack_file_mode=PHP_INCLUDE_ORACLE_FILE_MODE,
        after_attack_link_count=1,
        after_attack_is_regular_file=True,
        after_attack_is_symlink=False,
        after_control_lstat_exists=False,
        after_host_measurement=after_host_measurement,
        execution_started_monotonic_ns=execution_started_ns,
        execution_finished_monotonic_ns=execution_finished_ns,
        after_monotonic_ns=after_ns,
    )


def test_oracle_and_proxy_share_the_exact_receipt_header() -> None:
    assert PHP_INCLUDE_ORACLE_HEADER_NAME == PHP_INCLUDE_RECEIPT_HEADER


def test_attestation_error_taxonomy_is_closed_and_value_free() -> None:
    error = PhpIncludeAttestationError(
        "verification",
        "attack_content_sha256",
        "mismatch",
    )

    assert str(error) == "invalid PHP include verification attestation"
    assert error.args == ("invalid PHP include verification attestation",)
    assert vars(error) == {
        "phase": "verification",
        "field": "attack_content_sha256",
        "category": "mismatch",
        "reason": "attack_content_sha256_mismatch",
    }
    with pytest.raises(ValueError, match="error category"):
        PhpIncludeAttestationError("verification", "dynamic-secret", "mismatch")
    with pytest.raises(ValueError, match="error category"):
        PhpIncludeAttestationError("verification", "attack_owner_uid", "value-501")


def test_public_context_has_only_stable_opaque_php_paths_and_header() -> None:
    oracle = PhpIncludeOracle()
    context = oracle.public_context()

    assert context == {
        "attack_path": oracle.attack_path,
        "control_path": oracle.control_path,
        "attack_basename": oracle.attack_basename,
        "control_basename": oracle.control_basename,
        "header_name": PHP_INCLUDE_ORACLE_HEADER_NAME,
    }
    assert oracle.header_name == PHP_INCLUDE_ORACLE_HEADER_NAME
    assert oracle.attack_path == (
        f"{PHP_INCLUDE_ORACLE_DIRECTORY}/{oracle.attack_basename}"
    )
    assert oracle.control_path == (
        f"{PHP_INCLUDE_ORACLE_DIRECTORY}/{oracle.control_basename}"
    )
    assert re.fullmatch(r"[0-9a-f]{64}\.php", oracle.attack_basename)
    assert re.fullmatch(r"[0-9a-f]{64}\.php", oracle.control_basename)
    assert oracle.attack_path != oracle.control_path
    assert oracle.attack_basename != oracle.control_basename
    assert set(context) == {
        "attack_path",
        "control_path",
        "attack_basename",
        "control_basename",
        "header_name",
    }
    with pytest.raises(RuntimeError, match="generation state is invalid"):
        _ = oracle.generation_id
    with pytest.raises(RuntimeError, match="generation state is invalid"):
        _ = oracle.private_marker
    with pytest.raises(RuntimeError, match="generation state is invalid"):
        _ = oracle.private_attack_content


def test_generation_keeps_marker_and_canary_out_of_public_context() -> None:
    oracle = PhpIncludeOracle()
    public_context = oracle.public_context()
    generation_id = oracle.begin_generation()
    marker = oracle.private_marker
    content = oracle.private_attack_content

    assert re.fullmatch(r"[0-9a-f]{64}", generation_id)
    assert re.fullmatch(r"SQUADRONE_PHP_INCLUDE_[0-9a-f]{64}", marker)
    assert content == (
        f"<?php\nheader('{PHP_INCLUDE_ORACLE_HEADER_NAME}: {marker}');\nreturn;\n"
    ).encode("ascii")
    assert public_context == oracle.public_context()
    serialized = json.dumps(oracle.public_context(), sort_keys=True)
    assert marker not in serialized
    assert generation_id not in serialized
    assert content.decode("ascii") not in serialized
    assert "marker" not in serialized.lower()
    assert "content" not in serialized.lower()
    assert "sha256" not in serialized.lower()


def test_generation_is_strict_single_use_and_rotates_private_values() -> None:
    oracle = PhpIncludeOracle()
    public_context = oracle.public_context()
    first_generation = oracle.begin_generation()
    first_marker = oracle.private_marker
    first_content = oracle.private_attack_content

    with pytest.raises(RuntimeError, match="cannot rotate an unfinished"):
        oracle.begin_generation()
    provisioning = _provision(oracle)
    with pytest.raises(RuntimeError, match="cannot rotate an unfinished"):
        oracle.begin_generation()
    _verify(oracle, provisioning.filesystem.measured_monotonic_ns)

    second_generation = oracle.begin_generation()

    assert oracle.public_context() == public_context
    assert second_generation != first_generation
    assert oracle.private_marker != first_marker
    assert oracle.private_attack_content != first_content
    assert oracle.private_marker not in {oracle.attack_path, oracle.control_path}
    with pytest.raises(RuntimeError, match="incomplete or unverified"):
        oracle.snapshot()


def test_attestations_are_immutable_host_authoritative_and_secret_free() -> None:
    oracle = PhpIncludeOracle()
    generation_id = oracle.begin_generation()
    marker = oracle.private_marker
    content = oracle.private_attack_content
    provisioning = _provision(oracle)
    snapshot = _verify(oracle, provisioning.filesystem.measured_monotonic_ns)

    assert snapshot is not oracle.snapshot()
    assert snapshot == oracle.snapshot()
    assert snapshot.schema_version == 1
    assert snapshot.mode == PHP_INCLUDE_ORACLE_MODE
    assert snapshot.generation_id == generation_id
    assert provisioning == snapshot.provisioning
    assert (
        provisioning.marker_sha256 == hashlib.sha256(marker.encode("ascii")).hexdigest()
    )
    assert (
        provisioning.filesystem.attack_content_sha256
        == hashlib.sha256(content).hexdigest()
    )
    assert provisioning.filesystem.attack_owner_uid == 0
    assert provisioning.filesystem.attack_owner_gid == 0
    assert provisioning.filesystem.attack_file_mode == 0o444
    assert provisioning.filesystem.attack_link_count == 1
    assert provisioning.filesystem.attack_is_regular_file is True
    assert provisioning.filesystem.attack_is_symlink is False
    assert provisioning.filesystem.control_lstat_exists is False
    assert snapshot.verification.before == provisioning.filesystem
    assert snapshot.verification.after.attack_owner_uid == 33
    assert snapshot.verification.after.attack_owner_gid == 33
    assert snapshot.verification.after != snapshot.verification.before
    host_before = provisioning.host_filesystem
    host_after = snapshot.verification.host_after
    assert snapshot.verification.host_before == host_before
    assert host_before.host_identity_sha256 == host_after.host_identity_sha256
    assert host_before.attack_owner_matches_verifier is True
    assert host_after.attack_owner_matches_verifier is True
    assert host_before.attack_content_sha256 == _content_sha256(oracle)
    assert host_before.attack_content_size_bytes == len(content)
    assert host_before.attack_file_mode == PHP_INCLUDE_ORACLE_FILE_MODE
    assert host_before.attack_link_count == 1
    assert host_before.attack_is_regular_file is True
    assert host_before.attack_is_symlink is False
    assert host_before.control_lstat_exists is False
    assert (
        provisioning.started_monotonic_ns
        <= provisioning.host_filesystem.measured_monotonic_ns
        <= provisioning.filesystem.measured_monotonic_ns
        <= snapshot.verification.execution_started_monotonic_ns
        <= snapshot.verification.execution_finished_monotonic_ns
        <= snapshot.verification.host_after.measured_monotonic_ns
        <= snapshot.verification.after.measured_monotonic_ns
    )
    serialized = json.dumps(snapshot.as_dict(), sort_keys=True)
    dataclass_serialized = json.dumps(asdict(snapshot), sort_keys=True)
    assert marker not in serialized
    assert content.decode("ascii") not in serialized
    assert oracle.attack_path not in serialized
    assert oracle.control_path not in serialized
    assert marker not in dataclass_serialized
    assert content.decode("ascii") not in dataclass_serialized
    assert oracle.attack_path not in dataclass_serialized
    assert oracle.control_path not in dataclass_serialized
    host_keys = set(snapshot.provisioning.host_filesystem.as_dict())
    assert host_keys == {
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
        "measured_monotonic_ns",
    }
    dataclass_snapshot = asdict(snapshot)
    assert set(dataclass_snapshot["provisioning"]["host_filesystem"]) == host_keys
    assert set(dataclass_snapshot["verification"]["host_before"]) == host_keys
    assert set(dataclass_snapshot["verification"]["host_after"]) == host_keys
    assert "attack_device" not in serialized
    assert "attack_inode" not in serialized
    assert "host_attack_owner_uid" not in serialized
    assert "host_attack_owner_gid" not in serialized
    with pytest.raises(FrozenInstanceError):
        snapshot.provisioning.marker_sha256 = "0" * 64  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        snapshot.verification.after.control_lstat_exists = True  # type: ignore[misc]


def test_raw_host_measurement_is_redacted_and_not_serializable() -> None:
    oracle = PhpIncludeOracle()
    oracle.begin_generation()
    measurement = _host_measurement(oracle)

    assert repr(measurement) == "PhpIncludeHostFilesystemMeasurement(<redacted>)"
    assert str(measurement) == "PhpIncludeHostFilesystemMeasurement(<redacted>)"
    assert not hasattr(measurement, "as_dict")
    with pytest.raises(TypeError):
        json.dumps(measurement)


def test_host_identity_is_opaque_and_generation_scoped() -> None:
    oracle = PhpIncludeOracle()
    oracle.begin_generation()
    first_provisioning = _provision(oracle)
    first_snapshot = _verify(
        oracle,
        first_provisioning.filesystem.measured_monotonic_ns,
    )
    first_identity = first_snapshot.provisioning.host_filesystem.host_identity_sha256
    stale_measurement = _host_measurement(oracle)

    oracle.begin_generation()
    started_ns = time.monotonic_ns()
    finished_ns = time.monotonic_ns()
    with pytest.raises(PhpIncludeAttestationError) as caught:
        oracle.attest_provisioning(
            generation_id=oracle.generation_id,
            attack_resource_path=oracle.attack_path,
            control_resource_path=oracle.control_path,
            attack_content_sha256=_content_sha256(oracle),
            attack_content_size_bytes=len(oracle.private_attack_content),
            attack_owner_uid=0,
            attack_owner_gid=0,
            attack_file_mode=PHP_INCLUDE_ORACLE_FILE_MODE,
            attack_link_count=1,
            attack_is_regular_file=True,
            attack_is_symlink=False,
            control_lstat_exists=False,
            host_measurement=stale_measurement,
            started_monotonic_ns=started_ns,
            finished_monotonic_ns=finished_ns,
        )
    assert (caught.value.field, caught.value.category) == (
        "host_attack_content_sha256",
        "mismatch",
    )

    second_provisioning = _provision(oracle)
    second_snapshot = _verify(
        oracle,
        second_provisioning.filesystem.measured_monotonic_ns,
    )
    second_identity = second_snapshot.provisioning.host_filesystem.host_identity_sha256

    assert first_identity != second_identity
    for bare_identity in (
        f"{_HOST_DEVICE}:{_HOST_INODE}",
        f"{_HOST_DEVICE}\x00{_HOST_INODE}",
    ):
        assert first_identity != hashlib.sha256(bare_identity.encode()).hexdigest()
        assert second_identity != hashlib.sha256(bare_identity.encode()).hexdigest()


@pytest.mark.parametrize(
    ("override", "value", "field", "category"),
    [
        ("generation_id", "0" * 64, "generation_id", "mismatch"),
        (
            "attack_resource_path",
            "/tmp/not-the-attack-path.php",
            "attack_resource_path",
            "mismatch",
        ),
        (
            "control_resource_path",
            "/tmp/not-the-control-path.php",
            "control_resource_path",
            "mismatch",
        ),
        (
            "attack_content_sha256",
            "0" * 64,
            "attack_content_sha256",
            "mismatch",
        ),
        (
            "attack_content_size_bytes",
            0,
            "attack_content_size_bytes",
            "mismatch",
        ),
        ("attack_owner_uid", True, "attack_owner_uid", "invalid_shape"),
        ("attack_owner_gid", -1, "attack_owner_gid", "invalid_shape"),
        ("attack_file_mode", 0o644, "attack_file_mode", "mismatch"),
        ("attack_link_count", 2, "attack_link_count", "mismatch"),
        (
            "attack_is_regular_file",
            False,
            "attack_is_regular_file",
            "unsafe_state",
        ),
        ("attack_is_symlink", True, "attack_is_symlink", "unsafe_state"),
        (
            "control_lstat_exists",
            True,
            "control_lstat_exists",
            "unsafe_state",
        ),
        (
            "started_monotonic_ns",
            0,
            "started_monotonic_ns",
            "invalid_shape",
        ),
        (
            "finished_monotonic_ns",
            1,
            "finished_monotonic_ns",
            "out_of_order",
        ),
    ],
)
def test_provisioning_rejects_inexact_or_unsafe_state(
    override: str,
    value: object,
    field: str,
    category: str,
) -> None:
    oracle = PhpIncludeOracle()
    oracle.begin_generation()
    started_ns = time.monotonic_ns()
    host_measurement = _host_measurement(oracle)
    finished_ns = time.monotonic_ns()
    values: dict[str, object] = {
        "generation_id": oracle.generation_id,
        "attack_resource_path": oracle.attack_path,
        "control_resource_path": oracle.control_path,
        "attack_content_sha256": _content_sha256(oracle),
        "attack_content_size_bytes": len(oracle.private_attack_content),
        "attack_owner_uid": 0,
        "attack_owner_gid": 0,
        "attack_file_mode": PHP_INCLUDE_ORACLE_FILE_MODE,
        "attack_link_count": 1,
        "attack_is_regular_file": True,
        "attack_is_symlink": False,
        "control_lstat_exists": False,
        "host_measurement": host_measurement,
        "started_monotonic_ns": started_ns,
        "finished_monotonic_ns": finished_ns,
    }
    values[override] = value

    with pytest.raises(
        PhpIncludeAttestationError,
        match="provisioning attestation",
    ) as caught:
        oracle.attest_provisioning(**values)  # type: ignore[arg-type]
    assert caught.value.phase == "provisioning"
    assert caught.value.field == field
    assert caught.value.category == category
    assert caught.value.reason == f"{field}_{category}"
    with pytest.raises(RuntimeError, match="incomplete or unverified"):
        oracle.snapshot()
    with pytest.raises(RuntimeError, match="cannot rotate an unfinished"):
        oracle.begin_generation()


@pytest.mark.parametrize(
    ("override", "value", "field", "category"),
    [
        (
            "attack_content_sha256",
            "0" * 64,
            "host_attack_content_sha256",
            "mismatch",
        ),
        (
            "attack_content_size_bytes",
            0,
            "host_attack_content_size_bytes",
            "mismatch",
        ),
        (
            "attack_owner_uid",
            os.geteuid() + 1,
            "host_attack_owner",
            "mismatch",
        ),
        (
            "attack_owner_gid",
            True,
            "host_attack_owner",
            "invalid_shape",
        ),
        (
            "attack_file_mode",
            0o644,
            "host_attack_file_mode",
            "mismatch",
        ),
        (
            "attack_link_count",
            2,
            "host_attack_link_count",
            "mismatch",
        ),
        (
            "attack_is_regular_file",
            False,
            "host_attack_is_regular_file",
            "unsafe_state",
        ),
        (
            "attack_is_symlink",
            True,
            "host_attack_is_symlink",
            "unsafe_state",
        ),
        (
            "control_lstat_exists",
            True,
            "host_control_lstat_exists",
            "unsafe_state",
        ),
        (
            "attack_device",
            True,
            "host_attack_device",
            "invalid_shape",
        ),
        (
            "attack_inode",
            0,
            "host_attack_inode",
            "invalid_shape",
        ),
        (
            "measured_monotonic_ns",
            0,
            "host_measured_monotonic_ns",
            "invalid_shape",
        ),
    ],
)
def test_provisioning_rejects_invalid_raw_host_measurement(
    override: str,
    value: object,
    field: str,
    category: str,
) -> None:
    oracle = PhpIncludeOracle()
    oracle.begin_generation()
    started_ns = time.monotonic_ns()
    host_measurement = _host_measurement(
        oracle,
        overrides={override: value},
    )
    finished_ns = time.monotonic_ns()

    with pytest.raises(PhpIncludeAttestationError) as caught:
        oracle.attest_provisioning(
            generation_id=oracle.generation_id,
            attack_resource_path=oracle.attack_path,
            control_resource_path=oracle.control_path,
            attack_content_sha256=_content_sha256(oracle),
            attack_content_size_bytes=len(oracle.private_attack_content),
            attack_owner_uid=0,
            attack_owner_gid=0,
            attack_file_mode=PHP_INCLUDE_ORACLE_FILE_MODE,
            attack_link_count=1,
            attack_is_regular_file=True,
            attack_is_symlink=False,
            control_lstat_exists=False,
            host_measurement=host_measurement,
            started_monotonic_ns=started_ns,
            finished_monotonic_ns=finished_ns,
        )

    assert (caught.value.field, caught.value.category) == (field, category)
    assert repr(host_measurement) == ("PhpIncludeHostFilesystemMeasurement(<redacted>)")
    assert str(value) not in str(caught.value)


def test_provisioning_requires_an_exact_raw_host_measurement_object() -> None:
    oracle = PhpIncludeOracle()
    oracle.begin_generation()
    started_ns = time.monotonic_ns()
    finished_ns = time.monotonic_ns()

    with pytest.raises(PhpIncludeAttestationError) as caught:
        oracle.attest_provisioning(
            generation_id=oracle.generation_id,
            attack_resource_path=oracle.attack_path,
            control_resource_path=oracle.control_path,
            attack_content_sha256=_content_sha256(oracle),
            attack_content_size_bytes=len(oracle.private_attack_content),
            attack_owner_uid=0,
            attack_owner_gid=0,
            attack_file_mode=PHP_INCLUDE_ORACLE_FILE_MODE,
            attack_link_count=1,
            attack_is_regular_file=True,
            attack_is_symlink=False,
            control_lstat_exists=False,
            host_measurement={},  # type: ignore[arg-type]
            started_monotonic_ns=started_ns,
            finished_monotonic_ns=finished_ns,
        )

    assert (caught.value.field, caught.value.category) == (
        "host_measurement",
        "invalid_shape",
    )


@pytest.mark.parametrize("position", ["before", "after", "future"])
def test_provisioning_rejects_host_measurement_outside_parent_interval(
    position: str,
) -> None:
    oracle = PhpIncludeOracle()
    oracle.begin_generation()
    started_ns = time.monotonic_ns()
    if position == "before":
        measured_ns = started_ns - 1
        finished_ns = time.monotonic_ns()
        expected_category = "out_of_order"
    elif position == "after":
        finished_ns = time.monotonic_ns()
        measured_ns = time.monotonic_ns()
        expected_category = "out_of_order"
    else:
        finished_ns = time.monotonic_ns()
        measured_ns = time.monotonic_ns() + 1_000_000_000
        expected_category = "future"
    host_measurement = _host_measurement(
        oracle,
        measured_monotonic_ns=measured_ns,
    )

    with pytest.raises(PhpIncludeAttestationError) as caught:
        oracle.attest_provisioning(
            generation_id=oracle.generation_id,
            attack_resource_path=oracle.attack_path,
            control_resource_path=oracle.control_path,
            attack_content_sha256=_content_sha256(oracle),
            attack_content_size_bytes=len(oracle.private_attack_content),
            attack_owner_uid=0,
            attack_owner_gid=0,
            attack_file_mode=PHP_INCLUDE_ORACLE_FILE_MODE,
            attack_link_count=1,
            attack_is_regular_file=True,
            attack_is_symlink=False,
            control_lstat_exists=False,
            host_measurement=host_measurement,
            started_monotonic_ns=started_ns,
            finished_monotonic_ns=finished_ns,
        )

    assert (caught.value.field, caught.value.category) == (
        "host_measured_monotonic_ns",
        expected_category,
    )


@pytest.mark.parametrize(
    ("override", "value", "field", "category"),
    [
        ("generation_id", "0" * 64, "generation_id", "mismatch"),
        (
            "attack_resource_path",
            "/tmp/not-the-attack-path.php",
            "attack_resource_path",
            "mismatch",
        ),
        (
            "control_resource_path",
            "/tmp/not-the-control-path.php",
            "control_resource_path",
            "mismatch",
        ),
        (
            "after_attack_content_sha256",
            "0" * 64,
            "attack_content_sha256",
            "mismatch",
        ),
        (
            "after_attack_content_size_bytes",
            0,
            "attack_content_size_bytes",
            "mismatch",
        ),
        ("after_attack_owner_uid", True, "attack_owner_uid", "invalid_shape"),
        ("after_attack_owner_gid", -1, "attack_owner_gid", "invalid_shape"),
        ("after_attack_file_mode", 0o644, "attack_file_mode", "mismatch"),
        ("after_attack_link_count", 2, "attack_link_count", "mismatch"),
        (
            "after_attack_is_regular_file",
            False,
            "attack_is_regular_file",
            "unsafe_state",
        ),
        (
            "after_attack_is_symlink",
            True,
            "attack_is_symlink",
            "unsafe_state",
        ),
        (
            "after_control_lstat_exists",
            True,
            "control_lstat_exists",
            "unsafe_state",
        ),
        (
            "execution_started_monotonic_ns",
            1,
            "execution_started_monotonic_ns",
            "out_of_order",
        ),
        (
            "execution_finished_monotonic_ns",
            1,
            "execution_finished_monotonic_ns",
            "out_of_order",
        ),
        (
            "after_monotonic_ns",
            1,
            "after_monotonic_ns",
            "out_of_order",
        ),
    ],
)
def test_verification_rejects_changed_or_unbounded_state(
    override: str,
    value: object,
    field: str,
    category: str,
) -> None:
    oracle = PhpIncludeOracle()
    oracle.begin_generation()
    provisioning = _provision(oracle)
    execution_started_ns = max(
        provisioning.filesystem.measured_monotonic_ns,
        time.monotonic_ns(),
    )
    execution_finished_ns = time.monotonic_ns()
    after_host_measurement = _host_measurement(oracle)
    after_ns = time.monotonic_ns()
    values: dict[str, object] = {
        "generation_id": oracle.generation_id,
        "attack_resource_path": oracle.attack_path,
        "control_resource_path": oracle.control_path,
        "after_attack_content_sha256": _content_sha256(oracle),
        "after_attack_content_size_bytes": len(oracle.private_attack_content),
        "after_attack_owner_uid": 0,
        "after_attack_owner_gid": 0,
        "after_attack_file_mode": PHP_INCLUDE_ORACLE_FILE_MODE,
        "after_attack_link_count": 1,
        "after_attack_is_regular_file": True,
        "after_attack_is_symlink": False,
        "after_control_lstat_exists": False,
        "after_host_measurement": after_host_measurement,
        "execution_started_monotonic_ns": execution_started_ns,
        "execution_finished_monotonic_ns": execution_finished_ns,
        "after_monotonic_ns": after_ns,
    }
    values[override] = value

    with pytest.raises(
        PhpIncludeAttestationError,
        match="verification attestation",
    ) as caught:
        oracle.attest_verification(**values)  # type: ignore[arg-type]
    assert caught.value.phase == "verification"
    assert caught.value.field == field
    assert caught.value.category == category
    assert caught.value.reason == f"{field}_{category}"
    with pytest.raises(RuntimeError, match="incomplete or unverified"):
        oracle.snapshot()
    with pytest.raises(RuntimeError, match="cannot rotate an unfinished"):
        oracle.begin_generation()


@pytest.mark.parametrize(
    ("override", "value", "field", "category"),
    [
        (
            "attack_content_sha256",
            "0" * 64,
            "host_attack_content_sha256",
            "mismatch",
        ),
        (
            "attack_content_size_bytes",
            0,
            "host_attack_content_size_bytes",
            "mismatch",
        ),
        (
            "attack_owner_uid",
            os.geteuid() + 1,
            "host_attack_owner",
            "mismatch",
        ),
        (
            "attack_file_mode",
            0o644,
            "host_attack_file_mode",
            "mismatch",
        ),
        (
            "attack_link_count",
            2,
            "host_attack_link_count",
            "mismatch",
        ),
        (
            "attack_is_regular_file",
            False,
            "host_attack_is_regular_file",
            "unsafe_state",
        ),
        (
            "attack_is_symlink",
            True,
            "host_attack_is_symlink",
            "unsafe_state",
        ),
        (
            "control_lstat_exists",
            True,
            "host_control_lstat_exists",
            "unsafe_state",
        ),
        (
            "attack_device",
            _HOST_DEVICE + 1,
            "host_identity_sha256",
            "mismatch",
        ),
        (
            "attack_inode",
            _HOST_INODE + 1,
            "host_identity_sha256",
            "mismatch",
        ),
    ],
)
def test_verification_rejects_changed_authoritative_host_state(
    override: str,
    value: object,
    field: str,
    category: str,
) -> None:
    oracle = PhpIncludeOracle()
    oracle.begin_generation()
    provisioning = _provision(oracle)
    execution_started_ns = time.monotonic_ns()
    execution_finished_ns = time.monotonic_ns()
    host_measurement = _host_measurement(
        oracle,
        overrides={override: value},
    )
    after_ns = time.monotonic_ns()

    with pytest.raises(PhpIncludeAttestationError) as caught:
        oracle.attest_verification(
            generation_id=oracle.generation_id,
            attack_resource_path=oracle.attack_path,
            control_resource_path=oracle.control_path,
            after_attack_content_sha256=_content_sha256(oracle),
            after_attack_content_size_bytes=len(oracle.private_attack_content),
            after_attack_owner_uid=33,
            after_attack_owner_gid=33,
            after_attack_file_mode=PHP_INCLUDE_ORACLE_FILE_MODE,
            after_attack_link_count=1,
            after_attack_is_regular_file=True,
            after_attack_is_symlink=False,
            after_control_lstat_exists=False,
            after_host_measurement=host_measurement,
            execution_started_monotonic_ns=max(
                execution_started_ns,
                provisioning.filesystem.measured_monotonic_ns,
            ),
            execution_finished_monotonic_ns=execution_finished_ns,
            after_monotonic_ns=after_ns,
        )

    assert (caught.value.field, caught.value.category) == (field, category)
    assert caught.value.args == ("invalid PHP include verification attestation",)


@pytest.mark.parametrize("position", ["before", "after", "future"])
def test_verification_rejects_host_measurement_outside_parent_interval(
    position: str,
) -> None:
    oracle = PhpIncludeOracle()
    oracle.begin_generation()
    _provision(oracle)
    execution_started_ns = time.monotonic_ns()
    execution_finished_ns = time.monotonic_ns()
    if position == "before":
        host_measured_ns = execution_finished_ns - 1
        after_ns = time.monotonic_ns()
        expected_category = "out_of_order"
    elif position == "after":
        after_ns = time.monotonic_ns()
        host_measured_ns = time.monotonic_ns()
        expected_category = "out_of_order"
    else:
        after_ns = time.monotonic_ns()
        host_measured_ns = time.monotonic_ns() + 1_000_000_000
        expected_category = "future"
    host_measurement = _host_measurement(
        oracle,
        measured_monotonic_ns=host_measured_ns,
    )

    with pytest.raises(PhpIncludeAttestationError) as caught:
        oracle.attest_verification(
            generation_id=oracle.generation_id,
            attack_resource_path=oracle.attack_path,
            control_resource_path=oracle.control_path,
            after_attack_content_sha256=_content_sha256(oracle),
            after_attack_content_size_bytes=len(oracle.private_attack_content),
            after_attack_owner_uid=33,
            after_attack_owner_gid=33,
            after_attack_file_mode=PHP_INCLUDE_ORACLE_FILE_MODE,
            after_attack_link_count=1,
            after_attack_is_regular_file=True,
            after_attack_is_symlink=False,
            after_control_lstat_exists=False,
            after_host_measurement=host_measurement,
            execution_started_monotonic_ns=execution_started_ns,
            execution_finished_monotonic_ns=execution_finished_ns,
            after_monotonic_ns=after_ns,
        )

    assert (caught.value.field, caught.value.category) == (
        "host_measured_monotonic_ns",
        expected_category,
    )


def test_attestation_lifecycle_is_ordered_single_use_and_fail_closed() -> None:
    oracle = PhpIncludeOracle()
    with pytest.raises(RuntimeError, match="generation state is invalid"):
        _provision(oracle)

    oracle.begin_generation()
    with pytest.raises(RuntimeError, match="not provisioned"):
        oracle.attest_verification(
            generation_id=oracle.generation_id,
            attack_resource_path=oracle.attack_path,
            control_resource_path=oracle.control_path,
            after_attack_content_sha256=_content_sha256(oracle),
            after_attack_content_size_bytes=len(oracle.private_attack_content),
            after_attack_owner_uid=0,
            after_attack_owner_gid=0,
            after_attack_file_mode=PHP_INCLUDE_ORACLE_FILE_MODE,
            after_attack_link_count=1,
            after_attack_is_regular_file=True,
            after_attack_is_symlink=False,
            after_control_lstat_exists=False,
            after_host_measurement=_host_measurement(oracle),
            execution_started_monotonic_ns=time.monotonic_ns(),
            execution_finished_monotonic_ns=time.monotonic_ns(),
            after_monotonic_ns=time.monotonic_ns(),
        )

    provisioning = _provision(oracle)
    with pytest.raises(RuntimeError, match="already attested"):
        _provision(oracle)
    snapshot = _verify(oracle, provisioning.filesystem.measured_monotonic_ns)
    with pytest.raises(RuntimeError, match="already verified"):
        _verify(oracle, provisioning.filesystem.measured_monotonic_ns)

    object.__setattr__(
        snapshot.provisioning.filesystem,
        "control_lstat_exists",
        True,
    )
    with pytest.raises(RuntimeError, match="provisioning state is malformed"):
        oracle.snapshot()
    with pytest.raises(RuntimeError, match="provisioning state is malformed"):
        oracle.begin_generation()


def test_corrupted_sanitized_host_attestation_fails_closed() -> None:
    oracle = PhpIncludeOracle()
    oracle.begin_generation()
    provisioning = _provision(oracle)
    snapshot = _verify(oracle, provisioning.filesystem.measured_monotonic_ns)

    object.__setattr__(
        snapshot.verification.host_after,
        "host_identity_sha256",
        "0" * 64,
    )

    with pytest.raises(RuntimeError, match="verification state is malformed"):
        oracle.snapshot()
    with pytest.raises(RuntimeError, match="verification state is malformed"):
        oracle.begin_generation()


def test_corrupted_public_or_private_state_fails_closed() -> None:
    public_oracle = PhpIncludeOracle()
    object.__setattr__(
        public_oracle,
        "_control_path",
        "/var/lib/squadrone/php-include/not-issued.php",
    )
    with pytest.raises(RuntimeError, match="public path state is invalid"):
        public_oracle.public_context()
    with pytest.raises(RuntimeError, match="public path state is invalid"):
        public_oracle.begin_generation()

    private_oracle = PhpIncludeOracle()
    private_oracle.begin_generation()
    object.__setattr__(private_oracle, "_marker", "SQUADRONE_PHP_INCLUDE_" + "0" * 64)
    with pytest.raises(RuntimeError, match="generation state is invalid"):
        _ = private_oracle.private_attack_content
    with pytest.raises(RuntimeError, match="generation state is invalid"):
        _provision(private_oracle)

    wrong_public_type = PhpIncludeOracle()
    object.__setattr__(wrong_public_type, "_attack_capability", 1)
    with pytest.raises(RuntimeError, match="public path state is invalid"):
        wrong_public_type.public_context()

    wrong_private_type = PhpIncludeOracle()
    wrong_private_type.begin_generation()
    object.__setattr__(wrong_private_type, "_generation_id", None)
    with pytest.raises(RuntimeError, match="generation state is invalid"):
        _ = wrong_private_type.private_marker

    falsey_lifecycle_type = PhpIncludeOracle()
    object.__setattr__(falsey_lifecycle_type, "_generation_id", 0)
    with pytest.raises(RuntimeError, match="lifecycle state is invalid"):
        falsey_lifecycle_type.begin_generation()
