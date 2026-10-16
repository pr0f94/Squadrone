from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path

import pytest

import squadrone.services.sandbox as sandbox_module
from squadrone.poc_proxy import salted_scalar_sha256
from squadrone.schemas.config import SandboxConfig
from squadrone.schemas.observation import CIAImpact, PoCObservation
from squadrone.services.sandbox import (
    SandboxManager,
    SandboxRunResult,
    validate_execution_response_marker_http_trace,
    validate_poc_observation,
    validate_second_order_sqli_http_trace,
)

_TARGET = "http://127.0.0.1:48080"
_SALT = bytes.fromhex("31" * 32)
_SECRET = bytes.fromhex("42" * 32)
_TOKEN = "53" * 32
_WRITE_MARKER = "write-confirmed"
_SENTINEL_FLAGS = {
    "target": False,
    "target_encoded": False,
    "body": False,
    "body_encoded": False,
    "headers": False,
    "headers_encoded": False,
}


def test_parent_trace_transport_preserves_meaningful_trailing_slashes() -> None:
    with_slash = {
        "method": "POST",
        "route": "/store/",
        "dispatch": {},
    }
    without_slash = {**with_slash, "route": "/store"}

    assert sandbox_module._expected_trace_transport(with_slash) == (
        "POST",
        "/store/",
        (),
    )
    assert sandbox_module._expected_trace_transport(without_slash) == (
        "POST",
        "/store",
        (),
    )
    assert sandbox_module._exact_trace_record_transport_key(
        {"method": "POST", "path": "/store/"}
    ) == ("POST", "/store/")


@pytest.mark.parametrize(
    "path",
    [
        "/store//item",
        "/store/../item",
        "/store/%69tem",
        "/store\\item",
        " /store/item",
    ],
)
def test_parent_trace_transport_rejects_noncanonical_paths(path: str) -> None:
    assert (
        sandbox_module._exact_trace_record_transport_key(
            {"method": "POST", "path": path}
        )
        is None
    )


def _receipt(
    record: dict[str, object],
    *,
    user_id: int = 0,
    roles: tuple[str, ...] = (),
) -> str:
    payload = {
        "v": 2,
        "trace_token": _TOKEN,
        "nonce": f"{int(record['sequence']) + 100:032x}",
        "request_nonce": record["request_nonce"],
        "request_digest": record["request_digest"],
        "user_id": user_id,
        "roles": list(roles),
        "method": record["method"],
        "path": record["path"],
    }
    encoded = (
        base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode()
        )
        .decode("ascii")
        .rstrip("=")
    )
    signature = hmac.new(_SECRET, encoded.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{encoded}.{signature}"


def _record(
    sequence: int,
    *,
    method: str,
    path: str,
    fields: dict[tuple[str, str], str],
    response: str = "ok",
    status: int = 200,
    duration_seconds: float = 0.1,
    tracked_marker: tuple[str, str] | None = None,
    user_id: int = 0,
    roles: tuple[str, ...] = (),
) -> dict[str, object]:
    captured_fields = []
    for (location, name), value in fields.items():
        labels = []
        if tracked_marker is not None and tracked_marker[1] in value:
            labels.append(tracked_marker[0])
        captured_fields.append(
            {
                "location": location,
                "name": name,
                "kind": "scalar",
                "value_sha256": salted_scalar_sha256(value, _SALT),
                "contains_squadrone_sentinel": "SQUADRONE_" in value,
                "tracked_capabilities": labels,
            }
        )
    captured_fields.sort(
        key=lambda field: (
            field["location"],
            field["name"],
            field["kind"],
            field["value_sha256"],
        )
    )
    shape = [
        {"location": location, "name": name, "kind": "scalar", "count": 1}
        for location, name in sorted(fields)
    ]
    response_bytes = response.encode()
    started = sequence * 10_000_000_000
    record: dict[str, object] = {
        "trace_version": 1,
        "record_type": "request",
        "sequence": sequence,
        "request_nonce": f"{sequence:064x}",
        "request_digest": hashlib.sha256(f"request-{sequence}".encode()).hexdigest(),
        "request_headers_sha256": "a" * 64,
        "upstream_started_monotonic_ns": started,
        "upstream_finished_monotonic_ns": started
        + int(duration_seconds * 1_000_000_000),
        "method": method,
        "origin": _TARGET,
        "path": path,
        "fields": captured_fields,
        "parameter_shape": shape,
        "request_sentinel_flags": dict(_SENTINEL_FLAGS),
        "request_sentinel_categories": [],
        "request_tracked_capabilities_in_headers": [],
        "status_code": status,
        "response_body_sha256": hashlib.sha256(response_bytes).hexdigest(),
        "response_body_length": len(response_bytes),
        "response_body_b64": base64.b64encode(response_bytes).decode("ascii"),
        "response_body_tail_b64": "",
        "response_body_truncated": False,
        "response_actor_receipt": None,
        "response_actor_receipt_truncated": False,
        "forward_state": "completed",
        "forward_error": None,
        "terminal": False,
    }
    record["response_actor_receipt"] = _receipt(
        record,
        user_id=user_id,
        roles=roles,
    )
    return record


def _execution_observation(
    marker: str,
    *,
    attacker_role: str = "unauthenticated",
) -> PoCObservation:
    return PoCObservation(
        verdict="vulnerable",
        oracle="response_marker",
        attacker_role=attacker_role,
        request={"method": "POST", "url": f"{_TARGET}/execute"},
        attack={"observed": True, "marker": marker, "marker_present": True},
        control={"observed": False, "marker_present": False},
        impact=CIAImpact(
            integrity="high",
            description="The reviewed command sink constructed the marker.",
        ),
    )


def _legacy_execution_marker_requires_parent_captured_control_then_attack() -> None:
    marker = "SQUADRONE_COMMAND_EXEC_4F6C2A91"
    observation = _execution_observation(marker)
    transport: dict[str, object] = {
        "method": "POST",
        "route": "/execute",
        "dispatch": {"form:action": "run"},
        "destination_parameter": "command",
        "destination_location": "form",
    }
    records = [
        _record(
            1,
            method="POST",
            path="/execute",
            fields={
                ("form", "action"): "run",
                ("form", "command"): "benign",
            },
            tracked_marker=("execution_marker", marker),
        ),
        _record(
            2,
            method="POST",
            path="/execute",
            fields={
                ("form", "action"): "run",
                ("form", "command"): "attack-with-runtime-construction",
            },
            response=f"result:{marker}",
            tracked_marker=("execution_marker", marker),
        ),
    ]

    accepted, reason, evidence = validate_execution_response_marker_http_trace(
        observation,
        records,
        trace_salt=_SALT,
        target_url=_TARGET,
        receipt_secret=_SECRET,
        trace_token=_TOKEN,
        expected_http_transport=transport,
        expected_attacker_role="unauthenticated",
        expected_bug_class="CWE-78",
        expected_execution_marker=marker,
    )

    assert accepted is True, reason
    assert evidence["transmitted_marker_absent"] is True
    assert evidence["control"]["sequence"] == 1
    assert evidence["attack"]["sequence"] == 2

    records[1]["request_headers_sha256"] = "b" * 64
    accepted, reason, _evidence = validate_execution_response_marker_http_trace(
        observation,
        records,
        trace_salt=_SALT,
        target_url=_TARGET,
        receipt_secret=_SECRET,
        trace_token=_TOKEN,
        expected_http_transport=transport,
        expected_attacker_role="unauthenticated",
        expected_bug_class="CWE-78",
        expected_execution_marker=marker,
    )
    assert accepted is False
    assert "envelopes" in reason


def _legacy_execution_allows_only_declared_source_bound_form_preflight() -> None:
    marker = "SQUADRONE_COMMAND_EXEC_4F6C2A91"
    observation = _execution_observation(marker, attacker_role="contributor")
    transport: dict[str, object] = {
        "method": "POST",
        "route": "/execute",
        "dispatch": {"form:action": "run"},
        "destination_parameter": "command",
        "destination_location": "form",
    }
    contributor = {"user_id": 7, "roles": ("contributor",)}
    records = [
        _record(1, method="GET", path="/wp-login.php", fields={}),
        _record(
            2,
            method="POST",
            path="/wp-login.php",
            status=302,
            fields={
                ("form", "log"): "contributor",
                ("form", "pwd"): "password",
                ("form", "wp-submit"): "Log In",
                ("form", "redirect_to"): f"{_TARGET}/wp-admin/",
                ("form", "testcookie"): "1",
            },
        ),
        _record(3, method="GET", path="/wp-admin/", fields={}, **contributor),
        _record(4, method="GET", path="/wp-admin/", fields={}, **contributor),
        _record(
            5,
            method="GET",
            path="/wp-admin/admin-ajax.php",
            fields={("query", "action"): "rest-nonce"},
            **contributor,
        ),
        _record(
            6,
            method="GET",
            path="/",
            fields={
                ("query", "rest_route"): "/wp/v2/users/me",
                ("query", "context"): "edit",
            },
            **contributor,
        ),
        _record(
            7,
            method="GET",
            path="/wp-admin/admin.php",
            fields={("query", "page"): "plugin-form"},
            response="source-reviewed form",
            **contributor,
        ),
        _record(
            8,
            method="POST",
            path="/execute",
            fields={("form", "action"): "run", ("form", "command"): "benign"},
            tracked_marker=("execution_marker", marker),
            **contributor,
        ),
        _record(
            9,
            method="POST",
            path="/execute",
            fields={
                ("form", "action"): "run",
                ("form", "command"): "runtime-construction",
            },
            response=marker,
            tracked_marker=("execution_marker", marker),
            **contributor,
        ),
    ]
    declared = [
        {
            "method": "GET",
            "route": "/wp-admin/admin.php",
            "dispatch": {"query:page": "plugin-form"},
        }
    ]

    accepted, reason, _evidence = validate_execution_response_marker_http_trace(
        observation,
        records,
        trace_salt=_SALT,
        target_url=_TARGET,
        receipt_secret=_SECRET,
        trace_token=_TOKEN,
        expected_http_transport=transport,
        expected_attacker_role="contributor",
        expected_bug_class="CWE-78",
        expected_execution_marker=marker,
        expected_preflight_http_transports=declared,
    )
    assert accepted is True, reason

    accepted, reason, _evidence = validate_execution_response_marker_http_trace(
        observation,
        records,
        trace_salt=_SALT,
        target_url=_TARGET,
        receipt_secret=_SECRET,
        trace_token=_TOKEN,
        expected_http_transport=transport,
        expected_attacker_role="contributor",
        expected_bug_class="CWE-78",
        expected_execution_marker=marker,
    )
    assert accepted is False
    assert "undeclared" in reason


def _legacy_execution_marker_rejects_marker_transmitted_in_attack_value() -> None:
    marker = "SQUADRONE_COMMAND_EXEC_4F6C2A91"
    observation = _execution_observation(marker)
    transport: dict[str, object] = {
        "method": "POST",
        "route": "/execute",
        "dispatch": {"form:action": "run"},
        "destination_parameter": "command",
        "destination_location": "form",
    }
    records = [
        _record(
            1,
            method="POST",
            path="/execute",
            fields={("form", "action"): "run", ("form", "command"): "benign"},
            tracked_marker=("execution_marker", marker),
        ),
        _record(
            2,
            method="POST",
            path="/execute",
            fields={("form", "action"): "run", ("form", "command"): marker},
            response=marker,
            tracked_marker=("execution_marker", marker),
        ),
    ]

    accepted, reason, _evidence = validate_execution_response_marker_http_trace(
        observation,
        records,
        trace_salt=_SALT,
        target_url=_TARGET,
        receipt_secret=_SECRET,
        trace_token=_TOKEN,
        expected_http_transport=transport,
        expected_attacker_role="unauthenticated",
        expected_bug_class="CWE-78",
        expected_execution_marker=marker,
    )

    assert accepted is False
    assert "transmitted" in reason


def _legacy_execution_marker_rejects_hidden_request_between_proof_arms() -> None:
    marker = "SQUADRONE_COMMAND_EXEC_4F6C2A91"
    observation = _execution_observation(marker)
    transport: dict[str, object] = {
        "method": "POST",
        "route": "/execute",
        "dispatch": {"form:action": "run"},
        "destination_parameter": "command",
        "destination_location": "form",
    }
    records = [
        _record(
            1,
            method="POST",
            path="/execute",
            fields={("form", "action"): "run", ("form", "command"): "benign"},
            tracked_marker=("execution_marker", marker),
        ),
        _record(
            2,
            method="POST",
            path="/hidden-setup",
            fields={("form", "state"): "mutate"},
            tracked_marker=("execution_marker", marker),
        ),
        _record(
            3,
            method="POST",
            path="/execute",
            fields={
                ("form", "action"): "run",
                ("form", "command"): "runtime-construction",
            },
            response=marker,
            tracked_marker=("execution_marker", marker),
        ),
    ]

    accepted, reason, _evidence = validate_execution_response_marker_http_trace(
        observation,
        records,
        trace_salt=_SALT,
        target_url=_TARGET,
        receipt_secret=_SECRET,
        trace_token=_TOKEN,
        expected_http_transport=transport,
        expected_attacker_role="unauthenticated",
        expected_bug_class="CWE-78",
        expected_execution_marker=marker,
    )

    assert accepted is False
    assert "causal-window" in reason


@pytest.mark.parametrize("expected_bug_class", ["CWE-78", "CWE-94"])
@pytest.mark.parametrize("oracle", ["state_change", "file_effect"])
def test_execution_rejects_child_authored_non_marker_oracles(
    expected_bug_class: str,
    oracle: str,
) -> None:
    if oracle == "state_change":
        attack = {"observed": True, "before": "safe", "after": "changed"}
        control = {"observed": False, "before": "safe", "after": "safe"}
    else:
        attack = {
            "observed": True,
            "before_exists": False,
            "after_exists": True,
            "exists": True,
            "path": "/tmp/command-effect",
            "file_sha256": "a" * 64,
        }
        control = {
            "observed": False,
            "before_exists": False,
            "after_exists": False,
            "exists": False,
            "path": "/tmp/command-control",
        }
    observation = PoCObservation(
        verdict="vulnerable",
        oracle=oracle,
        attacker_role="unauthenticated",
        request={"method": "POST", "url": f"{_TARGET}/execute"},
        attack=attack,
        control=control,
        impact=CIAImpact(integrity="high", description="A child-authored effect."),
    )

    accepted, reason = validate_poc_observation(
        observation,
        expected_bug_class=expected_bug_class,
        expected_attacker_role="unauthenticated",
    )

    assert accepted is False
    assert "expected one of ['response_marker']" in reason


def test_write_success_marker_is_exactly_source_bound(tmp_path: Path) -> None:
    script = tmp_path / "poc.py"
    script.write_text('WRITE_SUCCESS_MARKER = "write-confirmed-4F6C2A91"\n')

    assert sandbox_module._source_bound_write_success_marker_from_script(
        str(script),
        "write-confirmed-4F6C2A91",
    ) == "write-confirmed-4F6C2A91"
    assert (
        sandbox_module._source_bound_write_success_marker_from_script(
            str(script),
            "different-confirmation-91A2C6F4",
        )
        is None
    )
    assert sandbox_module._valid_write_success_marker("success") is False
    assert sandbox_module._valid_write_success_marker("aaaaaaaa") is False
    assert sandbox_module._valid_write_success_marker(" write-confirmed ") is False
    assert sandbox_module._valid_write_success_marker("écriture-confirmée-1234") is False

    script.write_text(
        'WRITE_SUCCESS_MARKER = "write-confirmed-4F6C2A91"\n'
        'WRITE_SUCCESS_MARKER = "write-confirmed-4F6C2A91"\n'
    )
    assert (
        sandbox_module._source_bound_write_success_marker_from_script(
            str(script),
            "write-confirmed-4F6C2A91",
        )
        is None
    )

    for expected, python_literal in (
        ('"updated":true', r'"\"updated\":true"'),
        ("writer's receipt", '"writer\'s receipt"'),
        ("<stored>", r'"\u003cstored\u003e"'),
    ):
        script.write_text(f"WRITE_SUCCESS_MARKER = {python_literal}\n")
        assert sandbox_module._source_bound_write_success_marker_from_script(
            str(script),
            expected,
        ) == expected


def _second_order_observation() -> PoCObservation:
    write = {"method": "POST", "url": f"{_TARGET}/store"}
    trigger = {"method": "GET", "url": f"{_TARGET}/render"}
    common = {
        "write_confirmed": True,
        "write_request": write,
        "trigger_request": trigger,
        "storage_binding": "option:example_query_fragment",
    }
    return PoCObservation(
        verdict="vulnerable",
        oracle="timing",
        attacker_role="unauthenticated",
        request=trigger,
        attack={
            "observed": True,
            "samples_seconds": [4.2, 4.3, 4.1, 4.2, 4.3, 4.1],
            **common,
        },
        control={
            "observed": False,
            "samples_seconds": [0.1, 0.2, 0.1, 0.2, 0.1, 0.2],
            **common,
        },
        impact=CIAImpact(
            confidentiality="high",
            description="A stored value changed later SQL execution.",
        ),
    )


@pytest.mark.parametrize("injection_order", [None, "direct"])
def test_non_second_order_sqli_rejects_lifecycle_observation_fields(
    injection_order: str | None,
) -> None:
    accepted, reason = validate_poc_observation(
        _second_order_observation(),
        expected_bug_class="CWE-89",
        expected_attacker_role="unauthenticated",
        expected_injection_order=injection_order,
    )

    assert accepted is False
    assert "non-second-order SQLi" in reason


def test_second_order_requires_three_samples_in_each_arm_order() -> None:
    observation = _second_order_observation()
    observation.attack["samples_seconds"] = [4.2] * 5
    observation.control["samples_seconds"] = [0.1] * 5

    accepted, reason = validate_poc_observation(
        observation,
        expected_bug_class="CWE-89",
        expected_attacker_role="unauthenticated",
        expected_injection_order="second",
    )

    assert accepted is False
    assert "at least six paired" in reason


def _second_order_timing_records(
    *,
    start_sequence: int = 0,
    sample_count: int = 6,
    delay_every_second_trigger: bool = False,
) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    sequence = start_sequence
    for sample in range(sample_count):
        arm_order = (
            ("control", "attack") if sample % 2 == 0 else ("attack", "control")
        )
        for arm_position, arm in enumerate(arm_order):
            write_value = "delayed-sql" if arm == "attack" else "safe"
            sequence += 1
            records.append(
                _record(
                    sequence,
                    method="POST",
                    path="/store",
                    fields={
                        ("form", "action"): "save",
                        ("form", "value"): write_value,
                    },
                    status=302,
                    duration_seconds=0.1,
                    response=f"{_WRITE_MARKER}:{write_value}",
                )
            )
            sequence += 1
            if delay_every_second_trigger:
                trigger_duration = 4.2 if arm_position == 1 else 0.1
            else:
                trigger_duration = 4.2 if arm == "attack" else 0.1
            records.append(
                _record(
                    sequence,
                    method="GET",
                    path="/render",
                    fields={("query", "view"): "render"},
                    status=200,
                    duration_seconds=trigger_duration + sample * 0.01,
                    response="rendered",
                )
            )
    return records


def test_second_order_timing_requires_parent_measured_write_trigger_cycles() -> None:
    observation = _second_order_observation()
    accepted, reason = validate_poc_observation(
        observation,
        expected_bug_class="CWE-89",
        expected_attacker_role="unauthenticated",
        expected_injection_order="second",
    )
    assert accepted is True, reason

    accepted, reason, evidence = validate_second_order_sqli_http_trace(
        observation,
        _second_order_timing_records(),
        trace_salt=_SALT,
        target_url=_TARGET,
        receipt_secret=_SECRET,
        trace_token=_TOKEN,
        expected_http_transport={
            "method": "POST",
            "route": "/store",
            "dispatch": {"form:action": "save"},
            "destination_parameter": "value",
            "destination_location": "form",
        },
        expected_trigger_http_transport={
            "method": "GET",
            "route": "/render",
            "dispatch": {"query:view": "render"},
        },
        expected_storage_binding="option:example_query_fragment",
        expected_attacker_role="unauthenticated",
        expected_write_success_marker=_WRITE_MARKER,
    )

    assert accepted is True, reason
    assert evidence["cycles"] == 6
    assert evidence["trigger_timing"]["trigger_only"] is True
    assert evidence["trigger_timing"]["alternating_arm_order"] is True
    assert set(evidence["trigger_timing"]["by_arm_order"]) == {
        "control_then_attack",
        "attack_then_control",
    }


def test_second_order_parent_promotion_replaces_fake_child_timing_samples() -> None:
    observation = _second_order_observation()
    child_attack_samples = [9.0] * 6
    child_control_samples = [1.0] * 6
    observation.attack["samples_seconds"] = child_attack_samples
    observation.control["samples_seconds"] = child_control_samples

    accepted, reason, evidence = validate_second_order_sqli_http_trace(
        observation,
        _second_order_timing_records(),
        trace_salt=_SALT,
        target_url=_TARGET,
        receipt_secret=_SECRET,
        trace_token=_TOKEN,
        expected_http_transport={
            "method": "POST",
            "route": "/store",
            "dispatch": {"form:action": "save"},
            "destination_parameter": "value",
            "destination_location": "form",
        },
        expected_trigger_http_transport={
            "method": "GET",
            "route": "/render",
            "dispatch": {"query:view": "render"},
        },
        expected_storage_binding="option:example_query_fragment",
        expected_attacker_role="unauthenticated",
        expected_write_success_marker=_WRITE_MARKER,
    )
    assert accepted is True, reason

    promoted = sandbox_module._parent_second_order_sqli_observation(
        observation,
        evidence,
    )
    parent_timing = evidence["trigger_timing"]

    assert promoted.attack["samples_seconds"] == parent_timing[
        "attack_samples_seconds"
    ]
    assert promoted.control["samples_seconds"] == parent_timing[
        "control_samples_seconds"
    ]
    assert promoted.attack["samples_seconds"] != child_attack_samples
    assert promoted.control["samples_seconds"] != child_control_samples
    assert child_attack_samples == [9.0] * 6
    assert child_control_samples == [1.0] * 6


def test_second_order_parent_trace_requires_three_samples_per_order() -> None:
    observation = _second_order_observation()
    observation.attack["samples_seconds"] = [4.2] * 5
    observation.control["samples_seconds"] = [0.1] * 5

    accepted, reason, evidence = validate_second_order_sqli_http_trace(
        observation,
        _second_order_timing_records(sample_count=5),
        trace_salt=_SALT,
        target_url=_TARGET,
        receipt_secret=_SECRET,
        trace_token=_TOKEN,
        expected_http_transport={
            "method": "POST",
            "route": "/store",
            "dispatch": {"form:action": "save"},
            "destination_parameter": "value",
            "destination_location": "form",
        },
        expected_trigger_http_transport={
            "method": "GET",
            "route": "/render",
            "dispatch": {"query:view": "render"},
        },
        expected_storage_binding="option:example_query_fragment",
        expected_attacker_role="unauthenticated",
        expected_write_success_marker=_WRITE_MARKER,
    )

    assert accepted is False
    assert "at least six paired cycles" in reason
    assert evidence == {}


def test_second_order_partitions_declared_read_on_trigger_route() -> None:
    observation = _second_order_observation()
    records = [
        _record(
            1,
            method="GET",
            path="/render",
            fields={("query", "view"): "form"},
            response="source-reviewed nonce form",
        ),
        *_second_order_timing_records(start_sequence=1),
    ]

    accepted, reason, evidence = validate_second_order_sqli_http_trace(
        observation,
        records,
        trace_salt=_SALT,
        target_url=_TARGET,
        receipt_secret=_SECRET,
        trace_token=_TOKEN,
        expected_http_transport={
            "method": "POST",
            "route": "/store",
            "dispatch": {"form:action": "save"},
            "destination_parameter": "value",
            "destination_location": "form",
        },
        expected_trigger_http_transport={
            "method": "GET",
            "route": "/render",
            "dispatch": {"query:view": "render"},
        },
        expected_storage_binding="option:example_query_fragment",
        expected_attacker_role="unauthenticated",
        expected_write_success_marker=_WRITE_MARKER,
        expected_preflight_http_transports=[
            {
                "method": "GET",
                "route": "/render",
                "dispatch": {"query:view": "form"},
            }
        ],
    )

    assert accepted is True, reason
    assert evidence["cycles"] == 6


def test_second_order_rejects_fixed_every_second_trigger_delay() -> None:
    observation = _second_order_observation()
    observation.attack["samples_seconds"] = [4.2] * 7
    observation.control["samples_seconds"] = [0.1] * 7

    accepted, reason, evidence = validate_second_order_sqli_http_trace(
        observation,
        _second_order_timing_records(
            sample_count=7,
            delay_every_second_trigger=True,
        ),
        trace_salt=_SALT,
        target_url=_TARGET,
        receipt_secret=_SECRET,
        trace_token=_TOKEN,
        expected_http_transport={
            "method": "POST",
            "route": "/store",
            "dispatch": {"form:action": "save"},
            "destination_parameter": "value",
            "destination_location": "form",
        },
        expected_trigger_http_transport={
            "method": "GET",
            "route": "/render",
            "dispatch": {"query:view": "render"},
        },
        expected_storage_binding="option:example_query_fragment",
        expected_attacker_role="unauthenticated",
        expected_write_success_marker=_WRITE_MARKER,
    )

    assert accepted is False
    assert "attack-then-control arm order" in reason
    assert evidence == {}


def test_second_order_response_markers_are_manual_review_only() -> None:
    marker = "SQUADRONE_SQL_EXEC_MANUAL_REVIEW_ONLY"
    write = {"method": "POST", "url": f"{_TARGET}/store"}
    trigger = {"method": "GET", "url": f"{_TARGET}/render"}
    common = {
        "write_confirmed": True,
        "write_request": write,
        "trigger_request": trigger,
        "storage_binding": "option:example_query_fragment",
    }
    observation = PoCObservation(
        verdict="vulnerable",
        oracle="response_marker",
        attacker_role="unauthenticated",
        request=trigger,
        attack={
            "observed": True,
            "marker": marker,
            "marker_present": True,
            **common,
        },
        control={"observed": False, "marker_present": False, **common},
        impact=CIAImpact(
            confidentiality="high",
            description="The natural trigger returned the attack-only SQL marker.",
        ),
    )

    accepted, reason = validate_poc_observation(
        observation,
        expected_bug_class="CWE-89",
        expected_injection_order="second",
    )
    assert accepted is False
    assert "parent-measured timing" in reason

    accepted, reason, evidence = validate_second_order_sqli_http_trace(
        observation,
        [],
        trace_salt=_SALT,
        target_url=_TARGET,
        receipt_secret=_SECRET,
        trace_token=_TOKEN,
        expected_http_transport=None,
        expected_trigger_http_transport=None,
        expected_storage_binding="option:example_query_fragment",
        expected_attacker_role="unauthenticated",
        expected_write_success_marker=_WRITE_MARKER,
    )
    assert accepted is False
    assert "parent-measured timing" in reason
    assert evidence == {}


def test_second_order_rejects_different_storage_bindings() -> None:
    observation = _second_order_observation()
    observation.control["storage_binding"] = "option:a_different_slot"

    accepted, reason = validate_poc_observation(
        observation,
        expected_bug_class="CWE-89",
        expected_injection_order="second",
    )

    assert accepted is False
    assert "same storage binding" in reason


def test_second_order_distinguishes_writer_and_trigger_on_same_route() -> None:
    route = f"{_TARGET}/ajax"
    common = {
        "write_confirmed": True,
        "write_request": {"method": "POST", "url": route},
        "trigger_request": {"method": "POST", "url": route},
        "storage_binding": "option:example_query_fragment",
    }
    observation = PoCObservation(
        verdict="vulnerable",
        oracle="timing",
        attacker_role="unauthenticated",
        request={"method": "POST", "url": route},
        attack={
            "observed": True,
            "samples_seconds": [4.2, 4.3, 4.1, 4.2, 4.3, 4.1],
            **common,
        },
        control={
            "observed": False,
            "samples_seconds": [0.1, 0.2, 0.1, 0.2, 0.1, 0.2],
            **common,
        },
        impact=CIAImpact(
            confidentiality="high",
            description="A stored value changed later SQL execution.",
        ),
    )
    records: list[dict[str, object]] = []
    sequence = 0
    for sample in range(6):
        arm_order = (
            ("control", "attack") if sample % 2 == 0 else ("attack", "control")
        )
        for arm in arm_order:
            for action, value, duration, status in (
                (
                    "save",
                    "delayed-sql" if arm == "attack" else "safe",
                    0.1,
                    302,
                ),
                ("render", "fixed", 4.2 if arm == "attack" else 0.1, 200),
            ):
                sequence += 1
                fields = {("form", "action"): action}
                fields[("form", "value" if action == "save" else "view")] = value
                records.append(
                    _record(
                        sequence,
                        method="POST",
                        path="/ajax",
                        fields=fields,
                        status=status,
                        duration_seconds=duration,
                        response=(
                            f"{_WRITE_MARKER}:{value}"
                            if action == "save"
                            else "rendered"
                        ),
                    )
                )

    accepted, reason, _evidence = validate_second_order_sqli_http_trace(
        observation,
        records,
        trace_salt=_SALT,
        target_url=_TARGET,
        receipt_secret=_SECRET,
        trace_token=_TOKEN,
        expected_http_transport={
            "method": "POST",
            "route": "/ajax",
            "dispatch": {"form:action": "save"},
            "destination_parameter": "value",
            "destination_location": "form",
        },
        expected_trigger_http_transport={
            "method": "POST",
            "route": "/ajax",
            "dispatch": {"form:action": "render"},
        },
        expected_storage_binding="option:example_query_fragment",
        expected_attacker_role="unauthenticated",
        expected_write_success_marker=_WRITE_MARKER,
    )

    assert accepted is True, reason


@pytest.mark.asyncio
async def test_run_poc_threads_expected_injection_order(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager = SandboxManager(
        SandboxConfig(
            wordpress_image="unused",
            db_image="unused",
            wp_admin_user="admin",
            wp_admin_pass="password",
            wp_admin_email="admin@example.test",
        )
    )
    captured: dict[str, object] = {}

    async def fake_locked(_self: SandboxManager, script_path: str, **kwargs: object):
        captured["script_path"] = script_path
        captured.update(kwargs)
        return SandboxRunResult(success=False, output="", elapsed=0)

    monkeypatch.setattr(SandboxManager, "_run_poc_locked", fake_locked)
    script = tmp_path / "poc.py"
    script.write_text("print('unused')\n")

    await manager.run_poc(
        str(script),
        expected_bug_class="CWE-89",
        expected_injection_order="second",
        expected_trigger_http_transport={
            "method": "GET",
            "route": "/trigger",
            "dispatch": {},
        },
        expected_storage_binding="option:stored_sql",
        expected_write_success_marker=_WRITE_MARKER,
    )

    assert captured["expected_injection_order"] == "second"
    assert captured["expected_storage_binding"] == "option:stored_sql"
    assert captured["expected_write_success_marker"] == _WRITE_MARKER
    assert captured["expected_bug_class"] == "CWE-89"
    assert sandbox_module._requires_trusted_http_isolation("CWE-89", "second")
