from __future__ import annotations

import base64
import copy
import dataclasses
import hashlib
import hmac
import json
from collections import Counter

import pytest

from squadrone.poc_proxy import salted_headers_sha256
from squadrone.poc_runner import salted_scalar_sha256
from squadrone.schemas import BugClass, CIAImpact, PoCObservation
from squadrone.services.sandbox import (
    POC_RESULT_PREFIX,
    _parse_poc_observation,
    validate_cross_object_http_trace,
    validate_confirmation_observations,
    validate_poc_observation,
    validate_ssrf_response_marker_http_trace,
)
from squadrone.services.ssrf_oracle import SsrfOracleHit, SsrfOracleSnapshot


_TRACE_SALT = bytes.fromhex("77" * 32)
_TRACE_SECRET = bytes.fromhex("88" * 32)
_TRACE_TOKEN = "99" * 32
_TRACE_TARGET = "http://localhost:8100"
_SSRF_ATTACK_URL = "http://host.docker.internal:49152/_squadrone/ssrf/" + ("a" * 64)
_SSRF_CONTROL_URL = "http://host.docker.internal:49152/_squadrone/ssrf/" + ("b" * 64)
_SSRF_MARKER = "SQUADRONE_SSRF_" + ("c" * 64)
_SSRF_GENERATION = "d" * 64
_DEFAULT_SSRF_HTTP_TRANSPORT: dict[str, object] = {
    "method": "GET",
    "route": "/wp-json/example/v1/proxy",
    "dispatch": {},
    "destination_parameter": "url",
    "destination_location": "query",
}


def _actor_receipt(
    sequence: int,
    *,
    user_id: int,
    roles: list[str],
    method: str,
    path: str,
    request_nonce: str,
    request_digest: str,
) -> str:
    payload = {
        "v": 2,
        "trace_token": _TRACE_TOKEN,
        "nonce": f"{sequence:032x}",
        "request_nonce": request_nonce,
        "request_digest": request_digest,
        "user_id": user_id,
        "roles": sorted(set(roles)),
        "method": method,
        "path": path,
    }
    encoded = (
        base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode())
        .decode()
        .rstrip("=")
    )
    signature = hmac.new(_TRACE_SECRET, encoded.encode(), hashlib.sha256).hexdigest()
    return f"{encoded}.{signature}"


def _trace_record(
    sequence: int,
    *,
    method: str,
    path: str,
    fields: list[tuple[str, str, str]],
    user_id: int,
    roles: list[str],
    body: str,
    status_code: int = 200,
) -> dict:
    traced_fields = [
        {
            "location": location,
            "name": name,
            "kind": "scalar",
            "value_sha256": salted_scalar_sha256(value, _TRACE_SALT),
            "contains_squadrone_sentinel": "SQUADRONE_" in value,
        }
        for location, name, value in fields
    ]
    shape_counts = Counter((location, name) for location, name, _value in fields)
    body_bytes = body.encode()
    request_nonce = f"{sequence:064x}"
    request_digest = hashlib.sha256(
        f"request-{sequence}-{method}-{path}".encode()
    ).hexdigest()
    sentinel_flags = {
        "target": any(
            location == "query" and "SQUADRONE_" in value
            for location, _name, value in fields
        ),
        "target_encoded": False,
        "body": any(
            location in {"form", "json", "multipart"} and "SQUADRONE_" in value
            for location, _name, value in fields
        ),
        "body_encoded": False,
        "headers": False,
        "headers_encoded": False,
    }
    return {
        "trace_version": 1,
        "record_type": "request",
        "sequence": sequence,
        "request_nonce": request_nonce,
        "request_digest": request_digest,
        "request_headers_sha256": salted_headers_sha256([], _TRACE_SALT),
        "upstream_started_monotonic_ns": sequence * 1_000_000,
        "upstream_finished_monotonic_ns": sequence * 1_000_000 + 900_000,
        "method": method,
        "origin": "http://localhost:8100",
        "path": path,
        "fields": traced_fields,
        "parameter_shape": [
            {
                "location": location,
                "name": name,
                "kind": "scalar",
                "count": count,
            }
            for (location, name), count in sorted(shape_counts.items())
        ],
        "request_sentinel_flags": sentinel_flags,
        "request_sentinel_categories": sorted(
            name for name, present in sentinel_flags.items() if present
        ),
        "status_code": status_code,
        "response_body_sha256": hashlib.sha256(body_bytes).hexdigest(),
        "response_body_length": len(body_bytes),
        "response_body_b64": base64.b64encode(body_bytes).decode(),
        "response_body_tail_b64": "",
        "response_body_truncated": False,
        "response_actor_receipt": _actor_receipt(
            sequence,
            user_id=user_id,
            roles=roles,
            method=method,
            path=path,
            request_nonce=request_nonce,
            request_digest=request_digest,
        ),
        "response_actor_receipt_truncated": False,
        "forward_state": "completed",
        "forward_error": None,
        "terminal": False,
    }


def _append_trace_field(
    record: dict,
    location: str,
    name: str,
    value: str,
) -> None:
    record["fields"].append(
        {
            "location": location,
            "name": name,
            "kind": "scalar",
            "value_sha256": salted_scalar_sha256(value, _TRACE_SALT),
            "contains_squadrone_sentinel": "SQUADRONE_" in value,
        }
    )
    record["fields"].sort(
        key=lambda item: (
            item["location"],
            item["name"],
            item["kind"],
            item["value_sha256"],
        )
    )
    record["parameter_shape"].append(
        {
            "location": location,
            "name": name,
            "kind": "scalar",
            "count": 1,
        }
    )
    record["parameter_shape"].sort(
        key=lambda item: (item["location"], item["name"], item["kind"])
    )
    if "SQUADRONE_" in value:
        category = "target" if location == "query" else "body"
        record["request_sentinel_flags"][category] = True
        record["request_sentinel_categories"] = sorted(
            name
            for name, present in record["request_sentinel_flags"].items()
            if present
        )


def _observation(**overrides) -> PoCObservation:
    data = {
        "schema_version": 1,
        "verdict": "vulnerable",
        "oracle": "response_marker",
        "attacker_role": "unauthenticated",
        "request": {"method": "POST", "url": "http://localhost/endpoint"},
        "attack": {
            "observed": True,
            "marker": "private-marker",
            "marker_present": True,
        },
        "control": {"observed": False, "marker_present": False},
        "impact": CIAImpact(
            confidentiality="high",
            description="The response disclosed a private marker.",
        ),
    }
    data.update(overrides)
    return PoCObservation.model_validate(data)


def _ssrf_request_fingerprint() -> dict[str, object]:
    return {
        "method": "GET",
        "route": "/wp-json/example/v1/proxy",
        "destination_parameter": "url",
        "destination_location": "query",
        "dispatch": {},
        "csrf_fields": [],
    }


def _ssrf_observation() -> PoCObservation:
    fingerprint = _ssrf_request_fingerprint()
    return PoCObservation(
        verdict="vulnerable",
        oracle="response_marker",
        attacker_role="subscriber",
        request={
            "method": "GET",
            "url": _TRACE_TARGET + "/wp-json/example/v1/proxy",
        },
        attack={
            "observed": True,
            "marker": _SSRF_MARKER,
            "marker_present": True,
            "destination_url": _SSRF_ATTACK_URL,
            "attacker_user_id": 2,
            "identity_verified": True,
            "request_fingerprint": fingerprint,
        },
        control={
            "observed": False,
            "marker_present": False,
            "destination_url": _SSRF_CONTROL_URL,
            "attacker_user_id": 2,
            "identity_verified": True,
            "request_fingerprint": fingerprint,
        },
        impact=CIAImpact(
            confidentiality="low",
            description="A subscriber read a private loopback-only marker.",
        ),
    )


def _ssrf_snapshot(
    records: list[dict],
    *,
    marker: str = _SSRF_MARKER,
    generation_id: str = _SSRF_GENERATION,
) -> SsrfOracleSnapshot:
    def record_for(url: str, other_url: str) -> dict:
        digest = salted_scalar_sha256(url, _TRACE_SALT)
        exact = [
            record
            for record in records
            if any(field.get("value_sha256") == digest for field in record["fields"])
        ]
        if exact:
            return exact[0]
        other_digest = salted_scalar_sha256(other_url, _TRACE_SALT)
        return next(
            record
            for record in records
            if any(
                field.get("location") == "query"
                and field.get("name") == "url"
                and field.get("value_sha256") != other_digest
                for field in record["fields"]
            )
        )

    attack_record = record_for(_SSRF_ATTACK_URL, _SSRF_CONTROL_URL)
    control_record = record_for(_SSRF_CONTROL_URL, _SSRF_ATTACK_URL)

    def hit_time(record: dict, offset: int) -> int:
        return int(record["upstream_started_monotonic_ns"]) + offset

    return SsrfOracleSnapshot(
        schema_version=1,
        generation_id=generation_id,
        overflow=False,
        hits=(
            SsrfOracleHit(
                schema_version=1,
                sequence=1,
                arm="attack",
                method="GET",
                received_monotonic_ns=hit_time(attack_record, 100_000),
                responded_monotonic_ns=hit_time(attack_record, 200_000),
                status_code=200,
                marker_sha256=hashlib.sha256(marker.encode()).hexdigest(),
            ),
            SsrfOracleHit(
                schema_version=1,
                sequence=2,
                arm="control",
                method="GET",
                received_monotonic_ns=hit_time(control_record, 100_000),
                responded_monotonic_ns=hit_time(control_record, 200_000),
                status_code=404,
                marker_sha256=None,
            ),
        ),
    )


def _ssrf_trace_records() -> list[dict]:
    route = "/wp-json/example/v1/proxy"
    return [
        _trace_record(
            1,
            method="GET",
            path=route,
            fields=[
                ("query", "url", _SSRF_ATTACK_URL),
                ("query", "stable", "same-value"),
            ],
            user_id=2,
            roles=["subscriber"],
            body=json.dumps({"data": {"marker": _SSRF_MARKER}}),
        ),
        _trace_record(
            2,
            method="GET",
            path=route,
            fields=[
                ("query", "url", _SSRF_CONTROL_URL),
                ("query", "stable", "same-value"),
            ],
            user_id=2,
            roles=["subscriber"],
            body=json.dumps({"error": "not_found"}),
        ),
    ]


def _validate_ssrf(
    observation: PoCObservation | None = None,
    trace_records: list[dict] | None = None,
    snapshot: object | None = None,
    expected_http_transport: dict[str, object] | None = _DEFAULT_SSRF_HTTP_TRANSPORT,
) -> tuple[bool, str, dict]:
    records = _ssrf_trace_records() if trace_records is None else trace_records
    return validate_ssrf_response_marker_http_trace(
        observation or _ssrf_observation(),
        records,
        trace_salt=_TRACE_SALT,
        target_url=_TRACE_TARGET,
        receipt_secret=_TRACE_SECRET,
        trace_token=_TRACE_TOKEN,
        oracle_attack_url=_SSRF_ATTACK_URL,
        oracle_control_url=_SSRF_CONTROL_URL,
        oracle_marker=_SSRF_MARKER,
        oracle_snapshot=_ssrf_snapshot(records) if snapshot is None else snapshot,
        oracle_generation_id=_SSRF_GENERATION,
        expected_http_transport=expected_http_transport,
    )


def _cross_object_request_fingerprint() -> dict[str, object]:
    return {
        "method": "POST",
        "route": "/wp-admin/admin.php",
        "object_parameter": "object_id",
        "object_type": "calendar_event",
        "object_location": "form",
        "dispatch": {
            "query:page": "objects",
            "form:action": "save_object",
        },
    }


def _cross_object_write_request_fingerprint() -> dict[str, object]:
    fingerprint = _cross_object_request_fingerprint()
    fingerprint.update(
        {
            "marker_field": "form:marker",
            "owner_field": "form:owner_id",
            "csrf_fields": [],
        }
    )
    return fingerprint


def _cross_object_availability_fingerprint() -> dict[str, object]:
    return {
        "method": "GET",
        "route": "/wp-admin/admin.php",
        "object_parameter": "object_id",
        "object_type": "calendar_event",
        "object_location": "query",
        "dispatch": {
            "query:page": "objects",
            "query:view": "availability",
        },
    }


def _cross_object_protection_fingerprint() -> dict[str, object]:
    return {
        "method": "GET",
        "route": "/wp-admin/admin.php",
        "dispatch": {
            "query:page": "objects",
            "query:view": "owner-filtered-list",
        },
    }


def _cross_object_owner_fingerprint() -> dict[str, object]:
    return {
        "method": "GET",
        "route": "/wp-admin/admin.php",
        "object_parameter": "object_id",
        "object_type": "calendar_event",
        "object_location": "query",
        "dispatch": {
            "query:page": "objects",
            "query:view": "owner-observer",
        },
    }


def _cross_object_read_observation(**overrides) -> PoCObservation:
    data = {
        "oracle": "cross_object_access",
        "attacker_role": "subscriber",
        "request": {
            "method": "POST",
            "url": "http://localhost/wp-admin/admin.php?page=objects",
        },
        "attack": {
            "observed": True,
            "access_type": "read",
            "request_fingerprint": _cross_object_request_fingerprint(),
            "attacker_user_id": "2",
            "owner_user_id": "5",
            "object_id": "101",
            "object_provenance": "setup_id",
            "identity_verified": True,
            "authorization_expected": False,
            "protection_basis": "Owner-only event visibility is enabled.",
            "protection_observed": True,
            "protection_request_fingerprint": _cross_object_protection_fingerprint(),
            "protection_visible_marker": "SQUADRONE_ATTACKER_SECRET-202",
            "owner_verified": True,
            "owner_request_fingerprint": _cross_object_owner_fingerprint(),
            "marker": "SQUADRONE_VICTIM_SECRET-101",
            "marker_present": True,
            "observed_value": "private response: SQUADRONE_VICTIM_SECRET-101",
        },
        "control": {
            "observed": False,
            "access_type": "read",
            "request_fingerprint": _cross_object_request_fingerprint(),
            "control_basis": "attacker_owned",
            "attacker_user_id": "2",
            "owner_user_id": "2",
            "object_id": "202",
            "object_provenance": "create_response",
            "identity_verified": True,
            "owner_verified": True,
            "authorization_expected": True,
            "marker": "SQUADRONE_ATTACKER_SECRET-202",
            "marker_present": True,
            "observed_value": "own response: SQUADRONE_ATTACKER_SECRET-202",
            "attack_marker_present": False,
            "legitimate_access_succeeded": True,
        },
        "impact": CIAImpact(
            confidentiality="high",
            description="A Subscriber read a private object owned by another user.",
        ),
    }
    data.update(overrides)
    return _observation(**data)


def _cross_object_write_observation(**overrides) -> PoCObservation:
    data = {
        "oracle": "cross_object_access",
        "attacker_role": "subscriber",
        "request": {
            "method": "POST",
            "url": "http://localhost/wp-admin/admin.php?page=objects",
        },
        "attack": {
            "observed": True,
            "access_type": "write",
            "write_effect": "modify",
            "request_fingerprint": _cross_object_write_request_fingerprint(),
            "attacker_user_id": "2",
            "owner_user_id": "5",
            "object_id": "101",
            "object_provenance": "setup_id",
            "identity_verified": True,
            "authorization_expected": False,
            "protection_basis": "Owner-only event editing is enabled.",
            "protection_observed": True,
            "protection_request_fingerprint": _cross_object_protection_fingerprint(),
            "protection_visible_marker": "SQUADRONE_CONTROL_ORIGINAL-202",
            "owner_verified": True,
            "marker": "SQUADRONE_VICTIM_WRITTEN-101",
            "baseline_marker": "SQUADRONE_VICTIM_ORIGINAL-101",
            "before": "SQUADRONE_VICTIM_ORIGINAL-101",
            "after": "SQUADRONE_VICTIM_WRITTEN-101",
            "before_marker_present": False,
            "after_marker_present": True,
            "observer_user_id": "5",
            "observer_role": "editor",
            "observer_request_fingerprint": _cross_object_owner_fingerprint(),
        },
        "control": {
            "observed": False,
            "access_type": "write",
            "write_effect": "modify",
            "request_fingerprint": _cross_object_write_request_fingerprint(),
            "control_basis": "attacker_owned",
            "attacker_user_id": "2",
            "owner_user_id": "2",
            "object_id": "202",
            "object_provenance": "create_response",
            "identity_verified": True,
            "owner_verified": True,
            "authorization_expected": True,
            "marker": "SQUADRONE_CONTROL_WRITTEN-202",
            "baseline_marker": "SQUADRONE_CONTROL_ORIGINAL-202",
            "before": "SQUADRONE_CONTROL_ORIGINAL-202",
            "after": "SQUADRONE_CONTROL_WRITTEN-202",
            "before_marker_present": False,
            "after_marker_present": True,
            "attack_marker_present": False,
            "legitimate_access_succeeded": True,
            "observer_user_id": "2",
            "observer_role": "subscriber",
            "observer_request_fingerprint": _cross_object_owner_fingerprint(),
        },
        "impact": CIAImpact(
            integrity="high",
            description="A Subscriber changed an object owned by another user.",
        ),
    }
    data.update(overrides)
    return _observation(**data)


def _cross_object_delete_observation(**overrides) -> PoCObservation:
    base = _cross_object_write_observation().model_dump()
    base["attack"]["request_fingerprint"]["marker_field"] = ""
    base["control"]["request_fingerprint"]["marker_field"] = ""
    base["attack"].update(
        {
            "write_effect": "delete",
            "marker": "SQUADRONE_VICTIM_DELETED-101",
            "before": "SQUADRONE_VICTIM_DELETED-101",
            "after": None,
            "before_marker_present": True,
            "after_marker_present": False,
            "before_exists": True,
            "after_exists": False,
            "availability_probe": {
                "object_id": "101",
                "object_type": "calendar_event",
                "marker": "SQUADRONE_VICTIM_DELETED-101",
                "request_fingerprint": _cross_object_availability_fingerprint(),
                "observer_user_id": "5",
                "observer_role": "editor",
                "identity_verified": True,
                "authorization_expected": True,
                "before": {
                    "status_code": 200,
                    "usable": True,
                    "observed_value": "usable event SQUADRONE_VICTIM_DELETED-101",
                },
                "after": {
                    "status_code": 404,
                    "usable": False,
                    "observed_value": "event not found",
                },
            },
        }
    )
    base["control"].update(
        {
            "write_effect": "delete",
            "marker": "SQUADRONE_CONTROL_DELETED-202",
            "before": "SQUADRONE_CONTROL_DELETED-202",
            "after": None,
            "before_marker_present": True,
            "after_marker_present": False,
            "before_exists": True,
            "after_exists": False,
        }
    )
    base["attack"]["protection_visible_marker"] = base["control"]["marker"]
    base["impact"] = CIAImpact(
        integrity="high",
        availability="low",
        description="A Subscriber deleted an object owned by another user.",
    )
    base.update(overrides)
    return PoCObservation.model_validate(base)


def _valid_cross_object_read_trace() -> tuple[PoCObservation, list[dict]]:
    observation = _cross_object_read_observation()
    observation.request["url"] = "http://localhost:8100/wp-admin/admin.php?page=objects"
    records = [
        _trace_record(
            1,
            method="GET",
            path="/wp-admin/admin.php",
            fields=[
                ("query", "page", "objects"),
                ("query", "view", "owner-filtered-list"),
            ],
            user_id=2,
            roles=["subscriber"],
            body="owner-filtered list: SQUADRONE_ATTACKER_SECRET-202",
        ),
        _trace_record(
            2,
            method="GET",
            path="/wp-admin/admin.php",
            fields=[
                ("query", "page", "objects"),
                ("query", "view", "owner-observer"),
                ("query", "object_id", "101"),
            ],
            user_id=5,
            roles=["editor"],
            body="owner view SQUADRONE_VICTIM_SECRET-101",
        ),
        _trace_record(
            3,
            method="POST",
            path="/wp-admin/admin.php",
            fields=[
                ("query", "page", "objects"),
                ("form", "action", "save_object"),
                ("form", "object_id", "101"),
            ],
            user_id=2,
            roles=["subscriber"],
            body="foreign response SQUADRONE_VICTIM_SECRET-101",
        ),
        _trace_record(
            4,
            method="POST",
            path="/wp-admin/admin.php",
            fields=[
                ("query", "page", "objects"),
                ("form", "action", "save_object"),
                ("form", "object_id", "202"),
            ],
            user_id=2,
            roles=["subscriber"],
            body="own response SQUADRONE_ATTACKER_SECRET-202",
        ),
    ]
    return observation, records


def _valid_cross_object_write_trace() -> tuple[PoCObservation, list[dict]]:
    observation = _cross_object_write_observation()
    observation.request["url"] = "http://localhost:8100/wp-admin/admin.php?page=objects"
    main_fields = [("query", "page", "objects"), ("form", "action", "save_object")]

    def observer_fields(object_id: str) -> list[tuple[str, str, str]]:
        return [
            ("query", "page", "objects"),
            ("query", "view", "owner-observer"),
            ("query", "object_id", object_id),
        ]

    records = [
        _trace_record(
            1,
            method="GET",
            path="/wp-admin/admin.php",
            fields=[
                ("query", "page", "objects"),
                ("query", "view", "owner-filtered-list"),
            ],
            user_id=2,
            roles=["subscriber"],
            body="own object SQUADRONE_CONTROL_ORIGINAL-202; foreign hidden",
        ),
        _trace_record(
            2,
            method="GET",
            path="/wp-admin/admin.php",
            fields=observer_fields("101"),
            user_id=5,
            roles=["editor"],
            body="SQUADRONE_VICTIM_ORIGINAL-101",
        ),
        _trace_record(
            3,
            method="POST",
            path="/wp-admin/admin.php",
            fields=[
                *main_fields,
                ("form", "object_id", "101"),
                ("form", "marker", "SQUADRONE_VICTIM_WRITTEN-101"),
                ("form", "owner_id", "5"),
            ],
            user_id=2,
            roles=["subscriber"],
            body="event updated",
        ),
        _trace_record(
            4,
            method="GET",
            path="/wp-admin/admin.php",
            fields=observer_fields("101"),
            user_id=5,
            roles=["editor"],
            body="SQUADRONE_VICTIM_WRITTEN-101",
        ),
        _trace_record(
            5,
            method="GET",
            path="/wp-admin/admin.php",
            fields=observer_fields("202"),
            user_id=2,
            roles=["subscriber"],
            body="SQUADRONE_CONTROL_ORIGINAL-202",
        ),
        _trace_record(
            6,
            method="POST",
            path="/wp-admin/admin.php",
            fields=[
                *main_fields,
                ("form", "object_id", "202"),
                ("form", "marker", "SQUADRONE_CONTROL_WRITTEN-202"),
                ("form", "owner_id", "2"),
            ],
            user_id=2,
            roles=["subscriber"],
            body="event updated",
        ),
        _trace_record(
            7,
            method="GET",
            path="/wp-admin/admin.php",
            fields=observer_fields("202"),
            user_id=2,
            roles=["subscriber"],
            body="SQUADRONE_CONTROL_WRITTEN-202",
        ),
    ]
    return observation, records


def _valid_cross_object_delete_trace() -> tuple[PoCObservation, list[dict]]:
    observation = _cross_object_delete_observation()
    observation.request["url"] = "http://localhost:8100/wp-admin/admin.php?page=objects"

    def main_fields(object_id: str) -> list[tuple[str, str, str]]:
        return [
            ("query", "page", "objects"),
            ("form", "action", "save_object"),
            ("form", "object_id", object_id),
            ("form", "owner_id", "5" if object_id == "101" else "2"),
        ]

    def observer_fields(object_id: str) -> list[tuple[str, str, str]]:
        return [
            ("query", "page", "objects"),
            ("query", "view", "owner-observer"),
            ("query", "object_id", object_id),
        ]

    def availability_fields(object_id: str) -> list[tuple[str, str, str]]:
        return [
            ("query", "page", "objects"),
            ("query", "view", "availability"),
            ("query", "object_id", object_id),
        ]

    records = [
        _trace_record(
            1,
            method="GET",
            path="/wp-admin/admin.php",
            fields=[
                ("query", "page", "objects"),
                ("query", "view", "owner-filtered-list"),
            ],
            user_id=2,
            roles=["subscriber"],
            body="own object SQUADRONE_CONTROL_DELETED-202; foreign hidden",
        ),
        _trace_record(
            2,
            method="GET",
            path="/wp-admin/admin.php",
            fields=observer_fields("101"),
            user_id=5,
            roles=["editor"],
            body="SQUADRONE_VICTIM_DELETED-101",
        ),
        _trace_record(
            3,
            method="GET",
            path="/wp-admin/admin.php",
            fields=availability_fields("101"),
            user_id=5,
            roles=["editor"],
            body="usable SQUADRONE_VICTIM_DELETED-101",
        ),
        _trace_record(
            4,
            method="POST",
            path="/wp-admin/admin.php",
            fields=main_fields("101"),
            user_id=2,
            roles=["subscriber"],
            body="event deleted",
        ),
        _trace_record(
            5,
            method="GET",
            path="/wp-admin/admin.php",
            fields=observer_fields("101"),
            user_id=5,
            roles=["editor"],
            body="event not found",
            status_code=404,
        ),
        _trace_record(
            6,
            method="GET",
            path="/wp-admin/admin.php",
            fields=availability_fields("101"),
            user_id=5,
            roles=["editor"],
            body="event not found",
            status_code=404,
        ),
        _trace_record(
            7,
            method="GET",
            path="/wp-admin/admin.php",
            fields=observer_fields("202"),
            user_id=2,
            roles=["subscriber"],
            body="SQUADRONE_CONTROL_DELETED-202",
        ),
        _trace_record(
            8,
            method="POST",
            path="/wp-admin/admin.php",
            fields=main_fields("202"),
            user_id=2,
            roles=["subscriber"],
            body="event deleted",
        ),
        _trace_record(
            9,
            method="GET",
            path="/wp-admin/admin.php",
            fields=observer_fields("202"),
            user_id=2,
            roles=["subscriber"],
            body="event not found",
            status_code=404,
        ),
    ]
    return observation, records


def _validate_trace(
    observation: PoCObservation, records: list[dict]
) -> tuple[bool, str, dict]:
    return validate_cross_object_http_trace(
        observation,
        records,
        trace_salt=_TRACE_SALT,
        target_url=_TRACE_TARGET,
        receipt_secret=_TRACE_SECRET,
        trace_token=_TRACE_TOKEN,
    )


def test_unstructured_success_text_is_not_proof():
    observation, reason = _parse_poc_observation("[+] SUCCESS: got HTTP 200\n")

    assert observation is None
    assert "missing final" in reason


def test_parser_uses_final_structured_result_line():
    expected = _observation()
    stdout = (
        "debug output\n"
        + POC_RESULT_PREFIX
        + json.dumps(expected.model_dump(mode="json"))
    )

    parsed, reason = _parse_poc_observation(stdout)

    assert reason == ""
    assert parsed == expected


def test_parser_rejects_multiple_structured_results():
    expected = _observation()
    result_line = POC_RESULT_PREFIX + json.dumps(expected.model_dump(mode="json"))

    parsed, reason = _parse_poc_observation(result_line + "\n" + result_line)

    assert parsed is None
    assert "more than one" in reason


def test_parser_rejects_output_after_structured_result():
    expected = _observation()
    stdout = (
        POC_RESULT_PREFIX
        + json.dumps(expected.model_dump(mode="json"))
        + "\nlate debug"
    )

    parsed, reason = _parse_poc_observation(stdout)

    assert parsed is None
    assert "final output line" in reason


def test_confirmation_must_reproduce_same_claim():
    first = _observation()
    confirmation = first.model_copy(deep=True)

    accepted, reason = validate_confirmation_observations(first, confirmation)

    assert accepted is True
    assert "reproduced" in reason


def test_confirmation_rejects_changed_role_or_impact():
    first = _observation()
    confirmation = _observation(
        attacker_role="subscriber",
        impact=CIAImpact(
            integrity="high",
            description="A different security effect was claimed.",
        ),
    )

    accepted, reason = validate_confirmation_observations(first, confirmation)

    assert accepted is False
    assert "attacker role" in reason


def test_confirmation_compares_canonicalized_attacker_roles():
    first = _observation(attacker_role="anonymous remote attacker")
    confirmation = _observation(attacker_role="unauthenticated")

    accepted, reason = validate_confirmation_observations(first, confirmation)

    assert accepted is True, reason


def test_confirmation_rejects_unrecognized_attacker_roles():
    first = _observation(attacker_role="authenticated user")
    confirmation = _observation(attacker_role="authenticated user")

    accepted, reason = validate_confirmation_observations(first, confirmation)

    assert accepted is False
    assert "unrecognized attacker role" in reason


def test_ssrf_confirmation_reproduces_the_full_request_and_identity_signature():
    first = _ssrf_observation()
    confirmation = first.model_copy(deep=True)
    confirmation.attack["marker"] = "SQUADRONE_SSRF_" + ("e" * 64)

    accepted, reason = validate_confirmation_observations(first, confirmation)

    assert accepted is True, reason


def test_ssrf_confirmation_rejects_changed_bound_claim_fields():
    first = _ssrf_observation()
    confirmations = []

    changed_fingerprint = first.model_copy(deep=True)
    changed_fingerprint.attack["request_fingerprint"]["route"] = "/different"
    confirmations.append(changed_fingerprint)

    changed_destination = first.model_copy(deep=True)
    changed_destination.control["destination_url"] = _SSRF_ATTACK_URL
    confirmations.append(changed_destination)

    changed_actor = first.model_copy(deep=True)
    changed_actor.attack["attacker_user_id"] = 3
    confirmations.append(changed_actor)

    changed_identity = first.model_copy(deep=True)
    changed_identity.control["identity_verified"] = False
    confirmations.append(changed_identity)

    for confirmation in confirmations:
        accepted, reason = validate_confirmation_observations(first, confirmation)
        assert accepted is False
        assert "SSRF request fingerprint" in reason


def test_ssrf_confirmation_rejects_same_private_marker_replay():
    first = _ssrf_observation()
    confirmation = first.model_copy(deep=True)

    accepted, reason = validate_confirmation_observations(first, confirmation)

    assert accepted is False
    assert "fresh private SSRF response marker" in reason


def test_valid_timing_oracle_requires_repeatable_differential():
    observation = _observation(
        oracle="timing",
        attack={"observed": True, "samples_seconds": [5.1, 5.0, 5.2]},
        control={"observed": False, "samples_seconds": [0.2, 0.3, 0.2]},
        impact=CIAImpact(
            confidentiality="high", description="Boolean SQL result was inferred."
        ),
    )

    accepted, reason = validate_poc_observation(observation, expected_bug_class="SQLI")

    assert accepted is True
    assert "passed" in reason


def test_response_marker_rejection_names_the_required_marker_field():
    observation = _observation(
        attack={
            "observed": True,
            "response_marker": "private-marker",
            "marker_present": True,
        },
    )

    accepted, reason = validate_poc_observation(
        observation,
        expected_bug_class="SQLI",
    )

    assert accepted is False
    assert "attack.marker" in reason


def test_ssrf_response_marker_binds_outer_trace_actors_and_inner_hits():
    accepted, reason, evidence = _validate_ssrf()

    assert accepted is True, reason
    assert evidence["oracle"] == "ssrf_response_marker"
    assert evidence["destination_field"] == {"location": "query", "name": "url"}
    assert [hit["arm"] for hit in evidence["inner_hits"]] == ["attack", "control"]
    serialized = json.dumps(evidence)
    assert _SSRF_MARKER not in serialized
    assert _SSRF_ATTACK_URL not in serialized
    assert _SSRF_CONTROL_URL not in serialized


@pytest.mark.parametrize(
    "expected_http_transport",
    [
        None,
        {
            "method": "",
            "route": "/wp-json/example/v1/proxy",
            "dispatch": {},
            "destination_parameter": "url",
            "destination_location": "query",
        },
        {
            "method": "POST",
            "route": "/wp-json/example/v1/proxy",
            "dispatch": {},
            "destination_parameter": "url",
            "destination_location": "query",
        },
        {
            "method": "GET",
            "route": "/wp-json/example/v1/other",
            "dispatch": {},
            "destination_parameter": "url",
            "destination_location": "query",
        },
        {
            "method": "GET",
            "route": "/wp-json/example/v1/proxy",
            "dispatch": {"query:mode": "different"},
            "destination_parameter": "url",
            "destination_location": "query",
        },
        {
            "method": "GET",
            "route": "/wp-json/example/v1/proxy",
            "dispatch": {},
            "destination_parameter": "different",
            "destination_location": "query",
        },
        {
            "method": "GET",
            "route": "/wp-json/example/v1/proxy",
            "dispatch": {},
            "destination_parameter": "url",
            "destination_location": "form",
        },
    ],
)
def test_ssrf_response_marker_rejects_missing_or_unrelated_hypothesis_transport(
    expected_http_transport: dict[str, object] | None,
) -> None:
    accepted, reason, _evidence = _validate_ssrf(
        expected_http_transport=expected_http_transport
    )

    assert accepted is False
    assert "transport" in reason


def test_ssrf_response_marker_accepts_pretty_to_plain_rest_transport_equivalence():
    accepted, reason, _evidence = _validate_ssrf(
        expected_http_transport={
            "method": "GET",
            "route": "/",
            "dispatch": {"query:rest_route": "/example/v1/proxy"},
            "destination_parameter": "url",
            "destination_location": "query",
        }
    )

    assert accepted is True, reason


def test_ssrf_response_marker_accepts_plain_to_pretty_rest_transport_equivalence():
    observation = _ssrf_observation()
    plain_fingerprint = _ssrf_request_fingerprint()
    plain_fingerprint.update(
        {
            "route": "/",
            "dispatch": {"query:rest_route": "/example/v1/proxy"},
        }
    )
    observation.request["url"] = _TRACE_TARGET + "/"
    observation.attack["request_fingerprint"] = plain_fingerprint
    observation.control["request_fingerprint"] = copy.deepcopy(plain_fingerprint)
    records = _ssrf_trace_records()
    for record in records:
        record["path"] = "/"
        _append_trace_field(
            record,
            "query",
            "rest_route",
            "/example/v1/proxy",
        )
        record["response_actor_receipt"] = _actor_receipt(
            record["sequence"],
            user_id=2,
            roles=["subscriber"],
            method="GET",
            path="/",
            request_nonce=record["request_nonce"],
            request_digest=record["request_digest"],
        )

    accepted, reason, _evidence = _validate_ssrf(
        observation=observation,
        trace_records=records,
    )

    assert accepted is True, reason


def test_ssrf_response_marker_rejects_self_report_without_captured_marker():
    records = _ssrf_trace_records()
    body = b'{"data":"ordinary"}'
    records[0]["response_body_b64"] = base64.b64encode(body).decode()
    records[0]["response_body_length"] = len(body)
    records[0]["response_body_sha256"] = hashlib.sha256(body).hexdigest()

    accepted, reason, _evidence = _validate_ssrf(trace_records=records)

    assert accepted is False
    assert "exactly one private marker" in reason


def test_ssrf_response_marker_rejects_marker_in_any_child_request():
    records = _ssrf_trace_records()
    _append_trace_field(records[0], "query", "seed", _SSRF_MARKER)

    accepted, reason, _evidence = _validate_ssrf(trace_records=records)

    assert accepted is False
    assert "sentinel-bearing child request" in reason


def test_ssrf_response_marker_requires_identical_csrf_values_and_child_headers():
    observation = _ssrf_observation()
    for arm in (observation.attack, observation.control):
        arm["request_fingerprint"]["csrf_fields"] = ["query:_wpnonce"]
    records = _ssrf_trace_records()
    for record in records:
        _append_trace_field(record, "query", "_wpnonce", "same-nonce")

    accepted, reason, _evidence = _validate_ssrf(
        observation=observation,
        trace_records=records,
    )
    assert accepted is True, reason

    drifted_csrf = copy.deepcopy(records)
    csrf_field = next(
        field
        for field in drifted_csrf[1]["fields"]
        if field["location"] == "query" and field["name"] == "_wpnonce"
    )
    csrf_field["value_sha256"] = salted_scalar_sha256("different", _TRACE_SALT)
    accepted, reason, _evidence = _validate_ssrf(
        observation=observation,
        trace_records=drifted_csrf,
    )
    assert accepted is False
    assert "undeclared request values" in reason

    drifted_headers = copy.deepcopy(records)
    drifted_headers[1]["request_headers_sha256"] = "d" * 64
    accepted, reason, _evidence = _validate_ssrf(
        observation=observation,
        trace_records=drifted_headers,
    )
    assert accepted is False
    assert "headers differ" in reason


def test_ssrf_response_marker_rejects_capability_digest_outside_matched_field():
    records = _ssrf_trace_records()
    records.append(
        _trace_record(
            3,
            method="GET",
            path="/unrelated",
            fields=[("query", "decoy", _SSRF_ATTACK_URL)],
            user_id=2,
            roles=["subscriber"],
            body="ordinary",
        )
    )

    accepted, reason, _evidence = _validate_ssrf(trace_records=records)

    assert accepted is False
    assert "outside their exact matched" in reason


def test_ssrf_response_marker_rejects_unbound_destination_and_request_drift():
    records = _ssrf_trace_records()
    attack_destination = next(
        field
        for field in records[0]["fields"]
        if field["location"] == "query" and field["name"] == "url"
    )
    attack_destination["value_sha256"] = salted_scalar_sha256(
        "http://127.0.0.1/not-the-oracle",
        _TRACE_SALT,
    )

    accepted, reason, _evidence = _validate_ssrf(trace_records=records)

    assert accepted is False
    assert "signed SSRF attack request" in reason

    records = _ssrf_trace_records()
    stable_control = next(
        field
        for field in records[1]["fields"]
        if field["location"] == "query" and field["name"] == "stable"
    )
    stable_control["value_sha256"] = salted_scalar_sha256("drift", _TRACE_SALT)
    accepted, reason, _evidence = _validate_ssrf(trace_records=records)
    assert accepted is False
    assert "undeclared request values" in reason


def test_ssrf_response_marker_rejects_forged_actor_and_extra_causal_traffic():
    records = _ssrf_trace_records()
    records[0]["response_actor_receipt"] = "forged"

    accepted, reason, _evidence = _validate_ssrf(trace_records=records)

    assert accepted is False
    assert "signed SSRF attack request" in reason

    records = _ssrf_trace_records()
    control = _trace_record(
        3,
        method="GET",
        path="/wp-json/example/v1/proxy",
        fields=[
            ("query", "url", _SSRF_CONTROL_URL),
            ("query", "stable", "same-value"),
        ],
        user_id=2,
        roles=["subscriber"],
        body=json.dumps({"error": "not_found"}),
    )
    records[1] = _trace_record(
        2,
        method="GET",
        path="/wp-json/example/v1/other",
        fields=[("query", "benign", "value")],
        user_id=2,
        roles=["subscriber"],
        body="ok",
    )
    records.append(control)
    accepted, reason, _evidence = _validate_ssrf(trace_records=records)
    assert accepted is False
    assert "extra traffic" in reason


def test_ssrf_response_marker_rejects_elevated_matched_or_preproof_actor():
    records = _ssrf_trace_records()
    for record in records:
        record["response_actor_receipt"] = _actor_receipt(
            record["sequence"],
            user_id=2,
            roles=["administrator", "subscriber"],
            method="GET",
            path=record["path"],
            request_nonce=record["request_nonce"],
            request_digest=record["request_digest"],
        )

    accepted, reason, _evidence = _validate_ssrf(trace_records=records)

    assert accepted is False
    assert "privileges outside" in reason

    route = "/wp-json/example/v1/proxy"
    records = [
        _trace_record(
            1,
            method="GET",
            path="/wp-admin/",
            fields=[],
            user_id=1,
            roles=["administrator"],
            body="setup",
        ),
        _trace_record(
            2,
            method="GET",
            path=route,
            fields=[
                ("query", "url", _SSRF_ATTACK_URL),
                ("query", "stable", "same-value"),
            ],
            user_id=2,
            roles=["subscriber"],
            body=json.dumps({"data": {"marker": _SSRF_MARKER}}),
        ),
        _trace_record(
            3,
            method="GET",
            path=route,
            fields=[
                ("query", "url", _SSRF_CONTROL_URL),
                ("query", "stable", "same-value"),
            ],
            user_id=2,
            roles=["subscriber"],
            body=json.dumps({"error": "not_found"}),
        ),
    ]

    accepted, reason, _evidence = _validate_ssrf(trace_records=records)

    assert accepted is False
    assert "pre-proof traffic" in reason


def test_ssrf_response_marker_requires_complete_attack_and_control_captures():
    records = _ssrf_trace_records()
    records[0]["response_body_truncated"] = True
    records[0]["response_body_tail_b64"] = base64.b64encode(b"tail").decode()
    records[0]["response_body_length"] = int(records[0]["response_body_length"]) + 10

    accepted, reason, _evidence = _validate_ssrf(trace_records=records)

    assert accepted is False
    assert "complete response captures" in reason


def test_ssrf_response_marker_fails_closed_on_invalid_external_snapshot():
    records = _ssrf_trace_records()
    baseline = _ssrf_snapshot(records)
    wrong_hash_hit = dataclasses.replace(baseline.hits[0], marker_sha256="0" * 64)
    outside_interval_hit = dataclasses.replace(
        baseline.hits[0],
        received_monotonic_ns=1,
        responded_monotonic_ns=2,
    )
    invalid_snapshots = (
        dataclasses.replace(baseline, overflow=True),
        dataclasses.replace(baseline, hits=baseline.hits[:1]),
        dataclasses.replace(baseline, hits=(wrong_hash_hit, baseline.hits[1])),
        dataclasses.replace(baseline, hits=tuple(reversed(baseline.hits))),
        dataclasses.replace(baseline, hits=(outside_interval_hit, baseline.hits[1])),
        dataclasses.replace(baseline, generation_id="e" * 64),
    )

    for snapshot in invalid_snapshots:
        accepted, _reason, _evidence = _validate_ssrf(
            trace_records=records,
            snapshot=snapshot,
        )
        assert accepted is False


def test_ssrf_response_marker_rejects_oracle_hit_outside_parent_interval():
    records = _ssrf_trace_records()
    snapshot = _ssrf_snapshot(records)
    early_attack = dataclasses.replace(
        snapshot.hits[0],
        received_monotonic_ns=records[0]["upstream_started_monotonic_ns"] - 2,
        responded_monotonic_ns=records[0]["upstream_started_monotonic_ns"] - 1,
    )
    snapshot = dataclasses.replace(
        snapshot,
        hits=(early_attack, snapshot.hits[1]),
    )

    accepted, reason, _evidence = _validate_ssrf(
        trace_records=records,
        snapshot=snapshot,
    )

    assert accepted is False
    assert "outside its parent request" in reason


def test_ssrf_response_marker_rejects_unsupported_integrity_or_availability_claims():
    observation = _ssrf_observation()
    observation.impact.integrity = "low"

    accepted, reason, _evidence = _validate_ssrf(observation=observation)

    assert accepted is False
    assert "confidentiality only" in reason

    observation = _ssrf_observation()
    observation.impact.confidentiality = "high"
    accepted, reason, _evidence = _validate_ssrf(observation=observation)
    assert accepted is False
    assert "confidentiality=low" in reason


def test_timing_oracle_rejects_small_or_single_sample_delta():
    observation = _observation(
        oracle="timing",
        attack={"observed": True, "samples_seconds": [1.0, 1.1, 1.2]},
        control={"observed": False, "samples_seconds": [0.8, 0.9, 0.9]},
    )

    accepted, reason = validate_poc_observation(observation, expected_bug_class="SQLI")

    assert accepted is False
    assert "too small" in reason


def test_callback_hit_without_sensitive_marker_is_only_an_ssrf_primitive():
    observation = _observation(
        oracle="callback",
        attack={"observed": True, "hit_count": 1},
        control={"observed": False, "hit_count": 0, "marker_present": False},
        impact=CIAImpact(
            confidentiality="high", description="Claimed internal disclosure."
        ),
    )

    accepted, reason = validate_poc_observation(observation, expected_bug_class="SSRF")

    assert accepted is False
    assert "trusted response_marker" in reason


def test_cross_object_oracle_accepts_authenticated_read_with_owned_control():
    accepted, reason = validate_poc_observation(
        _cross_object_read_observation(), expected_bug_class="IDOR"
    )

    assert accepted is True, reason


def test_cross_object_oracle_accepts_anonymous_read_with_public_control():
    observation = _cross_object_read_observation(
        attacker_role="unauthenticated",
        attack={
            "observed": True,
            "access_type": "read",
            "request_fingerprint": _cross_object_request_fingerprint(),
            "attacker_user_id": "anonymous",
            "owner_user_id": "5",
            "object_id": "101",
            "object_provenance": "setup_id",
            "identity_verified": True,
            "authorization_expected": False,
            "protection_basis": "The owner marked the event private.",
            "protection_observed": True,
            "protection_request_fingerprint": _cross_object_protection_fingerprint(),
            "protection_visible_marker": "SQUADRONE_PUBLIC_MARKER_202",
            "owner_verified": True,
            "owner_request_fingerprint": _cross_object_owner_fingerprint(),
            "marker": "SQUADRONE_VICTIM_SECRET-101",
            "marker_present": True,
            "observed_value": "private response: SQUADRONE_VICTIM_SECRET-101",
        },
        control={
            "observed": False,
            "access_type": "read",
            "request_fingerprint": _cross_object_request_fingerprint(),
            "control_basis": "public",
            "attacker_user_id": "anonymous",
            "owner_user_id": "6",
            "object_id": "202",
            "object_provenance": "setup_id",
            "identity_verified": True,
            "owner_verified": True,
            "authorization_expected": True,
            "marker": "SQUADRONE_PUBLIC_MARKER_202",
            "marker_present": True,
            "observed_value": "public response: SQUADRONE_PUBLIC_MARKER_202",
            "attack_marker_present": False,
            "legitimate_access_succeeded": True,
            "publicly_authorized": True,
        },
    )

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is True, reason


def test_cross_object_oracle_accepts_anonymous_read_with_authorized_actor_control():
    observation = _cross_object_read_observation(
        attacker_role="unauthenticated",
        attack={
            "observed": True,
            "access_type": "read",
            "request_fingerprint": _cross_object_request_fingerprint(),
            "attacker_user_id": "anonymous",
            "owner_user_id": "5",
            "object_id": "101",
            "object_provenance": "setup_id",
            "identity_verified": True,
            "authorization_expected": False,
            "protection_basis": "The owner marked the event private.",
            "protection_observed": True,
            "protection_request_fingerprint": _cross_object_protection_fingerprint(),
            "protection_visible_marker": "SQUADRONE_OWNER_MARKER_202",
            "owner_verified": True,
            "owner_request_fingerprint": _cross_object_owner_fingerprint(),
            "marker": "SQUADRONE_VICTIM_SECRET-101",
            "marker_present": True,
            "observed_value": "private response: SQUADRONE_VICTIM_SECRET-101",
        },
        control={
            "observed": False,
            "access_type": "read",
            "request_fingerprint": _cross_object_request_fingerprint(),
            "control_basis": "authorized_actor",
            "attacker_user_id": "6",
            "owner_user_id": "6",
            "object_id": "202",
            "object_provenance": "setup_id",
            "identity_verified": True,
            "owner_verified": True,
            "authorization_expected": True,
            "marker": "SQUADRONE_OWNER_MARKER_202",
            "marker_present": True,
            "observed_value": "owner response: SQUADRONE_OWNER_MARKER_202",
            "attack_marker_present": False,
            "legitimate_access_succeeded": True,
            "actor_role": "subscriber",
        },
    )

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is True, reason


def test_cross_object_oracle_accepts_write_observed_by_owner():
    accepted, reason = validate_poc_observation(
        _cross_object_write_observation(), expected_bug_class="IDOR"
    )

    assert accepted is True, reason


def test_cross_object_oracle_accepts_unambiguous_write_marker_transitions():
    observation = _cross_object_write_observation()
    for arm in (observation.attack, observation.control):
        arm.pop("before_marker_present")
        arm.pop("after_marker_present")
        arm["write_marker_present_before"] = False
        arm["write_marker_present_after"] = True

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is True, reason


def test_cross_object_oracle_accepts_unambiguous_delete_marker_transitions():
    observation = _cross_object_delete_observation()
    for arm in (observation.attack, observation.control):
        arm.pop("before_marker_present")
        arm.pop("after_marker_present")
        arm["write_marker_present_before"] = True
        arm["write_marker_present_after"] = False

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is True, reason


def test_cross_object_oracle_rejects_conflicting_legacy_marker_transition():
    observation = _cross_object_write_observation()
    observation.attack["write_marker_present_before"] = True

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "conflicts with legacy before_marker_present" in reason


def test_cross_object_oracle_explains_write_marker_not_baseline_semantics():
    observation = _cross_object_write_observation()
    observation.attack["before_marker_present"] = True

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "refers to arm.marker, not baseline_marker" in reason


def test_cross_object_http_trace_accepts_measured_read_and_sanitizes_evidence():
    observation, records = _valid_cross_object_read_trace()

    accepted, reason, evidence = _validate_trace(observation, records)

    assert accepted is True, reason
    assert evidence["attack_request"]["actor_user_id"] == 2
    assert evidence["owner_request"]["actor_user_id"] == 5
    serialized = json.dumps(evidence)
    assert "SQUADRONE_VICTIM_SECRET-101" not in serialized
    assert _TRACE_TOKEN not in serialized


def test_cross_object_http_trace_binds_plain_permalink_rest_route_object():
    observation, records = _valid_cross_object_read_trace()
    fingerprint = {
        "method": "POST",
        "route": "/",
        "object_parameter": "rest_route",
        "object_type": "calendar_event",
        "object_location": "query",
        "object_value_template": "/calendar/v1/events/{object_id}",
        "dispatch": {},
    }
    observation.attack["request_fingerprint"] = dict(fingerprint)
    observation.control["request_fingerprint"] = dict(fingerprint)
    observation.request["url"] = (
        "http://localhost:8100/?rest_route=/calendar/v1/events/101"
    )
    records[2] = _trace_record(
        3,
        method="POST",
        path="/",
        fields=[
            ("query", "rest_route", "/calendar/v1/events/101"),
        ],
        user_id=2,
        roles=["subscriber"],
        body="foreign response SQUADRONE_VICTIM_SECRET-101",
    )
    records[3] = _trace_record(
        4,
        method="POST",
        path="/",
        fields=[
            ("query", "rest_route", "/calendar/v1/events/202"),
        ],
        user_id=2,
        roles=["subscriber"],
        body="own response SQUADRONE_ATTACKER_SECRET-202",
    )

    accepted, reason, _evidence = _validate_trace(observation, records)

    assert accepted is True, reason


def test_cross_object_http_trace_accepts_owner_observed_write():
    observation, records = _valid_cross_object_write_trace()

    accepted, reason, evidence = _validate_trace(observation, records)

    assert accepted is True, reason
    assert evidence["attack_before"]["actor_user_id"] == 5
    assert evidence["attack_after"]["actor_user_id"] == 5


def test_cross_object_http_trace_rejects_unrelated_protection_page():
    observation, records = _valid_cross_object_write_trace()
    unrelated = b"generic account page with no owned control object"
    records[0]["response_body_b64"] = base64.b64encode(unrelated).decode()
    records[0]["response_body_length"] = len(unrelated)
    records[0]["response_body_sha256"] = hashlib.sha256(unrelated).hexdigest()

    accepted, reason, _evidence = _validate_trace(observation, records)

    assert accepted is False
    assert "protection-policy" in reason


def test_cross_object_http_trace_rejects_failed_or_inconsistent_after_state():
    observation, records = _valid_cross_object_write_trace()
    records[3]["status_code"] = 500

    accepted, reason, _evidence = _validate_trace(observation, records)

    assert accepted is False
    assert "after-state" in reason

    observation, records = _valid_cross_object_write_trace()
    records[3]["response_body_length"] += 1

    accepted, reason, _evidence = _validate_trace(observation, records)

    assert accepted is False
    assert "after-state" in reason


def test_cross_object_http_trace_rejects_replayed_receipt_binding():
    observation, records = _valid_cross_object_read_trace()
    records[2]["response_actor_receipt"] = records[1]["response_actor_receipt"]

    accepted, reason, _evidence = _validate_trace(observation, records)

    assert accepted is False
    assert "no signed attack request" in reason


def test_cross_object_http_trace_rejects_reflected_marker_probe():
    observation, records = _valid_cross_object_write_trace()
    _append_trace_field(
        records[1],
        "query",
        "echo",
        "SQUADRONE_VICTIM_ORIGINAL-101",
    )

    accepted, reason, _evidence = _validate_trace(observation, records)

    assert accepted is False
    assert "sentinel-bearing request outside" in reason


def test_cross_object_http_trace_rejects_raw_header_marker_reflection():
    observation, records = _valid_cross_object_read_trace()
    records[2]["request_sentinel_flags"]["headers"] = True
    records[2]["request_sentinel_categories"] = ["headers"]

    accepted, reason, _evidence = _validate_trace(observation, records)

    assert accepted is False
    assert "sentinel-bearing request outside" in reason


def test_cross_object_http_trace_rejects_inconsistent_sentinel_metadata():
    observation, records = _valid_cross_object_read_trace()
    records[2]["request_sentinel_flags"]["headers"] = True

    accepted, reason, _evidence = _validate_trace(observation, records)

    assert accepted is False
    assert "invalid sentinel metadata" in reason


def test_cross_object_http_trace_allows_only_typed_encoded_write_markers():
    observation, records = _valid_cross_object_write_trace()
    for index in (2, 5):
        records[index]["request_sentinel_flags"]["body"] = False
        records[index]["request_sentinel_flags"]["body_encoded"] = True
        records[index]["request_sentinel_categories"] = ["body_encoded"]

    accepted, reason, _evidence = _validate_trace(observation, records)

    assert accepted is True, reason

    observation, records = _valid_cross_object_write_trace()
    records[2]["request_sentinel_flags"]["headers_encoded"] = True
    records[2]["request_sentinel_categories"] = ["body", "headers_encoded"]

    accepted, reason, _evidence = _validate_trace(observation, records)

    assert accepted is False
    assert "undeclared raw-wire sentinel" in reason


def test_cross_object_http_trace_rejects_unclassified_intervening_request():
    observation, records = _valid_cross_object_write_trace()
    extra = _trace_record(
        40,
        method="POST",
        path="/wp-admin/admin.php",
        fields=[("query", "page", "unclassified")],
        user_id=1,
        roles=["administrator"],
        body="unclassified mutation response",
    )
    extra["sequence"] = 4
    for record in records[3:]:
        record["sequence"] += 1
    records.insert(3, extra)

    accepted, reason, _evidence = _validate_trace(observation, records)

    assert accepted is False
    assert "unclassified traffic" in reason


def test_cross_object_http_trace_rejects_nonterminal_or_opaque_records():
    mutations = (
        {"forward_state": "pending"},
        {
            "forward_state": "failed",
            "forward_error": "upstream_reset",
            "terminal": True,
        },
        {"request_body_parse_error": "unsupported_content_type"},
        {"request_metadata_omitted": True},
        {"response_capture_omitted": True},
    )
    for mutation in mutations:
        observation, records = _valid_cross_object_read_trace()
        records[2].update(mutation)

        accepted, reason, _evidence = _validate_trace(observation, records)

        assert accepted is False, mutation
        assert "incomplete, opaque, or omitted" in reason, mutation


def test_cross_object_http_trace_requires_one_complete_parent_sequence():
    observation, records = _valid_cross_object_read_trace()
    records[2]["sequence"] = 8

    accepted, reason, _evidence = _validate_trace(observation, records)

    assert accepted is False
    assert "sequence is incomplete or unordered" in reason

    observation, records = _valid_cross_object_read_trace()
    records.append({**records[-1], "origin": "http://localhost:9999", "sequence": 5})

    accepted, reason, _evidence = _validate_trace(observation, records)

    assert accepted is False
    assert "invalid-origin" in reason


def test_cross_object_http_trace_rejects_undeclared_value_differences():
    observation, records = _valid_cross_object_write_trace()
    _append_trace_field(records[2], "form", "unchanged", "attack-value")
    _append_trace_field(records[5], "form", "unchanged", "control-value")

    accepted, reason, _evidence = _validate_trace(observation, records)

    assert accepted is False
    assert "undeclared request values" in reason


def test_cross_object_http_trace_accepts_separate_delete_availability_probe():
    observation, records = _valid_cross_object_delete_trace()

    accepted, reason, evidence = _validate_trace(observation, records)

    assert accepted is True, reason
    assert evidence["availability_before"]["status_code"] == 200
    assert evidence["availability_after"]["status_code"] == 404


def test_cross_object_http_trace_rejects_labels_without_requests():
    observation, _records = _valid_cross_object_read_trace()

    accepted, reason, _evidence = _validate_trace(observation, [])

    assert accepted is False
    assert "no signed attack request" in reason


def test_cross_object_http_trace_binds_actual_object_value_and_dispatch():
    observation, records = _valid_cross_object_read_trace()
    records[2]["fields"] = [
        field for field in records[2]["fields"] if field["name"] != "object_id"
    ]

    accepted, reason, _evidence = _validate_trace(observation, records)

    assert accepted is False
    assert "no signed attack request" in reason

    observation, records = _valid_cross_object_read_trace()
    action_field = next(
        field for field in records[2]["fields"] if field["name"] == "action"
    )
    action_field["value_sha256"] = salted_scalar_sha256(
        "different_handler", _TRACE_SALT
    )

    accepted, reason, _evidence = _validate_trace(observation, records)

    assert accepted is False
    assert "no signed attack request" in reason


def test_cross_object_http_trace_rejects_forged_actor_and_response_marker():
    observation, records = _valid_cross_object_read_trace()
    records[2]["response_actor_receipt"] += "0"

    accepted, reason, _evidence = _validate_trace(observation, records)

    assert accepted is False
    assert "no signed attack request" in reason

    observation, records = _valid_cross_object_read_trace()
    body = b"foreign response without the claimed marker"
    records[2]["response_body_b64"] = base64.b64encode(body).decode()

    accepted, reason, _evidence = _validate_trace(observation, records)

    assert accepted is False
    assert "foreign marker" in reason


def test_cross_object_http_trace_rejects_attacker_only_write_observer():
    observation, records = _valid_cross_object_write_trace()
    for index in (1, 3):
        record = records[index]
        record["response_actor_receipt"] = _actor_receipt(
            record["sequence"],
            user_id=2,
            roles=["subscriber"],
            method=record["method"],
            path=record["path"],
            request_nonce=record["request_nonce"],
            request_digest=record["request_digest"],
        )

    accepted, reason, _evidence = _validate_trace(observation, records)

    assert accepted is False
    assert "no signed attack owner before-state" in reason


def test_cross_object_oracle_rejects_non_owner_administrator_observer():
    observation = _cross_object_write_observation()
    observation.attack["observer_user_id"] = "1"
    observation.attack["observer_role"] = "admin"
    observation.control["observer_user_id"] = "1"
    observation.control["observer_role"] = "administrator"

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "not the claimed owner" in reason


def test_cross_object_oracle_accepts_measured_delete_availability():
    accepted, reason = validate_poc_observation(
        _cross_object_delete_observation(), expected_bug_class="IDOR"
    )

    assert accepted is True, reason


def test_cross_object_oracle_accepts_other_authorization_bug_classes():
    for bug_class in (
        "MISSING_CAP_CHECK",
        "MISSING_AUTH_CRITICAL_FUNCTION",
        "LOGIC_FLAW",
    ):
        accepted, reason = validate_poc_observation(
            _cross_object_read_observation(), expected_bug_class=bug_class
        )

        assert accepted is True, (bug_class, reason)


def test_cross_object_oracle_requires_dispatch_for_shared_wordpress_endpoint():
    observation = _cross_object_read_observation()
    observation.attack["request_fingerprint"].pop("dispatch")
    observation.control["request_fingerprint"].pop("dispatch")

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "dispatch" in reason


def test_cross_object_oracle_requires_complete_matching_request_fingerprints():
    observation = _cross_object_read_observation()
    observation.control["request_fingerprint"]["object_type"] = "unrelated_object"

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "do not match" in reason

    observation = _cross_object_read_observation()
    observation.attack["request_fingerprint"].pop("object_parameter")

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "request_fingerprint" in reason

    observation = _cross_object_read_observation()
    observation.attack["request_fingerprint"]["method"] = "GET"
    observation.control["request_fingerprint"]["method"] = "GET"

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "request.method" in reason

    observation = _cross_object_read_observation()
    observation.attack["request_fingerprint"].pop("object_location")

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "object_location" in reason


def test_cross_object_oracle_rejects_sentinel_material_as_an_object_identifier():
    observation = _cross_object_read_observation()
    observation.attack["object_id"] = "SQUADRONE_OBJECT_101"

    accepted, reason = validate_poc_observation(
        observation,
        expected_bug_class="IDOR",
    )

    assert accepted is False
    assert "object identifiers cannot contain proof sentinels" in reason


def test_cross_object_oracle_binds_fingerprint_route_to_reported_url():
    observation = _cross_object_read_observation()
    observation.request["url"] = "http://localhost/wp-admin/admin-ajax.php"

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "route does not match request.url" in reason


def test_cross_object_oracle_binds_object_type_across_all_evidence_routes():
    observation = _cross_object_read_observation()
    observation.attack["owner_request_fingerprint"]["object_type"] = "other_type"

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "owner fingerprint" in reason

    observation = _cross_object_write_observation()
    observation.attack["observer_request_fingerprint"]["object_type"] = "other_type"

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "observer fingerprint" in reason

    observation = _cross_object_read_observation()
    observation.attack["protection_request_fingerprint"].update(
        {
            "object_parameter": "object_id",
            "object_type": "other_type",
            "object_location": "query",
        }
    )

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "protection fingerprint" in reason


def test_cross_object_oracle_accepts_plain_permalink_rest_route_template():
    observation = _cross_object_read_observation()
    fingerprint = {
        "method": "POST",
        "route": "/",
        "object_parameter": "rest_route",
        "object_type": "calendar_event",
        "object_location": "query",
        "object_value_template": "/calendar/v1/events/{object_id}",
        "dispatch": {},
    }
    observation.attack["request_fingerprint"] = dict(fingerprint)
    observation.control["request_fingerprint"] = dict(fingerprint)
    observation.request["url"] = "http://localhost/?rest_route=/calendar/v1/events/101"

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is True, reason


def test_cross_object_oracle_requires_attack_policy_evidence():
    cases = (
        ("authorization_expected", True, "authorization_expected=false"),
        ("protection_basis", "", "protection_basis"),
        ("protection_observed", False, "protection_observed=true"),
        ("owner_verified", False, "owner_verified=true"),
    )
    for field, value, expected_reason in cases:
        observation = _cross_object_read_observation()
        observation.attack[field] = value

        accepted, reason = validate_poc_observation(
            observation, expected_bug_class="IDOR"
        )

        assert accepted is False, field
        assert expected_reason in reason, field

    observation = _cross_object_read_observation()
    observation.attack["protection_basis"] = "private"

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "at least 8 characters" in reason


def test_cross_object_oracle_accepts_explicit_owner_filtered_collection_scope():
    observation = _cross_object_write_observation()
    observation.attack["protection_request_fingerprint"]["scope"] = (
        "owner_filtered_collection"
    )

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is True, reason


def test_cross_object_oracle_rejects_protection_scope_shape_mismatch():
    observation = _cross_object_write_observation()
    protection = observation.attack["protection_request_fingerprint"]
    protection.update(
        {
            "scope": "owner_filtered_collection",
            "object_parameter": "object_id",
            "object_type": "calendar_event",
            "object_location": "query",
        }
    )

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "protection_request_fingerprint" in reason

    observation = _cross_object_write_observation()
    observation.attack["protection_request_fingerprint"]["scope"] = "object"

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "protection_request_fingerprint" in reason


def test_cross_object_oracle_requires_measured_identity_and_ownership() -> None:
    cases = (
        ("attack", "identity_verified", False, "identity_verified=true"),
        ("control", "identity_verified", False, "identity_verified=true"),
        ("control", "owner_verified", False, "owner_verified=true"),
    )
    for arm, field, value, expected_reason in cases:
        observation = _cross_object_read_observation()
        getattr(observation, arm)[field] = value

        accepted, reason = validate_poc_observation(
            observation, expected_bug_class="IDOR"
        )

        assert accepted is False, (arm, field)
        assert expected_reason in reason, (arm, field)


def test_cross_object_oracle_requires_authorized_control_policy():
    observation = _cross_object_read_observation()
    observation.control["authorization_expected"] = False

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "authorization_expected=true" in reason


def test_cross_object_oracle_requires_authoritative_object_provenance():
    observation = _cross_object_read_observation()
    observation.attack["object_provenance"] = "first_title_match"

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "object_provenance" in reason

    for invalid_count in (2, 1.0, True):
        observation = _cross_object_read_observation()
        observation.control["object_provenance"] = "unique_lookup"
        observation.control["match_count"] = invalid_count

        accepted, reason = validate_poc_observation(
            observation, expected_bug_class="IDOR"
        )

        assert accepted is False
        assert "match_count=1" in reason


def test_cross_object_oracle_accepts_one_match_unique_lookup():
    observation = _cross_object_read_observation()
    observation.attack["object_provenance"] = "unique_lookup"
    observation.attack["match_count"] = 1

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is True, reason


def test_cross_object_oracle_requires_distinct_nonempty_ids():
    observation = _cross_object_read_observation()
    observation.attack["attacker_user_id"] = ""

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "positive numeric" in reason


def test_cross_object_oracle_rejects_mismatched_access_types():
    observation = _cross_object_read_observation()
    observation.control["access_type"] = "write"

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "access_type" in reason


def test_cross_object_oracle_rejects_owner_as_foreign_attacker():
    observation = _cross_object_read_observation()
    observation.attack["owner_user_id"] = "2"

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "owner as attacker" in reason


def test_cross_object_oracle_canonicalizes_numeric_user_ids():
    observation = _cross_object_read_observation()
    observation.attack["attacker_user_id"] = "02"
    observation.attack["owner_user_id"] = 2

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "owner as attacker" in reason


def test_cross_object_oracle_requires_positive_numeric_wordpress_user_ids():
    observation = _cross_object_read_observation()
    observation.attack["attacker_user_id"] = "subscriber_user"

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "positive numeric" in reason

    observation = _cross_object_read_observation()
    observation.attack["owner_user_id"] = "0"

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "owners require positive numeric" in reason


def test_cross_object_oracle_requires_canonical_anonymous_actor_id():
    observation = _cross_object_read_observation()
    observation.attacker_role = "unauthenticated"
    observation.attack["attacker_user_id"] = "guest"
    observation.control["control_basis"] = "public"
    observation.control["attacker_user_id"] = "guest"
    observation.control["owner_user_id"] = "6"
    observation.control["publicly_authorized"] = True

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "canonical" in reason


def test_cross_object_oracle_rejects_same_attack_and_control_object():
    observation = _cross_object_read_observation()
    observation.control["object_id"] = "101"

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "same object identifier" in reason


def test_cross_object_oracle_canonicalizes_numeric_object_ids():
    observation = _cross_object_read_observation()
    observation.attack["object_id"] = "0101"
    observation.control["object_id"] = 101

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "same object identifier" in reason


def test_cross_object_oracle_rejects_invalid_authenticated_control_ownership():
    observation = _cross_object_read_observation()
    observation.control["owner_user_id"] = "7"

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "not owned by the attacker" in reason


def test_cross_object_oracle_accepts_public_read_control_for_authenticated_actor():
    observation = _cross_object_read_observation()
    observation.control["control_basis"] = "public"
    observation.control["owner_user_id"] = "7"
    observation.control["publicly_authorized"] = True

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is True, reason


def test_cross_object_oracle_rejects_public_write_control():
    observation = _cross_object_write_observation()
    observation.control["control_basis"] = "public"
    observation.control["owner_user_id"] = "7"
    observation.control["publicly_authorized"] = True

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "only for reads" in reason


def test_cross_object_oracle_accepts_authorized_actor_control_for_authenticated_actor():
    observation = _cross_object_read_observation()
    observation.control["control_basis"] = "authorized_actor"
    observation.control["attacker_user_id"] = "7"
    observation.control["owner_user_id"] = "7"
    observation.control["actor_role"] = "editor"

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is True, reason


def test_cross_object_oracle_rejects_unverified_public_control():
    observation = _cross_object_read_observation(
        attacker_role="unauthenticated",
        attack={
            "observed": True,
            "access_type": "read",
            "request_fingerprint": _cross_object_request_fingerprint(),
            "attacker_user_id": "anonymous",
            "owner_user_id": "5",
            "object_id": "101",
            "object_provenance": "setup_id",
            "identity_verified": True,
            "authorization_expected": False,
            "protection_basis": "The owner marked the event private.",
            "protection_observed": True,
            "protection_request_fingerprint": _cross_object_protection_fingerprint(),
            "owner_verified": True,
            "owner_request_fingerprint": _cross_object_owner_fingerprint(),
            "marker": "SQUADRONE_VICTIM_SECRET-101",
            "marker_present": True,
            "observed_value": "private response: SQUADRONE_VICTIM_SECRET-101",
        },
        control={
            "observed": False,
            "access_type": "read",
            "request_fingerprint": _cross_object_request_fingerprint(),
            "control_basis": "public",
            "attacker_user_id": "anonymous",
            "owner_user_id": "6",
            "object_id": "202",
            "object_provenance": "setup_id",
            "identity_verified": True,
            "owner_verified": True,
            "authorization_expected": True,
            "marker": "PUBLIC-MARKER-202",
            "marker_present": True,
            "observed_value": "public response: PUBLIC-MARKER-202",
            "attack_marker_present": False,
            "legitimate_access_succeeded": True,
        },
    )

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "publicly_authorized" in reason


def test_cross_object_oracle_rejects_missing_functional_control():
    observation = _cross_object_read_observation()
    observation.control["legitimate_access_succeeded"] = False

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "functional control" in reason


def test_cross_object_read_recomputes_markers_from_observed_values():
    observation = _cross_object_read_observation()
    observation.attack["observed_value"] = "response without the private sentinel"

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "observed_value does not contain its marker" in reason

    observation = _cross_object_read_observation()
    observation.control["observed_value"] += " SQUADRONE_VICTIM_SECRET-101"

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "contains the attack marker" in reason


def test_cross_object_oracle_rejects_overlapping_markers():
    observation = _cross_object_read_observation()
    observation.control["marker"] = observation.attack["marker"] + "-CONTROL"

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "contain one another" in reason


def test_cross_object_oracle_rejects_placeholder_and_low_diversity_markers():
    for marker in (
        "ATTACK-MARKER",
        "  SQUADRONE_VICTIM_SECRET-101  ",
        "AAAAAAAAAAAA1",
        "nonascii-é-12345",
    ):
        observation = _cross_object_read_observation()
        observation.attack["marker"] = marker
        observation.attack["observed_value"] = marker

        accepted, reason = validate_poc_observation(
            observation, expected_bug_class="IDOR"
        )

        assert accepted is False, marker
        assert "strong unique sentinel" in reason, marker


def test_cross_object_oracle_rejects_case_insensitive_marker_overlap():
    observation = _cross_object_read_observation()
    observation.control["marker"] = "SQUADRONE_victim_secret-101-CONTROL9"
    observation.control["observed_value"] = observation.control["marker"]

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "contain one another" in reason


def test_cross_object_oracle_rejects_read_with_unmeasured_integrity():
    observation = _cross_object_read_observation(
        impact=CIAImpact(
            confidentiality="high",
            integrity="low",
            description="Claimed both disclosure and modification.",
        )
    )

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "unmeasured integrity" in reason


def test_cross_object_oracle_rejects_attacker_only_write_observation():
    observation = _cross_object_write_observation()
    observation.attack["observer_user_id"] = "2"
    observation.attack["observer_role"] = "subscriber"

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "attacker identity" in reason


def test_cross_object_oracle_rejects_write_without_state_change():
    observation = _cross_object_write_observation()
    observation.attack["after"] = observation.attack["before"]

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "before/after change" in reason


def test_cross_object_oracle_recomputes_write_marker_from_state():
    observation = _cross_object_write_observation()
    observation.attack["after"] = "A different value without the sentinel"

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "after state does not contain its marker" in reason


def test_cross_object_oracle_recomputes_attack_marker_absence_from_control_state():
    observation = _cross_object_write_observation()
    observation.control["after"] = (
        observation.control["after"] + " " + observation.attack["marker"]
    )
    observation.control["attack_marker_present"] = False

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "control state contains the attack marker" in reason


def test_cross_object_oracle_requires_numeric_write_observer_id():
    observation = _cross_object_write_observation()
    observation.attack["observer_user_id"] = "victim_editor"

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "positive numeric" in reason


def test_cross_object_oracle_rejects_modify_with_unmeasured_availability():
    observation = _cross_object_write_observation(
        impact=CIAImpact(
            integrity="high",
            availability="low",
            description="Claimed modification and availability loss.",
        )
    )

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "unmeasured availability" in reason


def test_cross_object_oracle_rejects_delete_availability_with_only_a_boolean_flag():
    observation = _cross_object_delete_observation()
    observation.attack.pop("availability_probe")
    observation.attack["availability_before"] = True
    observation.attack["availability_after"] = False
    observation.attack["availability_observed"] = True

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "availability_probe" in reason


def test_cross_object_oracle_rejects_high_single_object_availability():
    observation = _cross_object_delete_observation()
    observation.impact.availability = "high"

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "at most low" in reason


def test_cross_object_oracle_rejects_circular_availability_probe_route():
    observation = _cross_object_delete_observation()
    observation.attack["availability_probe"]["request_fingerprint"] = (
        observation.attack["observer_request_fingerprint"]
    )

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "distinct" in reason


def test_cross_object_oracle_rejects_unmeasured_availability_transition():
    observation = _cross_object_delete_observation()
    observation.attack["availability_probe"]["after"]["observed_value"] = (
        "still usable SQUADRONE_VICTIM_DELETED-101"
    )

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "present before and absent after" in reason


def test_cross_object_oracle_rejects_unauthorized_availability_observer():
    observation = _cross_object_delete_observation()
    observation.attack["availability_probe"]["observer_user_id"] = "6"

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "same verified" in reason


def test_cross_object_oracle_rejects_non_owner_administrator_availability_observer():
    observation = _cross_object_delete_observation()
    observation.attack["observer_user_id"] = "1"
    observation.attack["observer_role"] = "admin"
    observation.attack["availability_probe"]["observer_user_id"] = "1"
    observation.attack["availability_probe"]["observer_role"] = "administrator"

    accepted, reason = validate_poc_observation(observation, expected_bug_class="IDOR")

    assert accepted is False
    assert "not the claimed owner" in reason


def test_cross_object_confirmation_preserves_claim_identities():
    first = _cross_object_write_observation()
    confirmation = first.model_copy(deep=True)

    accepted, reason = validate_confirmation_observations(first, confirmation)

    assert accepted is True, reason


def test_cross_object_confirmation_binds_request_policy_and_provenance():
    first = _cross_object_write_observation()

    confirmations = []
    changed_request = first.model_copy(deep=True)
    changed_request.attack["request_fingerprint"]["route"] = "/different-route"
    changed_request.control["request_fingerprint"]["route"] = "/different-route"
    changed_request.request["url"] = "http://localhost/different-route"
    confirmations.append(changed_request)

    changed_policy = first.model_copy(deep=True)
    changed_policy.attack["protection_basis"] = "A different ownership policy."
    confirmations.append(changed_policy)

    changed_provenance = first.model_copy(deep=True)
    changed_provenance.attack["object_provenance"] = "create_response"
    confirmations.append(changed_provenance)

    for confirmation in confirmations:
        valid, validation_reason = validate_poc_observation(
            confirmation, expected_bug_class="IDOR"
        )
        assert valid is True, validation_reason

        accepted, reason = validate_confirmation_observations(first, confirmation)

        assert accepted is False
        assert "different request URL" in reason or "cross-object" in reason


def test_cross_object_confirmation_rejects_changed_object_identity():
    first = _cross_object_write_observation()
    confirmation = first.model_copy(deep=True)
    confirmation.attack["object_id"] = "different-object"

    accepted, reason = validate_confirmation_observations(first, confirmation)

    assert accepted is False
    assert "cross-object" in reason


def test_cross_object_confirmation_compares_canonical_observer_roles():
    first = _cross_object_write_observation()
    first.attack["observer_user_id"] = "1"
    first.attack["observer_role"] = "admin"
    confirmation = first.model_copy(deep=True)
    confirmation.attack["observer_role"] = "administrator"

    accepted, reason = validate_confirmation_observations(first, confirmation)

    assert accepted is True, reason


def test_cross_object_confirmation_rejects_changed_marker_or_observer():
    first = _cross_object_write_observation()
    confirmation = first.model_copy(deep=True)
    confirmation.control["marker"] = "DIFFERENT-SQUADRONE_CONTROL_MARKER"
    confirmation.attack["observer_user_id"] = "1"
    confirmation.attack["observer_role"] = "administrator"

    accepted, reason = validate_confirmation_observations(first, confirmation)

    assert accepted is False
    assert "markers, or observers" in reason


def test_file_oracle_requires_hex_sha256():
    observation = _observation(
        oracle="file_effect",
        attack={
            "observed": True,
            "before_exists": False,
            "after_exists": True,
            "exists": True,
            "path": "/tmp/marker",
            "marker_sha256": "z" * 64,
        },
        control={
            "observed": False,
            "path": "/tmp/control",
            "before_exists": False,
            "after_exists": False,
            "exists": False,
        },
        impact=CIAImpact(integrity="high", description="A protected file was written."),
    )

    accepted, reason = validate_poc_observation(
        observation,
        expected_bug_class="ARBITRARY_FILE_WRITE",
    )

    assert accepted is False
    assert "SHA-256" in reason


def test_file_oracle_accepts_measured_file_sha256_alias():
    observation = _observation(
        oracle="file_effect",
        attack={
            "observed": True,
            "before_exists": False,
            "after_exists": True,
            "exists": True,
            "path": "/wp-content/uploads/marker.php",
            "file_sha256": "a" * 64,
        },
        control={
            "observed": False,
            "path": "/wp-content/uploads/control.php",
            "before_exists": False,
            "after_exists": False,
            "exists": False,
        },
        impact=CIAImpact(integrity="high", description="A protected file was written."),
    )

    accepted, reason = validate_poc_observation(
        observation,
        expected_bug_class="ARBITRARY_FILE_WRITE",
    )

    assert accepted is True, reason


@pytest.mark.parametrize("dimension", ["confidentiality", "availability"])
def test_file_oracle_rejects_unmeasured_non_integrity_impact(dimension):
    impact = CIAImpact(integrity="high", description="A protected file was written.")
    setattr(impact, dimension, "high")
    observation = _observation(
        oracle="file_effect",
        attack={
            "observed": True,
            "before_exists": False,
            "after_exists": True,
            "path": "/wp-content/uploads/marker.php",
            "after_sha256": "a" * 64,
        },
        control={
            "observed": False,
            "before_exists": False,
            "after_exists": False,
            "path": "/wp-content/uploads/control.php",
        },
        impact=impact,
    )

    accepted, reason = validate_poc_observation(
        observation,
        expected_bug_class="ARBITRARY_FILE_WRITE",
    )

    assert accepted is False
    assert "file creation or overwrite integrity" in reason


def test_file_oracle_rejects_identical_attack_and_control_paths():
    observation = _observation(
        oracle="file_effect",
        attack={
            "observed": True,
            "before_exists": False,
            "after_exists": True,
            "path": "/wp-content/uploads/marker.php",
            "after_sha256": "a" * 64,
        },
        control={
            "observed": False,
            "path": "/wp-content/uploads/marker.php",
            "before_exists": False,
            "after_exists": False,
        },
        impact=CIAImpact(integrity="high", description="A protected file was written."),
    )

    accepted, reason = validate_poc_observation(
        observation,
        expected_bug_class="ARBITRARY_FILE_WRITE",
    )

    assert accepted is False
    assert "distinct normalized attack/control paths" in reason


def test_file_oracle_rejects_normalized_aliases_of_the_same_path():
    observation = _observation(
        oracle="file_effect",
        attack={
            "observed": True,
            "before_exists": False,
            "after_exists": True,
            "path": (
                "http://localhost/wp-content//uploads/staging/../%6darker.php?attack=1"
            ),
            "after_sha256": "a" * 64,
        },
        control={
            "observed": False,
            "path": "http://localhost/wp-content/uploads/marker.php#control",
            "before_exists": False,
            "after_exists": False,
        },
        impact=CIAImpact(integrity="high", description="A protected file was written."),
    )

    accepted, reason = validate_poc_observation(
        observation,
        expected_bug_class="ARBITRARY_FILE_WRITE",
    )

    assert accepted is False
    assert "distinct normalized attack/control paths" in reason


def test_file_oracle_rejects_post_state_without_pre_request_measurements():
    observation = _observation(
        oracle="file_effect",
        attack={
            "observed": True,
            "exists": True,
            "path": "/wp-content/uploads/marker.php",
            "marker_sha256": "a" * 64,
        },
        control={
            "observed": False,
            "exists": False,
            "path": "/wp-content/uploads/control.php",
        },
        impact=CIAImpact(integrity="high", description="A protected file was written."),
    )

    accepted, reason = validate_poc_observation(
        observation,
        expected_bug_class="ARBITRARY_FILE_WRITE",
    )

    assert accepted is False
    assert "attack.before_exists" in reason


def test_file_oracle_rejects_unchanged_preseeded_attack_file():
    observation = _observation(
        oracle="file_effect",
        attack={
            "observed": True,
            "path": "/wp-content/uploads/marker.php",
            "before_exists": True,
            "after_exists": True,
            "before_sha256": "a" * 64,
            "after_sha256": "a" * 64,
        },
        control={
            "observed": False,
            "path": "/wp-content/uploads/control.php",
            "before_exists": False,
            "after_exists": False,
        },
        impact=CIAImpact(integrity="high", description="A protected file was written."),
    )

    accepted, reason = validate_poc_observation(
        observation,
        expected_bug_class="ARBITRARY_FILE_WRITE",
    )

    assert accepted is False
    assert "creation or overwrite" in reason


def test_file_oracle_accepts_request_induced_overwrite():
    observation = _observation(
        oracle="file_effect",
        attack={
            "observed": True,
            "path": "/wp-content/uploads/marker.php",
            "before_exists": True,
            "after_exists": True,
            "before_sha256": "a" * 64,
            "after_sha256": "b" * 64,
        },
        control={
            "observed": False,
            "path": "/wp-content/uploads/control.php",
            "before_exists": True,
            "after_exists": True,
            "before_sha256": "c" * 64,
            "after_sha256": "c" * 64,
        },
        impact=CIAImpact(
            integrity="high", description="An existing protected file was overwritten."
        ),
    )

    accepted, reason = validate_poc_observation(
        observation,
        expected_bug_class="ARBITRARY_FILE_WRITE",
    )

    assert accepted is True, reason


def test_file_oracle_rejects_control_file_creation():
    observation = _observation(
        oracle="file_effect",
        attack={
            "observed": True,
            "path": "/wp-content/uploads/marker.php",
            "before_exists": False,
            "after_exists": True,
            "after_sha256": "a" * 64,
        },
        control={
            "observed": False,
            "path": "/wp-content/uploads/control.php",
            "before_exists": False,
            "after_exists": True,
            "after_sha256": "b" * 64,
        },
        impact=CIAImpact(integrity="high", description="A protected file was written."),
    )

    accepted, reason = validate_poc_observation(
        observation,
        expected_bug_class="ARBITRARY_FILE_WRITE",
    )

    assert accepted is False
    assert "negative control changed" in reason


def test_file_oracle_rejects_control_file_overwrite():
    observation = _observation(
        oracle="file_effect",
        attack={
            "observed": True,
            "path": "/wp-content/uploads/marker.php",
            "before_exists": False,
            "after_exists": True,
            "after_sha256": "a" * 64,
        },
        control={
            "observed": False,
            "path": "/wp-content/uploads/control.php",
            "before_exists": True,
            "after_exists": True,
            "before_sha256": "b" * 64,
            "after_sha256": "c" * 64,
        },
        impact=CIAImpact(integrity="high", description="A protected file was written."),
    )

    accepted, reason = validate_poc_observation(
        observation,
        expected_bug_class="ARBITRARY_FILE_WRITE",
    )

    assert accepted is False
    assert "negative control changed" in reason


def test_oracle_must_match_vulnerability_class():
    accepted, reason = validate_poc_observation(
        _observation(),
        expected_bug_class="XSS_STORED",
    )

    assert accepted is False
    assert "cannot prove" in reason


def test_missing_authentication_accepts_measured_response_marker_oracle():
    accepted, reason = validate_poc_observation(
        _observation(),
        expected_bug_class="MISSING_AUTH_CRITICAL_FUNCTION",
    )

    assert accepted is True, reason


@pytest.mark.parametrize("bug_class", ["CWE-1234", "CWE-9999"])
def test_unmapped_cwe_has_no_automatic_oracle_policy(bug_class: str):
    accepted, reason = validate_poc_observation(
        _observation(),
        expected_bug_class=bug_class,
    )

    assert accepted is False
    assert "no automatic oracle" in reason


@pytest.mark.parametrize(
    "bug_class",
    ["CWE-601", "CWE-307", "CWE-400", "CWE-0", "cwe-1234", "unknown"],
)
def test_known_nonautomated_and_invalid_cwes_remain_oracle_fail_closed(bug_class):
    accepted, reason = validate_poc_observation(
        _observation(),
        expected_bug_class=bug_class,
    )

    assert accepted is False
    assert "no automatic oracle" in reason


def test_known_cwe_value_cannot_bypass_its_exact_oracle_policy():
    accepted, reason = validate_poc_observation(
        _observation(),
        expected_bug_class=BugClass.IDOR.value,
    )

    assert accepted is False
    assert "cannot prove" in reason
    assert "cross_object_access" in reason


def test_open_cwe_fallback_does_not_bypass_cross_object_isolation_contract():
    accepted, reason = validate_poc_observation(
        _cross_object_read_observation(),
        expected_bug_class="CWE-1234",
    )

    assert accepted is False
    assert "no automatic oracle" in reason


def test_observation_without_cia_impact_is_rejected():
    observation = _observation(impact=CIAImpact(description="No protected effect."))

    accepted, reason = validate_poc_observation(observation, expected_bug_class="SQLI")

    assert accepted is False
    assert "no confidentiality" in reason


def test_observation_must_use_source_reviewed_attacker_role():
    accepted, reason = validate_poc_observation(
        _observation(attacker_role="administrator"),
        expected_bug_class="SQLI",
        expected_attacker_role="unauthenticated",
    )

    assert accepted is False
    assert "source review requires" in reason


def test_observation_accepts_descriptive_equivalent_attacker_role():
    accepted, reason = validate_poc_observation(
        _observation(attacker_role="unauthenticated_remote_attacker"),
        expected_bug_class="SQLI",
        expected_attacker_role="unauthenticated",
    )

    assert accepted is True, reason


def test_observation_rejects_unrecognized_source_role():
    accepted, reason = validate_poc_observation(
        _observation(),
        expected_bug_class="SQLI",
        expected_attacker_role="authenticated user",
    )

    assert accepted is False
    assert "source review has an unrecognized" in reason


def test_observation_request_must_target_local_sandbox():
    observation = _observation(
        request={"method": "POST", "url": "https://example.com/endpoint"},
    )

    accepted, reason = validate_poc_observation(observation, expected_bug_class="SQLI")

    assert accepted is False
    assert "local sandbox" in reason
