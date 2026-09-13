from __future__ import annotations

from pathlib import Path

import pytest

from squadrone.agents.poc_author import _parse_entry_point_transport
from squadrone.schemas.config import PipelineConfig
from squadrone.schemas.hypothesis import (
    BugClass,
    Confidence,
    Hypothesis,
    SecurityOutcome,
)
from squadrone.poc_proxy import normalize_trace_origin, salted_scalar_sha256
from squadrone.services import sandbox as sandbox_module
from squadrone.stages import verify as verify_stage


TARGET = "http://127.0.0.1:48080"
TRACE_SALT = b"trace-salt-for-upload-transport-tests"
REST_ROUTE = "/acme/v1/upload"


def _expected_transport(
    *,
    route: str,
    dispatch: dict[str, str] | None = None,
) -> tuple[str, str, str, tuple[tuple[str, str], ...]]:
    signature = sandbox_module._expected_executable_upload_transport(
        {
            "method": "POST",
            "route": route,
            "dispatch": dispatch or {},
        }
    )
    assert signature is not None
    return signature


def _candidate_transport(
    url: str,
    *,
    method: str = "POST",
) -> tuple[str, str, str, tuple[tuple[str, str], ...]]:
    signature, _request_url, reason = sandbox_module._candidate_request_transport(
        {"method": method, "url": url},
        target_url=TARGET,
    )
    assert signature is not None, reason
    return signature


def _scalar_field(location: str, name: str, value: str) -> dict[str, object]:
    return {
        "location": location,
        "name": name,
        "kind": "scalar",
        "value_sha256": salted_scalar_sha256(value, TRACE_SALT),
        "contains_squadrone_sentinel": False,
    }


def _trace_record(
    *,
    path: str,
    fields: list[dict[str, object]],
) -> dict[str, object]:
    return {
        "trace_version": 1,
        "record_type": "request",
        "forward_state": "completed",
        "forward_error": None,
        "terminal": False,
        "request_body_parse_error": None,
        "request_metadata_omitted": None,
        "response_capture_omitted": None,
        "origin": normalize_trace_origin(TARGET),
        "method": "POST",
        "path": path,
        "fields": fields,
    }


def _trace_matches(
    record: dict[str, object],
    signature: tuple[str, str, str, tuple[tuple[str, str], ...]],
) -> bool:
    return sandbox_module._trace_matches_executable_upload_transport(
        record,
        signature,
        trace_salt=TRACE_SALT,
        target_url=TARGET,
    )


def test_rest_permalink_and_rest_route_query_are_the_only_route_aliases() -> None:
    direct = _expected_transport(route=f"/wp-json{REST_ROUTE}")
    query_alias = _expected_transport(
        route="/",
        dispatch={"query:rest_route": REST_ROUTE},
    )
    assert direct == query_alias

    for url in (
        f"{TARGET}/wp-json{REST_ROUTE}",
        f"{TARGET}/?rest_route={REST_ROUTE}",
    ):
        candidate = _candidate_transport(url)
        assert sandbox_module._candidate_matches_executable_upload_transport(
            candidate,
            direct,
        )

    wrong_route = _candidate_transport(f"{TARGET}/wp-json/acme/v1/other")
    assert not sandbox_module._candidate_matches_executable_upload_transport(
        wrong_route,
        direct,
    )

    malformed, _url, reason = sandbox_module._candidate_request_transport(
        {
            "method": "POST",
            "url": (
                f"{TARGET}/wp-json{REST_ROUTE}?rest_route={REST_ROUTE}"
            ),
        },
        target_url=TARGET,
    )
    assert malformed is None
    assert reason == "candidate request transport is malformed"


@pytest.mark.parametrize("method", ["post", " POST", "POST ", "GET"])
def test_candidate_transport_requires_exact_post(method: str) -> None:
    signature, _url, reason = sandbox_module._candidate_request_transport(
        {"method": method, "url": f"{TARGET}/upload"},
        target_url=TARGET,
    )

    assert signature is None
    assert reason == "candidate request method must be exact POST"


@pytest.mark.parametrize(
    "route",
    ["/", "/wp-admin/admin.php", "/wp-admin/admin-ajax.php", "/wp-admin/admin-post.php"],
)
def test_expected_transport_rejects_shared_route_without_dispatch(route: str) -> None:
    assert (
        sandbox_module._expected_executable_upload_transport(
            {"method": "POST", "route": route, "dispatch": {}}
        )
        is None
    )


def test_rest_alias_preserves_exact_source_query_dispatch() -> None:
    expected = _expected_transport(
        route=f"/wp-json{REST_ROUTE}",
        dispatch={"query:purpose": "files"},
    )
    accepted = (
        f"{TARGET}/wp-json{REST_ROUTE}?purpose=files",
        f"{TARGET}/?rest_route={REST_ROUTE}&purpose=files",
    )
    for url in accepted:
        assert sandbox_module._candidate_matches_executable_upload_transport(
            _candidate_transport(url),
            expected,
        )

    rejected = (
        f"{TARGET}/wp-json{REST_ROUTE}",
        f"{TARGET}/wp-json{REST_ROUTE}?purpose=images",
        f"{TARGET}/wp-json{REST_ROUTE}?purpose=files&extra=1",
    )
    for url in rejected:
        assert not sandbox_module._candidate_matches_executable_upload_transport(
            _candidate_transport(url),
            expected,
        )


@pytest.mark.parametrize(
    ("route", "dispatch"),
    [
        ("/wp-admin/admin-ajax.php", {"form:action": "acme_upload"}),
        ("/api/upload", {"json:operation": "acme_upload"}),
    ],
)
def test_candidate_url_projects_out_body_dispatch_but_not_query_aliases(
    route: str,
    dispatch: dict[str, str],
) -> None:
    expected = _expected_transport(route=route, dispatch=dispatch)
    assert sandbox_module._candidate_matches_executable_upload_transport(
        _candidate_transport(TARGET + route),
        expected,
    )

    field_name, expected_value = next(iter(dispatch.items()))
    _location, name = field_name.split(":", 1)
    moved_to_query = _candidate_transport(
        f"{TARGET}{route}?{name}={expected_value}"
    )
    assert not sandbox_module._candidate_matches_executable_upload_transport(
        moved_to_query,
        expected,
    )


@pytest.mark.parametrize(
    ("route", "location", "name"),
    [
        ("/wp-admin/admin-ajax.php", "form", "action"),
        ("/api/upload", "json", "operation"),
    ],
)
def test_trace_requires_body_dispatch_at_its_source_declared_location(
    route: str,
    location: str,
    name: str,
) -> None:
    expected = _expected_transport(
        route=route,
        dispatch={f"{location}:{name}": "acme_upload"},
    )
    assert _trace_matches(
        _trace_record(
            path=route,
            fields=[_scalar_field(location, name, "acme_upload")],
        ),
        expected,
    )
    if location == "form":
        assert _trace_matches(
            _trace_record(
                path=route,
                fields=[_scalar_field("multipart", name, "acme_upload")],
            ),
            expected,
        )

    for fields in (
        [],
        [_scalar_field(location, name, "other")],
        [_scalar_field("query", name, "acme_upload")],
        [
            _scalar_field(location, name, "acme_upload"),
            _scalar_field("query", name, "acme_upload"),
        ],
    ):
        assert not _trace_matches(
            _trace_record(path=route, fields=fields),
            expected,
        )


def test_trace_accepts_both_rest_aliases_with_json_dispatch() -> None:
    expected = _expected_transport(
        route=f"/wp-json{REST_ROUTE}",
        dispatch={"json:operation": "acme_upload"},
    )
    direct = _trace_record(
        path=f"/wp-json{REST_ROUTE}",
        fields=[_scalar_field("json", "operation", "acme_upload")],
    )
    query_alias = _trace_record(
        path="/",
        fields=[
            _scalar_field("query", "rest_route", REST_ROUTE),
            _scalar_field("json", "operation", "acme_upload"),
        ],
    )

    assert _trace_matches(direct, expected)
    assert _trace_matches(query_alias, expected)


@pytest.mark.parametrize(
    "entry_point",
    [
        "POST /upload?action=one&action=two",
        "POST /upload?action",
        "POST /upload?action=%ZZ",
        "POST /upl%6fad",
        "POST /upload\\path",
        "POST /upload?" + "&".join(f"field{index}=1" for index in range(65)),
    ],
)
def test_ambiguous_source_transport_falls_back_completely(
    entry_point: str,
) -> None:
    assert _parse_entry_point_transport(entry_point) == {
        "method": "",
        "route": "",
        "dispatch": {},
    }


def _full_compromise_upload_hypothesis(entry_point: str) -> Hypothesis:
    return Hypothesis(
        id="ambiguous-upload-transport",
        specialist="injection_files",
        bug_class=BugClass.ARBITRARY_FILE_WRITE,
        entry_point=entry_point,
        file="plugin.php",
        line=1,
        sink="attacker-controlled executable upload",
        sink_code="move_uploaded_file($tmp, $destination);",
        taint_path=["request", "move_uploaded_file"],
        reasoning="An attacker-controlled upload reaches a public path.",
        confidence=Confidence.HIGH,
        preconditions="Authenticated subscriber.",
        affected_versions="<= 1.0",
        security_outcome=SecurityOutcome(
            confidentiality="high",
            integrity="high",
            availability="high",
            description="The source path can yield server-side execution.",
        ),
    )


@pytest.mark.asyncio
async def test_ambiguous_full_compromise_source_stops_before_sandbox(
    tmp_path: Path,
) -> None:
    config = PipelineConfig.from_yaml("tests/fixtures/pipeline.yaml")

    with pytest.raises(
        RuntimeError,
        match=(
            "trusted executable-upload verification requires one unambiguous "
            "source-derived POST transport"
        ),
    ):
        await verify_stage._verify_one(
            _full_compromise_upload_hypothesis(
                "POST /upload?action=one&action=two"
            ),
            str(tmp_path),
            str(tmp_path / "plugin.zip"),
            "plugin",
            config,
            object(),  # type: ignore[arg-type]
            tmp_path / "verification",
        )
