from __future__ import annotations

from pathlib import Path

import pytest

from squadrone.schemas.recon import CoverageArtifact, CoverageItem
from squadrone.services.coverage import build_coverage_artifact

_FIXTURES = Path(__file__).parents[1] / "fixtures" / "discovery_regressions"


def _inventory(family: str, variant: str) -> tuple[CoverageArtifact, list[CoverageItem]]:
    artifact, _, _ = build_coverage_artifact(_FIXTURES / family / variant)
    return artifact, artifact.items


def _types(items: list[CoverageItem]) -> set[str]:
    return {item.type for item in items}


def _entry(items: list[CoverageItem], name: str) -> CoverageItem:
    return next(
        item
        for item in items
        if item.kind == "entry_point" and item.name == name
    )


def test_command_and_code_execution_fixture_reaches_focused_review() -> None:
    artifact, items = _inventory("command_code_execution", "vulnerable")

    assert artifact.production_files == ["plugin.php"]
    assert {"command_execution", "php_code_execution"} <= _types(items)
    assert any(
        item.type == "command_execution"
        and item.name.lower() == "system"
        and "$_POST['host']" not in item.snippet
        and "$host" in item.snippet
        and "injection_files" in item.review_areas
        for item in items
    )
    assert any(
        item.type == "php_code_execution"
        and item.name.lower() == "eval"
        and "$expression" in item.snippet
        and "injection_files" in item.review_areas
        for item in items
    )
    assert "injection_files" in _entry(
        items, "wp_ajax_nopriv_run_diagnostic"
    ).review_areas


def test_command_decoys_do_not_create_execution_review_targets() -> None:
    _, items = _inventory("command_code_execution", "safe")

    assert not (_types(items) & {"command_execution", "php_code_execution"})
    assert "injection_files" not in _entry(
        items, "wp_ajax_nopriv_render_diagnostic_help"
    ).review_areas


def test_upload_and_write_fixture_reaches_focused_review() -> None:
    _, items = _inventory("upload_write", "vulnerable")

    assert {"file_upload", "file_write", "file_read", "upload_policy"} <= _types(
        items
    )
    focused = {
        item.type: item
        for item in items
        if item.type in {"file_upload", "file_write", "upload_policy"}
    }
    assert "$_FILES['package']" in focused["file_upload"].snippet
    assert "$destination" in focused["file_write"].snippet
    assert focused["upload_policy"].name == "upload_mimes"
    assert all("injection_files" in item.review_areas for item in focused.values())
    assert "injection_files" in _entry(
        items, "wp_ajax_nopriv_receive_package"
    ).review_areas


def test_upload_and_policy_decoys_do_not_create_review_targets() -> None:
    _, items = _inventory("upload_write", "safe")

    assert not (
        _types(items)
        & {"file_upload", "file_write", "archive_extract", "upload_policy"}
    )
    assert "injection_files" not in _entry(
        items, "wp_ajax_nopriv_render_upload_help"
    ).review_areas


def test_second_order_sql_fixture_records_persistent_operand_and_query() -> None:
    _, items = _inventory("second_order_sqli", "vulnerable")

    persistent = [item for item in items if item.type == "persistent_sql_operand"]
    assert len(persistent) == 1
    assert persistent[0].name == "get_option"
    assert "demo_sort" in persistent[0].snippet
    assert persistent[0].kind == "storage_read"
    assert persistent[0].review_areas == ["injection_files"]
    assert any(
        item.type == "sql_query"
        and "$query" in item.snippet
        and "injection_files" in item.review_areas
        for item in items
    )


def test_prepared_persistent_value_is_not_classified_as_second_order_sqli() -> None:
    _, items = _inventory("second_order_sqli", "safe")

    assert "sql_query" in _types(items)
    assert "persistent_sql_operand" not in _types(items)


@pytest.mark.parametrize(
    ("family", "variant"),
    [
        ("command_code_execution", "vulnerable"),
        ("command_code_execution", "safe"),
        ("upload_write", "vulnerable"),
        ("upload_write", "safe"),
        ("second_order_sqli", "vulnerable"),
        ("second_order_sqli", "safe"),
    ],
)
def test_discovery_fixtures_are_synthetic_and_self_identifying(
    family: str,
    variant: str,
) -> None:
    source = (_FIXTURES / family / variant / "plugin.php").read_text()

    assert "Synthetic" in source
    assert "third-party plugin source" in source
