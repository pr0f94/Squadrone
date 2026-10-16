from __future__ import annotations

from squadrone.schemas import CoverageItem
from squadrone.stages.hypothesis import (
    _FOCUSED_INJECTION_TYPES,
    _build_review_batches,
)


def _target(index: int, surface_type: str) -> CoverageItem:
    return CoverageItem(
        id=f"cov-{index:04d}",
        kind="storage_read" if surface_type == "persistent_sql_operand" else "sink",
        review_areas=["injection_files"],
        type=surface_type,
        name=surface_type,
        file="plugin.php",
        line=index * 10,
        snippet=f"{surface_type}($value);",
    )


def test_high_risk_injection_surfaces_receive_singleton_batches() -> None:
    focused = [
        _target(index, surface_type)
        for index, surface_type in enumerate(
            sorted(_FOCUSED_INJECTION_TYPES),
            start=1,
        )
    ]
    ordinary = [
        _target(100, "sql_query"),
        _target(101, "file_read"),
    ]

    batches = _build_review_batches([*ordinary, *focused], "injection_files")

    by_id = {
        item.id: batch
        for batch in batches
        for item in batch
    }
    assert all(len(by_id[item.id]) == 1 for item in focused)
    assert len(by_id[ordinary[0].id]) == 2
    assert len(by_id[ordinary[1].id]) == 2
    assert sorted(by_id) == sorted(item.id for item in [*ordinary, *focused])


def test_same_target_matching_multiple_focus_rules_is_not_duplicated() -> None:
    dynamic_include = CoverageItem(
        id="cov-0001",
        kind="sink",
        review_areas=["injection_files"],
        type="dynamic_include",
        name="include",
        file="plugin.php",
        line=10,
        snippet="include __DIR__ . '/' . $view . '.php';",
    )
    command = _target(2, "command_execution")

    batches = _build_review_batches(
        [dynamic_include, command],
        "injection_files",
    )

    ids = [item.id for batch in batches for item in batch]
    assert ids.count(dynamic_include.id) == 1
    assert ids.count(command.id) == 1
    assert all(len(batch) == 1 for batch in batches)


def test_dense_high_risk_inventory_is_bounded_without_starving_ordinary_review() -> None:
    ordinary = _target(900, "file_read").model_copy(
        update={"id": "cov-ordinary", "line": 1}
    )
    focused = [_target(index, "file_write") for index in range(1, 81)]

    batches = _build_review_batches([*focused, ordinary], "injection_files")

    assert batches[0] == [ordinary]
    focused_batches = [
        batch for batch in batches if any(item.type == "file_write" for item in batch)
    ]
    assert focused_batches
    assert all(1 <= len(batch) <= 4 for batch in focused_batches)
    assert len(focused_batches) < len(focused) / 2
    ids = [item.id for batch in batches for item in batch]
    assert len(ids) == len(set(ids)) == len(focused) + 1
