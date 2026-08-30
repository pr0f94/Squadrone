from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from squadrone import orchestrator
from squadrone.schemas.finding import DedupStatus, Finding, PoCStatus
from squadrone.schemas.hypothesis import BugClass, Confidence, Hypothesis


def _finding(
    finding_id: str,
    *,
    dedup_status: DedupStatus = DedupStatus.NOT_CHECKED,
) -> Finding:
    return Finding(
        id=finding_id,
        hypothesis=Hypothesis(
            id=f"hyp-{finding_id}",
            specialist="authentication",
            bug_class=BugClass.AUTH_BYPASS,
            entry_point="POST /",
            file="plugin.php",
            line=10,
            sink="wp_set_auth_cookie",
            taint_path=["request", "wp_set_auth_cookie"],
            reasoning="An unauthenticated request establishes an administrator session.",
            confidence=Confidence.HIGH,
            preconditions="unauthenticated attacker",
            affected_versions="<= 1.0",
        ),
        poc_status=PoCStatus.SUCCESS,
        poc_script_path="iter_1.py",
        poc_attempts=[],
        evidence={},
        confidence_runs=2,
        dedup_status=dedup_status,
        dedup_matches=[],
    )


async def _start_run(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    run_id: str,
    plugin_slug: str = "plugin",
) -> Path:
    db_path = tmp_path / "squadrone.sqlite"
    monkeypatch.setattr(orchestrator, "DB_PATH", str(db_path))
    await orchestrator._init_db()
    await orchestrator._record_run_start(run_id, plugin_slug)
    return db_path


@pytest.mark.asyncio
async def test_persist_findings_replaces_only_undisclosed_run_findings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    db_path = await _start_run(monkeypatch, tmp_path, "run-current")
    await orchestrator._persist_findings(
        "run-current",
        "plugin",
        [
            _finding("f-current"),
            _finding("f-stale"),
            _finding("f-disclosed"),
        ],
    )
    await orchestrator._record_run_start("run-other", "plugin")
    await orchestrator._persist_findings(
        "run-other",
        "plugin",
        [_finding("f-other")],
    )
    with sqlite3.connect(db_path) as db:
        db.executemany(
            "INSERT INTO disclosures(finding_id, submitted_to, status) "
            "VALUES (?, ?, ?)",
            [
                ("f-current", "direct", "submitted"),
                ("f-disclosed", "direct", "submitted"),
            ],
        )
        db.commit()

    await orchestrator._persist_findings(
        "run-current",
        "plugin",
        [
            _finding("f-current", dedup_status=DedupStatus.NOVEL),
            _finding("f-new"),
        ],
    )

    with sqlite3.connect(db_path) as db:
        current_ids = db.execute(
            "SELECT finding_id FROM findings WHERE run_id=? ORDER BY finding_id",
            ("run-current",),
        ).fetchall()
        current_status = db.execute(
            "SELECT dedup_status FROM findings WHERE finding_id=?",
            ("f-current",),
        ).fetchone()
        other_ids = db.execute(
            "SELECT finding_id FROM findings WHERE run_id=?",
            ("run-other",),
        ).fetchall()
        disclosure = db.execute(
            "SELECT finding_id, status FROM disclosures ORDER BY finding_id"
        ).fetchall()

    assert current_ids == [("f-current",), ("f-disclosed",), ("f-new",)]
    assert current_status == (DedupStatus.NOVEL.value,)
    assert other_ids == [("f-other",)]
    assert disclosure == [
        ("f-current", "submitted"),
        ("f-disclosed", "submitted"),
    ]


@pytest.mark.asyncio
async def test_persist_findings_empty_list_clears_only_undisclosed_findings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    db_path = await _start_run(monkeypatch, tmp_path, "run-empty")
    await orchestrator._persist_findings(
        "run-empty",
        "plugin",
        [_finding("f-stale"), _finding("f-disclosed")],
    )
    with sqlite3.connect(db_path) as db:
        db.execute(
            "INSERT INTO disclosures(finding_id, submitted_to, status) "
            "VALUES (?, ?, ?)",
            ("f-disclosed", "direct", "submitted"),
        )
        db.commit()

    await orchestrator._persist_findings("run-empty", "plugin", [])

    with sqlite3.connect(db_path) as db:
        remaining = db.execute(
            "SELECT finding_id FROM findings WHERE run_id=? ORDER BY finding_id",
            ("run-empty",),
        ).fetchall()

    assert remaining == [("f-disclosed",)]
