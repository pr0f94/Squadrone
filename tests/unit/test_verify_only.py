"""Verify-only orchestration and finding-state tests."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from typing import Callable

import pytest

from squadrone import orchestrator
from squadrone.schemas.finding import DedupStatus, Finding, PoCStatus
from squadrone.schemas.hypothesis import (
    BugClass,
    Confidence,
    Hypothesis,
    TriagedArtifact,
)


def _finding() -> Finding:
    hypothesis = Hypothesis(
        id="hyp-1",
        specialist="test",
        bug_class=BugClass.IDOR,
        entry_point="wp_ajax_test",
        file="plugin.php",
        line=10,
        sink="read protected object",
        taint_path=[],
        reasoning="test candidate",
        confidence=Confidence.HIGH,
        preconditions="subscriber",
        affected_versions="<= 1.0",
    )
    return Finding(
        id="finding-1",
        hypothesis=hypothesis,
        poc_status=PoCStatus.SUCCESS,
        poc_script_path="iter_1.py",
        poc_attempts=[],
        evidence={},
        confidence_runs=2,
        dedup_status=DedupStatus.NOT_CHECKED,
        dedup_matches=[],
    )


def _patch_pipeline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[list[str], list[tuple[str, str]], Finding, Callable[[str, str, dict], None]]:
    finding = _finding()
    hypothesis = finding.hypothesis
    calls: list[str] = []
    events: list[tuple[str, str]] = []
    config = SimpleNamespace(
        cost_ceiling_usd=1.0,
        models=SimpleNamespace(developer="test", developer_followup="test"),
        developer_calls_per_agent=1,
        llm=SimpleNamespace(model_dump=lambda **_kwargs: {}),
        reasoning=SimpleNamespace(model_dump=lambda **_kwargs: {}),
        llm_options_for_role=lambda _role: {},
    )

    monkeypatch.setattr(orchestrator, "PLUGINS_ROOT", str(tmp_path / "plugins"))
    monkeypatch.setattr(orchestrator, "DB_PATH", str(tmp_path / "squadrone.sqlite"))
    monkeypatch.setattr(
        orchestrator.PipelineConfig,
        "from_yaml",
        staticmethod(lambda _path: config),
    )
    monkeypatch.setattr(orchestrator, "DeveloperAgent", lambda **_kwargs: object())
    monkeypatch.setattr(orchestrator, "AgentRuntime", lambda **_kwargs: object())

    async def no_op(*_args, **_kwargs):
        return None

    monkeypatch.setattr(orchestrator, "init_cache", no_op)

    async def intake(*_args, **_kwargs):
        calls.append("intake")
        return SimpleNamespace(
            plugin_slug="plugin",
            plugin_version="1.0",
            source_path=str(tmp_path / "plugin"),
            file_count=1,
            total_lines=10,
        )

    async def recon(*_args, **_kwargs):
        calls.append("recon")
        return SimpleNamespace(entry_points=[], sinks=[])

    async def hypotheses(*_args, **_kwargs):
        calls.append("hypothesis")
        return SimpleNamespace(hypotheses=[hypothesis])

    async def triage(*_args, **_kwargs):
        calls.append("triage")
        return TriagedArtifact(
            plugin_slug="plugin",
            accepted=[hypothesis],
            rejected=[],
            merged=[],
        )

    async def verify(*_args, **_kwargs):
        calls.append("verify")
        return [finding]

    async def dedup(findings, *_args, **_kwargs):
        calls.append("dedup")
        findings[0].dedup_status = DedupStatus.NOVEL
        return findings

    async def report(*_args, **_kwargs):
        calls.append("report")
        return ["report.md"]

    monkeypatch.setattr(orchestrator.intake_stage, "run", intake)
    monkeypatch.setattr(orchestrator.recon_stage, "run", recon)
    monkeypatch.setattr(orchestrator.hypothesis_stage, "run", hypotheses)
    monkeypatch.setattr(orchestrator.triage_stage, "run", triage)
    monkeypatch.setattr(orchestrator.verify_stage, "run", verify)
    monkeypatch.setattr(orchestrator.dedup_stage, "run", dedup)
    monkeypatch.setattr(orchestrator.report_stage, "run", report)

    def on_event(stage: str, status: str, _info: dict) -> None:
        events.append((stage, status))

    return calls, events, finding, on_event


@pytest.mark.asyncio
async def test_verify_only_completes_and_never_invokes_dedup_or_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls, events, finding, on_event = _patch_pipeline(monkeypatch, tmp_path)

    result = await orchestrator.run_scan(
        "plugin",
        config_path="unused.yaml",
        verify_only=True,
        on_event=on_event,
    )

    assert result.status == "complete"
    assert result.finding_count == 1
    assert result.novel_count == 0
    assert result.report_paths == []
    assert calls == ["intake", "recon", "hypothesis", "triage", "verify"]
    assert not any(stage in {"dedup", "report"} for stage, _status in events)
    findings_path = (
        tmp_path / "plugins" / "plugin" / "runs" / result.run_id / "findings.jsonl"
    )
    stored = Finding.model_validate_json(findings_path.read_text())
    assert stored.dedup_status is DedupStatus.NOT_CHECKED
    with sqlite3.connect(tmp_path / "squadrone.sqlite") as db:
        finding_row = db.execute(
            "SELECT dedup_status FROM findings WHERE finding_id = ?", (finding.id,)
        ).fetchone()
        run_row = db.execute(
            "SELECT status FROM runs WHERE run_id = ?", (result.run_id,)
        ).fetchone()
    assert finding_row == ("not_checked",)
    assert run_row == ("complete",)


@pytest.mark.asyncio
async def test_normal_scan_still_invokes_dedup_and_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls, _events, finding, on_event = _patch_pipeline(monkeypatch, tmp_path)

    result = await orchestrator.run_scan(
        "plugin",
        config_path="unused.yaml",
        on_event=on_event,
    )

    assert result.status == "complete"
    assert calls[-2:] == ["dedup", "report"]
    assert result.novel_count == 1
    assert result.report_paths == ["report.md"]
    assert finding.dedup_status is DedupStatus.NOVEL


def test_historical_novel_finding_remains_loadable() -> None:
    payload = json.loads(_finding().model_dump_json())
    payload["dedup_status"] = "novel"

    loaded = Finding.model_validate(payload)

    assert loaded.dedup_status is DedupStatus.NOVEL
