"""Verify-only orchestration and finding-state tests."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
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
from squadrone.schemas.intake import IntakeArtifact
from squadrone.schemas.recon import ReconArtifact
from squadrone.stages import triage as triage_stage


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
    triage = orchestrator.triage_stage.run
    scope_modes: list[bool | None] = []

    async def capture_scope_mode(*args, **kwargs):
        scope_modes.append(kwargs.get("enforce_submission_scope"))
        return await triage(*args, **kwargs)

    monkeypatch.setattr(orchestrator.triage_stage, "run", capture_scope_mode)

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
    assert scope_modes == [False]
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
    triage = orchestrator.triage_stage.run
    scope_modes: list[bool | None] = []

    async def capture_scope_mode(*args, **kwargs):
        scope_modes.append(kwargs.get("enforce_submission_scope"))
        return await triage(*args, **kwargs)

    monkeypatch.setattr(orchestrator.triage_stage, "run", capture_scope_mode)

    result = await orchestrator.run_scan(
        "plugin",
        config_path="unused.yaml",
        on_event=on_event,
    )

    assert result.status == "complete"
    assert calls[-2:] == ["dedup", "report"]
    assert scope_modes == [True]
    assert result.novel_count == 1
    assert result.report_paths == ["report.md"]
    assert finding.dedup_status is DedupStatus.NOVEL


def test_historical_novel_finding_remains_loadable() -> None:
    payload = json.loads(_finding().model_dump_json())
    payload["dedup_status"] = "novel"

    loaded = Finding.model_validate(payload)

    assert loaded.dedup_status is DedupStatus.NOVEL


@pytest.mark.asyncio
async def test_verify_only_resume_invalidates_enforced_triage_and_verify_checkpoints(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls, events, finding, on_event = _patch_pipeline(monkeypatch, tmp_path)
    run_id = "resume-scope-mode"
    run_dir = tmp_path / "plugins" / "plugin" / "runs" / run_id
    plugin_dir = run_dir / "plugin"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "plugin.php").write_text("<?php\n")
    IntakeArtifact(
        run_id=run_id,
        plugin_slug="plugin",
        plugin_version="1.0",
        source_path=str(plugin_dir),
        file_count=1,
        total_lines=1,
        source_url="https://plugins.svn.wordpress.org/plugin/tags/1.0",
        scanned_at=datetime.now(timezone.utc),
    ).to_json_file(str(run_dir / "intake.json"))
    ReconArtifact(
        plugin_slug="plugin",
        entry_points=[],
        sinks=[],
        entry_to_sink_paths={},
        raw_grep_hits={},
    ).to_json_file(str(run_dir / "recon.json"))
    (run_dir / "hypotheses.jsonl").write_text(
        finding.hypothesis.model_dump_json() + "\n"
    )
    TriagedArtifact(
        plugin_slug="plugin",
        accepted=[],
        rejected=[],
        merged=[],
        deferred=[
            {
                "hypothesis_id": finding.hypothesis.id,
                "reason": "no current automatic CVE submission route",
                "hypothesis": finding.hypothesis.model_dump(mode="json"),
            }
        ],
        submission_scope_enforced=True,
    ).to_json_file(str(run_dir / "triaged.json"))
    (run_dir / "findings.jsonl").write_text("")
    (run_dir / "verify_complete.json").write_text(
        json.dumps(
            {
                "status": "complete",
                "accepted_hypothesis_ids": [],
                "finding_ids": [],
            }
        )
    )

    mocked_triage = orchestrator.triage_stage.run

    async def persist_local_triage(*args, **kwargs):
        triaged = await mocked_triage(*args, **kwargs)
        triaged.submission_scope_enforced = kwargs["enforce_submission_scope"]
        triaged.to_json_file(str(run_dir / "triaged.json"))
        return triaged

    mocked_verify = orchestrator.verify_stage.run
    verify_force: list[bool] = []

    async def capture_verify_force(*args, **kwargs):
        verify_force.append(kwargs["force"])
        return await mocked_verify(*args, **kwargs)

    monkeypatch.setattr(orchestrator.triage_stage, "run", persist_local_triage)
    monkeypatch.setattr(orchestrator.verify_stage, "run", capture_verify_force)

    async def skip_database_persistence(*_args, **_kwargs):
        return None

    monkeypatch.setattr(orchestrator, "_persist_findings", skip_database_persistence)

    result = await orchestrator.run_scan(
        "plugin",
        config_path="unused.yaml",
        resume_run_id=run_id,
        verify_only=True,
        on_event=on_event,
    )

    assert result.status == "complete"
    assert calls == ["triage", "verify"]
    assert verify_force == [True]
    assert ("triage", "start") in events
    assert ("triage", "skipped") not in events
    reloaded = TriagedArtifact.from_json_file(str(run_dir / "triaged.json"))
    assert reloaded.submission_scope_enforced is False


@pytest.mark.asyncio
async def test_normal_resume_invalidates_local_triage_and_verify_checkpoints(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls, events, finding, on_event = _patch_pipeline(monkeypatch, tmp_path)
    run_id = "resume-local-to-normal"
    run_dir = tmp_path / "plugins" / "plugin" / "runs" / run_id
    plugin_dir = run_dir / "plugin"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "plugin.php").write_text("<?php\n")
    IntakeArtifact(
        run_id=run_id,
        plugin_slug="plugin",
        plugin_version="1.0",
        source_path=str(plugin_dir),
        file_count=1,
        total_lines=1,
        source_url="https://plugins.svn.wordpress.org/plugin/tags/1.0",
        scanned_at=datetime.now(timezone.utc),
    ).to_json_file(str(run_dir / "intake.json"))
    ReconArtifact(
        plugin_slug="plugin",
        entry_points=[],
        sinks=[],
        entry_to_sink_paths={},
        raw_grep_hits={},
    ).to_json_file(str(run_dir / "recon.json"))
    (run_dir / "hypotheses.jsonl").write_text(
        finding.hypothesis.model_dump_json() + "\n"
    )
    TriagedArtifact(
        plugin_slug="plugin",
        accepted=[finding.hypothesis],
        rejected=[],
        merged=[],
        submission_scope_enforced=False,
    ).to_json_file(str(run_dir / "triaged.json"))
    (run_dir / "findings.jsonl").write_text(finding.model_dump_json() + "\n")
    (run_dir / "verify_complete.json").write_text(
        json.dumps(
            {
                "status": "complete",
                "accepted_hypothesis_ids": [finding.hypothesis.id],
                "finding_ids": [finding.id],
                "submission_scope_enforced": False,
            }
        )
    )

    mocked_triage = orchestrator.triage_stage.run

    async def persist_enforced_triage(*args, **kwargs):
        triaged = await mocked_triage(*args, **kwargs)
        triaged.submission_scope_enforced = kwargs["enforce_submission_scope"]
        triaged.to_json_file(str(run_dir / "triaged.json"))
        return triaged

    mocked_verify = orchestrator.verify_stage.run
    verify_force: list[bool] = []

    async def capture_verify_force(*args, **kwargs):
        verify_force.append(kwargs["force"])
        return await mocked_verify(*args, **kwargs)

    monkeypatch.setattr(orchestrator.triage_stage, "run", persist_enforced_triage)
    monkeypatch.setattr(orchestrator.verify_stage, "run", capture_verify_force)

    async def skip_database_persistence(*_args, **_kwargs):
        return None

    monkeypatch.setattr(orchestrator, "_persist_findings", skip_database_persistence)

    result = await orchestrator.run_scan(
        "plugin",
        config_path="unused.yaml",
        resume_run_id=run_id,
        verify_only=False,
        on_event=on_event,
    )

    assert result.status == "complete"
    assert calls == ["triage", "verify", "dedup", "report"]
    assert verify_force == [True]
    assert ("triage", "start") in events
    assert ("triage", "skipped") not in events
    reloaded = TriagedArtifact.from_json_file(str(run_dir / "triaged.json"))
    assert reloaded.submission_scope_enforced is True


def test_local_verification_retains_source_valid_candidate_without_route(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    hypothesis = _finding().hypothesis
    triaged = TriagedArtifact(
        plugin_slug="plugin",
        accepted=[hypothesis],
        rejected=[],
        merged=[],
    )
    monkeypatch.setattr(
        triage_stage,
        "preverification_programs",
        lambda _hypothesis: (
            [],
            {
                "wordfence": "not currently routed",
                "patchstack": "not currently routed",
            },
        ),
    )

    triage_stage._apply_submission_scope(
        triaged,
        tmp_path,
        enforce_submission_scope=False,
    )

    assert triaged.accepted == [hypothesis]
    assert triaged.deferred == []
    assert hypothesis.bounty_programs == []
    ledger = [
        json.loads(line)
        for line in (tmp_path / "decision_ledger.jsonl").read_text().splitlines()
    ]
    assert ledger[-1]["result"] == "local_verification_only"


def test_normal_triage_still_defers_candidate_without_route(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    hypothesis = _finding().hypothesis
    triaged = TriagedArtifact(
        plugin_slug="plugin",
        accepted=[hypothesis],
        rejected=[],
        merged=[],
    )
    monkeypatch.setattr(
        triage_stage,
        "preverification_programs",
        lambda _hypothesis: (
            [],
            {
                "wordfence": "not currently routed",
                "patchstack": "not currently routed",
            },
        ),
    )

    triage_stage._apply_submission_scope(
        triaged,
        tmp_path,
        enforce_submission_scope=True,
    )

    assert triaged.accepted == []
    assert [item["hypothesis_id"] for item in triaged.deferred] == [hypothesis.id]
    ledger = [
        json.loads(line)
        for line in (tmp_path / "decision_ledger.jsonl").read_text().splitlines()
    ]
    assert ledger[-1]["result"] == "no_eligible_program"
