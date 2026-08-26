"""Verify-stage checkpoint and forced-resume semantics."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from squadrone import orchestrator
from squadrone.schemas.finding import DedupStatus, Finding, PoCStatus
from squadrone.schemas.hypothesis import (
    BugClass,
    Confidence,
    Hypothesis,
    TriagedArtifact,
)
from squadrone.stages import verify as verify_stage


def _hyp(hypothesis_id: str) -> Hypothesis:
    return Hypothesis(
        id=hypothesis_id,
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


def _finding(finding_id: str, hypothesis: Hypothesis) -> Finding:
    return Finding(
        id=finding_id,
        hypothesis=hypothesis,
        poc_status=PoCStatus.SUCCESS,
        poc_script_path="iter_1.py",
        poc_attempts=[],
        evidence={},
        confidence_runs=2,
        dedup_status=DedupStatus.NOVEL,
        dedup_matches=[],
    )


def _config() -> SimpleNamespace:
    return SimpleNamespace(verify=SimpleNamespace(persistent_sandbox=False))


def _patch_zip(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    staging = tmp_path / "zip-staging"
    staging.mkdir()
    monkeypatch.setattr(
        verify_stage,
        "_zip_plugin",
        lambda *_args: (str(tmp_path / "plugin.zip"), staging),
    )


async def _run(
    tmp_path: Path,
    triaged: TriagedArtifact,
    *,
    force: bool = False,
) -> list[Finding]:
    return await verify_stage.run(
        triaged,
        str(tmp_path / "plugin"),
        _config(),
        object(),
        object(),
        runs_root=str(tmp_path / "runs"),
        run_id="run-1",
        force=force,
    )


@pytest.mark.asyncio
async def test_ordinary_resume_skips_confirmed_and_clean_not_confirmed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _patch_zip(monkeypatch, tmp_path)
    confirmed = _hyp("confirmed")
    rejected = _hyp("rejected")
    run_dir = tmp_path / "runs" / "run-1"
    rejected_dir = run_dir / "verifications" / rejected.id
    rejected_dir.mkdir(parents=True)
    (rejected_dir / "iter_1.py").write_text("# prior clean attempt")
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "findings.jsonl").write_text(
        _finding("f-old", confirmed).model_dump_json() + "\n"
    )

    async def should_not_run(*_args, **_kwargs):
        raise AssertionError("terminal candidate checkpoint should be skipped")

    monkeypatch.setattr(verify_stage, "_verify_one", should_not_run)

    findings = await _run(
        tmp_path,
        TriagedArtifact(
            plugin_slug="plugin",
            accepted=[confirmed, rejected],
            rejected=[],
            merged=[],
        ),
    )

    assert [finding.id for finding in findings] == ["f-old"]
    marker = json.loads((run_dir / verify_stage.VERIFY_COMPLETE_FILENAME).read_text())
    assert marker["accepted_hypothesis_ids"] == ["confirmed", "rejected"]


@pytest.mark.asyncio
async def test_ordinary_resume_retries_and_archives_error_checkpoint(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _patch_zip(monkeypatch, tmp_path)
    hypothesis = _hyp("errored")
    run_dir = tmp_path / "runs" / "run-1"
    hyp_dir = run_dir / "verifications" / hypothesis.id
    hyp_dir.mkdir(parents=True)
    (hyp_dir / "iter_1.py").write_text("# iteration before exception")
    (hyp_dir / "error.log").write_text("prior exception")
    calls: list[str] = []

    async def retry(*args, poc_dir: Path, **_kwargs):
        calls.append(args[0].id)
        assert not (poc_dir / "error.log").exists()
        (poc_dir / "iter_1.py").write_text("# clean retry")
        return None

    monkeypatch.setattr(verify_stage, "_verify_one", retry)

    findings = await _run(
        tmp_path,
        TriagedArtifact(
            plugin_slug="plugin",
            accepted=[hypothesis],
            rejected=[],
            merged=[],
        ),
    )

    assert findings == []
    assert calls == ["errored"]
    assert (run_dir / verify_stage.VERIFY_COMPLETE_FILENAME).exists()
    archived = list(
        (run_dir / "verify_archive").glob("*/verifications/errored/error.log")
    )
    assert len(archived) == 1
    assert archived[0].read_text() == "prior exception"


@pytest.mark.asyncio
async def test_forced_verify_archives_and_replaces_all_prior_outputs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _patch_zip(monkeypatch, tmp_path)
    hypothesis = _hyp("candidate")
    run_dir = tmp_path / "runs" / "run-1"
    hyp_dir = run_dir / "verifications" / hypothesis.id
    hyp_dir.mkdir(parents=True)
    (hyp_dir / "iter_1.py").write_text("# old attempt")
    (run_dir / "findings.jsonl").write_text(
        _finding("f-old", hypothesis).model_dump_json() + "\n"
    )
    (run_dir / verify_stage.VERIFY_COMPLETE_FILENAME).write_text("{}")
    replacement = _finding("f-new", hypothesis)

    async def rerun(*_args, poc_dir: Path, **_kwargs):
        assert not any(poc_dir.iterdir())
        (poc_dir / "iter_1.py").write_text("# forced retry")
        return replacement

    monkeypatch.setattr(verify_stage, "_verify_one", rerun)

    findings = await _run(
        tmp_path,
        TriagedArtifact(
            plugin_slug="plugin",
            accepted=[hypothesis],
            rejected=[],
            merged=[],
        ),
        force=True,
    )

    assert [finding.id for finding in findings] == ["f-new"]
    assert [
        Finding.model_validate_json(line).id
        for line in (run_dir / "findings.jsonl").read_text().splitlines()
    ] == ["f-new"]
    archives = list((run_dir / "verify_archive").iterdir())
    assert len(archives) == 1
    assert (archives[0] / "findings.jsonl").exists()
    assert (archives[0] / verify_stage.VERIFY_COMPLETE_FILENAME).exists()
    assert (archives[0] / "verifications" / hypothesis.id / "iter_1.py").exists()


@pytest.mark.asyncio
async def test_candidate_exception_continues_then_fails_stage(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _patch_zip(monkeypatch, tmp_path)
    errored = _hyp("errored")
    completed = _hyp("completed")
    calls: list[str] = []

    async def verify_one(*args, poc_dir: Path, **_kwargs):
        hypothesis = args[0]
        calls.append(hypothesis.id)
        if hypothesis.id == "errored":
            raise RuntimeError("temporary service failure")
        (poc_dir / "iter_1.py").write_text("# clean negative")
        return None

    monkeypatch.setattr(verify_stage, "_verify_one", verify_one)

    with pytest.raises(verify_stage.VerifyStageError) as raised:
        await _run(
            tmp_path,
            TriagedArtifact(
                plugin_slug="plugin",
                accepted=[errored, completed],
                rejected=[],
                merged=[],
            ),
        )

    run_dir = tmp_path / "runs" / "run-1"
    assert calls == ["errored", "completed"]
    assert raised.value.errors == [("errored", "temporary service failure")]
    assert (run_dir / "verifications" / "errored" / "error.log").exists()
    assert not (run_dir / verify_stage.VERIFY_COMPLETE_FILENAME).exists()
    ledger = [json.loads(line) for line in (run_dir / "decision_ledger.jsonl").read_text().splitlines()]
    assert any(row["action"] == "reject" and row.get("hypothesis_id") == "completed" for row in ledger)


@pytest.mark.asyncio
async def test_silent_failure_is_error_not_rejection(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _patch_zip(monkeypatch, tmp_path)
    hypothesis = _hyp("silent")

    async def silent(*_args, **_kwargs):
        return None

    monkeypatch.setattr(verify_stage, "_verify_one", silent)

    with pytest.raises(verify_stage.VerifyStageError):
        await _run(
            tmp_path,
            TriagedArtifact(
                plugin_slug="plugin",
                accepted=[hypothesis],
                rejected=[],
                merged=[],
            ),
        )

    run_dir = tmp_path / "runs" / "run-1"
    ledger = [json.loads(line) for line in (run_dir / "decision_ledger.jsonl").read_text().splitlines()]
    candidate_rows = [row for row in ledger if row.get("hypothesis_id") == "silent"]
    assert any(row["result"] == "silent_failure" for row in candidate_rows)
    assert not any(row["action"] == "reject" for row in candidate_rows)
    assert not (run_dir / verify_stage.VERIFY_COMPLETE_FILENAME).exists()


def test_orchestrator_verify_checkpoint_and_force_boundaries(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "findings.jsonl").write_text("")

    assert not orchestrator._verify_checkpoint_complete(run_dir)
    (run_dir / verify_stage.VERIFY_COMPLETE_FILENAME).write_text("{}")
    assert orchestrator._verify_checkpoint_complete(run_dir)

    assert orchestrator._stage_is_forced("verify", orchestrator.STAGE_ORDER.index("triage"))
    assert orchestrator._stage_is_forced("verify", orchestrator.STAGE_ORDER.index("verify"))
    assert not orchestrator._stage_is_forced("verify", orchestrator.STAGE_ORDER.index("dedup"))
    assert not orchestrator._stage_is_forced("verify", orchestrator.STAGE_ORDER.index("report"))
    assert not orchestrator._stage_is_forced("verify", None)
