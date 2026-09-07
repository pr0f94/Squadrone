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


def _hyp(
    hypothesis_id: str,
    bug_class: BugClass = BugClass.IDOR,
) -> Hypothesis:
    return Hypothesis(
        id=hypothesis_id,
        specialist="test",
        bug_class=bug_class,
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


def _open_hyp(hypothesis_id: str) -> Hypothesis:
    return _hyp(hypothesis_id, BugClass("CWE-1234"))


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


def _write_attempt_checkpoint(
    hyp_dir: Path,
    *,
    status: str,
    hypothesis_id: str | None = None,
    attempts: list[dict] | None = None,
    schema_version: int = 1,
) -> None:
    default_attempt = {
        "iteration": 1,
        "phase": "confirmation" if status == "confirmed" else "attack",
        "script_path": "iter_1.py",
        "result": "success" if status == "confirmed" else "failed",
        "validation_reason": None if status == "confirmed" else "not reproduced",
    }
    (hyp_dir / "attempts.json").write_text(
        json.dumps(
            {
                "schema_version": schema_version,
                "hypothesis_id": hypothesis_id or hyp_dir.name,
                "status": status,
                "attempts": attempts if attempts is not None else [default_attempt],
            }
        )
    )


@pytest.mark.parametrize("status", ["in_progress", "not_confirmed", "confirmed"])
def test_attempt_checkpoint_state_accepts_known_statuses(
    tmp_path: Path,
    status: str,
) -> None:
    hyp_dir = tmp_path / "candidate"
    hyp_dir.mkdir()
    _write_attempt_checkpoint(hyp_dir, status=status)

    assert verify_stage._attempt_checkpoint_state(hyp_dir) == status


def test_attempt_checkpoint_state_preserves_historical_absence(tmp_path: Path) -> None:
    hyp_dir = tmp_path / "candidate"
    hyp_dir.mkdir()

    assert verify_stage._attempt_checkpoint_state(hyp_dir) is None


@pytest.mark.parametrize(
    "payload",
    [
        "not-json",
        json.dumps([]),
        json.dumps(
            {
                "schema_version": 2,
                "hypothesis_id": "candidate",
                "status": "not_confirmed",
                "attempts": [{"iteration": 1}],
            }
        ),
        json.dumps(
            {
                "schema_version": 1,
                "hypothesis_id": "different",
                "status": "not_confirmed",
                "attempts": [{"iteration": 1}],
            }
        ),
        json.dumps(
            {
                "schema_version": 1,
                "hypothesis_id": "candidate",
                "status": "unknown",
                "attempts": [{"iteration": 1}],
            }
        ),
        json.dumps(
            {
                "schema_version": 1,
                "hypothesis_id": "candidate",
                "status": "in_progress",
                "attempts": [],
            }
        ),
        json.dumps(
            {
                "schema_version": 1,
                "hypothesis_id": "candidate",
                "status": "not_confirmed",
                "attempts": [{"garbage": True}],
            }
        ),
        json.dumps(
            {
                "schema_version": 1,
                "hypothesis_id": "candidate",
                "status": "not_confirmed",
                "attempts": [
                    {
                        "iteration": 1,
                        "phase": "confirmation",
                        "script_path": "iter_1.py",
                        "result": "success",
                    }
                ],
            }
        ),
    ],
)
def test_attempt_checkpoint_state_rejects_untrusted_payloads(
    tmp_path: Path,
    payload: str,
) -> None:
    hyp_dir = tmp_path / "candidate"
    hyp_dir.mkdir()
    (hyp_dir / "attempts.json").write_text(payload)

    assert verify_stage._attempt_checkpoint_state(hyp_dir) == "incomplete"


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
    assert marker["submission_scope_enforced"] is True


@pytest.mark.asyncio
async def test_open_cwe_is_idempotently_handed_to_manual_review_and_archives_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    queue_path = tmp_path / "manual-review.jsonl"
    monkeypatch.setattr(verify_stage.verify_helpers, "MANUAL_REVIEW_QUEUE", queue_path)
    monkeypatch.setattr(
        verify_stage,
        "_zip_plugin",
        lambda *_args: (_ for _ in ()).throw(
            AssertionError("manual-only verification must not package the plugin")
        ),
    )

    async def should_not_verify(*_args, **_kwargs):
        raise AssertionError("open CWE must not enter automatic verification")

    monkeypatch.setattr(verify_stage, "_verify_one", should_not_verify)
    hypothesis = _open_hyp("open-cwe")
    run_dir = tmp_path / "runs" / "run-1"
    old_dir = run_dir / "verifications" / hypothesis.id
    old_dir.mkdir(parents=True)
    (old_dir / "error.log").write_text("prior automatic verification error")

    triaged = TriagedArtifact(
        plugin_slug="plugin",
        accepted=[hypothesis],
        rejected=[],
        merged=[],
    )
    assert await _run(tmp_path, triaged) == []
    assert await _run(tmp_path, triaged) == []

    queue_rows = [json.loads(line) for line in queue_path.read_text().splitlines()]
    assert len(queue_rows) == 1
    assert queue_rows[0]["hypothesis_id"] == hypothesis.id
    assert queue_rows[0]["verifier_notes"] == {
        "source": "verify_open_cwe",
        "manual_review": True,
        "automatic_verification": False,
        "poc_template": "generic_open_cwe.py.j2",
    }

    current_dir = run_dir / "verifications" / hypothesis.id
    assert not (current_dir / "error.log").exists()
    assert (current_dir / "manual_scaffold" / "README.md").is_file()
    manual_marker = json.loads(
        (current_dir / verify_stage.OPEN_CWE_MANUAL_REVIEW_FILENAME).read_text()
    )
    assert manual_marker["status"] == "manual_review"
    assert manual_marker["automatic_verification"] is False

    archived_errors = list(
        (run_dir / "verify_archive").glob(
            "*/verifications/open-cwe/error.log"
        )
    )
    assert len(archived_errors) == 1
    assert archived_errors[0].read_text() == "prior automatic verification error"

    complete = json.loads(
        (run_dir / verify_stage.VERIFY_COMPLETE_FILENAME).read_text()
    )
    assert complete["finding_ids"] == []
    assert complete["automatic_verification_hypothesis_ids"] == []
    assert complete["manual_review_hypothesis_ids"] == [hypothesis.id]
    assert complete["manual_review_queue"] == {"queued": 0, "already_queued": 1}

    ledger = [
        json.loads(line)
        for line in (run_dir / "decision_ledger.jsonl").read_text().splitlines()
    ]
    results = {row["result"] for row in ledger}
    assert "previous_error_before_open_cwe_manual_review" in results
    assert "open_cwe_manual_review_queued" in results
    assert "open_cwe_manual_review_already_queued" in results


@pytest.mark.asyncio
async def test_open_cwe_prior_finding_is_quarantined_not_resumed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        verify_stage.verify_helpers,
        "MANUAL_REVIEW_QUEUE",
        tmp_path / "manual-review.jsonl",
    )

    async def should_not_verify(*_args, **_kwargs):
        raise AssertionError("open CWE must not enter automatic verification")

    monkeypatch.setattr(verify_stage, "_verify_one", should_not_verify)
    hypothesis = _open_hyp("formerly-confirmed-open-cwe")
    run_dir = tmp_path / "runs" / "run-1"
    run_dir.mkdir(parents=True)
    (run_dir / "findings.jsonl").write_text(
        _finding("f-unsafe", hypothesis).model_dump_json() + "\n"
    )

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
    assert (run_dir / "findings.jsonl").read_text() == ""
    quarantined = [
        Finding.model_validate_json(line)
        for line in (
            run_dir / "findings_open_cwe_quarantined.jsonl"
        ).read_text().splitlines()
    ]
    assert [finding.id for finding in quarantined] == ["f-unsafe"]


@pytest.mark.asyncio
async def test_primitive_only_cwe502_finding_is_quarantined_and_retried(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _patch_zip(monkeypatch, tmp_path)
    hypothesis = _hyp("legacy-object-finding", BugClass.PHP_OBJECT_INJECTION)
    hypothesis.evidence_summary["usable_gadget"] = True
    run_dir = tmp_path / "runs" / "run-1"
    run_dir.mkdir(parents=True)
    (run_dir / "findings.jsonl").write_text(
        _finding("f-primitive-only", hypothesis).model_dump_json() + "\n"
    )
    verified: list[str] = []

    async def retry(*args, poc_dir: Path, **_kwargs):
        verified.append(args[0].id)
        (poc_dir / "iter_1.py").write_text("# retried incomplete CWE-502 proof")
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
    assert verified == [hypothesis.id]
    quarantined = [
        Finding.model_validate_json(line)
        for line in (run_dir / "findings_php_object_unproven.jsonl")
        .read_text()
        .splitlines()
    ]
    assert [finding.id for finding in quarantined] == ["f-primitive-only"]


@pytest.mark.asyncio
async def test_open_cwe_manual_handoff_does_not_block_known_candidate(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _patch_zip(monkeypatch, tmp_path)
    monkeypatch.setattr(
        verify_stage.verify_helpers,
        "MANUAL_REVIEW_QUEUE",
        tmp_path / "manual-review.jsonl",
    )
    open_cwe = _open_hyp("open-cwe")
    known = _hyp("known-cwe")
    verified_ids: list[str] = []

    async def reject_known(*args, poc_dir: Path, **_kwargs):
        hypothesis = args[0]
        verified_ids.append(hypothesis.id)
        (poc_dir / "iter_1.py").write_text("# clean known-CWE attempt")
        return None

    monkeypatch.setattr(verify_stage, "_verify_one", reject_known)
    findings = await _run(
        tmp_path,
        TriagedArtifact(
            plugin_slug="plugin",
            accepted=[open_cwe, known],
            rejected=[],
            merged=[],
        ),
    )

    assert findings == []
    assert verified_ids == [known.id]
    complete = json.loads(
        (
            tmp_path
            / "runs"
            / "run-1"
            / verify_stage.VERIFY_COMPLETE_FILENAME
        ).read_text()
    )
    assert complete["automatic_verification_hypothesis_ids"] == [known.id]
    assert complete["manual_review_hypothesis_ids"] == [open_cwe.id]


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
@pytest.mark.parametrize("status", ["in_progress", "confirmed"])
async def test_ordinary_resume_retries_nonterminal_attempt_checkpoint(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    status: str,
) -> None:
    _patch_zip(monkeypatch, tmp_path)
    hypothesis = _hyp("interrupted")
    run_dir = tmp_path / "runs" / "run-1"
    hyp_dir = run_dir / "verifications" / hypothesis.id
    hyp_dir.mkdir(parents=True)
    (hyp_dir / "iter_1.py").write_text("# iteration before interruption")
    _write_attempt_checkpoint(hyp_dir, status=status)
    calls: list[str] = []

    async def retry(*args, poc_dir: Path, **_kwargs):
        calls.append(args[0].id)
        assert not (poc_dir / "attempts.json").exists()
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
    assert calls == ["interrupted"]
    archived = list(
        (run_dir / "verify_archive").glob(
            "*/verifications/interrupted/attempts.json"
        )
    )
    assert len(archived) == 1
    assert json.loads(archived[0].read_text())["status"] == status


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
async def test_ordinary_resume_quarantines_finding_outside_current_triage(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _patch_zip(monkeypatch, tmp_path)
    current = _hyp("current")
    stale = _hyp("stale")
    run_dir = tmp_path / "runs" / "run-1"
    run_dir.mkdir(parents=True)
    (run_dir / "findings.jsonl").write_text(
        _finding("f-stale", stale).model_dump_json() + "\n"
    )

    async def reject_current(*_args, poc_dir: Path, **_kwargs):
        (poc_dir / "iter_1.py").write_text("# clean negative")
        return None

    monkeypatch.setattr(verify_stage, "_verify_one", reject_current)

    findings = await _run(
        tmp_path,
        TriagedArtifact(
            plugin_slug="plugin",
            accepted=[current],
            rejected=[],
            merged=[],
        ),
    )

    assert findings == []
    assert (run_dir / "findings.jsonl").read_text() == ""
    quarantined = [
        Finding.model_validate_json(line)
        for line in (run_dir / "findings_stale.jsonl").read_text().splitlines()
    ]
    assert [finding.hypothesis.id for finding in quarantined] == ["stale"]
    marker = json.loads((run_dir / verify_stage.VERIFY_COMPLETE_FILENAME).read_text())
    assert marker["accepted_hypothesis_ids"] == ["current"]
    assert marker["finding_ids"] == []


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
    ledger = [
        json.loads(line)
        for line in (run_dir / "decision_ledger.jsonl").read_text().splitlines()
    ]
    assert any(
        row["action"] == "reject" and row.get("hypothesis_id") == "completed"
        for row in ledger
    )


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
    ledger = [
        json.loads(line)
        for line in (run_dir / "decision_ledger.jsonl").read_text().splitlines()
    ]
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

    assert orchestrator._stage_is_forced(
        "verify", orchestrator.STAGE_ORDER.index("triage")
    )
    assert orchestrator._stage_is_forced(
        "verify", orchestrator.STAGE_ORDER.index("verify")
    )
    assert not orchestrator._stage_is_forced(
        "verify", orchestrator.STAGE_ORDER.index("dedup")
    )
    assert not orchestrator._stage_is_forced(
        "verify", orchestrator.STAGE_ORDER.index("report")
    )
    assert not orchestrator._stage_is_forced("verify", None)


def test_verify_checkpoint_mode_and_candidate_set_must_match_triage(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "findings.jsonl").write_text("")
    hypothesis = _hyp("candidate")
    local_triage = TriagedArtifact(
        plugin_slug="plugin",
        accepted=[hypothesis],
        rejected=[],
        merged=[],
        submission_scope_enforced=False,
    )
    marker_path = run_dir / verify_stage.VERIFY_COMPLETE_FILENAME

    marker_path.write_text(
        json.dumps(
            {
                "accepted_hypothesis_ids": ["candidate"],
                "finding_ids": [],
                "submission_scope_enforced": False,
            }
        )
    )
    assert orchestrator._verify_checkpoint_matches_triage(run_dir, local_triage)

    marker_path.write_text(
        json.dumps(
            {
                "accepted_hypothesis_ids": ["candidate"],
                "finding_ids": [],
                "submission_scope_enforced": True,
            }
        )
    )
    assert not orchestrator._verify_checkpoint_matches_triage(run_dir, local_triage)

    marker_path.write_text(
        json.dumps(
            {
                "accepted_hypothesis_ids": ["different"],
                "finding_ids": [],
                "submission_scope_enforced": False,
            }
        )
    )
    assert not orchestrator._verify_checkpoint_matches_triage(run_dir, local_triage)


def test_historical_verify_marker_defaults_to_enforced_scope(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "findings.jsonl").write_text("")
    hypothesis = _hyp("candidate")
    marker_path = run_dir / verify_stage.VERIFY_COMPLETE_FILENAME
    marker_path.write_text(
        json.dumps({"accepted_hypothesis_ids": ["candidate"], "finding_ids": []})
    )

    enforced = TriagedArtifact(
        plugin_slug="plugin",
        accepted=[hypothesis],
        rejected=[],
        merged=[],
    )
    local_only = enforced.model_copy(update={"submission_scope_enforced": False})

    assert orchestrator._verify_checkpoint_matches_triage(run_dir, enforced)
    assert not orchestrator._verify_checkpoint_matches_triage(run_dir, local_only)


def test_verify_checkpoint_requires_manual_resolution_for_open_cwe(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    findings_path = run_dir / "findings.jsonl"
    findings_path.write_text("")
    hypothesis = _open_hyp("open-cwe")
    triaged = TriagedArtifact(
        plugin_slug="plugin",
        accepted=[hypothesis],
        rejected=[],
        merged=[],
    )
    marker_path = run_dir / verify_stage.VERIFY_COMPLETE_FILENAME
    marker = {
        "accepted_hypothesis_ids": [hypothesis.id],
        "finding_ids": [],
        "submission_scope_enforced": True,
    }
    marker_path.write_text(json.dumps(marker))

    assert not orchestrator._verify_checkpoint_matches_triage(run_dir, triaged)

    marker["manual_review_hypothesis_ids"] = [hypothesis.id]
    marker_path.write_text(json.dumps(marker))
    assert orchestrator._verify_checkpoint_matches_triage(run_dir, triaged)

    unsafe_finding = _finding("f-unsafe", hypothesis)
    findings_path.write_text(unsafe_finding.model_dump_json() + "\n")
    marker["finding_ids"] = [unsafe_finding.id]
    marker_path.write_text(json.dumps(marker))
    assert not orchestrator._verify_checkpoint_matches_triage(run_dir, triaged)


def test_verify_checkpoint_rejects_finding_outside_accepted_set(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    current = _hyp("current")
    stale = _hyp("stale")
    (run_dir / "findings.jsonl").write_text(
        _finding("f-stale", stale).model_dump_json() + "\n"
    )
    (run_dir / verify_stage.VERIFY_COMPLETE_FILENAME).write_text(
        json.dumps(
            {
                "accepted_hypothesis_ids": ["current"],
                "finding_ids": ["f-stale"],
                "submission_scope_enforced": True,
            }
        )
    )
    triaged = TriagedArtifact(
        plugin_slug="plugin",
        accepted=[current],
        rejected=[],
        merged=[],
    )

    assert not orchestrator._verify_checkpoint_matches_triage(run_dir, triaged)
