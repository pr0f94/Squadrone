"""Orchestrator — runs every stage in order, persists run + findings to SQLite, catches errors cleanly."""

from __future__ import annotations

import json
import logging
import time
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Awaitable, Callable, Optional

from pydantic import BaseModel

from .agents.developer import DeveloperAgent
from .agents.runtime import AgentRuntime
from .schemas.config import PipelineConfig
from .schemas.finding import DedupStatus, Finding
from .schemas.hypothesis import Hypothesis, TriagedArtifact
from .services.artifacts import (
    atomic_write_json,
    atomic_write_jsonl,
    atomic_write_text,
    read_jsonl_models,
)
from .services.budget import BudgetExceededError, BudgetTracker
from .services.decision_ledger import append_decision
from .services.llm import init_cache
from .services import verify_helpers
from .services.sqlite import connect_sqlite
from .stages import dedup as dedup_stage
from .stages import hypothesis as hypothesis_stage
from .stages import intake as intake_stage
from .stages import recon as recon_stage
from .stages import report as report_stage
from .stages import triage as triage_stage
from .stages import verify as verify_stage

logger = logging.getLogger(__name__)

DB_PATH = "db/squadrone.sqlite"
SCHEMA_PATH = "db/schema.sql"
PLUGINS_ROOT = "plugins"


def _runs_root(plugin_slug: str) -> str:
    """Per-plugin runs directory: plugins/<slug>/runs."""
    return str(Path(PLUGINS_ROOT) / plugin_slug / "runs")


def _resolve_run_dir(run_id: str) -> Path:
    """Locate an existing run by id without knowing the slug — used for resume."""
    matches = list(Path(PLUGINS_ROOT).glob(f"*/runs/{run_id}"))
    if not matches:
        raise FileNotFoundError(f"plugins/*/runs/{run_id} not found")
    return matches[0]


EventCallback = Callable[[str, str, dict], Awaitable[None] | None]


class ScanResult(BaseModel):
    run_id: str
    plugin_slug: str
    status: str
    finding_count: int
    novel_count: int
    cost_usd: float
    duration_seconds: float
    report_paths: list[str]
    cache_hit_rate: float = (
        0.0  # 0.0–1.0; fraction of input tokens served from prompt cache
    )


def _hypothesis_from_manual_item(item: dict) -> Optional[Hypothesis]:
    try:
        hyp_data = item.get("hypothesis")
        if not hyp_data:
            return None
        return Hypothesis.model_validate(hyp_data)
    except Exception:
        return None


def _emit_triage_manual_review_queue(
    triaged: TriagedArtifact,
    run_dir: Path,
    plugin_slug: str,
) -> dict[str, int]:
    import json as _json

    marker_path = run_dir / "manual_review_queued.json"
    queued_ids: set[str] = set()
    if marker_path.exists():
        try:
            data = _json.loads(marker_path.read_text())
            queued_ids = {str(x) for x in data.get("hypothesis_ids", [])}
        except Exception:
            queued_ids = set()

    queued = 0
    already_queued = 0
    unavailable = 0
    for item in triaged.manual_review:
        item_id = str(item.get("hypothesis_id") or "")
        if item_id and item_id in queued_ids:
            already_queued += 1
            continue
        hyp = _hypothesis_from_manual_item(item)
        if hyp is None:
            append_decision(
                run_dir,
                stage="manual_queue",
                action="error",
                result="missing_hypothesis",
                hypothesis_id=str(item.get("hypothesis_id") or ""),
                reason="manual-review item did not contain a valid hypothesis payload",
                artifact=run_dir / "triaged.json",
            )
            unavailable += 1
            continue
        hyp_dir = run_dir / "verifications" / hyp.id
        hyp_dir.mkdir(parents=True, exist_ok=True)
        reason = str(
            item.get("reason") or "triage/manual quality gate requested manual review"
        )
        verify_helpers.write_manual_scaffold(
            hyp,
            hyp_dir,
            plugin_slug,
            "",
            handoff_reason=reason,
        )
        was_queued = verify_helpers.emit_to_manual_review_queue(
            hyp,
            run_dir,
            reason=reason,
            verifier_notes={
                "source": item.get("source") or "triage",
                "manual_review": True,
                "rules": item.get("rules") or [],
                "warnings": item.get("warnings") or [],
            },
        )
        if not was_queued:
            already_queued += 1
            queued_ids.add(hyp.id)
            continue
        append_decision(
            run_dir,
            stage="manual_queue",
            action="enqueue",
            result=str(item.get("source") or "triage"),
            hypothesis_id=hyp.id,
            reason=reason,
            artifact=hyp_dir / "manual_scaffold",
        )
        queued += 1
        queued_ids.add(hyp.id)
    if queued:
        atomic_write_json(marker_path, {"hypothesis_ids": sorted(queued_ids)})
    return {
        "manual_queued": queued,
        "already_queued": already_queued,
        "unavailable": unavailable,
        "candidates": len(triaged.manual_review),
    }


async def _init_db() -> None:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    schema = Path(SCHEMA_PATH).read_text()
    async with connect_sqlite(DB_PATH) as db:
        await db.executescript(schema)
        await db.commit()


async def _record_run_start(run_id: str, plugin_slug: str) -> None:
    async with connect_sqlite(DB_PATH) as db:
        await db.execute(
            "INSERT OR IGNORE INTO plugins(slug) VALUES (?)",
            (plugin_slug,),
        )
        await db.execute(
            "INSERT INTO runs(run_id, plugin_slug, started_at, status, cost_usd, finding_count) "
            "VALUES (?, ?, ?, 'running', 0, 0)",
            (run_id, plugin_slug, datetime.now(timezone.utc).isoformat()),
        )
        await db.commit()


async def _record_run_finish(
    run_id: str, status: str, cost: float, finding_count: int
) -> None:
    async with connect_sqlite(DB_PATH) as db:
        # Cumulative cost across resumes: add this run's spend to the previous
        # value rather than overwriting (an empty cost row is 0, so first
        # finish reads 0 and stores `cost`; subsequent --resume finishes add).
        await db.execute(
            "UPDATE runs SET finished_at=?, status=?, "
            "cost_usd=COALESCE(cost_usd,0)+?, finding_count=? WHERE run_id=?",
            (
                datetime.now(timezone.utc).isoformat(),
                status,
                cost,
                finding_count,
                run_id,
            ),
        )
        await db.execute(
            "UPDATE plugins SET last_scanned_at=?, finding_count=finding_count+? WHERE slug="
            "(SELECT plugin_slug FROM runs WHERE run_id=?)",
            (datetime.now(timezone.utc).isoformat(), finding_count, run_id),
        )
        await db.execute(
            "UPDATE plugins SET finding_count=("
            "SELECT COUNT(*) FROM findings WHERE plugin_slug=plugins.slug"
            ") WHERE slug=(SELECT plugin_slug FROM runs WHERE run_id=?)",
            (run_id,),
        )
        await db.commit()


async def _persist_findings(
    run_id: str, plugin_slug: str, findings: list[Finding]
) -> None:
    async with connect_sqlite(DB_PATH) as db:
        for f in findings:
            await db.execute(
                "INSERT INTO findings(finding_id, run_id, plugin_slug, bug_class, "
                "cwe, confidence, poc_status, dedup_status, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(finding_id) DO UPDATE SET "
                "run_id=excluded.run_id, plugin_slug=excluded.plugin_slug, "
                "bug_class=excluded.bug_class, cwe=excluded.cwe, "
                "confidence=excluded.confidence, poc_status=excluded.poc_status, "
                "dedup_status=excluded.dedup_status, created_at=excluded.created_at",
                (
                    f.id,
                    run_id,
                    plugin_slug,
                    f.hypothesis.vulnerability_type,
                    f.hypothesis.root_cause_cwe,
                    f.hypothesis.confidence.value,
                    f.poc_status.value,
                    f.dedup_status.value,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )

        current_ids = sorted({finding.id for finding in findings})
        current_filter = ""
        params: list[str] = [run_id]
        if current_ids:
            placeholders = ",".join("?" for _ in current_ids)
            current_filter = f"AND finding_id NOT IN ({placeholders}) "
            params.extend(current_ids)
        await db.execute(
            "DELETE FROM findings WHERE run_id=? "
            f"{current_filter}"
            "AND NOT EXISTS ("
            "SELECT 1 FROM disclosures "
            "WHERE disclosures.finding_id=findings.finding_id"
            ")",
            params,
        )
        await db.commit()


async def _emit(
    cb: Optional[EventCallback], stage: str, status: str, info: dict
) -> None:
    if cb is None:
        return
    import inspect

    res = cb(stage, status, info)
    if inspect.isawaitable(res):
        await res


STAGE_ORDER = ["intake", "recon", "hypothesis", "triage", "verify", "dedup", "report"]


def _stage_is_forced(stage: str, force_idx: int | None) -> bool:
    return force_idx is not None and STAGE_ORDER.index(stage) >= force_idx


def _verify_checkpoint_complete(run_dir: Path) -> bool:
    return (run_dir / verify_stage.VERIFY_COMPLETE_FILENAME).exists() and (
        run_dir / "findings.jsonl"
    ).exists()


def _verify_checkpoint_matches_triage(
    run_dir: Path,
    triaged: TriagedArtifact,
) -> bool:
    """Reject complete markers produced for another scope mode or candidate set."""
    if not _verify_checkpoint_complete(run_dir):
        return False
    try:
        marker = json.loads(
            (run_dir / verify_stage.VERIFY_COMPLETE_FILENAME).read_text()
        )
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(marker, dict):
        return False
    # Missing markers are historical and therefore came from enforced-scope runs.
    stored_scope = marker.get("submission_scope_enforced", True)
    stored_ids = marker.get("accepted_hypothesis_ids", [])
    expected_ids = [hypothesis.id for hypothesis in triaged.accepted]
    expected_manual_ids = [
        hypothesis.id
        for hypothesis in triaged.accepted
        if not hypothesis.bug_class.is_known
    ]
    # Historical markers remain valid for registry-backed candidates. An open CWE
    # requires an explicit manual-resolution record so a pre-policy automatic
    # confirmation cannot be silently resumed.
    stored_manual_ids = marker.get("manual_review_hypothesis_ids", [])
    findings, corrupt_count = read_jsonl_models(
        run_dir / "findings.jsonl",
        Finding,
    )
    if corrupt_count:
        return False
    finding_ids = [finding.id for finding in findings]
    finding_hypothesis_ids = {finding.hypothesis.id for finding in findings}
    stored_finding_ids = marker.get("finding_ids", [])
    return (
        stored_scope is triaged.submission_scope_enforced
        and stored_ids == expected_ids
        and stored_manual_ids == expected_manual_ids
        and finding_hypothesis_ids <= set(expected_ids)
        and all(finding.hypothesis.bug_class.is_known for finding in findings)
        and stored_finding_ids == finding_ids
    )


async def run_scan(
    plugin_slug: str,
    config_path: str = "pipelines/default.yaml",
    budget_override: Optional[float] = None,
    on_event: Optional[EventCallback] = None,
    version: Optional[str] = None,
    resume_run_id: Optional[str] = None,
    resume_from: Optional[str] = None,
    verify_only: bool = False,
) -> ScanResult:
    config = PipelineConfig.from_yaml(config_path)
    ceiling = (
        budget_override if budget_override is not None else config.cost_ceiling_usd
    )

    if resume_from is not None and resume_from not in STAGE_ORDER:
        raise ValueError(f"--from must be one of {STAGE_ORDER}, got {resume_from!r}")
    if resume_from is not None and resume_run_id is None:
        raise ValueError("--from requires --resume <run_id>")

    if resume_run_id:
        run_id = resume_run_id
        run_dir = _resolve_run_dir(run_id)
    else:
        run_id = uuid.uuid4().hex[:12]
        run_dir = Path(_runs_root(plugin_slug)) / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
    started = time.time()

    # Determine which stages to skip (load from disk) vs run.
    # Auto-resume picks up at the first missing artifact.
    # --from forces re-run from that stage onwards (later artifacts ignored).
    force_idx = STAGE_ORDER.index(resume_from) if resume_from else None

    def _should_load(stage: str) -> bool:
        """True if stage should be loaded from disk rather than re-run."""
        if not resume_run_id:
            return False
        if _stage_is_forced(stage, force_idx):
            return False
        return True

    budget = BudgetTracker(ceiling_usd=ceiling)

    await init_cache()
    await _init_db()
    if not resume_run_id:
        await _record_run_start(run_id, plugin_slug)
    else:
        # Mark the existing run record as running again
        async with connect_sqlite(DB_PATH) as db:
            await db.execute(
                "UPDATE runs SET status='running', finished_at=NULL WHERE run_id=?",
                (run_id,),
            )
            await db.commit()

    developer = DeveloperAgent(
        model=config.models.developer,
        followup_model=config.models.developer_followup,
        budget_tracker=budget,
        llm_options=config.llm_options_for_role("developer"),
        followup_llm_options=config.llm_options_for_role("developer_followup"),
    )
    runtime = AgentRuntime(
        run_dir=str(run_dir),
        developer=developer,
        developer_calls_per_agent=config.developer_calls_per_agent,
        budget_tracker=budget,
        llm_options=config.llm.model_dump(exclude_none=True),
        role_reasoning=config.reasoning.model_dump(exclude_none=True),
    )

    status = "running"
    findings: list[Finding] = []
    report_paths: list[str] = []
    novel_count = 0

    try:
        from .schemas.hypothesis import Hypothesis, HypothesesArtifact, TriagedArtifact
        from .schemas.intake import IntakeArtifact
        from .schemas.recon import ReconArtifact

        intake_path = run_dir / "intake.json"
        recon_path = run_dir / "recon.json"
        hyps_path = run_dir / "hypotheses.jsonl"
        triaged_path = run_dir / "triaged.json"
        findings_path = run_dir / "findings.jsonl"

        # ---- intake ----
        budget.set_stage("intake")
        if _should_load("intake") and intake_path.exists():
            intake = IntakeArtifact.from_json_file(str(intake_path))
            await _emit(
                on_event,
                "intake",
                "skipped",
                {
                    "version": intake.plugin_version,
                    "files": intake.file_count,
                    "lines": intake.total_lines,
                },
            )
        else:
            await _emit(
                on_event,
                "intake",
                "start",
                {
                    "plugin_slug": plugin_slug,
                    "run_id": run_id,
                    "version": version or "latest",
                },
            )
            intake = await intake_stage.run(
                plugin_slug,
                run_id,
                config,
                runs_root=_runs_root(plugin_slug),
                version=version,
            )
            await _emit(
                on_event,
                "intake",
                "done",
                {
                    "version": intake.plugin_version,
                    "files": intake.file_count,
                    "lines": intake.total_lines,
                    "spent": budget.spent,
                },
            )

        # ---- recon ----
        budget.set_stage("recon")
        if _should_load("recon") and recon_path.exists():
            recon = ReconArtifact.from_json_file(str(recon_path))
            await _emit(
                on_event,
                "recon",
                "skipped",
                {
                    "entry_points": len(recon.entry_points),
                    "sinks": len(recon.sinks),
                },
            )
        else:
            await _emit(on_event, "recon", "start", {})
            recon = await recon_stage.run(
                intake, config, runtime, runs_root=_runs_root(plugin_slug)
            )
            await _emit(
                on_event,
                "recon",
                "done",
                {
                    "entry_points": len(recon.entry_points),
                    "sinks": len(recon.sinks),
                    "spent": budget.spent,
                },
            )

        # ---- hypothesis ----
        budget.set_stage("hypothesis")
        if _should_load("hypothesis") and hyps_path.exists():
            hypotheses = [
                Hypothesis.model_validate_json(line)
                for line in hyps_path.read_text().splitlines()
                if line.strip()
            ]
            hyps = HypothesesArtifact(
                plugin_slug=intake.plugin_slug, hypotheses=hypotheses
            )
            await _emit(on_event, "hypothesis", "skipped", {"count": len(hypotheses)})
        else:
            await _emit(on_event, "hypothesis", "start", {})
            hyps = await hypothesis_stage.run(
                recon,
                intake.source_path,
                config,
                budget,
                runtime,
                runs_root=_runs_root(plugin_slug),
                run_id=run_id,
            )
            await _emit(
                on_event,
                "hypothesis",
                "done",
                {
                    "count": len(hyps.hypotheses),
                    "spent": budget.spent,
                },
            )

        # ---- triage ----
        budget.set_stage("triage")
        expected_submission_scope = not verify_only
        triage_scope_changed = False
        loaded_triage = False
        if _should_load("triage") and triaged_path.exists():
            triaged = TriagedArtifact.from_json_file(str(triaged_path))
            triage_scope_changed = (
                triaged.submission_scope_enforced != expected_submission_scope
            )
            if triage_scope_changed:
                logger.info(
                    "triage: submission-scope mode changed on resume; "
                    "invalidating triage and verify checkpoints"
                )
                append_decision(
                    run_dir,
                    stage="triage",
                    action="invalidate",
                    result="submission_scope_mode_changed",
                    reason=(
                        "resume changed submission-scope enforcement from "
                        f"{triaged.submission_scope_enforced} to "
                        f"{expected_submission_scope}"
                    ),
                    artifact=triaged_path,
                )
            else:
                loaded_triage = True
                await _emit(
                    on_event,
                    "triage",
                    "skipped",
                    {
                        "accepted": len(triaged.accepted),
                        "rejected": len(triaged.rejected),
                        "merged": len(triaged.merged),
                        "deferred": len(triaged.deferred),
                    },
                )
        if not loaded_triage:
            await _emit(on_event, "triage", "start", {})
            triaged = await triage_stage.run(
                hyps,
                intake.source_path,
                config,
                budget,
                runtime,
                runs_root=_runs_root(plugin_slug),
                run_id=run_id,
                enforce_submission_scope=expected_submission_scope,
            )
            await _emit(
                on_event,
                "triage",
                "done",
                {
                    "accepted": len(triaged.accepted),
                    "rejected": len(triaged.rejected),
                    "merged": len(triaged.merged),
                    "deferred": len(triaged.deferred),
                    "manual_review_candidates": len(triaged.manual_review),
                    "spent": budget.spent,
                },
            )

        triage_manual_queue = _emit_triage_manual_review_queue(
            triaged, run_dir, intake.plugin_slug
        )
        if triage_manual_queue["candidates"]:
            await _emit(
                on_event,
                "manual_queue",
                "done",
                {
                    **triage_manual_queue,
                    "reason": "triage_or_quality_gate",
                },
            )

        # ---- verify ----
        budget.set_stage("verify")
        verify_checkpoint_stale = _verify_checkpoint_complete(
            run_dir
        ) and not _verify_checkpoint_matches_triage(run_dir, triaged)
        force_verify = (
            _stage_is_forced("verify", force_idx)
            or triage_scope_changed
            or verify_checkpoint_stale
        )
        if (
            not force_verify
            and _should_load("verify")
            and _verify_checkpoint_complete(run_dir)
        ):
            findings, corrupt_count = read_jsonl_models(
                findings_path,
                Finding,
                corrupt_path=run_dir / "findings_corrupt.jsonl",
            )
            if corrupt_count:
                append_decision(
                    run_dir,
                    stage="verify",
                    action="recover",
                    result="corrupt_findings_quarantined",
                    reason=f"{corrupt_count} malformed findings.jsonl line(s)",
                    artifact=run_dir / "findings_corrupt.jsonl",
                )
            await _emit(on_event, "verify", "skipped", {"findings": len(findings)})
        else:
            await _emit(
                on_event, "verify", "start", {"to_verify": len(triaged.accepted)}
            )
            try:
                findings = await verify_stage.run(
                    triaged,
                    intake.source_path,
                    config,
                    budget,
                    runtime,
                    runs_root=_runs_root(plugin_slug),
                    run_id=run_id,
                    developer=developer,
                    force=force_verify,
                )
            except verify_stage.VerifyStageError as exc:
                # Preserve partial confirmations in the failed ScanResult and run
                # record; findings.jsonl remains the crash-safe source of truth.
                findings = exc.findings
                raise
            await _emit(
                on_event,
                "verify",
                "done",
                {"findings": len(findings), "spent": budget.spent},
            )

        if verify_only:
            # Verification already checkpoints this artifact, but write it once more
            # at the orchestration boundary so mocked/custom verifiers get the same
            # durable contract. No dedup client is constructed in this mode.
            atomic_write_jsonl(findings_path, findings)
            await _persist_findings(run_id, plugin_slug, findings)
        else:
            # ---- dedup (cheap; always re-run on resume since output overwrites findings.jsonl) ----
            budget.set_stage("dedup")
            await _emit(on_event, "dedup", "start", {})
            findings = await dedup_stage.run(
                findings,
                plugin_slug,
                config,
                runs_root=_runs_root(plugin_slug),
                run_id=run_id,
            )
            novel_count = sum(
                1 for f in findings if f.dedup_status == DedupStatus.NOVEL
            )
            await _emit(
                on_event,
                "dedup",
                "done",
                {
                    "novel": novel_count,
                    "possibly_known": sum(
                        1
                        for f in findings
                        if f.dedup_status == DedupStatus.POSSIBLY_KNOWN
                    ),
                    "known_dupe": sum(
                        1 for f in findings if f.dedup_status == DedupStatus.KNOWN_DUPE
                    ),
                },
            )

            await _persist_findings(run_id, plugin_slug, findings)

            # ---- report (per-finding skip: existing report files are preserved) ----
            budget.set_stage("report")
            await _emit(on_event, "report", "start", {})
            report_paths = await report_stage.run(
                findings,
                plugin_slug,
                config,
                budget,
                runtime,
                runs_root=_runs_root(plugin_slug),
                run_id=run_id,
                plugin_path=intake.source_path,
                plugin_version=intake.plugin_version,
            )
            await _emit(
                on_event,
                "report",
                "done",
                {
                    "reports": len(report_paths),
                    "spent": budget.spent,
                },
            )

        status = "complete"
        append_decision(
            run_dir,
            stage="_pipeline",
            action="finish",
            result=status,
            details={
                "findings": len(findings),
                "cost_usd": budget.spent,
                "verify_only": verify_only,
            },
        )

    except BudgetExceededError as e:
        logger.warning("scan %s: budget exceeded — %s", run_id, e)
        await _persist_findings(run_id, plugin_slug, findings)
        status = "budget_exceeded"
        append_decision(
            run_dir,
            stage="_pipeline",
            action="finish",
            result=status,
            reason=str(e),
            details={"findings": len(findings), "cost_usd": budget.spent},
        )
        await _emit(on_event, "_pipeline", "budget_exceeded", {"message": str(e)})

    except Exception as e:
        logger.exception("scan %s: failed — %s", run_id, e)
        atomic_write_text(run_dir / "error.log", traceback.format_exc())
        status = "failed"
        append_decision(
            run_dir,
            stage="_pipeline",
            action="finish",
            result=status,
            reason=str(e),
            artifact=run_dir / "error.log",
            details={"findings": len(findings), "cost_usd": budget.spent},
        )
        await _emit(on_event, "_pipeline", "failed", {"message": str(e)})

    finally:
        try:
            budget.write_cost_report(run_dir)
        except Exception as e:
            logger.warning("scan %s: failed to write cost report: %s", run_id, e)
        try:
            await _record_run_finish(run_id, status, budget.spent, len(findings))
        except Exception as e:
            logger.warning("scan %s: failed to record run finish: %s", run_id, e)

    duration = time.time() - started
    return ScanResult(
        run_id=run_id,
        plugin_slug=plugin_slug,
        status=status,
        finding_count=len(findings),
        novel_count=novel_count,
        cost_usd=budget.spent,
        duration_seconds=duration,
        report_paths=report_paths,
        cache_hit_rate=budget.cache_hit_rate,
    )
