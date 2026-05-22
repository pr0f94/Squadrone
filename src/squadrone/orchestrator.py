"""Orchestrator — runs every stage in order, persists run + findings to SQLite, catches errors cleanly."""

from __future__ import annotations

import logging
import time
import traceback
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Awaitable, Callable, Optional

import aiosqlite
from pydantic import BaseModel

from .agents.developer import DeveloperAgent
from .agents.runtime import AgentRuntime
from .schemas.config import PipelineConfig
from .schemas.finding import DedupStatus, Finding
from .services.budget import BudgetExceededError, BudgetTracker
from .services.llm import init_cache
from .stages import chain as chain_stage
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
    cache_hit_rate: float = 0.0  # 0.0–1.0; fraction of input tokens served from prompt cache


async def _init_db() -> None:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    schema = Path(SCHEMA_PATH).read_text()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript(schema)
        await db.commit()


async def _record_run_start(run_id: str, plugin_slug: str) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
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


async def _record_run_finish(run_id: str, status: str, cost: float, finding_count: int) -> None:
    async with aiosqlite.connect(DB_PATH) as db:
        # Cumulative cost across resumes: add this run's spend to the previous
        # value rather than overwriting (an empty cost row is 0, so first
        # finish reads 0 and stores `cost`; subsequent --resume finishes add).
        await db.execute(
            "UPDATE runs SET finished_at=?, status=?, "
            "cost_usd=COALESCE(cost_usd,0)+?, finding_count=? WHERE run_id=?",
            (datetime.now(timezone.utc).isoformat(), status, cost, finding_count, run_id),
        )
        await db.execute(
            "UPDATE plugins SET last_scanned_at=?, finding_count=finding_count+? WHERE slug="
            "(SELECT plugin_slug FROM runs WHERE run_id=?)",
            (datetime.now(timezone.utc).isoformat(), finding_count, run_id),
        )
        await db.commit()


async def _persist_findings(run_id: str, plugin_slug: str, findings: list[Finding]) -> None:
    if not findings:
        return
    async with aiosqlite.connect(DB_PATH) as db:
        for f in findings:
            await db.execute(
                "INSERT OR REPLACE INTO findings(finding_id, run_id, plugin_slug, bug_class, "
                "cwe, confidence, poc_status, dedup_status, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    f.id, run_id, plugin_slug,
                    f.hypothesis.bug_class.name, f.hypothesis.bug_class.value,
                    f.hypothesis.confidence.value,
                    f.poc_status.value, f.dedup_status.value,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
        await db.commit()


async def _emit(cb: Optional[EventCallback], stage: str, status: str, info: dict) -> None:
    if cb is None:
        return
    import inspect
    res = cb(stage, status, info)
    if inspect.isawaitable(res):
        await res


STAGE_ORDER = ["intake", "recon", "hypothesis", "chain", "triage", "verify", "dedup", "report"]


async def run_scan(
    plugin_slug: str,
    config_path: str = "pipelines/default.yaml",
    budget_override: Optional[float] = None,
    on_event: Optional[EventCallback] = None,
    version: Optional[str] = None,
    no_triage: bool = False,
    resume_run_id: Optional[str] = None,
    resume_from: Optional[str] = None,
    apply_scope_filter: bool = True,
    enable_chain: bool = False,
    enable_cross_file_taint: bool = False,
    diff_baseline: Optional[str] = None,
) -> ScanResult:
    config = PipelineConfig.from_yaml(config_path)
    ceiling = budget_override if budget_override is not None else config.cost_ceiling_usd

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
        if force_idx is not None and STAGE_ORDER.index(stage) >= force_idx:
            return False
        return True

    budget = BudgetTracker(ceiling_usd=ceiling)

    await init_cache()
    await _init_db()
    if not resume_run_id:
        await _record_run_start(run_id, plugin_slug)
    else:
        # Mark the existing run record as running again
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "UPDATE runs SET status='running', finished_at=NULL WHERE run_id=?", (run_id,),
            )
            await db.commit()

    developer = DeveloperAgent(
        model=config.models.developer,
        followup_model=config.models.developer_followup,
        budget_tracker=budget,
    )
    runtime = AgentRuntime(
        run_dir=str(run_dir),
        developer=developer,
        developer_calls_per_agent=config.developer_calls_per_agent,
        budget_tracker=budget,
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
            await _emit(on_event, "intake", "skipped", {
                "version": intake.plugin_version, "files": intake.file_count, "lines": intake.total_lines,
            })
        else:
            await _emit(on_event, "intake", "start", {"plugin_slug": plugin_slug, "run_id": run_id, "version": version or "latest"})
            intake = await intake_stage.run(
                plugin_slug, run_id, config,
                runs_root=_runs_root(plugin_slug),
                version=version,
                diff_baseline=diff_baseline,
            )
            await _emit(on_event, "intake", "done", {
                "version": intake.plugin_version, "files": intake.file_count, "lines": intake.total_lines,
                "spent": budget.spent,
            })

        # ---- recon ----
        budget.set_stage("recon")
        if _should_load("recon") and recon_path.exists():
            recon = ReconArtifact.from_json_file(str(recon_path))
            await _emit(on_event, "recon", "skipped", {
                "entry_points": len(recon.entry_points), "sinks": len(recon.sinks),
            })
        else:
            await _emit(on_event, "recon", "start", {})
            recon = await recon_stage.run(intake, config, runtime, runs_root=_runs_root(plugin_slug))
            await _emit(on_event, "recon", "done", {
                "entry_points": len(recon.entry_points), "sinks": len(recon.sinks), "spent": budget.spent,
            })

        # ---- hypothesis ----
        budget.set_stage("hypothesis")
        if _should_load("hypothesis") and hyps_path.exists():
            hypotheses = [
                Hypothesis.model_validate_json(line)
                for line in hyps_path.read_text().splitlines() if line.strip()
            ]
            hyps = HypothesesArtifact(plugin_slug=intake.plugin_slug, hypotheses=hypotheses)
            await _emit(on_event, "hypothesis", "skipped", {"count": len(hypotheses)})
        else:
            await _emit(on_event, "hypothesis", "start", {})
            hyps = await hypothesis_stage.run(
                recon, intake.source_path, config, budget, runtime,
                runs_root=_runs_root(plugin_slug), run_id=run_id,
                enable_cross_file_taint=enable_cross_file_taint,
                diff_summary=intake.diff_summary,
            )
            await _emit(on_event, "hypothesis", "done", {
                "count": len(hyps.hypotheses), "spent": budget.spent,
            })

        # ---- chain (optional, --chain flag) ----
        # Skipped entirely when enable_chain=False so default flow is byte-identical.
        # When enabled, may rewrite hyps_path with chain annotations + write chains.json.
        budget.set_stage("chain")
        if enable_chain:
            chains_path = run_dir / "chains.json"
            if _should_load("chain") and chains_path.exists():
                # On resume, hyps_path already has annotations from the previous run.
                await _emit(on_event, "chain", "skipped", {"chains_path": str(chains_path)})
            else:
                await _emit(on_event, "chain", "start", {})
                hyps = await chain_stage.run(
                    hyps, config, runtime,
                    runs_root=_runs_root(plugin_slug), run_id=run_id,
                )
                import json as _json_chain
                try:
                    chain_count = len(_json_chain.loads(chains_path.read_text()))
                except Exception:
                    chain_count = 0
                await _emit(on_event, "chain", "done", {
                    "chains": chain_count, "spent": budget.spent,
                })

        # ---- triage ----
        budget.set_stage("triage")
        if _should_load("triage") and triaged_path.exists():
            triaged = TriagedArtifact.from_json_file(str(triaged_path))
            await _emit(on_event, "triage", "skipped", {
                "accepted": len(triaged.accepted), "rejected": len(triaged.rejected),
                "merged": len(triaged.merged),
            })
        elif no_triage:
            from .schemas.hypothesis import Confidence as _Conf
            _rank = {_Conf.HIGH: 0, _Conf.MEDIUM: 1, _Conf.LOW: 2}
            accepted = sorted(hyps.hypotheses, key=lambda h: _rank.get(h.confidence, 99))
            cap = config.max_hypotheses_to_verify
            triaged = TriagedArtifact(
                plugin_slug=hyps.plugin_slug,
                accepted=accepted[:cap], rejected=[], merged=[],
            )
            triaged.to_json_file(str(run_dir / "triaged.json"))
            await _emit(on_event, "triage", "done", {
                "accepted": len(triaged.accepted), "rejected": 0, "merged": 0,
                "spent": budget.spent, "skipped": "no_triage",
            })
        else:
            await _emit(on_event, "triage", "start", {})
            triaged = await triage_stage.run(
                hyps, intake.source_path, config, budget, runtime,
                recon=recon, runs_root=_runs_root(plugin_slug), run_id=run_id,
                apply_scope_filter=apply_scope_filter,
            )
            await _emit(on_event, "triage", "done", {
                "accepted": len(triaged.accepted), "rejected": len(triaged.rejected),
                "merged": len(triaged.merged), "spent": budget.spent,
            })

        # ---- verify ----
        budget.set_stage("verify")
        if _should_load("verify") and findings_path.exists():
            findings = [
                Finding.model_validate_json(line)
                for line in findings_path.read_text().splitlines() if line.strip()
            ]
            await _emit(on_event, "verify", "skipped", {"findings": len(findings)})
        else:
            await _emit(on_event, "verify", "start", {"to_verify": len(triaged.accepted)})
            findings = await verify_stage.run(
                triaged, intake.source_path, config, budget, runtime,
                runs_root=_runs_root(plugin_slug), run_id=run_id,
                developer=developer,
            )
            await _emit(on_event, "verify", "done", {"findings": len(findings), "spent": budget.spent})

        # ---- dedup (cheap; always re-run on resume since output overwrites findings.jsonl) ----
        budget.set_stage("dedup")
        await _emit(on_event, "dedup", "start", {})
        findings = await dedup_stage.run(
            findings, plugin_slug, config, runs_root=_runs_root(plugin_slug), run_id=run_id,
        )
        novel_count = sum(1 for f in findings if f.dedup_status == DedupStatus.NOVEL)
        await _emit(on_event, "dedup", "done", {
            "novel": novel_count, "possibly_known": sum(1 for f in findings if f.dedup_status == DedupStatus.POSSIBLY_KNOWN),
            "known_dupe": sum(1 for f in findings if f.dedup_status == DedupStatus.KNOWN_DUPE),
        })

        await _persist_findings(run_id, plugin_slug, findings)

        # ---- report (per-finding skip: existing report files are preserved) ----
        budget.set_stage("report")
        await _emit(on_event, "report", "start", {})
        report_paths = await report_stage.run(
            findings, plugin_slug, config, budget, runtime,
            runs_root=_runs_root(plugin_slug), run_id=run_id,
            plugin_path=intake.source_path,
            plugin_version=intake.plugin_version,
        )
        await _emit(on_event, "report", "done", {"reports": len(report_paths), "spent": budget.spent})

        status = "complete"

    except BudgetExceededError as e:
        logger.warning("scan %s: budget exceeded — %s", run_id, e)
        await _persist_findings(run_id, plugin_slug, findings)
        status = "budget_exceeded"
        await _emit(on_event, "_pipeline", "budget_exceeded", {"message": str(e)})

    except Exception as e:
        logger.exception("scan %s: failed — %s", run_id, e)
        (run_dir / "error.log").write_text(traceback.format_exc())
        status = "failed"
        await _emit(on_event, "_pipeline", "failed", {"message": str(e)})

    finally:
        try:
            budget.write_cost_report(run_dir)
        except Exception as e:
            logger.warning("scan %s: failed to write cost report: %s", run_id, e)
        await _record_run_finish(run_id, status, budget.spent, len(findings))

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
