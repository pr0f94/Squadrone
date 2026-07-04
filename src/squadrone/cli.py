"""Squadrone CLI entry point."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.prompt import Prompt
from rich.syntax import Syntax
from rich.table import Table

from .services.artifacts import atomic_write_json
from .services.sqlite import connect_sqlite


def _configure_logging(verbose: bool = False) -> None:
    """Configure command logging.

    Normal CLI output is intentionally user-facing and concise; --verbose turns
    the existing INFO log stream back on for debugging long-running scans.
    """
    level = logging.INFO if verbose else logging.WARNING
    if logging.getLogger().handlers:
        logging.getLogger().setLevel(level)
        for handler in logging.getLogger().handlers:
            handler.setLevel(level)
        for noisy in ("httpx", "httpcore", "litellm", "LiteLLM", "aiosqlite", "asyncio"):
            logging.getLogger(noisy).setLevel(logging.WARNING)
        return  # already configured (e.g., when used as a library)
    if "WPVH_LOG_LEVEL" in os.environ:
        level_name = os.environ["WPVH_LOG_LEVEL"].upper()
        level = getattr(logging, level_name, level)
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[
            RichHandler(
                console=console,
                markup=True,
                rich_tracebacks=True,
                show_path=False,
                log_time_format="%H:%M:%S",
            )
        ],
    )
    for noisy in ("httpx", "httpcore", "litellm", "LiteLLM", "aiosqlite", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

app = typer.Typer(help="Squadrone — multi-agent WordPress plugin vulnerability research tool")
runs_app = typer.Typer(help="Manage scan runs")
findings_app = typer.Typer(help="Inspect findings")
manual_app = typer.Typer(help="Inspect and manage the manual review queue")
app.add_typer(runs_app, name="runs")
app.add_typer(findings_app, name="findings")
app.add_typer(manual_app, name="manual")

console = Console()
MANUAL_QUEUE_PATH = Path("cache/findings_for_manual_review.jsonl")


class ScanMode(str, Enum):
    quick = "quick"
    default = "default"
    research = "research"


STAGE_LABELS = {
    "intake": "Intake",
    "recon": "Recon",
    "hypothesis": "Hypothesis",
    "chain": "Chain synthesis",
    "triage": "Triage",
    "manual_queue": "Manual queue",
    "verify": "Verification",
    "dedup": "Deduplication",
    "report": "Reporting",
}

STAGE_DESCRIPTIONS = {
    "intake": "Downloading the plugin from WordPress.org SVN and recording source metadata.",
    "recon": "Mapping reachable entry points, nonce/capability checks, and risky sinks.",
    "hypothesis": "Running specialist agents to look for source-grounded vulnerability candidates.",
    "chain": "Checking whether accepted hypotheses combine into stronger exploit chains.",
    "triage": "Filtering candidates against exploitability and bounty-scope rules.",
    "verify": "Building a WordPress sandbox and attempting PoC reproduction for accepted candidates.",
    "dedup": "Comparing confirmed findings against known vulnerability databases.",
    "report": "Writing private disclosure-ready report drafts for confirmed findings.",
}


def _fmt_money(value: Any) -> str:
    if isinstance(value, int | float):
        return f"${value:.4f}"
    return "-"


def _fmt_int(value: Any) -> str:
    if isinstance(value, int):
        return f"{value:,}"
    return str(value)


def _fmt_elapsed(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, sec = divmod(seconds, 60)
    if minutes < 60:
        return f"{int(minutes)}m {sec:.0f}s"
    hours, minutes = divmod(minutes, 60)
    return f"{int(hours)}h {int(minutes)}m"


def _stage_label(stage: str) -> str:
    return STAGE_LABELS.get(stage, stage.replace("_", " ").title())


def _stage_done_summary(stage: str, info: dict[str, Any]) -> str:
    keys_by_stage = {
        "intake": ("version", "files", "lines"),
        "recon": ("entry_points", "sinks"),
        "hypothesis": ("count",),
        "chain": ("status", "hypothesis_count", "chains", "annotated_hypothesis_count"),
        "triage": ("accepted", "rejected", "merged", "manual_review_candidates"),
        "manual_queue": ("candidates", "manual_queued", "already_queued", "unavailable", "reason"),
        "verify": ("findings", "manual_queued", "already_queued"),
        "dedup": ("novel", "possibly_known", "known_dupe"),
        "report": ("reports",),
    }
    parts: list[str] = []
    for key in keys_by_stage.get(stage, tuple(k for k in info if k != "spent")):
        if key not in info:
            continue
        if key in {"already_queued", "unavailable"} and info[key] == 0:
            continue
        label = key.replace("_", " ")
        value = _fmt_int(info[key])
        parts.append(f"{label} {value}")
    if "spent" in info:
        parts.append(f"spent {_fmt_money(info['spent'])}")
    return " · ".join(parts)


def _print_scan_header(
    plugin_slug: str,
    config: str,
    budget: float | None,
    version: str | None,
    resume: str | None,
    verbose: bool,
    mode: ScanMode,
) -> None:
    lines = [
        f"[b]Plugin[/b]        {plugin_slug}",
        f"[b]Scan mode[/b]     {mode.value}",
        f"[b]Config[/b]        {config}",
        f"[b]Budget[/b]        {f'${budget:.2f}' if budget is not None else 'from config'}",
        f"[b]Version[/b]       {version or 'latest'}",
        f"[b]Run[/b]           {'resume ' + resume if resume else 'new scan'}",
        f"[b]Verbosity[/b]     {'verbose logs enabled' if verbose else 'concise progress'}",
    ]
    console.print(Panel("\n".join(lines), title="Squadrone Scan", border_style="cyan"))


def _print_artifacts(result: Any) -> None:
    run_dir = _run_dir(result.run_id)
    table = Table(title="Artifacts", show_header=False)
    table.add_column("name", style="bold")
    table.add_column("path")
    table.add_row("run directory", str(run_dir))
    for report_path in result.report_paths:
        table.add_row("report", report_path)
    if not result.report_paths:
        table.add_row("reports", "none")
    console.print(table)


def _print_scan_result(result: Any) -> None:
    table = Table(title=f"Scan summary — {result.plugin_slug}")
    table.add_column("field")
    table.add_column("value")
    table.add_row("run_id", result.run_id)
    table.add_row("status", result.status)
    table.add_row("findings", str(result.finding_count))
    table.add_row("novel", str(result.novel_count))
    table.add_row("cost", f"${result.cost_usd:.4f}")
    table.add_row("cache hit rate", f"{result.cache_hit_rate * 100:.1f}%")
    table.add_row("duration", f"{result.duration_seconds:.1f}s")
    table.add_row("reports", str(len(result.report_paths)))
    console.print(table)
    _print_artifacts(result)

    # Per-stage cost breakdown, sourced from the cost_per_stage.tsv the orchestrator
    # writes at scan finish. Skipped silently if the file is missing (e.g. early crash).
    stage_tsv = _run_dir(result.run_id) / "cost_per_stage.tsv"
    if stage_tsv.exists():
        stage_table = Table(title="Cost per stage")
        for col in ("stage", "calls", "cost", "input", "output", "cache_read", "hit_rate"):
            stage_table.add_column(col)
        for line in stage_tsv.read_text().splitlines()[1:]:
            cols = line.split("\t")
            if len(cols) >= 8:
                stage, calls, cost, inp, out, cache_read, _cache_write, hit = cols[:8]
                stage_table.add_row(
                    stage, calls, f"${float(cost):.4f}",
                    inp, out, cache_read, f"{float(hit) * 100:.1f}%",
                )
        console.print(stage_table)


async def _run_scan_cli(
    *,
    plugin_slug: str,
    mode: ScanMode,
    config: str,
    budget: float | None,
    version: str | None,
    no_triage: bool,
    no_verify: bool,
    ignore_scope: bool,
    resume: str | None,
    resume_from: str | None,
    chain: bool | None,
    cross_file_taint: bool | None,
    diff_baseline: str | None,
    strict_quality: bool | None,
    triage_votes: int | None,
    verbose: bool,
    batch_prefix: str | None = None,
) -> Any:
    from .orchestrator import run_scan

    if mode is ScanMode.quick:
        no_verify = True
        chain = False if chain is None else chain
        cross_file_taint = False if cross_file_taint is None else cross_file_taint
        strict_quality = True if strict_quality is None else strict_quality
        triage_votes = 1 if triage_votes is None else triage_votes
    elif mode is ScanMode.research:
        chain = True if chain is None else chain
        cross_file_taint = True if cross_file_taint is None else cross_file_taint
        strict_quality = True if strict_quality is None else strict_quality
        triage_votes = 3 if triage_votes is None else triage_votes
    else:
        chain = False if chain is None else chain
        cross_file_taint = False if cross_file_taint is None else cross_file_taint

    _print_scan_header(plugin_slug, config, budget, version, resume, verbose, mode)

    stage_started_at: dict[str, float] = {}
    run_id_seen: str | None = resume
    prefix = f"[dim]{batch_prefix}[/] " if batch_prefix else ""

    def on_event(stage: str, status: str, info: dict) -> None:
        nonlocal run_id_seen
        label = _stage_label(stage)
        if status == "start":
            stage_started_at[stage] = time.monotonic()
            if info.get("run_id"):
                run_id_seen = str(info["run_id"])
            description = STAGE_DESCRIPTIONS.get(stage, "Running this pipeline stage.")
            detail_parts = []
            if info.get("run_id"):
                detail_parts.append(f"run {info['run_id']}")
            if info.get("version"):
                detail_parts.append(f"version {info['version']}")
            detail = f" [dim]({' · '.join(detail_parts)})[/]" if detail_parts else ""
            console.print(f"\n{prefix}[bold cyan]▶ {label}[/]{detail}")
            console.print(f"[dim]{description}[/]")
            if verbose and run_id_seen:
                console.print(f"[dim]Artifacts: plugins/{plugin_slug}/runs/{run_id_seen}/[/]")
        elif status == "done":
            elapsed = time.monotonic() - stage_started_at.get(stage, time.monotonic())
            summary = _stage_done_summary(stage, info)
            suffix = f" · {summary}" if summary else ""
            console.print(f"{prefix}[green]✓ {label} complete[/] [dim]in {_fmt_elapsed(elapsed)}[/]{suffix}")
        elif status == "skipped":
            extras = _stage_done_summary(stage, info)
            suffix = f" · {extras}" if extras else ""
            if info.get("reason") == "no_verify":
                console.print(f"{prefix}[yellow]↷ {label} skipped by --no-verify{suffix}[/]")
            else:
                console.print(f"{prefix}[dim]↺ {label} loaded from existing artifacts{suffix}[/]")
        elif status == "budget_exceeded":
            console.print(f"{prefix}[yellow]⚠ budget exceeded — {info.get('message','')}[/]")
        elif status == "failed":
            console.print(f"{prefix}[red]✗ pipeline failed — {info.get('message','')}[/]")

    result = await run_scan(
        plugin_slug=plugin_slug,
        config_path=config,
        budget_override=budget,
        on_event=on_event,
        version=version,
        no_triage=no_triage,
        no_verify=no_verify,
        resume_run_id=resume,
        resume_from=resume_from,
        apply_scope_filter=not ignore_scope,
        enable_chain=chain,
        enable_cross_file_taint=cross_file_taint,
        diff_baseline=diff_baseline,
        strict_quality=strict_quality,
        triage_votes=triage_votes,
    )

    _print_scan_result(result)
    return result


def _run_dir(run_id: str) -> Path:
    """Resolve a run_id to its directory under plugins/<slug>/runs/<run_id>.

    Globs the filesystem for plugins/*/runs/<run_id>. Raises FileNotFoundError
    if no match exists.
    """
    matches = list(Path("plugins").glob(f"*/runs/{run_id}"))
    if matches:
        return matches[0]
    raise FileNotFoundError(f"plugins/*/runs/{run_id} not found")


def _load_manual_queue() -> list[dict[str, Any]]:
    if not MANUAL_QUEUE_PATH.exists():
        return []

    entries: list[dict[str, Any]] = []
    for line_no, line in enumerate(MANUAL_QUEUE_PATH.read_text().splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            raise typer.BadParameter(f"manual queue has invalid JSON on line {line_no}: {exc}") from exc
        entry["_line_no"] = line_no
        entries.append(entry)
    return entries


def _manual_plugin_slug(entry: dict[str, Any]) -> str:
    if entry.get("plugin_slug"):
        return str(entry["plugin_slug"])
    run_dir = str(entry.get("run_dir", ""))
    parts = Path(run_dir).parts
    if len(parts) >= 2 and parts[0] == "plugins":
        return parts[1]
    return "-"


def _manual_hypothesis_id(entry: dict[str, Any]) -> str:
    return str(entry.get("hypothesis_id") or entry.get("hypothesis", {}).get("id") or "-")


def _manual_role(entry: dict[str, Any]) -> str:
    notes = entry.get("verifier_notes")
    if isinstance(notes, dict):
        role = notes.get("attacker_role")
        if role:
            return str(role)
    hyp = entry.get("hypothesis")
    if isinstance(hyp, dict):
        evidence = hyp.get("evidence_summary")
        if isinstance(evidence, dict) and evidence.get("attacker_role"):
            return str(evidence["attacker_role"])
    return "-"


def _manual_impact(entry: dict[str, Any]) -> str:
    hyp = entry.get("hypothesis")
    if isinstance(hyp, dict):
        impact = hyp.get("impact") or hyp.get("reasoning")
        if impact:
            text = " ".join(str(impact).split())
            return text[:120] + ("..." if len(text) > 120 else "")
    return "-"


def _manual_bug_class(entry: dict[str, Any]) -> str:
    bug_class = entry.get("bug_class")
    if bug_class:
        return str(bug_class)
    hyp = entry.get("hypothesis")
    if isinstance(hyp, dict) and hyp.get("bug_class"):
        return str(hyp["bug_class"])
    return "-"


def _write_manual_queue(entries: list[dict[str, Any]]) -> None:
    if not entries:
        if MANUAL_QUEUE_PATH.exists():
            MANUAL_QUEUE_PATH.unlink()
        return
    MANUAL_QUEUE_PATH.parent.mkdir(parents=True, exist_ok=True)
    clean_entries = []
    for entry in entries:
        cleaned = dict(entry)
        cleaned.pop("_line_no", None)
        clean_entries.append(cleaned)
    MANUAL_QUEUE_PATH.write_text("\n".join(json.dumps(e, sort_keys=True) for e in clean_entries) + "\n")


@manual_app.command("list")
def manual_list() -> None:
    """List findings waiting for manual review."""
    _configure_logging()
    entries = _load_manual_queue()
    table = Table(title=f"Manual review queue — {len(entries)} queued")
    table.add_column("#", justify="right")
    table.add_column("plugin")
    table.add_column("hypothesis")
    table.add_column("class")
    table.add_column("role")
    table.add_column("reason")
    table.add_column("impact")

    for idx, entry in enumerate(entries, start=1):
        table.add_row(
            str(idx),
            _manual_plugin_slug(entry),
            _manual_hypothesis_id(entry),
            _manual_bug_class(entry),
            _manual_role(entry),
            str(entry.get("reason") or "-"),
            _manual_impact(entry),
        )

    console.print(table)
    if entries:
        console.print(f"[dim]Queue file: {MANUAL_QUEUE_PATH}[/]")


@manual_app.command("remove")
def manual_remove(
    selector: str = typer.Argument(
        ...,
        help="Queue row number, hypothesis id, or plugin:hypothesis id",
    ),
) -> None:
    """Remove one manual-review queue entry."""
    _configure_logging()
    entries = _load_manual_queue()
    if not entries:
        console.print("[yellow]Manual review queue is empty.[/]")
        return

    def matches(idx: int, entry: dict[str, Any]) -> bool:
        hyp_id = _manual_hypothesis_id(entry)
        plugin = _manual_plugin_slug(entry)
        return selector == str(idx) or selector == hyp_id or selector == f"{plugin}:{hyp_id}"

    remaining = [entry for idx, entry in enumerate(entries, start=1) if not matches(idx, entry)]
    removed = len(entries) - len(remaining)
    if removed == 0:
        console.print(f"[red]No manual queue entry matched {selector!r}.[/]")
        raise typer.Exit(code=1)

    _write_manual_queue(remaining)
    console.print(f"[green]Removed {removed} manual queue entr{'y' if removed == 1 else 'ies'}.[/]")
    console.print(f"[dim]{len(remaining)} remaining.[/]")


@manual_app.command("clear")
def manual_clear() -> None:
    """Remove every active manual-review queue entry."""
    _configure_logging()
    count = len(_load_manual_queue())
    _write_manual_queue([])
    console.print(f"[green]Cleared manual review queue.[/] [dim]removed {count} entr{'y' if count == 1 else 'ies'}[/]")


@app.command()
def scan(
    plugin_slug: str = typer.Argument(..., help="WordPress plugin slug"),
    mode: ScanMode = typer.Option(
        ScanMode.default,
        "--mode",
        "-m",
        help=(
            "Scan preset: quick is static/manual-review only, default verifies likely findings, "
            "research enables deeper review and stricter triage."
        ),
        case_sensitive=False,
    ),
    config: str = typer.Option("pipelines/default.yaml", "--config", help="Pipeline config YAML path"),
    budget: float | None = typer.Option(None, "--budget", help="Override cost ceiling (USD)"),
    version: str | None = typer.Option(None, "--version", help="Pin a specific plugin version (e.g. for re-scanning a historical release). Defaults to the latest version on wordpress.org."),
    no_triage: bool = typer.Option(
        False,
        "--no-triage",
        help="Advanced: skip Critic; pipe hypotheses straight to verify.",
        rich_help_panel="Advanced",
    ),
    no_verify: bool = typer.Option(
        False,
        "--no-verify",
        help="Skip sandbox verification; queue triage-accepted hypotheses for manual review instead of creating findings.",
    ),
    ignore_scope: bool = typer.Option(
        False, "--ignore-scope",
        help="Disable Wordfence/Patchstack scope filtering in triage; verify everything technically valid.",
    ),
    resume: str | None = typer.Option(
        None, "--resume",
        help="Resume an existing run by ID — auto-detects the latest completed stage from disk artifacts and re-runs from the next stage onwards",
    ),
    resume_from: str | None = typer.Option(
        None, "--from",
        help="Force re-run from a specific stage (requires --resume). One of: intake, recon, hypothesis, chain, triage, verify, dedup, report.",
    ),
    chain: bool | None = typer.Option(
        None, "--chain/--no-chain",
        help="Advanced: override exploit-chain synthesis for this run.",
        rich_help_panel="Advanced",
    ),
    cross_file_taint: bool | None = typer.Option(
        None, "--cross-file-taint/--no-cross-file-taint",
        help="Advanced: override the larger cross-file stored-XSS specialist.",
        rich_help_panel="Advanced",
    ),
    diff_baseline: str | None = typer.Option(
        None, "--diff",
        help="Advanced: compare the scanned version against this prior WordPress.org release.",
        rich_help_panel="Advanced",
    ),
    strict_quality: bool | None = typer.Option(
        None,
        "--strict-quality/--no-strict-quality",
        help="Advanced: override quality gates from the selected mode/config.",
        rich_help_panel="Advanced",
    ),
    triage_votes: int | None = typer.Option(
        None,
        "--triage-votes",
        min=1,
        help="Advanced: run N independent Critic triage votes. Overrides mode/config.",
        rich_help_panel="Advanced",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v",
        help="Show detailed INFO logs from stages, agents, sandbox setup, and LLM calls. Default output stays concise.",
    ),
) -> None:
    """Scan a single plugin for vulnerabilities."""
    _configure_logging(verbose=verbose)
    result = asyncio.run(_run_scan_cli(
        plugin_slug=plugin_slug,
        mode=mode,
        config=config,
        budget=budget,
        version=version,
        no_triage=no_triage,
        no_verify=no_verify,
        ignore_scope=ignore_scope,
        resume=resume,
        resume_from=resume_from,
        chain=chain,
        cross_file_taint=cross_file_taint,
        diff_baseline=diff_baseline,
        strict_quality=strict_quality,
        triage_votes=triage_votes,
        verbose=verbose,
    ))

    if result.status != "complete":
        console.print(f"[yellow]Run ended with status [b]{result.status}[/b]; "
                      f"inspect plugins/{result.plugin_slug}/runs/{result.run_id}/ for details.[/]")
        raise typer.Exit(code=1)


def _read_plugins_file(path: str) -> list[str]:
    plugins_path = Path(path)
    try:
        lines = plugins_path.read_text().splitlines()
    except FileNotFoundError as exc:
        raise typer.BadParameter(f"plugins file not found: {path}") from exc

    slugs: list[str] = []
    for line in lines:
        slug = line.strip()
        if not slug or slug.startswith("#"):
            continue
        slugs.append(slug)
    if not slugs:
        raise typer.BadParameter(f"plugins file contains no plugin slugs: {path}")
    return slugs


@app.command("scan-batch")
def scan_batch(
    plugins_file: str = typer.Argument(..., help="File containing plugin slugs (one per line)"),
    mode: ScanMode = typer.Option(
        ScanMode.default,
        "--mode",
        "-m",
        help=(
            "Scan preset: quick is static/manual-review only, default verifies likely findings, "
            "research enables deeper review and stricter triage."
        ),
        case_sensitive=False,
    ),
    concurrency: int = typer.Option(1, "--concurrency", min=1, help="Number of plugins to scan in parallel"),
    config: str = typer.Option("pipelines/default.yaml", "--config", help="Pipeline config YAML path"),
    budget: float | None = typer.Option(None, "--budget", help="Per-plugin cost ceiling override (USD)"),
    version: str | None = typer.Option(None, "--version", help="Pin the same plugin version for every slug in the batch"),
    no_triage: bool = typer.Option(
        False,
        "--no-triage",
        help="Advanced: skip Critic; pipe hypotheses straight to verify.",
        rich_help_panel="Advanced",
    ),
    no_verify: bool = typer.Option(
        False,
        "--no-verify",
        help="Skip sandbox verification; queue triage-accepted hypotheses for manual review instead of creating findings",
    ),
    ignore_scope: bool = typer.Option(
        False, "--ignore-scope",
        help="Disable Wordfence/Patchstack scope filtering in triage; verify everything that's technically a bug",
    ),
    chain: bool | None = typer.Option(
        None, "--chain/--no-chain",
        help="Advanced: override exploit-chain synthesis for this batch.",
        rich_help_panel="Advanced",
    ),
    cross_file_taint: bool | None = typer.Option(
        None, "--cross-file-taint/--no-cross-file-taint",
        help="Advanced: override the larger cross-file stored-XSS specialist.",
        rich_help_panel="Advanced",
    ),
    diff_baseline: str | None = typer.Option(
        None, "--diff",
        help="Advanced: compare the scanned version against this prior WordPress.org release.",
        rich_help_panel="Advanced",
    ),
    strict_quality: bool | None = typer.Option(
        None,
        "--strict-quality/--no-strict-quality",
        help="Advanced: override quality gates from the selected mode/config.",
        rich_help_panel="Advanced",
    ),
    triage_votes: int | None = typer.Option(
        None,
        "--triage-votes",
        min=1,
        help="Advanced: run N independent Critic triage votes per plugin. Overrides mode/config.",
        rich_help_panel="Advanced",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v",
        help="Show detailed INFO logs from stages, agents, sandbox setup, and LLM calls. Default output stays concise.",
    ),
) -> None:
    """Scan multiple plugins from a newline-delimited file."""
    _configure_logging(verbose=verbose)
    plugin_slugs = _read_plugins_file(plugins_file)
    console.print(Panel(
        "\n".join([
            f"[b]Plugins[/b]      {len(plugin_slugs)}",
            f"[b]Scan mode[/b]    {mode.value}",
            f"[b]Config[/b]       {config}",
            f"[b]Budget[/b]       {f'${budget:.2f} per plugin' if budget is not None else 'from config'}",
            f"[b]Concurrency[/b]  {concurrency}",
            f"[b]Version[/b]      {version or 'latest'}",
        ]),
        title="Squadrone Batch Scan",
        border_style="cyan",
    ))

    async def run_batch() -> list[tuple[str, str, str | None]]:
        semaphore = asyncio.Semaphore(concurrency)
        outcomes: list[tuple[str, str, str | None]] = []

        async def run_one(index: int, slug: str) -> None:
            async with semaphore:
                prefix = f"[{index}/{len(plugin_slugs)} {slug}]"
                try:
                    result = await _run_scan_cli(
                        plugin_slug=slug,
                        mode=mode,
                        config=config,
                        budget=budget,
                        version=version,
                        no_triage=no_triage,
                        no_verify=no_verify,
                        ignore_scope=ignore_scope,
                        resume=None,
                        resume_from=None,
                        chain=chain,
                        cross_file_taint=cross_file_taint,
                        diff_baseline=diff_baseline,
                        strict_quality=strict_quality,
                        triage_votes=triage_votes,
                        verbose=verbose,
                        batch_prefix=prefix,
                    )
                except Exception as exc:
                    outcomes.append((slug, "failed", str(exc)))
                    console.print(f"[red]{prefix} failed — {exc}[/]")
                    return

                outcomes.append((slug, result.status, result.run_id))
                if result.status != "complete":
                    console.print(
                        f"[yellow]{prefix} ended with status [b]{result.status}[/b]; "
                        f"inspect plugins/{result.plugin_slug}/runs/{result.run_id}/ for details.[/]"
                    )

        await asyncio.gather(*(run_one(index, slug) for index, slug in enumerate(plugin_slugs, start=1)))
        return outcomes

    outcomes = asyncio.run(run_batch())
    summary = Table(title="Batch summary")
    summary.add_column("plugin")
    summary.add_column("status")
    summary.add_column("run/error")
    failed = False
    for slug, status, detail in outcomes:
        if status != "complete":
            failed = True
        summary.add_row(slug, status, detail or "")
    console.print(summary)

    if failed:
        raise typer.Exit(code=1)


@app.command(rich_help_panel="Advanced")
def benchmark(
    corpus: str = typer.Argument(..., help="Path to benchmark corpus JSON"),
    split: str = typer.Option("train", "--split", help="Corpus split to evaluate (e.g. train, test, holdout)"),
    config: str = typer.Option("pipelines/default.yaml", "--config", help="Pipeline config YAML path"),
    budget: float | None = typer.Option(None, "--budget", help="Per-scan budget override (USD)"),
    no_triage: bool = typer.Option(False, "--no-triage", help="Skip Critic per scan"),
    ignore_scope: bool = typer.Option(
        False, "--ignore-scope",
        help="Disable Wordfence/Patchstack scope filtering in triage; verify everything that's technically a bug",
    ),
) -> None:
    """Run the benchmark harness over a corpus."""
    _configure_logging()
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "benchmarks"))
    from runner import run_benchmark  # type: ignore

    result = asyncio.run(run_benchmark(
        corpus_path=corpus, split=split, config_path=config,
        budget_override=budget, no_triage=no_triage,
        apply_scope_filter=not ignore_scope,
    ))

    table = Table(title=f"Benchmark — {corpus} (split={split})")
    table.add_column("metric")
    table.add_column("value")
    table.add_row("entries", str(result.entry_count))
    table.add_row("recall@1", f"{result.recall_at_1:.2%}")
    table.add_row("recall@3", f"{result.recall_at_3:.2%}")
    table.add_row("recall@10", f"{result.recall_at_10:.2%}")
    table.add_row("precision", f"{result.precision:.2%}")
    table.add_row("PoC success rate", f"{result.poc_success_rate:.2%}")
    table.add_row("cost / finding", f"${result.cost_per_finding:.4f}")
    table.add_row("total cost", f"${result.total_cost_usd:.4f}")
    console.print(table)

    per_bc = Table(title="Per bug class")
    per_bc.add_column("CWE")
    per_bc.add_column("count")
    per_bc.add_column("recall")
    for bc, v in result.per_bug_class.items():
        per_bc.add_row(bc, str(v["count"]), f"{v['recall']:.2%}")
    console.print(per_bc)

    detail = Table(title="Per entry")
    detail.add_column("CVE")
    detail.add_column("slug")
    detail.add_column("status")
    detail.add_column("matched")
    detail.add_column("via")
    detail.add_column("cost")
    for e in result.entries:
        detail.add_row(
            e.cve_id, e.slug, e.status,
            str(e.matched_at_rank) if e.matched_at_rank else "—",
            e.matched_via or "—",
            f"${e.cost_usd:.4f}",
        )
    console.print(detail)


@app.command(rich_help_panel="Advanced")
def review(run_id: str = typer.Argument(..., help="Run ID to review")) -> None:
    """Interactively review findings from a completed run."""
    from .schemas.finding import Finding

    findings_path = _run_dir(run_id) / "findings.jsonl"
    if not findings_path.exists():
        console.print(f"[red]No findings.jsonl at {findings_path}[/]")
        raise typer.Exit(code=1)

    findings: list[Finding] = []
    for line in findings_path.read_text().splitlines():
        line = line.strip()
        if line:
            findings.append(Finding.model_validate_json(line))

    if not findings:
        console.print(f"[yellow]No findings in {findings_path}[/]")
        return

    review_path = _run_dir(run_id) / "review.json"
    decisions: dict[str, dict] = {}
    if review_path.exists():
        decisions = json.loads(review_path.read_text())

    idx = 0
    while True:
        f = findings[idx]
        prior = decisions.get(f.id, {})
        console.clear()
        console.rule(f"[b]Finding {idx+1}/{len(findings)} — {f.id}[/b]")
        console.print(f"[b]bug_class:[/b] {f.hypothesis.bug_class.name} ({f.hypothesis.bug_class.value})")
        console.print(f"[b]confidence:[/b] {f.hypothesis.confidence.value}")
        console.print(f"[b]entry:[/b] {f.hypothesis.entry_point}  [b]sink:[/b] {f.hypothesis.sink}")
        console.print(f"[b]file:[/b] {f.hypothesis.file}:{f.hypothesis.line}")
        console.print(f"[b]reasoning:[/b] {f.hypothesis.reasoning}")
        console.print(f"[b]preconditions:[/b] {f.hypothesis.preconditions}")
        console.print(f"[b]poc_status:[/b] {f.poc_status.value}  [b]dedup:[/b] {f.dedup_status.value}")
        console.print(f"[b]evidence:[/b] {f.evidence}")
        if f.dedup_matches:
            console.print(f"[b]dedup_matches ({len(f.dedup_matches)}):[/b]")
            for m in f.dedup_matches[:5]:
                console.print(f"  - {m.get('source','?')} {m.get('cve_id','?')} {str(m.get('title',''))[:80]}")
        if Path(f.poc_script_path).exists():
            console.print(Panel(
                Syntax(Path(f.poc_script_path).read_text()[:4000], "python", line_numbers=True),
                title=f"PoC: {f.poc_script_path}",
            ))
        # Reports are now per-program (report_<id>_<program>.md); show all that exist.
        for report_path in sorted((_run_dir(run_id)).glob(f"report_{f.id}*.md")):
            console.print(Panel(report_path.read_text()[:2000], title=f"Draft report: {report_path}"))

        if prior:
            console.print(f"\n[dim]Prior decision: {prior.get('decision')} @ {prior.get('at','')}[/]")

        choice = Prompt.ask(
            "\n[n]ext / [p]rev / [v]alid / [i]nvalid / needs-[m]ore / [q]uit",
            choices=["n", "p", "v", "i", "m", "q"], default="n",
        )
        if choice == "q":
            break
        if choice in ("v", "i", "m"):
            decisions[f.id] = {
                "decision": {"v": "valid", "i": "invalid", "m": "needs_more_investigation"}[choice],
                "at": datetime.now(timezone.utc).isoformat(),
            }
            atomic_write_json(review_path, decisions)
            console.print(f"[green]saved {decisions[f.id]['decision']}[/]")
            idx = min(idx + 1, len(findings) - 1)
        elif choice == "n":
            idx = min(idx + 1, len(findings) - 1)
        elif choice == "p":
            idx = max(idx - 1, 0)

    console.print(f"\nDecisions saved to {review_path}")


class DiscloseTarget(str, Enum):
    wordfence = "wordfence"
    patchstack = "patchstack"
    mitre = "mitre"
    github = "github"
    direct = "direct"


@app.command(rich_help_panel="Advanced")
def disclose(
    finding_id: str = typer.Argument(...),
    to: DiscloseTarget = typer.Option(..., "--to", help="Submission target", case_sensitive=False),
    notes: str | None = typer.Option(None, "--notes", help="Free-text note recorded with the disclosure (e.g. submission timestamp, ticket ID, reviewer feedback)"),
    date: str | None = typer.Option(None, "--date", help="Submission date (YYYY-MM-DD or ISO 8601). Defaults to now. Use for backfilling historical submissions."),
) -> None:
    """Mark a finding as disclosed."""
    from .orchestrator import DB_PATH

    if date is not None:
        try:
            submitted_at = datetime.fromisoformat(date).isoformat()
        except ValueError:
            console.print(f"[red]Invalid --date {date!r}: expected YYYY-MM-DD or ISO 8601.[/]")
            raise typer.Exit(code=2)
    else:
        submitted_at = datetime.now(timezone.utc).isoformat()

    async def _run():
        async with connect_sqlite(DB_PATH) as db:
            async with db.execute(
                "SELECT bug_class, cwe, confidence, poc_status, dedup_status, plugin_slug, run_id "
                "FROM findings WHERE finding_id=?", (finding_id,)
            ) as cur:
                row = await cur.fetchone()
            if row is None:
                console.print(f"[red]No finding {finding_id} in db.[/]")
                raise typer.Exit(code=1)
            await db.execute(
                "INSERT OR REPLACE INTO disclosures(finding_id, submitted_to, submitted_at, status, notes) "
                "VALUES (?,?,?,?,?)",
                (finding_id, to.value, submitted_at, "submitted", notes),
            )
            await db.commit()
            return row

    row = asyncio.run(_run())
    table = Table(title=f"Disclosed {finding_id}")
    table.add_column("field")
    table.add_column("value")
    table.add_row("submitted_to", to.value)
    table.add_row("submitted_at", submitted_at)
    table.add_row("notes", notes or "—")
    table.add_row("plugin_slug", row[5])
    table.add_row("run_id", row[6])
    table.add_row("bug_class", f"{row[0]} ({row[1]})")
    table.add_row("confidence", row[2])
    table.add_row("poc_status", row[3])
    table.add_row("dedup_status", row[4])
    console.print(table)


@runs_app.command("list")
def runs_list() -> None:
    """List scan runs."""
    from .orchestrator import DB_PATH

    async def _query():
        async with connect_sqlite(DB_PATH) as db:
            async with db.execute(
                "SELECT run_id, plugin_slug, status, finding_count, cost_usd, started_at "
                "FROM runs ORDER BY started_at DESC"
            ) as cur:
                return [r async for r in cur]

    rows = asyncio.run(_query())
    if not rows:
        console.print("[yellow]No runs found.[/]")
        return

    table = Table(title="Scan runs")
    for col in ("run_id", "plugin_slug", "status", "findings", "cost", "started_at"):
        table.add_column(col)
    for r in rows:
        table.add_row(r[0], r[1], r[2], str(r[3]), f"${(r[4] or 0):.4f}", r[5] or "—")
    console.print(table)


@findings_app.command("show")
def findings_show(finding_id: str = typer.Argument(...)) -> None:
    """Show full detail for a finding."""
    from .orchestrator import DB_PATH
    from .schemas.finding import Finding

    async def _query():
        async with connect_sqlite(DB_PATH) as db:
            async with db.execute(
                "SELECT run_id, plugin_slug FROM findings WHERE finding_id=?", (finding_id,)
            ) as cur:
                return await cur.fetchone()

    row = asyncio.run(_query())
    if not row:
        console.print(f"[red]No finding {finding_id} in db.[/]")
        raise typer.Exit(code=1)
    run_id, plugin_slug = row

    findings_path = _run_dir(run_id) / "findings.jsonl"
    found: Finding | None = None
    for line in findings_path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        f = Finding.model_validate_json(line)
        if f.id == finding_id:
            found = f
            break
    if found is None:
        console.print(f"[red]Finding {finding_id} not found in {findings_path}[/]")
        raise typer.Exit(code=1)

    console.rule(f"[b]Finding {finding_id} — {plugin_slug} (run {run_id})[/]")
    console.print(found.model_dump_json(indent=2))
    console.print(f"\n[b]PoC script:[/b] {found.poc_script_path}")
    report_paths = sorted((_run_dir(run_id)).glob(f"report_{found.id}*.md"))
    if report_paths:
        for p in report_paths:
            console.print(f"[b]Report:[/b] {p}")
    else:
        console.print(f"[b]Report:[/b] (none — no per-program reports written for {found.id})")


if __name__ == "__main__":
    app()
