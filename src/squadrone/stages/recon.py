"""Recon stage — ripgrep + Surveyor agent."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from ..agents.runtime import AgentRuntime
from ..agents.surveyor import SurveyorAgent
from ..schemas.config import PipelineConfig
from ..schemas.intake import IntakeArtifact
from ..schemas.recon import ReconArtifact
from ..services import recon_helpers
from ..services.artifacts import atomic_write_json
from ..services.coverage import build_coverage_artifact, merge_deterministic_coverage

logger = logging.getLogger(__name__)

# Patterns named after the design doc: "add_action, add_filter, wp_ajax_, $wpdb->, unserialize, etc."
RIPGREP_PATTERNS: dict[str, str] = {
    "add_action": r"add_action\s*\(",
    "add_filter": r"add_filter\s*\(",
    "wp_ajax_": r"wp_ajax_(?:nopriv_)?",
    "register_rest_route": r"register_rest_route\s*\(",
    "add_shortcode": r"add_shortcode\s*\(",
    "wpdb": r"\$wpdb->",
    "unserialize": r"\b(?:maybe_)?unserialize\s*\(",
    "file_put_contents": r"\bfile_put_contents\s*\(",
    "move_uploaded_file": r"\bmove_uploaded_file\s*\(",
    "unlink": r"\bunlink\s*\(",
    "include_require": r"\b(?:include|require)(?:_once)?\s*\(",
    "eval": r"\beval\s*\(",
    "shell_exec": r"\b(?:shell_exec|exec|system|passthru|popen|proc_open)\s*\(",
    "wp_remote": r"\bwp_remote_(?:get|post|request|head)\s*\(",
    "xml_parsers": r"\b(?:simplexml_load_string|DOMDocument|SimpleXMLElement)\b",
    "current_user_can": r"\bcurrent_user_can\s*\(",
    "nonce_check": r"\b(?:wp_verify_nonce|check_ajax_referer|check_admin_referer)\s*\(",
    "user_input": r"\$_(?:GET|POST|REQUEST|FILES|COOKIE)\b",
}

async def _ripgrep(pattern: str, plugin_path: Path) -> list[str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            "rg", "-n", "--no-heading", "--color=never", "-e", pattern, str(plugin_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        logger.warning("ripgrep ('rg') not found on PATH — install with: brew install ripgrep")
        return []
    stdout, _ = await proc.communicate()
    if proc.returncode not in (0, 1):
        return []
    out = stdout.decode("utf-8", errors="replace")
    base = str(plugin_path) + "/"
    hits = []
    for line in out.splitlines():
        if line.startswith(base):
            line = line[len(base):]
        hits.append(line[:400])
    return hits


def _filter_included(hits: list[str], included_paths: set[str]) -> list[str]:
    return [hit for hit in hits if hit.split(":", 1)[0] in included_paths]


async def run(
    intake: IntakeArtifact,
    config: PipelineConfig,
    runtime: AgentRuntime,
    runs_root: str = "runs",
) -> ReconArtifact:
    plugin_path = Path(intake.source_path)

    coverage, static_callbacks, static_sinks = build_coverage_artifact(plugin_path)
    production_paths = set(coverage.production_files)
    logger.info(
        "recon: deterministic coverage found %d production files, %d dependency files, %d review items",
        len(coverage.production_files), len(coverage.dependency_files), len(coverage.items),
    )

    logger.info("recon: ripgrep over %s", plugin_path)
    pattern_results = await asyncio.gather(
        *[_ripgrep(pat, plugin_path) for pat in RIPGREP_PATTERNS.values()]
    )
    raw_grep_hits = dict(zip(RIPGREP_PATTERNS.keys(), pattern_results))
    raw_grep_hits = {key: _filter_included(hits, production_paths) for key, hits in raw_grep_hits.items()}

    file_tree = coverage.production_files + coverage.dependency_files

    logger.info("recon: %d files, %d total grep hits",
                len(file_tree), sum(len(v) for v in raw_grep_hits.values()))

    logger.info("recon: deterministic callback scan found %d registrations", len(static_callbacks))

    surveyor = SurveyorAgent(runtime, model=config.models.surveyor)
    artifact = await surveyor.survey(
        plugin_slug=intake.plugin_slug,
        file_tree=file_tree,
        ripgrep_hits=raw_grep_hits,
        plugin_path=str(plugin_path),
        coverage=coverage,
    )
    artifact.plugin_slug = intake.plugin_slug
    artifact.raw_grep_hits = raw_grep_hits

    merge_deterministic_coverage(
        artifact,
        plugin_path,
        coverage,
        static_callbacks,
        static_sinks,
    )

    from ..schemas.recon import StaticCallEdge, StaticCallback
    artifact.static_callbacks = [StaticCallback.model_validate(item) for item in static_callbacks]
    artifact.static_call_edges = [
        StaticCallEdge.model_validate(item)
        for item in recon_helpers.trace_static_call_edges(plugin_path, static_callbacks)
    ]
    logger.info("recon: deterministic call edges=%d", len(artifact.static_call_edges or []))

    fn_def_map = recon_helpers.build_function_def_map(plugin_path, coverage.production_files)
    for ep in artifact.entry_points:
        if not ep.body_slice:
            ep.body_slice = recon_helpers.extract_body_slice(plugin_path, ep.file, ep.line, max_lines=200)
        if not ep.confidence:
            ep.confidence = recon_helpers.score_confidence(
                handler_function=ep.handler_function,
                body_slice=ep.body_slice,
            )
    artifact.cross_file_callees = {
        ep.handler_function: recon_helpers.trace_callees(ep.body_slice or "", fn_def_map)
        for ep in artifact.entry_points
        if ep.handler_function
    }
    artifact.nonce_emission_sites = recon_helpers.scan_nonce_emissions(
        plugin_path,
        files_to_scan=coverage.production_files,
    )

    out_path = Path(runs_root) / intake.run_id / "recon.json"
    artifact.to_json_file(str(out_path))
    atomic_write_json(out_path.with_name("coverage.json"), coverage.model_dump(mode="json"))
    logger.info("recon: wrote %s (entry_points=%d sinks=%d)",
                out_path, len(artifact.entry_points), len(artifact.sinks))
    return artifact
