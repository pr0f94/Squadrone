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
    "implicit_deserialization": r"(?i:\bupdate_metadata)\s*\(",
    "file_put_contents": (
        r"(?i:\b(?:file_put_contents|fwrite|fputs|fopen|copy|rename|touch|"
        r"symlink|link|extractTo|stream_copy_to_stream)\s*\(|"
        r"->\s*(?:put_contents|move|copy)\s*\()"
    ),
    "move_uploaded_file": (
        r"(?i:\b(?:move_uploaded_file|wp_handle_upload|media_handle_upload|"
        r"wp_handle_sideload|media_handle_sideload|wp_upload_bits)\s*\()"
    ),
    "file_reads": (
        r"(?i:\b(?:file_get_contents|readfile|readgzfile|fpassthru|fread|"
        r"stream_get_contents|gzfile|file|glob|SplFileObject)\s*\(|"
        r"->\s*(?:get_contents|get_contents_array)\s*\()"
    ),
    "unlink": (
        r"(?i:\b(?:unlink|rmdir|wp_delete_file|"
        r"wp_delete_file_from_directory)\s*\()"
    ),
    "include_require": r"(?i:\b(?:include|require)(?:_once)?\b)",
    "eval": r"(?i:\beval\b)",
    "shell_exec": (
        r"(?i:(?:^|[^>:A-Za-z0-9_$])\b(?:shell_exec|exec|system|passthru|"
        r"popen|proc_open|pcntl_exec|expect_popen)\s*\()"
    ),
    "php_backticks": r"`[^`\r\n]{0,2000}`",
    "dynamic_callables": (
        r"(?i:\b(?:call_user_func|call_user_func_array|forward_static_call|"
        r"forward_static_call_array|ReflectionFunction|ReflectionMethod)\s*\()"
    ),
    "command_wrappers": (
        r"(?i:\bnew\s+(?:\\?[A-Za-z_][A-Za-z0-9_]*\\)*Process\s*\(|"
        r"\b(?:Process|WP_CLI)\s*::\s*(?:fromShellCommandline|runcommand|"
        r"launch|launch_self)\s*\()"
    ),
    "archive_extract": (
        r"(?i:\b(?:unzip_file|_unzip_file_ziparchive|_unzip_file_pclzip)\s*\(|"
        r"\bnew\s+(?:\\?[A-Za-z_][A-Za-z0-9_]*\\)*"
        r"(?:PclZip|Archive_Tar|ZipArchive|PharData)\s*\(|"
        r"\$(?:(?:archive|zip|tar|phar)[A-Za-z0-9_]*|"
        r"[A-Za-z_][A-Za-z0-9_]*(?:archive|zip|tar|phar)[A-Za-z0-9_]*)\s*"
        r"->\s*(?:extract|extractByIndex|extractModify|extractTo)\s*\()"
    ),
    "upload_policy": (
        r"(?i:\b(?:upload_mimes|mime_types|ext2type|wp_check_filetype_and_ext|"
        r"wp_handle_(?:upload|sideload)_(?:prefilter|overrides)|"
        r"pre_move_uploaded_file|sanitize_file_name(?:_chars)?|upload_dir)\b)"
    ),
    "persistent_reads": (
        r"(?i:\b(?:get_option|get_site_option|get_transient|get_site_transient|"
        r"get_metadata|get_[A-Za-z_][A-Za-z0-9_]*_meta)\s*\(|"
        r"\$wpdb\s*->\s*(?:get_results|get_row|get_var|get_col)\s*\()"
    ),
    "wp_remote": r"\bwp_remote_(?:get|post|request|head)\s*\(",
    "xml_parsers": r"\b(?:simplexml_load_string|DOMDocument|SimpleXMLElement)\b",
    "current_user_can": r"\bcurrent_user_can\s*\(",
    "nonce_check": r"\b(?:wp_verify_nonce|check_ajax_referer|check_admin_referer)\s*\(",
    "user_input": r"\$_(?:GET|POST|REQUEST|FILES|COOKIE)\b",
}

_PHP_ONLY_RIPGREP_PATTERNS = frozenset(
    {
        "shell_exec",
        "php_backticks",
        "dynamic_callables",
        "command_wrappers",
        "archive_extract",
        "upload_policy",
        "persistent_reads",
    }
)
_PHP_SOURCE_SUFFIXES = frozenset({".php", ".phtml", ".inc"})
_RAW_GREP_HIT_LIMITS = {
    # These navigation-only inventories can be extremely common in large
    # plugins. Deterministic coverage remains authoritative beyond this bound.
    "persistent_reads": 2_000,
    "php_backticks": 1_000,
}

async def _ripgrep(
    pattern_name: str,
    pattern: str,
    plugin_path: Path,
    included_paths: set[str] | None = None,
) -> list[str]:
    command = [
        "rg",
        "-n",
        "--no-heading",
        "--color=never",
        "--max-columns=400",
        "--max-columns-preview",
    ]
    if pattern_name in _PHP_ONLY_RIPGREP_PATTERNS:
        for suffix in sorted(_PHP_SOURCE_SUFFIXES):
            command.extend(("--iglob", f"*{suffix}"))
    command.extend(("-e", pattern, str(plugin_path)))
    try:
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            # Results are streamed so capped inventories do not first buffer
            # an unbounded stdout payload.  Leaving a second PIPE unread while
            # waiting for stdout EOF can deadlock when rg emits enough
            # diagnostics to fill the stderr pipe, so discard diagnostics that
            # this navigation-only inventory never consumes.
            stderr=asyncio.subprocess.DEVNULL,
        )
    except FileNotFoundError:
        logger.warning("ripgrep ('rg') not found on PATH — install with: brew install ripgrep")
        return []
    if proc.stdout is None:
        await proc.wait()
        return []
    base = str(plugin_path) + "/"
    hits: list[str] = []
    limit = _RAW_GREP_HIT_LIMITS.get(pattern_name)
    capped = False
    try:
        while True:
            raw_line = await proc.stdout.readline()
            if not raw_line:
                break
            line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
            line = line.removeprefix(base)
            relative_path = line.split(":", 1)[0]
            if included_paths is not None and relative_path not in included_paths:
                continue
            hits.append(line[:400])
            if limit is None or len(hits) < limit:
                continue
            capped = True
            if proc.returncode is None:
                try:
                    proc.terminate()
                except ProcessLookupError:
                    pass
            break
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except TimeoutError:
            if proc.returncode is None:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
            await proc.wait()
    finally:
        # Cancellation or a decoding/stream error must not orphan rg.
        if proc.returncode is None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            await proc.wait()
    if not capped and proc.returncode not in (0, 1):
        return []
    return hits


def _filter_included(
    pattern_name: str,
    hits: list[str],
    included_paths: set[str],
) -> list[str]:
    filtered = []
    php_only = pattern_name in _PHP_ONLY_RIPGREP_PATTERNS
    limit = _RAW_GREP_HIT_LIMITS.get(pattern_name)
    for hit in hits:
        relative_path = hit.split(":", 1)[0]
        if relative_path not in included_paths:
            continue
        if php_only and Path(relative_path).suffix.lower() not in _PHP_SOURCE_SUFFIXES:
            continue
        filtered.append(hit)
        if limit is not None and len(filtered) >= limit:
            break
    return filtered


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
        *(
            _ripgrep(
                pattern_name,
                pattern,
                plugin_path,
                production_paths,
            )
            for pattern_name, pattern in RIPGREP_PATTERNS.items()
        )
    )
    raw_grep_hits = dict(zip(RIPGREP_PATTERNS.keys(), pattern_results))
    raw_grep_hits = {
        key: _filter_included(key, hits, production_paths)
        for key, hits in raw_grep_hits.items()
    }

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
