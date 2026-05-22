"""Recon stage — ripgrep + Surveyor agent."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from ..agents.entry_point_validator import EntryPointValidator
from ..agents.runtime import AgentRuntime
from ..agents.surveyor import SurveyorAgent
from ..schemas.config import PipelineConfig
from ..schemas.intake import IntakeArtifact
from ..schemas.recon import ReconArtifact
from ..services import recon_helpers

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

# #7: appended to the surveyor system prompt when negative_pattern_reference toggle is on
NEGATIVE_PATTERN_REFERENCE = """

NEGATIVE EXAMPLES — these patterns are SAFE and should NOT be flagged as sinks:
- `$wpdb->prepare(...)` with placeholders is correctly parameterised; flag the QUERY only if the prepared
  string is later re-concatenated unsafely.
- `esc_url(...)` / `esc_attr(...)` / `esc_html(...)` / `esc_js(...)` outputs are sanitised. Flag only if
  the surrounding context defeats the escape (e.g. attribute with mismatched delimiter).
- `wp_kses(...)` / `wp_kses_post(...)` strip script tags; only flag if the chain allows
  `target="_blank" rel="opener"` reverse-tabnabbing.
- `sanitize_text_field(...)` / `sanitize_key(...)` / `absint(...)` are safe sanitisers for their domains.
- `current_user_can(...)` / `User::Access(...)` / `wp_verify_nonce(...)` / `check_ajax_referer(...)` are
  GUARDS, not sinks — note their presence per entry point but don't list them as sinks.
"""


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


def _file_tree(plugin_path: Path) -> list[str]:
    files: list[str] = []
    for p in sorted(plugin_path.rglob("*")):
        if p.is_file():
            files.append(str(p.relative_to(plugin_path)))
    return files


def _filter_excluded(hits: list[str], excluded_paths: set[str]) -> list[str]:
    """Drop any 'file:line:text' hit whose file portion is in excluded_paths."""
    out = []
    for h in hits:
        first_colon = h.find(":")
        if first_colon == -1:
            out.append(h)
            continue
        f = h[:first_colon]
        if f not in excluded_paths:
            out.append(h)
    return out


async def run(
    intake: IntakeArtifact,
    config: PipelineConfig,
    runtime: AgentRuntime,
    runs_root: str = "runs",
) -> ReconArtifact:
    plugin_path = Path(intake.source_path)
    cfg = config.recon

    # #8: cache check (BEFORE any work)
    cfg_dict = cfg.model_dump()
    ckey = recon_helpers.cache_key(intake.plugin_slug, intake.plugin_version, cfg_dict) if cfg.cache_enabled else None
    if ckey:
        cached = recon_helpers.load_cached_recon(ckey)
        if cached:
            logger.info("recon: cache hit %s — reusing", ckey)
            artifact = ReconArtifact.model_validate(cached)
            out_path = Path(runs_root) / intake.run_id / "recon.json"
            artifact.to_json_file(str(out_path))
            return artifact

    # #4: vendor/tests/lang exclusion (depends on intake.file_classification)
    excluded_paths: set[str] = set()
    excluded_buckets: list[str] = []
    if cfg.exclude_vendor_tests_lang and intake.file_classification:
        for bucket in ("vendor", "tests", "lang"):
            files = intake.file_classification.get(bucket, [])
            if files:
                excluded_paths.update(files)
                excluded_buckets.append(bucket)
        if excluded_paths:
            logger.info("recon: excluding %d files in %s", len(excluded_paths), excluded_buckets)

    logger.info("recon: ripgrep over %s", plugin_path)
    pattern_results = await asyncio.gather(
        *[_ripgrep(pat, plugin_path) for pat in RIPGREP_PATTERNS.values()]
    )
    raw_grep_hits = dict(zip(RIPGREP_PATTERNS.keys(), pattern_results))
    if excluded_paths:
        raw_grep_hits = {k: _filter_excluded(v, excluded_paths) for k, v in raw_grep_hits.items()}

    file_tree = _file_tree(plugin_path)
    if excluded_paths:
        file_tree = [f for f in file_tree if f not in excluded_paths]

    logger.info("recon: %d files, %d total grep hits",
                len(file_tree), sum(len(v) for v in raw_grep_hits.values()))

    static_callbacks: list[dict] = []
    if cfg.deterministic_analysis:
        static_callbacks = recon_helpers.extract_static_callbacks(plugin_path)
        logger.info("recon: deterministic callback scan found %d registrations", len(static_callbacks))

    surveyor = SurveyorAgent(runtime, model=config.models.surveyor)
    # #7: optionally inject negative-pattern reference into the surveyor prompt
    if cfg.negative_pattern_reference:
        surveyor.extra_system = NEGATIVE_PATTERN_REFERENCE
    artifact = await surveyor.survey(
        plugin_slug=intake.plugin_slug,
        file_tree=file_tree,
        ripgrep_hits=raw_grep_hits,
        plugin_path=str(plugin_path),
    )

    if cfg.deterministic_analysis:
        from ..schemas.recon import StaticCallEdge, StaticCallback
        artifact.static_callbacks = [
            StaticCallback.model_validate(item) for item in static_callbacks
        ]
        artifact.static_call_edges = [
            StaticCallEdge.model_validate(item)
            for item in recon_helpers.trace_static_call_edges(plugin_path, static_callbacks)
        ]
        logger.info("recon: deterministic call edges=%d", len(artifact.static_call_edges or []))

    # #5 + #6: enrich each entry point with body_slice + confidence
    if cfg.enrich_entry_points:
        for ep in artifact.entry_points:
            ep.body_slice = recon_helpers.extract_body_slice(plugin_path, ep.file, ep.line)
            ep.confidence = recon_helpers.score_confidence(
                entry_point_file=ep.file,
                handler_function=ep.handler_function,
                body_slice=ep.body_slice,
                excluded_buckets=excluded_buckets or None,
                file_classification=intake.file_classification,
            )

    # #2: cross-file callee tracing
    if cfg.trace_cross_file_callees:
        fn_def_map = recon_helpers.build_function_def_map(plugin_path)
        artifact.cross_file_callees = {
            ep.handler_function: recon_helpers.trace_callees(ep.body_slice or "", fn_def_map)
            for ep in artifact.entry_points
            if ep.handler_function
        }
        logger.info("recon: cross-file callee map for %d handlers (fn_def_map size=%d)",
                    len(artifact.cross_file_callees), len(fn_def_map))

    # #3: nonce-emission scan (PHP wp_create_nonce + JS nonce values)
    if cfg.scan_nonce_emissions:
        artifact.nonce_emission_sites = recon_helpers.scan_nonce_emissions(plugin_path)
        php_actions = [k for k in artifact.nonce_emission_sites if not k.startswith("_js_value_only_")]
        logger.info("recon: nonce-emission scan — %d PHP actions, %d JS-only values",
                    len(php_actions),
                    len(artifact.nonce_emission_sites) - len(php_actions))

    # #4: record what we excluded
    if excluded_buckets:
        artifact.excluded_buckets = excluded_buckets

    # #1: per-entry-point validation pass (LLM)
    if cfg.validate_entry_points and artifact.entry_points:
        validator = EntryPointValidator(runtime, model=config.models.hypothesis_verifier)
        order_key = {"high": 0, "medium": 1, "low": 2}
        sorted_eps = sorted(
            artifact.entry_points,
            key=lambda ep: order_key.get(ep.confidence or "medium", 1),
        )
        targets = sorted_eps[:cfg.max_entries_to_validate]
        logger.info("recon: validating %d/%d entry points (cap=%d)",
                    len(targets), len(artifact.entry_points), cfg.max_entries_to_validate)
        validations = await asyncio.gather(
            *[validator.validate_one(ep) for ep in targets],
            return_exceptions=False,
        )
        for ep, val in zip(targets, validations):
            if val is None:
                continue
            ep.validated_auth_gating = val.auth_gating
            ep.validated_nonce_action = val.nonce_action
            ep.validated_capability = val.capability
            ep.validation_citation = val.citation
            ep.validation_notes = val.notes

    out_path = Path(runs_root) / intake.run_id / "recon.json"
    artifact.to_json_file(str(out_path))
    if ckey:
        recon_helpers.save_cached_recon(ckey, artifact.model_dump(mode="json"))
        logger.info("recon: cached at %s", recon_helpers.cache_path(ckey))

    logger.info("recon: wrote %s (entry_points=%d sinks=%d)",
                out_path, len(artifact.entry_points), len(artifact.sinks))
    return artifact
