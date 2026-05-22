"""Intake stage — pull plugin source from SVN, write intake.json."""

from __future__ import annotations

import filecmp
import logging
import shutil
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from ..schemas.config import PipelineConfig
from ..schemas.intake import IntakeArtifact
from ..services.svn import SVNClient
from ..services import intake_helpers, wp_core

logger = logging.getLogger(__name__)


class PluginClosedError(RuntimeError):
    """Raised when intake.detect_closed=True and wp.org marks the plugin closed."""


def _count_files(root: Path) -> tuple[int, int]:
    file_count = 0
    line_count = 0
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        file_count += 1
        try:
            with p.open("rb") as f:
                line_count += sum(1 for _ in f)
        except OSError:
            pass
    return file_count, line_count


def _maybe_unpack_zip_tag(plugin_dir: Path, slug: str) -> None:
    """Some plugins commit a release ZIP into their SVN tag instead of unpacked source
    (e.g. wp-file-manager). Detect that and unpack in place."""
    files = [p for p in plugin_dir.iterdir() if p.is_file()]
    zips = [p for p in files if p.suffix.lower() == ".zip"]
    if len(files) != 1 or not zips:
        return
    zip_path = zips[0]
    logger.info("intake: SVN tag contained only %s — unpacking in place", zip_path.name)
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(plugin_dir)
    zip_path.unlink()
    # If the unpacked content lives in a single subdir matching the slug, hoist it up
    # so plugin_dir directly contains the plugin's PHP files (recon expects flat layout).
    entries = list(plugin_dir.iterdir())
    if len(entries) == 1 and entries[0].is_dir():
        inner = entries[0]
        for item in inner.iterdir():
            item.rename(plugin_dir / item.name)
        inner.rmdir()
        logger.info("intake: hoisted contents from %s/", inner.name)


def _compute_diff_summary(current_dir: Path, baseline_dir: Path) -> str:
    """Return a compact PHP-only diff summary between two plugin source trees.

    Format: a newline-separated list of `STATUS path` entries where STATUS is
    one of A (added), D (deleted), M (modified). Non-PHP files are ignored
    because specialists only reason about PHP source. Intended for the
    specialist `diff_summary` field, not a full unified diff.
    """
    def php_files(root: Path) -> dict[str, Path]:
        out: dict[str, Path] = {}
        for p in root.rglob("*.php"):
            if p.is_file():
                out[str(p.relative_to(root))] = p
        return out

    cur = php_files(current_dir)
    base = php_files(baseline_dir)
    lines: list[str] = []
    for rel in sorted(set(cur) | set(base)):
        if rel in cur and rel not in base:
            lines.append(f"A {rel}")
        elif rel in base and rel not in cur:
            lines.append(f"D {rel}")
        else:
            try:
                if not filecmp.cmp(cur[rel], base[rel], shallow=False):
                    lines.append(f"M {rel}")
            except OSError:
                lines.append(f"M {rel}")
    return "\n".join(lines)


async def _fetch_diff_summary(
    svn: SVNClient, plugin_slug: str, current_dir: Path, baseline_version: str,
) -> str | None:
    """Export `baseline_version` to a tempdir, diff against `current_dir`, return summary."""
    with tempfile.TemporaryDirectory(prefix=f"{plugin_slug}-{baseline_version}-") as td:
        baseline_dir = Path(td) / "baseline"
        try:
            await svn.export(plugin_slug, baseline_version, str(baseline_dir))
        except Exception as e:
            logger.warning("intake: diff baseline export failed (%s@%s): %s",
                           plugin_slug, baseline_version, e)
            return None
        try:
            return _compute_diff_summary(current_dir, baseline_dir)
        finally:
            shutil.rmtree(baseline_dir, ignore_errors=True)


async def run(
    plugin_slug: str,
    run_id: str,
    config: PipelineConfig,
    runs_root: str = "runs",
    version: str | None = None,
    diff_baseline: str | None = None,
) -> IntakeArtifact:
    intake_cfg = config.intake

    # #6: closed-plugin detection (early bail; runs BEFORE svn.export so we don't waste a download)
    is_closed: bool | None = None
    if intake_cfg.detect_closed:
        is_closed = await intake_helpers.is_plugin_closed(plugin_slug)
        if is_closed is True:
            raise PluginClosedError(
                f"Plugin '{plugin_slug}' is marked closed on wp.org — refusing to scan "
                "(set intake.detect_closed=false to bypass, but Wordfence treats closed "
                "plugins as out of scope)"
            )
        # is_closed=False or None (lookup failed) → continue

    svn = SVNClient()
    if version is None:
        version = await svn.get_latest_version(plugin_slug)
        logger.info("intake: %s latest=%s", plugin_slug, version)
    else:
        logger.info("intake: %s pinned=%s", plugin_slug, version)

    run_dir = Path(runs_root) / run_id
    plugin_dir = run_dir / "plugin"
    plugin_dir.parent.mkdir(parents=True, exist_ok=True)

    await svn.export(plugin_slug, version, str(plugin_dir))
    _maybe_unpack_zip_tag(plugin_dir, plugin_slug)
    file_count, total_lines = _count_files(plugin_dir)

    # #1: WP core source bundle (cache hit on repeat scans)
    wp_core_path: str | None = None
    if intake_cfg.bundle_wp_core:
        wp_core_dir = await wp_core.ensure_wp_core_cached(intake_cfg.wp_core_version)
        wp_core_path = str(wp_core_dir) if wp_core_dir else None
        if wp_core_path is None:
            logger.warning("intake: WP core bundling enabled but cache fetch failed — continuing")

    # #2: file classification (heuristic path-pattern bucketing)
    file_classification: dict[str, list[str]] | None = None
    if intake_cfg.classify_files:
        file_classification = intake_helpers.classify_files(plugin_dir)
        bucket_summary = ", ".join(f"{k}={len(v)}" for k, v in file_classification.items() if v)
        logger.info("intake: file classification — %s", bucket_summary)

    # #4: changelog parsing
    recent_changelog: list[dict] | None = None
    if intake_cfg.fetch_changelog:
        recent_changelog = intake_helpers.parse_recent_changelog(plugin_dir)
        if recent_changelog:
            recent_versions = [c["version"] for c in recent_changelog]
            logger.info("intake: parsed %d changelog entries (%s)",
                         len(recent_changelog), ", ".join(recent_versions))
        else:
            logger.info("intake: changelog parse returned no entries")

    diff_summary: str | None = None
    if diff_baseline:
        if diff_baseline == version:
            logger.warning("intake: --diff baseline %s == scan version, skipping diff", diff_baseline)
        else:
            logger.info("intake: computing PHP diff vs baseline %s", diff_baseline)
            diff_summary = await _fetch_diff_summary(svn, plugin_slug, plugin_dir, diff_baseline)
            if diff_summary:
                line_count = diff_summary.count("\n") + 1
                logger.info("intake: diff vs %s — %d changed files", diff_baseline, line_count)

    artifact = IntakeArtifact(
        run_id=run_id,
        plugin_slug=plugin_slug,
        plugin_version=version,
        source_path=str(plugin_dir),
        file_count=file_count,
        total_lines=total_lines,
        svn_url=f"https://plugins.svn.wordpress.org/{plugin_slug}/tags/{version}",
        scanned_at=datetime.now(timezone.utc),
        wp_core_path=wp_core_path,
        file_classification=file_classification,
        recent_changelog=recent_changelog,
        is_plugin_closed=is_closed,
        diff_baseline_version=diff_baseline if diff_summary else None,
        diff_summary=diff_summary,
    )
    artifact.to_json_file(str(run_dir / "intake.json"))
    logger.info("intake: wrote %s (files=%d lines=%d)", run_dir / "intake.json", file_count, total_lines)
    return artifact
