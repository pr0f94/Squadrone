"""Intake stage — pull plugin source from SVN, write intake.json."""

from __future__ import annotations

import logging
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from ..schemas.config import PipelineConfig
from ..schemas.intake import IntakeArtifact
from ..services.svn import SVNClient
from ..services.intake_helpers import is_plugin_closed

logger = logging.getLogger(__name__)


class PluginClosedError(RuntimeError):
    """Raised when WordPress.org marks a latest-version target as closed."""


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


async def run(
    plugin_slug: str,
    run_id: str,
    config: PipelineConfig,
    runs_root: str = "runs",
    version: str | None = None,
) -> IntakeArtifact:
    is_closed: bool | None = None
    if version is None:
        is_closed = await is_plugin_closed(plugin_slug)
        if is_closed is True:
            raise PluginClosedError(
                f"Plugin '{plugin_slug}' is marked closed on WordPress.org and is not "
                "eligible for the configured disclosure programs"
            )

    svn = SVNClient()
    if version is None:
        release = await svn.get_latest_release(plugin_slug)
        version = release.version
        logger.info("intake: %s latest=%s", plugin_slug, version)
    else:
        release = None
        logger.info("intake: %s pinned=%s", plugin_slug, version)

    run_dir = Path(runs_root) / run_id
    plugin_dir = run_dir / "plugin"
    plugin_dir.parent.mkdir(parents=True, exist_ok=True)

    if release is not None:
        await svn.export_release(plugin_slug, release, str(plugin_dir))
    else:
        await svn.export(plugin_slug, version, str(plugin_dir))
    _maybe_unpack_zip_tag(plugin_dir, plugin_slug)
    file_count, total_lines = _count_files(plugin_dir)

    artifact = IntakeArtifact(
        run_id=run_id,
        plugin_slug=plugin_slug,
        plugin_version=version,
        source_path=str(plugin_dir),
        file_count=file_count,
        total_lines=total_lines,
        source_url=(
            release.download_url
            if release is not None
            else f"https://plugins.svn.wordpress.org/{plugin_slug}/tags/{version}"
        ),
        scanned_at=datetime.now(timezone.utc),
        is_plugin_closed=is_closed,
    )
    artifact.to_json_file(str(run_dir / "intake.json"))
    logger.info("intake: wrote %s (files=%d lines=%d)", run_dir / "intake.json", file_count, total_lines)
    return artifact
