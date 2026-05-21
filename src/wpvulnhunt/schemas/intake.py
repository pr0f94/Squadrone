"""Intake stage artifact schema."""

from __future__ import annotations

from datetime import datetime

from ._base import JSONFileMixin


class IntakeArtifact(JSONFileMixin):
    run_id: str
    plugin_slug: str
    plugin_version: str
    source_path: str
    file_count: int
    total_lines: int
    svn_url: str
    scanned_at: datetime
    # Stage 1 opt-in metadata (all None by default — backward compatible with old runs)
    wp_core_path: str | None = None                          # #1: bundle_wp_core
    file_classification: dict[str, list[str]] | None = None  # #2: classify_files
    recent_changelog: list[dict] | None = None               # #4: fetch_changelog
    is_plugin_closed: bool | None = None                     # #6: detect_closed
    diff_baseline_version: str | None = None
    diff_summary: str | None = None
