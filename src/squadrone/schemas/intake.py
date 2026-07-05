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
    wp_core_path: str | None = None
    file_classification: dict[str, list[str]] | None = None
    recent_changelog: list[dict] | None = None
    is_plugin_closed: bool | None = None
