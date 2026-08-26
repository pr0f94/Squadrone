"""Intake stage artifact schema."""

from __future__ import annotations

from datetime import datetime

from pydantic import AliasChoices, Field

from ._base import JSONFileMixin


class IntakeArtifact(JSONFileMixin):
    run_id: str
    plugin_slug: str
    plugin_version: str
    source_path: str
    file_count: int
    total_lines: int
    source_url: str = Field(validation_alias=AliasChoices("source_url", "svn_url"))
    scanned_at: datetime
    is_plugin_closed: bool | None = None
