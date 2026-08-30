from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

from squadrone.schemas.config import PipelineConfig
from squadrone.schemas.intake import IntakeArtifact
from squadrone.services.svn import PluginExport
from squadrone.stages import intake


@pytest.mark.asyncio
async def test_pinned_intake_records_actual_export_source(monkeypatch, tmp_path):
    download_url = "https://downloads.wordpress.org/plugin/demo.1.2.3.zip"

    class StubSVNClient:
        async def export_pinned_release(self, slug, version, dest):
            assert (slug, version) == ("demo", "1.2.3")
            plugin_dir = Path(dest)
            plugin_dir.mkdir(parents=True)
            (plugin_dir / "demo.php").write_text("<?php\n")
            return PluginExport(path=str(plugin_dir), source_url=download_url)

    monkeypatch.setattr(intake, "SVNClient", StubSVNClient)

    artifact = await intake.run(
        "demo",
        "run-1",
        cast(PipelineConfig, object()),
        runs_root=str(tmp_path),
        version="1.2.3",
    )

    assert artifact.plugin_version == "1.2.3"
    assert artifact.source_url == download_url
    assert artifact.file_count == 1
    persisted = IntakeArtifact.from_json_file(str(tmp_path / "run-1" / "intake.json"))
    assert persisted.source_url == download_url
