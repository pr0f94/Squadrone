"""Unit tests for scan-batch CLI scheduling."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from typer.testing import CliRunner

from squadrone import cli


runner = CliRunner()


def _scan_result(plugin_slug: str) -> SimpleNamespace:
    return SimpleNamespace(
        plugin_slug=plugin_slug,
        run_id=f"run-{plugin_slug}",
        status="complete",
        finding_count=0,
        novel_count=0,
        cost_usd=0.0,
        duration_seconds=0.0,
        report_paths=[],
        cache_hit_rate=0.0,
    )


def test_scan_batch_defaults_to_sequential(tmp_path, monkeypatch):
    plugins_file = tmp_path / "plugins.txt"
    plugins_file.write_text("alpha\n\n# comment\nbeta\ngamma\n")
    calls: list[str] = []
    active = 0
    max_active = 0

    async def fake_run_scan_cli(**kwargs):
        nonlocal active, max_active
        plugin_slug = kwargs["plugin_slug"]
        calls.append(plugin_slug)
        active += 1
        max_active = max(max_active, active)
        await asyncio.sleep(0)
        active -= 1
        return _scan_result(plugin_slug)

    monkeypatch.setattr(cli, "_run_scan_cli", fake_run_scan_cli)

    result = runner.invoke(cli.app, ["scan-batch", str(plugins_file)])

    assert result.exit_code == 0
    assert calls == ["alpha", "beta", "gamma"]
    assert max_active == 1


def test_scan_batch_honors_concurrency_option(tmp_path, monkeypatch):
    plugins_file = tmp_path / "plugins.txt"
    plugins_file.write_text("alpha\nbeta\ngamma\n")
    active = 0
    max_active = 0

    async def fake_run_scan_cli(**kwargs):
        nonlocal active, max_active
        plugin_slug = kwargs["plugin_slug"]
        active += 1
        max_active = max(max_active, active)
        await asyncio.sleep(0)
        active -= 1
        return _scan_result(plugin_slug)

    monkeypatch.setattr(cli, "_run_scan_cli", fake_run_scan_cli)

    result = runner.invoke(cli.app, ["scan-batch", str(plugins_file), "--concurrency", "2"])

    assert result.exit_code == 0
    assert max_active == 2
