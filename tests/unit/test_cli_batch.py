"""Unit tests for scan-batch CLI scheduling."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
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

    result = runner.invoke(
        cli.app, ["scan-batch", str(plugins_file), "--concurrency", "2"]
    )

    assert result.exit_code == 0
    assert max_active == 2


def test_scan_batch_propagates_cancellation_and_cancels_peers(tmp_path, monkeypatch):
    plugins_file = tmp_path / "plugins.txt"
    plugins_file.write_text("alpha\nbeta\n")
    cancellation = asyncio.CancelledError("operator stop")
    both_started = asyncio.Event()
    never = asyncio.Event()
    started: set[str] = set()
    finalized: list[str] = []

    async def fake_run_scan_cli(**kwargs):
        plugin_slug = kwargs["plugin_slug"]
        started.add(plugin_slug)
        if len(started) == 2:
            both_started.set()
        await both_started.wait()
        if plugin_slug == "alpha":
            raise cancellation
        try:
            await never.wait()
        finally:
            finalized.append(plugin_slug)

    monkeypatch.setattr(cli, "_run_scan_cli", fake_run_scan_cli)

    with pytest.raises(asyncio.CancelledError) as caught:
        runner.invoke(
            cli.app,
            ["scan-batch", str(plugins_file), "--concurrency", "2"],
        )

    assert caught.value is cancellation
    assert started == {"alpha", "beta"}
    assert finalized == ["beta"]


@pytest.mark.asyncio
async def test_run_scan_cli_renders_interrupted_event_and_propagates(
    monkeypatch, capsys
):
    cancellation = asyncio.CancelledError("operator stop")

    async def fake_run_scan(**kwargs):
        kwargs["on_event"]("_pipeline", "interrupted", {"message": "operator stop"})
        raise cancellation

    monkeypatch.setattr("squadrone.orchestrator.run_scan", fake_run_scan)
    monkeypatch.setattr(cli, "_print_scan_header", lambda *_args: None)

    with pytest.raises(asyncio.CancelledError) as caught:
        await cli._run_scan_cli(
            plugin_slug="alpha",
            config="pipelines/chatgpt.yaml",
            budget=None,
            version=None,
            resume=None,
            resume_from=None,
            verbose=False,
        )

    assert caught.value is cancellation
    assert "pipeline interrupted — operator stop" in capsys.readouterr().out


def test_run_scan_cli_uses_fixed_scan_path(monkeypatch):
    seen: dict = {}

    async def fake_run_scan(**kwargs):
        seen.update(kwargs)
        return _scan_result(kwargs["plugin_slug"])

    monkeypatch.setattr("squadrone.orchestrator.run_scan", fake_run_scan)
    monkeypatch.setattr(cli, "_print_scan_result", lambda _result: None)

    asyncio.run(
        cli._run_scan_cli(
            plugin_slug="alpha",
            config="pipelines/chatgpt.yaml",
            budget=None,
            version=None,
            resume=None,
            resume_from=None,
            verbose=False,
            verify_only=True,
            triage_only=False,
        )
    )

    assert seen["plugin_slug"] == "alpha"
    assert seen["config_path"] == "pipelines/chatgpt.yaml"
    assert set(seen) == {
        "plugin_slug",
        "config_path",
        "budget_override",
        "on_event",
        "version",
        "resume_run_id",
        "resume_from",
        "verify_only",
        "triage_only",
    }
    assert seen["verify_only"] is True
    assert seen["triage_only"] is False


def test_scan_accepts_verify_only_flag(monkeypatch):
    seen: dict = {}

    async def fake_run_scan_cli(**kwargs):
        seen.update(kwargs)
        return _scan_result(kwargs["plugin_slug"])

    monkeypatch.setattr(cli, "_run_scan_cli", fake_run_scan_cli)

    result = runner.invoke(cli.app, ["scan", "alpha", "--verify-only"])

    assert result.exit_code == 0
    assert seen["verify_only"] is True
    assert seen["triage_only"] is False


def test_scan_accepts_triage_only_flag(monkeypatch):
    seen: dict = {}

    async def fake_run_scan_cli(**kwargs):
        seen.update(kwargs)
        return _scan_result(kwargs["plugin_slug"])

    monkeypatch.setattr(cli, "_run_scan_cli", fake_run_scan_cli)

    result = runner.invoke(cli.app, ["scan", "alpha", "--triage-only"])

    assert result.exit_code == 0
    assert seen["triage_only"] is True
    assert seen["verify_only"] is False


def test_scan_rejects_triage_only_with_verify_only(monkeypatch):
    called = False

    async def fake_run_scan_cli(**_kwargs):
        nonlocal called
        called = True
        return _scan_result("alpha")

    monkeypatch.setattr(cli, "_run_scan_cli", fake_run_scan_cli)

    result = runner.invoke(
        cli.app,
        ["scan", "alpha", "--triage-only", "--verify-only"],
    )

    assert result.exit_code == 2
    assert "mutually exclusive" in result.output
    assert called is False
