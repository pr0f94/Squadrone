from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace

from typer.testing import CliRunner

from squadrone import cli


runner = CliRunner()


def _install_fake_runner(monkeypatch, *, failed: bool = False) -> dict:
    seen: dict = {}

    async def fake_run_regressions(**kwargs):
        seen.update(kwargs)
        case = SimpleNamespace(
            case_id="example-case",
            cve_id="CVE-2024-1000",
            plugin_slug="example-plugin",
            version="1.0",
            mode="confirm",
            status="failed" if failed else "passed",
            finding_count=0 if failed else 1,
            cost_usd=1.25,
            errors=["not confirmed"] if failed else [],
        )
        return SimpleNamespace(
            cases=[case],
            passed_count=0 if failed else 1,
            case_count=1,
            failed_count=1 if failed else 0,
            total_cost_usd=1.25,
            result_path="benchmarks/results/regression-test.json",
        )

    module = ModuleType("regression_runner")
    module.run_regressions = fake_run_regressions  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "regression_runner", module)
    return seen


def test_regression_cli_requires_explicit_budget() -> None:
    result = runner.invoke(cli.app, ["regression", "benchmarks/regressions.json"])

    assert result.exit_code != 0
    assert "--budget" in result.output


def test_regression_cli_forwards_per_case_budget_and_selection(monkeypatch) -> None:
    seen = _install_fake_runner(monkeypatch)

    result = runner.invoke(
        cli.app,
        [
            "regression",
            "benchmarks/regressions.json",
            "--budget",
            "100",
            "--config",
            "pipelines/chatgpt.yaml",
            "--case",
            "first",
            "--case",
            "second",
        ],
    )

    assert result.exit_code == 0
    assert seen == {
        "manifest_path": "benchmarks/regressions.json",
        "config_path": "pipelines/chatgpt.yaml",
        "budget_per_case_usd": 100.0,
        "case_ids": ["first", "second"],
    }


def test_regression_cli_exits_nonzero_when_a_case_fails(monkeypatch) -> None:
    _install_fake_runner(monkeypatch, failed=True)

    result = runner.invoke(
        cli.app,
        ["regression", "benchmarks/regressions.json", "--budget", "100"],
    )

    assert result.exit_code == 1
    assert "not confirmed" in result.output
