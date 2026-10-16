from __future__ import annotations

import asyncio
from io import StringIO
from pathlib import Path
from types import SimpleNamespace

import pytest
from rich.console import Console

from squadrone import cli, orchestrator
from squadrone.schemas.hypothesis import (
    BugClass,
    Confidence,
    Hypothesis,
    SecurityOutcome,
    TriagedArtifact,
)


def _hypothesis(
    hypothesis_id: str,
    bug_class: BugClass,
    *,
    description: str,
    injection_order: str | None = None,
    storage_boundary: str | None = None,
    impact_labels: list[str] | None = None,
) -> Hypothesis:
    return Hypothesis(
        id=hypothesis_id,
        specialist="test",
        bug_class=bug_class,
        entry_point="POST /candidate",
        file="includes/candidate.php",
        line=42,
        sink="dangerous sink",
        taint_path=["request", "sink"],
        reasoning="Fallback candidate reasoning.",
        confidence=Confidence.HIGH,
        preconditions="subscriber",
        affected_versions="1.0",
        injection_order=injection_order,
        storage_boundary=storage_boundary,
        impact_labels=impact_labels or [],
        security_outcome=SecurityOutcome(
            integrity="high",
            description=description,
        ),
    )


def _write_hypotheses(path: Path, hypotheses: list[Hypothesis]) -> None:
    path.write_text(
        "\n".join(hypothesis.model_dump_json() for hypothesis in hypotheses) + "\n"
    )


def test_verbose_triage_feed_renders_every_final_disposition_compactly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    accepted = _hypothesis(
        "xss-accepted",
        BugClass.XSS_STORED,
        description="Contributor payload\nexecutes when [bold]an admin[/] views the page.",
    )
    manual = _hypothesis(
        "open-manual",
        BugClass("CWE-269"),
        description="A privilege-management boundary may be crossed.",
    )
    deferred = _hypothesis(
        "sqli-deferred",
        BugClass.SQLI,
        description="Stored input later reaches a query.",
        injection_order="second",
        storage_boundary="option",
    )
    rejected = _hypothesis(
        "csrf-rejected",
        BugClass.MISSING_NONCE,
        description="A cross-site request changes low-impact settings.",
    )
    merged = _hypothesis(
        "write-merged",
        BugClass.ARBITRARY_FILE_WRITE,
        description="A file-write path overlaps a stronger candidate.",
        impact_labels=["potential_rce"],
    )
    triaged = TriagedArtifact(
        plugin_slug="demo",
        accepted=[accepted],
        manual_review=[
            {
                "hypothesis_id": manual.id,
                "reason": "Manual oracle required.",
                "hypothesis": manual.model_dump(mode="json"),
            }
        ],
        deferred=[
            {
                "hypothesis_id": deferred.id,
                "reason": "Ranked below the verification cap.",
                "hypothesis": deferred.model_dump(mode="json"),
            }
        ],
        rejected=[
            {
                "hypothesis_id": rejected.id,
                "reason": "Rejected because the demonstrated impact is low.",
            }
        ],
        merged=[
            {
                "merged_from_id": merged.id,
                "kept_id": accepted.id,
                "reason": "Merged into the stronger source-equivalent candidate.",
            }
        ],
        submission_scope_enforced=False,
    )
    triaged.to_json_file(str(tmp_path / "triaged.json"))
    _write_hypotheses(
        tmp_path / "hypotheses.jsonl",
        [accepted, manual, deferred, rejected, merged],
    )
    output = StringIO()
    monkeypatch.setattr(
        cli,
        "console",
        Console(file=output, color_system=None, force_terminal=False, width=400),
    )

    assert cli._print_triage_candidate_feed(tmp_path, batch_prefix="[1/2 demo]")

    lines = output.getvalue().splitlines()
    assert len(lines) == 6
    assert lines[0] == (
        "[1/2 demo] Candidates · ✓ Accepted 1 · ◌ Manual 1 "
        "· ↷ Deferred 1 · ✕ Rejected 1 · ↪ Merged 1"
    )
    assert "✓ Stored XSS [xss-accepted]" in lines[1]
    assert "payload executes when [bold]an admin[/] views" in lines[1]
    assert (
        "◌ CWE-269 [open-manual] — A privilege-management boundary may be crossed."
        in lines[2]
    )
    assert "↷ SQLi/2nd [sqli-deferred]" in lines[3]
    assert "Stored input later reaches a query." in lines[3]
    assert "✕ CSRF [csrf-rejected]" in lines[4]
    assert "Rejected because the demonstrated impact is low." in lines[4]
    assert "↪ File Write/RCE [write-merged] → [xss-accepted]" in lines[5]
    assert all(line.startswith("[1/2 demo] ") for line in lines)


def test_verbose_triage_feed_degrades_safely_when_type_index_is_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    TriagedArtifact(
        plugin_slug="demo",
        accepted=[],
        rejected=[{"hypothesis_id": "missing", "reason": "Malformed candidate."}],
        merged=[],
    ).to_json_file(str(tmp_path / "triaged.json"))
    (tmp_path / "hypotheses.jsonl").write_text("not-json\n")
    output = StringIO()
    monkeypatch.setattr(
        cli,
        "console",
        Console(file=output, color_system=None, force_terminal=False, width=200),
    )

    assert cli._print_triage_candidate_feed(tmp_path)

    lines = output.getvalue().splitlines()
    assert len(lines) == 2
    assert "✕ Unknown [missing] — Malformed candidate." in lines[1]


def test_verbose_triage_feed_truncates_long_descriptions_to_one_line(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    accepted = _hypothesis(
        "long-description",
        BugClass.SSRF,
        description="line one\n" + ("x" * 250),
    )
    TriagedArtifact(
        plugin_slug="demo",
        accepted=[accepted],
        rejected=[],
        merged=[],
    ).to_json_file(str(tmp_path / "triaged.json"))
    output = StringIO()
    monkeypatch.setattr(
        cli,
        "console",
        Console(file=output, color_system=None, force_terminal=False, width=400),
    )

    assert cli._print_triage_candidate_feed(tmp_path)

    lines = output.getvalue().splitlines()
    assert len(lines) == 2
    assert lines[1].endswith("…")
    assert len(lines[1].split("—", 1)[1].strip()) == 140


def test_verbose_triage_feed_never_wraps_at_narrow_terminal_width(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    accepted = _hypothesis(
        "narrow",
        BugClass.XSS_REFLECTED,
        description="A deliberately long candidate description " + ("word " * 50),
    )
    TriagedArtifact(
        plugin_slug="demo",
        accepted=[accepted],
        rejected=[],
        merged=[],
    ).to_json_file(str(tmp_path / "triaged.json"))
    output = StringIO()
    monkeypatch.setattr(
        cli,
        "console",
        Console(file=output, color_system=None, force_terminal=False, width=72),
    )

    assert cli._print_triage_candidate_feed(tmp_path)

    lines = output.getvalue().splitlines()
    assert len(lines) == 2
    assert all(len(line) <= 72 for line in lines)
    assert lines[0].endswith("…")
    assert lines[1].endswith("…")


@pytest.mark.parametrize(
    ("verbose", "triage_only", "status", "expected"),
    [
        (True, True, "complete", True),
        (False, True, "complete", False),
        (True, False, "complete", False),
        (True, True, "failed", False),
    ],
)
def test_scan_cli_prints_feed_only_for_successful_verbose_triage_only_runs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    verbose: bool,
    triage_only: bool,
    status: str,
    expected: bool,
) -> None:
    result = SimpleNamespace(
        plugin_slug="demo",
        run_id="run-1",
        status=status,
        finding_count=0,
        novel_count=0,
        cost_usd=0.0,
        duration_seconds=0.0,
        report_paths=[],
        cache_hit_rate=0.0,
    )

    async def fake_run_scan(**_kwargs):
        return result

    calls: list[tuple[Path, str | None]] = []
    monkeypatch.setattr(orchestrator, "run_scan", fake_run_scan)
    monkeypatch.setattr(cli, "_print_scan_header", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(cli, "_print_scan_result", lambda _result: None)
    monkeypatch.setattr(cli, "_run_dir", lambda _run_id: tmp_path)
    monkeypatch.setattr(
        cli,
        "_print_triage_candidate_feed",
        lambda run_dir, *, batch_prefix=None: calls.append(
            (run_dir, batch_prefix)
        ),
    )

    asyncio.run(
        cli._run_scan_cli(
            plugin_slug="demo",
            config="pipeline.yaml",
            budget=None,
            version=None,
            resume=None,
            resume_from=None,
            verbose=verbose,
            triage_only=triage_only,
            batch_prefix="[1/1 demo]",
        )
    )

    assert bool(calls) is expected
    if expected:
        assert calls == [(tmp_path, "[1/1 demo]")]
