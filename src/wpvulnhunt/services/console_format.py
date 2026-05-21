"""Helpers for readable verbose console log messages."""

from __future__ import annotations

from textwrap import fill
from typing import Any


def _wrap(text: str, *, width: int = 72, indent: str = "    ") -> str:
    text = " ".join(str(text or "").split())
    if not text:
        return f"{indent}-"
    return fill(text, width=width, initial_indent=indent, subsequent_indent=indent)


def _hypothesis_context(hypothesis: Any) -> str:
    parts = [
        getattr(hypothesis, "bug_class", ""),
        getattr(hypothesis, "specialist", ""),
        f"{getattr(hypothesis, 'file', '?')}:{getattr(hypothesis, 'line', '?')}",
    ]
    return " | ".join(str(part.value if hasattr(part, "value") else part) for part in parts if part)


def format_verifier_decision(
    hypothesis: Any,
    verdict: str,
    reason: str,
    *,
    citation: str | None = None,
) -> str:
    style = "green" if verdict.startswith("keep") else "red"
    if verdict == "escalate_to_manual_review":
        style = "yellow"
    label = verdict.replace("_", " ").upper()
    lines = [
        "",
        f"[bold {style}]VERIFIER {label}[/] [bold]{hypothesis.id}[/] [dim]{_hypothesis_context(hypothesis)}[/]",
        f"[{style}]Reason[/]",
        _wrap(reason),
    ]
    if citation:
        lines.extend((f"[{style}]Citation[/]", _wrap(citation)))
    return "\n".join(lines)


def format_triage_accept(hypothesis: Any) -> str:
    programs = ", ".join(getattr(hypothesis, "bounty_programs", []) or []) or "not tagged"
    return "\n".join([
        "",
        f"[bold green]TRIAGE ACCEPT[/] [bold]{hypothesis.id}[/] [dim]{_hypothesis_context(hypothesis)}[/]",
        "[green]Bounty programs[/]",
        _wrap(programs),
    ])


def format_triage_reject(rejection: dict[str, Any]) -> str:
    hypothesis_id = (
        rejection.get("hypothesis_id")
        or rejection.get("id")
        or rejection.get("rejected_id")
        or "unknown"
    )
    reason = rejection.get("reason") or rejection.get("rationale") or rejection
    return "\n".join([
        "",
        f"[bold red]TRIAGE REJECT[/] [bold]{hypothesis_id}[/]",
        "[red]Reason[/]",
        _wrap(str(reason)),
    ])


def format_triage_merge(merge: dict[str, Any]) -> str:
    merged_from = merge.get("merged_from_id") or merge.get("from") or merge.get("hypothesis_id") or "unknown"
    kept = merge.get("kept_id") or merge.get("into") or merge.get("target_id") or "unknown"
    reason = merge.get("reason") or merge.get("rationale") or "duplicate or overlapping hypothesis"
    return "\n".join([
        "",
        f"[bold yellow]TRIAGE MERGE[/] [bold]{merged_from}[/] [dim]into {kept}[/]",
        "[yellow]Reason[/]",
        _wrap(str(reason)),
    ])


def format_triage_reframe(reframe: dict[str, Any]) -> str:
    hypothesis_id = reframe.get("hypothesis_id") or reframe.get("id") or "unknown"
    suggested = reframe.get("suggested_framing") or "-"
    reason = reframe.get("reason_original_rejected") or "-"
    return "\n".join([
        "",
        f"[bold yellow]TRIAGE REFRAME[/] [bold]{hypothesis_id}[/]",
        "[yellow]Suggested framing[/]",
        _wrap(str(suggested)),
        "[yellow]Original issue[/]",
        _wrap(str(reason)),
    ])
