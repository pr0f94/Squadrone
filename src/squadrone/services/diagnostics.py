"""Bounded text formatting for persisted and model-facing diagnostics."""

from __future__ import annotations

import re


DIAGNOSTIC_OMISSION_MARKER = "\n... [middle diagnostic omitted] ...\n"
_INLINE_OMISSION_MARKER = "..."
_QUALIFIED_EXCEPTION_RE = re.compile(
    r"^(?P<name>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)"
    r"(?::(?: .*)?)?$"
)
_CONVENTIONAL_EXCEPTION_SUFFIXES = (
    "Error",
    "Exception",
    "Exit",
    "Interrupt",
    "Iteration",
    "Warning",
)


def _line_spans(value: str) -> list[tuple[int, int, str]]:
    """Return line-content spans without including newline characters."""
    spans: list[tuple[int, int, str]] = []
    offset = 0
    for line in value.splitlines(keepends=True):
        content = line.rstrip("\r\n")
        spans.append((offset, offset + len(content), content))
        offset += len(line)
    return spans


def _matches_exception_summary(line: str, *, within_traceback: bool) -> bool:
    """Recognize a Python-style exception summary without matching log prefixes."""
    match = _QUALIFIED_EXCEPTION_RE.fullmatch(line)
    if match is None:
        return False
    if within_traceback:
        return True
    exception_name = match.group("name").rsplit(".", maxsplit=1)[-1]
    return exception_name.endswith(_CONVENTIONAL_EXCEPTION_SUFFIXES)


def _actionable_exception_span(value: str) -> tuple[int, int] | None:
    """Find the last exception summary, preferring a real traceback terminus."""
    spans = _line_spans(value)
    traceback_starts = [
        index
        for index, (_, _, line) in enumerate(spans)
        if line == "Traceback (most recent call last):"
    ]
    for traceback_start in reversed(traceback_starts):
        for start, end, line in spans[traceback_start + 1 :]:
            if not line or line[0].isspace():
                continue
            if line == "Traceback (most recent call last):":
                break
            if _matches_exception_summary(line, within_traceback=True):
                return start, end

    for start, end, line in reversed(spans):
        if _matches_exception_summary(line, within_traceback=False):
            return start, end
    return None


def _clip_middle(value: str, *, limit: int) -> str:
    """Clip one priority fragment while retaining both ends."""
    if len(value) <= limit:
        return value
    if limit <= len(_INLINE_OMISSION_MARKER):
        return value[:limit]
    context_size = limit - len(_INLINE_OMISSION_MARKER)
    head_size = context_size // 2
    tail_size = context_size - head_size
    return value[:head_size] + _INLINE_OMISSION_MARKER + value[-tail_size:]


def bound_diagnostic(value: str, *, limit: int) -> str:
    """Keep bounded head/tail context and an otherwise-hidden exception."""
    if limit < len(DIAGNOSTIC_OMISSION_MARKER) + 2:
        raise ValueError("diagnostic limit is too small for bounded head/tail context")
    if len(value) <= limit:
        return value

    context_size = limit - len(DIAGNOSTIC_OMISSION_MARKER)
    head_size = context_size // 2
    tail_size = context_size - head_size
    default_result = value[:head_size] + DIAGNOSTIC_OMISSION_MARKER + value[-tail_size:]

    exception_span = _actionable_exception_span(value)
    if exception_span is None:
        return default_result
    exception_start, exception_end = exception_span
    tail_start = len(value) - tail_size
    if exception_end <= head_size or exception_start >= tail_start:
        return default_result

    priority_context_size = limit - (2 * len(DIAGNOSTIC_OMISSION_MARKER))
    if priority_context_size < 3:
        return default_result
    exception_limit = max(1, priority_context_size // 2)
    exception_context = _clip_middle(
        value[exception_start:exception_end],
        limit=exception_limit,
    )
    surrounding_context_size = priority_context_size - len(exception_context)
    if surrounding_context_size < 2:
        return default_result
    priority_head_size = surrounding_context_size // 2
    priority_tail_size = surrounding_context_size - priority_head_size
    return (
        value[:priority_head_size]
        + DIAGNOSTIC_OMISSION_MARKER
        + exception_context
        + DIAGNOSTIC_OMISSION_MARKER
        + value[-priority_tail_size:]
    )
