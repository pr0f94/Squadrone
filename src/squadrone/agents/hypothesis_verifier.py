"""Hypothesis verifier — cheap per-hypothesis sanity check after specialists."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Optional

from pydantic import BaseModel

from ..schemas.hypothesis import Hypothesis
from .prompts_io import load_prompt

if TYPE_CHECKING:
    from .runtime import AgentRuntime

logger = logging.getLogger(__name__)

VerdictType = Literal["keep", "drop"]
_MAX_CITATION_LINE_DRIFT = 15


class VerifierVerdict(BaseModel):
    verdict: VerdictType
    reason: str
    citation: Optional[str] = None


def _resolve_path(plugin_root: Path, rel_file: str) -> Path | None:
    root = plugin_root.resolve()
    candidate = (root / rel_file).resolve()
    if not candidate.is_relative_to(root):
        return None
    if candidate.is_file():
        return candidate
    for prefix in (
        "wp-content/plugins/" + plugin_root.name + "/",
        plugin_root.name + "/",
    ):
        if rel_file.startswith(prefix):
            candidate = (root / rel_file[len(prefix) :]).resolve()
            if not candidate.is_relative_to(root):
                return None
            if candidate.is_file():
                return candidate
    return None


def _read_lines(path: Path) -> list[str] | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None


def _slice_around(lines: list[str], line_1based: int, ctx: int = 15) -> str:
    start = max(0, line_1based - 1 - ctx)
    end = min(len(lines), line_1based - 1 + ctx)
    return "\n".join(f"{i + 1:5}  {lines[i]}" for i in range(start, end))


def _normalise(text: str) -> str:
    """Collapse whitespace for fuzzy substring comparison."""
    return re.sub(r"\s+", " ", text).strip()


def _sink_matches_at(lines: list[str], line_1based: int, sink_code: str) -> bool:
    """Return whether a whitespace-normalized sink quote begins at a source line."""
    first_fragment = next(
        (
            normalized
            for raw_line in sink_code.splitlines()
            if (normalized := _normalise(raw_line))
        ),
        "",
    )
    if not first_fragment or first_fragment not in _normalise(lines[line_1based - 1]):
        return False
    span = max(1, sink_code.count("\n") + 2)
    expression = "\n".join(lines[line_1based - 1 : line_1based - 1 + span])
    return _normalise(sink_code) in _normalise(expression)


def _exact_sink_matches_at(lines: list[str], line_1based: int, sink_code: str) -> bool:
    """Match a complete quote at a line, ignoring indentation and line endings only."""
    quote_lines = sink_code.strip("\r\n").splitlines()
    if not quote_lines:
        return False
    source_start = line_1based - 1
    source_end = source_start + len(quote_lines)
    if source_start < 0 or source_end > len(lines):
        return False
    return [line.strip() for line in quote_lines] == [
        line.strip() for line in lines[source_start:source_end]
    ]


def validate_exact_sink_anchor(
    plugin_root: Path,
    rel_file: str,
    line: int,
    sink_code: str,
) -> str | None:
    """Return an error when a sink quote is not grounded at its exact citation."""
    if not rel_file:
        return "hypothesis has no cited source file"
    path = _resolve_path(plugin_root, rel_file)
    if path is None:
        return "cited source file could not be read inside the plugin root"
    lines = _read_lines(path)
    if lines is None or line < 1 or line > len(lines):
        return "cited source line is outside the file"
    if len(_normalise(sink_code)) < 8:
        return "sink_code is missing or too short to verify"
    if not _sink_matches_at(lines, line, sink_code):
        return "sink_code does not match the expression at the cited line"
    return None


def _read_verified_source_slice(
    plugin_root: Path,
    rel_file: str,
    line: int,
    sink_code: str,
    ctx: int = 15,
) -> tuple[str | None, str, int | None]:
    """Return a source window when the sink quote matches at or uniquely near its citation."""
    if not rel_file:
        return None, "hypothesis has no cited source file", None
    path = _resolve_path(plugin_root, rel_file)
    if path is None:
        return None, "cited source file could not be read", None
    lines = _read_lines(path)
    if lines is None or line < 1 or line > len(lines):
        return None, "cited source line is outside the file", None
    needle = _normalise(sink_code)
    if len(needle) < 8:
        return None, "sink_code is missing or too short to verify", None
    if _sink_matches_at(lines, line, sink_code):
        return _slice_around(lines, line, ctx), "", line

    nearby_start = max(1, line - _MAX_CITATION_LINE_DRIFT)
    nearby_end = min(len(lines), line + _MAX_CITATION_LINE_DRIFT)
    nearby_matches = [
        candidate_line
        for candidate_line in range(nearby_start, nearby_end + 1)
        if candidate_line != line
        and _exact_sink_matches_at(lines, candidate_line, sink_code)
    ]
    if len(nearby_matches) == 1:
        matched_line = nearby_matches[0]
        return _slice_around(lines, matched_line, ctx), "", matched_line
    if len(nearby_matches) > 1:
        return (
            None,
            "sink_code has multiple nearby matches, so the cited source is ambiguous",
            None,
        )
    return (
        None,
        f"sink_code does not match at the cited line or within "
        f"±{_MAX_CITATION_LINE_DRIFT} lines",
        None,
    )


class HypothesisVerifier:
    NAME = "hypothesis_verifier"
    PROMPT = "hypothesis_verifier"

    def __init__(
        self,
        runtime: "AgentRuntime",
        model: str,
    ):
        self.runtime = runtime
        self.model = model

    def _build_system_prompt(self) -> str:
        return (
            load_prompt(self.PROMPT)
            + "\n\n# WordPress idiom reference\n\n"
            + load_prompt("_wp_idioms")
        )

    async def verify(self, hyp: Hypothesis, plugin_path: str) -> VerifierVerdict:
        plugin_root = Path(plugin_path)
        cited_line = hyp.line
        slice_text, citation_error, verified_line = _read_verified_source_slice(
            plugin_root, hyp.file, hyp.line, hyp.sink_code or ""
        )
        if slice_text is None:
            verdict = VerifierVerdict(
                verdict="drop",
                reason=f"{citation_error}, so the hypothesis is not source-grounded",
            )
            return verdict
        relocation_citation: str | None = None
        if verified_line is not None and verified_line != cited_line:
            hyp.line = verified_line
            relocation_citation = (
                f"exact sink citation normalized from {hyp.file}:{cited_line} "
                f"to {hyp.file}:{verified_line}"
            )
            logger.info("hypothesis_verifier: %s %s", hyp.id, relocation_citation)

        system = self._build_system_prompt()
        user = (
            f"HYPOTHESIS:\n{hyp.model_dump_json(indent=2)}\n\n"
            f"SOURCE_SLICE ({hyp.file} around line {hyp.line}):\n```\n{slice_text}\n```"
        )

        run_kwargs: dict = {
            "agent_name": self.NAME,
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "output_schema": VerifierVerdict,
        }

        result = await self.runtime.run(**run_kwargs)
        verdict = result.output
        if relocation_citation:
            verdict.citation = (
                f"{verdict.citation}; {relocation_citation}"
                if verdict.citation
                else relocation_citation
            )
        return verdict
