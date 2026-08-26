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


class VerifierVerdict(BaseModel):
    verdict: VerdictType
    reason: str
    citation: Optional[str] = None


def _resolve_path(plugin_root: Path, rel_file: str) -> Path | None:
    candidate = plugin_root / rel_file
    if candidate.is_file():
        return candidate
    for prefix in ("wp-content/plugins/" + plugin_root.name + "/", plugin_root.name + "/"):
        if rel_file.startswith(prefix):
            candidate = plugin_root / rel_file[len(prefix):]
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
    return "\n".join(f"{i+1:5}  {lines[i]}" for i in range(start, end))


def _normalise(text: str) -> str:
    """Collapse whitespace for fuzzy substring comparison."""
    return re.sub(r"\s+", " ", text).strip()


def _read_verified_source_slice(
    plugin_root: Path,
    rel_file: str,
    line: int,
    sink_code: str,
    ctx: int = 15,
) -> tuple[str | None, str]:
    """Return a source window only when the sink quote matches its cited line."""
    if not rel_file:
        return None, "hypothesis has no cited source file"
    path = _resolve_path(plugin_root, rel_file)
    if path is None:
        return None, "cited source file could not be read"
    lines = _read_lines(path)
    if lines is None or line < 1 or line > len(lines):
        return None, "cited source line is outside the file"
    needle = _normalise(sink_code)
    if len(needle) < 8:
        return None, "sink_code is missing or too short to verify"
    first_fragment = _normalise(sink_code.splitlines()[0])
    if first_fragment not in _normalise(lines[line - 1]):
        return None, "sink_code does not begin at the cited line"
    span = max(1, sink_code.count("\n") + 2)
    cited_expression = "\n".join(lines[line - 1:line - 1 + span])
    if needle not in _normalise(cited_expression):
        return None, "sink_code does not match the expression at the cited line"
    return _slice_around(lines, line, ctx), ""


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
        slice_text, citation_error = _read_verified_source_slice(
            plugin_root, hyp.file, hyp.line, hyp.sink_code or ""
        )
        if slice_text is None:
            verdict = VerifierVerdict(
                verdict="drop",
                reason=f"{citation_error}, so the hypothesis is not source-grounded",
            )
            return verdict

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
        return result.output
