"""Chain synthesizer — identifies exploit chains across hypotheses from different specialists.

Opt-in stage (--chain flag). Runs after hypothesis, before triage. Emits annotations
on existing hypotheses (chains_with / chain_impact / chain_severity_bump) rather than
new entries.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from pydantic import BaseModel, RootModel

from ..schemas.hypothesis import Hypothesis
from .prompts_io import load_prompt

if TYPE_CHECKING:
    from .runtime import AgentRuntime

logger = logging.getLogger(__name__)


class ChainEntry(BaseModel):
    ids: list[str]
    impact: str
    severity_bump: str
    bypass_mechanism: str


class _ChainList(RootModel[list[ChainEntry]]):
    pass


@dataclass
class ChainSynthesisResult:
    chains: list[ChainEntry]
    status: str
    hypothesis_count: int
    raw_chain_count: int = 0
    accepted_chain_count: int = 0
    dropped_self_or_single_count: int = 0
    dropped_unknown_id_count: int = 0
    error: str | None = None

    def diagnostics(self) -> dict:
        return {
            "status": self.status,
            "hypothesis_count": self.hypothesis_count,
            "raw_chain_count": self.raw_chain_count,
            "accepted_chain_count": self.accepted_chain_count,
            "dropped_self_or_single_count": self.dropped_self_or_single_count,
            "dropped_unknown_id_count": self.dropped_unknown_id_count,
            "error": self.error,
        }


def _truncate(value: object, limit: int = 1200) -> object:
    if value is None:
        return None
    if isinstance(value, str):
        return value if len(value) <= limit else value[: limit - 3] + "..."
    return value


def _compact_hypothesis(h: Hypothesis) -> dict:
    return {
        "id": h.id,
        "specialist": h.specialist,
        "bug_class": h.bug_class.value,
        "entry_point": h.entry_point,
        "file": h.file,
        "line": h.line,
        "sink": _truncate(h.sink),
        "sink_code": _truncate(h.sink_code),
        "taint_path": h.taint_path[:20],
        "reasoning": _truncate(h.reasoning, 2000),
        "preconditions": _truncate(h.preconditions),
        "confidence": h.confidence.value,
        "exploit_classification": h.exploit_classification,
        "bounty_fit": h.bounty_fit,
        "requires_verification": h.requires_verification,
        "evidence_summary": h.evidence_summary,
        "quality_gate": h.quality_gate,
        "derived_severity": h.derived_severity,
    }


class ChainSynthesizer:
    NAME = "chain_synthesizer"

    def __init__(self, runtime: "AgentRuntime", model: str) -> None:
        self.runtime = runtime
        self.model = model

    async def synthesize(self, hypotheses: list[Hypothesis]) -> ChainSynthesisResult:
        if len(hypotheses) < 2:
            return ChainSynthesisResult(
                chains=[],
                status="insufficient_hypotheses",
                hypothesis_count=len(hypotheses),
            )

        system = load_prompt("chain_synthesis")
        compact = [_compact_hypothesis(h) for h in hypotheses]
        user = (
            "Identify exploit chains in the following hypothesis list. "
            "Apply the rules strictly. Empty output is valid.\n\n"
            f"HYPOTHESES:\n{json.dumps(compact, indent=2)}"
        )

        try:
            result = await self.runtime.run(
                agent_name=self.NAME,
                model=self.model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                output_schema=_ChainList,
            )
            chains: list[ChainEntry] = result.output.root
        except Exception as e:
            logger.warning("chain_synthesizer crashed: %s — marking chain stage failed", e)
            return ChainSynthesisResult(
                chains=[],
                status="failed",
                hypothesis_count=len(hypotheses),
                error=str(e),
            )

        valid_ids = {h.id for h in hypotheses}
        clean: list[ChainEntry] = []
        dropped_self_or_single = 0
        dropped_unknown = 0
        for c in chains:
            unique_ids = list(dict.fromkeys(c.ids))
            if len(unique_ids) < 2:
                dropped_self_or_single += 1
                logger.info("chain_synthesizer: dropping chain with <2 unique ids: %s", c.ids)
                continue
            unknown = [i for i in unique_ids if i not in valid_ids]
            if unknown:
                dropped_unknown += 1
                logger.info("chain_synthesizer: dropping chain referencing unknown ids %s", unknown)
                continue
            clean.append(ChainEntry(
                ids=unique_ids,
                impact=c.impact,
                severity_bump=c.severity_bump,
                bypass_mechanism=c.bypass_mechanism,
            ))
        return ChainSynthesisResult(
            chains=clean,
            status="complete",
            hypothesis_count=len(hypotheses),
            raw_chain_count=len(chains),
            accepted_chain_count=len(clean),
            dropped_self_or_single_count=dropped_self_or_single,
            dropped_unknown_id_count=dropped_unknown,
        )


def annotate_hypotheses(
    hypotheses: list[Hypothesis],
    chains: list[ChainEntry],
) -> list[Hypothesis]:
    """Return a copy of hypotheses with chain annotations merged in.

    A hypothesis appearing in multiple chains gets the strongest severity_bump and
    a joined chain_impact. chains_with accumulates all partner IDs.
    """
    by_id: dict[str, list[ChainEntry]] = {}
    for c in chains:
        for hid in c.ids:
            by_id.setdefault(hid, []).append(c)

    bump_rank = {
        None: 0,
        "low->medium": 1, "low->high": 3, "low->critical": 4,
        "medium->high": 2, "medium->critical": 4,
        "high->critical": 3,
    }
    out: list[Hypothesis] = []
    for h in hypotheses:
        cs = by_id.get(h.id, [])
        if not cs:
            out.append(h)
            continue
        partners: list[str] = []
        impacts: list[str] = []
        best_bump: Optional[str] = None
        best_rank = -1
        for c in cs:
            for pid in c.ids:
                if pid != h.id and pid not in partners:
                    partners.append(pid)
            impacts.append(c.impact)
            r = bump_rank.get(c.severity_bump, 0)
            if r > best_rank:
                best_rank = r
                best_bump = c.severity_bump
        out.append(h.model_copy(update={
            "chains_with": partners,
            "chain_impact": " | ".join(impacts),
            "chain_severity_bump": best_bump,
        }))
    return out
