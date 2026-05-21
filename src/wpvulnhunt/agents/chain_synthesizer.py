"""Chain synthesizer — identifies exploit chains across hypotheses from different specialists.

Opt-in stage (--chain flag). Runs after hypothesis, before triage. Emits annotations
on existing hypotheses (chains_with / chain_impact / chain_severity_bump) rather than
new entries.
"""

from __future__ import annotations

import json
import logging
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


class ChainSynthesizer:
    NAME = "chain_synthesizer"

    def __init__(self, runtime: "AgentRuntime", model: str) -> None:
        self.runtime = runtime
        self.model = model

    async def synthesize(self, hypotheses: list[Hypothesis]) -> list[ChainEntry]:
        if len(hypotheses) < 2:
            return []

        system = load_prompt("chain_synthesis")
        compact = [
            {
                "id": h.id,
                "specialist": h.specialist,
                "bug_class": h.bug_class.value,
                "entry_point": h.entry_point,
                "file": h.file,
                "line": h.line,
                "sink": h.sink,
                "preconditions": h.preconditions,
                "confidence": h.confidence.value,
            }
            for h in hypotheses
        ]
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
            logger.warning("chain_synthesizer crashed: %s — emitting no chains", e)
            return []

        valid_ids = {h.id for h in hypotheses}
        clean: list[ChainEntry] = []
        for c in chains:
            unique_ids = list(dict.fromkeys(c.ids))
            if len(unique_ids) < 2:
                logger.info("chain_synthesizer: dropping chain with <2 unique ids: %s", c.ids)
                continue
            unknown = [i for i in unique_ids if i not in valid_ids]
            if unknown:
                logger.info("chain_synthesizer: dropping chain referencing unknown ids %s", unknown)
                continue
            clean.append(ChainEntry(
                ids=unique_ids,
                impact=c.impact,
                severity_bump=c.severity_bump,
                bypass_mechanism=c.bypass_mechanism,
            ))
        return clean


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
