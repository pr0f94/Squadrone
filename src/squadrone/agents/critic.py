"""Critic — adversarial reviewer over specialist hypotheses."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from ..schemas.hypothesis import HypothesesArtifact, TriagedArtifact
from .prompts_io import load_prompt
from .tools import CONSULT_DEVELOPER_TOOL

if TYPE_CHECKING:
    from .runtime import AgentRuntime

logger = logging.getLogger(__name__)


_V2_ADVERSARIAL_INSTRUCTIONS = """

# Squadrone V2 adversarial review

Every triage pass must include a rejection attempt before accepting a
hypothesis. For each hypothesis, ask:

1. What is the strongest technical reason this is not exploitable?
2. What is the strongest Patchstack or Wordfence rejection reason?
3. Is attacker control actually proven from source to sink?
4. Is the lowest claimed role realistic?
5. Is the affected feature enabled by default and present in the current
   unmodified component?
6. Is there a concrete security impact, not just weird behavior?
7. Is object ownership/payment/approval/token binding actually violated?

If the hypothesis survives those questions, accept it. If it does not, reject
with the clearest failure reason. Prefer a useful rejection over a weak manual
queue item.
"""

class CriticAgent:
    NAME = "critic"
    PROMPT = "critic"

    def __init__(self, runtime: "AgentRuntime", model: str):
        self.runtime = runtime
        self.model = model

    def _build_system_prompt(self) -> str:
        return load_prompt(self.PROMPT) + _V2_ADVERSARIAL_INSTRUCTIONS

    async def review(
        self,
        hypotheses: HypothesesArtifact,
        code_slices: dict[str, str],
        apply_scope_filter: bool = True,
    ) -> TriagedArtifact:
        system = self._build_system_prompt()
        user_payload: dict = {
            "plugin_slug": hypotheses.plugin_slug,
            "hypotheses": hypotheses.model_dump()["hypotheses"],
            "code_slices": code_slices,
        }
        user_parts = [json.dumps(user_payload, default=str)]
        if apply_scope_filter:
            # T1: bounty-program scope docs (already in place pre-stage-4 — confirmed kept)
            wf_scope = load_prompt("wordfence_scope")
            ps_scope = load_prompt("patchstack_scope")
            user_parts.append("WORDFENCE_SCOPE:\n" + wf_scope)
            user_parts.append("PATCHSTACK_SCOPE:\n" + ps_scope)
        user = "\n\n".join(user_parts)

        result = await self.runtime.run(
            agent_name=self.NAME,
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            tools=[CONSULT_DEVELOPER_TOOL],
            output_schema=TriagedArtifact,
        )
        art: TriagedArtifact = result.output
        return art
