"""Critic — adversarial reviewer over specialist hypotheses."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from ..schemas.hypothesis import HypothesesArtifact, TriagedArtifact
from .plugin_tools import PluginToolHandlers
from .prompts_io import load_prompt
from .tools import CONSULT_DEVELOPER_TOOL

if TYPE_CHECKING:
    from .runtime import AgentRuntime

logger = logging.getLogger(__name__)


_ADVERSARIAL_INSTRUCTIONS = """

# Adversarial review

Every triage pass must include a rejection attempt before accepting a
hypothesis. For each hypothesis, ask:

1. What is the strongest technical reason this is not exploitable?
2. Is attacker control actually proven from source to sink?
3. Is the lowest claimed role realistic?
4. Is the affected feature enabled by default and present in the current
   unmodified component?
5. Is there a concrete security impact, not just weird behavior?
6. Is object ownership/approval/token binding actually violated?

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
        return load_prompt(self.PROMPT) + _ADVERSARIAL_INSTRUCTIONS

    async def review(
        self,
        hypotheses: HypothesesArtifact,
        code_slices: dict[str, str],
        plugin_path: str | None = None,
    ) -> TriagedArtifact:
        system = self._build_system_prompt()
        user_payload: dict = {
            "plugin_slug": hypotheses.plugin_slug,
            "hypotheses": hypotheses.model_dump()["hypotheses"],
            "code_slices": code_slices,
        }
        user_parts = [json.dumps(user_payload, default=str)]
        # Disclosure eligibility is deterministic and runs after this technical
        # review. The critic must not turn a valid vulnerability into a false
        # positive merely because one program would not accept it.
        user = "\n\n".join(user_parts)

        tools = [CONSULT_DEVELOPER_TOOL]
        tool_handlers = None
        if plugin_path:
            handlers = PluginToolHandlers(plugin_path)
            tools.extend(handlers.tool_definitions())
            tool_handlers = handlers.tool_handlers()
        result = await self.runtime.run(
            agent_name=self.NAME,
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            tools=tools,
            tool_handlers=tool_handlers,
            output_schema=TriagedArtifact,
        )
        art: TriagedArtifact = result.output
        return art
