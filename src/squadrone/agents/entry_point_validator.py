"""Stage-2 #1 — Per-entry-point validation pass.

After the surveyor produces an initial entry-point list with auth/nonce/cap flags
derived from grep-pattern co-occurrence (which is unreliable — see wp-statistics auth-001
where conditional capability gates were ticked at file-level), this validator re-reads
each entry point's actual function body and re-asserts the gating decision with
file:line citations.

Uses Haiku — cheap, structured output. Capped to top-N entries by confidence to bound cost.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Optional

from pydantic import BaseModel

from .prompts_io import load_prompt

if TYPE_CHECKING:
    from .runtime import AgentRuntime
    from ..schemas.recon import EntryPoint

logger = logging.getLogger(__name__)


class EntryPointValidation(BaseModel):
    auth_gating: str    # "logged_in_only" | "capability:<X>" | "nonce_only:<action>" | "none" | "mixed"
    nonce_action: Optional[str] = None
    capability: Optional[str] = None
    citation: Optional[str] = None    # "file:line — quote of the gating call"
    notes: Optional[str] = None


class EntryPointValidator:
    NAME = "entry_point_validator"
    PROMPT = "entry_point_validator"

    def __init__(self, runtime: "AgentRuntime", model: str):
        self.runtime = runtime
        self.model = model

    async def validate_one(self, ep: "EntryPoint") -> EntryPointValidation | None:
        """Validate a single entry point. Returns None if no body_slice available."""
        if not ep.body_slice:
            return None
        system = load_prompt(self.PROMPT)
        user = json.dumps({
            "entry_point": {
                "type": ep.type,
                "name": ep.name,
                "file": ep.file,
                "line": ep.line,
                "handler_function": ep.handler_function,
            },
            "body_slice": ep.body_slice,
        })
        try:
            result = await self.runtime.run(
                agent_name=self.NAME,
                model=self.model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                output_schema=EntryPointValidation,
                max_tokens=1024,
            )
            return result.output
        except Exception as e:
            logger.warning("entry_point_validator: failed for %s (%s)", ep.handler_function, e)
            return None
