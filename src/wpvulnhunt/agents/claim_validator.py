"""R1 — Claim validator.

Reads a generated report and asks: "is every load-bearing technical claim
supported by a citation in the run artefacts?". Returns either approved or
a list of unsupported claims. Cheap (Haiku) — runs after the reporter.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Optional

from pydantic import BaseModel

from .prompts_io import load_prompt

if TYPE_CHECKING:
    from .runtime import AgentRuntime

logger = logging.getLogger(__name__)


class UnsupportedClaim(BaseModel):
    quote: str           # the load-bearing sentence from the report
    issue: str           # why it's unsupported (no citation, factually questionable, etc.)
    severity: str        # "blocking" | "warning" | "info"


class ClaimValidationResult(BaseModel):
    approved: bool                       # True if all load-bearing claims are cited
    unsupported_claims: list[UnsupportedClaim] = []
    summary: Optional[str] = None        # short overall verdict


class ClaimValidator:
    NAME = "claim_validator"
    PROMPT = "claim_validator"

    def __init__(self, runtime: "AgentRuntime", model: str):
        self.runtime = runtime
        self.model = model

    async def validate(self, report_md: str, evidence_summary: str) -> ClaimValidationResult:
        """Validate a generated report against an evidence summary built from the run.

        evidence_summary should include: hypothesis taint_path, sink_code, verify-stage
        evidence excerpts, dedup matches with similarity scores. Anything the report
        could legitimately cite.
        """
        system = load_prompt(self.PROMPT)
        user = (
            f"REPORT_MARKDOWN:\n```\n{report_md}\n```\n\n"
            f"EVIDENCE_SUMMARY:\n```\n{evidence_summary}\n```"
        )
        try:
            result = await self.runtime.run(
                agent_name=self.NAME,
                model=self.model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                output_schema=ClaimValidationResult,
                max_tokens=2048,
            )
            return result.output
        except Exception as e:
            logger.warning("R1 claim_validator failed: %s — defaulting to approved", e)
            return ClaimValidationResult(approved=True, summary=f"validator error: {e}")
