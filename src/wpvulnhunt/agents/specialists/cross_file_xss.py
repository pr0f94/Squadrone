"""Cross-file stored-XSS specialist — receives the full corpus, not a filtered subset.

Opt-in via the --cross-file-taint flag. Other specialists see a pattern-filtered
subset of files (~50-70% reduction), which by design hides the write/read pairs
this specialist depends on. Wiring this up costs the full-corpus input on every
invocation, which is why it is gated behind a flag.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ...schemas.hypothesis import HypothesesArtifact
from ...schemas.config import HypothesisConfig
from ...schemas.recon import ReconArtifact
from .._specialist_base import run_specialist

if TYPE_CHECKING:
    from ..runtime import AgentRuntime


class CrossFileXssSpecialist:
    NAME = "cross_file_xss"
    PROMPT = "specialists/cross_file_xss"

    def __init__(self, runtime: "AgentRuntime", model: str):
        self.runtime = runtime
        self.model = model

    async def analyze(
        self,
        recon: ReconArtifact,
        code_slices: dict[str, str],
        hypothesis_cfg: HypothesisConfig | None = None,
        diff_summary: str | None = None,
        plugin_path: str | None = None,
        priority_files: list[str] | None = None,
    ) -> HypothesesArtifact:
        return await run_specialist(
            runtime=self.runtime,
            name=self.NAME,
            prompt_path=self.PROMPT,
            model=self.model,
            recon=recon,
            code_slices=code_slices,
            hypothesis_cfg=hypothesis_cfg,
            diff_summary=diff_summary,
            plugin_path=plugin_path,
            priority_files=priority_files,
        )
