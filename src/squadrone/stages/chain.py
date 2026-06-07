"""Chain stage — optional cross-specialist exploit-chain synthesis.

Runs after `hypothesis`, before `triage`, only when --chain is set. Reads the
merged hypotheses.jsonl, asks an LLM to identify exploit chains, writes:

- `chains.json` — full chain list (for resume + audit)
- `hypotheses.jsonl` — rewritten with chain annotations merged into matching entries

Downstream stages see hypotheses with `chains_with`, `chain_impact`, and
`chain_severity_bump` populated where applicable. Existing fields are untouched.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from ..agents.chain_synthesizer import ChainSynthesizer, annotate_hypotheses
from ..agents.runtime import AgentRuntime
from ..schemas.config import PipelineConfig
from ..schemas.hypothesis import HypothesesArtifact

logger = logging.getLogger(__name__)


async def run(
    hypotheses: HypothesesArtifact,
    config: PipelineConfig,
    runtime: AgentRuntime,
    runs_root: str = "runs",
    run_id: str = "",
) -> HypothesesArtifact:
    if not hypotheses.hypotheses:
        logger.info("chain: no hypotheses to chain — skipping")
        out_dir = Path(runs_root) / run_id
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "chains.json").write_text("[]")
        (out_dir / "chain_diagnostics.json").write_text(json.dumps({
            "status": "insufficient_hypotheses",
            "hypothesis_count": 0,
            "raw_chain_count": 0,
            "accepted_chain_count": 0,
            "annotated_hypothesis_count": 0,
            "dropped_self_or_single_count": 0,
            "dropped_unknown_id_count": 0,
            "error": None,
        }, indent=2))
        return hypotheses

    synthesizer = ChainSynthesizer(runtime, model=config.models.chain_synthesizer)
    result = await synthesizer.synthesize(hypotheses.hypotheses)
    chains = result.chains
    logger.info("chain: synthesized %d chains from %d hypotheses",
                len(chains), len(hypotheses.hypotheses))

    out_dir = Path(runs_root) / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    chains_path = out_dir / "chains.json"
    chains_path.write_text(json.dumps([c.model_dump() for c in chains], indent=2))

    annotated = annotate_hypotheses(hypotheses.hypotheses, chains)
    hyps_path = out_dir / "hypotheses.jsonl"
    with hyps_path.open("w") as f:
        for h in annotated:
            f.write(h.model_dump_json() + "\n")

    annotated_count = sum(1 for h in annotated if h.chains_with)
    diagnostics = result.diagnostics()
    diagnostics["annotated_hypothesis_count"] = annotated_count
    (out_dir / "chain_diagnostics.json").write_text(json.dumps(diagnostics, indent=2))
    logger.info("chain: annotated %d hypotheses with chain info", annotated_count)
    return HypothesesArtifact(plugin_slug=hypotheses.plugin_slug, hypotheses=annotated)
