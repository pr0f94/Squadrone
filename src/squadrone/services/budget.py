"""Budget tracker — accumulates LLM spend and enforces a hard ceiling.

Anthropic prompt-cache pricing (per Anthropic docs):
  - Cache write: 1.25× the base input rate
  - Cache read: 0.10× the base input rate (90% off)

We track prompt_tokens (uncached input), cache_creation_input_tokens, and
cache_read_input_tokens separately so cost reflects actual cache behaviour and
we can see the cache hit rate on each scan.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

COST_PER_1M: dict[str, dict[str, float]] = {
    "claude-opus-4-5": {"input": 15.00, "output": 75.00},
    "claude-sonnet-4-5": {"input": 3.00, "output": 15.00},
    "claude-haiku-4-5-20251001": {"input": 0.80, "output": 4.00},
}

CACHE_WRITE_MULT = 1.25
CACHE_READ_MULT = 0.10


class BudgetExceededError(Exception):
    pass


@dataclass
class CallRecord:
    """Per-LLM-call record for stage/agent cost attribution."""
    stage: str
    agent: str
    model: str
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int
    cache_write_tokens: int
    cost_usd: float


def _get(usage: Any, key: str) -> int:
    """Pull a token-count field from either an object or a dict."""
    val = getattr(usage, key, None)
    if val is None and isinstance(usage, dict):
        val = usage.get(key, 0)
    return int(val or 0)


class BudgetTracker:
    def __init__(self, ceiling_usd: float):
        self.ceiling = ceiling_usd
        self.spent = 0.0
        # Telemetry — totals across the run, useful for verifying cache hits.
        self.input_tokens = 0
        self.output_tokens = 0
        self.cache_write_tokens = 0
        self.cache_read_tokens = 0
        self._lock = asyncio.Lock()
        # Per-call attribution. Set current_stage from the orchestrator at each stage
        # boundary; each call_llm passes its agent_name. Cheap (one append per call).
        self.current_stage: str = "unknown"
        self.calls: list[CallRecord] = []

    @property
    def cache_hit_rate(self) -> float:
        """Fraction of input tokens served from cache (0.0 to 1.0)."""
        total_in = self.input_tokens + self.cache_write_tokens + self.cache_read_tokens
        if total_in == 0:
            return 0.0
        return self.cache_read_tokens / total_in

    def set_stage(self, stage: str) -> None:
        """Tag subsequent LLM calls with this stage name. Called by the orchestrator."""
        self.current_stage = stage

    def per_stage_summary(self) -> dict[str, dict[str, float]]:
        """Aggregate {stage: {calls, cost_usd, input, output, cache_read, cache_write}}."""
        agg: dict[str, dict[str, float]] = defaultdict(lambda: {
            "calls": 0, "cost_usd": 0.0,
            "input_tokens": 0, "output_tokens": 0,
            "cache_read_tokens": 0, "cache_write_tokens": 0,
        })
        for r in self.calls:
            s = agg[r.stage]
            s["calls"] += 1
            s["cost_usd"] += r.cost_usd
            s["input_tokens"] += r.input_tokens
            s["output_tokens"] += r.output_tokens
            s["cache_read_tokens"] += r.cache_read_tokens
            s["cache_write_tokens"] += r.cache_write_tokens
        return dict(agg)

    def write_cost_report(self, run_dir: str | Path) -> Path:
        """Write per-call TSV + per-stage summary TSV to the run dir. Returns the summary path."""
        run_dir = Path(run_dir)
        run_dir.mkdir(parents=True, exist_ok=True)
        calls_path = run_dir / "cost_calls.tsv"
        with calls_path.open("w") as f:
            f.write("stage\tagent\tmodel\tinput\toutput\tcache_read\tcache_write\tcost_usd\n")
            for r in self.calls:
                f.write(
                    f"{r.stage}\t{r.agent}\t{r.model}\t{r.input_tokens}\t{r.output_tokens}\t"
                    f"{r.cache_read_tokens}\t{r.cache_write_tokens}\t{r.cost_usd:.6f}\n"
                )
        summary_path = run_dir / "cost_per_stage.tsv"
        with summary_path.open("w") as f:
            f.write("stage\tcalls\tcost_usd\tinput\toutput\tcache_read\tcache_write\tcache_hit_rate\n")
            for stage, s in sorted(self.per_stage_summary().items(), key=lambda kv: -kv[1]["cost_usd"]):
                total_in = s["input_tokens"] + s["cache_read_tokens"] + s["cache_write_tokens"]
                hit = (s["cache_read_tokens"] / total_in) if total_in else 0.0
                f.write(
                    f"{stage}\t{int(s['calls'])}\t{s['cost_usd']:.6f}\t"
                    f"{int(s['input_tokens'])}\t{int(s['output_tokens'])}\t"
                    f"{int(s['cache_read_tokens'])}\t{int(s['cache_write_tokens'])}\t{hit:.3f}\n"
                )
        return summary_path

    async def add(self, usage: Any, model: str, agent: str = "unknown") -> None:
        rates = COST_PER_1M.get(model, {"input": 3.0, "output": 15.0})
        # Standard fields
        prompt_tokens = _get(usage, "prompt_tokens")
        completion_tokens = _get(usage, "completion_tokens")
        # Anthropic-specific cache fields (passed through by litellm)
        cache_write = _get(usage, "cache_creation_input_tokens")
        cache_read = _get(usage, "cache_read_input_tokens")
        # litellm sometimes nests cache info under prompt_tokens_details
        if cache_write == 0 and cache_read == 0:
            details = getattr(usage, "prompt_tokens_details", None) or (
                usage.get("prompt_tokens_details") if isinstance(usage, dict) else None
            )
            if details:
                cache_read = _get(details, "cached_tokens")
        # The "uncached input" is what's billed at base rate. cache_write_tokens are
        # billed at 1.25x; cache_read_tokens at 0.10x. prompt_tokens from the API
        # already EXCLUDES the cached input on Anthropic, so we add them separately.
        uncached_input = max(prompt_tokens - cache_read - cache_write, 0)
        cost = (
            uncached_input * rates["input"]
            + cache_write * rates["input"] * CACHE_WRITE_MULT
            + cache_read * rates["input"] * CACHE_READ_MULT
            + completion_tokens * rates["output"]
        ) / 1_000_000
        async with self._lock:
            self.input_tokens += uncached_input
            self.output_tokens += completion_tokens
            self.cache_write_tokens += cache_write
            self.cache_read_tokens += cache_read
            self.spent += cost
            self.calls.append(CallRecord(
                stage=self.current_stage,
                agent=agent,
                model=model,
                input_tokens=uncached_input,
                output_tokens=completion_tokens,
                cache_read_tokens=cache_read,
                cache_write_tokens=cache_write,
                cost_usd=cost,
            ))
            if self.spent >= self.ceiling:
                raise BudgetExceededError(
                    f"Budget ceiling ${self.ceiling:.2f} reached (spent ${self.spent:.2f})"
                )
