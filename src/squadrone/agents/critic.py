"""Critic — adversarial reviewer over specialist hypotheses."""

from __future__ import annotations

import hashlib
import json
import logging
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

from ..schemas.hypothesis import HypothesesArtifact, TriagedArtifact
from .prompts_io import load_prompt
from .tools import CONSULT_DEVELOPER_TOOL

if TYPE_CHECKING:
    from .runtime import AgentRuntime

logger = logging.getLogger(__name__)

CACHE_DIR = Path("cache/triage")
DRIFT_LOG_PATH = Path("cache/triage_decisions.jsonl")


# T3: cluster hypotheses by (file, line, bug_class) — same key as X1 dedup but used here for
# group-judgement awareness rather than merging. Critic gets the cluster map in the user
# payload so it can make consistent decisions across related hypotheses.
def _cluster_hypotheses(hypotheses: list[dict]) -> dict[str, list[str]]:
    """Return {cluster_id: [hypothesis_id, ...]} grouped by (file, line, bug_class)."""
    groups: dict[tuple, list[str]] = defaultdict(list)
    for h in hypotheses:
        key = (h.get("file", ""), h.get("line", 0), h.get("bug_class", ""))
        groups[key].append(h.get("id", ""))
    out: dict[str, list[str]] = {}
    for i, (_key, ids) in enumerate(groups.items()):
        if len(ids) > 1:  # only label clusters of 2+
            out[f"cluster_{i}"] = ids
    return out


# T6: triage caching. Cache key includes hypotheses signature, plugin slug+version,
# and toggles that affect the prompt.
def _triage_cache_key(
    hypotheses: HypothesesArtifact,
    plugin_version: str,
    apply_scope_filter: bool,
    review_md_present: bool,
    cluster_aware: bool,
    allow_reframing: bool,
) -> str:
    payload = json.dumps({
        "slug": hypotheses.plugin_slug,
        "version": plugin_version,
        "scope": apply_scope_filter,
        "review_md": review_md_present,
        "cluster": cluster_aware,
        "reframing": allow_reframing,
        "hyp_signature": hashlib.sha256(
            json.dumps([h.model_dump(mode="json") for h in hypotheses.hypotheses],
                       sort_keys=True).encode()
        ).hexdigest()[:16],
    }, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def _triage_cache_load(key: str) -> TriagedArtifact | None:
    p = CACHE_DIR / f"{key}.json"
    if not p.exists():
        return None
    try:
        return TriagedArtifact.model_validate_json(p.read_text())
    except (OSError, ValueError):
        return None


def _triage_cache_save(key: str, art: TriagedArtifact) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    (CACHE_DIR / f"{key}.json").write_text(art.model_dump_json(indent=2))


# T5: drift log. Append-only JSONL so we can analyse decision patterns over time.
def _log_drift(plugin_slug: str, plugin_version: str, art: TriagedArtifact) -> None:
    try:
        DRIFT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with DRIFT_LOG_PATH.open("a") as f:
            ts = datetime.now(timezone.utc).isoformat()
            for h in art.accepted:
                f.write(json.dumps({
                    "ts": ts, "slug": plugin_slug, "version": plugin_version,
                    "hypothesis_id": h.id, "decision": "accepted",
                    "bug_class": h.bug_class.value, "confidence": h.confidence.value,
                    "bounty_programs": h.bounty_programs,
                }) + "\n")
            for r in art.rejected:
                f.write(json.dumps({
                    "ts": ts, "slug": plugin_slug, "version": plugin_version,
                    "hypothesis_id": r.get("hypothesis_id"), "decision": "rejected",
                    "reason": (r.get("reason") or "")[:300],
                }) + "\n")
            for m in art.merged:
                f.write(json.dumps({
                    "ts": ts, "slug": plugin_slug, "version": plugin_version,
                    "hypothesis_id": m.get("merged_from_id"), "decision": "merged",
                    "kept_id": m.get("kept_id"),
                }) + "\n")
            for rf in art.request_reframing:
                f.write(json.dumps({
                    "ts": ts, "slug": plugin_slug, "version": plugin_version,
                    "hypothesis_id": rf.get("hypothesis_id"), "decision": "request_reframing",
                    "suggested": (rf.get("suggested_framing") or "")[:200],
                }) + "\n")
    except OSError as e:
        logger.warning("triage drift log write failed: %s", e)


# T4: prompt extension allowing the critic to emit `request_reframing` entries
_T4_REFRAMING_INSTRUCTIONS = """

# T4: request_reframing decision

In addition to accepted/rejected/merged, you may populate `request_reframing` for
hypotheses where the bug-shape is interesting but the framing is wrong (e.g. an
"unauth file upload" hypothesis on an intentionally-unauth registration endpoint
should be reframed as "anonymous upload that doesn't honour users_can_register=0
+ stored XSS chain via uploaded SVG"). Each entry:
```json
{
  "hypothesis_id": "<id>",
  "suggested_framing": "<one-sentence reframe>",
  "reason_original_rejected": "<why the original framing fails>"
}
```
Do NOT also add the same id to `rejected`. The reframing entry IS the decision.
"""


# T3: prompt extension for cluster-aware decisions
_T3_CLUSTER_INSTRUCTIONS = """

# T3: Cluster-aware decisions

The user payload includes `clusters` — groups of hypotheses sharing (file, line,
bug_class). Hypotheses in the same cluster usually share their fate: if you reject
one because the chain is broken, the others in the same cluster likely have the
same broken chain. Apply consistent verdicts across clusters and call this out
explicitly in your `rejected[].reason` ("rejected as part of cluster_N: <reason>").
"""


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


_V2_ADVERSARIAL_MODE = """

# Dedicated adversarial vote mode

This pass is the adversarial reviewer. Your default posture is rejection. Accept
only if you cannot identify a solid technical, scope, default-configuration,
attacker-control, or impact reason to reject. Your rejection reasons should be
written as if explaining why a bounty triager would close the report.
"""


class CriticAgent:
    NAME = "critic"
    PROMPT = "critic"

    def __init__(
        self,
        runtime: "AgentRuntime",
        model: str,
        *,
        # T2-T6 toggle wiring (all default-off so existing callers are unaffected)
        inject_review_md: bool = False,
        cluster_aware: bool = False,
        allow_reframing: bool = False,
        drift_logging: bool = False,
        cache_enabled: bool = False,
        review_md_max_chars: int = 12000,
        plugin_version: str = "",
        review_mode: str = "standard",
    ):
        self.runtime = runtime
        self.model = model
        self.inject_review_md = inject_review_md
        self.cluster_aware = cluster_aware
        self.allow_reframing = allow_reframing
        self.drift_logging = drift_logging
        self.cache_enabled = cache_enabled
        self.review_md_max_chars = review_md_max_chars
        self.plugin_version = plugin_version
        self.review_mode = review_mode

    def _build_system_prompt(self) -> str:
        parts = [load_prompt(self.PROMPT), _V2_ADVERSARIAL_INSTRUCTIONS]
        if self.cluster_aware:
            parts.append(_T3_CLUSTER_INSTRUCTIONS)
        if self.allow_reframing:
            parts.append(_T4_REFRAMING_INSTRUCTIONS)
        if self.review_mode == "adversarial":
            parts.append(_V2_ADVERSARIAL_MODE)
        return "".join(parts)

    def _load_review_md(self, plugin_slug: str) -> str | None:
        """T2: pull plugins/<slug>/review.md if it exists; cap to review_md_max_chars."""
        path = Path("plugins") / plugin_slug / "review.md"
        if not path.exists():
            return None
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return None
        if len(text) > self.review_md_max_chars:
            text = text[:self.review_md_max_chars] + "\n\n[...truncated by triage review_md_max_chars cap...]"
        return text

    async def review(
        self,
        hypotheses: HypothesesArtifact,
        code_slices: dict[str, str],
        apply_scope_filter: bool = True,
    ) -> TriagedArtifact:
        review_md_text = self._load_review_md(hypotheses.plugin_slug) if self.inject_review_md else None
        clusters = _cluster_hypotheses(
            [h.model_dump() for h in hypotheses.hypotheses]
        ) if self.cluster_aware else {}

        # T6: cache check (BEFORE the LLM call)
        cache_key: str | None = None
        if self.cache_enabled:
            cache_key = _triage_cache_key(
                hypotheses, self.plugin_version, apply_scope_filter,
                review_md_present=bool(review_md_text), cluster_aware=self.cluster_aware,
                allow_reframing=self.allow_reframing,
            )
            cached = _triage_cache_load(cache_key)
            if cached is not None:
                logger.info("triage: cache hit %s — reusing", cache_key)
                if self.drift_logging:
                    _log_drift(hypotheses.plugin_slug, self.plugin_version, cached)
                return cached

        system = self._build_system_prompt()
        user_payload: dict = {
            "plugin_slug": hypotheses.plugin_slug,
            "hypotheses": hypotheses.model_dump()["hypotheses"],
            "code_slices": code_slices,
            "review_mode": self.review_mode,
        }
        if clusters:
            user_payload["clusters"] = clusters
        if review_md_text:
            user_payload["plugin_review_md"] = review_md_text
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

        if cache_key:
            _triage_cache_save(cache_key, art)
        if self.drift_logging:
            _log_drift(hypotheses.plugin_slug, self.plugin_version, art)
        return art
