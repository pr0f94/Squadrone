"""Pipeline configuration schema (loaded from pipelines/*.yaml)."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel


class ModelConfig(BaseModel):
    critic: str
    developer: str  # propose_setup (initial) + consult — Opus-tier reasoning
    surveyor: str
    poc_author: str
    specialists: str
    reporter: str
    dedup_fallback: str
    hypothesis_verifier: str = "claude-haiku-4-5-20251001"  # cheap source-quote check
    # propose_setup_followup is a structured diagnostic task — Sonnet handles it fine
    # at ~30% the cost of Opus. Falls back to `developer` if not set.
    developer_followup: str = "claude-sonnet-4-6"
    # Used only when --chain flag is enabled. Defaults to the same tier as critic.
    chain_synthesizer: str = "claude-opus-4-6"


ReasoningEffort = Literal["none", "minimal", "low", "medium", "high", "xhigh", "default"]
Verbosity = Literal["low", "medium", "high"]


class LLMConfig(BaseModel):
    """Provider-level generation controls passed through to LiteLLM."""

    reasoning_effort: ReasoningEffort | None = None
    verbosity: Verbosity | None = None


class ReasoningConfig(BaseModel):
    """Optional per-role reasoning-effort overrides.

    These override `llm.reasoning_effort` for matching roles only. Specialist
    implementation names such as `auth`, `xss`, and `file_ops` map to the
    `specialists` role.
    """

    critic: ReasoningEffort | None = None
    developer: ReasoningEffort | None = None
    developer_followup: ReasoningEffort | None = None
    surveyor: ReasoningEffort | None = None
    poc_author: ReasoningEffort | None = None
    specialists: ReasoningEffort | None = None
    reporter: ReasoningEffort | None = None
    dedup_fallback: ReasoningEffort | None = None
    hypothesis_verifier: ReasoningEffort | None = None
    chain_synthesizer: ReasoningEffort | None = None


class SandboxConfig(BaseModel):
    wordpress_image: str
    db_image: str
    wp_admin_user: str
    wp_admin_pass: str
    wp_admin_email: str
    wp_url: str


class VulnDbSourceConfig(BaseModel):
    base_url: str


class VulnDbConfig(BaseModel):
    wordfence: VulnDbSourceConfig
    wpscan: VulnDbSourceConfig


class IntakeConfig(BaseModel):
    """Stage 1 (intake) opt-in features. All default off — additive metadata only."""
    bundle_wp_core: bool = False           # #1: cache WP core source for downstream grep
    classify_files: bool = False           # #2: bucket files admin/frontend/vendor/tests/lang
    fetch_changelog: bool = False          # #4: parse readme.txt Changelog into structured data
    detect_closed: bool = False            # #6: bail early if wp.org marks plugin closed
    wp_core_version: str = "latest"        # used when bundle_wp_core=True


class ReconConfig(BaseModel):
    """Stage 2 (recon) opt-in features. All default off."""
    deterministic_analysis: bool = False   # static hook/callback/callee metadata for grounding
    validate_entry_points: bool = False    # #1: per-entry-point LLM validation pass with citations
    trace_cross_file_callees: bool = False # #2: regex-based call-graph for handler bodies
    scan_nonce_emissions: bool = False     # #3: PHP+JS scan for wp_create_nonce / wp_localize_script
    exclude_vendor_tests_lang: bool = False# #4: skip files in those buckets (needs intake.classify_files)
    enrich_entry_points: bool = False      # #5+#6: extract body_slice + confidence for each entry point
    negative_pattern_reference: bool = False # #7: include "what NOT to flag" guidance in surveyor prompt
    cache_enabled: bool = False            # #8: cache recon.json keyed by (slug, version, config)
    max_entries_to_validate: int = 30      # cost-cap for #1 — top-N entries by confidence


class ReportConfig(BaseModel):
    """Stage 7 (report) opt-in features. All default off."""
    claim_validation_pass: bool = False    # R1: post-report critic that checks every claim cites source
    submission_readiness_gate: bool = False # R2: emit *_NOT_READY.md when prerequisites missing
    poc_bundling: bool = False             # R4: write plugins/<slug>/submissions/<finding_id>/ bundle
    screenshot_capture: bool = False       # R5: screenshot during verify when W2 toggle is also on
    submission_json: bool = False          # R7: alongside report.md, emit wordfence/patchstack submission JSON


class DedupConfig(BaseModel):
    """Stage 6 (dedup) opt-in features. All default off."""
    meaningful_scoring: bool = False        # D1: per-match similarity scoring beyond bug_class match
    submission_recommendation: bool = False # D4: emit submit_as_novel / regression_of / skip_dupe / rebuttal
    review_md_signal: bool = False          # D5: parse plugins/<slug>/review.md for past-FP signals


class VerifyConfig(BaseModel):
    """Stage 5 (verify) opt-in features. All default off.

    W1 (proper HTML parser context detection) is implemented unconditionally inside
    xss_check.py — there's no toggle because it's a pure bug-fix; the broken heuristic
    is gone for everyone.
    """
    headless_browser_check: bool = False        # W2: Playwright execution check
    persistent_sandbox: bool = False            # W3: one sandbox boot per scan, snapshot/restore between PoCs
    payload_variants: bool = False              # W4: test multiple payload variants per hypothesis
    state_introspection_on_failure: bool = False # W5: dump DB/uploads/error.log on persistent fail
    manual_review_handoff: bool = False         # W6: emit manual-review queue + sandbox scaffold on fail
    negative_control: bool = False              # W8: differential reflection check w/ benign marker
    collaborative_dev_poc_loop: bool = False    # W9: PoC author can call developer mid-iteration
    cache_enabled: bool = False                 # W10: cache verify outcomes per (hypothesis, version)
    payload_variant_cap: int = 6                # cost-cap for W4
    headless_browser_timeout_s: int = 15        # W2: per-page render budget


class TriageConfig(BaseModel):
    """Stage 4 (triage critic) opt-in features. All default off."""
    inject_review_md: bool = False        # T2: load plugins/<slug>/review.md into critic context
    cluster_aware: bool = False           # T3: pre-cluster hypotheses by (file, line, bug_class)
    allow_reframing: bool = False         # T4: critic can output `request_reframing` decisions
    drift_logging: bool = False           # T5: append every decision to cache/triage_decisions.jsonl
    cache_enabled: bool = False           # T6: cache triage results per (hypotheses_hash, plugin_version, scope)
    review_md_max_chars: int = 12000      # T2 size cap so review.md doesn't blow up the prompt


class HypothesisConfig(BaseModel):
    """Stage 3 (hypothesis specialists + verifier) opt-in features. All default off."""
    # Specialists
    specialist_grep_read_tools: bool = False   # S1: expose read_plugin_file + grep tools to specialists
    specialist_wp_idioms: bool = False         # S2 + X2: append _wp_idioms.md to specialist prompts
    require_branch_enumeration: bool = False   # S3: require taint_path_branches in output
    require_exploit_classification: bool = False  # S4: require exploit_classification block
    require_bounty_fit_pretagging: bool = False   # S5: require bounty_fit block
    self_critique_pass: bool = False           # S7: second LLM pass per specialist to flag uncited claims
    # Verifier
    iterative_verifier: bool = False           # V1: multi-pass verifier with grep/read tools
    verifier_max_iterations: int = 3           # iteration cap for V1
    verifier_require_citation: bool = False    # V3: drop reasons must cite file:line
    verifier_wp_idioms: bool = False           # V4 + X2: append _wp_idioms.md to verifier prompt
    verifier_drop_categorisation: bool = False # V5: 5-state verdicts instead of binary keep/drop
    verifier_cache_enabled: bool = False       # V7: cache verifier decisions per (hypothesis_hash, plugin_version)
    # Cross-cutting
    pre_verifier_dedup: bool = False           # X1: merge near-duplicate hypotheses before verifier runs


class PipelineConfig(BaseModel):
    cost_ceiling_usd: float
    max_hypotheses_to_verify: int
    sandbox_timeout_seconds: int
    verify_max_iterations: int
    developer_calls_per_agent: int
    models: ModelConfig
    sandbox: SandboxConfig
    vuln_dbs: VulnDbConfig
    stages: list[str]
    llm: LLMConfig = LLMConfig()
    reasoning: ReasoningConfig = ReasoningConfig()
    intake: IntakeConfig = IntakeConfig()  # default-off, fully backward-compatible
    recon: ReconConfig = ReconConfig()     # default-off, fully backward-compatible
    hypothesis: HypothesisConfig = HypothesisConfig()  # default-off, fully backward-compatible
    triage: TriageConfig = TriageConfig()  # default-off, fully backward-compatible
    verify: VerifyConfig = VerifyConfig()  # default-off, fully backward-compatible
    dedup: DedupConfig = DedupConfig()     # default-off, fully backward-compatible
    report: ReportConfig = ReportConfig()  # default-off, fully backward-compatible

    @classmethod
    def from_yaml(cls, path: str) -> "PipelineConfig":
        data = yaml.safe_load(Path(path).read_text())
        return cls.model_validate(data)

    def llm_options_for_role(self, role: str) -> dict:
        """Return LiteLLM keyword args for a configured role."""
        opts = self.llm.model_dump(exclude_none=True)
        role_effort = getattr(self.reasoning, role, None)
        if role_effort is not None:
            opts["reasoning_effort"] = role_effort
        return opts
