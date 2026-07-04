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
    bundle_wp_core: bool = False           # cache WP core source for downstream grep
    classify_files: bool = False           # bucket files admin/frontend/vendor/tests/lang
    fetch_changelog: bool = False          # parse readme.txt changelog into structured data
    detect_closed: bool = False            # bail early if WordPress.org marks the plugin closed
    wp_core_version: str = "latest"        # used when bundle_wp_core=True


class ReconConfig(BaseModel):
    """Stage 2 (recon) opt-in features. All default off."""
    deterministic_analysis: bool = False   # static hook/callback/callee metadata for grounding
    validate_entry_points: bool = False    # LLM validation pass with file:line citations
    trace_cross_file_callees: bool = False # regex-based call graph for handler bodies
    scan_nonce_emissions: bool = False     # PHP+JS scan for wp_create_nonce / wp_localize_script
    exclude_vendor_tests_lang: bool = False# skip files in those buckets; needs intake.classify_files
    enrich_entry_points: bool = False      # extract body slices and confidence for each entry point
    negative_pattern_reference: bool = False # include "what NOT to flag" guidance in surveyor prompt
    max_entries_to_validate: int = 30      # validation cost cap


class ReportConfig(BaseModel):
    """Stage 7 (report) opt-in features. All default off."""
    claim_validation_pass: bool = False    # post-report critic that checks every claim cites source
    submission_readiness_gate: bool = False # emit *_NOT_READY.md when prerequisites are missing
    screenshot_capture: bool = False       # screenshot during verify when browser checks are enabled


class DedupConfig(BaseModel):
    """Stage 6 (dedup) opt-in features. All default off."""
    meaningful_scoring: bool = False        # per-match similarity scoring beyond bug-class match
    submission_recommendation: bool = False # emit submit_as_novel / regression_of / skip_dupe / rebuttal


class VerifyConfig(BaseModel):
    """Stage 5 (verify) opt-in features. All default off.

    Proper HTML parser context detection is implemented unconditionally inside
    xss_check.py; there is no toggle because it is a pure bug fix.
    """
    headless_browser_check: bool = False        # Playwright execution check
    persistent_sandbox: bool = False            # one sandbox boot per scan, snapshot/restore between PoCs
    payload_variants: bool = False              # test multiple payload variants per hypothesis
    state_introspection_on_failure: bool = False # dump DB/uploads/error.log on persistent fail
    manual_review_handoff: bool = False         # emit manual-review queue + sandbox scaffold on fail
    negative_control: bool = False              # differential reflection check with a benign marker
    collaborative_dev_poc_loop: bool = False    # PoC author can call developer mid-iteration
    payload_variant_cap: int = 6                # payload variant cost cap
    headless_browser_timeout_s: int = 15        # per-page render budget


class TriageConfig(BaseModel):
    """Stage 4 (triage critic) opt-in features. All default off."""
    inject_review_md: bool = False        # load plugins/<slug>/review.md into critic context
    cluster_aware: bool = False           # pre-cluster hypotheses by file, line, and bug class
    review_md_max_chars: int = 12000      # size cap so review.md does not blow up the prompt
    verifier_votes: int = 1               # number of independent critic votes


class QualityConfig(BaseModel):
    """Strict quality controls inspired by reference harness verifier/grader stages."""
    enabled: bool = False                 # master switch for pre-manual/pre-report quality gates
    require_evidence_schema: bool = True  # require core attacker/source/sink/impact fields before queue/report
    false_positive_rules: bool = True     # deterministic WP false-positive rules
    recompute_severity: bool = True       # derive severity from bug class, role, impact, and preconditions
    finding_grader: bool = True           # grade triage-accepted hypotheses before manual queue/verify
    report_grader: bool = True            # grade confirmed findings before generating reports
    focus_area_fanout: bool = True        # write focus-area map and feed it to specialist context
    reject_below_submit_bar: bool = True  # reject accepted hypotheses that lack realistic submit-worthy impact
    borderline_to_manual_review: bool = True # route borderline impact/evidence cases to manual queue instead of hard reject


class HypothesisConfig(BaseModel):
    """Stage 3 (hypothesis specialists + verifier) opt-in features. All default off."""
    # Specialists
    specialist_grep_read_tools: bool = False   # expose read_plugin_file + grep tools to specialists
    specialist_wp_idioms: bool = False         # append WordPress idiom guidance to specialist prompts
    require_branch_enumeration: bool = False   # require taint_path_branches in output
    require_exploit_classification: bool = False  # require exploit_classification block
    # Verifier
    iterative_verifier: bool = False           # multi-pass verifier with grep/read tools
    verifier_max_iterations: int = 3           # iteration cap
    verifier_require_citation: bool = False    # drop reasons must cite file:line
    verifier_wp_idioms: bool = False           # append WordPress idiom guidance to verifier prompt
    verifier_drop_categorisation: bool = False # five-state verdicts instead of binary keep/drop
    # Cross-cutting
    pre_verifier_dedup: bool = False           # merge near-duplicate hypotheses before verifier runs


class PipelineConfig(BaseModel):
    cost_ceiling_usd: float
    max_hypotheses_to_verify: int
    sandbox_timeout_seconds: int
    verify_max_iterations: int
    developer_calls_per_agent: int
    models: ModelConfig
    sandbox: SandboxConfig
    vuln_dbs: VulnDbConfig
    llm: LLMConfig = LLMConfig()
    reasoning: ReasoningConfig = ReasoningConfig()
    intake: IntakeConfig = IntakeConfig()  # default-off, fully backward-compatible
    recon: ReconConfig = ReconConfig()     # default-off, fully backward-compatible
    hypothesis: HypothesisConfig = HypothesisConfig()  # default-off, fully backward-compatible
    triage: TriageConfig = TriageConfig()  # default-off, fully backward-compatible
    quality: QualityConfig = QualityConfig()  # default-off, fully backward-compatible
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
