"""Pipeline configuration schema (loaded from pipelines/*.yaml)."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml  # type: ignore[import-untyped]
from pydantic import BaseModel, Field, field_validator

HypothesisReviewArea = Literal[
    "authorization_workflows",
    "injection_files",
    "xss_lifecycle",
    "authentication",
]

DEFAULT_HYPOTHESIS_REVIEW_AREAS: tuple[HypothesisReviewArea, ...] = (
    "authorization_workflows",
    "injection_files",
    "xss_lifecycle",
    "authentication",
)


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


ReasoningEffort = Literal["none", "minimal", "low", "medium", "high", "xhigh", "default"]
Verbosity = Literal["low", "medium", "high"]


class LLMConfig(BaseModel):
    """Provider-level generation controls passed through to LiteLLM."""

    reasoning_effort: ReasoningEffort | None = None
    verbosity: Verbosity | None = None


class ReasoningConfig(BaseModel):
    """Optional per-role reasoning-effort overrides.

    These override `llm.reasoning_effort` for matching roles only. All four
    focused source reviewers map to the `specialists` role.
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


class ReportConfig(BaseModel):
    """Report evidence options."""
    screenshot_capture: bool = False


class VerifyConfig(BaseModel):
    """Operational sandbox options; proof controls are always enforced."""
    persistent_sandbox: bool = False
    state_introspection_on_failure: bool = False
    headless_browser_timeout_s: int = 15


class PipelineConfig(BaseModel):
    cost_ceiling_usd: float
    max_hypotheses_to_verify: int
    sandbox_timeout_seconds: int
    verify_max_iterations: int
    developer_calls_per_agent: int
    models: ModelConfig
    sandbox: SandboxConfig
    vuln_dbs: VulnDbConfig
    llm: LLMConfig = Field(default_factory=LLMConfig)
    reasoning: ReasoningConfig = Field(default_factory=ReasoningConfig)
    verify: VerifyConfig = Field(default_factory=VerifyConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    hypothesis_review_areas: list[HypothesisReviewArea] = Field(
        default_factory=lambda: list(DEFAULT_HYPOTHESIS_REVIEW_AREAS),
        min_length=1,
    )
    hypothesis_review_item_types: list[str] | None = None

    @field_validator("hypothesis_review_areas")
    @classmethod
    def _review_areas_are_unique(
        cls, review_areas: list[HypothesisReviewArea]
    ) -> list[HypothesisReviewArea]:
        if len(review_areas) != len(set(review_areas)):
            raise ValueError("hypothesis_review_areas must not contain duplicates")
        return review_areas

    @field_validator("hypothesis_review_item_types")
    @classmethod
    def _review_item_types_are_valid(
        cls, item_types: list[str] | None
    ) -> list[str] | None:
        if item_types is None:
            return None
        if not item_types:
            raise ValueError("hypothesis_review_item_types must not be empty")
        if any(not item_type.strip() for item_type in item_types):
            raise ValueError("hypothesis_review_item_types must not contain blanks")
        if len(item_types) != len(set(item_types)):
            raise ValueError("hypothesis_review_item_types must not contain duplicates")
        return item_types

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
