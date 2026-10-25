"""Pipeline configuration schema (loaded from pipelines/*.yaml)."""

from __future__ import annotations

from pathlib import Path
from typing import Literal
import re
from urllib.parse import urlsplit

import yaml  # type: ignore[import-untyped]
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

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
    developer: str
    developer_followup: str
    surveyor: str
    poc_author: str
    specialists: str
    reporter: str
    hypothesis_verifier: str


ReasoningEffort = Literal["none", "minimal", "low", "medium", "high", "xhigh", "max", "default"]
Verbosity = Literal["low", "medium", "high"]


class LLMConfig(BaseModel):
    """Provider-level generation controls passed through to LiteLLM."""

    reasoning_effort: ReasoningEffort | None = None
    verbosity: Verbosity | None = None


class ModelPricing(BaseModel):
    """Route-specific estimates, not subscription balances or invoices."""

    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)
    input_per_million: float = Field(ge=0)
    output_per_million: float = Field(ge=0)
    cache_read_per_million: float | None = Field(default=None, ge=0)
    cache_write_per_million: float | None = Field(default=None, ge=0)


class ProfileGenerationConfig(LLMConfig):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class ModelProfile(BaseModel):
    """Non-secret connection metadata for an explicitly selected model route."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    model: str = Field(min_length=1, pattern=r"^[A-Za-z0-9_.-]+$")
    api_format: Literal["openai_chat", "anthropic_messages"]
    api_base: str
    api_key_env: str
    generation: ProfileGenerationConfig = Field(default_factory=ProfileGenerationConfig)
    reasoning_efforts: list[ReasoningEffort] = Field(default_factory=list)
    thinking: Literal["enabled", "disabled"] | None = None
    # Some thinking Chat routes require an explicit empty reasoning slot when
    # a tool response supplied no reasoning. Never synthesize reasoning text.
    empty_tool_reasoning: bool = False
    history_policy: Literal["trim", "preserve"] = "preserve"
    max_input_tokens: int | None = Field(default=None, gt=0)
    # Request allowance (reasoning + answer), not a minimum generated length.
    output_budget_floor: int | None = Field(default=None, gt=0)
    max_output_tokens: int | None = Field(default=None, gt=0)
    pricing: ModelPricing

    @field_validator("api_base")
    @classmethod
    def _safe_api_base(cls, value: str) -> str:
        parsed = urlsplit(value)
        # Accessing .port validates non-numeric and out-of-range ports too.
        if parsed.port == 0:
            raise ValueError("api_base must not use port zero")
        if (any(char.isspace() or ord(char) < 32 for char in value)
                or parsed.scheme != "https" or not parsed.hostname or parsed.username
                or parsed.password or parsed.query or parsed.fragment):
            raise ValueError("api_base must be an HTTPS URL without credentials, query or fragment")
        return value.rstrip("/")

    @field_validator("api_key_env")
    @classmethod
    def _env_name_only(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
            raise ValueError("api_key_env must name an environment variable, not contain a key")
        return value

    @model_validator(mode="after")
    def _supported_generation(self) -> ModelProfile:
        if (self.output_budget_floor is not None and self.max_output_tokens is not None
                and self.output_budget_floor > self.max_output_tokens):
            raise ValueError("output_budget_floor must not exceed max_output_tokens")
        effort = self.generation.reasoning_effort
        if effort is not None and effort not in self.reasoning_efforts:
            raise ValueError("generation.reasoning_effort must be listed in reasoning_efforts")
        if self.generation.verbosity is not None:
            raise ValueError("verbosity is not supported by these profile API formats")
        if self.api_format == "anthropic_messages" and (effort or self.thinking):
            raise ValueError("Anthropic-compatible profile reasoning needs an explicit model-specific adapter")
        if self.empty_tool_reasoning and (
            self.api_format != "openai_chat" or self.thinking != "enabled"
        ):
            raise ValueError("empty_tool_reasoning requires a thinking-enabled Chat profile")
        return self


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
    hypothesis_verifier: ReasoningEffort | None = None


class SandboxConfig(BaseModel):
    wordpress_image: str
    db_image: str
    wp_admin_user: str
    wp_admin_pass: str
    wp_admin_email: str


class ReportConfig(BaseModel):
    """Report evidence options."""
    screenshot_capture: bool = False


class VerifyConfig(BaseModel):
    """Operational sandbox options; proof controls are always enforced."""
    persistent_sandbox: bool = False
    state_introspection_on_failure: bool = False
    headless_browser_timeout_s: int = 15


class PipelineConfig(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True)

    cost_ceiling_usd: float
    max_hypotheses_to_verify: int
    sandbox_timeout_seconds: int
    verify_max_iterations: int
    developer_calls_per_agent: int
    models: ModelConfig
    model_profiles: dict[str, ModelProfile] = Field(default_factory=dict)
    sandbox: SandboxConfig
    llm: LLMConfig = Field(default_factory=LLMConfig)
    reasoning: ReasoningConfig = Field(default_factory=ReasoningConfig)
    verify: VerifyConfig = Field(default_factory=VerifyConfig)
    report: ReportConfig = Field(default_factory=ReportConfig)
    hypothesis_review_areas: list[HypothesisReviewArea] = Field(
        default_factory=lambda: list(DEFAULT_HYPOTHESIS_REVIEW_AREAS),
        min_length=1,
    )
    hypothesis_review_item_types: list[str] | None = None

    @model_validator(mode="after")
    def _profile_references_exist(self) -> PipelineConfig:
        for name in self.model_profiles:
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
                raise ValueError("model profile names must contain only letters, numbers, _, . or -")
        for model in self.models.model_dump().values():
            if model.startswith("profile/") and model.removeprefix("profile/") not in self.model_profiles:
                raise ValueError(f"unknown model profile: {model}")
        return self

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
    def from_yaml(cls, path: str) -> PipelineConfig:
        data = yaml.safe_load(Path(path).read_text())
        return cls.model_validate(data)

    def llm_options_for_role(self, role: str) -> dict:
        """Return LiteLLM keyword args for a configured role."""
        opts = self.gateway_options()
        role_effort = getattr(self.reasoning, role, None)
        if role_effort is not None:
            opts["reasoning_effort"] = role_effort
        return opts

    def gateway_options(self) -> dict:
        """Generation settings plus non-secret profiles for the shared gateway."""
        opts = self.llm.model_dump(exclude_none=True)
        if self.model_profiles:
            opts["_model_profiles"] = {
                name: profile.model_dump(mode="json", exclude_none=True)
                for name, profile in self.model_profiles.items()
            }
        return opts
