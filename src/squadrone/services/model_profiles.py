"""Resolve configured model routes without reading credentials or mutating SDK globals."""

from __future__ import annotations

import copy
from dataclasses import dataclass
import os
from typing import Any

from ..schemas.config import ModelProfile

_RESERVED_OPTIONS = frozenset({
    "model", "messages", "tools", "max_tokens", "api_base", "base_url", "api_key",
    "extra_headers", "headers", "pricing", "conversation_id", "custom_llm_provider",
})


@dataclass(frozen=True)
class ResolvedModel:
    request_model: str
    options: dict[str, Any]
    identity: dict[str, Any]
    history_policy: str = "trim"
    profile: ModelProfile | None = None

    @property
    def pricing(self) -> dict | None:
        return self.profile.pricing.model_dump(exclude_none=True) if self.profile else None

    def output_limit(self, requested: int) -> int:
        if requested <= 0:
            raise ValueError("max_tokens must be positive")
        floor = self.profile.output_budget_floor if self.profile else None
        requested = max(requested, floor or requested)
        cap = self.profile.max_output_tokens if self.profile else None
        return min(requested, cap) if cap else requested

    def prepare_messages(self, messages: list[dict]) -> list[dict]:
        """Normalize required empty tool-reasoning slots without changing history.

        A missing/null slot contains no recoverable reasoning text. Selected
        routes require the JSON field even for such non-thinking tool turns;
        an explicit empty string represents that absence, not invented thought.
        Actual reasoning and all other assistant/provider fields stay intact.
        """
        if self.profile is None or not self.profile.empty_tool_reasoning:
            return messages
        prepared = copy.deepcopy(messages)
        for message in prepared:
            if message.get("role") != "assistant" or not message.get("tool_calls"):
                continue
            if message.get("reasoning_content") is None:
                provider_fields = message.get("provider_specific_fields") or {}
                reasoning = provider_fields.get("reasoning_content")
                message["reasoning_content"] = reasoning if reasoning is not None else ""
        return prepared

    def connection_kwargs(self, conversation_id: str) -> dict:
        """Read secrets only after cache lookup, immediately before dispatch."""
        if self.profile is None:
            return {}
        if self.profile.api_format == "openai_chat":
            # The OpenAI SDK inherits arbitrary custom headers even when an
            # explicit API key/base is supplied. Refuse ambiguous ambient
            # defaults rather than send another provider's credentials or
            # organization metadata, or mutate process-wide environment state.
            ambient = [name for name in (
                "OPENAI_CUSTOM_HEADERS", "OPENAI_ORG_ID", "OPENAI_PROJECT_ID",
                "OPENAI_ORGANIZATION",
            ) if os.environ.get(name, "").strip()]
            if ambient:
                raise ValueError(
                    "Profile routes refuse inherited OpenAI SDK headers; unset "
                    + ", ".join(ambient) + " for this process"
                )
        key = os.environ.get(self.profile.api_key_env, "").strip()
        if not key:
            raise ValueError(f"Missing required environment variable {self.profile.api_key_env}")
        headers = {
            "Authorization": f"Bearer {key}",
            "User-Agent": "squadrone/0.1.0",
            "x-opencode-session": conversation_id,
        }
        return {
            "api_base": self.profile.api_base,
            "api_key": key,
            # Explicit nonempty headers also avoid LiteLLM's global defaults.
            "headers": dict(headers),
            "extra_headers": headers,
        }


def resolve_model(model: str, llm_options: dict | None = None) -> ResolvedModel:
    """Profiles have explicit, validated routes; ordinary LiteLLM strings stay valid."""
    options = dict(llm_options or {})
    profiles = options.pop("_model_profiles", {})
    if not model.startswith("profile/"):
        return ResolvedModel(model, options, {"model": model, "options": options})
    name = model.removeprefix("profile/")
    if name not in profiles:
        raise ValueError(f"Unknown model profile: {name}")
    profile = ModelProfile.model_validate(profiles[name])
    blocked = _RESERVED_OPTIONS.intersection(options)
    if blocked or set(options) - {"reasoning_effort", "verbosity"}:
        raise ValueError("Model profile options may contain only generation controls")
    controls = profile.generation.model_dump(exclude_none=True) | options
    effort = controls.get("reasoning_effort")
    if effort is not None and effort not in profile.reasoning_efforts:
        raise ValueError(f"{name} does not support reasoning_effort={effort!r}; supported: {profile.reasoning_efforts}")
    if controls.get("verbosity") is not None:
        raise ValueError(f"{name} does not support verbosity")
    if profile.api_format == "anthropic_messages" and effort is not None:
        raise ValueError(f"{name} requires model-specific Messages reasoning controls")
    if profile.api_format == "openai_chat":
        request_model = f"openai/{profile.model}"
        # Unknown compatible model IDs need this narrow allowlist in LiteLLM.
        if effort is not None:
            controls["allowed_openai_params"] = ["reasoning_effort"]
        if profile.thinking:
            controls["extra_body"] = {"thinking": {"type": profile.thinking}}
    else:
        request_model = f"anthropic/{profile.model}"
    identity = {
        "model": request_model,
        "api_base": profile.api_base,
        "api_format": profile.api_format,
        "options": controls,
        "history_policy": profile.history_policy,
        "max_input_tokens": profile.max_input_tokens,
        "output_budget_floor": profile.output_budget_floor,
        "max_output_tokens": profile.max_output_tokens,
    }
    return ResolvedModel(request_model, controls, identity, profile.history_policy, profile)
