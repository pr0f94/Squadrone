"""LiteLLM-backed LLM gateway with on-disk SQLite cache.

`call_llm()` is the bottom layer for all LLM access in Squadrone. LiteLLM
handles provider routing (Anthropic, OpenAI, Gemini, Bedrock, Vertex, etc.)
via API keys and ChatGPT-subscription OAuth — see `pipelines/chatgpt.yaml`
for the ChatGPT-via-LiteLLM example.

LiteLLM is the only LLM transport used by the application.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import ssl
from uuid import uuid4
from pathlib import Path
from typing import Any, Optional

import litellm
from litellm.exceptions import (
    APIConnectionError,
    APIError,
    InternalServerError,
    RateLimitError,
    ServiceUnavailableError,
    Timeout,
)
from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

from .budget import BudgetTracker
from .model_profiles import resolve_model
from .sqlite import connect_sqlite

DEFAULT_CACHE_DB = os.getenv("SQUADRONE_LLM_CACHE_DB", "cache/llm.sqlite")

logger = logging.getLogger(__name__)

CHATGPT_COMPAT_SOURCE_MODEL = "chatgpt/gpt-5.4"
CHATGPT_COMPAT_MODELS = (
    "chatgpt/gpt-5.5",
    "chatgpt/gpt-5.6-sol",
    "chatgpt/gpt-daybreak-blue-latest",
)

_RETRYABLE_LLM_EXCEPTIONS = (
    APIConnectionError,
    InternalServerError,
    RateLimitError,
    ServiceUnavailableError,
    Timeout,
)


def _is_retryable_llm_error(exc: BaseException) -> bool:
    if isinstance(exc, _RETRYABLE_LLM_EXCEPTIONS):
        return True
    if isinstance(exc, (ssl.SSLError, ConnectionError, TimeoutError)):
        return True
    # Some providers wrap transport failures in APIError/InternalServerError
    # while preserving only the original message.
    if isinstance(exc, APIError):
        message = str(exc).lower()
        if any(
            marker in message
            for marker in (
                "ssl",
                "tls",
                "bad record mac",
                "connection reset",
                "connection aborted",
                "temporarily unavailable",
                "timeout",
            )
        ):
            return True

        # Some providers report transient control-plane/access checks as a
        # generic APIError instead of ServiceUnavailableError.  Retry only
        # when the provider supplies both a temporal qualifier and an explicit
        # retry directive, so permanent authentication/authorization failures
        # remain non-retryable.
        has_verification_failure = any(
            marker in message
            for marker in (
                "unable to verify",
                "cannot verify",
                "could not verify",
                "failed to verify",
            )
        )
        has_retry_directive = any(
            marker in message for marker in ("please retry", "try again")
        )
        has_temporal_qualifier = any(
            marker in message for marker in ("right now", "temporar", "later")
        )
        return (
            has_verification_failure
            and has_retry_directive
            and has_temporal_qualifier
        )
    return False


def _ensure_parent(path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)


def _estimate_request_tokens(messages: list[dict], tools: list[dict] | None) -> int:
    """Conservative provider-independent estimate used only for cost reservation."""
    payload_chars = len(json.dumps({"messages": messages, "tools": tools}, default=str))
    return max(1, (payload_chars + 2) // 3)


def _coerce_response_api_usage(response: object) -> object:
    """Normalize LiteLLM Responses API usage after model_construct paths.

    LiteLLM's ChatGPT Responses adapter may fall back to
    `ResponsesAPIResponse.model_construct(**payload)` when the streamed
    `response.completed` payload contains fields that fail normal validation.
    That bypasses Pydantic validators, leaving `usage` as a plain dict even
    though the model field expects `ResponseAPIUsage`. A later `model_dump()`
    then emits a noisy serializer warning.
    """
    usage = getattr(response, "usage", None)
    if not isinstance(usage, dict):
        return response

    try:
        from litellm.types.llms.openai import ResponseAPIUsage
    except ImportError:
        return response

    try:
        coerced = ResponseAPIUsage(**usage)
    except Exception:
        return response

    try:
        setattr(response, "usage", coerced)
    except Exception:
        try:
            response.__dict__["usage"] = coerced  # type: ignore[attr-defined]
        except Exception:
            pass

    return response


def _install_chatgpt_model_patches() -> tuple[str, ...]:
    """Register newer ChatGPT models in LiteLLM's in-memory model map.

    LiteLLM's ChatGPT provider can route these models through the Codex backend,
    but some released model registries do not list them yet. Clone the
    known-working `chatgpt/gpt-5.4` metadata for the current Python process only.
    This does not modify LiteLLM's package files on disk, and each entry becomes
    a no-op once upstream LiteLLM ships native metadata for that model.
    """
    model_cost = getattr(litellm, "model_cost", None)
    if not isinstance(model_cost, dict):
        return ()

    source = model_cost.get(CHATGPT_COMPAT_SOURCE_MODEL)
    if not source:
        return ()

    chatgpt_models = getattr(litellm, "chatgpt_models", None)
    registered: list[str] = []
    for target_model in CHATGPT_COMPAT_MODELS:
        if target_model in model_cost:
            continue

        patched = copy.deepcopy(source)
        patched["litellm_provider"] = "chatgpt"
        patched["mode"] = "responses"
        model_cost[target_model] = patched

        if isinstance(chatgpt_models, set):
            chatgpt_models.add(target_model)
        elif isinstance(chatgpt_models, list) and target_model not in chatgpt_models:
            chatgpt_models.append(target_model)

        registered.append(target_model)
        logger.info(
            "registered %s in LiteLLM model map from %s metadata",
            target_model,
            CHATGPT_COMPAT_SOURCE_MODEL,
        )

    return tuple(registered)


def _install_chatgpt_model_family_patch() -> None:
    """Teach LiteLLM that compatibility aliases use GPT-5 parameters.

    LiteLLM chooses its parameter mapper from the model name, independently of
    the model metadata registered above.  Product aliases such as Daybreak Blue
    do not contain ``gpt-5``, so LiteLLM otherwise rejects valid GPT-5 controls
    (notably ``reasoning_effort``) before making the provider request.

    Extend the detector only for Squadrone's explicit compatibility aliases.
    Native model detection remains authoritative for every other model, and the
    wrapper becomes a harmless no-op once LiteLLM recognizes an alias itself.
    """
    try:
        from litellm.llms.openai.chat.gpt_5_transformation import OpenAIGPT5Config
    except ImportError:
        return

    if getattr(OpenAIGPT5Config, "_squadrone_model_family_patched", False):
        return

    original = OpenAIGPT5Config.is_model_gpt_5_model.__func__
    compat_names = frozenset(model.rsplit("/", 1)[-1] for model in CHATGPT_COMPAT_MODELS)

    @classmethod
    def patched(cls, model: str) -> bool:
        normalized = model.rsplit("/", 1)[-1]
        return normalized in compat_names or original(cls, model)

    OpenAIGPT5Config.is_model_gpt_5_model = patched  # type: ignore[method-assign]
    OpenAIGPT5Config._squadrone_model_family_patched = True  # type: ignore[attr-defined]
    logger.info(
        "extended LiteLLM GPT-5 parameter mapping for ChatGPT compatibility aliases"
    )


async def init_cache(cache_db: str = DEFAULT_CACHE_DB) -> None:
    _ensure_parent(cache_db)
    async with connect_sqlite(cache_db) as db:
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS llm_cache (
                cache_key  TEXT PRIMARY KEY,
                response   TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now'))
            )
            """
        )
        await db.commit()


def _cache_key(
    model: str, messages: list, tools: list | None,
    llm_options: dict | None = None, max_tokens: int = 4096,
) -> str:
    payload = json.dumps(
        {"version": 2, "model": model, "messages": messages, "tools": tools,
         "llm_options": llm_options or {}, "max_tokens": max_tokens},
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


class IncompleteLLMResponse(RuntimeError):
    """A provider response cannot be treated as a complete authoritative answer."""


def require_complete_response(response: dict, *, require_content: bool = True) -> None:
    """Reject interrupted output before parsing or executing even valid-looking JSON.

    Reasoning-only and empty final turns are not successful answers. Tool-only
    assistant turns are legitimate when the caller explicitly allows them.
    Never put model text or reasoning in the exception.
    """
    choice = (response.get("choices") or [{}])[0]
    finish_reason = choice.get("finish_reason")
    message = choice.get("message") or {}
    if finish_reason in {"length", "max_tokens", "content_filter"}:
        raise IncompleteLLMResponse(f"Incomplete model response (finish_reason={finish_reason})")
    if message.get("refusal"):
        raise IncompleteLLMResponse("Model refused the requested answer")
    content = message.get("content")
    has_content = isinstance(content, str) and bool(content.strip())
    if not has_content and (require_content or not message.get("tool_calls")):
        raise IncompleteLLMResponse("Model returned no final answer")


async def call_llm_oneshot(
    *,
    model: str,
    messages: list[dict],
    max_tokens: int = 4096,
    budget_tracker: Optional[BudgetTracker] = None,
    agent_name: str = "unknown",
    llm_options: dict | None = None,
    conversation_id: str | None = None,
    return_response: bool = False,
) -> str | dict:
    """Single-turn LLM call (no tools, no agent loop).

    Returns the assistant's text content. Used by agents that don't
    participate in the tool-use loop (e.g. `DeveloperAgent`), where the full
    `AgentRuntime.run` agent loop would be overkill.
    """
    resolved = resolve_model(model, llm_options)
    allowance = resolved.output_limit(max_tokens)
    ceiling = resolved.profile.max_output_tokens if resolved.profile else None
    # Retry a failed generation, not a continuation of its incomplete answer.
    # Preserve one session across both attempts even outside an agent context.
    if conversation_id is None:
        from .llm_context import current_conversation

        context = current_conversation()
        conversation_id = context.conversation_id if context else str(uuid4())
    for attempt in range(2):
        resp = await call_llm(
            model=model, messages=messages, max_tokens=allowance,
            budget_tracker=budget_tracker, agent_name=agent_name,
            llm_options=llm_options,
            conversation_id=conversation_id,
        )
        try:
            require_complete_response(resp)
        except IncompleteLLMResponse:
            choice = (resp.get("choices") or [{}])[0]
            # Refusals/filtering are not exhaustion and must not trigger retries.
            blocked = choice.get("finish_reason") == "content_filter" or (
                choice.get("message") or {}
            ).get("refusal")
            if attempt or blocked or ceiling is None or allowance >= ceiling:
                raise
            logger.warning(
                "%s: incomplete answer with %d-token allowance; retrying once at %d",
                agent_name, allowance, ceiling,
            )
            allowance = ceiling
            continue
        if return_response:
            return resp
        choice = resp["choices"][0]
        return choice["message"]["content"].strip()
    raise AssertionError("unreachable")


def _install_chatgpt_aggregator_patch() -> None:
    """Normalize LiteLLM chatgpt-provider streamed response aggregation.

    The upstream aggregator at
    `.venv/.../litellm/llms/chatgpt/responses/transformation.py`,
    `ChatGPTResponsesAPIConfig.transform_response_api_response()`, reads the
    SSE response stream looking for the `response.completed` event. It extracts
    `response.completed.response.output` and uses it as the `output` field of
    the returned `ResponsesAPIResponse`.

    For ChatGPT-subscription auth requests, the server's `response.completed`
    event reliably carries `output: []` (empty) even when the response is
    successful. The actual output items arrive via separate intermediate
    `response.output_item.done` SSE events that the aggregator does not
    inspect. Net effect: `ResponsesAPIResponse.output = []` despite a fully
    successful response containing message / tool-call items.

    The downstream choice-converter
    (`completion_extras/litellm_responses_transformation/transformation.py:
    _convert_response_output_to_choices`) then walks the empty output list,
    builds zero `Choices`, and the caller raises:
        ValueError: Unknown items in responses API response: []

    This adapter wraps `transform_response_api_response`: it pre-scans the raw
    SSE body for `response.output_item.done` events, collects each `item`
    payload as a raw dict, calls the original aggregator, and if the result
    has an empty `output` field, fills it with the collected dicts. The
    downstream choice-converter accepts raw dicts via its
    `handle_raw_dict_callback` parameter (which the chatgpt provider already
    registers), so dict items round-trip correctly into chat-completion
    Choices.

    The adapter is idempotent (won't re-wrap on repeated import) and is a no-op
    if the chatgpt provider isn't present in the installed LiteLLM version.

    This is a compatibility adapter for LiteLLM's chatgpt responses
    transformation. If the provider already returns populated output, the
    conditional fill-in does not activate.
    """
    try:
        from litellm.llms.chatgpt.responses.transformation import (
            ChatGPTResponsesAPIConfig,
        )
    except ImportError:
        return  # LiteLLM build without chatgpt provider; nothing to patch.

    if getattr(ChatGPTResponsesAPIConfig, "_squadrone_aggregator_patched", False):
        return  # already wrapped

    original = ChatGPTResponsesAPIConfig.transform_response_api_response

    def patched(self, model, raw_response, logging_obj):  # type: ignore[no-redef]
        # Pre-scan SSE body for output_item.done events. These carry the
        # actual content items that response.completed.output omits.
        body_text = getattr(raw_response, "text", "") or ""
        accumulated_items: list = []
        if "output_item.done" in body_text:
            for line in body_text.splitlines():
                line = line.strip()
                if not line.startswith("data:"):
                    continue
                payload_str = line[5:].strip()
                if not payload_str or payload_str == "[DONE]":
                    continue
                try:
                    parsed = json.loads(payload_str)
                except (json.JSONDecodeError, ValueError):
                    continue
                if (
                    isinstance(parsed, dict)
                    and parsed.get("type") == "response.output_item.done"
                ):
                    item = parsed.get("item")
                    if item:
                        accumulated_items.append(item)

        result = _coerce_response_api_usage(original(self, model, raw_response, logging_obj))

        if accumulated_items:
            existing = getattr(result, "output", None)
            if not existing:
                # Empty `output` from response.completed. Substitute the
                # items we recovered from output_item.done events. The
                # downstream converter handles raw dicts via its
                # handle_raw_dict_callback hook.
                try:
                    result.output = accumulated_items
                except Exception:
                    # If the model is frozen / Pydantic v2 strict, fall
                    # back to direct attribute assignment via __dict__.
                    result.__dict__["output"] = accumulated_items

        return result

    setattr(ChatGPTResponsesAPIConfig, "transform_response_api_response", patched)
    setattr(ChatGPTResponsesAPIConfig, "_squadrone_aggregator_patched", True)
    logger.info(
        "patched ChatGPTResponsesAPIConfig.transform_response_api_response "
        "to recover output items from response.output_item.done SSE events"
    )


# Install at import time so any caller of call_llm() benefits.
_install_chatgpt_model_patches()
_install_chatgpt_model_family_patch()
_install_chatgpt_aggregator_patch()


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(min=2, max=30),
    retry=retry_if_exception(_is_retryable_llm_error),
    before_sleep=before_sleep_log(logger, logging.WARNING),
    reraise=True,
)
async def _acompletion_with_retries(request_kwargs: dict) -> Any:
    return await litellm.acompletion(**request_kwargs)


async def call_llm(
    model: str,
    messages: list[dict],
    tools: list[dict] | None = None,
    max_tokens: int = 4096,
    budget_tracker: Optional[BudgetTracker] = None,
    cache_db: str = DEFAULT_CACHE_DB,
    agent_name: str = "unknown",
    llm_options: dict | None = None,
    conversation_id: str | None = None,
) -> dict:
    """Direct LiteLLM completion with on-disk response cache.

    For `chatgpt/...` models, module-import compatibility patches register newer
    Codex models when missing from LiteLLM's registry and normalize streamed
    output items into the final response's `output` field.
    """
    _ensure_parent(cache_db)
    resolved = resolve_model(model, llm_options)
    messages = resolved.prepare_messages(messages)
    max_tokens = resolved.output_limit(max_tokens)
    if max_tokens <= 0:
        raise ValueError("max_tokens must be positive")
    if resolved.profile and resolved.profile.max_input_tokens is not None:
        estimated = _estimate_request_tokens(messages, tools)
        if estimated > resolved.profile.max_input_tokens:
            raise ValueError(
                f"{model}: estimated input {estimated} tokens exceeds configured "
                f"limit {resolved.profile.max_input_tokens}; history was not silently truncated"
            )
    key = _cache_key(resolved.request_model, messages, tools, resolved.identity, max_tokens)

    async with connect_sqlite(cache_db) as db:
        async with db.execute(
            "SELECT response FROM llm_cache WHERE cache_key = ?", (key,)
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                logger.debug("llm cache HIT model=%s key=%s", model, key[:12])
                return json.loads(row[0])

    logger.debug("llm cache MISS model=%s key=%s", model, key[:12])

    request_kwargs = {
        "model": resolved.request_model,
        "messages": messages,
        "tools": tools,
        "max_tokens": max_tokens,
    }
    request_kwargs.update(resolved.options)
    # A single logical request keeps its ID through every transport retry.
    if conversation_id is None:
        from .llm_context import current_conversation

        context = current_conversation()
        conversation_id = context.conversation_id if context else str(uuid4())
    request_kwargs.update(resolved.connection_kwargs(conversation_id))
    reservation = 0.0
    if budget_tracker is not None:
        pricing_kwargs = {"pricing": resolved.pricing} if resolved.pricing else {}
        reservation = await budget_tracker.reserve(
            model,
            _estimate_request_tokens(messages, tools),
            max_tokens,
            **pricing_kwargs,
        )
    try:
        response = await _acompletion_with_retries(request_kwargs)
    except BaseException:
        if budget_tracker is not None:
            await budget_tracker.release(reservation)
        raise

    if budget_tracker is not None:
        await budget_tracker.add(
            response.usage,
            model,
            agent=agent_name,
            reservation_usd=reservation,
            **({"pricing": resolved.pricing} if resolved.pricing else {}),
        )

    _coerce_response_api_usage(response)
    result = response.model_dump()

    async with connect_sqlite(cache_db) as db:
        await db.execute(
            "INSERT OR IGNORE INTO llm_cache (cache_key, response) VALUES (?, ?)",
            (key, json.dumps(result)),
        )
        await db.commit()

    return result
