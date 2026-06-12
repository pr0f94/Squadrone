"""LiteLLM-backed LLM gateway with on-disk SQLite cache.

`call_llm()` is the bottom layer for all LLM access in Squadrone. LiteLLM
handles provider routing (Anthropic, OpenAI, Gemini, Bedrock, Vertex, etc.)
via API keys and ChatGPT-subscription OAuth — see `pipelines/openai.yaml`
for the ChatGPT-via-LiteLLM example.

LiteLLM is the only LLM transport used by the application.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import ssl
from pathlib import Path
from typing import Optional

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
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from .budget import BudgetTracker
from .sqlite import connect_sqlite

DEFAULT_CACHE_DB = "cache/llm.sqlite"

logger = logging.getLogger(__name__)

CHATGPT_55_MODEL = "chatgpt/gpt-5.5"
CHATGPT_55_SOURCE_MODEL = "chatgpt/gpt-5.4"

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
        return any(
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
        )
    return False


def _ensure_parent(path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)


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


def _install_chatgpt_55_model_patch() -> bool:
    """Register chatgpt/gpt-5.5 in LiteLLM's in-memory model map.

    LiteLLM's ChatGPT provider can route gpt-5.5 through the Codex backend, but
    some released model registries do not list `chatgpt/gpt-5.5` yet. Clone the
    known-working `chatgpt/gpt-5.4` metadata for the current Python process only.
    This does not modify LiteLLM's package files on disk and becomes a no-op once
    upstream LiteLLM ships native metadata for the target model.
    """
    model_cost = getattr(litellm, "model_cost", None)
    if not isinstance(model_cost, dict):
        return False

    if CHATGPT_55_MODEL in model_cost:
        return False

    source = model_cost.get(CHATGPT_55_SOURCE_MODEL)
    if not source:
        return False

    patched = copy.deepcopy(source)
    patched["litellm_provider"] = "chatgpt"
    patched["mode"] = "responses"
    model_cost[CHATGPT_55_MODEL] = patched

    chatgpt_models = getattr(litellm, "chatgpt_models", None)
    if isinstance(chatgpt_models, set):
        chatgpt_models.add(CHATGPT_55_MODEL)
    elif isinstance(chatgpt_models, list) and CHATGPT_55_MODEL not in chatgpt_models:
        chatgpt_models.append(CHATGPT_55_MODEL)

    logger.info(
        "registered %s in LiteLLM model map from %s metadata",
        CHATGPT_55_MODEL,
        CHATGPT_55_SOURCE_MODEL,
    )
    return True


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


def _cache_key(model: str, messages: list, tools: list | None, llm_options: dict | None = None) -> str:
    payload = json.dumps(
        {"model": model, "messages": messages, "tools": tools, "llm_options": llm_options or {}},
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(min=2, max=30),
    retry=retry_if_exception_type(RateLimitError),
    reraise=True,
)
async def call_llm_oneshot(
    *,
    model: str,
    messages: list[dict],
    max_tokens: int = 4096,
    budget_tracker: Optional[BudgetTracker] = None,
    agent_name: str = "unknown",
    llm_options: dict | None = None,
) -> str:
    """Single-turn LLM call (no tools, no agent loop).

    Returns the assistant's text content. Used by agents that don't
    participate in the tool-use loop (e.g. `DeveloperAgent`), where the full
    `AgentRuntime.run` agent loop would be overkill.
    """
    resp = await call_llm(
        model=model, messages=messages, max_tokens=max_tokens,
        budget_tracker=budget_tracker, agent_name=agent_name,
        llm_options=llm_options,
    )
    choice = (resp.get("choices") or [{}])[0]
    return ((choice.get("message") or {}).get("content") or "").strip()


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

    ChatGPTResponsesAPIConfig.transform_response_api_response = patched
    ChatGPTResponsesAPIConfig._squadrone_aggregator_patched = True
    logger.info(
        "patched ChatGPTResponsesAPIConfig.transform_response_api_response "
        "to recover output items from response.output_item.done SSE events"
    )


# Install at import time so any caller of call_llm() benefits.
_install_chatgpt_55_model_patch()
_install_chatgpt_aggregator_patch()


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(min=2, max=30),
    retry=retry_if_exception(_is_retryable_llm_error),
    before_sleep=before_sleep_log(logger, logging.WARNING),
    reraise=True,
)
async def _acompletion_with_retries(request_kwargs: dict) -> object:
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
) -> dict:
    """Direct LiteLLM completion with on-disk response cache.

    For `chatgpt/...` models, module-import compatibility patches register
    chatgpt/gpt-5.5 when missing from LiteLLM's registry and normalize streamed
    output items into the final response's `output` field.
    """
    _ensure_parent(cache_db)
    options = dict(llm_options or {})
    key = _cache_key(model, messages, tools, options)

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
        "model": model,
        "messages": messages,
        "tools": tools,
        "max_tokens": max_tokens,
    }
    request_kwargs.update(options)
    response = await _acompletion_with_retries(request_kwargs)

    if budget_tracker is not None:
        await budget_tracker.add(response.usage, model, agent=agent_name)

    _coerce_response_api_usage(response)
    result = response.model_dump()

    async with connect_sqlite(cache_db) as db:
        await db.execute(
            "INSERT OR IGNORE INTO llm_cache (cache_key, response) VALUES (?, ?)",
            (key, json.dumps(result)),
        )
        await db.commit()

    return result
