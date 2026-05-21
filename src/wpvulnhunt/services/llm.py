"""LiteLLM-backed LLM gateway with on-disk SQLite cache.

`call_llm()` is the bottom layer for all LLM access in Squadrone. LiteLLM
handles provider routing (Anthropic, OpenAI, Gemini, Bedrock, Vertex, etc.)
via API keys and ChatGPT-subscription OAuth — see `pipelines/openai.yaml`
for the ChatGPT-via-LiteLLM example.

LiteLLM is the only LLM transport used by the application.
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Optional

import aiosqlite
import litellm
from litellm.exceptions import RateLimitError
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from .budget import BudgetTracker

DEFAULT_CACHE_DB = "cache/llm.sqlite"

logger = logging.getLogger(__name__)


def _ensure_parent(path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)


async def init_cache(cache_db: str = DEFAULT_CACHE_DB) -> None:
    _ensure_parent(cache_db)
    async with aiosqlite.connect(cache_db) as db:
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


def _cache_key(model: str, messages: list, tools: list | None) -> str:
    payload = json.dumps(
        {"model": model, "messages": messages, "tools": tools},
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
) -> str:
    """Single-turn LLM call (no tools, no agent loop).

    Returns the assistant's text content. Used by agents that don't
    participate in the tool-use loop (e.g. `DeveloperAgent`), where the full
    `AgentRuntime.run` agent loop would be overkill.
    """
    resp = await call_llm(
        model=model, messages=messages, max_tokens=max_tokens,
        budget_tracker=budget_tracker, agent_name=agent_name,
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

    if getattr(ChatGPTResponsesAPIConfig, "_wpvulnhunt_aggregator_patched", False):
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

        result = original(self, model, raw_response, logging_obj)

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
    ChatGPTResponsesAPIConfig._wpvulnhunt_aggregator_patched = True
    logger.info(
        "patched ChatGPTResponsesAPIConfig.transform_response_api_response "
        "to recover output items from response.output_item.done SSE events"
    )


# Install at import time so any caller of call_llm() benefits.
_install_chatgpt_aggregator_patch()


async def call_llm(
    model: str,
    messages: list[dict],
    tools: list[dict] | None = None,
    max_tokens: int = 4096,
    budget_tracker: Optional[BudgetTracker] = None,
    cache_db: str = DEFAULT_CACHE_DB,
    agent_name: str = "unknown",
) -> dict:
    """Direct LiteLLM completion with on-disk response cache.

    For `chatgpt/...` models, `_install_chatgpt_aggregator_patch()` (called
    at module-import time) normalizes streamed output items into the final
    response's `output` field.
    """
    _ensure_parent(cache_db)
    key = _cache_key(model, messages, tools)

    async with aiosqlite.connect(cache_db) as db:
        async with db.execute(
            "SELECT response FROM llm_cache WHERE cache_key = ?", (key,)
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                logger.debug("llm cache HIT model=%s key=%s", model, key[:12])
                return json.loads(row[0])

    logger.debug("llm cache MISS model=%s key=%s", model, key[:12])

    response = await litellm.acompletion(
        model=model,
        messages=messages,
        tools=tools,
        max_tokens=max_tokens,
    )

    if budget_tracker is not None:
        await budget_tracker.add(response.usage, model, agent=agent_name)

    result = response.model_dump()

    async with aiosqlite.connect(cache_db) as db:
        await db.execute(
            "INSERT OR IGNORE INTO llm_cache (cache_key, response) VALUES (?, ?)",
            (key, json.dumps(result)),
        )
        await db.commit()

    return result
