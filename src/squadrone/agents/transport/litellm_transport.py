"""LiteLLM transport: drives the LLM tool-call loop using `services.llm.call_llm`.

The body of this class's `run_agent` method is the original `AgentRuntime.run`
implementation, relocated here without behavioural change. It preserves:
- Ephemeral cache_control marking on system / first-user / last-tool messages
- Per-call request/response tracing
- Forced finalisation when max_iterations is exhausted
- Schema validation with one retry
- Tool dispatch through `runtime._dispatch_tool`

Multi-provider support is inherited from LiteLLM. Auth is via API key
environment variables (e.g. ANTHROPIC_API_KEY, OPENAI_API_KEY).
"""

from __future__ import annotations

import json
import logging
import re
from typing import Optional, TYPE_CHECKING

from pydantic import BaseModel, ValidationError

from ...services.llm import call_llm
from .base import AgentOutputError, AgentResult

if TYPE_CHECKING:
    from ..runtime import AgentRuntime

logger = logging.getLogger(__name__)


_FENCE_RE = re.compile(r"^```(?:json)?\s*\n?(.*?)\n?```\s*$", re.DOTALL)
_EMBED_FENCE_RE = re.compile(r"```(?:json)?\s*\n(.*?)\n```", re.DOTALL)


def _apply_cache_control(msgs: list[dict], model: str) -> list[dict]:
    """For Claude models, mark up to 4 messages with Anthropic ephemeral cache_control.

    Strategy: cache the system message, the first user message (often the big setup with
    hypothesis + entry-point source), and the most recent tool message. This means a long
    tool-call loop pays cache-read rate (~10% of input rate) for everything before the
    last tool result, and full input rate only for the freshly-added content.
    """
    if not model or not model.lower().startswith("claude-"):
        return msgs
    if not msgs:
        return msgs

    sys_idx: Optional[int] = None
    first_user_idx: Optional[int] = None
    last_tool_idx: Optional[int] = None
    for i, m in enumerate(msgs):
        role = m.get("role")
        if role == "system" and sys_idx is None:
            sys_idx = i
        elif role == "user" and first_user_idx is None:
            first_user_idx = i
        elif role == "tool":
            last_tool_idx = i

    cache_indices = {i for i in (sys_idx, first_user_idx, last_tool_idx) if i is not None}
    if not cache_indices:
        return msgs

    out: list[dict] = []
    for i, m in enumerate(msgs):
        if i not in cache_indices:
            out.append(m)
            continue
        content = m.get("content")
        if isinstance(content, str):
            block = {"type": "text", "text": content, "cache_control": {"type": "ephemeral"}}
            out.append({**m, "content": [block]})
        elif isinstance(content, list) and content:
            new_blocks = list(content)
            last = new_blocks[-1]
            if isinstance(last, dict):
                new_blocks[-1] = {**last, "cache_control": {"type": "ephemeral"}}
            out.append({**m, "content": new_blocks})
        else:
            out.append(m)
    return out


def _strip_fences(text: str) -> str:
    """Extract JSON payload from `text`, tolerating prose preamble + markdown fences."""
    s = text.strip()
    m = _FENCE_RE.match(s)
    if m:
        return m.group(1).strip()
    m = _EMBED_FENCE_RE.search(s)
    if m:
        return m.group(1).strip()
    candidates = [(s.find(o), o, c) for o, c in (("[", "]"), ("{", "}"))]
    candidates = [(i, o, c) for i, o, c in candidates if i != -1]
    if not candidates:
        return s
    start, opener, closer = min(candidates, key=lambda t: t[0])
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(s)):
        ch = s[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return s[start:i + 1].strip()
    return s


def _accumulate_usage(acc: dict, usage: Optional[dict]) -> None:
    if not usage:
        return
    for k in ("prompt_tokens", "completion_tokens", "total_tokens"):
        if k in usage and usage[k] is not None:
            acc[k] = acc.get(k, 0) + int(usage[k])


# Sliding-window trim defaults. 80KB is roughly 20K input tokens, leaving
# headroom for the model's reply while keeping tool-loop conversations bounded.
_TRIM_THRESHOLD_BYTES = 80_000
_TRIM_KEEP_TOOL_CYCLES = 5


def _trim_history_for_budget(
    msgs: list[dict],
    max_keep_tool_cycles: int = _TRIM_KEEP_TOOL_CYCLES,
    trim_threshold_bytes: int = _TRIM_THRESHOLD_BYTES,
) -> tuple[list[dict], int]:
    """Drop older tool-call cycles when the conversation gets too big.

    Returns `(trimmed_msgs, dropped_cycles_count)`. If no trimming is needed,
    returns `(msgs, 0)` with the original list reference.

    Structure preserved:
      [system*, first_user, ?runtime_note, last_N_cycles..., tail]

    A "tool cycle" is `[assistant_with_tool_calls, role=tool ...]` — we always
    drop complete cycles, never half a cycle (OpenAI rejects orphan tool_calls
    or orphan tool responses).
    """
    try:
        size = sum(len(json.dumps(m, default=str)) for m in msgs)
    except (TypeError, ValueError):
        return msgs, 0
    if size <= trim_threshold_bytes:
        return msgs, 0

    prefix: list[dict] = []
    cycles: list[list[dict]] = []
    i = 0
    saw_first_user = False
    while i < len(msgs):
        m = msgs[i]
        if m.get("role") == "system":
            prefix.append(m)
            i += 1
        elif m.get("role") == "user" and not saw_first_user:
            prefix.append(m)
            saw_first_user = True
            i += 1
        else:
            break

    while i < len(msgs):
        m = msgs[i]
        if m.get("role") == "assistant" and m.get("tool_calls"):
            cycle = [m]
            i += 1
            while i < len(msgs) and msgs[i].get("role") == "tool":
                cycle.append(msgs[i])
                i += 1
            cycles.append(cycle)
        else:
            break
    tail = msgs[i:]

    if len(cycles) <= max_keep_tool_cycles:
        return msgs, 0

    kept_cycles = cycles[-max_keep_tool_cycles:]
    dropped = len(cycles) - len(kept_cycles)

    result: list[dict] = list(prefix)
    result.append({
        "role": "user",
        "content": (
            f"[runtime] {dropped} earlier tool-call turn(s) were trimmed from this "
            f"conversation to stay within the context budget. Below are the most "
            f"recent {len(kept_cycles)} turn(s). Use the information you already "
            "have to make progress or produce your final output — do not call the "
            "same tools again expecting different results."
        ),
    })
    for cycle in kept_cycles:
        result.extend(cycle)
    result.extend(tail)
    return result, dropped


class LiteLLMTransport:
    async def run_agent(
        self,
        *,
        runtime: "AgentRuntime",
        agent_name: str,
        model: str,
        messages: list[dict],
        tools: Optional[list[dict]],
        max_iterations: int,
        output_schema: Optional[type[BaseModel]],
        tool_handlers: Optional[dict],
        force_finalise_after: Optional[int],
        max_tokens: int,
    ) -> AgentResult:
        msgs = [dict(m) for m in messages]
        usage_acc: dict = {}
        dev_calls = [0]
        call_history: dict = {}

        async def _one_call(call_msgs: list[dict]) -> dict:
            trimmed_msgs, dropped = _trim_history_for_budget(call_msgs)
            if dropped:
                runtime._trace(agent_name, "history_trimmed", {
                    "dropped_cycles": dropped,
                    "kept_messages": len(trimmed_msgs),
                    "original_messages": len(call_msgs),
                })
            cached_msgs = _apply_cache_control(trimmed_msgs, model)
            llm_options = runtime.llm_options_for_agent(agent_name)
            runtime._trace(agent_name, "request", {
                "model": model,
                "messages": trimmed_msgs,
                "tools": tools,
                "llm_options": llm_options,
            })
            resp = await call_llm(
                model=model,
                messages=cached_msgs,
                tools=tools,
                max_tokens=max_tokens,
                budget_tracker=runtime.budget_tracker,
                agent_name=agent_name,
                llm_options=llm_options,
            )
            usage = resp.get("usage") if isinstance(resp, dict) else None
            _accumulate_usage(usage_acc, usage if isinstance(usage, dict) else None)
            runtime._trace(agent_name, "response", {
                "choices": resp.get("choices", []),
                "usage": usage,
            })
            return resp

        iteration = 0
        final_content: str = ""
        total_tool_calls = 0
        forced = False
        for iteration in range(1, max_iterations + 1):
            resp = await _one_call(msgs)
            choice = (resp.get("choices") or [{}])[0]
            message = choice.get("message") or {}
            content = message.get("content") or ""
            tool_calls = message.get("tool_calls") or []

            if tool_calls:
                msgs.append({
                    "role": "assistant",
                    "content": content or None,
                    "tool_calls": tool_calls,
                })
                for tc in tool_calls:
                    fn = tc.get("function", {}) or {}
                    name = fn.get("name", "")
                    raw_args = fn.get("arguments") or "{}"
                    try:
                        args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                    except json.JSONDecodeError:
                        args = {}
                    result = await runtime._dispatch_tool(
                        agent_name, name, args, dev_calls,
                        extra_handlers=tool_handlers,
                        call_history=call_history,
                    )
                    msgs.append({
                        "role": "tool",
                        "tool_call_id": tc.get("id", ""),
                        "content": result,
                    })
                    total_tool_calls += 1

                if (
                    not forced
                    and force_finalise_after is not None
                    and total_tool_calls >= force_finalise_after
                ):
                    msgs.append({
                        "role": "user",
                        "content": (
                            f"You have made {total_tool_calls} tool calls — that is enough investigation. "
                            "Stop calling tools and produce your final output now using what you already know. "
                            "Do not call any more tools. If you are uncertain about a detail, make a reasonable "
                            "assumption and proceed."
                        ),
                    })
                    runtime._trace(agent_name, "force_finalise", {"after_tool_calls": total_tool_calls})
                    forced = True
                continue

            final_content = content
            break
        else:
            runtime._trace(agent_name, "forced_finalisation", {"reason": "max_iterations_exhausted"})
            msgs.append({
                "role": "user",
                "content": (
                    f"You have exhausted your investigation budget ({max_iterations} turns). "
                    "Stop investigating. Output your final answer NOW based on what you know "
                    "so far. NO tool calls — only the requested output format. "
                    "If you are uncertain about a detail, make a reasonable assumption based "
                    "on what you have read and proceed. Producing an imperfect answer is better "
                    "than producing none."
                ),
            })
            trimmed_msgs, dropped = _trim_history_for_budget(msgs)
            if dropped:
                runtime._trace(agent_name, "history_trimmed", {
                    "dropped_cycles": dropped,
                    "kept_messages": len(trimmed_msgs),
                    "original_messages": len(msgs),
                    "where": "forced_finalisation",
                })
            cached_msgs = _apply_cache_control(trimmed_msgs, model)
            llm_options = runtime.llm_options_for_agent(agent_name)
            runtime._trace(agent_name, "forced_request", {
                "model": model,
                "messages": trimmed_msgs,
                "llm_options": llm_options,
            })
            try:
                resp = await call_llm(
                    model=model,
                    messages=cached_msgs,
                    tools=[],
                    max_tokens=max_tokens,
                    budget_tracker=runtime.budget_tracker,
                    agent_name=agent_name,
                    llm_options=llm_options,
                )
            except Exception as e:
                raise AgentOutputError(
                    f"{agent_name}: exceeded {max_iterations} iterations and forced "
                    f"finalisation also failed: {e}"
                )
            usage = resp.get("usage") if isinstance(resp, dict) else None
            _accumulate_usage(usage_acc, usage if isinstance(usage, dict) else None)
            runtime._trace(agent_name, "forced_response", {"choices": resp.get("choices", []), "usage": usage})
            choice = (resp.get("choices") or [{}])[0]
            message = choice.get("message") or {}
            final_content = message.get("content") or ""
            if not final_content.strip():
                raise AgentOutputError(
                    f"{agent_name}: exceeded {max_iterations} iterations and forced "
                    f"finalisation returned empty content"
                )
            iteration = max_iterations + 1

        if output_schema is None:
            return AgentResult(
                output=final_content,
                token_usage=usage_acc,
                developer_calls_made=dev_calls[0],
                iterations=iteration,
            )

        for attempt in (1, 2):
            stripped = _strip_fences(final_content)
            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError as e:
                err = f"Your response was not valid JSON: {e}. Output ONLY the JSON now, no prose, no fences."
            else:
                try:
                    validated = output_schema.model_validate(parsed)
                    return AgentResult(
                        output=validated,
                        token_usage=usage_acc,
                        developer_calls_made=dev_calls[0],
                        iterations=iteration,
                    )
                except ValidationError as e:
                    err = f"Your JSON failed schema validation:\n{e}\nFix it and return ONLY the corrected JSON."

            if attempt == 2:
                raise AgentOutputError(f"{agent_name}: schema validation failed after retry — {err}")

            msgs.append({"role": "assistant", "content": final_content})
            msgs.append({"role": "user", "content": err})
            runtime._trace(agent_name, "retry", {"reason": err[:500]})
            resp = await _one_call(msgs)
            choice = (resp.get("choices") or [{}])[0]
            final_content = (choice.get("message") or {}).get("content") or ""

        raise AgentOutputError(f"{agent_name}: schema validation loop exited unexpectedly")
