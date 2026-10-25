"""Exercise the real LiteLLM Messages adapter against a mocked HTTP boundary."""

from __future__ import annotations

import json

import litellm
import pytest

from squadrone.agents.runtime import AgentRuntime
from squadrone.schemas.config import PipelineConfig
from squadrone.services import llm


_MESSAGES_URL = "https://opencode.ai/inference/go/anthropic/v1/messages"
_GO_KEY = "test-go-messages-secret"
_THINKING = {
    "type": "thinking",
    "thinking": "Inspect the source before answering.",
    "signature": "opaque-signed-thinking",
}
_REDACTED = {"type": "redacted_thinking", "data": "opaque-redacted-thinking"}
_TOOL_USE = {
    "type": "tool_use",
    "id": "toolu-inspect",
    "name": "inspect",
    "input": {"path": "plugin.php"},
}
_TOOLS = [{
    "type": "function",
    "function": {
        "name": "inspect",
        "description": "Read source evidence.",
        "parameters": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
}]


def _message(content: list[dict], stop_reason: str = "end_turn") -> dict:
    return {
        "id": "msg-qwen",
        "type": "message",
        "role": "assistant",
        "model": "qwen3.8-max",
        "content": content,
        "stop_reason": stop_reason,
        "stop_sequence": None,
        "usage": {"input_tokens": 10, "output_tokens": 3},
    }


@pytest.fixture
def go_config(monkeypatch):
    # Keep real request/response serialization while allowing pytest-httpx to
    # intercept HTTPX; LiteLLM's aiohttp transport bypasses that fixture.
    monkeypatch.setattr(litellm, "disable_aiohttp_transport", True)
    monkeypatch.setenv("OPENCODE_GO_API_KEY", _GO_KEY)
    monkeypatch.setenv("OPENAI_API_KEY", "unrelated-openai-key")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "unrelated-anthropic-key")
    return PipelineConfig.from_yaml("pipelines/opencode-go.yaml")


def _assert_go_headers(request, session_id: str) -> None:
    assert request.headers["authorization"] == f"Bearer {_GO_KEY}"
    assert request.headers["user-agent"] == "squadrone/0.1.0"
    assert request.headers["x-opencode-session"] == session_id
    headers = str(dict(request.headers))
    assert "unrelated-openai-key" not in headers
    assert "unrelated-anthropic-key" not in headers


@pytest.mark.asyncio
async def test_qwen_messages_tool_roundtrip_keeps_signed_and_redacted_thinking(
    go_config, monkeypatch, tmp_path, httpx_mock,
):
    httpx_mock.add_response(
        method="POST", url=_MESSAGES_URL,
        json=_message([_THINKING, _REDACTED, _TOOL_USE], "tool_use"),
    )
    httpx_mock.add_response(
        method="POST", url=_MESSAGES_URL,
        json=_message([{"type": "text", "text": "Evidence confirmed."}]),
    )
    cache = str(tmp_path / "llm.sqlite")
    await llm.init_cache(cache)

    async def cached_call(**kwargs):
        return await llm.call_llm(cache_db=cache, **kwargs)

    monkeypatch.setattr(
        "squadrone.agents.transport.litellm_transport.call_llm", cached_call
    )
    runtime = AgentRuntime(
        str(tmp_path / "run"), llm_options=go_config.gateway_options()
    )
    result = await runtime.run(
        agent_name="reporter",
        model=go_config.models.reporter,
        messages=[{"role": "user", "content": "Check plugin.php."}],
        tools=_TOOLS,
        tool_handlers={"inspect": lambda args: "Exact source evidence."},
        max_iterations=2,
        max_tokens=256,
    )

    assert result.output == "Evidence confirmed."
    requests = httpx_mock.get_requests()
    assert len(requests) == 2
    session_id = requests[0].headers["x-opencode-session"]
    assert session_id
    for request in requests:
        _assert_go_headers(request, session_id)
        body = json.loads(request.content)
        assert body["model"] == "qwen3.8-max"
        assert body["max_tokens"] == 256

    second = json.loads(requests[1].content)
    assistant = next(message for message in second["messages"] if message["role"] == "assistant")
    assert assistant["content"] == [_THINKING, _REDACTED, _TOOL_USE]
    tool_reply = second["messages"][-1]
    assert tool_reply["role"] == "user"
    assert tool_reply["content"] == [{
        "type": "tool_result",
        "tool_use_id": "toolu-inspect",
        "content": "Exact source evidence.",
    }]
    trace = [json.loads(line) for line in runtime.trace_path.read_text().splitlines()]
    returned = next(record for record in trace if record["kind"] == "response")["choices"][0]["message"]
    assert returned["thinking_blocks"] == [_THINKING, _REDACTED]
    assert returned["provider_specific_fields"]["thinking_blocks"] == [_THINKING, _REDACTED]
    assert _GO_KEY not in runtime.trace_path.read_text()
    assert _GO_KEY.encode() not in (tmp_path / "llm.sqlite").read_bytes()


@pytest.mark.asyncio
async def test_qwen_http_429_retry_keeps_headers_and_conversation(
    go_config, monkeypatch, tmp_path, httpx_mock,
):
    httpx_mock.add_response(
        method="POST", url=_MESSAGES_URL, status_code=429,
        json={"type": "error", "error": {"type": "rate_limit_error", "message": "Try again"}},
    )
    httpx_mock.add_response(
        method="POST", url=_MESSAGES_URL,
        json=_message([{"type": "text", "text": "Recovered."}]),
    )

    async def no_retry_delay(seconds):
        pass

    monkeypatch.setattr(llm._acompletion_with_retries.retry, "sleep", no_retry_delay)
    cache = str(tmp_path / "llm.sqlite")
    await llm.init_cache(cache)
    response = await llm.call_llm(
        model=go_config.models.reporter,
        messages=[{"role": "user", "content": "Report the evidence."}],
        llm_options=go_config.gateway_options(),
        cache_db=cache,
        max_tokens=256,
        conversation_id="qwen-retry-conversation",
    )

    assert response["choices"][0]["message"]["content"] == "Recovered."
    requests = httpx_mock.get_requests()
    assert len(requests) == 2
    for request in requests:
        _assert_go_headers(request, "qwen-retry-conversation")
    assert json.loads(requests[0].content) == json.loads(requests[1].content)
