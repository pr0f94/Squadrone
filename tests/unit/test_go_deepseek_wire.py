"""Go DeepSeek needs an explicit empty reasoning slot for non-thinking tool turns."""

from __future__ import annotations

import copy
import json

import litellm
import pytest
from pydantic import ValidationError

from squadrone.agents.runtime import AgentRuntime
from squadrone.schemas.config import ModelProfile, PipelineConfig
from squadrone.services import llm
from squadrone.services.model_profiles import resolve_model


_URL = "https://opencode.ai/inference/go/openai/v1/chat/completions"
_ABSENT = "__absent__"
_OPAQUE = "Exact opaque reasoning, including spacing.\nDo not rewrite."
_TOOLS = [{
    "type": "function",
    "function": {
        "name": "inspect",
        "parameters": {"type": "object", "properties": {}},
    },
}]


def _response(message, finish_reason="tool_calls"):
    return {
        "id": "chatcmpl-deepseek", "object": "chat.completion", "created": 1,
        "model": "deepseek-v4.1-flash",
        "choices": [{"index": 0, "finish_reason": finish_reason, "message": message}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12},
    }


def _tool_message(number, reasoning):
    message = {
        "role": "assistant", "content": "Inspect the next source range.",
        "tool_calls": [{
            "id": f"inspect-{number}", "type": "function",
            "function": {"name": "inspect", "arguments": json.dumps({"range": number})},
        }],
    }
    if reasoning != _ABSENT:
        message["reasoning_content"] = reasoning
    return message


@pytest.fixture
def go_config(monkeypatch):
    monkeypatch.setattr(litellm, "disable_aiohttp_transport", True)
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "test-deepseek-only")
    return PipelineConfig.from_yaml("pipelines/opencode-go.yaml")


@pytest.mark.parametrize("updates", [
    {"thinking": "disabled"},
    {"thinking": None},
    {"api_format": "anthropic_messages", "thinking": None, "generation": {}},
])
def test_empty_tool_reasoning_requires_thinking_chat(go_config, updates):
    profile = go_config.model_profiles["go-deepseek"].model_dump() | updates
    with pytest.raises(ValidationError, match="empty_tool_reasoning"):
        ModelProfile.model_validate(profile)


def test_normalization_is_opt_in_and_preserves_original_nested_reasoning(go_config):
    nested = _tool_message(1, _ABSENT)
    nested["provider_specific_fields"] = {
        "reasoning_content": _OPAQUE, "signature": "opaque provider signature",
    }
    explicit_empty = _tool_message(2, "")
    explicit_empty["provider_specific_fields"] = {"reasoning_content": "do not overwrite top-level"}
    messages = [
        {"role": "user", "content": "Inspect."},
        nested,
        {"role": "tool", "tool_call_id": "inspect-1", "content": "source"},
        explicit_empty,
        {"role": "assistant", "content": "Final answer."},
        _tool_message(3, None),
    ]
    original = copy.deepcopy(messages)
    options = go_config.gateway_options()
    prepared = resolve_model("profile/go-deepseek", options).prepare_messages(messages)

    assert messages == original
    assert prepared is not messages
    assert prepared[1]["reasoning_content"] == _OPAQUE
    assert prepared[1]["provider_specific_fields"] == nested["provider_specific_fields"]
    assert prepared[3]["reasoning_content"] == ""
    assert prepared[3]["provider_specific_fields"] == explicit_empty["provider_specific_fields"]
    assert prepared[5]["reasoning_content"] == ""
    for index in (0, 2, 4):
        assert "reasoning_content" not in prepared[index]
    for model in ("profile/go-glm", "profile/go-qwen", "legacy-model"):
        assert resolve_model(model, options).prepare_messages(messages) is messages
    disabled = copy.deepcopy(options)
    disabled["_model_profiles"]["go-deepseek"]["empty_tool_reasoning"] = False
    disabled_route = resolve_model("profile/go-deepseek", disabled)
    assert disabled_route.prepare_messages(messages) is messages
    enabled_route = resolve_model("profile/go-deepseek", options)
    assert disabled_route.identity == enabled_route.identity
    assert llm._cache_key(
        enabled_route.request_model, prepared, _TOOLS, enabled_route.identity,
    ) != llm._cache_key(
        disabled_route.request_model, messages, _TOOLS, disabled_route.identity,
    )


@pytest.mark.asyncio
async def test_wire_recovers_actual_nested_reasoning_without_mutating_history(
    go_config, tmp_path, httpx_mock,
):
    httpx_mock.add_response(
        method="POST", url=_URL,
        json=_response({"role": "assistant", "content": "Evidence complete."}, "stop"),
    )
    assistant = _tool_message(1, _ABSENT)
    assistant["provider_specific_fields"] = {"reasoning_content": _OPAQUE}
    messages = [
        {"role": "user", "content": "Inspect."}, assistant,
        {"role": "tool", "tool_call_id": "inspect-1", "content": "source"},
    ]
    original = copy.deepcopy(messages)
    cache = str(tmp_path / "llm.sqlite")
    await llm.init_cache(cache)

    await llm.call_llm(
        model="profile/go-deepseek", messages=messages, tools=_TOOLS,
        llm_options=go_config.gateway_options(), cache_db=cache,
        conversation_id="nested-reasoning-session",
    )

    body = json.loads(httpx_mock.get_requests()[0].content)
    assert body["messages"][1]["reasoning_content"] == _OPAQUE
    assert body["messages"][1]["tool_calls"] == assistant["tool_calls"]
    assert messages == original
    assert "reasoning_content" not in messages[1]


@pytest.mark.asyncio
@pytest.mark.parametrize("first_reasoning", [_ABSENT, None, "", _OPAQUE])
async def test_real_deepseek_tool_wire_keeps_empty_and_opaque_reasoning(
    go_config, first_reasoning, monkeypatch, tmp_path, httpx_mock,
):
    first = _tool_message(1, first_reasoning)
    second = _tool_message(2, _OPAQUE)
    httpx_mock.add_response(method="POST", url=_URL, json=_response(first))
    httpx_mock.add_response(method="POST", url=_URL, json=_response(second))
    httpx_mock.add_response(
        method="POST", url=_URL,
        json=_response({"role": "assistant", "content": "Evidence complete."}, "stop"),
    )
    cache = str(tmp_path / "llm.sqlite")
    await llm.init_cache(cache)
    gateway_inputs = []

    async def gateway_call(**kwargs):
        original = copy.deepcopy(kwargs["messages"])
        result = await llm.call_llm(cache_db=cache, **kwargs)
        assert kwargs["messages"] == original
        gateway_inputs.append(original)
        return result

    monkeypatch.setattr("squadrone.agents.transport.litellm_transport.call_llm", gateway_call)
    runtime = AgentRuntime(str(tmp_path / "run"), llm_options=go_config.gateway_options())
    result = await runtime.run(
        agent_name="injection_files.b002-retry", model="profile/go-deepseek",
        messages=[{"role": "user", "content": "Inspect exact source."}],
        tools=_TOOLS, tool_handlers={"inspect": lambda args: "bounded source evidence"},
        max_iterations=3,
    )

    assert result.output == "Evidence complete."
    requests = httpx_mock.get_requests()
    assert len(requests) == 3
    sessions = {request.headers["x-opencode-session"] for request in requests}
    assert len(sessions) == 1
    expected = "" if first_reasoning in {_ABSENT, None} else first_reasoning
    for request in requests[1:]:
        body = json.loads(request.content)
        assert body["model"] == "deepseek-v4.1-flash"
        assert body["max_tokens"] == 32768
        assistants = [message for message in body["messages"] if message["role"] == "assistant"]
        assert assistants[0]["reasoning_content"] == expected
        assert assistants[0]["tool_calls"] == first["tool_calls"]
        assert assistants[0]["content"] == first["content"]
    assistants = [
        message for message in json.loads(requests[-1].content)["messages"]
        if message["role"] == "assistant"
    ]
    assert assistants[1]["reasoning_content"] == _OPAQUE
    assert assistants[1]["tool_calls"] == second["tool_calls"]
    # Original provider history is untouched: normalize only at the gateway.
    original_first = gateway_inputs[1][1]
    if first_reasoning in {_ABSENT, None}:
        assert "reasoning_content" not in original_first
    else:
        assert original_first["reasoning_content"] == first_reasoning
