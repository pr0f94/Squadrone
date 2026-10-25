from __future__ import annotations

import copy
import json

import pytest
import litellm
from pydantic import ValidationError

from squadrone.schemas.config import ModelProfile, PipelineConfig
from squadrone.services.llm import _cache_key, call_llm, init_cache
from squadrone.services.model_profiles import resolve_model


@pytest.fixture(autouse=True)
def use_mockable_httpx_transport(monkeypatch):
    # LiteLLM otherwise uses an aiohttp-backed HTTPX transport, which bypasses
    # pytest-httpx. Keep real adapter serialization, but mock the HTTP boundary.
    monkeypatch.setattr(litellm, "disable_aiohttp_transport", True)


@pytest.fixture
def go_config():
    return PipelineConfig.from_yaml("pipelines/opencode-go.yaml")


def test_complete_role_mapping_and_legacy_compatibility(go_config):
    expected = {role: "profile/go-deepseek" for role in go_config.models.model_dump()}
    expected.update(surveyor="profile/go-glm", reporter="profile/go-qwen")
    assert go_config.models.model_dump() == expected
    old = PipelineConfig.from_yaml("pipelines/chatgpt.yaml")
    assert old.model_profiles == {}
    assert old.llm_options_for_role("surveyor") == {"reasoning_effort": "medium"}
    assert resolve_model(old.models.surveyor, old.gateway_options()).request_model == old.models.surveyor


def test_profile_resolution_has_no_secrets_and_checks_controls(go_config, monkeypatch):
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "secret-only-at-dispatch")
    route = resolve_model(go_config.models.surveyor, go_config.gateway_options())
    assert route.options["reasoning_effort"] == "max"
    assert route.options["extra_body"] == {"thinking": {"type": "enabled"}}
    assert "secret-only-at-dispatch" not in json.dumps(route.identity)
    assert route.output_limit(65536) == 32768
    assert route.output_limit(4096) == 4096
    deepseek = resolve_model(go_config.models.developer, go_config.gateway_options())
    assert deepseek.output_limit(4096) == 32768
    assert deepseek.output_limit(65536) == 32768
    with pytest.raises(ValueError, match="positive"):
        deepseek.output_limit(0)
    for options in ({"reasoning_effort": "medium"}, {"api_key": "forbidden"}, {"drop_params": True}):
        with pytest.raises(ValueError):
            resolve_model(go_config.models.surveyor, go_config.gateway_options() | options)
    with pytest.raises(ValueError, match="does not support"):
        resolve_model(go_config.models.reporter, go_config.gateway_options() | {"reasoning_effort": "high"})


@pytest.mark.parametrize("updates", [
    {"api_base": "https://user:password@opencode.ai/inference"},
    {"api_base": "https://opencode.ai/inference?key=secret"},
    {"api_base": "http://opencode.ai/inference"},
    {"api_base": "https://opencode.ai/inference\n"},
    {"api_base": "https://opencode.ai:notaport/inference"},
    {"api_base": "https://opencode.ai:99999/inference"},
    {"api_key_env": "literal-secret-key"},
    {"api_key": "not-allowed"},
    {"generation": {"api_key": "not-allowed"}},
    {"output_budget_floor": 0},
    {"output_budget_floor": 65536},
    {"pricing": {"input_per_million": -1, "output_per_million": 1}},
])
def test_profile_rejects_unsafe_configuration(go_config, updates):
    profile = go_config.model_profiles["go-glm"].model_dump() | updates
    with pytest.raises(ValidationError):
        ModelProfile.model_validate(profile)


def test_missing_profile_reference_rejected(go_config):
    data = go_config.model_dump()
    data["models"]["surveyor"] = "profile/missing"
    with pytest.raises(ValidationError, match="unknown model profile"):
        PipelineConfig.model_validate(data)


def test_cache_identity_changes_with_route_options_and_output_limit(go_config):
    options = go_config.gateway_options()
    route = resolve_model("profile/go-glm", options)
    base = _cache_key(route.request_model, [], None, route.identity, 100)
    assert _cache_key(route.request_model, [], None, route.identity, 200) != base
    changed = copy.deepcopy(options)
    changed["_model_profiles"]["go-glm"]["api_base"] = "https://other.example/v1"
    assert _cache_key(route.request_model, [], None, resolve_model("profile/go-glm", changed).identity, 100) != base
    changed = options | {"reasoning_effort": "low"}
    assert _cache_key(route.request_model, [], None, resolve_model("profile/go-glm", changed).identity, 100) != base


def _chat_response(model, message=None):
    return {
        "id": "chatcmpl-test", "object": "chat.completion", "created": 1,
        "model": model,
        "choices": [{"index": 0, "finish_reason": "stop", "message": message or {"role": "assistant", "content": "ok"}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12},
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("role,model,effort", [
    ("surveyor", "glm-5.3", "max"),
    ("specialists", "deepseek-v4.1-flash", "high"),
    ("reporter", "qwen3.8-max", None),
])
async def test_real_adapter_wire_routing_headers_and_secret_free_cache(
    go_config, role, model, effort, monkeypatch, tmp_path, httpx_mock,
):
    secret = "test-go-secret-never-store"
    monkeypatch.setenv("OPENCODE_GO_API_KEY", secret)
    monkeypatch.setenv("OPENAI_API_KEY", "unrelated-openai-key")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "unrelated-anthropic-key")
    if role == "reporter":
        response = {
            "id": "msg-test", "type": "message", "role": "assistant", "model": model,
            "content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 2},
        }
        url = "https://opencode.ai/inference/go/anthropic/v1/messages"
    else:
        response = _chat_response(model)
        url = "https://opencode.ai/inference/go/openai/v1/chat/completions"
    httpx_mock.add_response(method="POST", url=url, json=response)
    cache = str(tmp_path / "llm.sqlite")
    await init_cache(cache)
    kwargs = dict(
        model=getattr(go_config.models, role), messages=[{"role": "user", "content": "hello"}],
        llm_options=go_config.llm_options_for_role(role), max_tokens=100,
        cache_db=cache, conversation_id="conversation-one",
    )
    result = await call_llm(**kwargs)
    assert result["choices"][0]["message"]["content"] == "ok"
    request = httpx_mock.get_requests()[0]
    assert request.headers["authorization"] == f"Bearer {secret}"
    assert request.headers["user-agent"] == "squadrone/0.1.0"
    assert request.headers["x-opencode-session"] == "conversation-one"
    assert "unrelated-openai-key" not in str(dict(request.headers))
    assert "unrelated-anthropic-key" not in str(dict(request.headers))
    body = json.loads(request.content)
    assert body["model"] == model
    assert body["max_tokens"] == (32768 if role == "specialists" else 100)
    if effort:
        assert body["reasoning_effort"] == effort
        assert body["thinking"] == {"type": "enabled"}
    else:
        assert "reasoning_effort" not in body
        assert "thinking" not in body
    # A cache hit requires neither credentials nor a network call. Session IDs
    # deliberately do not fragment a response's semantic cache identity.
    monkeypatch.delenv("OPENCODE_GO_API_KEY")
    assert await call_llm(**(kwargs | {"conversation_id": "another-session"})) == result
    assert len(httpx_mock.get_requests()) == 1
    assert secret.encode() not in (tmp_path / "llm.sqlite").read_bytes()


@pytest.mark.asyncio
@pytest.mark.parametrize("name,model", [("go-glm", "glm-5.3"), ("go-deepseek", "deepseek-v4.1-flash")])
async def test_actual_chat_adapter_preserves_reasoning_on_tool_continuation(
    go_config, name, model, monkeypatch, tmp_path, httpx_mock,
):
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "test-key")
    assistant = {
        "role": "assistant", "content": None, "reasoning_content": "opaque reasoning history",
        "tool_calls": [{"id": "call-1", "type": "function", "function": {"name": "inspect", "arguments": "{}"}}],
    }
    url = "https://opencode.ai/inference/go/openai/v1/chat/completions"
    httpx_mock.add_response(method="POST", url=url, json=_chat_response(model, assistant))
    httpx_mock.add_response(method="POST", url=url, json=_chat_response(model))
    cache = str(tmp_path / "llm.sqlite")
    await init_cache(cache)
    messages = [{"role": "user", "content": "inspect"}]
    kwargs = dict(model=f"profile/{name}", cache_db=cache, llm_options=go_config.gateway_options(), conversation_id="stable-session")
    tools = [{"type": "function", "function": {"name": "inspect", "parameters": {"type": "object", "properties": {}}}}]
    result = await call_llm(messages=messages, tools=tools, **kwargs)
    reply = result["choices"][0]["message"]
    assert reply["reasoning_content"] == assistant["reasoning_content"]
    messages.extend([reply, {"role": "tool", "tool_call_id": "call-1", "content": "source"}])
    await call_llm(messages=messages, tools=tools, **kwargs)
    second = json.loads(httpx_mock.get_requests()[1].content)
    assert second["messages"][1]["reasoning_content"] == assistant["reasoning_content"]
    assert second["messages"][1]["tool_calls"] == assistant["tool_calls"]


@pytest.mark.asyncio
async def test_missing_key_and_configured_overflow_fail_without_dispatch(go_config, monkeypatch, tmp_path):
    monkeypatch.delenv("OPENCODE_GO_API_KEY", raising=False)
    cache = str(tmp_path / "llm.sqlite")
    await init_cache(cache)
    kwargs = dict(model="profile/go-glm", messages=[{"role": "user", "content": "hello"}], cache_db=cache, llm_options=go_config.gateway_options())
    with pytest.raises(ValueError, match="OPENCODE_GO_API_KEY"):
        await call_llm(**kwargs)
    options = go_config.gateway_options()
    options["_model_profiles"]["go-glm"]["max_input_tokens"] = 1
    with pytest.raises(ValueError, match="not silently truncated"):
        await call_llm(**(kwargs | {"llm_options": options}))


@pytest.mark.asyncio
@pytest.mark.parametrize("variable", ["OPENAI_CUSTOM_HEADERS", "OPENAI_ORG_ID", "OPENAI_PROJECT_ID", "OPENAI_ORGANIZATION"])
async def test_ambient_sdk_headers_are_rejected_without_dispatch(
    go_config, monkeypatch, tmp_path, httpx_mock, variable,
):
    monkeypatch.setenv("OPENCODE_GO_API_KEY", "go-key")
    secret = "unrelated-private-header-value"
    monkeypatch.setenv(variable, f"x-api-key: {secret}" if variable == "OPENAI_CUSTOM_HEADERS" else secret)
    cache = str(tmp_path / "llm.sqlite")
    await init_cache(cache)
    with pytest.raises(ValueError, match="unset") as error:
        await call_llm(model="profile/go-glm", messages=[], llm_options=go_config.gateway_options(), cache_db=cache)
    assert secret not in str(error.value)
    assert httpx_mock.get_requests() == []


def test_malformed_config_errors_do_not_echo_literal_keys(go_config):
    data = go_config.model_dump()
    data["model_profiles"]["go-glm"]["api_key"] = "accidentally-pasted-secret"
    with pytest.raises(ValidationError) as error:
        PipelineConfig.model_validate(data)
    assert "accidentally-pasted-secret" not in str(error.value)
