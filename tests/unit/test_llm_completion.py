"""Reasoning-heavy helpers must yield complete answers, not plausible fragments."""

from __future__ import annotations

import copy

import litellm
import pytest

from squadrone.schemas.config import PipelineConfig
from squadrone.agents.developer import DeveloperAgent
from squadrone.services import llm
from squadrone.services.budget import BudgetExceededError, BudgetTracker


def _response(content, finish="stop", **message):
    return {
        "choices": [{"finish_reason": finish, "message": {
            "role": "assistant", "content": content, **message,
        }}],
    }


def _escalation_config() -> PipelineConfig:
    """Shipped routes with headroom for the one-shot escalation retry.

    The shipped profile starts at its output ceiling, so the escalation path is
    exercised here with the historical 16K floor.
    """
    config = PipelineConfig.from_yaml("pipelines/opencode-go.yaml")
    config.model_profiles["go-deepseek"].output_budget_floor = 16384
    return config


@pytest.mark.parametrize("response", [
    _response(None, "length", reasoning_content="opaque reasoning"),
    _response('{"commands":[]}', "length"),
    _response("partial advice", "max_tokens"),
    _response("", "stop"), _response("  ", "stop"),
    _response("filtered", "content_filter"),
    _response(None, refusal="refused"), {},
])
def test_incomplete_output_is_not_a_success(response):
    with pytest.raises(llm.IncompleteLLMResponse):
        llm.require_complete_response(response)


def test_tool_only_turns_are_allowed_only_when_explicit():
    response = _response(None, "tool_calls", tool_calls=[{"id": "call-1"}])
    llm.require_complete_response(response, require_content=False)
    with pytest.raises(llm.IncompleteLLMResponse):
        llm.require_complete_response(response)
    with pytest.raises(llm.IncompleteLLMResponse):
        llm.require_complete_response(_response(None), require_content=False)


@pytest.mark.asyncio
@pytest.mark.parametrize("first", [None, "partial advice", '{"commands":[]}'])
async def test_oneshot_retries_once_with_larger_allowance_same_prompt_and_session(monkeypatch, first):
    config = _escalation_config()
    responses = iter([_response(first, "length"), _response("complete answer")])
    requests = []

    async def fake_call(**kwargs):
        requests.append(copy.deepcopy(kwargs))
        return next(responses)

    monkeypatch.setattr(llm, "call_llm", fake_call)
    messages = [{"role": "user", "content": "source-grounded question"}]
    result = await llm.call_llm_oneshot(
        model=config.models.developer, messages=messages,
        llm_options=config.gateway_options(), return_response=True,
    )
    assert result["choices"][0]["message"]["content"] == "complete answer"
    assert [request["max_tokens"] for request in requests] == [16384, 32768]
    assert requests[0]["messages"] == requests[1]["messages"] == messages
    assert requests[0]["conversation_id"] == requests[1]["conversation_id"]
    assert requests[0]["conversation_id"]


@pytest.mark.asyncio
async def test_oneshot_exhaustion_is_bounded_and_visible(monkeypatch):
    config = _escalation_config()
    requests = []

    async def fake_call(**kwargs):
        requests.append(kwargs)
        return _response(None, "length")

    monkeypatch.setattr(llm, "call_llm", fake_call)
    with pytest.raises(llm.IncompleteLLMResponse, match="length"):
        await llm.call_llm_oneshot(
            model=config.models.developer, messages=[], llm_options=config.gateway_options(),
        )
    assert len(requests) == 2


@pytest.mark.asyncio
async def test_setup_never_parses_or_executes_parseable_truncated_commands(monkeypatch):
    config = _escalation_config()
    requests = []

    async def fake_call(**kwargs):
        requests.append(kwargs)
        return _response('{"rationale":"partial","commands":[["eval","do_something();"]]}', "length")

    def forbidden_parse(_content):
        pytest.fail("Incomplete provider output reached setup command parsing")

    monkeypatch.setattr(llm, "call_llm", fake_call)
    monkeypatch.setattr("squadrone.agents.developer._parse_json_resilient", forbidden_parse)
    developer = DeveloperAgent(config.models.developer, llm_options=config.gateway_options())
    with pytest.raises(llm.IncompleteLLMResponse):
        await developer._call_setup_json(
            model=developer.model,
            messages=[{"role": "user", "content": "Plan benign setup."}],
            agent_name="developer.propose_setup",
        )
    assert [request["max_tokens"] for request in requests] == [16384, 32768]


@pytest.mark.asyncio
@pytest.mark.parametrize("model,finish,message", [
    ("legacy-model", "length", {}),
    ("profile/go-deepseek", "content_filter", {}),
    ("profile/go-deepseek", "stop", {"refusal": "no"}),
])
async def test_no_expansion_for_legacy_or_refused_responses(monkeypatch, model, finish, message):
    config = _escalation_config()
    requests = []

    async def fake_call(**kwargs):
        requests.append(kwargs)
        return _response(None, finish, **message)

    monkeypatch.setattr(llm, "call_llm", fake_call)
    with pytest.raises(llm.IncompleteLLMResponse):
        await llm.call_llm_oneshot(model=model, messages=[], llm_options=config.gateway_options())
    assert len(requests) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("ceiling,expected_calls", [(1.0, 2), (0.04, 1)])
async def test_every_expansion_is_reserved_and_charged(monkeypatch, tmp_path, ceiling, expected_calls):
    config = _escalation_config()
    tracker = BudgetTracker(ceiling)
    requests = []
    cache = str(tmp_path / "llm.sqlite")
    await llm.init_cache(cache)
    real_call = llm.call_llm

    async def local_cache_call(**kwargs):
        return await real_call(**kwargs, cache_db=cache)

    async def completion(kwargs):
        requests.append(kwargs)
        content = None if len(requests) == 1 else "answer"
        reason = "length" if len(requests) == 1 else "stop"
        return litellm.ModelResponse(
            model=kwargs["model"], choices=_response(content, reason)["choices"],
            usage={"prompt_tokens": 10, "completion_tokens": 16384 if content is None else 100},
        )

    monkeypatch.setenv("OPENCODE_GO_API_KEY", "test-key")
    monkeypatch.setattr(llm, "call_llm", local_cache_call)
    monkeypatch.setattr(llm, "_acompletion_with_retries", completion)
    kwargs = dict(model=config.models.developer, messages=[], llm_options=config.gateway_options(), budget_tracker=tracker)
    if expected_calls == 1:
        with pytest.raises(BudgetExceededError):
            await llm.call_llm_oneshot(**kwargs)
    else:
        assert await llm.call_llm_oneshot(**kwargs) == "answer"
    assert len(requests) == len(tracker.calls) == expected_calls
    assert tracker._reserved_usd == 0
    assert tracker.output_tokens == (16384 if expected_calls == 1 else 16484)
    # A cached incomplete response can never become a successful answer. Both
    # semantic budget keys are distinct; cached replay makes no provider calls.
    if expected_calls == 2:
        assert await llm.call_llm_oneshot(**kwargs) == "answer"
        assert len(requests) == 2
