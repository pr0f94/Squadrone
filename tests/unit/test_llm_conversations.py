"""Conversation identity and complete assistant history across agent paths."""

from __future__ import annotations

import asyncio
import copy
import json

import pytest
from pydantic import BaseModel

from squadrone.agents.developer import DeveloperAgent
from squadrone.agents.runtime import AgentRuntime
from squadrone.agents.transport.litellm_transport import LiteLLMTransport
from squadrone.services.llm_context import current_conversation, new_conversation
from squadrone.services.model_profiles import ResolvedModel


class _Output(BaseModel):
    answer: str


def _reply(content: str | None, **fields) -> dict:
    return {
        "choices": [{"message": {"role": "assistant", "content": content, **fields}}],
        "usage": {},
    }


def _tool_reply(index: int, **fields) -> dict:
    return _reply(
        None,
        tool_calls=[{
            "id": f"call-{index}",
            "type": "function",
            "function": {"name": "read", "arguments": json.dumps({"index": index})},
            "provider_specific_fields": {"signature": "tool-signature"},
        }],
        **fields,
    )


def _reasoning_fields() -> dict:
    return {
        "reasoning_content": "Preserved model reasoning",
        "thinking_blocks": [{"type": "thinking", "thinking": "thought", "signature": "signed"}],
        "reasoning_items": [{"type": "reasoning", "id": "rs-1", "encrypted_content": "opaque", "summary": []}],
        "provider_specific_fields": {"opaque": "provider-state"},
    }


async def _run(runtime: AgentRuntime, **overrides):
    options = {
        "runtime": runtime,
        "agent_name": "surveyor",
        "model": "test-model",
        "messages": [{"role": "user", "content": "Inspect this plugin."}],
        "tools": [],
        "max_iterations": 4,
        "output_schema": None,
        "tool_handlers": {"read": lambda args: "source evidence"},
        "force_finalise_after": None,
        "max_tokens": 100,
    }
    options.update(overrides)
    return await LiteLLMTransport().run_agent(**options)


@pytest.mark.asyncio
async def test_tool_loop_and_json_repair_replay_complete_assistant(monkeypatch, tmp_path):
    tool_response = _tool_reply(0, **_reasoning_fields())
    invalid_response = _reply("not json", **_reasoning_fields())
    responses = iter([tool_response, invalid_response, _reply('{"answer":"ok"}')])
    requests = []

    async def fake_call(**kwargs):
        requests.append(copy.deepcopy(kwargs))
        return next(responses)

    monkeypatch.setattr("squadrone.agents.transport.litellm_transport.call_llm", fake_call)
    result = await _run(AgentRuntime(str(tmp_path)), output_schema=_Output)

    assert result.output.answer == "ok"
    assert requests[1]["messages"][1] == tool_response["choices"][0]["message"]
    assert requests[2]["messages"][-2] == invalid_response["choices"][0]["message"]
    assert len({request["conversation_id"] for request in requests}) == 1
    assert requests[0]["conversation_id"]
    assert current_conversation() is None


@pytest.mark.asyncio
async def test_forced_finalisation_and_its_repair_keep_session_and_reasoning(monkeypatch, tmp_path):
    forced_response = _reply("invalid json", **_reasoning_fields())
    responses = iter([_tool_reply(0), forced_response, _reply('{"answer":"forced"}')])
    requests = []

    async def fake_call(**kwargs):
        requests.append(copy.deepcopy(kwargs))
        return next(responses)

    monkeypatch.setattr("squadrone.agents.transport.litellm_transport.call_llm", fake_call)
    result = await _run(AgentRuntime(str(tmp_path)), max_iterations=1, output_schema=_Output)

    assert result.output.answer == "forced"
    assert requests[1]["tools"] == []
    assert "exhausted" in requests[1]["messages"][-1]["content"]
    assert requests[2]["messages"][-2] == forced_response["choices"][0]["message"]
    assert len({request["conversation_id"] for request in requests}) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("history_policy", ["preserve", "trim"])
async def test_preserved_profiles_bypass_legacy_history_window(monkeypatch, tmp_path, history_policy):
    responses = iter([*[_tool_reply(index, **_reasoning_fields()) for index in range(13)], _reply("done")])
    requests = []

    async def fake_call(**kwargs):
        requests.append(copy.deepcopy(kwargs))
        return next(responses)

    monkeypatch.setattr("squadrone.agents.transport.litellm_transport.call_llm", fake_call)
    monkeypatch.setattr(
        "squadrone.agents.transport.litellm_transport.resolve_model",
        lambda model, options: ResolvedModel(
            request_model=model,
            options={"reasoning_effort": "max"},
            identity={"model": model},
            history_policy=history_policy,
        ),
    )
    runtime = AgentRuntime(str(tmp_path), llm_options={"_model_profiles": {"configuration": "not a request control"}})
    await _run(
        runtime,
        max_iterations=14,
        tool_handlers={"read": lambda args: "source " + "x" * 10_000},
    )

    last_history = requests[-1]["messages"]
    tool_ids = [message.get("tool_call_id") for message in last_history if message["role"] == "tool"]
    assert ("call-0" in tool_ids) == (history_policy == "preserve")
    assert len(tool_ids) == (13 if history_policy == "preserve" else 12)
    trace = [json.loads(line) for line in runtime.trace_path.read_text().splitlines()]
    request_trace = next(record for record in trace if record["kind"] == "request")
    assert request_trace["llm_options"] == {"reasoning_effort": "max"}
    assert "_model_profiles" not in request_trace["llm_options"]


@pytest.mark.asyncio
async def test_concurrent_agents_have_independent_conversations(monkeypatch, tmp_path):
    sessions = {}

    async def fake_call(**kwargs):
        sessions[kwargs["agent_name"]] = kwargs["conversation_id"]
        await asyncio.sleep(0)
        assert current_conversation().conversation_id == kwargs["conversation_id"]
        return _reply("done")

    monkeypatch.setattr("squadrone.agents.transport.litellm_transport.call_llm", fake_call)
    runtime = AgentRuntime(str(tmp_path))
    await asyncio.gather(_run(runtime, agent_name="first"), _run(runtime, agent_name="second"))

    assert sessions["first"] != sessions["second"]
    assert current_conversation() is None


@pytest.mark.asyncio
async def test_developer_setup_repairs_preserve_full_turn_and_session(monkeypatch):
    original = _reply("not json", **_reasoning_fields())
    responses = iter([original, _reply('{"rationale":"ok","commands":[]}')])
    requests = []

    async def fake_oneshot(**kwargs):
        requests.append(copy.deepcopy(kwargs))
        return next(responses)

    monkeypatch.setattr("squadrone.agents.developer.call_llm_oneshot", fake_oneshot)
    developer = DeveloperAgent("test-model")
    parsed = await developer._call_setup_json(
        model="test-model",
        messages=[{"role": "user", "content": "Set up a fixture."}],
        agent_name="developer.propose_setup",
    )

    assert parsed == {"rationale": "ok", "commands": []}
    assert all(request["return_response"] for request in requests)
    assert requests[0]["conversation_id"] == requests[1]["conversation_id"]
    assert requests[1]["messages"][-2] == original["choices"][0]["message"]


@pytest.mark.asyncio
async def test_nested_consultations_have_distinct_child_sessions(monkeypatch, tmp_path):
    requests = []

    async def fake_oneshot(**kwargs):
        requests.append((kwargs["conversation_id"], current_conversation()))
        return "consultation answer"

    monkeypatch.setattr("squadrone.agents.developer.call_llm_oneshot", fake_oneshot)
    developer = DeveloperAgent("test-model")

    @new_conversation
    async def parent():
        parent_id = current_conversation().conversation_id
        await developer.consult("question", "source")
        await developer.consult("different question", "source")
        assert current_conversation().conversation_id == parent_id
        return parent_id

    parent_id = await parent()
    assert requests[0][0] != requests[1][0]
    assert all(context.parent_conversation_id == parent_id for _, context in requests)
    assert all(session == context.conversation_id for session, context in requests)
    assert current_conversation() is None


@pytest.mark.asyncio
async def test_conversation_scope_restores_after_failure():
    @new_conversation
    async def broken():
        assert current_conversation() is not None
        raise RuntimeError("failed invocation")

    with pytest.raises(RuntimeError, match="failed invocation"):
        await broken()
    assert current_conversation() is None
