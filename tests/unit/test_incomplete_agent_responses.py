"""Interrupted generations must not become expert advice or valid artifacts."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from pydantic import BaseModel, RootModel

from squadrone.agents.runtime import AgentOutputError, AgentRuntime
from squadrone.services.llm import IncompleteLLMResponse


class _Output(BaseModel):
    answer: str


class _Outputs(RootModel[list[_Output]]):
    pass


def _response(content, finish_reason="stop", **message_fields):
    return {
        "choices": [{
            "finish_reason": finish_reason,
            "message": {"role": "assistant", "content": content, **message_fields},
        }],
        "usage": {"completion_tokens": 10},
    }


def _tool_response(finish_reason="tool_calls"):
    return _response(
        None,
        finish_reason,
        reasoning_content="Preserve the complete reasoning state.",
        tool_calls=[{
            "id": "tool-1",
            "type": "function",
            "function": {"name": "read", "arguments": "{}"},
        }],
    )


def _trace(runtime):
    return [json.loads(line) for line in runtime.trace_path.read_text().splitlines()]


async def _run(runtime, **overrides):
    kwargs = {
        "agent_name": "specialists.test",
        "model": "test-model",
        "messages": [{"role": "user", "content": "Inspect the source."}],
        "tools": [],
        "max_iterations": 3,
        "output_schema": _Output,
    }
    kwargs.update(overrides)
    return await runtime.run(**kwargs)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["incomplete", "empty", "unavailable", "limit"])
async def test_unavailable_consultation_is_non_authoritative_failure(tmp_path, failure):
    consult = AsyncMock(return_value="")
    if failure == "incomplete":
        consult.side_effect = IncompleteLLMResponse("finish_reason=length")
    runtime = AgentRuntime(
        str(tmp_path),
        developer=None if failure == "unavailable" else SimpleNamespace(consult=consult),
        developer_calls_per_agent=0 if failure == "limit" else 3,
    )
    calls = [0]
    history = {}

    result = await runtime._dispatch_tool(
        "specialists.test",
        "consult_developer",
        {"question": "Is this reachable?", "code_snippet": "source"},
        calls,
        call_history=history,
    )

    assert result.startswith("[runtime] Developer consultation failed:")
    assert "No authoritative developer answer" in result
    assert "not evidence for or against" in result
    record = _trace(runtime)[0]
    assert record["kind"] == "developer_call"
    assert record["status"] == "unavailable"
    assert record["authoritative"] is False
    assert record["error"]
    assert "answer" not in record
    assert list(history.values()) == [result]
    assert calls[0] == (0 if failure in {"unavailable", "limit"} else 1)


@pytest.mark.asyncio
async def test_consultation_does_not_swallow_unrelated_failure(tmp_path):
    consult = AsyncMock(side_effect=RuntimeError("budget or programming failure"))
    runtime = AgentRuntime(str(tmp_path), developer=SimpleNamespace(consult=consult))

    with pytest.raises(RuntimeError, match="budget or programming failure"):
        await runtime._dispatch_tool(
            "specialists.test", "consult_developer", {}, [0],
        )


@pytest.mark.asyncio
async def test_failed_consultation_continues_as_explicit_tool_failure(monkeypatch, tmp_path):
    tool_reply = _tool_response()
    tool_reply["choices"][0]["message"]["tool_calls"][0]["function"] = {
        "name": "consult_developer",
        "arguments": json.dumps({"question": "Reachable?", "code_snippet": "source"}),
    }
    call = AsyncMock(side_effect=[tool_reply, _response('{"answer":"source evidence only"}')])
    monkeypatch.setattr("squadrone.agents.transport.litellm_transport.call_llm", call)
    consult = AsyncMock(side_effect=IncompleteLLMResponse("finish_reason=length"))
    runtime = AgentRuntime(str(tmp_path), developer=SimpleNamespace(consult=consult))

    result = await _run(runtime)

    assert result.output.answer == "source evidence only"
    assert result.developer_calls_made == 1
    request = call.await_args_list[1].kwargs
    assert request["messages"][-1]["role"] == "tool"
    assert "No authoritative developer answer" in request["messages"][-1]["content"]
    assert request["messages"][-2] == tool_reply["choices"][0]["message"]
    assert call.await_args_list[0].kwargs["conversation_id"] == request["conversation_id"]


@pytest.mark.asyncio
@pytest.mark.parametrize("finish_reason", ["length", "max_tokens", "content_filter"])
async def test_parseable_interrupted_final_is_not_accepted_or_repaired(
    monkeypatch, tmp_path, finish_reason,
):
    call = AsyncMock(return_value=_response('{"answer":"partial"}', finish_reason))
    monkeypatch.setattr("squadrone.agents.transport.litellm_transport.call_llm", call)
    runtime = AgentRuntime(str(tmp_path))

    with pytest.raises(AgentOutputError, match="incomplete"):
        await _run(runtime)

    assert call.await_count == 1
    assert _trace(runtime)[-1]["kind"] == "incomplete_response"
    assert _trace(runtime)[-1]["finish_reason"] == finish_reason
    assert not list(tmp_path.glob("schema_invalid_*.json"))


@pytest.mark.asyncio
@pytest.mark.parametrize("content", [None, "", "   "])
async def test_empty_final_cannot_become_empty_root_list(monkeypatch, tmp_path, content):
    call = AsyncMock(return_value=_response(content))
    monkeypatch.setattr("squadrone.agents.transport.litellm_transport.call_llm", call)
    runtime = AgentRuntime(str(tmp_path))

    with pytest.raises(AgentOutputError, match="incomplete"):
        await _run(runtime, output_schema=_Outputs)

    assert call.await_count == 1
    assert not list(tmp_path.glob("schema_invalid_*.json"))


@pytest.mark.asyncio
async def test_refusal_is_not_accepted_as_parseable_json(monkeypatch, tmp_path):
    call = AsyncMock(return_value=_response('{"answer":"not evidence"}', refusal="blocked"))
    monkeypatch.setattr("squadrone.agents.transport.litellm_transport.call_llm", call)

    with pytest.raises(AgentOutputError, match="refused"):
        await _run(AgentRuntime(str(tmp_path)))

    assert call.await_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("content,finish_reason", [("[]", "length"), ("", "stop")])
async def test_incomplete_schema_repair_cannot_be_salvaged(
    monkeypatch, tmp_path, content, finish_reason,
):
    call = AsyncMock(side_effect=[
        _response("not JSON"),
        _response(content, finish_reason),
    ])
    monkeypatch.setattr("squadrone.agents.transport.litellm_transport.call_llm", call)
    runtime = AgentRuntime(str(tmp_path))

    with pytest.raises(AgentOutputError, match="incomplete schema_repair"):
        await _run(runtime, output_schema=_Outputs)

    assert call.await_count == 2
    assert not list(tmp_path.glob("schema_invalid_*.json"))
    assert not any(record["kind"].startswith("schema_") for record in _trace(runtime))


@pytest.mark.asyncio
@pytest.mark.parametrize("content,finish_reason", [('{"answer":"partial"}', "length"), ("", "stop")])
async def test_forced_finalisation_rejects_incomplete_output(
    monkeypatch, tmp_path, content, finish_reason,
):
    call = AsyncMock(side_effect=[_tool_response(), _response(content, finish_reason)])
    monkeypatch.setattr("squadrone.agents.transport.litellm_transport.call_llm", call)
    runtime = AgentRuntime(str(tmp_path))

    with pytest.raises(AgentOutputError, match="incomplete forced_finalisation"):
        await _run(runtime, max_iterations=1, tool_handlers={"read": lambda args: "source"})

    assert call.await_count == 2
    assert _trace(runtime)[-1]["kind"] == "incomplete_response"


@pytest.mark.asyncio
async def test_interrupted_tool_batch_is_not_executed(monkeypatch, tmp_path):
    call = AsyncMock(return_value=_tool_response("length"))
    monkeypatch.setattr("squadrone.agents.transport.litellm_transport.call_llm", call)
    handler = AsyncMock(return_value="source")

    with pytest.raises(AgentOutputError, match="incomplete"):
        await _run(AgentRuntime(str(tmp_path)), tool_handlers={"read": handler})

    handler.assert_not_awaited()


@pytest.mark.asyncio
async def test_legitimate_tool_only_turn_still_continues(monkeypatch, tmp_path):
    tool_reply = _tool_response()
    call = AsyncMock(side_effect=[tool_reply, _response('{"answer":"complete"}')])
    monkeypatch.setattr("squadrone.agents.transport.litellm_transport.call_llm", call)
    handler = AsyncMock(return_value="source")

    result = await _run(AgentRuntime(str(tmp_path)), tool_handlers={"read": handler})

    assert result.output.answer == "complete"
    handler.assert_awaited_once_with({})
    request = call.await_args_list[1].kwargs
    assert request["messages"][1] == tool_reply["choices"][0]["message"]
    assert call.await_args_list[0].kwargs["conversation_id"] == request["conversation_id"]
