from __future__ import annotations

import json

import pytest

from squadrone.agents.runtime import AgentRuntime
from squadrone.agents.transport.litellm_transport import LiteLLMTransport


def _tool(name: str) -> dict:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": name,
            "parameters": {"type": "object", "properties": {}},
        },
    }


def _tool_response(*calls: tuple[str, str, dict]) -> dict:
    return {
        "choices": [
            {
                "message": {
                    "content": None,
                    "tool_calls": [
                        {
                            "id": call_id,
                            "type": "function",
                            "function": {
                                "name": name,
                                "arguments": json.dumps(arguments),
                            },
                        }
                        for call_id, name, arguments in calls
                    ],
                }
            }
        ],
        "usage": {},
    }


@pytest.mark.asyncio
async def test_forced_finalisation_dispatches_only_one_allowlisted_tool(
    monkeypatch, tmp_path
):
    responses = iter(
        [
            _tool_response(("read-1", "read_source", {"path": "entry.php"})),
            _tool_response(
                ("read-2", "read_source", {"path": "more.php"}),
                (
                    "setup-1",
                    "request_additional_setup",
                    {"description": "create normal state"},
                ),
                (
                    "setup-2",
                    "request_additional_setup",
                    {"description": "try twice"},
                ),
            ),
            {
                "choices": [{"message": {"content": "final output"}}],
                "usage": {},
            },
        ]
    )
    requests = []

    async def fake_call_llm(**kwargs):
        requests.append(kwargs)
        return next(responses)

    monkeypatch.setattr(
        "squadrone.agents.transport.litellm_transport.call_llm",
        fake_call_llm,
    )
    dispatched = []

    async def read_source(arguments):
        dispatched.append(("read_source", arguments))
        return "source"

    async def request_setup(arguments):
        dispatched.append(("request_additional_setup", arguments))
        return "setup applied"

    result = await LiteLLMTransport().run_agent(
        runtime=AgentRuntime(run_dir=str(tmp_path)),
        agent_name="generic-agent",
        model="test-model",
        messages=[{"role": "user", "content": "Investigate, then finish."}],
        tools=[_tool("read_source"), _tool("request_additional_setup")],
        max_iterations=3,
        output_schema=None,
        tool_handlers={
            "read_source": read_source,
            "request_additional_setup": request_setup,
        },
        force_finalise_after=1,
        force_finalise_allowed_tools={"request_additional_setup"},
        max_tokens=100,
    )

    assert result.output == "final output"
    assert dispatched == [
        ("read_source", {"path": "entry.php"}),
        ("request_additional_setup", {"description": "create normal state"}),
    ]
    assert [_tool["function"]["name"] for _tool in requests[0]["tools"]] == [
        "read_source",
        "request_additional_setup",
    ]
    assert [_tool["function"]["name"] for _tool in requests[1]["tools"]] == [
        "request_additional_setup"
    ]
    assert requests[2]["tools"] == []
    assert (
        "No further tool calls are permitted" in requests[2]["messages"][-1]["content"]
    )

    trace = [
        json.loads(line) for line in (tmp_path / "trace.jsonl").read_text().splitlines()
    ]
    assert [
        item["tool"] for item in trace if item["kind"] == "finalisation_tool_dispatched"
    ] == ["request_additional_setup"]
    assert [
        item["tool"] for item in trace if item["kind"] == "finalisation_tool_blocked"
    ] == ["read_source", "request_additional_setup"]


@pytest.mark.asyncio
async def test_force_finalise_without_allowlist_preserves_existing_tool_behavior(
    monkeypatch, tmp_path
):
    responses = iter(
        [
            _tool_response(("read-1", "read_source", {"path": "entry.php"})),
            _tool_response(("read-2", "read_source", {"path": "more.php"})),
            {
                "choices": [{"message": {"content": "legacy final"}}],
                "usage": {},
            },
        ]
    )
    requests = []

    async def fake_call_llm(**kwargs):
        requests.append(kwargs)
        return next(responses)

    monkeypatch.setattr(
        "squadrone.agents.transport.litellm_transport.call_llm",
        fake_call_llm,
    )
    dispatched = []

    async def read_source(arguments):
        dispatched.append(arguments)
        return "source"

    result = await LiteLLMTransport().run_agent(
        runtime=AgentRuntime(run_dir=str(tmp_path)),
        agent_name="legacy-agent",
        model="test-model",
        messages=[{"role": "user", "content": "Investigate, then finish."}],
        tools=[_tool("read_source")],
        max_iterations=3,
        output_schema=None,
        tool_handlers={"read_source": read_source},
        force_finalise_after=1,
        max_tokens=100,
    )

    assert result.output == "legacy final"
    assert dispatched == [{"path": "entry.php"}, {"path": "more.php"}]
    assert requests[1]["tools"] == [_tool("read_source")]
    assert any(
        "Do not call any more tools" in message.get("content", "")
        for message in requests[1]["messages"]
        if isinstance(message.get("content"), str)
    )
