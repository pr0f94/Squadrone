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
async def test_search_batch_can_finish_with_one_batched_source_read(
    monkeypatch, tmp_path
):
    responses = iter(
        [
            _tool_response(
                *(
                    (
                        f"grep-{index}",
                        "grep_plugin",
                        {"pattern": f"symbol_{index}"},
                    )
                    for index in range(6)
                )
            ),
            _tool_response(
                (
                    "ranges-1",
                    "read_plugin_ranges",
                    {
                        "ranges": [
                            {
                                "path": "plugin.php",
                                "start_line": 10,
                                "end_line": 30,
                            }
                        ]
                    },
                )
            ),
            {
                "choices": [{"message": {"content": "final setup plan"}}],
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

    async def grep_plugin(arguments):
        dispatched.append(("grep_plugin", arguments))
        return "plugin.php:10: matching symbol"

    async def read_plugin_ranges(arguments):
        dispatched.append(("read_plugin_ranges", arguments))
        return "source range"

    result = await LiteLLMTransport().run_agent(
        runtime=AgentRuntime(run_dir=str(tmp_path)),
        agent_name="developer.propose_setup_followup",
        model="test-model",
        messages=[{"role": "user", "content": "Inspect source, then plan setup."}],
        tools=[_tool("grep_plugin"), _tool("read_plugin_ranges")],
        max_iterations=3,
        output_schema=None,
        tool_handlers={
            "grep_plugin": grep_plugin,
            "read_plugin_ranges": read_plugin_ranges,
        },
        force_finalise_after=6,
        force_finalise_allowed_tools={"read_plugin_ranges"},
        max_tokens=100,
    )

    assert result.output == "final setup plan"
    assert [name for name, _arguments in dispatched] == [
        *("grep_plugin" for _index in range(6)),
        "read_plugin_ranges",
    ]
    assert [tool["function"]["name"] for tool in requests[0]["tools"]] == [
        "grep_plugin",
        "read_plugin_ranges",
    ]
    assert [tool["function"]["name"] for tool in requests[1]["tools"]] == [
        "read_plugin_ranges"
    ]
    assert requests[2]["tools"] == []


@pytest.mark.asyncio
async def test_search_batch_can_finish_with_two_batched_source_reads(
    monkeypatch, tmp_path
):
    responses = iter(
        [
            _tool_response(
                *(
                    (
                        f"grep-{index}",
                        "grep_plugin",
                        {"pattern": f"symbol_{index}"},
                    )
                    for index in range(6)
                )
            ),
            _tool_response(
                (
                    "ranges-1",
                    "read_plugin_ranges",
                    {
                        "ranges": [
                            {"path": "plugin.php", "start_line": 10, "end_line": 30}
                        ]
                    },
                )
            ),
            _tool_response(
                (
                    "ranges-2",
                    "read_plugin_ranges",
                    {
                        "ranges": [
                            {"path": "helper.php", "start_line": 40, "end_line": 60}
                        ]
                    },
                )
            ),
            _tool_response(
                (
                    "ranges-3",
                    "read_plugin_ranges",
                    {
                        "ranges": [
                            {"path": "extra.php", "start_line": 70, "end_line": 90}
                        ]
                    },
                )
            ),
            {
                "choices": [{"message": {"content": "final setup plan"}}],
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

    async def grep_plugin(arguments):
        dispatched.append(("grep_plugin", arguments))
        return "plugin.php:10: matching symbol"

    async def read_plugin_ranges(arguments):
        dispatched.append(("read_plugin_ranges", arguments))
        path = arguments["ranges"][0]["path"]
        if path == "plugin.php":
            return "FIRST RANGE RESULT: helper reference needs one focused read"
        return "SECOND RANGE RESULT: complete helper source"

    result = await LiteLLMTransport().run_agent(
        runtime=AgentRuntime(run_dir=str(tmp_path)),
        agent_name="developer.propose_setup_followup",
        model="test-model",
        messages=[{"role": "user", "content": "Inspect source, then plan setup."}],
        tools=[_tool("grep_plugin"), _tool("read_plugin_ranges")],
        max_iterations=5,
        output_schema=None,
        tool_handlers={
            "grep_plugin": grep_plugin,
            "read_plugin_ranges": read_plugin_ranges,
        },
        force_finalise_after=6,
        force_finalise_allowed_tools={"read_plugin_ranges"},
        force_finalise_allowed_tool_calls=2,
        max_tokens=100,
    )

    assert result.output == "final setup plan"
    assert [name for name, _arguments in dispatched] == [
        *("grep_plugin" for _index in range(6)),
        "read_plugin_ranges",
        "read_plugin_ranges",
    ]
    assert [tool["function"]["name"] for tool in requests[1]["tools"]] == [
        "read_plugin_ranges"
    ]
    assert [tool["function"]["name"] for tool in requests[2]["tools"]] == [
        "read_plugin_ranges"
    ]
    assert requests[3]["tools"] == []
    assert requests[4]["tools"] == []
    second_read_context = json.dumps(requests[2]["messages"])
    assert "FIRST RANGE RESULT" in second_read_context
    assert (
        "at most 1 additional permitted finalisation tool call"
        in second_read_context
    )
    final_context = json.dumps(requests[3]["messages"])
    assert "FIRST RANGE RESULT" in final_context
    assert "SECOND RANGE RESULT" in final_context
    assert "No further tool calls are permitted" in final_context

    trace = [
        json.loads(line) for line in (tmp_path / "trace.jsonl").read_text().splitlines()
    ]
    dispatches = [
        item for item in trace if item["kind"] == "finalisation_tool_dispatched"
    ]
    assert [item["finalisation_tool_calls"] for item in dispatches] == [1, 2]
    assert all(item["finalisation_tool_call_limit"] == 2 for item in dispatches)
    blocked = [
        item
        for item in trace
        if item["kind"] == "finalisation_tool_blocked"
    ]
    assert [item["tool"] for item in blocked] == ["read_plugin_ranges"]
    assert blocked[0]["args"]["ranges"][0]["path"] == "extra.php"


@pytest.mark.asyncio
async def test_threshold_crossing_batch_finishes_before_finalisation_read(
    monkeypatch, tmp_path
):
    responses = iter(
        [
            _tool_response(
                *(
                    (f"initial-{index}", "grep_plugin", {"pattern": f"initial_{index}"})
                    for index in range(3)
                )
            ),
            _tool_response(
                ("cross-1", "grep_plugin", {"pattern": "company"}),
                ("cross-2", "grep_plugin", {"pattern": "title"}),
                (
                    "cross-3",
                    "read_plugin_ranges",
                    {
                        "ranges": [
                            {"path": "entry.php", "start_line": 10, "end_line": 30}
                        ]
                    },
                ),
            ),
            _tool_response(
                (
                    "final-read",
                    "read_plugin_ranges",
                    {
                        "ranges": [
                            {"path": "mapping.php", "start_line": 40, "end_line": 80}
                        ]
                    },
                )
            ),
            {
                "choices": [{"message": {"content": "grounded final output"}}],
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

    async def record_tool(arguments):
        dispatched.append(arguments)
        return "source evidence"

    result = await LiteLLMTransport().run_agent(
        runtime=AgentRuntime(run_dir=str(tmp_path)),
        agent_name="injection_files.b001-retry",
        model="test-model",
        messages=[{"role": "user", "content": "Trace the assigned operation."}],
        tools=[_tool("grep_plugin"), _tool("read_plugin_ranges")],
        max_iterations=4,
        output_schema=None,
        tool_handlers={
            "grep_plugin": record_tool,
            "read_plugin_ranges": record_tool,
        },
        force_finalise_after=4,
        force_finalise_allowed_tools={"read_plugin_ranges"},
        force_finalise_allowed_tool_calls=1,
        max_tokens=100,
    )

    assert result.output == "grounded final output"
    assert [item.get("pattern", "range") for item in dispatched] == [
        "initial_0",
        "initial_1",
        "initial_2",
        "company",
        "title",
        "range",
        "range",
    ]
    assert [tool["function"]["name"] for tool in requests[1]["tools"]] == [
        "grep_plugin",
        "read_plugin_ranges",
    ]
    assert [tool["function"]["name"] for tool in requests[2]["tools"]] == [
        "read_plugin_ranges"
    ]
    assert requests[3]["tools"] == []

    trace = [
        json.loads(line) for line in (tmp_path / "trace.jsonl").read_text().splitlines()
    ]
    force_events = [item for item in trace if item["kind"] == "force_finalise"]
    assert force_events[0]["after_tool_calls"] == 6
    assert force_events[0]["allowed_tools"] == ["read_plugin_ranges"]
    final_reads = [
        item for item in trace if item["kind"] == "finalisation_tool_dispatched"
    ]
    assert [item["tool"] for item in final_reads] == ["read_plugin_ranges"]
    assert not [item for item in trace if item["kind"] == "finalisation_tool_blocked"]


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
