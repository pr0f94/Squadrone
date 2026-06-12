"""Unit tests for LLM schema-payload normalisation."""

from __future__ import annotations

import pytest
from pydantic import BaseModel, RootModel

from squadrone.agents.runtime import AgentRuntime
from squadrone.agents.transport.litellm_transport import LiteLLMTransport, _normalise_schema_payload


class _Item(BaseModel):
    id: str


class _ItemList(RootModel[list[_Item]]):
    pass


class _Envelope(BaseModel):
    items: list[_Item]


def test_normalises_root_list_object_wrapper():
    payload = {"hypotheses": [{"id": "logic-001"}]}

    normalised = _normalise_schema_payload(payload, _ItemList)

    assert normalised == [{"id": "logic-001"}]
    assert _ItemList.model_validate(normalised).root[0].id == "logic-001"


def test_normalises_root_list_single_item_wrapper():
    payload = [{"hypotheses": [{"id": "logic-001"}]}]

    normalised = _normalise_schema_payload(payload, _ItemList)

    assert normalised == [{"id": "logic-001"}]
    assert _ItemList.model_validate(normalised).root[0].id == "logic-001"


def test_normalises_root_list_output_wrapper():
    payload = {"output": [{"id": "inj-001"}]}

    normalised = _normalise_schema_payload(payload, _ItemList)

    assert normalised == [{"id": "inj-001"}]
    assert _ItemList.model_validate(normalised).root[0].id == "inj-001"


def test_normalises_root_list_single_list_value_wrapper():
    payload = {"summary": "No confirmed issues.", "issues": []}

    normalised = _normalise_schema_payload(payload, _ItemList)

    assert normalised == []


def test_normalises_root_list_no_issue_summary_to_empty_list():
    payload = {"summary": "No confirmed object authorization issues found."}

    normalised = _normalise_schema_payload(payload, _ItemList)

    assert normalised == []


def test_leaves_ambiguous_root_list_wrapper_unchanged():
    payload = {"accepted": [], "rejected": []}

    normalised = _normalise_schema_payload(payload, _ItemList)

    assert normalised is payload


def test_leaves_non_empty_summary_wrapper_unchanged():
    payload = {"summary": "One candidate may exist but details were omitted."}

    normalised = _normalise_schema_payload(payload, _ItemList)

    assert normalised is payload


def test_does_not_normalise_non_root_model():
    payload = {"items": [{"id": "logic-001"}]}

    normalised = _normalise_schema_payload(payload, _Envelope)

    assert normalised is payload


@pytest.mark.asyncio
async def test_root_list_schema_falls_back_to_empty_after_retry(monkeypatch, tmp_path):
    async def fake_call_llm(**kwargs):
        return {
            "choices": [
                {
                    "message": {
                        "content": '{"summary": "No injection issues found."}',
                    }
                }
            ],
            "usage": {},
        }

    monkeypatch.setattr(
        "squadrone.agents.transport.litellm_transport.call_llm",
        fake_call_llm,
    )
    runtime = AgentRuntime(run_dir=str(tmp_path))

    result = await LiteLLMTransport().run_agent(
        runtime=runtime,
        agent_name="injection",
        model="test-model",
        messages=[{"role": "user", "content": "Return hypotheses"}],
        tools=[],
        max_iterations=1,
        output_schema=_ItemList,
        tool_handlers=None,
        force_finalise_after=None,
        max_tokens=100,
    )

    assert result.output.root == []
