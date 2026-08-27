from __future__ import annotations

import pytest

from squadrone.agents.developer import DeveloperAgent, SetupPlan
from squadrone.schemas.hypothesis import BugClass, Confidence, Hypothesis


def _hypothesis() -> Hypothesis:
    return Hypothesis(
        id="h-setup",
        specialist="test",
        bug_class=BugClass.ARBITRARY_FILE_WRITE,
        entry_point="rest_route",
        file="includes/api.php",
        line=42,
        sink="copy",
        taint_path=["request file", "copy sink"],
        reasoning="A file reaches copy.",
        confidence=Confidence.HIGH,
        preconditions="A runtime directory exists.",
        affected_versions="<=1.0",
    )


@pytest.mark.asyncio
async def test_followup_distinguishes_proposals_from_execution_feedback(monkeypatch):
    agent = DeveloperAgent(model="test-model")
    captured: dict[str, object] = {}

    async def fake_call_setup_json(**kwargs):
        captured.update(kwargs)
        return {
            "failure_class": "setup",
            "rationale": "Create the source-grounded directory.",
            "commands": [["eval", "wp_mkdir_p('/srv/site/uploads');"]],
        }

    monkeypatch.setattr(agent, "_call_setup_json", fake_call_setup_json)
    source = "S" * 12000 + "UNBOUNDED_SOURCE_TAIL"

    result = await agent.propose_setup_followup(
        hypothesis=_hypothesis(),
        prior_plan=SetupPlan(
            rationale="Directory may be needed.",
            commands=[["eval", "wp_mkdir_p('/srv/site/uploads');"]],
        ),
        last_iteration=1,
        last_stdout="not found",
        last_stderr="",
        last_error_log="",
        code_slice=source,
        setup_execution_feedback="command 1 was blocked atomically",
    )

    messages = captured["messages"]
    assert isinstance(messages, list)
    user_message = messages[-1]["content"]
    assert "PRIOR SETUP COMMANDS (PROPOSED; NOT NECESSARILY EXECUTED)" in user_message
    assert "AUTHORITATIVE SETUP EXECUTION FEEDBACK" in user_message
    assert "command 1 was blocked atomically" in user_message
    assert "BOUNDED SOURCE CONTEXT FOR REACHABILITY" in user_message
    assert "... [truncated]" in user_message
    assert "UNBOUNDED_SOURCE_TAIL" not in user_message
    assert result.failure_class == "setup"


def test_setup_prompts_preserve_managed_permissions_and_require_source_grounding():
    agent = DeveloperAgent(model="test-model")

    for prompt in (agent.setup_prompt, agent.setup_followup_prompt):
        assert "preconditions` are" in prompt
        assert "not observations" in prompt
        assert "managed web-server operating-system user" in prompt
        for forbidden_name in ("chmod", "chown", "chgrp", "umask", "wp_chmod"):
            assert f"`{forbidden_name}`" in prompt
        assert "wp_mkdir_p($path)` alone" in prompt
        assert "whole command is blocked" in prompt
        assert "source-grounded" in prompt

    assert "public_api" not in agent.setup_prompt
    assert "module_api" not in agent.setup_prompt
