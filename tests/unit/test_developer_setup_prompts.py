from __future__ import annotations

from types import SimpleNamespace

import pytest

from squadrone.agents.developer import DeveloperAgent, SetupPlan
from squadrone.agents.runtime import AgentRuntime
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


@pytest.mark.asyncio
async def test_followup_source_repair_exposes_only_bounded_read_tools(tmp_path):
    source = tmp_path / "plugin.php"
    source.write_text(
        "<?php\nfunction create_fixture($id, $data) { return true; }\n",
        encoding="utf-8",
    )
    captured: dict[str, object] = {}

    class FakeRuntime:
        async def run(self, **kwargs):
            captured.update(kwargs)
            handlers = kwargs["tool_handlers"]
            grep_result = handlers["grep_plugin"](
                {"pattern": "function create_fixture"}
            )
            read_result = handlers["read_plugin_file"](
                {"path": "plugin.php", "start_line": 1, "end_line": 2}
            )
            assert "create_fixture" in grep_result
            assert "create_fixture($id, $data)" in read_result
            return SimpleNamespace(
                output=SetupPlan(
                    failure_class="setup",
                    rationale="Use the inspected helper signature.",
                    commands=[["eval", "create_fixture(0, array());"]],
                )
            )

    agent = DeveloperAgent(model="test-model", followup_model="followup-model")
    result = await agent.propose_setup_followup(
        hypothesis=_hypothesis(),
        prior_plan=SetupPlan(),
        last_iteration=1,
        last_stdout="fixture missing",
        last_stderr="",
        last_error_log="",
        runtime=FakeRuntime(),  # type: ignore[arg-type]
        plugin_root=tmp_path,
    )

    tool_names = {
        tool["function"]["name"] for tool in captured["tools"]  # type: ignore[index]
    }
    assert tool_names == {
        "grep_plugin",
        "glob_plugin",
        "read_plugin_file",
        "read_plugin_ranges",
    }
    assert set(captured["tool_handlers"]) == tool_names  # type: ignore[arg-type]
    assert captured["agent_name"] == "developer.propose_setup_followup"
    assert captured["model"] == "followup-model"
    assert captured["max_iterations"] == 6
    assert captured["force_finalise_after"] == 3
    assert captured["force_finalise_allowed_tools"] == set()
    assert captured["output_schema"] is SetupPlan
    assert result.failure_class == "setup"
    assert result.commands == [["eval", "create_fixture(0, array());"]]


def test_runtime_maps_setup_followup_to_its_own_reasoning_role(tmp_path):
    runtime = AgentRuntime(
        str(tmp_path / "run"),
        llm_options={"verbosity": "medium"},
        role_reasoning={
            "developer": "high",
            "developer_followup": "low",
        },
    )

    assert runtime.llm_options_for_agent("developer.consult") == {
        "verbosity": "medium",
        "reasoning_effort": "high",
    }
    assert runtime.llm_options_for_agent("developer.propose_setup_followup") == {
        "verbosity": "medium",
        "reasoning_effort": "low",
    }


@pytest.mark.asyncio
async def test_cross_object_setup_guidance_is_family_scoped(monkeypatch):
    agent = DeveloperAgent(model="test-model")
    user_messages: list[str] = []

    async def fake_call_setup_json(**kwargs):
        user_messages.append(kwargs["messages"][-1]["content"])
        return {"failure_class": "setup", "rationale": "", "commands": []}

    monkeypatch.setattr(agent, "_call_setup_json", fake_call_setup_json)
    idor = _hypothesis().model_copy(update={"bug_class": BugClass.IDOR})

    await agent.propose_setup(idor)
    await agent.propose_setup_followup(
        hypothesis=idor,
        prior_plan=SetupPlan(),
        last_iteration=1,
        last_stdout="",
        last_stderr="",
        last_error_log="",
    )
    await agent.propose_setup(_hypothesis())

    assert "FAMILY-SPECIFIC SETUP REQUIREMENTS" in user_messages[0]
    assert "cross-object modification proof" in user_messages[0]
    assert "FAMILY-SPECIFIC SETUP REQUIREMENTS" in user_messages[1]
    assert "cross-object modification proof" not in user_messages[2]
    assert "cross-object modification proof" not in agent.setup_prompt
    assert "cross-object modification proof" not in agent.setup_followup_prompt


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
        assert "configured WordPress administrator" in prompt
        assert "`--user`" in prompt
        assert "wp_set_current_user(...)" in prompt
        assert "plugin's lifecycle" in prompt
        assert "wp_set_current_user(1)" not in prompt
        assert "no WordPress current user" not in prompt

    assert "public_api" not in agent.setup_prompt
    assert "module_api" not in agent.setup_prompt


def test_setup_prompts_require_self_verifying_eval_and_safe_database_fallbacks():
    agent = DeveloperAgent(model="test-model")

    for prompt in (agent.setup_prompt, agent.setup_followup_prompt):
        normalized = " ".join(prompt.split())
        assert "every `wp eval` must prove its semantic postconditions" in normalized
        assert "source-grounded WordPress Core or plugin APIs" in normalized
        assert "authoritative re-read" in normalized
        assert "positive nonzero integer" in normalized
        assert "IDs for distinct objects are unique" in normalized
        assert "ownership or authorship is correct" in normalized
        assert "persisted value equals" in normalized
        assert "$wpdb->last_error" in normalized
        assert (
            "WP_CLI::error('setup postcondition failed: foreign owner')" in normalized
        )
        assert "WP_CLI::log(wp_json_encode($result))" in normalized
        assert "$wpdb->insert_id" in normalized
        assert "affected-row count is a semantic postcondition by itself" in normalized
        assert "canonical persisted" in normalized
    assert "Ninja_Forms" not in agent.setup_followup_prompt
