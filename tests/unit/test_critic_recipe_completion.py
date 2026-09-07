from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
import squadrone.stages.triage as triage_stage

from squadrone.agents.critic import (
    CriticAgent,
    PhpObjectGadgetRecipeCompletions,
)
from squadrone.schemas.config import PipelineConfig
from squadrone.schemas.hypothesis import (
    Confidence,
    Hypothesis,
    TriagedArtifact,
)
from squadrone.schemas.php_object_gadget import PhpObjectGadgetRecipe
from squadrone.schemas.taxonomy import BugClass
from squadrone.services.budget import BudgetTracker
from squadrone.stages.triage import (
    _complete_missing_php_object_gadget_recipes,
    _record_php_object_gadget_recipe_completions,
)
from squadrone.stages.verify import (
    _php_object_gadget_oracle_enabled_for_hypotheses,
)


_PLUGIN_SOURCE = """<?php
class FileEraser {
    protected $path;
    public function __destruct() {
        unlink($this->path);
    }
}
add_action('wp_ajax_nopriv_process_submission', 'process_submission');
function process_submission() {
    unserialize($_POST['payload']);
}
"""


def _plugin_root(tmp_path: Path, source: str = _PLUGIN_SOURCE) -> Path:
    root = tmp_path / "generic-plugin"
    root.mkdir()
    (root / "plugin.php").write_text(source, encoding="utf-8")
    return root


def _recipe() -> PhpObjectGadgetRecipe:
    return PhpObjectGadgetRecipe.model_validate(
        {
            "schema_version": 1,
            "effect": "file_delete",
            "effect_sink": "unlink",
            "gadget_object": {
                "class_name": "FileEraser",
                "class_anchor": {
                    "file": "plugin.php",
                    "line": 2,
                    "source_code": "class FileEraser {",
                },
                "trigger": "__destruct",
                "trigger_declaring_class": "FileEraser",
                "trigger_anchor": {
                    "file": "plugin.php",
                    "line": 4,
                    "source_code": (
                        "public function __destruct() {\n"
                        "        unlink($this->path);\n"
                        "    }"
                    ),
                },
                "properties": [
                    {
                        "name": "path",
                        "declaring_class": "FileEraser",
                        "visibility": "protected",
                        "value": {
                            "kind": "capability",
                            "capability": "ephemeral_file_path",
                        },
                    }
                ],
            },
            "effect_binding": {
                "kind": "direct_path",
                "effect_property": "path",
                "access": "property",
                "effect_anchor": {
                    "file": "plugin.php",
                    "line": 5,
                    "source_code": "unlink($this->path);",
                },
            },
            "helper_anchors": [],
            "guarded_effect_anchors": [],
        }
    )


def _hypothesis(
    hypothesis_id: str = "object-1",
    *,
    bug_class: BugClass = BugClass.PHP_OBJECT_INJECTION,
    usable_gadget: object = True,
    recipe: PhpObjectGadgetRecipe | None = None,
) -> Hypothesis:
    return Hypothesis(
        id=hypothesis_id,
        specialist="injection_files",
        bug_class=bug_class,
        entry_point="wp_ajax_nopriv_process_submission",
        file="plugin.php",
        line=10,
        sink="unserialize",
        sink_code="unserialize($_POST['payload']);",
        taint_path=["POST payload", "unserialize"],
        reasoning="The public callback passes serialized payload bytes to the sink.",
        confidence=Confidence.HIGH,
        affected_versions="<=1.0",
        evidence_summary={
            "attacker_role": "unauthenticated",
            "source": "POST payload containing object bytes",
            "usable_gadget": usable_gadget,
        },
        php_object_gadget_recipe=recipe,
    )


def _recipe_result(*hypothesis_ids: str) -> PhpObjectGadgetRecipeCompletions:
    return PhpObjectGadgetRecipeCompletions.model_validate(
        {
            "plugin_slug": "generic-plugin",
            "completions": [
                {
                    "hypothesis_id": hypothesis_id,
                    "outcome": "recipe_v1",
                    "recipe": _recipe().model_dump(mode="json"),
                    "reason": "Exact direct-path destructor recipe is source anchored.",
                }
                for hypothesis_id in hypothesis_ids
            ],
        }
    )


def _unrepresentable_result(
    *hypothesis_ids: str,
) -> PhpObjectGadgetRecipeCompletions:
    return PhpObjectGadgetRecipeCompletions.model_validate(
        {
            "plugin_slug": "generic-plugin",
            "completions": [
                {
                    "hypothesis_id": hypothesis_id,
                    "outcome": "unrepresentable_v1",
                    "recipe": None,
                    "violated_rule": (
                        "v1 permits only __wakeup or __destruct on the serialized class"
                    ),
                    "reason": "The reviewed chain is triggered only by __unserialize.",
                }
                for hypothesis_id in hypothesis_ids
            ],
        }
    )


def _incomplete_result(
    *hypothesis_ids: str,
) -> PhpObjectGadgetRecipeCompletions:
    return PhpObjectGadgetRecipeCompletions.model_validate(
        {
            "plugin_slug": "generic-plugin",
            "completions": [
                {
                    "hypothesis_id": hypothesis_id,
                    "outcome": "incomplete_source_review",
                    "recipe": None,
                    "violated_rule": None,
                    "needed_context": "Complete body of the called path-check helper.",
                    "reason": "The bounded source read did not complete.",
                }
                for hypothesis_id in hypothesis_ids
            ],
        }
    )


class _FakeCritic:
    def __init__(self, result: PhpObjectGadgetRecipeCompletions) -> None:
        self.result = result
        self.calls: list[dict[str, object]] = []

    async def complete_php_object_gadget_recipes(
        self,
        plugin_slug: str,
        hypotheses: list[Hypothesis],
        code_slices: dict[str, str],
        plugin_path: str,
    ) -> PhpObjectGadgetRecipeCompletions:
        self.calls.append(
            {
                "plugin_slug": plugin_slug,
                "hypotheses": hypotheses,
                "code_slices": code_slices,
                "plugin_path": plugin_path,
            }
        )
        return self.result


@pytest.mark.asyncio
async def test_valid_completion_persists_and_enables_natural_route(
    tmp_path: Path,
) -> None:
    plugin_root = _plugin_root(tmp_path)
    triaged = TriagedArtifact(
        plugin_slug="generic-plugin",
        accepted=[_hypothesis()],
        rejected=[],
        merged=[],
    )
    critic = _FakeCritic(_recipe_result("object-1"))

    completed = await _complete_missing_php_object_gadget_recipes(
        cast(CriticAgent, critic),
        triaged,
        str(plugin_root),
    )

    assert completed is critic.result
    assert len(critic.calls) == 1
    completion_slices = cast(dict[str, str], critic.calls[0]["code_slices"])
    assert list(completion_slices) == ["plugin.php"]
    assert triaged.accepted[0].php_object_gadget_recipe == _recipe()

    artifact = tmp_path / "triaged.json"
    triaged.to_json_file(str(artifact))
    reloaded = TriagedArtifact.from_json_file(str(artifact))
    assert reloaded.accepted[0].php_object_gadget_recipe == _recipe()
    assert _php_object_gadget_oracle_enabled_for_hypotheses(
        reloaded.accepted,
        plugin_root,
        "generic-plugin",
    )


@pytest.mark.asyncio
async def test_unrepresentable_completion_remains_null_and_is_explicit_in_ledger(
    tmp_path: Path,
) -> None:
    plugin_root = _plugin_root(tmp_path)
    original = _hypothesis()
    original_payload = original.model_dump(mode="json")
    triaged = TriagedArtifact(
        plugin_slug="generic-plugin",
        accepted=[original],
        rejected=[],
        merged=[],
    )
    critic = _FakeCritic(_unrepresentable_result("object-1"))

    result = await _complete_missing_php_object_gadget_recipes(
        cast(CriticAgent, critic),
        triaged,
        str(plugin_root),
    )

    assert result is not None
    assert triaged.accepted[0].model_dump(mode="json") == original_payload
    _record_php_object_gadget_recipe_completions(tmp_path / "run", result)
    record = json.loads(
        (tmp_path / "run" / "decision_ledger.jsonl").read_text(encoding="utf-8")
    )
    assert record["result"] == "unrepresentable_v1"
    assert record["details"]["violated_rule"].startswith("v1 permits only")
    assert record["hypothesis_id"] == "object-1"


@pytest.mark.asyncio
async def test_incomplete_source_review_fails_atomically_and_is_not_recordable(
    tmp_path: Path,
) -> None:
    plugin_root = _plugin_root(tmp_path)
    original = _hypothesis()
    triaged = TriagedArtifact(
        plugin_slug="generic-plugin",
        accepted=[original],
        rejected=[],
        merged=[],
    )
    result = _incomplete_result("object-1")
    critic = _FakeCritic(result)

    with pytest.raises(ValueError, match="source review was incomplete"):
        await _complete_missing_php_object_gadget_recipes(
            cast(CriticAgent, critic),
            triaged,
            str(plugin_root),
        )

    assert triaged.accepted == [original]
    assert original.php_object_gadget_recipe is None
    with pytest.raises(ValueError, match="cannot be recorded"):
        _record_php_object_gadget_recipe_completions(tmp_path / "run", result)
    assert not (tmp_path / "run" / "decision_ledger.jsonl").exists()


@pytest.mark.asyncio
async def test_completion_batches_multiple_targets_in_one_critic_call(
    tmp_path: Path,
) -> None:
    plugin_root = _plugin_root(tmp_path)
    hypotheses = [_hypothesis("object-1"), _hypothesis("object-2")]
    triaged = TriagedArtifact(
        plugin_slug="generic-plugin",
        accepted=hypotheses,
        rejected=[],
        merged=[],
    )
    critic = _FakeCritic(_unrepresentable_result("object-1", "object-2"))

    await _complete_missing_php_object_gadget_recipes(
        cast(CriticAgent, critic),
        triaged,
        str(plugin_root),
    )

    assert len(critic.calls) == 1
    sent_hypotheses = cast(list[Hypothesis], critic.calls[0]["hypotheses"])
    assert [hypothesis.id for hypothesis in sent_hypotheses] == [
        "object-1",
        "object-2",
    ]


@pytest.mark.asyncio
async def test_triage_completes_only_post_quality_scope_and_cap_candidates(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    plugin_root = _plugin_root(tmp_path)
    hypotheses = [_hypothesis("object-1"), _hypothesis("object-2")]
    observed_completion_ids: list[str] = []

    class FakeCritic:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        async def review(
            self,
            artifact: object,
            _code_slices: object,
            plugin_path: str | None = None,
        ) -> TriagedArtifact:
            del artifact, plugin_path
            return TriagedArtifact(
                plugin_slug="generic-plugin",
                accepted=hypotheses,
                rejected=[],
                merged=[],
            )

        async def complete_php_object_gadget_recipes(
            self,
            _plugin_slug: str,
            targets: list[Hypothesis],
            _code_slices: dict[str, str],
            _plugin_path: str,
        ) -> PhpObjectGadgetRecipeCompletions:
            observed_completion_ids.extend(item.id for item in targets)
            return _unrepresentable_result(*(item.id for item in targets))

    monkeypatch.setattr(triage_stage, "CriticAgent", FakeCritic)
    monkeypatch.setattr(
        triage_stage,
        "apply_quality_gate",
        lambda artifact, *, artifact_path: artifact,
    )
    monkeypatch.setattr(
        triage_stage,
        "_apply_submission_scope",
        lambda artifact, run_dir, *, enforce_submission_scope: None,
    )
    monkeypatch.setattr(triage_stage, "rank_hypothesis", lambda item: item.id)
    config = PipelineConfig.from_yaml("pipelines/test.yaml")
    config.max_hypotheses_to_verify = 1

    result = await triage_stage.run(
        triage_stage.HypothesesArtifact(
            plugin_slug="generic-plugin",
            hypotheses=hypotheses,
        ),
        str(plugin_root),
        config,
        BudgetTracker(10.0),
        SimpleNamespace(),  # type: ignore[arg-type]
        runs_root=str(tmp_path / "runs"),
        run_id="post-cap",
        enforce_submission_scope=False,
    )

    assert observed_completion_ids == ["object-1"]
    assert [item.id for item in result.accepted] == ["object-1"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "hypothesis",
    [
        _hypothesis(bug_class=BugClass.IDOR),
        _hypothesis(usable_gadget=False),
        _hypothesis(usable_gadget="true"),
        _hypothesis(usable_gadget=1),
        _hypothesis(recipe=_recipe()),
    ],
    ids=["other-cwe", "false", "string-true", "integer-one", "existing-recipe"],
)
async def test_completion_skips_every_non_exact_target(
    tmp_path: Path,
    hypothesis: Hypothesis,
) -> None:
    plugin_root = _plugin_root(tmp_path)
    triaged = TriagedArtifact(
        plugin_slug="generic-plugin",
        accepted=[hypothesis],
        rejected=[],
        merged=[],
    )
    critic = _FakeCritic(_unrepresentable_result(hypothesis.id))

    result = await _complete_missing_php_object_gadget_recipes(
        cast(CriticAgent, critic),
        triaged,
        str(plugin_root),
    )

    assert result is None
    assert critic.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "accounting_error", ["slug", "duplicate", "unknown", "missing"]
)
async def test_completion_rejects_inexact_batch_accounting(
    tmp_path: Path,
    accounting_error: str,
) -> None:
    plugin_root = _plugin_root(tmp_path)
    original = _hypothesis()
    triaged = TriagedArtifact(
        plugin_slug="generic-plugin",
        accepted=[original],
        rejected=[],
        merged=[],
    )
    payload = _unrepresentable_result("object-1").model_dump(mode="json")
    expected = ""
    if accounting_error == "slug":
        payload["plugin_slug"] = "different-plugin"
        expected = "plugin_slug"
    elif accounting_error == "duplicate":
        payload["completions"].append(payload["completions"][0])
        expected = "duplicate"
    elif accounting_error == "unknown":
        payload["completions"][0]["hypothesis_id"] = "unknown"
        expected = "unknown"
    else:
        payload["completions"] = []
        expected = "omitted"
    critic = _FakeCritic(PhpObjectGadgetRecipeCompletions.model_validate(payload))

    with pytest.raises(ValueError, match=expected):
        await _complete_missing_php_object_gadget_recipes(
            cast(CriticAgent, critic),
            triaged,
            str(plugin_root),
        )

    assert triaged.accepted[0] is original
    assert original.php_object_gadget_recipe is None


@pytest.mark.asyncio
async def test_source_invalid_recipe_fails_without_partial_mutation(
    tmp_path: Path,
) -> None:
    source = _PLUGIN_SOURCE.replace(
        "unlink($this->path);",
        "unlink($this->different_path);",
    )
    plugin_root = _plugin_root(tmp_path, source)
    first = _hypothesis("object-1")
    second = _hypothesis("object-2")
    triaged = TriagedArtifact(
        plugin_slug="generic-plugin",
        accepted=[first, second],
        rejected=[],
        merged=[],
    )
    critic = _FakeCritic(_recipe_result("object-1", "object-2"))

    with pytest.raises(ValueError, match="failed source validation"):
        await _complete_missing_php_object_gadget_recipes(
            cast(CriticAgent, critic),
            triaged,
            str(plugin_root),
        )

    assert triaged.accepted == [first, second]
    assert all(item.php_object_gadget_recipe is None for item in triaged.accepted)


@pytest.mark.asyncio
async def test_completion_agent_supplies_exact_schema_and_bounded_runtime_options(
    tmp_path: Path,
) -> None:
    plugin_root = _plugin_root(tmp_path)
    expected = _unrepresentable_result("object-1")

    class Runtime:
        def __init__(self) -> None:
            self.calls: list[dict[str, object]] = []

        async def run(self, **kwargs: object) -> SimpleNamespace:
            self.calls.append(kwargs)
            return SimpleNamespace(output=expected)

    runtime = Runtime()
    critic = CriticAgent(runtime, model="test-model")  # type: ignore[arg-type]

    result = await critic.complete_php_object_gadget_recipes(
        "generic-plugin",
        [_hypothesis()],
        {"plugin.php": "source slice"},
        str(plugin_root),
    )

    assert result is expected
    assert len(runtime.calls) == 1
    call = runtime.calls[0]
    assert call["agent_name"] == "critic.php_object_gadget_recipe_completion"
    assert call["output_schema"] is PhpObjectGadgetRecipeCompletions
    assert call["max_iterations"] == 10
    assert call["force_finalise_after"] == 8
    assert call["force_finalise_allowed_tools"] == set()
    messages = cast(list[dict[str, str]], call["messages"])
    system = messages[0]["content"]
    assert "Exact completion response and embedded" in system
    assert '"PhpObjectGadgetRecipe"' in system
    assert '"unrepresentable_v1"' in system
    assert "bare PHP\nidentifier without a leading `$`" in system
    assert "complete\nbraced `foreach` region" in system
    assert "dataflow prefix ending at the classified\nprimary `unlink`" in system
    assert "post-sink cleanup is not by itself a v1 violation" in system
    assert "strict zero-offset `strpos(...) === 0`" in system
    assert "do not require whole-string equality" in system
    assert "Missing or unread source context is not a v1 contract violation" in system
    assert "source-proven rule the reviewed chain actually violates" in system
    assert "batched `read_plugin_ranges` calls" in system
    assert "`incomplete_source_review`" in system
