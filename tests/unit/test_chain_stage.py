from __future__ import annotations

import json

import pytest

from squadrone.agents.chain_synthesizer import ChainEntry, ChainSynthesizer
from squadrone.schemas import BugClass, Confidence, Hypothesis, HypothesesArtifact
from squadrone.schemas.config import PipelineConfig
from squadrone.stages import chain as chain_stage


def _hypothesis(hypothesis_id: str, specialist: str = "auth") -> Hypothesis:
    return Hypothesis(
        id=hypothesis_id,
        specialist=specialist,
        bug_class=BugClass.MISSING_CAP_CHECK,
        entry_point="wp_ajax_demo",
        file="demo.php",
        line=10,
        sink="update_option",
        sink_code="update_option('demo', $_POST['value']);",
        taint_path=["$_POST['value']", "update_option"],
        reasoning="Subscriber can reach a privileged option write without a capability check.",
        confidence=Confidence.HIGH,
        preconditions="subscriber",
        affected_versions="<=1.0",
        exploit_classification={"type": "direct"},
        quality_gate={"accepted": True},
        derived_severity={"rating": "high", "cvss_estimate": 8.1},
    )


class _Output:
    root = [
        ChainEntry(
            ids=["h1", "h2"],
            impact="Subscriber can turn a settings write into file write.",
            severity_bump="medium->high",
            bypass_mechanism="h1 changes the setting consumed by h2.",
        )
    ]


class _Result:
    output = _Output()


class _Runtime:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def run(self, **kwargs):
        self.calls.append(kwargs)
        return _Result()


class _FailingRuntime:
    async def run(self, **kwargs):
        raise RuntimeError("model unavailable")


def _config() -> PipelineConfig:
    cfg = PipelineConfig.from_yaml("pipelines/openai.yaml")
    cfg.models.chain_synthesizer = "test-model"
    return cfg


@pytest.mark.asyncio
async def test_chain_stage_writes_chains_annotations_and_diagnostics(tmp_path):
    runtime = _Runtime()
    artifact = HypothesesArtifact(
        plugin_slug="demo",
        hypotheses=[_hypothesis("h1", "auth"), _hypothesis("h2", "file_ops")],
    )

    result = await chain_stage.run(artifact, _config(), runtime, runs_root=str(tmp_path), run_id="run1")

    assert len(runtime.calls) == 1
    prompt = runtime.calls[0]["messages"][1]["content"]
    assert "sink_code" in prompt
    assert "taint_path" in prompt
    assert "quality_gate" in prompt
    assert [h.chains_with for h in result.hypotheses] == [["h2"], ["h1"]]

    chains = json.loads((tmp_path / "run1" / "chains.json").read_text())
    diagnostics = json.loads((tmp_path / "run1" / "chain_diagnostics.json").read_text())
    assert chains[0]["ids"] == ["h1", "h2"]
    assert diagnostics["status"] == "complete"
    assert diagnostics["hypothesis_count"] == 2
    assert diagnostics["accepted_chain_count"] == 1
    assert diagnostics["annotated_hypothesis_count"] == 2


@pytest.mark.asyncio
async def test_chain_stage_marks_insufficient_hypotheses_without_model_call(tmp_path):
    artifact = HypothesesArtifact(plugin_slug="demo", hypotheses=[_hypothesis("h1")])

    result = await chain_stage.run(artifact, _config(), _Runtime(), runs_root=str(tmp_path), run_id="run1")

    assert result.hypotheses[0].chains_with == []
    diagnostics = json.loads((tmp_path / "run1" / "chain_diagnostics.json").read_text())
    assert diagnostics["status"] == "insufficient_hypotheses"
    assert diagnostics["hypothesis_count"] == 1
    assert diagnostics["accepted_chain_count"] == 0


@pytest.mark.asyncio
async def test_chain_synthesizer_distinguishes_model_failure():
    synthesizer = ChainSynthesizer(_FailingRuntime(), model="test-model")

    result = await synthesizer.synthesize([_hypothesis("h1"), _hypothesis("h2")])

    assert result.status == "failed"
    assert result.chains == []
    assert "model unavailable" in (result.error or "")
