"""Smoke tests — every Pydantic schema instantiates with valid data and round-trips through JSON."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from squadrone.schemas import (
    BugClass,
    Confidence,
    DedupStatus,
    EntryPoint,
    Finding,
    Hypothesis,
    HypothesesArtifact,
    IntakeArtifact,
    PipelineConfig,
    PoCAttempt,
    PoCStatus,
    ReconArtifact,
    Sink,
    StaticCallEdge,
    StaticCallback,
    TriagedArtifact,
)


def _hypothesis() -> Hypothesis:
    return Hypothesis(
        id="h-1", specialist="auth", bug_class=BugClass.MISSING_CAP_CHECK,
        entry_point="wp_ajax_demo", file="demo.php", line=10,
        sink="wp_delete_post", taint_path=["$_POST", "wp_delete_post"],
        reasoning="No cap check.", confidence=Confidence.HIGH,
        preconditions="any subscriber", affected_versions="<=1.0",
    )


def _finding() -> Finding:
    h = _hypothesis()
    return Finding(
        id="f-1", hypothesis=h, poc_status=PoCStatus.SUCCESS,
        poc_script_path="/tmp/p.py",
        poc_attempts=[PoCAttempt(iteration=1, script_path="/tmp/p.py", result=PoCStatus.SUCCESS)],
        evidence={"deleted": 1}, confidence_runs=1,
        dedup_status=DedupStatus.NOVEL, dedup_matches=[],
    )


def test_intake_round_trip(tmp_path):
    a = IntakeArtifact(
        run_id="r1", plugin_slug="x", plugin_version="1.0",
        source_path="/tmp/x", file_count=1, total_lines=10,
        svn_url="https://example/", scanned_at=datetime.now(timezone.utc),
    )
    p = tmp_path / "intake.json"
    a.to_json_file(str(p))
    assert IntakeArtifact.from_json_file(str(p)) == a


def test_recon_round_trip(tmp_path):
    a = ReconArtifact(
        plugin_slug="x",
        entry_points=[EntryPoint(
            type="ajax_priv", name="wp_ajax_x", file="x.php", line=1,
            handler_function="x", requires_auth=True,
            has_nonce_check=False, has_capability_check=False, capability=None,
        )],
        sinks=[Sink(type="db_query", function="wpdb->query", file="x.php", line=2, tainted_args=["a"])],
        entry_to_sink_paths={"wp_ajax_x": ["x.php:1->x.php:2"]},
        raw_grep_hits={"add_action": ["x.php:1"]},
        static_callbacks=[
            StaticCallback(
                type="ajax_priv",
                name="wp_ajax_x",
                file="x.php",
                line=1,
                handler_function="x",
                callback_kind="function",
                raw="add_action('wp_ajax_x', 'x')",
            )
        ],
        static_call_edges=[
            StaticCallEdge(
                caller="x",
                callee="helper",
                caller_file="x.php",
                caller_line=2,
                callee_file="x.php",
                callee_line=8,
                confidence="high",
            )
        ],
    )
    p = tmp_path / "recon.json"
    a.to_json_file(str(p))
    assert ReconArtifact.from_json_file(str(p)) == a


def test_hypothesis_artifacts():
    h = _hypothesis()
    ha = HypothesesArtifact(plugin_slug="x", hypotheses=[h])
    assert ha.hypotheses[0].bug_class == BugClass.MISSING_CAP_CHECK
    ta = TriagedArtifact(plugin_slug="x", accepted=[h], rejected=[], merged=[])
    assert ta.accepted == [h]


def test_finding_round_trip(tmp_path):
    f = _finding()
    p = tmp_path / "f.json"
    f.to_json_file(str(p))
    assert Finding.from_json_file(str(p)) == f


def test_invalid_data_raises():
    with pytest.raises(ValidationError):
        IntakeArtifact()  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        Hypothesis(  # type: ignore[call-arg]
            id="x", specialist="s", bug_class="not-a-cwe",
            entry_point="e", file="f", line=1, sink="s", taint_path=[],
            reasoning="r", confidence="maybe",
            preconditions="p", affected_versions="v",
        )
    with pytest.raises(ValidationError):
        PoCAttempt(iteration=1, script_path="/tmp", result="nope")  # type: ignore[arg-type]


def test_pipeline_config_loads():
    cfg = PipelineConfig.from_yaml("pipelines/default.yaml")
    assert cfg.cost_ceiling_usd > 0
    assert cfg.models.specialists
    assert "wordfence" in cfg.vuln_dbs.model_dump()


def test_pipeline_llm_options_load():
    cfg = PipelineConfig.from_yaml("pipelines/openai.yaml")
    assert cfg.llm_options_for_role("critic") == {
        "reasoning_effort": "high",
        "verbosity": "high",
    }
    assert cfg.llm_options_for_role("surveyor") == {
        "reasoning_effort": "high",
        "verbosity": "high",
    }


def test_hypothesis_coerces_list_to_str():
    """LLMs sometimes emit list[str] for fields we declared as str. Coerce."""
    h = Hypothesis.model_validate({
        "id": "x", "specialist": "auth", "bug_class": "CWE-862",
        "entry_point": "wp_ajax_x", "file": "x.php", "line": 1,
        "sink": ["a", "b"],
        "taint_path": ["src", "sink"],
        "reasoning": ["one reason", "another"],
        "confidence": "high",
        "preconditions": ["a precondition", "another"],
        "affected_versions": ["<= 1.0", "and 2.0"],
    })
    assert h.preconditions == "a precondition; another"
    assert h.reasoning == "one reason; another"
    assert h.sink == "a; b"


def test_strip_fences_handles_prose_and_embedded_json():
    """Runtime must extract JSON from various LLM response shapes."""
    import json as _json
    from squadrone.agents.runtime import _strip_fences
    assert _json.loads(_strip_fences("```json\n[1,2]\n```")) == [1, 2]
    assert _json.loads(_strip_fences("Here you go:\n```json\n[1,2]\n```")) == [1, 2]
    assert _json.loads(_strip_fences("Based on analysis:\n[{\"a\":1}]\nThanks.")) == [{"a": 1}]
    assert _json.loads(_strip_fences('[{"x":"has [bracket]"}]')) == [{"x": "has [bracket]"}]
    # Object containing nested array — must return the OBJECT, not the inner array
    out = _strip_fences('Here is the recon: {"plugin_slug":"x","entry_points":[{"a":1}],"sinks":[]}')
    parsed = _json.loads(out)
    assert isinstance(parsed, dict) and parsed["plugin_slug"] == "x"
