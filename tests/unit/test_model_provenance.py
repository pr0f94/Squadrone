"""Model changes never silently reuse results from another route or generation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from squadrone.schemas.config import PipelineConfig
from squadrone.schemas.recon import CoverageItem, ReconArtifact
from squadrone.services.model_provenance import (
    MODEL_PROVENANCE_FILENAME,
    prepare_model_resume,
    record_stage_model_identity,
    stage_model_identities,
)
from squadrone.stages.hypothesis import _batch_input_fingerprint


def _config(*, profile: bool = False) -> PipelineConfig:
    data = PipelineConfig.from_yaml("pipelines/chatgpt.yaml").model_dump()
    data["llm"] = {}
    if profile:
        data["models"]["surveyor"] = "profile/go"
        data["model_profiles"] = {
            "go": {
                "model": "test-model",
                "api_format": "openai_chat",
                "api_base": "https://example.test/v1",
                "api_key_env": "SQUADRONE_TEST_KEY",
                "reasoning_efforts": ["low", "high"],
                "generation": {"reasoning_effort": "low"},
                "pricing": {"input_per_million": 1, "output_per_million": 2},
            },
        }
    return PipelineConfig.model_validate(data)


def _tracked_run(run_dir: Path, config: PipelineConfig) -> None:
    plan = prepare_model_resume(run_dir, config, resuming=False)
    for stage in plan.identities:
        record_stage_model_identity(run_dir, plan, stage)
    for name in (
        "intake.json", "recon.json", "coverage.json", "hypotheses.jsonl",
        "triaged.json", "findings.jsonl", "verify_complete.json", "report_f1_wordfence.md",
        "trace.jsonl", "cost_calls.tsv",
    ):
        (run_dir / name).write_text(f"original {name}")
    for directory in ("review_batches", "verifications"):
        (run_dir / directory).mkdir()
        (run_dir / directory / "checkpoint.json").write_text("original checkpoint")


@pytest.mark.parametrize(
    ("role", "first_stage"),
    [
        ("surveyor", "recon"),
        ("specialists", "hypothesis"),
        ("hypothesis_verifier", "hypothesis"),
        ("critic", "triage"),
        ("developer", "hypothesis"),
        ("developer_followup", "verify"),
        ("poc_author", "verify"),
        ("reporter", "report"),
    ],
)
def test_model_change_archives_only_affected_outputs(tmp_path, role, first_stage):
    config = _config()
    _tracked_run(tmp_path, config)
    setattr(config.models, role, "openai/another-model")

    plan = prepare_model_resume(tmp_path, config, resuming=True)

    assert plan.invalidated_from == first_stage
    assert plan.archive_path is not None
    stages = list(plan.identities)
    for stage, name in {
        "recon": "recon.json",
        "hypothesis": "hypotheses.jsonl",
        "triage": "triaged.json",
        "verify": "findings.jsonl",
        "report": "report_f1_wordfence.md",
    }.items():
        affected = stages.index(stage) >= stages.index(first_stage)
        assert (tmp_path / name).exists() is not affected
        assert (plan.archive_path / name).exists() is affected
        if affected:
            assert (plan.archive_path / name).read_text() == f"original {name}"
    assert (tmp_path / "intake.json").exists()
    assert (tmp_path / "trace.jsonl").exists()
    assert (tmp_path / "cost_calls.tsv").exists()
    assert (tmp_path / "review_batches").exists() is (first_stage not in {"recon", "hypothesis"})
    assert (tmp_path / "verifications").exists() is (first_stage == "report")


@pytest.mark.parametrize("setting", ["api_base", "model", "generation", "history_policy"])
def test_profile_contents_not_just_alias_control_resume(tmp_path, setting):
    config = _config(profile=True)
    _tracked_run(tmp_path, config)
    profile = config.model_profiles["go"]
    if setting == "generation":
        profile.generation.reasoning_effort = "high"
    elif setting == "history_policy":
        profile.history_policy = "trim"
    elif setting == "model":
        profile.model = "another-model"
    else:
        profile.api_base = "https://another.test/v1"

    assert prepare_model_resume(tmp_path, config, resuming=True).invalidated_from == "recon"


def test_same_profile_can_resume_without_reading_secret(tmp_path, monkeypatch):
    config = _config(profile=True)
    monkeypatch.setenv("SQUADRONE_TEST_KEY", "must-never-appear-in-provenance")
    _tracked_run(tmp_path, config)
    before = (tmp_path / MODEL_PROVENANCE_FILENAME).read_text()
    assert "must-never-appear" not in before
    monkeypatch.delenv("SQUADRONE_TEST_KEY")

    plan = prepare_model_resume(tmp_path, config, resuming=True)

    assert plan.invalidated_from is None
    assert plan.tracking
    assert not (tmp_path / "model_archive").exists()
    assert (tmp_path / MODEL_PROVENANCE_FILENAME).read_text() == before


@pytest.mark.parametrize("prompt,first_stage", [
    ("surveyor", "recon"), ("developer", "hypothesis"),
    ("critic", "triage"), ("developer_setup", "verify"),
    ("reporter_wordfence", "report"),
])
def test_prompt_change_archives_affected_results(tmp_path, monkeypatch, prompt, first_stage):
    from squadrone.services import model_provenance

    config = _config(profile=True)
    _tracked_run(tmp_path, config)
    original = model_provenance.load_prompt
    monkeypatch.setattr(
        model_provenance, "load_prompt",
        lambda name: original(name) + ("\nnew methodology" if name == prompt else ""),
    )
    plan = prepare_model_resume(tmp_path, config, resuming=True)
    assert plan.invalidated_from == first_stage
    assert plan.archive_path is not None
    assert (plan.archive_path / "report_f1_wordfence.md").exists()


def test_output_allowance_changes_invalidate_stages(tmp_path):
    config = _config(profile=True)
    _tracked_run(tmp_path, config)
    config.model_profiles["go"].output_budget_floor = 16384
    assert prepare_model_resume(tmp_path, config, resuming=True).invalidated_from == "recon"


def test_empty_reasoning_wire_fix_preserves_completed_checkpoints(tmp_path):
    config = PipelineConfig.from_yaml("pipelines/opencode-go.yaml")
    config.model_profiles["go-deepseek"].empty_tool_reasoning = False
    _tracked_run(tmp_path, config)
    config.model_profiles["go-deepseek"].empty_tool_reasoning = True
    plan = prepare_model_resume(tmp_path, config, resuming=True)
    assert plan.invalidated_from is None
    assert (tmp_path / "review_batches" / "checkpoint.json").read_text() == "original checkpoint"
    assert not (tmp_path / "model_archive").exists()


def test_partial_batch_identity_is_recorded_before_stage_completion(tmp_path):
    config = _config(profile=True)
    plan = prepare_model_resume(tmp_path, config, resuming=False)
    record_stage_model_identity(tmp_path, plan, "hypothesis")
    batch_dir = tmp_path / "review_batches"
    batch_dir.mkdir()
    (batch_dir / "partial.json").write_text("partial current-model result")

    resumed = prepare_model_resume(tmp_path, config, resuming=True)

    assert resumed.invalidated_from is None
    assert (batch_dir / "partial.json").exists()


def test_unknown_legacy_run_requires_fresh_profile_run_and_preserves_files(tmp_path):
    path = tmp_path / "recon.json"
    path.write_text("legacy source artifact")

    with pytest.raises(ValueError, match="no model provenance.*start a fresh run"):
        prepare_model_resume(tmp_path, _config(profile=True), resuming=True)

    assert path.read_text() == "legacy source artifact"
    assert not (tmp_path / MODEL_PROVENANCE_FILENAME).exists()
    assert not (tmp_path / "model_archive").exists()


def test_legacy_pipeline_keeps_unknown_legacy_resume_behavior(tmp_path):
    path = tmp_path / "recon.json"
    path.write_text("legacy source artifact")
    plan = prepare_model_resume(tmp_path, _config(), resuming=True)
    record_stage_model_identity(tmp_path, plan, "recon")

    assert not plan.tracking
    assert plan.invalidated_from is None
    assert path.read_text() == "legacy source artifact"
    assert not (tmp_path / MODEL_PROVENANCE_FILENAME).exists()


def test_unknown_stage_inside_tracked_profile_run_is_not_relabelled(tmp_path):
    config = _config(profile=True)
    plan = prepare_model_resume(tmp_path, config, resuming=False)
    record_stage_model_identity(tmp_path, plan, "recon")
    (tmp_path / "hypotheses.jsonl").write_text("unknown old hypotheses")

    with pytest.raises(ValueError, match="provenance is missing for hypothesis"):
        prepare_model_resume(tmp_path, config, resuming=True)

    assert (tmp_path / "hypotheses.jsonl").read_text() == "unknown old hypotheses"


def test_malformed_provenance_fails_without_touching_results(tmp_path):
    (tmp_path / MODEL_PROVENANCE_FILENAME).write_text("not json")
    (tmp_path / "recon.json").write_text("preserved")
    with pytest.raises(ValueError, match="cannot be read safely"):
        prepare_model_resume(tmp_path, _config(), resuming=True)
    assert (tmp_path / "recon.json").read_text() == "preserved"


def test_specialist_fingerprint_binds_effective_model_generation_and_developer():
    config = _config()
    target = CoverageItem(
        id="cov-1", kind="sink", review_areas=["injection_files"], type="sql_query",
        name="query", file="plugin.php", line=2, snippet="$wpdb->query($sql);",
    )
    recon = ReconArtifact(
        plugin_slug="demo", entry_points=[], sinks=[], entry_to_sink_paths={}, raw_grep_hits={},
    )

    def fingerprint() -> str:
        return _batch_input_fingerprint(
            recon, [target], "injection_files",
            model_identity=stage_model_identities(config)["hypothesis"],
        )

    original = fingerprint()
    config.models.specialists = "openai/another-model"
    model_changed = fingerprint()
    assert original != model_changed
    config.reasoning.specialists = "high"
    effort_changed = fingerprint()
    assert effort_changed != model_changed
    config.models.developer = "openai/another-consultant"
    assert fingerprint() != effort_changed


def test_specialist_fingerprint_binds_inspected_version():
    config = _config()
    recon = ReconArtifact(plugin_slug="demo", entry_points=[], sinks=[], entry_to_sink_paths={}, raw_grep_hits={})
    args = (recon, [], "injection_files")
    identity = stage_model_identities(config)["hypothesis"]
    first = _batch_input_fingerprint(*args, model_identity=identity, plugin_version="1.2.3")
    assert first != _batch_input_fingerprint(*args, model_identity=identity, plugin_version="1.2.4")


def test_identity_manifest_does_not_claim_downstream_stage_before_it_runs(tmp_path):
    config = _config()
    plan = prepare_model_resume(tmp_path, config, resuming=False)
    record_stage_model_identity(tmp_path, plan, "recon")
    stored = json.loads((tmp_path / MODEL_PROVENANCE_FILENAME).read_text())
    assert set(stored["stages"]) == {"recon"}


def test_archive_rejects_symlink_parent_without_moving_results(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    config = _config()
    _tracked_run(run_dir, config)
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    (run_dir / "model_archive").symlink_to(unrelated, target_is_directory=True)
    config.models.surveyor = "openai/another-model"

    with pytest.raises(ValueError, match="archive directory is a symlink"):
        prepare_model_resume(run_dir, config, resuming=True)

    assert (run_dir / "recon.json").read_text() == "original recon.json"
    assert list(unrelated.iterdir()) == []


def test_archive_interruption_does_not_bless_remaining_stale_results(tmp_path, monkeypatch):
    config = _config(profile=True)
    _tracked_run(tmp_path, config)
    config.models.critic = "openai/another-critic"
    rename = Path.rename
    calls = 0

    def fail_second_move(path, target):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("simulated interruption while moving artifacts")
        return rename(path, target)

    monkeypatch.setattr(Path, "rename", fail_second_move)
    with pytest.raises(OSError, match="simulated interruption"):
        prepare_model_resume(tmp_path, config, resuming=True)
    monkeypatch.setattr(Path, "rename", rename)

    resumed = prepare_model_resume(tmp_path, config, resuming=True)

    assert resumed.invalidated_from == "triage"
    assert not (tmp_path / "triaged.json").exists()
    assert not (tmp_path / "findings.jsonl").exists()
    archives = list((tmp_path / "model_archive").iterdir())
    assert len(archives) == 2
    assert any((archive / "triaged.json").exists() for archive in archives)
    assert any((archive / "findings.jsonl").exists() for archive in archives)
