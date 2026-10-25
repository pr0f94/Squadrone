"""Non-secret model identities and recoverable resume invalidation."""

from __future__ import annotations

import json
import hashlib
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from .artifacts import atomic_write_json
from .model_profiles import resolve_model
from ..agents.prompts_io import load_prompt

if TYPE_CHECKING:
    from ..schemas.config import PipelineConfig


MODEL_PROVENANCE_FILENAME = "model_provenance.json"
_SCHEMA_VERSION = 1
_MODEL_STAGES = ("recon", "hypothesis", "triage", "verify", "report")
_STAGE_ROLES = {
    "recon": ("surveyor",),
    "hypothesis": ("specialists", "hypothesis_verifier", "developer"),
    "triage": ("critic", "developer"),
    "verify": ("poc_author", "developer", "developer_followup"),
    "report": ("reporter",),
}
_STAGE_PROMPTS = {
    "recon": ("surveyor",),
    "hypothesis": (
        "specialists/_shared_rules", "specialists/authorization_workflows",
        "specialists/injection_files", "specialists/xss_lifecycle",
        "specialists/authentication", "hypothesis_verifier", "_wp_idioms", "developer",
    ),
    "triage": ("critic", "developer", "_wp_idioms"),
    "verify": (
        "poc_author", "developer", "developer_setup", "developer_setup_followup",
        "developer_setup_requested",
    ),
    "report": ("reporter_wordfence", "reporter_patchstack"),
}
# Increment when deterministic acceptance/runtime semantics change independently
# of prompts or model settings. Historical artifacts are archived, never edited.
_STAGE_POLICY_REVISIONS = {
    "recon": "complete-output-v1",
    "hypothesis": "complete-output-consultation-v1",
    "triage": "attacker-prerequisites-inspected-version-v1",
    "verify": "complete-output-setup-v1",
    "report": "complete-output-v1",
}
_STAGE_ARTIFACTS = {
    "recon": ("recon.json", "coverage.json"),
    "hypothesis": (
        "hypotheses.jsonl", "hypotheses_*.jsonl", "coverage_*.json",
        "hypothesis_verifier_drops.json", "review_batches",
    ),
    "triage": (
        "triaged.json", "triaged.jsonl", "quality_gate_triage.json",
        "manual_review_queued.json",
    ),
    "verify": (
        "findings.jsonl", "findings_*.jsonl", "verify_complete.json", "verifications",
    ),
    "report": ("report_*.md",),
}


@dataclass(frozen=True)
class ModelResumePlan:
    identities: dict[str, dict]
    tracking: bool
    invalidated_from: str | None = None
    archive_path: Path | None = None


def stage_model_identities(config: PipelineConfig) -> dict[str, dict]:
    """Resolve generation/route identities without looking up any credentials."""
    identities = {
        stage: {
            role: resolve_model(
                model, config.llm_options_for_role(role)
            ).identity
            for role in roles
            if (model := getattr(config.models, role, None)) is not None
        }
        for stage, roles in _STAGE_ROLES.items()
    }
    for stage, prompts in _STAGE_PROMPTS.items():
        identities[stage]["_methodology"] = {
            "revision": _STAGE_POLICY_REVISIONS[stage],
            "prompts": {
                name: hashlib.sha256(load_prompt(name).encode()).hexdigest()
                for name in prompts
            },
        }
    return identities


def _read_provenance(run_dir: Path) -> dict[str, dict]:
    path = run_dir / MODEL_PROVENANCE_FILENAME
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
        if (
            not isinstance(data, dict)
            or data.get("version") != _SCHEMA_VERSION
            or not isinstance(data.get("stages"), dict)
            or any(
                stage not in _MODEL_STAGES or not isinstance(identity, dict)
                for stage, identity in data["stages"].items()
            )
        ):
            raise ValueError("invalid schema")
    except (OSError, ValueError) as exc:
        raise ValueError(
            "Model provenance cannot be read safely; start a fresh run. "
            "Existing run artifacts have been preserved."
        ) from exc
    return data["stages"]


def _stage_artifacts(run_dir: Path, stage: str) -> list[Path]:
    paths: set[Path] = set()
    for pattern in _STAGE_ARTIFACTS[stage]:
        paths.update(run_dir.glob(pattern))
    return sorted(paths)


def prepare_model_resume(
    run_dir: Path,
    config: PipelineConfig,
    *,
    resuming: bool,
) -> ModelResumePlan:
    """Archive known stale results, or reject unknown legacy profile provenance.

    Historical runs without profiles retain their existing resume behavior. They
    are never relabeled as having been produced by the current model selection.
    New/tracked runs record identities before a stage starts, so interrupted
    per-batch work has the same provenance protection as complete artifacts.
    """
    identities = stage_model_identities(config)
    manifest_exists = (run_dir / MODEL_PROVENANCE_FILENAME).exists()
    artifacts = {stage: _stage_artifacts(run_dir, stage) for stage in _MODEL_STAGES}
    profiles_enabled = bool(getattr(config, "model_profiles", {}))
    if resuming and not manifest_exists and any(artifacts.values()):
        if profiles_enabled:
            raise ValueError(
                "This run has no model provenance. A model-profile pipeline cannot "
                "safely reuse its results; start a fresh run. Existing artifacts "
                "have been preserved."
            )
        return ModelResumePlan(identities=identities, tracking=False)

    stored = _read_provenance(run_dir)
    if resuming and profiles_enabled:
        unknown = [stage for stage in _MODEL_STAGES if artifacts[stage] and stage not in stored]
        if unknown:
            raise ValueError(
                f"Model provenance is missing for {', '.join(unknown)}. Start a "
                "fresh run; existing artifacts have been preserved."
            )
    changed = next(
        (stage for stage in _MODEL_STAGES if stage in stored and stored[stage] != identities[stage]),
        None,
    ) if resuming else None
    if changed is None:
        return ModelResumePlan(identities=identities, tracking=True)

    affected = _MODEL_STAGES[_MODEL_STAGES.index(changed):]
    archive_root = run_dir / "model_archive"
    if archive_root.is_symlink():
        raise ValueError(
            "The model archive directory is a symlink; existing artifacts have "
            "been preserved. Use a fresh run or a real archive directory."
        )
    archive = archive_root / uuid.uuid4().hex
    archive.mkdir(parents=True)
    # Write the archive envelope first. If interrupted mid-move, the unchanged
    # live provenance still prevents stale results from being reused on resume.
    atomic_write_json(archive / MODEL_PROVENANCE_FILENAME, {
        "version": _SCHEMA_VERSION, "stages": stored,
    })
    for stage in affected:
        for path in artifacts[stage]:
            path.rename(archive / path.name)
        stored.pop(stage, None)
    atomic_write_json(run_dir / MODEL_PROVENANCE_FILENAME, {
        "version": _SCHEMA_VERSION, "stages": stored,
    })
    return ModelResumePlan(
        identities=identities,
        tracking=True,
        invalidated_from=changed,
        archive_path=archive,
    )


def record_stage_model_identity(run_dir: Path, plan: ModelResumePlan, stage: str) -> None:
    """Bind subsequent stage writes, including partial checkpoints, to its model."""
    if not plan.tracking:
        return
    stored = _read_provenance(run_dir)
    stored[stage] = plan.identities[stage]
    atomic_write_json(run_dir / MODEL_PROVENANCE_FILENAME, {
        "version": _SCHEMA_VERSION, "stages": stored,
    })
