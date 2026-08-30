from __future__ import annotations

from copy import deepcopy

import pytest

from squadrone.agents.hypothesis_verifier import validate_exact_sink_anchor
from squadrone.agents.prompts_io import load_prompt
from squadrone.schemas import (
    BugClass,
    Confidence,
    Hypothesis,
    HypothesesArtifact,
    SecurityOutcome,
    SourceAnchor,
    SourceAnchorRepair,
    TriagedArtifact,
)
from squadrone.stages.triage import _validate_critic_accounting


def _original_hypothesis() -> Hypothesis:
    return Hypothesis(
        id="h-upload",
        specialist="injection_files",
        bug_class=BugClass.ARBITRARY_FILE_WRITE,
        entry_point="direct multipart upload",
        file="driver.php",
        line=20,
        sink="file_put_contents($path, $fp)",
        sink_code="file_put_contents($path, $fp);",
        taint_path=["multipart bytes", "Driver::_save", "file_put_contents"],
        reasoning="The multipart bytes reach a file-write operation.",
        confidence=Confidence.HIGH,
        preconditions="unauthenticated; writable destination",
        affected_versions="<= 1.0",
        security_outcome=SecurityOutcome(
            integrity="high",
            description="An unauthenticated attacker can create an arbitrary file.",
        ),
        evidence_summary={
            "attacker_role": "unauthenticated",
            "source": "Multipart filename and bytes.",
            "control": "No authentication or safe-extension allowlist.",
            "sink": "file_put_contents($path, $fp)",
            "reachable_path": "multipart -> _save -> file_put_contents",
            "boundary": "An unauthenticated user crosses the filesystem boundary.",
            "impact": "An arbitrary file is created.",
        },
    )


def _corrected_hypothesis(original: Hypothesis) -> Hypothesis:
    corrected = original.model_copy(deep=True)
    corrected.line = 12
    corrected.sink = "rename($uri, $path), with copy fallback"
    corrected.sink_code = "if ((!rename($uri, $path)) && !copy($uri, $path)) {"
    corrected.taint_path[-1] = "rename($uri, $path), with copy fallback"
    corrected.reasoning = (
        "The multipart temporary file reaches the local rename/copy branch."
    )
    corrected.evidence_summary["sink"] = "rename($uri, $path), with copy fallback"
    corrected.evidence_summary["reachable_path"] = "multipart -> _save -> rename/copy"
    return corrected


def _repair(original: Hypothesis, corrected: Hypothesis) -> SourceAnchorRepair:
    return SourceAnchorRepair(
        hypothesis_id=original.id,
        original=SourceAnchor(
            file=original.file,
            line=original.line,
            sink=original.sink,
            sink_code=original.sink_code,
        ),
        corrected=SourceAnchor(
            file=corrected.file,
            line=corrected.line,
            sink=corrected.sink,
            sink_code=corrected.sink_code,
        ),
        reason="The normal local multipart stream selects the rename/copy branch.",
    )


def _write_source(tmp_path) -> None:
    lines = ["<?php", *["safe();"] * 10]
    lines.append("if ((!rename($uri, $path)) && !copy($uri, $path)) {")
    lines.extend(["safe();"] * 7)
    lines.append("file_put_contents($path, $fp);")
    (tmp_path / "driver.php").write_text("\n".join(lines) + "\n")


def _artifacts(
    original: Hypothesis,
    corrected: Hypothesis,
    *,
    include_repair: bool = True,
) -> tuple[HypothesesArtifact, TriagedArtifact]:
    inputs = HypothesesArtifact(plugin_slug="demo", hypotheses=[original])
    output = TriagedArtifact(
        plugin_slug="demo",
        accepted=[corrected],
        rejected=[],
        merged=[],
        source_anchor_repairs=(
            [_repair(original, corrected)] if include_repair else []
        ),
    )
    return inputs, output


def test_same_claim_local_source_anchor_repair_is_accepted(tmp_path):
    _write_source(tmp_path)
    original = _original_hypothesis()
    corrected = _corrected_hypothesis(original)
    inputs, output = _artifacts(original, corrected)

    _validate_critic_accounting(inputs, output, plugin_path=str(tmp_path))


def test_changed_anchor_requires_explicit_audit_metadata(tmp_path):
    _write_source(tmp_path)
    original = _original_hypothesis()
    corrected = _corrected_hypothesis(original)
    inputs, output = _artifacts(original, corrected, include_repair=False)

    with pytest.raises(ValueError, match="without source_anchor_repairs"):
        _validate_critic_accounting(inputs, output, plugin_path=str(tmp_path))


@pytest.mark.parametrize(
    "mutation",
    [
        "entry_point",
        "bug_class",
        "attacker_role",
        "security_outcome",
        "source",
        "control",
        "boundary",
        "impact",
    ],
)
def test_source_anchor_repair_cannot_launder_a_changed_claim(tmp_path, mutation):
    _write_source(tmp_path)
    original = _original_hypothesis()
    corrected = _corrected_hypothesis(original)
    if mutation == "entry_point":
        corrected.entry_point = "different handler"
    elif mutation == "bug_class":
        corrected.bug_class = BugClass.SQLI
    elif mutation == "attacker_role":
        corrected.evidence_summary["attacker_role"] = "administrator"
    elif mutation == "security_outcome":
        corrected.security_outcome.availability = "high"
    else:
        corrected.evidence_summary[mutation] = "A materially different claim."
    inputs, output = _artifacts(original, corrected)

    with pytest.raises(ValueError, match="changed claim fields"):
        _validate_critic_accounting(inputs, output, plugin_path=str(tmp_path))


@pytest.mark.parametrize("change", ["cross_file", "too_far"])
def test_source_anchor_repair_must_remain_same_file_and_local(tmp_path, change):
    _write_source(tmp_path)
    original = _original_hypothesis()
    corrected = _corrected_hypothesis(original)
    if change == "cross_file":
        corrected.file = "other.php"
        (tmp_path / "other.php").write_text(corrected.sink_code + "\n")
        corrected.line = 1
    else:
        corrected.line = 40
        (tmp_path / "driver.php").write_text(
            (tmp_path / "driver.php").read_text()
            + ("safe();\n" * 19)
            + corrected.sink_code
            + "\n"
        )
    inputs, output = _artifacts(original, corrected)

    with pytest.raises(ValueError, match="same-file local correction"):
        _validate_critic_accounting(inputs, output, plugin_path=str(tmp_path))


@pytest.mark.parametrize("stale_field", ["taint_path", "evidence_sink"])
def test_source_anchor_repair_must_update_anchor_bearing_evidence(
    tmp_path, stale_field
):
    _write_source(tmp_path)
    original = _original_hypothesis()
    corrected = _corrected_hypothesis(original)
    if stale_field == "taint_path":
        corrected.taint_path = deepcopy(original.taint_path)
    else:
        corrected.evidence_summary["sink"] = original.evidence_summary["sink"]
    inputs, output = _artifacts(original, corrected)

    with pytest.raises(ValueError, match="left .* unchanged"):
        _validate_critic_accounting(inputs, output, plugin_path=str(tmp_path))


def test_corrected_anchor_must_match_exact_plugin_source(tmp_path):
    _write_source(tmp_path)
    original = _original_hypothesis()
    corrected = _corrected_hypothesis(original)
    corrected.sink_code = "rename($different, $path);"
    corrected.taint_path[-1] = corrected.sink_code
    corrected.evidence_summary["sink"] = corrected.sink_code
    inputs, output = _artifacts(original, corrected)

    with pytest.raises(ValueError, match="invalid source anchor"):
        _validate_critic_accounting(inputs, output, plugin_path=str(tmp_path))


def test_unchanged_accurate_hypothesis_needs_no_repair_metadata(tmp_path):
    _write_source(tmp_path)
    original = _original_hypothesis()
    inputs, output = _artifacts(original, original, include_repair=False)

    _validate_critic_accounting(inputs, output, plugin_path=str(tmp_path))


def test_source_anchor_repair_schema_is_backward_compatible_and_round_trips():
    legacy = TriagedArtifact.model_validate(
        {"plugin_slug": "demo", "accepted": [], "rejected": [], "merged": []}
    )
    assert legacy.source_anchor_repairs == []

    original = _original_hypothesis()
    corrected = _corrected_hypothesis(original)
    artifact = _artifacts(original, corrected)[1]
    restored = TriagedArtifact.model_validate_json(artifact.model_dump_json())
    assert restored.source_anchor_repairs == artifact.source_anchor_repairs


def test_exact_anchor_validator_cannot_read_outside_plugin_root(tmp_path):
    outside = tmp_path.parent / "outside-secret.php"
    outside.write_text("dangerous($secret);\n")

    error = validate_exact_sink_anchor(
        tmp_path,
        "../outside-secret.php",
        1,
        "dangerous($secret);",
    )

    assert error and "inside the plugin root" in error


def test_specialist_and_critic_prompts_require_bounded_branch_repair():
    shared = " ".join(load_prompt("specialists/_shared_rules").split())
    critic = " ".join(load_prompt("critic").split())

    assert "Source presence is not branch reachability" in shared
    assert "mutually exclusive dangerous operations" in shared
    assert "same source file and within 15 lines" in critic
    assert "source_anchor_repairs" in critic
    assert "Never use an unrelated nearby dangerous expression" in critic
    assert "copy invariant claim values byte-for-byte" in critic
    assert (
        "`evidence_summary.attacker_role`, `.source`, `.control`, `.boundary`" in critic
    )
