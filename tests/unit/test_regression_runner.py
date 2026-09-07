from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from benchmarks import regression_runner
from benchmarks.regression_runner import (
    AttributionExpectation,
    ImpactExpectation,
    RegressionCase,
    RegressionCaseResult,
    RegressionExpectation,
    RegressionManifest,
    _assess_confirmed_findings,
    _assess_policy_rejection,
    _hash_source_tree,
)
from squadrone.schemas.finding import DedupStatus, Finding, PoCAttempt, PoCStatus
from squadrone.schemas.hypothesis import (
    BugClass,
    Confidence,
    Hypothesis,
    SecurityOutcome,
)
from squadrone.schemas.observation import CIAImpact, PoCObservation
from squadrone.services.quality_gate import Grade


def _hypothesis(
    *,
    bug_class: BugClass = BugClass.SQLI,
    hypothesis_id: str = "inject-b001-001",
    security_outcome: SecurityOutcome | None = None,
    reasoning: str = "An unauthenticated caller extracts a protected database value.",
) -> Hypothesis:
    return Hypothesis(
        id=hypothesis_id,
        specialist="injection_files",
        bug_class=bug_class,
        entry_point="POST /wp-admin/admin-ajax.php?action=demo",
        file="plugin.php",
        line=1,
        sink="$wpdb->get_results executes attacker-controlled SQL",
        sink_code="$wpdb->get_results($_POST['query']);",
        taint_path=["$_POST['query']", "$wpdb->get_results"],
        reasoning=reasoning,
        confidence=Confidence.HIGH,
        preconditions="Unauthenticated attacker",
        affected_versions="1.0",
        security_outcome=security_outcome
        or SecurityOutcome(
            confidentiality="high",
            description="Disclosure of a protected database value.",
        ),
        evidence_summary={
            "attacker_role": "unauthenticated",
            "source": "$_POST['query']",
            "control": "no prepared statement",
            "sink": "$wpdb->get_results",
            "reachable_path": "public AJAX -> callback -> $wpdb->get_results",
            "boundary": "anonymous caller reads a protected database value",
            "impact": "disclosure of a protected database value",
            "counterevidence": "none",
            "proof_gaps": "runtime confirmation only",
        },
    )


def _confirm_case(
    *,
    case_id: str = "sqli-1",
    cve_id: str = "CVE-2024-1000",
    seed_line: int = 1,
    expected_line: int | None = None,
    expected_sink: str | None = None,
    expected_sink_code: str | None = None,
) -> RegressionCase:
    hypothesis = _hypothesis(hypothesis_id=f"hyp-{case_id}")
    hypothesis.line = seed_line
    return RegressionCase(
        case_id=case_id,
        cve_id=cve_id,
        plugin_slug="example-plugin",
        version="1.0",
        mode="confirm",
        hypothesis=hypothesis,
        expected=RegressionExpectation(
            attribution=AttributionExpectation(
                hypothesis_id=hypothesis.id,
                bug_class=hypothesis.bug_class,
                root_cause_cwe=hypothesis.root_cause_cwe,
                file=hypothesis.file,
                line=expected_line if expected_line is not None else seed_line,
                sink=expected_sink if expected_sink is not None else hypothesis.sink,
                sink_code=(
                    expected_sink_code
                    if expected_sink_code is not None
                    else hypothesis.sink_code
                ),
            ),
            attacker_role="unauthenticated",
            minimum_impact=ImpactExpectation(confidentiality="high"),
            allowed_oracles=["response_marker"],
        ),
    )


def _policy_case() -> RegressionCase:
    hypothesis = _hypothesis(
        bug_class=BugClass.MISSING_NONCE,
        hypothesis_id="policy-csrf-1",
        security_outcome=SecurityOutcome(),
        reasoning="A CSRF changes only a cosmetic search-box preference.",
    )
    hypothesis.sink = "Updates a cosmetic search-box preference"
    hypothesis.sink_code = "update_option('demo', $_POST['value']);"
    hypothesis.evidence_summary.update(
        {
            "control": "missing nonce",
            "sink": "update_option",
            "reachable_path": "admin form -> update handler -> update_option",
            "boundary": "anonymous attacker changes a cosmetic search preference",
            "impact": "cosmetic preference only",
        }
    )
    return RegressionCase(
        case_id="cosmetic-csrf",
        cve_id="CVE-2024-1001",
        plugin_slug="example-plugin",
        version="1.0",
        mode="policy_reject",
        hypothesis=hypothesis,
        expected=RegressionExpectation(
            attribution=AttributionExpectation(
                hypothesis_id=hypothesis.id,
                bug_class=hypothesis.bug_class,
                root_cause_cwe=hypothesis.root_cause_cwe,
                file=hypothesis.file,
                line=hypothesis.line,
                sink=hypothesis.sink,
                sink_code=hypothesis.sink_code,
            ),
            attacker_role="unauthenticated",
            rejection_rules=[
                "cosmetic_or_no_security_impact",
                "csrf_without_high_impact_outcome",
            ],
        ),
    )


def _finding(case: RegressionCase) -> Finding:
    observation = PoCObservation(
        verdict="vulnerable",
        oracle="response_marker",
        attacker_role="unauthenticated",
        request={"method": "POST", "url": "http://localhost/test"},
        attack={"observed": True, "marker_present": True},
        control={"observed": False, "marker_present": False},
        impact=CIAImpact(
            confidentiality="high",
            description="Disclosure of a protected database value.",
        ),
    )
    return Finding(
        id="finding-1",
        hypothesis=case.hypothesis.model_copy(deep=True),
        poc_status=PoCStatus.SUCCESS,
        poc_script_path="iter_1.py",
        poc_attempts=[
            PoCAttempt(
                iteration=1,
                phase="attack",
                script_path="iter_1.py",
                result=PoCStatus.SUCCESS,
                observation=observation,
            ),
            PoCAttempt(
                iteration=1,
                phase="confirmation",
                script_path="iter_1.py",
                result=PoCStatus.SUCCESS,
                observation=observation,
            ),
        ],
        evidence={"clean_state_restored": True},
        confidence_runs=2,
        dedup_status=DedupStatus.NOT_CHECKED,
        dedup_matches=[],
        verified_impact=observation.impact,
    )


def test_manifest_rejects_duplicate_case_ids() -> None:
    case = _confirm_case()

    with pytest.raises(ValidationError, match="duplicate regression case IDs"):
        RegressionManifest(cases=[case, case.model_copy(deep=True)])


def test_confirm_contract_requires_role_oracle_and_impact() -> None:
    payload = _confirm_case().model_dump(mode="json")
    payload["expected"] = {
        "attribution": payload["expected"]["attribution"],
    }

    with pytest.raises(ValidationError, match="attacker_role"):
        RegressionCase.model_validate(payload)


def test_confirm_contract_requires_final_attribution() -> None:
    payload = _confirm_case().model_dump(mode="json")
    payload["expected"]["attribution"] = None

    with pytest.raises(ValidationError, match="expected.attribution"):
        RegressionCase.model_validate(payload)


def test_confirmed_finding_assessment_accepts_exact_clean_confirmation() -> None:
    case = _confirm_case()

    assert _assess_confirmed_findings(case, [_finding(case)]) == []


def test_assessment_requires_repaired_final_anchor_not_seed_anchor() -> None:
    corrected_sink = (
        "Unauthenticated rename of the uploaded temporary file to the "
        "web-addressable lib/files volume, with a copy fallback"
    )
    corrected_sink_code = (
        "if (($isCmdCopy || !rename($uri, $path)) && !copy($uri, $path)) {"
    )
    case = _confirm_case(
        seed_line=1037,
        expected_line=1029,
        expected_sink=corrected_sink,
        expected_sink_code=corrected_sink_code,
    )
    case.hypothesis.sink = (
        "Unauthenticated arbitrary file write into the web-addressable lib/files volume"
    )
    case.hypothesis.sink_code = "file_put_contents($path, $fp, LOCK_EX)"
    repaired = _finding(case)
    repaired.hypothesis.line = 1029
    repaired.hypothesis.sink = corrected_sink
    repaired.hypothesis.sink_code = corrected_sink_code

    assert _assess_confirmed_findings(case, [repaired]) == []

    unrepaired = _finding(case)
    errors = _assess_confirmed_findings(case, [unrepaired])

    assert any(
        "source line mismatch: expected 1029, got 1037" in error for error in errors
    )
    assert any("sink mismatch" in error for error in errors)
    assert any("sink_code mismatch" in error for error in errors)


def test_assessment_detects_attribution_and_confirmation_regressions() -> None:
    case = _confirm_case()
    finding = _finding(case)
    finding.hypothesis.line += 1
    finding.hypothesis.root_cause_cwe = "CWE-79"
    finding.confidence_runs = 1
    finding.evidence["clean_state_restored"] = False
    finding.poc_attempts = [finding.poc_attempts[0]]

    errors = _assess_confirmed_findings(case, [finding])

    assert any("root_cause_cwe mismatch" in error for error in errors)
    assert any("source line mismatch" in error for error in errors)
    assert any("clean-state" in error for error in errors)
    assert any("no successful confirmation" in error for error in errors)


def test_policy_assessment_requires_named_rules_and_zero_outputs() -> None:
    case = _policy_case()
    grade = Grade(
        accepted=False,
        reason="rejected",
        evidence={},
        severity={},
        warnings=[],
        rules=["cosmetic_or_no_security_impact"],
    )

    errors = _assess_policy_rejection(
        case,
        grade,
        accepted_count=1,
        finding_count=1,
    )

    assert any("csrf_without_high_impact_outcome" in error for error in errors)
    assert any("retained 1" in error for error in errors)
    assert any("produced 1" in error for error in errors)


def test_source_tree_hash_is_order_independent_and_content_sensitive(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    (first / "nested").mkdir(parents=True)
    (second / "nested").mkdir(parents=True)
    (first / "nested" / "b.php").write_text("b")
    (first / "a.php").write_text("a")
    (second / "a.php").write_text("a")
    (second / "nested" / "b.php").write_text("b")

    assert _hash_source_tree(first) == _hash_source_tree(second)

    (second / "a.php").write_text("changed")
    assert _hash_source_tree(first) != _hash_source_tree(second)


def test_run_regressions_is_sequential_with_fresh_per_case_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest_path = tmp_path / "regressions.json"
    manifest = RegressionManifest(
        cases=[
            _confirm_case(case_id="first", cve_id="CVE-2024-1002"),
            _confirm_case(case_id="second", cve_id="CVE-2024-1003"),
        ]
    )
    manifest_path.write_text(manifest.model_dump_json())
    config_path = tmp_path / "pipeline.yaml"
    config_path.write_text("test: true\n")
    monkeypatch.setattr(
        regression_runner.PipelineConfig,
        "from_yaml",
        staticmethod(lambda _path: object()),
    )

    async def fake_init_cache() -> None:
        return None

    monkeypatch.setattr(regression_runner, "init_cache", fake_init_cache)
    active = 0
    max_active = 0
    seen: list[tuple[str, float]] = []

    async def fake_run_case(case, *, config, budget_per_case_usd, plugins_root):
        nonlocal active, max_active
        del config, plugins_root
        active += 1
        max_active = max(max_active, active)
        seen.append((case.case_id, budget_per_case_usd))
        await asyncio.sleep(0)
        active -= 1
        return RegressionCaseResult(
            case_id=case.case_id,
            cve_id=case.cve_id,
            plugin_slug=case.plugin_slug,
            version=case.version,
            mode=case.mode,
            run_id=f"run-{case.case_id}",
            status="passed",
            cost_usd=1.0,
            duration_seconds=1.0,
            finding_count=1,
        )

    monkeypatch.setattr(regression_runner, "_run_case", fake_run_case)

    result = asyncio.run(
        regression_runner.run_regressions(
            str(manifest_path),
            config_path=str(config_path),
            budget_per_case_usd=100.0,
            plugins_root=tmp_path / "plugins",
            results_root=tmp_path / "results",
        )
    )

    assert seen == [("first", 100.0), ("second", 100.0)]
    assert max_active == 1
    assert result.passed_count == 2
    assert Path(result.result_path).is_file()


def test_policy_case_never_builds_runtime_or_invokes_verify(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _policy_case()
    source = tmp_path / "source"
    source.mkdir()
    (source / "plugin.php").write_text("update_option('demo', $_POST['value']);\n")

    async def fake_intake(*_args, **_kwargs):
        return SimpleNamespace(plugin_version="1.0", source_path=str(source))

    async def forbidden_verify(*_args, **_kwargs):
        raise AssertionError("policy regression invoked sandbox verification")

    monkeypatch.setattr(regression_runner.intake_stage, "run", fake_intake)
    monkeypatch.setattr(regression_runner.verify_stage, "run", forbidden_verify)
    monkeypatch.setattr(
        regression_runner,
        "_build_runtime",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("policy regression built an LLM runtime")
        ),
    )

    result = asyncio.run(
        regression_runner._run_case(
            case,
            config=SimpleNamespace(),
            budget_per_case_usd=100.0,
            plugins_root=tmp_path / "plugins",
        )
    )

    assert result.status == "passed"
    assert result.finding_count == 0


def test_load_manifest_and_case_selection_reject_unknown_ids(tmp_path: Path) -> None:
    manifest_path = tmp_path / "regressions.json"
    manifest_path.write_text(
        json.dumps(RegressionManifest(cases=[_confirm_case()]).model_dump(mode="json"))
    )

    loaded = regression_runner.load_regression_manifest(manifest_path)

    assert loaded.cases[0].case_id == "sqli-1"
    with pytest.raises(ValueError, match="unknown regression case IDs"):
        regression_runner._select_cases(loaded, ["missing"])
