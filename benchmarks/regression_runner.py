"""Seeded historical-CVE regression runner for triage and verification.

This harness deliberately starts from a curated, source-grounded hypothesis.  It
is complementary to :mod:`benchmarks.runner`, which measures fresh discovery on
paired vulnerable/fixed releases.  Regression runs never invoke deduplication,
report generation, or vulnerability-database feeds.
"""

from __future__ import annotations

import hashlib
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Sequence

from pydantic import BaseModel, Field, model_validator

from squadrone.agents.developer import DeveloperAgent
from squadrone.agents.hypothesis_verifier import (
    HypothesisVerifier,
    validate_exact_sink_anchor,
)
from squadrone.agents.runtime import AgentRuntime
from squadrone.schemas.config import PipelineConfig
from squadrone.schemas.finding import DedupStatus, Finding, PoCAttempt, PoCStatus
from squadrone.schemas.hypothesis import (
    BugClass,
    HypothesesArtifact,
    Hypothesis,
    TriagedArtifact,
)
from squadrone.schemas.observation import OracleType
from squadrone.services.artifacts import atomic_write_json, atomic_write_jsonl
from squadrone.services.budget import BudgetTracker
from squadrone.services.llm import init_cache
from squadrone.services.quality_gate import (
    Grade,
    apply_quality_gate,
    grade_hypothesis,
    infer_attacker_role,
)
from squadrone.services.roles import UNKNOWN_ATTACKER_ROLE, normalize_attacker_role
from squadrone.stages import intake as intake_stage
from squadrone.stages import triage as triage_stage
from squadrone.stages import verify as verify_stage


RegressionMode = Literal["confirm", "policy_reject"]
RegressionStatus = Literal["passed", "failed", "error"]
ImpactLevel = Literal["none", "low", "high"]

_IMPACT_RANK: dict[ImpactLevel, int] = {"none": 0, "low": 1, "high": 2}


class ImpactExpectation(BaseModel):
    """Minimum CIA impact that the clean confirmation must reproduce."""

    confidentiality: ImpactLevel = "none"
    integrity: ImpactLevel = "none"
    availability: ImpactLevel = "none"

    def has_security_impact(self) -> bool:
        return any(
            value != "none"
            for value in (self.confidentiality, self.integrity, self.availability)
        )


class AttributionExpectation(BaseModel):
    """Exact attribution required after source verification and triage."""

    hypothesis_id: str = Field(min_length=1)
    bug_class: BugClass
    root_cause_cwe: str = Field(pattern=r"^CWE-[1-9][0-9]*$")
    file: str = Field(min_length=1)
    line: int = Field(ge=1)
    sink: str = Field(min_length=1)
    sink_code: str = Field(min_length=1)


class RegressionExpectation(BaseModel):
    """Outcome assertions independent of a particular plugin or CWE family."""

    attribution: AttributionExpectation | None = None
    attacker_role: str | None = None
    minimum_impact: ImpactExpectation = Field(default_factory=ImpactExpectation)
    allowed_oracles: list[OracleType] = Field(default_factory=list)
    rejection_rules: list[str] = Field(default_factory=list)


class RegressionCase(BaseModel):
    """One pinned release and its curated canonical hypothesis."""

    case_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
    cve_id: str = Field(pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
    plugin_slug: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,199}$")
    version: str = Field(min_length=1)
    mode: RegressionMode
    hypothesis: Hypothesis
    expected: RegressionExpectation
    source_tree_sha256: str | None = Field(
        default=None,
        pattern=r"^[a-f0-9]{64}$",
        description="Optional digest of sorted relative paths and file bytes.",
    )
    notes: str = ""

    @model_validator(mode="after")
    def _validate_mode_contract(self) -> "RegressionCase":
        if (
            self.expected.attribution is not None
            and self.expected.attribution.hypothesis_id != self.hypothesis.id
        ):
            raise ValueError(
                "expected attribution hypothesis_id must match the seeded hypothesis"
            )
        if self.mode == "confirm":
            if not self.hypothesis.bug_class.is_known:
                raise ValueError("confirm cases require a supported automatic CWE")
            if self.expected.attribution is None:
                raise ValueError("confirm cases require expected.attribution")
            if not self.expected.attacker_role:
                raise ValueError("confirm cases require expected.attacker_role")
            if (
                normalize_attacker_role(self.expected.attacker_role)
                == UNKNOWN_ATTACKER_ROLE
            ):
                raise ValueError("confirm cases require a recognized attacker role")
            if not self.expected.allowed_oracles:
                raise ValueError("confirm cases require at least one allowed oracle")
            if not self.expected.minimum_impact.has_security_impact():
                raise ValueError("confirm cases require a non-zero minimum CIA impact")
            if self.expected.rejection_rules:
                raise ValueError("confirm cases cannot declare rejection rules")
        else:
            if not self.expected.rejection_rules:
                raise ValueError("policy_reject cases require rejection rules")
            if self.expected.allowed_oracles:
                raise ValueError("policy_reject cases cannot declare allowed oracles")
            if self.expected.minimum_impact.has_security_impact():
                raise ValueError("policy_reject cases cannot require a CIA impact")
        return self


class RegressionManifest(BaseModel):
    schema_version: Literal[1] = 1
    cases: list[RegressionCase] = Field(min_length=1)

    @model_validator(mode="after")
    def _unique_case_ids(self) -> "RegressionManifest":
        case_ids = [case.case_id for case in self.cases]
        duplicates = sorted(
            case_id for case_id in set(case_ids) if case_ids.count(case_id) > 1
        )
        if duplicates:
            raise ValueError(f"duplicate regression case IDs: {duplicates}")
        return self


class RegressionCaseResult(BaseModel):
    case_id: str
    cve_id: str
    plugin_slug: str
    version: str
    mode: RegressionMode
    run_id: str
    status: RegressionStatus
    cost_usd: float
    duration_seconds: float
    finding_count: int
    source_tree_sha256: str | None = None
    errors: list[str] = Field(default_factory=list)


class RegressionResult(BaseModel):
    manifest_path: str
    manifest_sha256: str
    config_path: str
    config_sha256: str
    budget_per_case_usd: float
    case_count: int
    passed_count: int
    failed_count: int
    total_cost_usd: float
    cases: list[RegressionCaseResult]
    result_path: str


def load_regression_manifest(path: str | Path) -> RegressionManifest:
    """Load and validate a versioned seeded-regression manifest."""

    return RegressionManifest.model_validate_json(Path(path).read_text())


def _sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _hash_source_tree(root: str | Path) -> str:
    """Hash source paths and bytes without depending on mtimes or file modes."""

    source_root = Path(root)
    digest = hashlib.sha256()
    paths = sorted(
        source_root.rglob("*"),
        key=lambda path: path.relative_to(source_root).as_posix(),
    )
    for path in paths:
        relative = path.relative_to(source_root).as_posix().encode("utf-8")
        if path.is_symlink():
            target = os.readlink(path).encode("utf-8")
            digest.update(b"L")
            digest.update(len(relative).to_bytes(8, "big"))
            digest.update(relative)
            digest.update(len(target).to_bytes(8, "big"))
            digest.update(target)
            continue
        if not path.is_file():
            continue
        digest.update(b"F")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(path.stat().st_size.to_bytes(8, "big"))
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def _successful_attempts(finding: Finding, phase: str) -> list[PoCAttempt]:
    return [
        attempt
        for attempt in finding.poc_attempts
        if attempt.phase == phase and attempt.result is PoCStatus.SUCCESS
    ]


def _assess_confirmed_findings(
    case: RegressionCase,
    findings: Sequence[Finding],
) -> list[str]:
    """Return exact baseline mismatches for a positive regression case."""

    errors: list[str] = []
    if len(findings) != 1:
        errors.append(f"expected exactly one finding, got {len(findings)}")
    matches = [
        finding for finding in findings if finding.hypothesis.id == case.hypothesis.id
    ]
    if len(matches) != 1:
        errors.append(
            f"expected exactly one finding for hypothesis {case.hypothesis.id!r}, "
            f"got {len(matches)}"
        )
        return errors

    finding = matches[0]
    attribution = case.expected.attribution
    if attribution is None:
        errors.append("confirm case has no expected final attribution")
        return errors
    actual_hypothesis = finding.hypothesis
    comparisons = {
        "hypothesis ID": (actual_hypothesis.id, attribution.hypothesis_id),
        "bug_class": (actual_hypothesis.bug_class, attribution.bug_class),
        "root_cause_cwe": (
            actual_hypothesis.root_cause_cwe,
            attribution.root_cause_cwe,
        ),
        "source file": (actual_hypothesis.file, attribution.file),
        "source line": (actual_hypothesis.line, attribution.line),
        "sink": (actual_hypothesis.sink, attribution.sink),
        "sink_code": (actual_hypothesis.sink_code, attribution.sink_code),
    }
    for label, (actual, expected) in comparisons.items():
        if actual != expected:
            errors.append(f"{label} mismatch: expected {expected!r}, got {actual!r}")

    if finding.poc_status is not PoCStatus.SUCCESS:
        errors.append(f"finding status is {finding.poc_status.value!r}, not 'success'")
    if finding.dedup_status is not DedupStatus.NOT_CHECKED:
        errors.append("dedup status changed; seeded regressions must not invoke feeds")
    if finding.confidence_runs < 2:
        errors.append("finding lacks both attack and clean-state confirmation runs")
    if finding.evidence.get("clean_state_restored") is not True:
        errors.append("finding does not attest clean-state restoration")

    attacks = _successful_attempts(finding, "attack")
    confirmations = _successful_attempts(finding, "confirmation")
    if not attacks:
        errors.append("no successful attack attempt was recorded")
    if not confirmations:
        errors.append("no successful confirmation attempt was recorded")
        return errors

    observation = confirmations[-1].observation
    confirmation = confirmations[-1]
    if not any(
        attack.iteration == confirmation.iteration
        and attack.script_path == confirmation.script_path
        for attack in attacks
    ):
        errors.append("clean confirmation does not match a successful attack script")
    if observation is None:
        errors.append("successful confirmation has no structured observation")
        return errors
    if observation.verdict != "vulnerable":
        errors.append(f"confirmation verdict is {observation.verdict!r}")
    if observation.oracle not in case.expected.allowed_oracles:
        errors.append(
            f"confirmation oracle {observation.oracle!r} is not in "
            f"{case.expected.allowed_oracles!r}"
        )

    expected_role = normalize_attacker_role(case.expected.attacker_role)
    actual_role = normalize_attacker_role(observation.attacker_role)
    if actual_role != expected_role:
        errors.append(
            f"attacker role mismatch: expected {expected_role!r}, got {actual_role!r}"
        )

    impact = finding.verified_impact or observation.impact
    for dimension in ("confidentiality", "integrity", "availability"):
        actual_level = getattr(impact, dimension)
        expected_level = getattr(case.expected.minimum_impact, dimension)
        if _IMPACT_RANK[actual_level] < _IMPACT_RANK[expected_level]:
            errors.append(
                f"{dimension} impact below baseline: expected at least "
                f"{expected_level!r}, got {actual_level!r}"
            )
    return errors


def _assess_policy_rejection(
    case: RegressionCase,
    grade: Grade,
    *,
    accepted_count: int,
    finding_count: int,
) -> list[str]:
    """Return mismatches for a deterministic no-sandbox policy regression."""

    errors: list[str] = []
    if grade.accepted:
        errors.append("quality gate accepted a policy-negative hypothesis")
    missing_rules = sorted(set(case.expected.rejection_rules) - set(grade.rules))
    if missing_rules:
        errors.append(f"quality gate omitted rejection rules: {missing_rules}")
    if accepted_count:
        errors.append(f"policy-negative triage retained {accepted_count} candidate(s)")
    if finding_count:
        errors.append(f"policy-negative case produced {finding_count} finding(s)")
    if case.expected.attacker_role:
        expected_role = normalize_attacker_role(case.expected.attacker_role)
        actual_role = infer_attacker_role(case.hypothesis)
        if actual_role != expected_role:
            errors.append(
                f"attacker role mismatch: expected {expected_role!r}, got {actual_role!r}"
            )
    attribution = case.expected.attribution
    if attribution is not None:
        hypothesis = case.hypothesis
        comparisons = {
            "hypothesis ID": (hypothesis.id, attribution.hypothesis_id),
            "bug_class": (hypothesis.bug_class, attribution.bug_class),
            "root_cause_cwe": (
                hypothesis.root_cause_cwe,
                attribution.root_cause_cwe,
            ),
            "source file": (hypothesis.file, attribution.file),
            "source line": (hypothesis.line, attribution.line),
            "sink": (hypothesis.sink, attribution.sink),
            "sink_code": (hypothesis.sink_code, attribution.sink_code),
        }
        for label, (actual, expected) in comparisons.items():
            if actual != expected:
                errors.append(
                    f"policy {label} mismatch: expected {expected!r}, got {actual!r}"
                )
    return errors


def _build_runtime(
    config: PipelineConfig,
    budget: BudgetTracker,
    run_dir: Path,
) -> tuple[DeveloperAgent, AgentRuntime]:
    developer = DeveloperAgent(
        model=config.models.developer,
        followup_model=config.models.developer_followup,
        budget_tracker=budget,
        llm_options=config.llm_options_for_role("developer"),
        followup_llm_options=config.llm_options_for_role("developer_followup"),
    )
    runtime = AgentRuntime(
        run_dir=str(run_dir),
        developer=developer,
        developer_calls_per_agent=config.developer_calls_per_agent,
        budget_tracker=budget,
        llm_options=config.llm.model_dump(exclude_none=True),
        role_reasoning=config.reasoning.model_dump(exclude_none=True),
    )
    return developer, runtime


async def _run_case(
    case: RegressionCase,
    *,
    config: PipelineConfig,
    budget_per_case_usd: float,
    plugins_root: str | Path,
) -> RegressionCaseResult:
    """Run one case with a fresh budget and isolated ignored artifact directory."""

    started = time.monotonic()
    run_id = f"regression-{case.case_id.lower()}-{uuid.uuid4().hex[:8]}"
    runs_root = Path(plugins_root) / case.plugin_slug / "runs"
    run_dir = runs_root / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    budget = BudgetTracker(ceiling_usd=budget_per_case_usd)
    errors: list[str] = []
    findings: list[Finding] = []
    actual_source_hash: str | None = None

    atomic_write_json(
        run_dir / "regression_case.json",
        case.model_dump(mode="json"),
    )
    atomic_write_jsonl(run_dir / "findings.jsonl", [])

    def result(status: RegressionStatus) -> RegressionCaseResult:
        return RegressionCaseResult(
            case_id=case.case_id,
            cve_id=case.cve_id,
            plugin_slug=case.plugin_slug,
            version=case.version,
            mode=case.mode,
            run_id=run_id,
            status=status,
            cost_usd=budget.spent,
            duration_seconds=time.monotonic() - started,
            finding_count=len(findings),
            source_tree_sha256=actual_source_hash,
            errors=errors,
        )

    try:
        budget.set_stage("intake")
        intake = await intake_stage.run(
            case.plugin_slug,
            run_id,
            config,
            runs_root=str(runs_root),
            version=case.version,
        )
        if intake.plugin_version != case.version:
            errors.append(
                f"intake version mismatch: expected {case.version!r}, "
                f"got {intake.plugin_version!r}"
            )
            return result("failed")

        actual_source_hash = _hash_source_tree(intake.source_path)
        if (
            case.source_tree_sha256 is not None
            and actual_source_hash != case.source_tree_sha256
        ):
            errors.append(
                "source tree digest mismatch: expected "
                f"{case.source_tree_sha256}, got {actual_source_hash}"
            )
            return result("failed")

        hypothesis = case.hypothesis.model_copy(deep=True)
        atomic_write_jsonl(run_dir / "hypotheses.jsonl", [hypothesis])

        if case.mode == "policy_reject":
            citation_error = validate_exact_sink_anchor(
                Path(intake.source_path),
                hypothesis.file,
                hypothesis.line,
                hypothesis.sink_code,
            )
            if citation_error:
                errors.append(f"source anchor is invalid: {citation_error}")
                return result("failed")

            grade = grade_hypothesis(hypothesis)
            triaged = apply_quality_gate(
                TriagedArtifact(
                    plugin_slug=case.plugin_slug,
                    accepted=[hypothesis],
                    rejected=[],
                    merged=[],
                    submission_scope_enforced=False,
                ),
                artifact_path=run_dir / "quality_gate_triage.json",
            )
            triaged.to_json_file(str(run_dir / "triaged.json"))
            atomic_write_jsonl(run_dir / "triaged.jsonl", triaged.accepted)
            errors.extend(
                _assess_policy_rejection(
                    case,
                    grade,
                    accepted_count=len(triaged.accepted),
                    finding_count=0,
                )
            )
            return result("failed" if errors else "passed")

        developer, runtime = _build_runtime(config, budget, run_dir)
        budget.set_stage("hypothesis_verifier")
        verifier = HypothesisVerifier(
            runtime,
            model=config.models.hypothesis_verifier,
        )
        verdict = await verifier.verify(hypothesis, intake.source_path)
        atomic_write_json(
            run_dir / "hypothesis_verifier.json",
            {
                "hypothesis": hypothesis.model_dump(mode="json"),
                "verdict": verdict.model_dump(mode="json"),
            },
        )
        if verdict.verdict != "keep":
            errors.append(f"source verifier dropped hypothesis: {verdict.reason}")
            return result("failed")

        # The verifier may normalize a nearby source line. Preserve its exact
        # output for triage, while assessment still compares against the manifest.
        hypotheses = HypothesesArtifact(
            plugin_slug=case.plugin_slug,
            hypotheses=[hypothesis],
        )
        atomic_write_jsonl(run_dir / "hypotheses.jsonl", [hypothesis])

        budget.set_stage("triage")
        triaged = await triage_stage.run(
            hypotheses,
            intake.source_path,
            config,
            budget,
            runtime,
            runs_root=str(runs_root),
            run_id=run_id,
            enforce_submission_scope=False,
        )
        if len(triaged.accepted) != 1:
            errors.append(
                f"technical triage retained {len(triaged.accepted)} candidate(s), "
                "expected one"
            )
            return result("failed")

        budget.set_stage("verify")
        findings = await verify_stage.run(
            triaged,
            intake.source_path,
            config,
            budget,
            runtime,
            runs_root=str(runs_root),
            run_id=run_id,
            developer=developer,
        )
        errors.extend(_assess_confirmed_findings(case, findings))
        return result("failed" if errors else "passed")
    except Exception as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
        return result("error")
    finally:
        budget.write_cost_report(run_dir)


def _select_cases(
    manifest: RegressionManifest,
    case_ids: Sequence[str] | None,
) -> list[RegressionCase]:
    if not case_ids:
        return list(manifest.cases)
    requested = list(dict.fromkeys(case_ids))
    available = {case.case_id for case in manifest.cases}
    unknown = sorted(set(requested) - available)
    if unknown:
        raise ValueError(f"unknown regression case IDs: {unknown}")
    requested_set = set(requested)
    return [case for case in manifest.cases if case.case_id in requested_set]


async def run_regressions(
    manifest_path: str,
    *,
    config_path: str,
    budget_per_case_usd: float,
    case_ids: Sequence[str] | None = None,
    plugins_root: str | Path = "plugins",
    results_root: str | Path = "benchmarks/results",
) -> RegressionResult:
    """Run selected cases sequentially with a fresh ceiling for every case."""

    if budget_per_case_usd <= 0:
        raise ValueError("per-case budget must be greater than zero")
    manifest = load_regression_manifest(manifest_path)
    selected = _select_cases(manifest, case_ids)
    config = PipelineConfig.from_yaml(config_path)
    await init_cache()

    case_results: list[RegressionCaseResult] = []
    for case in selected:
        # Deliberately sequential: verification may own one Docker sandbox.
        case_results.append(
            await _run_case(
                case,
                config=config,
                budget_per_case_usd=budget_per_case_usd,
                plugins_root=plugins_root,
            )
        )

    output_root = Path(results_root)
    output_root.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_path = output_root / f"regression-{timestamp}-{uuid.uuid4().hex[:8]}.json"
    failed_count = sum(case.status != "passed" for case in case_results)
    suite_result = RegressionResult(
        manifest_path=str(manifest_path),
        manifest_sha256=_sha256_file(manifest_path),
        config_path=str(config_path),
        config_sha256=_sha256_file(config_path),
        budget_per_case_usd=budget_per_case_usd,
        case_count=len(case_results),
        passed_count=len(case_results) - failed_count,
        failed_count=failed_count,
        total_cost_usd=sum(case.cost_usd for case in case_results),
        cases=case_results,
        result_path=str(output_path),
    )
    atomic_write_json(output_path, suite_result.model_dump(mode="json"))
    return suite_result
