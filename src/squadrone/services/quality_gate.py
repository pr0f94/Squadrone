"""Deterministic source/evidence quality checks and post-PoC CVSS scoring."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..schemas.finding import Finding
from ..schemas.hypothesis import BugClass, Confidence, Hypothesis, TriagedArtifact
from ..schemas.taxonomy import get_known_cwe_profile
from .artifacts import atomic_write_json
from .roles import UNKNOWN_ATTACKER_ROLE, normalize_attacker_role


UNSAFE_CONFIGURATION_RE = re.compile(
    r"\b(misconfig(?:uration)?|modified source|premium[- ]gated|debug mode|"
    r"admin(?:istrator)? must (?:disable|bypass|weaken|grant|install)|"
    r"(?:disable|bypass|weaken)(?:d|s|ing)? (?:authentication|authorization|security|validation|nonce|capability)|"
    r"custom (?:filter|code|bypass))\b",
    re.IGNORECASE,
)
FEATURE_CONFIGURATION_RE = re.compile(
    r"\b(admin(?:istrator)? must enable|must be enabled|disabled by default|"
    r"only if configured|non-default|(?:feature|api|integration|module|option).{0,40}(?:enabled|configured))\b",
    re.IGNORECASE,
)
COSMETIC_RE = re.compile(
    r"\b(cosmetic|dismiss notice|hide notice|ui state|preference|layout only|view count|vote count|cache clear)\b",
    re.IGNORECASE,
)
SOURCE_RE = re.compile(
    r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)|REST|AJAX|shortcode|form|upload|webhook",
    re.IGNORECASE,
)
BOUNDARY_RE = re.compile(
    r"\b(another user's|cross-user|higher[- ]priv|privilege|private|protected|sensitive|ownership|authorization|payment|approval|paid|token|secret|admin browser|internal service|filesystem|file system|uploads? (?:directory|tree))\b",
    re.IGNORECASE,
)
PROOF_GAP_RE = re.compile(
    r"\b(unknown|unclear|unproven|needs manual|maybe|possibly|appears to|entire path|whether .* reachable)\b",
    re.IGNORECASE,
)
CONFIDENTIALITY_RE = re.compile(
    r"\b(read|disclos|expos|leak|extract|secret|private|sensitive|credential|token|database)\b",
    re.IGNORECASE,
)
INTEGRITY_RE = re.compile(
    r"\b(change|modify|write|upload|delete|create|execut(?:e|ion)|bypass|takeover|escalat|approve|publish|overwrite|tamper)\b",
    re.IGNORECASE,
)
AVAILABILITY_RE = re.compile(
    r"\b(outage|denial|unavailable|crash|exhaust|delete all|site down)\b", re.IGNORECASE
)


@dataclass
class Grade:
    accepted: bool
    reason: str
    evidence: dict[str, Any]
    severity: dict[str, Any]
    warnings: list[str]
    rules: list[str]


def _text(hypothesis: Hypothesis) -> str:
    return " ".join(
        str(value or "")
        for value in (
            hypothesis.entry_point,
            hypothesis.sink,
            hypothesis.sink_code,
            hypothesis.reasoning,
            hypothesis.preconditions,
            " ".join(hypothesis.taint_path),
            hypothesis.security_outcome.description,
        )
    )


def infer_attacker_role(hypothesis: Hypothesis) -> str:
    supplied = str((hypothesis.evidence_summary or {}).get("attacker_role") or "")
    if supplied:
        return normalize_attacker_role(supplied)
    inferred = normalize_attacker_role(_text(hypothesis))
    if inferred != UNKNOWN_ATTACKER_ROLE:
        return inferred
    if "nopriv" in hypothesis.entry_point.lower():
        return "unauthenticated"
    return UNKNOWN_ATTACKER_ROLE


def _impact_dimensions(hypothesis: Hypothesis, description: str) -> dict[str, str]:
    dimensions: dict[str, str] = {
        "confidentiality": hypothesis.security_outcome.confidentiality,
        "integrity": hypothesis.security_outcome.integrity,
        "availability": hypothesis.security_outcome.availability,
    }
    if all(value == "none" for value in dimensions.values()) and description:
        if CONFIDENTIALITY_RE.search(description):
            dimensions["confidentiality"] = "low"
        if INTEGRITY_RE.search(description):
            dimensions["integrity"] = "low"
        if AVAILABILITY_RE.search(description):
            dimensions["availability"] = "low"
    return dimensions


def infer_evidence(hypothesis: Hypothesis) -> dict[str, Any]:
    supplied = dict(hypothesis.evidence_summary or {})
    taint = [str(value) for value in hypothesis.taint_path]
    source = str(supplied.get("source") or (taint[0] if taint else ""))
    control = str(supplied.get("control") or supplied.get("guard") or "")
    path = str(
        supplied.get("reachable_path") or supplied.get("path") or " -> ".join(taint)
    )
    boundary = str(supplied.get("boundary") or supplied.get("security_boundary") or "")
    impact = str(
        hypothesis.security_outcome.description
        or supplied.get("impact")
        or supplied.get("impact_statement")
        or ""
    )
    proof_gaps = supplied.get("proof_gaps") or supplied.get("proof_gap") or ""
    dimensions = _impact_dimensions(hypothesis, impact)
    return {
        "attacker_role": infer_attacker_role(hypothesis),
        "entry_point": hypothesis.entry_point,
        "source": source,
        "control": control,
        "sink": hypothesis.sink,
        "reachable_path": path,
        "boundary": boundary,
        "counterevidence": supplied.get("counterevidence")
        or supplied.get("counter_evidence")
        or "",
        "proof_gaps": proof_gaps,
        "impact": impact,
        "impact_dimensions": dimensions,
        "file": hypothesis.file,
        "line": hypothesis.line,
        "has_source_indicator": bool(source and (SOURCE_RE.search(source) or taint)),
        "has_reachable_path": bool(path and len(path.split("->")) >= 2),
        "has_security_boundary": bool(
            boundary and BOUNDARY_RE.search(boundary + " " + impact)
        ),
        "has_impact_statement": bool(
            impact and any(value != "none" for value in dimensions.values())
        ),
        "has_broad_proof_gap": bool(PROOF_GAP_RE.search(str(proof_gaps))),
        "bounty_programs": list(hypothesis.bounty_programs),
    }


def owasp_2021_for(bug_class: BugClass) -> str:
    profile = get_known_cwe_profile(bug_class)
    return profile.owasp_2021 if profile is not None else "Unmapped"


def recompute_severity(
    hypothesis: Hypothesis, evidence: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Pre-verification priority metadata; deliberately not a guessed CVSS score."""
    evidence = evidence or infer_evidence(hypothesis)
    dimensions = evidence["impact_dimensions"]
    levels = [
        dimensions[key] for key in ("confidentiality", "integrity", "availability")
    ]
    priority = (
        "high" if "high" in levels else "medium" if "low" in levels else "unknown"
    )
    return {
        "cvss_estimate": None,
        "cvss_vector": None,
        "rating": "unscored",
        "priority": priority,
        "owasp_2021": owasp_2021_for(hypothesis.bug_class),
        "attacker_role": evidence["attacker_role"],
        "impact_dimensions": dimensions,
    }


def grade_hypothesis(
    hypothesis: Hypothesis,
) -> Grade:
    evidence = infer_evidence(hypothesis)
    severity = recompute_severity(hypothesis, evidence)
    warnings: list[str] = []
    rules: list[str] = []
    text = _text(hypothesis)

    if (
        not hypothesis.file
        or hypothesis.line <= 0
        or not hypothesis.sink
        or not hypothesis.sink_code.strip()
    ):
        rules.append("missing_code_location_or_sink")
    if not evidence["has_source_indicator"]:
        rules.append("source_parameter_not_explicit")
    if not evidence["has_reachable_path"]:
        rules.append("reachable_path_not_explicit")
    if not evidence["has_security_boundary"]:
        rules.append("missing_security_boundary")
    if not evidence["has_impact_statement"]:
        rules.append("missing_concrete_cia_impact")
    supplied_evidence = hypothesis.evidence_summary or {}
    if not hypothesis.preconditions.strip() and not (
        str(supplied_evidence.get("attacker_role") or "").strip()
        and str(supplied_evidence.get("proof_gaps") or "").strip()
    ):
        rules.append("missing_preconditions")
    if evidence["has_broad_proof_gap"]:
        warnings.append("broad_or_vague_proof_gap")

    if UNSAFE_CONFIGURATION_RE.search(text):
        rules.append("configuration_dependent")
    if COSMETIC_RE.search(text):
        rules.append("cosmetic_or_no_security_impact")
    if hypothesis.bug_class == BugClass.MISSING_NONCE and not any(
        value == "high" for value in evidence["impact_dimensions"].values()
    ):
        rules.append("csrf_without_high_impact_outcome")
    if hypothesis.bug_class == BugClass.SSRF:
        impact = evidence["impact"].lower()
        if not re.search(
            r"internal|metadata|credential|secret|private|protected|write|change|delete|admin",
            impact,
        ):
            rules.append("ssrf_without_cia_impact")

    accepted = not rules
    reason = (
        "passes source and impact gate"
        if accepted
        else "quality_gate: " + ", ".join(dict.fromkeys(rules))
    )
    return Grade(
        accepted, reason, evidence, severity, warnings, list(dict.fromkeys(rules))
    )


def annotate_hypothesis(hypothesis: Hypothesis, grade: Grade) -> Hypothesis:
    hypothesis.evidence_summary = grade.evidence
    hypothesis.derived_severity = grade.severity
    hypothesis.quality_gate = {
        "accepted": grade.accepted,
        "reason": grade.reason,
        "warnings": grade.warnings,
        "rules": grade.rules,
    }
    return hypothesis


def rank_hypothesis(hypothesis: Hypothesis) -> tuple[int, int, int, int, int, str]:
    """Rank verified source candidates before applying the sandbox budget cap."""
    evidence = infer_evidence(hypothesis)
    role_rank = {
        "unauthenticated": 0,
        "subscriber": 1,
        "customer": 1,
        "low-priv": 1,
        "low_priv": 1,
        "contributor": 2,
        "author": 3,
        "unknown": 4,
        "editor": 5,
        "shop_manager": 5,
        "administrator": 6,
    }.get(evidence["attacker_role"], 4)
    dimensions = evidence["impact_dimensions"]
    impact_rank = (
        0 if "high" in dimensions.values() else 1 if "low" in dimensions.values() else 2
    )
    impact_count_rank = -sum(value != "none" for value in dimensions.values())
    confidence_rank = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}[
        hypothesis.confidence
    ]
    text = _text(hypothesis)
    precondition_rank = (
        1
        if (
            FEATURE_CONFIGURATION_RE.search(text)
            or UNSAFE_CONFIGURATION_RE.search(text)
        )
        else 0
    )
    return (
        role_rank,
        impact_rank,
        impact_count_rank,
        precondition_rank,
        confidence_rank,
        hypothesis.id,
    )


def apply_quality_gate(
    triaged: TriagedArtifact,
    *,
    artifact_path: Path | None = None,
) -> TriagedArtifact:
    accepted: list[Hypothesis] = []
    rejected = list(triaged.rejected)
    decisions: list[dict[str, Any]] = []
    for hypothesis in triaged.accepted:
        grade = grade_hypothesis(hypothesis)
        annotate_hypothesis(hypothesis, grade)
        decisions.append(
            {
                "hypothesis_id": hypothesis.id,
                "accepted": grade.accepted,
                "disposition": "accepted" if grade.accepted else "rejected",
                "reason": grade.reason,
                "evidence": grade.evidence,
                "severity": grade.severity,
                "warnings": grade.warnings,
                "rules": grade.rules,
            }
        )
        if grade.accepted:
            accepted.append(hypothesis)
        else:
            rejected.append(
                {
                    "hypothesis_id": hypothesis.id,
                    "reason": grade.reason,
                    "evidence": grade.evidence,
                    "derived_severity": grade.severity,
                }
            )
    triaged.accepted = accepted
    triaged.rejected = rejected
    if artifact_path is not None:
        atomic_write_json(artifact_path, decisions)
    return triaged


def _round_up_1(value: float) -> float:
    return math.ceil((value - 1e-10) * 10.0) / 10.0


def _cvss31_score(vector: dict[str, str]) -> float:
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[vector["AV"]]
    ac = {"L": 0.77, "H": 0.44}[vector["AC"]]
    scope_changed = vector["S"] == "C"
    pr = {
        False: {"N": 0.85, "L": 0.62, "H": 0.27},
        True: {"N": 0.85, "L": 0.68, "H": 0.50},
    }[scope_changed][vector["PR"]]
    ui = {"N": 0.85, "R": 0.62}[vector["UI"]]
    impact_weight = {"N": 0.0, "L": 0.22, "H": 0.56}
    c = impact_weight[vector["C"]]
    i = impact_weight[vector["I"]]
    a = impact_weight[vector["A"]]
    isc = 1 - ((1 - c) * (1 - i) * (1 - a))
    if isc <= 0:
        return 0.0
    if scope_changed:
        impact = 7.52 * (isc - 0.029) - 3.25 * ((isc - 0.02) ** 15)
    else:
        impact = 6.42 * isc
    exploitability = 8.22 * av * ac * pr * ui
    base = min(10.0, impact + exploitability)
    if scope_changed:
        base = min(10.0, 1.08 * base)
    return _round_up_1(base)


def _confirmed_observation(finding: Finding) -> dict[str, Any] | None:
    evidence = finding.evidence or {}
    confirmation = evidence.get("confirmation_run")
    if isinstance(confirmation, dict) and isinstance(
        confirmation.get("observation"), dict
    ):
        return confirmation["observation"]
    return None


def severity_from_finding(finding: Finding) -> dict[str, Any]:
    observation = _confirmed_observation(finding)
    if observation is None:
        return {
            "cvss_estimate": None,
            "cvss_vector": None,
            "rating": "unscored",
            "owasp_2021": owasp_2021_for(finding.hypothesis.bug_class),
        }
    role = normalize_attacker_role(observation.get("attacker_role"))
    privilege = (
        "N"
        if role == "unauthenticated"
        else "H"
        if role
        in {
            "author",
            "editor",
            "shop_manager",
            "administrator",
        }
        else "H"
        if role == UNKNOWN_ATTACKER_ROLE
        else "L"
    )
    bug_class = finding.hypothesis.bug_class
    user_interaction = (
        "R"
        if bug_class
        in {
            BugClass.XSS_REFLECTED,
            BugClass.XSS_STORED,
            BugClass.MISSING_NONCE,
        }
        else "N"
    )
    scope = "C" if bug_class in {BugClass.XSS_REFLECTED, BugClass.XSS_STORED} else "U"
    impact = observation.get("impact") or {}
    level = {"none": "N", "low": "L", "high": "H"}
    metrics = {
        "AV": "N",
        "AC": "L",
        "PR": privilege,
        "UI": user_interaction,
        "S": scope,
        "C": level.get(str(impact.get("confidentiality") or "none"), "N"),
        "I": level.get(str(impact.get("integrity") or "none"), "N"),
        "A": level.get(str(impact.get("availability") or "none"), "N"),
    }
    vector = "CVSS:3.1/" + "/".join(f"{key}:{value}" for key, value in metrics.items())
    score = _cvss31_score(metrics)
    rating = (
        "critical"
        if score >= 9.0
        else "high"
        if score >= 7.0
        else "medium"
        if score >= 4.0
        else "low"
    )
    return {
        "cvss_estimate": score,
        "cvss_vector": vector,
        "rating": rating,
        "owasp_2021": owasp_2021_for(bug_class),
        "attacker_role": role,
        "impact_dimensions": impact,
    }


def grade_finding_for_report(
    finding: Finding,
) -> Grade:
    grade = grade_hypothesis(finding.hypothesis)
    grade.severity = severity_from_finding(finding)
    if finding.poc_status.value != "success":
        grade.rules.append("poc_not_confirmed")
    if not finding.evidence.get("clean_state_restored"):
        grade.rules.append("clean_confirmation_missing")
    if _confirmed_observation(finding) is None:
        grade.rules.append("structured_poc_evidence_missing")
    grade.rules = list(dict.fromkeys(grade.rules))
    grade.accepted = not grade.rules
    grade.reason = (
        "passes confirmed evidence gate"
        if grade.accepted
        else "quality_gate: " + ", ".join(grade.rules)
    )
    return grade
