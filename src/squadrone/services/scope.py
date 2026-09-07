"""Current Wordfence/Patchstack disclosure routing, separate from validity."""

from __future__ import annotations

import re
from typing import Any

from ..schemas.finding import Finding
from ..schemas.hypothesis import BugClass, Hypothesis
from ..schemas.taxonomy import (
    PATCHSTACK_POLICIES,
    WORDFENCE_POLICIES,
    get_known_cwe_profile,
)
from .quality_gate import (
    infer_attacker_role,
    severity_from_finding,
    validate_php_object_natural_finding_confirmation,
)
from .roles import STANDARD_PROGRAM_ATTACKER_ROLES, normalize_attacker_role


_QUALIFYING_AUTHZ_OUTCOME = re.compile(
    r"arbitrary[ _-](?:options?|file|content)|privilege|account[ _-]takeover|"
    r"authentication[ _-]bypass|remote[ _-]code|sql[ _-]injection|"
    r"sensitive[ _-](?:file|secret|backup|database)",
    re.IGNORECASE,
)


def _impact_text(hypothesis: Hypothesis) -> str:
    return " ".join(
        (
            hypothesis.vulnerability_type,
            hypothesis.security_outcome.description,
            str((hypothesis.evidence_summary or {}).get("impact") or ""),
            hypothesis.reasoning,
        )
    )


def _has_usable_gadget(hypothesis: Hypothesis, impact: str) -> bool:
    """Prefer structured gadget evidence while retaining legacy artifacts."""
    evidence = hypothesis.evidence_summary or {}
    if "usable_gadget" in evidence:
        return evidence["usable_gadget"] is True
    return (
        re.search(r"gadget|code execution|file (?:write|delete)", impact, re.I)
        is not None
    )


def preverification_programs(
    hypothesis: Hypothesis,
) -> tuple[list[str], dict[str, str]]:
    """Route source-valid candidates without inventing a pre-PoC CVSS score."""
    role = normalize_attacker_role(infer_attacker_role(hypothesis))
    impact = _impact_text(hypothesis)
    profile = get_known_cwe_profile(hypothesis.bug_class)
    programs: list[str] = []
    reasons: dict[str, str] = {}

    if role not in STANDARD_PROGRAM_ATTACKER_ROLES:
        reasons["wordfence"] = (
            f"requires role {role}; current scope accepts only unauthenticated/Subscriber/Customer"
        )
        reasons["patchstack"] = (
            f"requires role {role}; standard program accepts only unauthenticated/Subscriber/Customer"
        )
        return programs, reasons

    if profile is None:
        reasons["wordfence"] = "CWE has no declared automatic Wordfence routing policy"
        reasons["patchstack"] = (
            "CWE has no declared automatic Patchstack routing policy"
        )
        return programs, reasons

    wordfence_policy = profile.wordfence_policy
    wordfence_ok = wordfence_policy in WORDFENCE_POLICIES - {"none"}
    if wordfence_policy not in WORDFENCE_POLICIES:
        reasons["wordfence"] = (
            f"unsupported Wordfence routing policy {wordfence_policy!r}"
        )
    elif wordfence_policy == "usable_gadget" and not _has_usable_gadget(
        hypothesis, impact
    ):
        wordfence_ok = False
    elif wordfence_policy == "qualifying_authorization":
        wordfence_ok = bool(_QUALIFYING_AUTHZ_OUTCOME.search(impact))
    if wordfence_ok:
        programs.append("wordfence")
    else:
        reasons.setdefault(
            "wordfence",
            "vulnerability type is currently excluded or lacks a qualifying security outcome",
        )

    patchstack_policy = profile.patchstack_policy
    patchstack_ok = patchstack_policy in PATCHSTACK_POLICIES - {"none"}
    if patchstack_policy not in PATCHSTACK_POLICIES:
        reasons["patchstack"] = (
            f"unsupported Patchstack routing policy {patchstack_policy!r}"
        )
    elif patchstack_policy == "concrete_ssrf" and not re.search(
        r"internal|metadata|secret|credential|protected|write|change", impact, re.I
    ):
        patchstack_ok = False
    elif patchstack_policy == "significant_object" and re.search(
        r"attachment|ticket|event|order|appointment|pii alone", impact, re.I
    ):
        patchstack_ok = False
    elif (
        patchstack_policy == "qualifying_csrf"
        and not _QUALIFYING_AUTHZ_OUTCOME.search(impact)
    ):
        patchstack_ok = False
    if patchstack_ok:
        programs.append("patchstack")
    else:
        reasons.setdefault(
            "patchstack",
            "vulnerability type or demonstrated outcome does not meet the standard program conditions",
        )
    return programs, reasons


def _observation(finding: Finding) -> dict[str, Any]:
    if finding.hypothesis.bug_class == BugClass.PHP_OBJECT_INJECTION:
        accepted, _reason = validate_php_object_natural_finding_confirmation(finding)
        if not accepted:
            return {}
    confirmation = (finding.evidence or {}).get("confirmation_run") or {}
    observation = (
        confirmation.get("observation") if isinstance(confirmation, dict) else None
    )
    return observation if isinstance(observation, dict) else {}


def verified_programs(finding: Finding) -> tuple[list[str], dict[str, str]]:
    """Re-route after clean PoC confirmation and CVSS calculation."""
    programs, reasons = preverification_programs(finding.hypothesis)
    if finding.hypothesis.bug_class == BugClass.PHP_OBJECT_INJECTION:
        accepted, reason = validate_php_object_natural_finding_confirmation(finding)
        if not accepted:
            detail = f"full CWE-502 routing requires natural direct-path proof: {reason}"
            reasons["wordfence"] = detail
            reasons["patchstack"] = detail
            return [], reasons
    observation = _observation(finding)
    severity = severity_from_finding(finding)
    score = severity.get("cvss_estimate")
    impact = observation.get("impact") or {}
    low_count = sum(
        impact.get(key) == "low"
        for key in ("confidentiality", "integrity", "availability")
    )
    high_count = sum(
        impact.get(key) == "high"
        for key in ("confidentiality", "integrity", "availability")
    )
    role = normalize_attacker_role(
        observation.get("attacker_role") or infer_attacker_role(finding.hypothesis)
    )

    if "wordfence" in programs and isinstance(score, int | float) and score < 4.0:
        programs.remove("wordfence")
        reasons["wordfence"] = (
            f"confirmed CVSS {score} is below 4.0 without a higher-impact outcome"
        )

    if "patchstack" in programs:
        if role in {"subscriber", "customer"} and high_count == 0 and low_count >= 1:
            programs.remove("patchstack")
            reasons["patchstack"] = (
                "authenticated finding has only minor Low CIA impact"
            )
        elif role == "unauthenticated" and high_count == 0 and low_count == 1:
            programs.remove("patchstack")
            reasons["patchstack"] = (
                "unauthenticated finding has only one Low CIA impact"
            )
        elif finding.hypothesis.bug_class == BugClass.XSS_STORED:
            text = _impact_text(finding.hypothesis).lower()
            if not re.search(
                r"site[- ]wide|entire site|all administrators|any administrator", text
            ):
                programs.remove("patchstack")
                reasons["patchstack"] = "stored XSS was not demonstrated as site-wide"

    return programs, reasons
