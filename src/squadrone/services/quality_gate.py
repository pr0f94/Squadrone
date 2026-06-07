"""Deterministic quality gates for submit-worthy WordPress findings.

These checks intentionally cover boring false-positive classes before they reach
manual review or report generation. They complement, rather than replace, the
LLM critic and live sandbox verification.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..schemas.finding import Finding
from ..schemas.hypothesis import BugClass, Hypothesis, TriagedArtifact


TRUSTED_ROLE_RE = re.compile(
    r"\b(administrator|admin|editor|shop manager|manage_options|unfiltered_html)\b",
    re.IGNORECASE,
)
LOW_ROLE_RE = re.compile(
    r"\b(unauthenticated|anonymous|guest|subscriber|contributor|author|customer|shop_customer|low[- ]priv)\b",
    re.IGNORECASE,
)
CONFIG_REQUIRED_RE = re.compile(
    r"\b(misconfig|misconfiguration|configuration[- ]dependent|admin must|administrator must|site owner must|only if configured|non-default)\b",
    re.IGNORECASE,
)
SELF_ONLY_RE = re.compile(
    r"\b(self[- ]xss|own post|own content|own profile|own settings|their own|his own|her own|attacker's own|user's own)\b",
    re.IGNORECASE,
)
COSMETIC_RE = re.compile(
    r"\b(cosmetic|image quality|quality setting|dismiss notice|hide notice|ui state|preference|layout only)\b",
    re.IGNORECASE,
)
IMPACT_RE = re.compile(
    r"\b(admin account|privilege escalation|account takeover|rce|remote code|file delete|arbitrary file|stored xss|delete|modify other|sensitive|payment|subscription|order|webhook|ssrf|sql injection|data exfil)\b",
    re.IGNORECASE,
)
SOURCE_RE = re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)|REST|AJAX|shortcode|form|upload", re.IGNORECASE)
GUARD_RE = re.compile(r"current_user_can|wp_verify_nonce|check_ajax_referer|check_admin_referer|permission_callback", re.IGNORECASE)


HIGH_IMPACT_CLASSES = {
    BugClass.COMMAND_INJECTION,
    BugClass.ARBITRARY_FILE_WRITE,
    BugClass.AUTH_BYPASS,
    BugClass.SQLI,
    BugClass.PHP_OBJECT_INJECTION,
}

MEDIUM_IMPACT_CLASSES = {
    BugClass.XSS_STORED,
    BugClass.IDOR,
    BugClass.PATH_TRAVERSAL,
    BugClass.SSRF,
    BugClass.MASS_ASSIGNMENT,
    BugClass.LOGIC_FLAW,
}


@dataclass
class Grade:
    accepted: bool
    reason: str
    evidence: dict[str, Any]
    severity: dict[str, Any]
    warnings: list[str]
    rules: list[str]


def _text(h: Hypothesis) -> str:
    return " ".join(
        str(x or "")
        for x in (
            h.entry_point,
            h.sink,
            h.sink_code,
            h.reasoning,
            h.preconditions,
            " ".join(h.taint_path),
            h.chain_impact or "",
        )
    )


def infer_attacker_role(h: Hypothesis) -> str:
    text = _text(h)
    low = LOW_ROLE_RE.search(text)
    if low:
        role = low.group(1).lower().replace(" ", "_")
        if role == "anonymous":
            return "unauthenticated"
        if role == "guest":
            return "unauthenticated"
        return role
    trusted = TRUSTED_ROLE_RE.search(text)
    if trusted:
        role = trusted.group(1).lower().replace(" ", "_")
        if role in {"admin", "manage_options"}:
            return "administrator"
        if role == "unfiltered_html":
            return "trusted_html_role"
        return role
    if "nopriv" in h.entry_point.lower():
        return "unauthenticated"
    if "wp_ajax_" in h.entry_point.lower():
        return "authenticated"
    return "unknown"


def infer_evidence(h: Hypothesis) -> dict[str, Any]:
    role = infer_attacker_role(h)
    taint = [str(x) for x in h.taint_path]
    text = _text(h)
    return {
        "attacker_role": role,
        "entry_point": h.entry_point,
        "source": taint[0] if taint else "",
        "sink": h.sink,
        "file": h.file,
        "line": h.line,
        "has_source_indicator": bool(SOURCE_RE.search(text) or taint),
        "has_guard_discussion": bool(GUARD_RE.search(text)),
        "has_impact_statement": bool(IMPACT_RE.search(text) or h.chain_impact),
        "bounty_programs": list(h.bounty_programs),
    }


def recompute_severity(h: Hypothesis, evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    evidence = evidence or infer_evidence(h)
    role = str(evidence.get("attacker_role") or "unknown")
    text = _text(h)
    if h.bug_class in HIGH_IMPACT_CLASSES:
        base = 8.1
    elif h.bug_class in MEDIUM_IMPACT_CLASSES:
        base = 6.5
    elif h.bug_class == BugClass.XSS_REFLECTED:
        base = 6.1
    elif h.bug_class == BugClass.MISSING_NONCE:
        base = 5.4
    elif h.bug_class == BugClass.OPEN_REDIRECT:
        base = 4.3
    else:
        base = 5.3

    if role in {"unauthenticated", "subscriber", "contributor", "customer", "shop_customer", "low-priv", "low_priv"}:
        base += 0.4
    if role in {"administrator", "editor", "shop_manager", "trusted_html_role"}:
        base -= 2.5
    if CONFIG_REQUIRED_RE.search(text):
        base -= 1.5
    if SELF_ONLY_RE.search(text):
        base -= 2.0
    if COSMETIC_RE.search(text):
        base -= 2.0
    if h.chain_impact:
        base += 0.5

    score = max(0.0, min(10.0, round(base, 1)))
    if score >= 9.0:
        rating = "critical"
    elif score >= 7.0:
        rating = "high"
    elif score >= 4.0:
        rating = "medium"
    else:
        rating = "low"
    return {
        "cvss_estimate": score,
        "rating": rating,
        "owasp_2021": owasp_2021_for(h.bug_class),
        "attacker_role": role,
    }


def owasp_2021_for(bug_class: BugClass) -> str:
    mapping = {
        BugClass.MISSING_CAP_CHECK: "A01:2021-Broken Access Control",
        BugClass.MISSING_NONCE: "A01:2021-Broken Access Control",
        BugClass.IDOR: "A01:2021-Broken Access Control",
        BugClass.PATH_TRAVERSAL: "A01:2021-Broken Access Control",
        BugClass.ARBITRARY_FILE_WRITE: "A01:2021-Broken Access Control",
        BugClass.XSS_REFLECTED: "A03:2021-Injection",
        BugClass.XSS_STORED: "A03:2021-Injection",
        BugClass.SQLI: "A03:2021-Injection",
        BugClass.COMMAND_INJECTION: "A03:2021-Injection",
        BugClass.XXE: "A05:2021-Security Misconfiguration",
        BugClass.SSRF: "A10:2021-Server-Side Request Forgery",
        BugClass.PHP_OBJECT_INJECTION: "A08:2021-Software and Data Integrity Failures",
        BugClass.WEAK_CRYPTO: "A02:2021-Cryptographic Failures",
        BugClass.WEAK_PRNG: "A02:2021-Cryptographic Failures",
        BugClass.AUTH_BYPASS: "A07:2021-Identification and Authentication Failures",
        BugClass.WEAK_PASSWORD_RECOVERY: "A07:2021-Identification and Authentication Failures",
        BugClass.SESSION_FIXATION: "A07:2021-Identification and Authentication Failures",
        BugClass.MISSING_RATE_LIMIT: "A07:2021-Identification and Authentication Failures",
        BugClass.OPEN_REDIRECT: "A01:2021-Broken Access Control",
        BugClass.MASS_ASSIGNMENT: "A01:2021-Broken Access Control",
        BugClass.LOGIC_FLAW: "A04:2021-Insecure Design",
    }
    return mapping.get(bug_class, "A04:2021-Insecure Design")


def grade_hypothesis(
    h: Hypothesis,
    *,
    require_evidence_schema: bool = True,
    false_positive_rules: bool = True,
    recompute: bool = True,
    reject_below_submit_bar: bool = True,
) -> Grade:
    evidence = infer_evidence(h)
    severity = recompute_severity(h, evidence) if recompute else dict(h.derived_severity or {})
    if not severity:
        severity = {"cvss_estimate": None, "rating": "unknown", "owasp_2021": owasp_2021_for(h.bug_class)}
    warnings: list[str] = []
    rules: list[str] = []
    text = _text(h)

    if require_evidence_schema:
        if not h.file or h.line <= 0 or not h.sink:
            rules.append("missing_code_location_or_sink")
        if not evidence["has_source_indicator"]:
            warnings.append("source_parameter_not_explicit")
        if not evidence["has_impact_statement"]:
            warnings.append("impact_not_explicit")

    role = evidence["attacker_role"]
    if false_positive_rules:
        if TRUSTED_ROLE_RE.search(text) and role in {"administrator", "editor", "shop_manager", "trusted_html_role"}:
            if h.bug_class not in HIGH_IMPACT_CLASSES:
                rules.append("trusted_role_or_admin_only")
        if CONFIG_REQUIRED_RE.search(text):
            rules.append("configuration_dependent")
        if SELF_ONLY_RE.search(text):
            rules.append("self_or_own_resource_only")
        if COSMETIC_RE.search(text):
            rules.append("cosmetic_or_no_security_impact")
        if h.bug_class == BugClass.OPEN_REDIRECT:
            rules.append("open_redirect_low_value")
        if h.bug_class == BugClass.MISSING_NONCE and not IMPACT_RE.search(text):
            rules.append("csrf_without_meaningful_impact")
    score = severity.get("cvss_estimate")
    if reject_below_submit_bar and isinstance(score, int | float) and score < 6.5:
        rules.append("below_submit_bar")

    accepted = not rules
    reason = "passes quality gate"
    if not accepted:
        reason = "quality_gate: " + ", ".join(rules)
    return Grade(accepted, reason, evidence, severity, warnings, rules)


def annotate_hypothesis(h: Hypothesis, grade: Grade) -> Hypothesis:
    h.evidence_summary = grade.evidence
    h.derived_severity = grade.severity
    h.quality_gate = {
        "accepted": grade.accepted,
        "reason": grade.reason,
        "warnings": grade.warnings,
        "rules": grade.rules,
    }
    return h


def apply_quality_gate(
    triaged: TriagedArtifact,
    *,
    require_evidence_schema: bool = True,
    false_positive_rules: bool = True,
    recompute: bool = True,
    reject_below_submit_bar: bool = True,
    artifact_path: Path | None = None,
) -> TriagedArtifact:
    accepted: list[Hypothesis] = []
    decisions: list[dict[str, Any]] = []
    rejected = list(triaged.rejected)
    for h in triaged.accepted:
        grade = grade_hypothesis(
            h,
            require_evidence_schema=require_evidence_schema,
            false_positive_rules=false_positive_rules,
            recompute=recompute,
            reject_below_submit_bar=reject_below_submit_bar,
        )
        annotate_hypothesis(h, grade)
        decisions.append({
            "hypothesis_id": h.id,
            "accepted": grade.accepted,
            "reason": grade.reason,
            "evidence": grade.evidence,
            "severity": grade.severity,
            "warnings": grade.warnings,
            "rules": grade.rules,
        })
        if grade.accepted:
            accepted.append(h)
        else:
            rejected.append({
                "hypothesis_id": h.id,
                "reason": grade.reason,
                "evidence": grade.evidence,
                "derived_severity": grade.severity,
            })
    triaged.accepted = accepted
    triaged.rejected = rejected
    if artifact_path is not None:
        artifact_path.parent.mkdir(parents=True, exist_ok=True)
        artifact_path.write_text(json.dumps(decisions, indent=2))
    return triaged


def grade_finding_for_report(
    finding: Finding,
    *,
    require_evidence_schema: bool = True,
    false_positive_rules: bool = True,
    recompute: bool = True,
) -> Grade:
    grade = grade_hypothesis(
        finding.hypothesis,
        require_evidence_schema=require_evidence_schema,
        false_positive_rules=false_positive_rules,
        recompute=recompute,
        reject_below_submit_bar=True,
    )
    if finding.poc_status.value not in {"success", "partial"}:
        grade.accepted = False
        grade.rules.append("poc_not_confirmed")
        grade.reason = "quality_gate: poc_not_confirmed"
    if not finding.evidence:
        grade.accepted = False
        grade.rules.append("missing_poc_evidence")
        grade.reason = "quality_gate: " + ", ".join(grade.rules)
    return grade


def build_focus_area_summary(recon: Any) -> dict[str, list[str]]:
    focus: dict[str, list[str]] = {
        "ajax_rest_admin_post": [],
        "frontend_forms_shortcodes_blocks": [],
        "uploads_file_ops": [],
        "auth_capabilities_nonces": [],
        "sql_db_writes": [],
        "payments_webhooks_logic": [],
        "output_rendering_xss": [],
    }
    for ep in getattr(recon, "entry_points", []):
        label = f"{ep.name} ({ep.file}:{ep.line})"
        hay = " ".join(str(x or "") for x in (ep.type, ep.name, ep.handler_function, ep.file))
        if re.search(r"ajax|rest|admin_post", hay, re.IGNORECASE):
            focus["ajax_rest_admin_post"].append(label)
        if re.search(r"shortcode|block|widget|frontend|form", hay, re.IGNORECASE):
            focus["frontend_forms_shortcodes_blocks"].append(label)
        if getattr(ep, "has_capability_check", False) or getattr(ep, "has_nonce_check", False):
            focus["auth_capabilities_nonces"].append(label)
    for sink in getattr(recon, "sinks", []):
        label = f"{sink.function} ({sink.file}:{sink.line})"
        hay = " ".join(str(x or "") for x in (sink.type, sink.function, sink.file))
        if re.search(r"upload|file|unlink|readfile|include|require|zip", hay, re.IGNORECASE):
            focus["uploads_file_ops"].append(label)
        if re.search(r"sql|wpdb|db_|query|insert|update", hay, re.IGNORECASE):
            focus["sql_db_writes"].append(label)
        if re.search(r"payment|paypal|stripe|webhook|order|subscription|checkout", hay, re.IGNORECASE):
            focus["payments_webhooks_logic"].append(label)
        if re.search(r"echo|print|render|template|html|json|xss", hay, re.IGNORECASE):
            focus["output_rendering_xss"].append(label)
    return {k: sorted(set(v)) for k, v in focus.items() if v}


def render_focus_area_prompt(focus: dict[str, list[str]]) -> str:
    if not focus:
        return ""
    lines = ["Focus-area map from recon. Use this to avoid generic review and inspect the relevant routes/sinks:"]
    for area, items in sorted(focus.items()):
        lines.append(f"- {area}:")
        for item in items[:20]:
            lines.append(f"  - {item}")
    return "\n".join(lines)
