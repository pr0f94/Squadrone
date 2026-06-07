from __future__ import annotations

from squadrone.schemas import BugClass, Confidence, Hypothesis, TriagedArtifact
from squadrone.services.quality_gate import apply_quality_gate, grade_hypothesis, recompute_severity


def _hypothesis(**overrides) -> Hypothesis:
    data = {
        "id": "h-1",
        "specialist": "auth",
        "bug_class": BugClass.IDOR,
        "entry_point": "wp_ajax_nopriv_demo",
        "file": "demo.php",
        "line": 10,
        "sink": "get_post_meta",
        "sink_code": "get_post_meta($_GET['id'], '_secret', true)",
        "taint_path": ["$_GET['id']", "get_post_meta"],
        "reasoning": "Unauthenticated user can read sensitive metadata from another user's object.",
        "confidence": Confidence.HIGH,
        "preconditions": "unauthenticated attacker",
        "affected_versions": "<=1.0",
        "bounty_programs": ["wordfence", "patchstack"],
    }
    data.update(overrides)
    return Hypothesis(**data)


def test_quality_gate_accepts_low_priv_sensitive_access():
    grade = grade_hypothesis(_hypothesis())
    assert grade.accepted is True
    assert grade.evidence["attacker_role"] == "unauthenticated"
    assert grade.severity["cvss_estimate"] >= 6.5


def test_quality_gate_rejects_admin_only_non_high_impact():
    h = _hypothesis(
        id="h-2",
        bug_class=BugClass.XSS_STORED,
        entry_point="admin settings page",
        reasoning="Administrator can store JavaScript in their own plugin settings.",
        preconditions="administrator only",
    )
    grade = grade_hypothesis(h)
    assert grade.accepted is False
    assert "trusted_role_or_admin_only" in grade.rules


def test_quality_gate_rejects_missing_nonce_without_impact():
    h = _hypothesis(
        id="h-3",
        bug_class=BugClass.MISSING_NONCE,
        reasoning="The endpoint is missing a nonce and updates a dismiss notice flag.",
        preconditions="subscriber",
    )
    grade = grade_hypothesis(h)
    assert grade.accepted is False
    assert "csrf_without_meaningful_impact" in grade.rules


def test_apply_quality_gate_moves_rejections():
    accepted = _hypothesis()
    rejected = _hypothesis(
        id="h-4",
        bug_class=BugClass.OPEN_REDIRECT,
        reasoning="Unauthenticated open redirect.",
        preconditions="unauthenticated",
    )
    artifact = TriagedArtifact(plugin_slug="demo", accepted=[accepted, rejected], rejected=[], merged=[])
    gated = apply_quality_gate(artifact)
    assert [h.id for h in gated.accepted] == ["h-1"]
    assert gated.rejected[0]["hypothesis_id"] == "h-4"


def test_recompute_severity_maps_owasp():
    severity = recompute_severity(_hypothesis(bug_class=BugClass.SQLI))
    assert severity["owasp_2021"] == "A03:2021-Injection"
    assert severity["rating"] in {"high", "critical"}
