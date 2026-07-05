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


def test_quality_gate_rejects_missing_security_boundary():
    h = _hypothesis(
        id="h-boundary",
        reasoning="Unauthenticated user can read a public style asset.",
        sink="readfile",
        sink_code="readfile($asset)",
        taint_path=["$_GET['asset']", "readfile"],
    )

    grade = grade_hypothesis(h)

    assert grade.accepted is False
    assert "missing_security_boundary" in grade.rules


def test_preverification_gate_warns_missing_impact_instead_of_rejecting():
    h = _hypothesis(
        id="h-preverify",
        bug_class=BugClass.IDOR,
        reasoning="Subscriber reaches a suspicious object read path but runtime result needs probing.",
        sink="get_post_meta",
        sink_code="get_post_meta($_GET['id'], '_field', true)",
        taint_path=["$_GET['id']", "get_post_meta"],
        evidence_summary={
            "source": "$_GET['id']",
            "control": "missing ownership check",
            "sink": "get_post_meta",
            "reachable_path": "wp_ajax_demo -> get_post_meta",
        },
    )

    grade = grade_hypothesis(h, pre_verification=True)

    assert grade.accepted is True
    assert "missing_concrete_impact_preverify" in grade.warnings
    assert "missing_concrete_impact" not in grade.rules


def test_quality_gate_accepts_explicit_proof_tuple():
    h = _hypothesis(
        evidence_summary={
            "attacker_role": "subscriber",
            "source": "$_GET['id']",
            "control": "missing current_user_can('edit_post', $id)",
            "sink": "get_post_meta($id, '_secret', true)",
            "reachable_path": "wp_ajax_demo -> demo() -> get_post_meta()",
            "boundary": "subscriber reads another user's sensitive submission",
            "impact": "subscriber can read private submission metadata",
            "counterevidence": "nonce is present but only proves intent, not ownership",
            "proof_gaps": "none",
        }
    )

    grade = grade_hypothesis(h)

    assert grade.accepted is True
    assert grade.evidence["has_security_boundary"] is True
    assert grade.evidence["has_impact_statement"] is True


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


def test_apply_quality_gate_routes_borderline_to_manual_review():
    borderline = _hypothesis(
        id="h-5",
        bug_class=BugClass.WEAK_CRYPTO,
        entry_point="custom_magic_link_handler",
        reasoning="Weak crypto appears to protect a magic link token, but impact needs manual confirmation.",
        preconditions="authenticated user",
    )
    artifact = TriagedArtifact(plugin_slug="demo", accepted=[borderline], rejected=[], merged=[])

    gated = apply_quality_gate(artifact)

    assert gated.accepted == []
    assert gated.rejected == []
    assert gated.manual_review[0]["hypothesis_id"] == "h-5"
    assert gated.manual_review[0]["source"] == "quality_gate"


def test_recompute_severity_maps_owasp():
    severity = recompute_severity(_hypothesis(bug_class=BugClass.SQLI))
    assert severity["owasp_2021"] == "A03:2021-Injection"
    assert severity["rating"] in {"high", "critical"}
