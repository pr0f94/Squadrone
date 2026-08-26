from __future__ import annotations

from dataclasses import replace

from squadrone.schemas import BugClass, Confidence, Hypothesis, SecurityOutcome
from squadrone.schemas.taxonomy import known_cwe_profile
from squadrone.services import scope as scope_service
from squadrone.services.scope import preverification_programs


def _hypothesis(**overrides) -> Hypothesis:
    data = {
        "id": "h-1",
        "specialist": "injection_files",
        "bug_class": BugClass.SQLI,
        "entry_point": "wp_ajax_nopriv_query",
        "file": "plugin.php",
        "line": 20,
        "sink": "$wpdb->get_results",
        "sink_code": "$wpdb->get_results('SELECT ' . $_GET['id'])",
        "taint_path": ["$_GET['id']", "$wpdb->get_results"],
        "reasoning": "Unauthenticated SQL injection can extract private database data.",
        "confidence": Confidence.HIGH,
        "preconditions": "unauthenticated",
        "affected_versions": "<=1.0",
        "security_outcome": SecurityOutcome(
            confidentiality="high",
            description="Unauthenticated extraction of private database data.",
        ),
        "evidence_summary": {"attacker_role": "unauthenticated"},
    }
    data.update(overrides)
    return Hypothesis(**data)


def test_low_privilege_sqli_routes_to_both_programs():
    programs, reasons = preverification_programs(_hypothesis())

    assert programs == ["wordfence", "patchstack"]
    assert reasons == {}


def test_descriptive_unauthenticated_role_routes_like_canonical_role():
    programs, reasons = preverification_programs(
        _hypothesis(
            evidence_summary={"attacker_role": "unauthenticated_remote_attacker"}
        )
    )

    assert programs == ["wordfence", "patchstack"]
    assert reasons == {}


def test_descriptive_subscriber_role_is_not_incorrectly_deferred():
    programs, _ = preverification_programs(
        _hypothesis(
            bug_class=BugClass.MISSING_CAP_CHECK,
            evidence_summary={
                "attacker_role": "subscriber;_wp_ajax_mk_file_folder_manager_accepts_every_authenticated_role."
            },
        )
    )

    assert "patchstack" in programs


def test_unrecognized_authenticated_role_text_fails_closed():
    programs, reasons = preverification_programs(
        _hypothesis(evidence_summary={"attacker_role": "authenticated user"})
    )

    assert programs == []
    assert "requires role unknown" in reasons["wordfence"]
    assert "requires role unknown" in reasons["patchstack"]


def test_author_role_is_deferred_from_standard_programs():
    programs, reasons = preverification_programs(
        _hypothesis(
            preconditions="author",
            evidence_summary={"attacker_role": "author"},
        )
    )

    assert programs == []
    assert "requires role author" in reasons["wordfence"]
    assert "requires role author" in reasons["patchstack"]


def test_idor_with_significant_secret_routes_only_to_patchstack():
    programs, _ = preverification_programs(
        _hypothesis(
            bug_class=BugClass.IDOR,
            security_outcome=SecurityOutcome(
                confidentiality="high",
                description="Disclosure of password hashes from another user's backup.",
            ),
        )
    )

    assert programs == ["patchstack"]


def test_ticket_idor_is_not_routed_to_patchstack():
    programs, reasons = preverification_programs(
        _hypothesis(
            bug_class=BugClass.IDOR,
            security_outcome=SecurityOutcome(
                confidentiality="low",
                description="Read another user's support ticket.",
            ),
        )
    )

    assert programs == []
    assert "does not meet" in reasons["patchstack"]


def test_missing_authorization_with_arbitrary_options_impact_routes_wordfence():
    programs, _ = preverification_programs(
        _hypothesis(
            bug_class=BugClass.MISSING_CAP_CHECK,
            specialist="authorization_workflows",
            security_outcome=SecurityOutcome(
                integrity="high",
                description="Unauthenticated arbitrary options update enables user registration as Administrator.",
            ),
        )
    )

    assert "wordfence" in programs
    assert "patchstack" in programs


def test_missing_authentication_requires_qualifying_wordfence_outcome():
    programs, _ = preverification_programs(
        _hypothesis(
            bug_class=BugClass.MISSING_AUTH_CRITICAL_FUNCTION,
            security_outcome=SecurityOutcome(
                integrity="high",
                description="Unauthenticated arbitrary options update enables account takeover.",
            ),
        )
    )

    assert programs == ["wordfence", "patchstack"]


def test_missing_authentication_does_not_bypass_wordfence_outcome_filter():
    programs, reasons = preverification_programs(
        _hypothesis(
            bug_class=BugClass.MISSING_AUTH_CRITICAL_FUNCTION,
            reasoning="The route lacks authentication before a low-impact rename operation.",
            security_outcome=SecurityOutcome(
                integrity="low",
                description="Unauthenticated renaming of files in a plugin-managed volume.",
            ),
        )
    )

    assert programs == ["patchstack"]
    assert "qualifying security outcome" in reasons["wordfence"]


def test_unmapped_cwe_has_no_automatic_program_route():
    programs, reasons = preverification_programs(
        _hypothesis(
            bug_class=BugClass("CWE-1234"),
        )
    )

    assert programs == []
    assert "no declared automatic" in reasons["wordfence"]
    assert "no declared automatic" in reasons["patchstack"]


def test_unknown_scope_policy_values_fail_closed(monkeypatch):
    invalid_profile = replace(
        known_cwe_profile(BugClass.SQLI),
        wordfence_policy="diret",  # type: ignore[arg-type]
        patchstack_policy="diret",  # type: ignore[arg-type]
    )
    monkeypatch.setattr(
        scope_service,
        "get_known_cwe_profile",
        lambda _bug_class: invalid_profile,
    )

    programs, reasons = preverification_programs(_hypothesis())

    assert programs == []
    assert "unsupported Wordfence" in reasons["wordfence"]
    assert "unsupported Patchstack" in reasons["patchstack"]
