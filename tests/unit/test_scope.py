from __future__ import annotations

from dataclasses import replace

from squadrone.schemas import (
    BugClass,
    Confidence,
    DedupStatus,
    Finding,
    Hypothesis,
    PoCStatus,
    SecurityOutcome,
)
from squadrone.schemas.taxonomy import known_cwe_profile
from squadrone.services import scope as scope_service
from squadrone.services.scope import preverification_programs, verified_programs


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


def test_significant_idor_is_not_excluded_by_minor_object_substrings():
    for collision in ("prevents", "eventual", "disorder", "disappointment"):
        programs, _ = preverification_programs(
            _hypothesis(
                bug_class=BugClass.IDOR,
                reasoning=(
                    f"The route {collision} one unrelated condition while "
                    "disclosing protected reusable-block content."
                ),
                security_outcome=SecurityOutcome(
                    confidentiality="high",
                    description="Disclosure of protected reusable-block content.",
                ),
            )
        )

        assert programs == ["patchstack"]


def test_minor_object_terms_and_identifiers_remain_excluded():
    for object_reference in (
        "attachments",
        "ticket_id",
        "event_id",
        "order-id",
        "appointments",
        "PII alone",
    ):
        programs, _ = preverification_programs(
            _hypothesis(
                bug_class=BugClass.IDOR,
                security_outcome=SecurityOutcome(
                    confidentiality="high",
                    description=f"Disclosure of another user's {object_reference}.",
                ),
            )
        )

        assert programs == []


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


def test_minor_cache_maintenance_is_not_routed_to_patchstack():
    for operation in (
        "clears cache",
        "invalidates plugin caches",
        "reset_filters_cache",
        "deletes generated cache files",
    ):
        programs, reasons = preverification_programs(
            _hypothesis(
                bug_class=BugClass.MISSING_AUTH_CRITICAL_FUNCTION,
                reasoning=f"An unauthenticated request {operation}.",
                security_outcome=SecurityOutcome(
                    integrity="low",
                    availability="low",
                    description=f"The request {operation} and forces regeneration.",
                ),
            )
        )

        assert programs == []
        assert "cache clearing or invalidation" in reasons["patchstack"]


def test_high_impact_cache_operations_remain_routed_to_patchstack():
    for impact_dimension in ("confidentiality", "integrity", "availability"):
        dimensions = {impact_dimension: "high"}
        programs, _ = preverification_programs(
            _hypothesis(
                bug_class=BugClass.MISSING_AUTH_CRITICAL_FUNCTION,
                reasoning="An unauthenticated request clears a security cache.",
                security_outcome=SecurityOutcome(
                    **dimensions,
                    description="Clearing the cache has a demonstrated High impact.",
                ),
            )
        )

        assert "patchstack" in programs


def test_structured_false_gadget_evidence_overrides_negative_keywords():
    programs, reasons = preverification_programs(
        _hypothesis(
            bug_class=BugClass.PHP_OBJECT_INJECTION,
            reasoning=(
                "No natural gadget, code execution, file write, or file delete "
                "effect is established."
            ),
            evidence_summary={
                "attacker_role": "unauthenticated",
                "usable_gadget": False,
            },
        )
    )

    assert programs == ["patchstack"]
    assert "qualifying security outcome" in reasons["wordfence"]


def test_structured_true_gadget_evidence_routes_wordfence():
    programs, reasons = preverification_programs(
        _hypothesis(
            bug_class=BugClass.PHP_OBJECT_INJECTION,
            reasoning="Untrusted bytes reach unrestricted deserialization.",
            evidence_summary={
                "attacker_role": "unauthenticated",
                "usable_gadget": True,
            },
        )
    )

    assert programs == ["wordfence", "patchstack"]
    assert reasons == {}


def test_legacy_positive_gadget_wording_keeps_existing_routing():
    programs, reasons = preverification_programs(
        _hypothesis(
            bug_class=BugClass.PHP_OBJECT_INJECTION,
            reasoning="A reachable shipped gadget deletes a constrained file.",
            evidence_summary={"attacker_role": "unauthenticated"},
        )
    )

    assert programs == ["wordfence", "patchstack"]
    assert reasons == {}


def test_invalid_structured_gadget_evidence_fails_closed():
    programs, reasons = preverification_programs(
        _hypothesis(
            bug_class=BugClass.PHP_OBJECT_INJECTION,
            reasoning="A reachable shipped gadget deletes a constrained file.",
            evidence_summary={
                "attacker_role": "unauthenticated",
                "usable_gadget": "true",
            },
        )
    )

    assert programs == ["patchstack"]
    assert "qualifying security outcome" in reasons["wordfence"]


def test_verified_cwe502_routing_requires_full_natural_direct_path_proof():
    hypothesis = _hypothesis(
        bug_class=BugClass.PHP_OBJECT_INJECTION,
        reasoning="A reachable shipped gadget deletes a constrained file.",
        evidence_summary={
            "attacker_role": "unauthenticated",
            "usable_gadget": True,
        },
    )
    finding = Finding(
        id="f-502-primitive-only",
        hypothesis=hypothesis,
        poc_status=PoCStatus.SUCCESS,
        poc_script_path="poc.py",
        poc_attempts=[],
        evidence={
            "clean_state_restored": True,
            "confirmation_run": {
                "observation": {
                    "schema_version": 1,
                    "verdict": "vulnerable",
                    "oracle": "object_instantiation",
                    "attacker_role": "unauthenticated",
                    "request": {},
                    "attack": {},
                    "control": {},
                    "impact": {
                        "confidentiality": "none",
                        "integrity": "low",
                        "availability": "none",
                        "description": "Inert object instantiation only.",
                    },
                }
            },
        },
        confidence_runs=2,
        dedup_status=DedupStatus.NOVEL,
        dedup_matches=[],
    )

    programs, reasons = verified_programs(finding)

    assert programs == []
    assert "natural direct-path proof" in reasons["wordfence"]
    assert "natural direct-path proof" in reasons["patchstack"]


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
