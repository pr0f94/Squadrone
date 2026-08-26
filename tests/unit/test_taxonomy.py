from __future__ import annotations

from dataclasses import FrozenInstanceError
from importlib.resources import files
import re
from typing import get_args

import pytest

from squadrone.agents.poc_author import _select_template
from squadrone.schemas import BugClass, OracleType
from squadrone.schemas.hypothesis import root_cause_cwe_for
from squadrone.schemas.taxonomy import (
    KNOWN_CWE_REGISTRY,
    PATCHSTACK_POLICIES,
    WORDFENCE_POLICIES,
    get_known_cwe_profile,
    known_cwe_profile,
)
from squadrone.services.coverage import _review_areas_for_surface
from squadrone.services.quality_gate import owasp_2021_for
from squadrone.services.sandbox import _ALLOWED_ORACLES


def test_every_declared_bug_class_has_one_registry_profile() -> None:
    assert set(KNOWN_CWE_REGISTRY) == set(BugClass)


def test_declared_bug_classes_do_not_collapse_into_enum_aliases() -> None:
    assert len(BugClass.__members__) == len(BugClass)


def test_exact_profile_taxonomy_and_review_ownership() -> None:
    expected = {
        BugClass.MISSING_CAP_CHECK: (
            "missing_authorization",
            "authorization_workflows",
            ("entry_point", "role_capability_write"),
        ),
        BugClass.MISSING_NONCE: (
            "cross_site_request_forgery",
            "authorization_workflows",
            ("entry_point",),
        ),
        BugClass.SQLI: (
            "sql_injection",
            "injection_files",
            ("sql_query", "sql_write"),
        ),
        BugClass.COMMAND_INJECTION: (
            "command_injection",
            "injection_files",
            ("command_execution",),
        ),
        BugClass.PATH_TRAVERSAL: (
            "path_traversal_or_file_access",
            "injection_files",
            ("dynamic_include", "file_read", "file_delete"),
        ),
        BugClass.ARBITRARY_FILE_WRITE: (
            "arbitrary_file_upload_or_write",
            "injection_files",
            ("file_upload", "file_write", "file_delete", "file_read"),
        ),
        BugClass.SSRF: (
            "server_side_request_forgery",
            "injection_files",
            ("external_http",),
        ),
        BugClass.XXE: (
            "xml_external_entity_injection",
            "injection_files",
            ("xml_parse",),
        ),
        BugClass.PHP_OBJECT_INJECTION: (
            "php_object_injection",
            "injection_files",
            ("deserialization",),
        ),
        BugClass.XSS_REFLECTED: (
            "reflected_cross_site_scripting",
            "xss_lifecycle",
            ("entry_point", "dom_html"),
        ),
        BugClass.XSS_STORED: (
            "stored_cross_site_scripting",
            "xss_lifecycle",
            ("entry_point", "sql_write", "option_write", "object_write", "dom_html"),
        ),
        BugClass.OPEN_REDIRECT: ("open_redirect", None, ()),
        BugClass.IDOR: (
            "insecure_direct_object_reference",
            "authorization_workflows",
            ("entry_point", "object_write"),
        ),
        BugClass.WEAK_CRYPTO: (
            "practical_cryptographic_bypass",
            "authentication",
            ("weak_crypto_primitive",),
        ),
        BugClass.WEAK_PRNG: (
            "predictable_security_token",
            "authentication",
            ("non_cryptographic_randomness",),
        ),
        BugClass.MASS_ASSIGNMENT: (
            "mass_assignment",
            "authorization_workflows",
            ("entry_point", "object_write", "option_write"),
        ),
        BugClass.AUTH_BYPASS: (
            "authentication_bypass",
            "authentication",
            ("authentication_state",),
        ),
        BugClass.MISSING_AUTH_CRITICAL_FUNCTION: (
            "missing_authentication_for_critical_function",
            "authorization_workflows",
            ("entry_point",),
        ),
        BugClass.WEAK_PASSWORD_RECOVERY: (
            "password_recovery_bypass",
            "authentication",
            ("authentication_state",),
        ),
        BugClass.SESSION_FIXATION: (
            "session_fixation",
            "authentication",
            ("authentication_state",),
        ),
        BugClass.MISSING_RATE_LIMIT: ("missing_rate_limit", None, ()),
        BugClass.RESOURCE_EXHAUSTION: ("resource_exhaustion", None, ()),
        BugClass.LOGIC_FLAW: (
            "security_workflow_bypass",
            "authorization_workflows",
            ("entry_point", "object_write", "option_write"),
        ),
    }

    assert set(expected) == set(KNOWN_CWE_REGISTRY)
    for bug_class, (vulnerability_type, reviewer, surfaces) in expected.items():
        profile = known_cwe_profile(bug_class)
        assert profile.root_cwe == bug_class.value.split(":", 1)[0]
        assert profile.vulnerability_type == vulnerability_type
        assert profile.reviewer == reviewer
        assert profile.deterministic_surfaces == surfaces


def test_registry_profiles_have_explicit_grouping_and_delivery_metadata() -> None:
    for bug_class, profile in KNOWN_CWE_REGISTRY.items():
        assert re.fullmatch(r"CWE-[1-9][0-9]*", profile.root_cwe), bug_class
        assert profile.family
        assert profile.vulnerability_type
        assert profile.owasp_2021.startswith("A"), bug_class
        assert profile.analysis_support in {
            "active",
            "partial",
            "review_only",
            "excluded",
            "unowned",
        }
        assert profile.delivery_support in {
            "automated",
            "conditional",
            "manual",
            "none",
        }
        assert profile.template_fit in {"exact", "generic", "narrow", "none"}


def test_registry_family_partition_is_explicit_and_disjoint() -> None:
    expected = {
        "authorization_workflow": {
            BugClass.MISSING_CAP_CHECK,
            BugClass.MISSING_NONCE,
            BugClass.IDOR,
            BugClass.MASS_ASSIGNMENT,
            BugClass.MISSING_AUTH_CRITICAL_FUNCTION,
            BugClass.LOGIC_FLAW,
        },
        "authentication": {
            BugClass.AUTH_BYPASS,
            BugClass.WEAK_PASSWORD_RECOVERY,
            BugClass.SESSION_FIXATION,
        },
        "command_code_injection": {BugClass.COMMAND_INJECTION},
        "cross_site_scripting": {BugClass.XSS_REFLECTED, BugClass.XSS_STORED},
        "cryptography_tokens": {BugClass.WEAK_CRYPTO, BugClass.WEAK_PRNG},
        "database_injection": {BugClass.SQLI},
        "file_access": {BugClass.PATH_TRAVERSAL, BugClass.ARBITRARY_FILE_WRITE},
        "intentionally_excluded": {BugClass.OPEN_REDIRECT, BugClass.MISSING_RATE_LIMIT},
        "resource_exhaustion": {BugClass.RESOURCE_EXHAUSTION},
        "server_side_parser": {BugClass.XXE, BugClass.PHP_OBJECT_INJECTION},
        "server_side_request": {BugClass.SSRF},
    }

    actual = {
        family: {
            bug_class
            for bug_class, profile in KNOWN_CWE_REGISTRY.items()
            if profile.family == family
        }
        for family in {profile.family for profile in KNOWN_CWE_REGISTRY.values()}
    }

    assert actual == expected
    assert set().union(*actual.values()) == set(BugClass)
    assert sum(len(group) for group in actual.values()) == len(BugClass)


def test_reviewable_classes_have_an_owner() -> None:
    for bug_class, profile in KNOWN_CWE_REGISTRY.items():
        if profile.analysis_support in {"active", "partial", "review_only"}:
            assert profile.reviewer in {
                "authorization_workflows",
                "authentication",
                "injection_files",
                "xss_lifecycle",
            }, bug_class


def test_every_reviewable_class_has_a_discovery_mechanism() -> None:
    for bug_class, profile in KNOWN_CWE_REGISTRY.items():
        if profile.analysis_support not in {"active", "partial", "review_only"}:
            continue
        assert profile.deterministic_surfaces or profile.alternative_discovery, (
            bug_class
        )


def test_every_declared_surface_routes_to_its_registry_owner() -> None:
    for bug_class, profile in KNOWN_CWE_REGISTRY.items():
        if profile.reviewer is None:
            continue
        for surface in profile.deterministic_surfaces:
            assert profile.reviewer in _review_areas_for_surface(surface), (
                bug_class,
                surface,
            )


def test_policy_oracle_and_template_vocabularies_are_valid() -> None:
    valid_oracles = set(get_args(OracleType))
    template_root = files("squadrone.poc_templates")

    for bug_class, profile in KNOWN_CWE_REGISTRY.items():
        assert profile.wordfence_policy in WORDFENCE_POLICIES, bug_class
        assert profile.patchstack_policy in PATCHSTACK_POLICIES, bug_class
        assert profile.allowed_oracles <= valid_oracles, bug_class
        if profile.poc_template is not None:
            assert (template_root / profile.poc_template).is_file(), bug_class


def test_automatic_delivery_declares_template_oracle_and_scope() -> None:
    for bug_class, profile in KNOWN_CWE_REGISTRY.items():
        if profile.delivery_support not in {"automated", "conditional"}:
            continue
        assert profile.poc_template is not None, bug_class
        assert profile.allowed_oracles, bug_class
        assert {
            profile.wordfence_policy,
            profile.patchstack_policy,
        } != {"none"}, bug_class


def test_excluded_or_unowned_classes_fail_closed() -> None:
    for bug_class, profile in KNOWN_CWE_REGISTRY.items():
        if profile.analysis_support not in {"excluded", "unowned"}:
            continue
        assert profile.reviewer is None, bug_class
        assert profile.poc_template is None, bug_class
        assert profile.allowed_oracles == frozenset(), bug_class
        assert profile.wordfence_policy == "none", bug_class
        assert profile.patchstack_policy == "none", bug_class
        assert profile.delivery_support == "none", bug_class
        assert profile.exclusion_reason, bug_class


def test_xss_variants_share_root_but_not_vulnerability_type() -> None:
    reflected = known_cwe_profile(BugClass.XSS_REFLECTED)
    stored = known_cwe_profile(BugClass.XSS_STORED)

    assert reflected.root_cwe == stored.root_cwe == "CWE-79"
    assert reflected.vulnerability_type != stored.vulnerability_type


def test_registry_is_immutable() -> None:
    with pytest.raises(TypeError):
        KNOWN_CWE_REGISTRY[BugClass.SQLI] = known_cwe_profile(BugClass.SQLI)  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        known_cwe_profile(BugClass.SQLI).family = "changed"  # type: ignore[misc]


@pytest.mark.parametrize("bug_class", list(BugClass))
def test_known_consumers_match_registry(bug_class: BugClass) -> None:
    profile = known_cwe_profile(bug_class)

    assert BugClass(bug_class.value) is bug_class
    assert root_cause_cwe_for(bug_class) == profile.root_cwe
    assert owasp_2021_for(bug_class) == profile.owasp_2021
    assert _select_template(bug_class.value) == profile.poc_template
    assert _ALLOWED_ORACLES.get(bug_class.name, set()) == set(profile.allowed_oracles)


def test_open_cwe_preserves_exact_id_without_declaring_support() -> None:
    unknown = BugClass("CWE-1234")

    assert unknown.value == "CWE-1234"
    assert unknown.name == "UNMAPPED_CWE_1234"
    assert unknown.is_known is False
    assert unknown.oracle_key == "CWE-1234"
    assert get_known_cwe_profile(unknown) is None
    assert unknown not in KNOWN_CWE_REGISTRY
    assert len(BugClass) == len(KNOWN_CWE_REGISTRY) == 23


@pytest.mark.parametrize(
    "value",
    [
        "CWE-0",
        "CWE-01",
        "CWE-",
        "CWE-12x",
        "CWE-123: label",
        "cwe-1234",
        "cwe-89",
        "not-a-cwe",
    ],
)
def test_open_cwe_rejects_noncanonical_values(value: str) -> None:
    with pytest.raises(ValueError):
        BugClass(value)
