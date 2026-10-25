from __future__ import annotations

import pytest

from squadrone.services.roles import (
    UNKNOWN_ATTACKER_ROLE,
    extract_attacker_roles,
    normalize_attacker_role,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("unauthenticated", "unauthenticated"),
        ("anonymous", "unauthenticated"),
        ("guest", "unauthenticated"),
        ("unauthenticated_remote_attacker", "unauthenticated"),
        (
            "subscriber;_wp_ajax_mk_file_folder_manager_accepts_every_authenticated_role.",
            "subscriber",
        ),
        ("authenticated Subscriber account", "subscriber"),
        ("shop_customer", "customer"),
        ("low-privileged user", "low_priv"),
        ("contributor", "contributor"),
        ("Contributor (edit_posts on own draft)", "contributor"),
        ("author", "author"),
        ("editor", "editor"),
        ("shop_manager", "shop_manager"),
        ("administrator", "administrator"),
        ("admin", "administrator"),
        ("manage_options", "administrator"),
        ("subscriber payload viewed by an administrator", "subscriber"),
    ],
)
def test_normalize_attacker_role_recognizes_canonical_and_descriptive_roles(
    value: str,
    expected: str,
) -> None:
    assert normalize_attacker_role(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        None,
        "authenticated user",
        "logged-in WordPress account",
        "admin-ajax endpoint",
        "role was not established",
        "not a Subscriber",
        "Unauthenticated requests are rejected",
        "The victim is an Administrator",
        "An Administrator previews the Subscriber payload",
        "Only the victim has a Subscriber account",
        "The administrator enables the shipped feature",
        "The source does not establish whether a Contributor is the caller",
        "attacker is Subscriber or Editor",
        "Contributor (Editor role required)",
        "Editor (acting as Contributor)",
        "unknown (Contributor victim)",
        "There is no evidence the attacker is Subscriber",
        "It is unknown whether the caller is Contributor",
        "It is not true that attacker is Editor",
        "The attacker can author post content in the editor",
    ],
)
def test_normalize_attacker_role_fails_closed_for_unknown_text(value: object) -> None:
    assert normalize_attacker_role(value) == UNKNOWN_ATTACKER_ROLE


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (
            "Subscriber attacker; the Administrator victim opens the payload",
            {"subscriber"},
        ),
        ("Attacker is not a Contributor but an Editor", {"editor"}),
        ("Attacker is Contributor or Author", {"contributor", "author"}),
        ("An Author or Editor can submit content", {"author", "editor"}),
        ("A Contributor who can edit their own post", {"contributor"}),
        (
            "Shipped default configuration. Lowest role: Contributor saving its "
            "own draft and previewing that draft, or Author publishing its own "
            "post; an Editor with unfiltered_html can submit content directly.",
            {"contributor", "author", "editor"},
        ),
        (
            "Default shipped configuration. Attacker can author post content "
            "containing raw block markup (an Editor with unfiltered_html on a "
            "default single-site install) and the post is publicly rendered; "
            "REST/admin renders are suppressed.",
            {"editor"},
        ),
        (
            "Attacker is any authenticated user who can edit a post "
            "(Contributor/Author on their own post, up to Editor).",
            {"contributor", "author", "editor"},
        ),
        (
            "The administrator enables the shipped feature; no caller role is known",
            set(),
        ),
        ("The victim Administrator views a Subscriber's payload", set()),
    ],
)
def test_extract_attacker_roles_attributes_positive_prerequisites_only(
    value: str, expected: set[str]
) -> None:
    assert extract_attacker_roles(value) == frozenset(expected)
