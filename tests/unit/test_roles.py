from __future__ import annotations

import pytest

from squadrone.services.roles import UNKNOWN_ATTACKER_ROLE, normalize_attacker_role


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
    ],
)
def test_normalize_attacker_role_fails_closed_for_unknown_text(value: object) -> None:
    assert normalize_attacker_role(value) == UNKNOWN_ATTACKER_ROLE
