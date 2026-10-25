"""Shared reminders must preserve provenance and uncertainty across agents."""

from squadrone.agents.prompts_io import load_prompt


def test_surveyor_does_not_promote_inventory_flags_into_path_proof():
    prompt = " ".join(load_prompt("surveyor").split())
    for reminder in (
        "hook callback is not itself a public HTTP route",
        "not proof that the check protects every mutation",
        "settings label describing intended users is not an allowlist",
        "same exact option/meta key, scope, and object identity",
    ):
        assert reminder in prompt


def test_shared_rules_bind_one_actor_and_exact_inspected_version():
    prompt = " ".join(load_prompt("specialists/_shared_rules").split())
    assert "one actor/configuration contract" in prompt
    assert "unavailable developer consultation is not agreement" in prompt
    assert "exact supplied `plugin_version`" in prompt
    assert 'does not establish "and earlier"' in prompt


def test_developer_core_contracts_are_qualified_and_sourced():
    prompt = " ".join(load_prompt("developer").split())
    assert "`false`, `null` or `WP_Error` deny permission" in prompt
    assert "DISALLOW_UNFILTERED_HTML" in prompt
    assert "non-super-admins on multisite" in prompt
    assert "cannot inspect missing files or run WordPress" in prompt
    assert "does not by itself prove" in prompt
    for source in ("populate_roles_160/", "map_meta_cap/", "kses_init/", "respond_to_request/"):
        assert "https://developer.wordpress.org/reference/" in prompt
        assert source in prompt
