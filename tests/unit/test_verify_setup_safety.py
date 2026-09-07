from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from squadrone.agents.developer import RequestedSetupPlan, SetupPlan
from squadrone.schemas.config import PipelineConfig
from squadrone.schemas.hypothesis import BugClass, Confidence, Hypothesis
from squadrone.services.sandbox import SandboxRunResult
from squadrone.stages import verify as verify_stage
from squadrone.stages.verify import (
    _build_setup_code_context,
    _managed_setup_state_drift,
    _required_attacker_account,
    _run_setup_commands,
    _run_setup_round_atomically,
    _setup_command_mutates_managed_context,
    _setup_command_plants_exploit_payload,
    _setup_result_taints_confirmation,
    _summarise_forbidden_setup,
    _summarise_setup_results,
    _summarise_setup_state,
)


def _hyp(cwe: BugClass) -> Hypothesis:
    return Hypothesis(
        id="h",
        specialist="test",
        bug_class=cwe,
        entry_point="wp_ajax_x",
        file="x.php",
        line=1,
        sink="sink",
        taint_path=[],
        reasoning="r",
        confidence=Confidence.HIGH,
        preconditions="subscriber",
        affected_versions="<=1.0",
    )


def test_blocks_direct_xss_seed():
    reason = _setup_command_plants_exploit_payload(
        ["eval", "global $wpdb; $wpdb->insert('x', ['v' => '<svg onload=alert(1)>']);"],
        _hyp(BugClass.XSS_STORED),
    )
    assert reason and "XSS" in reason


def test_blocks_direct_sqli_seed():
    reason = _setup_command_plants_exploit_payload(
        ["db", "query", "insert into x values ('1 UNION SELECT password')"],
        _hyp(BugClass.SQLI),
    )
    assert reason and "SQL injection" in reason


def test_allows_benign_prerequisite_seed():
    reason = _setup_command_plants_exploit_payload(
        ["eval", "global $wpdb; $wpdb->insert('x', ['title' => 'Normal record']);"],
        _hyp(BugClass.XSS_STORED),
    )
    assert reason is None


@pytest.mark.parametrize(
    "args",
    [
        ["eval", "update_option('demo', '<script>alert(1)</script>');"],
        [
            "eval",
            "file_put_contents('/tmp/demo.html', '<svg onload=alert(1)>');",
        ],
        ["post", "create", "--post_content=<img src=x onerror=alert(1)>"],
        [
            "eval",
            "call_user_func('update_user_meta', 7, 'demo', "
            "'<details ontoggle=alert(1)>');",
        ],
    ],
)
def test_blocks_xss_seed_through_raw_core_option_meta_post_and_file_writes(args):
    reason = _setup_command_plants_exploit_payload(
        args,
        _hyp(BugClass.XSS_STORED),
    )

    assert reason and "XSS payload" in reason


@pytest.mark.parametrize(
    "args",
    [
        ["option", "update", "demo_enabled", "1"],
        ["post", "create", "--post_title=Normal prerequisite"],
        ["post", "create", "--post_content=<img src=/normal-image.png>"],
        ["eval", "Plugin_Setup::install_defaults();"],
    ],
)
def test_allows_benign_raw_prerequisites_and_source_defined_setup_apis(args):
    reason = _setup_command_plants_exploit_payload(
        args,
        _hyp(BugClass.XSS_STORED),
    )

    assert reason is None


def test_allows_runtime_directory_creation_without_permission_mutation():
    reason = _setup_command_plants_exploit_payload(
        ["eval", "$dir = WP_PLUGIN_DIR . '/demo/files'; wp_mkdir_p($dir);"],
        _hyp(BugClass.ARBITRARY_FILE_WRITE),
    )
    assert reason is None


@pytest.mark.parametrize(
    ("args", "reason_fragment"),
    [
        (["--user=1", "plugin", "deactivate", "demo-plugin"], "plugin lifecycle"),
        (["plugin", "--quiet", "activate", "demo-plugin"], "plugin lifecycle"),
        (["plugin", "install", "demo-plugin"], "plugin lifecycle"),
        (["plugin", "update", "demo-plugin"], "plugin lifecycle"),
        (["eval", "activate_plugin('demo-plugin/demo-plugin.php');"], "lifecycle API"),
        (
            ["eval", "deactivate_plugins('demo-plugin/demo-plugin.php');"],
            "lifecycle API",
        ),
        (["--user=admin@example.test", "option", "get", "siteurl"], "WordPress user"),
        (["--user", "1", "option", "get", "siteurl"], "WordPress user"),
        (
            ["eval", "wp_set_current_user(1); update_option('demo', 1);"],
            "wp_set_current_user",
        ),
    ],
)
def test_blocks_managed_identity_and_plugin_lifecycle_mutations(args, reason_fragment):
    reason = _setup_command_mutates_managed_context(args)

    assert reason and reason_fragment in reason


@pytest.mark.parametrize(
    "args",
    [
        ["option", "add", "home", "http://127.0.0.1:80"],
        ["option", "update", "siteurl", "http://127.0.0.1:80"],
        ["option", "delete", "home"],
        ["option", "patch", "update", "siteurl", "host", "localhost"],
        ["config", "set", "WP_HOME", "http://127.0.0.1:80", "--raw"],
        ["config", "delete", "WP_SITEURL"],
        ["eval", "update_option('home', 'http://127.0.0.1:80');"],
        ["eval", "delete_option(\"siteurl\");"],
        [
            "eval",
            "call_user_func('update_option', 'siteurl', 'http://127.0.0.1:80');",
        ],
        ["eval", "WP_CLI::runcommand('option update home http://127.0.0.1:80');"],
        ["eval", "WP_CLI::runcommand('config set WP_HOME http://127.0.0.1:80');"],
        ["eval", "WP_CLI::runcommand(\"config delete WP_SITEURL\");"],
        [
            "eval",
            "file_put_contents(ABSPATH . 'wp-config.php', $replacement);",
        ],
        ["eval", "unlink(ABSPATH . '/wp-config.php');"],
        [
            "eval",
            "global $wpdb; $wpdb->update($wpdb->options, "
            "['option_value' => 'http://127.0.0.1:80'], "
            "['option_name' => 'home']);",
        ],
        [
            "db",
            "query",
            "UPDATE wp_options SET option_value='http://127.0.0.1:80' "
            "WHERE option_name='siteurl'",
        ],
    ],
)
def test_blocks_canonical_wordpress_url_mutations(args):
    reason = _setup_command_mutates_managed_context(args)

    assert reason and "home/siteurl" in reason


@pytest.mark.parametrize(
    "args",
    [
        ["option", "get", "home"],
        ["option", "get", "siteurl"],
        ["option", "update", "homepage_enabled", "1"],
        ["option", "update", "demo_siteurl", "https://example.test"],
        ["eval", "$url = home_url('/'); update_option('demo_url', $url);"],
        ["eval", "$url = get_option('siteurl'); WP_CLI::log($url);"],
        ["eval", "$plugin->update_option('home', 'landing');"],
        ["eval", "Plugin_Settings::delete_option('siteurl');"],
        ["site", "option", "update", "home", "network-value"],
        ["eval", "WP_CLI::runcommand('site option update home network-value');"],
        ["eval", "$config = file_get_contents(ABSPATH . '/wp-config.php');"],
    ],
)
def test_allows_canonical_url_reads_and_unrelated_option_writes(args):
    assert _setup_command_mutates_managed_context(args) is None


@pytest.mark.parametrize(
    "args",
    [
        ["user", "set-role", "subscriber_user", "administrator"],
        ["user", "add-cap", "subscriber_user", "manage_options"],
        ["user", "update", "subscriber_user", "--role=administrator"],
        [
            "eval",
            "$user = get_user_by('login', 'subscriber_user'); "
            "$user->set_role('administrator');",
        ],
        ["eval", "wp_set_password('changed', 7);"],
        [
            "eval",
            "call_user_func('wp_update_user', ['ID' => 7, 'user_pass' => 'changed']);",
        ],
        [
            "eval",
            "$update = 'wp_update_user'; "
            "$update(['ID' => 7, 'user_pass' => 'changed']);",
        ],
        [
            "user",
            "application-password",
            "create",
            "subscriber_user",
            "setup credential",
        ],
        [
            "user",
            "--quiet",
            "application-password",
            "--porcelain",
            "delete",
            "subscriber_user",
            "credential-uuid",
        ],
        [
            "eval",
            "WP_CLI::runcommand('user application-password update "
            "subscriber_user credential-uuid --name=changed');",
        ],
        [
            "eval",
            "WP_Application_Passwords::create_new_application_password(7, "
            "['name' => 'setup credential']);",
        ],
        [
            "eval",
            "call_user_func(['WP_Application_Passwords', "
            "'delete_application_password'], 7, 'credential-uuid');",
        ],
        [
            "eval",
            "$method = 'update_application_password'; "
            "WP_Application_Passwords::$method(7, 'credential-uuid', []);",
        ],
        [
            "eval",
            "update_user_meta(7, '_application_passwords', []);",
        ],
        [
            "user",
            "meta",
            "update",
            "subscriber_user",
            "_application_passwords",
            "[]",
        ],
        [
            "eval",
            "global $wpdb; $wpdb->delete($wpdb->usermeta, "
            "['meta_key' => WP_Application_Passwords::"
            "USERMETA_KEY_APPLICATION_PASSWORDS]);",
        ],
        [
            "eval",
            "global $wpdb; $wpdb->update($wpdb->users, "
            "['user_pass' => 'changed'], ['ID' => 1]);",
        ],
        ["eval", "call_user_func('add_role', 'elevated', ['manage_options'=>1]);"],
        [
            "eval",
            "update_user_meta(7, $wpdb->prefix . 'capabilities', "
            "['administrator' => true]);",
        ],
        ["option", "update", "wp_user_roles", "{}"],
        ["option", "update", "active_plugins", "[]"],
        ["eval", "update_option('active_sitewide_plugins', []);"],
        [
            "eval",
            "call_user_func('update_option', 'active_plugins', []);",
        ],
        [
            "eval",
            "WP_CLI::runcommand('plugin deactivate demo-plugin');",
        ],
        [
            "user",
            "create",
            "extra-owner",
            "owner@example.test",
            "--role=administrator",
        ],
        [
            "--role",
            "ADMIN",
            "user",
            "create",
            "extra-owner",
            "owner@example.test",
        ],
        [
            "user",
            "--role=administrator",
            "update",
            "subscriber_user",
        ],
        [
            "user",
            "create",
            "extra-owner",
            "owner@example.test",
            "--role",
            "super administrator",
        ],
        ["super-admin", "add", "extra-owner"],
        [
            "eval",
            "$id = wp_create_user('extra-owner', 'secret'); "
            "$user = new WP_User($id); $user->set_role('administrator');",
        ],
        [
            "eval",
            "wp_insert_user(['user_login' => 'extra-owner', "
            "'user_pass' => 'secret', 'role' => 'administrator']);",
        ],
        [
            "eval",
            "WP_CLI::runcommand('user create extra-owner owner@example.test "
            "--role=administrator');",
        ],
    ],
)
def test_blocks_direct_role_capability_and_active_plugin_state_mutations(args):
    reason = _setup_command_mutates_managed_context(args)

    assert reason is not None


@pytest.mark.parametrize(
    "args",
    [
        [
            "user",
            "create",
            "object-owner",
            "owner@example.test",
            "--role=subscriber",
        ],
        [
            "user",
            "create",
            "object-owner",
            "owner@example.test",
            "--role",
            "author",
        ],
        ["eval", "wp_create_user('object-owner', 'secret');"],
    ],
)
def test_allows_low_privilege_owner_or_control_user_creation(args):
    assert _setup_command_mutates_managed_context(args) is None


def test_allows_indirect_noncredential_user_profile_setup():
    assert (
        _setup_command_mutates_managed_context(
            [
                "eval",
                "$update = 'wp_update_user'; "
                "$update(['ID' => 7, 'display_name' => 'Object Owner']);",
            ]
        )
        is None
    )


@pytest.mark.parametrize(
    "args",
    [
        ["user", "application-password", "list", "subscriber_user"],
        [
            "user",
            "--format=json",
            "application-password",
            "get",
            "subscriber_user",
            "credential-uuid",
        ],
        [
            "eval",
            "WP_Application_Passwords::get_user_application_passwords(7);",
        ],
        ["user", "meta", "get", "subscriber_user", "_application_passwords"],
    ],
)
def test_allows_read_only_application_password_diagnostics(args):
    assert _setup_command_mutates_managed_context(args) is None


@pytest.mark.parametrize(
    "args",
    [
        ["eval", "wp_generate_auth_cookie(1, time() + 3600, 'auth');"],
        ["eval", "wp_set_auth_cookie(1);"],
        ["eval", "wp_signon(['user_login' => 'admin', 'user_password' => 'x']);"],
        [
            "eval",
            "call_user_func('wp_generate_auth_cookie', 1, time() + 3600, 'auth');",
        ],
        [
            "eval",
            "$tokens = WP_Session_Tokens::get_instance(1); "
            "$tokens->create(time() + 3600);",
        ],
        ["eval", "WP_Session_Tokens::destroy_all_for_all_users();"],
        [
            "eval",
            "$tokens = WP_User_Meta_Session_Tokens::get_instance(1); "
            "call_user_func([$tokens, 'update'], 'token', []);",
        ],
        ["user", "session", "destroy", "admin", "token"],
        ["user", "session", "destroy-all", "admin"],
        ["eval", "WP_CLI::runcommand('user session destroy-all admin');"],
        ["user", "meta", "update", "admin", "session_tokens", "[]"],
        ["eval", "update_user_meta(1, 'session_tokens', []);"],
    ],
)
def test_blocks_synthetic_auth_cookie_and_session_token_mutations(args):
    reason = _setup_command_mutates_managed_context(args)

    assert reason and "session" in reason.casefold()


@pytest.mark.parametrize(
    "args",
    [
        ["eval", "$user_id = wp_validate_auth_cookie($cookie, 'auth');"],
        ["eval", "$parts = wp_parse_auth_cookie($cookie, 'auth');"],
        ["eval", "$token = wp_get_session_token();"],
        [
            "eval",
            "$tokens = WP_Session_Tokens::get_instance(1); "
            "$valid = $tokens->verify($token);",
        ],
        ["user", "session", "list", "admin", "--format=json"],
        ["user", "meta", "get", "admin", "session_tokens"],
        ["option", "update", "plugin_session_tokens_enabled", "1"],
        [
            "eval",
            "$response = wp_remote_get('http://127.0.0.1:80/wp-login.php');",
        ],
    ],
)
def test_allows_auth_diagnostics_and_unauthenticated_reachability_gets(args):
    assert _setup_command_mutates_managed_context(args) is None


def test_managed_context_guard_allows_benign_installer_and_object_setup():
    assert (
        _setup_command_mutates_managed_context(
            ["eval", "Plugin_Setup::install_defaults();"]
        )
        is None
    )
    assert (
        _setup_command_mutates_managed_context(
            ["option", "update", "demo_enabled", "1"]
        )
        is None
    )


def test_allows_read_only_plugin_diagnostics():
    reason = _setup_command_mutates_managed_context(
        ["plugin", "is-active", "demo-plugin"]
    )

    assert reason is None


@pytest.mark.asyncio
async def test_managed_context_violation_is_blocked_before_execution():
    class FailIfCalledWPCli:
        async def _exec_result(self, *args, user=None, wp_user=None):
            raise AssertionError("managed-context mutation reached WP-CLI")

    sandbox = type("FakeSandbox", (), {"wp_cli": FailIfCalledWPCli()})()

    results = await _run_setup_commands(
        sandbox,
        [["--user=1", "plugin", "deactivate", "demo-plugin"]],
        hypothesis=_hyp(BugClass.ARBITRARY_FILE_WRITE),
    )

    assert results[0]["failed"] is True
    assert results[0]["forbidden_payload_seed"] is False
    assert "plugin lifecycle" in results[0]["forbidden_setup_reason"]
    assert results[0]["blocked_before_execution"] is True
    assert results[0]["executed"] is False


@pytest.mark.asyncio
async def test_failed_setup_round_rolls_back_all_partial_state(tmp_path):
    class RecordingWPCli:
        def __init__(self, sandbox):
            self.sandbox = sandbox

        async def _exec_result(self, *args, user=None, wp_user=None):
            self.sandbox.state.append(args[-1])
            if args[-1] == "second":
                return 1, "", "Error: setup postcondition failed: public page"
            return 0, "updated", ""

    class FakeSandbox:
        config = SimpleNamespace(wp_admin_email="owner@example.test")

        def __init__(self):
            self.state = []
            self.saved = {}
            self.restore_count = 0
            self.restart_count = 0
            self.wp_cli = RecordingWPCli(self)

        async def snapshot(self):
            path = tmp_path / "setup-round-snapshot"
            path.mkdir()
            self.saved[path] = list(self.state)
            return path

        async def restore(self, snapshot):
            self.restore_count += 1
            self.state = list(self.saved[snapshot])

        async def restart_wordpress_runtime(self):
            self.restart_count += 1

    sandbox = FakeSandbox()
    results = await _run_setup_round_atomically(
        sandbox,  # type: ignore[arg-type]
        [["option", "update", "first"], ["option", "update", "second"]],
        hypothesis=_hyp(BugClass.ARBITRARY_FILE_WRITE),
    )

    assert sandbox.state == []
    assert sandbox.restore_count == 1
    assert sandbox.restart_count == 1
    assert all(item["setup_round_rolled_back"] is True for item in results)
    assert all(item["setup_state_committed"] is False for item in results)
    summary = _summarise_setup_results(results)
    assert "NOT COMMITTED — SETUP ROUND ROLLED BACK" in summary
    assert "ENTIRE SETUP ROUND ROLLED BACK" in summary
    assert not (tmp_path / "setup-round-snapshot").exists()


@pytest.mark.asyncio
async def test_successful_setup_round_commits_without_restore(tmp_path):
    class RecordingWPCli:
        async def _exec_result(self, *args, user=None, wp_user=None):
            return 0, "updated", ""

    class FakeSandbox:
        config = SimpleNamespace(wp_admin_email="owner@example.test")
        wp_cli = RecordingWPCli()

        def __init__(self):
            self.restore_count = 0

        async def snapshot(self):
            path = tmp_path / "successful-setup-snapshot"
            path.mkdir()
            return path

        async def restore(self, _snapshot):
            self.restore_count += 1

    sandbox = FakeSandbox()
    results = await _run_setup_round_atomically(
        sandbox,  # type: ignore[arg-type]
        [["option", "update", "demo_enabled", "1"]],
        hypothesis=_hyp(BugClass.ARBITRARY_FILE_WRITE),
    )

    assert sandbox.restore_count == 0
    assert results[0]["setup_round_rolled_back"] is False
    assert results[0]["setup_state_committed"] is True
    assert not (tmp_path / "successful-setup-snapshot").exists()


def test_setup_state_summary_keeps_committed_state_ahead_of_latest_rollback():
    huge_program = "create_normal_object();" + ("x" * 12000) + "HIDDEN_PROGRAM_TAIL"
    committed = {
        "args": ["eval", huge_program],
        "returncode": 0,
        "output": json.dumps(
            {
                "object_id": 41,
                "public_url": (
                    "http://example.test/object/41?_wpnonce=url-secret-must-not-leak"
                ),
                "form_nonce": "nonce-value-must-not-leak",
                "nonce_present": True,
                "token_count": 1,
            }
        ),
        "stderr": "",
        "failed": False,
        "executed": True,
        "setup_round_rolled_back": False,
        "setup_state_committed": True,
    }
    rolled_back = {
        "args": ["eval", huge_program.replace("41", "42")],
        "returncode": 1,
        "output": "",
        "stderr": (
            "PHP Notice: unrelated bootstrap notice\n"
            "Error: setup postcondition failed: missing controls: "
            "email,amount nonce=second-secret"
        ),
        "failed": True,
        "executed": True,
        "setup_round_rolled_back": True,
        "setup_state_committed": False,
    }

    summary = _summarise_setup_state(
        [committed, rolled_back], latest_round_results=[rolled_back]
    )

    assert summary.index("RETAINED COMMITTED SETUP STATE") < summary.index(
        "LATEST SETUP ROUND"
    )
    assert '"object_id":41' in summary
    assert '"form_nonce":"<redacted:present>"' in summary
    assert '"nonce_present":true' in summary
    assert '"token_count":1' in summary
    assert "nonce-value-must-not-leak" not in summary
    assert "url-secret-must-not-leak" not in summary
    assert "_wpnonce=<redacted>" in summary
    assert "second-secret" not in summary
    assert "missing controls: email,amount" in summary
    assert "HIDDEN_PROGRAM_TAIL" not in summary
    assert "wp eval <PHP omitted; chars=" in summary
    assert "Only the latest failed setup round shown above was rolled back" in summary
    assert "Earlier committed setup state remains present" in summary
    assert "instead of recreating it" in summary
    assert len(summary) < 3000


@pytest.mark.asyncio
async def test_failed_setup_round_retains_snapshot_when_rollback_fails(tmp_path):
    class FailingWPCli:
        async def _exec_result(self, *args, user=None, wp_user=None):
            return 1, "", "Error: setup postcondition failed: expected state"

    class FakeSandbox:
        config = SimpleNamespace(wp_admin_email="owner@example.test")
        wp_cli = FailingWPCli()

        async def snapshot(self):
            path = tmp_path / "unrestored-setup-snapshot"
            path.mkdir()
            (path / "db.sql").write_text("recovery")
            return path

        async def restore(self, _snapshot):
            raise RuntimeError("simulated rollback failure")

    with pytest.raises(RuntimeError, match="simulated rollback failure"):
        await _run_setup_round_atomically(
            FakeSandbox(),  # type: ignore[arg-type]
            [["option", "update", "demo_enabled", "1"]],
            hypothesis=_hyp(BugClass.ARBITRARY_FILE_WRITE),
        )

    retained = tmp_path / "unrestored-setup-snapshot"
    assert retained.is_dir()
    assert (retained / "db.sql").read_text() == "recovery"


def _managed_state(
    *,
    subscriber_caps=None,
    active_plugins=None,
    privileged_users=None,
    canonical_urls=None,
):
    return {
        "users": {
            "sandbox-owner": {
                "id": 1,
                "login": "sandbox-owner",
                "roles": ["administrator"],
                "caps": {"administrator": True},
                "allcaps": ["manage_options"],
                "privileged_caps": ["manage_options"],
                "network_super_admin": False,
                "credential_fingerprint": "a" * 64,
            },
            "subscriber_user": {
                "id": 2,
                "login": "subscriber_user",
                "roles": ["subscriber"],
                "caps": {"subscriber": True},
                "allcaps": subscriber_caps or ["read"],
                "privileged_caps": [],
                "network_super_admin": False,
                "credential_fingerprint": "b" * 64,
            },
        },
        "active_plugins": (
            ["demo-plugin/demo-plugin.php"]
            if active_plugins is None
            else active_plugins
        ),
        "active_sitewide_plugins": [],
        "canonical_urls": canonical_urls
        or {
            "home": "http://localhost:8100",
            "siteurl": "http://localhost:8100",
        },
        "privileged_users": (
            {
                "sandbox-owner": {
                    "id": 1,
                    "roles": ["administrator"],
                    "caps": ["manage_options"],
                    "super_admin": False,
                }
            }
            if privileged_users is None
            else privileged_users
        ),
        "target_plugin_active": True,
    }


def test_managed_setup_state_drift_detects_stable_id_replacement():
    before = _managed_state()
    after = _managed_state()
    after["users"]["subscriber_user"]["id"] = 99

    reason = _managed_setup_state_drift(before, after)

    assert reason is not None
    assert "identity, or credentials" in reason


def test_managed_setup_state_drift_detects_password_or_token_change():
    before = _managed_state()
    after = _managed_state()
    after["users"]["subscriber_user"]["credential_fingerprint"] = "c" * 64

    reason = _managed_setup_state_drift(before, after)

    assert reason is not None
    assert "identity, or credentials" in reason


def test_required_attacker_account_is_hypothesis_specific():
    editor = {
        "id": 7,
        "login": "editor_user",
        "password": "verified",
        "role": "editor",
    }

    assert _required_attacker_account([], "unauthenticated") is None
    assert _required_attacker_account([editor], "editor") is editor
    with pytest.raises(RuntimeError, match="subscriber"):
        _required_attacker_account([editor], "subscriber")


def test_low_priv_attacker_uses_lowest_verified_concrete_account():
    customer = {"login": "customer_user", "password": "x", "role": "customer"}
    subscriber = {
        "login": "subscriber_user",
        "password": "y",
        "role": "subscriber",
    }

    assert _required_attacker_account([customer, subscriber], "low_priv") is subscriber


@pytest.mark.asyncio
async def test_post_execution_state_monitor_taints_indirect_capability_mutation():
    states = iter(
        [
            _managed_state(),
            _managed_state(subscriber_caps=["manage_options", "read"]),
        ]
    )

    class RecordingWPCli:
        called = False

        async def _exec_result(self, *args, user=None, wp_user=None):
            self.called = True
            return 0, "installer complete", ""

    class FakeSandbox:
        config = SimpleNamespace(wp_admin_email="owner@example.test")

        def __init__(self):
            self.wp_cli = RecordingWPCli()

        async def capture_setup_security_state(self, _plugin_slug):
            return next(states)

    sandbox = FakeSandbox()
    results = await _run_setup_commands(
        sandbox,
        [["eval", "Plugin_Setup::install_defaults();"]],
        hypothesis=_hyp(BugClass.XSS_STORED),
        plugin_slug="demo-plugin",
    )

    assert sandbox.wp_cli.called is True
    assert results[0]["failed"] is True
    assert results[0]["managed_context_violation"] is True
    assert "roles or capabilities" in results[0]["forbidden_setup_reason"]
    assert _setup_result_taints_confirmation(results[0]) is True


@pytest.mark.asyncio
async def test_post_execution_state_monitor_taints_configured_admin_mutation():
    before = _managed_state()
    after = _managed_state()
    after["users"]["sandbox-owner"] = {
        "roles": ["subscriber"],
        "caps": {"subscriber": True},
        "allcaps": ["read"],
    }
    after["privileged_users"] = {}
    states = iter([before, after])

    class RecordingWPCli:
        async def _exec_result(self, *args, user=None, wp_user=None):
            return 0, "installer complete", ""

    class FakeSandbox:
        config = SimpleNamespace(wp_admin_email="owner@example.test")
        wp_cli = RecordingWPCli()

        async def capture_setup_security_state(self, _plugin_slug):
            return next(states)

    results = await _run_setup_commands(
        FakeSandbox(),
        [["eval", "Plugin_Setup::install_defaults();"]],
        hypothesis=_hyp(BugClass.XSS_STORED),
        plugin_slug="demo-plugin",
    )

    assert results[0]["failed"] is True
    assert results[0]["managed_context_violation"] is True
    assert "sandbox-owner" in results[0]["forbidden_setup_reason"]


@pytest.mark.asyncio
async def test_post_execution_state_monitor_taints_indirect_plugin_deactivation():
    before = _managed_state()
    after = _managed_state(active_plugins=[])
    after["target_plugin_active"] = False
    states = iter([before, after])

    class RecordingWPCli:
        async def _exec_result(self, *args, user=None, wp_user=None):
            return 0, "installer complete", ""

    class FakeSandbox:
        config = SimpleNamespace(wp_admin_email="owner@example.test")
        wp_cli = RecordingWPCli()

        async def capture_setup_security_state(self, _plugin_slug):
            return next(states)

    results = await _run_setup_commands(
        FakeSandbox(),
        [["eval", "Plugin_Setup::install_defaults();"]],
        hypothesis=_hyp(BugClass.XSS_STORED),
        plugin_slug="demo-plugin",
    )

    assert results[0]["failed"] is True
    assert results[0]["managed_context_violation"] is True
    assert "deactivated the target plugin" in results[0]["forbidden_setup_reason"]


@pytest.mark.asyncio
async def test_post_execution_state_monitor_taints_indirect_canonical_url_mutation():
    states = iter(
        [
            _managed_state(),
            _managed_state(
                canonical_urls={
                    "home": "http://127.0.0.1:80",
                    "siteurl": "http://localhost:8100",
                }
            ),
        ]
    )

    class RecordingWPCli:
        async def _exec_result(self, *args, user=None, wp_user=None):
            return 0, "installer complete", ""

    class FakeSandbox:
        config = SimpleNamespace(wp_admin_email="owner@example.test")
        wp_cli = RecordingWPCli()

        async def capture_setup_security_state(self, _plugin_slug):
            return next(states)

    results = await _run_setup_commands(
        FakeSandbox(),
        [["eval", "Plugin_Setup::install_defaults();"]],
        hypothesis=_hyp(BugClass.XSS_STORED),
        plugin_slug="demo-plugin",
    )

    assert results[0]["failed"] is True
    assert results[0]["managed_context_violation"] is True
    assert "home/siteurl" in results[0]["forbidden_setup_reason"]
    assert _setup_result_taints_confirmation(results[0]) is True


@pytest.mark.asyncio
async def test_post_execution_state_monitor_taints_new_elevated_user():
    before = _managed_state()
    after_privileged = dict(before["privileged_users"])
    after_privileged["extra-owner"] = {
        "roles": ["custom-owner"],
        "caps": ["manage_options"],
        "super_admin": False,
    }
    after = _managed_state(privileged_users=after_privileged)
    states = iter([before, after])

    class RecordingWPCli:
        async def _exec_result(self, *args, user=None, wp_user=None):
            return 0, "installer complete", ""

    class FakeSandbox:
        config = SimpleNamespace(wp_admin_email="owner@example.test")
        wp_cli = RecordingWPCli()

        async def capture_setup_security_state(self, _plugin_slug):
            return next(states)

    results = await _run_setup_commands(
        FakeSandbox(),
        [["eval", "Plugin_Setup::install_defaults();"]],
        hypothesis=_hyp(BugClass.XSS_STORED),
        plugin_slug="demo-plugin",
    )

    assert results[0]["failed"] is True
    assert results[0]["managed_context_violation"] is True
    assert "elevated WordPress user" in results[0]["forbidden_setup_reason"]


@pytest.mark.asyncio
async def test_post_execution_state_monitor_normalises_plugin_list_order():
    before = _managed_state(
        active_plugins=["other/other.php", "demo-plugin/demo-plugin.php"]
    )
    before["active_sitewide_plugins"] = ["network/network.php", "mu/mu.php"]
    after = _managed_state(
        active_plugins=["demo-plugin/demo-plugin.php", "other/other.php"]
    )
    after["active_sitewide_plugins"] = ["mu/mu.php", "network/network.php"]
    states = iter([before, after])

    class RecordingWPCli:
        async def _exec_result(self, *args, user=None, wp_user=None):
            return 0, "installer complete", ""

    class FakeSandbox:
        config = SimpleNamespace(wp_admin_email="owner@example.test")
        wp_cli = RecordingWPCli()

        async def capture_setup_security_state(self, _plugin_slug):
            return next(states)

    results = await _run_setup_commands(
        FakeSandbox(),
        [["eval", "Plugin_Setup::install_defaults();"]],
        hypothesis=_hyp(BugClass.XSS_STORED),
        plugin_slug="demo-plugin",
    )

    assert results[0]["failed"] is False
    assert results[0]["managed_context_violation"] is False


@pytest.mark.asyncio
async def test_post_execution_state_monitor_allows_safe_source_defined_setup_api():
    state = _managed_state()

    class RecordingWPCli:
        async def _exec_result(self, *args, user=None, wp_user=None):
            return 0, "normal object created", ""

    class FakeSandbox:
        config = SimpleNamespace(wp_admin_email="owner@example.test")
        wp_cli = RecordingWPCli()

        async def capture_setup_security_state(self, _plugin_slug):
            return state

    results = await _run_setup_commands(
        FakeSandbox(),
        [["eval", "Plugin_Setup::install_defaults();"]],
        hypothesis=_hyp(BugClass.XSS_STORED),
        plugin_slug="demo-plugin",
    )

    assert results[0]["failed"] is False
    assert results[0]["managed_context_violation"] is False
    assert _setup_result_taints_confirmation(results[0]) is False


@pytest.mark.asyncio
async def test_setup_is_blocked_if_managed_state_cannot_be_captured():
    class FailIfCalledWPCli:
        async def _exec_result(self, *args, user=None, wp_user=None):
            raise AssertionError("setup ran without a managed-state baseline")

    class FakeSandbox:
        config = SimpleNamespace(wp_admin_email="owner@example.test")
        wp_cli = FailIfCalledWPCli()

        async def capture_setup_security_state(self, _plugin_slug):
            raise RuntimeError("state unavailable")

    results = await _run_setup_commands(
        FakeSandbox(),
        [["eval", "Plugin_Setup::install_defaults();"]],
        hypothesis=_hyp(BugClass.XSS_STORED),
        plugin_slug="demo-plugin",
    )

    assert results[0]["blocked_before_execution"] is True
    assert results[0]["executed"] is False
    assert "could not establish managed setup security state" in results[0]["stderr"]


@pytest.mark.asyncio
async def test_verification_rejects_success_after_indirect_managed_state_drift(
    monkeypatch,
    tmp_path,
):
    plugin_root = tmp_path / "plugin"
    plugin_root.mkdir()
    (plugin_root / "x.php").write_text("<?php\nPlugin_Setup::install_defaults();\n")
    poc_dir = tmp_path / "verification"
    states = iter(
        [
            _managed_state(),
            _managed_state(subscriber_caps=["manage_options", "read"]),
        ]
    )

    class FakeWPCli:
        async def _exec_result(self, *args, user=None, wp_user=None):
            return 0, "installer complete", ""

    class FakeSandbox:
        target_url = "http://localhost:8100"
        config = SimpleNamespace(wp_admin_email="owner@example.test")
        wp_cli = FakeWPCli()

        def __init__(self):
            self.poc_runs = 0
            self.restores = 0

        async def capture_setup_security_state(self, _plugin_slug):
            return next(states)

        def baseline_user_accounts(self):
            return [
                {
                    "login": "subscriber_user",
                    "password": "password",
                    "role": "subscriber",
                }
            ]

        def setup_http_context(self):
            return verify_stage.SetupHttpContext.from_wordpress_origins(
                internal_connect_origin=(
                    verify_stage.SandboxManager.INTERNAL_WORDPRESS_ORIGIN
                ),
                canonical_wordpress_origin=self.target_url,
            )

        async def snapshot(self):
            path = tmp_path / "snapshot"
            path.mkdir(exist_ok=True)
            return path

        async def restore(self, _snapshot):
            self.restores += 1

        async def run_poc(self, *_args, **_kwargs):
            self.poc_runs += 1
            return SandboxRunResult(
                success=True,
                output="SQUADRONE_RESULT={}",
                elapsed=0,
                response="claimed success",
            )

    class FakeDeveloper:
        async def propose_setup(self, *_args, **_kwargs):
            return SetupPlan(
                rationale="Run the normal source-defined installer.",
                commands=[["eval", "Plugin_Setup::install_defaults();"]],
            )

        async def propose_setup_followup(self, **_kwargs):
            return SetupPlan(
                rationale="Do not repair a protected-state change.",
                commands=[],
                failure_class="setup",
            )

    class FakePoCAuthor:
        def __init__(self, *_args, **_kwargs):
            pass

        async def write(self, **_kwargs):
            return "import requests\n"

    monkeypatch.setattr(verify_stage, "PoCAuthorAgent", FakePoCAuthor)
    config = PipelineConfig.from_yaml("pipelines/test.yaml")
    config.verify_max_iterations = 1
    sandbox = FakeSandbox()

    finding = await verify_stage._verify_one(
        _hyp(BugClass.XSS_STORED),
        str(plugin_root),
        str(tmp_path / "plugin.zip"),
        "demo-plugin",
        config,
        object(),
        poc_dir,
        developer=FakeDeveloper(),
        persistent_sb=sandbox,
    )

    assert finding is None
    assert sandbox.poc_runs == 1
    # The failed setup round is restored immediately, then the attempted PoC is
    # restored before the protected-boundary rejection returns.
    assert sandbox.restores == 2
    checkpoint = json.loads((poc_dir / "setup_results.json").read_text())
    assert checkpoint["results"][0]["managed_context_violation"] is True
    assert checkpoint["results"][0]["setup_round_rolled_back"] is True
    assert checkpoint["results"][0]["setup_state_committed"] is False
    attempts_checkpoint = json.loads((poc_dir / "attempts.json").read_text())
    assert attempts_checkpoint["schema_version"] == 1
    assert attempts_checkpoint["hypothesis_id"] == "h"
    assert attempts_checkpoint["status"] == "not_confirmed"
    assert len(attempts_checkpoint["attempts"]) == 1
    assert attempts_checkpoint["attempts"][0]["result"] == "failed"
    assert attempts_checkpoint["attempts"][0]["validation_reason"]
    assert "protected verification boundary" in (
        attempts_checkpoint["attempts"][0]["developer_analysis"]
    )


@pytest.mark.parametrize(
    "php",
    [
        "chmod($dir, 0777);",
        "$wp_filesystem->chmod($dir, FS_CHMOD_DIR);",
        "chown($dir, 'www-data');",
        "umask(0);",
    ],
)
def test_blocks_setup_filesystem_permission_mutation(php):
    reason = _setup_command_plants_exploit_payload(
        ["eval", php],
        _hyp(BugClass.ARBITRARY_FILE_WRITE),
    )
    assert reason and "filesystem permissions or ownership" in reason


@pytest.mark.parametrize(
    "args",
    [
        [
            "eval",
            """file_put_contents(WP_CONTENT_DIR . '/uploads/proof.php',
            '<?php echo "SQUADRONE_MARKER";');""",
        ],
        [
            "eval",
            "copy('/tmp/proof.php', WP_CONTENT_DIR . '/uploads/proof.php');",
        ],
        ["eval", "touch(WP_CONTENT_DIR . '/uploads/proof.phtml');"],
        [
            "eval",
            "$wp_filesystem->put_contents(WP_CONTENT_DIR . "
            "'/uploads/proof.php', 'marker');",
        ],
        ["media", "import", "/tmp/proof.php"],
        [
            "db",
            "query",
            "SELECT '<?php echo 1;' INTO OUTFILE '/tmp/proof.php'",
        ],
    ],
)
def test_blocks_direct_file_seed_for_file_write_or_upload_finding(args):
    reason = _setup_command_plants_exploit_payload(
        args,
        _hyp(BugClass.ARBITRARY_FILE_WRITE),
    )

    assert reason and "directly" in reason


def test_blocks_direct_executable_file_seed_without_hypothesis_metadata():
    reason = _setup_command_plants_exploit_payload(
        [
            "eval",
            """file_put_contents('/tmp/proof.php',
            '<?php system($_GET["cmd"]);');""",
        ],
        None,
    )

    assert reason and "executable file content" in reason


@pytest.mark.parametrize(
    "args",
    [
        ["eval", "wp_mkdir_p(WP_CONTENT_DIR . '/uploads/demo');"],
        ["post", "create", "--post_title=Normal prerequisite page"],
        ["eval", "Plugin_Setup::install_defaults();"],
    ],
)
def test_file_seed_guard_allows_directory_page_and_source_defined_setup(args):
    assert (
        _setup_command_plants_exploit_payload(
            args,
            _hyp(BugClass.ARBITRARY_FILE_WRITE),
        )
        is None
    )


@pytest.mark.asyncio
async def test_forbidden_permission_setup_is_not_executed():
    class FakeWPCli:
        called = False

        async def _exec_result(self, *args, user=None, wp_user=None):
            self.called = True
            return 0, "", ""

    wp_cli = FakeWPCli()
    sandbox = type("FakeSandbox", (), {"wp_cli": wp_cli})()

    results = await _run_setup_commands(
        sandbox,
        [["eval", "chmod(WP_PLUGIN_DIR . '/demo/files', 0777);"]],
        hypothesis=_hyp(BugClass.ARBITRARY_FILE_WRITE),
    )

    assert wp_cli.called is False
    assert results[0]["failed"] is True
    assert results[0]["forbidden_payload_seed"] is True
    assert results[0]["blocked_before_execution"] is True
    assert results[0]["executed"] is False


@pytest.mark.asyncio
async def test_mixed_safe_and_forbidden_setup_is_blocked_atomically():
    class FailIfCalledWPCli:
        async def _exec_result(self, *args, user=None, wp_user=None):
            raise AssertionError("mixed setup reached WP-CLI")

    sandbox = type("FakeSandbox", (), {"wp_cli": FailIfCalledWPCli()})()

    results = await _run_setup_commands(
        sandbox,
        [
            [
                "eval",
                "wp_mkdir_p('/srv/site/uploads'); chmod('/srv/site/uploads', 0777);",
            ]
        ],
        hypothesis=_hyp(BugClass.ARBITRARY_FILE_WRITE),
    )

    summary = _summarise_setup_results(results)
    assert "BLOCKED BEFORE EXECUTION" in summary
    assert "No part of this command ran" in summary
    assert "containing only permitted prerequisite operations" in summary


def test_pre_execution_block_does_not_taint_later_confirmation():
    blocked = {
        "forbidden_payload_seed": True,
        "blocked_before_execution": True,
        "executed": False,
    }
    assert not _setup_result_taints_confirmation(blocked)
    assert _summarise_forbidden_setup([blocked]) == ""
    # Old artifacts did not record execution metadata, so retain their conservative
    # behaviour instead of weakening the integrity of prior findings.
    assert _setup_result_taints_confirmation({"forbidden_payload_seed": True})
    assert _setup_result_taints_confirmation(
        {
            "forbidden_payload_seed": True,
            "blocked_before_execution": False,
            "executed": True,
        }
    )


@pytest.mark.asyncio
async def test_permission_guard_does_not_depend_on_hypothesis_metadata():
    class FailIfCalledWPCli:
        async def _exec_result(self, *args, user=None, wp_user=None):
            raise AssertionError("forbidden setup reached WP-CLI")

    sandbox = type("FakeSandbox", (), {"wp_cli": FailIfCalledWPCli()})()

    results = await _run_setup_commands(
        sandbox,
        [["eval", "chmod('/tmp/plugin-state', 0777);"]],
    )

    assert results[0]["forbidden_payload_seed"] is True


@pytest.mark.asyncio
async def test_allowed_setup_runs_as_web_and_configured_wordpress_admin_identities():
    calls: list[tuple[tuple[str, ...], str | None, str | None]] = []

    class RecordingWPCli:
        async def _exec_result(self, *args, user=None, wp_user=None):
            calls.append((args, user, wp_user))
            return 0, "updated", ""

    sandbox = type(
        "FakeSandbox",
        (),
        {
            "wp_cli": RecordingWPCli(),
            "config": SimpleNamespace(wp_admin_email="owner@example.test"),
        },
    )()

    results = await _run_setup_commands(
        sandbox,
        [["option", "update", "demo_enabled", "1"]],
        hypothesis=_hyp(BugClass.ARBITRARY_FILE_WRITE),
    )

    assert calls == [
        (
            ("option", "update", "demo_enabled", "1"),
            "www-data",
            "owner@example.test",
        )
    ]
    assert results[0]["failed"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "advisory",
    [
        "Warning: Could not update .htaccess.",
        "PHP Deprecated: Passing null is deprecated.",
    ],
)
async def test_successful_wp_cli_command_is_not_failed_by_advisory_output(advisory):
    class WarningWPCli:
        async def _exec_result(self, *args, user=None, wp_user=None):
            return 0, "Success: Rewrite rules flushed.", advisory

    sandbox = type(
        "FakeSandbox",
        (),
        {
            "wp_cli": WarningWPCli(),
            "config": SimpleNamespace(wp_admin_email="owner@example.test"),
        },
    )()

    results = await _run_setup_commands(
        sandbox,
        [["rewrite", "flush"]],
        hypothesis=_hyp(BugClass.ARBITRARY_FILE_WRITE),
    )

    assert results[0]["failed"] is False
    summary = _summarise_setup_results(results)
    assert "[1] OK" in summary
    assert "command: wp rewrite flush" in summary
    assert "Success: Rewrite rules flushed." in summary
    assert advisory in summary


@pytest.mark.asyncio
async def test_structured_postcondition_survives_unrelated_plugin_bootstrap_warning():
    bootstrap_warning = (
        'PHP Warning: Attempt to read property "current_options" on null in '
        "/var/www/html/wp-content/plugins/example/includes/block.php on line 25"
    )

    class BootstrapWarningWPCli:
        async def _exec_result(self, *args, user=None, wp_user=None):
            return 0, '{"foreign_id":41,"control_id":42}\n', bootstrap_warning

    sandbox = type(
        "FakeSandbox",
        (),
        {
            "wp_cli": BootstrapWarningWPCli(),
            "config": SimpleNamespace(wp_admin_email="owner@example.test"),
        },
    )()
    command = [
        "eval",
        "$rows = array('foreign_id' => 41, 'control_id' => 42); "
        "WP_CLI::log(wp_json_encode($rows));",
    ]

    results = await _run_setup_commands(
        sandbox,
        [command],
        hypothesis=_hyp(BugClass.IDOR),
    )

    assert results[0]["failed"] is False
    assert results[0]["advisory_bootstrap_warning"] is True
    summary = _summarise_setup_results(results)
    assert "[1] OK WITH WARNINGS" in summary
    assert "command: wp eval <PHP omitted" in summary
    assert '"foreign_id":41' in summary
    assert bootstrap_warning in summary


@pytest.mark.asyncio
async def test_wp_cli_error_remains_failed_despite_structured_output_and_warning():
    stderr = (
        'PHP Warning: Attempt to read property "state" on null in '
        "/var/www/html/wp-content/plugins/example/bootstrap.php on line 9\n"
        "Error: setup postcondition failed"
    )

    class ErrorWPCli:
        async def _exec_result(self, *args, user=None, wp_user=None):
            return 0, '{"foreign_id":41}\n', stderr

    sandbox = type(
        "FakeSandbox",
        (),
        {
            "wp_cli": ErrorWPCli(),
            "config": SimpleNamespace(wp_admin_email="owner@example.test"),
        },
    )()

    results = await _run_setup_commands(
        sandbox,
        [["eval", "WP_CLI::log(wp_json_encode(array('foreign_id' => 41)));"]],
        hypothesis=_hyp(BugClass.IDOR),
    )

    assert results[0]["failed"] is True
    assert results[0]["advisory_bootstrap_warning"] is False


@pytest.mark.asyncio
async def test_php_warning_still_fails_setup_even_with_zero_exit_status():
    class PhpWarningWPCli:
        async def _exec_result(self, *args, user=None, wp_user=None):
            return (
                0,
                '{"directory":"/srv/site/uploads"}',
                "PHP Warning: mkdir(): Permission denied in "
                "/var/www/html/wp-includes/functions.php on line 2047",
            )

    sandbox = type(
        "FakeSandbox",
        (),
        {
            "wp_cli": PhpWarningWPCli(),
            "config": SimpleNamespace(wp_admin_email="owner@example.test"),
        },
    )()

    results = await _run_setup_commands(
        sandbox,
        [
            [
                "eval",
                "$ok = wp_mkdir_p('/srv/site/uploads'); "
                "WP_CLI::log(wp_json_encode(array('directory' => "
                "'/srv/site/uploads')));",
            ]
        ],
        hypothesis=_hyp(BugClass.ARBITRARY_FILE_WRITE),
    )

    assert results[0]["executed"] is True
    assert results[0]["blocked_before_execution"] is False
    assert results[0]["failed"] is True
    summary = _summarise_setup_results(results)
    assert "FAILED AFTER EXECUTION — STATE MAY BE PARTIAL" in summary


def test_setup_context_includes_cited_entry_point_and_sink_files(tmp_path):
    classes = tmp_path / "classes"
    classes.mkdir()
    api_lines = ["// filler"] * 700
    api_lines[20] = "$public_api = $this->core->get_option( 'public_api' );"
    api_lines[672] = "public function rest_simpleFileUpload( $request ) {"
    (classes / "api.php").write_text("\n".join(api_lines))
    files_lines = ["// filler"] * 400
    files_lines[366] = "if ( !copy( $path, $destination ) ) {"
    (classes / "files.php").write_text("\n".join(files_lines))
    hypothesis = _hyp(BugClass.ARBITRARY_FILE_WRITE)
    hypothesis.entry_point = "classes/api.php:673 rest_simpleFileUpload"
    hypothesis.file = "classes/files.php"
    hypothesis.line = 367
    hypothesis.taint_path = [
        "classes/api.php:673 receives the file",
        "classes/files.php:367 copies it",
    ]

    context = _build_setup_code_context(tmp_path, hypothesis)

    assert context is not None
    assert "--- classes/api.php ---" in context
    assert "get_option( 'public_api' )" in context
    assert "rest_simpleFileUpload" in context
    assert "--- classes/files.php ---" in context
    assert "copy( $path, $destination )" in context


def test_setup_context_recovers_uncited_entry_guard_from_semantic_identifier(tmp_path):
    routes = tmp_path / "includes" / "routes.php"
    routes.parent.mkdir()
    routes.write_text(
        "\n".join(
            [
                "class Example_Public_API {",
                "$feature_enabled = get_option( 'demo_public_uploads' );",
                "register_rest_route( 'demo/v1', '/store-asset', [",
                "  'callback' => [ $this, 'rest_store_asset' ],",
                "] );",
                "}",
            ]
        )
    )
    bootstrap = tmp_path / "includes" / "core.php"
    bootstrap.write_text(
        "\n".join(
            [
                "private $option_name = 'example_options';",
                *(["// filler"] * 60),
                "$api = new Example_Public_API();",
            ]
        )
    )
    sink = tmp_path / "includes" / "storage.php"
    sink.write_text("copy( $temporary_path, $destination );\n")
    hypothesis = _hyp(BugClass.ARBITRARY_FILE_WRITE)
    hypothesis.entry_point = "POST /wp-json/demo/v1/store-asset"
    hypothesis.file = "includes/storage.php"
    hypothesis.line = 1
    hypothesis.taint_path = [
        "Example_Public_API::rest_store_asset receives attacker bytes",
        "copy writes the selected extension",
    ]

    context = _build_setup_code_context(tmp_path, hypothesis)

    assert context is not None
    assert "--- includes/routes.php ---" in context
    assert "demo_public_uploads" in context
    assert "rest_store_asset" in context
    assert "--- includes/core.php ---" in context
    assert "example_options" in context
    assert "--- includes/storage.php ---" in context
    assert context.index("--- includes/routes.php ---") < context.index(
        "--- includes/storage.php ---"
    )
    assert len(context) <= 12_000


def test_setup_context_reserves_primary_sink_and_config_when_auxiliary_overflows(
    tmp_path,
):
    primary_lines = ["// primary filler"] * 360
    primary_lines[49] = "private $option_name = 'demo_options'; // PRIMARY_CONFIG"
    primary_lines[69] = "add_action('wp_ajax_demo_store_asset', 'demo_store_asset');"
    primary_lines[299] = "$wpdb->query($sql); // PRIMARY_SINK"
    (tmp_path / "main.php").write_text("\n".join(primary_lines))

    includes = tmp_path / "includes"
    includes.mkdir()
    for index, name in enumerate(("a_route", "b_noise", "c_noise", "d_noise")):
        auxiliary_lines = [f"// {name} " + ("x" * 100)] * 90
        auxiliary_lines[index + 1] = (
            f"demo_store_asset(); // {name.upper()}_SEMANTIC_MATCH"
        )
        (includes / f"{name}.php").write_text("\n".join(auxiliary_lines))

    hypothesis = _hyp(BugClass.IDOR)
    hypothesis.entry_point = "wp_ajax_demo_store_asset"
    hypothesis.file = "main.php"
    hypothesis.line = 300
    hypothesis.sink_code = "$wpdb->query($sql);"
    hypothesis.taint_path = [
        "demo_store_asset receives the object ID",
        "demo_store_asset dispatches the update",
    ]

    context = _build_setup_code_context(tmp_path, hypothesis, max_chars=8_000)

    assert context is not None
    assert len(context) <= 8_000
    assert "ROUTE_SEMANTIC_MATCH" in context
    assert "--- main.php ---" in context
    assert "PRIMARY_CONFIG" in context
    assert "PRIMARY_SINK" in context
    assert context.index("--- includes/a_route.php ---") < context.index(
        "--- main.php ---"
    )


def test_setup_context_keeps_sink_when_primary_itself_overflows(tmp_path):
    primary_lines = ["// " + ("y" * 70)] * 700
    primary_lines[9] = "private $option_name = 'demo_options'; // PRIMARY_CONFIG"
    semantic_tokens = ["demo_route_one", "demo_route_two", "demo_route_three"]
    for line_number, token in zip((100, 250, 400), semantic_tokens, strict=True):
        primary_lines[line_number - 1] = f"function {token}() {{}}"
    primary_lines[649] = "$wpdb->query($sql); // PRIMARY_SINK"
    (tmp_path / "main.php").write_text("\n".join(primary_lines))

    hypothesis = _hyp(BugClass.IDOR)
    hypothesis.entry_point = "wp_ajax_demo_route_one"
    hypothesis.file = "main.php"
    hypothesis.line = 650
    hypothesis.sink_code = "$wpdb->query($sql);"
    hypothesis.taint_path = [
        "demo_route_two receives the object ID",
        "demo_route_three dispatches the update",
    ]

    context = _build_setup_code_context(tmp_path, hypothesis, max_chars=5_000)

    assert context is not None
    assert len(context) <= 5_000
    assert "PRIMARY_CONFIG" in context
    assert "PRIMARY_SINK" in context


@pytest.mark.asyncio
async def test_atomic_setup_repair_does_not_consume_poc_requested_quota(
    monkeypatch, tmp_path
):
    plugin_root = tmp_path / "plugin"
    plugin_root.mkdir()
    (plugin_root / "x.php").write_text("<?php\ncopy($source, $destination);\n")
    poc_dir = tmp_path / "verification"
    mixed = [
        "eval",
        "wp_mkdir_p('/srv/site/uploads'); chmod('/srv/site/uploads', 0777);",
    ]
    safe = ["eval", "wp_mkdir_p('/srv/site/uploads');"]
    poc_forbidden = [
        "eval",
        "wp_mkdir_p('/srv/site/poc-uploads'); chmod('/srv/site/poc-uploads', 0777);",
    ]

    class RecordingWPCli:
        def __init__(self):
            self.calls = []

        async def _exec_result(self, *args, user=None, wp_user=None):
            self.calls.append((args, user, wp_user))
            return 0, "directory ready", ""

    class FakeSandbox:
        target_url = "http://localhost:8100"
        config = SimpleNamespace(wp_admin_email="owner@example.test")

        def __init__(self):
            self.wp_cli = RecordingWPCli()
            self.snapshot_count = 0

        def baseline_user_accounts(self):
            return [
                {
                    "login": "subscriber_user",
                    "password": "password",
                    "role": "subscriber",
                }
            ]

        def setup_http_context(self):
            return verify_stage.SetupHttpContext.from_wordpress_origins(
                internal_connect_origin=(
                    verify_stage.SandboxManager.INTERNAL_WORDPRESS_ORIGIN
                ),
                canonical_wordpress_origin=self.target_url,
            )

        async def snapshot(self):
            self.snapshot_count += 1
            path = tmp_path / f"snapshot-{self.snapshot_count}"
            path.mkdir()
            return path

        async def restore(self, _snapshot):
            return None

        async def run_poc(self, *_args, **_kwargs):
            return SandboxRunResult(
                success=False,
                output="",
                elapsed=0,
                response="not confirmed",
            )

    class FakeDeveloper:
        def __init__(self):
            self.followup_feedback = []
            self.requested_setup_calls = []

        async def propose_setup(self, *_args, **_kwargs):
            return SetupPlan(
                rationale="Create the runtime directory.", commands=[mixed]
            )

        async def propose_setup_followup(self, **kwargs):
            self.followup_feedback.append(kwargs["setup_execution_feedback"])
            if len(self.followup_feedback) == 1:
                return SetupPlan(rationale="Retry the mixed command.", commands=[mixed])
            if len(self.followup_feedback) == 2:
                return SetupPlan(
                    rationale="Use only the safe operation.", commands=[safe]
                )
            raise AssertionError("an automatic setup followup quota was exceeded")

        async def propose_requested_setup(self, **kwargs):
            self.requested_setup_calls.append(kwargs)
            if len(self.requested_setup_calls) == 1:
                return RequestedSetupPlan(
                    rationale="Apply the source-grounded PoC prerequisite.",
                    commands=[poc_forbidden],
                )
            if len(self.requested_setup_calls) == 2:
                return RequestedSetupPlan(
                    rationale="Do not bypass the setup safety guard.", commands=[]
                )
            raise AssertionError("a PoC-requested setup quota was exceeded")

    callback_results = []

    class FakePoCAuthor:
        def __init__(self, *_args, setup_callback=None, **_kwargs):
            self.setup_callback = setup_callback

        async def write(self, **_kwargs):
            callback_results.append(await self.setup_callback("request more setup"))
            return "from pathlib import Path\n"

    monkeypatch.setattr(verify_stage, "PoCAuthorAgent", FakePoCAuthor)
    config = PipelineConfig.from_yaml("pipelines/test.yaml")
    config.verify_max_iterations = 1
    developer = FakeDeveloper()
    sandbox = FakeSandbox()
    runtime = object()

    finding = await verify_stage._verify_one(
        _hyp(BugClass.ARBITRARY_FILE_WRITE),
        str(plugin_root),
        str(tmp_path / "plugin.zip"),
        "plugin",
        config,
        runtime,
        poc_dir,
        developer=developer,
        persistent_sb=sandbox,
    )

    assert finding is None
    assert len(developer.followup_feedback) == 2
    assert len(developer.requested_setup_calls) == 2
    assert "BLOCKED BEFORE EXECUTION" in developer.followup_feedback[0]
    assert "LATEST SETUP ROUND" in developer.followup_feedback[1]
    assert "RETAINED COMMITTED SETUP STATE" in developer.followup_feedback[1]
    assert "CUMULATIVE HISTORY COUNTS" in developer.followup_feedback[1]
    assert all(
        call["request_description"] == "request more setup"
        for call in developer.requested_setup_calls
    )
    assert all("last_iteration" not in call for call in developer.requested_setup_calls)
    assert all("last_stdout" not in call for call in developer.requested_setup_calls)
    assert all("last_stderr" not in call for call in developer.requested_setup_calls)
    assert all("last_error_log" not in call for call in developer.requested_setup_calls)
    assert (
        "BLOCKED BEFORE EXECUTION"
        in developer.requested_setup_calls[1]["setup_execution_feedback"]
    )
    assert sandbox.wp_cli.calls == [(tuple(safe), "www-data", "owner@example.test")]
    assert len(callback_results) == 1
    assert callback_results[0].startswith(
        "[request_additional_setup] setup remains incomplete;"
    )
    checkpoint = json.loads((poc_dir / "setup_results.json").read_text())
    assert checkpoint["followups_used"] == 4
    assert checkpoint["followup_cap"] == 4
    assert checkpoint["automatic_followups_used"] == 2
    assert checkpoint["automatic_followup_cap"] == 2
    assert checkpoint["poc_requested_followups_used"] == 2
    assert checkpoint["poc_requested_followup_cap"] == 2
    assert len(checkpoint["results"]) == 4
    assert [item["blocked_before_execution"] for item in checkpoint["results"]] == [
        True,
        True,
        False,
        True,
    ]
    assert checkpoint["results"][-1]["executed"] is False


@pytest.mark.asyncio
async def test_blocked_lifecycle_repairs_cannot_starve_poc_requested_setup(
    monkeypatch, tmp_path
):
    plugin_root = tmp_path / "plugin"
    plugin_root.mkdir()
    (plugin_root / "x.php").write_text("<?php\ncopy($source, $destination);\n")
    poc_dir = tmp_path / "verification"
    initial_lifecycle = ["plugin", "deactivate", "plugin"]
    first_repair = ["plugin", "activate", "plugin"]
    second_repair = ["--user=1", "plugin", "deactivate", "plugin"]
    poc_initial = ["option", "update", "demo_runtime_ready", "1"]
    poc_corrective = ["option", "update", "demo_runtime_postcondition", "1"]

    class RecordingWPCli:
        def __init__(self):
            self.calls = []

        async def _exec_result(self, *args, user=None, wp_user=None):
            self.calls.append((args, user, wp_user))
            if args == tuple(poc_initial):
                return 0, '{"foreign_id":41,"control_id":42}', ""
            if args == tuple(poc_corrective):
                return 0, '{"observer_id":7,"postcondition":"ready"}', ""
            return 0, "updated", ""

    class FakeSandbox:
        target_url = "http://localhost:8100"
        config = SimpleNamespace(wp_admin_email="owner@example.test")

        def __init__(self):
            self.wp_cli = RecordingWPCli()
            self.snapshot_count = 0

        def baseline_user_accounts(self):
            return [
                {
                    "login": "subscriber_user",
                    "password": "password",
                    "role": "subscriber",
                }
            ]

        def setup_http_context(self):
            return verify_stage.SetupHttpContext.from_wordpress_origins(
                internal_connect_origin=(
                    verify_stage.SandboxManager.INTERNAL_WORDPRESS_ORIGIN
                ),
                canonical_wordpress_origin=self.target_url,
            )

        async def snapshot(self):
            self.snapshot_count += 1
            path = tmp_path / f"lifecycle-snapshot-{self.snapshot_count}"
            path.mkdir()
            return path

        async def restore(self, _snapshot):
            return None

        async def run_poc(self, *_args, **_kwargs):
            return SandboxRunResult(
                success=False,
                output="",
                elapsed=0,
                response="not confirmed",
            )

    class FakeDeveloper:
        def __init__(self):
            self.followup_calls = []
            self.requested_setup_calls = []
            self.initial_setup_http_contexts = []

        async def propose_setup(self, *_args, **kwargs):
            self.initial_setup_http_contexts.append(kwargs["setup_http_context"])
            return SetupPlan(
                rationale="Incorrectly cycle the managed plugin.",
                commands=[initial_lifecycle],
            )

        async def propose_setup_followup(self, **kwargs):
            self.followup_calls.append(kwargs)
            call_number = len(self.followup_calls)
            if call_number == 1:
                return SetupPlan(
                    rationale="Incorrect lifecycle retry.", commands=[first_repair]
                )
            if call_number == 2:
                return SetupPlan(
                    rationale="Incorrect identity and lifecycle retry.",
                    commands=[second_repair],
                )
            raise AssertionError("an automatic setup followup quota was exceeded")

        async def propose_requested_setup(self, **kwargs):
            self.requested_setup_calls.append(kwargs)
            call_number = len(self.requested_setup_calls)
            if call_number == 1:
                return RequestedSetupPlan(
                    rationale="Create the source-grounded normal prerequisite.",
                    commands=[poc_initial],
                )
            if call_number == 2:
                return RequestedSetupPlan(
                    rationale="Correct the source-grounded frontend postcondition.",
                    commands=[poc_corrective],
                )
            raise AssertionError("a PoC-requested setup quota was exceeded")

    callback_results = []
    write_setup_summaries = []

    class FakePoCAuthor:
        def __init__(self, *_args, setup_callback=None, **_kwargs):
            self.setup_callback = setup_callback
            self.write_count = 0

        async def write(self, **kwargs):
            self.write_count += 1
            write_setup_summaries.append(
                kwargs["extra_context"].get("setup_summary", "")
            )
            descriptions = {
                1: "create the source-grounded normal state",
                2: "correct the failed frontend postcondition",
                3: "request a third PoC setup round",
            }
            callback_results.append(
                await self.setup_callback(descriptions[self.write_count])
            )
            return "from pathlib import Path\n"

    monkeypatch.setattr(verify_stage, "PoCAuthorAgent", FakePoCAuthor)
    config = PipelineConfig.from_yaml("pipelines/test.yaml")
    config.verify_max_iterations = 3
    developer = FakeDeveloper()
    sandbox = FakeSandbox()
    runtime = object()

    finding = await verify_stage._verify_one(
        _hyp(BugClass.ARBITRARY_FILE_WRITE),
        str(plugin_root),
        str(tmp_path / "plugin.zip"),
        "plugin",
        config,
        runtime,
        poc_dir,
        developer=developer,
        persistent_sb=sandbox,
    )

    assert finding is None
    assert len(developer.initial_setup_http_contexts) == 1
    assert (
        developer.initial_setup_http_contexts[0].internal_connect_origin
        == verify_stage.SandboxManager.INTERNAL_WORDPRESS_ORIGIN
    )
    assert developer.initial_setup_http_contexts[0].canonical_host_header == (
        "localhost:8100"
    )
    assert len(developer.followup_calls) == 2
    assert len(developer.requested_setup_calls) == 2
    all_setup_calls = developer.followup_calls + developer.requested_setup_calls
    assert all(
        call["setup_http_context"].internal_connect_origin
        == verify_stage.SandboxManager.INTERNAL_WORDPRESS_ORIGIN
        for call in all_setup_calls
    )
    assert all(
        call["setup_http_context"].canonical_host_header == "localhost:8100"
        for call in all_setup_calls
    )
    assert sandbox.target_url == "http://localhost:8100"
    assert all(call["runtime"] is runtime for call in all_setup_calls)
    assert all(
        call["plugin_root"] == str(plugin_root)
        for call in all_setup_calls
    )
    assert developer.requested_setup_calls[0]["request_description"] == (
        "create the source-grounded normal state"
    )
    assert developer.requested_setup_calls[1]["request_description"] == (
        "correct the failed frontend postcondition"
    )
    assert all(
        call["schema_diagnostics"] == ""
        for call in developer.requested_setup_calls
    )
    assert sandbox.wp_cli.calls == [
        (tuple(poc_initial), "www-data", "owner@example.test"),
        (tuple(poc_corrective), "www-data", "owner@example.test"),
    ]
    assert callback_results[0].startswith(
        "[request_additional_setup] applied 1 permitted commands."
    )
    assert callback_results[1].startswith(
        "[request_additional_setup] applied 1 permitted commands."
    )
    assert callback_results[2] == (
        "[request_additional_setup] PoC-requested setup followup limit reached (2/2)"
    )
    assert '"foreign_id":41' not in write_setup_summaries[0]
    assert '"foreign_id":41' in write_setup_summaries[1]
    assert '"foreign_id":41' in write_setup_summaries[2]
    assert '"observer_id":7' in write_setup_summaries[2]
    assert "ordered oldest to newest" in write_setup_summaries[2]
    assert "newer self-verified result as canonical" in write_setup_summaries[2]
    assert "FAILED or partial commands are not evidence" in write_setup_summaries[2]

    checkpoint = json.loads((poc_dir / "setup_results.json").read_text())
    assert checkpoint["followups_used"] == 4
    assert checkpoint["followup_cap"] == 4
    assert checkpoint["automatic_followups_used"] == 2
    assert checkpoint["automatic_followup_cap"] == 2
    assert checkpoint["poc_requested_followups_used"] == 2
    assert checkpoint["poc_requested_followup_cap"] == 2
    assert [item["blocked_before_execution"] for item in checkpoint["results"]] == [
        True,
        True,
        True,
        False,
        False,
    ]
