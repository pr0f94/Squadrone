from __future__ import annotations

import asyncio
import json
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

import squadrone.services.sandbox as sandbox_module
import squadrone.services.wp_cli as wp_cli_module
from squadrone.schemas import SandboxConfig
from squadrone.services.sandbox import SandboxManager
from squadrone.services.wp_cli import WPCli


def test_ssrf_bind_source_aliases_are_exact_and_darwin_only() -> None:
    expected = "/private/var/folders/example/oracle"

    assert sandbox_module._accepted_ssrf_bind_sources(
        expected,
        platform="darwin",
    ) == {
        expected,
        "/var/folders/example/oracle",
        "/host_mnt/private/var/folders/example/oracle",
        "/host_mnt/var/folders/example/oracle",
    }
    assert sandbox_module._accepted_ssrf_bind_sources(
        expected,
        platform="linux",
    ) == {expected}
    assert "/host_mnt/private/var/folders/example/sibling" not in (
        sandbox_module._accepted_ssrf_bind_sources(expected, platform="darwin")
    )


def _manager(
    *,
    ssrf_oracle_modes: frozenset[str] = frozenset(),
    php_include_oracle_enabled: bool = False,
    php_object_oracle_enabled: bool = False,
) -> SandboxManager:
    manager = SandboxManager(
        SandboxConfig(
            wordpress_image="wordpress:latest",
            db_image="mariadb:10.11",
            wp_admin_user="admin",
            wp_admin_pass="password",
            wp_admin_email="admin@example.test",
        ),
        ssrf_oracle_modes=ssrf_oracle_modes,  # type: ignore[arg-type]
        php_include_oracle_enabled=php_include_oracle_enabled,
        php_object_oracle_enabled=php_object_oracle_enabled,
    )
    manager.container_name = "test-project-wordpress-1"
    manager._pre_plugin_role_capabilities = {
        "subscriber": frozenset({"read", "level_0"}),
        "contributor": frozenset({"read", "level_0", "level_1", "edit_posts"}),
        "author": frozenset({"read", "edit_posts", "publish_posts", "upload_files"}),
        "editor": frozenset(
            {
                "read",
                "level_0",
                "level_1",
                "edit_posts",
                "publish_posts",
                "upload_files",
                "edit_others_posts",
            }
        ),
        "administrator": frozenset(
            {
                "read",
                "level_0",
                "level_1",
                "edit_posts",
                "publish_posts",
                "upload_files",
                "edit_others_posts",
                "manage_options",
            }
        ),
    }
    return manager


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "ssrf_oracle_modes",
    [
        frozenset(),
        frozenset({"http"}),
        frozenset({"local_resource"}),
        frozenset({"http", "local_resource"}),
    ],
    ids=("none", "http", "local-resource", "both"),
)
@pytest.mark.parametrize("php_include_oracle_enabled", [False, True])
async def test_boot_renders_only_requested_ssrf_resources(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    ssrf_oracle_modes: frozenset[str],
    php_include_oracle_enabled: bool,
) -> None:
    workdir = tmp_path / "sandbox-workdir"
    workdir.mkdir()

    async def fake_run(*_args: str, **_kwargs: object) -> tuple[int, str, str]:
        return 0, "", ""

    async def no_op() -> None:
        return None

    manager = _manager(
        ssrf_oracle_modes=ssrf_oracle_modes,
        php_include_oracle_enabled=php_include_oracle_enabled,
    )
    monkeypatch.setattr(sandbox_module, "_alloc_port", lambda: 8199)
    monkeypatch.setattr(
        sandbox_module.tempfile,
        "mkdtemp",
        lambda **_kwargs: str(workdir),
    )
    monkeypatch.setattr(sandbox_module, "_run", fake_run)
    monkeypatch.setattr(manager, "_wait_for_wordpress", no_op)
    monkeypatch.setattr(manager, "_ensure_wp_installed", no_op)
    monkeypatch.setattr(manager, "_seal_runtime_network", no_op)
    monkeypatch.setattr(manager, "_install_actor_receipt_plugin", no_op)
    monkeypatch.setattr(manager, "_ensure_wp_upload_path", no_op)

    await manager.boot()

    compose_text = (workdir / "docker-compose.yml").read_text()
    compose = yaml.safe_load(compose_text)
    wordpress = compose["services"]["wordpress"]
    ingress = compose["services"]["ingress"]
    http_ssrf_enabled = "http" in ssrf_oracle_modes
    assert compose["networks"]["default"] == {"internal": True}
    assert wordpress["networks"] == {
        "default": {"priority": 1000},
        "bootstrap": {"gw_priority": 1000},
    }
    assert compose["services"]["db"]["networks"] == ["default"]
    if http_ssrf_enabled:
        assert ingress["networks"] == {
            "default": {"aliases": ["squadrone-ssrf-relay.internal"]},
            "ingress": None,
        }
        assert ingress["extra_hosts"] == ["squadrone.host.internal:host-gateway"]
    else:
        assert ingress["networks"] == ["default", "ingress"]
        assert "extra_hosts" not in ingress
    assert ingress["ports"] == ["127.0.0.1:8199:80"]
    assert compose["networks"]["bootstrap"] == {
        "external": True,
        "name": manager.bootstrap_network_name,
    }
    assert "extra_hosts" not in wordpress
    assert ("squadrone.host.internal:host-gateway" in compose_text) is (
        http_ssrf_enabled
    )
    assert ("squadrone-ssrf-relay.internal" in compose_text) is http_ssrf_enabled
    assert ("/var/lib/squadrone/ssrf:ro" in compose_text) is (
        "local_resource" in ssrf_oracle_modes
    )
    assert (manager._ssrf_local_host_dir is not None) is (
        "local_resource" in ssrf_oracle_modes
    )
    assert (workdir / "ssrf-local-resource").exists() is (
        "local_resource" in ssrf_oracle_modes
    )
    assert ("/var/lib/squadrone/php-include:ro" in compose_text) is (
        php_include_oracle_enabled
    )
    assert (manager._php_include_host_dir is not None) is (php_include_oracle_enabled)
    assert (workdir / "php-include").exists() is php_include_oracle_enabled


@pytest.mark.asyncio
async def test_unrequested_ssrf_oracles_fail_before_side_effects() -> None:
    manager = _manager()
    manager._booted = True
    manager.container_name = "must-not-be-used"

    with pytest.raises(RuntimeError, match="HTTP SSRF oracle was not enabled"):
        await manager.prepare_ssrf_oracle()
    with pytest.raises(
        RuntimeError,
        match="local-resource SSRF oracle was not enabled",
    ):
        await manager.prepare_ssrf_local_resource_oracle()
    with pytest.raises(RuntimeError, match="PHP include oracle was not enabled"):
        await manager.prepare_php_include_oracle()

    assert manager._ssrf_oracle is None
    assert manager._ssrf_local_oracle is None
    assert manager._php_include_oracle is None


def _baseline_inspection(
    manager: SandboxManager,
    *,
    unavailable_roles: set[str] | None = None,
) -> dict:
    unavailable_roles = unavailable_roles or set()
    expected = [
        (manager.config.wp_admin_user, "administrator"),
        *manager.BASELINE_USERS,
    ]

    def inspected_user(user_id: int, login: str, role: str) -> dict:
        privileged = ["manage_options"] if role == "administrator" else []
        return {
            "id": user_id,
            "login": login,
            "roles": [role],
            "authenticated": True,
            "caps": {role: True},
            "allcaps": ["read", *privileged],
            "privileged_caps": privileged,
            "unexpected_effective_core_caps": [],
            "unexpected_individual_caps": [],
            "network_super_admin": False,
            "authority_exceeds_baseline": False,
        }

    return {
        "roles": {role: role not in unavailable_roles for _login, role in expected},
        "users": {
            login: (
                None
                if role in unavailable_roles
                else inspected_user(user_id, login, role)
            )
            for user_id, (login, role) in enumerate(expected, start=1)
        },
    }


def _seed_verified_accounts(manager: SandboxManager) -> None:
    inspection = _baseline_inspection(manager)
    manager._baseline_accounts = [
        {
            "id": inspection["users"][login]["id"],
            "login": login,
            "password": (
                manager.config.wp_admin_pass
                if role == "administrator"
                else manager._baseline_passwords[login]
            ),
            "role": role,
        }
        for login, role in [
            (manager.config.wp_admin_user, "administrator"),
            *manager.BASELINE_USERS,
        ]
    ]


def test_baseline_user_accounts_requires_a_verified_setup():
    with pytest.raises(RuntimeError, match="until setup_test_users completes"):
        _manager().baseline_user_accounts()


@pytest.mark.asyncio
async def test_setup_users_rejects_case_variant_login_collisions_before_wp_cli():
    manager = _manager()
    manager.config.wp_admin_user = "Subscriber_User"

    class FailIfCalledWPCli:
        async def reconcile_users(self, _accounts):
            raise AssertionError("case-colliding account spec reached WP-CLI")

    manager.wp_cli = FailIfCalledWPCli()  # type: ignore[assignment]

    with pytest.raises(RuntimeError, match="case-insensitively unique"):
        await manager.setup_test_users()


@pytest.mark.asyncio
async def test_setup_users_omits_unavailable_optional_role_from_verified_manifest():
    manager = _manager()
    inspection = _baseline_inspection(manager, unavailable_roles={"customer"})
    reconciliation_calls: list[list[dict[str, str]]] = []

    class FakeWPCli:
        async def reconcile_users(self, accounts: list[dict[str, str]]) -> dict:
            reconciliation_calls.append(accounts)
            return inspection

    manager.wp_cli = FakeWPCli()  # type: ignore[assignment]

    await manager.setup_test_users()

    accounts = manager.baseline_user_accounts()
    assert [
        (account["id"], account["login"], account["role"]) for account in accounts
    ] == [
        (1, "admin", "administrator"),
        (2, "subscriber_user", "subscriber"),
        (4, "contributor_user", "contributor"),
        (5, "author_user", "author"),
        (6, "editor_user", "editor"),
    ]
    assert all(account["login"] != "customer_user" for account in accounts)
    assert len(reconciliation_calls) == 1
    reconciled = reconciliation_calls[0]
    assert {account["login"] for account in reconciled} == {
        "admin",
        "subscriber_user",
        "customer_user",
        "contributor_user",
        "author_user",
        "editor_user",
    }
    assert all(account["password"] for account in reconciled)
    by_role = {account["role"]: account for account in reconciled}
    assert "edit_others_posts" in by_role["subscriber"]["forbidden_core_caps"]
    assert "manage_options" in by_role["subscriber"]["forbidden_core_caps"]
    assert "manage_options" not in by_role["administrator"]["forbidden_core_caps"]
    optional_passwords = [
        account["password"]
        for account in reconciled
        if account["role"] != "administrator"
    ]
    assert "password" not in optional_passwords
    assert len(set(optional_passwords)) == len(optional_passwords)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("login", "replacement", "message"),
    [
        ("subscriber_user", None, "user is missing"),
        (
            "editor_user",
            {
                **_baseline_inspection(_manager())["users"]["editor_user"],
                "roles": ["subscriber"],
            },
            "inspected roles",
        ),
    ],
)
async def test_setup_users_omits_missing_or_wrong_optional_account(
    login, replacement, message
):
    manager = _manager()
    inspection = _baseline_inspection(manager)
    inspection["users"][login] = replacement

    class FakeWPCli:
        async def reconcile_users(self, _accounts: list[dict[str, str]]) -> dict:
            return inspection

    manager.wp_cli = FakeWPCli()  # type: ignore[assignment]

    await manager.setup_test_users()

    assert login not in {
        account["login"] for account in manager.baseline_user_accounts()
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("authenticated", False, "credentials did not authenticate"),
        (
            "authority_exceeds_baseline",
            True,
            "effective authority exceeds the intended role baseline",
        ),
        (
            "unexpected_effective_core_caps",
            ["edit_others_posts"],
            "effective authority exceeds the intended role baseline",
        ),
    ],
)
async def test_setup_users_omits_optional_accounts_without_proven_baseline(
    field, value, message, caplog
):
    caplog.set_level("INFO")
    manager = _manager()
    inspection = _baseline_inspection(manager)
    inspection["users"]["subscriber_user"][field] = value
    if field == "authority_exceeds_baseline":
        inspection["users"]["subscriber_user"]["privileged_caps"] = ["manage_options"]
    elif field == "unexpected_effective_core_caps":
        inspection["users"]["subscriber_user"]["authority_exceeds_baseline"] = True

    class FakeWPCli:
        async def reconcile_users(self, _accounts: list[dict[str, str]]) -> dict:
            return inspection

    manager.wp_cli = FakeWPCli()  # type: ignore[assignment]

    await manager.setup_test_users()

    assert "subscriber_user" not in {
        account["login"] for account in manager.baseline_user_accounts()
    }
    assert message in caplog.text


@pytest.mark.asyncio
async def test_setup_users_fails_closed_when_administrator_cannot_authenticate():
    manager = _manager()
    inspection = _baseline_inspection(manager)
    inspection["users"]["admin"]["authenticated"] = False

    class FakeWPCli:
        async def reconcile_users(self, _accounts: list[dict[str, str]]) -> dict:
            return inspection

    manager.wp_cli = FakeWPCli()  # type: ignore[assignment]

    with pytest.raises(RuntimeError, match="credentials did not authenticate"):
        await manager.setup_test_users()
    with pytest.raises(RuntimeError, match="until setup_test_users completes"):
        manager.baseline_user_accounts()


@pytest.mark.asyncio
async def test_setup_users_accepts_plugin_defined_direct_caps_on_administrator():
    manager = _manager()
    inspection = _baseline_inspection(manager)
    inspection["users"]["admin"]["caps"]["bookingpress"] = True
    inspection["users"]["admin"]["allcaps"].append("bookingpress")
    inspection["users"]["admin"]["unexpected_individual_caps"] = ["bookingpress"]

    class FakeWPCli:
        async def reconcile_users(self, _accounts: list[dict[str, str]]) -> dict:
            return inspection

    manager.wp_cli = FakeWPCli()  # type: ignore[assignment]

    await manager.setup_test_users()

    assert manager.baseline_admin_user_id() == 1


@pytest.mark.asyncio
async def test_setup_users_still_rejects_plugin_defined_direct_caps_on_subscriber(
    caplog,
):
    caplog.set_level("INFO")
    manager = _manager()
    inspection = _baseline_inspection(manager)
    subscriber = inspection["users"]["subscriber_user"]
    subscriber["caps"]["bookingpress"] = True
    subscriber["allcaps"].append("bookingpress")
    subscriber["unexpected_individual_caps"] = ["bookingpress"]
    subscriber["authority_exceeds_baseline"] = True

    class FakeWPCli:
        async def reconcile_users(self, _accounts: list[dict[str, str]]) -> dict:
            return inspection

    manager.wp_cli = FakeWPCli()  # type: ignore[assignment]

    await manager.setup_test_users()

    assert "subscriber_user" not in {
        account["login"] for account in manager.baseline_user_accounts()
    }
    assert "bookingpress" in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("unexpected_effective_core_caps", ["manage_network"]),
        ("network_super_admin", True),
    ],
)
async def test_setup_users_rejects_administrator_boundary_escalation(field, value):
    manager = _manager()
    inspection = _baseline_inspection(manager)
    inspection["users"]["admin"][field] = value
    inspection["users"]["admin"]["authority_exceeds_baseline"] = True

    class FakeWPCli:
        async def reconcile_users(self, _accounts: list[dict[str, str]]) -> dict:
            return inspection

    manager.wp_cli = FakeWPCli()  # type: ignore[assignment]

    with pytest.raises(
        RuntimeError,
        match="effective authority exceeds the intended role baseline",
    ):
        await manager.setup_test_users()


@pytest.mark.asyncio
async def test_setup_security_state_captures_managed_users_and_plugin_activity():
    manager = _manager()
    manager.target_url = "http://localhost:8100/"
    _seed_verified_accounts(manager)
    managed_users = {
        account["login"]: {
            "id": account["id"],
            "login": account["login"],
            "roles": [account["role"]],
            "caps": {account["role"]: True},
            "allcaps": ["manage_options"]
            if account["role"] == "administrator"
            else ["read"],
            "privileged_caps": ["manage_options"]
            if account["role"] == "administrator"
            else [],
            "network_super_admin": False,
            "credential_fingerprint": "a" * 64,
        }
        for account in manager.baseline_user_accounts()
    }
    payload = {
        "users": managed_users,
        "privileged_users": {
            "admin": {
                "id": 1,
                "roles": ["administrator"],
                "caps": ["manage_options"],
                "super_admin": False,
            }
        },
        "active_plugins": ["other/other.php", "demo-plugin/demo.php"],
        "active_sitewide_plugins": ["network/network.php"],
        "canonical_urls": {
            "home": "http://localhost:8100",
            "siteurl": "http://localhost:8100",
        },
    }
    calls = []

    class FakeWPCli:
        async def _exec_result(self, *args, user=None, wp_user=None):
            calls.append((args, user, wp_user))
            return (
                0,
                "SQUADRONE_SETUP_SECURITY_STATE=" + json.dumps(payload),
                "",
            )

    manager.wp_cli = FakeWPCli()  # type: ignore[assignment]

    state = await manager.capture_setup_security_state("demo-plugin")

    assert state["target_plugin_active"] is True
    assert state["users"]["subscriber_user"]["roles"] == ["subscriber"]
    assert state["users"]["subscriber_user"]["id"] == 2
    assert state["users"]["subscriber_user"]["credential_fingerprint"] == "a" * 64
    assert state["users"]["admin"]["roles"] == ["administrator"]
    assert state["privileged_users"]["admin"]["caps"] == ["manage_options"]
    assert state["active_plugins"] == [
        "demo-plugin/demo.php",
        "other/other.php",
    ]
    assert state["canonical_urls"] == {
        "home": "http://localhost:8100",
        "siteurl": "http://localhost:8100",
    }
    assert len(calls) == 1
    args, os_user, wp_user = calls[0]
    assert args[0] == "eval"
    assert "subscriber_user" not in args[1]
    assert "'admin'" not in args[1]
    assert "'password'" not in args[1]
    assert "get_option('home', '')" in args[1]
    assert "get_option('siteurl', '')" in args[1]
    assert os_user == "www-data"
    assert wp_user == "1"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "canonical_urls",
    [
        {
            "home": "http://127.0.0.1:80",
            "siteurl": "http://localhost:8100",
        },
        {
            "home": "http://localhost:8100",
            "siteurl": "http://localhost:8101",
        },
    ],
)
async def test_setup_security_state_rejects_urls_outside_sandbox_target(
    canonical_urls,
):
    manager = _manager()
    manager.target_url = "http://localhost:8100/"
    _seed_verified_accounts(manager)
    managed_users = {
        account["login"]: {
            "id": account["id"],
            "login": account["login"],
            "roles": [account["role"]],
            "caps": {},
            "allcaps": [],
            "privileged_caps": [],
            "network_super_admin": False,
            "credential_fingerprint": "a" * 64,
        }
        for account in manager.baseline_user_accounts()
    }
    payload = {
        "users": managed_users,
        "privileged_users": {},
        "active_plugins": ["demo-plugin/demo.php"],
        "active_sitewide_plugins": [],
        "canonical_urls": canonical_urls,
    }

    class FakeWPCli:
        async def _exec_result(self, *args, user=None, wp_user=None):
            return (
                0,
                "SQUADRONE_SETUP_SECURITY_STATE=" + json.dumps(payload),
                "",
            )

    manager.wp_cli = FakeWPCli()  # type: ignore[assignment]

    with pytest.raises(RuntimeError, match="do not match the sandbox target URL"):
        await manager.capture_setup_security_state("demo-plugin")


@pytest.mark.asyncio
async def test_post_install_admin_init_uses_configured_admin_credentials(monkeypatch):
    calls = []

    class FakeClient:
        def __init__(self):
            self.cookies = SimpleNamespace(jar=[])

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, url):
            calls.append(("GET", url))
            return SimpleNamespace(status_code=200)

        async def post(self, url, data):
            calls.append(("POST", url, data))
            self.cookies.jar.append(SimpleNamespace(name="wordpress_logged_in_hash"))
            return SimpleNamespace(status_code=200)

    client = FakeClient()
    monkeypatch.setattr(
        sandbox_module.httpx,
        "AsyncClient",
        lambda **_kwargs: client,
    )
    manager = SandboxManager(
        SandboxConfig(
            wordpress_image="wordpress:latest",
            db_image="mariadb:10.11",
            wp_admin_user="configured-owner",
            wp_admin_pass="configured-secret",
            wp_admin_email="owner@example.test",
        )
    )
    manager.target_url = "http://localhost:8199"

    succeeded = await manager._fire_admin_init()

    assert succeeded is True
    login_call = next(item for item in calls if item[0] == "POST")
    assert login_call[2]["log"] == "configured-owner"
    assert login_call[2]["pwd"] == "configured-secret"
    assert calls[-1] == ("GET", "http://localhost:8199/wp-admin/")


@pytest.mark.asyncio
async def test_ensure_upload_path_runs_as_web_identity_without_permission_changes():
    calls: list[tuple[tuple[str, ...], str | None]] = []

    class FakeWPCli:
        async def _exec_result(self, *args: str, user: str | None = None):
            calls.append((args, user))
            return 0, "/var/www/html/wp-content/uploads/2026/08", ""

    manager = _manager()
    manager.wp_cli = FakeWPCli()  # type: ignore[assignment]

    await manager._ensure_wp_upload_path()

    assert len(calls) == 1
    args, user = calls[0]
    assert args[0] == "eval"
    assert "wp_upload_dir()" in args[1]
    assert "wp_mkdir_p($path)" in args[1]
    assert "is_writable($path)" in args[1]
    assert "chmod" not in args[1]
    assert "chown" not in args[1]
    assert user == "www-data"


@pytest.mark.asyncio
async def test_ensure_upload_path_fails_closed_when_web_user_cannot_write():
    class FakeWPCli:
        async def _exec_result(self, *args: str, user: str | None = None):
            return (
                1,
                "",
                "Error: WordPress upload path is not writable by the web user.",
            )

    manager = _manager()
    manager.wp_cli = FakeWPCli()  # type: ignore[assignment]

    with pytest.raises(RuntimeError, match="failed to prepare WordPress upload path"):
        await manager._ensure_wp_upload_path()


@pytest.mark.asyncio
async def test_actor_receipt_install_enforces_sticky_shared_directory_and_root_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls: list[tuple[tuple[str, ...], dict[str, object]]] = []

    async def fake_run(
        *args: str,
        **kwargs: object,
    ) -> tuple[int, str, str]:
        calls.append((args, kwargs))
        if args[3:] == ("id", "-u", "www-data"):
            return 0, "33\n", ""
        if args[3:] == ("id", "-g", "www-data"):
            return 0, "82\n", ""
        if args[3:6] == ("stat", "-c", "%u:%g:%a"):
            return 0, "0:82:1775\n0:0:444\n", ""
        return 0, "", ""

    manager = _manager()
    manager.workdir = tmp_path
    monkeypatch.setattr(sandbox_module, "_run", fake_run)

    await manager._install_actor_receipt_plugin()

    destination_dir = "/var/www/html/wp-content/mu-plugins"
    destination = f"{destination_dir}/squadrone-actor-receipt.php"
    container_exec = ("docker", "exec", "test-project-wordpress-1")
    commands = [args for args, _kwargs in calls]
    assert commands == [
        (*container_exec, "id", "-u", "www-data"),
        (*container_exec, "id", "-g", "www-data"),
        (*container_exec, "mkdir", "-p", destination_dir),
        (*container_exec, "chown", "root:82", destination_dir),
        (*container_exec, "chmod", "1775", destination_dir),
        (
            "docker",
            "cp",
            str(tmp_path / "squadrone-actor-receipt.php"),
            f"test-project-wordpress-1:{destination}",
        ),
        (*container_exec, "chown", "root:root", destination),
        (*container_exec, "chmod", "0444", destination),
        (
            *container_exec,
            "stat",
            "-c",
            "%u:%g:%a",
            destination_dir,
            destination,
        ),
        (*container_exec, "php", "-l", destination),
    ]
    assert [kwargs for _args, kwargs in calls] == [
        {"check": False},
        {"check": False},
        {},
        {},
        {},
        {},
        {},
        {},
        {"check": False},
        {"check": False},
    ]


@pytest.mark.asyncio
async def test_actor_receipt_install_rejects_root_web_identity_before_mutation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls: list[tuple[str, ...]] = []

    async def fake_run(*args: str, **_kwargs: object) -> tuple[int, str, str]:
        calls.append(args)
        return 0, "0\n", ""

    manager = _manager()
    manager.workdir = tmp_path
    monkeypatch.setattr(sandbox_module, "_run", fake_run)

    with pytest.raises(RuntimeError, match="must resolve to a non-root UID"):
        await manager._install_actor_receipt_plugin()

    assert calls == [
        (
            "docker",
            "exec",
            "test-project-wordpress-1",
            "id",
            "-u",
            "www-data",
        )
    ]


@pytest.mark.asyncio
async def test_actor_receipt_install_fails_closed_on_metadata_mismatch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls: list[tuple[str, ...]] = []

    async def fake_run(*args: str, **_kwargs: object) -> tuple[int, str, str]:
        calls.append(args)
        if args[3:] == ("id", "-u", "www-data"):
            return 0, "33\n", ""
        if args[3:] == ("id", "-g", "www-data"):
            return 0, "33\n", ""
        if args[3:6] == ("stat", "-c", "%u:%g:%a"):
            return 0, "0:33:775\n0:33:644\n", ""
        return 0, "", ""

    manager = _manager()
    manager.workdir = tmp_path
    monkeypatch.setattr(sandbox_module, "_run", fake_run)

    with pytest.raises(RuntimeError, match="filesystem protections are invalid"):
        await manager._install_actor_receipt_plugin()

    assert not any("php" in call for call in calls)


@pytest.mark.asyncio
async def test_boot_prepares_upload_path_before_becoming_ready(monkeypatch, tmp_path):
    events: list[str] = []
    workdir = tmp_path / "sandbox-workdir"
    workdir.mkdir()

    async def fake_run(*args: str, **_kwargs) -> tuple[int, str, str]:
        if args[:3] == ("docker", "network", "create"):
            events.append("network_create")
        elif args[:2] == ("docker", "compose"):
            events.append("compose")
        else:
            raise AssertionError(f"unexpected command: {args!r}")
        return 0, "", ""

    async def fake_wait() -> None:
        events.append("wait")

    async def fake_ensure() -> None:
        events.append("ensure")

    async def fake_seal() -> None:
        assert manager._booted is False
        assert manager.wp_cli is None
        events.append("seal")

    async def fake_upload_path() -> None:
        assert manager._booted is False
        events.append("upload_path")

    async def fake_actor_receipt() -> None:
        assert manager._booted is False
        assert manager.wp_cli is not None
        events.append("actor_receipt")

    manager = _manager()
    monkeypatch.setattr(sandbox_module, "_alloc_port", lambda: 8199)
    monkeypatch.setattr(
        sandbox_module.tempfile,
        "mkdtemp",
        lambda **_kwargs: str(workdir),
    )
    monkeypatch.setattr(sandbox_module, "_run", fake_run)
    monkeypatch.setattr(manager, "_wait_for_wordpress", fake_wait)
    monkeypatch.setattr(manager, "_ensure_wp_installed", fake_ensure)
    monkeypatch.setattr(manager, "_seal_runtime_network", fake_seal)
    monkeypatch.setattr(manager, "_install_actor_receipt_plugin", fake_actor_receipt)
    monkeypatch.setattr(manager, "_ensure_wp_upload_path", fake_upload_path)

    await manager.boot()

    assert events == [
        "network_create",
        "compose",
        "wait",
        "ensure",
        "seal",
        "wait",
        "actor_receipt",
        "upload_path",
    ]
    assert manager._booted is True


def _network_test_manager() -> SandboxManager:
    manager = _manager()
    manager.project = "squadrone-deadbeef"
    manager.container_name = "squadrone-deadbeef-wordpress-1"
    manager.port = 8199
    return manager


def _network_settings(
    networks: set[str],
    ports: dict[str, object],
) -> str:
    return json.dumps(
        {
            "Networks": {name: {} for name in sorted(networks)},
            "Ports": ports,
        }
    )


def test_ssrf_relay_config_has_one_literal_default_denied_upstream() -> None:
    config = sandbox_module._ssrf_relay_apache_config(49152)

    assert config.splitlines() == [
        "Listen 49152",
        "<VirtualHost *:49152>",
        "    ServerName squadrone-ssrf-relay.internal",
        "    ProxyRequests Off",
        "    ProxyPreserveHost On",
        "    ProxyAddHeaders Off",
        "    ProxyPassInterpolateEnv Off",
        "    ProxyPassInherit Off",
        "    UseCanonicalName Off",
        "    AllowEncodedSlashes NoDecode",
        '    <Location "/">',
        "        Require all denied",
        "    </Location>",
        '    <Location "/_squadrone/ssrf/">',
        "        Require all granted",
        "    </Location>",
        '    ProxyPass "/_squadrone/ssrf/" '
        '"http://squadrone.host.internal:49152/_squadrone/ssrf/" nocanon',
        '    ProxyPassReverse "/_squadrone/ssrf/" '
        '"http://squadrone.host.internal:49152/_squadrone/ssrf/"',
        "</VirtualHost>",
    ]
    assert config.count("ProxyPass ") == 1
    assert config.count("ProxyPassReverse ") == 1
    assert "${" not in config


@pytest.mark.parametrize("port", [True, 0, 1023, 65536, "49152"])
def test_ssrf_relay_config_rejects_non_high_integer_ports(port: object) -> None:
    with pytest.raises(ValueError, match="high TCP port"):
        sandbox_module._ssrf_relay_apache_config(port)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_ssrf_relay_install_rotation_and_removal_are_exact(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager = _manager(ssrf_oracle_modes=frozenset({"http"}))
    manager.project = "squadrone-deadbeef"
    manager.container_name = "squadrone-deadbeef-wordpress-1"
    manager.workdir = tmp_path
    manager._booted = True
    calls: list[tuple[str, ...]] = []
    copied_config = ""
    copied_mode = 0

    async def fake_run(*args: str, **_kwargs: object) -> tuple[int, str, str]:
        nonlocal copied_config, copied_mode
        calls.append(args)
        if args[:2] == ("docker", "cp"):
            source = Path(args[2])
            copied_config = source.read_text()
            copied_mode = stat.S_IMODE(source.stat().st_mode)
        return 0, "", ""

    monkeypatch.setattr(sandbox_module, "_run", fake_run)

    await manager._configure_ssrf_relay_locked(49152)

    assert manager._ssrf_relay_port == 49152
    assert copied_config == sandbox_module._ssrf_relay_apache_config(49152)
    assert copied_mode == 0o600
    assert not (tmp_path / "squadrone-ssrf-relay.conf").exists()
    assert calls == [
        (
            "docker",
            "cp",
            str(tmp_path / "squadrone-ssrf-relay.conf"),
            "squadrone-deadbeef-ingress-1:"
            "/etc/apache2/conf-enabled/.squadrone-ssrf-relay.conf.new",
        ),
        (
            "docker",
            "exec",
            "squadrone-deadbeef-ingress-1",
            "chown",
            "root:root",
            "/etc/apache2/conf-enabled/.squadrone-ssrf-relay.conf.new",
        ),
        (
            "docker",
            "exec",
            "squadrone-deadbeef-ingress-1",
            "chmod",
            "0600",
            "/etc/apache2/conf-enabled/.squadrone-ssrf-relay.conf.new",
        ),
        (
            "docker",
            "exec",
            "squadrone-deadbeef-ingress-1",
            "mv",
            "-f",
            "--",
            "/etc/apache2/conf-enabled/.squadrone-ssrf-relay.conf.new",
            "/etc/apache2/conf-enabled/squadrone-ssrf-relay.conf",
        ),
        (
            "docker",
            "exec",
            "squadrone-deadbeef-ingress-1",
            "apache2ctl",
            "configtest",
        ),
        (
            "docker",
            "exec",
            "squadrone-deadbeef-ingress-1",
            "apache2ctl",
            "-k",
            "graceful",
        ),
    ]

    calls.clear()
    await manager._disable_ssrf_relay_locked()

    assert manager._ssrf_relay_port is None
    assert calls == [
        (
            "docker",
            "exec",
            "squadrone-deadbeef-ingress-1",
            "rm",
            "-f",
            "--",
            "/etc/apache2/conf-enabled/squadrone-ssrf-relay.conf",
            "/etc/apache2/conf-enabled/.squadrone-ssrf-relay.conf.new",
        ),
        (
            "docker",
            "exec",
            "squadrone-deadbeef-ingress-1",
            "apache2ctl",
            "configtest",
        ),
        (
            "docker",
            "exec",
            "squadrone-deadbeef-ingress-1",
            "apache2ctl",
            "-k",
            "graceful",
        ),
    ]


@pytest.mark.asyncio
async def test_ssrf_relay_removal_failure_stops_ingress_and_latches_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _network_test_manager()
    manager._booted = True
    manager._ssrf_relay_port = 49152
    calls: list[tuple[str, ...]] = []

    async def fake_run(*args: str, **_kwargs: object) -> tuple[int, str, str]:
        calls.append(args)
        if args[:2] == ("docker", "exec"):
            raise RuntimeError("synthetic relay cleanup failure")
        return 0, "", ""

    monkeypatch.setattr(sandbox_module, "_run", fake_run)

    with pytest.raises(RuntimeError, match="synthetic relay cleanup failure"):
        await manager._disable_ssrf_relay_locked()

    assert manager._booted is False
    assert manager._ssrf_relay_port == 49152
    assert calls[-1] == (
        "docker",
        "stop",
        "--time",
        "5",
        manager.ingress_container_name,
    )


@pytest.mark.asyncio
async def test_runtime_network_seal_removes_egress_and_attests_exact_topology(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = _network_test_manager()
    calls: list[tuple[str, ...]] = []

    async def fake_run(*args: str, **_kwargs: object) -> tuple[int, str, str]:
        calls.append(args)
        if args[:3] == ("docker", "network", "inspect"):
            network = args[-1]
            return (
                0,
                "true" if network == manager.internal_network_name else "false",
                "",
            )
        if args[:2] == ("docker", "inspect"):
            if args[3] == "{{json .HostConfig.NetworkMode}}":
                return 0, json.dumps(manager.internal_network_name), ""
            container = args[-1]
            if container == manager.container_name:
                return 0, _network_settings(
                    {manager.internal_network_name}, {"80/tcp": None}
                ), ""
            if container == manager.db_container_name:
                return 0, _network_settings(
                    {manager.internal_network_name}, {"3306/tcp": None}
                ), ""
            if container == manager.ingress_container_name:
                return 0, _network_settings(
                    {
                        manager.internal_network_name,
                        manager.ingress_network_name,
                    },
                    {
                        "80/tcp": [
                            {"HostIp": "127.0.0.1", "HostPort": "8199"}
                        ]
                    },
                ), ""
        return 0, "", ""

    monkeypatch.setattr(sandbox_module, "_run", fake_run)

    await manager._seal_runtime_network()

    assert calls[:2] == [
        (
            "docker",
            "network",
            "disconnect",
            manager.bootstrap_network_name,
            manager.container_name,
        ),
        ("docker", "network", "rm", manager.bootstrap_network_name),
    ]
    assert calls[2:] == [
        (
            "docker",
            "network",
            "inspect",
            "--format",
            "{{json .Internal}}",
            manager.internal_network_name,
        ),
        (
            "docker",
            "network",
            "inspect",
            "--format",
            "{{json .Internal}}",
            manager.ingress_network_name,
        ),
        (
            "docker",
            "inspect",
            "--format",
            "{{json .HostConfig.NetworkMode}}",
            manager.container_name,
        ),
        (
            "docker",
            "inspect",
            "--format",
            "{{json .NetworkSettings}}",
            manager.container_name,
        ),
        (
            "docker",
            "inspect",
            "--format",
            "{{json .NetworkSettings}}",
            manager.db_container_name,
        ),
        (
            "docker",
            "inspect",
            "--format",
            "{{json .NetworkSettings}}",
            manager.ingress_container_name,
        ),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failure_mode", "message"),
    [
        ("internal_is_public", "network isolation"),
        ("ingress_is_internal", "network isolation"),
        ("wordpress_has_egress", "container network topology"),
        ("database_has_egress", "container network topology"),
        ("ingress_has_bootstrap", "container network topology"),
        ("ingress_is_publicly_bound", "published-port topology"),
        ("malformed_network_inspection", "network inspection was malformed"),
        ("failed_network_inspection", "network inspection failed"),
        (
            "stale_persistent_network_mode",
            "persistent network mode attestation failed",
        ),
        (
            "malformed_persistent_network_mode",
            "persistent network mode inspection was malformed",
        ),
        (
            "failed_persistent_network_mode_inspection",
            "persistent network mode inspection failed",
        ),
        ("failed_container_inspection", "container network inspection failed"),
        ("malformed_inspection", "container network inspection was malformed"),
        ("malformed_port_binding", "published-port inspection was malformed"),
    ],
)
async def test_runtime_network_seal_fails_closed_on_topology_mismatch(
    monkeypatch: pytest.MonkeyPatch,
    failure_mode: str,
    message: str,
) -> None:
    manager = _network_test_manager()

    async def fake_run(*args: str, **_kwargs: object) -> tuple[int, str, str]:
        if args[:3] == ("docker", "network", "inspect"):
            network = args[-1]
            if network == manager.internal_network_name:
                if failure_mode == "malformed_network_inspection":
                    return 0, "null", ""
                if failure_mode == "failed_network_inspection":
                    return 1, "", "synthetic inspect failure"
                return 0, "false" if failure_mode == "internal_is_public" else "true", ""
            return 0, "true" if failure_mode == "ingress_is_internal" else "false", ""
        if args[:2] == ("docker", "inspect"):
            if args[3] == "{{json .HostConfig.NetworkMode}}":
                if failure_mode == "failed_persistent_network_mode_inspection":
                    return 1, "", "synthetic inspect failure"
                if failure_mode == "malformed_persistent_network_mode":
                    return 0, "null", ""
                mode = (
                    manager.bootstrap_network_name
                    if failure_mode == "stale_persistent_network_mode"
                    else manager.internal_network_name
                )
                return 0, json.dumps(mode), ""
            container = args[-1]
            if container == manager.container_name:
                if failure_mode == "failed_container_inspection":
                    return 1, "", "synthetic inspect failure"
                if failure_mode == "malformed_inspection":
                    return 0, "not-json", ""
                networks = {manager.internal_network_name}
                if failure_mode == "wordpress_has_egress":
                    networks.add(manager.bootstrap_network_name)
                return 0, _network_settings(networks, {"80/tcp": None}), ""
            if container == manager.db_container_name:
                networks = {manager.internal_network_name}
                if failure_mode == "database_has_egress":
                    networks.add(manager.ingress_network_name)
                return 0, _network_settings(networks, {"3306/tcp": None}), ""
            networks = {
                manager.internal_network_name,
                manager.ingress_network_name,
            }
            if failure_mode == "ingress_has_bootstrap":
                networks.add(manager.bootstrap_network_name)
            host_ip = (
                "0.0.0.0"
                if failure_mode == "ingress_is_publicly_bound"
                else "127.0.0.1"
            )
            return 0, _network_settings(
                networks,
                {
                    "80/tcp": (
                        {"HostIp": host_ip, "HostPort": "8199"}
                        if failure_mode == "malformed_port_binding"
                        else [{"HostIp": host_ip, "HostPort": "8199"}]
                    )
                },
            ), ""
        return 0, "", ""

    monkeypatch.setattr(sandbox_module, "_run", fake_run)

    with pytest.raises(RuntimeError, match=message):
        await manager._seal_runtime_network()


@pytest.mark.asyncio
@pytest.mark.parametrize("failed_command", ["disconnect", "rm"])
async def test_runtime_network_seal_fails_closed_when_egress_removal_fails(
    monkeypatch: pytest.MonkeyPatch,
    failed_command: str,
) -> None:
    manager = _network_test_manager()

    async def fake_run(*args: str, **_kwargs: object) -> tuple[int, str, str]:
        if args[:3] == ("docker", "network", failed_command):
            raise RuntimeError("synthetic Docker failure")
        return 0, "", ""

    monkeypatch.setattr(sandbox_module, "_run", fake_run)

    with pytest.raises(RuntimeError, match="synthetic Docker failure"):
        await manager._seal_runtime_network()


@pytest.mark.asyncio
async def test_boot_seal_failure_tears_down_partial_project(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager = _manager()
    workdir = tmp_path / "sandbox-workdir"
    workdir.mkdir()
    calls: list[tuple[str, ...]] = []

    async def fake_run(*args: str, **_kwargs: object) -> tuple[int, str, str]:
        calls.append(args)
        return 0, "", ""

    async def no_op() -> None:
        return None

    async def fail_seal() -> None:
        raise RuntimeError("synthetic isolation failure")

    monkeypatch.setattr(sandbox_module, "_alloc_port", lambda: 8199)
    monkeypatch.setattr(
        sandbox_module.tempfile,
        "mkdtemp",
        lambda **_kwargs: str(workdir),
    )
    monkeypatch.setattr(sandbox_module, "_run", fake_run)
    monkeypatch.setattr(manager, "_wait_for_wordpress", no_op)
    monkeypatch.setattr(manager, "_ensure_wp_installed", no_op)
    monkeypatch.setattr(manager, "_seal_runtime_network", fail_seal)
    monkeypatch.setattr(manager, "_remove_actor_receipt_plugin", no_op)

    with pytest.raises(RuntimeError, match="synthetic isolation failure"):
        async with manager:
            pytest.fail("an unsealed sandbox must never be yielded")

    assert manager._booted is False
    assert manager.wp_cli is None
    assert not workdir.exists()
    assert any(call[:2] == ("docker", "compose") and "down" in call for call in calls)
    assert any(call[:3] == ("docker", "network", "rm") for call in calls)


@pytest.mark.asyncio
async def test_direct_boot_cancellation_tears_down_partial_project(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager = _manager()
    workdir = tmp_path / "sandbox-workdir"
    workdir.mkdir()
    calls: list[tuple[str, ...]] = []

    async def fake_run(*args: str, **_kwargs: object) -> tuple[int, str, str]:
        calls.append(args)
        return 0, "", ""

    async def no_op() -> None:
        return None

    async def cancel_seal() -> None:
        raise asyncio.CancelledError

    monkeypatch.setattr(sandbox_module, "_alloc_port", lambda: 8199)
    monkeypatch.setattr(
        sandbox_module.tempfile,
        "mkdtemp",
        lambda **_kwargs: str(workdir),
    )
    monkeypatch.setattr(sandbox_module, "_run", fake_run)
    monkeypatch.setattr(manager, "_wait_for_wordpress", no_op)
    monkeypatch.setattr(manager, "_ensure_wp_installed", no_op)
    monkeypatch.setattr(manager, "_seal_runtime_network", cancel_seal)
    monkeypatch.setattr(manager, "_remove_actor_receipt_plugin", no_op)

    with pytest.raises(asyncio.CancelledError):
        await manager.boot()

    assert not workdir.exists()
    assert manager.project == ""
    assert any(call[:2] == ("docker", "compose") and "down" in call for call in calls)
    assert any(call[:3] == ("docker", "network", "rm") for call in calls)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failed_command", "retains_retry_state"),
    [
        ("disconnect", False),
        ("compose", True),
        ("network_rm", True),
        ("network_attestation", True),
    ],
)
async def test_teardown_attempts_all_cleanup_and_preserves_retry_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    failed_command: str,
    retains_retry_state: bool,
) -> None:
    manager = _network_test_manager()
    workdir = tmp_path / "sandbox-workdir"
    workdir.mkdir()
    manager.workdir = workdir
    bootstrap_network_name = manager.bootstrap_network_name
    calls: list[tuple[str, ...]] = []
    failed_once = False

    async def fake_run(*args: str, **_kwargs: object) -> tuple[int, str, str]:
        nonlocal failed_once
        calls.append(args)
        should_fail = (
            (
                failed_command == "disconnect"
                and args[:3] == ("docker", "network", "disconnect")
            )
            or (
                failed_command == "compose"
                and args[:2] == ("docker", "compose")
            )
            or (
                failed_command == "network_rm"
                and args[:3] == ("docker", "network", "rm")
            )
            or (
                failed_command == "network_attestation"
                and args[:3] == ("docker", "network", "ls")
            )
        )
        if should_fail and not failed_once:
            failed_once = True
            raise RuntimeError(f"synthetic {failed_command} failure")
        return 0, "", ""

    monkeypatch.setattr(sandbox_module, "_run", fake_run)

    with pytest.raises(RuntimeError, match=f"synthetic {failed_command} failure"):
        await manager.teardown()

    assert any(call[:2] == ("docker", "compose") and "down" in call for call in calls)
    assert ("docker", "network", "rm", bootstrap_network_name) in calls
    assert manager._booted is False
    assert manager.wp_cli is None
    if retains_retry_state:
        assert workdir.exists()
        assert manager.port == 8199
        assert manager.project == "squadrone-deadbeef"
        assert manager.workdir == workdir
        assert manager.container_name == "squadrone-deadbeef-wordpress-1"
        assert manager.target_url == ""
    else:
        assert not workdir.exists()
        assert manager.port == 0
        assert manager.project == ""
        assert manager.workdir is None
        assert manager.container_name == ""
        assert manager.target_url == ""

    calls_before_retry = len(calls)
    await manager.teardown()
    if retains_retry_state:
        assert len(calls) > calls_before_retry
        assert not workdir.exists()
        assert manager.project == ""
        assert manager.workdir is None
        assert manager.container_name == ""
    else:
        assert len(calls) == calls_before_retry


@pytest.mark.asyncio
async def test_fallback_core_install_runs_as_wordpress_web_identity(monkeypatch):
    calls: list[tuple[str, ...]] = []

    async def fake_run(*args: str, **_kwargs) -> tuple[int, str, str]:
        calls.append(args)
        if "is-installed" in args:
            return 1, "", "not installed"
        return 0, "", ""

    manager = _manager()
    monkeypatch.setattr(sandbox_module, "_run", fake_run)

    await manager._ensure_wp_installed()

    assert not any("db" in args and "check" in args for args in calls)
    install = next(args for args in calls if "install" in args)
    assert install[:6] == (
        "docker",
        "exec",
        "--user",
        "www-data",
        "test-project-wordpress-1",
        "wp",
    )
    assert "--allow-root" not in install


@pytest.mark.asyncio
async def test_install_and_activation_run_as_wordpress_web_identity(monkeypatch):
    events: list[tuple] = []

    class FakeWPCli:
        async def role_capabilities(self) -> dict[str, frozenset[str]]:
            events.append(("role_capabilities",))
            return {
                "subscriber": frozenset({"read"}),
                "contributor": frozenset({"read", "edit_posts"}),
                "author": frozenset({"read", "edit_posts", "publish_posts"}),
                "editor": frozenset({"read", "edit_others_posts"}),
                "administrator": frozenset({"read", "manage_options"}),
            }

        async def install_plugin(
            self,
            zip_path: str,
            *,
            user: str | None = None,
            wp_user: str | None = None,
        ) -> None:
            events.append(("install", zip_path, user, wp_user))

    async def fake_run(*args: str, **kwargs) -> tuple[int, str, str]:
        events.append(("docker", args, kwargs))
        return 0, "", ""

    async def fake_admin_init() -> None:
        events.append(("admin_init",))

    manager = _manager()
    manager._pre_plugin_role_capabilities = None
    manager.wp_cli = FakeWPCli()  # type: ignore[assignment]
    monkeypatch.setattr(sandbox_module, "_run", fake_run)
    monkeypatch.setattr(manager, "_fire_admin_init", fake_admin_init)

    await manager.install_plugin("/host/a surprising archive.zip", "demo-plugin")

    assert events == [
        ("role_capabilities",),
        (
            "docker",
            (
                "docker",
                "cp",
                "/host/a surprising archive.zip",
                "test-project-wordpress-1:/tmp/squadrone-demo-plugin.zip",
            ),
            {},
        ),
        (
            "install",
            "/tmp/squadrone-demo-plugin.zip",
            "www-data",
            "admin@example.test",
        ),
        ("admin_init",),
    ]
    assert all("chmod" not in event[1] for event in events if event[0] == "docker")


@pytest.mark.asyncio
async def test_wp_cli_web_identity_uses_docker_user_without_allow_root(monkeypatch):
    command: tuple[str, ...] = ()

    class FakeProcess:
        returncode = 0

        async def communicate(self):
            return b"installed", b""

    async def fake_create_subprocess_exec(*args, **kwargs):
        nonlocal command
        command = args
        return FakeProcess()

    monkeypatch.setattr(
        wp_cli_module.asyncio, "create_subprocess_exec", fake_create_subprocess_exec
    )

    await WPCli("wordpress-container").install_plugin(
        "/tmp/squadrone-demo-plugin.zip",
        user="www-data",
        wp_user="sandbox-owner@example.test",
    )

    assert command == (
        "docker",
        "exec",
        "--user",
        "www-data",
        "wordpress-container",
        "wp",
        "--user=sandbox-owner@example.test",
        "plugin",
        "install",
        "/tmp/squadrone-demo-plugin.zip",
        "--activate",
        "--force",
    )


@pytest.mark.asyncio
async def test_wp_cli_default_commands_still_run_as_root(monkeypatch):
    command: tuple[str, ...] = ()

    class FakeProcess:
        returncode = 0

        async def communicate(self):
            return b"value", b""

    async def fake_create_subprocess_exec(*args, **kwargs):
        nonlocal command
        command = args
        return FakeProcess()

    monkeypatch.setattr(
        wp_cli_module.asyncio, "create_subprocess_exec", fake_create_subprocess_exec
    )

    await WPCli("wordpress-container").get_option("siteurl")

    assert command == (
        "docker",
        "exec",
        "wordpress-container",
        "wp",
        "--allow-root",
        "option",
        "get",
        "siteurl",
    )


@pytest.mark.asyncio
async def test_wp_cli_reconciles_credentials_over_private_stdin(monkeypatch):
    command: tuple[str, ...] = ()
    private_input = b""

    class FakeProcess:
        returncode = 0

        async def communicate(self, supplied_input):
            nonlocal private_input
            private_input = supplied_input
            return b'SQUADRONE_RECONCILED_USERS={"roles":{},"users":{}}\n', b""

    async def fake_create_subprocess_exec(*args, **kwargs):
        nonlocal command
        command = args
        assert kwargs["stdin"] is asyncio.subprocess.PIPE
        return FakeProcess()

    monkeypatch.setattr(
        wp_cli_module.asyncio, "create_subprocess_exec", fake_create_subprocess_exec
    )
    secret = "manifest-only-secret"

    await WPCli("wordpress-container").reconcile_users(
        [
            {
                "login": "subscriber_user",
                "password": secret,
                "role": "subscriber",
                "email": "subscriber_user@test.local",
                "forbidden_core_caps": ["manage_options"],
            }
        ]
    )

    assert command[:4] == ("docker", "exec", "-i", "wordpress-container")
    assert secret not in " ".join(command)
    assert secret in private_input.decode("utf-8")
    reconciliation_program = command[-1]
    assert reconciliation_program.count("foreach ($expected as $account)") == 3
    assert reconciliation_program.rindex("wp_check_password") > (
        reconciliation_program.index("wp_authenticate")
    )
    assert "unexpected_effective_core_caps" in reconciliation_program
    assert (
        "$role !== 'administrator' && count($individual_excess) > 0"
        in reconciliation_program
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "unsafe_slug",
    [
        "",
        "../other-plugin",
        "demo/other",
        "-R",
        ".hidden",
        "Demo-Plugin",
        "demo plugin",
    ],
)
async def test_install_rejects_unsafe_slug_before_any_container_action(
    monkeypatch, unsafe_slug
):
    called = False

    async def fake_run(*args: str, **kwargs) -> tuple[int, str, str]:
        nonlocal called
        called = True
        return 0, "", ""

    manager = _manager()
    manager.wp_cli = object()  # type: ignore[assignment]
    monkeypatch.setattr(sandbox_module, "_run", fake_run)

    with pytest.raises(ValueError, match="plugin slug"):
        await manager.install_plugin("/host/plugin.zip", unsafe_slug)

    assert called is False
