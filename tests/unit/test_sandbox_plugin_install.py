from __future__ import annotations

import pytest

import squadrone.services.sandbox as sandbox_module
import squadrone.services.wp_cli as wp_cli_module
from squadrone.schemas import SandboxConfig
from squadrone.services.sandbox import SandboxManager
from squadrone.services.wp_cli import WPCli


def _manager() -> SandboxManager:
    manager = SandboxManager(
        SandboxConfig(
            wordpress_image="wordpress:latest",
            db_image="mariadb:10.11",
            wp_admin_user="admin",
            wp_admin_pass="password",
            wp_admin_email="admin@example.test",
            wp_url="http://localhost:8080",
        )
    )
    manager.container_name = "test-project-wordpress-1"
    return manager


@pytest.mark.asyncio
async def test_install_and_activation_run_as_wordpress_web_identity(monkeypatch):
    events: list[tuple] = []

    class FakeWPCli:
        async def install_plugin(
            self, zip_path: str, *, user: str | None = None
        ) -> None:
            events.append(("install", zip_path, user))

    async def fake_run(*args: str, **kwargs) -> tuple[int, str, str]:
        events.append(("docker", args, kwargs))
        return 0, "", ""

    async def fake_admin_init() -> None:
        events.append(("admin_init",))

    manager = _manager()
    manager.wp_cli = FakeWPCli()  # type: ignore[assignment]
    monkeypatch.setattr(sandbox_module, "_run", fake_run)
    monkeypatch.setattr(manager, "_fire_admin_init", fake_admin_init)

    await manager.install_plugin("/host/a surprising archive.zip", "demo-plugin")

    assert events == [
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
        ("install", "/tmp/squadrone-demo-plugin.zip", "www-data"),
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
        "/tmp/squadrone-demo-plugin.zip", user="www-data"
    )

    assert command == (
        "docker",
        "exec",
        "--user",
        "www-data",
        "wordpress-container",
        "wp",
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
