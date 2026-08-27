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
async def test_boot_prepares_upload_path_before_becoming_ready(
    monkeypatch, tmp_path
):
    events: list[str] = []
    workdir = tmp_path / "sandbox-workdir"
    workdir.mkdir()

    async def fake_run(*_args: str, **_kwargs) -> tuple[int, str, str]:
        events.append("compose")
        return 0, "", ""

    async def fake_wait() -> None:
        events.append("wait")

    async def fake_ensure() -> None:
        events.append("ensure")

    async def fake_upload_path() -> None:
        assert manager._booted is False
        events.append("upload_path")

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
    monkeypatch.setattr(manager, "_ensure_wp_upload_path", fake_upload_path)

    await manager.boot()

    assert events == ["compose", "wait", "ensure", "upload_path"]
    assert manager._booted is True


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
