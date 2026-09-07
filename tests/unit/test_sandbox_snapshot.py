from __future__ import annotations

from pathlib import Path

import pytest
import squadrone.services.sandbox as sandbox_module

from squadrone.schemas import SandboxConfig
from squadrone.services.sandbox import SandboxManager


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
    manager._booted = True
    manager.project = "test-project"
    manager.container_name = "test-project-wordpress-1"
    return manager


@pytest.mark.asyncio
async def test_snapshot_fails_closed_when_database_dump_fails(monkeypatch):
    async def fake_run(*args, **kwargs):
        return 1, "", "database unavailable"

    monkeypatch.setattr(sandbox_module, "_run", fake_run)

    with pytest.raises(RuntimeError, match="database dump failed"):
        await _manager().snapshot()


@pytest.mark.asyncio
async def test_restore_rejects_incomplete_snapshot(tmp_path):
    with pytest.raises(RuntimeError, match="no database dump"):
        await _manager().restore(tmp_path)


@pytest.mark.asyncio
async def test_snapshot_archives_complete_wordpress_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    snap_dir = tmp_path / "snapshot"
    calls: list[tuple[tuple[str, ...], dict[str, object]]] = []

    def fake_mkdtemp(*, prefix: str) -> str:
        assert prefix == "test-project-snap-"
        snap_dir.mkdir()
        return str(snap_dir)

    async def fake_run(*args: str, **kwargs: object) -> tuple[int, str, str]:
        calls.append((args, kwargs))
        if args[:4] == (
            "docker",
            "exec",
            "test-project-db-1",
            "mariadb-dump",
        ):
            return 0, "-- complete database dump\n", ""
        if args[:2] == ("docker", "cp"):
            Path(args[3]).write_bytes(b"complete-wordpress-root-archive")
        return 0, "", ""

    monkeypatch.setattr(sandbox_module.tempfile, "mkdtemp", fake_mkdtemp)
    monkeypatch.setattr(sandbox_module, "_run", fake_run)

    manager = _manager()
    result = await manager.snapshot()

    assert result == snap_dir
    assert snap_dir in manager._snapshot_dirs
    assert (snap_dir / "db.sql").read_text() == "-- complete database dump\n"
    assert (snap_dir / "wordpress-root.tar.gz").read_bytes()
    assert (snap_dir / "db.sql").stat().st_mode & 0o777 == 0o600
    assert (snap_dir / "wordpress-root.tar.gz").stat().st_mode & 0o777 == 0o600
    dump_call = next(
        args
        for args, _kwargs in calls
        if args[:4]
        == (
            "docker",
            "exec",
            "test-project-db-1",
            "mariadb-dump",
        )
    )
    assert dump_call[4:6] == sandbox_module._SANDBOX_MARIADB_CLIENT_AUTH
    assert dump_call[-1] == sandbox_module._SANDBOX_DATABASE_NAME
    archive_call = next(
        args
        for args, _kwargs in calls
        if args[:7]
        == (
            "docker",
            "exec",
            "--user",
            "root",
            "test-project-wordpress-1",
            "sh",
            "-c",
        )
    )
    archive_command = archive_call[7]
    archive_path = archive_call[9]
    assert sandbox_module._CONTAINER_SNAPSHOT_ARCHIVE_RE.fullmatch(archive_path)
    assert 'umask 077' in archive_command
    assert 'tar czf "$archive"' in archive_command
    assert 'chmod 0600 "$archive"' in archive_command
    assert "-C /var/www/html ." in archive_command
    assert "-C /var/www/html wp-content" not in archive_command
    assert "/var/lib/squadrone" not in archive_command
    assert any(
        args
        == (
            "docker",
            "cp",
            f"test-project-wordpress-1:{archive_path}",
            str(snap_dir / "wordpress-root.tar.gz"),
        )
        for args, _kwargs in calls
    )
    assert calls[-1][0][-3:] == ("-f", "--", archive_path)


@pytest.mark.asyncio
async def test_snapshot_removes_partial_host_snapshot_when_root_archive_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    snap_dir = tmp_path / "partial-snapshot"

    def fake_mkdtemp(*, prefix: str) -> str:
        assert prefix == "test-project-snap-"
        snap_dir.mkdir()
        return str(snap_dir)

    calls: list[tuple[str, ...]] = []

    async def fake_run(*args: str, **_kwargs: object) -> tuple[int, str, str]:
        calls.append(args)
        if args[:4] == (
            "docker",
            "exec",
            "test-project-db-1",
            "mariadb-dump",
        ):
            return 0, "-- complete database dump\n", ""
        if args[:2] == ("docker", "exec") and "rm" in args:
            return 0, "", ""
        raise RuntimeError("root archive failed")

    monkeypatch.setattr(sandbox_module.tempfile, "mkdtemp", fake_mkdtemp)
    monkeypatch.setattr(sandbox_module, "_run", fake_run)

    with pytest.raises(RuntimeError, match="root archive failed"):
        await _manager().snapshot()

    assert not snap_dir.exists()
    assert calls[-1][-4:] == ("rm", "-f", "--", calls[-1][-1])
    assert sandbox_module._CONTAINER_SNAPSHOT_ARCHIVE_RE.fullmatch(calls[-1][-1])


@pytest.mark.asyncio
async def test_restore_replaces_complete_webroot_and_removes_stale_root_entry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    (tmp_path / "db.sql").write_text("-- database snapshot\n")
    (tmp_path / "wordpress-root.tar.gz").write_bytes(b"root archive")
    events: list[tuple[str, tuple[str, ...]]] = []
    root_entries = {".htaccess", "wp-config.php", "wp-content", "stale-root.php"}

    class FakeImportProcess:
        returncode = 0

        async def communicate(self, payload: bytes) -> tuple[bytes, bytes]:
            assert payload == b"-- database snapshot\n"
            return b"", b""

    async def fake_create_subprocess_exec(
        *args: str,
        **_kwargs: object,
    ) -> FakeImportProcess:
        events.append(("database_import", args))
        return FakeImportProcess()

    async def fake_run(*args: str, **_kwargs: object) -> tuple[int, str, str]:
        events.append(("run", args))
        if args[:7] == (
            "docker",
            "exec",
            "--user",
            "root",
            "test-project-wordpress-1",
            "sh",
            "-c",
        ):
            command = args[7]
            if "find /var/www/html" in command:
                assert (
                    "find /var/www/html -mindepth 1 -maxdepth 1 "
                    "-exec rm -rf -- {} +"
                ) in command
                assert command.index("find /var/www/html") < command.index("tar xzf")
                root_entries.clear()
                root_entries.update({".htaccess", "wp-config.php", "wp-content"})
        return 0, "", ""

    monkeypatch.setattr(
        sandbox_module.asyncio,
        "create_subprocess_exec",
        fake_create_subprocess_exec,
    )
    monkeypatch.setattr(sandbox_module, "_run", fake_run)

    await _manager().restore(tmp_path)

    assert "stale-root.php" not in root_entries
    assert root_entries == {".htaccess", "wp-config.php", "wp-content"}
    staged_path = events[0][1][3].split(":", 1)[1]
    assert sandbox_module._CONTAINER_SNAPSHOT_ARCHIVE_RE.fullmatch(staged_path)
    assert events[0] == (
        "run",
        (
            "docker",
            "cp",
            str(tmp_path / "wordpress-root.tar.gz"),
            f"test-project-wordpress-1:{staged_path}",
        ),
    )
    assert "chmod 0600" in events[1][1][7]
    assert "tar tzf" in events[1][1][7]
    assert events[2][0] == "database_import"
    assert events[2][1][5:] == sandbox_module._SANDBOX_MARIADB_CLIENT_AUTH
    assert events[3][0] == "run"
    assert "/var/lib/squadrone" not in events[3][1][7]
    assert events[4][0] == "run"
    assert events[4][1][-3:] == ("-f", "--", staged_path)


@pytest.mark.asyncio
async def test_restore_rejects_missing_root_archive_before_database_import(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    (tmp_path / "db.sql").write_text("-- database snapshot\n")

    async def fail_if_called(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("database import started before archive validation")

    monkeypatch.setattr(
        sandbox_module.asyncio,
        "create_subprocess_exec",
        fail_if_called,
    )

    with pytest.raises(RuntimeError, match="no WordPress root archive"):
        await _manager().restore(tmp_path)


@pytest.mark.asyncio
async def test_restore_import_failure_removes_root_only_staging_archive(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    (tmp_path / "db.sql").write_text("-- database snapshot\n")
    (tmp_path / "wordpress-root.tar.gz").write_bytes(b"root archive")
    calls: list[tuple[str, ...]] = []

    class FailedImportProcess:
        returncode = 1

        async def communicate(self, _payload: bytes) -> tuple[bytes, bytes]:
            return b"", b"authentication failed"

    async def fake_create_subprocess_exec(
        *_args: str,
        **_kwargs: object,
    ) -> FailedImportProcess:
        return FailedImportProcess()

    async def fake_run(*args: str, **_kwargs: object) -> tuple[int, str, str]:
        calls.append(args)
        return 0, "", ""

    monkeypatch.setattr(
        sandbox_module.asyncio,
        "create_subprocess_exec",
        fake_create_subprocess_exec,
    )
    monkeypatch.setattr(sandbox_module, "_run", fake_run)

    with pytest.raises(RuntimeError, match="database import failed"):
        await _manager().restore(tmp_path)

    staged_path = calls[0][3].split(":", 1)[1]
    assert sandbox_module._CONTAINER_SNAPSHOT_ARCHIVE_RE.fullmatch(staged_path)
    assert calls[-1][-3:] == ("-f", "--", staged_path)


@pytest.mark.asyncio
async def test_teardown_removes_every_tracked_snapshot_directory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager = _manager()
    retained = tmp_path / "retained-after-restore-failure"
    retained.mkdir()
    (retained / "wp-config-secret.txt").write_text("sensitive")
    already_removed = tmp_path / "already-removed"
    manager._snapshot_dirs.update({retained, already_removed})

    async def fake_run(*_args: str, **_kwargs: object) -> tuple[int, str, str]:
        return 0, "", ""

    monkeypatch.setattr(sandbox_module, "_run", fake_run)

    await manager.teardown()

    assert not retained.exists()
    assert not already_removed.exists()
    assert manager._snapshot_dirs == set()
