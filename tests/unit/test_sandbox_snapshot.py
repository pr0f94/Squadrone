from __future__ import annotations

import pytest
import squadrone.services.sandbox as sandbox_module

from squadrone.schemas import SandboxConfig
from squadrone.services.sandbox import SandboxManager


def _manager() -> SandboxManager:
    manager = SandboxManager(SandboxConfig(
        wordpress_image="wordpress:latest",
        db_image="mariadb:10.11",
        wp_admin_user="admin",
        wp_admin_pass="password",
        wp_admin_email="admin@example.test",
        wp_url="http://localhost:8080",
    ))
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
