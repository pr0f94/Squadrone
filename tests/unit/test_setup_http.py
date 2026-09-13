from __future__ import annotations

import pytest

from squadrone.schemas import SandboxConfig
from squadrone.services.sandbox import SandboxManager
from squadrone.services.setup_http import SetupHttpContext


def _manager() -> SandboxManager:
    return SandboxManager(
        SandboxConfig(
            wordpress_image="wordpress:latest",
            db_image="mariadb:10.11",
            wp_admin_user="admin",
            wp_admin_pass="password",
            wp_admin_email="admin@example.test",
        )
    )


def test_setup_http_context_separates_connect_origin_from_canonical_host() -> None:
    context = SetupHttpContext.from_wordpress_origins(
        internal_connect_origin="http://127.0.0.1:80",
        canonical_wordpress_origin="http://localhost:8100",
    )

    assert context.internal_connect_origin == "http://127.0.0.1:80"
    assert context.canonical_host_header == "localhost:8100"
    assert not hasattr(context, "canonical_wordpress_origin")


@pytest.mark.parametrize(
    ("connect_origin", "canonical_origin"),
    [
        ("https://127.0.0.1:80", "http://localhost:8100"),
        ("http://example.test:80", "http://localhost:8100"),
        ("http://127.0.0.1:80/path", "http://localhost:8100"),
        ("http://127.0.0.1:80", "http://host.docker.internal:8100"),
        ("http://127.0.0.1:80", "http://user@localhost:8100"),
        ("http://127.0.0.1:80", "http://localhost:8100/path"),
    ],
)
def test_setup_http_context_rejects_non_loopback_or_non_origin_values(
    connect_origin: str,
    canonical_origin: str,
) -> None:
    with pytest.raises(ValueError):
        SetupHttpContext.from_wordpress_origins(
            internal_connect_origin=connect_origin,
            canonical_wordpress_origin=canonical_origin,
        )


def test_sandbox_exposes_only_internal_origin_and_canonical_host_authority() -> None:
    manager = _manager()
    manager.target_url = "http://localhost:8199"

    context = manager.setup_http_context()

    assert context == SetupHttpContext(
        internal_connect_origin=SandboxManager.INTERNAL_WORDPRESS_ORIGIN,
        canonical_host_header="localhost:8199",
    )


def test_sandbox_setup_http_context_requires_allocated_target() -> None:
    with pytest.raises(RuntimeError, match="target URL is unavailable"):
        _manager().setup_http_context()
