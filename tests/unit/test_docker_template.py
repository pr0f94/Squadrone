from __future__ import annotations

from importlib.resources import files

import yaml
from jinja2 import Template


def _render_images(**images: str) -> tuple[str, str]:
    template = Template(
        (files("squadrone.docker") / "docker-compose.yml.j2").read_text()
    )
    rendered = template.render(
        **images,
        port=8080,
        wp_url="http://localhost:8080",
        wp_title="test",
        wp_admin_user="admin",
        wp_admin_pass="password",
        wp_admin_email="admin@example.test",
        database_name="wordpress",
        database_user="wordpress",
        database_password="password",
        enable_http_ssrf=False,
        enable_local_resource_ssrf=False,
        ssrf_local_host_dir="",
        enable_php_include_oracle=False,
        enable_php_object_gadget_oracle=False,
        php_object_gadget_directory_constants=(),
        php_include_host_dir="",
    )
    compose = yaml.safe_load(rendered)
    return (
        compose["services"]["wordpress"]["image"],
        compose["services"]["db"]["image"],
    )


def test_compose_image_variables_are_used() -> None:
    assert _render_images(
        wordpress_image="wordpress@sha256:wordpress-digest",
        db_image="mariadb@sha256:mariadb-digest",
    ) == (
        "wordpress@sha256:wordpress-digest",
        "mariadb@sha256:mariadb-digest",
    )


def test_compose_image_variables_remain_compatible_with_loaded_old_processes() -> None:
    assert _render_images() == ("wordpress:latest", "mariadb:10.11")
