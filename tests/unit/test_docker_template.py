from __future__ import annotations

from importlib.resources import files

import yaml
from jinja2 import Template


def _render_compose(**images: str) -> dict:
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
        bootstrap_network_name="squadrone-test-bootstrap",
    )
    return yaml.safe_load(rendered)


def _render_images(**images: str) -> tuple[str, str, str]:
    compose = _render_compose(**images)
    return (
        compose["services"]["wordpress"]["image"],
        compose["services"]["db"]["image"],
        compose["services"]["ingress"]["image"],
    )


def test_compose_image_variables_are_used() -> None:
    assert _render_images(
        wordpress_image="wordpress@sha256:wordpress-digest",
        db_image="mariadb@sha256:mariadb-digest",
    ) == (
        "wordpress@sha256:wordpress-digest",
        "mariadb@sha256:mariadb-digest",
        "wordpress@sha256:wordpress-digest",
    )


def test_compose_image_variables_remain_compatible_with_loaded_old_processes() -> None:
    assert _render_images() == (
        "wordpress:latest",
        "mariadb:10.11",
        "wordpress:latest",
    )


def test_compose_isolates_targets_behind_fixed_local_ingress() -> None:
    compose = _render_compose()
    services = compose["services"]

    assert compose["networks"] == {
        "default": {"internal": True},
        "ingress": None,
        "bootstrap": {
            "external": True,
            "name": "squadrone-test-bootstrap",
        },
    }
    assert services["db"]["networks"] == ["default"]
    assert services["wordpress"]["networks"] == {
        "default": {"priority": 1000},
        "bootstrap": {"gw_priority": 1000},
    }
    assert "ports" not in services["wordpress"]
    assert services["ingress"]["networks"] == ["default", "ingress"]
    assert services["ingress"]["ports"] == ["127.0.0.1:8080:80"]
    assert "volumes" not in services["ingress"]
    assert "environment" not in services["ingress"]
    assert services["ingress"]["entrypoint"] == ["/bin/sh", "-ec"]
    assert services["ingress"]["image"] == services["wordpress"]["image"]

    command = services["ingress"]["command"][0]
    printed_directives = []
    for line in command.splitlines():
        token = line.strip().removesuffix("\\").strip()
        if token.startswith("'") and token.endswith("'"):
            printed_directives.append(token[1:-1])
    assert printed_directives == [
        "ServerName localhost",
        "<VirtualHost *:80>",
        "  ServerName localhost",
        "  ProxyRequests Off",
        "  ProxyPreserveHost On",
        "  ProxyAddHeaders Off",
        "  ProxyPassInterpolateEnv Off",
        "  UseCanonicalName Off",
        "  AllowEncodedSlashes NoDecode",
        '  ProxyPass "/" "http://wordpress:80/" nocanon',
        '  ProxyPassReverse "/" "http://wordpress:80/"',
        "</VirtualHost>",
    ]
    assert "a2dissite 000-default >/dev/null" in command
    assert command.count("ProxyPass ") == 1
    assert command.count("ProxyPassReverse ") == 1
    assert "${" not in command
