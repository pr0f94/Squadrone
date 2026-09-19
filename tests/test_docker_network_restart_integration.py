from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import uuid
from importlib.resources import files
from pathlib import Path

import pytest
import yaml  # type: ignore[import-untyped]
from jinja2 import Template

_RUN_ENGINE_TEST = os.environ.get("SQUADRONE_RUN_DOCKER_ENGINE_TESTS") == "1"

pytestmark = pytest.mark.skipif(
    not _RUN_ENGINE_TEST,
    reason=(
        "set SQUADRONE_RUN_DOCKER_ENGINE_TESTS=1 to run the real Docker "
        "network regression"
    ),
)


def _docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ("docker", *args),
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if check and result.returncode != 0:
        pytest.fail(
            f"Docker command failed ({' '.join(args)}): "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )
    return result


def _version(value: str) -> tuple[int, int, int]:
    match = re.search(r"(\d+)\.(\d+)\.(\d+)", value)
    if match is None:
        pytest.fail(f"Docker returned an unrecognised version: {value!r}")
    major, minor, patch = (int(part) for part in match.groups())
    return major, minor, patch


def _render_probe_compose(*, image: str, bootstrap_network: str) -> str:
    template = Template(
        (files("squadrone.docker") / "docker-compose.yml.j2").read_text()
    )
    rendered = template.render(
        wordpress_image=image,
        db_image="mariadb:10.11",
        port=8080,
        wp_url="http://localhost:8080",
        wp_title="Docker network regression",
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
        bootstrap_network_name=bootstrap_network,
    )
    compose = yaml.safe_load(rendered)
    wordpress = compose["services"]["wordpress"]

    # Keep the shipped network declaration while replacing application startup
    # with a passive local process. This regression must never pull dependencies
    # or contact an external service.
    wordpress["image"] = image
    wordpress["entrypoint"] = ["/bin/sh", "-c"]
    wordpress["command"] = ["while :; do sleep 60; done"]
    for key in ("depends_on", "environment", "volumes", "tmpfs"):
        wordpress.pop(key, None)
    compose["services"] = {"wordpress": wordpress}
    compose["networks"] = {
        "default": compose["networks"]["default"],
        "bootstrap": compose["networks"]["bootstrap"],
    }
    compose.pop("volumes", None)
    return yaml.safe_dump(compose, sort_keys=False)


def _container_inspect(container: str) -> dict[str, object]:
    result = _docker("inspect", container)
    values = json.loads(result.stdout)
    assert isinstance(values, list) and len(values) == 1
    assert isinstance(values[0], dict)
    return values[0]


def _container_networks(container: str) -> set[str]:
    inspected = _container_inspect(container)
    network_settings = inspected["NetworkSettings"]
    assert isinstance(network_settings, dict)
    networks = network_settings["Networks"]
    assert isinstance(networks, dict)
    return set(networks)


def _container_network_mode(container: str) -> str:
    inspected = _container_inspect(container)
    host_config = inspected["HostConfig"]
    assert isinstance(host_config, dict)
    mode = host_config["NetworkMode"]
    assert isinstance(mode, str)
    return mode


def _network_details(network: str) -> dict[str, object]:
    result = _docker("network", "inspect", network)
    values = json.loads(result.stdout)
    assert isinstance(values, list) and len(values) == 1
    assert isinstance(values[0], dict)
    return values[0]


def _network_gateway(network: str) -> str:
    inspected = _network_details(network)
    ipam = inspected["IPAM"]
    assert isinstance(ipam, dict)
    configs = ipam["Config"]
    assert isinstance(configs, list) and configs
    config = configs[0]
    assert isinstance(config, dict)
    gateway = config["Gateway"]
    assert isinstance(gateway, str)
    return gateway


def _default_ipv4_routes(container: str) -> tuple[tuple[str, str], ...]:
    result = _docker("exec", container, "cat", "/proc/net/route")
    routes: list[tuple[str, str]] = []
    for line in result.stdout.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 4 or fields[1] != "00000000":
            continue
        gateway_bytes = bytes.fromhex(fields[2])[::-1]
        routes.append((fields[0], str(ipaddress.IPv4Address(gateway_bytes))))
    return tuple(routes)


def test_compose_network_survives_bootstrap_removal_and_restart(
    tmp_path: Path,
) -> None:
    compose_version = _version(_docker("compose", "version", "--short").stdout)
    engine_version = _version(
        _docker("version", "--format", "{{.Server.Version}}").stdout
    )
    assert compose_version >= (2, 33, 1)
    assert engine_version >= (28, 0, 0)

    image = os.environ.get("SQUADRONE_DOCKER_ENGINE_TEST_IMAGE", "wordpress:latest")
    if _docker("image", "inspect", image, check=False).returncode != 0:
        pytest.fail(
            f"the opt-in Docker regression requires local image {image!r}; "
            "it never pulls images"
        )

    suffix = uuid.uuid4().hex[:10]
    project = f"squadrone-engine-test-{suffix}"
    container = f"{project}-wordpress-1"
    internal_network = f"{project}_default"
    bootstrap_network = f"{project}-bootstrap"
    compose_path = tmp_path / "docker-compose.yml"
    compose_path.write_text(
        _render_probe_compose(
            image=image,
            bootstrap_network=bootstrap_network,
        )
    )

    try:
        _docker("network", "create", "--driver", "bridge", bootstrap_network)
        _docker(
            "compose",
            "-p",
            project,
            "-f",
            str(compose_path),
            "up",
            "-d",
            "--no-deps",
            "--pull",
            "never",
            "wordpress",
        )

        assert _container_network_mode(container) == internal_network
        assert _container_networks(container) == {
            internal_network,
            bootstrap_network,
        }
        bootstrap_routes = _default_ipv4_routes(container)
        assert len(bootstrap_routes) == 1
        assert bootstrap_routes[0][1] == _network_gateway(bootstrap_network)

        _docker("network", "disconnect", bootstrap_network, container)
        _docker("network", "rm", bootstrap_network)

        assert _container_network_mode(container) == internal_network
        assert _container_networks(container) == {internal_network}
        assert _network_details(internal_network)["Internal"] is True
        assert _default_ipv4_routes(container) == ()

        _docker("restart", container)

        inspected = _container_inspect(container)
        state = inspected["State"]
        assert isinstance(state, dict)
        assert state["Running"] is True
        assert _container_network_mode(container) == internal_network
        assert _container_networks(container) == {internal_network}
        assert _default_ipv4_routes(container) == ()
    finally:
        _docker(
            "compose",
            "-p",
            project,
            "-f",
            str(compose_path),
            "down",
            "-v",
            "--remove-orphans",
            check=False,
        )
        _docker("rm", "-f", container, check=False)
        _docker("network", "rm", bootstrap_network, check=False)
        _docker("network", "rm", internal_network, check=False)

    assert _docker("inspect", container, check=False).returncode != 0
    assert _docker("network", "inspect", bootstrap_network, check=False).returncode != 0
    assert _docker("network", "inspect", internal_network, check=False).returncode != 0
