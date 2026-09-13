from __future__ import annotations

import os
import shutil
import subprocess
import sys
from importlib.resources import files
from pathlib import Path
from zipfile import ZipFile

import pytest

from squadrone.services import sandbox

ROOT = Path(__file__).resolve().parents[2]
REQUIRED_RUNTIME_ASSETS = {
    "docker-compose.yml.j2",
    "squadrone-actor-receipt.php.j2",
    "wp-init.sh",
}


@pytest.fixture(scope="module")
def clean_wheel(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("clean-wheel")
    source = root / "source"
    wheels = root / "wheels"
    source.mkdir()
    wheels.mkdir()
    shutil.copy2(ROOT / "pyproject.toml", source / "pyproject.toml")
    shutil.copytree(
        ROOT / "src",
        source / "src",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.egg-info"),
    )

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--disable-pip-version-check",
            "--no-build-isolation",
            "--no-deps",
            "--wheel-dir",
            os.fspath(wheels),
            os.fspath(source),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    built = list(wheels.glob("squadrone-*.whl"))
    assert len(built) == 1
    return built[0]


def test_runtime_assets_resolve_from_the_package_outside_repo_cwd(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    resource_dir = files("squadrone.docker")

    assert sandbox._DOCKER_DIR == resource_dir
    assert sandbox._ACTOR_RECEIPT_TEMPLATE == (
        resource_dir / "squadrone-actor-receipt.php.j2"
    )
    for name in REQUIRED_RUNTIME_ASSETS:
        resource = resource_dir / name
        assert resource.is_file()
        assert resource.read_bytes()


def test_repository_compatibility_assets_match_packaged_resources() -> None:
    """Keep already-loaded editable processes compatible during upgrades."""
    resource_dir = files("squadrone.docker")
    for name in REQUIRED_RUNTIME_ASSETS:
        assert (ROOT / "docker" / name).read_bytes() == (resource_dir / name).read_bytes()


def test_clean_wheel_contains_every_runtime_asset(clean_wheel: Path) -> None:
    with ZipFile(clean_wheel) as archive:
        members = set(archive.namelist())

    assert {
        f"squadrone/docker/{name}" for name in REQUIRED_RUNTIME_ASSETS
    } <= members


def test_runtime_assets_resolve_from_an_installed_wheel(
    clean_wheel: Path,
    tmp_path: Path,
) -> None:
    target = tmp_path / "site-packages"
    install = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-deps",
            "--no-index",
            "--target",
            os.fspath(target),
            os.fspath(clean_wheel),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert install.returncode == 0, install.stdout + install.stderr

    script = """
from importlib.resources import files
from pathlib import Path
import squadrone
from squadrone.services import sandbox
import sys

target = Path(sys.argv[1]).resolve()
assert Path(squadrone.__file__).resolve().is_relative_to(target)
resource_dir = files("squadrone.docker")
assert sandbox._DOCKER_DIR == resource_dir
for name in sys.argv[2:]:
    resource = resource_dir / name
    assert resource.is_file()
    assert resource.read_bytes()
"""
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.fspath(target)
    environment["PYTHONNOUSERSITE"] = "1"
    resolved = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            os.fspath(target),
            *sorted(REQUIRED_RUNTIME_ASSETS),
        ],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert resolved.returncode == 0, resolved.stdout + resolved.stderr
