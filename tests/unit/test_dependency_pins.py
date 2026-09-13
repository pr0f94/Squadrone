from __future__ import annotations

import re
import tomllib
from pathlib import Path

from packaging.requirements import Requirement

ROOT = Path(__file__).resolve().parents[2]


def _exact_version(requirement: str) -> tuple[str, str]:
    parsed = Requirement(requirement)
    specs = list(parsed.specifier)
    assert len(specs) == 1 and specs[0].operator == "==", requirement
    return parsed.name.lower().replace("-", "_"), specs[0].version


def test_project_and_build_dependencies_are_exactly_pinned() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())

    assert project["project"]["requires-python"] == ">=3.12,<3.13"
    assert (ROOT / ".python-version").read_text().strip() == "3.12.14"

    requirements = [
        *project["build-system"]["requires"],
        *project["project"]["dependencies"],
        *project["project"]["optional-dependencies"]["dev"],
    ]
    for requirement in requirements:
        _exact_version(requirement)


def test_constraints_exactly_cover_every_project_dependency() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    constraint_lines = [
        line.strip()
        for line in (ROOT / "requirements" / "constraints.txt").read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]
    constraints = dict(_exact_version(line) for line in constraint_lines)

    assert len(constraints) == len(constraint_lines)
    assert all(
        re.fullmatch(r"[A-Za-z0-9_.-]+==[^=\s]+", line) for line in constraint_lines
    )

    declared = [
        *project["project"]["dependencies"],
        *project["project"]["optional-dependencies"]["dev"],
    ]
    for requirement in declared:
        name, version = _exact_version(requirement)
        assert constraints[name] == version
