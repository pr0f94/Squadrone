"""Durable artifact file helpers."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Iterable, TypeVar

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


def atomic_write_text(path: str | Path, text: str) -> None:
    """Write text via temp file + atomic replace.

    This prevents resume from reading half-written JSON/JSONL after a crash.
    """
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, target)
    finally:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)


def atomic_write_json(path: str | Path, data: object, *, indent: int = 2) -> None:
    atomic_write_text(path, json.dumps(data, indent=indent, default=str))


def atomic_write_jsonl(path: str | Path, rows: Iterable[BaseModel | dict]) -> None:
    lines: list[str] = []
    for row in rows:
        if isinstance(row, BaseModel):
            lines.append(row.model_dump_json())
        else:
            lines.append(json.dumps(row, default=str))
    atomic_write_text(path, "".join(f"{line}\n" for line in lines))


def read_jsonl_models(path: str | Path, model: type[T], *, corrupt_path: str | Path | None = None) -> tuple[list[T], int]:
    """Read JSONL model rows, optionally quarantining malformed lines."""
    source = Path(path)
    rows: list[T] = []
    corrupt: list[str] = []
    if not source.exists():
        return rows, 0
    for line in source.read_text().splitlines():
        if not line.strip():
            continue
        try:
            rows.append(model.model_validate_json(line))
        except Exception:
            corrupt.append(line)
    if corrupt and corrupt_path is not None:
        atomic_write_text(corrupt_path, "".join(f"{line}\n" for line in corrupt))
    return rows, len(corrupt)
