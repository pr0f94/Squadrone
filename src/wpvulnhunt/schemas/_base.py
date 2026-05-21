"""Shared base for artifact schemas — adds JSON file round-trip methods."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel


class JSONFileMixin(BaseModel):
    def to_json_file(self, path: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(self.model_dump_json(indent=2))

    @classmethod
    def from_json_file(cls, path: str):
        return cls.model_validate_json(Path(path).read_text())
