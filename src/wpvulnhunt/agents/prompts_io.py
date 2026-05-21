"""Load prompt text from /prompts/*.md files (importlib.resources-aware)."""

from __future__ import annotations

from importlib.resources import files


def load_prompt(name: str) -> str:
    """Load a prompt by relative name, e.g. 'surveyor' or 'specialists/auth'."""
    parts = name.split("/")
    pkg = ".".join(["wpvulnhunt", "prompts", *parts[:-1]])
    fname = f"{parts[-1]}.md"
    return (files(pkg) / fname).read_text()
