"""Surveyor — maps the plugin's attack surface (entry points, sinks). No vuln finding."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from ..schemas.recon import CoverageArtifact, ReconArtifact
from .plugin_tools import PluginToolHandlers
from .prompts_io import load_prompt

if TYPE_CHECKING:
    from .runtime import AgentRuntime


_SOURCE_EXPLORATION_INSTRUCTIONS = """\
You have range-aware grep, glob, and read tools over the shipped plugin source.
Version-control metadata and node_modules are excluded; bundled vendor, dist,
and build files remain available.

Workflow:
1. The compact manifest contains deterministic callbacks and high-risk
   operations. Do not repeat it wholesale in your output.
2. Search for dynamic registrations the static extractor cannot resolve.
3. Resolve handlers and shared permission/token helpers needed for the plugin
   threat profile and downstream workflow review.
4. Return only source-proven additional entry points/sinks plus the security
   profile. Deterministic inventory is merged by the runner afterwards.
5. Output only the ReconArtifact JSON.
"""


_COMPACT_KINDS = {"entry_point", "sink"}


def _compact_coverage(coverage: CoverageArtifact) -> dict:
    """Keep navigation data while omitting duplicated snippets and storage noise."""
    items = [
        {
            "id": item.id,
            "kind": item.kind,
            "type": item.type,
            "name": item.name,
            "file": item.file,
            "line": item.line,
            "column": item.column,
            "handler_function": item.handler_function,
            "review_areas": item.review_areas,
        }
        for item in coverage.items
        if item.kind in _COMPACT_KINDS
    ]
    return {
        "production_files": coverage.production_files,
        "dependency_files": coverage.dependency_files,
        "items": items,
    }


class SurveyorAgent:
    NAME = "surveyor"
    PROMPT = "surveyor"

    def __init__(self, runtime: "AgentRuntime", model: str):
        self.runtime = runtime
        self.model = model
        self.extra_system: str = ""

    async def survey(
        self,
        plugin_slug: str,
        file_tree: list[str],
        ripgrep_hits: dict[str, list[str]],
        plugin_path: str,
        coverage: CoverageArtifact,
    ) -> ReconArtifact:
        system = load_prompt(self.PROMPT) + (self.extra_system or "")
        handlers = PluginToolHandlers(plugin_root=plugin_path)
        hit_counts = {pattern: len(hits) for pattern, hits in ripgrep_hits.items()}
        user_payload: dict = {
            "plugin_slug": plugin_slug,
            "file_count": len(file_tree),
            "ripgrep_hit_counts": hit_counts,
            "compact_manifest": _compact_coverage(coverage),
        }
        user = (
            json.dumps(user_payload, indent=2)
            + "\n\n"
            + _SOURCE_EXPLORATION_INSTRUCTIONS
        )
        return (await self.runtime.run(
            agent_name=self.NAME,
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            tools=handlers.tool_definitions(),
            tool_handlers=handlers.tool_handlers(),
            output_schema=ReconArtifact,
            max_iterations=40,
            force_finalise_after=25,
            max_tokens=32768,
        )).output
