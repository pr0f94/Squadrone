"""Surveyor — maps the plugin's attack surface (entry points, sinks). No vuln finding.

Two execution paths:

- **tool-loop path (default when `plugin_path` is provided)**: receives a slim
  user prompt with ripgrep hit *counts* only, and is granted three
  plugin-scoped tools (`grep_plugin`, `glob_plugin`, `read_plugin_file`) via
  `PluginToolHandlers`. The agent drives its own exploration loop. Works for
  any function-calling model LiteLLM supports.

- **legacy dump fallback (only when `plugin_path` is missing)**: dumps
  `file_tree` + `ripgrep_hits` inline. Kept for backwards compatibility but
  quadratic in plugin size; production scans always supply `plugin_path`.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from ..schemas.recon import ReconArtifact
from .plugin_tools import PluginToolHandlers
from .prompts_io import load_prompt

if TYPE_CHECKING:
    from .runtime import AgentRuntime


_TOOL_LOOP_EXPLORATION_INSTRUCTIONS = """\
You have three plugin-scoped tools available; use them to explore on demand
instead of expecting the source inline:

- `grep_plugin(pattern, path_glob=?, max_results=?, context_lines=?, case_insensitive=?)`
  Regex search across all text files under the plugin root. Vendor / node_modules
  / .git are excluded automatically.
- `glob_plugin(pattern, max_results=?)`
  List files by glob (e.g. `**/*.php`).
- `read_plugin_file(path, start_line=?, end_line=?, max_lines=?)`
  Read a specific file or line range. Prefer line ranges for long files.

Suggested workflow:
1. Call `grep_plugin` to locate entry-point patterns: `register_rest_route`,
   `add_action\\s*\\(\\s*['\"]wp_ajax_`, `add_action\\s*\\(\\s*['\"]admin_post_`,
   `add_shortcode`, `register_setting`. The ripgrep hit *counts* in the user
   message tell you which patterns are worth investigating.
2. Call `grep_plugin` to locate sink patterns: `\\$wpdb->(query|get_results|get_var|get_row|prepare)`,
   `file_put_contents`, `move_uploaded_file`, `unlink`, `(include|require)\\s*\\(`,
   `\\b(exec|shell_exec|system|passthru|popen)\\b`, `wp_remote_(get|post|request)`,
   `(maybe_)?unserialize\\s*\\(`.
3. For each entry point, call `read_plugin_file` with a line range around the
   handler (~20 lines context) to determine `requires_auth`, `has_nonce_check`,
   `has_capability_check`, and `capability`.
4. Do NOT read every file — only the ones containing entry points or sinks you
   flagged. Aim for thoroughness on the attack surface, not exhaustive reading.
5. Build `security_profile` from plugin type, object names, custom roles,
   state-changing workflows, file/import/export/payment/webhook routes, and
   low-privileged stored input that privileged users may later view.
6. When you have enough information, stop calling tools and output ONLY the
   ReconArtifact JSON. No prose, no markdown fences.
"""


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
        plugin_path: str | None = None,
    ) -> ReconArtifact:
        system = load_prompt(self.PROMPT) + (self.extra_system or "")

        # Tool-loop path: works for every LiteLLM-backed function-calling model.
        # The agent receives hit *counts* (not the full match list) plus three
        # plugin-scoped tools, and drives exploration itself.
        if plugin_path:
            handlers = PluginToolHandlers(plugin_root=plugin_path)
            hit_counts = {pattern: len(hits) for pattern, hits in ripgrep_hits.items()}
            user_payload: dict = {
                "plugin_slug": plugin_slug,
                "file_count": len(file_tree),
                "ripgrep_hit_counts": hit_counts,
            }
            user = (
                json.dumps(user_payload, indent=2)
                + "\n\n"
                + _TOOL_LOOP_EXPLORATION_INSTRUCTIONS
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

        # Legacy dump fallback (plugin_path missing): inline file_tree + full hits.
        user = json.dumps({
            "plugin_slug": plugin_slug,
            "file_tree": file_tree,
            "ripgrep_hits": ripgrep_hits,
        })
        return (await self.runtime.run(
            agent_name=self.NAME,
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            output_schema=ReconArtifact,
            max_tokens=32768,
        )).output
