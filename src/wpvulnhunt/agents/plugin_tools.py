"""Plugin-scoped exploration tools (grep / glob / read).

Provides three pure-Python, filesystem-bound tools the LLM can call to explore
the plugin source on demand instead of receiving a giant pre-rendered dump.

The tool definitions are LiteLLM/OpenAI-style function schemas. The same schemas
are translated by LiteLLM into the equivalent Anthropic / Gemini / Bedrock tool
formats, so this works for every provider LiteLLM supports.

Wire-up:
    handlers = PluginToolHandlers(plugin_root="/path/to/plugin")
    tools = handlers.tool_definitions()
    tool_handlers = handlers.tool_handlers()
    await runtime.run(..., tools=tools, tool_handlers=tool_handlers)

Safety:
- Every path is resolved and confined under `plugin_root` (no `..` escape).
- Output is byte-capped per call to keep tool-result tokens bounded.
- Binary/non-text files are detected and refused.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Optional

from .tools import READ_PLUGIN_FILE_TOOL


# ---------------------------------------------------------------------------
# Tool definitions (LiteLLM/OpenAI function-calling schema)
# ---------------------------------------------------------------------------

GREP_PLUGIN_TOOL: dict = {
    "type": "function",
    "function": {
        "name": "grep_plugin",
        "description": (
            "Search the plugin source for a regular expression. Use this to locate "
            "entry points (e.g. `register_rest_route`, `add_action.*wp_ajax_`), sinks "
            "(e.g. `\\$wpdb->query`, `file_put_contents`), or any other pattern. "
            "Returns up to `max_results` matches as `path:line:content` lines. "
            "Prefer narrowing with `path_glob` (e.g. `**/*.php`) on large plugins."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Python regular expression. Escape backslashes once (JSON-encoded), e.g. \"\\\\$wpdb->query\".",
                },
                "path_glob": {
                    "type": "string",
                    "description": "Optional glob to restrict the search (e.g. '**/*.php', 'includes/**/*.php').",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Max matches to return (default 50, hard cap 200).",
                },
                "context_lines": {
                    "type": "integer",
                    "description": "Lines of context to include around each match (default 0, max 5).",
                },
                "case_insensitive": {
                    "type": "boolean",
                    "description": "Case-insensitive match (default false).",
                },
            },
            "required": ["pattern"],
        },
    },
}


GLOB_PLUGIN_TOOL: dict = {
    "type": "function",
    "function": {
        "name": "glob_plugin",
        "description": (
            "List plugin files matching a glob pattern. Use this to discover the "
            "directory layout before grepping or reading. Returns paths relative to "
            "the plugin root, one per line."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Glob pattern, e.g. '**/*.php', 'admin/**/*.js', 'readme.txt'.",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Max paths to return (default 200, hard cap 1000).",
                },
            },
            "required": ["pattern"],
        },
    },
}


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

# Directories typically excluded — dependencies / build output / VCS noise.
_DEFAULT_EXCLUDED_DIRS = frozenset({
    "vendor", "node_modules", ".git", ".svn", "dist", "build", "__pycache__",
})

# Text-y extensions we'll read/grep. Anything else returns "[binary or unsupported]".
_TEXT_EXTENSIONS = frozenset({
    ".php", ".phtml", ".inc", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".css", ".scss", ".html", ".htm", ".xml", ".json", ".yml", ".yaml",
    ".md", ".txt", ".rst", ".ini", ".conf", ".cfg", ".toml", ".env",
    ".sh", ".bash", ".sql", ".po", ".pot",
})

_READ_FILE_HARD_BYTE_CAP = 60_000
_GREP_OUTPUT_HARD_BYTE_CAP = 30_000


class PluginToolHandlers:
    """Filesystem-bound handler closures for plugin-scoped tools.

    One instance per scan run. Pass `tool_definitions()` and `tool_handlers()` to
    `AgentRuntime.run` (or any consumer of LiteLLMTransport) to give the agent
    on-demand exploration capability.
    """

    def __init__(
        self,
        plugin_root: str | Path,
        excluded_dirs: Optional[frozenset[str]] = None,
    ):
        self.plugin_root: Path = Path(plugin_root).resolve()
        if not self.plugin_root.is_dir():
            raise ValueError(f"plugin_root is not a directory: {self.plugin_root}")
        self.excluded_dirs = excluded_dirs if excluded_dirs is not None else _DEFAULT_EXCLUDED_DIRS

    # -- public wiring -----------------------------------------------------

    def tool_definitions(self) -> list[dict]:
        """Return the three tool schemas to advertise to the LLM."""
        return [GREP_PLUGIN_TOOL, GLOB_PLUGIN_TOOL, READ_PLUGIN_FILE_TOOL]

    def tool_handlers(self) -> dict:
        """Return the {tool_name: callable} dict for AgentRuntime.run(tool_handlers=...)."""
        return {
            "grep_plugin": self.grep_plugin,
            "glob_plugin": self.glob_plugin,
            "read_plugin_file": self.read_plugin_file,
        }

    # -- safety helpers ----------------------------------------------------

    def _resolve_safely(self, rel: str) -> Optional[Path]:
        """Resolve `rel` under plugin_root and reject traversal escapes."""
        target = (self.plugin_root / rel).resolve()
        try:
            target.relative_to(self.plugin_root)
        except ValueError:
            return None
        return target

    def _is_excluded(self, rel_path: Path) -> bool:
        return any(part in self.excluded_dirs for part in rel_path.parts)

    def _iter_text_files(self, glob_pattern: Optional[str] = None):
        """Yield (relative_path, absolute_path) for non-excluded text files."""
        pattern = glob_pattern or "**/*"
        for abs_path in sorted(self.plugin_root.glob(pattern)):
            if not abs_path.is_file():
                continue
            rel = abs_path.relative_to(self.plugin_root)
            if self._is_excluded(rel):
                continue
            if abs_path.suffix.lower() not in _TEXT_EXTENSIONS:
                continue
            yield rel, abs_path

    # -- handlers ----------------------------------------------------------

    def grep_plugin(self, args: dict) -> str:
        pattern = (args.get("pattern") or "").strip()
        if not pattern:
            return "[grep_plugin] missing required `pattern`"
        path_glob = args.get("path_glob") or None
        max_results = min(int(args.get("max_results") or 50), 200)
        context_lines = max(0, min(int(args.get("context_lines") or 0), 5))
        flags = re.IGNORECASE if args.get("case_insensitive") else 0
        try:
            regex = re.compile(pattern, flags)
        except re.error as e:
            return f"[grep_plugin] invalid regex: {e}"

        hits: list[str] = []
        files_scanned = 0
        truncated_files = 0
        output_bytes = 0
        for rel, abs_path in self._iter_text_files(path_glob):
            files_scanned += 1
            try:
                text = abs_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            lines = text.splitlines()
            for i, line in enumerate(lines):
                if not regex.search(line):
                    continue
                if context_lines:
                    lo = max(0, i - context_lines)
                    hi = min(len(lines), i + context_lines + 1)
                    block_lines = [
                        f"{rel}:{lo + j + 1}{'>' if (lo + j) == i else ':'}{lines[lo + j]}"
                        for j in range(hi - lo)
                    ]
                    block = "\n".join(block_lines) + "\n--"
                else:
                    block = f"{rel}:{i + 1}:{line}"
                if output_bytes + len(block) + 1 > _GREP_OUTPUT_HARD_BYTE_CAP:
                    truncated_files += 1
                    break
                hits.append(block)
                output_bytes += len(block) + 1
                if len(hits) >= max_results:
                    break
            if len(hits) >= max_results:
                break

        if not hits:
            return (
                f"[grep_plugin] 0 matches for /{pattern}/ across {files_scanned} files"
                f"{f' (glob={path_glob})' if path_glob else ''}"
            )
        header = (
            f"[grep_plugin] {len(hits)} match(es) for /{pattern}/"
            f"{f' (glob={path_glob})' if path_glob else ''}"
            f"{' — output truncated; narrow with path_glob' if truncated_files else ''}"
        )
        return header + "\n" + "\n".join(hits)

    def glob_plugin(self, args: dict) -> str:
        pattern = (args.get("pattern") or "").strip()
        if not pattern:
            return "[glob_plugin] missing required `pattern`"
        max_results = min(int(args.get("max_results") or 200), 1000)

        if pattern.startswith("/") or ".." in pattern.split("/"):
            return "[glob_plugin] refused: pattern must be relative and may not contain '..'"

        paths: list[str] = []
        truncated = False
        for abs_path in sorted(self.plugin_root.glob(pattern)):
            if not abs_path.is_file():
                continue
            rel = abs_path.relative_to(self.plugin_root)
            if self._is_excluded(rel):
                continue
            paths.append(str(rel))
            if len(paths) >= max_results:
                truncated = True
                break

        if not paths:
            return f"[glob_plugin] 0 files match {pattern}"
        suffix = "\n... [truncated; tighten pattern]" if truncated else ""
        return f"[glob_plugin] {len(paths)} file(s) matching {pattern}\n" + "\n".join(paths) + suffix

    def read_plugin_file(self, args: dict) -> str:
        rel = (args.get("path") or "").strip()
        if not rel:
            return "[read_plugin_file] missing required `path`"
        target = self._resolve_safely(rel)
        if target is None:
            return f"[read_plugin_file] refused: '{rel}' resolves outside plugin root"
        if not target.is_file():
            return f"[read_plugin_file] not found: {rel}"
        if target.suffix.lower() and target.suffix.lower() not in _TEXT_EXTENSIONS:
            return f"[read_plugin_file] refused: {rel} is not a recognised text file"

        try:
            text = target.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            return f"[read_plugin_file] read failed: {e}"

        all_lines = text.splitlines()
        total_lines = len(all_lines)
        start_line = max(1, int(args.get("start_line") or 1))
        end_line_arg = args.get("end_line")
        end_line = int(end_line_arg) if end_line_arg is not None else total_lines
        end_line = max(start_line, min(end_line, total_lines))
        max_lines = int(args.get("max_lines") or 500)

        sliced = all_lines[start_line - 1:end_line]
        sliced_truncated = False
        if len(sliced) > max_lines:
            sliced = sliced[:max_lines]
            end_line = start_line + max_lines - 1
            sliced_truncated = True

        body = "\n".join(sliced)
        byte_truncated = False
        if len(body) > _READ_FILE_HARD_BYTE_CAP:
            body = body[:_READ_FILE_HARD_BYTE_CAP]
            byte_truncated = True

        header = f"--- {rel} (lines {start_line}-{end_line} of {total_lines}) ---"
        footer = ""
        if sliced_truncated or byte_truncated or end_line < total_lines:
            footer = (
                f"\n\n... [truncated; full file is {total_lines} lines. "
                f"Re-call with start_line={end_line + 1} to continue]"
            )
        return f"{header}\n{body}{footer}"
