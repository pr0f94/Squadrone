"""Plugin-scoped exploration tools (grep / glob / bounded reads).

Provides four pure-Python, filesystem-bound tools the LLM can call to explore
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

import re
from pathlib import Path
from typing import Optional

from .tools import READ_PLUGIN_FILE_TOOL, READ_PLUGIN_RANGES_TOOL


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
            "Returns up to `max_results` matches as `path:line:column:content` lines, "
            "with long minified lines centered on the match. "
            "Prefer narrowing with `path_glob` (e.g. `**/*.php`) on large plugins."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": 'Python regular expression. Escape backslashes once (JSON-encoded), e.g. "\\\\$wpdb->query".',
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
            "List plugin files and directories matching a glob pattern. Use this to "
            "discover the directory layout before grepping or reading, including "
            "empty or hidden-file-only directories. Returns paths relative to the "
            "plugin root, one per line; directory paths end with '/'."
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

# Only non-shipped or duplicate source trees are excluded. Bundled vendor,
# dist, and build code can be security-relevant and must remain inspectable.
_DEFAULT_EXCLUDED_DIRS = frozenset(
    {
        "node_modules",
        ".git",
        ".svn",
        "__pycache__",
    }
)

# Text-y extensions we'll read/grep. Anything else returns "[binary or unsupported]".
_TEXT_EXTENSIONS = frozenset(
    {
        ".php",
        ".phtml",
        ".inc",
        ".js",
        ".jsx",
        ".ts",
        ".tsx",
        ".mjs",
        ".cjs",
        ".css",
        ".scss",
        ".html",
        ".htm",
        ".xml",
        ".json",
        ".yml",
        ".yaml",
        ".md",
        ".txt",
        ".rst",
        ".ini",
        ".conf",
        ".cfg",
        ".toml",
        ".env",
        ".sh",
        ".bash",
        ".sql",
        ".po",
        ".pot",
    }
)

_READ_FILE_HARD_BYTE_CAP = 60_000
_READ_RANGES_HARD_COUNT_CAP = 8
_READ_RANGES_HARD_LINES_PER_RANGE = 500
_GREP_OUTPUT_HARD_BYTE_CAP = 30_000


def _line_excerpt(value: str, center: int, width: int = 1200) -> str:
    """Return a bounded line excerpt centered on a regex match."""
    if len(value) <= width:
        return value
    start = max(0, min(center - width // 2, len(value) - width))
    end = start + width
    return (
        ("..." if start else "")
        + value[start:end]
        + ("..." if end < len(value) else "")
    )


def _utf8_prefix(value: str, max_bytes: int) -> tuple[str, bool]:
    """Return a valid UTF-8 prefix and whether any content was omitted."""
    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return value, False
    if max_bytes <= 0:
        return "", bool(value)
    return encoded[:max_bytes].decode("utf-8", errors="ignore"), True


def _display_path(value: str, max_chars: int = 180) -> str:
    """Render an untrusted path compactly without allowing control-line output."""
    clipped = value[:max_chars]
    if len(value) > max_chars:
        clipped += "..."
    return ascii(clipped)


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
        self.excluded_dirs = (
            excluded_dirs if excluded_dirs is not None else _DEFAULT_EXCLUDED_DIRS
        )
        self.read_columns: dict[tuple[str, int], list[tuple[int, int]]] = {}

    def was_read(self, path: str, line: int, column: int | None = 1) -> bool:
        """Return whether a read result included this exact source position."""
        target = self._resolve_safely(path)
        if target is None:
            return False
        rel = str(target.relative_to(self.plugin_root))
        spans = self.read_columns.get((rel, line), [])
        if column is None:
            return bool(spans)
        return any(start <= column <= end for start, end in spans)

    def _record_read(
        self, rel: str, line: int, start_column: int, end_column: int
    ) -> None:
        self.read_columns.setdefault((rel, line), []).append((start_column, end_column))

    # -- public wiring -----------------------------------------------------

    def tool_definitions(self) -> list[dict]:
        """Return the plugin-scoped tool schemas to advertise to the LLM."""
        return [
            GREP_PLUGIN_TOOL,
            GLOB_PLUGIN_TOOL,
            READ_PLUGIN_FILE_TOOL,
            READ_PLUGIN_RANGES_TOOL,
        ]

    def tool_handlers(self) -> dict:
        """Return the {tool_name: callable} dict for AgentRuntime.run(tool_handlers=...)."""
        return {
            "grep_plugin": self.grep_plugin,
            "glob_plugin": self.glob_plugin,
            "read_plugin_file": self.read_plugin_file,
            "read_plugin_ranges": self.read_plugin_ranges,
        }

    # -- safety helpers ----------------------------------------------------

    def _resolve_path_safely(self, path: Path) -> Optional[Path]:
        """Resolve a candidate and reject symlink/traversal escapes."""
        try:
            target = path.resolve()
            target.relative_to(self.plugin_root)
        except (OSError, RuntimeError, ValueError):
            return None
        return target

    def _resolve_safely(self, rel: str) -> Optional[Path]:
        """Resolve `rel` under plugin_root and reject traversal escapes."""
        return self._resolve_path_safely(self.plugin_root / rel)

    @staticmethod
    def _safe_glob_pattern(pattern: str) -> bool:
        """Return whether a glob is relative and has no parent traversal."""
        return (
            bool(pattern)
            and not pattern.startswith("/")
            and ".." not in pattern.split("/")
        )

    def _is_excluded(self, rel_path: Path) -> bool:
        return any(part in self.excluded_dirs for part in rel_path.parts)

    def _iter_text_files(self, glob_pattern: Optional[str] = None):
        """Yield (relative_path, absolute_path) for non-excluded text files."""
        pattern = glob_pattern or "**/*"
        if not self._safe_glob_pattern(pattern):
            return
        for candidate in sorted(self.plugin_root.glob(pattern)):
            abs_path = self._resolve_path_safely(candidate)
            if abs_path is None or not abs_path.is_file():
                continue
            rel = candidate.relative_to(self.plugin_root)
            resolved_rel = abs_path.relative_to(self.plugin_root)
            if self._is_excluded(rel) or self._is_excluded(resolved_rel):
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
        if path_glob is not None and not self._safe_glob_pattern(path_glob):
            return "[grep_plugin] refused: path_glob must be relative and may not contain '..'"
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
                match = regex.search(line)
                if not match:
                    continue
                match_column = match.start() + 1
                if context_lines:
                    lo = max(0, i - context_lines)
                    hi = min(len(lines), i + context_lines + 1)
                    block_lines = [
                        (
                            f"{rel}:{lo + j + 1}:"
                            f"{match_column if (lo + j) == i else 1}"
                            f"{'>' if (lo + j) == i else ':'}"
                            f"{_line_excerpt(lines[lo + j], match.start() if (lo + j) == i else 0)}"
                        )
                        for j in range(hi - lo)
                    ]
                    block = "\n".join(block_lines) + "\n--"
                else:
                    block = (
                        f"{rel}:{i + 1}:{match_column}:"
                        f"{_line_excerpt(line, match.start())}"
                    )
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

        if not self._safe_glob_pattern(pattern):
            return "[glob_plugin] refused: pattern must be relative and may not contain '..'"

        paths: list[str] = []
        truncated = False
        for candidate in sorted(self.plugin_root.glob(pattern)):
            abs_path = self._resolve_path_safely(candidate)
            if abs_path is None or not (abs_path.is_file() or abs_path.is_dir()):
                continue
            rel = candidate.relative_to(self.plugin_root)
            resolved_rel = abs_path.relative_to(self.plugin_root)
            if self._is_excluded(rel) or self._is_excluded(resolved_rel):
                continue
            rendered = str(rel)
            if abs_path.is_dir():
                rendered += "/"
            paths.append(rendered)
            if len(paths) >= max_results:
                truncated = True
                break

        if not paths:
            return f"[glob_plugin] 0 paths match {pattern}"
        suffix = "\n... [truncated; tighten pattern]" if truncated else ""
        return (
            f"[glob_plugin] {len(paths)} path(s) matching {pattern}\n"
            + "\n".join(paths)
            + suffix
        )

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
        rel = str(target.relative_to(self.plugin_root))

        try:
            text = target.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            return f"[read_plugin_file] read failed: {e}"

        all_lines = text.splitlines()
        total_lines = len(all_lines)
        start_line = max(1, int(args.get("start_line") or 1))
        if start_line > total_lines:
            return (
                f"[read_plugin_file] refused: start_line {start_line} is beyond "
                f"the end of {rel} ({total_lines} lines)"
            )
        start_column_arg = args.get("start_column")
        if start_column_arg is not None:
            line = all_lines[start_line - 1]
            start_column = max(1, int(start_column_arg))
            if start_column > max(len(line), 1):
                return (
                    f"[read_plugin_file] refused: start_column {start_column} is beyond "
                    f"the end of {rel}:{start_line} ({len(line)} characters)"
                )
            max_chars = max(
                1,
                min(
                    int(args.get("max_chars") or _READ_FILE_HARD_BYTE_CAP),
                    _READ_FILE_HARD_BYTE_CAP,
                ),
            )
            body = line[start_column - 1 : start_column - 1 + max_chars]
            end_column = start_column + max(len(body) - 1, 0)
            self._record_read(rel, start_line, start_column, end_column)
            header = (
                f"--- {rel} (line {start_line}, columns {start_column}-{end_column} "
                f"of {len(line)}) ---"
            )
            footer = ""
            if end_column < len(line):
                footer = (
                    f"\n\n... [truncated; re-call with start_line={start_line}, "
                    f"start_column={end_column + 1}]"
                )
            return f"{header}\n{body}{footer}"
        end_line_arg = args.get("end_line")
        end_line = int(end_line_arg) if end_line_arg is not None else total_lines
        end_line = max(start_line, min(end_line, total_lines))
        max_lines = int(args.get("max_lines") or 500)

        sliced = all_lines[start_line - 1 : end_line]
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

        # Track source columns actually returned. This matters for minified files,
        # where one physical line can be much larger than the output cap.
        remaining = len(body)
        last_line = start_line
        last_column = 1
        for offset, source_line in enumerate(sliced):
            if offset:
                if remaining < 1:
                    break
                remaining -= 1
            line_no = start_line + offset
            if not source_line:
                self._record_read(rel, line_no, 1, 1)
                last_line, last_column = line_no, 1
                continue
            visible_chars = min(len(source_line), remaining)
            if visible_chars < 1:
                break
            self._record_read(rel, line_no, 1, visible_chars)
            last_line, last_column = line_no, visible_chars
            remaining -= visible_chars
        end_line = last_line

        header = f"--- {rel} (lines {start_line}-{end_line} of {total_lines}) ---"
        footer = ""
        if sliced_truncated or byte_truncated or end_line < total_lines:
            source_line_length = len(all_lines[end_line - 1]) if total_lines else 0
            if last_column < source_line_length:
                continuation = f"start_line={end_line}, start_column={last_column + 1}"
            else:
                continuation = f"start_line={end_line + 1}"
            footer = (
                f"\n\n... [truncated; full file is {total_lines} lines. "
                f"Re-call with {continuation} to continue]"
            )
        return f"{header}\n{body}{footer}"

    def read_plugin_ranges(self, args: dict) -> str:
        """Read ordered source ranges under one aggregate output/evidence cap."""
        ranges = args.get("ranges") if isinstance(args, dict) else None
        if not isinstance(ranges, list) or not ranges:
            return "[read_plugin_ranges] missing required non-empty `ranges` array"
        if len(ranges) > _READ_RANGES_HARD_COUNT_CAP:
            return (
                f"[read_plugin_ranges] refused: {len(ranges)} ranges exceeds the "
                f"hard cap of {_READ_RANGES_HARD_COUNT_CAP}"
            )

        parts = [f"[read_plugin_ranges] {len(ranges)} requested range(s)"]
        used_bytes = len(parts[0].encode("utf-8"))

        def append_bounded(value: str) -> bool:
            nonlocal used_bytes
            remaining = _READ_FILE_HARD_BYTE_CAP - used_bytes
            prefix, truncated = _utf8_prefix(value, remaining)
            parts.append(prefix)
            used_bytes += len(prefix.encode("utf-8"))
            return not truncated

        def parse_line(value: object, field: str) -> tuple[int | None, str | None]:
            try:
                parsed = int(value)  # type: ignore[arg-type]
            except (TypeError, ValueError, OverflowError):
                return None, f"`{field}` must be an integer"
            return max(1, parsed), None

        for index, requested in enumerate(ranges, start=1):
            if not append_bounded("\n\n"):
                break
            label = f"range {index}/{len(ranges)}"
            if not isinstance(requested, dict):
                append_bounded(
                    f"--- {label}: error ---\n"
                    "[read_plugin_ranges] range must be an object"
                )
                continue

            path_value = requested.get("path")
            if not isinstance(path_value, str) or not path_value.strip():
                append_bounded(
                    f"--- {label}: error ---\n"
                    "[read_plugin_ranges] missing required `path`"
                )
                continue
            supplied_path = path_value.strip()

            if "start_line" not in requested or "end_line" not in requested:
                append_bounded(
                    f"--- {label}: {_display_path(supplied_path)} ---\n"
                    "[read_plugin_ranges] both `start_line` and `end_line` are required"
                )
                continue
            start_line, start_error = parse_line(
                requested.get("start_line"), "start_line"
            )
            end_line, end_error = parse_line(requested.get("end_line"), "end_line")
            if start_error or end_error:
                append_bounded(
                    f"--- {label}: {_display_path(supplied_path)} ---\n"
                    f"[read_plugin_ranges] {start_error or end_error}"
                )
                continue
            assert start_line is not None and end_line is not None

            target = self._resolve_safely(supplied_path)
            if target is None:
                append_bounded(
                    f"--- {label}: {_display_path(supplied_path)} ---\n"
                    "[read_plugin_ranges] refused: path resolves outside plugin root"
                )
                continue
            try:
                is_file = target.is_file()
            except OSError as error:
                append_bounded(
                    f"--- {label}: {_display_path(supplied_path)} ---\n"
                    f"[read_plugin_ranges] stat failed: {error}"
                )
                continue
            if not is_file:
                append_bounded(
                    f"--- {label}: {_display_path(supplied_path)} ---\n"
                    "[read_plugin_ranges] not found"
                )
                continue
            if target.suffix.lower() and target.suffix.lower() not in _TEXT_EXTENSIONS:
                append_bounded(
                    f"--- {label}: {_display_path(supplied_path)} ---\n"
                    "[read_plugin_ranges] refused: not a recognised text file"
                )
                continue

            rel = str(target.relative_to(self.plugin_root))
            try:
                all_lines = target.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines()
            except OSError as error:
                append_bounded(
                    f"--- {label}: {_display_path(rel)} ---\n"
                    f"[read_plugin_ranges] read failed: {error}"
                )
                continue
            total_lines = len(all_lines)
            if start_line > total_lines:
                append_bounded(
                    f"--- {label}: {_display_path(rel)} ---\n"
                    f"[read_plugin_ranges] refused: start_line {start_line} is beyond "
                    f"the end of the file ({total_lines} lines)"
                )
                continue

            end_line = max(start_line, min(end_line, total_lines))
            requested_end = end_line
            if end_line - start_line + 1 > _READ_RANGES_HARD_LINES_PER_RANGE:
                end_line = start_line + _READ_RANGES_HARD_LINES_PER_RANGE - 1
            line_capped = end_line < requested_end
            selected = all_lines[start_line - 1 : end_line]
            heading = (
                f"--- {label}: {rel} (lines {start_line}-{end_line} "
                f"of {total_lines}) ---\n"
            )
            if not append_bounded(heading):
                break

            line_marker = (
                f"\n... [range capped at {_READ_RANGES_HARD_LINES_PER_RANGE} lines; "
                f"continue with start_line={end_line + 1}]"
                if line_capped
                else ""
            )
            available = _READ_FILE_HARD_BYTE_CAP - used_bytes
            selected_bytes = sum(len(line.encode("utf-8")) for line in selected)
            selected_bytes += max(0, len(selected) - 1)
            required_bytes = selected_bytes + len(line_marker.encode("utf-8"))

            aggregate_truncated = required_bytes > available
            marker = line_marker
            if aggregate_truncated:
                marker = (
                    "\n... [aggregate output truncated at 60000 bytes; re-call this "
                    "range or the remaining ranges separately]"
                )
            source_budget = max(0, available - len(marker.encode("utf-8")))
            if not aggregate_truncated:
                source_budget = selected_bytes

            source_parts: list[str] = []
            source_spans: list[tuple[int, int, int]] = []
            remaining = source_budget
            for offset, source_line in enumerate(selected):
                if offset:
                    if remaining < 1:
                        break
                    source_parts.append("\n")
                    remaining -= 1
                line_no = start_line + offset
                if not source_line:
                    source_spans.append((line_no, 1, 1))
                    continue
                visible, truncated = _utf8_prefix(source_line, remaining)
                if visible:
                    source_parts.append(visible)
                    source_spans.append((line_no, 1, len(visible)))
                    remaining -= len(visible.encode("utf-8"))
                if truncated:
                    break

            append_bounded("".join(source_parts))
            for line_no, start_column, end_column in source_spans:
                self._record_read(rel, line_no, start_column, end_column)
            append_bounded(marker)
            if aggregate_truncated:
                break

        return "".join(parts)
