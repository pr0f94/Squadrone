"""Shared tool definitions used by multiple agents."""

from __future__ import annotations

READ_PLUGIN_FILE_TOOL: dict = {
    "type": "function",
    "function": {
        "name": "read_plugin_file",
        "description": (
            "Read the contents of a file from the target plugin's source directory. "
            "Use this to inspect any plugin file beyond the entry point already provided "
            "(e.g. helper classes, included files, JS that consumes server output, "
            "shortcode rendering files). Path is relative to the plugin root. For long "
            "files, prefer the line-range form (start_line + end_line) over reading the "
            "whole file. For a minified line, set start_line and start_column to read "
            "the relevant character window."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "File path relative to the plugin root, e.g. 'includes/ee-uploader.php'",
                },
                "start_line": {
                    "type": "integer",
                    "description": "Optional 1-indexed first line to return (default 1). Combine with end_line for partial reads of long files.",
                },
                "end_line": {
                    "type": "integer",
                    "description": "Optional 1-indexed inclusive last line. Defaults to end of file (subject to max_lines).",
                },
                "max_lines": {
                    "type": "integer",
                    "description": "Optional cap on lines returned (default 500). Applies after start_line/end_line slicing.",
                },
                "start_column": {
                    "type": "integer",
                    "description": "Optional 1-indexed first character on start_line. When set, returns only that line from this column.",
                },
                "max_chars": {
                    "type": "integer",
                    "description": "Optional character cap for start_column reads (default and hard cap 60000).",
                },
            },
            "required": ["path"],
        },
    },
}

READ_PLUGIN_RANGES_TOOL: dict = {
    "type": "function",
    "function": {
        "name": "read_plugin_ranges",
        "description": (
            "Read up to eight independent bounded line ranges from plugin source "
            "in one call. Prefer this over separate read_plugin_file calls when "
            "the relevant source-local ranges are already known. Results preserve "
            "the requested order and share a 60000-byte output cap. Use "
            "read_plugin_file for a minified-line character window or when you need "
            "to expand one range iteratively."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "ranges": {
                    "type": "array",
                    "description": "One to eight bounded source ranges, returned in this order.",
                    "minItems": 1,
                    "maxItems": 8,
                    "items": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "description": "File path relative to the plugin root.",
                            },
                            "start_line": {
                                "type": "integer",
                                "minimum": 1,
                                "description": "1-indexed first line to return.",
                            },
                            "end_line": {
                                "type": "integer",
                                "minimum": 1,
                                "description": "1-indexed inclusive last line to return.",
                            },
                        },
                        "required": ["path", "start_line", "end_line"],
                    },
                }
            },
            "required": ["ranges"],
        },
    },
}

REQUEST_ADDITIONAL_SETUP_TOOL: dict = {
    "type": "function",
    "function": {
        "name": "request_additional_setup",
        "description": (
            "Ask the runner to apply additional sandbox setup BEFORE your next PoC attempt. "
            "Use when your PoC is failing because expected state is missing — e.g. you need a "
            "specific user role, a published post, an option set, or a benign prerequisite "
            "record. Do not request setup that directly plants the exploit payload into the "
            "claimed vulnerable storage location; stored bugs must submit malicious input "
            "through the real plugin entry point. The runner will dispatch to the developer "
            "agent, run the proposed setup commands inside the sandbox, and return a summary. "
            "Then write your PoC against the new state."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "description": {
                    "type": "string",
                    "description": "What sandbox state you need and why your PoC is failing without it",
                },
            },
            "required": ["description"],
        },
    },
}


CONSULT_DEVELOPER_TOOL: dict = {
    "type": "function",
    "function": {
        "name": "consult_developer",
        "description": (
            "Ask the WordPress developer expert a question about the codebase. "
            "Use when you need to understand what a piece of code does, whether a "
            "code path is reachable, what a WordPress API call returns, or why a "
            "payload may or may not work. Be specific — include the relevant code "
            "snippet and your exact question."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "question": {
                    "type": "string",
                    "description": "Your specific question about the code",
                },
                "code_snippet": {
                    "type": "string",
                    "description": "The relevant code snippet you are asking about",
                },
                "context": {
                    "type": "string",
                    "description": "Any additional context",
                },
            },
            "required": ["question", "code_snippet"],
        },
    },
}
