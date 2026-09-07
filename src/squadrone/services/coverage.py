"""Deterministic production-surface inventory and review ledger helpers."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable, cast

from ..schemas.recon import (
    CoverageArtifact,
    CoverageItem,
    EntryPoint,
    ReconArtifact,
    ReviewArea,
    Sink,
)
from ..schemas.taxonomy import KNOWN_CWE_REGISTRY
from . import recon_helpers


_CODE_EXTENSIONS = {
    ".php",
    ".phtml",
    ".inc",
    ".js",
    ".mjs",
    ".cjs",
    ".jsx",
    ".ts",
    ".tsx",
    ".html",
    ".htm",
    ".twig",
    ".mustache",
    ".vue",
}
_NON_PRODUCTION_PARTS = {
    ".git",
    ".github",
    ".svn",
    "__pycache__",
    "docs",
    "documentation",
    "examples",
    "example",
    "languages",
    "language",
    "lang",
    "node_modules",
    "samples",
    "sample",
    "tests",
    "test",
    "testing",
    "__tests__",
}
_DEPENDENCY_PARTS = {"vendor"}

_REVIEWABLE_SUPPORT = {"active", "partial", "review_only"}
_SURFACE_SNIPPET_MAX_CHARS = 4_000
_BARE_PHP_VARIABLE_RE = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*")
_SQL_OPERATION_RE = re.compile(
    r"\b(?P<operation>SELECT|UPDATE|DELETE|INSERT|REPLACE)\b",
    re.IGNORECASE,
)
_SQL_AGGREGATE_RE = re.compile(r"\b(?:COUNT|SUM|AVG|MIN|MAX)\s*\(", re.IGNORECASE)
_SQL_IDENTITY_PREDICATE_RE = re.compile(
    r"(?<![A-Za-z0-9_])"
    r"(?:`?[A-Za-z_][A-Za-z0-9_]*`?\s*\.\s*)?"
    r"`?(?:id|[A-Za-z_][A-Za-z0-9_]*_id)`?\s*"
    r"(?P<operator>=|IN\s*\()",
    re.IGNORECASE,
)
_SQL_PLACEHOLDER_RE = re.compile(r"%(?:(?P<position>[1-9][0-9]*)\$)?[disfF]")
_SQL_CLAUSE_BOUNDARY_RE = re.compile(
    r"\b(?:AND|OR|ORDER\s+BY|GROUP\s+BY|HAVING|LIMIT|UNION)\b",
    re.IGNORECASE,
)
_PHP_FUNCTION_RE = re.compile(r"\bfunction\b", re.IGNORECASE)
_CURRENT_USER_ID_RE = re.compile(
    r"(?:(?i:get_current_user_id)\s*\(\s*\)|"
    r"(?i:wp_get_current_user)\s*\(\s*\)\s*->\s*ID)"
)
def _review_areas_for_surface(
    surface_type: str,
    existing: Iterable[ReviewArea] = (),
) -> list[ReviewArea]:
    """Merge legacy useful routing with the registry's declared CWE owners."""
    areas = list(dict.fromkeys(existing))
    for profile in KNOWN_CWE_REGISTRY.values():
        if (
            profile.reviewer is None
            or profile.analysis_support not in _REVIEWABLE_SUPPORT
            or surface_type not in profile.deterministic_surfaces
        ):
            continue
        reviewer = cast(ReviewArea, profile.reviewer)
        if reviewer not in areas:
            areas.append(reviewer)
    return areas


# (type, function pattern, review areas, coverage kind)
_PHP_SURFACES: list[tuple[str, re.Pattern[str], list[ReviewArea], str]] = [
    (
        "sql_query",
        re.compile(
            r"\$wpdb\s*->\s*(?P<fn>query|get_results|get_row|get_var|get_col)\s*\("
        ),
        ["injection_files"],
        "sink",
    ),
    (
        "sql_write",
        re.compile(r"\$wpdb\s*->\s*(?P<fn>insert|update|delete|replace)\s*\("),
        ["injection_files", "xss_lifecycle"],
        "storage_write",
    ),
    (
        "command_execution",
        re.compile(r"\b(?P<fn>exec|shell_exec|system|passthru|popen|proc_open)\s*\("),
        ["injection_files"],
        "sink",
    ),
    (
        "external_http",
        re.compile(
            r"\b(?P<fn>wp_remote_get|wp_remote_post|wp_remote_request|wp_remote_head|curl_exec)\s*\("
        ),
        ["injection_files"],
        "sink",
    ),
    (
        "deserialization",
        re.compile(r"\b(?P<fn>unserialize|maybe_unserialize)\s*\("),
        ["injection_files"],
        "sink",
    ),
    (
        "implicit_deserialization",
        # WordPress update_metadata() can consume the existing stored value
        # through core metadata handling. Keep this deliberately narrower than
        # every get_*_meta()/update_*_meta() wrapper: the specialist follows
        # those calls only after a raw metadata write establishes byte ingress.
        re.compile(r"\b(?P<fn>update_metadata)\s*\(", re.IGNORECASE),
        ["injection_files"],
        "sink",
    ),
    (
        "xml_parse",
        re.compile(
            r"\b(?P<fn>simplexml_load_string|simplexml_load_file|loadXML|SimpleXMLElement)\s*\("
        ),
        ["injection_files"],
        "sink",
    ),
    (
        "file_upload",
        re.compile(
            r"\b(?P<fn>move_uploaded_file|wp_handle_upload|media_handle_upload)\s*\("
        ),
        ["injection_files"],
        "sink",
    ),
    (
        "file_write",
        re.compile(
            r"\b(?P<fn>file_put_contents|fwrite|fopen|copy|rename|extractTo)\s*\("
        ),
        ["injection_files"],
        "sink",
    ),
    (
        "file_delete",
        re.compile(r"\b(?P<fn>unlink|rmdir)\s*\("),
        ["injection_files"],
        "sink",
    ),
    (
        "file_read",
        re.compile(r"\b(?P<fn>file_get_contents|readfile|file|glob)\s*\("),
        ["injection_files"],
        "sink",
    ),
    (
        "dynamic_include",
        re.compile(r"\b(?P<fn>include|include_once|require|require_once)\s*[\($]"),
        ["injection_files"],
        "sink",
    ),
    # Persistent writes are XSS lifecycle anchors. Their later reads/renders are
    # followed from source; making every get_option(), metadata read, and echo a
    # separate review target creates a large operation inventory without adding
    # a distinct security workflow.
    (
        "option_write",
        re.compile(
            r"\b(?P<fn>update_option|add_option|delete_option|update_site_option|delete_site_option)\s*\("
        ),
        ["xss_lifecycle"],
        "storage_write",
    ),
    (
        "object_write",
        re.compile(
            r"\b(?P<fn>update_(?:post|user|comment)_meta|add_(?:post|user|comment)_meta|delete_(?:post|user|comment)_meta|wp_insert_post|wp_update_post|wp_delete_post|wp_insert_user|wp_update_user|wp_delete_user)\s*\("
        ),
        ["xss_lifecycle"],
        "storage_write",
    ),
    (
        "authentication_state",
        re.compile(
            r"\b(?P<fn>wp_set_auth_cookie|wp_set_current_user|wp_signon|wp_authenticate|reset_password|check_password_reset_key|get_password_reset_key)\s*\("
        ),
        ["authentication"],
        "sink",
    ),
    (
        "weak_crypto_primitive",
        re.compile(r"\b(?P<fn>md5|sha1)\s*\("),
        [],
        "sink",
    ),
    (
        "non_cryptographic_randomness",
        re.compile(r"\b(?P<fn>rand|mt_rand|uniqid|lcg_value)\s*\("),
        [],
        "sink",
    ),
    (
        "role_capability_write",
        re.compile(r"(?P<fn>set_role|add_role|add_cap|remove_cap)\s*\("),
        ["authorization_workflows", "authentication"],
        "storage_write",
    ),
]

_JS_SURFACES: list[tuple[str, re.Pattern[str], list[ReviewArea], str]] = [
    (
        "dom_html",
        re.compile(
            r"\.(?P<fn>innerHTML|outerHTML)\s*=|\b(?P<fn2>insertAdjacentHTML|document\.write)\s*\("
        ),
        ["xss_lifecycle"],
        "sink",
    ),
    (
        "javascript_eval",
        re.compile(r"\b(?P<fn>eval|Function)\s*\("),
        ["injection_files", "xss_lifecycle"],
        "sink",
    ),
]

# Registry ownership is additive: retain intentional broad/legacy review areas,
# while guaranteeing each declared deterministic surface reaches its owner.
_PHP_SURFACES = [
    (surface_type, pattern, _review_areas_for_surface(surface_type, areas), kind)
    for surface_type, pattern, areas, kind in _PHP_SURFACES
]
_JS_SURFACES = [
    (surface_type, pattern, _review_areas_for_surface(surface_type, areas), kind)
    for surface_type, pattern, areas, kind in _JS_SURFACES
]

_AUTH_FLOW_RE = re.compile(
    r"login|logout|auth|password|reset|recover|register|signup|2fa|totp|otp|token|magic",
    re.IGNORECASE,
)
_NONCE_RE = re.compile(
    r"\b(?:wp_verify_nonce|check_ajax_referer|check_admin_referer)\s*\("
)
_CAP_RE = re.compile(r"\b(?:current_user_can|user_can)\s*\(")
_GENERIC_HANDLER_NAMES = {"", "closure", "function", "init", "__invoke"}
_DIRECT_DISPATCH_RE = re.compile(
    r"(?:->|::)\s*(?P<method>run|dispatch|handle|serve|process|execute|respond)\s*\(",
    re.IGNORECASE,
)
_DIRECT_REQUEST_RE = re.compile(
    r"\$_(?:GET|POST|REQUEST|FILES|COOKIE|SERVER)\b",
    re.IGNORECASE,
)
_DIRECT_LOCAL_BOOTSTRAP_RE = re.compile(
    r"\b(?:include|include_once|require|require_once)\b",
    re.IGNORECASE,
)
_DIRECT_BOOTSTRAP_GUARD_RE = re.compile(
    r"(?:"
    r"if\s*\([^)]*!\s*defined\s*\(\s*['\"](?:ABSPATH|WPINC|WP_UNINSTALL_PLUGIN)['\"]\s*\)"
    r"[^;{]*(?:\{[^}]{0,400})?\b(?:exit|die|return)\b"
    r"|defined\s*\(\s*['\"](?:ABSPATH|WPINC|WP_UNINSTALL_PLUGIN)['\"]\s*\)\s*"
    r"(?:\|\||\bor\b)\s*(?:exit|die|return)\b"
    r")",
    re.IGNORECASE | re.DOTALL,
)


def _mask_non_code(source: str, *, mask_strings: bool) -> str:
    """Mask comments (and optionally strings) without changing source offsets."""
    result: list[str] = []
    state = "code"
    quote = ""
    index = 0
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""

        if state == "line_comment":
            if char in "\r\n":
                result.append(char)
                state = "code"
            else:
                result.append(" ")
            index += 1
            continue

        if state == "block_comment":
            if char == "*" and following == "/":
                result.extend((" ", " "))
                index += 2
                state = "code"
            else:
                result.append(char if char in "\r\n" else " ")
                index += 1
            continue

        if state == "string":
            if char == "\\" and following:
                if mask_strings:
                    result.extend((" ", following if following in "\r\n" else " "))
                else:
                    result.extend((char, following))
                index += 2
                continue
            if char == quote:
                result.append(char)
                state = "code"
                quote = ""
            else:
                result.append(char if not mask_strings or char in "\r\n" else " ")
            index += 1
            continue

        if char == "/" and following == "/":
            result.extend((" ", " "))
            index += 2
            state = "line_comment"
            continue
        if char == "/" and following == "*":
            result.extend((" ", " "))
            index += 2
            state = "block_comment"
            continue
        if char == "#" and following != "[":
            result.append(" ")
            index += 1
            state = "line_comment"
            continue
        if char in {"'", '"'}:
            result.append(char)
            state = "string"
            quote = char
            index += 1
            continue
        result.append(char)
        index += 1
    return "".join(result)


def _top_level_php(source: str) -> str:
    """Return only executable PHP text outside function/class/closure bodies."""
    comments_stripped = _mask_non_code(source, mask_strings=False)
    code_masked = _mask_non_code(source, mask_strings=True)
    result = [char if char in "\r\n" else " " for char in source]
    depth = 0
    in_php = False
    index = 0
    while index < len(code_masked):
        if not in_php:
            if code_masked.startswith("<?php", index):
                in_php = True
                index += 5
                continue
            if code_masked.startswith("<?=", index):
                in_php = True
                index += 3
                continue
            if code_masked.startswith("<?", index):
                in_php = True
                index += 2
                continue
            index += 1
            continue
        if code_masked.startswith("?>", index):
            in_php = False
            depth = 0
            index += 2
            continue

        char = code_masked[index]
        if char == "}":
            depth = max(0, depth - 1)
        if depth == 0:
            result[index] = comments_stripped[index]
        if char == "{":
            depth += 1
        index += 1
    return "".join(result)


def _extract_direct_php_callbacks(
    plugin_dir: Path,
    php_files: list[str],
) -> list[dict[str, Any]]:
    """Find standalone PHP dispatch scripts omitted by WP hook discovery."""
    callbacks: list[dict[str, Any]] = []
    for rel in php_files:
        if Path(rel).suffix.lower() not in {".php", ".phtml"}:
            continue
        source_path = plugin_dir / rel
        try:
            source = source_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        comments_stripped = _mask_non_code(source, mask_strings=False)
        if _DIRECT_BOOTSTRAP_GUARD_RE.search(comments_stripped):
            continue
        # Keep only executable top-level tokens. In particular, examples such
        # as "$_GET" or "$app->run()" inside translations and comments must
        # not make an include-only view look like a public controller.
        top_level = _mask_non_code(_top_level_php(source), mask_strings=True)
        dispatch = _DIRECT_DISPATCH_RE.search(top_level)
        bootstrap = _DIRECT_LOCAL_BOOTSTRAP_RE.search(top_level)
        if (
            dispatch is None
            or bootstrap is None
            or bootstrap.start() > dispatch.start()
        ):
            continue
        request = _DIRECT_REQUEST_RE.search(top_level)
        # A dispatcher that visibly consumes request state is a definite direct
        # script. Without that signal it remains useful review coverage, but its
        # public reachability and authentication state are intentionally unknown.
        callback_type = "direct_php" if request is not None else "direct_php_candidate"
        line = source.count("\n", 0, dispatch.start()) + 1
        source_lines = source.splitlines()
        raw_line = source_lines[line - 1].strip() if source_lines else rel
        callbacks.append(
            {
                "type": callback_type,
                "name": rel,
                "file": rel,
                "line": line,
                # A top-level script has no PHP callback function. Keeping this empty
                # avoids pretending a common method name such as run() is globally
                # unique in the static call graph.
                "handler_function": "",
                "callback_kind": (
                    "direct_script"
                    if request is not None
                    else "direct_script_candidate"
                ),
                "raw": raw_line[:500],
            }
        )
    return callbacks


def normalize_entry_name(value: str) -> str:
    """Normalize route/action spacing without changing its semantic name."""
    return re.sub(r"\s*/\s*", "/", value.strip())


def _dedupe_entry_points(entries: list[EntryPoint]) -> list[EntryPoint]:
    """Collapse exact routes and cross-source representations of one callback."""
    exact: dict[tuple[str, str], EntryPoint] = {}
    for entry in entries:
        entry.name = normalize_entry_name(entry.name)
        key = (entry.type, entry.name)
        existing = exact.get(key)
        if existing is None or (
            existing.confidence != "high" and entry.confidence == "high"
        ):
            exact[key] = entry

    by_handler: dict[tuple[str, str], list[EntryPoint]] = {}
    passthrough: list[EntryPoint] = []
    for entry in exact.values():
        handler = entry.handler_function.strip()
        if handler.lower() in _GENERIC_HANDLER_NAMES:
            passthrough.append(entry)
            continue
        by_handler.setdefault((entry.type, handler), []).append(entry)

    for grouped in by_handler.values():
        surveyor = [entry for entry in grouped if entry.source != "deterministic"]
        deterministic = [entry for entry in grouped if entry.source == "deterministic"]
        if not surveyor or not deterministic:
            passthrough.extend(grouped)
            continue
        passthrough.extend(surveyor)
        if len(deterministic) > len(surveyor):
            passthrough.extend(deterministic[len(surveyor) :])
    return passthrough


def _code_files(plugin_dir: Path) -> tuple[list[str], list[str]]:
    production: list[str] = []
    dependencies: list[str] = []
    for path in sorted(plugin_dir.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in _CODE_EXTENSIONS:
            continue
        rel = path.relative_to(plugin_dir)
        lower_parts = {part.lower() for part in rel.parts[:-1]}
        if lower_parts & _NON_PRODUCTION_PARTS:
            continue
        if lower_parts & _DEPENDENCY_PARTS:
            dependencies.append(str(rel))
        else:
            production.append(str(rel))
    return production, dependencies


def _php_call_snippet(
    source: str,
    masked_source: str,
    match_start: int,
    match_end: int,
) -> str:
    """Return one bounded, balanced PHP call starting at a surface match."""
    opening = masked_source.find("(", match_start, match_end)
    if opening < 0:
        return ""

    limit = min(len(source), match_start + _SURFACE_SNIPPET_MAX_CHARS)
    depth = 0
    closing = -1
    for index in range(opening, limit):
        char = masked_source[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                closing = index + 1
                break
    end = closing if closing >= 0 else limit
    return source[match_start:end].strip()


def _php_call_arguments(snippet: str, function_name: str) -> list[str] | None:
    """Return the top-level arguments of one complete PHP call."""
    snippet = _mask_non_code(snippet, mask_strings=False)
    match = re.search(
        rf"(?<![A-Za-z0-9_]){re.escape(function_name)}\s*\(",
        snippet,
        re.IGNORECASE,
    )
    if match is None:
        return None

    opening = snippet.find("(", match.start())
    stack = ["("]
    pairs = {")": "(", "]": "[", "}": "{"}
    arguments: list[str] = []
    argument_start = opening + 1
    quote = ""
    escaped = False
    for index in range(opening + 1, len(snippet)):
        char = snippet[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {"'", '"', "`"}:
            quote = char
            continue
        if char in "([{":
            stack.append(char)
            continue
        if char in ")]}":
            if not stack or stack[-1] != pairs[char]:
                return None
            if len(stack) == 1:
                argument = snippet[argument_start:index].strip()
                if argument:
                    arguments.append(argument)
                return arguments
            stack.pop()
            continue
        if char == "," and len(stack) == 1:
            arguments.append(snippet[argument_start:index].strip())
            argument_start = index + 1
    return None


def _php_function_ranges(masked_source: str) -> list[tuple[int, int]]:
    """Return balanced named/anonymous function body ranges."""
    ranges: list[tuple[int, int]] = []
    for function_match in _PHP_FUNCTION_RE.finditer(masked_source):
        paren_depth = 0
        bracket_depth = 0
        body_start = -1
        for index in range(function_match.end(), len(masked_source)):
            char = masked_source[index]
            if char == "(":
                paren_depth += 1
            elif char == ")":
                paren_depth = max(0, paren_depth - 1)
            elif char == "[":
                bracket_depth += 1
            elif char == "]":
                bracket_depth = max(0, bracket_depth - 1)
            elif char == ";" and paren_depth == bracket_depth == 0:
                break
            elif char == "{" and paren_depth == bracket_depth == 0:
                body_start = index
                break
        if body_start < 0:
            continue

        depth = 0
        for index in range(body_start, len(masked_source)):
            char = masked_source[index]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    ranges.append((body_start, index + 1))
                    break
    return ranges


def _php_function_scope(
    function_ranges: list[tuple[int, int]],
    offset: int,
) -> tuple[int, int] | None:
    """Return the innermost PHP function containing an offset."""
    containing = [
        function_range
        for function_range in function_ranges
        if function_range[0] < offset < function_range[1]
    ]
    return max(containing, key=lambda function_range: function_range[0], default=None)


def _php_assignment_end(masked_source: str, start: int, limit: int) -> int:
    """Find a top-level semicolon terminating an assignment expression."""
    stack: list[str] = []
    pairs = {")": "(", "]": "[", "}": "{"}
    for index in range(start, limit):
        char = masked_source[index]
        if char in "([{":
            stack.append(char)
        elif char in ")]}":
            if stack and stack[-1] == pairs[char]:
                stack.pop()
        elif char == ";" and not stack:
            return index
    return -1


def _php_brace_depth(masked_source: str, offset: int) -> int:
    """Return lexical brace depth at an executable PHP offset."""
    return masked_source.count("{", 0, offset) - masked_source.count("}", 0, offset)


def _reaching_same_function_assignments(
    source: str,
    masked_source: str,
    function_ranges: list[tuple[int, int]],
    variable: str,
    before: int,
) -> list[str]:
    """Approximate branch-aware reaching definitions in one PHP function."""
    sink_scope = _php_function_scope(function_ranges, before)
    sink_depth = _php_brace_depth(masked_source, before)
    assignment_re = re.compile(rf"{re.escape(variable)}\s*=(?!=|>)")
    matches = list(assignment_re.finditer(masked_source, 0, before))
    assignments: list[tuple[int, str]] = []
    for match in matches:
        if _php_function_scope(function_ranges, match.start()) != sink_scope:
            continue
        expression_start = match.end()
        expression_end = _php_assignment_end(
            masked_source,
            expression_start,
            before,
        )
        if expression_end < 0:
            continue
        assignments.append(
            (
                _php_brace_depth(masked_source, match.start()),
                source[expression_start:expression_end].strip(),
            )
        )

    # A definition at the sink's own (or an outer) lexical depth dominates all
    # earlier definitions. Assignments nested after that reset may be mutually
    # exclusive branch definitions that still reach a sink outside the branch.
    reset_index = next(
        (
            index
            for index in range(len(assignments) - 1, -1, -1)
            if assignments[index][0] <= sink_depth
        ),
        None,
    )
    if reset_index is None:
        return [expression for _, expression in assignments]
    reset_expression = assignments[reset_index][1]
    return [
        reset_expression,
        *[
            expression
            for depth, expression in assignments[reset_index + 1 :]
            if depth > sink_depth
        ],
    ]


def _is_fixed_php_scalar(expression: str) -> bool:
    """Whether an expression is provably a fixed scalar literal."""
    expression = expression.strip()
    if re.fullmatch(
        r"[+-]?(?:0[xX][0-9A-Fa-f]+|(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)",
        expression,
    ):
        return True
    if expression.lower() in {"true", "false", "null"}:
        return True
    if re.fullmatch(r"'(?:\\.|[^'\\])*'", expression, re.DOTALL):
        return True
    if re.fullmatch(r'"(?:\\.|[^"\\])*"', expression, re.DOTALL):
        return "$" not in expression
    return False


def _is_current_user_identity(expression: str) -> bool:
    """Whether a selector is constrained to WordPress's current user id."""
    return _CURRENT_USER_ID_RE.fullmatch(expression.strip()) is not None


def _has_untrusted_php_variable(expression: str) -> bool:
    """Whether an expression contains a variable beyond the current-user id."""
    without_current_user = _CURRENT_USER_ID_RE.sub("", expression)
    return _BARE_PHP_VARIABLE_RE.search(without_current_user) is not None


def _php_array_entries(expression: str) -> list[str] | None:
    """Return entries from one complete inline PHP array."""
    expression = expression.strip()
    if re.match(r"array\s*\(", expression, re.IGNORECASE):
        if not expression.endswith(")"):
            return None
        return _php_call_arguments(expression, "array")
    if not (expression.startswith("[") and expression.endswith("]")):
        return None
    return _php_call_arguments(
        f"__squadrone_array({expression[1:-1]})",
        "__squadrone_array",
    )


def _php_array_pair(entry: str) -> tuple[str, str] | None:
    """Split a top-level associative-array entry around its arrow."""
    stack: list[str] = []
    pairs = {")": "(", "]": "[", "}": "{"}
    quote = ""
    escaped = False
    for index, char in enumerate(entry):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {"'", '"', "`"}:
            quote = char
            continue
        if char in "([{":
            stack.append(char)
            continue
        if char in ")]}":
            if stack and stack[-1] == pairs[char]:
                stack.pop()
            continue
        if char == "=" and not stack and entry[index : index + 2] == "=>":
            return entry[:index].strip(), entry[index + 2 :].strip()
    return None


def _identity_key(expression: str) -> bool:
    """Whether a fixed SQL/map key denotes a likely row identity."""
    expression = expression.strip()
    if (
        len(expression) >= 2
        and expression[0] == expression[-1]
        and expression[0]
        in {
            "'",
            '"',
        }
    ):
        expression = expression[1:-1]
    return (
        re.fullmatch(r"(?:id|[A-Za-z_][A-Za-z0-9_]*_id)", expression, re.I) is not None
    )


def _inline_where_map_has_dynamic_identity(expression: str) -> bool:
    entries = _php_array_entries(expression)
    if entries is None:
        return False
    for entry in entries:
        pair = _php_array_pair(entry)
        if pair is None:
            continue
        key, value = pair
        if (
            _identity_key(key)
            and not _is_fixed_php_scalar(value)
            and not _is_current_user_identity(value)
        ):
            return True
    return False


def _prepare_bound_values(arguments: list[str]) -> list[str]:
    """Normalize the variadic and legacy array forms of wpdb::prepare."""
    if len(arguments) != 1:
        return arguments
    entries = _php_array_entries(arguments[0])
    return entries if entries is not None else arguments


def _placeholder_value(
    query_expression: str,
    placeholder: re.Match[str],
    bound_values: list[str],
) -> str | None:
    explicit_position = placeholder.group("position")
    if explicit_position is not None:
        value_index = int(explicit_position) - 1
    else:
        value_index = (
            len(
                list(
                    _SQL_PLACEHOLDER_RE.finditer(query_expression, 0, placeholder.end())
                )
            )
            - 1
        )
    if 0 <= value_index < len(bound_values):
        return bound_values[value_index]
    return None


def _select_projection_is_pure_aggregate(
    query_expression: str,
    operation_end: int,
) -> bool:
    from_match = re.search(r"\bFROM\b", query_expression[operation_end:], re.IGNORECASE)
    if from_match is None:
        return False
    projection = query_expression[operation_end : operation_end + from_match.start()]
    aggregate = _SQL_AGGREGATE_RE.search(projection)
    if aggregate is None:
        return False

    remainder = list(projection)
    search_from = 0
    while aggregate is not None:
        opening = projection.find("(", aggregate.start(), aggregate.end())
        depth = 0
        closing = -1
        for index in range(opening, len(projection)):
            if projection[index] == "(":
                depth += 1
            elif projection[index] == ")":
                depth -= 1
                if depth == 0:
                    closing = index + 1
                    break
        if closing < 0:
            return False
        remainder[aggregate.start() : closing] = " " * (closing - aggregate.start())
        search_from = closing
        aggregate = _SQL_AGGREGATE_RE.search(projection, search_from)

    non_aggregate = "".join(remainder)
    non_aggregate = re.sub(
        r"\b(?:ALL|DISTINCT|SQL_CALC_FOUND_ROWS)\b",
        "",
        non_aggregate,
        flags=re.I,
    )
    non_aggregate = re.sub(
        r"\bAS\s+`?[A-Za-z_][A-Za-z0-9_]*`?",
        "",
        non_aggregate,
        flags=re.I,
    )
    return re.search(r"[A-Za-z0-9_$]", non_aggregate) is None


def _sql_expression_has_dynamic_identity(expression: str) -> bool:
    """Identify dynamic row-specific SELECT/UPDATE/DELETE expressions."""
    prepare_arguments = _php_call_arguments(expression, "prepare")
    if prepare_arguments:
        query_expression = prepare_arguments[0]
        bound_values = _prepare_bound_values(prepare_arguments[1:])
    else:
        query_expression = expression
        bound_values = []

    operation = _SQL_OPERATION_RE.search(query_expression)
    if operation is None or operation.group("operation").upper() not in {
        "SELECT",
        "UPDATE",
        "DELETE",
    }:
        return False
    if operation.group(
        "operation"
    ).upper() == "SELECT" and _select_projection_is_pure_aggregate(
        query_expression,
        operation.end(),
    ):
        return False

    for identity in _SQL_IDENTITY_PREDICATE_RE.finditer(
        query_expression,
        operation.end(),
    ):
        rhs = query_expression[identity.end() :]
        if identity.group("operator").upper().startswith("IN"):
            closing = rhs.find(")")
            placeholder_region = rhs if closing < 0 else rhs[:closing]
            relative_placeholders = list(
                _SQL_PLACEHOLDER_RE.finditer(placeholder_region)
            )
        else:
            first_placeholder = re.match(
                rf"\s*['\"]?\s*(?P<value>{_SQL_PLACEHOLDER_RE.pattern})",
                rhs,
            )
            relative_placeholders = (
                list(
                    _SQL_PLACEHOLDER_RE.finditer(
                        rhs,
                        0,
                        first_placeholder.end(),
                    )
                )
                if first_placeholder is not None
                else []
            )
        if relative_placeholders and bound_values:
            for relative_placeholder in relative_placeholders:
                absolute_placeholder = _SQL_PLACEHOLDER_RE.search(
                    query_expression,
                    identity.end() + relative_placeholder.start(),
                    identity.end() + relative_placeholder.end(),
                )
                if absolute_placeholder is None:
                    continue
                value = _placeholder_value(
                    query_expression,
                    absolute_placeholder,
                    bound_values,
                )
                if (
                    value is not None
                    and not _is_fixed_php_scalar(value)
                    and not _is_current_user_identity(value)
                ):
                    return True
            continue

        boundary = _SQL_CLAUSE_BOUNDARY_RE.search(rhs)
        selector_expression = rhs[: boundary.start()] if boundary else rhs
        if _has_untrusted_php_variable(selector_expression):
            return True
    return False


def _sql_object_access_review(
    *,
    surface_type: str,
    function_name: str,
    snippet: str,
    source: str,
    masked_source: str,
    function_ranges: list[tuple[int, int]],
    match_start: int,
) -> bool:
    """Whether one SQL surface merits a row-authorization review."""
    arguments = _php_call_arguments(snippet, function_name)
    if arguments is None:
        return False

    if surface_type == "sql_write":
        function_name = function_name.lower()
        if function_name not in {"update", "delete"}:
            return False
        where_index = 2 if function_name == "update" else 1
        if len(arguments) <= where_index:
            return False
        where_expression = arguments[where_index].strip()
        if _BARE_PHP_VARIABLE_RE.fullmatch(where_expression):
            where_expressions = _reaching_same_function_assignments(
                source,
                masked_source,
                function_ranges,
                where_expression,
                match_start,
            )
        else:
            where_expressions = [where_expression]
        return any(
            _inline_where_map_has_dynamic_identity(candidate)
            for candidate in where_expressions
        )

    if surface_type != "sql_query" or not arguments:
        return False
    query_expression = arguments[0].strip()
    if _BARE_PHP_VARIABLE_RE.fullmatch(query_expression):
        query_expressions = _reaching_same_function_assignments(
            source,
            masked_source,
            function_ranges,
            query_expression,
            match_start,
        )
    else:
        query_expressions = [query_expression]
    return any(
        _sql_expression_has_dynamic_identity(candidate)
        for candidate in query_expressions
    )


def _surface_items(
    plugin_dir: Path, production_files: list[str]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    raw_items: list[dict[str, Any]] = []
    static_sinks: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int, str]] = set()
    for rel in production_files:
        path = plugin_dir / rel
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        patterns = (
            _PHP_SURFACES
            if path.suffix.lower() in {".php", ".phtml", ".inc"}
            else _JS_SURFACES
        )
        scan_source = (
            _mask_non_code(source, mask_strings=True)
            if patterns is _PHP_SURFACES
            else source
        )
        function_ranges = (
            _php_function_ranges(scan_source) if patterns is _PHP_SURFACES else []
        )
        lines = source.splitlines(keepends=True)
        scan_lines = scan_source.splitlines(keepends=True)
        line_start = 0
        for line_no, (line, scan_line) in enumerate(zip(lines, scan_lines), 1):
            if not scan_line.strip():
                line_start += len(line)
                continue
            for surface_type, pattern, areas, kind in patterns:
                match = pattern.search(scan_line)
                if not match:
                    continue
                groups = match.groupdict()
                name = next((value for value in groups.values() if value), surface_type)
                key = (kind, rel, line_no, name)
                if key in seen:
                    continue
                seen.add(key)
                fallback_snippet = line[
                    max(0, match.start() - 200) : match.end() + 300
                ].strip()
                if patterns is _PHP_SURFACES and "(" in match.group(0):
                    snippet = (
                        _php_call_snippet(
                            source,
                            scan_source,
                            line_start + match.start(),
                            line_start + match.end(),
                        )
                        or fallback_snippet
                    )
                else:
                    snippet = fallback_snippet
                item_areas = list(areas)
                if patterns is _PHP_SURFACES and _sql_object_access_review(
                    surface_type=surface_type,
                    function_name=name,
                    snippet=snippet,
                    source=source,
                    masked_source=scan_source,
                    function_ranges=function_ranges,
                    match_start=line_start + match.start(),
                ):
                    item_areas = _review_areas_for_surface(
                        "sql_object_access",
                        item_areas,
                    )
                raw_items.append(
                    {
                        "kind": kind,
                        "review_areas": item_areas,
                        "type": surface_type,
                        "name": name,
                        "file": rel,
                        "line": line_no,
                        "column": match.start() + 1,
                        "snippet": snippet,
                    }
                )
                if kind == "sink":
                    static_sinks.append(
                        {
                            "type": surface_type,
                            "function": name,
                            "file": rel,
                            "line": line_no,
                            "tainted_args": [],
                            "source": "deterministic",
                        }
                    )
            line_start += len(line)
    return raw_items, static_sinks


def build_coverage_artifact(
    plugin_dir: Path,
) -> tuple[CoverageArtifact, list[dict[str, Any]], list[dict[str, Any]]]:
    """Enumerate shipped review surfaces before model-led recon begins."""
    production_files, dependency_files = _code_files(plugin_dir)
    php_files = [
        path
        for path in production_files
        if Path(path).suffix.lower() in {".php", ".phtml", ".inc"}
    ]
    callbacks = recon_helpers.extract_static_callbacks(plugin_dir, php_files=php_files)
    callbacks.extend(_extract_direct_php_callbacks(plugin_dir, php_files))
    raw_items, static_sinks = _surface_items(plugin_dir, production_files)

    for callback in callbacks:
        # Callback workflows own both authorization and reflected/rendered input
        # review. This preserves reflected-XSS coverage without turning every
        # generic echo/print operation into an independent task.
        areas = _review_areas_for_surface(
            "entry_point", ("authorization_workflows", "xss_lifecycle")
        )
        if callback["type"] in {"direct_php", "direct_php_candidate"}:
            if "injection_files" not in areas:
                areas.append("injection_files")
        callback_text = " ".join(
            str(callback.get(key) or "") for key in ("name", "handler_function", "file")
        )
        if _AUTH_FLOW_RE.search(callback_text):
            if "authentication" not in areas:
                areas.append("authentication")
        raw_items.append(
            {
                "kind": "entry_point",
                "review_areas": areas,
                "type": callback["type"],
                "name": callback["name"],
                "file": callback["file"],
                "line": callback["line"],
                "snippet": callback["raw"][:500],
                "handler_function": callback.get("handler_function") or "",
            }
        )

    raw_items.sort(
        key=lambda item: (
            item["file"],
            item["line"],
            item["kind"],
            item["type"],
            item["name"],
        )
    )
    items = [
        CoverageItem(id=f"cov-{index:04d}", **item)
        for index, item in enumerate(raw_items, 1)
    ]
    return (
        CoverageArtifact(
            production_files=production_files,
            dependency_files=dependency_files,
            items=items,
        ),
        callbacks,
        static_sinks,
    )


def _callback_access(callback: dict[str, Any]) -> tuple[bool, bool]:
    name = str(callback.get("name") or "").lower()
    ep_type = str(callback.get("type") or "")
    if ep_type == "direct_php":
        return False, True
    if ep_type == "direct_php_candidate":
        return False, False
    if "nopriv" in name or ep_type == "ajax_nopriv":
        return False, True
    if ep_type == "ajax_priv" or name.startswith("admin_post_"):
        return True, True
    if ep_type in {
        "shortcode",
        "block",
        "form_handler",
        "rest_route",
        "wc_ajax",
        "webhook",
    }:
        return False, False
    return False, False


def merge_deterministic_coverage(
    artifact: ReconArtifact,
    plugin_dir: Path,
    coverage: CoverageArtifact,
    callbacks: list[dict[str, Any]],
    static_sinks: list[dict[str, Any]],
) -> None:
    """Merge deterministic inventory into the canonical recon collections."""
    artifact.entry_points = _dedupe_entry_points(artifact.entry_points)
    existing_entries = {
        (ep.type, normalize_entry_name(ep.name)): ep for ep in artifact.entry_points
    }
    fallback_entries: dict[tuple[str, str], list[EntryPoint]] = {}
    for entry in artifact.entry_points:
        handler = entry.handler_function.strip()
        if handler.lower() not in _GENERIC_HANDLER_NAMES:
            fallback_entries.setdefault((entry.type, handler), []).append(entry)
    fallback_matches: set[int] = set()
    fn_map = recon_helpers.build_function_def_map(plugin_dir, coverage.production_files)
    for callback in callbacks:
        normalized_name = normalize_entry_name(callback["name"])
        key = (callback["type"], normalized_name)
        handler_file = callback["file"]
        handler_line = callback["line"]
        handler = callback.get("handler_function") or ""
        defloc = fn_map.get(handler) if callback["type"] != "direct_php" else None
        if defloc and ":" in defloc:
            candidate_file, candidate_line = defloc.rsplit(":", 1)
            try:
                handler_file, handler_line = candidate_file, int(candidate_line)
            except ValueError:
                pass
        body = (
            recon_helpers.extract_body_slice(
                plugin_dir, handler_file, handler_line, max_lines=200
            )
            or ""
        )
        requires_auth, access_known = _callback_access(callback)
        existing = existing_entries.get(key)
        if existing is None and handler.lower() not in _GENERIC_HANDLER_NAMES:
            existing = next(
                (
                    entry
                    for entry in fallback_entries.get((callback["type"], handler), [])
                    if id(entry) not in fallback_matches
                ),
                None,
            )
        if existing is not None:
            fallback_matches.add(id(existing))
            if handler:
                existing.handler_function = handler
            if defloc:
                existing.file = handler_file
                existing.line = handler_line
                existing.confidence = "high"
            existing.body_slice = existing.body_slice or body or None
            existing.has_nonce_check = existing.has_nonce_check or bool(
                _NONCE_RE.search(body)
            )
            existing.has_capability_check = existing.has_capability_check or bool(
                _CAP_RE.search(body)
            )
            existing.access_known = existing.access_known or access_known
            continue
        artifact.entry_points.append(
            EntryPoint(
                type=callback["type"],
                name=normalized_name,
                file=handler_file,
                line=handler_line,
                handler_function=handler,
                requires_auth=requires_auth,
                has_nonce_check=bool(_NONCE_RE.search(body)),
                has_capability_check=bool(_CAP_RE.search(body)),
                body_slice=body or None,
                confidence=(
                    "high" if defloc or callback["type"] == "direct_php" else "medium"
                ),
                source="deterministic",
                access_known=access_known,
            )
        )
        existing_entries[key] = artifact.entry_points[-1]

    deduped_sinks: dict[tuple[str, int, str], Sink] = {}
    for sink in artifact.sinks:
        sink_key = (sink.file, sink.line, sink.function)
        sink_existing = deduped_sinks.get(sink_key)
        if sink_existing is None or (
            not sink_existing.tainted_args and sink.tainted_args
        ):
            deduped_sinks[sink_key] = sink
    artifact.sinks = list(deduped_sinks.values())
    existing_sinks = {
        (sink.file, sink.line, sink.function): sink for sink in artifact.sinks
    }
    for raw in static_sinks:
        sink_key = (raw["file"], raw["line"], raw["function"])
        if sink_key not in existing_sinks:
            artifact.sinks.append(Sink.model_validate(raw))
            existing_sinks[sink_key] = artifact.sinks[-1]

    # The surveyor can resolve dynamic registrations and operations that regex
    # cannot. Add those to the same ledger so model-led discoveries do not bypass
    # coverage accounting.
    next_id = len(coverage.items) + 1
    covered_entries = {
        (item.type, normalize_entry_name(item.name))
        for item in coverage.items
        if item.kind == "entry_point"
    }
    covered_handlers = {
        (item.type, item.handler_function)
        for item in coverage.items
        if item.kind == "entry_point"
        and item.handler_function.lower() not in _GENERIC_HANDLER_NAMES
    }
    for ep in artifact.entry_points:
        ep.name = normalize_entry_name(ep.name)
        if (ep.type, ep.name) in covered_entries or (
            ep.type,
            ep.handler_function,
        ) in covered_handlers:
            continue
        entry_areas = _review_areas_for_surface(
            "entry_point", ("authorization_workflows", "xss_lifecycle")
        )
        if _AUTH_FLOW_RE.search(" ".join((ep.name, ep.handler_function, ep.file))):
            if "authentication" not in entry_areas:
                entry_areas.append("authentication")
        coverage.items.append(
            CoverageItem(
                id=f"cov-{next_id:04d}",
                kind="entry_point",
                review_areas=entry_areas,
                type=ep.type,
                name=ep.name,
                file=ep.file,
                line=ep.line,
                snippet=(ep.body_slice or "").splitlines()[0][:500]
                if ep.body_slice
                else ep.name,
                handler_function=ep.handler_function,
            )
        )
        next_id += 1

    covered_sinks = {
        (item.file, item.line, item.name)
        for item in coverage.items
        if item.kind != "entry_point"
    }
    for sink in artifact.sinks:
        if (sink.file, sink.line, sink.function) in covered_sinks:
            continue
        haystack = " ".join((sink.type, sink.function)).lower()
        if re.search(
            r"sql|query|file|upload|unlink|include|require|remote|curl|xml|unserial|exec|system",
            haystack,
        ):
            sink_areas: list[ReviewArea] = ["injection_files"]
        elif re.search(r"echo|print|render|html|json", haystack):
            sink_areas = ["xss_lifecycle"]
        elif _AUTH_FLOW_RE.search(haystack):
            sink_areas = ["authentication"]
        else:
            sink_areas = ["authorization_workflows"]
        sink_areas = _review_areas_for_surface(sink.type, sink_areas)
        snippet = ""
        source_path = plugin_dir / sink.file
        try:
            source_lines = source_path.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
            if 0 < sink.line <= len(source_lines):
                snippet = source_lines[sink.line - 1].strip()[:500]
        except OSError:
            pass
        coverage.items.append(
            CoverageItem(
                id=f"cov-{next_id:04d}",
                kind="sink",
                review_areas=sink_areas,
                type=sink.type,
                name=sink.function,
                file=sink.file,
                line=sink.line,
                snippet=snippet,
            )
        )
        next_id += 1

    artifact.entry_points.sort(key=lambda ep: (ep.file, ep.line, ep.name))
    artifact.sinks.sort(key=lambda sink: (sink.file, sink.line, sink.function))
    artifact.coverage = coverage
