"""Deterministic production-surface inventory and review ledger helpers."""

from __future__ import annotations

import re
from bisect import bisect_right
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
_PHP_PROPERTY_LVALUE_RE = re.compile(
    r"\$(?P<object>this)\s*->\s*(?P<property>[A-Za-z_][A-Za-z0-9_]*)"
)
_PHP_LITERAL_ARRAY_LVALUE_RE = re.compile(
    r"\$(?P<array>[A-Za-z_][A-Za-z0-9_]*)\s*\[\s*"
    r"(?P<quote>['\"])(?P<key>[A-Za-z_][A-Za-z0-9_.:-]{0,127})(?P=quote)\s*\]"
)
_PHP_LITERAL_NUMERIC_ARRAY_LVALUE_RE = re.compile(
    r"\$(?P<array>[A-Za-z_][A-Za-z0-9_]*)\s*\[\s*"
    r"(?P<key>-?(?:0|[1-9][0-9]{0,127}))\s*\]"
)
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

_COMMAND_FUNCTION_NAMES = (
    "exec",
    "shell_exec",
    "system",
    "passthru",
    "popen",
    "proc_open",
    "pcntl_exec",
    "expect_popen",
)
_COMMAND_FUNCTION_TOKEN_RE = re.compile(
    r"(?<![$A-Za-z0-9_])(?P<fn>"
    + "|".join(re.escape(name) for name in _COMMAND_FUNCTION_NAMES)
    + r")\b",
    re.IGNORECASE,
)
_COMMAND_RECEIVER_RE = re.compile(r"(?:->|::)\s*$")
_FUNCTION_DECLARATION_RE = re.compile(r"\bfunction\s+&?\s*$", re.IGNORECASE)
_PERSISTENT_GETTER_RE = re.compile(
    r"\b(?P<fn>get_option|get_site_option|get_transient|get_site_transient|"
    r"get_metadata|get_[A-Za-z_][A-Za-z0-9_]*_meta)\s*\(",
    re.IGNORECASE,
)
_PERSISTENT_CORE_FIELD_RE = re.compile(
    r"\b(?P<fn>get_post_field|get_comment_field|get_term_field|"
    r"get_the_author_meta|get_user_option)\s*\(",
    re.IGNORECASE,
)
_PERSISTENT_WPDB_READ_RE = re.compile(
    r"\$wpdb\s*->\s*(?P<fn>get_results|get_row|get_var|get_col)\s*\(",
    re.IGNORECASE,
)
_UPLOAD_POLICY_HOOKS = (
    "upload_mimes",
    "mime_types",
    "ext2type",
    "wp_check_filetype_and_ext",
    "wp_handle_upload_prefilter",
    "wp_handle_sideload_prefilter",
    "wp_handle_upload_overrides",
    "wp_handle_sideload_overrides",
    "pre_move_uploaded_file",
    "sanitize_file_name",
    "sanitize_file_name_chars",
    "upload_dir",
)
_UPLOAD_POLICY_FILTER_RE = re.compile(
    r"\badd_filter\s*\(\s*(['\"])(?P<hook>"
    + "|".join(re.escape(hook) for hook in _UPLOAD_POLICY_HOOKS)
    + r")\1\s*,",
    re.IGNORECASE,
)
_ADD_FILTER_TOKEN_RE = re.compile(r"\badd_filter\s*\(", re.IGNORECASE)
_PHP_HEREDOC_START_RE = re.compile(
    r"<<<[ \t]*(?:(?P<quote>['\"])(?P<quoted>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?P=quote)|(?P<bare>[A-Za-z_][A-Za-z0-9_]*))[ \t]*\r?\n"
)
_FILESYSTEM_OBJECT_METHOD_RE = re.compile(
    r"(?:\$(?:wp_?filesystem|file_?system|fs|storage|uploads?|files?|"
    r"(?:filesystem_?)?adapter)|"
    r"\$[A-Za-z_][A-Za-z0-9_]*(?:\s*->\s*[A-Za-z_][A-Za-z0-9_]*)*"
    r"\s*->\s*(?:filesystem|file_system|storage|uploads?|files?|"
    r"(?:filesystem_?)?adapter))"
    r"\s*->\s*(?P<method>put_contents|move|copy|write|writeStream)\s*\(",
    re.IGNORECASE,
)
_FILESYSTEM_OBJECT_DELETE_METHOD_RE = re.compile(
    r"(?:\$(?:wp_?filesystem|file_?system|fs|storage|uploads?|files?|"
    r"(?:filesystem_?)?adapter)|"
    r"\$[A-Za-z_][A-Za-z0-9_]*(?:\s*->\s*[A-Za-z_][A-Za-z0-9_]*)*"
    r"\s*->\s*(?:filesystem|file_system|storage|uploads?|files?|"
    r"(?:filesystem_?)?adapter))"
    r"\s*->\s*(?P<method>delete)\s*\(",
    re.IGNORECASE,
)
_HIGH_SIGNAL_FUNCTION_TOKEN_RE = re.compile(
    r"\b(?:call_user_func|call_user_func_array|forward_static_call|"
    r"forward_static_call_array|unzip_file|_unzip_file_ziparchive|"
    r"_unzip_file_pclzip|file_put_contents|fwrite|fputs|fopen|copy|rename|"
    r"touch|symlink|link|"
    r"move_uploaded_file|wp_handle_upload|wp_handle_sideload|"
    r"media_handle_upload|media_handle_sideload|wp_upload_bits|"
    r"stream_copy_to_stream|unlink|rmdir|wp_delete_file|"
    r"wp_delete_file_from_directory)\b",
    re.IGNORECASE,
)
_HIGH_SIGNAL_INJECTION_CODE_RE = re.compile(
    r"(?:"
    r"\$_FILES\b|"
    r"\bnew\s+(?:\\?[A-Za-z_][A-Za-z0-9_]*\\)*"
    r"(?:Process|PclZip|Archive_Tar|ZipArchive|PharData)\s*\(|"
    r"\b(?:Process|WP_CLI)\s*::\s*(?:fromShellCommandline|runcommand|launch|launch_self)\s*\(|"
    r"\$(?:(?:archive|zip|tar|phar)[A-Za-z0-9_]*|"
    r"[A-Za-z_][A-Za-z0-9_]*(?:archive|zip|tar|phar)[A-Za-z0-9_]*)"
    r"\s*->\s*(?:extract|extractByIndex|extractModify|extractTo)\s*\("
    r")",
    re.IGNORECASE,
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
        _COMMAND_FUNCTION_TOKEN_RE,
        ["injection_files"],
        "sink",
    ),
    (
        "command_wrapper",
        re.compile(
            r"(?:\bnew\s+(?:\\?[A-Za-z_][A-Za-z0-9_]*\\)*"
            r"(?P<class>Process)\s*\(|"
            r"\b(?P<static_class>Process)\s*::\s*"
            r"(?P<method>fromShellCommandline)\s*\()",
            re.IGNORECASE,
        ),
        ["injection_files"],
        "review_anchor",
    ),
    (
        "command_wrapper",
        re.compile(
            r"(?:\b(?P<static_class>WP_CLI)\s*::\s*"
            r"(?P<static_method>runcommand|launch|launch_self)\s*\(|"
            r"\$(?:process|proc|command|cmd)[A-Za-z0-9_]*\s*->\s*"
            r"(?P<method>run|mustRun|start)\s*\()",
            re.IGNORECASE,
        ),
        ["injection_files"],
        "sink",
    ),
    (
        "dynamic_callable",
        re.compile(
            r"\b(?P<fn>call_user_func|call_user_func_array|"
            r"forward_static_call|forward_static_call_array)\s*\(|"
            r"\$(?:reflect|reflection|reflector)[A-Za-z0-9_]*\s*->\s*"
            r"(?P<method>invoke|invokeArgs)\s*\(",
            re.IGNORECASE,
        ),
        ["injection_files"],
        "sink",
    ),
    (
        "dynamic_callable",
        re.compile(
            r"\bnew\s+(?P<class>ReflectionFunction|ReflectionMethod)\s*\(",
            re.IGNORECASE,
        ),
        ["injection_files"],
        "review_anchor",
    ),
    (
        "php_code_execution",
        # eval is a language construct and PHP permits whitespace/newlines before
        # its opening parenthesis. Match the executable token here; statement
        # extraction below captures and validates the complete construct.
        re.compile(r"(?<![$A-Za-z0-9_])(?P<fn>eval)\b", re.IGNORECASE),
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
            r"\b(?P<fn>move_uploaded_file|wp_handle_upload|media_handle_upload|"
            r"wp_handle_sideload|media_handle_sideload|wp_upload_bits)\s*\(",
            re.IGNORECASE,
        ),
        ["injection_files"],
        "sink",
    ),
    (
        "archive_extract",
        re.compile(
            r"(?:\b(?P<fn>unzip_file|_unzip_file_ziparchive|"
            r"_unzip_file_pclzip)\s*\(|"
            r"\$(?:(?:archive|zip|tar|phar)[A-Za-z0-9_]*|"
            r"[A-Za-z_][A-Za-z0-9_]*(?:archive|zip|tar|phar)[A-Za-z0-9_]*)"
            r"\s*->\s*(?P<method>extract|extractByIndex|extractModify|extractTo)\s*\()",
            re.IGNORECASE,
        ),
        ["injection_files"],
        "sink",
    ),
    (
        "archive_extract",
        re.compile(
            r"\bnew\s+(?P<class>(?:\\?[A-Za-z_][A-Za-z0-9_]*\\)*"
            r"(?:PclZip|Archive_Tar|ZipArchive|PharData))\s*\(",
            re.IGNORECASE,
        ),
        ["injection_files"],
        "review_anchor",
    ),
    (
        "file_write",
        re.compile(
            r"\b(?P<fn>file_put_contents|fwrite|fputs|fopen|copy|rename|touch|"
            r"symlink|link|stream_copy_to_stream)\s*\(",
            re.IGNORECASE,
        ),
        ["injection_files"],
        "sink",
    ),
    (
        "file_write",
        _FILESYSTEM_OBJECT_METHOD_RE,
        ["injection_files"],
        "sink",
    ),
    (
        "file_delete",
        re.compile(
            r"\b(?P<fn>unlink|rmdir|wp_delete_file|"
            r"wp_delete_file_from_directory)\s*\(",
            re.IGNORECASE,
        ),
        ["injection_files"],
        "sink",
    ),
    (
        "file_delete",
        _FILESYSTEM_OBJECT_DELETE_METHOD_RE,
        ["injection_files"],
        "sink",
    ),
    (
        "file_read",
        re.compile(
            r"(?:\b(?P<fn>file_get_contents|readfile|readgzfile|fpassthru|fread|"
            r"stream_get_contents|gzfile|file|glob|SplFileObject)\s*\(|"
            r"\$[A-Za-z_][A-Za-z0-9_]*(?:\s*->\s*[A-Za-z_][A-Za-z0-9_]*)*"
            r"\s*->\s*(?P<method>get_contents|get_contents_array)\s*\()",
            re.IGNORECASE,
        ),
        ["injection_files"],
        "sink",
    ),
    (
        "dynamic_include",
        re.compile(
            r"\b(?P<fn>include|include_once|require|require_once)\b",
            re.IGNORECASE,
        ),
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
_VARIABLE_FUNCTION_CALL_RE = re.compile(
    r"(?<![A-Za-z0-9_>$:])\$(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\("
)
_VARIABLE_METHOD_CALL_RE = re.compile(
    r"\$(?P<dynamic_class>[A-Za-z_][A-Za-z0-9_]*)\s*::\s*"
    r"(?:\$(?P<dynamic_static_method>[A-Za-z_][A-Za-z0-9_]*)|"
    r"\{\s*\$(?P<braced_static_method>[A-Za-z_][A-Za-z0-9_]*)\s*\})\s*\(|"
    r"\$(?P<class_selector>[A-Za-z_][A-Za-z0-9_]*)\s*::\s*"
    r"[A-Za-z_][A-Za-z0-9_]*\s*\(|"
    r"(?:\$[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_\\][A-Za-z0-9_\\]*)\s*"
    r"(?:->|::)\s*(?:\$(?P<method>[A-Za-z_][A-Za-z0-9_]*)|"
    r"\{\s*\$(?P<braced_method>[A-Za-z_][A-Za-z0-9_]*)\s*\})\s*\("
)
_DIRECT_REQUEST_METHOD_CALL_RE = re.compile(
    r"(?:\$[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_\\][A-Za-z0-9_\\]*)\s*"
    r"(?:->|::)\s*\{(?P<expression>[^{}\r\n]{1,500})\}\s*\("
)
_DIRECT_REQUEST_FUNCTION_CALL_RE = re.compile(
    r"(?:"
    r"\(\s*(?P<parenthesized>\$_(?:GET|POST|REQUEST|FILES|COOKIE|SERVER)"
    r"\s*(?:\[[^\]\r\n]{0,200}\]\s*)+)\)\s*\(|"
    r"(?P<direct>\$_(?:GET|POST|REQUEST|FILES|COOKIE|SERVER)"
    r"\s*(?:\[[^\]\r\n]{0,200}\]\s*)+)\("
    r")",
    re.IGNORECASE,
)
_CALLBACK_EXECUTION_API_RE = re.compile(
    r"\b(?P<fn>array_map|array_filter|array_walk|array_walk_recursive|"
    r"usort|uasort|uksort|preg_replace_callback|register_shutdown_function|"
    r"set_error_handler|set_exception_handler|iterator_apply)\s*\(",
    re.IGNORECASE,
)
_CALLBACK_EXECUTION_ARGUMENT = {
    "array_map": 0,
    "array_filter": 1,
    "array_walk": 1,
    "array_walk_recursive": 1,
    "usort": 1,
    "uasort": 1,
    "uksort": 1,
    "preg_replace_callback": 1,
    "register_shutdown_function": 0,
    "set_error_handler": 0,
    "set_exception_handler": 0,
    "iterator_apply": 1,
}
_COMMAND_CALLBACK_DATA_ARGUMENTS: dict[str, tuple[int, ...] | None] = {
    # None means every argument after the callback operand is passed through.
    "array_map": None,
    "array_filter": (0,),
    "register_shutdown_function": None,
}
_COMMAND_CALLBACK_ARITIES = {
    # Exclude callback arities that would bind an internal by-reference
    # parameter: callback dispatchers cannot establish those references.
    "exec": {1},
    "shell_exec": {1},
    "system": {1},
    "passthru": {1},
    "popen": {2},
    "pcntl_exec": {1, 2, 3},
    "expect_popen": {1},
}
_FIXED_CALLBACK_RE = re.compile(
    r"(?P<quote>['\"])(?P<name>\\?[A-Za-z_][A-Za-z0-9_]*)\1",
    re.IGNORECASE,
)
_SYMFONY_PROCESS_USE_RE = re.compile(
    r"\buse\s+\\?Symfony\\Component\\Process\\Process"
    r"(?:\s+as\s+(?P<alias>[A-Za-z_][A-Za-z0-9_]*))?\s*;",
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


def _mask_outside_php(source: str) -> str:
    """Mask non-PHP template regions while preserving byte offsets and lines.

    Files without an opening tag are treated as PHP fragments because this
    helper is also used on extracted function bodies.  Once a PHP tag is
    present, HTML and JavaScript outside PHP regions must not become PHP sink
    candidates.  The small lexer deliberately honours strings, comments, and
    heredocs so a literal ``?>`` does not end the executable region.
    """
    if "<?" not in source:
        return source

    result = [char if char in "\r\n" else " " for char in source]
    state = "outside"
    quote = ""
    heredoc_end = -1
    index = 0
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""

        if state == "outside":
            if char == "<" and following == "?":
                state = "code"
                # Tags themselves cannot contain a reviewed sink, so leave
                # them masked and begin copying immediately after the tag.
                if source.startswith("<?php", index):
                    index += 5
                elif source.startswith("<?=", index):
                    index += 3
                else:
                    index += 2
                continue
            index += 1
            continue

        result[index] = char

        if state == "line_comment":
            if char == "?" and following == ">":
                result[index + 1] = following
                state = "outside"
                index += 2
            elif char in "\r\n":
                state = "code"
                index += 1
            else:
                index += 1
            continue

        if state == "block_comment":
            if char == "*" and following == "/":
                result[index + 1] = following
                state = "code"
                index += 2
            else:
                index += 1
            continue

        if state == "string":
            if char == "\\" and following:
                result[index + 1] = following
                index += 2
            elif char == quote:
                state = "code"
                quote = ""
                index += 1
            else:
                index += 1
            continue

        if state == "heredoc":
            if index >= heredoc_end:
                state = "code"
                heredoc_end = -1
                continue
            index += 1
            continue

        if source.startswith("<<<", index):
            heredoc = _PHP_HEREDOC_START_RE.match(source, index)
            if heredoc is not None:
                label = heredoc.group("quoted") or heredoc.group("bare")
                terminator = re.compile(
                    rf"(?m)^[ \t]*{re.escape(label)}(?![A-Za-z0-9_])"
                ).search(source, heredoc.end())
                state = "heredoc"
                heredoc_end = (
                    terminator.end() if terminator is not None else len(source)
                )
                index += 1
                continue

        if char == "?" and following == ">":
            result[index + 1] = following
            state = "outside"
            index += 2
            continue
        if char == "/" and following == "/":
            result[index + 1] = following
            state = "line_comment"
            index += 2
            continue
        if char == "/" and following == "*":
            result[index + 1] = following
            state = "block_comment"
            index += 2
            continue
        if char == "#" and following != "[":
            state = "line_comment"
            index += 1
            continue
        if char in {"'", '"', "`"}:
            state = "string"
            quote = char
        index += 1
    return "".join(result)


def _mask_non_code(
    source: str,
    *,
    mask_strings: bool,
    preserve_interpolated_variables: bool = False,
) -> str:
    """Mask comments (and optionally strings) without changing source offsets.

    ``preserve_interpolated_variables`` is deliberately narrow: when string
    masking is enabled, it retains exact local/property/literal-array values
    from double-quoted strings and interpolating heredocs only. Single-quoted
    strings, nowdocs, and escaped dollar signs remain masked. This lets the
    persistent-SQL tracer follow stored values through PHP interpolation
    without exposing arbitrary string contents to broader surface scanners.
    """
    result: list[str] = []
    state = "code"
    quote = ""
    heredoc_end = -1
    heredoc_interpolates = False
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
            if (
                mask_strings
                and preserve_interpolated_variables
                and quote == '"'
                and char == "$"
                and (index == 0 or source[index - 1] != "$")
            ):
                lvalue_end = _simple_php_lvalue_end(source, index)
                if lvalue_end is not None:
                    result.extend(source[index:lvalue_end])
                    index = lvalue_end
                    continue
            if char == quote:
                result.append(char)
                state = "code"
                quote = ""
            else:
                result.append(char if not mask_strings or char in "\r\n" else " ")
            index += 1
            continue

        if state == "heredoc":
            if index >= heredoc_end:
                state = "code"
                heredoc_end = -1
                heredoc_interpolates = False
                continue
            if (
                mask_strings
                and preserve_interpolated_variables
                and heredoc_interpolates
                and char == "$"
                and (index == 0 or source[index - 1] != "$")
            ):
                backslash_count = 0
                cursor = index - 1
                while cursor >= 0 and source[cursor] == "\\":
                    backslash_count += 1
                    cursor -= 1
                lvalue_end = _simple_php_lvalue_end(source, index)
                if lvalue_end is not None and backslash_count % 2 == 0:
                    result.extend(source[index:lvalue_end])
                    index = lvalue_end
                    continue
            result.append(char if not mask_strings or char in "\r\n" else " ")
            index += 1
            continue

        if source.startswith("<<<", index):
            heredoc = _PHP_HEREDOC_START_RE.match(source, index)
            if heredoc is not None:
                label = heredoc.group("quoted") or heredoc.group("bare")
                terminator = re.compile(
                    rf"(?m)^[ \t]*{re.escape(label)}(?![A-Za-z0-9_])"
                ).search(source, heredoc.end())
                state = "heredoc"
                heredoc_end = (
                    terminator.end() if terminator is not None else len(source)
                )
                heredoc_interpolates = heredoc.group("quote") != "'"
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
        if char in {"'", '"', "`"}:
            result.append(char)
            state = "string"
            quote = char
            index += 1
            continue
        result.append(char)
        index += 1
    return "".join(result)


def _is_direct_command_call(
    masked_source: str,
    match_start: int,
    match_end: int,
) -> bool:
    """Accept direct PHP command calls while excluding methods/declarations."""
    prefix = masked_source[max(0, match_start - 80) : match_start]
    if _COMMAND_RECEIVER_RE.search(prefix):
        return False
    if _FUNCTION_DECLARATION_RE.search(prefix):
        return False
    # A leading global namespace separator still resolves the PHP builtin, but
    # Foo\exec() may be an unrelated namespaced helper rather than an OS sink.
    if re.search(r"[A-Za-z_][A-Za-z0-9_]*\\\s*$", prefix):
        return False
    suffix = masked_source[match_end : match_end + 256]
    return re.match(r"\s*\(", suffix) is not None


def _is_unqualified_function_call(masked_source: str, match_start: int) -> bool:
    """Reject method, declaration, and namespaced lookalikes for PHP builtins."""
    prefix = masked_source[max(0, match_start - 80) : match_start]
    if _COMMAND_RECEIVER_RE.search(prefix):
        return False
    if _FUNCTION_DECLARATION_RE.search(prefix):
        return False
    return re.search(r"[A-Za-z_][A-Za-z0-9_]*\\\s*$", prefix) is None


def _php_backtick_spans(
    source: str,
    *,
    max_chars: int = 2_000,
    assume_php_fragment: bool = False,
) -> list[tuple[int, int]]:
    """Return bounded executable PHP backtick spans, excluding comments/strings."""
    spans: list[tuple[int, int]] = []
    state = "code"
    quote = ""
    opening = -1
    escaped = False
    index = 0
    in_php = assume_php_fragment or "<?" not in source
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""

        if not in_php:
            if char == "<" and following == "?":
                in_php = True
                index += 2
            else:
                index += 1
            continue

        if state == "code" and source.startswith("<<<", index):
            heredoc = _PHP_HEREDOC_START_RE.match(source, index)
            if heredoc is not None:
                label = heredoc.group("quoted") or heredoc.group("bare")
                terminator = re.compile(
                    rf"(?m)^[ \t]*{re.escape(label)}(?![A-Za-z0-9_])"
                ).search(source, heredoc.end())
                index = terminator.end() if terminator is not None else len(source)
                continue

        if state == "line_comment":
            # In PHP, a closing tag also terminates // and # comments. Resume
            # scanning as template text so JavaScript template literals after
            # it cannot be mistaken for executable PHP backticks.
            if char == "?" and following == ">":
                state = "code"
                in_php = False
                index += 2
                continue
            if char in "\r\n":
                state = "code"
            index += 1
            continue
        if state == "block_comment":
            if char == "*" and following == "/":
                state = "code"
                index += 2
            else:
                index += 1
            continue
        if state == "string":
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                state = "code"
                quote = ""
            index += 1
            continue
        if state == "backtick":
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == "`":
                if index + 1 - opening <= max_chars:
                    spans.append((opening, index + 1))
                state = "code"
                opening = -1
            index += 1
            continue

        if char == "?" and following == ">":
            in_php = False
            index += 2
            continue

        if char == "/" and following == "/":
            state = "line_comment"
            index += 2
            continue
        if char == "/" and following == "*":
            state = "block_comment"
            index += 2
            continue
        if char == "#" and following != "[":
            state = "line_comment"
            index += 1
            continue
        if char in {"'", '"'}:
            state = "string"
            quote = char
            escaped = False
            index += 1
            continue
        if char == "`":
            state = "backtick"
            opening = index
            escaped = False
        index += 1
    return spans


def _has_high_signal_injection_surface(
    source: str,
    *,
    assume_php_fragment: bool = False,
    command_wrapper_aliases: Iterable[str] = (),
) -> bool:
    """Whether a callback/file contains a focused injection/filesystem signal."""
    php_source = source if assume_php_fragment else _mask_outside_php(source)
    code = _mask_non_code(php_source, mask_strings=True)
    if _HIGH_SIGNAL_INJECTION_CODE_RE.search(code):
        return True
    if _FILESYSTEM_OBJECT_METHOD_RE.search(code):
        return True
    if _FILESYSTEM_OBJECT_DELETE_METHOD_RE.search(code):
        return True
    process_aliases = {
        *command_wrapper_aliases,
        *_symfony_process_aliases(code),
    }
    if _aliased_process_constructor_matches(code, process_aliases):
        return True
    if any(
        _is_unqualified_function_call(code, match.start())
        and re.match(r"\s*\(", code[match.end() : match.end() + 64])
        for match in _HIGH_SIGNAL_FUNCTION_TOKEN_RE.finditer(code)
    ):
        return True
    if _request_selected_variable_call_matches(
        code,
        _php_function_ranges(code),
    ):
        return True
    if _direct_request_function_call_matches(code):
        return True
    if _request_selected_callback_matches(
        php_source,
        code,
        _php_function_ranges(code),
    ):
        return True
    if _fixed_command_callback_matches(
        php_source,
        code,
        _php_function_ranges(code),
    ):
        return True
    if _request_selected_method_call_matches(
        code,
        _php_function_ranges(code),
    ):
        return True
    if any(
        _is_direct_command_call(code, match.start(), match.end())
        for match in _COMMAND_FUNCTION_TOKEN_RE.finditer(code)
    ):
        return True
    if _php_backtick_spans(source, assume_php_fragment=assume_php_fragment):
        return True
    comments_stripped = _mask_non_code(php_source, mask_strings=False)
    raw_input = re.compile(
        r"\bfile_get_contents\s*\(\s*(['\"])php://input\1",
        re.IGNORECASE,
    )
    has_raw_input = any(
        code[match.start() :].lstrip().lower().startswith("file_get_contents")
        for match in raw_input.finditer(comments_stripped)
    )
    return has_raw_input or bool(_upload_policy_matches(source))


def _upload_policy_matches(source: str) -> list[re.Match[str]]:
    """Find upload-policy registrations without matching examples in strings."""
    php_source = _mask_outside_php(source)
    code = _mask_non_code(php_source, mask_strings=True)
    comments_stripped = _mask_non_code(php_source, mask_strings=False)
    matches: list[re.Match[str]] = []
    for token in _ADD_FILTER_TOKEN_RE.finditer(code):
        match = _UPLOAD_POLICY_FILTER_RE.match(comments_stripped, token.start())
        if match is not None:
            matches.append(match)
    return matches


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


def _php_statement_snippet(
    source: str,
    masked_source: str,
    line_start: int,
    match_start: int,
) -> str:
    """Return one bounded PHP statement, retaining multiline operands."""
    limit = min(len(source), match_start + _SURFACE_SNIPPET_MAX_CHARS)
    round_depth = 0
    square_depth = 0
    brace_depth = 0
    end = -1
    for index in range(match_start, limit):
        char = masked_source[index]
        if char == "(":
            round_depth += 1
        elif char == ")":
            round_depth = max(0, round_depth - 1)
        elif char == "[":
            square_depth += 1
        elif char == "]":
            square_depth = max(0, square_depth - 1)
        elif char == "{":
            brace_depth += 1
        elif char == "}":
            brace_depth = max(0, brace_depth - 1)
        elif char == ";" and not (round_depth or square_depth or brace_depth):
            end = index + 1
            break
    if end < 0:
        end = limit
    return source[line_start:end].strip()


def _is_reviewable_php_construct(surface_type: str, snippet: str) -> bool:
    """Filter broad PHP construct tokens after complete statement extraction."""
    masked = _mask_non_code(snippet, mask_strings=True)
    if surface_type == "php_code_execution":
        return (
            re.search(
                r"(?<![$A-Za-z0-9_:>])eval\s*\(",
                masked,
                re.IGNORECASE,
            )
            is not None
        )
    if surface_type != "dynamic_include":
        return True
    match = re.search(
        r"\b(?:include|include_once|require|require_once)\b",
        masked,
        re.IGNORECASE,
    )
    if match is None:
        return False
    operand = masked[match.end() :].lstrip()
    # Preserve existing fixed parenthesized include coverage while excluding
    # ordinary unparenthesized fixed bootstraps. Any variable in the complete
    # operand makes expression-form and multiline includes reviewable.
    return operand.startswith("(") or "$" in operand


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


def _latest_request_assignment(
    masked_source: str,
    function_ranges: list[tuple[int, int]],
    variable: str,
    before: int,
) -> tuple[int, int] | None:
    """Return the latest same-scope request-derived assignment for a variable."""
    scope = _php_function_scope(function_ranges, before)
    scope_start = scope[0] if scope is not None else 0
    assignment_re = re.compile(
        rf"\${re.escape(variable)}\s*=(?!=|>)",
    )
    assignments = [
        assignment
        for assignment in assignment_re.finditer(masked_source, scope_start, before)
        if _php_function_scope(function_ranges, assignment.start()) == scope
    ]
    if not assignments:
        return None
    assignment = assignments[-1]
    assignment_end = _php_assignment_end(
        masked_source,
        assignment.end(),
        before,
    )
    if assignment_end < 0:
        return None
    expression = masked_source[assignment.end() : assignment_end]
    if _DIRECT_REQUEST_RE.search(expression) is None:
        return None
    return assignment.start(), assignment_end + 1


def _request_selected_variable_call_matches(
    masked_source: str,
    function_ranges: list[tuple[int, int]],
) -> list[tuple[re.Match[str], int, int]]:
    """Find variable calls whose latest same-scope assignment reads a request.

    Variable function syntax is common enough that treating every ``$fn()`` as
    a sink would create substantial noise.  This bounded anchor requires a
    direct request source in the most recent local assignment and therefore
    catches request-selected callables, including sanitizer-wrapped values,
    without classifying ordinary callbacks as code execution.
    """
    matches: list[tuple[re.Match[str], int, int]] = []
    for call in _VARIABLE_FUNCTION_CALL_RE.finditer(masked_source):
        variable = call.group("name")
        assignment = _latest_request_assignment(
            masked_source,
            function_ranges,
            variable,
            call.start(),
        )
        if assignment is None:
            continue
        matches.append((call, *assignment))
    return matches


def _direct_request_function_call_matches(
    masked_source: str,
) -> list[re.Match[str]]:
    """Find direct request-array expressions used as PHP callables.

    Requiring a request superglobal followed by at least one complete array
    offset keeps this narrower than arbitrary parenthesized request data while
    covering both ``$_GET['fn']()`` and ``($_GET['fn'])()`` syntax.
    """
    return list(_DIRECT_REQUEST_FUNCTION_CALL_RE.finditer(masked_source))


def _request_selected_callback_matches(
    source: str,
    masked_source: str,
    function_ranges: list[tuple[int, int]],
) -> list[tuple[re.Match[str], str, int, int]]:
    """Find request-selected callback operands at known execution APIs."""
    matches: list[tuple[re.Match[str], str, int, int]] = []
    for call in _CALLBACK_EXECUTION_API_RE.finditer(masked_source):
        if not _is_unqualified_function_call(masked_source, call.start("fn")):
            continue
        function_name = call.group("fn")
        snippet = _php_call_snippet(
            source,
            masked_source,
            call.start(),
            call.end(),
        )
        if not snippet:
            continue
        arguments = _php_call_arguments(snippet, function_name)
        callback_index = _CALLBACK_EXECUTION_ARGUMENT[function_name.lower()]
        if arguments is None or len(arguments) <= callback_index:
            continue
        callback = arguments[callback_index].strip()
        callback_code = _mask_non_code(
            callback,
            mask_strings=True,
            preserve_interpolated_variables=True,
        )
        if _DIRECT_REQUEST_RE.search(callback_code) is not None:
            matches.append((call, function_name, call.start(), call.end()))
            continue
        callback_lvalue = _simple_php_lvalue(callback)
        if _BARE_PHP_VARIABLE_RE.fullmatch(callback_lvalue) is None:
            continue
        assignment = _latest_request_assignment(
            masked_source,
            function_ranges,
            callback_lvalue[1:],
            call.start(),
        )
        if assignment is not None:
            matches.append((call, function_name, *assignment))
    return matches


def _request_derived_argument_assignment(
    expression: str,
    masked_source: str,
    function_ranges: list[tuple[int, int]],
    before: int,
) -> tuple[int, int] | None:
    """Locate a direct, same-scope request source for one callback argument."""
    expression_code = _mask_non_code(
        expression,
        mask_strings=True,
        preserve_interpolated_variables=True,
    )
    if _DIRECT_REQUEST_RE.search(expression_code) is not None:
        return before, before
    lvalue = _simple_php_lvalue(expression)
    if _BARE_PHP_VARIABLE_RE.fullmatch(lvalue) is None:
        return None
    return _latest_request_assignment(
        masked_source,
        function_ranges,
        lvalue[1:],
        before,
    )


def _fixed_command_callback_matches(
    source: str,
    masked_source: str,
    function_ranges: list[tuple[int, int]],
) -> list[tuple[re.Match[str], str, str, int, int]]:
    """Find literal OS-command callbacks fed by source-grounded request data."""
    matches: list[tuple[re.Match[str], str, str, int, int]] = []
    command_names = {name.casefold() for name in _COMMAND_FUNCTION_NAMES}
    for call in _CALLBACK_EXECUTION_API_RE.finditer(masked_source):
        function_name = call.group("fn")
        normalized_function = function_name.lower()
        if normalized_function not in _COMMAND_CALLBACK_DATA_ARGUMENTS or not (
            _is_unqualified_function_call(masked_source, call.start("fn"))
        ):
            continue
        snippet = _php_call_snippet(
            source,
            masked_source,
            call.start(),
            call.end(),
        )
        if not snippet:
            continue
        arguments = _php_call_arguments(snippet, function_name)
        callback_index = _CALLBACK_EXECUTION_ARGUMENT[normalized_function]
        if arguments is None or len(arguments) <= callback_index:
            continue
        callback = _FIXED_CALLBACK_RE.fullmatch(arguments[callback_index].strip())
        if callback is None:
            continue
        command_name = callback.group("name").lstrip("\\")
        if command_name.casefold() not in command_names:
            continue
        if normalized_function == "array_filter":
            # A third mode argument changes the callback signature. Keeping
            # only the ordinary value callback avoids speculative arity and
            # by-reference behavior.
            if len(arguments) != 2:
                continue
            invocation_arity = 1
        else:
            invocation_arity = len(arguments) - 1
        if invocation_arity not in _COMMAND_CALLBACK_ARITIES.get(
            command_name.casefold(),
            set(),
        ):
            continue

        configured_indexes = _COMMAND_CALLBACK_DATA_ARGUMENTS[normalized_function]
        data_indexes = (
            range(callback_index + 1, len(arguments))
            if configured_indexes is None
            else configured_indexes
        )
        assignments = [
            assignment
            for index in data_indexes
            if index < len(arguments)
            if (
                assignment := _request_derived_argument_assignment(
                    arguments[index],
                    masked_source,
                    function_ranges,
                    call.start(),
                )
            )
            is not None
        ]
        if not assignments:
            continue
        assignment_start, assignment_end = min(
            assignments,
            key=lambda assignment: assignment[0],
        )
        matches.append(
            (
                call,
                function_name,
                command_name,
                assignment_start,
                assignment_end,
            )
        )
    return matches


def _symfony_process_aliases(masked_source: str) -> set[str]:
    """Return locally imported aliases for Symfony's Process class."""
    return {
        match.group("alias") or "Process"
        for match in _SYMFONY_PROCESS_USE_RE.finditer(masked_source)
    }


def _aliased_process_constructor_matches(
    masked_source: str,
    aliases: Iterable[str],
) -> list[re.Match[str]]:
    """Find constructors proved to resolve to an imported Symfony Process."""
    nonstandard = sorted(
        {alias for alias in aliases if alias.casefold() != "process"},
        key=str.casefold,
    )
    if not nonstandard:
        return []
    pattern = re.compile(
        r"\bnew\s+\\?(?P<class>"
        + "|".join(re.escape(alias) for alias in nonstandard)
        + r")\s*\(",
        re.IGNORECASE,
    )
    return list(pattern.finditer(masked_source))


def _request_selected_method_call_matches(
    masked_source: str,
    function_ranges: list[tuple[int, int]],
) -> list[tuple[re.Match[str], str, int, int]]:
    """Find request-selected object/static method or class dispatch anchors."""
    matches: list[tuple[re.Match[str], str, int, int]] = []
    for call in _VARIABLE_METHOD_CALL_RE.finditer(masked_source):
        selectors = [value for value in call.groupdict().values() if value]
        assignments = [
            (selector, assignment)
            for selector in selectors
            if (
                assignment := _latest_request_assignment(
                    masked_source,
                    function_ranges,
                    selector,
                    call.start(),
                )
            )
            is not None
        ]
        if not assignments:
            continue
        selector, (assignment_start, assignment_end) = min(
            assignments,
            key=lambda item: item[1][0],
        )
        matches.append((call, selector, assignment_start, assignment_end))
    for call in _DIRECT_REQUEST_METHOD_CALL_RE.finditer(masked_source):
        if _DIRECT_REQUEST_RE.search(call.group("expression")) is None:
            continue
        matches.append((call, "request_method", call.start(), call.start()))
    return matches


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


def _simple_php_lvalue(expression: str) -> str:
    """Normalize one exact local/property/literal-array assignment target."""
    value = expression.strip()
    if _BARE_PHP_VARIABLE_RE.fullmatch(value):
        return value
    property_match = _PHP_PROPERTY_LVALUE_RE.fullmatch(value)
    if property_match is not None:
        return f"$this->{property_match.group('property')}"
    array_match = _PHP_LITERAL_ARRAY_LVALUE_RE.fullmatch(value)
    if array_match is not None:
        return f"${array_match.group('array')}['{array_match.group('key')}']"
    numeric_array_match = _PHP_LITERAL_NUMERIC_ARRAY_LVALUE_RE.fullmatch(value)
    if numeric_array_match is not None:
        return (
            f"${numeric_array_match.group('array')}[{numeric_array_match.group('key')}]"
        )
    return ""


def _simple_php_lvalue_end(source: str, start: int) -> int | None:
    """Return the end of one exact traceable PHP value at ``start``.

    Complex values are preferred over their bare-variable prefix. Property
    reads that are actually method calls are deliberately excluded.
    """
    property_match = _PHP_PROPERTY_LVALUE_RE.match(source, start)
    if property_match is not None:
        following = source[property_match.end() :]
        if re.match(r"\s*\(", following) is None:
            return property_match.end()
    for pattern in (
        _PHP_LITERAL_ARRAY_LVALUE_RE,
        _PHP_LITERAL_NUMERIC_ARRAY_LVALUE_RE,
    ):
        match = pattern.match(source, start)
        if match is not None:
            return match.end()
    variable = _BARE_PHP_VARIABLE_RE.match(source, start)
    return variable.end() if variable is not None else None


def _simple_php_lvalues_in_expression(
    expression: str,
    masked_expression: str,
) -> set[str]:
    """Extract exact traceable values whose ``$`` token remains executable."""
    values: set[str] = set()
    for variable in _BARE_PHP_VARIABLE_RE.finditer(masked_expression):
        start = variable.start()
        end = _simple_php_lvalue_end(expression, start)
        if end is None:
            continue
        candidate = _simple_php_lvalue(expression[start:end])
        values.add(candidate or variable.group(0))
    return values


def _php_lvalue_assignment_pattern(lvalue: str) -> str:
    """Build a whitespace-tolerant exact regex for a normalized lvalue."""
    property_match = _PHP_PROPERTY_LVALUE_RE.fullmatch(lvalue)
    if property_match is not None:
        return r"\$this\s*->\s*" + re.escape(property_match.group("property"))
    array_match = _PHP_LITERAL_ARRAY_LVALUE_RE.fullmatch(lvalue)
    if array_match is not None:
        return (
            rf"\${re.escape(array_match.group('array'))}\s*\[\s*(?:'"
            + re.escape(array_match.group("key"))
            + r"'|\""
            + re.escape(array_match.group("key"))
            + r"\")\s*\]"
        )
    numeric_array_match = _PHP_LITERAL_NUMERIC_ARRAY_LVALUE_RE.fullmatch(lvalue)
    if numeric_array_match is not None:
        return (
            rf"\${re.escape(numeric_array_match.group('array'))}\s*\[\s*"
            + re.escape(numeric_array_match.group("key"))
            + r"\s*\]"
        )
    return re.escape(lvalue)


def _reaching_same_function_assignment_details(
    source: str,
    masked_source: str,
    function_ranges: list[tuple[int, int]],
    variable: str,
    before: int,
) -> list[tuple[int, int, int, str]]:
    """Return branch-aware reaching definitions and their source offsets."""
    sink_scope = _php_function_scope(function_ranges, before)
    sink_depth = _php_brace_depth(masked_source, before)
    assignment_re = re.compile(
        rf"{_php_lvalue_assignment_pattern(variable)}\s*"
        rf"(?P<operator>\.=|=(?!=|>))"
    )
    matches = [
        match
        for match in assignment_re.finditer(source, 0, before)
        if masked_source[match.start() : match.start() + 1] == "$"
    ]
    assignments: list[tuple[int, str, int, int, int, str]] = []
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
        expression_source = source[expression_start:expression_end]
        leading = len(expression_source) - len(expression_source.lstrip())
        trailing = len(expression_source) - len(expression_source.rstrip())
        expression_start += leading
        expression_end -= trailing
        assignments.append(
            (
                _php_brace_depth(masked_source, match.start()),
                match.group("operator"),
                match.start(),
                expression_start,
                expression_end,
                source[expression_start:expression_end],
            )
        )

    # A definition at the sink's own (or an outer) lexical depth dominates all
    # earlier definitions. Assignments nested after that reset may be mutually
    # exclusive branch definitions that still reach a sink outside the branch.
    reset_index = next(
        (
            index
            for index in range(len(assignments) - 1, -1, -1)
            if assignments[index][0] <= sink_depth and assignments[index][1] == "="
        ),
        None,
    )
    if reset_index is None:
        return [assignment[2:] for assignment in assignments]
    reset_assignment = assignments[reset_index][2:]
    return [
        reset_assignment,
        *[
            assignment[2:]
            for assignment in assignments[reset_index + 1 :]
            for depth in [assignment[0]]
            if assignment[1] == ".=" or depth > sink_depth
        ],
    ]


def _reaching_same_function_assignments(
    source: str,
    masked_source: str,
    function_ranges: list[tuple[int, int]],
    variable: str,
    before: int,
) -> list[str]:
    """Approximate branch-aware reaching definitions in one PHP function."""
    return [
        expression
        for _, _, _, expression in _reaching_same_function_assignment_details(
            source,
            masked_source,
            function_ranges,
            variable,
            before,
        )
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
        where_lvalue = _simple_php_lvalue(where_expression)
        if where_lvalue:
            where_expressions = _reaching_same_function_assignments(
                source,
                masked_source,
                function_ranges,
                where_lvalue,
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
    query_lvalue = _simple_php_lvalue(query_expression)
    if query_lvalue:
        query_expressions = _reaching_same_function_assignments(
            source,
            masked_source,
            function_ranges,
            query_lvalue,
            match_start,
        )
    else:
        query_expressions = [query_expression]
    return any(
        _sql_expression_has_dynamic_identity(candidate)
        for candidate in query_expressions
    )


def _php_first_argument_span(
    snippet: str,
    function_name: str,
) -> tuple[int, int] | None:
    """Return offsets for the first argument of a complete PHP call snippet."""
    comments_stripped = _mask_non_code(snippet, mask_strings=False)
    match = re.search(
        rf"(?<![A-Za-z0-9_]){re.escape(function_name)}\s*\(",
        comments_stripped,
        re.IGNORECASE,
    )
    if match is None:
        return None
    opening = comments_stripped.find("(", match.start(), match.end())
    index = opening + 1
    while index < len(comments_stripped) and comments_stripped[index].isspace():
        index += 1
    argument_start = index
    stack: list[str] = []
    pairs = {")": "(", "]": "[", "}": "{"}
    quote = ""
    escaped = False
    for index in range(argument_start, len(comments_stripped)):
        char = comments_stripped[index]
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
            if not stack:
                return argument_start, index
            if stack[-1] == pairs[char]:
                stack.pop()
            continue
        if char == "," and not stack:
            return argument_start, index
    return None


def _is_prepared_query_expression(expression: str) -> bool:
    """Whether wpdb::prepare consumes the complete final query expression."""
    masked = _mask_non_code(expression, mask_strings=True)
    match = re.match(
        r"^\s*\$wpdb\s*->\s*prepare\s*\(",
        masked,
        re.IGNORECASE,
    )
    if match is None:
        return False
    opening = masked.rfind("(", 0, match.end())
    depth = 0
    for index in range(opening, len(masked)):
        char = masked[index]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return not masked[index + 1 :].strip()
    return False


def _persistent_operand_matches(
    *,
    source: str,
    masked_source: str,
    function_ranges: list[tuple[int, int]],
    expression: str,
    expression_start: int,
    before: int,
    visited: set[tuple[str, int]],
    depth: int = 0,
) -> list[tuple[str, int, str]]:
    """Trace exact local assignments from a query operand to persistent reads."""
    if depth > 3:
        return []

    if _is_prepared_query_expression(expression):
        query_span = _php_first_argument_span(expression, "prepare")
        if query_span is None:
            return []
        query_start, query_end = query_span
        query_source = expression[query_start:query_end]
        leading = len(query_source) - len(query_source.lstrip())
        query_source = query_source.strip()
        if not query_source:
            return []
        # Only the SQL template is part of the raw query. Values passed in
        # later arguments remain excluded because wpdb::prepare binds them to
        # placeholders rather than interpolating them into the query text.
        return _persistent_operand_matches(
            source=source,
            masked_source=masked_source,
            function_ranges=function_ranges,
            expression=query_source,
            expression_start=expression_start + query_start + leading,
            before=before,
            visited=visited,
            depth=depth,
        )

    masked_expression = _mask_non_code(
        expression,
        mask_strings=True,
        preserve_interpolated_variables=True,
    )
    matches: list[tuple[str, int, str]] = []
    for pattern in (
        _PERSISTENT_GETTER_RE,
        _PERSISTENT_CORE_FIELD_RE,
        _PERSISTENT_WPDB_READ_RE,
    ):
        for match in pattern.finditer(masked_expression):
            if pattern is not _PERSISTENT_WPDB_READ_RE and not (
                _is_unqualified_function_call(
                    masked_expression,
                    match.start("fn"),
                )
            ):
                continue
            function_name = match.group("fn")
            absolute = expression_start + match.start("fn")
            key = (function_name.lower(), absolute)
            if key in visited:
                continue
            visited.add(key)
            matches.append(
                (
                    function_name,
                    absolute,
                    _php_call_snippet(
                        source,
                        masked_source,
                        absolute,
                        expression_start + match.end(),
                    )
                    or source[absolute : absolute + 300].splitlines()[0].strip(),
                )
            )

    variables = {
        lvalue
        for lvalue in _simple_php_lvalues_in_expression(
            expression,
            masked_expression,
        )
        if lvalue
        not in {
            "$wpdb",
            "$_GET",
            "$_POST",
            "$_REQUEST",
            "$_FILES",
            "$_COOKIE",
            "$_SERVER",
            "$_ENV",
            "$_SESSION",
            "$GLOBALS",
            "$this",
        }
    }
    for variable in sorted(variables):
        definition_key = (variable, before)
        if definition_key in visited:
            continue
        visited.add(definition_key)
        for (
            _,
            assigned_start,
            _,
            assigned_expression,
        ) in _reaching_same_function_assignment_details(
            source,
            masked_source,
            function_ranges,
            variable,
            min(before, expression_start),
        ):
            matches.extend(
                _persistent_operand_matches(
                    source=source,
                    masked_source=masked_source,
                    function_ranges=function_ranges,
                    expression=assigned_expression,
                    expression_start=assigned_start,
                    before=assigned_start,
                    visited=visited,
                    depth=depth + 1,
                )
            )
    return matches


def _persistent_sql_operand_items(
    *,
    rel: str,
    source: str,
    masked_source: str,
    function_ranges: list[tuple[int, int]],
    function_name: str,
    snippet: str,
    snippet_start: int,
    match_start: int,
) -> list[dict[str, Any]]:
    """Create conservative second-order SQLi review anchors for one SQL call."""
    span = _php_first_argument_span(snippet, function_name)
    if span is None:
        return []
    argument_start, argument_end = span
    expression = snippet[argument_start:argument_end].strip()
    leading = len(snippet[argument_start:argument_end]) - len(
        snippet[argument_start:argument_end].lstrip()
    )
    expression_start = snippet_start + argument_start + leading
    if not expression:
        return []

    expression_lvalue = _simple_php_lvalue(expression)
    if expression_lvalue:
        candidates = [
            (assigned_start, assigned_expression)
            for _, assigned_start, _, assigned_expression in (
                _reaching_same_function_assignment_details(
                    source,
                    masked_source,
                    function_ranges,
                    expression_lvalue,
                    match_start,
                )
            )
        ]
    else:
        candidates = [(expression_start, expression)]

    persistent_matches: list[tuple[str, int, str]] = []
    visited: set[tuple[str, int]] = set()
    for candidate_start, candidate in candidates:
        # A persistent value only matters here when the final operand is
        # genuinely dynamic rather than an unrelated getter elsewhere nearby.
        candidate_code = _mask_non_code(
            candidate,
            mask_strings=True,
            preserve_interpolated_variables=True,
        )
        dynamic = bool(
            _BARE_PHP_VARIABLE_RE.search(
                _CURRENT_USER_ID_RE.sub(
                    "",
                    candidate_code,
                )
            )
            or _PERSISTENT_GETTER_RE.search(candidate_code)
            or _PERSISTENT_CORE_FIELD_RE.search(candidate_code)
            or _PERSISTENT_WPDB_READ_RE.search(candidate_code)
        )
        if not dynamic:
            continue
        persistent_matches.extend(
            _persistent_operand_matches(
                source=source,
                masked_source=masked_source,
                function_ranges=function_ranges,
                expression=candidate,
                expression_start=candidate_start,
                before=candidate_start,
                visited=visited,
            )
        )

    items: list[dict[str, Any]] = []
    for getter, offset, getter_snippet in persistent_matches:
        items.append(
            {
                "kind": "storage_read",
                "review_areas": ["injection_files"],
                "type": "persistent_sql_operand",
                "name": getter,
                "file": rel,
                "line": source.count("\n", 0, offset) + 1,
                "column": offset - source.rfind("\n", 0, offset),
                "snippet": getter_snippet,
            }
        )
    return items


def _surface_items(
    plugin_dir: Path, production_files: list[str]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    raw_items: list[dict[str, Any]] = []
    static_sinks: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int, int, str]] = set()
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
            _mask_non_code(_mask_outside_php(source), mask_strings=True)
            if patterns is _PHP_SURFACES
            else source
        )
        function_ranges = (
            _php_function_ranges(scan_source) if patterns is _PHP_SURFACES else []
        )
        line_starts = [0]
        line_starts.extend(
            index + 1 for index, char in enumerate(source) if char == "\n"
        )
        for surface_type, pattern, areas, kind in patterns:
            for match in pattern.finditer(scan_source):
                absolute_start = match.start()
                absolute_end = match.end()
                line_index = bisect_right(line_starts, absolute_start) - 1
                line_no = line_index + 1
                line_start = line_starts[line_index]
                column = absolute_start - line_start + 1
                if (
                    patterns is _PHP_SURFACES
                    and surface_type == "command_execution"
                    and not _is_direct_command_call(
                        scan_source,
                        absolute_start,
                        absolute_end,
                    )
                ):
                    continue
                groups = match.groupdict()
                if (
                    patterns is _PHP_SURFACES
                    and surface_type
                    in {
                        "archive_extract",
                        "dynamic_callable",
                        "file_delete",
                        "file_read",
                        "file_upload",
                        "file_write",
                    }
                    and groups.get("fn")
                    and not _is_unqualified_function_call(
                        scan_source,
                        absolute_start,
                    )
                ):
                    continue
                name = next(
                    (value for value in groups.values() if value),
                    surface_type,
                )
                fallback_snippet = source[
                    max(line_start, absolute_start - 200) : min(
                        len(source), absolute_end + 300
                    )
                ].strip()
                if patterns is _PHP_SURFACES and surface_type in {
                    "command_execution",
                    "dynamic_include",
                    "php_code_execution",
                }:
                    snippet = _php_statement_snippet(
                        source,
                        scan_source,
                        line_start,
                        absolute_start,
                    )
                    if not _is_reviewable_php_construct(surface_type, snippet):
                        continue
                elif patterns is _PHP_SURFACES and "(" in match.group(0):
                    snippet = (
                        _php_call_snippet(
                            source,
                            scan_source,
                            absolute_start,
                            absolute_end,
                        )
                        or fallback_snippet
                    )
                else:
                    snippet = fallback_snippet
                effective_surface_type = surface_type
                effective_areas = list(areas)
                if surface_type == "file_write" and name.lower() == "fopen":
                    arguments = _php_call_arguments(snippet, name)
                    if (
                        arguments is not None
                        and len(arguments) >= 2
                        and re.fullmatch(
                            r"(['\"])r[bt]?(?:\1)",
                            arguments[1].strip(),
                            re.IGNORECASE,
                        )
                    ):
                        effective_surface_type = "file_read"
                        effective_areas = _review_areas_for_surface(
                            "file_read",
                            ["injection_files"],
                        )
                key = (kind, rel, line_no, column, name)
                if key in seen:
                    continue
                seen.add(key)
                item_areas = effective_areas
                if patterns is _PHP_SURFACES and _sql_object_access_review(
                    surface_type=effective_surface_type,
                    function_name=name,
                    snippet=snippet,
                    source=source,
                    masked_source=scan_source,
                    function_ranges=function_ranges,
                    match_start=absolute_start,
                ):
                    item_areas = _review_areas_for_surface(
                        "sql_object_access",
                        item_areas,
                    )
                raw_items.append(
                    {
                        "kind": kind,
                        "review_areas": item_areas,
                        "type": effective_surface_type,
                        "name": name,
                        "file": rel,
                        "line": line_no,
                        "column": column,
                        "snippet": snippet,
                    }
                )
                if kind == "sink":
                    static_sinks.append(
                        {
                            "type": effective_surface_type,
                            "function": name,
                            "file": rel,
                            "line": line_no,
                            "tainted_args": [],
                            "source": "deterministic",
                        }
                    )
                if patterns is _PHP_SURFACES and effective_surface_type == "sql_query":
                    for persistent_item in _persistent_sql_operand_items(
                        rel=rel,
                        source=source,
                        masked_source=scan_source,
                        function_ranges=function_ranges,
                        function_name=name,
                        snippet=snippet,
                        snippet_start=absolute_start,
                        match_start=absolute_start,
                    ):
                        persistent_key = (
                            persistent_item["kind"],
                            rel,
                            persistent_item["line"],
                            persistent_item["column"],
                            persistent_item["name"],
                        )
                        if persistent_key in seen:
                            continue
                        seen.add(persistent_key)
                        raw_items.append(persistent_item)

        if patterns is not _PHP_SURFACES:
            continue

        for (
            call,
            assignment_start,
            _assignment_end,
        ) in _request_selected_variable_call_matches(scan_source, function_ranges):
            line_index = bisect_right(line_starts, call.start()) - 1
            line_no = line_index + 1
            line_start = line_starts[line_index]
            column = call.start() - line_start + 1
            name = call.group("name")
            key = ("review_anchor", rel, line_no, column, name)
            if key in seen:
                continue
            seen.add(key)
            call_end = _php_assignment_end(
                scan_source,
                call.start(),
                min(len(scan_source), call.start() + _SURFACE_SNIPPET_MAX_CHARS),
            )
            snippet_end = call_end + 1 if call_end >= 0 else call.end()
            raw_items.append(
                {
                    "kind": "review_anchor",
                    "review_areas": _review_areas_for_surface(
                        "dynamic_callable",
                        ["injection_files"],
                    ),
                    "type": "dynamic_callable",
                    "name": name,
                    "file": rel,
                    "line": line_no,
                    "column": column,
                    "snippet": source[assignment_start:snippet_end].strip(),
                }
            )

        for call in _direct_request_function_call_matches(scan_source):
            line_index = bisect_right(line_starts, call.start()) - 1
            line_no = line_index + 1
            line_start = line_starts[line_index]
            column = call.start() - line_start + 1
            name = "request_callable"
            key = ("review_anchor", rel, line_no, column, name)
            if key in seen:
                continue
            seen.add(key)
            call_end = _php_assignment_end(
                scan_source,
                call.start(),
                min(len(scan_source), call.start() + _SURFACE_SNIPPET_MAX_CHARS),
            )
            snippet_end = call_end + 1 if call_end >= 0 else call.end()
            raw_items.append(
                {
                    "kind": "review_anchor",
                    "review_areas": _review_areas_for_surface(
                        "dynamic_callable",
                        ["injection_files"],
                    ),
                    "type": "dynamic_callable",
                    "name": name,
                    "file": rel,
                    "line": line_no,
                    "column": column,
                    "snippet": source[call.start() : snippet_end].strip(),
                }
            )

        for (
            call,
            function_name,
            assignment_start,
            _assignment_end,
        ) in _request_selected_callback_matches(
            source,
            scan_source,
            function_ranges,
        ):
            line_index = bisect_right(line_starts, call.start()) - 1
            line_no = line_index + 1
            line_start = line_starts[line_index]
            column = call.start() - line_start + 1
            key = ("review_anchor", rel, line_no, column, function_name)
            if key in seen:
                continue
            seen.add(key)
            call_end = _php_assignment_end(
                scan_source,
                call.start(),
                min(len(scan_source), call.start() + _SURFACE_SNIPPET_MAX_CHARS),
            )
            snippet_end = call_end + 1 if call_end >= 0 else call.end()
            raw_items.append(
                {
                    "kind": "review_anchor",
                    "review_areas": _review_areas_for_surface(
                        "dynamic_callable",
                        ["injection_files"],
                    ),
                    "type": "dynamic_callable",
                    "name": function_name,
                    "file": rel,
                    "line": line_no,
                    "column": column,
                    "snippet": source[assignment_start:snippet_end].strip(),
                }
            )

        for (
            call,
            _function_name,
            command_name,
            assignment_start,
            _assignment_end,
        ) in _fixed_command_callback_matches(
            source,
            scan_source,
            function_ranges,
        ):
            line_index = bisect_right(line_starts, call.start()) - 1
            line_no = line_index + 1
            line_start = line_starts[line_index]
            column = call.start() - line_start + 1
            key = ("sink", rel, line_no, column, command_name)
            if key in seen:
                continue
            seen.add(key)
            call_end = _php_assignment_end(
                scan_source,
                call.start(),
                min(len(scan_source), call.start() + _SURFACE_SNIPPET_MAX_CHARS),
            )
            snippet_end = call_end + 1 if call_end >= 0 else call.end()
            raw_items.append(
                {
                    "kind": "sink",
                    "review_areas": _review_areas_for_surface(
                        "command_execution",
                        ["injection_files"],
                    ),
                    "type": "command_execution",
                    "name": command_name,
                    "file": rel,
                    "line": line_no,
                    "column": column,
                    "snippet": source[assignment_start:snippet_end].strip(),
                }
            )
            static_sinks.append(
                {
                    "type": "command_execution",
                    "function": command_name,
                    "file": rel,
                    "line": line_no,
                    "tainted_args": [],
                    "source": "deterministic",
                }
            )

        for (
            call,
            selector,
            assignment_start,
            _assignment_end,
        ) in _request_selected_method_call_matches(scan_source, function_ranges):
            line_index = bisect_right(line_starts, call.start()) - 1
            line_no = line_index + 1
            line_start = line_starts[line_index]
            column = call.start() - line_start + 1
            key = ("review_anchor", rel, line_no, column, selector)
            if key in seen:
                continue
            seen.add(key)
            call_end = _php_assignment_end(
                scan_source,
                call.start(),
                min(len(scan_source), call.start() + _SURFACE_SNIPPET_MAX_CHARS),
            )
            snippet_end = call_end + 1 if call_end >= 0 else call.end()
            raw_items.append(
                {
                    "kind": "review_anchor",
                    "review_areas": _review_areas_for_surface(
                        "dynamic_callable",
                        ["injection_files"],
                    ),
                    "type": "dynamic_callable",
                    "name": selector,
                    "file": rel,
                    "line": line_no,
                    "column": column,
                    "snippet": source[assignment_start:snippet_end].strip(),
                }
            )

        process_aliases = _symfony_process_aliases(scan_source)
        for constructor in _aliased_process_constructor_matches(
            scan_source,
            process_aliases,
        ):
            line_index = bisect_right(line_starts, constructor.start()) - 1
            line_no = line_index + 1
            line_start = line_starts[line_index]
            column = constructor.start() - line_start + 1
            name = constructor.group("class")
            key = ("review_anchor", rel, line_no, column, name)
            if key in seen:
                continue
            seen.add(key)
            snippet = _php_statement_snippet(
                source,
                scan_source,
                line_start,
                constructor.start(),
            )
            raw_items.append(
                {
                    "kind": "review_anchor",
                    "review_areas": _review_areas_for_surface(
                        "command_wrapper",
                        ["injection_files"],
                    ),
                    "type": "command_wrapper",
                    "name": name,
                    "file": rel,
                    "line": line_no,
                    "column": column,
                    "snippet": snippet,
                }
            )

        for start, end in _php_backtick_spans(source):
            line_no = source.count("\n", 0, start) + 1
            column = start - source.rfind("\n", 0, start)
            key = ("sink", rel, line_no, column, "backtick")
            if key in seen:
                continue
            seen.add(key)
            raw_items.append(
                {
                    "kind": "sink",
                    "review_areas": ["injection_files"],
                    "type": "command_execution",
                    "name": "backtick",
                    "file": rel,
                    "line": line_no,
                    "column": column,
                    "snippet": source[start:end].strip(),
                }
            )
            static_sinks.append(
                {
                    "type": "command_execution",
                    "function": "backtick",
                    "file": rel,
                    "line": line_no,
                    "tainted_args": [],
                    "source": "deterministic",
                }
            )

        for match in _upload_policy_matches(source):
            hook = match.group("hook")
            line_no = source.count("\n", 0, match.start()) + 1
            line_start = source.rfind("\n", 0, match.start()) + 1
            column = match.start() - line_start + 1
            key = ("review_anchor", rel, line_no, column, hook)
            if key in seen:
                continue
            seen.add(key)
            snippet = _php_call_snippet(
                source,
                scan_source,
                match.start(),
                match.end(),
            )
            raw_items.append(
                {
                    "kind": "review_anchor",
                    "review_areas": ["injection_files"],
                    "type": "upload_policy",
                    "name": hook,
                    "file": rel,
                    "line": line_no,
                    "column": column,
                    "snippet": snippet or source[line_start:].splitlines()[0].strip(),
                }
            )
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
    function_definitions = recon_helpers.build_function_definitions(
        plugin_dir,
        php_files,
    )
    source_cache: dict[str, str] = {}
    process_alias_cache: dict[str, set[str]] = {}

    def process_aliases_for_file(relative_path: str) -> set[str]:
        cached = process_alias_cache.get(relative_path)
        if cached is not None:
            return cached
        file_source = source_cache.get(relative_path, "")
        if relative_path not in source_cache:
            try:
                file_source = (plugin_dir / relative_path).read_text(
                    encoding="utf-8",
                    errors="replace",
                )
            except OSError:
                file_source = ""
            source_cache[relative_path] = file_source
        masked = _mask_non_code(
            _mask_outside_php(file_source),
            mask_strings=True,
        )
        aliases = _symfony_process_aliases(masked)
        process_alias_cache[relative_path] = aliases
        return aliases

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
        else:
            callback_file = str(callback.get("file") or "")
            selected_definitions, _ = _callback_definition_candidates(
                callback,
                function_definitions,
            )
            if selected_definitions:
                injection_sources = [
                    (
                        recon_helpers.extract_body_slice(
                            plugin_dir,
                            definition_file,
                            definition_line,
                            max_lines=250,
                        )
                        or "",
                        True,
                        process_aliases_for_file(definition_file),
                    )
                    for definition_file, definition_line in selected_definitions
                ]
            else:
                # Anonymous/unresolved callbacks still receive focused routing
                # when their source-local file has an unmistakable surface.
                injection_source = source_cache.get(callback_file, "")
                if callback_file not in source_cache:
                    try:
                        injection_source = (plugin_dir / callback_file).read_text(
                            encoding="utf-8",
                            errors="replace",
                        )
                    except OSError:
                        injection_source = ""
                    source_cache[callback_file] = injection_source
                injection_sources = [
                    (
                        injection_source,
                        False,
                        process_aliases_for_file(callback_file),
                    )
                ]
            if any(
                _has_high_signal_injection_surface(
                    source,
                    assume_php_fragment=assume_php_fragment,
                    command_wrapper_aliases=command_wrapper_aliases,
                )
                for (
                    source,
                    assume_php_fragment,
                    command_wrapper_aliases,
                ) in injection_sources
            ):
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


def _callback_definition_candidates(
    callback: dict[str, Any],
    function_definitions: dict[str, list[tuple[str, int]]],
    *,
    limit: int = 6,
) -> tuple[list[tuple[str, int]], bool]:
    """Resolve a named callback without selecting an unrelated duplicate.

    A registration-local definition is the strongest deterministic binding.  A
    single global definition is also unambiguous.  Multiple definitions in
    other files remain useful bounded review targets, but are not safe grounds
    for rewriting the canonical entry point to an arbitrary file.
    """
    handler = str(callback.get("handler_function") or "").strip()
    if not handler:
        return [], False
    candidates = [
        location
        for function_name, locations in function_definitions.items()
        if function_name.casefold() == handler.casefold()
        for location in locations
    ]
    callback_file = str(callback.get("file") or "")
    callback_line = int(callback.get("line") or 0)
    same_file = [item for item in candidates if item[0] == callback_file]
    if same_file:
        same_file.sort(key=lambda item: (abs(item[1] - callback_line), item[1]))
        return same_file[:limit], True
    if len(candidates) == 1:
        return candidates, True
    return candidates[:limit], False


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
    function_definitions = recon_helpers.build_function_definitions(
        plugin_dir,
        [
            rel
            for rel in coverage.production_files
            if Path(rel).suffix.lower() in {".php", ".phtml", ".inc"}
        ],
    )
    for callback in callbacks:
        normalized_name = normalize_entry_name(callback["name"])
        key = (callback["type"], normalized_name)
        handler_file = callback["file"]
        handler_line = callback["line"]
        handler = callback.get("handler_function") or ""
        definitions: list[tuple[str, int]] = []
        definition_resolved = False
        if callback["type"] != "direct_php":
            definitions, definition_resolved = _callback_definition_candidates(
                callback,
                function_definitions,
                limit=1,
            )
        if definition_resolved and definitions:
            handler_file, handler_line = definitions[0]
        body = ""
        if definition_resolved or callback["type"] == "direct_php":
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
            if definition_resolved:
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
                    "high"
                    if definition_resolved or callback["type"] == "direct_php"
                    else "medium"
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
            r"sql|query|file|upload|unlink|include|require|remote|curl|xml|"
            r"unserial|exec|system|eval|php[_ -]?code",
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
