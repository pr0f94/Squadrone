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
_PHP_SURFACES: list[tuple[str, re.Pattern[str], list[str], str]] = [
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

_JS_SURFACES: list[tuple[str, re.Pattern[str], list[str], str]] = [
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
        lines = source.splitlines()
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
        scan_lines = scan_source.splitlines()
        for line_no, (line, scan_line) in enumerate(zip(lines, scan_lines), 1):
            if not scan_line.strip():
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
                raw_items.append(
                    {
                        "kind": kind,
                        "review_areas": areas,
                        "type": surface_type,
                        "name": name,
                        "file": rel,
                        "line": line_no,
                        "column": match.start() + 1,
                        "snippet": line[
                            max(0, match.start() - 200) : match.end() + 300
                        ].strip(),
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
