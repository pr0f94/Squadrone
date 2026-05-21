"""Stage-2 recon helpers (pure static analysis, no LLM cost).

#2 cross_file_callees    — best-effort regex-based call-graph for entry-point handlers
#3 nonce_emission_sites  — JS + PHP scan for wp_localize_script / wp_create_nonce sites
#5 extract_body_slice    — function body slice for an entry-point file:line
#6 score_confidence      — heuristic confidence per entry point
#8 cache_key / load / save — recon.json cache keyed by (slug, version, config)
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

CACHE_DIR = Path("cache/recon")


# ---------- #5: extract function body slice -------------------------------------------

# A naïve "find the next function/class boundary" scanner. Doesn't parse PHP — works
# on indentation + brace heuristics, which is enough for typical WP plugin code where
# functions are at file scope or within classes with consistent indentation.
_FN_BOUNDARY = re.compile(
    r"^\s*(?:public|private|protected|static|abstract|final|\s)*\bfunction\s+\w+\s*\(",
    re.MULTILINE,
)
_CLASS_BOUNDARY = re.compile(r"^\s*(?:abstract\s+|final\s+)?class\s+\w+", re.MULTILINE)


def extract_body_slice(plugin_dir: Path, file_rel: str, line: int, max_lines: int = 80) -> str | None:
    """Return ~max_lines of source starting at (line) up to the next function/class boundary.

    Returns None if the file doesn't exist or line is out of range.
    Best-effort — for highly nested code or non-standard formatting, the slice may be
    too long or too short. Specialists are expected to read the actual source for the
    final word; this is a fast convenience preview shipped in recon.json.
    """
    f = plugin_dir / file_rel
    if not f.exists() or not f.is_file():
        return None
    try:
        text = f.read_text(errors="replace")
    except OSError:
        return None
    lines = text.splitlines()
    if line < 1 or line > len(lines):
        return None

    # Walk forward from `line` until we hit the next function/class boundary, or max_lines.
    start_idx = line - 1
    end_idx = min(len(lines), start_idx + max_lines)
    # Find the first boundary AFTER our starting line — that's where the next function begins.
    body_text = "\n".join(lines[start_idx:end_idx])
    next_fn = _FN_BOUNDARY.search(body_text, pos=len(lines[start_idx]) + 1 if lines[start_idx] else 0)
    if next_fn:
        # Cut at the start of the next function's match
        offset_chars = next_fn.start()
        cumulative = 0
        for i, ln in enumerate(body_text.splitlines()):
            cumulative += len(ln) + 1
            if cumulative >= offset_chars:
                return "\n".join(body_text.splitlines()[:max(i, 1)])
    return body_text


# ---------- #2: cross-file callee tracing ---------------------------------------------

# Build a map: function_name -> "file:line" of its definition. Best effort.
_FN_DEF = re.compile(r"^\s*(?:public|private|protected|static|abstract|final|\s)*\bfunction\s+(\w+)\s*\(",
                      re.MULTILINE)
# Match function calls — naïve: any identifier followed by `(` that isn't a keyword.
_CALL = re.compile(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(")
_KEYWORDS = {
    "if", "else", "elseif", "while", "for", "foreach", "switch", "function",
    "isset", "empty", "array", "list", "return", "echo", "print", "die", "exit",
    "include", "require", "include_once", "require_once", "new", "throw", "catch",
    "try", "instanceof", "use", "namespace", "class", "extends", "implements",
}


_ADD_ACTION_RE = re.compile(
    r"\badd_action\s*\(\s*['\"](?P<hook>[^'\"]+)['\"]\s*,\s*(?P<callback>[^;\n]+?)\s*(?:,\s*\d+\s*)?\)\s*;",
)
_ADD_SHORTCODE_RE = re.compile(
    r"\badd_shortcode\s*\(\s*['\"](?P<name>[^'\"]+)['\"]\s*,\s*(?P<callback>[^;\n]+?)\s*\)\s*;",
)
_REST_ROUTE_RE = re.compile(
    r"\bregister_rest_route\s*\(\s*(?P<args>[^\n;]{0,1600})\)\s*;",
)
_CALLBACK_ARRAY_RE = re.compile(
    r"(?:array\s*\(\s*)?(?:\$this|self|static|[A-Za-z_][\w\\]*)(?:::class)?\s*,\s*['\"](?P<method>[A-Za-z_]\w*)['\"]",
)
_CALLBACK_STRING_RE = re.compile(r"['\"](?P<name>[A-Za-z_]\w*)['\"]")
_CALLBACK_KEY_RE = re.compile(
    r"['\"]callback['\"]\s*=>\s*(?P<callback>array\s*\([^)]+\)|\[[^\]]+\]|['\"][^'\"]+['\"]|[A-Za-z_]\w*)",
    re.DOTALL,
)


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _callback_name(raw: str) -> tuple[str, str]:
    raw = raw.strip()
    arr = _CALLBACK_ARRAY_RE.search(raw)
    if arr:
        return arr.group("method"), "method"
    string = _CALLBACK_STRING_RE.search(raw)
    if string:
        return string.group("name"), "function"
    if re.match(r"^[A-Za-z_]\w*$", raw):
        return raw, "function"
    return "", "dynamic"


def _entry_type_for_hook(hook: str) -> str | None:
    if hook.startswith("wp_ajax_nopriv_"):
        return "ajax_nopriv"
    if hook.startswith("wp_ajax_"):
        return "ajax_priv"
    if hook.startswith("admin_post_nopriv_") or hook.startswith("admin_post_"):
        return "form_handler"
    if hook in {"admin_init", "init", "template_redirect"}:
        return "form_handler"
    return None


def extract_static_callbacks(plugin_dir: Path, php_files: list[str] | None = None) -> list[dict[str, Any]]:
    """Return plugin-agnostic, regex-derived entry point registrations.

    This is intentionally conservative metadata for grounding LLM recon. It does
    not replace the surveyor and does not try to prove vulnerability reachability.
    """
    callbacks: list[dict[str, Any]] = []
    targets = php_files if php_files is not None else [
        str(p.relative_to(plugin_dir)) for p in plugin_dir.rglob("*.php") if p.is_file()
    ]
    seen: set[tuple[str, str, str, int]] = set()
    for rel in targets:
        f = plugin_dir / rel
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue

        for m in _ADD_ACTION_RE.finditer(text):
            hook = m.group("hook")
            ep_type = _entry_type_for_hook(hook)
            if ep_type is None:
                continue
            callback, kind = _callback_name(m.group("callback"))
            line = _line_number(text, m.start())
            key = (ep_type, hook, rel, line)
            if key in seen:
                continue
            seen.add(key)
            callbacks.append({
                "type": ep_type,
                "name": hook,
                "file": rel,
                "line": line,
                "handler_function": callback,
                "callback_kind": kind,
                "raw": text[m.start():text.find("\n", m.start()) if text.find("\n", m.start()) != -1 else m.end()].strip(),
            })

        for m in _ADD_SHORTCODE_RE.finditer(text):
            callback, kind = _callback_name(m.group("callback"))
            line = _line_number(text, m.start())
            key = ("shortcode", m.group("name"), rel, line)
            if key in seen:
                continue
            seen.add(key)
            callbacks.append({
                "type": "shortcode",
                "name": m.group("name"),
                "file": rel,
                "line": line,
                "handler_function": callback,
                "callback_kind": kind,
                "raw": text[m.start():text.find("\n", m.start()) if text.find("\n", m.start()) != -1 else m.end()].strip(),
            })

        for m in _REST_ROUTE_RE.finditer(text):
            args = m.group("args")
            callback_raw = ""
            cb = _CALLBACK_KEY_RE.search(args)
            if cb:
                callback_raw = cb.group("callback")
            callback, kind = _callback_name(callback_raw)
            route_bits = re.findall(r"['\"]([^'\"]+)['\"]", args)
            route = " ".join(route_bits[:2]) if route_bits else "register_rest_route"
            line = _line_number(text, m.start())
            key = ("rest_route", route, rel, line)
            if key in seen:
                continue
            seen.add(key)
            callbacks.append({
                "type": "rest_route",
                "name": route,
                "file": rel,
                "line": line,
                "handler_function": callback,
                "callback_kind": kind,
                "raw": text[m.start():m.end()].replace("\n", " ")[:500],
            })
    return callbacks


def trace_static_call_edges(
    plugin_dir: Path,
    callbacks: list[dict[str, Any]],
    *,
    max_edges_per_callback: int = 25,
) -> list[dict[str, Any]]:
    """Best-effort direct call edges from each static callback's function body."""
    fn_map = build_function_def_map(plugin_dir)
    edges: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, int]] = set()
    for cb in callbacks:
        handler = cb.get("handler_function") or ""
        if not handler:
            continue
        body_file = cb.get("file", "")
        body_line = int(cb.get("line") or 1)
        handler_def = fn_map.get(handler)
        if handler_def and ":" in handler_def:
            maybe_file, maybe_line = handler_def.rsplit(":", 1)
            try:
                body_file = maybe_file
                body_line = int(maybe_line)
            except ValueError:
                pass
        body = extract_body_slice(plugin_dir, body_file, body_line, max_lines=120) or ""
        if not body:
            continue
        count = 0
        for m in _CALL.finditer(body):
            callee = m.group(1)
            if callee in _KEYWORDS or callee == handler:
                continue
            call_line = body_line + body[:m.start()].count("\n")
            defloc = fn_map.get(callee)
            callee_file = None
            callee_line = None
            if defloc and ":" in defloc:
                callee_file, raw_line = defloc.rsplit(":", 1)
                try:
                    callee_line = int(raw_line)
                except ValueError:
                    callee_line = None
            key = (handler, callee, cb.get("file", ""), call_line)
            if key in seen:
                continue
            seen.add(key)
            edges.append({
                "caller": handler,
                "callee": callee,
                "caller_file": body_file,
                "caller_line": call_line,
                "callee_file": callee_file,
                "callee_line": callee_line,
                "confidence": "high" if callee_file else "low",
            })
            count += 1
            if count >= max_edges_per_callback:
                break
    return edges


def build_function_def_map(plugin_dir: Path, php_files: list[str] | None = None) -> dict[str, str]:
    """Walk PHP files, return {function_name: 'file:line'} of every top-level function definition."""
    fn_map: dict[str, str] = {}
    targets = php_files if php_files is not None else [
        str(p.relative_to(plugin_dir)) for p in plugin_dir.rglob("*.php") if p.is_file()
    ]
    for rel in targets:
        f = plugin_dir / rel
        if not f.exists() or not f.is_file():
            continue
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        for m in _FN_DEF.finditer(text):
            name = m.group(1)
            line_no = text.count("\n", 0, m.start()) + 1
            # First-wins: don't overwrite if duplicate (preserves the first definition site)
            fn_map.setdefault(name, f"{rel}:{line_no}")
    return fn_map


def trace_callees(body_slice: str, fn_def_map: dict[str, str]) -> list[str]:
    """Return list of 'file:line callee_name' for each function call in `body_slice`
    that resolves against `fn_def_map`. Skips PHP keywords and built-ins.
    """
    seen: set[str] = set()
    out: list[str] = []
    if not body_slice:
        return out
    for m in _CALL.finditer(body_slice):
        name = m.group(1)
        if name in _KEYWORDS or name in seen:
            continue
        seen.add(name)
        defloc = fn_def_map.get(name)
        if defloc is not None:
            out.append(f"{defloc} {name}")
    return out


# ---------- #3: JS nonce-emission scanner ---------------------------------------------

# wp_localize_script(handle, var, ['nonce' => wp_create_nonce('action')])
_LOCALIZE = re.compile(
    r"wp_localize_script\s*\(\s*[^,]+,\s*[^,]+,\s*(?:array|\[)(.{0,2000}?)\)\s*;?",
    re.DOTALL,
)
# wp_create_nonce('action_name')
_CREATE_NONCE = re.compile(r"wp_create_nonce\s*\(\s*['\"]([^'\"]+)['\"]\s*\)")
# JS-side: nonce: 'value', or nonce: "value" inside object literal
_JS_NONCE_KEY = re.compile(r"\bnonce\s*[:=]\s*['\"]([^'\"]+)['\"]")


def scan_nonce_emissions(plugin_dir: Path, files_to_scan: list[str] | None = None
                         ) -> dict[str, list[str]]:
    """Return {nonce_action: ['file:line — context', ...]} of every wp_create_nonce call
    we can resolve to a string action.

    Both PHP wp_create_nonce('action') sites and any wp_localize_script blocks that wrap
    them are captured. JS files are scanned for `nonce: 'value'` patterns but those only
    contribute a hint — the action they verify against can't be statically derived from
    JS alone, so they're tagged as `_js_value_only_<value>`.
    """
    out: dict[str, list[str]] = {}
    targets = files_to_scan or [
        str(p.relative_to(plugin_dir))
        for p in plugin_dir.rglob("*")
        if p.is_file() and p.suffix.lower() in (".php", ".js")
    ]

    for rel in targets:
        f = plugin_dir / rel
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue

        # PHP wp_create_nonce sites
        if rel.endswith(".php"):
            for m in _CREATE_NONCE.finditer(text):
                action = m.group(1)
                line_no = text.count("\n", 0, m.start()) + 1
                excerpt = text[max(0, m.start() - 30):m.end() + 30].replace("\n", " ")[:120]
                out.setdefault(action, []).append(f"{rel}:{line_no} — {excerpt}")

        # JS nonce values (action unknown — flag as _js_value_only)
        if rel.endswith(".js"):
            for m in _JS_NONCE_KEY.finditer(text):
                value = m.group(1)
                # Skip placeholder/templating syntax
                if any(c in value for c in "<{$%"):
                    continue
                line_no = text.count("\n", 0, m.start()) + 1
                key = f"_js_value_only_{value[:10]}"
                excerpt = text[max(0, m.start() - 30):m.end() + 30].replace("\n", " ")[:120]
                out.setdefault(key, []).append(f"{rel}:{line_no} — {excerpt}")

    return out


# ---------- #6: confidence scorer -----------------------------------------------------

def score_confidence(
    entry_point_file: str,
    handler_function: str,
    body_slice: str | None,
    excluded_buckets: list[str] | None,
    file_classification: dict[str, list[str]] | None,
) -> str:
    """Return 'high' | 'medium' | 'low' based on:
    - file is in vendor/tests/lang bucket → low (likely false-positive entry point)
    - handler exists in body_slice (we could extract a slice) → high
    - no slice extracted (file:line resolution failed) → low
    - default → medium
    """
    if file_classification:
        for bucket in ("vendor", "tests", "lang"):
            if entry_point_file in file_classification.get(bucket, []):
                return "low"

    if body_slice is None:
        return "low"

    # If the slice contains the handler name as a function definition, high confidence
    if handler_function and re.search(rf"\bfunction\s+{re.escape(handler_function)}\b", body_slice):
        return "high"

    return "medium"


# ---------- #8: recon caching ---------------------------------------------------------

def cache_key(plugin_slug: str, plugin_version: str, recon_config: dict[str, Any]) -> str:
    """Stable cache key for a (slug, version, config) tuple.

    Different recon-config toggle combinations get different cache entries — so enabling
    a new feature won't serve stale cached output that lacks that feature's metadata.
    """
    payload = json.dumps(
        {"slug": plugin_slug, "version": plugin_version, "cfg": recon_config},
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def cache_path(key: str) -> Path:
    return CACHE_DIR / f"{key}.json"


def load_cached_recon(key: str) -> dict | None:
    p = cache_path(key)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return None


def save_cached_recon(key: str, recon_dict: dict) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_path(key).write_text(json.dumps(recon_dict, indent=2))
