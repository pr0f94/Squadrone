"""Triage stage — Critic narrows hypotheses, capped to max_hypotheses_to_verify."""

from __future__ import annotations

import json
import logging
from pathlib import Path
import re
import stat

from ..agents.critic import (
    CriticAgent,
    PhpObjectGadgetRecipeCompletion,
    PhpObjectGadgetRecipeCompletions,
)
from ..agents.hypothesis_verifier import validate_exact_sink_anchor
from ..agents.runtime import AgentRuntime
from ..schemas.config import PipelineConfig
from ..schemas.hypothesis import (
    HypothesesArtifact,
    Hypothesis,
    SourceAnchor,
    TriagedArtifact,
)
from ..schemas.php_object_gadget import (
    PhpObjectGadgetDirectPathEffectBinding,
    PhpObjectGadgetGuardedEffectAnchor,
    PhpObjectGadgetGuardedOpaquePrefixEffectBinding,
    PhpObjectGadgetHelperAnchor,
    PhpObjectGadgetRecipe,
    PhpObjectGadgetSourceAnchor,
    normalize_php_contract_source,
)
from ..schemas.taxonomy import BugClass
from ..services.budget import BudgetTracker
from ..services.console_format import (
    format_triage_accept,
    format_triage_merge,
    format_triage_reject,
)
from ..services.artifacts import atomic_write_jsonl
from ..services.decision_ledger import append_decision
from ..services.quality_gate import (
    apply_quality_gate,
    infer_attacker_role,
    rank_hypothesis,
)
from ..services.scope import preverification_programs
from .hypothesis import _build_code_slices

logger = logging.getLogger(__name__)

_MAX_SOURCE_ANCHOR_REPAIR_LINE_DRIFT = 15

_SAFE_GADGET_BUILTINS = frozenset(
    {
        "array",
        "array_key_exists",
        "array_keys",
        "array_merge",
        "array_values",
        "basename",
        "closedir",
        "count",
        "defined",
        "dirname",
        "empty",
        "file_exists",
        "get_class",
        "get_object_vars",
        "in_array",
        "is_array",
        "is_bool",
        "is_dir",
        "is_file",
        "is_int",
        "is_null",
        "is_object",
        "is_readable",
        "is_string",
        "isset",
        "max",
        "method_exists",
        "min",
        "opendir",
        "pathinfo",
        "property_exists",
        "realpath",
        "readdir",
        "sizeof",
        "str_contains",
        "str_ends_with",
        "str_starts_with",
        "strlen",
        "strpos",
        "strrpos",
        "substr",
        "trim",
        "unlink",
        "unset",
    }
)
_GADGET_CALL_TOKEN = re.compile(
    r"(?<![$A-Za-z0-9_\\])"
    r"(?P<name>\\?[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*"
    r"(?:\\[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*)*)\s*\("
)
_GADGET_METHOD_CALL = re.compile(
    r"(?P<receiver>\$this|self|static|parent|"
    r"\\?[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*"
    r"(?:\\[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*)*)"
    r"\s*(?:->|::)\s*(?P<method>[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*)\s*\("
)
_GADGET_ANY_METHOD_CALL = re.compile(r"(?:->|::)\s*[^\s(]+\s*\(")
_GADGET_VARIABLE_CALL = re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*\s*\(")
_GADGET_UNLINK_CALL = re.compile(
    r"(?<![A-Za-z0-9_])@?\\?unlink\s*\(",
    re.IGNORECASE,
)
_GADGET_FORBIDDEN_CONSTRUCT = re.compile(
    r"`|\b(?:clone|die|echo|eval|exit|global|include|include_once|new|print|"
    r"require|require_once|throw|yield)\b",
    re.IGNORECASE,
)
_GADGET_EXTERNAL_STATE = re.compile(
    r"\$(?:GLOBALS|_COOKIE|_ENV|_FILES|_GET|_POST|_REQUEST|_SERVER|_SESSION)\b",
    re.IGNORECASE,
)
_GADGET_MAGIC_METHOD = re.compile(
    r"\bfunction\s*&?\s*(?P<name>__[A-Za-z_][A-Za-z0-9_]*)\s*\(",
    re.IGNORECASE,
)
_GADGET_LIFECYCLE_HOOKS = frozenset({"__wakeup", "__unserialize", "__destruct"})
_PHP_ASSIGNMENT_OPERATOR = (
    r"(?:\?\?=|\*\*=|<<=|>>=|\+=|-=|\*=|/=|%=|\.=|&=|\|=|\^=|=(?!=|>))"
)
_PHP_ASSIGNMENT_OPERATOR_RE = re.compile(_PHP_ASSIGNMENT_OPERATOR)
_SAFE_GADGET_STATIC_MARKER = re.compile(
    r"\A\s*self::\$(?P<marker>[A-Za-z_][A-Za-z0-9_]*)\s*"
    r"\[\s*\$this\s*->\s*(?P<property>[A-Za-z_][A-Za-z0-9_]*)\s*\]"
    r"\s*=\s*true\s*;\s*\Z",
    re.IGNORECASE,
)


def _mask_php_non_code(source: str) -> str:
    """Replace PHP comments and quoted strings while retaining line positions."""
    masked = list(source)
    index = 0
    state = "code"
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if char == "'":
                state = "single"
                masked[index] = " "
            elif char == '"':
                state = "double"
                masked[index] = " "
            elif char == "/" and next_char == "/":
                state = "line_comment"
                masked[index] = masked[index + 1] = " "
                index += 1
            elif char == "#":
                state = "line_comment"
                masked[index] = " "
            elif char == "/" and next_char == "*":
                state = "block_comment"
                masked[index] = masked[index + 1] = " "
                index += 1
        elif state in {"single", "double"}:
            if char == "\\":
                masked[index] = " "
                if index + 1 < len(source):
                    if source[index + 1] != "\n":
                        masked[index + 1] = " "
                    index += 1
            elif (state == "single" and char == "'") or (
                state == "double" and char == '"'
            ):
                masked[index] = " "
                state = "code"
            elif char != "\n":
                masked[index] = " "
        elif state == "line_comment":
            if char == "\n":
                state = "code"
            else:
                masked[index] = " "
        else:
            masked[index] = " "
            if char == "*" and next_char == "/":
                masked[index + 1] = " "
                index += 1
                state = "code"
        index += 1
    if state in {"single", "double", "block_comment"}:
        raise ValueError("unterminated PHP string or block comment in source anchor")
    return "".join(masked)


def _complete_braced_region(source: str, declaration: re.Pattern[str]) -> bool:
    if "<<<" in source:
        return False
    try:
        masked = _mask_php_non_code(source)
    except ValueError:
        return False
    match = declaration.search(masked)
    if match is None:
        return False
    opening = masked.find("{", match.end())
    if opening < 0 or ";" in masked[match.end() : opening]:
        return False
    depth = 0
    for index in range(opening, len(masked)):
        if masked[index] == "{":
            depth += 1
        elif masked[index] == "}":
            depth -= 1
            if depth == 0:
                return not masked[index + 1 :].strip()
            if depth < 0:
                return False
    return False


def _matching_php_brace(masked: str, opening: int) -> int | None:
    depth = 0
    for index in range(opening, len(masked)):
        if masked[index] == "{":
            depth += 1
        elif masked[index] == "}":
            depth -= 1
            if depth == 0:
                return index
            if depth < 0:
                return None
    return None


def _line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def _php_class_ranges(source: str) -> dict[str, tuple[int, int, int, int, str]]:
    """Return case-folded FQCN -> byte/line range plus namespace."""
    masked = _mask_php_non_code(source)
    bracketed_namespace = re.search(
        r"\bnamespace\s+[A-Za-z_\\][A-Za-z0-9_\\]*\s*\{",
        masked,
        re.IGNORECASE,
    )
    if bracketed_namespace is not None:
        raise ValueError("bracketed PHP namespaces are outside gadget recipe v1")
    namespaces = list(
        re.finditer(
            r"\bnamespace\s+(?P<name>[A-Za-z_][A-Za-z0-9_\\]*)\s*;",
            masked,
            re.IGNORECASE,
        )
    )
    classes: dict[str, tuple[int, int, int, int, str]] = {}
    declaration = re.compile(
        r"\b(?:(?:abstract|final|readonly)\s+)*class\s+"
        r"(?P<name>[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*)\b",
        re.IGNORECASE,
    )
    for match in declaration.finditer(masked):
        if re.search(r"\bnew\s*$", masked[max(0, match.start() - 16) : match.start()]):
            continue
        opening = masked.find("{", match.end())
        if opening < 0:
            raise ValueError("class declaration lacks a braced body")
        closing = _matching_php_brace(masked, opening)
        if closing is None:
            raise ValueError("class declaration has an unbalanced body")
        namespace = ""
        for namespace_match in namespaces:
            if namespace_match.start() >= match.start():
                break
            namespace = namespace_match.group("name")
        fqcn = (
            f"{namespace}\\{match.group('name')}" if namespace else match.group("name")
        )
        key = fqcn.lower()
        if key in classes:
            raise ValueError(f"duplicate class declaration for {fqcn!r}")
        classes[key] = (
            match.start(),
            closing + 1,
            _line_number(source, match.start()),
            _line_number(source, closing),
            namespace,
        )
    return classes


def _validate_gadget_class_binding(
    plugin_root: Path,
    *,
    anchor: PhpObjectGadgetSourceAnchor,
    fqcn: str,
    method: str | None,
    class_declaration: bool,
    source_cache: dict[Path, list[str]],
) -> tuple[tuple[int, int, int, int, str] | None, str | None]:
    try:
        source_file = _resolve_gadget_source_file(plugin_root, anchor.file)
        lines = source_cache[source_file]
        source = "\n".join(lines)
        classes = _php_class_ranges(source)
    except (KeyError, OSError, UnicodeError, ValueError) as exc:
        return None, str(exc)
    class_range = classes.get(fqcn.lstrip("\\").lower())
    if class_range is None:
        return None, f"source anchor is not inside declared class {fqcn!r}"
    _, _, class_start_line, class_end_line, _ = class_range
    if class_declaration and anchor.line != class_start_line:
        return None, f"class anchor does not identify {fqcn!r}'s declaration line"
    anchor_end_line = anchor.line + len(anchor.source_code.splitlines() or [""]) - 1
    if not class_declaration and not (
        class_start_line <= anchor.line <= anchor_end_line <= class_end_line
    ):
        return None, f"method anchor is outside declared class {fqcn!r}"
    if method is not None:
        class_source = source[class_range[0] : class_range[1]]
        declaration = re.compile(
            rf"\bfunction\s*&?\s*{re.escape(method)}\s*\(",
            re.IGNORECASE,
        )
        method_lines = {
            _line_number(source, class_range[0] + match.start())
            for match in declaration.finditer(_mask_php_non_code(class_source))
        }
        if method_lines != {anchor.line}:
            return None, (
                f"method anchor does not uniquely bind {fqcn}::{method} at its "
                "declaration line"
            )
    return class_range, None


def _validate_gadget_lifecycle_hooks(
    plugin_root: Path,
    recipe: PhpObjectGadgetRecipe,
    source_cache: dict[Path, list[str]],
) -> str | None:
    obj = recipe.gadget_object
    checked: dict[
        str, tuple[PhpObjectGadgetSourceAnchor, tuple[int, int, int, int, str]]
    ] = {}
    for fqcn, anchor, method, class_declaration in (
        (obj.class_name, obj.class_anchor, None, True),
        (obj.trigger_declaring_class, obj.trigger_anchor, obj.trigger, False),
    ):
        class_range, error = _validate_gadget_class_binding(
            plugin_root,
            anchor=anchor,
            fqcn=fqcn,
            method=method,
            class_declaration=class_declaration,
            source_cache=source_cache,
        )
        if error is not None or class_range is None:
            return error
        prior = checked.get(fqcn.lower())
        if prior is not None and (
            prior[0].file != anchor.file or prior[1][0:4] != class_range[0:4]
        ):
            return f"class {fqcn!r} resolves to conflicting source ranges"
        checked[fqcn.lower()] = (anchor, class_range)
    for helper in recipe.helper_anchors:
        if "::" not in helper.symbol:
            return "gadget recipe v1 helper anchors must name explicit class methods"
        helper_fqcn, helper_method = helper.symbol.rsplit("::", 1)
        class_range, error = _validate_gadget_class_binding(
            plugin_root,
            anchor=helper.anchor,
            fqcn=helper_fqcn,
            method=helper_method,
            class_declaration=False,
            source_cache=source_cache,
        )
        if error is not None or class_range is None:
            return error
        prior = checked.get(helper_fqcn.lower())
        if prior is not None and (
            prior[0].file != helper.anchor.file or prior[1][0:4] != class_range[0:4]
        ):
            return f"class {helper_fqcn!r} resolves to conflicting source ranges"
        checked.setdefault(helper_fqcn.lower(), (helper.anchor, class_range))

    declared_classes = set(checked)
    unknown_property_classes = {
        prop.declaring_class.lower()
        for prop in obj.properties
        if prop.declaring_class.lower() not in declared_classes
    }
    if unknown_property_classes:
        return (
            "property declaring classes lack exact class source binding: "
            + ", ".join(sorted(unknown_property_classes))
        )

    gadget_anchor, gadget_range = checked[obj.class_name.lower()]
    source_file = _resolve_gadget_source_file(plugin_root, gadget_anchor.file)
    source = "\n".join(source_cache[source_file])
    class_source = source[gadget_range[0] : gadget_range[1]]
    declared_magic = {
        match.group("name").lower()
        for match in _GADGET_MAGIC_METHOD.finditer(_mask_php_non_code(class_source))
    }
    lifecycle = declared_magic & _GADGET_LIFECYCLE_HOOKS
    if lifecycle != {obj.trigger.lower()}:
        return (
            "gadget class must declare exactly the selected deserialization lifecycle "
            f"hook; found {sorted(lifecycle)}"
        )
    unreviewed_magic = declared_magic - {"__construct", obj.trigger.lower()}
    if unreviewed_magic:
        return "gadget class declares unreviewed invokable magic hooks: " + ", ".join(
            sorted(unreviewed_magic)
        )
    return None


def _resolve_gadget_source_file(plugin_root: Path, relative_file: str) -> Path:
    root = plugin_root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("plugin root is not a directory")
    candidate = root
    for part in relative_file.split("/"):
        candidate = candidate / part
        if candidate.is_symlink():
            raise ValueError(f"source anchor traverses symlink {relative_file!r}")
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(
            f"source anchor escapes plugin root: {relative_file!r}"
        ) from exc
    metadata = resolved.stat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"source anchor is not a regular file: {relative_file!r}")
    return resolved


def _validate_gadget_anchor_quote(
    plugin_root: Path,
    anchor: PhpObjectGadgetSourceAnchor,
    source_cache: dict[Path, list[str]],
) -> str | None:
    try:
        source_file = _resolve_gadget_source_file(plugin_root, anchor.file)
        lines = source_cache.get(source_file)
        if lines is None:
            lines = source_file.read_text(
                encoding="utf-8", errors="strict"
            ).splitlines()
            source_cache[source_file] = lines
    except (OSError, UnicodeError, ValueError) as exc:
        return str(exc)
    quoted_lines = anchor.source_code.splitlines() or [anchor.source_code]
    start = anchor.line - 1
    actual_lines = lines[start : start + len(quoted_lines)]
    if len(actual_lines) != len(quoted_lines):
        return f"source quote at {anchor.file}:{anchor.line} extends past end of file"
    if [line.strip() for line in actual_lines] != [
        line.strip() for line in quoted_lines
    ]:
        return f"source quote does not match {anchor.file}:{anchor.line}"
    return None


def _gadget_effect_identity(
    anchor: PhpObjectGadgetSourceAnchor,
) -> tuple[str, int, str]:
    lines = anchor.source_code.splitlines() or [anchor.source_code]
    if len(lines) != 1 or len(_GADGET_UNLINK_CALL.findall(lines[0])) != 1:
        raise ValueError(
            "each effect anchor must be one exact line with one unlink call"
        )
    return (anchor.file, anchor.line, lines[0].strip())


def _gadget_unlink_occurrences(
    anchors: tuple[PhpObjectGadgetSourceAnchor, ...],
) -> set[tuple[str, int, str]]:
    occurrences: set[tuple[str, int, str]] = set()
    for anchor in anchors:
        for offset, line in enumerate(anchor.source_code.splitlines() or [""]):
            count = len(_GADGET_UNLINK_CALL.findall(line))
            if count > 1:
                raise ValueError(
                    "one reviewed source line cannot contain multiple unlink calls"
                )
            if count == 1:
                identity = (anchor.file, anchor.line + offset, line.strip())
                if identity in occurrences:
                    raise ValueError(
                        "reviewed method anchors overlap at an unlink call"
                    )
                occurrences.add(identity)
    return occurrences


def _validate_safe_static_markers(
    source: str,
    *,
    opaque_properties: frozenset[str],
) -> str | None:
    masked = _mask_php_non_code(source)
    if re.search(r"\bstatic\s+\$", masked, re.IGNORECASE):
        return "selected gadget body declares mutable function-static state"
    static_mutation = re.compile(
        r"(?:self|static|parent|[A-Za-z_\\][A-Za-z0-9_\\]*)::\$[A-Za-z_]"
        r"[A-Za-z0-9_]*(?:\s*\[[^\]\n]+\])?\s*"
        rf"(?:{_PHP_ASSIGNMENT_OPERATOR}|\+\+|--)",
        re.IGNORECASE,
    )
    lines = masked.splitlines()
    for line in lines:
        if not static_mutation.search(line) and not re.search(
            r"(?:unset\s*\(\s*|&\s*)(?:self|static|parent|"
            r"[A-Za-z_\\][A-Za-z0-9_\\]*)::\$",
            line,
            re.IGNORECASE,
        ):
            continue
        marker = _SAFE_GADGET_STATIC_MARKER.fullmatch(line)
        if marker is None or marker.group("property") not in opaque_properties:
            return (
                "selected gadget body has a class-static write other than a bounded "
                "opaque-ID boolean marker"
            )
    return None


def _validate_source_bound_static_markers(
    plugin_root: Path,
    recipe: PhpObjectGadgetRecipe,
    source_cache: dict[Path, list[str]],
    *,
    body_sources: dict[str, tuple[str, str, str]],
) -> str | None:
    """Bind the narrow boolean-marker exception to a native static array."""
    markers: dict[str, str] = {}
    gadget_class = recipe.gadget_object.class_name.lower()
    for source, _, declaring_class in body_sources.values():
        try:
            masked = _mask_php_non_code(source)
        except ValueError as exc:
            return str(exc)
        for line in masked.splitlines():
            marker = _SAFE_GADGET_STATIC_MARKER.fullmatch(line)
            if marker is None:
                continue
            if declaring_class.lower() != gadget_class:
                return "bounded static markers must be declared on the gadget class"
            marker_name = marker.group("marker")
            opaque_property = marker.group("property")
            previous = markers.setdefault(marker_name, opaque_property)
            if previous != opaque_property:
                return "one bounded static marker cannot use multiple opaque properties"
    if not markers:
        return None

    class_anchor = recipe.gadget_object.class_anchor
    try:
        source_file = _resolve_gadget_source_file(plugin_root, class_anchor.file)
        source = "\n".join(source_cache[source_file])
        class_range = _php_class_ranges(source)[gadget_class]
        class_source = source[class_range[0] : class_range[1]]
        masked_class = _mask_php_non_code(class_source)
    except (KeyError, OSError, UnicodeError, ValueError) as exc:
        return str(exc)
    if re.search(
        r"(?:self|static|parent|[A-Za-z_\\][A-Za-z0-9_\\]*|"
        r"\$[A-Za-z_][A-Za-z0-9_]*)\s*::\s*\$(?:\$|\{)",
        masked_class,
        re.IGNORECASE,
    ):
        return "gadget class uses dynamic class-static property access"

    for marker_name, opaque_property in markers.items():
        escaped_marker = re.escape(marker_name)
        escaped_opaque = re.escape(opaque_property)
        declaration = re.compile(
            rf"\A\s*(?:public\s+|protected\s+|private\s+)?static\s+"
            rf"\${escaped_marker}\s*=\s*(?:array\s*\(\s*\)|\[\s*\])\s*;\s*\Z",
            re.IGNORECASE,
        )
        guarded_read = re.compile(
            rf"\A\s*if\s*\(\s*isset\s*\(\s*self\s*::\s*\${escaped_marker}"
            rf"\s*\[\s*\$this\s*->\s*{escaped_opaque}\s*\]\s*\)\s*\)\s*\{{\s*\Z",
            re.IGNORECASE,
        )
        marker_write = re.compile(
            rf"\A\s*self\s*::\s*\${escaped_marker}\s*\[\s*\$this\s*->\s*"
            rf"{escaped_opaque}\s*\]\s*=\s*true\s*;\s*\Z",
            re.IGNORECASE,
        )
        declarations = 0
        reads = 0
        writes = 0
        static_reference = re.compile(
            rf"(?:[A-Za-z_\\][A-Za-z0-9_\\]*|\$[A-Za-z_][A-Za-z0-9_]*|"
            rf"self|static|parent)\s*::\s*\${escaped_marker}\b",
            re.IGNORECASE,
        )
        for line in masked_class.splitlines():
            if declaration.fullmatch(line):
                declarations += 1
                continue
            occurrences = len(static_reference.findall(line))
            if occurrences == 0:
                continue
            if occurrences != 1:
                return "bounded static marker has an ambiguous class-static reference"
            if guarded_read.fullmatch(line):
                reads += 1
            elif marker_write.fullmatch(line):
                writes += 1
            else:
                return "bounded static marker has an unreviewed class-static reference"
        if declarations != 1 or reads != 1 or writes != 1:
            return (
                "bounded static marker requires one native-array declaration, "
                "one opaque-key read, and one boolean write"
            )
    return None


def _validate_bound_directory_calls(
    source: str,
    *,
    directory_constants: frozenset[str],
) -> str | None:
    masked = _mask_php_non_code(source)
    directory_call = re.compile(
        r"(?<![A-Za-z0-9_])@?\\?(?P<name>opendir|readdir|closedir|glob)\s*\(",
        re.IGNORECASE,
    )
    if not directory_call.search(masked):
        return None
    if re.search(r"(?<![A-Za-z0-9_])@?\\?glob\s*\(", masked, re.IGNORECASE):
        return "glob is not an allowlisted guarded-directory traversal"
    opened: set[str] = set()
    accepted_opens: list[tuple[int, int]] = []
    open_call = re.compile(
        r"(?P<handle>\$[A-Za-z_][A-Za-z0-9_]*)\s*=\s*@?\\?opendir\s*"
        r"\(\s*(?P<constant>[A-Z_][A-Z0-9_]*)\s*\)",
        re.IGNORECASE,
    )
    for match in open_call.finditer(masked):
        if match.group("constant") not in directory_constants:
            return "opendir must use a source-bound gadget directory constant"
        opened.add(match.group("handle"))
        accepted_opens.append(match.span())
    for handle in opened:
        if len(
            re.findall(
                rf"{re.escape(handle)}\s*(?<!=)=(?!=)",
                masked,
            )
        ) != 1 or re.search(rf"&\s*{re.escape(handle)}\b", masked):
            return "bound opendir handle cannot be reassigned or aliased"
    for match in re.finditer(
        r"(?<![A-Za-z0-9_])@?\\?opendir\s*\(", masked, re.IGNORECASE
    ):
        if not any(start <= match.start() < end for start, end in accepted_opens):
            return "opendir result must be assigned to one bounded local handle"
    for function_name in ("readdir", "closedir"):
        calls = list(
            re.finditer(
                rf"(?<![A-Za-z0-9_])@?\\?{function_name}\s*"
                r"\(\s*(?P<handle>\$[A-Za-z_][A-Za-z0-9_]*)\s*\)",
                masked,
                re.IGNORECASE,
            )
        )
        generic_calls = list(
            re.finditer(
                rf"(?<![A-Za-z0-9_])@?\\?{function_name}\s*\(",
                masked,
                re.IGNORECASE,
            )
        )
        if len(calls) != len(generic_calls) or any(
            match.group("handle") not in opened for match in calls
        ):
            return f"{function_name} must use the bound opendir handle"
    return None


def _validate_local_path_exists_contract(
    helper: PhpObjectGadgetHelperAnchor,
    *,
    namespace: str,
) -> str | None:
    method = helper.symbol.rsplit("::", 1)[-1]
    try:
        compact = normalize_php_contract_source(helper.anchor.source_code)
    except (TypeError, ValueError):
        return "local_path_exists helper has malformed PHP tokens"
    function_prefix = r"\\?" if not namespace else r"\\"
    contract = re.compile(
        rf"\A(?:public)?staticfunction{re.escape(method)}\(\$(?P<arg>[A-Za-z_]"
        rf"[A-Za-z0-9_]*)\)\{{if\({function_prefix}preg_match\((?P<q1>['\"])"
        rf"\|\^https\?://\|(?P=q1),\$(?P=arg)\)===?1\)\{{returnself::"
        rf"url_exists\(\$(?P=arg)\);\}}if\({function_prefix}strpos\(\$(?P=arg),"
        rf"(?P<q2>['\"])://(?P=q2)\)\)\{{returnfalse;\}}return@?"
        rf"{function_prefix}file_exists\(\$(?P=arg)\);\}}\Z",
        re.IGNORECASE,
    )
    if contract.fullmatch(compact) is None:
        return (
            "local_path_exists helper must exactly reject schemes before its final "
            "local file_exists branch"
        )
    return None


def _validate_direct_local_path_guard(
    binding: PhpObjectGadgetDirectPathEffectBinding,
) -> str | None:
    check = binding.local_path_check
    if check is None:
        return None
    variable = binding.effect_variable
    if binding.access != "list_item" or variable is None:
        return "local_path_exists guard currently requires list_item direct access"
    prefix = check.guard_anchor.source_code.split("{", 1)[0].strip()
    helper_class, helper_method = check.helper_symbol.rsplit("::", 1)
    condition = re.compile(
        rf"\Aif\s*\(\s*\\?strpos\s*\(\s*\${re.escape(variable)}\s*,\s*"
        rf"{re.escape(check.directory_constant)}\s*\)\s*===\s*0\s*&&\s*"
        rf"\\?{re.escape(helper_class)}::{re.escape(helper_method)}\s*"
        rf"\(\s*\${re.escape(variable)}\s*\)\s*\)\s*\Z",
        re.IGNORECASE,
    )
    if condition.fullmatch(prefix) is None:
        return (
            "direct local-path guard must bind the effect variable to the directory "
            "constant and local_path_exists helper"
        )
    guard_pattern = re.compile(r"\A\s*if\s*\(", re.IGNORECASE)
    if not _complete_braced_region(check.guard_anchor.source_code, guard_pattern):
        return "direct local-path guard must be one complete braced if region"
    return None


def _anchor_is_within(
    child: PhpObjectGadgetSourceAnchor,
    parent: PhpObjectGadgetSourceAnchor,
) -> bool:
    if child.file != parent.file or child.line < parent.line:
        return False
    parent_lines = parent.source_code.splitlines() or [parent.source_code]
    child_lines = child.source_code.splitlines() or [child.source_code]
    offset = child.line - parent.line
    return offset + len(child_lines) <= len(parent_lines) and [
        line.strip() for line in parent_lines[offset : offset + len(child_lines)]
    ] == [line.strip() for line in child_lines]


def _php_reference_is_written(
    masked: str,
    reference: re.Pattern[str],
) -> bool:
    """Recognise writes after a bounded PHP variable/property reference."""
    for match in reference.finditer(masked):
        cursor = match.end()
        while True:
            while cursor < len(masked) and masked[cursor].isspace():
                cursor += 1
            if cursor >= len(masked) or masked[cursor] not in "[{":
                break
            opening = masked[cursor]
            closing = "]" if opening == "[" else "}"
            depth = 0
            while cursor < len(masked):
                if masked[cursor] == opening:
                    depth += 1
                elif masked[cursor] == closing:
                    depth -= 1
                    if depth == 0:
                        cursor += 1
                        break
                cursor += 1
            if depth != 0:
                return True
        while cursor < len(masked) and masked[cursor].isspace():
            cursor += 1
        if _PHP_ASSIGNMENT_OPERATOR_RE.match(masked, cursor) or masked.startswith(
            ("++", "--"),
            cursor,
        ):
            return True
        prefix = masked[max(0, match.start() - 32) : match.start()]
        if re.search(r"(?:\+\+|--|&|unset\s*\(\s*)\s*\Z", prefix, re.IGNORECASE):
            return True
    return False


def _validate_gadget_effect_dataflow(
    recipe: PhpObjectGadgetRecipe,
    *,
    body_anchors: tuple[PhpObjectGadgetSourceAnchor, ...],
    guarded_effects: tuple[PhpObjectGadgetGuardedEffectAnchor, ...],
) -> str | None:
    binding = recipe.effect_binding
    if isinstance(binding, PhpObjectGadgetDirectPathEffectBinding):
        effect_containing = [
            body
            for body in body_anchors
            if _anchor_is_within(binding.effect_anchor, body)
        ]
        if len(effect_containing) != 1:
            return "direct effect does not bind to exactly one complete helper body"
        effect_body = effect_containing[0]
        effect_prefix_lines = (effect_body.source_code.splitlines() or [""])[
            : binding.effect_anchor.line - effect_body.line
        ]
        effect_prefix = "\n".join(effect_prefix_lines)
        prop = re.escape(binding.effect_property)
        property_reference = rf"\$this\s*->\s*{prop}\b(?:\s*\[[^\]\n]*\])*"
        property_base = re.compile(
            rf"\$this\s*->\s*{prop}\b",
            re.IGNORECASE,
        )
        property_alias_or_unset = re.compile(
            rf"(?:unset\s*\(\s*|&\s*){property_reference}",
            re.IGNORECASE,
        )
        dynamic_property_write = re.compile(
            r"(?:\$this\s*->\s*(?:\$[A-Za-z_][A-Za-z0-9_]*|\{[^}\n]+\})"
            rf"(?:\s*\[[^\]\n]*\])*\s*(?:{_PHP_ASSIGNMENT_OPERATOR}|\+\+|--)"
            r"|(?:unset\s*\(\s*|&\s*)\$this\s*->\s*(?:\$|\{))",
            re.IGNORECASE,
        )
        this_alias = re.compile(
            r"\$[A-Za-z_][A-Za-z0-9_]*\s*=\s*&?\s*\$this\s*;",
            re.IGNORECASE,
        )
        for body in body_anchors:
            source = effect_prefix if body is effect_body else body.source_code
            try:
                masked = _mask_php_non_code(source)
            except ValueError as exc:
                return str(exc)
            if _php_reference_is_written(
                masked,
                property_base,
            ) or property_alias_or_unset.search(masked):
                return "effect property is mutated or aliased before its direct sink"
            if re.search(
                rf"\bforeach\s*\([^{{}};]*\bas\b[^{{}};]*{property_reference}"
                rf"[^{{}};]*\)",
                masked,
                re.IGNORECASE,
            ) or re.search(
                rf"(?:\blist\s*\(|\[)[^;=]*{property_reference}[^;=]*"
                r"(?:\)|\])\s*=(?!=)",
                masked,
                re.IGNORECASE,
            ):
                return "effect property is rebound by a PHP binding construct"
            if (
                dynamic_property_write.search(masked)
                or re.search(r"\$this\s*->\s*\{", masked)
                or re.search(r"\$\$|\$\{", masked)
                or this_alias.search(masked)
                or re.search(r"\$this\b(?!\s*->)", masked)
            ):
                return "dynamic object mutation or alias can change the direct effect"

        for body in body_anchors:
            try:
                masked = _mask_php_non_code(body.source_code)
            except ValueError as exc:
                return str(exc)
            declaration = re.search(
                r"\bfunction\s*(?P<return_ref>&?)\s*"
                r"[A-Za-z_][A-Za-z0-9_]*\s*\((?P<args>[^)]*)\)",
                masked,
                re.IGNORECASE,
            )
            if declaration is not None and (
                declaration.group("return_ref") or "&" in declaration.group("args")
            ):
                return (
                    "selected gadget helpers cannot declare by-reference returns "
                    "or parameters"
                )

        iteration = binding.iteration_anchor
        if iteration is not None:
            containing = [
                body for body in body_anchors if _anchor_is_within(iteration, body)
            ]
            if len(containing) != 1:
                return (
                    "direct iteration does not bind to exactly one complete helper body"
                )
            body = containing[0]
            prefix_lines = (body.source_code.splitlines() or [""])[
                : iteration.line - body.line
            ]
            prefix = "\n".join(prefix_lines)
            if _php_reference_is_written(
                _mask_php_non_code(prefix),
                property_base,
            ) or re.search(
                rf"(?:unset\s*\(\s*|&\s*)\$this\s*->\s*{prop}\b",
                prefix,
                re.IGNORECASE,
            ):
                return (
                    "effect property is mutated or aliased before its direct iteration"
                )
            if _GADGET_METHOD_CALL.search(_mask_php_non_code(prefix)):
                return "helper call before direct iteration could mutate its effect property"

            variable = binding.effect_variable
            assert variable is not None
            iteration_prefix_lines = (iteration.source_code.splitlines() or [""])[
                : binding.effect_anchor.line - iteration.line
            ]
            iteration_prefix = _mask_php_non_code("\n".join(iteration_prefix_lines))
            variable_ref = rf"\${re.escape(variable)}\b(?:\s*\[[^\]\n]*\])*"
            variable_base = re.compile(
                rf"\${re.escape(variable)}\b",
                re.IGNORECASE,
            )
            if _php_reference_is_written(
                iteration_prefix,
                variable_base,
            ) or re.search(
                rf"(?:unset\s*\(\s*|&\s*){variable_ref}",
                iteration_prefix,
                re.IGNORECASE,
            ):
                return "direct effect variable is mutated or aliased before its sink"
            loop_prefix = iteration_prefix.split("{", 1)[-1]
            if re.search(
                rf"\bforeach\s*\([^{{}};]*\bas\b[^{{}};]*{variable_ref}"
                rf"[^{{}};]*\)",
                loop_prefix,
                re.IGNORECASE,
            ) or re.search(
                rf"(?:\blist\s*\(|\[)[^;=]*{variable_ref}[^;=]*"
                r"(?:\)|\])\s*=(?!=)",
                loop_prefix,
                re.IGNORECASE,
            ):
                return "direct effect variable is rebound by a PHP binding construct"

    for guarded in guarded_effects:
        containing = [
            body
            for body in body_anchors
            if _anchor_is_within(guarded.guard_anchor, body)
        ]
        if len(containing) != 1:
            return "guarded effect does not bind to exactly one complete helper body"
        body = containing[0]
        prefix_lines = (body.source_code.splitlines() or [""])[
            : guarded.guard_anchor.line - body.line
        ]
        prefix = "\n".join(prefix_lines)
        condition = guarded.guard_anchor.source_code.split("{", 1)[0]
        variable_match = re.search(
            r"\\?strpos\s*\(\s*\$(?P<name>[A-Za-z_][A-Za-z0-9_]*)",
            condition,
            re.IGNORECASE,
        )
        if variable_match is None:
            return "guarded effect lacks one source-bound basename variable"
        variable = variable_match.group("name")
        assignments = list(
            re.finditer(
                rf"\${re.escape(variable)}\s*=\s*\\?readdir\s*"
                r"\(\s*\$(?P<handle>[A-Za-z_][A-Za-z0-9_]*)\s*\)",
                prefix,
                re.IGNORECASE,
            )
        )
        if not assignments:
            return "guarded basename must come from the bound directory handle"
        assignment = assignments[-1]
        later_prefix = prefix[assignment.end() :]
        if re.search(rf"\${re.escape(variable)}\s*(?<!=)=(?!=)", later_prefix):
            return "guarded basename is reassigned after its bound directory read"
        handle = assignment.group("handle")
        if (
            re.search(
                rf"\${re.escape(handle)}\s*=\s*@?\\?opendir\s*\(\s*"
                rf"{re.escape(guarded.directory_constant)}\s*\)",
                prefix,
                re.IGNORECASE,
            )
            is None
        ):
            return "guarded basename directory does not match its declared constant"
    return None


def _resolve_gadget_body_calls(
    source: str,
    *,
    helper_symbols: tuple[str, ...],
    namespace: str,
    declaring_class: str,
    opaque_properties: frozenset[str],
    directory_constants: frozenset[str],
) -> tuple[set[str], str | None]:
    """Resolve every selected-body call to a safe builtin or reviewed helper."""
    try:
        masked = _mask_php_non_code(source)
    except ValueError as exc:
        return set(), str(exc)
    if _GADGET_FORBIDDEN_CONSTRUCT.search(masked):
        return set(), "selected gadget body contains a forbidden PHP construct"
    if _GADGET_EXTERNAL_STATE.search(masked):
        return set(), "selected gadget body reads or mutates external request state"
    if re.search(
        r"(?:self|static|parent|[A-Za-z_\\][A-Za-z0-9_\\]*|"
        r"\$[A-Za-z_][A-Za-z0-9_]*)\s*::\s*\$(?:\$|\{)",
        masked,
        re.IGNORECASE,
    ):
        return set(), "selected gadget body uses dynamic class-static property access"
    static_error = _validate_safe_static_markers(
        source,
        opaque_properties=opaque_properties,
    )
    if static_error is not None:
        return set(), static_error
    directory_error = _validate_bound_directory_calls(
        source,
        directory_constants=directory_constants,
    )
    if directory_error is not None:
        return set(), directory_error
    if _GADGET_VARIABLE_CALL.search(masked) or re.search(
        r"(?:->|::)\s*\$[A-Za-z_][A-Za-z0-9_]*\s*\(",
        masked,
    ):
        return set(), "selected gadget body contains a dynamic callback"
    if re.search(
        r"(?:'[^'\n]*'|\"[^\"\n]*\"|\([^()]*\$[^()]*\)|\[[^]]+\]"
        r"|\$\{[^}]+\}|\))\s*\(",
        source,
    ) or re.search(r"\bfunction\s*\(", masked, re.IGNORECASE):
        return set(), "selected gadget body contains an indirect callable expression"

    helper_by_method: dict[str, list[str]] = {}
    helper_functions: dict[str, str] = {}
    for symbol in helper_symbols:
        if "::" in symbol:
            helper_by_method.setdefault(symbol.rsplit("::", 1)[-1].lower(), []).append(
                symbol
            )
        else:
            helper_functions[symbol.lower().lstrip("\\")] = symbol

    resolved_calls: set[str] = set()
    method_spans: list[tuple[int, int]] = []
    for match in _GADGET_METHOD_CALL.finditer(masked):
        method_spans.append(match.span())
        method = match.group("method").lower()
        receiver = match.group("receiver").lstrip("\\")
        candidates = helper_by_method.get(method, [])
        if receiver.lower() in {"$this", "self", "static"}:
            candidates = [
                symbol
                for symbol in candidates
                if symbol.rsplit("::", 1)[0].lstrip("\\").lower()
                == declaring_class.lower()
            ]
        elif receiver.lower() == "parent":
            return set(), "parent helper calls are outside gadget recipe v1"
        else:
            candidates = [
                symbol
                for symbol in candidates
                if symbol.rsplit("::", 1)[0].lstrip("\\").lower() == receiver.lower()
            ]
        if len(candidates) != 1:
            return set(), f"unresolved or ambiguous helper method call {method!r}"
        resolved_calls.add(candidates[0])
    for match in _GADGET_ANY_METHOD_CALL.finditer(masked):
        if not any(
            start <= match.start() and match.end() <= end for start, end in method_spans
        ):
            return set(), "selected gadget body contains an unresolved method call"

    for match in _GADGET_CALL_TOKEN.finditer(masked):
        prefix = masked[max(0, match.start() - 32) : match.start()]
        if prefix.rstrip().endswith(("->", "::")):
            continue
        if re.search(r"\bfunction\s*&?\s*$", prefix, re.IGNORECASE):
            continue
        raw_name = match.group("name")
        name = raw_name.lstrip("\\").lower()
        if name in _SAFE_GADGET_BUILTINS:
            if namespace and not raw_name.startswith("\\"):
                return set(), (
                    f"unqualified builtin {name!r} can be shadowed in namespace "
                    f"{namespace!r}"
                )
            continue
        if name in {
            "and",
            "catch",
            "declare",
            "elseif",
            "for",
            "foreach",
            "if",
            "or",
            "switch",
            "while",
            "xor",
        }:
            continue
        helper = helper_functions.get(name)
        if helper is None:
            return set(), f"unresolved or non-allowlisted function call {name!r}"
        resolved_calls.add(helper)
    return resolved_calls, None


def validate_php_object_gadget_recipe_sources(
    plugin_root: Path,
    recipe: PhpObjectGadgetRecipe,
) -> str | None:
    """Bind a natural-gadget recipe to exact, plugin-local shipped PHP source."""
    direct_binding = (
        recipe.effect_binding
        if isinstance(recipe.effect_binding, PhpObjectGadgetDirectPathEffectBinding)
        else None
    )
    primary_guarded = (
        recipe.effect_binding.effect
        if isinstance(
            recipe.effect_binding,
            PhpObjectGadgetGuardedOpaquePrefixEffectBinding,
        )
        else None
    )
    all_guarded = (
        *((primary_guarded,) if primary_guarded is not None else ()),
        *recipe.guarded_effect_anchors,
    )
    binding_anchors: list[PhpObjectGadgetSourceAnchor] = []
    if direct_binding is not None:
        binding_anchors.append(direct_binding.effect_anchor)
        if direct_binding.iteration_anchor is not None:
            binding_anchors.append(direct_binding.iteration_anchor)
        if direct_binding.local_path_check is not None:
            binding_anchors.append(direct_binding.local_path_check.guard_anchor)
    elif primary_guarded is not None:
        binding_anchors.extend((primary_guarded.anchor, primary_guarded.guard_anchor))
    anchors = [
        recipe.gadget_object.class_anchor,
        recipe.gadget_object.trigger_anchor,
        *(helper.anchor for helper in recipe.helper_anchors),
        *binding_anchors,
        *(
            anchor
            for guarded in recipe.guarded_effect_anchors
            for anchor in (guarded.anchor, guarded.guard_anchor)
        ),
    ]
    source_cache: dict[Path, list[str]] = {}
    for anchor in anchors:
        error = _validate_gadget_anchor_quote(plugin_root, anchor, source_cache)
        if error is not None:
            return error

    lifecycle_error = _validate_gadget_lifecycle_hooks(
        plugin_root,
        recipe,
        source_cache,
    )
    if lifecycle_error is not None:
        return lifecycle_error

    trigger_pattern = re.compile(
        rf"\bfunction\s*&?\s*{re.escape(recipe.gadget_object.trigger)}\s*\(",
        re.IGNORECASE,
    )
    if not _complete_braced_region(
        recipe.gadget_object.trigger_anchor.source_code,
        trigger_pattern,
    ):
        return "trigger anchor must quote one complete braced method body"
    for helper in recipe.helper_anchors:
        method = helper.symbol.rsplit("::", 1)[-1]
        helper_pattern = re.compile(
            rf"\bfunction\s*&?\s*{re.escape(method)}\s*\(",
            re.IGNORECASE,
        )
        if not _complete_braced_region(helper.anchor.source_code, helper_pattern):
            return (
                f"helper anchor {helper.symbol!r} must quote its complete braced body"
            )
    for guarded in all_guarded:
        guard_pattern = re.compile(r"\A\s*if\s*\(", re.IGNORECASE)
        if not _complete_braced_region(
            guarded.guard_anchor.source_code,
            guard_pattern,
        ):
            return "guard anchor must quote one complete braced if region"
    if direct_binding is not None:
        if direct_binding.iteration_anchor is not None:
            iteration_pattern = re.compile(r"\A\s*foreach\s*\(", re.IGNORECASE)
            if not _complete_braced_region(
                direct_binding.iteration_anchor.source_code,
                iteration_pattern,
            ):
                return "direct-path iteration must be one complete braced foreach"
        local_guard_error = _validate_direct_local_path_guard(direct_binding)
        if local_guard_error is not None:
            return local_guard_error

    body_anchors = (
        recipe.gadget_object.trigger_anchor,
        *(helper.anchor for helper in recipe.helper_anchors),
    )
    dataflow_error = _validate_gadget_effect_dataflow(
        recipe,
        body_anchors=body_anchors,
        guarded_effects=all_guarded,
    )
    if dataflow_error is not None:
        return dataflow_error

    helper_symbols = tuple(helper.symbol for helper in recipe.helper_anchors)
    helpers_by_symbol = {helper.symbol: helper for helper in recipe.helper_anchors}
    body_sources: dict[str, tuple[str, str, str]] = {
        "<trigger>": (
            recipe.gadget_object.trigger_anchor.source_code,
            recipe.gadget_object.trigger_declaring_class.rpartition("\\")[0],
            recipe.gadget_object.trigger_declaring_class,
        ),
        **{
            helper.symbol: (
                helper.anchor.source_code,
                helper.symbol.rsplit("::", 1)[0].rpartition("\\")[0],
                helper.symbol.rsplit("::", 1)[0],
            )
            for helper in recipe.helper_anchors
        },
    }
    static_marker_error = _validate_source_bound_static_markers(
        plugin_root,
        recipe,
        source_cache,
        body_sources=body_sources,
    )
    if static_marker_error is not None:
        return static_marker_error
    opaque_properties = frozenset(
        prop.name
        for prop in recipe.gadget_object.properties
        if prop.value.kind == "opaque_generation_id"
    )
    directory_constants = frozenset(
        {
            *(guarded.directory_constant for guarded in all_guarded),
            *(
                (direct_binding.local_path_check.directory_constant,)
                if direct_binding is not None
                and direct_binding.local_path_check is not None
                else ()
            ),
        }
    )
    edges: dict[str, set[str]] = {}
    for symbol, (source, namespace, declaring_class) in body_sources.items():
        selected_helper = helpers_by_symbol.get(symbol)
        if (
            selected_helper is not None
            and selected_helper.contract == "local_path_exists"
        ):
            contract_error = _validate_local_path_exists_contract(
                selected_helper,
                namespace=namespace,
            )
            if contract_error is not None:
                return f"{symbol}: {contract_error}"
            edges[symbol] = set()
            continue
        calls, error = _resolve_gadget_body_calls(
            source,
            helper_symbols=helper_symbols,
            namespace=namespace,
            declaring_class=declaring_class,
            opaque_properties=opaque_properties,
            directory_constants=directory_constants,
        )
        if error is not None:
            return f"{symbol}: {error}"
        edges[symbol] = calls

    reachable = {"<trigger>"}
    pending = ["<trigger>"]
    while pending:
        current = pending.pop()
        for helper_symbol in edges[current]:
            if helper_symbol not in reachable:
                reachable.add(helper_symbol)
                pending.append(helper_symbol)
    unreachable_helpers = set(helper_symbols) - reachable
    if unreachable_helpers:
        return "helper anchors are not reachable from the trigger: " + ", ".join(
            sorted(unreachable_helpers)
        )
    try:
        observed_unlinks = _gadget_unlink_occurrences(body_anchors)
        if direct_binding is not None:
            primary_identity = _gadget_effect_identity(direct_binding.effect_anchor)
        else:
            assert primary_guarded is not None
            primary_identity = _gadget_effect_identity(primary_guarded.anchor)
        declared_unlinks = {
            primary_identity,
            *(
                _gadget_effect_identity(guarded.anchor)
                for guarded in recipe.guarded_effect_anchors
            ),
        }
    except ValueError as exc:
        return str(exc)
    if observed_unlinks != declared_unlinks:
        return (
            "every reachable unlink in the complete trigger/helper bodies must equal "
            "the primary plus classified guarded effects"
        )
    return None


def _apply_submission_scope(
    triaged: TriagedArtifact,
    run_dir: Path,
    *,
    enforce_submission_scope: bool,
) -> None:
    """Route candidates for delivery, optionally retaining local-only verification."""
    triaged.submission_scope_enforced = enforce_submission_scope
    scope_eligible = []
    for hypothesis in triaged.accepted:
        programs, reasons = preverification_programs(hypothesis)
        hypothesis.bounty_programs = programs
        if programs or not enforce_submission_scope:
            scope_eligible.append(hypothesis)
            if not programs:
                reason = "; ".join(
                    f"{program}: {detail}" for program, detail in reasons.items()
                )
                append_decision(
                    run_dir,
                    stage="scope",
                    action="retain",
                    result="local_verification_only",
                    hypothesis_id=hypothesis.id,
                    reason=reason,
                    details={"bounty_programs": []},
                )
            continue
        reason = "; ".join(
            f"{program}: {detail}" for program, detail in reasons.items()
        )
        triaged.deferred.append(
            {
                "hypothesis_id": hypothesis.id,
                "reason": "no current automatic CVE submission route: " + reason,
                "hypothesis": hypothesis.model_dump(mode="json"),
            }
        )
        append_decision(
            run_dir,
            stage="scope",
            action="defer",
            result="no_eligible_program",
            hypothesis_id=hypothesis.id,
            reason=reason,
        )
    triaged.accepted = scope_eligible


def _validate_critic_accounting(
    hypotheses: HypothesesArtifact,
    triaged: TriagedArtifact,
    *,
    plugin_path: str | None = None,
) -> None:
    """Fail rather than silently losing or duplicating a critic input."""
    expected = {hypothesis.id for hypothesis in hypotheses.hypotheses}
    if triaged.plugin_slug != hypotheses.plugin_slug:
        raise ValueError(
            f"critic returned plugin_slug {triaged.plugin_slug!r}; "
            f"expected {hypotheses.plugin_slug!r}"
        )

    accepted = {hypothesis.id for hypothesis in triaged.accepted}
    rejected = {str(item.get("hypothesis_id") or "") for item in triaged.rejected}
    merged = {
        str(item.get("merged_from_id") or item.get("source_id") or "")
        for item in triaged.merged
    }
    manual = {str(item.get("hypothesis_id") or "") for item in triaged.manual_review}
    groups = {
        "accepted": accepted,
        "rejected": rejected,
        "merged": merged,
        "manual_review": manual,
    }
    if any("" in values for values in groups.values()):
        raise ValueError("critic returned a disposition without a hypothesis_id")

    seen: dict[str, str] = {}
    for disposition, values in groups.items():
        for hypothesis_id in values:
            prior = seen.setdefault(hypothesis_id, disposition)
            if prior != disposition:
                raise ValueError(
                    f"critic assigned {hypothesis_id!r} to both {prior} and {disposition}"
                )

    unknown = set(seen) - expected
    missing = expected - set(seen)
    if unknown:
        raise ValueError(f"critic returned unknown hypothesis ids: {sorted(unknown)}")
    if missing:
        raise ValueError(f"critic omitted hypothesis ids: {sorted(missing)}")

    for item in triaged.merged:
        kept_id = str(item.get("kept_id") or "")
        if not kept_id or kept_id not in accepted:
            raise ValueError(
                "critic merge must reference a kept_id present in accepted"
            )
    for item in triaged.manual_review:
        hypothesis_id = str(item.get("hypothesis_id") or "")
        payload = item.get("hypothesis")
        try:
            manual_hypothesis = Hypothesis.model_validate(payload)
        except Exception as exc:
            raise ValueError(
                f"manual-review item {hypothesis_id!r} lacks a valid hypothesis payload"
            ) from exc
        if manual_hypothesis.id != hypothesis_id:
            raise ValueError(
                f"manual-review item id {hypothesis_id!r} does not match its payload"
            )

    input_by_id = {hypothesis.id: hypothesis for hypothesis in hypotheses.hypotheses}
    repairs_by_id = {}
    for repair in triaged.source_anchor_repairs:
        if repair.hypothesis_id in repairs_by_id:
            raise ValueError(
                f"critic returned duplicate source-anchor repairs for "
                f"{repair.hypothesis_id!r}"
            )
        if repair.hypothesis_id not in accepted:
            raise ValueError(
                "critic source-anchor repair must reference an accepted hypothesis"
            )
        repairs_by_id[repair.hypothesis_id] = repair

    def _anchor(hypothesis: Hypothesis) -> SourceAnchor:
        return SourceAnchor(
            file=hypothesis.file,
            line=hypothesis.line,
            sink=hypothesis.sink,
            sink_code=hypothesis.sink_code,
        )

    for accepted_hypothesis in triaged.accepted:
        original = input_by_id[accepted_hypothesis.id]
        original_anchor = _anchor(original)
        accepted_anchor = _anchor(accepted_hypothesis)
        anchor_changed = accepted_anchor != original_anchor
        recorded_repair = repairs_by_id.get(accepted_hypothesis.id)

        if anchor_changed and recorded_repair is None:
            raise ValueError(
                f"critic changed source anchor for {accepted_hypothesis.id!r} "
                "without source_anchor_repairs audit metadata"
            )
        if not anchor_changed and recorded_repair is not None:
            raise ValueError(
                f"critic returned a source-anchor repair for unchanged hypothesis "
                f"{accepted_hypothesis.id!r}"
            )
        if recorded_repair is not None:
            if (
                recorded_repair.original != original_anchor
                or recorded_repair.corrected != accepted_anchor
            ):
                raise ValueError(
                    f"critic source-anchor repair for {accepted_hypothesis.id!r} "
                    "does not match the input and accepted hypotheses"
                )
            if not recorded_repair.reason.strip():
                raise ValueError("critic source-anchor repair lacks a reason")
            if (
                accepted_hypothesis.file != original.file
                or abs(accepted_hypothesis.line - original.line)
                > _MAX_SOURCE_ANCHOR_REPAIR_LINE_DRIFT
            ):
                raise ValueError(
                    f"critic source-anchor repair for {accepted_hypothesis.id!r} "
                    "is not a same-file local correction"
                )

            invariant_pairs = {
                "specialist": (original.specialist, accepted_hypothesis.specialist),
                "bug_class": (original.bug_class, accepted_hypothesis.bug_class),
                "entry_point": (original.entry_point, accepted_hypothesis.entry_point),
                "preconditions": (
                    original.preconditions,
                    accepted_hypothesis.preconditions,
                ),
                "affected_versions": (
                    original.affected_versions,
                    accepted_hypothesis.affected_versions,
                ),
                "attacker_role": (
                    infer_attacker_role(original),
                    infer_attacker_role(accepted_hypothesis),
                ),
                "security_outcome": (
                    original.security_outcome.model_dump(mode="json"),
                    accepted_hypothesis.security_outcome.model_dump(mode="json"),
                ),
                "source": (
                    str((original.evidence_summary or {}).get("source") or ""),
                    str(
                        (accepted_hypothesis.evidence_summary or {}).get("source") or ""
                    ),
                ),
                "control": (
                    str((original.evidence_summary or {}).get("control") or ""),
                    str(
                        (accepted_hypothesis.evidence_summary or {}).get("control")
                        or ""
                    ),
                ),
                "boundary": (
                    str((original.evidence_summary or {}).get("boundary") or ""),
                    str(
                        (accepted_hypothesis.evidence_summary or {}).get("boundary")
                        or ""
                    ),
                ),
                "impact": (
                    str((original.evidence_summary or {}).get("impact") or ""),
                    str(
                        (accepted_hypothesis.evidence_summary or {}).get("impact") or ""
                    ),
                ),
            }
            changed_claim_fields = [
                name
                for name, values in invariant_pairs.items()
                if values[0] != values[1]
            ]
            if changed_claim_fields:
                raise ValueError(
                    f"critic source-anchor repair for {accepted_hypothesis.id!r} "
                    "changed claim fields: " + ", ".join(changed_claim_fields)
                )

            if original.sink_code != accepted_hypothesis.sink_code:
                if (
                    original.taint_path
                    and accepted_hypothesis.taint_path
                    and original.taint_path[-1] == accepted_hypothesis.taint_path[-1]
                ):
                    raise ValueError(
                        f"critic source-anchor repair for {accepted_hypothesis.id!r} "
                        "left the terminal taint path unchanged"
                    )
                original_evidence_sink = str(
                    (original.evidence_summary or {}).get("sink") or ""
                )
                accepted_evidence_sink = str(
                    (accepted_hypothesis.evidence_summary or {}).get("sink") or ""
                )
                if (
                    original_evidence_sink
                    and original_evidence_sink == accepted_evidence_sink
                ):
                    raise ValueError(
                        f"critic source-anchor repair for {accepted_hypothesis.id!r} "
                        "left evidence_summary.sink unchanged"
                    )

        if plugin_path:
            citation_error = validate_exact_sink_anchor(
                Path(plugin_path),
                accepted_hypothesis.file,
                accepted_hypothesis.line,
                accepted_hypothesis.sink_code,
            )
            if citation_error:
                raise ValueError(
                    f"critic accepted {accepted_hypothesis.id!r} with an invalid "
                    f"source anchor: {citation_error}"
                )
            recipe = accepted_hypothesis.php_object_gadget_recipe
            if recipe is not None:
                recipe_error = validate_php_object_gadget_recipe_sources(
                    Path(plugin_path),
                    recipe,
                )
                if recipe_error is not None:
                    raise ValueError(
                        f"critic accepted {accepted_hypothesis.id!r} with an "
                        f"invalid PHP object gadget recipe: {recipe_error}"
                    )


def _needs_php_object_gadget_recipe_completion(hypothesis: Hypothesis) -> bool:
    """Select only reviewed CWE-502 gadget claims missing the optional recipe."""
    return (
        hypothesis.bug_class == BugClass.PHP_OBJECT_INJECTION
        and (hypothesis.evidence_summary or {}).get("usable_gadget") is True
        and hypothesis.php_object_gadget_recipe is None
    )


async def _complete_missing_php_object_gadget_recipes(
    critic: CriticAgent,
    triaged: TriagedArtifact,
    plugin_path: str,
) -> PhpObjectGadgetRecipeCompletions | None:
    """Apply one exact, source-validated completion batch to accepted candidates."""
    targets = [
        hypothesis
        for hypothesis in triaged.accepted
        if _needs_php_object_gadget_recipe_completion(hypothesis)
    ]
    if not targets:
        return None

    target_code_slices = _build_code_slices(targets, Path(plugin_path))
    result = await critic.complete_php_object_gadget_recipes(
        triaged.plugin_slug,
        targets,
        target_code_slices,
        plugin_path,
    )
    if result.plugin_slug != triaged.plugin_slug:
        raise ValueError(
            "critic recipe completion returned plugin_slug "
            f"{result.plugin_slug!r}; expected {triaged.plugin_slug!r}"
        )

    expected = {hypothesis.id for hypothesis in targets}
    completions_by_id: dict[str, PhpObjectGadgetRecipeCompletion] = {}
    for completion in result.completions:
        if completion.hypothesis_id in completions_by_id:
            raise ValueError(
                "critic recipe completion returned duplicate hypothesis id "
                f"{completion.hypothesis_id!r}"
            )
        completions_by_id[completion.hypothesis_id] = completion
    unknown = set(completions_by_id) - expected
    missing = expected - set(completions_by_id)
    if unknown:
        raise ValueError(
            "critic recipe completion returned unknown hypothesis ids: "
            f"{sorted(unknown)}"
        )
    if missing:
        raise ValueError(
            f"critic recipe completion omitted hypothesis ids: {sorted(missing)}"
        )

    incomplete = [
        completion
        for completion in result.completions
        if completion.outcome == "incomplete_source_review"
    ]
    if incomplete:
        details = "; ".join(
            f"{completion.hypothesis_id}: {completion.needed_context} "
            f"({completion.reason})"
            for completion in incomplete
        )
        raise ValueError(
            "critic recipe completion source review was incomplete: " + details
        )

    plugin_root = Path(plugin_path)
    replacements: dict[str, Hypothesis] = {}
    for target in targets:
        completion = completions_by_id[target.id]
        if completion.outcome == "unrepresentable_v1":
            continue
        if completion.outcome != "recipe_v1":
            raise RuntimeError(
                "incomplete recipe source review escaped the fail-closed gate"
            )
        recipe_error = validate_php_object_gadget_recipe_sources(
            plugin_root,
            completion.recipe,
        )
        if recipe_error is not None:
            raise ValueError(
                f"critic recipe completion for {target.id!r} failed source "
                f"validation: {recipe_error}"
            )
        payload = target.model_dump(mode="python")
        payload["php_object_gadget_recipe"] = completion.recipe
        try:
            replacements[target.id] = Hypothesis.model_validate(payload)
        except Exception as exc:
            raise ValueError(
                f"critic recipe completion for {target.id!r} produced an "
                "invalid completed hypothesis"
            ) from exc

    # Apply only after the whole response has passed ID and source accounting,
    # so one invalid completion cannot partially alter the accepted batch.
    triaged.accepted = [
        replacements.get(hypothesis.id, hypothesis) for hypothesis in triaged.accepted
    ]
    return result


def _record_php_object_gadget_recipe_completions(
    run_dir: Path,
    completions: PhpObjectGadgetRecipeCompletions,
) -> None:
    """Persist explicit recipe-v1 and unrepresentable-v1 triage decisions."""
    for completion in completions.completions:
        if completion.outcome == "recipe_v1":
            reason = completion.reason
            details: dict[str, object] = {
                "schema_version": completion.recipe.schema_version,
                "effect_binding": completion.recipe.effect_binding.kind,
            }
        elif completion.outcome == "unrepresentable_v1":
            reason = f"{completion.violated_rule}: {completion.reason}"
            details = {"violated_rule": completion.violated_rule}
        else:
            raise ValueError(
                "incomplete source review cannot be recorded as a recipe decision"
            )
        append_decision(
            run_dir,
            stage="triage",
            action="complete_php_object_gadget_recipe",
            result=completion.outcome,
            hypothesis_id=completion.hypothesis_id,
            reason=reason,
            artifact=run_dir / "triaged.json",
            details=details,
        )


async def run(
    hypotheses: HypothesesArtifact,
    plugin_path: str,
    config: PipelineConfig,
    budget: BudgetTracker,
    runtime: AgentRuntime,
    runs_root: str = "runs",
    run_id: str = "",
    enforce_submission_scope: bool = True,
) -> TriagedArtifact:
    code_slices = _build_code_slices(hypotheses.hypotheses, Path(plugin_path))

    critic = CriticAgent(runtime, model=config.models.critic)
    triaged = await critic.review(
        hypotheses,
        code_slices,
        plugin_path=plugin_path,
    )
    _validate_critic_accounting(hypotheses, triaged, plugin_path=plugin_path)
    run_dir = Path(runs_root) / run_id
    for h in triaged.accepted:
        logger.info(format_triage_accept(h))
    for rejection in triaged.rejected:
        logger.info(format_triage_reject(rejection))
    for merge in triaged.merged:
        logger.info(format_triage_merge(merge))
    for item in triaged.manual_review:
        logger.info(
            "triage: manual review %s — %s",
            item.get("hypothesis_id"),
            item.get("reason"),
        )

    for repair in triaged.source_anchor_repairs:
        append_decision(
            run_dir,
            stage="triage",
            action="repair_source_anchor",
            result="accepted",
            hypothesis_id=repair.hypothesis_id,
            reason=repair.reason,
            artifact=run_dir / "triaged.json",
            details={
                "original": repair.original.model_dump(mode="json"),
                "corrected": repair.corrected.model_dump(mode="json"),
            },
        )
    for rejection in triaged.rejected:
        append_decision(
            run_dir,
            stage="triage",
            action="reject",
            result="rejected",
            hypothesis_id=str(rejection.get("hypothesis_id") or ""),
            reason=str(rejection.get("reason") or ""),
            artifact=run_dir / "triaged.json",
        )
    for item in triaged.manual_review:
        append_decision(
            run_dir,
            stage="triage",
            action="manual_review",
            result=str(item.get("source") or "manual_review"),
            hypothesis_id=str(item.get("hypothesis_id") or ""),
            reason=str(item.get("reason") or ""),
            artifact=run_dir / "triaged.json",
        )
    for merge in triaged.merged:
        append_decision(
            run_dir,
            stage="triage",
            action="merge",
            result="merged",
            hypothesis_id=str(
                merge.get("merged_from_id")
                or merge.get("hypothesis_id")
                or merge.get("source_id")
                or ""
            ),
            reason=str(merge.get("reason") or ""),
            artifact=run_dir / "triaged.json",
            details={"merge": merge},
        )

    before = len(triaged.accepted)
    quality_path = run_dir / "quality_gate_triage.json"
    triaged = apply_quality_gate(triaged, artifact_path=quality_path)
    if quality_path.exists():
        try:
            for decision in json.loads(quality_path.read_text()):
                accepted = bool(decision.get("accepted"))
                append_decision(
                    run_dir,
                    stage="quality_gate",
                    action="accept" if accepted else "reject",
                    result="accepted" if accepted else "rejected",
                    hypothesis_id=str(decision.get("hypothesis_id") or ""),
                    reason=str(decision.get("reason") or ""),
                    artifact=quality_path,
                    details={
                        "rules": decision.get("rules") or [],
                        "warnings": decision.get("warnings") or [],
                        "severity": decision.get("severity") or {},
                    },
                )
        except Exception as exc:
            logger.warning(
                "triage: failed to mirror quality gate decisions into ledger: %s", exc
            )
    logger.info("triage: quality gate accepted %d/%d", len(triaged.accepted), before)

    _apply_submission_scope(
        triaged,
        run_dir,
        enforce_submission_scope=enforce_submission_scope,
    )

    # Apply the sandbox budget only after source/evidence validation. Ranking is
    # based on demonstrated role reachability and CIA outcome, not model
    # confidence alone.
    cap = config.max_hypotheses_to_verify
    accepted_sorted = sorted(triaged.accepted, key=rank_hypothesis)
    if len(accepted_sorted) > cap:
        logger.info(
            "triage: selected %d/%d source-valid candidates for verification; deferred=%d",
            cap,
            len(accepted_sorted),
            len(accepted_sorted) - cap,
        )
        for hypothesis in accepted_sorted[cap:]:
            triaged.deferred.append(
                {
                    "hypothesis_id": hypothesis.id,
                    "reason": f"verification budget cap {cap}; ranked below selected candidates",
                    "hypothesis": hypothesis.model_dump(mode="json"),
                }
            )
            append_decision(
                run_dir,
                stage="triage",
                action="defer",
                result="verification_budget_cap",
                hypothesis_id=hypothesis.id,
                reason=f"max_hypotheses_to_verify cap {cap}",
            )
    triaged.accepted = accepted_sorted[:cap]

    recipe_completions = await _complete_missing_php_object_gadget_recipes(
        critic,
        triaged,
        plugin_path,
    )
    if recipe_completions is not None:
        _record_php_object_gadget_recipe_completions(run_dir, recipe_completions)

    for hypothesis in triaged.accepted:
        append_decision(
            run_dir,
            stage="triage",
            action="accept",
            result="selected_for_verification",
            hypothesis_id=hypothesis.id,
            artifact=run_dir / "triaged.json",
        )

    out_path = Path(runs_root) / run_id / "triaged.jsonl"
    atomic_write_jsonl(out_path, triaged.accepted)
    # Also write the full TriagedArtifact for posterity.
    triaged.to_json_file(str(out_path.with_suffix(".json")))
    logger.info(
        "triage: accepted=%d rejected=%d merged=%d deferred=%d -> %s",
        len(triaged.accepted),
        len(triaged.rejected),
        len(triaged.merged),
        len(triaged.deferred),
        out_path,
    )
    return triaged
