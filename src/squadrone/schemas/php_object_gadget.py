"""Strict, source-reviewed recipes for bounded PHP object gadget proofs.

These models describe data for a parent-owned serializer.  They deliberately do
not accept serialized bytes, arbitrary filesystem paths, callbacks, references,
or nested PHP objects.
"""

from __future__ import annotations

import re
from typing import Annotated, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)


_PHP_IDENTIFIER = re.compile(r"\A[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*\Z")
_PHP_CLASS_NAME = re.compile(
    r"\A\\?[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*"
    r"(?:\\[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*)*\Z"
)
_PHP_HELPER_SYMBOL = re.compile(
    r"\A(?:\\?[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*"
    r"(?:\\[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*)*::)?"
    r"[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*\Z"
)
_URI_SCHEME = re.compile(r"\A[A-Za-z][A-Za-z0-9+.-]*:")
_SERIALIZED_FRAGMENT = re.compile(
    r"(?:\A|[;{}])(?:O|C|R|r|a|s|i|b|d):(?:[0-9]+:)?",
    re.IGNORECASE,
)
_ENCODED_PATH_OR_NUL = re.compile(r"%(?:00|2f|5c)", re.IGNORECASE)
_UNLINK_CALL = re.compile(r"(?<![A-Za-z0-9_])@?\\?unlink\s*\(", re.IGNORECASE)
_CALLABLE_SHAPE = re.compile(r"(?:->|::|\([^)]*\)|\[[^]]*\])")
_MAX_SIGNED_INTEGER = (1 << 63) - 1
_MIN_SIGNED_INTEGER = -(1 << 63)
_MAX_VALUE_DEPTH = 4
_MAX_VALUE_NODES = 64
_MAX_TOTAL_ANCHOR_BYTES = 128 * 1024

_DANGEROUS_CALLABLE_LITERALS = frozenset(
    {
        "assert",
        "call_user_func",
        "call_user_func_array",
        "copy",
        "curl_exec",
        "eval",
        "exec",
        "file_put_contents",
        "fopen",
        "fwrite",
        "include",
        "include_once",
        "passthru",
        "popen",
        "proc_open",
        "rename",
        "require",
        "require_once",
        "shell_exec",
        "system",
        "unlink",
    }
)


def normalize_php_contract_source(source: str) -> str:
    """Remove PHP comments and insignificant whitespace, preserving strings."""
    if not isinstance(source, str):
        raise TypeError("PHP contract source must be a string")
    output: list[str] = []
    index = 0
    state: Literal["code", "single", "double", "line", "block"] = "code"
    while index < len(source):
        character = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "code":
            if character == "'":
                state = "single"
                output.append(character)
            elif character == '"':
                state = "double"
                output.append(character)
            elif character == "/" and following == "/":
                state = "line"
                index += 1
            elif character == "#":
                state = "line"
            elif character == "/" and following == "*":
                state = "block"
                index += 1
            else:
                output.append(character)
        elif state in {"single", "double"}:
            output.append(character)
            if character == "\\" and index + 1 < len(source):
                index += 1
                output.append(source[index])
            elif (state == "single" and character == "'") or (
                state == "double" and character == '"'
            ):
                state = "code"
        elif state == "line":
            if character in {"\r", "\n"}:
                output.append(character)
                state = "code"
        elif character == "*" and following == "/":
            state = "code"
            index += 1
        elif character in {"\r", "\n"}:
            output.append(character)
        index += 1
    if state in {"single", "double", "block"}:
        raise ValueError("PHP contract source contains an unterminated token")
    return re.sub(r"\s+", "", "".join(output))


def _validate_php_identifier(value: str, *, field_name: str) -> str:
    if len(value.encode("utf-8")) > 128 or not _PHP_IDENTIFIER.fullmatch(value):
        raise ValueError(f"{field_name} must be one bounded PHP identifier")
    return value


def _validate_php_class_name(value: str, *, field_name: str) -> str:
    if len(value.encode("utf-8")) > 512 or not _PHP_CLASS_NAME.fullmatch(value):
        raise ValueError(f"{field_name} must be one bounded PHP class name")
    return value.lstrip("\\")


def _validate_safe_literal(value: str, *, field_name: str, max_bytes: int) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) > max_bytes:
        raise ValueError(f"{field_name} exceeds {max_bytes} UTF-8 bytes")
    if any(ord(character) < 0x20 or ord(character) > 0x7E for character in value):
        raise ValueError(f"{field_name} must contain printable ASCII only")
    if "/" in value or "\\" in value or ".." in value:
        raise ValueError(f"{field_name} must not contain a filesystem path")
    if _URI_SCHEME.match(value) or _ENCODED_PATH_OR_NUL.search(value):
        raise ValueError(f"{field_name} must not contain an encoded path or URI")
    if _SERIALIZED_FRAGMENT.search(value):
        raise ValueError(f"{field_name} must not contain serialized PHP bytes")
    if _CALLABLE_SHAPE.search(value):
        raise ValueError(f"{field_name} must not contain a callback")
    if value.strip().lower() in _DANGEROUS_CALLABLE_LITERALS:
        raise ValueError(f"{field_name} must not name an executable callback")
    return value


def _valid_local_path_exists_source(symbol: str, source: str) -> bool:
    if "::" not in symbol:
        return False
    class_name, method = symbol.rsplit("::", 1)
    namespace = class_name.rpartition("\\")[0]
    try:
        compact = normalize_php_contract_source(source)
    except (TypeError, ValueError):
        return False
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
    return contract.fullmatch(compact) is not None


class _StrictGadgetModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PhpObjectGadgetSourceAnchor(_StrictGadgetModel):
    """An exact shipped-plugin source quote beginning at ``line``."""

    file: StrictStr
    line: Annotated[StrictInt, Field(ge=1, le=10_000_000)]
    source_code: StrictStr = Field(min_length=1)

    @field_validator("file")
    @classmethod
    def _validate_file(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 1024:
            raise ValueError("source anchor file is too long")
        if (
            not value
            or value.startswith("/")
            or "\\" in value
            or "\x00" in value
            or any(part in {"", ".", ".."} for part in value.split("/"))
            or not value.lower().endswith(".php")
        ):
            raise ValueError(
                "source anchor file must be a canonical plugin-relative PHP path"
            )
        if not value.isascii():
            raise ValueError("source anchor file must contain ASCII characters only")
        return value

    @field_validator("source_code")
    @classmethod
    def _validate_source_code(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("source anchor code must not contain NUL bytes")
        if len(value.encode("utf-8")) > 32 * 1024:
            raise ValueError("one source anchor cannot exceed 32 KiB")
        if not value.strip():
            raise ValueError("source anchor code must not be blank")
        return value


class PhpObjectGadgetMapEntry(_StrictGadgetModel):
    key: StrictInt | StrictStr
    value: "PhpObjectGadgetValue"

    @field_validator("key")
    @classmethod
    def _validate_key(cls, value: int | str) -> int | str:
        if isinstance(value, int):
            if not _MIN_SIGNED_INTEGER <= value <= _MAX_SIGNED_INTEGER:
                raise ValueError("map integer key is outside the signed 64-bit range")
            return value
        return _validate_safe_literal(value, field_name="map key", max_bytes=128)


class PhpObjectGadgetValue(_StrictGadgetModel):
    """One bounded value consumed by the trusted parent serializer."""

    kind: Literal[
        "null",
        "boolean",
        "integer",
        "string",
        "list",
        "map",
        "capability",
        "opaque_generation_id",
    ]
    value: StrictBool | StrictInt | StrictStr | None = None
    items: tuple["PhpObjectGadgetValue", ...] = Field(default=(), max_length=16)
    entries: tuple[PhpObjectGadgetMapEntry, ...] = Field(default=(), max_length=16)
    capability: Literal["ephemeral_file_path"] | None = None

    @model_validator(mode="after")
    def _validate_shape(self) -> Self:
        scalar_empty = self.value is None
        collections_empty = not self.items and not self.entries

        if self.kind == "null":
            if not scalar_empty or not collections_empty or self.capability is not None:
                raise ValueError("null gadget values cannot carry data")
        elif self.kind == "boolean":
            if (
                not isinstance(self.value, bool)
                or not collections_empty
                or self.capability is not None
            ):
                raise ValueError("boolean gadget values require one strict boolean")
        elif self.kind == "integer":
            if (
                not isinstance(self.value, int)
                or isinstance(self.value, bool)
                or not _MIN_SIGNED_INTEGER <= self.value <= _MAX_SIGNED_INTEGER
                or not collections_empty
                or self.capability is not None
            ):
                raise ValueError(
                    "integer gadget values require one signed 64-bit integer"
                )
        elif self.kind == "string":
            if (
                not isinstance(self.value, str)
                or not collections_empty
                or self.capability is not None
            ):
                raise ValueError("string gadget values require one bounded string")
            _validate_safe_literal(
                self.value,
                field_name="gadget string value",
                max_bytes=512,
            )
        elif self.kind == "list":
            if not scalar_empty or self.entries or self.capability is not None:
                raise ValueError("list gadget values may contain only items")
        elif self.kind == "map":
            if not scalar_empty or self.items or self.capability is not None:
                raise ValueError("map gadget values may contain only entries")
            seen: set[tuple[str, int | str]] = set()
            for entry in self.entries:
                key: tuple[str, int | str]
                if isinstance(entry.key, int):
                    key = ("integer", entry.key)
                elif re.fullmatch(r"-?(?:0|[1-9][0-9]*)", entry.key):
                    key = ("integer", int(entry.key))
                else:
                    key = ("string", entry.key)
                if key in seen:
                    raise ValueError(
                        "map gadget values cannot contain duplicate PHP keys"
                    )
                seen.add(key)
        elif self.kind == "capability":
            if (
                not scalar_empty
                or not collections_empty
                or self.capability != "ephemeral_file_path"
            ):
                raise ValueError(
                    "capability gadget values require only ephemeral_file_path"
                )
        elif not scalar_empty or not collections_empty or self.capability is not None:
            raise ValueError("opaque_generation_id cannot carry model-authored data")
        return self


PhpObjectGadgetValue.model_rebuild()


class PhpObjectGadgetProperty(_StrictGadgetModel):
    name: StrictStr
    declaring_class: StrictStr
    visibility: Literal["public", "protected", "private"]
    value: PhpObjectGadgetValue

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        return _validate_php_identifier(value, field_name="property name")

    @field_validator("declaring_class")
    @classmethod
    def _validate_declaring_class(cls, value: str) -> str:
        return _validate_php_class_name(value, field_name="property declaring_class")


class PhpObjectGadgetHelperAnchor(_StrictGadgetModel):
    symbol: StrictStr
    anchor: PhpObjectGadgetSourceAnchor
    contract: Literal["reviewed", "local_path_exists"] = "reviewed"

    @field_validator("symbol")
    @classmethod
    def _validate_symbol(cls, value: str) -> str:
        if len(value.encode("utf-8")) > 640 or not _PHP_HELPER_SYMBOL.fullmatch(value):
            raise ValueError("helper symbol must be a bounded PHP function or method")
        return value.lstrip("\\")

    @model_validator(mode="after")
    def _validate_declaration_quote(self) -> Self:
        method = self.symbol.rsplit("::", 1)[-1]
        declaration = re.compile(
            rf"\bfunction\s*&?\s*{re.escape(method)}\s*\(",
            re.IGNORECASE,
        )
        if not declaration.search(self.anchor.source_code):
            raise ValueError("helper anchor must quote the declared helper body")
        if self.contract == "local_path_exists" and not _valid_local_path_exists_source(
            self.symbol,
            self.anchor.source_code,
        ):
            raise ValueError(
                "local_path_exists must exactly reject schemes before its final "
                "same-parameter local file_exists branch"
            )
        return self


class PhpObjectGadgetGuardedEffectAnchor(_StrictGadgetModel):
    """An additional unlink constrained by a parent-generated identifier."""

    anchor: PhpObjectGadgetSourceAnchor
    guard_anchor: PhpObjectGadgetSourceAnchor
    guard_property: StrictStr
    directory_constant: StrictStr
    basename_prefix: StrictStr
    basename_suffix: StrictStr

    @field_validator("guard_property")
    @classmethod
    def _validate_guard_property(cls, value: str) -> str:
        return _validate_php_identifier(value, field_name="guard property")

    @field_validator("directory_constant")
    @classmethod
    def _validate_directory_constant(cls, value: str) -> str:
        if len(value) > 128 or not re.fullmatch(r"[A-Z_][A-Z0-9_]*", value):
            raise ValueError("directory_constant must be one bounded PHP constant")
        return value

    @field_validator("basename_prefix", "basename_suffix")
    @classmethod
    def _validate_basename_fragment(cls, value: str) -> str:
        if (
            not 1 <= len(value) <= 64
            or not value.isascii()
            or not re.fullmatch(r"[A-Za-z0-9_.-]+", value)
            or ".." in value
            or "*" in value
            or "?" in value
        ):
            raise ValueError("guarded basename fragments must be bounded literals")
        return value


class PhpObjectGadgetObject(_StrictGadgetModel):
    class_name: StrictStr
    class_anchor: PhpObjectGadgetSourceAnchor
    trigger: Literal["__wakeup", "__destruct"]
    trigger_declaring_class: StrictStr
    trigger_anchor: PhpObjectGadgetSourceAnchor
    properties: tuple[PhpObjectGadgetProperty, ...] = Field(
        min_length=1,
        max_length=32,
    )

    @field_validator("class_name")
    @classmethod
    def _validate_class_name(cls, value: str) -> str:
        return _validate_php_class_name(value, field_name="gadget class_name")

    @field_validator("trigger_declaring_class")
    @classmethod
    def _validate_trigger_declaring_class(cls, value: str) -> str:
        return _validate_php_class_name(value, field_name="trigger declaring class")

    @model_validator(mode="after")
    def _validate_source_and_properties(self) -> Self:
        if self.trigger_declaring_class.lower() != self.class_name.lower():
            raise ValueError(
                "gadget recipe v1 requires the trigger on the serialized class"
            )
        short_class = self.class_name.rsplit("\\", 1)[-1]
        declaration = re.compile(
            rf"\bclass\s+{re.escape(short_class)}\b",
            re.IGNORECASE,
        )
        if not declaration.search(self.class_anchor.source_code):
            raise ValueError("class anchor must quote the gadget class declaration")
        trigger_declaration = re.compile(
            rf"\bfunction\s*&?\s*{re.escape(self.trigger)}\s*\(",
            re.IGNORECASE,
        )
        if not trigger_declaration.search(self.trigger_anchor.source_code):
            raise ValueError("trigger anchor must quote the selected complete method")

        names: set[str] = set()
        serialized_names: set[str] = set()
        for prop in self.properties:
            if prop.name in names:
                raise ValueError("gadget properties must have unambiguous unique names")
            names.add(prop.name)
            if prop.visibility == "public":
                serialized_name = prop.name
            elif prop.visibility == "protected":
                serialized_name = f"\x00*\x00{prop.name}"
            else:
                serialized_name = f"\x00{prop.declaring_class}\x00{prop.name}"
            if serialized_name in serialized_names:
                raise ValueError("gadget properties collide after visibility encoding")
            serialized_names.add(serialized_name)
        return self


def _walk_value(
    value: PhpObjectGadgetValue,
    *,
    depth: int = 1,
) -> tuple[int, int, int]:
    if depth > _MAX_VALUE_DEPTH:
        raise ValueError(f"gadget values cannot exceed depth {_MAX_VALUE_DEPTH}")
    nodes = 1
    path_capabilities = int(
        value.kind == "capability" and value.capability == "ephemeral_file_path"
    )
    opaque_ids = int(value.kind == "opaque_generation_id")
    children = value.items or tuple(entry.value for entry in value.entries)
    for child in children:
        child_nodes, child_paths, child_ids = _walk_value(child, depth=depth + 1)
        nodes += child_nodes
        path_capabilities += child_paths
        opaque_ids += child_ids
    return nodes, path_capabilities, opaque_ids


def _source_lines(anchor: PhpObjectGadgetSourceAnchor) -> list[str]:
    return anchor.source_code.splitlines() or [anchor.source_code]


def _effect_identity(anchor: PhpObjectGadgetSourceAnchor) -> tuple[str, int, str]:
    lines = _source_lines(anchor)
    if len(lines) != 1 or len(_UNLINK_CALL.findall(lines[0])) != 1:
        raise ValueError(
            "each effect anchor must be one exact line with one unlink call"
        )
    return (anchor.file, anchor.line, lines[0].strip())


def _anchor_contains(
    parent: PhpObjectGadgetSourceAnchor,
    child: PhpObjectGadgetSourceAnchor,
) -> bool:
    if parent.file != child.file or child.line < parent.line:
        return False
    parent_lines = _source_lines(parent)
    child_lines = _source_lines(child)
    offset = child.line - parent.line
    if offset + len(child_lines) > len(parent_lines):
        return False
    return [
        line.strip() for line in parent_lines[offset : offset + len(child_lines)]
    ] == [line.strip() for line in child_lines]


def _unlink_occurrences(
    anchors: tuple[PhpObjectGadgetSourceAnchor, ...],
) -> set[tuple[str, int, str]]:
    occurrences: set[tuple[str, int, str]] = set()
    for anchor in anchors:
        for offset, line in enumerate(_source_lines(anchor)):
            count = len(_UNLINK_CALL.findall(line))
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


class PhpObjectGadgetLocalPathCheck(_StrictGadgetModel):
    """A source-bound no-scheme/local-exists guard around a direct-path sink."""

    guard_anchor: PhpObjectGadgetSourceAnchor
    directory_constant: StrictStr
    helper_symbol: StrictStr

    @field_validator("directory_constant")
    @classmethod
    def _validate_directory_constant(cls, value: str) -> str:
        if len(value) > 128 or not re.fullmatch(r"[A-Z_][A-Z0-9_]*", value):
            raise ValueError("directory_constant must be one bounded PHP constant")
        return value

    @field_validator("helper_symbol")
    @classmethod
    def _validate_helper_symbol(cls, value: str) -> str:
        if (
            len(value.encode("utf-8")) > 640
            or "::" not in value
            or not _PHP_HELPER_SYMBOL.fullmatch(value)
        ):
            raise ValueError("local path helper must be one explicit PHP class method")
        return value.lstrip("\\")


class PhpObjectGadgetDirectPathEffectBinding(_StrictGadgetModel):
    kind: Literal["direct_path"] = "direct_path"
    effect_property: StrictStr
    access: Literal["property", "list_item"]
    effect_anchor: PhpObjectGadgetSourceAnchor
    effect_variable: StrictStr | None = None
    iteration_anchor: PhpObjectGadgetSourceAnchor | None = None
    local_path_check: PhpObjectGadgetLocalPathCheck | None = None

    @field_validator("effect_property")
    @classmethod
    def _validate_effect_property(cls, value: str) -> str:
        return _validate_php_identifier(value, field_name="effect property")

    @field_validator("effect_variable")
    @classmethod
    def _validate_effect_variable(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _validate_php_identifier(value, field_name="effect variable")

    @model_validator(mode="after")
    def _validate_access_shape(self) -> Self:
        if self.access == "property":
            if self.effect_variable is not None or self.iteration_anchor is not None:
                raise ValueError("property access cannot declare an iteration variable")
        elif self.effect_variable is None or self.iteration_anchor is None:
            raise ValueError("list_item access requires variable and iteration anchor")
        if self.local_path_check is not None:
            parent = self.local_path_check.guard_anchor
            if not _anchor_contains(parent, self.effect_anchor):
                raise ValueError("local path guard must contain the direct unlink line")
            if self.iteration_anchor is not None and not _anchor_contains(
                self.iteration_anchor,
                parent,
            ):
                raise ValueError("local path guard must occur inside the iteration")
        return self


class PhpObjectGadgetGuardedOpaquePrefixEffectBinding(_StrictGadgetModel):
    """Lower-tier prefix-selected target; never proves arbitrary direct deletion."""

    kind: Literal["guarded_opaque_prefix"] = "guarded_opaque_prefix"
    effect: PhpObjectGadgetGuardedEffectAnchor


PhpObjectGadgetEffectBinding = Annotated[
    PhpObjectGadgetDirectPathEffectBinding
    | PhpObjectGadgetGuardedOpaquePrefixEffectBinding,
    Field(discriminator="kind"),
]


class PhpObjectGadgetRecipe(_StrictGadgetModel):
    """Versioned recipe for one inertly parameterized shipped PHP object."""

    schema_version: Literal[1] = 1
    effect: Literal["file_delete"] = "file_delete"
    effect_sink: Literal["unlink"] = "unlink"
    gadget_object: PhpObjectGadgetObject
    effect_binding: PhpObjectGadgetEffectBinding
    helper_anchors: tuple[PhpObjectGadgetHelperAnchor, ...] = Field(
        default=(),
        max_length=16,
    )
    guarded_effect_anchors: tuple[PhpObjectGadgetGuardedEffectAnchor, ...] = Field(
        default=(),
        max_length=16,
    )

    @field_validator("schema_version")
    @classmethod
    def _validate_schema_version(cls, value: int) -> int:
        if type(value) is not int or value != 1:
            raise ValueError("gadget recipe schema_version must be integer 1")
        return value

    @model_validator(mode="after")
    def _validate_recipe(self) -> Self:
        total_nodes = 0
        path_capabilities = 0
        opaque_ids = 0
        properties = {prop.name: prop for prop in self.gadget_object.properties}
        for prop in self.gadget_object.properties:
            nodes, paths, ids = _walk_value(prop.value)
            total_nodes += nodes
            path_capabilities += paths
            opaque_ids += ids
        if total_nodes > _MAX_VALUE_NODES:
            raise ValueError(f"gadget recipe exceeds {_MAX_VALUE_NODES} value nodes")
        primary_guarded: PhpObjectGadgetGuardedEffectAnchor | None = None
        if isinstance(self.effect_binding, PhpObjectGadgetDirectPathEffectBinding):
            if path_capabilities != 1:
                raise ValueError(
                    "direct_path recipes require exactly one ephemeral_file_path"
                )
            if opaque_ids > 1:
                raise ValueError(
                    "gadget recipe permits at most one opaque_generation_id"
                )
            effect_property = properties.get(self.effect_binding.effect_property)
            if effect_property is None:
                raise ValueError(
                    "effect_property must name one declared object property"
                )
            _, effect_paths, _ = _walk_value(effect_property.value)
            if effect_paths != 1:
                raise ValueError(
                    "effect_property must contain the sole ephemeral_file_path"
                )
            if self.effect_binding.access == "property":
                if effect_property.value.kind != "capability":
                    raise ValueError(
                        "property access requires a direct path capability"
                    )
                expected_operand = rf"\$this\s*->\s*{re.escape(effect_property.name)}"
            else:
                if (
                    effect_property.value.kind != "list"
                    or len(effect_property.value.items) != 1
                    or effect_property.value.items[0].kind != "capability"
                ):
                    raise ValueError(
                        "list_item access requires one sole path capability item"
                    )
                variable = self.effect_binding.effect_variable
                assert variable is not None
                iteration = self.effect_binding.iteration_anchor
                assert iteration is not None
                foreach = re.compile(
                    rf"\bforeach\s*\(\s*\$this\s*->\s*"
                    rf"{re.escape(effect_property.name)}\s+as\s+\$"
                    rf"{re.escape(variable)}\s*\)",
                    re.IGNORECASE,
                )
                if not foreach.search(iteration.source_code):
                    raise ValueError(
                        "iteration anchor must bind effect_property to effect_variable"
                    )
                if not _anchor_contains(iteration, self.effect_binding.effect_anchor):
                    raise ValueError("iteration anchor must contain the direct unlink")
                effect_offset = self.effect_binding.effect_anchor.line - iteration.line
                prefix_lines = _source_lines(iteration)[:effect_offset]
                if re.search(
                    rf"\${re.escape(variable)}\s*(?:=|\+=|-=|\*=|/=|\.=|\+\+|--|&)",
                    "\n".join(prefix_lines),
                ):
                    raise ValueError(
                        "direct effect variable cannot be reassigned or aliased"
                    )
                expected_operand = rf"\${re.escape(variable)}"
            direct_unlink = re.compile(
                rf"\A\s*@?\\?unlink\s*\(\s*{expected_operand}\s*\)\s*;?\s*\Z",
                re.IGNORECASE,
            )
            if not direct_unlink.fullmatch(
                self.effect_binding.effect_anchor.source_code
            ):
                raise ValueError(
                    "direct effect anchor must unlink its bound path value"
                )
            _effect_identity(self.effect_binding.effect_anchor)
        else:
            if path_capabilities != 0 or opaque_ids != 1:
                raise ValueError(
                    "guarded_opaque_prefix requires no path capability and one "
                    "opaque_generation_id"
                )
            primary_guarded = self.effect_binding.effect

        all_guarded = (
            *((primary_guarded,) if primary_guarded is not None else ()),
            *self.guarded_effect_anchors,
        )
        for guarded in all_guarded:
            guard_property = properties.get(guarded.guard_property)
            if (
                guard_property is None
                or guard_property.value.kind != "opaque_generation_id"
            ):
                raise ValueError(
                    "each guarded unlink must name the opaque_generation_id property"
                )
            guard_prefix = guarded.guard_anchor.source_code.split("{", 1)[0]
            literal_prefix = re.escape(guarded.basename_prefix)
            literal_suffix = re.escape(guarded.basename_suffix)
            variable = r"(?P<guarded_name>\$[A-Za-z_][A-Za-z0-9_]*)"
            guarded_condition = re.compile(
                rf"\A\s*if\s*\(\s*\\?strpos\s*\(\s*{variable}\s*,\s*"
                rf"(?P<q1>['\"]){literal_prefix}(?P=q1)\s*\.\s*"
                rf"\$this\s*->\s*{re.escape(guarded.guard_property)}\s*\.\s*"
                rf"(?P<q2>['\"]){literal_suffix}(?P=q2)\s*\)\s*===\s*0\s*\)\s*\Z",
                re.IGNORECASE,
            )
            guard_match = guarded_condition.fullmatch(guard_prefix.strip())
            if guard_match is None:
                raise ValueError(
                    "guard condition must exactly bind basename fragments and opaque ID"
                )
            effect_line = guarded.anchor.source_code
            guarded_unlink = re.compile(
                rf"\A\s*@?\\?unlink\s*\(\s*{re.escape(guarded.directory_constant)}"
                rf"\s*\.\s*{re.escape(guard_match.group('guarded_name'))}\s*\)\s*;?\s*\Z",
                re.IGNORECASE,
            )
            if not guarded_unlink.fullmatch(effect_line):
                raise ValueError(
                    "guarded unlink must join its bound directory and guarded basename"
                )
            if not _anchor_contains(guarded.guard_anchor, guarded.anchor):
                raise ValueError("guard anchor must contain its classified unlink line")
        if all_guarded and opaque_ids != 1:
            raise ValueError("guarded unlinks require one opaque_generation_id")

        if isinstance(self.effect_binding, PhpObjectGadgetDirectPathEffectBinding):
            local_path_check = self.effect_binding.local_path_check
            if local_path_check is not None:
                matching_helper = [
                    helper
                    for helper in self.helper_anchors
                    if helper.symbol.lower() == local_path_check.helper_symbol.lower()
                ]
                if len(matching_helper) != 1 or matching_helper[0].contract != (
                    "local_path_exists"
                ):
                    raise ValueError(
                        "local path check must name one local_path_exists helper"
                    )

        helper_symbols = [helper.symbol.lower() for helper in self.helper_anchors]
        if len(helper_symbols) != len(set(helper_symbols)):
            raise ValueError("helper symbols must be unique")

        all_anchors = (
            self.gadget_object.class_anchor,
            self.gadget_object.trigger_anchor,
            *(helper.anchor for helper in self.helper_anchors),
            *(
                (
                    self.effect_binding.effect_anchor,
                    *(
                        (self.effect_binding.iteration_anchor,)
                        if self.effect_binding.iteration_anchor is not None
                        else ()
                    ),
                    *(
                        (self.effect_binding.local_path_check.guard_anchor,)
                        if self.effect_binding.local_path_check is not None
                        else ()
                    ),
                )
                if isinstance(
                    self.effect_binding,
                    PhpObjectGadgetDirectPathEffectBinding,
                )
                else (
                    self.effect_binding.effect.anchor,
                    self.effect_binding.effect.guard_anchor,
                )
            ),
            *(
                nested
                for guarded in self.guarded_effect_anchors
                for nested in (guarded.anchor, guarded.guard_anchor)
            ),
        )
        if sum(len(anchor.source_code.encode("utf-8")) for anchor in all_anchors) > (
            _MAX_TOTAL_ANCHOR_BYTES
        ):
            raise ValueError("gadget recipe source anchors exceed 128 KiB")

        body_anchors = (
            self.gadget_object.trigger_anchor,
            *(helper.anchor for helper in self.helper_anchors),
        )
        if (
            isinstance(self.effect_binding, PhpObjectGadgetDirectPathEffectBinding)
            and self.effect_binding.iteration_anchor is not None
        ):
            containing_bodies = sum(
                _anchor_contains(body, self.effect_binding.iteration_anchor)
                for body in body_anchors
            )
            if containing_bodies != 1:
                raise ValueError(
                    "direct iteration must occur in exactly one reviewed helper body"
                )
        for guarded in all_guarded:
            containing_bodies = sum(
                _anchor_contains(body, guarded.guard_anchor) for body in body_anchors
            )
            if containing_bodies != 1:
                raise ValueError(
                    "each guarded source region must occur in exactly one reviewed body"
                )
        for guarded in all_guarded:
            identity = _effect_identity(guarded.anchor)
            guarded_occurrences = _unlink_occurrences((guarded.guard_anchor,))
            if guarded_occurrences != {identity}:
                raise ValueError(
                    "each guard source region must contain exactly its one unlink call"
                )
        return self


__all__ = [
    "PhpObjectGadgetGuardedEffectAnchor",
    "PhpObjectGadgetGuardedOpaquePrefixEffectBinding",
    "PhpObjectGadgetHelperAnchor",
    "PhpObjectGadgetDirectPathEffectBinding",
    "PhpObjectGadgetEffectBinding",
    "PhpObjectGadgetLocalPathCheck",
    "PhpObjectGadgetMapEntry",
    "PhpObjectGadgetObject",
    "PhpObjectGadgetProperty",
    "PhpObjectGadgetRecipe",
    "PhpObjectGadgetSourceAnchor",
    "PhpObjectGadgetValue",
    "normalize_php_contract_source",
]
