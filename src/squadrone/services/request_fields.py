"""Fail-closed extraction of source-reviewed HTTP request fields."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

_PHP_REQUEST_PARAMETER_RE = re.compile(
    r"\$_(?P<source>GET|POST|REQUEST)\s*\[\s*(?P<quote>['\"])"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_.:-]{0,127})(?P=quote)\s*\]",
)
_DESCRIBED_REQUEST_PARAMETER_RE = re.compile(
    r"\b(?P<name>[A-Za-z_][A-Za-z0-9_.:-]{0,127})\s+"
    r"(?P<location>query|string|form|body|json|request|url)\s+parameter\b",
    re.IGNORECASE,
)
_CANONICAL_WIRE_FIELD_RE = re.compile(
    r"\b(?:(?:GET|POST|PUT|PATCH)\s+)?"
    r"(?P<location>query|form|json)\s+(?:parameter|field)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_.:-]{0,127})\b",
    re.IGNORECASE,
)
_DESCRIBED_NON_FIELD_NAMES = frozenset(
    {
        "a",
        "an",
        "delete",
        "get",
        "head",
        "options",
        "patch",
        "post",
        "put",
        "the",
    }
)
_CANONICAL_NON_FIELD_NAMES = frozenset(
    {
        "a",
        "an",
        "and",
        "at",
        "for",
        "from",
        "in",
        "of",
        "on",
        "or",
        "the",
        "to",
        "via",
        "with",
    }
)

_PHP_SUPERGLOBAL_CHAIN_RE = re.compile(
    r"\$_(?P<source>GET|POST|REQUEST|COOKIE|FILES|SERVER)\s*"
    r"(?P<indices>\[\s*(?:'[A-Za-z_][A-Za-z0-9_.:%\[\]-]{0,127}'|"
    r'"[A-Za-z_][A-Za-z0-9_.:%\[\]-]{0,127}")\s*\]'
    r"(?:(?:\s|/\*[^*]*\*/)*\[\s*(?:'"
    r"[A-Za-z_][A-Za-z0-9_.:%\[\]-]{0,127}'|"
    r'"[A-Za-z_][A-Za-z0-9_.:%\[\]-]{0,127}")\s*\])*)',
)
_PHP_INDEX_RE = re.compile(
    r"\[\s*(?P<quote>['\"])(?P<name>[A-Za-z_][A-Za-z0-9_.:%\[\]-]{0,127})"
    r"(?P=quote)\s*\]"
)
_HEADER_FIELD_RE = re.compile(
    r"\b(?:request\s+|HTTP\s+)?header\s+"
    r"(?:(?:parameter|field)\s+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_.:-]{0,127})\b",
    re.IGNORECASE,
)
_COOKIE_FIELD_RE = re.compile(
    r"\bcookie\s+(?:(?:parameter|field)\s+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_.:-]{0,127})\b",
    re.IGNORECASE,
)
_PATH_FIELD_RE = re.compile(
    r"\bpath\s+(?:parameter|field)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_.:-]{0,127})\b",
    re.IGNORECASE,
)
_MULTIPART_FIELD_RE = re.compile(
    r"\bmultipart(?:\s+(?:file|form))?\s+field\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_.:-]{0,127})\b",
    re.IGNORECASE,
)
_NESTED_FIELD_RE = re.compile(
    r"\bnested(?:\s+(?P<location>query|form|json))?\s+"
    r"(?:parameter|field)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_.:-]{0,127})\b",
    re.IGNORECASE,
)
_RAW_BODY_RE = re.compile(
    r"\b(?:unnamed\s+)?raw(?:\s+request)?\s+body\b|php://input",
    re.IGNORECASE,
)
_RAW_BODY_FIELD_RE = re.compile(
    r"\braw(?:\s+request)?\s+body\s+(?:parameter|field)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_.:-]{0,127})\b",
    re.IGNORECASE,
)
_XML_BODY_RE = re.compile(
    r"\b(?:unnamed\s+)?XML(?:\s+request)?\s+body\b",
    re.IGNORECASE,
)
_XML_BODY_FIELD_RE = re.compile(
    r"\bXML(?:\s+request)?\s+body\s+(?:parameter|field)\s+"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_.:-]{0,127})\b",
    re.IGNORECASE,
)
_ALTERNATIVE_LOCATION_RE = re.compile(
    r"\b(?:query|form|json|header|cookie|path|multipart|raw|XML)\b"
    r"\s*(?:/|\bor\b)\s*"
    r"\b(?:query|form|json|header|cookie|path|multipart|raw|XML)\b",
    re.IGNORECASE,
)

RequestFieldDisposition = Literal["supported", "unsupported", "invalid"]


@dataclass(frozen=True, slots=True)
class RequestFieldClassification:
    """One exact source field classified at the automatic-verifier boundary."""

    disposition: RequestFieldDisposition
    name: str = ""
    location: str = ""
    encoding: str = ""
    reason: str = ""
    top_level_name: str = ""


@dataclass(frozen=True, slots=True)
class _FieldCandidate:
    disposition: Literal["supported", "unsupported", "invalid"]
    name: str
    location: str
    encoding: str
    top_level_name: str

    def identity(self) -> tuple[str, str, str, str]:
        name = self.name.casefold() if self.encoding == "header" else self.name
        return self.disposition, self.encoding, self.location, name


def _unsupported_candidate(
    encoding: str,
    name: str = "",
    *,
    location: str = "",
    top_level_name: str = "",
) -> _FieldCandidate:
    return _FieldCandidate(
        disposition="unsupported",
        name=name,
        location=location,
        encoding=encoding,
        top_level_name=top_level_name or name,
    )


def _nested_top_level_name(name: str) -> str:
    return re.split(r"\.|\[|%5b", name, maxsplit=1, flags=re.IGNORECASE)[0]


def classify_request_field_source(source: object) -> RequestFieldClassification:
    """Classify one exact cited wire source without guessing from prose.

    Only top-level query, form, and JSON fields are automatically supported.
    A single exact unsupported encoding remains distinguishable from missing,
    ambiguous, or location-indeterminate evidence so callers can route it to
    manual review without salvaging malformed hypotheses.
    """
    if not isinstance(source, str) or not source.strip():
        return RequestFieldClassification("invalid", reason="missing")
    value = source.strip()
    if _ALTERNATIVE_LOCATION_RE.search(value):
        return RequestFieldClassification("invalid", reason="ambiguous")

    candidates: list[_FieldCandidate] = []
    for match in _PHP_SUPERGLOBAL_CHAIN_RE.finditer(value):
        source_name = match.group("source")
        names = [item.group("name") for item in _PHP_INDEX_RE.finditer(match.group("indices"))]
        if not names:
            continue
        top_level_name = names[0]
        if source_name == "REQUEST":
            candidates.append(
                _FieldCandidate(
                    "invalid",
                    ".".join(names),
                    "",
                    "request",
                    top_level_name,
                )
            )
        elif source_name in {"GET", "POST"}:
            location = "query" if source_name == "GET" else "form"
            encoded_name = top_level_name.casefold()
            if (
                len(names) == 1
                and "." not in top_level_name
                and "[" not in top_level_name
                and "%5b" not in encoded_name
            ):
                candidates.append(
                    _FieldCandidate(
                        "supported",
                        top_level_name,
                        location,
                        location,
                        top_level_name,
                    )
                )
            else:
                candidates.append(
                    _unsupported_candidate(
                        "nested",
                        ".".join(names),
                        location=location,
                        top_level_name=_nested_top_level_name(top_level_name),
                    )
                )
        elif source_name == "COOKIE":
            candidates.append(_unsupported_candidate("cookie", ".".join(names)))
        elif source_name == "FILES":
            candidates.append(
                _unsupported_candidate(
                    "multipart",
                    top_level_name,
                    location="form",
                    top_level_name=top_level_name,
                )
            )
        elif source_name == "SERVER" and top_level_name.startswith("HTTP_"):
            header_name = top_level_name.removeprefix("HTTP_").replace("_", "-")
            candidates.append(_unsupported_candidate("header", header_name))
        else:
            candidates.append(
                _FieldCandidate(
                    "invalid",
                    ".".join(names),
                    "",
                    "server",
                    top_level_name,
                )
            )

    raw_body_field_matches = list(_RAW_BODY_FIELD_RE.finditer(value))
    xml_body_field_matches = list(_XML_BODY_FIELD_RE.finditer(value))
    body_field_matches = [*raw_body_field_matches, *xml_body_field_matches]
    described_matches = [
        match
        for match in _DESCRIBED_REQUEST_PARAMETER_RE.finditer(value)
        if match.group("name").casefold() not in _DESCRIBED_NON_FIELD_NAMES
        and not any(
            body.start() <= match.start() < body.end()
            for body in body_field_matches
        )
    ]
    for match in described_matches:
        raw_location = match.group("location").lower()
        location = {
            "query": "query",
            "form": "form",
            "json": "json",
        }.get(raw_location, "")
        name = match.group("name")
        if "." in name:
            candidates.append(
                _unsupported_candidate(
                    "nested",
                    name,
                    location=location,
                    top_level_name=name.split(".", 1)[0],
                )
            )
        elif raw_location == "body":
            candidates.append(_unsupported_candidate("raw", name))
        elif raw_location == "url":
            candidates.append(_unsupported_candidate("path", name))
        else:
            candidates.append(
                _FieldCandidate(
                    "supported" if location else "invalid",
                    name,
                    location,
                    location or "request",
                    name,
                )
            )
    unsupported_field_matches = [
        *list(_MULTIPART_FIELD_RE.finditer(value)),
        *list(_NESTED_FIELD_RE.finditer(value)),
    ]
    for match in _CANONICAL_WIRE_FIELD_RE.finditer(value):
        if match.group("name").casefold() in _CANONICAL_NON_FIELD_NAMES:
            continue
        if any(
            described.start() <= match.start() < described.end()
            for described in described_matches
        ):
            continue
        if any(
            unsupported.start() <= match.start() < unsupported.end()
            for unsupported in unsupported_field_matches
        ):
            continue
        location = match.group("location").lower()
        name = match.group("name")
        suffix = value[match.end() :]
        if "." in name or re.match(r"\s*(?:\[|%5b)", suffix, re.IGNORECASE):
            candidates.append(
                _unsupported_candidate(
                    "nested",
                    name,
                    location=location,
                    top_level_name=name.split(".", 1)[0],
                )
            )
        else:
            candidates.append(
                _FieldCandidate(
                    "supported",
                    name,
                    location,
                    location,
                    name,
                )
            )

    for pattern, encoding in (
        (_HEADER_FIELD_RE, "header"),
        (_COOKIE_FIELD_RE, "cookie"),
        (_PATH_FIELD_RE, "path"),
        (_MULTIPART_FIELD_RE, "multipart"),
    ):
        for match in pattern.finditer(value):
            location = "form" if encoding == "multipart" else ""
            candidates.append(
                _unsupported_candidate(
                    encoding,
                    match.group("name"),
                    location=location,
                )
            )
    for match in _NESTED_FIELD_RE.finditer(value):
        location = str(match.group("location") or "").lower()
        candidates.append(
            _unsupported_candidate(
                "nested",
                match.group("name"),
                location=location,
            )
        )
    for match in raw_body_field_matches:
        candidates.append(_unsupported_candidate("raw", match.group("name")))
    for match in xml_body_field_matches:
        candidates.append(_unsupported_candidate("xml", match.group("name")))
    if _RAW_BODY_RE.search(value) and not raw_body_field_matches:
        candidates.append(_unsupported_candidate("raw"))
    if _XML_BODY_RE.search(value) and not xml_body_field_matches:
        candidates.append(_unsupported_candidate("xml"))

    nested_candidates = [
        candidate for candidate in candidates if candidate.encoding == "nested"
    ]
    if nested_candidates:
        candidates = [
            candidate
            for candidate in candidates
            if not (
                candidate.disposition == "supported"
                and any(
                    nested.top_level_name == candidate.name
                    and (
                        not nested.location
                        or nested.location == candidate.location
                    )
                    for nested in nested_candidates
                )
            )
        ]

    unique: dict[tuple[str, str, str, str], _FieldCandidate] = {}
    for candidate in candidates:
        # Prefer the first (most structural) representation. For example, a
        # PHP nested-chain citation may be followed by an equivalent prose
        # label; the chain retains the exact top-level dispatch key.
        unique.setdefault(candidate.identity(), candidate)
    if not unique:
        return RequestFieldClassification("invalid", reason="missing")
    if any(candidate.disposition == "invalid" for candidate in unique.values()):
        return RequestFieldClassification("invalid", reason="ambiguous")
    if len(unique) != 1:
        return RequestFieldClassification("invalid", reason="ambiguous")
    candidate = next(iter(unique.values()))
    return RequestFieldClassification(
        disposition=candidate.disposition,
        name=candidate.name,
        location=candidate.location,
        encoding=candidate.encoding,
        top_level_name=candidate.top_level_name,
    )


def _candidates(value: str) -> set[tuple[str, str]] | None:
    found: set[tuple[str, str]] = set()
    for match in _PHP_REQUEST_PARAMETER_RE.finditer(value):
        # A nested aggregate does not identify one scalar wire field.  Do not
        # silently reinterpret its outer key as that field.
        if re.match(r"\s*\[", value[match.end() :]):
            return None
        source = match.group("source").upper()
        location = {"GET": "query", "POST": "form"}.get(source, "")
        found.add((match.group("name"), location))
    described_matches = [
        match
        for match in _DESCRIBED_REQUEST_PARAMETER_RE.finditer(value)
        if match.group("name").casefold() not in _DESCRIBED_NON_FIELD_NAMES
    ]
    for match in described_matches:
        raw_location = match.group("location").lower()
        location = {
            "query": "query",
            "string": "query",
            "url": "query",
            "form": "form",
            "body": "form",
            "json": "json",
        }.get(raw_location, "")
        found.add((match.group("name"), location))
    # Retain both source grammars while preventing the location-first pattern
    # from starting inside a valid name-first phrase and reinterpreting its
    # following prose (for example, ``parameter on the route``) as a field.
    for match in _CANONICAL_WIRE_FIELD_RE.finditer(value):
        if match.group("name").casefold() in _CANONICAL_NON_FIELD_NAMES:
            continue
        if any(
            described.start() <= match.start() < described.end()
            for described in described_matches
        ):
            continue
        found.add((match.group("name"), match.group("location").lower()))
    return found


def _resolve(found: set[tuple[str, str]]) -> tuple[str, str]:
    names = {name for name, _ in found}
    if len(names) != 1:
        return "", ""
    name = next(iter(names))
    exact_locations = {location for _, location in found if location}
    if len(exact_locations) > 1:
        return "", ""
    return name, next(iter(exact_locations), "")


def explicit_request_field(
    source: str,
    taint_path: Iterable[str],
    sink_code: str,
) -> tuple[str, str]:
    """Return one cited field/location pair, or empty values on ambiguity."""
    classified = classify_request_field_source(source)
    if classified.disposition == "supported":
        return classified.name, classified.location
    if classified.disposition == "unsupported" or classified.reason == "ambiguous":
        # An explicit but unsupported/ambiguous source must never be silently
        # replaced by a convenient supported field found later in the taint
        # path or sink text.
        return "", ""
    source_candidates = _candidates(str(source or ""))
    if source_candidates is None:
        return "", ""
    if source_candidates:
        return _resolve(source_candidates)

    fallback_candidates: set[tuple[str, str]] = set()
    for value in [*[str(item) for item in taint_path], str(sink_code or "")]:
        candidates = _candidates(value)
        if candidates is None:
            return "", ""
        fallback_candidates.update(candidates)
    return _resolve(fallback_candidates)
