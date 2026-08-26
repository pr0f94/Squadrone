"""Hypothesis + triage artifact schemas."""

from __future__ import annotations

from enum import Enum
import json
import re
from typing import Annotated, Any, Literal

from pydantic import BeforeValidator, Field, model_validator

from ._base import JSONFileMixin
from .recon import CoverageDisposition
from .taxonomy import BugClass, get_known_cwe_profile


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


_BUG_CLASS_LABEL_ALIASES: dict[str, BugClass] = {
    "missing authorization": BugClass.MISSING_CAP_CHECK,
    "cross site request forgery": BugClass.MISSING_NONCE,
    "csrf": BugClass.MISSING_NONCE,
    "sql injection": BugClass.SQLI,
    "command injection": BugClass.COMMAND_INJECTION,
    "path traversal": BugClass.PATH_TRAVERSAL,
    "arbitrary file upload": BugClass.ARBITRARY_FILE_WRITE,
    "arbitrary file write": BugClass.ARBITRARY_FILE_WRITE,
    "unrestricted upload of file with dangerous type": BugClass.ARBITRARY_FILE_WRITE,
    "server side request forgery": BugClass.SSRF,
    "ssrf": BugClass.SSRF,
    "xml external entity injection": BugClass.XXE,
    "xxe": BugClass.XXE,
    "php object injection": BugClass.PHP_OBJECT_INJECTION,
    "reflected cross site scripting": BugClass.XSS_REFLECTED,
    "stored cross site scripting": BugClass.XSS_STORED,
    "open redirect": BugClass.OPEN_REDIRECT,
    "insecure direct object reference": BugClass.IDOR,
    "idor": BugClass.IDOR,
    "authentication bypass": BugClass.AUTH_BYPASS,
    "missing authentication": BugClass.MISSING_AUTH_CRITICAL_FUNCTION,
    "missing authentication for critical function": BugClass.MISSING_AUTH_CRITICAL_FUNCTION,
    "uncontrolled resource consumption": BugClass.RESOURCE_EXHAUSTION,
    "resource exhaustion": BugClass.RESOURCE_EXHAUSTION,
}


def _bug_class_label_key(value: str) -> str:
    return " ".join(re.sub(r"[^a-z0-9]+", " ", value.lower()).split())


def root_cause_cwe_for(bug_class: BugClass) -> str:
    profile = get_known_cwe_profile(bug_class)
    return profile.root_cwe if profile is not None else bug_class.value


ImpactLevel = Literal["none", "low", "high"]


class SecurityOutcome(JSONFileMixin):
    confidentiality: ImpactLevel = "none"
    integrity: ImpactLevel = "none"
    availability: ImpactLevel = "none"
    description: str = ""


def _coerce_str(v: Any) -> Any:
    """LLMs sometimes return arrays where we ask for a single string — coerce."""
    if isinstance(v, list):
        return "; ".join(str(_coerce_str(item)) for item in v)
    if isinstance(v, dict):
        # Preserve structured source references in a stable, readable string.
        # This accepts schema-shape drift without discarding file/line/code facts.
        kind = str(v.get("type") or "").strip()
        name_key = next(
            (
                key
                for key in ("name", "function", "method", "route", "action")
                if v.get(key) not in (None, "")
            ),
            None,
        )
        name = str(v.get(name_key) or "").strip() if name_key else ""
        descriptor = " ".join(part for part in (kind, name) if part)

        file = str(v.get("file") or "").strip()
        line = v.get("line")
        location = f"{file}:{line}" if file and line not in (None, "") else file
        code_key = next(
            (
                key
                for key in ("code", "snippet", "expression", "value")
                if v.get(key) not in (None, "")
            ),
            None,
        )
        code = str(v.get(code_key) or "").strip() if code_key else ""

        consumed = {"type", "file", "line"}
        if name_key:
            consumed.add(name_key)
        if code_key:
            consumed.add(code_key)
        extras = {
            key: value
            for key, value in v.items()
            if key not in consumed and value not in (None, "")
        }
        parts = [part for part in (descriptor, location, code) if part]
        if extras:
            parts.append(json.dumps(extras, sort_keys=True, default=str))
        return " | ".join(parts) or json.dumps(v, sort_keys=True, default=str)
    return v


def _coerce_str_list(v: Any) -> Any:
    """Accept common scalar/list drift in model-produced path fields."""
    if isinstance(v, str):
        if "->" in v:
            return [part.strip() for part in v.split("->") if part.strip()]
        return [v]
    if isinstance(v, list):
        coerced: list[str] = []
        for item in v:
            if isinstance(item, str):
                coerced.append(item)
            elif isinstance(item, dict) and isinstance(item.get("step"), str):
                coerced.append(item["step"])
            else:
                coerced.append(str(item))
        return coerced
    return v


def _coerce_lower_str(v: Any) -> Any:
    if isinstance(v, str):
        return v.lower()
    return v


_StrLike = Annotated[str, BeforeValidator(_coerce_str)]
_StrListLike = Annotated[list[str], BeforeValidator(_coerce_str_list)]
_ConfidenceLike = Annotated[Confidence, BeforeValidator(_coerce_lower_str)]


class Hypothesis(JSONFileMixin):
    id: str
    specialist: str
    bug_class: BugClass
    entry_point: _StrLike
    file: str
    line: int
    sink: _StrLike
    sink_code: _StrLike = ""  # Verbatim source line(s) of the sink when available.
    taint_path: _StrListLike
    reasoning: _StrLike
    confidence: _ConfidenceLike
    preconditions: _StrLike = ""
    affected_versions: _StrLike
    root_cause_cwe: str = ""
    vulnerability_type: str = ""
    security_outcome: SecurityOutcome = Field(default_factory=SecurityOutcome)
    # Populated by the triage stage. Empty for hypotheses produced before scope filtering ran;
    # may contain "wordfence", "patchstack", or both. Routing/report stages should respect this.
    bounty_programs: list[str] = Field(default_factory=list)
    evidence_summary: dict[str, Any] = Field(default_factory=dict)
    quality_gate: dict[str, Any] = Field(default_factory=dict)
    derived_severity: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _normalize_contract_aliases(cls, data: Any) -> Any:
        """Normalize common model key drift without replacing canonical values."""
        if not isinstance(data, dict):
            return data
        normalized = dict(data)
        for canonical, alias in (("id", "hypothesis_id"), ("specialist", "reviewer")):
            if canonical not in normalized and alias in normalized:
                normalized[canonical] = normalized[alias]
        if normalized.get("confidence") in (None, ""):
            normalized["confidence"] = Confidence.MEDIUM.value
        return normalized

    @model_validator(mode="before")
    @classmethod
    def _fill_location_from_explicit_sink(cls, data: Any) -> Any:
        """Copy omitted file/line only from an explicit sink source reference."""
        if not isinstance(data, dict) or (
            data.get("file") not in (None, "") and data.get("line") not in (None, "")
        ):
            return data

        sink = data.get("sink")
        sink_file: Any = None
        sink_line: Any = None
        if isinstance(sink, dict):
            sink_file = sink.get("file")
            sink_line = sink.get("line")
        elif isinstance(sink, str):
            match = re.search(
                r"(?P<file>[A-Za-z0-9_./\\-]+\.[A-Za-z0-9]+):"
                r"(?P<line>[1-9][0-9]*)",
                sink,
            )
            if match:
                sink_file = match.group("file")
                sink_line = int(match.group("line"))

        normalized = dict(data)
        if normalized.get("file") in (None, "") and isinstance(sink_file, str):
            normalized["file"] = sink_file
        if normalized.get("line") in (None, "") and sink_line not in (None, ""):
            normalized["line"] = sink_line
        return normalized

    @model_validator(mode="before")
    @classmethod
    def _normalize_bug_class(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        exact_values = {bug_class.value for bug_class in BugClass}
        # Model responses often pair a descriptive bug_class with an exact
        # auxiliary `cwe`. Prefer an already-valid bug_class, then normalize
        # either representation without accepting unknown taxonomy values.
        for raw_candidate in (data.get("bug_class"), data.get("cwe")):
            if not isinstance(raw_candidate, str):
                continue
            candidate = raw_candidate.strip()
            if candidate in exact_values:
                if candidate == data.get("bug_class"):
                    return data
                normalized = dict(data)
                normalized["bug_class"] = candidate
                return normalized

            root_match = re.fullmatch(
                r"(CWE-[1-9][0-9]*)(?:\s*:\s*.+)?",
                candidate,
                re.IGNORECASE,
            )
            root = root_match.group(1).upper() if root_match else ""
            if root == "CWE-79":
                text = " ".join(
                    str(data.get(key) or "")
                    for key in (
                        "bug_class",
                        "cwe",
                        "title",
                        "specialist",
                        "reasoning",
                        "sink",
                        "preconditions",
                        "vulnerability_type",
                    )
                ).lower()
                normalized = dict(data)
                normalized["bug_class"] = (
                    BugClass.XSS_STORED.value
                    if "stored" in text
                    else BugClass.XSS_REFLECTED.value
                )
                return normalized
            if root:
                normalized = dict(data)
                normalized["bug_class"] = root
                return normalized

            alias = _BUG_CLASS_LABEL_ALIASES.get(_bug_class_label_key(candidate))
            if alias is not None:
                normalized = dict(data)
                normalized["bug_class"] = alias.value
                return normalized
        return data

    @model_validator(mode="after")
    def _fill_taxonomy(self) -> "Hypothesis":
        # These fields are derived taxonomy, not model-authored metadata.  Always
        # replace supplied values so artifacts cannot disagree with bug_class.
        profile = get_known_cwe_profile(self.bug_class)
        self.root_cause_cwe = (
            profile.root_cwe if profile is not None else self.bug_class.value
        )
        self.vulnerability_type = (
            profile.vulnerability_type if profile is not None else "unclassified_cwe"
        )
        if not self.security_outcome.description:
            impact = str((self.evidence_summary or {}).get("impact") or "")
            if impact:
                self.security_outcome.description = impact
        return self


class HypothesesArtifact(JSONFileMixin):
    plugin_slug: str
    hypotheses: list[Hypothesis]


class SpecialistReviewArtifact(JSONFileMixin):
    hypotheses: list[Hypothesis]
    coverage: list[CoverageDisposition]
    # Runner-owned digest of the complete batch inputs. Model responses omit it;
    # checkpoint persistence fills it so changed targets/context cannot reuse a
    # semantically stale review solely because coverage IDs happen to match.
    input_fingerprint: str = ""


class TriagedArtifact(JSONFileMixin):
    plugin_slug: str
    accepted: list[Hypothesis]
    rejected: list[dict]
    merged: list[dict]
    manual_review: list[dict] = Field(default_factory=list)
    deferred: list[dict] = Field(default_factory=list)
