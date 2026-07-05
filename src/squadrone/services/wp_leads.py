"""Deterministic WordPress vulnerability lead generation.

These leads are intentionally pre-verification candidates, not findings. The
goal is to let cheap, common WordPress bug shapes reach the sandbox before
strict submit-worthiness gates decide whether they have real CIA impact.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from ..schemas.hypothesis import BugClass, Confidence, Hypothesis
from ..schemas.recon import EntryPoint, ReconArtifact, Sink


STATE_CHANGE_RE = re.compile(
    r"update|delete|insert|create|save|approve|reject|publish|trash|restore|"
    r"status|enable|disable|set_|wp_update|wp_insert|wp_delete",
    re.IGNORECASE,
)
SENSITIVE_READ_RE = re.compile(
    r"get_(post|user|comment)_meta|get_option|get_user|download|export|"
    r"submission|entry|invoice|booking|order|private|secret|token",
    re.IGNORECASE,
)
SQL_RE = re.compile(r"wpdb|query|get_var|get_row|get_results", re.IGNORECASE)
SSRF_RE = re.compile(r"wp_remote_|curl_", re.IGNORECASE)
FILE_READ_RE = re.compile(r"file_get_contents|readfile|fopen|include|require", re.IGNORECASE)
FILE_WRITE_RE = re.compile(r"file_put_contents|fwrite|copy|move_uploaded_file|wp_handle_upload|extractTo", re.IGNORECASE)
FILE_DELETE_RE = re.compile(r"unlink|rmdir", re.IGNORECASE)
REQUEST_ARG_RE = re.compile(r"\$_(?:GET|POST|REQUEST|FILES|COOKIE)\s*\[\s*['\"]([^'\"]+)['\"]")


def _sink_text(sink: Sink) -> str:
    return " ".join(str(x or "") for x in (sink.type, sink.function, " ".join(sink.tainted_args)))


def _source_from_sink(sink: Sink) -> str:
    for arg in sink.tainted_args:
        text = str(arg)
        match = REQUEST_ARG_RE.search(text)
        if match:
            return f"request parameter `{match.group(1)}`"
        if text:
            return text
    return "request parameters reaching the handler"


def _read_source_line(plugin_path: Path, rel: str, line: int) -> str:
    target = plugin_path / rel
    if not target.is_file() or line <= 0:
        return ""
    try:
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    if line > len(lines):
        return ""
    return lines[line - 1].strip()


def _path_matches_sink(path: str, sink: Sink) -> bool:
    return f"{sink.file}:{sink.line}" in path or sink.file in path


def _candidate_sinks(recon: ReconArtifact, ep: EntryPoint) -> Iterable[Sink]:
    paths = recon.entry_to_sink_paths.get(ep.name) or []
    for sink in recon.sinks:
        if paths and any(_path_matches_sink(path, sink) for path in paths):
            yield sink
        elif not paths and sink.file == ep.file:
            yield sink


def _has_meaningful_sink(sink: Sink) -> bool:
    text = _sink_text(sink)
    return bool(
        STATE_CHANGE_RE.search(text)
        or SENSITIVE_READ_RE.search(text)
        or SQL_RE.search(text)
        or SSRF_RE.search(text)
        or FILE_READ_RE.search(text)
        or FILE_WRITE_RE.search(text)
        or FILE_DELETE_RE.search(text)
    )


def _classify(ep: EntryPoint, sink: Sink) -> tuple[BugClass, str, str] | None:
    text = _sink_text(sink)
    is_public = not ep.requires_auth or "nopriv" in ep.type or "nopriv" in ep.name
    missing_cap = not ep.has_capability_check and not ep.validated_capability
    missing_nonce = not ep.has_nonce_check and not ep.validated_nonce_action

    if SQL_RE.search(text) and sink.tainted_args:
        return (
            BugClass.SQLI,
            "attacker-controlled input reaches a database query sink",
            "attacker may alter query semantics or extract database data",
        )
    if SSRF_RE.search(text) and sink.tainted_args:
        return (
            BugClass.SSRF,
            "attacker-controlled input reaches a server-side HTTP client",
            "attacker may make the server initiate requests to internal or sensitive services",
        )
    if FILE_WRITE_RE.search(text) and sink.tainted_args:
        return (
            BugClass.ARBITRARY_FILE_WRITE,
            "attacker-controlled input reaches a file write/upload sink",
            "attacker may write or upload files through the plugin",
        )
    if FILE_READ_RE.search(text) and sink.tainted_args:
        return (
            BugClass.PATH_TRAVERSAL,
            "attacker-controlled input reaches a file read/include sink",
            "attacker may read protected files or include attacker-selected paths",
        )
    if FILE_DELETE_RE.search(text) and sink.tainted_args:
        return (
            BugClass.PATH_TRAVERSAL,
            "attacker-controlled input reaches a file delete sink",
            "attacker may delete files that should require higher privileges",
        )
    if SENSITIVE_READ_RE.search(text) and sink.tainted_args and missing_cap:
        return (
            BugClass.IDOR,
            "handler reads object or sensitive data without an ownership/capability check",
            "attacker may read another user's private or sensitive plugin data",
        )
    if STATE_CHANGE_RE.search(text) and missing_cap:
        if is_public:
            return (
                BugClass.MISSING_CAP_CHECK,
                "public or low-privilege handler reaches a state-changing sink without a capability check",
                "attacker may change plugin, post, user, or workflow state that should require authorization",
            )
        return (
            BugClass.MISSING_CAP_CHECK,
            "authenticated handler reaches a state-changing sink without a capability check",
            "low-privilege user may change state that should require a stronger capability",
        )
    if STATE_CHANGE_RE.search(text) and missing_nonce:
        return (
            BugClass.MISSING_NONCE,
            "state-changing handler lacks an obvious nonce check",
            "attacker may trigger a meaningful state change through CSRF if the victim has sufficient privileges",
        )
    return None


def generate_wp_leads(recon: ReconArtifact, plugin_path: str) -> list[Hypothesis]:
    """Return source-grounded, deterministic leads for common WP CVE shapes."""
    root = Path(plugin_path)
    leads: list[Hypothesis] = []
    seen: set[tuple[str, str, int, BugClass]] = set()
    counter = 1
    for ep in recon.entry_points:
        for sink in _candidate_sinks(recon, ep):
            if not _has_meaningful_sink(sink):
                continue
            classified = _classify(ep, sink)
            if classified is None:
                continue
            bug_class, control, impact = classified
            key = (ep.name, sink.file, sink.line, bug_class)
            if key in seen:
                continue
            seen.add(key)
            source = _source_from_sink(sink)
            role = "unauthenticated" if (not ep.requires_auth or "nopriv" in ep.type or "nopriv" in ep.name) else "authenticated low-privilege user"
            path = " -> ".join(recon.entry_to_sink_paths.get(ep.name) or [f"{ep.file}:{ep.line} -> {sink.file}:{sink.line}"])
            sink_code = _read_source_line(root, sink.file, sink.line)
            boundary = (
                "crosses an authorization, ownership, or intent boundary because "
                f"{role} reaches `{sink.function}` through `{ep.name}`"
            )
            lead_id = f"wp-lead-{counter:03d}"
            counter += 1
            leads.append(Hypothesis(
                id=lead_id,
                specialist="deterministic_wp_lead",
                bug_class=bug_class,
                entry_point=ep.name,
                file=sink.file,
                line=sink.line,
                sink=sink.function,
                sink_code=sink_code,
                taint_path=[source, ep.name, sink.function],
                reasoning=(
                    f"{role} can reach `{sink.function}` from `{ep.name}`. "
                    f"{control}; sandbox should verify whether the operation succeeds "
                    "and whether the resulting CIA impact is reportable."
                ),
                confidence=Confidence.MEDIUM,
                preconditions=role,
                affected_versions="current scanned version",
                evidence_summary={
                    "attacker_role": role,
                    "source": source,
                    "control": control,
                    "sink": sink.function,
                    "reachable_path": path,
                    "boundary": boundary,
                    "impact": impact,
                    "counterevidence": "deterministic lead; sandbox must confirm runtime guard behavior and result",
                    "proof_gaps": "whether the request succeeds in the sandbox and produces concrete CIA impact",
                    "pre_verification_lead": True,
                },
            ))
    return leads
