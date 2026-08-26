"""Recon stage artifact schema."""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import Field

from ._base import JSONFileMixin


class EntryPoint(JSONFileMixin):
    type: str
    name: str
    file: str
    line: int
    handler_function: str
    requires_auth: bool
    has_nonce_check: bool
    has_capability_check: bool
    capability: Optional[str] = None
    body_slice: Optional[str] = None
    confidence: Optional[str] = None
    source: str = "surveyor"
    access_known: bool = True


class Sink(JSONFileMixin):
    type: str
    function: str
    file: str
    line: int
    tainted_args: list[str]
    source: str = "surveyor"


class StaticCallback(JSONFileMixin):
    type: str
    name: str
    file: str
    line: int
    handler_function: str
    callback_kind: str
    raw: str


class StaticCallEdge(JSONFileMixin):
    caller: str
    callee: str
    caller_file: str
    caller_line: int
    callee_file: str | None = None
    callee_line: int | None = None
    confidence: str = "medium"


class SecurityProfile(JSONFileMixin):
    """Plugin-level security map produced by the surveyor.

    All fields are optional/additive from the pipeline's perspective. The
    specialist stage consumes this as grounding context when present, but older
    recon artifacts remain valid because ReconArtifact.security_profile defaults
    to None.
    """

    plugin_type: str | None = None
    sensitive_objects: list[str] = []
    custom_roles: list[str] = []
    custom_capabilities: list[str] = []
    high_risk_workflows: list[str] = []
    state_changing_workflows: list[str] = []
    file_workflows: list[str] = []
    payment_workflows: list[str] = []
    stored_input_to_privileged_view: list[str] = []
    webhook_routes: list[str] = []
    import_export_routes: list[str] = []
    notes: str | None = None


ReviewArea = Literal[
    "authorization_workflows",
    "injection_files",
    "xss_lifecycle",
    "authentication",
]
CoverageKind = Literal["entry_point", "sink", "storage_read", "storage_write"]
CoverageStatus = Literal["candidate", "reviewed", "unreachable", "unreviewed"]


class CoverageItem(JSONFileMixin):
    id: str
    kind: CoverageKind
    review_areas: list[ReviewArea]
    type: str
    name: str
    file: str
    line: int
    column: int = 1
    snippet: str
    handler_function: str = ""
    dependency: bool = False


class CoverageDisposition(JSONFileMixin):
    item_id: str
    reviewer: ReviewArea
    status: CoverageStatus
    reason: str
    evidence_locations: list[str] = Field(default_factory=list)
    hypothesis_ids: list[str] = Field(default_factory=list)


class CoverageArtifact(JSONFileMixin):
    production_files: list[str] = Field(default_factory=list)
    dependency_files: list[str] = Field(default_factory=list)
    items: list[CoverageItem] = Field(default_factory=list)
    dispositions: list[CoverageDisposition] = Field(default_factory=list)


class ReconArtifact(JSONFileMixin):
    plugin_slug: str
    entry_points: list[EntryPoint]
    sinks: list[Sink]
    entry_to_sink_paths: dict[str, list[str]]
    raw_grep_hits: dict[str, list[str]]
    nonce_emission_sites: Optional[dict[str, list[str]]] = None
    cross_file_callees: Optional[dict[str, list[str]]] = None
    static_callbacks: Optional[list[StaticCallback]] = None
    static_call_edges: Optional[list[StaticCallEdge]] = None
    security_profile: Optional[SecurityProfile] = None
    coverage: Optional[CoverageArtifact] = None
