"""Recon stage artifact schema."""

from __future__ import annotations

from typing import Optional

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
    # Stage 2 opt-in metadata (all None when toggles are off — backward compatible)
    body_slice: Optional[str] = None              # #5: function body lifted into recon.json
    confidence: Optional[str] = None              # #6: "high" | "medium" | "low"
    # #1: per-entry-point validation pass output — overrides pattern-derived flags when present
    validated_auth_gating: Optional[str] = None   # "logged_in_only" | "capability:<X>" |
                                                  # "nonce_only:<action>" | "none" | "mixed"
    validated_nonce_action: Optional[str] = None  # action name if nonce-gated
    validated_capability: Optional[str] = None    # capability if cap-gated
    validation_citation: Optional[str] = None     # "file:line — quote of the gating call"
    validation_notes: Optional[str] = None        # short prose


class Sink(JSONFileMixin):
    type: str
    function: str
    file: str
    line: int
    tainted_args: list[str]


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
    """V2 plugin-level security map produced by the surveyor.

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


class ReconArtifact(JSONFileMixin):
    plugin_slug: str
    entry_points: list[EntryPoint]
    sinks: list[Sink]
    entry_to_sink_paths: dict[str, list[str]]
    raw_grep_hits: dict[str, list[str]]
    # Stage 2 opt-in additions:
    nonce_emission_sites: Optional[dict[str, list[str]]] = None  # #3: nonce_action -> ["file:line — context"]
    cross_file_callees: Optional[dict[str, list[str]]] = None    # #2: handler_name -> ["file:line callee_name"]
    excluded_buckets: Optional[list[str]] = None                  # #4: which intake.file_classification buckets we skipped
    static_callbacks: Optional[list[StaticCallback]] = None       # deterministic hook/route/shortcode registrations
    static_call_edges: Optional[list[StaticCallEdge]] = None      # best-effort callback -> helper call edges
    security_profile: Optional[SecurityProfile] = None            # V2: plugin type/object/workflow map
