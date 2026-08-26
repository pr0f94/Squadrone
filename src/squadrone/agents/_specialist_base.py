"""Shared specialist runner — every specialist follows the same pattern."""

from __future__ import annotations

import json
import logging
from pathlib import PurePosixPath
import re
from typing import TYPE_CHECKING

from ..schemas.hypothesis import SpecialistReviewArtifact
from ..schemas.recon import CoverageItem, ReconArtifact, ReviewArea, StaticCallEdge
from .plugin_tools import PluginToolHandlers
from .prompts_io import load_prompt
from .tools import CONSULT_DEVELOPER_TOOL

if TYPE_CHECKING:
    from .runtime import AgentRuntime

logger = logging.getLogger(__name__)


_LOCATION_RE = re.compile(r"^(?P<path>.+):(?P<line>[1-9][0-9]*)$")
_GENERIC_HANDLERS = {"", "closure", "function", "init", "__invoke"}


_METHODOLOGY = """

## Role-aware workflow review

Do not behave like a sink-only scanner. For every candidate, prove a concrete
security story. Treat `recon.security_profile` as this plugin's lightweight
threat model: it tells you which objects, roles, capabilities, and workflows
matter, but it is not proof by itself.

Every emitted hypothesis must satisfy this proof tuple:

1. **Source**: the attacker-controlled request, stored value, file, API event,
   shortcode/form input, webhook, or external trigger.
2. **Control**: the closest nonce, capability, ownership, sanitizer, validator,
   token binding, allowlist, feature gate, or missing security control.
3. **Sink/outcome**: the operation or security effect reached by the source.
4. **Reachable path**: the concrete route/callback/helper chain and preconditions.
5. **Boundary**: why this crosses a real WordPress/plugin security boundary.
6. **Counterevidence**: nearby facts that could make the claim false.
7. **Proof gaps**: the smallest remaining fact that would need sandbox/manual
   validation. If the gap is broad or vague, do not emit the hypothesis.

Also state the user-facing security story:

1. **Attacker role**: unauthenticated, subscriber, contributor, author, customer,
   vendor, editor, shop manager, administrator, or custom role.
2. **Object/workflow**: identify the object or workflow being affected
   (submission, order, booking, file, user, option, template, payment, etc.).
3. **Security rule**: state the rule that should have blocked the attacker
   (ownership, capability, payment, approval, nonce plus authorization, token
   binding, default configuration).
4. **Source-to-sink proof**: show that attacker-controlled data reaches the
   sink with the required guard missing or bypassed.
5. **Impact**: explain what the attacker gets that they should not get.

Populate `evidence_summary` with the proof tuple keys:
`source`, `control`, `sink`, `reachable_path`, `boundary`, `counterevidence`,
`proof_gaps`, `attacker_role`, and `impact`. Keep values short and concrete.

Reject weak shapes before emitting:
- admin-only behavior with no privilege boundary
- public analytics/view-count manipulation
- logout or notice-dismissal CSRF
- fixed/public asset reads such as constrained `style.css`
- configuration-dependent findings requiring an administrator to disable or
  weaken a security control, grant the attacker an extra capability, modify
  source, enable debug behavior, or add custom bypass code
- self-XSS or own-object-only behavior
- premium paths without current source, or feature paths that cannot be enabled
  through the shipped unmodified plugin
- any claim where the actual C/I/A impact cannot be said in one plain sentence

A normal shipped feature toggle is a valid prerequisite even when disabled by
default. Keep the candidate when enabling the feature is its intended workflow,
the vulnerable security subsettings remain at their defaults for that feature,
and a low-privilege attacker then reaches concrete CIA impact. Record the exact
configuration as a precondition so triage and the sandbox can evaluate it.

Prefer fewer, stronger hypotheses. A useful empty list is better than a noisy
set of maybe-bugs.
"""


_SOURCE_EXPLORATION_INSTRUCTIONS = """

## Source-exploration tools

You have three plugin-scoped tools; use them to fetch any source you need
instead of expecting it inline:

- `grep_plugin(pattern, path_glob=?, max_results=?, context_lines=?, case_insensitive=?)`
- `glob_plugin(pattern, max_results=?)`
- `read_plugin_file(path, start_line=?, end_line=?, max_lines=?, start_column=?, max_chars=?)`

The user message contains one bounded review batch and only the recon facts
related to that batch. Inspect `priority_files` first. They are a navigation
starting point, not a source boundary: grep or read any other plugin file needed
to complete a callback, helper, template, or JavaScript path.

## Mandatory grounding rules — every hypothesis must satisfy these

1. **`sink_code` must be a verbatim copy** from the OUTPUT of a recent
   `read_plugin_file` call. Do NOT generate plausible-looking code from
   training-data recall. Do NOT paraphrase. If you cannot find an exact
   matching string in a tool result, do not emit the hypothesis.

2. **`file` and `line` must match where you actually read the sink.** The line
   number you cite must be inside the line range a `read_plugin_file` call
   returned, and the `sink_code` you quote must be on that line (or starting
   on that line for multi-line constructs).

3. **Before claiming "no capability check" / "no nonce check" / "no ownership
   check"**: you must have read the ENTIRE function body (from its `function`
   declaration to its closing brace) and verified the absence of:
     - `current_user_can(...)`, `user_can(...)`
     - `wp_verify_nonce(...)`, `check_ajax_referer(...)`, `check_admin_referer(...)`
     - any plugin-specific helper named like `can_*`, `*_can_*`, `verify_*`,
       `authorize_*` (e.g. `tutor_utils()->can_user_manage(...)`)
   If your read range did NOT cover the full function, expand your read first.
   If a guard exists, the hypothesis is invalid — drop it.

4. **If a hypothesis fails any rule above, DO NOT EMIT IT.** Emitting a
   fabricated or unverified hypothesis is worse than emitting nothing — the
   verifier will catch it and the cost is wasted.

5. **For a sink inside a reusable helper, inspect every request-reachable
   caller.** Grep for the helper name and compare each caller's controls. A
   nonce, capability check, type check, or sanitizer in one caller does not
   protect a second caller to the same helper. Do not mark the sink safe until
   alternate callers in `related_recon.static_call_edges` and
   `related_recon.entry_to_sink_paths` have been evaluated.

Do not invent or approximate source facts. When the source, control, reachable
path, boundary, and CIA outcome are concrete and only one narrow runtime fact
remains, emit the candidate so the sandbox can answer it. Drop the candidate
when source reachability or impact itself remains broad or speculative.
"""


def _static_target_functions(
    edges: list[StaticCallEdge],
    targets: list[CoverageItem],
) -> tuple[
    set[tuple[str, str, int]],
    dict[tuple[str, str, int], set[str]],
]:
    """Map sink targets to the nearest statically known containing function."""
    functions: set[tuple[str, str, int]] = set()
    locations_by_function: dict[tuple[str, str, int], set[str]] = {}
    definitions = {
        (edge.callee, edge.callee_file, edge.callee_line)
        for edge in edges
        if edge.callee_file is not None and edge.callee_line is not None
    }
    for target in targets:
        candidates = [
            (line, name)
            for name, file, line in definitions
            if file == target.file and line is not None and line <= target.line
        ]
        if not candidates:
            continue
        nearest_line = max(line for line, _ in candidates)
        for line, name in candidates:
            if line != nearest_line:
                continue
            function = (name, target.file, line)
            functions.add(function)
            locations_by_function.setdefault(function, set()).add(
                f"{target.file}:{target.line}"
            )
    return functions, locations_by_function


def _trace_static_paths(
    handler: str,
    target_functions: set[tuple[str, str, int]],
    target_locations: dict[tuple[str, str, int], set[str]],
    edges: list[StaticCallEdge],
    *,
    max_depth: int = 6,
    max_paths: int = 12,
) -> list[str]:
    """Return bounded callback-to-target paths from deterministic call edges."""
    graph: dict[str, list[StaticCallEdge]] = {}
    for edge in edges:
        graph.setdefault(edge.caller, []).append(edge)

    paths: list[str] = []
    queue: list[tuple[str, list[str], set[str]]] = [(handler, [], {handler})]
    while queue and len(paths) < max_paths:
        current, hops, seen = queue.pop(0)
        if len(hops) >= max_depth:
            continue
        for edge in graph.get(current, []):
            callee_location = (
                f"{edge.callee_file}:{edge.callee_line}"
                if edge.callee_file is not None and edge.callee_line is not None
                else "unresolved"
            )
            hop = (
                f"{edge.caller_file}:{edge.caller_line} "
                f"{edge.caller}->{edge.callee} ({callee_location})"
            )
            next_hops = [*hops, hop]
            callee_definition = (
                (edge.callee, edge.callee_file, edge.callee_line)
                if edge.callee_file is not None and edge.callee_line is not None
                else None
            )
            if callee_definition in target_functions:
                locations = target_locations.get(callee_definition) or {callee_location}
                for location in sorted(locations):
                    paths.append(" -> ".join([*next_hops, location]))
                    if len(paths) >= max_paths:
                        break
            if edge.callee not in seen:
                queue.append((edge.callee, next_hops, {*seen, edge.callee}))
    return paths


def _compact_recon(recon: ReconArtifact, targets: list[CoverageItem]) -> dict:
    """Return only recon facts directly related to a bounded review batch."""
    target_entry_keys = {
        (item.type, item.name) for item in targets if item.kind == "entry_point"
    }
    target_handlers = {
        item.handler_function
        for item in targets
        if item.handler_function.lower() not in _GENERIC_HANDLERS
    }
    target_locations = {f"{item.file}:{item.line}" for item in targets}
    target_directories = {PurePosixPath(item.file).parent for item in targets}
    static_edges = list(recon.static_call_edges or [])
    static_target_definitions, static_target_locations = _static_target_functions(
        static_edges, targets,
    )
    static_target_functions = {name for name, _, _ in static_target_definitions}

    related_functions = target_handlers | static_target_functions
    changed = True
    while changed:
        changed = False
        for edge in static_edges:
            if edge.callee in related_functions and edge.caller not in related_functions:
                related_functions.add(edge.caller)
                changed = True

    related_entries = []
    related_paths: dict[str, list[str]] = {}
    for entry in recon.entry_points:
        paths = list(recon.entry_to_sink_paths.get(entry.name) or [])
        paths.extend(_trace_static_paths(
            entry.handler_function,
            static_target_definitions,
            static_target_locations,
            static_edges,
        ))
        paths = list(dict.fromkeys(paths))
        direct_target = (
            (entry.type, entry.name) in target_entry_keys
            or entry.handler_function in target_handlers
        )
        nearby_direct_php = (
            entry.type in {"direct_php", "direct_php_candidate"}
            and PurePosixPath(entry.file).parent in target_directories
        )
        reaches_target = any(
            location in path for location in target_locations for path in paths
        )
        if not direct_target and not nearby_direct_php and not reaches_target:
            continue
        related_entries.append(entry.model_dump(mode="json", exclude={"body_slice"}))
        if paths:
            related_paths[entry.name] = paths

    path_locations = {
        f"{sink.file}:{sink.line}"
        for sink in recon.sinks
        if any(
            f"{sink.file}:{sink.line}" in path
            for paths in related_paths.values()
            for path in paths
        )
    }
    relevant_locations = target_locations | path_locations
    related_sinks = [
        sink.model_dump(mode="json")
        for sink in recon.sinks
        if f"{sink.file}:{sink.line}" in relevant_locations
    ]

    related_functions.update(
        str(entry.get("handler_function") or "") for entry in related_entries
    )
    related_edges = [
        edge.model_dump(mode="json")
        for edge in static_edges
        if edge.caller in related_functions and edge.callee in related_functions
    ][:120]

    return {
        "security_profile": (
            recon.security_profile.model_dump(mode="json")
            if recon.security_profile is not None else None
        ),
        "entry_points": related_entries,
        "sinks": related_sinks,
        "entry_to_sink_paths": related_paths,
        "static_call_edges": related_edges,
    }


def _enforce_read_evidence(
    artifact: SpecialistReviewArtifact,
    handlers: PluginToolHandlers,
    coverage_targets: list[CoverageItem],
) -> SpecialistReviewArtifact:
    """Downgrade dispositions whose cited source never appeared in a read result."""
    target_by_id = {target.id: target for target in coverage_targets}
    for disposition in artifact.coverage:
        observed_locations: list[str] = []
        for location in disposition.evidence_locations:
            match = _LOCATION_RE.match(location.strip())
            if match and handlers.was_read(
                match.group("path"), int(match.group("line")), column=None,
            ):
                observed_locations.append(location.strip())
        disposition.evidence_locations = observed_locations
        target = target_by_id.get(disposition.item_id)
        target_location = f"{target.file}:{target.line}" if target is not None else ""
        target_was_read = bool(
            target is not None
            and target_location in observed_locations
            and handlers.was_read(target.file, target.line, target.column)
        )
        if target_was_read and disposition.reason.strip():
            continue
        disposition.status = "unreviewed"
        disposition.hypothesis_ids = []
        disposition.reason = (
            "reviewer did not cite a source location returned by read_plugin_file"
        )
    return artifact


async def run_specialist(
    *,
    runtime: "AgentRuntime",
    name: str,
    prompt_path: str,
    model: str,
    recon: ReconArtifact,
    plugin_path: str,
    priority_files: list[str],
    coverage_targets: list[CoverageItem],
    batch_id: str,
) -> SpecialistReviewArtifact:
    parts = [
        load_prompt(prompt_path),
        "\n\n",
        load_prompt("specialists/_shared_rules"),
        _METHODOLOGY,
        "\n\n# Reference: WordPress idioms\n\n",
        load_prompt("_wp_idioms"),
    ]

    parts.append(_SOURCE_EXPLORATION_INSTRUCTIONS)
    system = "".join(parts)

    related_recon = _compact_recon(recon, coverage_targets)
    direct_php_files = {
        str(entry.get("file") or "")
        for entry in related_recon["entry_points"]
        if entry.get("type") in {"direct_php", "direct_php_candidate"}
        and entry.get("file")
    }
    user_payload: dict = {
        "plugin_slug": recon.plugin_slug,
        "review_area": name,
        "batch_id": batch_id,
        "hypothesis_id_prefix": batch_id,
        "related_recon": related_recon,
        "priority_files": sorted({*priority_files, *direct_php_files}),
        "coverage_targets": [target.model_dump(mode="json") for target in coverage_targets],
    }
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": json.dumps(user_payload, default=str)},
    ]

    handlers = PluginToolHandlers(plugin_root=plugin_path)
    tools: list[dict] = [CONSULT_DEVELOPER_TOOL, *handlers.tool_definitions()]
    result = await runtime.run(
        agent_name=f"{name}.{batch_id}",
        model=model,
        messages=messages,
        tools=tools,
        tool_handlers=handlers.tool_handlers(),
        output_schema=SpecialistReviewArtifact,
        max_iterations=25,
        force_finalise_after=20,
    )
    return _enforce_read_evidence(result.output, handlers, coverage_targets)


class FocusedSpecialist:
    """One of the four fixed source-review areas."""

    def __init__(
        self,
        runtime: "AgentRuntime",
        model: str,
        *,
        name: ReviewArea,
        prompt_path: str,
    ) -> None:
        self.runtime = runtime
        self.model = model
        self.NAME = name
        self.PROMPT = prompt_path

    async def analyze(
        self,
        recon: ReconArtifact,
        *,
        plugin_path: str,
        priority_files: list[str],
        coverage_targets: list[CoverageItem],
        batch_id: str,
    ) -> SpecialistReviewArtifact:
        return await run_specialist(
            runtime=self.runtime,
            name=self.NAME,
            prompt_path=self.PROMPT,
            model=self.model,
            recon=recon,
            plugin_path=plugin_path,
            priority_files=priority_files,
            coverage_targets=coverage_targets,
            batch_id=batch_id,
        )
