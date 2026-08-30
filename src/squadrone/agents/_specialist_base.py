"""Shared specialist runner — every specialist follows the same pattern."""

from __future__ import annotations

from collections import Counter, deque
import json
import logging
from pathlib import PurePosixPath
import re
from typing import TYPE_CHECKING

from ..schemas.hypothesis import SpecialistReviewArtifact
from ..schemas.recon import (
    CoverageDisposition,
    CoverageItem,
    ReconArtifact,
    ReviewArea,
    StaticCallEdge,
)
from .plugin_tools import PluginToolHandlers
from .prompts_io import load_prompt
from .tools import CONSULT_DEVELOPER_TOOL

if TYPE_CHECKING:
    from .runtime import AgentRuntime

logger = logging.getLogger(__name__)


_LOCATION_RE = re.compile(r"^(?P<path>.+):(?P<line>[1-9][0-9]*)$")
_GENERIC_HANDLERS = {"", "closure", "function", "init", "__invoke"}
_DYNAMIC_KEY_ARGUMENTS = {
    "add_comment_meta": 1,
    "add_blog_option": 1,
    "add_metadata": 2,
    "add_network_option": 1,
    "add_option": 0,
    "add_post_meta": 1,
    "add_site_option": 0,
    "add_user_meta": 1,
    "delete_comment_meta": 1,
    "delete_blog_option": 1,
    "delete_metadata": 2,
    "delete_network_option": 1,
    "delete_option": 0,
    "delete_post_meta": 1,
    "delete_site_option": 0,
    "delete_user_meta": 1,
    "update_comment_meta": 1,
    "update_blog_option": 1,
    "update_metadata": 2,
    "update_network_option": 1,
    "update_option": 0,
    "update_post_meta": 1,
    "update_site_option": 0,
    "update_user_meta": 1,
}
_AGGREGATE_ATTRIBUTE_WRITES = {
    "wp_insert_post",
    "wp_insert_user",
    "wp_update_post",
    "wp_update_user",
}
_SINGLE_QUOTED_PHP_STRING_RE = re.compile(r"'(?:\\.|[^'\\])*'\Z", re.DOTALL)
_DOUBLE_QUOTED_PHP_STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"\Z', re.DOTALL)
_FIXED_ARRAY_KEY_RE = re.compile(
    r"^\s*(?P<key>'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|[+-]?[0-9]+)\s*=>",
    re.DOTALL,
)
_NESTED_ATTRIBUTE_MAP_KEYS = {"meta_input", "tax_input"}
_DEFAULT_MAX_ITERATIONS = 25
_DEFAULT_FORCE_FINALISE_AFTER = 20
_DYNAMIC_KEY_MAX_ITERATIONS = 40
_DYNAMIC_KEY_FORCE_FINALISE_AFTER = 32
AUTHENTICATION_ALTERNATE_PATH_AUDIT_VERSION = 1


_AUTHENTICATION_ALTERNATE_PATH_INSTRUCTIONS = """

## Independent alternate-path audit

This is a second, independent review of authentication-state targets. The user
payload lists paths already identified by the primary reviewer. Do not repeat
those hypotheses. Instead, work backward from every assigned authentication
state transition and inventory distinct external producers, action/mode
branches, and lifecycle callbacks that the primary result did not cover.

For each producer, establish whether requester authentication dominates that
specific path. Inspect assignments into shared or deferred state, early returns
before the normal guard, fallthrough, and the registration/priority/order of
later hooks or callbacks that consume the state. Later validation or error
handling does not undo a session/current-user/cookie transition performed by an
earlier callback. Account-existence and account-role checks validate the target
identity, not the requester. Pay particular attention to paths with weaker or
different prerequisites from the listed hypotheses, including bootstrap,
onboarding, recovery, fallback, unsigned, and no-credential branches.

Emit a separate hypothesis for each newly established root cause or prerequisite
set. If no additional path exists for a target, return `reviewed` for that
target with a reason describing the alternate producers checked. Return one
coverage disposition for every assigned target and use the supplied alternate
hypothesis ID prefix.
"""


def _strip_php_comments(source: str) -> str:
    """Mask PHP comments while preserving strings, offsets, and newlines."""
    result: list[str] = []
    quote = ""
    escaped = False
    line_comment = False
    block_comment = False
    index = 0
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if line_comment:
            if char in "\r\n":
                result.append(char)
                line_comment = False
            else:
                result.append(" ")
            index += 1
            continue
        if block_comment:
            if char == "*" and next_char == "/":
                result.extend((" ", " "))
                block_comment = False
                index += 2
            else:
                result.append(char if char in "\r\n" else " ")
                index += 1
            continue
        if quote:
            result.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            index += 1
            continue
        if char in {"'", '"', "`"}:
            result.append(char)
            quote = char
            index += 1
            continue
        if char == "/" and next_char in {"/", "*"}:
            result.extend((" ", " "))
            line_comment = next_char == "/"
            block_comment = next_char == "*"
            index += 2
            continue
        if char == "#" and next_char != "[":
            result.append(" ")
            line_comment = True
            index += 1
            continue
        result.append(char)
        index += 1
    return "".join(result)


def _php_call_arguments(snippet: str, function_name: str) -> list[str] | None:
    """Return top-level call arguments, or None when the snippet is incomplete."""
    snippet = _strip_php_comments(snippet)
    match = re.search(
        rf"(?<![A-Za-z0-9_]){re.escape(function_name)}\s*\(",
        snippet,
        re.IGNORECASE,
    )
    if match is None:
        return None

    opening = snippet.find("(", match.start())
    stack = ["("]
    pairs = {")": "(", "]": "[", "}": "{"}
    arguments: list[str] = []
    argument_start = opening + 1
    quote = ""
    escaped = False
    index = opening + 1
    while index < len(snippet):
        char = snippet[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            index += 1
            continue
        if char in {"'", '"', "`"}:
            quote = char
            index += 1
            continue
        if char in "([{":
            stack.append(char)
        elif char in ")]}":
            expected = pairs[char]
            if not stack or stack[-1] != expected:
                return None
            if len(stack) == 1:
                argument = snippet[argument_start:index].strip()
                if argument:
                    arguments.append(argument)
                return arguments
            stack.pop()
        elif char == "," and len(stack) == 1:
            arguments.append(snippet[argument_start:index].strip())
            argument_start = index + 1
        index += 1
    return None


def _is_fixed_php_string(expression: str) -> bool:
    """Whether an expression is provably one non-interpolated string literal."""
    expression = expression.strip()
    if _SINGLE_QUOTED_PHP_STRING_RE.fullmatch(expression):
        return True
    if not _DOUBLE_QUOTED_PHP_STRING_RE.fullmatch(expression):
        return False
    # Treat even escaped dollars conservatively. False positives only buy the
    # write a focused review; false negatives can hide a protected attribute.
    return "$" not in expression


def _has_inline_attribute_map(
    expression: str,
    *,
    inspect_nested_maps: bool = True,
) -> bool:
    """Whether an aggregate write has an inline map with only fixed keys."""
    expression = _strip_php_comments(expression).strip()
    if re.match(r"array\s*\(", expression, re.IGNORECASE):
        entries = _php_call_arguments(expression, "array")
        opening = expression.find("(")
        closing = ")"
    elif expression.startswith("["):
        # Reuse the call parser to split top-level short-array entries.
        entries = _php_call_arguments(
            f"__squadrone_array({expression[1:-1]})",
            "__squadrone_array",
        )
        opening = 0
        closing = "]"
    else:
        return False
    if entries is None or not expression.endswith(closing):
        return False

    # The outer delimiter must close at the end; `array(...) . $other` and
    # `[... ] + $other` are aggregate expressions, not fixed inline maps.
    depth = 0
    quote = ""
    escaped = False
    outer_closing = -1
    opening_char = expression[opening]
    for index, char in enumerate(expression[opening:], opening):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {"'", '"', "`"}:
            quote = char
            continue
        if char == opening_char:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                outer_closing = index
                break
    if outer_closing != len(expression) - 1:
        return False

    for entry in entries:
        match = _FIXED_ARRAY_KEY_RE.match(entry)
        if match is None:
            return False
        key = match.group("key")
        if key[0] in {"'", '"'} and not _is_fixed_php_string(key):
            return False
        if "\\" in key:
            # Escaped double-quoted keys can encode a nested aggregate key.
            # Treat the uncommon ambiguous form conservatively.
            return False
        literal_key = key[1:-1] if key[0] in {"'", '"'} else key
        if inspect_nested_maps and literal_key in _NESTED_ATTRIBUTE_MAP_KEYS:
            value = entry[match.end() :].strip()
            if not _has_inline_attribute_map(value, inspect_nested_maps=False):
                return False
    return True


def _target_requires_dynamic_key_trace(target: CoverageItem) -> bool:
    """Classify field-selecting writes conservatively from deterministic syntax."""
    if target.kind != "storage_write":
        return False
    function_name = target.name.lower()
    arguments = _php_call_arguments(target.snippet, function_name)
    key_index = _DYNAMIC_KEY_ARGUMENTS.get(function_name)
    if key_index is not None:
        # Missing/truncated syntax is not evidence of a fixed key. Fail closed
        # and give the target a focused trace instead.
        return (
            arguments is None
            or len(arguments) <= key_index
            or not _is_fixed_php_string(arguments[key_index])
        )
    if function_name in _AGGREGATE_ATTRIBUTE_WRITES:
        return (
            arguments is None
            or not arguments
            or not _has_inline_attribute_map(arguments[0])
        )
    return False


def _requires_dynamic_key_trace(targets: list[CoverageItem]) -> bool:
    """Whether a batch contains a write whose protected field name may vary."""
    return any(_target_requires_dynamic_key_trace(target) for target in targets)


def _requires_authentication_alternate_path_audit(
    name: ReviewArea,
    targets: list[CoverageItem],
) -> bool:
    """Whether independent path enumeration protects an auth-state review."""
    return name == "authentication" and any(
        target.type == "authentication_state" for target in targets
    )


def _merge_alternate_path_reviews(
    primary: SpecialistReviewArtifact,
    alternate: SpecialistReviewArtifact,
    targets: list[CoverageItem],
    reviewer: ReviewArea,
) -> SpecialistReviewArtifact:
    """Merge an independent alternate-path audit into one coverage ledger."""
    target_ids = {target.id for target in targets}

    def _validated_dispositions(
        artifact: SpecialistReviewArtifact,
    ) -> tuple[dict[str, CoverageDisposition], set[str]]:
        hypothesis_counts = Counter(hypothesis.id for hypothesis in artifact.hypotheses)
        valid_hypothesis_ids = {
            hypothesis_id
            for hypothesis_id, count in hypothesis_counts.items()
            if count == 1
        }
        dispositions: dict[str, CoverageDisposition] = {}
        invalid: set[str] = set()
        for target_id in target_ids:
            matches = [
                item
                for item in artifact.coverage
                if item.item_id == target_id and item.reviewer == reviewer
            ]
            if len(matches) != 1:
                invalid.add(target_id)
                continue
            item = matches[0]
            if item.status == "unreviewed":
                invalid.add(target_id)
            elif item.status == "candidate":
                if not item.hypothesis_ids or any(
                    hypothesis_id not in valid_hypothesis_ids
                    for hypothesis_id in item.hypothesis_ids
                ):
                    invalid.add(target_id)
            elif item.hypothesis_ids:
                invalid.add(target_id)
            dispositions[target_id] = item
        return dispositions, invalid

    primary_by_id, primary_invalid = _validated_dispositions(primary)
    alternate_by_id, alternate_invalid = _validated_dispositions(alternate)
    combined_hypotheses = [*primary.hypotheses, *alternate.hypotheses]
    duplicate_hypothesis_ids = {
        hypothesis_id
        for hypothesis_id, count in Counter(
            hypothesis.id for hypothesis in combined_hypotheses
        ).items()
        if count > 1
    }
    merged_coverage: list[CoverageDisposition] = []
    for target in targets:
        dispositions = [
            item
            for item in (
                primary_by_id.get(target.id),
                alternate_by_id.get(target.id),
            )
            if item is not None
        ]
        invalid = target.id in primary_invalid or target.id in alternate_invalid
        candidate_ids = list(
            dict.fromkeys(
                hypothesis_id
                for item in dispositions
                if item.status == "candidate"
                for hypothesis_id in item.hypothesis_ids
            )
        )
        if duplicate_hypothesis_ids.intersection(candidate_ids):
            invalid = True
        evidence_locations = list(
            dict.fromkeys(
                location for item in dispositions for location in item.evidence_locations
            )
        )
        reasons = [item.reason for item in dispositions if item.reason]
        if invalid:
            status = "unreviewed"
            candidate_ids = []
            reasons.append(
                "Primary and alternate-path reviews must each account for this "
                "target exactly once with valid evidence and hypothesis references."
            )
        elif candidate_ids:
            status = "candidate"
        elif all(item.status == "unreachable" for item in dispositions):
            status = "unreachable"
        else:
            status = "reviewed"
        merged_coverage.append(
            CoverageDisposition(
                item_id=target.id,
                reviewer=reviewer,
                status=status,
                reason=" Alternate-path audit: ".join(dict.fromkeys(reasons)),
                evidence_locations=evidence_locations,
                hypothesis_ids=candidate_ids,
            )
        )

    referenced_ids = {
        hypothesis_id
        for item in merged_coverage
        for hypothesis_id in item.hypothesis_ids
    }
    hypotheses = [
        hypothesis
        for hypothesis in combined_hypotheses
        if hypothesis.id in referenced_ids
    ]
    return SpecialistReviewArtifact(
        hypotheses=hypotheses,
        coverage=merged_coverage,
    )


def _specialist_iteration_limits(
    name: ReviewArea,
    targets: list[CoverageItem],
) -> tuple[int, int]:
    """Return max iterations and force-finalise limit for one review batch."""
    if name == "authorization_workflows" and _requires_dynamic_key_trace(targets):
        return _DYNAMIC_KEY_MAX_ITERATIONS, _DYNAMIC_KEY_FORCE_FINALISE_AFTER
    return _DEFAULT_MAX_ITERATIONS, _DEFAULT_FORCE_FINALISE_AFTER


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
- self-XSS or own-object behavior that cannot change a protected attribute or
  cross a broader security boundary; object ownership does not grant authority
  over every attribute, so trace request-controlled field/key names separately
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
    callers_by_callee: dict[str, set[str]] = {}
    for edge in edges:
        graph.setdefault(edge.caller, []).append(edge)
        callers_by_callee.setdefault(edge.callee, set()).add(edge.caller)

    # Only traverse functions that can reach one of this batch's targets.  The
    # previous per-path breadth-first search explored every unrelated branch to
    # max_depth and copied a growing ``seen`` set for each branch.  On large
    # plugin call graphs that became combinatorial before the first specialist
    # request was even sent.
    reachable_functions = {name for name, _, _ in target_functions}
    reverse_queue = deque(reachable_functions)
    while reverse_queue:
        callee = reverse_queue.popleft()
        for caller in callers_by_callee.get(callee, ()):
            if caller in reachable_functions:
                continue
            reachable_functions.add(caller)
            reverse_queue.append(caller)
    if handler not in reachable_functions:
        return []

    paths: list[str] = []
    queue: deque[tuple[str, list[str]]] = deque([(handler, [])])
    # One shortest prefix per function is sufficient: every continuation from
    # that function is identical in this name-based static graph.  This bounds
    # traversal to O(functions + edges) while retaining a path for each entry
    # point and target location.
    best_depth: dict[str, int] = {handler: 0}
    while queue and len(paths) < max_paths:
        current, hops = queue.popleft()
        if len(hops) >= max_depth:
            continue
        for edge in graph.get(current, []):
            if edge.callee not in reachable_functions:
                continue
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
            next_depth = len(next_hops)
            prior_depth = best_depth.get(edge.callee)
            if next_depth < max_depth and (
                prior_depth is None or next_depth < prior_depth
            ):
                best_depth[edge.callee] = next_depth
                queue.append((edge.callee, next_hops))
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
        static_edges,
        targets,
    )
    static_target_functions = {name for name, _, _ in static_target_definitions}

    related_functions = target_handlers | static_target_functions
    changed = True
    while changed:
        changed = False
        for edge in static_edges:
            if (
                edge.callee in related_functions
                and edge.caller not in related_functions
            ):
                related_functions.add(edge.caller)
                changed = True

    related_entries = []
    related_paths: dict[str, list[str]] = {}
    for entry in recon.entry_points:
        paths = list(recon.entry_to_sink_paths.get(entry.name) or [])
        paths.extend(
            _trace_static_paths(
                entry.handler_function,
                static_target_definitions,
                static_target_locations,
                static_edges,
            )
        )
        paths = list(dict.fromkeys(paths))
        direct_target = (
            entry.type,
            entry.name,
        ) in target_entry_keys or entry.handler_function in target_handlers
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
            if recon.security_profile is not None
            else None
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
                match.group("path"),
                int(match.group("line")),
                column=None,
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
            "reviewer did not cite a source location returned by a plugin read tool"
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
        "coverage_targets": [
            target.model_dump(mode="json") for target in coverage_targets
        ],
    }
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": json.dumps(user_payload, default=str)},
    ]

    handlers = PluginToolHandlers(plugin_root=plugin_path)
    tools: list[dict] = [CONSULT_DEVELOPER_TOOL, *handlers.tool_definitions()]
    max_iterations, force_finalise_after = _specialist_iteration_limits(
        name,
        coverage_targets,
    )
    dynamic_key_trace = (
        name == "authorization_workflows"
        and _requires_dynamic_key_trace(coverage_targets)
    )
    if dynamic_key_trace:
        logger.info(
            "specialist %s.%s: extended trace budget for dynamic field/key write",
            name,
            batch_id,
        )
    result = await runtime.run(
        agent_name=f"{name}.{batch_id}",
        model=model,
        messages=messages,
        tools=tools,
        tool_handlers=handlers.tool_handlers(),
        output_schema=SpecialistReviewArtifact,
        max_iterations=max_iterations,
        force_finalise_after=force_finalise_after,
    )
    primary = _enforce_read_evidence(result.output, handlers, coverage_targets)
    if not _requires_authentication_alternate_path_audit(name, coverage_targets):
        return primary

    alternate_batch_id = f"{batch_id}-alternate"
    primary_hypothesis_counts = Counter(
        hypothesis.id for hypothesis in primary.hypotheses
    )
    linked_primary_ids = {
        hypothesis_id
        for disposition in primary.coverage
        if disposition.status == "candidate"
        and disposition.reviewer == name
        for hypothesis_id in disposition.hypothesis_ids
        if primary_hypothesis_counts[hypothesis_id] == 1
    }
    alternate_payload = dict(user_payload)
    alternate_payload.update(
        {
            "batch_id": alternate_batch_id,
            "hypothesis_id_prefix": alternate_batch_id,
            "already_identified_hypotheses": [
                {
                    "id": hypothesis.id,
                    "bug_class": hypothesis.bug_class.value,
                    "entry_point": hypothesis.entry_point,
                    "file": hypothesis.file,
                    "line": hypothesis.line,
                    "control": hypothesis.evidence_summary.get("control", ""),
                    "boundary": hypothesis.evidence_summary.get("boundary", ""),
                    "reachable_path": hypothesis.evidence_summary.get(
                        "reachable_path", ""
                    ),
                    "preconditions": hypothesis.preconditions,
                }
                for hypothesis in primary.hypotheses
                if hypothesis.id in linked_primary_ids
            ],
        }
    )
    alternate_messages = [
        {
            "role": "system",
            "content": system + _AUTHENTICATION_ALTERNATE_PATH_INSTRUCTIONS,
        },
        {"role": "user", "content": json.dumps(alternate_payload, default=str)},
    ]
    alternate_handlers = PluginToolHandlers(plugin_root=plugin_path)
    alternate_tools: list[dict] = [
        CONSULT_DEVELOPER_TOOL,
        *alternate_handlers.tool_definitions(),
    ]
    logger.info(
        "specialist %s.%s: running independent alternate-path audit",
        name,
        batch_id,
    )
    alternate_result = await runtime.run(
        agent_name=f"{name}.{alternate_batch_id}",
        model=model,
        messages=alternate_messages,
        tools=alternate_tools,
        tool_handlers=alternate_handlers.tool_handlers(),
        output_schema=SpecialistReviewArtifact,
        max_iterations=max_iterations,
        force_finalise_after=force_finalise_after,
    )
    alternate = _enforce_read_evidence(
        alternate_result.output,
        alternate_handlers,
        coverage_targets,
    )
    return _merge_alternate_path_reviews(
        primary,
        alternate,
        coverage_targets,
        name,
    )


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
