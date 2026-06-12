"""Shared specialist runner — every specialist follows the same pattern."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Optional

from pydantic import RootModel

from ..schemas.config import HypothesisConfig
from ..schemas.hypothesis import Hypothesis, HypothesesArtifact
from ..schemas.recon import ReconArtifact
from .plugin_tools import PluginToolHandlers
from .prompts_io import load_prompt
from .tools import CONSULT_DEVELOPER_TOOL, READ_PLUGIN_FILE_TOOL

if TYPE_CHECKING:
    from .runtime import AgentRuntime

logger = logging.getLogger(__name__)


class _HypothesisList(RootModel[list[Hypothesis]]):
    pass


# Stage-3 prompt extensions — appended conditionally to the specialist system prompt
# based on HypothesisConfig toggles. Kept here (rather than in separate .md files)
# because they're short, structured, and tightly coupled to the toggle semantics.

_S3_BRANCH_ENUMERATION = """

## S3: Mandatory branch enumeration

For each hypothesis, enumerate ALL forward-flowing branches from the entry point to
the sink in `taint_path_branches`. Each branch is a list of "step descriptions".

If the same entry handler has multiple call sites that reach different sinks (or
different shapes of the same sink), each is a separate branch. If you find only
one branch, that's fine — but you must explicitly populate the field.

Example:
```json
"taint_path_branches": [
  ["$_POST['action'] -> handle_ajax", "switch case 'foo' -> wp_statistics_visitor($atts['time'])", "$wpdb->get_var($sql)"],
  ["$_POST['action'] -> handle_ajax", "switch case 'bar' -> wp_statistics_useronline($atts['platform'])", "$wpdb->query($sql)"]
]
```
"""

_S4_EXPLOIT_CLASSIFICATION = """

## S4: Direct vs chained vs config-gated self-classification

In `exploit_classification`, output:
```json
{
  "type": "direct" | "chained" | "gated_by_external_config",
  "secondary_primitive_required": "<description of the OTHER bug needed>" (only when type=chained),
  "config_required": "<description of non-default config needed>" (only when type=gated_by_external_config),
  "realistic_in_default_install": true | false
}
```

- `direct` = exploitable on a default install with no other bugs
- `chained` = needs a separate primitive (e.g. SQLi elsewhere, arbitrary option write)
- `gated_by_external_config` = needs a non-default site setting (e.g. SVG enabled, registration enabled)

If you produce a `chained` hypothesis, BE EXPLICIT about what other bug is needed.
The triage stage will likely reject chained hypotheses unless the secondary primitive
is also discoverable in this same plugin.
"""

_S5_BOUNTY_FIT = """

## S5: Bounty-fit pre-tagging

In `bounty_fit`, output your tentative scope assessment:
```json
{
  "wordfence_tier": "high_threat" | "stored_xss_sqli" | "all_other" | "not_applicable",
  "wordfence_install_floor_satisfied": true | false | "unknown",
  "patchstack_cvss_estimate": <float, e.g. 6.5>,
  "patchstack_floor_satisfied": true | false | "unknown",
  "realistic_payout_likelihood": "high" | "medium" | "low" | "none"
}
```

If you don't know the install count, set `wordfence_install_floor_satisfied: "unknown"` —
triage will resolve. Use `realistic_payout_likelihood: "none"` for hypotheses that
fall under Wordfence rule 124 (missing-authz without consequential CIA impact) or
WPScan-equivalent enumeration findings.
"""

_S7_SELF_CRITIQUE = """

## S7: Self-critique before emitting

For EACH hypothesis you would emit, ask: "is every load-bearing claim in `reasoning`
either (a) directly visible in `code_slices`, or (b) something I read with
`read_plugin_file` and can quote at file:line?". If a claim rests on training-data
recall about a WP function's behaviour, set `requires_verification: true` and note
the unverified claim in `reasoning`.

Examples that demand verification:
- "esc_url() does not encode single quotes" → check WP core, do not recall
- "any logged-in user can compute the nonce via wp_create_nonce" → factually wrong
  (nonces are user-bound); set requires_verification=true if you find yourself
  about to emit such a claim
- "wp_ajax_X is gated to admin by WordPress" → factually wrong; same handling
"""


_V2_METHODOLOGY = """

## Squadrone V2 methodology: role-aware workflow review

Do not behave like a sink-only scanner. For every candidate, prove a concrete
security story:

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

Use `recon.security_profile` when present. It summarizes plugin type, sensitive
objects, custom roles/capabilities, state-changing workflows, payment/webhook
routes, import/export routes, and stored-input-to-privileged-view paths. Treat it
as a focus map, not proof: still cite exact code for every hypothesis.

Reject weak shapes before emitting:
- admin-only behavior with no privilege boundary
- public analytics/view-count manipulation
- logout or notice-dismissal CSRF
- fixed/public asset reads such as constrained `style.css`
- configuration-dependent findings requiring unsafe admin setup
- self-XSS or own-object-only behavior
- premium/default-disabled paths without current unmodified evidence

Prefer fewer, stronger hypotheses. A useful empty list is better than a noisy
set of maybe-bugs.
"""


_TOOL_LOOP_EXPLORATION_INSTRUCTIONS = """

## Source-exploration tools

You have three plugin-scoped tools; use them to fetch any source you need
instead of expecting it inline:

- `grep_plugin(pattern, path_glob=?, max_results=?, context_lines=?, case_insensitive=?)`
- `glob_plugin(pattern, max_results=?)`
- `read_plugin_file(path, start_line=?, end_line=?, max_lines=?)`

The user message lists only the entry-points and sinks the surveyor identified.
When the user message includes `priority_files`, inspect those files first. They
are a heuristic shortlist for your bug class, not a sandbox: you may still grep
or read other plugin files when a call chain, helper, template, or JavaScript
consumer is needed to validate or reject a hypothesis.

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

The cost of being conservative (dropping a real bug) is much lower than the
cost of asserting a false positive that gets dropped at verification.
"""


async def run_specialist(
    *,
    runtime: "AgentRuntime",
    name: str,
    prompt_path: str,
    model: str,
    recon: ReconArtifact,
    code_slices: dict[str, str],
    hypothesis_cfg: Optional[HypothesisConfig] = None,
    diff_summary: Optional[str] = None,
    plugin_path: Optional[str] = None,
    priority_files: Optional[list[str]] = None,
) -> HypothesesArtifact:
    cfg = hypothesis_cfg or HypothesisConfig()  # all-False defaults
    parts = [load_prompt(prompt_path), "\n\n", load_prompt("specialists/_shared_rules"), _V2_METHODOLOGY]
    if cfg.specialist_wp_idioms:
        parts.append("\n\n# Reference: WordPress idioms\n\n")
        parts.append(load_prompt("_wp_idioms"))
    if cfg.require_branch_enumeration:
        parts.append(_S3_BRANCH_ENUMERATION)
    if cfg.require_exploit_classification:
        parts.append(_S4_EXPLOIT_CLASSIFICATION)
    if cfg.require_bounty_fit_pretagging:
        parts.append(_S5_BOUNTY_FIT)
    if cfg.self_critique_pass:
        parts.append(_S7_SELF_CRITIQUE)

    tool_loop_mode = plugin_path is not None
    if tool_loop_mode:
        parts.append(_TOOL_LOOP_EXPLORATION_INSTRUCTIONS)
    system = "".join(parts)

    # In tool-loop mode the user payload is slim: recon (entry points + sinks)
    # only, no inline code_slices. The specialist pulls source via tools.
    user_payload: dict = {
        "plugin_slug": recon.plugin_slug,
        "recon": recon.model_dump(),
    }
    if priority_files:
        user_payload["priority_files"] = priority_files
    if not tool_loop_mode:
        user_payload["code_slices"] = code_slices
    if diff_summary:
        user_payload["diff_summary"] = diff_summary
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": json.dumps(user_payload, default=str)},
    ]

    tools: list[dict] = [CONSULT_DEVELOPER_TOOL]
    tool_handlers: dict = {}
    if tool_loop_mode:
        handlers = PluginToolHandlers(plugin_root=plugin_path)
        tools.extend(handlers.tool_definitions())
        tool_handlers.update(handlers.tool_handlers())
    elif cfg.specialist_grep_read_tools:
        tools.append(READ_PLUGIN_FILE_TOOL)

    result = await runtime.run(
        agent_name=name,
        model=model,
        messages=messages,
        tools=tools,
        tool_handlers=tool_handlers or None,
        output_schema=_HypothesisList,
        max_iterations=25 if tool_loop_mode else 10,
        force_finalise_after=15 if tool_loop_mode else None,
    )
    hypotheses: list[Hypothesis] = result.output.root
    return HypothesesArtifact(plugin_slug=recon.plugin_slug, hypotheses=hypotheses)
