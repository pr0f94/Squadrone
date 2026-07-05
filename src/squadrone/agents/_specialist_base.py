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
from .tools import CONSULT_DEVELOPER_TOOL

if TYPE_CHECKING:
    from .runtime import AgentRuntime

logger = logging.getLogger(__name__)


class _HypothesisList(RootModel[list[Hypothesis]]):
    pass


_V2_METHODOLOGY = """

## Squadrone V2 methodology: role-aware workflow review

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
- configuration-dependent findings requiring unsafe admin setup
- self-XSS or own-object-only behavior
- premium/default-disabled paths without current unmodified evidence
- any claim where the actual C/I/A impact cannot be said in one plain sentence

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
    plugin_path: Optional[str] = None,
    priority_files: Optional[list[str]] = None,
) -> HypothesesArtifact:
    cfg = hypothesis_cfg or HypothesisConfig()  # all-False defaults
    parts = [load_prompt(prompt_path), "\n\n", load_prompt("specialists/_shared_rules"), _V2_METHODOLOGY]
    if cfg.specialist_wp_idioms:
        parts.append("\n\n# Reference: WordPress idioms\n\n")
        parts.append(load_prompt("_wp_idioms"))

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
