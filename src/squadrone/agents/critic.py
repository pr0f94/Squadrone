"""Critic — adversarial reviewer over specialist hypotheses."""

from __future__ import annotations

import json
import logging
from typing import Annotated, TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictStr

from ..schemas.hypothesis import HypothesesArtifact, Hypothesis, TriagedArtifact
from ..schemas.php_object_gadget import PhpObjectGadgetRecipe
from ..schemas.taxonomy import (
    critic_evidence_contract_for,
    get_known_cwe_profile,
)
from .plugin_tools import PluginToolHandlers
from .prompts_io import load_prompt
from .tools import CONSULT_DEVELOPER_TOOL

if TYPE_CHECKING:
    from .runtime import AgentRuntime

logger = logging.getLogger(__name__)


class _StrictRecipeCompletionModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PhpObjectGadgetRecipeV1Completion(_StrictRecipeCompletionModel):
    """One source-reviewed v1 recipe returned by the bounded completion pass."""

    hypothesis_id: StrictStr = Field(min_length=1, max_length=512)
    outcome: Literal["recipe_v1"]
    recipe: PhpObjectGadgetRecipe
    violated_rule: None = None
    reason: StrictStr = Field(min_length=1, max_length=2000)


class PhpObjectGadgetUnrepresentableV1Completion(_StrictRecipeCompletionModel):
    """An explicit reason a reviewed natural gadget is outside closed recipe v1."""

    hypothesis_id: StrictStr = Field(min_length=1, max_length=512)
    outcome: Literal["unrepresentable_v1"]
    recipe: None = None
    violated_rule: StrictStr = Field(min_length=1, max_length=1000)
    reason: StrictStr = Field(min_length=1, max_length=2000)


class PhpObjectGadgetIncompleteSourceReviewCompletion(_StrictRecipeCompletionModel):
    """A fail-closed signal that the bounded pass lacks a required source read."""

    hypothesis_id: StrictStr = Field(min_length=1, max_length=512)
    outcome: Literal["incomplete_source_review"]
    recipe: None = None
    violated_rule: None = None
    needed_context: StrictStr = Field(min_length=1, max_length=2000)
    reason: StrictStr = Field(min_length=1, max_length=2000)


PhpObjectGadgetRecipeCompletion = Annotated[
    PhpObjectGadgetRecipeV1Completion
    | PhpObjectGadgetUnrepresentableV1Completion
    | PhpObjectGadgetIncompleteSourceReviewCompletion,
    Field(discriminator="outcome"),
]


class PhpObjectGadgetRecipeCompletions(_StrictRecipeCompletionModel):
    """Exact, batch-accounted response from one recipe-completion pass."""

    plugin_slug: StrictStr = Field(min_length=1, max_length=512)
    completions: tuple[PhpObjectGadgetRecipeCompletion, ...] = Field(max_length=128)


_ADVERSARIAL_INSTRUCTIONS = """

# Adversarial review

Every triage pass must include a rejection attempt before accepting a
hypothesis. For each hypothesis, ask:

1. What is the strongest technical reason this is not exploitable?
2. Is attacker control actually proven from source to sink?
3. Is the lowest claimed role realistic?
4. Is the affected feature enabled by default and present in the current
   unmodified component?
5. Is there a concrete security impact, not just weird behavior?
6. Is object ownership/approval/token binding actually violated?

If the hypothesis survives those questions, accept it. If it does not, reject
with the clearest failure reason. Prefer a useful rejection over a weak manual
queue item.
"""


_RECIPE_COMPLETION_INSTRUCTIONS = """

# Bounded PHP object gadget recipe-completion pass

This is a single, focused completion pass over already accepted CWE-502
hypotheses whose independently reviewed `evidence_summary.usable_gadget` value
is the strict JSON boolean `true`, but whose optional recipe is null. Do not
re-triage, reject, merge, rewrite, or broaden any hypothesis.

For every supplied hypothesis, return exactly one completion. Return
`outcome: recipe_v1` only when the natural gadget is exactly representable by
the closed `PhpObjectGadgetRecipe` v1 contract below, with complete exact source
anchors. Otherwise return `outcome: unrepresentable_v1`, leave `recipe` null,
and name one specific violated v1 rule in `violated_rule`; do not use vague
uncertainty or missing-time language. Never approximate a recipe, invent source,
or include model-authored serialized bytes, paths, callbacks, references, or
nested objects.

For a `list_item` direct-path binding, write `effect_variable` as the bare PHP
identifier without a leading `$`. Its `iteration_anchor` must quote the complete
braced `foreach` region, from the loop declaration through its matching closing
brace, including the `local_path_check.guard_anchor` and `effect_anchor` nested
inside it.

Apply immutability exclusions to the dataflow prefix ending at the classified
primary `unlink`. Code after that sink cannot retroactively alter its consumed
operand, so unrelated or post-sink cleanup is not by itself a v1 violation.
Treat a dynamic write or `unset` as disqualifying only when it can mutate,
alias, or rebind the effect property or iteration variable before that sink.

A guarded sibling deletion uses v1's strict zero-offset `strpos(...) === 0`
prefix binding for `basename_prefix + opaque_generation_id + basename_suffix`.
That is the exact guarded-prefix contract; do not require whole-string equality.

Missing or unread source context is not a v1 contract violation. Prioritise
batched `read_plugin_ranges` calls for complete trigger and helper bodies, and
use the available source tools to locate and read every required complete anchor
before finalising. Never return `unrepresentable_v1` merely because an anchor
was not included in an initial range or has not yet been inspected; that outcome
must name a source-proven rule the reviewed chain actually violates. If a
required read still could not be completed, return `incomplete_source_review`
with the exact `needed_context` and reason. That is an internal fail-closed
diagnostic, not an unrepresentable recipe decision.

Use only plugin source. Consolidate source reads because this pass is bounded.
The runner independently source-validates every returned recipe and fails the
stage on an invalid recipe. The earlier instruction to output a TriagedArtifact
does not apply to this focused pass. Output only the completion object matching
the exact completion schema appended below.
"""


def _evidence_contract_payload(hypotheses: HypothesesArtifact) -> dict[str, object]:
    """Render only the trusted taxonomy contracts used by this critic batch."""
    bug_classes = {hypothesis.bug_class for hypothesis in hypotheses.hypotheses}

    contracts: list[dict[str, object]] = []
    for bug_class in sorted(bug_classes, key=lambda item: item.value):
        profile = get_known_cwe_profile(bug_class)
        contract = critic_evidence_contract_for(bug_class)
        contracts.append(
            {
                "bug_class": bug_class.value,
                "family": profile.family if profile is not None else "open_unmapped",
                "contract_source": (
                    "known_taxonomy_profile"
                    if profile is not None
                    else "open_cwe_fallback"
                ),
                "acceptance_mode": contract.acceptance_mode,
                "acceptance_requirements": list(contract.acceptance_requirements),
                "required_evidence": [
                    {
                        "path": requirement.path,
                        "json_type": requirement.json_type,
                        "required_value": requirement.required_value,
                        "source_requirement": requirement.source_requirement,
                    }
                    for requirement in contract.required_evidence
                ],
                "non_evidence": list(contract.non_evidence),
            }
        )
    return {"schema_version": 1, "contracts": contracts}


class CriticAgent:
    NAME = "critic"
    PROMPT = "critic"

    def __init__(self, runtime: "AgentRuntime", model: str):
        self.runtime = runtime
        self.model = model

    def _build_system_prompt(self, hypotheses: HypothesesArtifact) -> str:
        contracts = json.dumps(
            _evidence_contract_payload(hypotheses),
            indent=2,
            sort_keys=True,
        )
        return (
            load_prompt(self.PROMPT)
            + _ADVERSARIAL_INSTRUCTIONS
            + "\n# Active contracts for this batch\n\n```json\n"
            + contracts
            + "\n```\n"
        )

    async def review(
        self,
        hypotheses: HypothesesArtifact,
        code_slices: dict[str, str],
        plugin_path: str | None = None,
    ) -> TriagedArtifact:
        system = self._build_system_prompt(hypotheses)
        user_payload: dict = {
            "plugin_slug": hypotheses.plugin_slug,
            "hypotheses": hypotheses.model_dump()["hypotheses"],
            "code_slices": code_slices,
        }
        user_parts = [json.dumps(user_payload, default=str)]
        # Disclosure eligibility is deterministic and runs after this technical
        # review. The critic must not turn a valid vulnerability into a false
        # positive merely because one program would not accept it.
        user = "\n\n".join(user_parts)

        tools = [CONSULT_DEVELOPER_TOOL]
        tool_handlers = None
        if plugin_path:
            handlers = PluginToolHandlers(plugin_path)
            tools.extend(handlers.tool_definitions())
            tool_handlers = handlers.tool_handlers()
        result = await self.runtime.run(
            agent_name=self.NAME,
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            tools=tools,
            tool_handlers=tool_handlers,
            output_schema=TriagedArtifact,
        )
        art: TriagedArtifact = result.output
        return art

    async def complete_php_object_gadget_recipes(
        self,
        plugin_slug: str,
        hypotheses: list[Hypothesis],
        code_slices: dict[str, str],
        plugin_path: str,
    ) -> PhpObjectGadgetRecipeCompletions:
        """Run one budget-accounted, source-scoped completion for a target batch."""
        completion_schema = json.dumps(
            PhpObjectGadgetRecipeCompletions.model_json_schema(),
            indent=2,
            sort_keys=True,
        )
        system = (
            load_prompt(self.PROMPT)
            + _RECIPE_COMPLETION_INSTRUCTIONS
            + "\n# Exact completion response and embedded "
            "PhpObjectGadgetRecipe v1 JSON Schema\n\n```json\n"
            + completion_schema
            + "\n```\n"
        )
        payload = {
            "plugin_slug": plugin_slug,
            "hypotheses": [
                hypothesis.model_dump(mode="json") for hypothesis in hypotheses
            ],
            "code_slices": code_slices,
        }
        handlers = PluginToolHandlers(plugin_path)
        result = await self.runtime.run(
            agent_name=f"{self.NAME}.php_object_gadget_recipe_completion",
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": json.dumps(payload, default=str)},
            ],
            tools=handlers.tool_definitions(),
            tool_handlers=handlers.tool_handlers(),
            output_schema=PhpObjectGadgetRecipeCompletions,
            max_iterations=10,
            force_finalise_after=8,
            force_finalise_allowed_tools=set(),
        )
        completions: PhpObjectGadgetRecipeCompletions = result.output
        return completions
