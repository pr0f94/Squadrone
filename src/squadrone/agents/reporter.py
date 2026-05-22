"""Reporter — drafts a markdown advisory from a verified Finding.

One template per bounty program. The right template is selected by the caller via
`program=` so a single Finding can yield multiple submission-shaped reports if it
qualified for multiple programs at triage time.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..schemas.finding import Finding
from .prompts_io import load_prompt

if TYPE_CHECKING:
    from .runtime import AgentRuntime


PROGRAM_PROMPTS = {
    "wordfence": "reporter_wordfence",
    "patchstack": "reporter_patchstack",
}


class ReporterAgent:
    NAME = "reporter"

    def __init__(self, runtime: "AgentRuntime", model: str):
        self.runtime = runtime
        self.model = model

    async def write(
        self,
        finding: Finding,
        plugin_slug: str,
        plugin_version: str | None = None,
        code_slice: str | None = None,
        program: str = "wordfence",
    ) -> str:
        prompt_name = PROGRAM_PROMPTS.get(program)
        if prompt_name is None:
            raise ValueError(f"Unknown bounty program {program!r}; expected one of {list(PROGRAM_PROMPTS)}")
        system = load_prompt(prompt_name)
        parts = [f"PLUGIN_SLUG: {plugin_slug}"]
        if plugin_version:
            parts.append(f"PLUGIN_VERSION: {plugin_version}")
        if code_slice:
            parts.append(
                "VERIFIED_SOURCE_SLICE (the actual code at the cited file:line — "
                "ground all sink/taint claims in this, NOT in the hypothesis taint_path which may be wrong):\n"
                f"```php\n{code_slice}\n```"
            )
        parts.append(f"FINDING:\n{finding.model_dump_json(indent=2)}")
        user = "\n\n".join(parts)
        result = await self.runtime.run(
            agent_name=self.NAME,
            model=self.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        text = str(result.output).strip()
        if text.startswith("```"):
            lines = text.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip().startswith("```"):
                lines = lines[:-1]
            text = "\n".join(lines)
        return text
