"""AgentRuntime — owns tool dispatch + tracing; runs agents via LiteLLMTransport.

The runtime keeps everything that is transport-agnostic: trace file
management, tool dispatch (`_dispatch_tool`), and the developer-agent
reference. The per-call LLM loop lives in `LiteLLMTransport.run_agent`.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Optional, TYPE_CHECKING

from pydantic import BaseModel

from .transport.base import AgentResult, AgentOutputError
from .transport.litellm_transport import LiteLLMTransport, _strip_fences

__all__ = [
    "AgentRuntime",
    "AgentResult",
    "AgentOutputError",
    "_strip_fences",
]

if TYPE_CHECKING:
    from .developer import DeveloperAgent

logger = logging.getLogger(__name__)


class AgentRuntime:
    def __init__(
        self,
        run_dir: str,
        developer: Optional["DeveloperAgent"] = None,
        developer_calls_per_agent: int = 3,
        budget_tracker=None,
        llm_options: dict | None = None,
        role_reasoning: dict | None = None,
    ):
        self.run_dir = Path(run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.trace_path = self.run_dir / "trace.jsonl"
        self.developer = developer
        self.developer_calls_per_agent = developer_calls_per_agent
        self.budget_tracker = budget_tracker
        self.llm_options = dict(llm_options or {})
        self.role_reasoning = {
            role: effort for role, effort in (role_reasoning or {}).items()
            if effort is not None
        }

    @staticmethod
    def _role_for_agent(agent_name: str) -> str:
        base = agent_name.split(".", 1)[0]
        if base in {"auth", "auth_flow", "cross_file_xss", "file_ops", "injection", "logic_flaw", "ssrf_deser", "xss"}:
            return "specialists"
        if base == "claim_validator":
            return "reporter"
        if base == "entry_point_validator":
            return "hypothesis_verifier"
        return base

    def llm_options_for_agent(self, agent_name: str) -> dict:
        opts = dict(self.llm_options)
        role = self._role_for_agent(agent_name)
        effort = self.role_reasoning.get(role)
        if effort is not None:
            opts["reasoning_effort"] = effort
        return opts

    def _trace(self, agent_name: str, kind: str, payload: dict) -> None:
        record = {"ts": time.time(), "agent": agent_name, "kind": kind, **payload}
        with self.trace_path.open("a") as f:
            f.write(json.dumps(record, default=str) + "\n")

    async def _dispatch_tool(
        self,
        agent_name: str,
        tool_name: str,
        arguments: dict,
        dev_calls: list[int],
        extra_handlers: Optional[dict] = None,
        call_history: Optional[dict] = None,
    ) -> str:
        dedup_key: Optional[tuple] = None
        if call_history is not None:
            try:
                args_canon = json.dumps(arguments, sort_keys=True, default=str)
            except (TypeError, ValueError):
                args_canon = str(arguments)
            dedup_key = (tool_name, args_canon)
            if dedup_key in call_history:
                prior = call_history[dedup_key]
                self._trace(agent_name, "tool_call", {
                    "tool": tool_name, "args": arguments, "deduped": True,
                })
                return (
                    f"[runtime] DUPLICATE: you already called {tool_name} with these arguments "
                    f"in this session. The earlier result was {len(prior)} chars long; refer to "
                    f"your prior reading. Do NOT call this again — read a different file or write "
                    f"the script with what you have. Brief recap of prior result: "
                    f"{prior[:300]!r}"
                )

        if extra_handlers and tool_name in extra_handlers:
            try:
                result = extra_handlers[tool_name](arguments)
                if hasattr(result, "__await__"):
                    result = await result
                result_str = str(result)
                self._trace(agent_name, "tool_call", {"tool": tool_name, "args": arguments, "result": result_str})
                if dedup_key is not None and call_history is not None:
                    call_history[dedup_key] = result_str
                return result_str
            except Exception as e:
                msg = f"[runtime] tool {tool_name} raised: {e}"
                self._trace(agent_name, "tool_call", {"tool": tool_name, "args": arguments, "error": str(e)})
                return msg
        if tool_name == "consult_developer":
            if dev_calls[0] >= self.developer_calls_per_agent:
                return (
                    "Developer consultation limit reached for this turn. "
                    "Make your best assessment from the code you have."
                )
            if self.developer is None:
                return "Developer agent unavailable."
            dev_calls[0] += 1
            answer = await self.developer.consult(
                question=arguments.get("question", ""),
                code_snippet=arguments.get("code_snippet", ""),
                context=arguments.get("context"),
            )
            self._trace(agent_name, "developer_call", {
                "n": dev_calls[0],
                "question": arguments.get("question", ""),
                "code_snippet": arguments.get("code_snippet", ""),
                "context": arguments.get("context") or "",
                "answer": answer,
            })
            if dedup_key is not None and call_history is not None:
                call_history[dedup_key] = answer
            return answer
        return f"[runtime] unknown tool: {tool_name}"

    async def run(
        self,
        agent_name: str,
        model: str,
        messages: list[dict],
        tools: Optional[list[dict]] = None,
        max_iterations: int = 10,
        output_schema: Optional[type[BaseModel]] = None,
        tool_handlers: Optional[dict] = None,
        force_finalise_after: Optional[int] = None,
        max_tokens: int = 16384,
    ) -> AgentResult:
        return await LiteLLMTransport().run_agent(
            runtime=self,
            agent_name=agent_name,
            model=model,
            messages=messages,
            tools=tools,
            max_iterations=max_iterations,
            output_schema=output_schema,
            tool_handlers=tool_handlers,
            force_finalise_after=force_finalise_after,
            max_tokens=max_tokens,
        )
