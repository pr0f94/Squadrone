"""Shared agent-result types used by LiteLLMTransport."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class AgentOutputError(RuntimeError):
    """Raised when the LLM cannot produce schema-valid output after one retry."""


class AgentResult(BaseModel):
    output: Any
    token_usage: dict
    developer_calls_made: int
    iterations: int
