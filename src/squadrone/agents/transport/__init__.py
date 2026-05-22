"""LLM agent transport — LiteLLM only.

A single implementation (`LiteLLMTransport`) wraps LiteLLM's
`acompletion()` in a tool-use agent loop. LiteLLM handles provider routing
(Anthropic, OpenAI, Gemini, Bedrock, Vertex, ChatGPT-subscription, etc.)
so no other transport is necessary.
"""

from .base import AgentResult, AgentOutputError
from .litellm_transport import LiteLLMTransport

__all__ = ["AgentResult", "AgentOutputError", "LiteLLMTransport"]
