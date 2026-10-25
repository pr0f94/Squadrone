"""Invocation-scoped conversation identities for model calls and nested agents."""

from __future__ import annotations

from contextvars import ContextVar
from dataclasses import dataclass
from functools import wraps
from typing import Awaitable, Callable, ParamSpec, TypeVar
from uuid import uuid4


@dataclass(frozen=True)
class ConversationContext:
    conversation_id: str
    parent_conversation_id: str | None = None


_conversation: ContextVar[ConversationContext | None] = ContextVar(
    "squadrone_llm_conversation", default=None
)
_P = ParamSpec("_P")
_R = TypeVar("_R")


def current_conversation() -> ConversationContext | None:
    return _conversation.get()


def new_conversation(
    function: Callable[_P, Awaitable[_R]],
) -> Callable[_P, Awaitable[_R]]:
    """Give one agent invocation its own identity, including all repair turns.

    Context variables keep concurrent invocations separate and retain the parent
    identity when a tool starts a nested agent. The context is restored on errors
    and cancellation as well as successful completion.
    """

    @wraps(function)
    async def wrapped(*args: _P.args, **kwargs: _P.kwargs) -> _R:
        parent = current_conversation()
        token = _conversation.set(
            ConversationContext(
                conversation_id=uuid4().hex,
                parent_conversation_id=parent.conversation_id if parent else None,
            )
        )
        try:
            return await function(*args, **kwargs)
        finally:
            _conversation.reset(token)

    return wrapped
