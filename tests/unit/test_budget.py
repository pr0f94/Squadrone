"""BudgetTracker accumulation + ceiling enforcement."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from wpvulnhunt.services.budget import BudgetExceededError, BudgetTracker


def _usage(prompt: int, completion: int):
    return SimpleNamespace(prompt_tokens=prompt, completion_tokens=completion)


def test_accumulates_under_ceiling():
    bt = BudgetTracker(ceiling_usd=10.0)
    asyncio.run(bt.add(_usage(1000, 1000), "claude-haiku-4-5-20251001"))
    # Haiku: 1000*0.80 + 1000*4.00 = 4800 / 1_000_000 = 0.0048
    assert bt.spent == pytest.approx(0.0048)
    asyncio.run(bt.add(_usage(1000, 1000), "claude-haiku-4-5-20251001"))
    assert bt.spent == pytest.approx(0.0096)


def test_unknown_model_falls_back_to_default():
    bt = BudgetTracker(ceiling_usd=10.0)
    asyncio.run(bt.add(_usage(1000, 1000), "some-unknown-model"))
    # Default rates: 3.0 in, 15.0 out -> (1000*3 + 1000*15)/1M = 0.018
    assert bt.spent == pytest.approx(0.018)


def test_ceiling_raises():
    bt = BudgetTracker(ceiling_usd=0.0001)
    with pytest.raises(BudgetExceededError):
        asyncio.run(bt.add(_usage(1000, 1000), "claude-sonnet-4-5"))


def test_dict_usage_supported():
    bt = BudgetTracker(ceiling_usd=10.0)
    asyncio.run(bt.add({"prompt_tokens": 1000, "completion_tokens": 1000}, "claude-haiku-4-5-20251001"))
    assert bt.spent == pytest.approx(0.0048)


def test_concurrent_add_preserves_total():
    bt = BudgetTracker(ceiling_usd=10.0)

    async def go():
        await asyncio.gather(*[
            bt.add(_usage(100, 100), "claude-haiku-4-5-20251001")
            for _ in range(50)
        ])

    asyncio.run(go())
    # 50 * (100*0.80 + 100*4.00) / 1_000_000 = 50 * 480 / 1e6 = 0.024
    assert bt.spent == pytest.approx(0.024)
