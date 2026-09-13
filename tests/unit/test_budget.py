"""BudgetTracker accumulation + ceiling enforcement."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from squadrone.services import llm
from squadrone.services.budget import BudgetExceededError, BudgetTracker


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


def test_reservation_rejects_call_before_ceiling():
    bt = BudgetTracker(ceiling_usd=0.0001)
    with pytest.raises(BudgetExceededError):
        asyncio.run(bt.reserve("claude-sonnet-4-5", 1000, 1000))


def test_completed_call_is_recorded_without_post_response_raise():
    bt = BudgetTracker(ceiling_usd=0.0001)

    asyncio.run(bt.add(_usage(1000, 1000), "claude-sonnet-4-5"))

    assert bt.spent > bt.ceiling
    assert len(bt.calls) == 1


def test_reservation_is_released_when_usage_is_recorded():
    bt = BudgetTracker(ceiling_usd=1.0)

    reservation = asyncio.run(bt.reserve("claude-sonnet-4-5", 1000, 1000))
    asyncio.run(bt.add(
        _usage(1000, 1000),
        "claude-sonnet-4-5",
        reservation_usd=reservation,
    ))
    second = asyncio.run(bt.reserve("claude-sonnet-4-5", 1000, 1000))

    assert second == pytest.approx(reservation)


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


def test_cost_report_restores_calls_and_cumulative_ceiling(tmp_path):
    first = BudgetTracker(ceiling_usd=0.02)
    asyncio.run(first.add(_usage(1000, 1000), "some-unknown-model", agent="reviewer"))
    first.set_stage("hypothesis")
    asyncio.run(first.add(_usage(100, 100), "some-unknown-model", agent="verifier"))
    first.write_cost_report(tmp_path)

    resumed = BudgetTracker(ceiling_usd=0.02)
    assert resumed.restore_cost_report(tmp_path) == 2
    assert resumed.spent == pytest.approx(first.spent, abs=1e-6)
    assert resumed.input_tokens == first.input_tokens
    assert resumed.output_tokens == first.output_tokens
    assert [record.agent for record in resumed.calls] == ["reviewer", "verifier"]

    with pytest.raises(BudgetExceededError):
        asyncio.run(resumed.reserve("some-unknown-model", 1000, 1000))

    resumed.write_cost_report(tmp_path)
    assert len((tmp_path / "cost_calls.tsv").read_text().splitlines()) == 3


@pytest.mark.asyncio
async def test_llm_budget_is_rejected_before_provider_dispatch(monkeypatch, tmp_path):
    cache_db = str(tmp_path / "llm.sqlite")
    await llm.init_cache(cache_db)
    provider_called = False

    async def fake_provider(_request_kwargs):
        nonlocal provider_called
        provider_called = True
        raise AssertionError("provider must not be called")

    monkeypatch.setattr(llm, "_acompletion_with_retries", fake_provider)

    with pytest.raises(BudgetExceededError):
        await llm.call_llm(
            model="test-model",
            messages=[{"role": "user", "content": "review source"}],
            max_tokens=4096,
            budget_tracker=BudgetTracker(ceiling_usd=0.0001),
            cache_db=cache_db,
        )

    assert not provider_called


@pytest.mark.asyncio
async def test_llm_provider_failure_releases_reserved_budget(monkeypatch, tmp_path):
    cache_db = str(tmp_path / "llm.sqlite")
    await llm.init_cache(cache_db)
    tracker = BudgetTracker(ceiling_usd=1.0)

    async def fake_provider(_request_kwargs):
        raise RuntimeError("provider failed")

    monkeypatch.setattr(llm, "_acompletion_with_retries", fake_provider)

    with pytest.raises(RuntimeError, match="provider failed"):
        await llm.call_llm(
            model="test-model",
            messages=[{"role": "user", "content": "review source"}],
            max_tokens=1000,
            budget_tracker=tracker,
            cache_db=cache_db,
        )

    reservation = await tracker.reserve("test-model", 1000, 1000)
    assert reservation > 0
    await tracker.release(reservation)
