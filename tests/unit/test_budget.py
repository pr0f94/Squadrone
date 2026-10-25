"""BudgetTracker accumulation + ceiling enforcement."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from squadrone.services import llm
from squadrone.services.budget import BudgetExceededError, BudgetTracker, COST_PER_1M


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


@pytest.mark.parametrize("as_object", [False, True])
@pytest.mark.parametrize(
    "usage",
    [
        # LiteLLM normalized prompt_tokens includes both cache categories.
        {
            "prompt_tokens": 1700, "completion_tokens": 100,
            "cache_creation_input_tokens": 200, "cache_read_input_tokens": 500,
        },
        # Native Anthropic input_tokens excludes both cache categories.
        {
            "input_tokens": 1000, "output_tokens": 100,
            "cache_creation_input_tokens": 200, "cache_read_input_tokens": 500,
        },
        # Some normalized responses retain native counts as well.
        {
            "prompt_tokens": 1700, "completion_tokens": 100,
            "input_tokens": 1000, "output_tokens": 100,
            "cache_creation_input_tokens": 200, "cache_read_input_tokens": 500,
            "prompt_tokens_details": {"cached_tokens": 500, "cache_creation_tokens": 200},
        },
        # Normalized cache details can be the only source of cache counts.
        {
            "prompt_tokens": 1700, "completion_tokens": 100,
            "prompt_tokens_details": {"cached_tokens": 500, "cache_creation_tokens": 200},
        },
        # Resolve cache reads independently when only writes are top-level.
        {
            "prompt_tokens": 1700, "completion_tokens": 100,
            "cache_creation_input_tokens": 200,
            "prompt_tokens_details": {"cached_tokens": 500},
        },
    ],
)
def test_route_prices_normalize_native_and_litellm_cache_usage(usage, as_object):
    if as_object:
        usage = SimpleNamespace(**usage)
        if hasattr(usage, "prompt_tokens_details"):
            usage.prompt_tokens_details = SimpleNamespace(**usage.prompt_tokens_details)
    tracker = BudgetTracker(ceiling_usd=1)
    pricing = {
        "input_per_million": 2, "output_per_million": 8,
        "cache_read_per_million": 0.2, "cache_write_per_million": 4,
    }

    asyncio.run(tracker.add(usage, "shared-provider-model", pricing=pricing))

    assert tracker.spent == pytest.approx(0.0037)
    assert tracker.input_tokens == 1000
    assert tracker.output_tokens == 100
    assert tracker.cache_read_tokens == 500
    assert tracker.cache_write_tokens == 200
    assert tracker.cache_hit_rate == pytest.approx(500 / 1700)
    record = tracker.calls[0]
    assert (record.input_tokens, record.cache_read_tokens, record.cache_write_tokens) == (1000, 500, 200)


def test_zero_normalized_counts_do_not_fall_back_to_native_counts():
    tracker = BudgetTracker(ceiling_usd=1)

    asyncio.run(tracker.add({
        "prompt_tokens": 0, "completion_tokens": 0,
        "input_tokens": 1000, "output_tokens": 1000,
    }, "some-unknown-model"))

    assert tracker.spent == 0
    assert tracker.input_tokens == tracker.output_tokens == 0


@pytest.mark.parametrize("cache_price", [None, 0])
def test_route_cache_prices_default_only_when_not_supplied(cache_price):
    tracker = BudgetTracker(ceiling_usd=1)
    pricing = {
        "input_per_million": 2, "output_per_million": 8,
        "cache_read_per_million": cache_price,
        "cache_write_per_million": cache_price,
    }
    asyncio.run(tracker.add({
        "input_tokens": 1000, "output_tokens": 100,
        "cache_creation_input_tokens": 200, "cache_read_input_tokens": 500,
    }, "some-unknown-model", pricing=pricing))

    assert tracker.spent == pytest.approx(0.0034 if cache_price is None else 0.0028)


def test_route_prices_do_not_leak_between_calls_or_change_legacy_rates():
    tracker = BudgetTracker(ceiling_usd=1)
    legacy_rates = {model: dict(rates) for model, rates in COST_PER_1M.items()}

    async def charge_routes():
        await asyncio.gather(
            tracker.add(_usage(1000, 1000), "claude-sonnet-4-5", agent="custom", pricing={
                "input_per_million": 1, "output_per_million": 2,
            }),
            tracker.add(_usage(1000, 1000), "claude-sonnet-4-5", agent="legacy"),
        )

    asyncio.run(charge_routes())

    assert {call.agent: call.cost_usd for call in tracker.calls} == pytest.approx({
        "custom": 0.003, "legacy": 0.018,
    })
    assert COST_PER_1M == legacy_rates


@pytest.mark.parametrize("cache_write,expected", [(4, 0.0048), (1, 0.0028)])
def test_route_reservations_cover_expensive_cache_writes(cache_write, expected):
    tracker = BudgetTracker(ceiling_usd=1)
    pricing = {
        "input_per_million": 2, "output_per_million": 8,
        "cache_write_per_million": cache_write,
    }

    reservation = asyncio.run(tracker.reserve("some-unknown-model", 1000, 100, pricing=pricing))

    assert reservation == pytest.approx(expected)
    assert BudgetTracker.estimate_call_cost("some-unknown-model", 1000, 100, pricing=pricing) == pytest.approx(expected)


def test_route_reservation_defaults_to_cache_write_multiplier_and_releases():
    tracker = BudgetTracker(ceiling_usd=0.0034)
    pricing = {"input_per_million": 2, "output_per_million": 8}

    async def reserve_and_charge():
        reservation = await tracker.reserve("some-unknown-model", 1000, 100, pricing=pricing)
        assert reservation == pytest.approx(0.0033)
        await tracker.add(_usage(1000, 100), "some-unknown-model", reservation_usd=reservation, pricing=pricing)
        # Only the actual 0.0028 charge remains; no reservation is leaked.
        return await tracker.reserve("some-unknown-model", 200, 0, pricing=pricing)

    assert asyncio.run(reserve_and_charge()) == pytest.approx(0.0005)


def test_route_cache_write_price_can_reject_otherwise_affordable_call():
    tracker = BudgetTracker(ceiling_usd=0.0045)

    with pytest.raises(BudgetExceededError):
        asyncio.run(tracker.reserve("some-unknown-model", 1000, 100, pricing={
            "input_per_million": 2, "output_per_million": 8,
            "cache_write_per_million": 4,
        }))


@pytest.mark.parametrize("price", [-1, float("inf"), float("nan")])
def test_invalid_route_price_is_rejected_without_budget_mutation(price):
    tracker = BudgetTracker(ceiling_usd=1)

    with pytest.raises(ValueError, match="invalid per-million token price"):
        asyncio.run(tracker.add(_usage(1000, 1000), "some-unknown-model", pricing={
            "input_per_million": price, "output_per_million": 8,
        }))

    assert tracker.spent == 0
    assert tracker.calls == []


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
