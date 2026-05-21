"""Unit tests for the sliding-window history trim in litellm_transport."""

from __future__ import annotations

from wpvulnhunt.agents.transport.litellm_transport import _trim_history_for_budget


def _cycle(call_id: str, body: str) -> list[dict]:
    """Build a [assistant_with_tool_calls, tool_response] pair."""
    return [
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [{
                "id": call_id,
                "type": "function",
                "function": {"name": "read_plugin_file", "arguments": "{}"},
            }],
        },
        {"role": "tool", "tool_call_id": call_id, "content": body},
    ]


def test_below_threshold_no_trim():
    msgs = [
        {"role": "system", "content": "you are a tool"},
        {"role": "user", "content": "do something"},
        *_cycle("c1", "small result"),
        *_cycle("c2", "another small result"),
    ]
    out, dropped = _trim_history_for_budget(msgs, trim_threshold_bytes=100_000)
    assert dropped == 0
    assert out is msgs  # same reference — no copy when no trim


def test_trims_when_over_threshold():
    # 8 cycles each with a fat body -> well over 80KB
    fat = "X" * 12_000
    msgs = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "task"},
    ]
    for i in range(8):
        msgs.extend(_cycle(f"c{i}", f"result {i}: {fat}"))

    out, dropped = _trim_history_for_budget(msgs, max_keep_tool_cycles=3, trim_threshold_bytes=50_000)
    assert dropped == 5  # 8 - 3 kept
    # Expect: [system, first_user, runtime_note, 3 cycles (6 msgs)] = 9 msgs
    assert len(out) == 1 + 1 + 1 + 3 * 2
    assert out[0]["role"] == "system"
    assert out[1]["role"] == "user" and out[1]["content"] == "task"
    assert out[2]["role"] == "user" and "trimmed" in out[2]["content"]
    # The kept cycles should be the LAST 3: c5, c6, c7
    assert "result 5" in out[4]["content"]
    assert "result 6" in out[6]["content"]
    assert "result 7" in out[8]["content"]


def test_preserves_tail_after_cycles():
    """When a force-finalise user message has been appended after cycles, keep it."""
    fat = "X" * 12_000
    msgs = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "task"},
    ]
    for i in range(7):
        msgs.extend(_cycle(f"c{i}", f"r{i}: {fat}"))
    msgs.append({"role": "user", "content": "now stop investigating and produce final output"})

    out, dropped = _trim_history_for_budget(msgs, max_keep_tool_cycles=2, trim_threshold_bytes=50_000)
    assert dropped == 5
    # Tail must be the last message
    assert out[-1]["content"].startswith("now stop investigating")


def test_complete_cycles_only_dropped():
    """Each kept cycle must contain both its assistant_with_tool_calls and its tool response."""
    fat = "X" * 12_000
    msgs = [{"role": "system", "content": "sys"}, {"role": "user", "content": "task"}]
    for i in range(6):
        msgs.extend(_cycle(f"c{i}", f"r{i}: {fat}"))

    out, _ = _trim_history_for_budget(msgs, max_keep_tool_cycles=3, trim_threshold_bytes=50_000)
    # Walk kept tool cycles in out and ensure every assistant_with_tool_calls is followed by a tool message
    for idx, m in enumerate(out):
        if m.get("role") == "assistant" and m.get("tool_calls"):
            # Must be followed by at least one tool message with matching tool_call_id
            assert idx + 1 < len(out)
            assert out[idx + 1].get("role") == "tool"
            assert out[idx + 1].get("tool_call_id") == m["tool_calls"][0]["id"]


def test_multi_tool_call_cycle_kept_intact():
    """Assistant message with multiple tool_calls must keep ALL matching tool responses together."""
    fat = "X" * 30_000
    multi_cycle = [
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {"id": "ca", "type": "function", "function": {"name": "f", "arguments": "{}"}},
                {"id": "cb", "type": "function", "function": {"name": "f", "arguments": "{}"}},
            ],
        },
        {"role": "tool", "tool_call_id": "ca", "content": "ra"},
        {"role": "tool", "tool_call_id": "cb", "content": "rb"},
    ]
    msgs = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "task"},
        *_cycle("filler1", fat),
        *_cycle("filler2", fat),
        *_cycle("filler3", fat),
        *multi_cycle,
    ]
    out, dropped = _trim_history_for_budget(msgs, max_keep_tool_cycles=1, trim_threshold_bytes=50_000)
    assert dropped == 3
    # The multi-tool cycle must be present in full
    assistant_idx = next(i for i, m in enumerate(out) if m.get("role") == "assistant" and m.get("tool_calls"))
    assert len(out[assistant_idx]["tool_calls"]) == 2
    assert out[assistant_idx + 1]["tool_call_id"] == "ca"
    assert out[assistant_idx + 2]["tool_call_id"] == "cb"


def test_idempotent():
    """Trimming an already-trimmed conversation should be a no-op (or further trim if still big)."""
    fat = "X" * 12_000
    msgs = [{"role": "system", "content": "sys"}, {"role": "user", "content": "task"}]
    for i in range(8):
        msgs.extend(_cycle(f"c{i}", f"r{i}: {fat}"))
    out1, _ = _trim_history_for_budget(msgs, max_keep_tool_cycles=3, trim_threshold_bytes=50_000)
    out2, dropped2 = _trim_history_for_budget(out1, max_keep_tool_cycles=3, trim_threshold_bytes=50_000)
    # After one trim, only 3 cycles remain — second pass has nothing to drop
    assert dropped2 == 0
    assert out2 is out1  # original-reference returned when no trim happened


def test_few_cycles_below_keep_limit_no_trim():
    """Even when over byte threshold, if cycles <= max_keep, do nothing."""
    fat = "X" * 50_000  # single huge cycle
    msgs = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "task"},
        *_cycle("only", fat),
    ]
    out, dropped = _trim_history_for_budget(msgs, max_keep_tool_cycles=3, trim_threshold_bytes=10_000)
    # 1 cycle, max_keep=3 — can't drop, return original
    assert dropped == 0
    assert out is msgs


def test_no_cycles_just_prefix():
    """A conversation with only prefix + a single user reply (no tool cycles) is untouchable."""
    msgs = [
        {"role": "system", "content": "X" * 60_000},
        {"role": "user", "content": "Y" * 60_000},
    ]
    out, dropped = _trim_history_for_budget(msgs, trim_threshold_bytes=10_000)
    assert dropped == 0
    assert out is msgs
