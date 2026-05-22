"""Unit tests for _parse_json_resilient — the LLM-output JSON parser."""

from __future__ import annotations

from squadrone.agents.developer import _parse_json_resilient, _autoclose_unbalanced


# ----- happy path ---------------------------------------------------------

def test_plain_valid_json():
    out = _parse_json_resilient('{"a": 1, "b": "x"}')
    assert out == {"a": 1, "b": "x"}


def test_empty_returns_none():
    assert _parse_json_resilient("") is None
    assert _parse_json_resilient(None) is None  # type: ignore[arg-type]


def test_non_dict_returns_none():
    # Top-level array, valid JSON but not a dict
    assert _parse_json_resilient('[1, 2, 3]') is None


# ----- existing fallbacks ------------------------------------------------

def test_markdown_fence_stripped():
    content = '```json\n{"ok": true}\n```'
    out = _parse_json_resilient(content)
    assert out == {"ok": True}


def test_leading_prose_then_json():
    content = 'Here is my answer:\n{"failure_class": "setup"}\nthanks'
    out = _parse_json_resilient(content)
    assert out == {"failure_class": "setup"}


def test_trailing_extra_data():
    content = '{"a": 1}{"b": 2}'  # second object after first
    out = _parse_json_resilient(content)
    assert out == {"a": 1}


def test_missing_outer_array_close():
    """Recovers a missing outer array close in an otherwise valid object."""
    content = (
        '{"failure_class":"setup","rationale":"reseed","commands":[["eval","echo 1;"]}'
    )
    # 2 [, 1 ] — should autoclose to add the missing ]
    out = _parse_json_resilient(content)
    assert out is not None
    assert out["failure_class"] == "setup"
    assert out["commands"] == [["eval", "echo 1;"]]


def test_missing_closing_brace():
    content = '{"a": 1, "b": {"c": 2}'  # missing final }
    out = _parse_json_resilient(content)
    assert out == {"a": 1, "b": {"c": 2}}


def test_missing_both_kinds():
    content = '{"a": [{"b": "x"'  # missing "}, ], }
    out = _parse_json_resilient(content)
    assert out == {"a": [{"b": "x"}]}


def test_string_with_brackets_doesnt_confuse():
    """Brackets inside strings must NOT count toward the imbalance."""
    content = '{"sql": "SELECT [a] FROM t WHERE x IN (1,2,3)"}'
    out = _parse_json_resilient(content)
    assert out == {"sql": "SELECT [a] FROM t WHERE x IN (1,2,3)"}


def test_escaped_quotes_in_strings():
    """The autoclose walker must respect \\\" escapes."""
    content = '{"php": "echo \\"hi\\";"'  # missing closing }
    out = _parse_json_resilient(content)
    assert out is not None
    assert out["php"] == 'echo "hi";'


def test_balanced_input_unchanged_by_autoclose():
    content = '{"a": 1, "b": [2, 3]}'
    assert _autoclose_unbalanced(content) == content


def test_autoclose_appends_correct_order():
    # Open: { then [, closers should append as ]} (LIFO)
    content = '{"x": [1, 2'
    assert _autoclose_unbalanced(content) == '{"x": [1, 2]}'


def test_unrecoverable_returns_none():
    """If the content isn't JSON-ish at all, return None instead of guessing."""
    assert _parse_json_resilient("just some prose") is None
    assert _parse_json_resilient("not_a_dict: true") is None


def test_actual_chatgpt_failing_response():
    """The exact 1851-char response that failed in the quiz-maker scan.

    Reproduced via /tmp/repro_followup.py; this is a regression guard so
    we know the parser handles this specific live failure shape.
    """
    content = (
        '{"failure_class":"setup","rationale":"The AJAX action returned success '
        'with an empty `rows` string, which means the prerequisite result/config '
        'state was not created in a way the plugin recognizes; reseeding via the '
        'plugin tables with an admin current user and enabling the email display '
        'option should produce a non-empty result row.","commands":[["eval",'
        '"wp_set_current_user(1); global $wpdb; $quizzes = $wpdb->prefix . '
        "'aysquiz_quizes'; echo 'done';\"]}"
    )
    out = _parse_json_resilient(content)
    assert out is not None, f"Failed to parse — content was {content!r}"
    assert out["failure_class"] == "setup"
    assert len(out["commands"]) == 1
    assert out["commands"][0][0] == "eval"
