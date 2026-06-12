from __future__ import annotations

from squadrone.schemas import BugClass, Confidence, Hypothesis
from squadrone.services.artifacts import atomic_write_json, atomic_write_jsonl, read_jsonl_models


def _hypothesis(hypothesis_id: str) -> Hypothesis:
    return Hypothesis(
        id=hypothesis_id,
        specialist="auth",
        bug_class=BugClass.IDOR,
        entry_point="wp_ajax_demo",
        file="demo.php",
        line=12,
        sink="get_post_meta",
        taint_path=["$_POST['id']", "get_post_meta"],
        reasoning="Subscriber can read another user's sensitive object.",
        confidence=Confidence.HIGH,
        preconditions="subscriber",
        affected_versions="<=1.0",
    )


def test_atomic_write_json_and_jsonl_round_trip(tmp_path):
    json_path = tmp_path / "data" / "artifact.json"
    atomic_write_json(json_path, {"ok": True})
    assert json_path.read_text() == '{\n  "ok": true\n}'

    jsonl_path = tmp_path / "rows.jsonl"
    hyp = _hypothesis("h-1")
    atomic_write_jsonl(jsonl_path, [hyp])

    rows, corrupt = read_jsonl_models(jsonl_path, Hypothesis)
    assert corrupt == 0
    assert [row.id for row in rows] == ["h-1"]


def test_read_jsonl_models_quarantines_corrupt_lines(tmp_path):
    path = tmp_path / "rows.jsonl"
    corrupt_path = tmp_path / "corrupt.jsonl"
    hyp = _hypothesis("h-1")
    path.write_text(hyp.model_dump_json() + "\nnot-json\n")

    rows, corrupt = read_jsonl_models(path, Hypothesis, corrupt_path=corrupt_path)

    assert [row.id for row in rows] == ["h-1"]
    assert corrupt == 1
    assert corrupt_path.read_text() == "not-json\n"
