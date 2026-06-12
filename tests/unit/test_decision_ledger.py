from __future__ import annotations

import json

from squadrone.services.decision_ledger import append_decision, ledger_path


def test_append_decision_writes_jsonl(tmp_path):
    append_decision(
        tmp_path,
        stage="triage",
        action="accept",
        result="accepted",
        hypothesis_id="xss-001",
        reason="passes review",
        artifact=tmp_path / "triaged.json",
        details={"votes": 3},
    )

    path = ledger_path(tmp_path)
    rows = [json.loads(line) for line in path.read_text().splitlines()]

    assert len(rows) == 1
    assert rows[0]["stage"] == "triage"
    assert rows[0]["action"] == "accept"
    assert rows[0]["result"] == "accepted"
    assert rows[0]["hypothesis_id"] == "xss-001"
    assert rows[0]["details"] == {"votes": 3}
    assert rows[0]["artifact"].endswith("triaged.json")
