from __future__ import annotations

from squadrone.schemas.hypothesis import BugClass, Confidence, Hypothesis
from squadrone.stages.verify import _setup_command_plants_exploit_payload


def _hyp(cwe: BugClass) -> Hypothesis:
    return Hypothesis(
        id="h",
        specialist="test",
        bug_class=cwe,
        entry_point="wp_ajax_x",
        file="x.php",
        line=1,
        sink="sink",
        taint_path=[],
        reasoning="r",
        confidence=Confidence.HIGH,
        preconditions="subscriber",
        affected_versions="<=1.0",
    )


def test_blocks_direct_xss_seed():
    reason = _setup_command_plants_exploit_payload(
        ["eval", "global $wpdb; $wpdb->insert('x', ['v' => '<svg onload=alert(1)>']);"],
        _hyp(BugClass.XSS_STORED),
    )
    assert reason and "XSS" in reason


def test_blocks_direct_sqli_seed():
    reason = _setup_command_plants_exploit_payload(
        ["db", "query", "insert into x values ('1 UNION SELECT password')"],
        _hyp(BugClass.SQLI),
    )
    assert reason and "SQL injection" in reason


def test_allows_benign_prerequisite_seed():
    reason = _setup_command_plants_exploit_payload(
        ["eval", "global $wpdb; $wpdb->insert('x', ['title' => 'Normal record']);"],
        _hyp(BugClass.XSS_STORED),
    )
    assert reason is None
