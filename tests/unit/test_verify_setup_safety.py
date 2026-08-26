from __future__ import annotations

import pytest

from squadrone.schemas.hypothesis import BugClass, Confidence, Hypothesis
from squadrone.stages.verify import (
    _build_setup_code_context,
    _run_setup_commands,
    _setup_command_plants_exploit_payload,
)


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


def test_allows_runtime_directory_creation_without_permission_mutation():
    reason = _setup_command_plants_exploit_payload(
        ["eval", "$dir = WP_PLUGIN_DIR . '/demo/files'; wp_mkdir_p($dir);"],
        _hyp(BugClass.ARBITRARY_FILE_WRITE),
    )
    assert reason is None


@pytest.mark.parametrize(
    "php",
    [
        "chmod($dir, 0777);",
        "$wp_filesystem->chmod($dir, FS_CHMOD_DIR);",
        "chown($dir, 'www-data');",
        "umask(0);",
    ],
)
def test_blocks_setup_filesystem_permission_mutation(php):
    reason = _setup_command_plants_exploit_payload(
        ["eval", php],
        _hyp(BugClass.ARBITRARY_FILE_WRITE),
    )
    assert reason and "filesystem permissions or ownership" in reason


@pytest.mark.asyncio
async def test_forbidden_permission_setup_is_not_executed():
    class FakeWPCli:
        called = False

        async def _exec_result(self, *args, user=None):
            self.called = True
            return 0, "", ""

    wp_cli = FakeWPCli()
    sandbox = type("FakeSandbox", (), {"wp_cli": wp_cli})()

    results = await _run_setup_commands(
        sandbox,
        [["eval", "chmod(WP_PLUGIN_DIR . '/demo/files', 0777);"]],
        hypothesis=_hyp(BugClass.ARBITRARY_FILE_WRITE),
    )

    assert wp_cli.called is False
    assert results[0]["failed"] is True
    assert results[0]["forbidden_payload_seed"] is True


@pytest.mark.asyncio
async def test_permission_guard_does_not_depend_on_hypothesis_metadata():
    class FailIfCalledWPCli:
        async def _exec_result(self, *args, user=None):
            raise AssertionError("forbidden setup reached WP-CLI")

    sandbox = type("FakeSandbox", (), {"wp_cli": FailIfCalledWPCli()})()

    results = await _run_setup_commands(
        sandbox,
        [["eval", "chmod('/tmp/plugin-state', 0777);"]],
    )

    assert results[0]["forbidden_payload_seed"] is True


@pytest.mark.asyncio
async def test_allowed_setup_runs_as_wordpress_web_identity():
    calls: list[tuple[tuple[str, ...], str | None]] = []

    class RecordingWPCli:
        async def _exec_result(self, *args, user=None):
            calls.append((args, user))
            return 0, "updated", ""

    sandbox = type("FakeSandbox", (), {"wp_cli": RecordingWPCli()})()

    results = await _run_setup_commands(
        sandbox,
        [["option", "update", "demo_enabled", "1"]],
        hypothesis=_hyp(BugClass.ARBITRARY_FILE_WRITE),
    )

    assert calls == [(("option", "update", "demo_enabled", "1"), "www-data")]
    assert results[0]["failed"] is False


def test_setup_context_includes_cited_entry_point_and_sink_files(tmp_path):
    classes = tmp_path / "classes"
    classes.mkdir()
    api_lines = ["// filler"] * 700
    api_lines[20] = "$public_api = $this->core->get_option( 'public_api' );"
    api_lines[672] = "public function rest_simpleFileUpload( $request ) {"
    (classes / "api.php").write_text("\n".join(api_lines))
    files_lines = ["// filler"] * 400
    files_lines[366] = "if ( !copy( $path, $destination ) ) {"
    (classes / "files.php").write_text("\n".join(files_lines))
    hypothesis = _hyp(BugClass.ARBITRARY_FILE_WRITE)
    hypothesis.entry_point = "classes/api.php:673 rest_simpleFileUpload"
    hypothesis.file = "classes/files.php"
    hypothesis.line = 367
    hypothesis.taint_path = [
        "classes/api.php:673 receives the file",
        "classes/files.php:367 copies it",
    ]

    context = _build_setup_code_context(tmp_path, hypothesis)

    assert context is not None
    assert "--- classes/api.php ---" in context
    assert "get_option( 'public_api' )" in context
    assert "rest_simpleFileUpload" in context
    assert "--- classes/files.php ---" in context
    assert "copy( $path, $destination )" in context
