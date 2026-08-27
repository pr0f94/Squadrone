from __future__ import annotations

import json

import pytest

from squadrone.agents.developer import SetupPlan
from squadrone.schemas.config import PipelineConfig
from squadrone.schemas.hypothesis import BugClass, Confidence, Hypothesis
from squadrone.services.sandbox import SandboxRunResult
from squadrone.stages import verify as verify_stage
from squadrone.stages.verify import (
    _build_setup_code_context,
    _run_setup_commands,
    _setup_command_plants_exploit_payload,
    _setup_result_taints_confirmation,
    _summarise_forbidden_setup,
    _summarise_setup_results,
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
    assert results[0]["blocked_before_execution"] is True
    assert results[0]["executed"] is False


@pytest.mark.asyncio
async def test_mixed_safe_and_forbidden_setup_is_blocked_atomically():
    class FailIfCalledWPCli:
        async def _exec_result(self, *args, user=None):
            raise AssertionError("mixed setup reached WP-CLI")

    sandbox = type("FakeSandbox", (), {"wp_cli": FailIfCalledWPCli()})()

    results = await _run_setup_commands(
        sandbox,
        [
            [
                "eval",
                "wp_mkdir_p('/srv/site/uploads'); chmod('/srv/site/uploads', 0777);",
            ]
        ],
        hypothesis=_hyp(BugClass.ARBITRARY_FILE_WRITE),
    )

    summary = _summarise_setup_results(results)
    assert "BLOCKED BEFORE EXECUTION" in summary
    assert "No part of this command ran" in summary
    assert "containing only permitted prerequisite operations" in summary


def test_pre_execution_block_does_not_taint_later_confirmation():
    blocked = {
        "forbidden_payload_seed": True,
        "blocked_before_execution": True,
        "executed": False,
    }
    assert not _setup_result_taints_confirmation(blocked)
    assert _summarise_forbidden_setup([blocked]) == ""
    # Old artifacts did not record execution metadata, so retain their conservative
    # behaviour instead of weakening the integrity of prior findings.
    assert _setup_result_taints_confirmation({"forbidden_payload_seed": True})
    assert _setup_result_taints_confirmation(
        {
            "forbidden_payload_seed": True,
            "blocked_before_execution": False,
            "executed": True,
        }
    )


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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "advisory",
    [
        "Warning: Could not update .htaccess.",
        "PHP Deprecated: Passing null is deprecated.",
    ],
)
async def test_successful_wp_cli_command_is_not_failed_by_advisory_output(advisory):
    class WarningWPCli:
        async def _exec_result(self, *args, user=None):
            return 0, "Success: Rewrite rules flushed.", advisory

    sandbox = type("FakeSandbox", (), {"wp_cli": WarningWPCli()})()

    results = await _run_setup_commands(
        sandbox,
        [["rewrite", "flush"]],
        hypothesis=_hyp(BugClass.ARBITRARY_FILE_WRITE),
    )

    assert results[0]["failed"] is False
    summary = _summarise_setup_results(results)
    assert "OK: wp rewrite flush" in summary
    assert "Success: Rewrite rules flushed." in summary
    assert advisory in summary


@pytest.mark.asyncio
async def test_php_warning_still_fails_setup_even_with_zero_exit_status():
    class PhpWarningWPCli:
        async def _exec_result(self, *args, user=None):
            return 0, "", "PHP Warning: mkdir(): Permission denied"

    sandbox = type("FakeSandbox", (), {"wp_cli": PhpWarningWPCli()})()

    results = await _run_setup_commands(
        sandbox,
        [["eval", "wp_mkdir_p('/srv/site/uploads');"]],
        hypothesis=_hyp(BugClass.ARBITRARY_FILE_WRITE),
    )

    assert results[0]["executed"] is True
    assert results[0]["blocked_before_execution"] is False
    assert results[0]["failed"] is True


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


def test_setup_context_recovers_uncited_entry_guard_from_semantic_identifier(tmp_path):
    routes = tmp_path / "includes" / "routes.php"
    routes.parent.mkdir()
    routes.write_text(
        "\n".join(
            [
                "class Example_Public_API {",
                "$feature_enabled = get_option( 'demo_public_uploads' );",
                "register_rest_route( 'demo/v1', '/store-asset', [",
                "  'callback' => [ $this, 'rest_store_asset' ],",
                "] );",
                "}",
            ]
        )
    )
    bootstrap = tmp_path / "includes" / "core.php"
    bootstrap.write_text(
        "\n".join(
            [
                "private $option_name = 'example_options';",
                *(["// filler"] * 60),
                "$api = new Example_Public_API();",
            ]
        )
    )
    sink = tmp_path / "includes" / "storage.php"
    sink.write_text("copy( $temporary_path, $destination );\n")
    hypothesis = _hyp(BugClass.ARBITRARY_FILE_WRITE)
    hypothesis.entry_point = "POST /wp-json/demo/v1/store-asset"
    hypothesis.file = "includes/storage.php"
    hypothesis.line = 1
    hypothesis.taint_path = [
        "Example_Public_API::rest_store_asset receives attacker bytes",
        "copy writes the selected extension",
    ]

    context = _build_setup_code_context(tmp_path, hypothesis)

    assert context is not None
    assert "--- includes/routes.php ---" in context
    assert "demo_public_uploads" in context
    assert "rest_store_asset" in context
    assert "--- includes/core.php ---" in context
    assert "example_options" in context
    assert "--- includes/storage.php ---" in context
    assert context.index("--- includes/routes.php ---") < context.index(
        "--- includes/storage.php ---"
    )


@pytest.mark.asyncio
async def test_atomic_setup_repair_retries_once_and_shares_followup_cap(
    monkeypatch, tmp_path
):
    plugin_root = tmp_path / "plugin"
    plugin_root.mkdir()
    (plugin_root / "x.php").write_text("<?php\ncopy($source, $destination);\n")
    poc_dir = tmp_path / "verification"
    mixed = [
        "eval",
        "wp_mkdir_p('/srv/site/uploads'); chmod('/srv/site/uploads', 0777);",
    ]
    safe = ["eval", "wp_mkdir_p('/srv/site/uploads');"]

    class RecordingWPCli:
        def __init__(self):
            self.calls = []

        async def _exec_result(self, *args, user=None):
            self.calls.append((args, user))
            return 0, "directory ready", ""

    class FakeSandbox:
        target_url = "http://sandbox.invalid"

        def __init__(self):
            self.wp_cli = RecordingWPCli()
            self.snapshot_count = 0

        def baseline_user_accounts(self):
            return [
                {
                    "login": "subscriber_user",
                    "password": "password",
                    "role": "subscriber",
                }
            ]

        async def snapshot(self):
            self.snapshot_count += 1
            path = tmp_path / f"snapshot-{self.snapshot_count}"
            path.mkdir()
            return path

        async def restore(self, _snapshot):
            return None

        async def run_poc(self, *_args, **_kwargs):
            return SandboxRunResult(
                success=False,
                output="",
                elapsed=0,
                response="not confirmed",
            )

    class FakeDeveloper:
        def __init__(self):
            self.followup_feedback = []

        async def propose_setup(self, *_args, **_kwargs):
            return SetupPlan(
                rationale="Create the runtime directory.", commands=[mixed]
            )

        async def propose_setup_followup(self, **kwargs):
            self.followup_feedback.append(kwargs["setup_execution_feedback"])
            if len(self.followup_feedback) == 1:
                return SetupPlan(rationale="Retry the mixed command.", commands=[mixed])
            if len(self.followup_feedback) == 2:
                return SetupPlan(
                    rationale="Use only the safe operation.", commands=[safe]
                )
            raise AssertionError("shared setup followup cap was exceeded")

    callback_results = []

    class FakePoCAuthor:
        def __init__(self, *_args, setup_callback=None, **_kwargs):
            self.setup_callback = setup_callback

        async def write(self, **_kwargs):
            callback_results.append(await self.setup_callback("request more setup"))
            return "from pathlib import Path\n"

    monkeypatch.setattr(verify_stage, "PoCAuthorAgent", FakePoCAuthor)
    config = PipelineConfig.from_yaml("pipelines/test.yaml")
    config.verify_max_iterations = 1
    developer = FakeDeveloper()
    sandbox = FakeSandbox()

    finding = await verify_stage._verify_one(
        _hyp(BugClass.ARBITRARY_FILE_WRITE),
        str(plugin_root),
        str(tmp_path / "plugin.zip"),
        "plugin",
        config,
        object(),
        poc_dir,
        developer=developer,
        persistent_sb=sandbox,
    )

    assert finding is None
    assert len(developer.followup_feedback) == 2
    assert "BLOCKED BEFORE EXECUTION" in developer.followup_feedback[0]
    assert "LATEST SETUP ROUND" in developer.followup_feedback[1]
    assert "CUMULATIVE SETUP HISTORY" in developer.followup_feedback[1]
    assert sandbox.wp_cli.calls == [(tuple(safe), "www-data")]
    assert callback_results == [
        "[request_additional_setup] setup followup limit reached (2/2)"
    ]
    checkpoint = json.loads((poc_dir / "setup_results.json").read_text())
    assert checkpoint["followups_used"] == 2
    assert len(checkpoint["results"]) == 3
    assert [item["blocked_before_execution"] for item in checkpoint["results"]] == [
        True,
        True,
        False,
    ]
