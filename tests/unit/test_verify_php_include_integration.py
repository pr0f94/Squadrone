from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from squadrone.schemas import (
    BugClass,
    CIAImpact,
    Confidence,
    Hypothesis,
    PipelineConfig,
    PoCObservation,
)
from squadrone.services.sandbox import (
    SandboxRunResult,
    validate_confirmation_observations,
)
from squadrone.stages import verify as verify_stage
from squadrone.stages.verify import (
    _expected_php_include_http_transport,
    _is_source_grounded_php_include_hypothesis,
)


def _hypothesis() -> Hypothesis:
    return Hypothesis(
        id="generic-php-include",
        specialist="injection_files",
        bug_class=BugClass.PATH_TRAVERSAL,
        entry_point=(
            "wp_ajax_nopriv_example_dispatch with "
            "function=render_editor&action=add&source=<traversal>"
        ),
        file="includes/actions.php",
        line=2,
        sink="request-selected PHP include",
        sink_code="require_once(PLUGIN_DIR . '/view-' . $source . '.php');",
        taint_path=[
            "$_REQUEST['function']=render_editor selects a public method",
            "$_GET['action']=add reaches the editor",
            "sanitize_text_field($_GET['source']) is assigned to $source",
            "$source is concatenated into require_once",
        ],
        reasoning="A nopriv dynamic dispatcher reaches a request-selected include.",
        confidence=Confidence.MEDIUM,
        preconditions="Unauthenticated request through the shipped AJAX action.",
        affected_versions="1.0.0",
        evidence_summary={
            "attacker_role": "unauthenticated",
            "source": ("$_REQUEST['function'], $_GET['action'], and $_GET['source']"),
        },
    )


def _plugin(tmp_path: Path, sink: str | None = None) -> Path:
    root = tmp_path / "generic-plugin"
    path = root / "includes" / "actions.php"
    path.parent.mkdir(parents=True)
    path.write_text(
        "<?php\n"
        + (sink or _hypothesis().sink_code)
        + "\n"
        + "add_action('wp_ajax_nopriv_example_dispatch', 'example_dispatch');\n"
        + "function example_dispatch() {\n"
        + "    $function = $_REQUEST['function'];\n"
        + "    $action = $_GET['action'];\n"
        + "    $source = $_GET['source'];\n"
        + "}\n"
    )
    return root


def test_php_include_capability_requires_exact_dynamic_source_anchor(
    tmp_path: Path,
) -> None:
    hypothesis = _hypothesis()
    root = _plugin(tmp_path)

    assert _is_source_grounded_php_include_hypothesis(hypothesis, root) is True

    wrong_line = hypothesis.model_copy(update={"line": 1})
    assert _is_source_grounded_php_include_hypothesis(wrong_line, root) is False
    wrong_quote = hypothesis.model_copy(update={"sink_code": "require_once($other);"})
    assert _is_source_grounded_php_include_hypothesis(wrong_quote, root) is False
    literal = hypothesis.model_copy(update={"sink_code": "require_once('fixed.php');"})
    literal_root = _plugin(tmp_path / "literal", literal.sink_code)
    assert _is_source_grounded_php_include_hypothesis(literal, literal_root) is False
    trailing = hypothesis.model_copy(
        update={
            "sink_code": "require_once('fixed.php'); $unrelated = $source;",
        }
    )
    trailing_root = _plugin(tmp_path / "trailing", trailing.sink_code)
    assert _is_source_grounded_php_include_hypothesis(trailing, trailing_root) is False
    parenthesized_tail = hypothesis.model_copy(
        update={"sink_code": "require_once('fixed.php') && $source;"}
    )
    parenthesized_tail_root = _plugin(
        tmp_path / "parenthesized-tail",
        parenthesized_tail.sink_code,
    )
    assert (
        _is_source_grounded_php_include_hypothesis(
            parenthesized_tail,
            parenthesized_tail_root,
        )
        is False
    )
    assigned_tail = hypothesis.model_copy(
        update={"sink_code": "$result = require_once('fixed.php') + $source;"}
    )
    assigned_tail_root = _plugin(tmp_path / "assigned-tail", assigned_tail.sink_code)
    assert (
        _is_source_grounded_php_include_hypothesis(
            assigned_tail,
            assigned_tail_root,
        )
        is False
    )
    string_only = hypothesis.model_copy(
        update={"sink_code": 'echo "require_once($source)";'}
    )
    string_root = _plugin(tmp_path / "string", string_only.sink_code)
    assert _is_source_grounded_php_include_hypothesis(string_only, string_root) is False
    comment_only = hypothesis.model_copy(
        update={"sink_code": "// require_once($source);"}
    )
    comment_root = _plugin(tmp_path / "comment", comment_only.sink_code)
    assert (
        _is_source_grounded_php_include_hypothesis(comment_only, comment_root) is False
    )
    sqli = hypothesis.model_copy(update={"bug_class": BugClass.SQLI})
    assert _is_source_grounded_php_include_hypothesis(sqli, root) is False


def test_php_include_transport_preserves_typed_ajax_dispatch(tmp_path: Path) -> None:
    hypothesis = _hypothesis()
    root = _plugin(tmp_path)

    assert _expected_php_include_http_transport(hypothesis, root) == {
        "alternatives": [
            {
                "method": "POST",
                "route": "/wp-admin/admin-ajax.php",
                "dispatch": {
                    "form:action": "example_dispatch",
                    "form:function": "render_editor",
                    "query:action": "add",
                },
                "destination_parameter": "source",
                "destination_location": "query",
            },
            {
                "method": "POST",
                "route": "/wp-admin/admin-ajax.php",
                "dispatch": {
                    "form:action": "example_dispatch",
                    "query:function": "render_editor",
                    "query:action": "add",
                },
                "destination_parameter": "source",
                "destination_location": "query",
            },
        ]
    }


def test_php_include_transport_requires_literal_source_entry_and_request_keys(
    tmp_path: Path,
) -> None:
    hypothesis = _hypothesis()
    root = tmp_path / "comment-only-plugin"
    path = root / "includes" / "actions.php"
    path.parent.mkdir(parents=True)
    path.write_text(
        "<?php\n"
        + hypothesis.sink_code
        + "\n// add_action('wp_ajax_nopriv_example_dispatch', 'callback');\n"
        + "// $_REQUEST['function']; $_GET['action']; $_GET['source'];\n"
    )

    assert _is_source_grounded_php_include_hypothesis(hypothesis, root) is True
    assert _expected_php_include_http_transport(hypothesis, root) is None


def test_php_include_transport_fails_closed_above_bounded_ambiguity(
    tmp_path: Path,
) -> None:
    hypothesis = _hypothesis().model_copy(
        update={
            "entry_point": (
                "wp_ajax_nopriv_example_dispatch with "
                "one=a&two=b&three=c&source=<traversal>"
            ),
            "taint_path": [
                "$_REQUEST['one'], $_REQUEST['two'], and $_REQUEST['three'] "
                "select the handler",
                "$_GET['source'] is assigned to $source",
                "$source reaches require_once",
            ],
            "evidence_summary": {
                "attacker_role": "unauthenticated",
                "source": (
                    "$_REQUEST['one'], $_REQUEST['two'], $_REQUEST['three'], "
                    "and $_GET['source']"
                ),
            },
        }
    )
    root = tmp_path / "ambiguous-plugin"
    path = root / "includes" / "actions.php"
    path.parent.mkdir(parents=True)
    path.write_text(
        "<?php\n"
        + hypothesis.sink_code
        + "\nadd_action('wp_ajax_nopriv_example_dispatch', 'callback');\n"
        + "function callback() {\n"
        + "    $one = $_REQUEST['one']; $two = $_REQUEST['two'];\n"
        + "    $three = $_REQUEST['three']; $source = $_GET['source'];\n"
        + "}\n"
    )

    assert (
        _expected_php_include_http_transport(hypothesis, root, "ambiguous-plugin")
        is None
    )


def test_php_include_transport_rejects_request_key_from_unrelated_callback(
    tmp_path: Path,
) -> None:
    hypothesis = _hypothesis()
    root = tmp_path / "scoped-plugin"
    path = root / "includes" / "actions.php"
    path.parent.mkdir(parents=True)
    path.write_text(
        "<?php\n"
        + hypothesis.sink_code
        + "\nadd_action('wp_ajax_nopriv_example_dispatch', 'example_dispatch');\n"
        + "function example_dispatch() {\n"
        + "    $function = $_REQUEST['function'];\n"
        + "    $action = $_GET['action'];\n"
        + "}\n"
        + "function unrelated_helper() {\n"
        + "    $source = $_GET['source'];\n"
        + "}\n"
    )

    assert (
        _expected_php_include_http_transport(hypothesis, root, "scoped-plugin") is None
    )


def test_php_include_direct_transport_uses_installed_plugin_slug(
    tmp_path: Path,
) -> None:
    root = tmp_path / "plugin"
    source = root / "direct.php"
    source.parent.mkdir(parents=True)
    source.write_text(
        "<?php\n"
        "$source = $_GET['source'];\n"
        "require_once('/srv/templates/' . $source . '.php');\n"
    )
    hypothesis = _hypothesis().model_copy(
        update={
            "entry_point": (
                "GET /wp-content/plugins/installed-slug/direct.php?source=<traversal>"
            ),
            "file": "direct.php",
            "line": 3,
            "sink_code": "require_once('/srv/templates/' . $source . '.php');",
            "taint_path": [
                "$_GET['source'] is assigned to $source",
                "$source reaches require_once",
            ],
            "evidence_summary": {
                "attacker_role": "unauthenticated",
                "source": "$_GET['source']",
            },
        }
    )

    assert _expected_php_include_http_transport(
        hypothesis,
        root,
        "installed-slug",
    ) == {
        "method": "GET",
        "route": "/wp-content/plugins/installed-slug/direct.php",
        "dispatch": {},
        "destination_parameter": "source",
        "destination_location": "query",
    }
    assert (
        _expected_php_include_http_transport(hypothesis, root, "different-slug") is None
    )


def _observation(marker: str) -> PoCObservation:
    fingerprint = {
        "method": "POST",
        "route": "/wp-admin/admin-ajax.php",
        "destination_parameter": "source",
        "destination_location": "query",
        "dispatch": {
            "form:action": "example_dispatch",
            "form:function": "render_editor",
            "query:action": "add",
        },
        "csrf_fields": [],
    }
    attack_path = "/var/lib/squadrone/php-include/" + "a" * 64 + ".php"
    control_path = "/var/lib/squadrone/php-include/" + "b" * 64 + ".php"
    return PoCObservation(
        verdict="vulnerable",
        oracle="response_marker",
        attacker_role="unauthenticated",
        request={
            "method": "POST",
            "url": "http://localhost:8123/wp-admin/admin-ajax.php",
        },
        attack={
            "observed": True,
            "marker": marker,
            "marker_present": True,
            "include_path": attack_path,
            "destination_value": "../../../../../../var/lib/squadrone/php-include/"
            + "a" * 64,
            "attacker_user_id": "anonymous",
            "identity_verified": True,
            "request_fingerprint": fingerprint,
        },
        control={
            "observed": False,
            "marker_present": False,
            "include_path": control_path,
            "destination_value": "../../../../../../var/lib/squadrone/php-include/"
            + "b" * 64,
            "attacker_user_id": "anonymous",
            "identity_verified": True,
            "request_fingerprint": copy.deepcopy(fingerprint),
        },
        impact=CIAImpact(
            confidentiality="low",
            description="A private verifier canary was included.",
        ),
    )


def test_php_include_clean_replay_requires_fresh_marker_and_stable_request() -> None:
    first = _observation("SQUADRONE_PHP_INCLUDE_" + "1" * 64)
    confirmation = _observation("SQUADRONE_PHP_INCLUDE_" + "2" * 64)

    assert validate_confirmation_observations(first, confirmation)[0] is True

    same_marker = confirmation.model_copy(deep=True)
    same_marker.attack["marker"] = first.attack["marker"]
    accepted, reason = validate_confirmation_observations(first, same_marker)
    assert accepted is False
    assert "fresh private PHP include marker" in reason

    changed_value = confirmation.model_copy(deep=True)
    changed_value.control["destination_value"] += "-drift"
    accepted, reason = validate_confirmation_observations(first, changed_value)
    assert accepted is False
    assert "destination values" in reason


@pytest.mark.asyncio
async def test_verify_wires_php_include_context_and_both_clean_runs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    hypothesis = _hypothesis()
    plugin_root = _plugin(tmp_path)
    transport = _expected_php_include_http_transport(hypothesis, plugin_root)
    attack_path = "/var/lib/squadrone/php-include/" + "a" * 64 + ".php"
    control_path = "/var/lib/squadrone/php-include/" + "b" * 64 + ".php"
    context = {
        "attack_path": attack_path,
        "control_path": control_path,
        "attack_basename": "a" * 64 + ".php",
        "control_basename": "b" * 64 + ".php",
        "header_name": "X-Squadrone-PHP-Include-Receipt",
    }
    author_contexts: list[dict] = []

    class FakePoCAuthor:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        async def write(self, **kwargs: object) -> str:
            author_contexts.append(dict(kwargs["extra_context"]))
            return "import requests\n"

    class FakeSandbox:
        target_url = "http://localhost:8123"

        def __init__(self) -> None:
            self.prepare_calls = 0
            self.run_calls: list[dict] = []
            self.snapshot_calls = 0
            self.restart_calls = 0

        def baseline_user_accounts(self) -> list[dict]:
            return [
                {
                    "id": 1,
                    "login": "admin_user",
                    "password": "admin-secret",
                    "role": "administrator",
                }
            ]

        async def prepare_php_include_oracle(self) -> dict[str, str]:
            self.prepare_calls += 1
            return dict(context)

        async def snapshot(self) -> Path:
            self.snapshot_calls += 1
            path = tmp_path / f"snapshot-{self.snapshot_calls}"
            path.mkdir()
            return path

        async def restore(self, _snapshot: Path) -> None:
            return None

        async def restart_wordpress_runtime(self) -> None:
            self.restart_calls += 1

        async def run_poc(
            self,
            _script_path: str,
            **kwargs: object,
        ) -> SandboxRunResult:
            self.run_calls.append(dict(kwargs))
            marker_digit = str(len(self.run_calls))
            marker = "SQUADRONE_PHP_INCLUDE_" + marker_digit * 64
            observation = _observation(marker)
            result = SandboxRunResult(
                success=True,
                output=f"private stdout {marker}",
                elapsed=0,
                response=f"private response {marker}",
                error_log=f"private error log {marker}",
                evidence={"run": len(self.run_calls), "private_marker_echo": marker},
                observation=observation,
                validation_reason=f"trusted validation {marker}",
            )
            result.retain_trusted_php_include_observation(observation)
            return result

    monkeypatch.setattr(verify_stage, "PoCAuthorAgent", FakePoCAuthor)
    live_marker_pairs: list[tuple[str, str]] = []

    def validate_live_confirmation(
        first: PoCObservation,
        confirmation: PoCObservation,
    ) -> tuple[bool, str]:
        live_marker_pairs.append(
            (str(first.attack["marker"]), str(confirmation.attack["marker"]))
        )
        return validate_confirmation_observations(first, confirmation)

    monkeypatch.setattr(
        verify_stage,
        "validate_confirmation_observations",
        validate_live_confirmation,
    )
    checkpoint_writes: list[dict[str, object]] = []
    real_atomic_write_json = verify_stage.atomic_write_json

    def capture_checkpoint(path: Path, payload: object) -> None:
        if path.name == "attempts.json" and isinstance(payload, dict):
            checkpoint_writes.append(copy.deepcopy(payload))
        real_atomic_write_json(path, payload)

    monkeypatch.setattr(verify_stage, "atomic_write_json", capture_checkpoint)
    caplog.set_level("DEBUG")
    config = PipelineConfig.from_yaml("pipelines/test.yaml")
    config.verify_max_iterations = 1
    config.report.screenshot_capture = False
    config.verify.state_introspection_on_failure = False
    sandbox = FakeSandbox()

    finding = await verify_stage._verify_one(
        hypothesis,
        str(plugin_root),
        str(tmp_path / "plugin.zip"),
        "generic-plugin",
        config,
        object(),
        tmp_path / "verification",
        persistent_sb=sandbox,
    )

    assert finding is not None
    assert sandbox.prepare_calls == 1
    assert sandbox.restart_calls == 1
    assert len(sandbox.run_calls) == 2
    assert all(call["expected_php_include"] is True for call in sandbox.run_calls)
    assert all(
        call["expected_http_transport"] == transport for call in sandbox.run_calls
    )
    assert len(author_contexts) == 1
    assert author_contexts[0]["php_include_oracle"] == context
    assert author_contexts[0]["php_include_http_transport"] == transport
    assert author_contexts[0]["user_accounts"] == []
    assert "admin-secret" not in repr(author_contexts[0])
    first_marker = "SQUADRONE_PHP_INCLUDE_" + "1" * 64
    confirmation_marker = "SQUADRONE_PHP_INCLUDE_" + "2" * 64
    assert live_marker_pairs == [(first_marker, confirmation_marker)]

    checkpoint = (tmp_path / "verification" / "attempts.json").read_text()
    persisted = finding.model_dump_json() + "\n" + checkpoint
    assert checkpoint_writes
    for private_marker in (first_marker, confirmation_marker):
        assert private_marker not in persisted
        assert private_marker not in caplog.text
        assert all(
            private_marker not in json.dumps(payload, sort_keys=True)
            for payload in checkpoint_writes
        )
        assert hashlib.sha256(private_marker.encode("ascii")).hexdigest() in persisted
    assert "<redacted>" in persisted
    assert attack_path in persisted
    assert control_path in persisted
    assert all(
        attempt.observation is not None
        and attempt.observation.attack["marker"] == "<redacted>"
        for attempt in finding.poc_attempts
    )
    assert all(
        "SQUADRONE_PHP_INCLUDE_" not in (attempt.response_snippet or "")
        and "SQUADRONE_PHP_INCLUDE_" not in (attempt.error_log_snippet or "")
        and "SQUADRONE_PHP_INCLUDE_" not in (attempt.validation_reason or "")
        for attempt in finding.poc_attempts
    )
