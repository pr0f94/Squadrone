from __future__ import annotations

import json
from pathlib import Path

import pytest

from squadrone.schemas.config import PipelineConfig
from squadrone.schemas.hypothesis import Confidence, Hypothesis
from squadrone.schemas.observation import CIAImpact, PoCObservation
from squadrone.schemas.taxonomy import BugClass
from squadrone.services.sandbox import SandboxRunResult
from squadrone.stages import verify as verify_stage


_ACCOUNTS = [
    {
        "id": 1,
        "login": "admin_user",
        "password": "admin-secret",
        "role": "administrator",
    },
    {
        "id": 2,
        "login": "subscriber_user",
        "password": "subscriber-secret",
        "role": "subscriber",
    },
]
_ORACLE_CONTEXT = {
    "attack_url": "http://host.docker.internal:49152/_squadrone/ssrf/" + "a" * 64,
    "control_url": "http://host.docker.internal:49152/_squadrone/ssrf/" + "b" * 64,
}


def _hypothesis(
    bug_class: BugClass,
    *,
    attacker_role: str,
    entry_point: str,
    source: str,
) -> Hypothesis:
    return Hypothesis(
        id="verify-context",
        specialist="test",
        bug_class=bug_class,
        entry_point=entry_point,
        file="includes/rest-api.php",
        line=6,
        sink="wp_remote_get($destination)",
        sink_code="$destination = $_GET['remote_url'];",
        taint_path=[source, "wp_remote_get($destination)"],
        reasoning="Source-grounded test hypothesis.",
        confidence=Confidence.HIGH,
        preconditions=attacker_role,
        affected_versions="<=1.0",
        evidence_summary={
            "attacker_role": attacker_role,
            "source": source,
        },
    )


def _write_direct_query_ssrf_fixture(plugin_root: Path) -> None:
    source_file = plugin_root / "includes" / "rest-api.php"
    source_file.parent.mkdir(parents=True)
    source_file.write_text(
        """<?php
class Demo_REST_API {
    public function get_remote_content() {
        $unrelated = $_POST['nearby_parameter'];
        $destination = esc_url_raw( $_GET['remote_url'] );
        $response = wp_remote_get(
            $destination,
            array( 'timeout' => 15 )
        );
        return wp_remote_retrieve_body( $response );
    }
}
""",
        encoding="utf-8",
    )


def _observation(attacker_role: str, *, ssrf: bool) -> PoCObservation:
    return PoCObservation(
        verdict="vulnerable",
        oracle="response_marker" if ssrf else "browser_execution",
        attacker_role=attacker_role,
        request={
            "method": "GET",
            "url": "http://sandbox.invalid/wp-json/example/v1/proxy",
        },
        attack={"marker": "proof"},
        control={"marker": ""},
        impact=CIAImpact(
            confidentiality="low" if ssrf else "none",
            integrity="none" if ssrf else "low",
        ),
    )


def test_ssrf_sandbox_modes_are_exact_and_order_independent() -> None:
    non_ssrf = _hypothesis(
        BugClass.XSS_REFLECTED,
        attacker_role="subscriber",
        entry_point="GET /reflect",
        source="query parameter reaches HTML",
    )
    http_ssrf = _hypothesis(
        BugClass.SSRF,
        attacker_role="unauthenticated",
        entry_point="GET /proxy",
        source="url query parameter reaches wp_remote_get",
    )
    local_ssrf = http_ssrf.model_copy(
        update={
            "id": "local-resource",
            "reasoning": "The source-reviewed wrapper accepts file:// URLs.",
        }
    )

    assert verify_stage._ssrf_oracle_modes_for_hypotheses([non_ssrf]) == frozenset()
    assert verify_stage._ssrf_oracle_modes_for_hypotheses(
        [non_ssrf, http_ssrf]
    ) == frozenset({"http"})
    assert verify_stage._ssrf_oracle_modes_for_hypotheses(
        [non_ssrf, local_ssrf]
    ) == frozenset({"local_resource"})
    assert verify_stage._ssrf_oracle_modes_for_hypotheses(
        [http_ssrf, local_ssrf]
    ) == verify_stage._ssrf_oracle_modes_for_hypotheses(
        [local_ssrf, http_ssrf]
    ) == frozenset({"http", "local_resource"})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    (
        "bug_class",
        "attacker_role",
        "source",
        "expected_accounts",
        "expected_oracle_calls",
        "expected_transport",
    ),
    [
        (
            BugClass.SSRF,
            "subscriber",
            "The remote_url query parameter reaches wp_remote_get",
            ["subscriber_user"],
            1,
            {
                "method": "GET",
                "route": "/wp-json/example/v1/proxy",
                "dispatch": {},
                "destination_parameter": "remote_url",
                "destination_location": "query",
            },
        ),
        (
            BugClass.SSRF,
            "unauthenticated",
            "$_GET['remote_url'] reaches wp_remote_get",
            [],
            1,
            {
                "method": "GET",
                "route": "/wp-json/example/v1/proxy",
                "dispatch": {},
                "destination_parameter": "remote_url",
                "destination_location": "query",
            },
        ),
        (
            BugClass.XSS_REFLECTED,
            "subscriber",
            "The remote_url query parameter reaches an HTML response",
            ["admin_user", "subscriber_user"],
            0,
            None,
        ),
    ],
)
async def test_verify_binds_ssrf_context_accounts_and_both_runs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    bug_class: BugClass,
    attacker_role: str,
    source: str,
    expected_accounts: list[str],
    expected_oracle_calls: int,
    expected_transport: dict[str, object] | None,
) -> None:
    author_contexts: list[dict] = []

    class FakePoCAuthor:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        async def write(self, **kwargs: object) -> str:
            author_contexts.append(dict(kwargs["extra_context"]))
            return "import requests\n"

    observation = _observation(
        attacker_role,
        ssrf=bug_class == BugClass.SSRF,
    )

    class FakeSandbox:
        target_url = "http://sandbox.invalid"

        def __init__(self) -> None:
            self.oracle_calls = 0
            self.run_calls: list[dict] = []
            self.snapshot_count = 0

        def baseline_user_accounts(self) -> list[dict]:
            return [dict(account) for account in _ACCOUNTS]

        async def prepare_ssrf_oracle(self) -> dict[str, str]:
            self.oracle_calls += 1
            return dict(_ORACLE_CONTEXT)

        async def snapshot(self) -> Path:
            self.snapshot_count += 1
            snapshot = tmp_path / f"snapshot-{self.snapshot_count}"
            snapshot.mkdir()
            return snapshot

        async def restore(self, _snapshot: Path) -> None:
            return None

        async def run_poc(
            self, _script_path: str, **kwargs: object
        ) -> SandboxRunResult:
            self.run_calls.append(dict(kwargs))
            return SandboxRunResult(
                success=True,
                output="SQUADRONE_RESULT={}",
                elapsed=0,
                evidence={"run": len(self.run_calls)},
                observation=observation.model_copy(deep=True),
            )

    monkeypatch.setattr(verify_stage, "PoCAuthorAgent", FakePoCAuthor)
    config = PipelineConfig.from_yaml("pipelines/test.yaml")
    config.verify_max_iterations = 1
    config.report.screenshot_capture = False
    config.verify.state_introspection_on_failure = False
    sandbox = FakeSandbox()
    plugin_root = tmp_path / "plugin"
    _write_direct_query_ssrf_fixture(plugin_root)
    hypothesis = _hypothesis(
        bug_class,
        attacker_role=attacker_role,
        entry_point="GET /wp-json/example/v1/proxy",
        source=source,
    )

    finding = await verify_stage._verify_one(
        hypothesis,
        str(plugin_root),
        str(tmp_path / "plugin.zip"),
        "example-plugin",
        config,
        object(),
        tmp_path / "verification",
        persistent_sb=sandbox,
    )

    assert finding is not None
    assert len(author_contexts) == 1
    context = author_contexts[0]
    assert [account["login"] for account in context["user_accounts"]] == (
        expected_accounts
    )
    assert sandbox.oracle_calls == expected_oracle_calls
    if bug_class == BugClass.SSRF:
        assert context["ssrf_oracle"] == _ORACLE_CONTEXT
        assert "admin-secret" not in repr(context)
        if attacker_role == "unauthenticated":
            assert context["test_username"] == ""
            assert context["test_password"] == ""
        else:
            assert context["test_username"] == "subscriber_user"
            assert context["test_password"] == "subscriber-secret"
    else:
        assert "ssrf_oracle" not in context
    assert len(sandbox.run_calls) == 2
    assert [call["expected_http_transport"] for call in sandbox.run_calls] == [
        expected_transport,
        expected_transport,
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("oracle_mode", "expected_events"),
    [
        (
            "local_resource",
            [
                "prepare:local_resource",
                "snapshot",
                "run:attack",
                "restore",
                "restart_wordpress_runtime",
                "run:confirmation",
                "restore",
                "restart_wordpress_runtime",
            ],
        ),
        (
            "http",
            [
                "prepare:http",
                "snapshot",
                "run:attack",
                "restore",
                "run:confirmation",
                "restore",
            ],
        ),
    ],
)
async def test_verify_restarts_wordpress_after_every_local_resource_restore_only(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    oracle_mode: str,
    expected_events: list[str],
) -> None:
    class FakePoCAuthor:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        async def write(self, **_kwargs: object) -> str:
            return "import requests\n"

    observation = _observation("unauthenticated", ssrf=True)

    class FakeSandbox:
        target_url = "http://sandbox.invalid"

        def __init__(self) -> None:
            self.events: list[str] = []
            self.run_count = 0

        def baseline_user_accounts(self) -> list[dict]:
            return [dict(account) for account in _ACCOUNTS]

        async def prepare_ssrf_local_resource_oracle(self) -> dict[str, str]:
            self.events.append("prepare:local_resource")
            return {
                "mode": "local_resource",
                "attack_url": "file://localhost/var/lib/squadrone/ssrf/" + "a" * 64,
                "control_url": "http://localhost/var/lib/squadrone/ssrf/" + "a" * 64,
            }

        async def prepare_ssrf_oracle(self) -> dict[str, str]:
            self.events.append("prepare:http")
            return dict(_ORACLE_CONTEXT)

        async def snapshot(self) -> Path:
            self.events.append("snapshot")
            snapshot = tmp_path / "attempt-snapshot"
            snapshot.mkdir()
            return snapshot

        async def restore(self, _snapshot: Path) -> None:
            self.events.append("restore")

        async def restart_wordpress_runtime(self) -> None:
            self.events.append("restart_wordpress_runtime")

        async def run_poc(
            self, _script_path: str, **_kwargs: object
        ) -> SandboxRunResult:
            self.run_count += 1
            phase = "attack" if self.run_count == 1 else "confirmation"
            self.events.append(f"run:{phase}")
            child_line = 'SQUADRONE_RESULT={"verdict":"vulnerable"}'
            replay_observation = observation.model_copy(deep=True)
            if phase == "confirmation":
                replay_observation.request["url"] = (
                    "http://sandbox.invalid/wp-json/example/v1/different"
                )
            return SandboxRunResult(
                success=True,
                output=child_line,
                response=child_line,
                error_log=child_line,
                elapsed=0,
                validation_reason="parent oracle accepted this individual run",
                observation=replay_observation,
            )

    monkeypatch.setattr(verify_stage, "PoCAuthorAgent", FakePoCAuthor)
    config = PipelineConfig.from_yaml("pipelines/test.yaml")
    config.verify_max_iterations = 1
    config.report.screenshot_capture = False
    config.verify.state_introspection_on_failure = False
    plugin_root = tmp_path / "plugin"
    if oracle_mode == "local_resource":
        plugin_root.mkdir()
        (plugin_root / "proxy.php").write_text(
            """<?php
$destination = $_GET['remote_url'];
echo file_get_contents($destination);
""",
            encoding="utf-8",
        )
        hypothesis = _hypothesis(
            BugClass.SSRF,
            attacker_role="unauthenticated",
            entry_point="Direct GET request to proxy.php",
            source="$_GET['remote_url'] reaches file_get_contents",
        ).model_copy(
            update={
                "file": "proxy.php",
                "line": 3,
                "sink": "file_get_contents($destination)",
                "sink_code": "echo file_get_contents($destination);",
                "taint_path": [
                    "$_GET['remote_url']",
                    "file://localhost reaches file_get_contents($destination)",
                ],
                "reasoning": "Missing scheme validation permits file://localhost reads.",
            }
        )
    else:
        _write_direct_query_ssrf_fixture(plugin_root)
        hypothesis = _hypothesis(
            BugClass.SSRF,
            attacker_role="unauthenticated",
            entry_point="GET /wp-json/example/v1/proxy",
            source="$_GET['remote_url'] reaches wp_remote_get",
        )

    sandbox = FakeSandbox()
    finding = await verify_stage._verify_one(
        hypothesis,
        str(plugin_root),
        str(tmp_path / "plugin.zip"),
        "example-plugin",
        config,
        object(),
        tmp_path / "verification",
        persistent_sb=sandbox,
    )

    assert finding is None
    assert sandbox.events == expected_events
    assert sandbox.events.count("restore") == 2
    assert sandbox.events.count("restart_wordpress_runtime") == (
        2 if oracle_mode == "local_resource" else 0
    )
    checkpoint = json.loads((tmp_path / "verification" / "attempts.json").read_text())
    assert len(checkpoint["attempts"]) == 2
    for attempt in checkpoint["attempts"]:
        assert attempt["result"] == "failed"
        assert attempt["observation"] is None
        assert attempt["rejected_observation"]["verdict"] == "vulnerable"
        assert "SQUADRONE_RESULT=" not in (attempt["response_snippet"] or "")
        assert "SQUADRONE_RESULT=" not in (attempt["error_log_snippet"] or "")


def test_ssrf_destination_inference_fails_closed_without_one_exact_source(
    tmp_path: Path,
) -> None:
    plugin_root = tmp_path / "plugin"
    _write_direct_query_ssrf_fixture(plugin_root)
    missing = _hypothesis(
        BugClass.SSRF,
        attacker_role="subscriber",
        entry_point="GET /wp-json/example/v1/proxy",
        source="An attacker-controlled destination reaches wp_remote_get",
    ).model_copy(update={"sink_code": ""})
    ambiguous = missing.model_copy(
        update={
            "taint_path": [
                "$_GET['first_url']",
                "$_POST['second_url']",
            ]
        }
    )

    assert verify_stage._expected_ssrf_http_transport(missing, plugin_root) == {
        "method": "GET",
        "route": "/wp-json/example/v1/proxy",
        "dispatch": {},
        "destination_parameter": "",
        "destination_location": "",
    }
    assert verify_stage._expected_ssrf_http_transport(ambiguous, plugin_root) == {
        "method": "GET",
        "route": "/wp-json/example/v1/proxy",
        "dispatch": {},
        "destination_parameter": "",
        "destination_location": "",
    }


def test_source_trace_binds_sink_input_not_unrelated_nearby_parameter(
    tmp_path: Path,
) -> None:
    plugin_root = tmp_path / "plugin"
    _write_direct_query_ssrf_fixture(plugin_root)
    hypothesis = _hypothesis(
        BugClass.SSRF,
        attacker_role="subscriber",
        entry_point="GET /wp-json/example/v1/proxy",
        source="The remote_url query parameter reaches wp_remote_get",
    )

    assert verify_stage._infer_ssrf_destination_from_plugin_source(
        plugin_root,
        hypothesis,
    ) == ("remote_url", "query")


def test_ssrf_source_and_model_destination_mismatch_fails_closed(
    tmp_path: Path,
) -> None:
    plugin_root = tmp_path / "plugin"
    _write_direct_query_ssrf_fixture(plugin_root)
    hypothesis = _hypothesis(
        BugClass.SSRF,
        attacker_role="subscriber",
        entry_point="GET /wp-json/example/v1/proxy",
        source="The different_url query parameter reaches wp_remote_get",
    ).model_copy(update={"sink_code": "wp_remote_get($destination)"})

    assert verify_stage._expected_ssrf_http_transport(hypothesis, plugin_root) == {
        "method": "GET",
        "route": "/wp-json/example/v1/proxy",
        "dispatch": {},
        "destination_parameter": "",
        "destination_location": "",
    }


@pytest.mark.parametrize("cited_file", ["includes/missing.php", "../outside.php"])
def test_ssrf_source_binding_rejects_missing_or_traversing_file(
    tmp_path: Path,
    cited_file: str,
) -> None:
    plugin_root = tmp_path / "plugin"
    _write_direct_query_ssrf_fixture(plugin_root)
    outside = tmp_path / "outside.php"
    outside.write_text(
        (plugin_root / "includes" / "rest-api.php").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    hypothesis = _hypothesis(
        BugClass.SSRF,
        attacker_role="subscriber",
        entry_point="GET /wp-json/example/v1/proxy",
        source="The remote_url query parameter reaches wp_remote_get",
    ).model_copy(update={"file": cited_file})

    assert verify_stage._expected_ssrf_http_transport(hypothesis, plugin_root) == {
        "method": "GET",
        "route": "/wp-json/example/v1/proxy",
        "dispatch": {},
        "destination_parameter": "",
        "destination_location": "",
    }


def test_ssrf_source_binding_supports_direct_literal_request_input(
    tmp_path: Path,
) -> None:
    plugin_root = tmp_path / "plugin"
    source_file = plugin_root / "includes" / "rest-api.php"
    source_file.parent.mkdir(parents=True)
    source_file.write_text(
        """<?php
function proxy_callback() {
    $unrelated = $_GET['nearby_parameter'];
    return wp_remote_post( $_POST['callback_url'] );
}
""",
        encoding="utf-8",
    )
    hypothesis = _hypothesis(
        BugClass.SSRF,
        attacker_role="subscriber",
        entry_point="POST /wp-json/example/v1/proxy",
        source="The callback_url form parameter reaches wp_remote_post",
    ).model_copy(
        update={
            "line": 4,
            "sink": "wp_remote_post($_POST['callback_url'])",
            "sink_code": "wp_remote_post($_POST['callback_url'])",
            "taint_path": ["$_POST['callback_url']", "wp_remote_post"],
        }
    )

    assert verify_stage._expected_ssrf_http_transport(hypothesis, plugin_root) == {
        "method": "POST",
        "route": "/wp-json/example/v1/proxy",
        "dispatch": {},
        "destination_parameter": "callback_url",
        "destination_location": "form",
    }


def test_ssrf_source_binding_rejects_ambiguous_request_dataflow(
    tmp_path: Path,
) -> None:
    plugin_root = tmp_path / "plugin"
    source_file = plugin_root / "includes" / "rest-api.php"
    source_file.parent.mkdir(parents=True)
    source_file.write_text(
        """<?php
function proxy_callback() {
    $destination = $condition ? $_GET['first_url'] : $_POST['second_url'];
    return wp_remote_get( $destination );
}
""",
        encoding="utf-8",
    )
    hypothesis = _hypothesis(
        BugClass.SSRF,
        attacker_role="subscriber",
        entry_point="GET /wp-json/example/v1/proxy",
        source="The first_url query parameter reaches wp_remote_get",
    ).model_copy(
        update={
            "line": 4,
            "sink_code": "wp_remote_get($destination)",
            "taint_path": ["$_GET['first_url']", "wp_remote_get"],
        }
    )

    assert (
        verify_stage._infer_ssrf_destination_from_plugin_source(
            plugin_root,
            hypothesis,
        )
        is None
    )


def test_ssrf_transport_removes_destination_but_retains_rest_dispatch(
    tmp_path: Path,
) -> None:
    plugin_root = tmp_path / "plugin"
    _write_direct_query_ssrf_fixture(plugin_root)
    hypothesis = _hypothesis(
        BugClass.SSRF,
        attacker_role="subscriber",
        entry_point=(
            "GET /?rest_route=/example/v1/proxy&remote_url=attacker-value&mode=preview"
        ),
        source="The remote_url query parameter reaches wp_remote_get",
    )

    assert verify_stage._expected_ssrf_http_transport(hypothesis, plugin_root) == {
        "method": "GET",
        "route": "/",
        "dispatch": {
            "query:mode": "preview",
            "query:rest_route": "/example/v1/proxy",
        },
        "destination_parameter": "remote_url",
        "destination_location": "query",
    }


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (
            "The callback_url query parameter reaches the HTTP client",
            ("callback_url", "query"),
        ),
        ("$_POST['callback_url'] reaches the HTTP client", ("callback_url", "form")),
        ("$_REQUEST['callback_url'] reaches the HTTP client", None),
    ],
)
def test_ssrf_destination_inference_requires_explicit_location_evidence(
    source: str,
    expected: tuple[str, str] | None,
) -> None:
    hypothesis = _hypothesis(
        BugClass.SSRF,
        attacker_role="subscriber",
        entry_point="POST /wp-admin/admin-ajax.php?action=proxy",
        source=source,
    ).model_copy(update={"sink_code": ""})

    assert verify_stage._infer_ssrf_destination_evidence(hypothesis) == expected


def test_local_scheme_bypass_binds_direct_helper_dispatch_alternatives(
    tmp_path: Path,
) -> None:
    plugin_root = tmp_path / "plugin"
    source_file = plugin_root / "proxy.php"
    plugin_root.mkdir()
    source_file.write_text(
        """<?php
function fetch_resource($url, &$fields) {
    $parts = parse_url($url);
    if (($parts['host'] ?? '') !== 'localhost') {
        return 'denied';
    }
    $fp = fopen($url, 'r');
    return stream_get_contents($fp);
}
if (isset($_POST['resource_url'])) {
    echo fetch_resource($_POST['resource_url'], $_POST);
} elseif (isset($_GET['resource_url'])) {
    echo fetch_resource($_GET['resource_url'], $_GET);
}
""",
        encoding="utf-8",
    )
    hypothesis = _hypothesis(
        BugClass.SSRF,
        attacker_role="unauthenticated",
        entry_point=(
            "Direct unauthenticated request to proxy.php with GET or POST "
            "parameter resource_url"
        ),
        source="$_GET['resource_url'] or $_POST['resource_url'] reaches fopen",
    ).model_copy(
        update={
            "file": "proxy.php",
            "line": 7,
            "sink": "fopen($url, 'r')",
            "sink_code": "$fp = fopen($url, 'r');",
            "taint_path": [
                "$_GET['resource_url'] or $_POST['resource_url']",
                "fetch_resource($url, $fields)",
                "file://localhost reaches fopen($url, 'r')",
            ],
            "reasoning": "Missing scheme validation permits file://localhost reads.",
        }
    )

    assert verify_stage._ssrf_oracle_mode(hypothesis) == "local_resource"
    assert verify_stage._infer_ssrf_destination_source_candidates(
        plugin_root,
        hypothesis,
    ) == (
        frozenset({("resource_url", "query"), ("resource_url", "form")}),
        True,
    )
    assert verify_stage._expected_ssrf_http_transport(
        hypothesis,
        plugin_root,
        "example-plugin",
    ) == {
        "alternatives": [
            {
                "method": "GET",
                "route": "/wp-content/plugins/example-plugin/proxy.php",
                "dispatch": {},
                "destination_parameter": "resource_url",
                "destination_location": "query",
            },
            {
                "method": "POST",
                "route": "/wp-content/plugins/example-plugin/proxy.php",
                "dispatch": {},
                "destination_parameter": "resource_url",
                "destination_location": "form",
            },
        ]
    }


def test_local_helper_source_binding_rejects_dynamic_or_cross_file_flow(
    tmp_path: Path,
) -> None:
    plugin_root = tmp_path / "plugin"
    plugin_root.mkdir()
    (plugin_root / "proxy.php").write_text(
        """<?php
function fetch_resource($url) {
    $reader = 'fopen';
    return $reader($url, 'r');
}
echo fetch_resource($_GET['resource_url']);
""",
        encoding="utf-8",
    )
    hypothesis = _hypothesis(
        BugClass.SSRF,
        attacker_role="unauthenticated",
        entry_point="Direct request to proxy.php",
        source="$_GET['resource_url'] reaches a dynamic reader",
    ).model_copy(
        update={
            "file": "proxy.php",
            "line": 4,
            "sink": "$reader($url, 'r')",
            "sink_code": "return $reader($url, 'r');",
            "taint_path": ["$_GET['resource_url']", "$reader($url, 'r')"],
        }
    )

    assert verify_stage._infer_ssrf_destination_source_candidates(
        plugin_root,
        hypothesis,
    ) == (frozenset(), False)
