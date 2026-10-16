from __future__ import annotations

import base64
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
from squadrone.services import sandbox as sandbox_service
from squadrone.services.sandbox import SandboxRunResult
from squadrone.stages import verify as verify_stage

_ATTACK_PATH = "/var/lib/squadrone/php-include/" + "a" * 64 + ".php"
_CONTROL_PATH = "/var/lib/squadrone/php-include/" + "b" * 64 + ".php"
_ORACLE_CONTEXT = {
    "attack_path": _ATTACK_PATH,
    "control_path": _CONTROL_PATH,
    "attack_basename": "a" * 64 + ".php",
    "control_basename": "b" * 64 + ".php",
    "header_name": "X-Squadrone-PHP-Include-Receipt",
}


def _hypothesis() -> Hypothesis:
    return Hypothesis(
        id="command-private-canary",
        specialist="injection_files",
        bug_class=BugClass.COMMAND_INJECTION,
        entry_point="POST /execute",
        file="plugin.php",
        line=3,
        sink="system",
        sink_code="system($command);",
        taint_path=["$_POST['command']", "$command", "system"],
        reasoning="Unauthenticated form input reaches an operating-system command.",
        confidence=Confidence.HIGH,
        preconditions="Unauthenticated request.",
        affected_versions="1.0.0",
        evidence_summary={
            "attacker_role": "unauthenticated",
            "source": "$_POST['command']",
        },
    )


def _observation(marker: str) -> PoCObservation:
    return PoCObservation(
        verdict="vulnerable",
        oracle="response_marker",
        attacker_role="unauthenticated",
        request={"method": "POST", "url": "http://localhost:8123/execute"},
        attack={
            "observed": True,
            "marker": marker,
            "marker_present": True,
            "execution_path": _ATTACK_PATH,
            "destination_value": f"php {_ATTACK_PATH}",
        },
        control={
            "observed": False,
            "marker_present": False,
            "execution_path": _CONTROL_PATH,
            "destination_value": f"php {_CONTROL_PATH}",
        },
        impact=CIAImpact(
            integrity="high",
            description="The parent-private execution canary ran.",
        ),
    )


@pytest.mark.asyncio
async def test_verify_prepares_public_execution_paths_before_authoring_and_generates_marker_after(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    plugin_root = tmp_path / "plugin"
    plugin_root.mkdir()
    (plugin_root / "plugin.php").write_text(
        "<?php\n$command = $_POST['command'];\nsystem($command);\n"
    )
    events: list[str] = []
    author_contexts: list[dict[str, object]] = []

    class FakePoCAuthor:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        async def write(self, **kwargs: object) -> str:
            assert events[-1] == "prepare_public_paths"
            context = dict(kwargs["extra_context"])
            assert context["execution_oracle"] == _ORACLE_CONTEXT
            assert "SQUADRONE_PHP_INCLUDE_" not in repr(context)
            author_contexts.append(context)
            events.append("author")
            return "import requests\n"

    class FakeSandbox:
        target_url = "http://localhost:8123"

        def __init__(self) -> None:
            self.run_calls: list[dict[str, object]] = []
            self.snapshot_calls = 0

        def baseline_user_accounts(self) -> list[dict[str, object]]:
            return []

        async def prepare_execution_oracle(self) -> dict[str, str]:
            events.append("prepare_public_paths")
            return dict(_ORACLE_CONTEXT)

        async def snapshot(self) -> Path:
            self.snapshot_calls += 1
            path = tmp_path / f"snapshot-{self.snapshot_calls}"
            path.mkdir()
            return path

        async def restore(self, _snapshot: Path) -> None:
            events.append("restore")

        async def restart_wordpress_runtime(self) -> None:
            events.append("restart")

        async def run_poc(
            self,
            _script_path: str,
            **kwargs: object,
        ) -> SandboxRunResult:
            assert "author" in events
            self.run_calls.append(dict(kwargs))
            marker = "SQUADRONE_PHP_INCLUDE_" + str(len(self.run_calls)) * 64
            events.append(f"run_with_private_marker:{len(self.run_calls)}")
            observation = _observation(marker)
            marker_hex = marker.encode("ascii").hex()
            marker_b64 = base64.b64encode(marker.encode("ascii")).decode("ascii")
            marker_left = marker[: len(marker) // 2]
            marker_right = marker[len(marker) // 2 :]
            observation.attack["child_encoded_claim"] = marker_b64
            observation.control["child_split_claim"] = [marker_left, marker_right]
            observation.impact.description = marker_hex
            result = SandboxRunResult(
                success=True,
                output=marker_hex,
                elapsed=0,
                response=marker_b64,
                error_log=f"{marker_left}\n{marker_right}",
                evidence={"child_split": [marker_left, marker_right]},
                observation=observation,
                validation_reason=marker_b64,
            )
            result.retain_trusted_execution_observation(
                sandbox_service._parent_execution_observation(observation)
            )
            return result

    monkeypatch.setattr(verify_stage, "PoCAuthorAgent", FakePoCAuthor)
    config = PipelineConfig.from_yaml("tests/fixtures/pipeline.yaml")
    config.verify_max_iterations = 1
    config.report.screenshot_capture = False
    config.verify.state_introspection_on_failure = False
    sandbox = FakeSandbox()

    finding = await verify_stage._verify_one(
        _hypothesis(),
        str(plugin_root),
        str(tmp_path / "plugin.zip"),
        "plugin",
        config,
        object(),
        tmp_path / "verification",
        persistent_sb=sandbox,
    )

    assert finding is not None
    assert author_contexts
    assert events == [
        "prepare_public_paths",
        "author",
        "run_with_private_marker:1",
        "restore",
        "restart",
        "run_with_private_marker:2",
    ]
    assert len(sandbox.run_calls) == 2
    assert all(
        call["expected_bug_class"] == BugClass.COMMAND_INJECTION.oracle_key
        for call in sandbox.run_calls
    )
    assert all(call["expected_php_include"] is False for call in sandbox.run_calls)
    assert all(
        call["expected_http_transport"]
        == {
            "method": "POST",
            "route": "/execute",
            "dispatch": {},
            "destination_parameter": "command",
            "destination_location": "form",
        }
        for call in sandbox.run_calls
    )
    persisted = (
        finding.model_dump_json()
        + (tmp_path / "verification" / "attempts.json").read_text()
    )
    for digit in ("1", "2"):
        marker = "SQUADRONE_PHP_INCLUDE_" + digit * 64
        assert marker not in persisted
        assert hashlib.sha256(marker.encode("ascii")).hexdigest() in persisted
        assert marker.encode("ascii").hex() not in persisted
        assert base64.b64encode(marker.encode("ascii")).decode("ascii") not in persisted
        assert marker[: len(marker) // 2] not in persisted
        assert marker[len(marker) // 2 :] not in persisted
    assert "<redacted>" in persisted
    for attempt in finding.poc_attempts:
        assert attempt.response_snippet is None
        assert attempt.error_log_snippet is None
        assert attempt.rejected_observation is None
        assert attempt.observation is not None
        assert attempt.observation.impact.model_dump(mode="json") == {
            "confidentiality": "none",
            "integrity": "high",
            "availability": "none",
            "description": (
                "A parent-owned private canary proved server-side command or PHP "
                "code execution."
            ),
        }
    assert "SQUADRONE_PHP_INCLUDE_" not in json.dumps(
        [attempt.model_dump(mode="json") for attempt in finding.poc_attempts],
        sort_keys=True,
    )
