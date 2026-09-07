from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from squadrone.agents.developer import RequestedSetupPlan, SetupPlan
from squadrone.schemas.config import PipelineConfig
from squadrone.schemas.hypothesis import (
    BugClass,
    Confidence,
    Hypothesis,
    SecurityOutcome,
)
from squadrone.schemas.finding import PoCAttempt, PoCStatus
from squadrone.schemas.observation import CIAImpact, PoCObservation
from squadrone.services.sandbox import SandboxRunResult
from squadrone.stages import verify as verify_stage


def _hypothesis() -> Hypothesis:
    return Hypothesis(
        id="setup-replay",
        specialist="test",
        bug_class=BugClass.ARBITRARY_FILE_WRITE,
        entry_point="wp_ajax_upload",
        file="plugin.php",
        line=10,
        sink="move_uploaded_file",
        taint_path=[],
        reasoning="A subscriber-controlled upload reaches the file-write sink.",
        confidence=Confidence.HIGH,
        preconditions="subscriber",
        affected_versions="<=1.0",
    )


class _WpCli:
    async def _exec_result(self, *_args, **_kwargs):
        return 0, "setup ready", ""


class _Sandbox:
    target_url = "http://localhost:8100"
    config = SimpleNamespace(wp_admin_email="owner@example.test")

    def __init__(self, tmp_path: Path):
        self.tmp_path = tmp_path
        self.wp_cli = _WpCli()
        self.snapshot_count = 0
        self.executed_scripts: list[str] = []
        self.run_kwargs: list[dict] = []

    def baseline_user_accounts(self):
        return [
            {
                "login": "subscriber_user",
                "password": "password",
                "role": "subscriber",
            }
        ]

    def setup_http_context(self):
        return verify_stage.SetupHttpContext.from_wordpress_origins(
            internal_connect_origin=verify_stage.SandboxManager.INTERNAL_WORDPRESS_ORIGIN,
            canonical_wordpress_origin=self.target_url,
        )

    async def snapshot(self):
        self.snapshot_count += 1
        path = self.tmp_path / f"snapshot-{self.snapshot_count}"
        path.mkdir()
        return path

    async def restore(self, _snapshot):
        return None

    async def run_poc(self, script_path, **_kwargs):
        self.executed_scripts.append(Path(script_path).read_text())
        self.run_kwargs.append(_kwargs)
        return SandboxRunResult(
            success=False,
            output="",
            elapsed=0,
            response="not confirmed",
        )


class _Developer:
    def __init__(self):
        self.followup_calls = 0

    async def propose_setup(self, *_args, **_kwargs):
        return SetupPlan()

    async def propose_setup_followup(self, **_kwargs):
        self.followup_calls += 1
        if self.followup_calls == 1:
            return SetupPlan(
                rationale="Create the missing benign prerequisite.",
                commands=[["option", "update", "demo_ready", "1"]],
                failure_class="setup",
            )
        return SetupPlan(
            rationale="The prerequisite is present; revise the exploit request.",
            commands=[],
            failure_class="exploit_shape",
        )


def _config(iterations: int) -> PipelineConfig:
    config = PipelineConfig.from_yaml("pipelines/test.yaml")
    config.verify_max_iterations = iterations
    config.verify.state_introspection_on_failure = False
    config.report.screenshot_capture = False
    return config


def _committed_setup_result() -> dict:
    return {
        "failed": False,
        "executed": True,
        "setup_state_committed": True,
        "setup_round_rolled_back": False,
        "blocked_before_execution": False,
        "forbidden_payload_seed": False,
        "managed_context_violation": False,
    }


def test_setup_replay_eligibility_fails_closed():
    followup = SetupPlan(
        commands=[["option", "update", "demo_ready", "1"]],
        failure_class="setup",
    )
    result = SandboxRunResult(success=False, output="", elapsed=0)
    committed = _committed_setup_result()
    rounds = [(followup, [committed])]

    assert verify_stage._should_replay_poc_after_setup(
        result, followup, rounds, replaying_setup_repair=False
    )
    assert not verify_stage._should_replay_poc_after_setup(
        result, followup, rounds, replaying_setup_repair=True
    )

    crashed = SandboxRunResult(
        success=False,
        output="",
        elapsed=0,
        error_log="Traceback (most recent call last):",
    )
    assert not verify_stage._should_replay_poc_after_setup(
        crashed, followup, rounds, replaying_setup_repair=False
    )

    oracle_failed = SandboxRunResult(
        success=False,
        output="",
        elapsed=0,
        evidence={"ssrf_oracle_error": "snapshot_failed"},
    )
    assert not verify_stage._should_replay_poc_after_setup(
        oracle_failed, followup, rounds, replaying_setup_repair=False
    )

    transport_incomplete = SandboxRunResult(
        success=False,
        output="",
        elapsed=0,
        evidence={"php_object_oracle_error": "transport_incomplete"},
    )
    assert verify_stage._should_replay_poc_after_setup(
        transport_incomplete, followup, rounds, replaying_setup_repair=False
    )

    rolled_back = {**committed, "setup_round_rolled_back": True}
    assert not verify_stage._should_replay_poc_after_setup(
        result,
        followup,
        [(followup, [rolled_back])],
        replaying_setup_repair=False,
    )


@pytest.mark.asyncio
async def test_committed_setup_repair_replays_exact_prior_poc_once(
    monkeypatch, tmp_path
):
    author_calls: list[dict] = []

    class FakePoCAuthor:
        def __init__(self, *_args, **_kwargs):
            pass

        async def write(self, **kwargs):
            author_calls.append(kwargs)
            return "FIRST_AUTHORED_SCRIPT\n"

    monkeypatch.setattr(verify_stage, "PoCAuthorAgent", FakePoCAuthor)
    sandbox = _Sandbox(tmp_path)
    developer = _Developer()
    poc_dir = tmp_path / "verification"

    finding = await verify_stage._verify_one(
        _hypothesis(),
        str(tmp_path),
        str(tmp_path / "plugin.zip"),
        "plugin",
        _config(2),
        object(),
        poc_dir,
        developer=developer,
        persistent_sb=sandbox,
    )

    assert finding is None
    assert developer.followup_calls == 1
    assert len(author_calls) == 1
    assert sandbox.executed_scripts == [
        "FIRST_AUTHORED_SCRIPT\n",
        "FIRST_AUTHORED_SCRIPT\n",
    ]
    assert (poc_dir / "iter_1.py").read_bytes() == (
        poc_dir / "iter_2.py"
    ).read_bytes()


@pytest.mark.asyncio
async def test_failed_setup_replay_returns_to_normal_authoring(monkeypatch, tmp_path):
    authored_scripts = iter(["FIRST_AUTHORED_SCRIPT\n", "SECOND_AUTHORED_SCRIPT\n"])
    author_calls: list[dict] = []

    class FakePoCAuthor:
        def __init__(self, *_args, **_kwargs):
            pass

        async def write(self, **kwargs):
            author_calls.append(kwargs)
            return next(authored_scripts)

    monkeypatch.setattr(verify_stage, "PoCAuthorAgent", FakePoCAuthor)
    sandbox = _Sandbox(tmp_path)

    class TwoRepairDeveloper(_Developer):
        async def propose_setup_followup(self, **_kwargs):
            self.followup_calls += 1
            return SetupPlan(
                rationale=f"Apply benign setup repair {self.followup_calls}.",
                commands=[
                    ["option", "update", f"demo_ready_{self.followup_calls}", "1"]
                ],
                failure_class="setup",
            )

    developer = TwoRepairDeveloper()
    poc_dir = tmp_path / "verification"

    finding = await verify_stage._verify_one(
        _hypothesis(),
        str(tmp_path),
        str(tmp_path / "plugin.zip"),
        "plugin",
        _config(3),
        object(),
        poc_dir,
        developer=developer,
        persistent_sb=sandbox,
    )

    assert finding is None
    assert developer.followup_calls == 2
    assert len(author_calls) == 2
    assert sandbox.executed_scripts == [
        "FIRST_AUTHORED_SCRIPT\n",
        "FIRST_AUTHORED_SCRIPT\n",
        "SECOND_AUTHORED_SCRIPT\n",
    ]
    assert (poc_dir / "iter_1.py").read_bytes() == (
        poc_dir / "iter_2.py"
    ).read_bytes()
    assert (poc_dir / "iter_3.py").read_text() == "SECOND_AUTHORED_SCRIPT\n"


def _observation(*, full_compromise: bool) -> PoCObservation:
    return PoCObservation(
        verdict="vulnerable",
        oracle="response_marker" if full_compromise else "file_effect",
        attacker_role="subscriber",
        request={"method": "POST", "url": "http://localhost:8100/upload"},
        attack={
            "observed": True,
            "marker": "SQUADRONE_EXECUTION_MARKER",
            "marker_present": True,
        },
        control={
            "observed": False,
            "marker_present": False,
        },
        impact=CIAImpact(
            confidentiality="high" if full_compromise else "none",
            integrity="high",
            availability="high" if full_compromise else "none",
            description=(
                "The execution-only marker proved full sandbox compromise."
                if full_compromise
                else "The attacker created a file through the vulnerable workflow."
            ),
        ),
    )


def _full_compromise_hypothesis() -> Hypothesis:
    hypothesis = _hypothesis()
    hypothesis.security_outcome = SecurityOutcome(
        confidentiality="high",
        integrity="high",
        availability="high",
        description="The source path can yield server-side code execution.",
    )
    return hypothesis


def _non_full_compromise_upload_hypothesis() -> Hypothesis:
    hypothesis = _hypothesis()
    hypothesis.security_outcome = SecurityOutcome(
        confidentiality="high",
        integrity="high",
        availability="none",
        description="The source path permits an attacker-controlled file write.",
    )
    return hypothesis


def _confirmation(
    iteration: int,
    *,
    confidentiality: str,
    integrity: str,
    availability: str,
) -> PoCAttempt:
    observation = _observation(full_compromise=False).model_copy(
        update={
            "impact": CIAImpact(
                confidentiality=confidentiality,
                integrity=integrity,
                availability=availability,
                description="Independently confirmed impact.",
            )
        }
    )
    return PoCAttempt(
        iteration=iteration,
        phase="confirmation",
        script_path=f"iter_{iteration}.py",
        result=PoCStatus.SUCCESS,
        observation=observation,
    )


def test_confirmation_selection_accepts_only_componentwise_improvements() -> None:
    baseline = _confirmation(
        1,
        confidentiality="none",
        integrity="high",
        availability="none",
    )
    improved = _confirmation(
        2,
        confidentiality="low",
        integrity="high",
        availability="none",
    )
    full = _confirmation(
        3,
        confidentiality="high",
        integrity="high",
        availability="high",
    )

    assert verify_stage._select_strongest_confirmation(
        [baseline, improved, full]
    ) is full


@pytest.mark.parametrize(
    ("baseline_impact", "candidate_impact"),
    [
        (("high", "high", "none"), ("high", "high", "none")),
        (("high", "high", "none"), ("none", "high", "high")),
        (("high", "low", "none"), ("none", "high", "high")),
    ],
)
def test_confirmation_selection_preserves_fallback_for_ties_or_incomparable_proofs(
    baseline_impact: tuple[str, str, str],
    candidate_impact: tuple[str, str, str],
) -> None:
    baseline = _confirmation(
        1,
        confidentiality=baseline_impact[0],
        integrity=baseline_impact[1],
        availability=baseline_impact[2],
    )
    candidate = _confirmation(
        2,
        confidentiality=candidate_impact[0],
        integrity=candidate_impact[1],
        availability=candidate_impact[2],
    )

    assert verify_stage._select_strongest_confirmation(
        [baseline, candidate]
    ) is baseline


@pytest.mark.asyncio
async def test_non_full_compromise_upload_keeps_historical_single_strategy_path(
    monkeypatch, tmp_path
):
    author_contexts: list[dict] = []

    class FakePoCAuthor:
        def __init__(self, *_args, **_kwargs):
            pass

        async def write(self, **kwargs):
            author_contexts.append(kwargs["extra_context"])
            return "BASELINE_SCRIPT\n"

    class ConfirmingSandbox(_Sandbox):
        def __init__(self, path):
            super().__init__(path)
            partial = _observation(full_compromise=False)
            self.results = iter([partial, partial])

        async def run_poc(self, script_path, **kwargs):
            self.executed_scripts.append(Path(script_path).read_text())
            self.run_kwargs.append(kwargs)
            return SandboxRunResult(
                success=True,
                output="SQUADRONE_RESULT={}",
                elapsed=0,
                observation=next(self.results).model_copy(deep=True),
            )

    monkeypatch.setattr(verify_stage, "PoCAuthorAgent", FakePoCAuthor)
    sandbox = ConfirmingSandbox(tmp_path)

    finding = await verify_stage._verify_one(
        _non_full_compromise_upload_hypothesis(),
        str(tmp_path),
        str(tmp_path / "plugin.zip"),
        "plugin",
        _config(3),
        object(),
        tmp_path / "verification",
        persistent_sb=sandbox,
    )

    assert finding is not None
    assert len(author_contexts) == 1
    assert "verification_target" not in author_contexts[0]
    assert "executable_upload_oracle" not in author_contexts[0]
    assert len(sandbox.executed_scripts) == 2
    assert all(
        options["expected_executable_upload"] is False
        for options in sandbox.run_kwargs
    )


@pytest.mark.asyncio
async def test_lower_bound_confirmation_refines_and_selects_stronger_proof(
    monkeypatch, tmp_path
):
    author_contexts: list[dict] = []

    class FakePoCAuthor:
        def __init__(self, *_args, **_kwargs):
            pass

        async def write(self, **kwargs):
            author_contexts.append(kwargs["extra_context"])
            return f"AUTHORED_SCRIPT_{len(author_contexts)}\n"

    class ProgressSandbox(_Sandbox):
        def __init__(self, path):
            super().__init__(path)
            partial = _observation(full_compromise=False)
            strong = _observation(full_compromise=True)
            self.results = iter([partial, partial, strong, strong])

        async def run_poc(self, script_path, **_kwargs):
            self.executed_scripts.append(Path(script_path).read_text())
            self.run_kwargs.append(_kwargs)
            observation = next(self.results).model_copy(deep=True)
            return SandboxRunResult(
                success=True,
                output="SQUADRONE_RESULT={}",
                elapsed=0,
                observation=observation,
            )

    monkeypatch.setattr(verify_stage, "PoCAuthorAgent", FakePoCAuthor)
    sandbox = ProgressSandbox(tmp_path)
    poc_dir = tmp_path / "verification"

    finding = await verify_stage._verify_one(
        _full_compromise_hypothesis(),
        str(tmp_path),
        str(tmp_path / "plugin.zip"),
        "plugin",
        _config(2),
        object(),
        poc_dir,
        persistent_sb=sandbox,
    )

    assert finding is not None
    assert len(author_contexts) == 2
    assert "verified_partial_proof" not in author_contexts[0]
    assert author_contexts[0]["executable_upload_oracle"] == {
        "mode": "post_upload_challenge_v1",
        "payload_environment": "SQUADRONE_EXEC_UPLOAD_PAYLOAD_B64",
        "attack_filename_environment": (
            "SQUADRONE_EXEC_UPLOAD_ATTACK_FILENAME"
        ),
        "control_filename_environment": (
            "SQUADRONE_EXEC_UPLOAD_CONTROL_FILENAME"
        ),
        "challenge_parameter": "squadrone_challenge",
        "response_prefix": "SQUADRONE_UPLOAD_EXEC_V1:",
        "response_derivation": (
            "implemented by the exact parent-generated PHP payload; "
            "the child must not reconstruct or alter those bytes"
        ),
    }
    assert author_contexts[1]["verified_partial_proof"]["oracle"] == "file_effect"
    assert author_contexts[1]["verified_partial_proof"]["unmet_dimensions"] == {
        "confidentiality": "none",
        "availability": "none",
    }
    assert sandbox.executed_scripts == [
        "AUTHORED_SCRIPT_1\n",
        "AUTHORED_SCRIPT_1\n",
        "AUTHORED_SCRIPT_2\n",
        "AUTHORED_SCRIPT_2\n",
    ]
    assert all(
        options["expected_executable_upload"] is True
        for options in sandbox.run_kwargs
    )
    assert all(
        options["expected_http_transport"]
        == {
            "method": "POST",
            "route": "/wp-admin/admin-ajax.php",
            "dispatch": {"form:action": "upload"},
        }
        for options in sandbox.run_kwargs
    )
    assert finding.poc_script_path.endswith("iter_2.py")
    assert finding.verified_impact == CIAImpact(
        confidentiality="high",
        integrity="high",
        availability="high",
        description="The execution-only marker proved full sandbox compromise.",
    )
    assert finding.confidence_runs == 2


@pytest.mark.asyncio
async def test_failed_full_compromise_refinement_retains_confirmed_lower_bound(
    monkeypatch, tmp_path
):
    author_calls = 0

    class FakePoCAuthor:
        def __init__(self, *_args, **_kwargs):
            pass

        async def write(self, **_kwargs):
            nonlocal author_calls
            author_calls += 1
            return f"AUTHORED_SCRIPT_{author_calls}\n"

    class FallbackSandbox(_Sandbox):
        def __init__(self, path):
            super().__init__(path)
            partial = _observation(full_compromise=False)
            self.results = iter([partial, partial, None])

        async def run_poc(self, script_path, **_kwargs):
            self.executed_scripts.append(Path(script_path).read_text())
            observation = next(self.results)
            if observation is None:
                return SandboxRunResult(success=False, output="", elapsed=0)
            return SandboxRunResult(
                success=True,
                output="SQUADRONE_RESULT={}",
                elapsed=0,
                observation=observation.model_copy(deep=True),
            )

    monkeypatch.setattr(verify_stage, "PoCAuthorAgent", FakePoCAuthor)
    sandbox = FallbackSandbox(tmp_path)
    poc_dir = tmp_path / "verification"

    finding = await verify_stage._verify_one(
        _full_compromise_hypothesis(),
        str(tmp_path),
        str(tmp_path / "plugin.zip"),
        "plugin",
        _config(3),
        object(),
        poc_dir,
        persistent_sb=sandbox,
    )

    assert finding is not None
    assert author_calls == 2
    assert sandbox.executed_scripts == [
        "AUTHORED_SCRIPT_1\n",
        "AUTHORED_SCRIPT_1\n",
        "AUTHORED_SCRIPT_2\n",
    ]
    assert finding.poc_script_path.endswith("iter_1.py")
    assert finding.verified_impact == CIAImpact(
        confidentiality="none",
        integrity="high",
        availability="none",
        description="The attacker created a file through the vulnerable workflow.",
    )
    assert finding.confidence_runs == 2


@pytest.mark.asyncio
async def test_refinement_author_failure_retains_confirmed_lower_bound(
    monkeypatch, tmp_path
):
    author_calls = 0

    class FailingRefinementAuthor:
        def __init__(self, *_args, **_kwargs):
            pass

        async def write(self, **_kwargs):
            nonlocal author_calls
            author_calls += 1
            if author_calls == 2:
                raise RuntimeError("author unavailable")
            return "BASELINE_SCRIPT\n"

    class ConfirmingSandbox(_Sandbox):
        def __init__(self, path):
            super().__init__(path)
            partial = _observation(full_compromise=False)
            self.results = iter([partial, partial])

        async def run_poc(self, script_path, **_kwargs):
            self.executed_scripts.append(Path(script_path).read_text())
            return SandboxRunResult(
                success=True,
                output="SQUADRONE_RESULT={}",
                elapsed=0,
                observation=next(self.results).model_copy(deep=True),
            )

    monkeypatch.setattr(verify_stage, "PoCAuthorAgent", FailingRefinementAuthor)
    sandbox = ConfirmingSandbox(tmp_path)

    finding = await verify_stage._verify_one(
        _full_compromise_hypothesis(),
        str(tmp_path),
        str(tmp_path / "plugin.zip"),
        "plugin",
        _config(2),
        object(),
        tmp_path / "verification",
        persistent_sb=sandbox,
    )

    assert finding is not None
    assert author_calls == 2
    assert finding.poc_script_path.endswith("iter_1.py")
    assert finding.verified_impact.integrity == "high"
    assert finding.verified_impact.confidentiality == "none"


@pytest.mark.asyncio
async def test_refinement_snapshot_failure_retains_confirmed_lower_bound(
    monkeypatch, tmp_path
):
    class FakePoCAuthor:
        def __init__(self, *_args, **_kwargs):
            pass

        async def write(self, **_kwargs):
            return "AUTHORED_SCRIPT\n"

    class SnapshotFailingSandbox(_Sandbox):
        def __init__(self, path):
            super().__init__(path)
            partial = _observation(full_compromise=False)
            self.results = iter([partial, partial])

        async def snapshot(self):
            if self.snapshot_count == 1:
                raise RuntimeError("snapshot unavailable")
            return await super().snapshot()

        async def run_poc(self, script_path, **_kwargs):
            self.executed_scripts.append(Path(script_path).read_text())
            return SandboxRunResult(
                success=True,
                output="SQUADRONE_RESULT={}",
                elapsed=0,
                observation=next(self.results).model_copy(deep=True),
            )

    monkeypatch.setattr(verify_stage, "PoCAuthorAgent", FakePoCAuthor)
    sandbox = SnapshotFailingSandbox(tmp_path)

    finding = await verify_stage._verify_one(
        _full_compromise_hypothesis(),
        str(tmp_path),
        str(tmp_path / "plugin.zip"),
        "plugin",
        _config(2),
        object(),
        tmp_path / "verification",
        persistent_sb=sandbox,
    )

    assert finding is not None
    assert sandbox.executed_scripts == ["AUTHORED_SCRIPT\n", "AUTHORED_SCRIPT\n"]
    assert finding.poc_script_path.endswith("iter_1.py")
    assert finding.verified_impact.integrity == "high"
    attempts = json.loads(
        (tmp_path / "verification" / "attempts.json").read_text()
    )["attempts"]
    assert attempts[-1]["validation_reason"].startswith(
        "clean-state snapshot failed:"
    )


@pytest.mark.asyncio
async def test_refinement_setup_callback_restore_failure_propagates(
    monkeypatch, tmp_path
):
    class CallbackUsingAuthor:
        def __init__(self, *_args, setup_callback, **_kwargs):
            self.setup_callback = setup_callback
            self.calls = 0

        async def write(self, **_kwargs):
            self.calls += 1
            if self.calls == 2:
                try:
                    await self.setup_callback("Create the missing benign object.")
                except RuntimeError:
                    # Agent runtimes render tool exceptions as feedback and may
                    # still return a script. The verifier latch must still win.
                    pass
            return f"AUTHORED_SCRIPT_{self.calls}\n"

    class FailingWpCli:
        async def _exec_result(self, *_args, **_kwargs):
            return 1, "", "setup command failed"

    class CallbackFailureDeveloper(_Developer):
        async def propose_requested_setup(self, **_kwargs):
            return RequestedSetupPlan(
                rationale="Create a benign prerequisite.",
                commands=[["option", "update", "demo_ready", "1"]],
            )

    class CallbackFailureSandbox(_Sandbox):
        def __init__(self, path):
            super().__init__(path)
            self.wp_cli = FailingWpCli()
            self.restore_count = 0
            partial = _observation(full_compromise=False)
            self.results = iter([partial, partial])

        async def restore(self, _snapshot):
            self.restore_count += 1
            if self.restore_count == 3:
                raise RuntimeError("atomic setup rollback failed")

        async def run_poc(self, script_path, **_kwargs):
            self.executed_scripts.append(Path(script_path).read_text())
            return SandboxRunResult(
                success=True,
                output="SQUADRONE_RESULT={}",
                elapsed=0,
                observation=next(self.results).model_copy(deep=True),
            )

    monkeypatch.setattr(verify_stage, "PoCAuthorAgent", CallbackUsingAuthor)

    with pytest.raises(
        RuntimeError,
        match="PoC-requested setup failed during authoring",
    ) as exc_info:
        await verify_stage._verify_one(
            _full_compromise_hypothesis(),
            str(tmp_path),
            str(tmp_path / "plugin.zip"),
            "plugin",
            _config(2),
            object(),
            tmp_path / "verification",
            developer=CallbackFailureDeveloper(),
            persistent_sb=CallbackFailureSandbox(tmp_path),
        )

    assert exc_info.value.__cause__ is not None
    assert "atomic setup rollback failed" in str(exc_info.value.__cause__)


@pytest.mark.asyncio
async def test_refinement_attack_restore_failure_propagates_and_keeps_snapshot(
    monkeypatch, tmp_path
):
    class FakePoCAuthor:
        def __init__(self, *_args, **_kwargs):
            pass

        async def write(self, **_kwargs):
            return "AUTHORED_SCRIPT\n"

    class RestoreFailingSandbox(_Sandbox):
        def __init__(self, path):
            super().__init__(path)
            self.restore_count = 0
            partial = _observation(full_compromise=False)
            self.results = iter([partial, partial, None])

        async def restore(self, _snapshot):
            self.restore_count += 1
            if self.restore_count == 3:
                raise RuntimeError("refinement state restore failed")

        async def run_poc(self, script_path, **_kwargs):
            self.executed_scripts.append(Path(script_path).read_text())
            observation = next(self.results)
            if observation is None:
                return SandboxRunResult(success=False, output="", elapsed=0)
            return SandboxRunResult(
                success=True,
                output="SQUADRONE_RESULT={}",
                elapsed=0,
                observation=observation.model_copy(deep=True),
            )

    monkeypatch.setattr(verify_stage, "PoCAuthorAgent", FakePoCAuthor)
    sandbox = RestoreFailingSandbox(tmp_path)

    with pytest.raises(RuntimeError, match="refinement state restore failed"):
        await verify_stage._verify_one(
            _full_compromise_hypothesis(),
            str(tmp_path),
            str(tmp_path / "plugin.zip"),
            "plugin",
            _config(2),
            object(),
            tmp_path / "verification",
            persistent_sb=sandbox,
        )

    assert (tmp_path / "snapshot-2").is_dir()
