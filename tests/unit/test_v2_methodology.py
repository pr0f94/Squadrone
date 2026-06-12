from __future__ import annotations

import pytest

from squadrone.agents.critic import CriticAgent
from squadrone.schemas import (
    BugClass,
    Confidence,
    EntryPoint,
    Hypothesis,
    HypothesesArtifact,
    ReconArtifact,
    SecurityProfile,
    Sink,
    TriagedArtifact,
)
from squadrone.schemas.config import PipelineConfig
from squadrone.stages import hypothesis as hypothesis_stage
from squadrone.stages import triage as triage_stage


def _hypothesis(hypothesis_id: str = "h-1") -> Hypothesis:
    return Hypothesis(
        id=hypothesis_id,
        specialist="object_authz",
        bug_class=BugClass.IDOR,
        entry_point="wp_ajax_demo",
        file="demo.php",
        line=10,
        sink="get_post_meta",
        sink_code="get_post_meta($_GET['id'], '_secret', true);",
        taint_path=["$_GET['id']", "get_post_meta"],
        reasoning="Subscriber can read another user's sensitive submission.",
        confidence=Confidence.HIGH,
        preconditions="subscriber",
        affected_versions="<=1.0",
    )


def _recon() -> ReconArtifact:
    return ReconArtifact(
        plugin_slug="demo",
        entry_points=[
            EntryPoint(
                type="ajax_priv",
                name="wp_ajax_demo",
                file="demo.php",
                line=1,
                handler_function="demo",
                requires_auth=True,
                has_nonce_check=True,
                has_capability_check=False,
            )
        ],
        sinks=[
            Sink(
                type="db_query",
                function="get_post_meta",
                file="demo.php",
                line=10,
                tainted_args=["id"],
            )
        ],
        entry_to_sink_paths={"wp_ajax_demo": ["demo.php:1 -> demo.php:10"]},
        raw_grep_hits={},
        security_profile=SecurityProfile(
            plugin_type="forms",
            sensitive_objects=["submission"],
            state_changing_workflows=["submission approval"],
            stored_input_to_privileged_view=["guest submission -> admin entries table"],
        ),
    )


class _Output:
    def __init__(self, accepted: list[Hypothesis] | None = None):
        self.plugin_slug = "demo"
        self.accepted = accepted or []
        self.rejected = []
        self.merged = []
        self.request_reframing = []


class _Result:
    def __init__(self, output):
        self.output = output


class _Runtime:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def run(self, **kwargs):
        self.calls.append(kwargs)
        return _Result(TriagedArtifact(plugin_slug="demo", accepted=[], rejected=[], merged=[]))


def test_recon_security_profile_round_trips(tmp_path):
    recon = _recon()
    path = tmp_path / "recon.json"

    recon.to_json_file(str(path))
    loaded = ReconArtifact.from_json_file(str(path))

    assert loaded.security_profile is not None
    assert loaded.security_profile.plugin_type == "forms"
    assert "submission" in loaded.security_profile.sensitive_objects


def test_default_specialist_set_includes_v2_agents():
    specialists = hypothesis_stage._build_specialists(_Runtime(), "test-model")
    names = [s.NAME for s in specialists]

    assert "object_authz" in names
    assert "state_change" in names
    assert "payment_logic" in names
    assert "stored_to_admin" in names


def test_v2_specialist_patterns_prioritize_relevant_files():
    code_slices = {
        "orders.php": "function callback() { $order = wc_get_order($_GET['order_id']); $order->payment_complete(); }",
        "assets.css": ".button { color: red; }",
        "entries.php": "echo get_post_meta($_GET['entry_id'], '_secret', true);",
    }

    payment = hypothesis_stage._filter_slices_for_specialist(code_slices, "payment_logic")
    object_authz = hypothesis_stage._filter_slices_for_specialist(code_slices, "object_authz")

    assert "orders.php" in payment
    assert "assets.css" not in payment
    assert "entries.php" in object_authz


@pytest.mark.asyncio
async def test_critic_prompt_always_includes_adversarial_review():
    runtime = _Runtime()
    critic = CriticAgent(runtime, model="test-model")

    await critic.review(HypothesesArtifact(plugin_slug="demo", hypotheses=[_hypothesis()]), {}, apply_scope_filter=False)

    system = runtime.calls[0]["messages"][0]["content"]
    assert "Squadrone V2 adversarial review" in system
    assert "strongest Patchstack or Wordfence rejection reason" in system


@pytest.mark.asyncio
async def test_multi_vote_final_critic_is_adversarial(monkeypatch, tmp_path):
    seen_modes: list[str] = []

    class FakeCritic:
        def __init__(self, *args, review_mode="standard", **kwargs):
            seen_modes.append(review_mode)

        async def review(self, hypotheses, code_slices, apply_scope_filter=True):
            return TriagedArtifact(
                plugin_slug=hypotheses.plugin_slug,
                accepted=[],
                rejected=[{"hypothesis_id": "h-1", "reason": "reject"}],
                merged=[],
            )

    cfg = PipelineConfig.from_yaml("pipelines/default.yaml")
    cfg.triage.verifier_votes = 3
    monkeypatch.setattr(triage_stage, "CriticAgent", FakeCritic)
    monkeypatch.setattr(triage_stage, "_build_code_slices", lambda recon, plugin_path: {})

    await triage_stage.run(
        HypothesesArtifact(plugin_slug="demo", hypotheses=[_hypothesis()]),
        plugin_path=str(tmp_path),
        config=cfg,
        budget=None,
        runtime=_Runtime(),
        recon=_recon(),
        runs_root=str(tmp_path),
        run_id="run1",
        apply_scope_filter=False,
    )

    assert seen_modes == ["standard", "standard", "adversarial"]
