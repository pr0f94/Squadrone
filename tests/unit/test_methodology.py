from __future__ import annotations

from types import SimpleNamespace

import pytest

from squadrone.agents.critic import CriticAgent
from squadrone.schemas import (
    BugClass,
    Confidence,
    CoverageArtifact,
    CoverageDisposition,
    CoverageItem,
    EntryPoint,
    Hypothesis,
    HypothesesArtifact,
    ReconArtifact,
    SecurityProfile,
    Sink,
    StaticCallEdge,
    TriagedArtifact,
)
from squadrone.schemas.config import PipelineConfig
from squadrone.schemas.hypothesis import SpecialistReviewArtifact
from squadrone.agents._specialist_base import _compact_recon, _enforce_read_evidence
from squadrone.agents.plugin_tools import PluginToolHandlers
from squadrone.agents.prompts_io import load_prompt
from squadrone.stages.hypothesis import (
    _batch_input_fingerprint,
    _build_review_batches,
    _canonicalize_batch_hypotheses,
    _reconcile_batch_coverage,
)
from squadrone.stages import hypothesis as hypothesis_stage
from squadrone.stages.triage import _validate_critic_accounting
from squadrone.services.budget import BudgetTracker


def _hypothesis(hypothesis_id: str = "h-1", line: int = 10) -> Hypothesis:
    return Hypothesis(
        id=hypothesis_id,
        specialist="authorization_workflows",
        bug_class=BugClass.IDOR,
        entry_point="wp_ajax_demo",
        file="demo.php",
        line=line,
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


def test_primitive_coverage_does_not_lower_authentication_candidate_bar():
    prompt = load_prompt("specialists/authentication")
    normalized = " ".join(prompt.split())

    assert "generic use of MD5/SHA1" in prompt
    assert "Prove the attacker can obtain, predict, forge, replay" in normalized
    assert "protected-data" in prompt


class _Result:
    def __init__(self, output):
        self.output = output


class _Runtime:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def run(self, **kwargs):
        self.calls.append(kwargs)
        return _Result(
            TriagedArtifact(plugin_slug="demo", accepted=[], rejected=[], merged=[])
        )


def test_recon_security_profile_round_trips(tmp_path):
    path = tmp_path / "recon.json"
    _recon().to_json_file(str(path))

    loaded = ReconArtifact.from_json_file(str(path))

    assert loaded.security_profile is not None
    assert loaded.security_profile.plugin_type == "forms"
    assert "submission" in loaded.security_profile.sensitive_objects


def test_default_review_areas_are_four_fixed_owners():
    reviewers = hypothesis_stage._build_specialists(_Runtime(), "test-model")

    assert [reviewer.NAME for reviewer in reviewers] == [
        "authorization_workflows",
        "injection_files",
        "xss_lifecycle",
        "authentication",
    ]


def test_critic_slice_is_centered_on_emitted_location_not_file_prefix(tmp_path):
    lines = [f"line {number}" for number in range(1, 901)]
    lines[749] = "get_post_meta($_GET['id'], '_secret', true);"
    (tmp_path / "demo.php").write_text("\n".join(lines))

    slices = hypothesis_stage._build_code_slices([_hypothesis(line=750)], tmp_path)

    assert "  750  get_post_meta" in slices["demo.php"]
    assert "    1  line 1" not in slices["demo.php"]
    assert "  720  line 720" in slices["demo.php"]
    assert "  780  line 780" in slices["demo.php"]


@pytest.mark.asyncio
async def test_critic_is_adversarial_but_scope_independent():
    runtime = _Runtime()
    critic = CriticAgent(runtime, model="test-model")

    await critic.review(
        HypothesesArtifact(plugin_slug="demo", hypotheses=[_hypothesis()]), {}
    )

    system = runtime.calls[0]["messages"][0]["content"]
    assert "strongest technical reason" in system
    assert "Disclosure-program routing happens separately" in system
    assert "Patchstack or Wordfence rejection" not in system


def test_critic_accounting_requires_every_input_disposition():
    inputs = HypothesesArtifact(
        plugin_slug="demo",
        hypotheses=[_hypothesis("h-1"), _hypothesis("h-2")],
    )
    output = TriagedArtifact(
        plugin_slug="demo",
        accepted=[_hypothesis("h-1")],
        rejected=[],
        merged=[],
    )

    with pytest.raises(ValueError, match="omitted hypothesis ids"):
        _validate_critic_accounting(inputs, output)


def test_critic_accounting_accepts_valid_manual_handoff():
    hypothesis = _hypothesis("h-manual")
    inputs = HypothesesArtifact(plugin_slug="demo", hypotheses=[hypothesis])
    output = TriagedArtifact(
        plugin_slug="demo",
        accepted=[],
        rejected=[],
        merged=[],
        manual_review=[
            {
                "hypothesis_id": hypothesis.id,
                "reason": "browser-only runtime fact",
                "hypothesis": hypothesis.model_dump(mode="json"),
            }
        ],
    )

    _validate_critic_accounting(inputs, output)


def test_review_batches_are_bounded_and_source_local():
    targets = [
        CoverageItem(
            id=f"cov-{index:04d}",
            kind="entry_point",
            review_areas=["authorization_workflows"],
            type="rest_route",
            name=f"demo/v1/{index}",
            file=f"file-{(index - 1) // 5:02d}.php",
            line=index,
            snippet="register_rest_route(...)" * 20,
            handler_function=f"handler_{index}",
        )
        for index in range(1, 51)
    ]

    batches = _build_review_batches(targets)

    assert sum(len(batch) for batch in batches) == len(targets)
    assert all(len(batch) <= 8 for batch in batches)
    assert all(len({item.file for item in batch}) <= 6 for batch in batches)
    assert [item.id for batch in batches for item in batch] == [
        item.id for item in targets
    ]


def test_batch_checkpoint_fingerprint_covers_target_semantics_and_recon_context():
    target = CoverageItem(
        id="cov-0001",
        kind="sink",
        review_areas=["injection_files"],
        type="file_write",
        name="file_put_contents",
        file="lib/php/filesystem.php",
        line=50,
        snippet="file_put_contents($path, $content);",
    )
    recon = _recon()
    initial = _batch_input_fingerprint(recon, [target], "injection_files")

    changed_target = target.model_copy(update={"line": 51})
    changed_context = recon.model_copy(deep=True)
    changed_context.entry_points.append(
        EntryPoint(
            type="direct_php",
            name="lib/php/connector.php",
            file="lib/php/connector.php",
            line=3,
            handler_function="",
            requires_auth=False,
            has_nonce_check=False,
            has_capability_check=False,
            source="deterministic",
            access_known=True,
        )
    )

    assert (
        _batch_input_fingerprint(
            recon,
            [changed_target],
            "injection_files",
        )
        != initial
    )
    assert (
        _batch_input_fingerprint(
            changed_context,
            [target],
            "injection_files",
        )
        != initial
    )


def test_batch_coverage_requires_exact_assigned_location():
    target = CoverageItem(
        id="cov-0001",
        kind="entry_point",
        review_areas=["authorization_workflows"],
        type="ajax_nopriv",
        name="wp_ajax_nopriv_demo",
        file="demo.php",
        line=10,
        snippet="add_action(...)",
        handler_function="demo",
    )
    wrong = SpecialistReviewArtifact(
        hypotheses=[],
        coverage=[
            CoverageDisposition(
                item_id=target.id,
                reviewer="authorization_workflows",
                status="reviewed",
                reason="A different line was inspected.",
                evidence_locations=["demo.php:11"],
            )
        ],
    )
    valid = SpecialistReviewArtifact(
        hypotheses=[],
        coverage=[
            CoverageDisposition(
                item_id=target.id,
                reviewer="authorization_workflows",
                status="reviewed",
                reason="The exact registration and handler were inspected.",
                evidence_locations=["demo.php:10", "demo.php:20"],
            )
        ],
    )

    _, unresolved, _ = _reconcile_batch_coverage(
        wrong,
        [target],
        "authorization_workflows",
    )
    accepted, valid_unresolved, linked = _reconcile_batch_coverage(
        valid,
        [target],
        "authorization_workflows",
    )

    assert unresolved == [target]
    assert valid_unresolved == []
    assert accepted[0].item_id == target.id
    assert linked == set()


def test_specialist_payload_omits_full_recon_and_disposition_requires_read(tmp_path):
    source = tmp_path / "demo.php"
    source.write_text(
        "<?php\nadd_action('wp_ajax_demo', 'demo');\nfunction demo() {}\n"
    )
    target = CoverageItem(
        id="cov-0001",
        kind="entry_point",
        review_areas=["authorization_workflows"],
        type="ajax_priv",
        name="wp_ajax_demo",
        file="demo.php",
        line=2,
        snippet="add_action('wp_ajax_demo', 'demo');",
        handler_function="demo",
    )
    recon = _recon().model_copy(
        update={
            "coverage": CoverageArtifact(items=[target]),
            "raw_grep_hits": {"large": ["noise"] * 100},
        }
    )

    compact = _compact_recon(recon, [target])

    assert "coverage" not in compact
    assert "raw_grep_hits" not in compact
    assert "body_slice" not in compact["entry_points"][0]

    handlers = PluginToolHandlers(tmp_path)
    artifact = SpecialistReviewArtifact(
        hypotheses=[],
        coverage=[
            CoverageDisposition(
                item_id=target.id,
                reviewer="authorization_workflows",
                status="reviewed",
                reason="The callback registration and handler were checked.",
                evidence_locations=["demo.php:2"],
            )
        ],
    )
    without_read = _enforce_read_evidence(
        artifact.model_copy(deep=True),
        handlers,
        [target],
    )
    handlers.read_plugin_file({"path": "demo.php", "start_line": 1, "end_line": 3})
    with_read = _enforce_read_evidence(
        artifact.model_copy(deep=True),
        handlers,
        [target],
    )

    assert without_read.coverage[0].status == "unreviewed"
    assert with_read.coverage[0].status == "reviewed"


def test_compact_recon_includes_every_static_caller_to_shared_sink():
    entries = [
        EntryPoint(
            type="rest_route",
            name="demo/v1/public-upload",
            file="api.php",
            line=10,
            handler_function="public_upload",
            requires_auth=True,
            has_nonce_check=False,
            has_capability_check=False,
        ),
        EntryPoint(
            type="rest_route",
            name="demo/v1/protected-upload",
            file="admin.php",
            line=10,
            handler_function="protected_upload",
            requires_auth=True,
            has_nonce_check=True,
            has_capability_check=True,
        ),
        EntryPoint(
            type="rest_route",
            name="demo/v1/unrelated",
            file="other.php",
            line=10,
            handler_function="unrelated",
            requires_auth=True,
            has_nonce_check=True,
            has_capability_check=True,
        ),
    ]
    edges = [
        StaticCallEdge(
            caller="public_upload",
            callee="prepare_upload",
            caller_file="api.php",
            caller_line=20,
            callee_file="api.php",
            callee_line=30,
            confidence="high",
        ),
        StaticCallEdge(
            caller="prepare_upload",
            callee="store_file",
            caller_file="api.php",
            caller_line=35,
            callee_file="files.php",
            callee_line=40,
            confidence="high",
        ),
        StaticCallEdge(
            caller="protected_upload",
            callee="store_file",
            caller_file="admin.php",
            caller_line=25,
            callee_file="files.php",
            callee_line=40,
            confidence="high",
        ),
    ]
    recon = ReconArtifact(
        plugin_slug="demo",
        entry_points=entries,
        sinks=[
            Sink(
                type="file_write",
                function="copy",
                file="files.php",
                line=50,
                tainted_args=["source"],
            )
        ],
        entry_to_sink_paths={},
        raw_grep_hits={},
        static_call_edges=edges,
    )
    target = CoverageItem(
        id="cov-0001",
        kind="sink",
        review_areas=["injection_files"],
        type="file_write",
        name="copy",
        file="files.php",
        line=50,
        snippet="copy($source, $destination);",
    )

    compact = _compact_recon(recon, [target])

    assert {entry["name"] for entry in compact["entry_points"]} == {
        "demo/v1/public-upload",
        "demo/v1/protected-upload",
    }
    assert "files.php:50" in compact["entry_to_sink_paths"]["demo/v1/public-upload"][0]
    assert (
        "files.php:50" in compact["entry_to_sink_paths"]["demo/v1/protected-upload"][0]
    )


@pytest.mark.parametrize("entry_type", ["direct_php", "direct_php_candidate"])
def test_compact_recon_includes_same_directory_direct_php_entry_for_file_sink(
    entry_type,
):
    recon = ReconArtifact(
        plugin_slug="demo",
        entry_points=[
            EntryPoint(
                type=entry_type,
                name="lib/php/connector.php",
                file="lib/php/connector.php",
                line=3,
                handler_function="",
                requires_auth=False,
                has_nonce_check=False,
                has_capability_check=False,
                source="deterministic",
                access_known=True,
            ),
            EntryPoint(
                type="direct_php",
                name="admin/connector.php",
                file="admin/connector.php",
                line=3,
                handler_function="",
                requires_auth=False,
                has_nonce_check=False,
                has_capability_check=False,
                source="deterministic",
                access_known=True,
            ),
        ],
        sinks=[
            Sink(
                type="file_write",
                function="file_put_contents",
                file="lib/php/filesystem.php",
                line=50,
                tainted_args=["content"],
            )
        ],
        entry_to_sink_paths={},
        raw_grep_hits={},
    )
    target = CoverageItem(
        id="cov-0001",
        kind="sink",
        review_areas=["injection_files"],
        type="file_write",
        name="file_put_contents",
        file="lib/php/filesystem.php",
        line=50,
        snippet="file_put_contents($path, $content);",
    )

    compact = _compact_recon(recon, [target])

    assert [entry["name"] for entry in compact["entry_points"]] == [
        "lib/php/connector.php",
    ]


def test_read_evidence_filters_unseen_locations_before_reconciliation(tmp_path):
    (tmp_path / "demo.php").write_text("<?php\nregistration();\nhandler();\n")
    handlers = PluginToolHandlers(tmp_path)
    handlers.read_plugin_file({"path": "demo.php", "start_line": 3, "end_line": 3})
    target = CoverageItem(
        id="cov-0001",
        kind="entry_point",
        review_areas=["authorization_workflows"],
        type="ajax_priv",
        name="wp_ajax_demo",
        file="demo.php",
        line=2,
        snippet="registration();",
    )
    artifact = SpecialistReviewArtifact(
        hypotheses=[],
        coverage=[
            CoverageDisposition(
                item_id="cov-0001",
                reviewer="authorization_workflows",
                status="reviewed",
                reason="Only the handler line was actually read.",
                evidence_locations=["demo.php:2", "demo.php:3"],
            )
        ],
    )

    enforced = _enforce_read_evidence(artifact, handlers, [target])

    assert enforced.coverage[0].evidence_locations == ["demo.php:3"]


def test_minified_target_disposition_requires_assigned_column_read(tmp_path):
    source = "x" * 70_000 + "new Function('return 1')();"
    (tmp_path / "app.js").write_text(source)
    target = CoverageItem(
        id="cov-0001",
        kind="sink",
        review_areas=["xss_lifecycle"],
        type="javascript_eval",
        name="Function",
        file="app.js",
        line=1,
        column=70_005,
        snippet="new Function('return 1')",
    )
    artifact = SpecialistReviewArtifact(
        hypotheses=[],
        coverage=[
            CoverageDisposition(
                item_id=target.id,
                reviewer="xss_lifecycle",
                status="reviewed",
                reason="The assigned constructor was inspected.",
                evidence_locations=["app.js:1"],
            )
        ],
    )
    handlers = PluginToolHandlers(tmp_path)
    handlers.read_plugin_file({"path": "app.js", "start_line": 1})

    initial = _enforce_read_evidence(artifact.model_copy(deep=True), handlers, [target])
    handlers.read_plugin_file(
        {
            "path": "app.js",
            "start_line": 1,
            "start_column": 69_950,
        }
    )
    targeted = _enforce_read_evidence(
        artifact.model_copy(deep=True), handlers, [target]
    )

    assert initial.coverage[0].status == "unreviewed"
    assert targeted.coverage[0].status == "reviewed"


def test_candidate_disposition_must_link_an_emitted_hypothesis():
    target = CoverageItem(
        id="cov-0001",
        kind="sink",
        review_areas=["injection_files"],
        type="sql_query",
        name="query",
        file="demo.php",
        line=10,
        snippet="$wpdb->query($sql);",
    )
    result = SpecialistReviewArtifact(
        hypotheses=[_hypothesis("model-id", line=10)],
        coverage=[
            CoverageDisposition(
                item_id=target.id,
                reviewer="injection_files",
                status="candidate",
                reason="The query receives request-controlled SQL.",
                evidence_locations=["demo.php:10"],
                hypothesis_ids=[],
            )
        ],
    )

    _, unresolved, linked = _reconcile_batch_coverage(
        result,
        [target],
        "injection_files",
    )
    result.coverage[0].hypothesis_ids = ["model-id"]
    accepted, resolved, valid_linked = _reconcile_batch_coverage(
        result,
        [target],
        "injection_files",
    )

    assert unresolved == [target]
    assert linked == set()
    assert resolved == []
    assert accepted[0].status == "candidate"
    assert valid_linked == {"model-id"}


def test_canonical_hypothesis_ids_can_replace_coverage_links():
    hypothesis = _hypothesis("model-id")
    disposition = CoverageDisposition(
        item_id="cov-0001",
        reviewer="authorization_workflows",
        status="candidate",
        reason="Concrete cross-object read.",
        evidence_locations=["demo.php:10"],
        hypothesis_ids=["model-id"],
    )

    id_map = _canonicalize_batch_hypotheses(
        [hypothesis],
        "authorization_workflows",
        2,
    )
    disposition.hypothesis_ids = [id_map[item] for item in disposition.hypothesis_ids]

    assert hypothesis.id == "authz-b002-001"
    assert disposition.hypothesis_ids == [hypothesis.id]


def test_canonicalization_uses_registry_owner_without_culling_cross_discoveries():
    idor = _hypothesis("idor")
    weak_crypto = Hypothesis.model_validate(
        {
            **_hypothesis("crypto").model_dump(mode="json"),
            "bug_class": BugClass.WEAK_CRYPTO.value,
        }
    )
    unknown = Hypothesis.model_validate(
        {
            **_hypothesis("unknown").model_dump(mode="json"),
            "bug_class": "CWE-1234",
        }
    )
    excluded = Hypothesis.model_validate(
        {
            **_hypothesis("excluded").model_dump(mode="json"),
            "bug_class": BugClass.OPEN_REDIRECT.value,
        }
    )

    _canonicalize_batch_hypotheses(
        [idor, weak_crypto, unknown, excluded],
        "injection_files",
        4,
    )

    assert idor.specialist == "authorization_workflows"
    assert weak_crypto.specialist == "authentication"
    assert unknown.specialist == "injection_files"
    assert excluded.specialist == "injection_files"
    assert all(
        hypothesis.id.startswith("inject-b004-")
        for hypothesis in (idor, weak_crypto, unknown, excluded)
    )


@pytest.mark.asyncio
async def test_hypothesis_stage_checkpoints_canonical_coverage_links(
    monkeypatch, tmp_path
):
    target = CoverageItem(
        id="cov-0001",
        kind="entry_point",
        review_areas=["authorization_workflows"],
        type="ajax_priv",
        name="wp_ajax_demo",
        file="demo.php",
        line=1,
        snippet="add_action('wp_ajax_demo', 'demo');",
        handler_function="demo",
    )
    recon = _recon().model_copy(update={"coverage": CoverageArtifact(items=[target])})
    (tmp_path / "demo.php").write_text("<?php\n")

    class FakeSpecialist:
        NAME = "authorization_workflows"

        def __init__(self, fail: bool = False) -> None:
            self.calls = 0
            self.fail = fail

        async def analyze(self, *_args, **_kwargs):
            self.calls += 1
            if self.fail:
                raise AssertionError("valid checkpoint should skip the specialist")
            return SpecialistReviewArtifact(
                hypotheses=[_hypothesis("model-id")],
                coverage=[
                    CoverageDisposition(
                        item_id=target.id,
                        reviewer=self.NAME,
                        status="candidate",
                        reason="Subscriber can read another user's sensitive object.",
                        evidence_locations=["demo.php:1"],
                        hypothesis_ids=["model-id"],
                    )
                ],
            )

    async def fake_verify(_verifier, hypotheses, _plugin_path):
        return [
            SimpleNamespace(verdict="keep", reason="grounded", citation=None)
            for _ in hypotheses
        ]

    first = FakeSpecialist()
    monkeypatch.setattr(hypothesis_stage, "_build_specialists", lambda *_args: [first])
    monkeypatch.setattr(hypothesis_stage, "_verify_hypotheses", fake_verify)
    config = PipelineConfig.from_yaml("pipelines/test.yaml")
    runs_root = str(tmp_path / "runs")

    artifact = await hypothesis_stage.run(
        recon,
        str(tmp_path),
        config,
        BudgetTracker(10.0),
        SimpleNamespace(),
        runs_root=runs_root,
        run_id="run-1",
    )

    checkpoint_path = (
        tmp_path
        / "runs"
        / "run-1"
        / "review_batches"
        / "authorization_workflows"
        / "b001.json"
    )
    checkpoint = SpecialistReviewArtifact.model_validate_json(
        checkpoint_path.read_text()
    )
    assert artifact.hypotheses[0].id == "authz-b001-001"
    assert checkpoint.coverage[0].hypothesis_ids == [artifact.hypotheses[0].id]

    resumed = FakeSpecialist(fail=True)
    monkeypatch.setattr(
        hypothesis_stage, "_build_specialists", lambda *_args: [resumed]
    )
    await hypothesis_stage.run(
        recon,
        str(tmp_path),
        config,
        BudgetTracker(10.0),
        SimpleNamespace(),
        runs_root=runs_root,
        run_id="run-1",
    )
    assert resumed.calls == 0
