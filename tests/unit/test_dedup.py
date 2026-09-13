from __future__ import annotations

from datetime import datetime, timezone
import json

import pytest

from squadrone.schemas import (
    BugClass,
    Confidence,
    DedupStatus,
    Finding,
    Hypothesis,
    IntakeArtifact,
    PipelineConfig,
    PoCStatus,
)
from squadrone.services.artifacts import atomic_write_jsonl
from squadrone.services.dedup_helpers import (
    affected_version_match,
    derive_submission_recommendation,
    is_exact_semantic_match,
)
from squadrone.services.vuln_db import (
    WORDFENCE_FEED_URL,
    VulnDBClient,
    VulnLookupResult,
    VulnMatch,
    VulnSourceResult,
    VulnSourceStatus,
)
from squadrone.stages import dedup as dedup_stage
from squadrone.stages.dedup import DedupSourceUnavailableError, _classify_scored


def _finding(
    *,
    role: str = "subscriber",
    vulnerability_type: str = "arbitrary_file_upload_or_write",
) -> Finding:
    hypothesis = Hypothesis(
        id="inject-b004-001",
        specialist="injection_files",
        bug_class=BugClass.ARBITRARY_FILE_WRITE,
        entry_point="POST mwai/v1/simpleFileUpload via rest_simpleFileUpload",
        file="classes/modules/files.php",
        line=367,
        sink="copy at classes/modules/files.php:367",
        taint_path=["request", "copy"],
        reasoning="The supplied file is copied into public uploads.",
        confidence=Confidence.HIGH,
        preconditions=f"authenticated {role}",
        affected_versions="2.9.4",
        vulnerability_type=vulnerability_type,
        evidence_summary={"attacker_role": role},
    )
    return Finding(
        id="f-64c101a52c",
        hypothesis=hypothesis,
        poc_status=PoCStatus.SUCCESS,
        poc_script_path="poc.py",
        poc_attempts=[],
        evidence={},
        confidence_runs=2,
        dedup_status=DedupStatus.NOVEL,
        dedup_matches=[],
    )


def _match(cve_id: str, title: str, affected_versions: str) -> VulnMatch:
    return VulnMatch(
        source="wordfence",
        cve_id=cve_id,
        title=title,
        affected_versions=affected_versions,
        bug_class="CWE-434",
    )


def _lookup_result(
    *,
    wordfence_status: VulnSourceStatus,
    wordfence_matches: list[VulnMatch] | None = None,
    wordfence_reason: str | None = None,
    wpscan_status: VulnSourceStatus = VulnSourceStatus.DISABLED,
    wpscan_matches: list[VulnMatch] | None = None,
    wpscan_reason: str | None = "WPSCAN_API_KEY not set",
) -> VulnLookupResult:
    wordfence = VulnSourceResult(
        source="wordfence",
        status=wordfence_status,
        matches=wordfence_matches or [],
        status_reason=wordfence_reason,
    )
    wpscan = VulnSourceResult(
        source="wpscan",
        status=wpscan_status,
        matches=wpscan_matches or [],
        status_reason=wpscan_reason,
    )
    return VulnLookupResult(
        matches=[*(wordfence_matches or []), *(wpscan_matches or [])],
        sources={"wordfence": wordfence, "wpscan": wpscan},
    )


def _write_intake(run_dir, *, version: str = "2.9.4") -> None:
    IntakeArtifact(
        run_id=run_dir.name,
        plugin_slug="ai-engine",
        plugin_version=version,
        source_path=str(run_dir / "plugin"),
        file_count=1,
        total_lines=1,
        source_url=f"https://example.test/ai-engine-{version}.zip",
        scanned_at=datetime.now(timezone.utc),
    ).to_json_file(str(run_dir / "intake.json"))


TARGET = _match(
    "CVE-2025-7847",
    "AI Engine 2.9.3 - 2.9.4 - Authenticated (Subscriber+) Arbitrary File Upload",
    "≥2.9.3, ≤2.9.4",
)


def test_exact_semantic_match_normalizes_descriptive_finding_role() -> None:
    assert is_exact_semantic_match(
        TARGET,
        "CWE-434",
        "2.9.4",
        "subscriber; route accepts every authenticated role",
        "arbitrary_file_upload_or_write",
    )


@pytest.mark.parametrize(
    ("expression", "scanned", "in_range", "exact_bound"),
    [
        ("≥2.9.3, ≤2.9.4", "2.9.4", True, True),
        ("≥2.9.3, ≤2.9.4", "2.9.3", True, True),
        ("≥2.9.3, ≤2.9.4", "2.9.2", False, False),
        ("≥2.9.3, ≤2.9.4", "2.9.5", False, False),
        ("≥20.0.0, ≤21.8.0; ≥2.9.3, ≤2.9.4", "2.9.4", True, True),
        ("≤3.3.2", "2.9.4", True, False),
        ("2.9.3 - 2.9.5", "2.9.4", True, False),
        ("<2.9.5", "2.9.4", True, False),
        ("current", "2.9.4", None, False),
        ("≥2.9.3, ≤2.9.4; malformed", "2.9.4", None, False),
    ],
)
def test_affected_version_match_is_strict_and_tracks_explicit_bounds(
    expression: str,
    scanned: str,
    in_range: bool | None,
    exact_bound: bool,
) -> None:
    result = affected_version_match(expression, scanned)

    assert result.in_range is in_range
    assert result.exact_inclusive_bound is exact_bound


def test_ai_engine_exact_semantic_match_beats_generic_same_cwe_matches() -> None:
    known = [
        _match(
            "CVE-2026-23802",
            "AI Engine <= 3.3.2 - Authenticated (Editor+) Arbitrary File Upload",
            "≤3.3.2",
        ),
        _match(
            "CVE-2026-1400",
            "AI Engine <= 3.3.2 - Authenticated (Editor+) Arbitrary File Upload via filename",
            "≤3.3.2",
        ),
        TARGET,
        _match(
            "CVE-2024-0699",
            "AI Engine <= 2.1.4 - Authenticated (Editor+) Arbitrary File Upload",
            "≤2.1.4",
        ),
        _match(
            "CVE-2024-34440",
            "AI Engine <= 2.2.63 - Authenticated (Editor+) Arbitrary File Upload",
            "≤2.2.63",
        ),
        _match(
            "CVE-2023-51409",
            "AI Engine <= 1.9.98 - Unauthenticated Arbitrary File Upload",
            "≤1.9.98",
        ),
    ]

    status, matches = _classify_scored(_finding(), known, "2.9.4")
    recommendation, reason = derive_submission_recommendation(status.value, matches)

    assert status is DedupStatus.KNOWN_DUPE
    assert matches[0]["cve_id"] == "CVE-2025-7847"
    assert matches[0]["similarity_score"] == 1.0
    assert matches[0]["exact_semantic_match"] is True
    assert matches[0]["match_basis"] == [
        "affected_version",
        "attacker_role",
        "vulnerability_type",
    ]
    assert recommendation == "skip_exact_dupe_of_CVE-2025-7847"
    assert reason == (
        "Affected version, attacker role, and vulnerability type uniquely align "
        "with CVE-2025-7847."
    )


@pytest.mark.parametrize(
    ("match", "scanned", "finding"),
    [
        (
            _match(
                "CVE-BROAD",
                "AI Engine <= 3.3.2 - Authenticated (Subscriber+) Arbitrary File Upload",
                "≤3.3.2",
            ),
            "2.9.4",
            _finding(),
        ),
        (
            _match(
                "CVE-ROLE",
                "AI Engine 2.9.4 - Authenticated (Editor+) Arbitrary File Upload",
                "=2.9.4",
            ),
            "2.9.4",
            _finding(),
        ),
        (
            _match(
                "CVE-TYPE",
                "AI Engine 2.9.4 - Authenticated (Subscriber+) Arbitrary File Read",
                "=2.9.4",
            ),
            "2.9.4",
            _finding(),
        ),
        (TARGET, "2.9.5", _finding()),
        (
            _match(
                "CVE-UNKNOWN",
                "AI Engine - Authenticated (Subscriber+) Arbitrary File Upload",
                "current",
            ),
            "2.9.4",
            _finding(),
        ),
    ],
)
def test_semantic_match_fails_closed_on_non_exact_dimensions(
    match: VulnMatch,
    scanned: str,
    finding: Finding,
) -> None:
    hypothesis = finding.hypothesis

    assert not is_exact_semantic_match(
        match,
        hypothesis.root_cause_cwe,
        scanned,
        str(hypothesis.evidence_summary["attacker_role"]),
        hypothesis.vulnerability_type,
    )

    status, matches = _classify_scored(finding, [match], scanned)
    recommendation, _ = derive_submission_recommendation(status.value, matches)
    assert status is DedupStatus.POSSIBLY_KNOWN
    assert matches[0]["exact_semantic_match"] is False
    assert not recommendation.startswith("skip_exact_dupe_of_")


def test_multiple_exact_semantic_candidates_remain_ambiguous() -> None:
    other = TARGET.model_copy(update={"cve_id": "CVE-OTHER"})

    status, matches = _classify_scored(_finding(), [TARGET, other], "2.9.4")
    recommendation, _ = derive_submission_recommendation(status.value, matches)

    assert status is DedupStatus.POSSIBLY_KNOWN
    assert all(match["exact_semantic_match"] is False for match in matches)
    assert all(match["semantic_match_ambiguous"] is True for match in matches)
    assert all(match["similarity_score"] < 0.95 for match in matches)
    assert recommendation == "submit_with_dedup_rebuttal"


@pytest.mark.asyncio
async def test_lookup_surfaces_wordfence_429_without_discarding_wpscan(
    monkeypatch,
    httpx_mock,
) -> None:
    monkeypatch.setenv("WORDFENCE_API_KEY", "test-wordfence-key")
    monkeypatch.setenv("WPSCAN_API_KEY", "test-wpscan-key")
    httpx_mock.add_response(
        url=WORDFENCE_FEED_URL,
        status_code=429,
        headers={"Retry-After": "60"},
    )
    vulnerabilities = [
        {
            "title": f"WPScan vulnerability {index}",
            "cve": [f"2026-{10000 + index}"],
            "fixed_in": "3.0.0",
            "vuln_type": "CWE-434",
        }
        for index in range(34)
    ]
    httpx_mock.add_response(
        url="https://wpscan.com/api/v3/plugins/ai-engine",
        json={"ai-engine": {"vulnerabilities": vulnerabilities}},
    )

    result = await VulnDBClient().lookup_all_with_status("ai-engine")

    wordfence = result.source("wordfence")
    assert wordfence.status is VulnSourceStatus.UNAVAILABLE
    assert wordfence.status_reason == "HTTP 429 (Retry-After: 60)"
    assert wordfence.matches == []
    assert result.source("wpscan").status is VulnSourceStatus.AVAILABLE
    assert len(result.matches) == 34
    assert all(match.source == "wpscan" for match in result.matches)


@pytest.mark.asyncio
async def test_wpscan_without_api_key_is_explicitly_disabled(monkeypatch) -> None:
    monkeypatch.delenv("WPSCAN_API_KEY", raising=False)

    result = await VulnDBClient().lookup_wpscan_with_status("ai-engine")

    assert result.status is VulnSourceStatus.DISABLED
    assert result.status_reason == "WPSCAN_API_KEY not set"
    assert result.matches == []


@pytest.mark.asyncio
async def test_dedup_reuses_stored_wordfence_matches_when_live_source_fails(
    monkeypatch,
    tmp_path,
) -> None:
    finding = _finding()
    finding.dedup_status = DedupStatus.POSSIBLY_KNOWN
    finding.dedup_matches = [TARGET.model_dump()]
    finding.submission_recommendation = "submit_with_dedup_rebuttal"
    live_wpscan = TARGET.model_copy(
        update={
            "source": "wpscan",
            "title": "Generic WPScan file upload record",
            "affected_versions": "<2.9.5",
        }
    )
    lookup = _lookup_result(
        wordfence_status=VulnSourceStatus.UNAVAILABLE,
        wordfence_reason="HTTP 429",
        wpscan_status=VulnSourceStatus.AVAILABLE,
        wpscan_matches=[live_wpscan],
        wpscan_reason=None,
    )

    async def fake_lookup(_self, _plugin_slug):
        return lookup

    monkeypatch.setattr(VulnDBClient, "lookup_all_with_status", fake_lookup)
    run_dir = tmp_path / "run"
    _write_intake(run_dir)

    result = await dedup_stage.run(
        [finding],
        "ai-engine",
        PipelineConfig.from_yaml("tests/fixtures/pipeline.yaml"),
        runs_root=str(tmp_path),
        run_id="run",
    )

    assert result == [finding]
    assert finding.dedup_status is DedupStatus.KNOWN_DUPE
    assert finding.dedup_matches[0]["source"] == "wordfence"
    assert finding.dedup_matches[0]["cve_id"] == "CVE-2025-7847"
    assert finding.submission_recommendation == "skip_exact_dupe_of_CVE-2025-7847"
    decision = json.loads(
        (run_dir / "decision_ledger.jsonl").read_text().splitlines()[-1]
    )
    assert decision["details"]["reused_stored_wordfence_matches"] is True
    assert decision["details"]["source_status"]["wordfence"] == {
        "status": "unavailable",
        "matches": 0,
        "status_reason": "HTTP 429",
    }


@pytest.mark.asyncio
async def test_dedup_wordfence_failure_without_stored_match_is_non_mutating(
    monkeypatch,
    tmp_path,
) -> None:
    finding = _finding()
    finding.dedup_status = DedupStatus.KNOWN_DUPE
    finding.dedup_matches = [
        TARGET.model_copy(update={"source": "wpscan"}).model_dump()
    ]
    finding.submission_recommendation = "skip_exact_dupe_of_CVE-2025-7847"
    finding.submission_recommendation_reason = "existing result"
    lookup = _lookup_result(
        wordfence_status=VulnSourceStatus.UNAVAILABLE,
        wordfence_reason="HTTP 429",
        wpscan_status=VulnSourceStatus.AVAILABLE,
        wpscan_matches=[TARGET.model_copy(update={"source": "wpscan"})],
        wpscan_reason=None,
    )

    async def fake_lookup(_self, _plugin_slug):
        return lookup

    monkeypatch.setattr(VulnDBClient, "lookup_all_with_status", fake_lookup)
    run_dir = tmp_path / "run"
    _write_intake(run_dir)
    findings_path = run_dir / "findings.jsonl"
    atomic_write_jsonl(findings_path, [finding])
    before_model = finding.model_dump()
    before_file = findings_path.read_bytes()

    with pytest.raises(DedupSourceUnavailableError) as raised:
        await dedup_stage.run(
            [finding],
            "ai-engine",
            PipelineConfig.from_yaml("tests/fixtures/pipeline.yaml"),
            runs_root=str(tmp_path),
            run_id="run",
        )

    assert raised.value.source == "wordfence"
    assert raised.value.source_status is VulnSourceStatus.UNAVAILABLE
    assert raised.value.source_error == "HTTP 429"
    assert raised.value.finding_ids == ["f-64c101a52c"]
    assert (
        "authoritative vulnerability source wordfence is unavailable (HTTP 429)"
        in str(raised.value)
    )
    assert finding.model_dump() == before_model
    assert findings_path.read_bytes() == before_file
    assert not (run_dir / "decision_ledger.jsonl").exists()


@pytest.mark.asyncio
async def test_dedup_allows_novel_when_wordfence_succeeded_and_wpscan_is_disabled(
    monkeypatch,
    tmp_path,
) -> None:
    lookup = _lookup_result(
        wordfence_status=VulnSourceStatus.AVAILABLE,
        wpscan_status=VulnSourceStatus.DISABLED,
    )

    async def fake_lookup(_self, _plugin_slug):
        return lookup

    monkeypatch.setattr(VulnDBClient, "lookup_all_with_status", fake_lookup)
    finding = _finding()
    run_dir = tmp_path / "run"
    _write_intake(run_dir)

    await dedup_stage.run(
        [finding],
        "ai-engine",
        PipelineConfig.from_yaml("tests/fixtures/pipeline.yaml"),
        runs_root=str(tmp_path),
        run_id="run",
    )

    assert finding.dedup_status is DedupStatus.NOVEL
    assert finding.submission_recommendation == "submit_as_novel"
    decision = json.loads(
        (run_dir / "decision_ledger.jsonl").read_text().splitlines()[-1]
    )
    assert decision["details"]["source_status"]["wordfence"]["status"] == "available"
    assert decision["details"]["source_status"]["wpscan"]["status"] == "disabled"
