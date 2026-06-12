"""Hypothesis stage — runs specialists sequentially with filtered code-slice subsets."""

from __future__ import annotations

import asyncio
import logging
import re
from pathlib import Path

from typing import Any

from ..agents.hypothesis_verifier import HypothesisVerifier
from ..agents.runtime import AgentRuntime
from ..agents.specialists.auth import AuthSpecialist
from ..agents.specialists.auth_flow import AuthFlowSpecialist
from ..agents.specialists.cross_file_xss import CrossFileXssSpecialist
from ..agents.specialists.file_ops import FileOpsSpecialist
from ..agents.specialists.injection import InjectionSpecialist
from ..agents.specialists.logic_flaw import LogicFlawSpecialist
from ..agents.specialists.object_authz import ObjectAuthzSpecialist
from ..agents.specialists.payment_logic import PaymentLogicSpecialist
from ..agents.specialists.ssrf_deser import SSRFDeserSpecialist
from ..agents.specialists.state_change import StateChangeSpecialist
from ..agents.specialists.stored_to_admin import StoredToAdminSpecialist
from ..agents.specialists.xss import XSSSpecialist
from ..schemas.config import PipelineConfig
from ..schemas.hypothesis import HypothesesArtifact, Hypothesis
from ..schemas.recon import ReconArtifact
from ..services.artifacts import atomic_write_json, atomic_write_jsonl
from ..services.budget import BudgetTracker
from ..services.console_format import format_verifier_decision
from ..services.decision_ledger import append_decision
from ..services.quality_gate import build_focus_area_summary, render_focus_area_prompt


# X1: pre-verifier dedup. Group hypotheses by (file, line, bug_class) and keep the
# highest-confidence representative. Conservative: only merges exact-match keys.
def _pre_verifier_dedup(hypotheses: list[Hypothesis]) -> tuple[list[Hypothesis], dict[str, str]]:
    """Return (deduped, merge_log: merged_id -> kept_id)."""
    by_key: dict[tuple, Hypothesis] = {}
    merge_log: dict[str, str] = {}
    conf_rank = {"high": 0, "medium": 1, "low": 2}
    for h in hypotheses:
        key = (h.file, h.line, h.bug_class.value)
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = h
            continue
        # Keep the higher-confidence one; if tied, keep the earlier one
        if conf_rank.get(h.confidence.value, 1) < conf_rank.get(existing.confidence.value, 1):
            merge_log[existing.id] = h.id
            by_key[key] = h
        else:
            merge_log[h.id] = existing.id
    return list(by_key.values()), merge_log

# Per-specialist file relevance patterns. A file is sent to a specialist if it matches
# any of that specialist's regexes. Conservative — overlap is fine; we'd rather include
# a file the specialist might not need than miss one it does.
_SPECIALIST_PATTERNS: dict[str, list[re.Pattern[str]]] = {
    "auth": [
        re.compile(r"add_action\(['\"]wp_ajax|register_rest_route|admin_post|admin_init"),
        re.compile(r"current_user_can|wp_verify_nonce|check_ajax_referer|permission_callback"),
    ],
    "injection": [
        re.compile(r"\$wpdb->|wpdb::"),
        re.compile(r"\b(exec|shell_exec|system|passthru|popen|proc_open)\s*\("),
        re.compile(r"\bheader\s*\(|\bwp_redirect\s*\("),
    ],
    "xss": [
        re.compile(r"\becho\b|\bprint\b|\bprintf\b|\bvprintf\b|wp_send_json|json_encode\s*\("),
        re.compile(r"esc_html|esc_attr|esc_url|wp_kses|esc_js"),  # files with escaping (also check for missing)
    ],
    "file_ops": [
        re.compile(r"\b(move_uploaded_file|wp_handle_upload|file_put_contents|fwrite|fopen|copy)\s*\("),
        re.compile(r"\b(file_get_contents|readfile|unlink|rmdir)\s*\("),
        re.compile(r"\b(include|require|include_once|require_once)\s*[\(\$]"),
        re.compile(r"ZipArchive::|extractTo"),
    ],
    "ssrf_deser": [
        re.compile(r"\bwp_remote_(get|post|head|request)\s*\(|\bcurl_(init|exec|setopt)"),
        re.compile(r"\bunserialize\s*\(|maybe_unserialize\s*\("),
        re.compile(r"simplexml_load|DOMDocument|SimpleXMLElement"),
    ],
    "auth_flow": [
        re.compile(r"wp_(set_current_user|set_auth_cookie|signon|authenticate|create_user|insert_user)\s*\("),
        re.compile(r"retrieve_password|reset_password|password_reset|check_password_reset_key|get_password_reset_key"),
        re.compile(r"two[_-]?factor|2fa|totp|otp|backup_codes?|recovery_codes?", re.IGNORECASE),
        re.compile(r"\bjwt\b|JsonWebToken|firebase\\\\JWT|tymon\\\\jwtauth", re.IGNORECASE),
        re.compile(r"users_can_register|register_new_user|wp_new_user_notification|wp_login_failed"),
        re.compile(r"login_form|login_url|wp_login_url|do_action\(['\"]wp_(login|logout|authenticate)['\"]"),
        re.compile(r"\b(md5|sha1)\s*\(|\bmt_rand\s*\(|\brand\s*\(|\buniqid\s*\("),
        re.compile(r"\bhash_equals\s*\(|password_(hash|verify)|openssl_(encrypt|decrypt)"),
    ],
    "object_authz": [
        re.compile(r"\b(id|post_id|user_id|entry_id|submission_id|form_id|order_id|booking_id|event_id|invoice_id|file_id)\b", re.IGNORECASE),
        re.compile(r"get_post|get_user|wc_get_order|get_user_meta|get_post_meta|update_post_meta|delete_post_meta", re.IGNORECASE),
        re.compile(r"current_user_can|permission_callback|author|owner|user_id|customer_id", re.IGNORECASE),
        re.compile(r"\$wpdb->(get_var|get_row|get_results|query|update|delete)", re.IGNORECASE),
    ],
    "state_change": [
        re.compile(r"\b(update|delete|insert|create|save|approve|reject|publish|trash|restore|status|enable|disable)\b", re.IGNORECASE),
        re.compile(r"update_option|delete_option|update_user_meta|update_post_meta|wp_update_user|wp_insert_user|wp_update_post|wp_insert_post|wp_delete_post", re.IGNORECASE),
        re.compile(r"current_user_can|wp_verify_nonce|check_ajax_referer|permission_callback", re.IGNORECASE),
        re.compile(r"add_action\(['\"]wp_ajax|register_rest_route|admin_post", re.IGNORECASE),
    ],
    "payment_logic": [
        re.compile(r"woocommerce|wc_get_(order|cart|product)|WC\(\)|WC_Order|WC_Cart", re.IGNORECASE),
        re.compile(r"easy[_-]digital[_-]downloads|edd_(get_|add_|update_)|EDD_Payment", re.IGNORECASE),
        re.compile(r"\b(payment|paid|pay|checkout|order|invoice|refund|subscription|coupon|discount|downloadable|webhook|gateway|stripe|paypal)\b", re.IGNORECASE),
        re.compile(r"update_status|payment_complete|set_status|verify_signature|hash_hmac", re.IGNORECASE),
    ],
    "logic_flaw": [
        re.compile(r"woocommerce|wc_get_(order|cart|product)|WC\(\)|WC_Order|WC_Cart", re.IGNORECASE),
        re.compile(r"easy[_-]digital[_-]downloads|edd_(get_|add_|update_)|EDD_Payment", re.IGNORECASE),
        re.compile(r"\b(coupon|discount|cart|checkout|order|invoice|refund|subscription|membership|paywall)\b", re.IGNORECASE),
        re.compile(r"\b(booking|appointment|reservation|schedule|slot)\b", re.IGNORECASE),
        re.compile(r"\b(quiz|certificate|grade|lesson|enrollment|course)\b", re.IGNORECASE),
        re.compile(r"\b(donation|campaign|fundrais|pledge|goal_amount)\b", re.IGNORECASE),
        re.compile(r"payment_(complete|status|method)|gateway_callback|webhook"),
    ],
    "stored_to_admin": [
        re.compile(r"update_(post|user|comment)_meta|update_option|\$wpdb->(insert|update)|wp_insert_(post|comment|user)", re.IGNORECASE),
        re.compile(r"get_(post|user|comment)_meta|get_option|\$wpdb->(get_var|get_row|get_results)", re.IGNORECASE),
        re.compile(r"\becho\b|\bprint\b|\bprintf\b|wp_send_json|admin_menu|admin_page|list_table", re.IGNORECASE),
        re.compile(r"esc_html|esc_attr|esc_url|esc_js|wp_kses|sanitize_text_field|sanitize_textarea_field", re.IGNORECASE),
    ],
}


def _filter_slices_for_specialist(
    code_slices: dict[str, str],
    specialist_name: str,
) -> dict[str, str]:
    """Return only the code slices likely relevant to this specialist's bug class."""
    patterns = _SPECIALIST_PATTERNS.get(specialist_name)
    if not patterns:
        return code_slices  # unknown specialist — fall back to full corpus
    filtered: dict[str, str] = {}
    for path, text in code_slices.items():
        if any(p.search(text) for p in patterns):
            filtered[path] = text
    # Always include at least 1 file so the specialist has *something* to look at —
    # if filtering eliminates everything, the specialist's bug class isn't represented
    # in this plugin and an empty hypothesis list is the correct output.
    return filtered

logger = logging.getLogger(__name__)

MAX_LINES_PER_SLICE = 500


def _build_specialists(runtime: AgentRuntime, model: str) -> list[Any]:
    return [
        AuthSpecialist(runtime, model=model),
        InjectionSpecialist(runtime, model=model),
        FileOpsSpecialist(runtime, model=model),
        SSRFDeserSpecialist(runtime, model=model),
        XSSSpecialist(runtime, model=model),
        AuthFlowSpecialist(runtime, model=model),
        LogicFlawSpecialist(runtime, model=model),
        ObjectAuthzSpecialist(runtime, model=model),
        StateChangeSpecialist(runtime, model=model),
        PaymentLogicSpecialist(runtime, model=model),
        StoredToAdminSpecialist(runtime, model=model),
    ]


def _build_code_slices(recon: ReconArtifact, plugin_path: Path) -> dict[str, str]:
    """v1 approximation — full file (capped to 500 lines) for every file referenced
    by an entry point or a sink. Computing transitive callees properly is left for v2."""
    relevant: set[str] = set()
    for ep in recon.entry_points:
        if ep.file:
            relevant.add(ep.file)
    for sink in recon.sinks:
        if sink.file:
            relevant.add(sink.file)

    slices: dict[str, str] = {}
    for rel in relevant:
        full = (plugin_path / rel) if not Path(rel).is_absolute() else Path(rel)
        if not full.is_file():
            continue
        try:
            text = full.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        if len(lines) > MAX_LINES_PER_SLICE:
            lines = lines[:MAX_LINES_PER_SLICE] + [f"... [truncated at {MAX_LINES_PER_SLICE} lines]"]
        slices[rel] = "\n".join(lines)
    return slices


async def run(
    recon: ReconArtifact,
    plugin_path: str,
    config: PipelineConfig,
    budget: BudgetTracker,
    runtime: AgentRuntime,
    runs_root: str = "runs",
    run_id: str = "",
    enable_cross_file_taint: bool = False,
    diff_summary: str | None = None,
) -> HypothesesArtifact:
    code_slices = _build_code_slices(recon, Path(plugin_path))
    logger.info("hypothesis: %d code slices for %d entry points",
                len(code_slices), len(recon.entry_points))
    if config.quality.enabled and config.quality.focus_area_fanout:
        focus = build_focus_area_summary(recon)
        focus_path = Path(runs_root) / run_id / "focus_areas.json"
        focus_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(focus_path, focus)
        focus_prompt = render_focus_area_prompt(focus)
        if focus_prompt:
            diff_summary = "\n\n".join(part for part in (diff_summary, focus_prompt) if part)
        logger.info("hypothesis: focus-area fanout mapped %d review areas -> %s", len(focus), focus_path)

    model = config.models.specialists
    hyp_cfg = config.hypothesis
    specialists = _build_specialists(runtime, model)
    if enable_cross_file_taint:
        specialists.append(CrossFileXssSpecialist(runtime, model=model))

    # Run specialists sequentially, each with a slice corpus filtered to its bug class.
    # Sequential avoids the rate-limit bursts we hit with asyncio.gather; per-specialist
    # filtering cuts each call's input size by roughly 50-70% on a typical plugin.
    #
    # Per-specialist checkpoint: each specialist writes its output to
    # hypotheses_<specialist>.jsonl as soon as it completes. On a crashed/resumed
    # scan, completed specialists' files are loaded and that specialist is skipped.
    from ..schemas.hypothesis import Hypothesis as _Hyp
    spec_dir = Path(runs_root) / run_id
    spec_dir.mkdir(parents=True, exist_ok=True)
    merged = []
    for spec in specialists:
        spec_path = spec_dir / f"hypotheses_{spec.NAME}.jsonl"
        if spec_path.exists():
            cached = [
                _Hyp.model_validate_json(line)
                for line in spec_path.read_text().splitlines() if line.strip()
            ]
            logger.info("specialist %s: loaded %d cached hypotheses (skipping)", spec.NAME, len(cached))
            merged.extend(cached)
            continue
        if spec.NAME == "cross_file_xss":
            spec_slices = code_slices
        else:
            spec_slices = _filter_slices_for_specialist(code_slices, spec.NAME)
        priority_files = sorted(spec_slices)
        logger.info("specialist %s: prioritizing %d/%d files",
                    spec.NAME, len(spec_slices), len(code_slices))
        try:
            res = await spec.analyze(
                recon, spec_slices, hypothesis_cfg=hyp_cfg, diff_summary=diff_summary,
                plugin_path=plugin_path, priority_files=priority_files,
            )
        except BaseException as e:
            logger.warning("specialist %s failed: %s", spec.NAME, e)
            continue
        # Persist this specialist's output BEFORE moving on, so a crash mid-loop
        # doesn't lose its work.
        atomic_write_jsonl(spec_path, res.hypotheses)
        merged.extend(res.hypotheses)

    # X1: pre-verifier dedup (config-toggled). Merges (file, line, bug_class) duplicates
    # before paying for verification of each.
    pre_dedup_count = len(merged)
    if hyp_cfg.pre_verifier_dedup and merged:
        merged, merge_log = _pre_verifier_dedup(merged)
        if merge_log:
            logger.info("hypothesis: pre-verifier dedup merged %d -> %d (saved %d verifier calls)",
                        pre_dedup_count, len(merged), pre_dedup_count - len(merged))

    # Self-verification pass: cheap source-quote + guard check per hypothesis.
    # Drops hallucinated sinks and missed-guard claims before they reach triage/verify.
    # All V1/V3/V4/V5/V7 toggles flow through the verifier constructor.
    plugin_version_for_cache = ""
    try:
        from ..schemas.intake import IntakeArtifact
        intake_path = Path(runs_root) / run_id / "intake.json"
        if intake_path.exists():
            plugin_version_for_cache = IntakeArtifact.from_json_file(str(intake_path)).plugin_version
    except Exception:
        pass

    verifier = HypothesisVerifier(
        runtime,
        model=config.models.hypothesis_verifier,
        wp_idioms_enabled=hyp_cfg.verifier_wp_idioms,
        require_citation=hyp_cfg.verifier_require_citation,
        drop_categorisation_enabled=hyp_cfg.verifier_drop_categorisation,
        iterative_enabled=hyp_cfg.iterative_verifier,
        max_iterations=hyp_cfg.verifier_max_iterations,
        cache_enabled=hyp_cfg.verifier_cache_enabled,
        plugin_version=plugin_version_for_cache,
    )
    verdicts = await asyncio.gather(
        *[verifier.verify(h, plugin_path) for h in merged],
        return_exceptions=True,
    )

    # V5 routing: 5-state verdicts route to kept / dropped / manual-review queue.
    # Legacy "keep"/"drop" still supported (drop_categorisation_enabled=False path).
    KEEP_VERDICTS = {"keep", "keep_high_confidence", "keep_conditional", "keep_insufficient_evidence"}
    DROP_VERDICTS = {"drop", "drop_definitely_not_a_bug"}
    ESCALATE_VERDICTS = {"escalate_to_manual_review"}

    kept: list = []
    drop_reasons: dict[str, str] = {}
    drop_categories: dict[str, str] = {}      # V5: track category per drop for reporting
    manual_review_queue: list[dict] = []       # V5: hypotheses needing human review
    keep_conditional: dict[str, str] = {}      # V5: track conditional keeps + their condition
    run_dir = Path(runs_root) / run_id

    for h, v in zip(merged, verdicts):
        if isinstance(v, BaseException):
            logger.warning("verifier crashed for %s: %s — keeping by default", h.id, v)
            kept.append(h)
            append_decision(
                run_dir,
                stage="hypothesis_verifier",
                action="keep",
                result="kept_by_default",
                hypothesis_id=h.id,
                reason=str(v),
            )
            continue
        if v.verdict in KEEP_VERDICTS:
            kept.append(h)
            if v.verdict == "keep_conditional":
                keep_conditional[h.id] = v.reason
            append_decision(
                run_dir,
                stage="hypothesis_verifier",
                action="keep",
                result=v.verdict,
                hypothesis_id=h.id,
                reason=v.reason,
                details={"citation": v.citation} if v.citation else None,
            )
        elif v.verdict in DROP_VERDICTS:
            drop_reasons[h.id] = v.reason
            drop_categories[h.id] = v.verdict
            logger.info(format_verifier_decision(h, v.verdict, v.reason, citation=v.citation))
            append_decision(
                run_dir,
                stage="hypothesis_verifier",
                action="drop",
                result=v.verdict,
                hypothesis_id=h.id,
                reason=v.reason,
                artifact=run_dir / "hypothesis_verifier_drops.json",
                details={"citation": v.citation} if v.citation else None,
            )
        elif v.verdict in ESCALATE_VERDICTS:
            manual_review_queue.append({
                "id": h.id, "reason": v.reason, "citation": v.citation,
                "hypothesis": h.model_dump(mode="json"),
            })
            logger.info(format_verifier_decision(h, v.verdict, v.reason, citation=v.citation))
            append_decision(
                run_dir,
                stage="hypothesis_verifier",
                action="manual_review",
                result=v.verdict,
                hypothesis_id=h.id,
                reason=v.reason,
                artifact=run_dir / "hypothesis_manual_review_queue.json",
                details={"citation": v.citation} if v.citation else None,
            )
        else:
            logger.warning("verifier returned unknown verdict %r for %s — keeping by default", v.verdict, h.id)
            kept.append(h)
            append_decision(
                run_dir,
                stage="hypothesis_verifier",
                action="keep",
                result="unknown_verdict_kept_by_default",
                hypothesis_id=h.id,
                reason=f"unknown verdict: {v.verdict}",
            )

    if drop_reasons:
        verifier_path = run_dir / "hypothesis_verifier_drops.json"
        verifier_path.parent.mkdir(parents=True, exist_ok=True)
        # Store reason + category (when V5 enabled) for downstream analysis
        drops_dump = {
            hid: {"reason": reason, "category": drop_categories.get(hid, "drop")}
            for hid, reason in drop_reasons.items()
        }
        atomic_write_json(verifier_path, drops_dump)
        logger.info("hypothesis: verifier dropped %d/%d -> %s",
                    len(drop_reasons), len(merged), verifier_path)
    if manual_review_queue:
        manual_path = run_dir / "hypothesis_manual_review_queue.json"
        manual_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(manual_path, manual_review_queue)
        logger.info("hypothesis: %d hypotheses escalated to manual review queue -> %s",
                    len(manual_review_queue), manual_path)
    if keep_conditional:
        cond_path = Path(runs_root) / run_id / "hypothesis_kept_conditional.json"
        cond_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(cond_path, keep_conditional)

    artifact = HypothesesArtifact(plugin_slug=recon.plugin_slug, hypotheses=kept)
    out_path = Path(runs_root) / run_id / "hypotheses.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_jsonl(out_path, kept)
    logger.info("hypothesis: wrote %d hypotheses to %s (verifier kept %d/%d)",
                len(kept), out_path, len(kept), len(merged))
    return artifact
