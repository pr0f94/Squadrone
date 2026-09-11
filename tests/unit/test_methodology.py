from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from squadrone.agents import _specialist_base as specialist_base
from squadrone.agents.critic import CriticAgent, _evidence_contract_payload
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
from squadrone.agents._specialist_base import (
    _METHODOLOGY,
    _compact_recon,
    _enforce_read_evidence,
    _merge_alternate_path_reviews,
    _requires_authentication_alternate_path_audit,
    _requires_dynamic_key_trace,
    _specialist_finalisation_policy,
    run_specialist,
)
from squadrone.agents.plugin_tools import PluginToolHandlers
from squadrone.agents.prompts_io import load_prompt
from squadrone.stages.hypothesis import (
    _batch_input_fingerprint,
    _build_review_batches,
    _canonicalize_batch_hypotheses,
    _pre_verifier_dedup,
    _reconcile_batch_coverage,
    _retry_progress_context,
)
from squadrone.stages import hypothesis as hypothesis_stage
from squadrone.stages.triage import _validate_critic_accounting
from squadrone.services.budget import BudgetTracker


def _hypothesis(
    hypothesis_id: str = "h-1",
    line: int = 10,
    bug_class: BugClass = BugClass.IDOR,
) -> Hypothesis:
    return Hypothesis(
        id=hypothesis_id,
        specialist="authorization_workflows",
        bug_class=bug_class,
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


def test_authentication_prompt_requires_path_dominating_requester_guards():
    prompt = " ".join(load_prompt("specialists/authentication").split())

    assert "dominates every externally reachable path" in prompt
    assert "session-establishment sink" in prompt
    assert "every producer of the selected identity" in prompt
    assert "early returns" in prompt
    assert "later hook/callback/dispatcher consumers" in prompt
    assert "hook registration, priority, and execution order" in prompt
    assert "returns before the normal guard" in prompt
    assert "Bootstrap, onboarding, recovery, and fallback" in prompt
    assert "validates the target identity" in prompt
    assert "does not authenticate the requester" in prompt
    assert "one vulnerable path does not discharge other paths" in prompt
    assert "Inventory every distinct external producer and action branch" in prompt
    assert "Emit separate hypotheses" in prompt
    assert "A later validation, response, or error cannot undo" in prompt


def test_critic_rechecks_guard_dominance_before_rejecting():
    prompt = " ".join(load_prompt("critic").split())

    assert "dominates every realistic external-source-to-sink path" in prompt
    assert "action/mode branches" in prompt
    assert "early returns" in prompt
    assert "deferred state" in prompt
    assert "later hooks, callbacks, or dispatchers" in prompt
    assert "normal or sibling branch" in prompt
    assert "require independent proof" in prompt
    assert "not the requester" in prompt


def test_injection_prompt_audits_scheme_and_host_controls_independently():
    prompt = " ".join(load_prompt("specialists/injection_files").split())

    assert (
        "URL and hostname allowlists independently from URI-scheme validation" in prompt
    )
    assert "cURL, `fopen`, or another URL-capable read/request wrapper" in prompt
    assert "non-HTTP schemes" in prompt
    assert "concrete confidentiality, integrity, or availability impact" in prompt
    assert "Host allowlisting alone is not sufficient counterevidence" in prompt
    assert "attacker can still select the scheme" in prompt


def test_injection_prompt_traces_read_streams_to_responses():
    prompt = " ".join(load_prompt("specialists/injection_files").split())

    assert "read-mode stream operations" in prompt
    assert "follow the returned bytes" in prompt
    assert "helper returns, buffering, `echo`/`print`" in prompt
    assert "attacker-visible response sink" in prompt


def test_xss_prompt_audits_core_custom_field_writers_narrowly():
    prompt = " ".join(load_prompt("specialists/xss_lifecycle").split())
    idioms = " ".join(load_prompt("_wp_idioms").split())

    assert "fixed post-meta key" in prompt
    assert "post ID selected through a shortcode attribute" in prompt
    assert "accepted type and object domain" in prompt
    assert "Do not stop at the plugin's intended save handler" in prompt
    assert "post-editor Custom Fields paths" in prompt
    assert "`add_meta()` and `wp_ajax_add_meta()`" in prompt
    assert "machine-readable `entry_point` `wp_ajax_add-meta`" in prompt
    assert "its route is `POST /wp-admin/admin-ajax.php`" in prompt
    for field in (
        "`action=add-meta`",
        "`post_id`",
        "`metakeyinput`",
        "`metavalue`",
        "`_ajax_nonce-add-meta`",
    ):
        assert field in prompt
    assert "`POST form field metavalue`" in prompt
    assert "edit the exact selected target post" in prompt
    assert "normally reachable Custom Fields form available to" in prompt
    assert "nonce-providing form need not belong to" in prompt
    assert "authenticated-AJAX boundary" in prompt
    assert "exact `add_post_meta` capability" in prompt
    assert "need not appear in the plugin tree" in prompt
    assert "For this supplied core-writer path only" in prompt
    assert "without a plugin `relative/file:line` for the writer" in prompt
    assert "do not invent a plugin expression for core" in prompt
    assert "still cite the plugin-read lines" in prompt
    assert "does not apply to plugin-defined or other external writers" in prompt
    assert "exact lowest role" in prompt
    assert "post type and status, object ownership, edit capability" in prompt
    assert "key publicness under `is_protected_meta()`" in prompt
    assert "ID source and type conversion" in prompt
    assert "final output context" in prompt
    assert "can bypass it" in prompt
    assert "never infer that every `get_post_meta()` read is attacker-writable" in prompt

    assert "Core Custom Fields post-meta writers" in idioms
    assert "rejects `is_protected_meta()` keys" in idioms
    assert "does not apply a generic text sanitizer or post-content KSES" in idioms
    assert "Metadata storage still invokes `sanitize_meta()`" in idioms
    assert "authenticated `wp_ajax_add-meta` dispatch" in idioms
    assert "`POST /wp-admin/admin-ajax.php`" in idioms
    assert "requires `edit_post` on that exact object" in idioms
    assert "nonce is emitted by the post editor's Custom Fields form" in idioms
    assert "edit the exact selected target post" in idioms
    assert "normally reachable Custom Fields form available to" in idioms
    assert "nonce-providing form need not belong to" in idioms
    assert "Do not fabricate one" in idioms
    assert "does not waive source grounding" in idioms
    assert "This is not proof that every post-meta read is attacker-writable" in idioms
    assert "same object" in idioms
    assert "Save-time KSES" in idioms


def test_critic_preserves_exact_public_post_meta_xss_writer_contract():
    prompt = " ".join(load_prompt("critic").split())

    assert "fixed post-meta key from an attacker-selectable" in prompt
    assert "insufficiently type-constrained post ID" in prompt
    assert "sanitized save handler as the only possible writer" in prompt
    assert "verified core Custom Fields contract" in prompt
    assert "applies no generic text sanitizer or post-content KSES" in prompt
    assert "Do not require these core functions to appear in the plugin source" in prompt
    assert "machine-readable `entry_point` `wp_ajax_add-meta`" in prompt
    assert "its route is `POST /wp-admin/admin-ajax.php`" in prompt
    assert "POST form fields `action=add-meta`, `post_id`, `metakeyinput`" in prompt
    assert "edit the exact selected target post" in prompt
    assert "normally reachable Custom Fields form available to" in prompt
    assert "nonce-providing form need not belong to" in prompt
    assert "authenticated AJAX, the nonce check, `edit_post`" in prompt
    assert "Anchor the fixed meta read, shortcode expansion" in prompt
    assert "For this core-writer path only" in prompt
    assert "without a plugin `relative/file:line` for the writer" in prompt
    assert "do not demand or invent a plugin expression for core" in prompt
    assert "exception does not cover a plugin-defined or other external writer" in prompt
    assert "ID source and accepted type/conversion" in prompt
    assert "selected post type/status and ownership" in prompt
    assert "key publicness, value transformation, victim route" in prompt
    assert "final output context" in prompt
    assert "numeric cast alone does not bind" in prompt
    assert "does not automatically cover HTML generated later by a shortcode" in prompt
    assert "do not infer writability from a metadata read alone" in prompt


def test_injection_prompt_traces_implicit_metadata_deserialization_narrowly():
    prompt = " ".join(load_prompt("specialists/injection_files").split())
    idioms = " ".join(load_prompt("_wp_idioms").split())

    assert "assigned `implicit_deserialization` operation" in prompt
    assert "low-level raw database write" in prompt
    assert "Bind the metadata type, object ID, and key" in prompt
    assert "server-generated object ID is not counterevidence" in prompt
    assert "attacker control is over the serialized value" in prompt
    assert "paired raw insert and same-model high-level read or update" in prompt
    assert "before exploring unrelated tables, migrations, or gadget code" in prompt
    assert "every realistic external assignment" in prompt
    assert "current and legacy public handlers coexist" in prompt
    assert "serialization rejection is applied only to a fixed set" in prompt
    assert "every externally assignable field" in prompt
    assert "proving that its handler independently accepts it" in prompt
    assert "external field, metadata type, object ID, key, later access" in prompt
    assert "batch's reachable handlers and adapters" in prompt
    assert "Do not expand the inventory to unrelated models" in prompt
    assert "separate hypothesis for each independently proven tuple" in prompt
    assert "source-grounded reachability rather than discovery order" in prompt
    assert "fewest runtime assumptions" in prompt
    assert "re-emits that exact property and tuple" in prompt
    assert "evidence for one model property" in prompt
    assert "Deduplicate only after this distinct-path inventory" in prompt
    assert "Order emitted hypotheses from strongest to weakest" in prompt
    assert "final tie-break among otherwise equally ranked candidates" in prompt
    assert "Do not inflate a hypothesis's confidence" in prompt
    assert "bind one exact request encoding and external wire field" in prompt
    assert "Do not merge JSON and form ingress" in prompt
    assert "UI label, JSON/DTO property, model property, or metadata key" in prompt
    assert "source statement that reads or maps that exact field" in prompt
    assert "carry every rename through `taint_path`" in prompt
    assert "one completely traced path substitute" in prompt
    assert "Complete that inventory before returning `candidate`" in prompt
    assert "return `unreviewed` for the assigned item" in prompt
    assert "specific remaining branches" in prompt
    assert "truncated broad search result is not a completed inventory" in prompt
    assert "one last `read_plugin_ranges` call" in prompt
    assert "bounded evidence-grounding allowance" in prompt
    assert "exact, already-located source windows" in prompt
    assert "do not guess locations or begin a new broad search" in prompt
    assert "complete source contract is established" in prompt
    assert "Inventory direct high-level metadata reads as well as updates" in prompt
    assert "same-request raw-write-to-read path" in prompt
    assert "Fixed model-defined metadata keys and server-generated object IDs" in prompt
    assert "stable standard WordPress hook and form-field transport" in prompt
    assert "runtime-generated query signatures, tokens, or request URLs" in prompt
    assert "proof-completeness ordering rule" in prompt
    assert "not an explicit PHP-serialization rejection" in prompt
    assert "exact transformation makes `is_serialized()` false" in prompt
    assert "classes with `__wakeup`, `__unserialize`, `__destruct`" in prompt
    assert "loaded or autoloadable" in prompt
    assert "serialized properties and their visibility encoding" in prompt
    assert "path/prefix constraints" in prompt
    assert "`evidence_summary.usable_gadget`" in prompt
    assert "verifier-owned canary class" in prompt
    assert "during `update_metadata()` processing" in prompt
    assert "direct `get_metadata()` call" in prompt
    assert "exact direct `get_metadata()` call" in prompt
    assert "object-specific wrapper in the taint path" in prompt
    assert "filters do not return a non-null short-circuit value" in prompt
    assert "previously populated metadata cache" in prompt
    assert "WordPress core is intentionally outside" in prompt
    assert "`$prev_value` can be empty" in prompt
    assert "usable gadget chain" in prompt
    assert "Normal metadata API writes" in prompt
    assert "tuple mismatch between the raw write and later access" in prompt
    assert "implicit deserialization boundary" in idioms
    assert "when `$prev_value` is empty" in idioms
    assert "non-empty-key `get_metadata()` read" in idioms
    assert "single-value and list branches" in idioms
    assert "filter short-circuits that cache/key branch" in idioms
    assert "already-populated metadata cache stale" in idioms
    assert "calls unrestricted `unserialize()`" in idioms
    assert "does not require a WordPress-core file" in idioms
    assert "definitely non-empty `$prev_value`" in idioms
    assert "attacker need control only the serialized value" in idioms
    assert "runs in the same workflow" in idioms
    assert "not by itself a PHP-serialization allowlist" in idioms
    assert "no embedded-NUL rejection" in idioms
    assert "PHP decodes `%HH` before populating `$_POST`" in idioms
    assert "serialized protected or private property names" in idioms
    assert "serialized byte lengths still match" in idioms
    assert "alternate current and legacy public callers" in idioms
    assert "serialize non-scalar values before storage" in idioms


def test_shared_rules_expose_unreviewed_for_incomplete_forced_finalization():
    prompt = " ".join(load_prompt("specialists/_shared_rules").split())

    assert "candidate | reviewed | unreachable | unreviewed" in prompt
    assert "If forced finalization leaves source or reachability unresolved" in prompt
    assert "never convert an incomplete trace" in prompt
    assert "`prior_incomplete_review` is non-authoritative progress" in prompt
    assert "Continue its concrete proof gaps and check alternate callers" in prompt


def test_shared_prompt_requires_machine_readable_transport_and_exact_wire_source():
    prompt = " ".join(load_prompt("specialists/_shared_rules").split())

    assert "machine-readable transport seed, not prose" in prompt
    assert "METHOD /origin-relative/path" in prompt
    assert "optionally followed by one or more source-proven fixed dispatch" in prompt
    assert "?mode=submit&view=public" in prompt
    assert "Do not invent a query pair for a queryless route" in prompt
    for hook in (
        "wp_ajax_nopriv_ACTION",
        "wp_ajax_ACTION",
        "admin_post_nopriv_ACTION",
        "admin_post_ACTION",
    ):
        assert hook in prompt
    assert "Preserve the leading `/`" in prompt
    assert "POST form field <name>" in prompt
    assert "multipart file field <name>" in prompt
    assert "query parameter <name>" in prompt
    assert "JSON field <name>" in prompt
    assert "path parameter <name>" in prompt
    assert "header <name>" in prompt
    assert "cookie <name>" in prompt
    assert "unnamed raw or XML body" in prompt
    assert "key when applicable" in prompt
    assert "verbatim source expression" in prompt
    assert "source-read result (`read_plugin_file` or `read_plugin_ranges`)" in prompt
    assert "alternatives such as `JSON or form`" in prompt
    assert "Record every proven rename in `taint_path`" in prompt


def test_critic_applies_verified_implicit_metadata_contract():
    prompt = " ".join(load_prompt("critic").split())

    assert "when `$prev_value` is empty" in prompt
    assert "applies `maybe_unserialize()`" in prompt
    assert "Do not require a WordPress core file" in prompt
    assert "fixed key or server-generated object ID binds the record" in prompt
    assert "definitely non-empty `$prev_value`" in prompt
    assert "non-empty-key `get_metadata()` call" in prompt
    assert "exact direct `get_metadata()` call" in prompt
    assert "does not disprove a separate reachable direct read" in prompt
    assert "non-null `get_{$meta_type}_metadata` filter result" in prompt
    assert "populated metadata cache does not hide" in prompt
    assert "one machine-readable, source-bound transport rather than prose" in prompt
    assert "one exact wire location and external field" in prompt
    assert "Do not normalize these immutable fields during triage" in prompt
    assert "runtime-generated query signatures, tokens, or a request URL" in prompt
    assert "not itself a reason for rejection or manual review" in prompt
    assert "do not ask the critic to predict runner support" in prompt
    assert "automatic verification must fail closed" in prompt
    assert "stable standard WordPress hook and form-field path" in prompt
    assert "trusted taxonomy evidence contract" in prompt
    assert "exact JSON type and value" in prompt
    assert "do not preserve or copy a specialist assertion" in prompt
    assert "missing or unrecognized contract" in prompt
    assert "manual_review_only" in prompt
    assert "CWE-502" not in prompt
    assert "evidence_summary.usable_gadget" not in prompt


def test_critic_keeps_the_strongest_implicit_deserialization_representative():
    prompt = " ".join(load_prompt("critic").split())

    assert (
        "independently compare each external field and raw-write metadata tuple"
        in prompt
    )
    assert (
        "common sink does not make their insert-to-access lifecycles interchangeable"
        in prompt
    )
    assert "shortest source-proven same-workflow transition" in prompt
    assert "fewest runtime assumptions" in prompt
    assert (
        "Never keep a weaker representative merely because it was listed first"
        in prompt
    )
    assert (
        "handler, tuple lifecycle, preconditions, boundary, or outcome differs"
        in prompt
    )


def test_critic_renders_exact_cwe502_contract_only_for_matching_candidates():
    php_object = _hypothesis(
        "object-candidate",
        bug_class=BugClass.PHP_OBJECT_INJECTION,
    )
    ordinary = _hypothesis("idor-candidate")

    payload = _evidence_contract_payload(
        HypothesesArtifact(
            plugin_slug="demo",
            hypotheses=[ordinary, php_object],
        )
    )

    contracts = {
        contract["bug_class"]: contract for contract in payload["contracts"]
    }
    object_contract = contracts["CWE-502"]
    assert object_contract["acceptance_mode"] == "source_review"
    assert object_contract["required_evidence"] == [
        {
            "path": "evidence_summary.usable_gadget",
            "json_type": "boolean",
            "required_value": True,
            "source_requirement": (
                "The independently reviewed shipped-source chain establishes a "
                "reachable usable gadget and concrete side effect."
            ),
        }
    ]
    assert contracts["CWE-639"]["required_evidence"] == []
    assert "usable_gadget" not in json.dumps(contracts["CWE-639"])


def test_critic_open_cwe_contract_is_explicitly_manual_and_fail_closed():
    open_candidate = _hypothesis(
        "open-candidate",
        bug_class=BugClass("CWE-1234"),
    )

    payload = _evidence_contract_payload(
        HypothesesArtifact(plugin_slug="demo", hypotheses=[open_candidate])
    )

    assert payload["contracts"] == [
        {
            "bug_class": "CWE-1234",
            "family": "open_unmapped",
            "contract_source": "open_cwe_fallback",
            "acceptance_mode": "manual_review_only",
            "acceptance_requirements": [
                "No reviewed family-specific evidence contract exists for this "
                "canonical open CWE. Apply the shared source-validity checks, but "
                "route a surviving candidate to manual_review instead of accepted."
            ],
            "required_evidence": [],
            "non_evidence": [],
        }
    ]


def test_injection_prompt_anchors_file_uploads_at_the_write_operation():
    prompt = " ".join(load_prompt("specialists/injection_files").split())

    assert "arbitrary file upload/write findings" in prompt
    assert "primary `file`, `line`, `sink`, and `sink_code`" in prompt
    assert "creates, moves, copies, renames, or writes" in prompt
    assert "attacker-controlled file or bytes" in prompt
    assert "include/require, autoload, fetch, parse, or execution" in prompt
    assert "impact evidence" in prompt
    assert "do not substitute it for the primary upload/write anchor" in prompt
    assert "record that as a proof gap" in prompt


def test_injection_prompt_uses_php_include_resolution_not_filesystem_prechecks():
    prompt = " ".join(load_prompt("specialists/injection_files").split())

    assert "fixed filename prefix" in prompt
    assert "`.php` suffix" in prompt
    assert "file_exists" in prompt
    assert "realpath" in prompt
    assert "stream_resolve_include_path" in prompt
    assert "strict finite allowlist" in prompt
    assert "canonical post-resolution containment check" in prompt
    assert "Classify request-controlled directory escape" in prompt
    assert "CWE-22" in prompt
    assert "synthetic `view-..` component is not a real directory" in prompt
    assert "following `/..` lexically cancels" in prompt
    assert "Do not require a directory or symlink" in prompt


def test_developer_consult_uses_php_include_semantics_not_directory_intuition():
    prompt = " ".join(load_prompt("developer").split())

    assert "PHP virtual-CWD resolution" in prompt
    assert "file_exists" in prompt
    assert "synthetic `view-..` component" in prompt
    assert "without any real directory or symlink" in prompt
    assert "fixed prefix or `.php` suffix" in prompt
    assert "ordinary filesystem intuition" in prompt
    assert "isolated runtime verification" in prompt


def test_injection_prompt_separates_file_inclusion_from_file_write_chain():
    prompt = " ".join(load_prompt("specialists/injection_files").split())

    assert "file-inclusion primitive separate" in prompt
    assert "without requiring the same component" in prompt
    assert "upload or arbitrary-byte-write primitive" in prompt
    assert "condition on maximum code-execution impact" in prompt
    assert "do not claim attacker-planted code execution" in prompt
    assert "negative control" in prompt


def test_critic_rechecks_php_include_resolution_before_rejecting_fixed_prefix():
    prompt = " ".join(load_prompt("critic").split())

    assert "exact completed path under PHP include-path semantics" in prompt
    assert "fixed filename prefix or suffix" in prompt
    assert "is not containment proof" in prompt
    assert "strict finite allowlist" in prompt
    assert "no file-write primitive" in prompt
    assert "conditional amplification" in prompt


def test_critic_does_not_treat_discarded_body_as_php_include_containment():
    prompt = " ".join(load_prompt("critic").split())

    assert "response-body suppression is not proof" in prompt
    assert "cannot undo code that PHP already executed at the include site" in prompt
    assert "headers, termination, and other behavior may survive" in prompt
    assert "even when emitted body bytes do not" in prompt
    assert "keep the candidate for sandbox verification" in prompt
    assert "useful body-emitting shipped target" in prompt


def test_critic_constrains_blind_php_include_claim_and_requires_strict_proof():
    prompt = " ".join(load_prompt("critic").split())

    assert "request-selected inclusion primitive" in prompt
    assert "`confidentiality=low`" in prompt
    assert "`integrity=none`" in prompt
    assert "`availability=none`" in prompt
    assert "input hypothesis that already limits itself" in prompt
    assert "do not silently rewrite an overclaimed high-impact or RCE" in prompt
    assert "Do not infer arbitrary protected-file disclosure" in prompt
    assert "attacker-planted code execution, or RCE" in prompt
    assert "exact source-derived request route and field" in prompt
    assert "verifier-owned PHP canary" in prompt
    assert "response receipt is bound to the attack trace and actor" in prompt
    assert "absent sibling control" in prompt
    assert "clean-state replay with a fresh private marker" in prompt
    assert "if that sandbox proof fails" in prompt


def test_injection_prompt_audits_request_selected_public_method_dispatch():
    prompt = " ".join(load_prompt("specialists/injection_files").split())

    assert "request-selected method dispatch as an alternate caller" in prompt
    assert "is_callable([$object, $method])" in prompt
    assert "$object->$method()" in prompt
    assert "every compatible public method" in prompt
    assert "static call graph has no edge" in prompt
    assert "hook/route registration" in prompt
    assert "normal admin-menu or UI caller" in prompt
    assert "dominates that dispatcher-to-method path" in prompt


def test_critic_rechecks_dynamic_dispatch_before_accepting_admin_only_rejection():
    prompt = " ".join(load_prompt("critic").split())

    assert "request-selected method dispatch" in prompt
    assert "do not rely only on explicit static call edges" in prompt
    assert "compatible public methods" in prompt
    assert "separate low-privilege dispatcher-to-method path" in prompt


def test_injection_prompt_separates_query_safety_from_object_authorization():
    prompt = " ".join(load_prompt("specialists/injection_files").split())

    assert "query-syntax safety only" in prompt
    assert "do not establish row or object authorization" in prompt
    assert "injection disposition limited to injection safety" in prompt
    assert "coarse route capability" in prompt
    assert "ownership predicate in a sibling or alternate caller" in prompt


def test_authorization_prompt_requires_route_local_object_binding():
    prompt = " ".join(load_prompt("specialists/authorization_workflows").split())

    assert "request-controlled object identifier" in prompt
    assert "object-scope rule" in prompt
    assert "nonce or coarse capability" in prompt
    assert "final lookup or mutation predicate" in prompt
    assert "Sanitization and SQL parameterization" in prompt
    assert "Review each caller and action independently" in prompt
    assert "UI or list filtering" in prompt
    assert "sibling or alternate caller" in prompt
    assert "valid restrictive configuration" in prompt
    assert "enabling it does not weaken a security control" in prompt
    assert "source-grounded cross-object moderator authority" in prompt


def test_authorization_prompts_distinguish_object_ownership_from_attribute_authority():
    prompt = "\n".join(
        (
            load_prompt("specialists/authorization_workflows"),
            load_prompt("specialists/_shared_rules"),
            _METHODOLOGY,
            load_prompt("_wp_idioms"),
        )
    )
    normalized = " ".join(prompt.split())

    assert (
        "Object ownership does not grant authority over every attribute" in normalized
    )
    assert "current or newly created" in normalized
    assert "request-controlled field/key" in normalized
    assert "wp_capabilities" in normalized
    assert "CWE-915" in normalized


@pytest.mark.parametrize(
    "prompt_name",
    ["developer_setup", "developer_setup_followup", "developer_setup_requested"],
)
def test_setup_prompts_do_not_misstate_plugin_activation_identity(prompt_name: str):
    prompt = " ".join(load_prompt(prompt_name).split())

    assert "configured WordPress administrator" in prompt
    assert "target plugin's lifecycle" in prompt
    assert "Do not include a WP-CLI `--user` selector" in prompt
    assert "wp_set_current_user(1)" not in prompt


@pytest.mark.parametrize("prompt_name", ["critic", "hypothesis_verifier"])
def test_downstream_review_keeps_protected_own_attribute_writes(prompt_name: str):
    prompt = " ".join(load_prompt(prompt_name).split())

    assert "protected attribute" in prompt
    assert "own" in prompt
    assert "field/key" in prompt


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


def test_hypothesis_review_areas_filter_reviewers_in_fixed_order():
    reviewers = hypothesis_stage._build_specialists(
        _Runtime(),
        "test-model",
        ["xss_lifecycle", "injection_files"],
    )

    assert [reviewer.NAME for reviewer in reviewers] == [
        "injection_files",
        "xss_lifecycle",
    ]


@pytest.mark.asyncio
async def test_hypothesis_review_item_types_filter_targets_and_dispositions(
    monkeypatch, tmp_path
):
    selected = CoverageItem(
        id="cov-deserialization",
        kind="sink",
        review_areas=["injection_files"],
        type="deserialization",
        name="unserialize",
        file="demo.php",
        line=2,
        snippet="unserialize($value);",
    )
    excluded = selected.model_copy(
        update={
            "id": "cov-sql-query",
            "type": "sql_query",
            "name": "$wpdb->query",
            "line": 3,
            "snippet": "$wpdb->query($sql);",
        }
    )
    recon = _recon().model_copy(
        update={"coverage": CoverageArtifact(items=[selected, excluded])}
    )
    (tmp_path / "demo.php").write_text("<?php\nunserialize($value);\n")

    class FakeSpecialist:
        NAME = "injection_files"

        def __init__(self) -> None:
            self.seen: list[CoverageItem] = []

        async def analyze(self, *_args, coverage_targets, **_kwargs):
            self.seen.extend(coverage_targets)
            return SpecialistReviewArtifact(
                hypotheses=[],
                coverage=[
                    CoverageDisposition(
                        item_id=target.id,
                        reviewer=self.NAME,
                        status="reviewed",
                        reason="Exact source target reviewed without a candidate.",
                        evidence_locations=[f"{target.file}:{target.line}"],
                    )
                    for target in coverage_targets
                ],
            )

    async def fake_verify(_verifier, hypotheses, _plugin_path):
        assert hypotheses == []
        return []

    specialist = FakeSpecialist()
    monkeypatch.setattr(
        hypothesis_stage, "_build_specialists", lambda *_args: [specialist]
    )
    monkeypatch.setattr(hypothesis_stage, "_verify_hypotheses", fake_verify)
    config = PipelineConfig.from_yaml("pipelines/test.yaml")
    config.hypothesis_review_item_types = ["deserialization"]
    runs_root = tmp_path / "runs"

    artifact = await hypothesis_stage.run(
        recon,
        str(tmp_path),
        config,
        BudgetTracker(10.0),
        SimpleNamespace(),
        runs_root=str(runs_root),
        run_id="focused-items",
    )

    assert artifact.hypotheses == []
    assert [target.id for target in specialist.seen] == [selected.id]
    assert recon.coverage is not None
    assert [item.item_id for item in recon.coverage.dispositions] == [selected.id]
    persisted = CoverageArtifact.model_validate_json(
        (runs_root / "focused-items" / "coverage.json").read_text()
    )
    assert [item.id for item in persisted.items] == [selected.id, excluded.id]
    assert [item.item_id for item in persisted.dispositions] == [selected.id]


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
    assert '"bug_class": "CWE-639"' in system
    assert "evidence_summary.usable_gadget" not in system


def test_critic_system_prompt_injects_only_active_family_contracts():
    critic = CriticAgent(_Runtime(), model="test-model")
    system = critic._build_system_prompt(
        HypothesesArtifact(
            plugin_slug="demo",
            hypotheses=[
                _hypothesis(
                    "object-candidate",
                    bug_class=BugClass.PHP_OBJECT_INJECTION,
                )
            ],
        )
    )

    assert '"bug_class": "CWE-502"' in system
    assert '"path": "evidence_summary.usable_gadget"' in system
    assert '"json_type": "boolean"' in system
    assert '"required_value": true' in system
    assert '"bug_class": "CWE-639"' not in system


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

    batches = _build_review_batches(targets, "authorization_workflows")

    assert sum(len(batch) for batch in batches) == len(targets)
    assert all(len(batch) <= 8 for batch in batches)
    assert all(len({item.file for item in batch}) <= 6 for batch in batches)
    assert [item.id for batch in batches for item in batch] == [
        item.id for item in targets
    ]


def test_non_authorization_batches_amortize_source_local_reviews():
    targets = [
        CoverageItem(
            id=f"cov-{index:04d}",
            kind="sink",
            review_areas=["injection_files"],
            type="sql_query",
            name="query",
            file=f"file-{(index - 1) // 8:02d}.php",
            line=index,
            snippet="$wpdb->query($sql);",
        )
        for index in range(1, 41)
    ]

    batches = _build_review_batches(targets, "injection_files")

    assert sum(len(batch) for batch in batches) == len(targets)
    assert max(len(batch) for batch in batches) == 16
    assert all(len(batch) <= 16 for batch in batches)
    assert all(len({item.file for item in batch}) <= 6 for batch in batches)
    assert [item.id for batch in batches for item in batch] == [
        item.id for item in targets
    ]


def test_injection_batches_isolate_variable_php_include_sinks():
    targets = [
        CoverageItem(
            id="fixed-include",
            kind="sink",
            review_areas=["injection_files"],
            type="dynamic_include",
            name="require_once",
            file="admin.php",
            line=10,
            snippet="require_once PLUGIN_DIR . '/fixed.php';",
        ),
        CoverageItem(
            id="variable-include",
            kind="sink",
            review_areas=["injection_files"],
            type="dynamic_include",
            name="require_once",
            file="admin.php",
            line=20,
            snippet="require_once PLUGIN_DIR . '/view-' . $view . '.php';",
        ),
        CoverageItem(
            id="query",
            kind="sink",
            review_areas=["injection_files"],
            type="sql_query",
            name="query",
            file="admin.php",
            line=30,
            snippet="$wpdb->query($sql);",
        ),
    ]

    batches = _build_review_batches(targets, "injection_files")

    assert sum(len(batch) for batch in batches) == len(targets)
    assert batches[0] == [targets[1]]
    assert next(batch for batch in batches if batch[0].id == "variable-include") == [
        targets[1]
    ]
    ordinary = [
        item.id
        for batch in batches
        if batch[0].id != "variable-include"
        for item in batch
    ]
    assert ordinary == ["fixed-include", "query"]


def test_injection_batches_isolate_implicit_metadata_deserialization_sinks():
    implicit = CoverageItem(
        id="implicit-deserialization",
        kind="sink",
        review_areas=["injection_files"],
        type="implicit_deserialization",
        name="update_metadata",
        file="metadata.php",
        line=20,
        snippet="update_metadata('post', $id, 'payload', $value);",
    )
    ordinary = CoverageItem(
        id="query",
        kind="sink",
        review_areas=["injection_files"],
        type="sql_query",
        name="query",
        file="metadata.php",
        line=30,
        snippet="$wpdb->query($sql);",
    )

    batches = _build_review_batches([ordinary, implicit], "injection_files")

    assert batches[0] == [implicit]
    assert batches[1] == [ordinary]


def test_authentication_state_targets_are_isolated_from_crypto_noise():
    auth_state = [
        CoverageItem(
            id=f"auth-state-{index}",
            kind="sink",
            review_areas=["authentication"],
            type="authentication_state",
            name="wp_set_auth_cookie",
            file="session.php",
            line=100 + index,
            snippet="wp_set_auth_cookie($user_id);",
        )
        for index in range(3)
    ]
    crypto_noise = [
        CoverageItem(
            id=f"crypto-{index}",
            kind="sink",
            review_areas=["authentication"],
            type="weak_randomness",
            name="rand",
            file="tokens.php",
            line=200 + index,
            snippet="$token = rand();",
        )
        for index in range(12)
    ]

    batches = _build_review_batches([*auth_state, *crypto_noise], "authentication")
    state_batches = [
        batch
        for batch in batches
        if any(item.type == "authentication_state" for item in batch)
    ]

    assert len(state_batches) == 1
    assert {item.id for item in state_batches[0]} == {
        item.id for item in auth_state
    }
    assert all(
        all(item.type == "authentication_state" for item in batch)
        for batch in state_batches
    )


def test_authentication_state_batches_require_an_alternate_path_audit():
    auth_state = CoverageItem(
        id="auth-state",
        kind="sink",
        review_areas=["authentication"],
        type="authentication_state",
        name="wp_set_auth_cookie",
        file="session.php",
        line=10,
        snippet="wp_set_auth_cookie($user_id);",
    )
    crypto = auth_state.model_copy(
        update={"id": "crypto", "type": "weak_randomness", "name": "rand"}
    )

    assert _requires_authentication_alternate_path_audit(
        "authentication", [auth_state]
    )
    assert not _requires_authentication_alternate_path_audit(
        "authentication", [crypto]
    )
    assert not _requires_authentication_alternate_path_audit(
        "authorization_workflows", [auth_state]
    )


def test_alternate_path_audit_merges_distinct_candidates_for_one_sink():
    target = CoverageItem(
        id="auth-state",
        kind="sink",
        review_areas=["authentication"],
        type="authentication_state",
        name="wp_set_auth_cookie",
        file="session.php",
        line=10,
        snippet="wp_set_auth_cookie($user_id);",
    )
    primary_hypothesis = _hypothesis("primary").model_copy(
        update={
            "specialist": "authentication",
            "bug_class": BugClass.SESSION_FIXATION,
            "file": "session.php",
            "line": 10,
            "sink": "replayed session establishment",
            "sink_code": "wp_set_auth_cookie($user_id);",
        }
    )
    alternate_hypothesis = primary_hypothesis.model_copy(
        update={
            "id": "alternate",
            "bug_class": BugClass.AUTH_BYPASS,
            "entry_point": "bootstrap request",
            "reasoning": "A separate pre-guard branch establishes the session.",
            "preconditions": "unauthenticated",
        }
    )
    primary = SpecialistReviewArtifact(
        hypotheses=[primary_hypothesis],
        coverage=[
            CoverageDisposition(
                item_id=target.id,
                reviewer="authentication",
                status="candidate",
                reason="Primary replay path.",
                evidence_locations=["session.php:10"],
                hypothesis_ids=[primary_hypothesis.id],
            )
        ],
    )
    alternate = SpecialistReviewArtifact(
        hypotheses=[alternate_hypothesis],
        coverage=[
            CoverageDisposition(
                item_id=target.id,
                reviewer="authentication",
                status="candidate",
                reason="Distinct bootstrap path.",
                evidence_locations=["dispatcher.php:20", "session.php:10"],
                hypothesis_ids=[alternate_hypothesis.id],
            )
        ],
    )

    merged = _merge_alternate_path_reviews(
        primary,
        alternate,
        [target],
        "authentication",
    )

    assert [hypothesis.id for hypothesis in merged.hypotheses] == [
        "primary",
        "alternate",
    ]
    assert merged.coverage[0].status == "candidate"
    assert merged.coverage[0].hypothesis_ids == ["primary", "alternate"]
    assert merged.coverage[0].evidence_locations == [
        "session.php:10",
        "dispatcher.php:20",
    ]

    incomplete = _merge_alternate_path_reviews(
        primary,
        SpecialistReviewArtifact(hypotheses=[], coverage=[]),
        [target],
        "authentication",
    )
    assert incomplete.hypotheses == []
    assert incomplete.coverage[0].status == "unreviewed"
    assert incomplete.coverage[0].hypothesis_ids == []


def test_pre_verifier_dedup_preserves_distinct_paths_to_same_sink_and_cwe():
    replay = _hypothesis("replay").model_copy(
        update={
            "specialist": "authentication",
            "bug_class": BugClass.AUTH_BYPASS,
            "entry_point": "signed replay route",
            "file": "session.php",
            "line": 10,
            "sink": "session establishment",
            "sink_code": "wp_set_auth_cookie($user_id);",
            "taint_path": ["signed request", "shared state", "session sink"],
            "evidence_summary": {
                "source": "signed request",
                "control": "replay guard",
                "boundary": "administrator session",
            },
        }
    )
    bootstrap = replay.model_copy(
        update={
            "id": "bootstrap",
            "entry_point": "unsigned bootstrap route",
            "taint_path": ["unsigned request", "early return", "session sink"],
            "evidence_summary": {
                "source": "unsigned request",
                "control": "pre-guard early return",
                "boundary": "administrator session",
            },
        }
    )

    deduped, merged = _pre_verifier_dedup([replay, bootstrap])

    assert [hypothesis.id for hypothesis in deduped] == ["replay", "bootstrap"]
    assert merged == {}


def test_non_authorization_batches_expand_only_for_one_file_and_six_windows():
    dense_targets = [
        CoverageItem(
            id=f"cov-{index:04d}",
            kind="sink",
            review_areas=["xss_lifecycle"],
            type="html_output",
            name="echo",
            file="dense.php",
            line=((index - 1) % 6) * 250 + ((index - 1) // 6) + 1,
            snippet="echo $value;",
        )
        for index in range(1, 33)
    ]

    dense_batches = _build_review_batches(dense_targets, "xss_lifecycle")
    with_second_file = _build_review_batches(
        [
            *dense_targets[:16],
            dense_targets[16].model_copy(
                update={"id": "cov-other", "file": "other.php"}
            ),
        ],
        "xss_lifecycle",
    )

    assert [len(batch) for batch in dense_batches] == [32]
    assert [len(batch) for batch in with_second_file] == [16, 1]
    assert len({_source.file for _source in dense_batches[0]}) == 1
    assert (
        len({(_source.file, (_source.line - 1) // 250) for _source in dense_batches[0]})
        == 6
    )


def test_non_authorization_batches_bound_distinct_source_windows():
    targets = [
        CoverageItem(
            id=f"cov-{index:04d}",
            kind="sink",
            review_areas=["injection_files"],
            type="sql_query",
            name="query",
            file="large.php",
            line=(index * 250) + 1,
            snippet="$wpdb->query($sql);",
        )
        for index in range(16)
    ]

    batches = _build_review_batches(targets, "injection_files")

    assert len(batches) == 3
    assert sum(len(batch) for batch in batches) == len(targets)
    assert all(
        len({(item.file, (item.line - 1) // 250) for item in batch}) <= 6
        for batch in batches
    )
    assert [item.id for batch in batches for item in batch] == [
        item.id for item in targets
    ]


@pytest.mark.parametrize(
    ("name", "surface_type", "snippet", "expected"),
    [
        (
            "update_user_meta",
            "object_write",
            "update_user_meta($id, 'display_name', $value);",
            False,
        ),
        (
            "update_user_meta",
            "object_write",
            'update_user_meta($id, "display_name", $value);',
            False,
        ),
        (
            "update_user_meta",
            "object_write",
            "update_user_meta($id, $key, $value);",
            True,
        ),
        (
            "delete_post_meta",
            "object_write",
            "delete_post_meta($id, '_prefix_' . $field);",
            True,
        ),
        (
            "update_site_option",
            "option_write",
            'update_site_option("tenant_{$id}", $value);',
            True,
        ),
        (
            "update_option",
            "option_write",
            "update_option(",
            True,
        ),
        (
            "wp_update_user",
            "object_write",
            "wp_update_user($changes);",
            True,
        ),
        (
            "wp_insert_post",
            "object_write",
            "wp_insert_post(array('post_title' => $title));",
            False,
        ),
        (
            "wp_update_user",
            "object_write",
            "wp_update_user([$field => $value]);",
            True,
        ),
        (
            "wp_update_user",
            "object_write",
            "wp_update_user(['ID' => $id, 'display_name' => $name]);",
            False,
        ),
        (
            "wp_update_user",
            "object_write",
            "wp_update_user(array('ID' => $id, 'display_name' => $name,));",
            False,
        ),
        (
            "wp_update_post",
            "object_write",
            "wp_update_post(array_merge($fixed, $request));",
            True,
        ),
        (
            "wp_insert_post",
            "object_write",
            "wp_insert_post(['post_title' => $title, "
            "'meta_input' => ['fixed_key' => $_POST['value']]]);",
            False,
        ),
        (
            "wp_insert_post",
            "object_write",
            "wp_insert_post(['post_title' => $title, "
            "'meta_input' => [$field => $_POST['value']]]);",
            True,
        ),
        (
            "wp_insert_post",
            "object_write",
            "wp_insert_post(['post_title' => $title, 'meta_input' => $_POST['meta']]);",
            True,
        ),
        (
            "wp_update_post",
            "object_write",
            "wp_update_post(['ID' => $id, "
            "'tax_input' => ['category' => $_POST['terms']]]);",
            False,
        ),
        (
            "wp_update_post",
            "object_write",
            "wp_update_post(['ID' => $id, 'tax_input' => $taxonomies]);",
            True,
        ),
    ],
)
def test_dynamic_attribute_write_classification_fails_closed(
    name: str,
    surface_type: str,
    snippet: str,
    expected: bool,
):
    target = CoverageItem(
        id="cov-0001",
        kind="storage_write",
        review_areas=["authorization_workflows"],
        type=surface_type,
        name=name,
        file="user.php",
        line=10,
        snippet=snippet,
    )

    assert _requires_dynamic_key_trace([target]) is expected


def test_dynamic_writes_receive_singleton_trace_local_batches():
    fixed_before = CoverageItem(
        id="cov-0001",
        kind="storage_write",
        review_areas=["authorization_workflows"],
        type="object_write",
        name="update_user_meta",
        file="user.php",
        line=10,
        snippet="update_user_meta($id, 'display_name', $value);",
    )
    dynamic_one = fixed_before.model_copy(
        update={
            "id": "cov-0002",
            "line": 20,
            "snippet": "update_user_meta($id, $key, $value);",
        }
    )
    dynamic_two = fixed_before.model_copy(
        update={
            "id": "cov-0003",
            "line": 21,
            "snippet": "delete_user_meta($id, $key);",
        }
    )
    fixed_after = fixed_before.model_copy(update={"id": "cov-0004", "line": 30})
    dynamic_aggregate = fixed_before.model_copy(
        update={
            "id": "cov-0005",
            "name": "wp_update_user",
            "file": "rest.php",
            "line": 40,
            "snippet": "wp_update_user($request_data);",
        }
    )
    targets = [
        fixed_before,
        dynamic_one,
        dynamic_two,
        fixed_after,
        dynamic_aggregate,
    ]

    batches = _build_review_batches(targets, "authorization_workflows")
    ordinary_only = _build_review_batches(
        [fixed_before, fixed_after],
        "authorization_workflows",
    )

    dynamic_ids = {"cov-0002", "cov-0003", "cov-0005"}
    assert sorted(item.id for batch in batches for item in batch) == sorted(
        item.id for item in targets
    )
    assert [
        [item.id for item in batch]
        for batch in batches
        if not _requires_dynamic_key_trace(batch)
    ] == [[item.id for item in batch] for batch in ordinary_only]
    for batch in batches:
        if any(item.id in dynamic_ids for item in batch):
            assert len(batch) == 1
            assert batch[0].id in dynamic_ids

    # Other reviewers retain ordinary batching and the default cost profile.
    assert len(_build_review_batches(targets, "xss_lifecycle")) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("reviewer", "prompt_path", "expected_limits"),
    [
        ("authorization_workflows", "specialists/authorization_workflows", (40, 32)),
        ("xss_lifecycle", "specialists/xss_lifecycle", (25, 20)),
    ],
)
async def test_dynamic_write_runtime_limits_are_authorization_specific(
    tmp_path,
    reviewer,
    prompt_path,
    expected_limits,
):
    target = CoverageItem(
        id="cov-0001",
        kind="storage_write",
        review_areas=[reviewer],
        type="object_write",
        name="update_user_meta",
        file="demo.php",
        line=2,
        snippet="update_user_meta($id, $key, $value);",
    )
    captured = {}

    class CapturingRuntime:
        async def run(self, **kwargs):
            captured.update(kwargs)
            return _Result(SpecialistReviewArtifact(hypotheses=[], coverage=[]))

    await run_specialist(
        runtime=CapturingRuntime(),
        name=reviewer,
        prompt_path=prompt_path,
        model="test-model",
        recon=_recon(),
        plugin_path=str(tmp_path),
        priority_files=["demo.php"],
        coverage_targets=[target],
        batch_id="b001",
    )

    assert (
        captured["max_iterations"],
        captured["force_finalise_after"],
    ) == expected_limits
    assert captured["force_finalise_allowed_tools"] == (
        {"read_plugin_ranges"} if reviewer == "xss_lifecycle" else None
    )
    assert captured["force_finalise_allowed_tool_calls"] == 1


def test_implicit_finalisation_read_policy_only_invalidates_implicit_batches(
    monkeypatch,
):
    implicit = CoverageItem(
        id="implicit",
        kind="sink",
        review_areas=["injection_files"],
        type="implicit_deserialization",
        name="update_metadata",
        file="demo.php",
        line=2,
        snippet="update_metadata('post', $id, 'payload', $value);",
    )
    ordinary = implicit.model_copy(
        update={"id": "ordinary", "type": "sql_query", "name": "query"}
    )
    recon = _recon()
    implicit_before = _batch_input_fingerprint(
        recon,
        [implicit],
        "injection_files",
    )
    ordinary_before = _batch_input_fingerprint(
        recon,
        [ordinary],
        "injection_files",
    )

    monkeypatch.setattr(
        specialist_base,
        "_IMPLICIT_DESERIALIZATION_FINALISATION_TOOL_CALLS",
        specialist_base._IMPLICIT_DESERIALIZATION_FINALISATION_TOOL_CALLS + 1,
    )

    assert (
        _batch_input_fingerprint(recon, [implicit], "injection_files")
        != implicit_before
    )
    assert (
        _batch_input_fingerprint(recon, [ordinary], "injection_files")
        == ordinary_before
    )


def test_xss_storage_finalisation_policy_is_reviewer_and_kind_specific():
    storage_write = CoverageItem(
        id="xss-storage",
        kind="storage_write",
        review_areas=["xss_lifecycle"],
        type="option_write",
        name="update_option",
        file="demo.php",
        line=2,
        snippet="update_option('message', $value);",
    )
    entry_point = storage_write.model_copy(
        update={
            "id": "xss-entry",
            "kind": "entry_point",
            "type": "ajax_nopriv",
            "name": "wp_ajax_nopriv_save_message",
        }
    )
    dom_sink = storage_write.model_copy(
        update={
            "id": "xss-dom",
            "kind": "sink",
            "type": "dom_html",
            "name": "innerHTML",
        }
    )

    assert _specialist_finalisation_policy(
        "xss_lifecycle",
        [entry_point, storage_write],
    ) == ({"read_plugin_ranges"}, 1)
    assert _specialist_finalisation_policy(
        "xss_lifecycle",
        [entry_point],
    ) == (None, 1)
    assert _specialist_finalisation_policy(
        "xss_lifecycle",
        [dom_sink],
    ) == (None, 1)
    assert _specialist_finalisation_policy(
        "injection_files",
        [storage_write],
    ) == (None, 1)


def test_xss_storage_policy_only_invalidates_xss_storage_checkpoints(monkeypatch):
    storage_write = CoverageItem(
        id="storage",
        kind="storage_write",
        review_areas=["xss_lifecycle"],
        type="option_write",
        name="update_option",
        file="demo.php",
        line=2,
        snippet="update_option('message', $value);",
    )
    entry_point = storage_write.model_copy(
        update={
            "id": "entry",
            "kind": "entry_point",
            "type": "ajax_nopriv",
            "name": "wp_ajax_nopriv_save_message",
        }
    )
    dom_sink = storage_write.model_copy(
        update={
            "id": "dom",
            "kind": "sink",
            "type": "dom_html",
            "name": "innerHTML",
        }
    )
    implicit = storage_write.model_copy(
        update={
            "id": "implicit",
            "kind": "sink",
            "review_areas": ["injection_files"],
            "type": "implicit_deserialization",
            "name": "update_metadata",
        }
    )
    recon = _recon()
    checkpoints = {
        "xss_storage": _batch_input_fingerprint(
            recon, [storage_write], "xss_lifecycle"
        ),
        "xss_entry": _batch_input_fingerprint(recon, [entry_point], "xss_lifecycle"),
        "xss_dom": _batch_input_fingerprint(recon, [dom_sink], "xss_lifecycle"),
        "other_reviewer_storage": _batch_input_fingerprint(
            recon, [storage_write], "injection_files"
        ),
        "implicit": _batch_input_fingerprint(
            recon, [implicit], "injection_files"
        ),
    }

    monkeypatch.setattr(
        specialist_base,
        "_XSS_STORAGE_FINALISATION_TOOL_CALLS",
        specialist_base._XSS_STORAGE_FINALISATION_TOOL_CALLS + 1,
    )

    assert (
        _batch_input_fingerprint(recon, [storage_write], "xss_lifecycle")
        != checkpoints["xss_storage"]
    )
    assert (
        _batch_input_fingerprint(recon, [entry_point], "xss_lifecycle")
        == checkpoints["xss_entry"]
    )
    assert (
        _batch_input_fingerprint(recon, [dom_sink], "xss_lifecycle")
        == checkpoints["xss_dom"]
    )
    assert (
        _batch_input_fingerprint(recon, [storage_write], "injection_files")
        == checkpoints["other_reviewer_storage"]
    )
    assert (
        _batch_input_fingerprint(recon, [implicit], "injection_files")
        == checkpoints["implicit"]
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("target_type", "expected_limits"),
    [
        ("implicit_deserialization", (52, 44)),
        ("deserialization", (25, 20)),
        ("sql_query", (25, 20)),
    ],
)
async def test_implicit_deserialization_runtime_limits_are_batch_specific(
    tmp_path,
    target_type,
    expected_limits,
):
    target = CoverageItem(
        id="cov-0001",
        kind="sink",
        review_areas=["injection_files"],
        type=target_type,
        name="update_metadata" if target_type == "implicit_deserialization" else "sink",
        file="demo.php",
        line=2,
        snippet="update_metadata('post', $id, 'payload', $value);",
    )
    captured = {}

    class CapturingRuntime:
        async def run(self, **kwargs):
            captured.update(kwargs)
            return _Result(SpecialistReviewArtifact(hypotheses=[], coverage=[]))

    await run_specialist(
        runtime=CapturingRuntime(),
        name="injection_files",
        prompt_path="specialists/injection_files",
        model="test-model",
        recon=_recon(),
        plugin_path=str(tmp_path),
        priority_files=["demo.php"],
        coverage_targets=[target],
        batch_id="b001",
    )

    assert (
        captured["max_iterations"],
        captured["force_finalise_after"],
    ) == expected_limits
    assert captured["force_finalise_allowed_tools"] == (
        {"read_plugin_ranges"} if target_type == "implicit_deserialization" else None
    )
    assert captured["force_finalise_allowed_tool_calls"] == 1


@pytest.mark.asyncio
async def test_authentication_state_review_runs_independent_alternate_path_audit(
    tmp_path,
):
    (tmp_path / "demo.php").write_text("<?php\nwp_set_auth_cookie($user_id);\n")
    target = CoverageItem(
        id="cov-auth-state",
        kind="sink",
        review_areas=["authentication"],
        type="authentication_state",
        name="wp_set_auth_cookie",
        file="demo.php",
        line=2,
        snippet="wp_set_auth_cookie($user_id);",
    )
    calls = []

    class CapturingRuntime:
        async def run(self, **kwargs):
            calls.append(kwargs)
            kwargs["tool_handlers"]["read_plugin_file"](
                {"path": "demo.php", "start_line": 1, "end_line": 2}
            )
            return _Result(
                SpecialistReviewArtifact(
                    hypotheses=[],
                    coverage=[
                        CoverageDisposition(
                            item_id=target.id,
                            reviewer="authentication",
                            status="reviewed",
                            reason="No additional path was established.",
                            evidence_locations=["demo.php:2"],
                        )
                    ],
                )
            )

    result = await run_specialist(
        runtime=CapturingRuntime(),
        name="authentication",
        prompt_path="specialists/authentication",
        model="test-model",
        recon=_recon(),
        plugin_path=str(tmp_path),
        priority_files=["demo.php"],
        coverage_targets=[target],
        batch_id="b001",
    )

    assert len(calls) == 2
    assert calls[0]["agent_name"] == "authentication.b001"
    assert calls[1]["agent_name"] == "authentication.b001-alternate"
    assert "Independent alternate-path audit" in calls[1]["messages"][0]["content"]
    alternate_payload = json.loads(calls[1]["messages"][1]["content"])
    assert alternate_payload["hypothesis_id_prefix"] == "b001-alternate"
    assert alternate_payload["already_identified_hypotheses"] == []
    assert result.coverage[0].status == "reviewed"


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


def test_batch_checkpoint_fingerprint_covers_batch_and_trace_budget_policy(
    monkeypatch,
):
    target = CoverageItem(
        id="cov-0001",
        kind="storage_write",
        review_areas=["authorization_workflows"],
        type="object_write",
        name="update_user_meta",
        file="demo.php",
        line=10,
        snippet="update_user_meta($id, $key, $value);",
    )
    recon = _recon()
    initial = _batch_input_fingerprint(
        recon,
        [target],
        "authorization_workflows",
    )

    monkeypatch.setattr(
        hypothesis_stage,
        "_REVIEW_BATCH_POLICY_VERSION",
        hypothesis_stage._REVIEW_BATCH_POLICY_VERSION + 1,
    )
    assert (
        _batch_input_fingerprint(
            recon,
            [target],
            "authorization_workflows",
        )
        != initial
    )

    monkeypatch.setattr(
        hypothesis_stage,
        "_REVIEW_BATCH_POLICY_VERSION",
        hypothesis_stage._REVIEW_BATCH_POLICY_VERSION - 1,
    )
    monkeypatch.setattr(
        specialist_base,
        "_DYNAMIC_KEY_FORCE_FINALISE_AFTER",
        specialist_base._DYNAMIC_KEY_FORCE_FINALISE_AFTER + 1,
    )
    assert (
        _batch_input_fingerprint(
            recon,
            [target],
            "authorization_workflows",
        )
        != initial
    )


def test_alternate_path_policy_only_invalidates_authentication_state_batches(
    monkeypatch,
):
    auth_state = CoverageItem(
        id="auth-state",
        kind="sink",
        review_areas=["authentication"],
        type="authentication_state",
        name="wp_set_auth_cookie",
        file="session.php",
        line=10,
        snippet="wp_set_auth_cookie($user_id);",
    )
    crypto = auth_state.model_copy(
        update={"id": "crypto", "type": "weak_randomness", "name": "rand"}
    )
    recon = _recon()
    state_before = _batch_input_fingerprint(recon, [auth_state], "authentication")
    crypto_before = _batch_input_fingerprint(recon, [crypto], "authentication")

    monkeypatch.setattr(
        hypothesis_stage,
        "AUTHENTICATION_ALTERNATE_PATH_AUDIT_VERSION",
        hypothesis_stage.AUTHENTICATION_ALTERNATE_PATH_AUDIT_VERSION + 1,
    )

    assert (
        _batch_input_fingerprint(recon, [auth_state], "authentication")
        != state_before
    )
    assert (
        _batch_input_fingerprint(recon, [crypto], "authentication")
        == crypto_before
    )


def test_wider_reviewer_locality_policy_does_not_invalidate_authorization(
    monkeypatch,
):
    authorization_target = CoverageItem(
        id="cov-0001",
        kind="storage_write",
        review_areas=["authorization_workflows"],
        type="object_write",
        name="update_user_meta",
        file="demo.php",
        line=10,
        snippet="update_user_meta($id, 'display_name', $value);",
    )
    injection_target = authorization_target.model_copy(
        update={
            "review_areas": ["injection_files"],
            "type": "sql_query",
            "name": "query",
            "snippet": "$wpdb->query($sql);",
        }
    )
    recon = _recon()
    authorization_before = _batch_input_fingerprint(
        recon,
        [authorization_target],
        "authorization_workflows",
    )
    injection_before = _batch_input_fingerprint(
        recon,
        [injection_target],
        "injection_files",
    )

    monkeypatch.setattr(
        hypothesis_stage,
        "_REVIEW_BATCH_MAX_WINDOWS",
        hypothesis_stage._REVIEW_BATCH_MAX_WINDOWS + 1,
    )

    assert (
        _batch_input_fingerprint(
            recon,
            [authorization_target],
            "authorization_workflows",
        )
        == authorization_before
    )
    assert (
        _batch_input_fingerprint(
            recon,
            [injection_target],
            "injection_files",
        )
        != injection_before
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


def test_multi_range_reads_use_the_same_exact_reconciliation_ledger(tmp_path):
    (tmp_path / "demo.php").write_text(
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
    artifact = SpecialistReviewArtifact(
        hypotheses=[],
        coverage=[
            CoverageDisposition(
                item_id=target.id,
                reviewer="authorization_workflows",
                status="reviewed",
                reason="The registration and callback were inspected.",
                evidence_locations=["demo.php:2", "demo.php:3"],
            )
        ],
    )
    handlers = PluginToolHandlers(tmp_path)

    handlers.read_plugin_ranges(
        {
            "ranges": [
                {"path": "demo.php", "start_line": 2, "end_line": 2},
                {"path": "demo.php", "start_line": 3, "end_line": 3},
            ]
        }
    )
    enforced = _enforce_read_evidence(artifact, handlers, [target])

    assert enforced.coverage[0].status == "reviewed"
    assert enforced.coverage[0].evidence_locations == ["demo.php:2", "demo.php:3"]


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


def test_compact_recon_keeps_request_selected_dispatch_for_variable_include():
    dispatcher = EntryPoint(
        type="ajax_nopriv",
        name="wp_ajax_nopriv_demo",
        file="includes/dispatcher.php",
        line=20,
        handler_function="dispatch",
        body_slice=(
            "$method = $_REQUEST['method'];\n"
            "if (is_callable([$this, $method])) { $this->$method(); }"
        ),
        requires_auth=False,
        has_nonce_check=False,
        has_capability_check=False,
    )
    unrelated = EntryPoint(
        type="ajax_nopriv",
        name="wp_ajax_nopriv_unrelated",
        file="includes/unrelated.php",
        line=10,
        handler_function="unrelated",
        requires_auth=False,
        has_nonce_check=False,
        has_capability_check=False,
    )
    recon = ReconArtifact(
        plugin_slug="demo",
        entry_points=[dispatcher, unrelated],
        sinks=[
            Sink(
                type="dynamic_include",
                function="require_once",
                file="admin/partials/render.php",
                line=50,
                tainted_args=["view"],
            )
        ],
        entry_to_sink_paths={},
        raw_grep_hits={},
    )
    variable_target = CoverageItem(
        id="cov-variable",
        kind="sink",
        review_areas=["injection_files"],
        type="dynamic_include",
        name="require_once",
        file="admin/partials/render.php",
        line=50,
        snippet="require_once BASE . '/view-' . $view . '.php';",
    )
    fixed_target = variable_target.model_copy(
        update={
            "id": "cov-fixed",
            "snippet": "require_once BASE . '/view-default.php';",
        }
    )

    variable_compact = _compact_recon(recon, [variable_target])
    fixed_compact = _compact_recon(recon, [fixed_target])

    assert [entry["name"] for entry in variable_compact["entry_points"]] == [
        "wp_ajax_nopriv_demo"
    ]
    assert fixed_compact["entry_points"] == []


def test_compact_recon_prunes_large_unrelated_static_call_subgraphs():
    noise_width = 80
    edges = [
        StaticCallEdge(
            caller="public_upload",
            callee=f"noise_{index}",
            caller_file="api.php",
            caller_line=20 + index,
            callee_file="noise.php",
            callee_line=100 + index,
            confidence="high",
        )
        for index in range(noise_width)
    ]
    edges.extend(
        StaticCallEdge(
            caller=f"noise_{parent}",
            callee=f"noise_{child}",
            caller_file="noise.php",
            caller_line=200 + parent,
            callee_file="noise.php",
            callee_line=100 + child,
            confidence="high",
        )
        for parent in range(noise_width)
        for child in range(noise_width)
        if parent != child
    )
    edges.extend(
        [
            StaticCallEdge(
                caller="public_upload",
                callee="prepare_upload",
                caller_file="api.php",
                caller_line=500,
                callee_file="api.php",
                callee_line=510,
                confidence="high",
            ),
            StaticCallEdge(
                caller="prepare_upload",
                callee="store_file",
                caller_file="api.php",
                caller_line=515,
                callee_file="files.php",
                callee_line=40,
                confidence="high",
            ),
        ]
    )
    recon = ReconArtifact(
        plugin_slug="demo",
        entry_points=[
            EntryPoint(
                type="rest_route",
                name="demo/v1/public-upload",
                file="api.php",
                line=10,
                handler_function="public_upload",
                requires_auth=False,
                has_nonce_check=False,
                has_capability_check=False,
            )
        ],
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

    paths = compact["entry_to_sink_paths"]["demo/v1/public-upload"]
    assert len(paths) == 1
    assert "public_upload->prepare_upload" in paths[0]
    assert "prepare_upload->store_file" in paths[0]
    assert "noise_" not in paths[0]


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


def test_retry_progress_context_is_bounded_and_excludes_other_targets():
    unresolved = CoverageItem(
        id="cov-unresolved",
        kind="sink",
        review_areas=["injection_files"],
        type="implicit_deserialization",
        name="update_metadata",
        file="metadata.php",
        line=20,
        snippet="update_metadata('post', $id, 'payload', $value);",
    )
    result = SpecialistReviewArtifact(
        hypotheses=[_hypothesis("discarded")],
        coverage=[
            CoverageDisposition(
                item_id=unresolved.id,
                reviewer="injection_files",
                status="unreviewed",
                reason="x" * 2_500,
                evidence_locations=[f"metadata.php:{index}" for index in range(1, 30)],
            ),
            CoverageDisposition(
                item_id="cov-other",
                reviewer="injection_files",
                status="reviewed",
                reason="Unrelated completed work.",
                evidence_locations=["other.php:1"],
            ),
        ],
    )

    context = _retry_progress_context(result, [unresolved], "injection_files")

    assert len(context) == 1
    assert context[0]["item_id"] == unresolved.id
    assert len(context[0]["reason"]) == 2_000
    assert len(context[0]["evidence_locations"]) == 24
    assert "hypotheses" not in context[0]


@pytest.mark.asyncio
async def test_hypothesis_retry_continues_bounded_incomplete_progress(
    monkeypatch, tmp_path
):
    target = CoverageItem(
        id="cov-0001",
        kind="sink",
        review_areas=["injection_files"],
        type="implicit_deserialization",
        name="update_metadata",
        file="metadata.php",
        line=2,
        snippet="update_metadata('post', $id, 'payload', $value);",
    )
    recon = _recon().model_copy(update={"coverage": CoverageArtifact(items=[target])})
    (tmp_path / "metadata.php").write_text("<?php\nupdate_metadata();\n")

    class FakeSpecialist:
        NAME = "injection_files"

        def __init__(self) -> None:
            self.calls: list[dict] = []

        async def analyze(self, *_args, **kwargs):
            self.calls.append(kwargs)
            first = len(self.calls) == 1
            return SpecialistReviewArtifact(
                hypotheses=[],
                coverage=[
                    CoverageDisposition(
                        item_id=target.id,
                        reviewer=self.NAME,
                        status="unreviewed" if first else "reviewed",
                        reason=(
                            "External ingress remains unresolved."
                            if first
                            else "The retry re-read the path and resolved the gap."
                        ),
                        evidence_locations=["metadata.php:2"],
                    )
                ],
            )

    async def fake_verify(_verifier, hypotheses, _plugin_path):
        assert hypotheses == []
        return []

    specialist = FakeSpecialist()
    monkeypatch.setattr(
        hypothesis_stage, "_build_specialists", lambda *_args: [specialist]
    )
    monkeypatch.setattr(hypothesis_stage, "_verify_hypotheses", fake_verify)
    config = PipelineConfig.from_yaml("pipelines/test.yaml")

    artifact = await hypothesis_stage.run(
        recon,
        str(tmp_path),
        config,
        BudgetTracker(10.0),
        SimpleNamespace(),
        runs_root=str(tmp_path / "runs"),
        run_id="retry-progress",
    )

    assert artifact.hypotheses == []
    assert len(specialist.calls) == 2
    assert "prior_incomplete_review" not in specialist.calls[0]
    assert specialist.calls[1]["prior_incomplete_review"] == [
        {
            "item_id": target.id,
            "status": "unreviewed",
            "reason": "External ingress remains unresolved.",
            "evidence_locations": ["metadata.php:2"],
        }
    ]


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


def test_new_authenticated_cwe306_candidate_is_explicitly_normalized():
    candidate = Hypothesis.model_validate(
        {
            **_hypothesis("model-authenticated").model_dump(mode="json"),
            "bug_class": BugClass.MISSING_AUTH_CRITICAL_FUNCTION.value,
            "evidence_summary": {"attacker_role": "authenticated Subscriber"},
        }
    )
    assert candidate.bug_class == BugClass.MISSING_AUTH_CRITICAL_FUNCTION

    _canonicalize_batch_hypotheses(
        [candidate],
        "authorization_workflows",
        5,
    )

    assert candidate.bug_class == BugClass.MISSING_CAP_CHECK
    assert candidate.root_cause_cwe == "CWE-862"
    assert candidate.vulnerability_type == "missing_authorization"


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
