"""Verify stage — sandbox boot + PoC iteration loop per accepted hypothesis."""

from __future__ import annotations

import logging
import re
import shutil
import tempfile
import uuid
from contextlib import asynccontextmanager
from importlib.resources import files as _pkg_files
from pathlib import Path
from typing import Any

from ..agents.developer import DeveloperAgent, SetupPlan
from ..agents.poc_author import PoCAuthorAgent
from ..agents.runtime import AgentRuntime
from ..schemas.config import PipelineConfig
from ..schemas.finding import DedupStatus, Finding, PoCAttempt, PoCStatus
from ..schemas.hypothesis import Hypothesis, TriagedArtifact
from ..services.artifacts import (
    atomic_write_json,
    atomic_write_jsonl,
    atomic_write_text,
    read_jsonl_models,
)
from ..services.budget import BudgetTracker
from ..services.decision_ledger import append_decision
from ..services.quality_gate import infer_attacker_role
from ..services.roles import normalize_attacker_role
from ..services.sandbox import (
    SandboxManager,
    WORDPRESS_WEB_USER,
    validate_confirmation_observations,
    validate_plugin_slug,
)
from ..services import verify_helpers

logger = logging.getLogger(__name__)

VERIFY_COMPLETE_FILENAME = "verify_complete.json"


class VerifyStageError(RuntimeError):
    """Verification finished its pass with one or more unresolved candidates."""

    def __init__(self, errors: list[tuple[str, str]], findings: list[Finding]) -> None:
        self.errors = errors
        self.findings = findings
        summary = "; ".join(
            f"{hypothesis_id}: {reason}" for hypothesis_id, reason in errors
        )
        super().__init__(
            f"verification incomplete for {len(errors)} candidate(s): {summary}"
        )


_XSS_CHECK_SRC = (
    _pkg_files("squadrone") / "poc_templates" / "xss_check.py"
).read_text()
_WP_LOGIN_SRC = (_pkg_files("squadrone") / "poc_templates" / "wp_login.py").read_text()
_POC_RESULT_SRC = (
    _pkg_files("squadrone") / "poc_templates" / "poc_result.py"
).read_text()


def _zip_plugin(plugin_path: str, slug: str) -> tuple[str, Path]:
    """Create a zip with the plugin folder at top level — wp plugin install expects this."""
    slug = validate_plugin_slug(slug)
    src = Path(plugin_path).resolve()
    staging = Path(tempfile.mkdtemp(prefix=f"squadrone-zip-{slug}-"))
    target = staging / slug
    shutil.copytree(src, target)
    out = shutil.make_archive(
        str(staging / slug), "zip", root_dir=str(staging), base_dir=slug
    )
    return out, staging


def _next_finding_id() -> str:
    return f"f-{uuid.uuid4().hex[:10]}"


_WP_SETUP_ERROR_RE = re.compile(
    r"WordPress database error|Unknown column|Table .* doesn't exist|does not exist|"
    r"PHP (?:Fatal error|Warning):|Parse error",
    re.IGNORECASE,
)

_DIRECT_STORAGE_WRITE_RE = re.compile(
    r"\$wpdb\s*->\s*(?:insert|update|replace|query)\s*\(|\b(?:insert\s+into|update\s+[`'\"]?\w+|replace\s+into)\b",
    re.IGNORECASE,
)

_XSS_PAYLOAD_SEED_RE = re.compile(
    r"<\s*(?:script|svg|img|iframe|body|details|marquee|math|video|audio)\b|"
    r"\bon(?:load|error|mouseover|focus|click|toggle)\s*=|javascript\s*:",
    re.IGNORECASE,
)

_SQLI_PAYLOAD_SEED_RE = re.compile(
    r"(?:\bunion\s+select\b|\bor\s+1\s*=\s*1\b|\bsleep\s*\(|benchmark\s*\(|--\s|/\*)",
    re.IGNORECASE,
)

_TRAVERSAL_PAYLOAD_SEED_RE = re.compile(
    r"(?:\.\./|\.\.\\|/etc/passwd|wp-config\.php|php://|file://)",
    re.IGNORECASE,
)

_SERIALIZED_OBJECT_SEED_RE = re.compile(r"\bO:\d+:\"[^\"]+\":", re.IGNORECASE)

_SHELL_PAYLOAD_SEED_RE = re.compile(
    r"(?:\b(?:id|whoami|uname)\b\s*[;&|`$]|\$\(|`[^`]+`)", re.IGNORECASE
)

_FILESYSTEM_PERMISSION_MUTATION_RE = re.compile(
    r"(?:\b(?:chmod|chown|chgrp)\s*(?:\(|\s)|"
    r"\bwp_chmod_(?:file|dir)\s*\(|"
    r"(?:->|::)\s*chmod\s*\(|"
    r"\bumask\s*\()",
    re.IGNORECASE,
)

_SETUP_FOLLOWUP_CAP = 2
_ATOMIC_SETUP_RETRY_CAP = 1


def _setup_command_plants_exploit_payload(
    args: list[str], hyp: Hypothesis | None
) -> str | None:
    """Detect setup that would invalidate the verification environment.

    Setup is allowed to create normal plugin state, but a confirmed PoC should not be
    based on `wpdb->insert`/`wp db query` writing the malicious value directly into the
    column/file/option that the hypothesis later reads. This guard blocks obvious
    direct exploit-payload seeding and permission manipulation while allowing benign
    runtime prerequisites.
    """
    command = " ".join(args)
    if _FILESYSTEM_PERMISSION_MUTATION_RE.search(command):
        return (
            "setup command mutates filesystem permissions or ownership; "
            "sandbox install ownership is managed internally"
        )
    if hyp is None or not _DIRECT_STORAGE_WRITE_RE.search(command):
        return None
    if hyp.root_cause_cwe == "CWE-79" and _XSS_PAYLOAD_SEED_RE.search(command):
        return "setup command directly wrote an XSS payload into storage"
    if hyp.bug_class.value == "CWE-89" and _SQLI_PAYLOAD_SEED_RE.search(command):
        return "setup command directly wrote an SQL injection payload into storage"
    if hyp.bug_class.value == "CWE-22" and _TRAVERSAL_PAYLOAD_SEED_RE.search(command):
        return "setup command directly wrote a traversal payload into storage"
    if hyp.bug_class.value == "CWE-502" and _SERIALIZED_OBJECT_SEED_RE.search(command):
        return "setup command directly wrote a serialized object payload into storage"
    if hyp.bug_class.value == "CWE-78" and _SHELL_PAYLOAD_SEED_RE.search(command):
        return "setup command directly wrote a command-injection payload into storage"
    return None


def _summarise_forbidden_setup(results: list[dict]) -> str:
    blocked = [item for item in results if _setup_result_taints_confirmation(item)]
    lines: list[str] = []
    for item in blocked:
        cmd = " ".join(item.get("args", [])[:10])
        reason = (
            item.get("forbidden_payload_seed_reason") or "direct exploit payload seed"
        )
        lines.append(f"- wp {cmd} ({reason})")
    return "\n".join(lines)


def _summarise_setup_results(results: list[dict]) -> str:
    lines: list[str] = []
    for item in results:
        blocked = item.get("blocked_before_execution") is True
        status = (
            "BLOCKED BEFORE EXECUTION"
            if blocked
            else ("FAILED" if item.get("failed") else "OK")
        )
        cmd = " ".join(item.get("args", [])[:8])
        output = " ".join(
            part.strip().replace("\n", " ")
            for part in (item.get("output") or "", item.get("stderr") or "")
            if part.strip()
        )
        if len(output) > 500:
            output = output[:500] + "..."
        if blocked:
            suffix = (
                " No part of this command ran. Submit a new command containing only "
                "permitted prerequisite operations."
            )
            output = (output + suffix).strip()
        lines.append(f"{status}: wp {cmd} -> {output}")
    return "\n".join(lines)


def _setup_result_taints_confirmation(item: dict) -> bool:
    """Whether a forbidden setup result can have contaminated the sandbox.

    New results explicitly record atomic pre-execution blocks. Older artifacts did
    not, so a legacy forbidden result remains conservatively tainting.
    """
    if not item.get("forbidden_payload_seed"):
        return False
    if item.get("blocked_before_execution") is True:
        return False
    return item.get("executed", True) is not False


async def _run_setup_commands(
    sb: SandboxManager,
    commands: list[list[str]],
    *,
    hypothesis: Hypothesis | None = None,
) -> list[dict]:
    """Execute developer-proposed wp-cli commands inside the sandbox."""
    if not commands or sb.wp_cli is None:
        return []
    results: list[dict] = []
    for args in commands:
        forbidden_reason = _setup_command_plants_exploit_payload(args, hypothesis)
        if forbidden_reason:
            logger.warning(
                "setup wp %s blocked before execution: %s",
                " ".join(args[:6]),
                forbidden_reason,
            )
            results.append(
                {
                    "args": args,
                    "returncode": -1,
                    "output": "",
                    "stderr": forbidden_reason,
                    "failed": True,
                    "forbidden_payload_seed": True,
                    "forbidden_payload_seed_reason": forbidden_reason,
                    "blocked_before_execution": True,
                    "executed": False,
                }
            )
            continue
        try:
            rc, out, err = await sb.wp_cli._exec_result(*args, user=WORDPRESS_WEB_USER)
            combined = "\n".join(x for x in (out, err) if x)
            failed = rc != 0 or bool(_WP_SETUP_ERROR_RE.search(combined))
            result = {
                "args": args,
                "returncode": rc,
                "output": out,
                "stderr": err,
                "failed": failed,
                "forbidden_payload_seed": bool(forbidden_reason),
                "forbidden_payload_seed_reason": forbidden_reason,
                "blocked_before_execution": False,
                "executed": True,
            }
            results.append(result)
            log = logger.warning if failed or forbidden_reason else logger.info
            log("setup wp %s -> %s", " ".join(args[:6]), (combined or "").strip()[:160])
            if forbidden_reason:
                logger.warning(
                    "setup wp %s rejected for verification: %s",
                    " ".join(args[:6]),
                    forbidden_reason,
                )
        except Exception as e:
            logger.warning("setup wp %s failed: %s", " ".join(args[:6]), e)
            results.append(
                {
                    "args": args,
                    "returncode": -1,
                    "output": "",
                    "stderr": str(e),
                    "failed": True,
                    "forbidden_payload_seed": bool(forbidden_reason),
                    "forbidden_payload_seed_reason": forbidden_reason,
                    "blocked_before_execution": False,
                    # The WP-CLI call was dispatched and could have partially run.
                    "executed": True,
                }
            )
    return results


# Tables referenced in raw SQL — used to seed schema diagnostics for the followup developer call.
_TABLE_RE = re.compile(
    r"\$wpdb->prefix\s*\.\s*['\"]([a-z0-9_]+)['\"]|"
    r"\b((?:wp_)?(?:aysquiz_|nf3_|nf_|wf|et_|elementor_|wcfm_|wc_|woocommerce_)[a-z0-9_]+)\b",
    re.IGNORECASE,
)


async def _collect_schema_diagnostics(
    sb: SandboxManager, commands: list[list[str]]
) -> str:
    """Run DESCRIBE on tables that appear in prior setup commands so the followup developer
    sees the real schema instead of guessing again."""
    if sb.wp_cli is None or not commands:
        return ""
    blob = " ".join(" ".join(c) for c in commands)
    tables: list[str] = []
    for m in _TABLE_RE.finditer(blob):
        name = m.group(1) or m.group(2)
        if name and name not in tables:
            tables.append(name)
    if not tables:
        return ""
    out_parts: list[str] = []
    for tbl in tables[:6]:  # cap to avoid runaway diagnostics
        try:
            php = (
                f"global $wpdb; $t = $wpdb->prefix . '{tbl.removeprefix('wp_')}'; "
                'if (in_array($t, $wpdb->get_col("SHOW TABLES"))) { '
                '  $rows = $wpdb->get_results("DESCRIBE `$t`", ARRAY_A); '
                "  echo $t . ': ' . json_encode(array_map(fn($r)=>$r['Field'].' '.$r['Type'],$rows)); "
                "} else { echo $t . ': (table does not exist)'; }"
            )
            res = await sb.wp_cli._eval(php)
            out_parts.append(res.strip())
        except Exception as e:
            out_parts.append(f"{tbl}: diagnostics failed ({e})")
    return "\n".join(out_parts)


_SOURCE_LOCATION_RE = re.compile(
    r"(?P<path>[A-Za-z0-9_./-]+\.php):(?P<line>[1-9][0-9]*)",
)

_SETUP_SEMANTIC_TOKEN_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]{4,}\b")
_SETUP_ROUTE_PATH_RE = re.compile(r"/[A-Za-z0-9_./-]+")
_SETUP_SEMANTIC_TOKEN_STOPWORDS = frozenset(
    {
        "attacker",
        "callback",
        "classes",
        "filename",
        "logged",
        "multipart",
        "plugin",
        "request",
        "response",
        "subscriber",
        "target",
        "uploads",
        "wordpress",
    }
)


def _setup_semantic_tokens(hypothesis: Hypothesis) -> list[str]:
    """Extract source identifiers that can locate an uncited entry-point guard."""
    # Setup needs the registration and reachability guard, not every downstream
    # symbol in a potentially long taint path. Keeping this entry-focused also
    # prevents common sink helpers from pulling unrelated files into the bounded
    # context ahead of the real route.
    source_text = "\n".join([hypothesis.entry_point, *hypothesis.taint_path[:2]])
    tokens: list[str] = []

    # Preserve the final route segment, including dashed/all-lowercase routes that
    # do not look like PHP identifiers. The leading slash makes short route names
    # substantially less noisy when searched in source.
    route_paths = _SETUP_ROUTE_PATH_RE.findall(hypothesis.entry_point)
    if route_paths:
        tail = route_paths[-1].rstrip("/").rsplit("/", 1)[-1]
        route_token = f"/{tail}"
        if len(tail) >= 4 and route_token not in tokens:
            tokens.append(route_token)

    for token in _SETUP_SEMANTIC_TOKEN_RE.findall(source_text):
        lowered = token.lower()
        if lowered in _SETUP_SEMANTIC_TOKEN_STOPWORDS:
            continue
        # Prefer identifiers over prose. Underscores and camelCase are strong PHP
        # source signals; an all-lowercase route component is too noisy on its own.
        # Class names are retained at lower priority because their bootstrap site
        # often carries the option storage or module construction needed for setup.
        if "_" not in token and re.search(r"[a-z][A-Z]", token) is None:
            continue
        if token not in tokens:
            tokens.append(token)
    return tokens[:16]


def _add_semantic_setup_locations(
    plugin_root: Path,
    hypothesis: Hypothesis,
    locations: dict[str, set[int]],
    *,
    max_extra_files: int = 4,
) -> None:
    """Add bounded snippets for entry identifiers when hypotheses omit file:line refs."""
    tokens = _setup_semantic_tokens(hypothesis)
    if not tokens:
        return

    matches: list[tuple[int, int, str, set[int]]] = []
    for candidate in sorted(plugin_root.rglob("*.php")):
        try:
            lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        first_line_by_token: dict[int, int] = {}
        for line_number, line in enumerate(lines, start=1):
            for token_rank, token in enumerate(tokens):
                if token_rank not in first_line_by_token and token in line:
                    first_line_by_token[token_rank] = line_number
        if first_line_by_token:
            rel_file = candidate.relative_to(plugin_root).as_posix()
            matches.append(
                (
                    -len(first_line_by_token),
                    min(first_line_by_token),
                    rel_file,
                    set(first_line_by_token.values()),
                )
            )

    added_files = 0
    for _term_count, _rank, rel_file, matched_lines in sorted(matches):
        if rel_file not in locations:
            if added_files >= max_extra_files:
                continue
            added_files += 1
        locations.setdefault(rel_file, set()).update(matched_lines)


def _resolve_plugin_file(plugin_root: Path, rel_file: str) -> Path | None:
    candidate = plugin_root / rel_file
    if not candidate.is_file():
        for prefix in (
            "wp-content/plugins/" + plugin_root.name + "/",
            plugin_root.name + "/",
        ):
            if rel_file.startswith(prefix):
                candidate = plugin_root / rel_file[len(prefix) :]
                if candidate.is_file():
                    break
    return candidate if candidate.is_file() else None


def _build_setup_code_context(
    plugin_root: Path,
    hypothesis: Hypothesis,
    *,
    max_chars: int = 12_000,
) -> str | None:
    """Build source context for setup from every file cited by the hypothesis."""
    locations: dict[str, set[int]] = {}
    source_text = "\n".join(
        [
            hypothesis.entry_point,
            *hypothesis.taint_path,
            hypothesis.reasoning,
            str(hypothesis.evidence_summary or {}),
        ]
    )
    for match in _SOURCE_LOCATION_RE.finditer(source_text):
        locations.setdefault(match.group("path"), set()).add(int(match.group("line")))

    if hypothesis.file:
        locations.setdefault(hypothesis.file, set()).add(hypothesis.line)

    # Specialist output does not always retain file:line citations for the entry
    # route. Recover the registration/feature-gate file from source identifiers so
    # setup agents do not have to invent plugin option names after a route-level 404.
    _add_semantic_setup_locations(plugin_root, hypothesis, locations)
    if hypothesis.file:
        sink_lines = locations.pop(hypothesis.file)
        # Keep the primary sink, but render entry/registration files first so a
        # large sink file cannot consume the bounded context before its guard.
        locations[hypothesis.file] = sink_lines

    sections: list[str] = []
    used = 0
    for rel_file, cited_lines in locations.items():
        candidate = _resolve_plugin_file(plugin_root, rel_file)
        if candidate is None:
            continue
        try:
            lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue

        selected = set(range(1, min(len(lines), 35) + 1))
        for line in cited_lines:
            selected.update(range(max(1, line - 25), min(len(lines), line + 25) + 1))

        rendered = [f"--- {rel_file} ---"]
        previous = 0
        for line in sorted(selected):
            if previous and line > previous + 1:
                rendered.append("...")
            rendered.append(f"{line:5}  {lines[line - 1]}")
            previous = line
        section = "\n".join(rendered)
        remaining = max_chars - used
        if remaining <= 0:
            break
        if len(section) > remaining:
            section = section[:remaining] + "\n... [source context truncated]"
        sections.append(section)
        used += len(section) + 2

    return "\n\n".join(sections) or None


def _read_readme(plugin_root: Path) -> str | None:
    for name in ("readme.txt", "README.txt", "readme.md", "README.md"):
        p = plugin_root / name
        if p.is_file():
            try:
                return p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
    return None


async def _verify_one(
    hyp: Hypothesis,
    plugin_path: str,
    plugin_zip: str,
    plugin_slug: str,
    config: PipelineConfig,
    runtime: AgentRuntime,
    poc_dir: Path,
    developer: DeveloperAgent | None = None,
    # When provided, the caller owns sandbox boot and teardown.
    persistent_sb: SandboxManager | None = None,
) -> Finding | None:
    verify_cfg = config.verify

    poc_dir.mkdir(parents=True, exist_ok=True)
    # Drop the xss_check helper next to the PoC scripts so they can `from xss_check import ...`.
    atomic_write_text(poc_dir / "xss_check.py", _XSS_CHECK_SRC)
    # Drop the wp_login helper too — robust GET-then-POST flow with the
    # `wordpress_test_cookie` handled. Eliminates "admin login failed" false
    # negatives caused by PoC scripts skipping the GET prime step.
    atomic_write_text(poc_dir / "wp_login.py", _WP_LOGIN_SRC)
    atomic_write_text(poc_dir / "poc_result.py", _POC_RESULT_SRC)
    attempts: list[PoCAttempt] = []
    last_evidence: dict = {}
    expected_attacker_role = infer_attacker_role(hyp)
    code_slice: str | None = None
    readme: str | None = None
    if developer is not None:
        plugin_root = Path(plugin_path)
        code_slice = _build_setup_code_context(plugin_root, hyp)
        readme = _read_readme(plugin_root)
    setup_plan = SetupPlan()
    setup_exec_results: list[dict] = []
    followups_used = 0
    # Preserve the historical per-hypothesis limit. Callback and stage-requested
    # repairs share it, so neither route can bypass the cost bound.
    followup_cap = _SETUP_FOLLOWUP_CAP

    def _checkpoint_setup_results() -> None:
        """Persist exact setup execution state for audit and interrupted runs."""
        atomic_write_json(
            poc_dir / "setup_results.json",
            {
                "followups_used": followups_used,
                "followup_cap": followup_cap,
                "proposed_commands": setup_plan.commands,
                "results": setup_exec_results,
            },
        )

    # Bound once the sandbox and developer are available.
    setup_callback_state: dict[str, Any] = {"sb": None}

    async def _request_setup_followup(
        sb_local: SandboxManager,
        *,
        last_iteration: int,
        last_stdout: str,
        last_stderr: str,
        last_error_log: str,
        schema_diagnostics: str = "",
        setup_execution_feedback: str = "",
    ) -> tuple[SetupPlan | None, list[tuple[SetupPlan, list[dict]]]]:
        """Request and apply bounded setup repairs, retrying atomic blocks directly."""
        nonlocal followups_used

        rounds: list[tuple[SetupPlan, list[dict]]] = []
        followup: SetupPlan | None = None
        feedback = setup_execution_feedback
        diagnostics = schema_diagnostics
        atomic_retries = 0
        while developer is not None and followups_used < followup_cap:
            # Count every developer request, including empty or errored responses.
            followups_used += 1
            try:
                followup = await developer.propose_setup_followup(
                    hypothesis=hyp,
                    prior_plan=setup_plan,
                    last_iteration=last_iteration,
                    last_stdout=last_stdout,
                    last_stderr=last_stderr,
                    last_error_log=last_error_log,
                    schema_diagnostics=diagnostics,
                    code_slice=code_slice,
                    setup_execution_feedback=feedback,
                )
            except Exception as exc:
                logger.warning("propose_setup_followup for %s failed: %s", hyp.id, exc)
                _checkpoint_setup_results()
                return None, rounds

            if not followup.commands:
                _checkpoint_setup_results()
                return followup, rounds

            logger.info(
                "verify: %s applying %d followup setup commands (round %d/%d)",
                hyp.id,
                len(followup.commands),
                followups_used,
                followup_cap,
            )
            results = await _run_setup_commands(
                sb_local, followup.commands, hypothesis=hyp
            )
            setup_exec_results.extend(results)
            # Preserve proposed history, but execution status is carried separately.
            setup_plan.commands.extend(followup.commands)
            rounds.append((followup, results))
            _checkpoint_setup_results()

            if not any(item.get("failed") for item in results):
                return followup, rounds

            # A mixed safe/forbidden argv is rejected atomically. Feed the exact
            # non-execution back once so a clean replacement can be issued without
            # spending a PoC iteration. Ordinary execution failures return to the
            # PoC loop instead of consuming the whole followup budget up front.
            blocked_before_execution = any(
                item.get("blocked_before_execution") is True for item in results
            )
            if (
                not blocked_before_execution
                or atomic_retries >= _ATOMIC_SETUP_RETRY_CAP
            ):
                return followup, rounds
            atomic_retries += 1

            latest_feedback = _summarise_setup_results(results)
            cumulative_feedback = _summarise_setup_results(setup_exec_results)
            feedback = (
                f"LATEST SETUP ROUND:\n{latest_feedback}\n\n"
                f"CUMULATIVE SETUP HISTORY:\n{cumulative_feedback}"
            )
            retry_diagnostics = await _collect_schema_diagnostics(
                sb_local, followup.commands
            )
            if retry_diagnostics:
                diagnostics = "\n".join(
                    part for part in (diagnostics, retry_diagnostics) if part
                )

        return followup, rounds

    async def _setup_callback(description: str) -> str:
        sb_local = setup_callback_state["sb"]
        if sb_local is None or developer is None:
            return "[request_additional_setup] sandbox or developer not yet ready"
        if followups_used >= followup_cap:
            return (
                "[request_additional_setup] setup followup limit reached "
                f"({followup_cap}/{followup_cap})"
            )

        followup, rounds = await _request_setup_followup(
            sb_local,
            last_iteration=0,
            last_stdout="",
            last_stderr="",
            last_error_log="",
            schema_diagnostics=(
                f"PoC author requested additional setup:\n{description}"
            ),
            setup_execution_feedback=_summarise_setup_results(setup_exec_results),
        )
        if not rounds:
            rationale = followup.rationale if followup else "none"
            return (
                "[request_additional_setup] developer returned no applicable commands "
                f"(rationale: {rationale!r})"
            )

        final_plan, final_results = rounds[-1]
        all_round_results = [item for _plan, results in rounds for item in results]
        result_summary = "\n".join(
            f"Round {round_number}:\n{_summarise_setup_results(results)}"
            for round_number, (_plan, results) in enumerate(rounds, start=1)
        )
        if any(item.get("failed") for item in final_results):
            applied = sum(
                1
                for item in all_round_results
                if item.get("executed") and not item.get("failed")
            )
            return (
                "[request_additional_setup] setup remains incomplete; "
                f"{applied} permitted commands were applied. "
                "Execution feedback is authoritative:\n"
                f"{result_summary}"
            )
        executed = sum(
            1
            for item in all_round_results
            if item.get("executed") and not item.get("failed")
        )
        return (
            f"[request_additional_setup] applied {executed} permitted commands. "
            f"Rationale: {final_plan.rationale or '(none)'}\n"
            f"Execution feedback:\n{result_summary}"
        )

    poc_author = PoCAuthorAgent(
        runtime,
        model=config.models.poc_author,
        plugin_root=plugin_path,
        setup_callback=_setup_callback,
    )

    # Every route type can depend on plugin-created objects, forms, pages, nonces,
    # or settings. Ask for legitimate setup even when the HTTP endpoint itself is
    # directly reachable.
    if developer is not None:
        try:
            setup_plan = await developer.propose_setup(
                hyp,
                plugin_slug=plugin_slug,
                code_slice=code_slice,
                readme_excerpt=readme,
            )
        except Exception as e:
            logger.warning("propose_setup for %s failed: %s", hyp.id, e)

    # persistent_sb is supplied when verify.run() reuses one sandbox.
    # In that mode we DO NOT enter a new SandboxManager context — the caller has already
    # booted, installed plugin, set up users, and called restore() to baseline state.
    # We just run the per-hypothesis logic against the existing sb.
    @asynccontextmanager
    async def _sb_ctx():
        if persistent_sb is not None:
            # Caller manages lifecycle — also already installed the plugin + test users
            # and applied snapshot/restore as needed. We only run the per-hypothesis
            # propose-setup commands.
            setup_exec_results.extend(
                await _run_setup_commands(
                    persistent_sb, setup_plan.commands, hypothesis=hyp
                ),
            )
            _checkpoint_setup_results()
            yield persistent_sb
            return
        async with SandboxManager(
            config.sandbox,
            boot_timeout_s=max(config.sandbox_timeout_seconds, 180),
            poc_timeout_s=config.sandbox_timeout_seconds,
        ) as fresh_sb:
            await fresh_sb.install_plugin(plugin_zip, plugin_slug)
            await fresh_sb.setup_test_users()
            setup_exec_results.extend(
                await _run_setup_commands(
                    fresh_sb, setup_plan.commands, hypothesis=hyp
                ),
            )
            _checkpoint_setup_results()
            yield fresh_sb

    async with _sb_ctx() as sb:
        # Bind the live sandbox into the PoC author's setup callback.
        setup_callback_state["sb"] = sb

        # Build a plain-language, execution-grounded setup summary. Proposed
        # commands are not described as executed when the preflight blocked them.
        setup_summary = None
        if setup_plan.rationale or setup_exec_results:
            execution_summary = (
                _summarise_setup_results(setup_exec_results)
                or "(no setup commands were executed)"
            )
            setup_summary = (
                f"The runner has just configured the sandbox before the PoC runs.\n"
                f"Reason: {setup_plan.rationale or '(none stated)'}\n"
                f"Authoritative setup execution results:\n{execution_summary}\n"
                "Use only state whose result is OK. A BLOCKED BEFORE EXECUTION "
                "command made no state change."
            )

        setup_failed = any(item.get("failed") for item in setup_exec_results)
        if setup_failed:
            setup_summary = (
                (setup_summary or "The initial sandbox setup ran before the PoC.")
                + "\n\nSETUP COMMAND WARNINGS:\n"
                + _summarise_setup_results(setup_exec_results)
            )
            if developer is not None and followups_used < followup_cap:
                diagnostics = await _collect_schema_diagnostics(sb, setup_plan.commands)
                _followup, repair_rounds = await _request_setup_followup(
                    sb,
                    last_iteration=0,
                    last_stdout="",
                    last_stderr="",
                    last_error_log="",
                    schema_diagnostics=diagnostics,
                    setup_execution_feedback=_summarise_setup_results(
                        setup_exec_results
                    ),
                )
                for repair_plan, repair_results in repair_rounds:
                    setup_summary += (
                        "\n\nSETUP REPAIR before PoC iteration 1: "
                        f"{repair_plan.rationale or '(no rationale)'}\n"
                        + _summarise_setup_results(repair_results)
                    )

        # Surface the credential table the sandbox provisioned. PoC author MUST
        # pick from this list rather than recalling credentials from system prompt.
        user_accounts = sb.baseline_user_accounts()
        normalized_role = expected_attacker_role
        role_account = next(
            (
                account
                for account in user_accounts
                if normalize_attacker_role(account.get("role")) == normalized_role
            ),
            None,
        )

        for iteration in range(1, config.verify_max_iterations + 1):
            extra_ctx: dict = {
                "user_accounts": user_accounts,
                "attacker_role": normalized_role,
                "test_username": role_account["login"] if role_account else "",
                "test_password": role_account["password"] if role_account else "",
            }
            if setup_summary:
                extra_ctx["setup_summary"] = setup_summary
            script = await poc_author.write(
                hypothesis=hyp,
                target_url=sb.target_url,
                previous_attempts=attempts,
                extra_context=extra_ctx or None,
            )
            script_path = poc_dir / f"iter_{iteration}.py"
            atomic_write_text(script_path, script)

            pre_attempt_snapshot: Path | None = None
            try:
                pre_attempt_snapshot = await sb.snapshot()
            except Exception as exc:
                reason = f"clean-state snapshot failed: {exc}"
                logger.warning("verify: %s %s", hyp.id, reason)
                attempts.append(
                    PoCAttempt(
                        iteration=iteration,
                        script_path=str(script_path),
                        result=PoCStatus.FAILED,
                        validation_reason=reason,
                    )
                )
                break

            result = await sb.run_poc(
                str(script_path),
                expected_bug_class=hyp.bug_class.oracle_key,
                expected_attacker_role=expected_attacker_role,
            )
            attempt = PoCAttempt(
                iteration=iteration,
                phase="attack",
                script_path=str(script_path),
                result=PoCStatus.SUCCESS if result.success else PoCStatus.FAILED,
                http_status=result.http_status,
                response_snippet=(result.response or "")[:500] or None,
                timing_seconds=result.elapsed,
                error_log_snippet=(result.error_log or "")[:500] or None,
                developer_analysis=None,  # PoC author re-evaluates with consult_developer in next iter
                observation=result.observation,
                validation_reason=result.validation_reason or None,
            )

            if result.success:
                forbidden_setup = any(
                    _setup_result_taints_confirmation(item)
                    for item in setup_exec_results
                )
                if forbidden_setup:
                    reason = (
                        "PoC returned SUCCESS, but verification rejected it because sandbox setup "
                        "directly planted the exploit payload into storage:\n"
                        f"{_summarise_forbidden_setup(setup_exec_results)}\n"
                        "A valid confirmation must submit the malicious value through a real "
                        "plugin/WordPress entry point reachable by the claimed attacker role."
                    )
                    attempt.result = PoCStatus.FAILED
                    attempt.developer_analysis = reason[:1000]
                    attempts.append(attempt)
                    logger.warning(
                        "verify: %s rejected tainted setup confirmation", hyp.id
                    )
                    if pre_attempt_snapshot is not None:
                        await sb.restore(pre_attempt_snapshot)
                        shutil.rmtree(pre_attempt_snapshot, ignore_errors=True)
                    break
                # Re-run from the exact state that existed before the first
                # attempt. This prevents one-shot state mutation from being
                # mistaken for independent confirmation.
                await sb.restore(pre_attempt_snapshot)
                confirm = await sb.run_poc(
                    str(script_path),
                    expected_bug_class=hyp.bug_class.oracle_key,
                    expected_attacker_role=expected_attacker_role,
                )
                confirmation_attempt = PoCAttempt(
                    iteration=iteration,
                    phase="confirmation",
                    script_path=str(script_path),
                    result=PoCStatus.SUCCESS if confirm.success else PoCStatus.FAILED,
                    http_status=confirm.http_status,
                    response_snippet=(confirm.response or "")[:500] or None,
                    timing_seconds=confirm.elapsed,
                    error_log_snippet=(confirm.error_log or "")[:500] or None,
                    observation=confirm.observation,
                    validation_reason=confirm.validation_reason or None,
                )
                matching_confirmation = False
                confirmation_reason = "confirmation did not produce a valid observation"
                if result.observation is not None and confirm.observation is not None:
                    matching_confirmation, confirmation_reason = (
                        validate_confirmation_observations(
                            result.observation,
                            confirm.observation,
                        )
                    )
                if confirm.success and matching_confirmation:
                    attempts.extend((attempt, confirmation_attempt))
                    last_evidence = {
                        "first_run": result.evidence,
                        "confirmation_run": confirm.evidence,
                        "clean_state_restored": True,
                    }
                    shutil.rmtree(pre_attempt_snapshot, ignore_errors=True)
                    if config.report.screenshot_capture:
                        screenshot_dir = poc_dir / "screenshots"
                        await verify_helpers.screenshot_url(
                            sb.target_url + "/wp-admin/",
                            screenshot_dir / f"{hyp.id}_admin.png",
                            timeout_s=verify_cfg.headless_browser_timeout_s,
                        )
                    break
                if confirm.success:
                    confirmation_attempt.result = PoCStatus.FAILED
                    confirmation_attempt.validation_reason = confirmation_reason
                attempt.result = PoCStatus.FAILED
                attempt.validation_reason = "clean-state confirmation failed: " + (
                    confirmation_reason
                    if confirm.success
                    else (confirm.validation_reason or "oracle did not reproduce")
                )
                attempt.developer_analysis = attempt.validation_reason[:1000]
                attempts.extend((attempt, confirmation_attempt))
                result = confirm
                await sb.restore(pre_attempt_snapshot)
                shutil.rmtree(pre_attempt_snapshot, ignore_errors=True)
            else:
                attempts.append(attempt)
                if pre_attempt_snapshot is not None:
                    await sb.restore(pre_attempt_snapshot)
                    shutil.rmtree(pre_attempt_snapshot, ignore_errors=True)

            # Failed iteration — ask the developer if it looks setup-shaped, before next PoC try.
            if (
                developer is not None
                and followups_used < followup_cap
                and iteration
                < config.verify_max_iterations  # no point on the last iter
            ):
                diagnostics = await _collect_schema_diagnostics(sb, setup_plan.commands)
                followup, followup_rounds = await _request_setup_followup(
                    sb,
                    last_iteration=iteration,
                    last_stdout=result.response or "",
                    last_stderr=result.error_log or "",
                    last_error_log=result.error_log or "",
                    schema_diagnostics=diagnostics,
                    setup_execution_feedback=_summarise_setup_results(
                        setup_exec_results
                    ),
                )
                for followup_plan, followup_results in followup_rounds:
                    setup_summary = (
                        (setup_summary or "Setup state:")
                        + "\n\n"
                        + f"FOLLOWUP after iter {iteration}: "
                        f"{followup_plan.rationale or '(no rationale)'}\n"
                        + "Authoritative execution results:\n"
                        + _summarise_setup_results(followup_results)
                    )
                if followup is not None and not followup.commands:
                    # No setup change is needed, but a failed generated request is not proof
                    # that the source candidate is safe. Give the PoC author the diagnosis
                    # and continue within the configured iteration bound.
                    fc = followup.failure_class
                    stderr_blob = result.error_log or ""
                    poc_crashed = (
                        "Traceback (most recent call last)" in stderr_blob
                        or "JSONDecodeError" in stderr_blob
                        or "KeyError" in stderr_blob
                        or "IndexError" in stderr_blob
                        or "AttributeError" in stderr_blob
                    )
                    classification = (
                        "poc_code" if poc_crashed else (fc or "exploit_shape")
                    )
                    attempt.developer_analysis = (
                        f"{classification}: {followup.rationale or '(none)'}"
                    )[:1000]
                    logger.info(
                        "verify: %s iter %d failure classified as %s — continuing PoC "
                        "iteration (rationale: %s)",
                        hyp.id,
                        iteration,
                        classification,
                        (followup.rationale or "(none)")[:200],
                    )

        # Collect optional diagnostics while the failed sandbox is still alive.
        any_confirmed = any(
            attempt.phase == "confirmation" and attempt.result == PoCStatus.SUCCESS
            for attempt in attempts
        )
        if not any_confirmed and verify_cfg.state_introspection_on_failure:
            try:
                await verify_helpers.dump_sandbox_state(sb, poc_dir / "state_dump")
            except Exception as e:
                logger.warning("verify: state dump for %s failed: %s", hyp.id, e)

        _checkpoint_setup_results()

    successful = [
        attempt for attempt in attempts if attempt.result == PoCStatus.SUCCESS
    ]
    confirmations = [
        attempt for attempt in successful if attempt.phase == "confirmation"
    ]
    if not confirmations:
        logger.info(
            "verify: %s NOT confirmed after %d iterations", hyp.id, len(attempts)
        )
        return None

    finding = Finding(
        id=_next_finding_id(),
        hypothesis=hyp,
        poc_status=PoCStatus.SUCCESS,
        poc_script_path=confirmations[-1].script_path,
        poc_attempts=attempts,
        evidence=last_evidence,
        confidence_runs=len(successful),
        dedup_status=DedupStatus.NOT_CHECKED,
        dedup_matches=[],
    )

    return finding


def _new_verify_archive_dir(run_dir: Path) -> Path:
    return run_dir / "verify_archive" / uuid.uuid4().hex[:12]


def _archive_forced_verify_artifacts(
    run_dir: Path,
    verifications_dir: Path,
    findings_path: Path,
    complete_path: Path,
) -> Path | None:
    """Move prior verify outputs aside before an explicitly forced re-run."""
    existing = [
        path
        for path in (verifications_dir, findings_path, complete_path)
        if path.exists()
    ]
    if not existing:
        return None

    archive_dir = _new_verify_archive_dir(run_dir)
    archive_dir.mkdir(parents=True, exist_ok=False)
    for path in existing:
        shutil.move(str(path), str(archive_dir / path.name))
    return archive_dir


def _archive_hypothesis_artifacts(
    run_dir: Path,
    hyp_dir: Path,
    archive_dir: Path | None,
) -> tuple[Path | None, Path | None]:
    """Archive an incomplete candidate before retrying it in a clean directory."""
    if not hyp_dir.exists():
        return archive_dir, None
    if archive_dir is None:
        archive_dir = _new_verify_archive_dir(run_dir)
    target = archive_dir / "verifications" / hyp_dir.name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(hyp_dir), str(target))
    return archive_dir, target


async def run(
    triaged: TriagedArtifact,
    plugin_path: str,
    config: PipelineConfig,
    budget: BudgetTracker,
    runtime: AgentRuntime,
    runs_root: str = "runs",
    run_id: str = "",
    developer: DeveloperAgent | None = None,
    force: bool = False,
) -> list[Finding]:
    plugin_zip, plugin_zip_staging = _zip_plugin(plugin_path, triaged.plugin_slug)
    logger.info("verify: zipped plugin to %s", plugin_zip)

    findings: list[Finding] = []
    run_dir = Path(runs_root) / run_id
    verifications_dir = Path(runs_root) / run_id / "verifications"
    findings_path = Path(runs_root) / run_id / "findings.jsonl"
    complete_path = run_dir / VERIFY_COMPLETE_FILENAME
    findings_path.parent.mkdir(parents=True, exist_ok=True)

    retry_archive_dir: Path | None = None
    if force:
        retry_archive_dir = _archive_forced_verify_artifacts(
            run_dir,
            verifications_dir,
            findings_path,
            complete_path,
        )
        if retry_archive_dir is not None:
            logger.info(
                "verify: archived prior forced-run artifacts to %s", retry_archive_dir
            )
            append_decision(
                run_dir,
                stage="verify",
                action="archive",
                result="forced_rerun",
                artifact=retry_archive_dir,
            )
    else:
        # A caller reached the stage because the prior pass was incomplete. Do not
        # leave a stale success marker behind if this retry fails.
        complete_path.unlink(missing_ok=True)

    # Per-hypothesis checkpoint: load any previously confirmed findings (so a
    # mid-list crash doesn't lose them). A clean iter_*.py checkpoint is a terminal
    # non-confirmation. error.log, or a directory without iterations, is incomplete
    # and must be retried.
    previously_confirmed: dict[str, Finding] = {}
    if not force and findings_path.exists() and findings_path.stat().st_size > 0:
        parsed, corrupt_count = read_jsonl_models(
            findings_path,
            Finding,
            corrupt_path=run_dir / "findings_corrupt.jsonl",
        )
        for f in parsed:
            previously_confirmed[f.hypothesis.id] = f
        if corrupt_count:
            logger.warning(
                "verify: quarantined %d malformed findings.jsonl line(s) to %s",
                corrupt_count,
                run_dir / "findings_corrupt.jsonl",
            )
            append_decision(
                run_dir,
                stage="verify",
                action="recover",
                result="corrupt_findings_quarantined",
                reason=f"{corrupt_count} malformed findings.jsonl line(s)",
                artifact=run_dir / "findings_corrupt.jsonl",
            )
        if previously_confirmed:
            logger.info(
                "verify: resuming with %d previously confirmed findings",
                len(previously_confirmed),
            )
    findings.extend(previously_confirmed.values())

    # Open findings.jsonl in append mode after preserving prior content.
    # Re-write what we have so the file is the canonical source of truth.
    atomic_write_jsonl(findings_path, findings)

    unresolved_errors: list[tuple[str, str]] = []

    # Persistent path: boot one sandbox at scan level, snapshot baseline,
    # restore between hypotheses. Cuts ~80% of sandbox cost for multi-hypothesis runs.
    persistent_sb: SandboxManager | None = None
    persistent_snapshot: Path | None = None
    if config.verify.persistent_sandbox and triaged.accepted:
        try:
            persistent_sb = SandboxManager(
                config.sandbox,
                boot_timeout_s=max(config.sandbox_timeout_seconds, 180),
                poc_timeout_s=config.sandbox_timeout_seconds,
            )
            await persistent_sb.boot()
            await persistent_sb.install_plugin(plugin_zip, triaged.plugin_slug)
            await persistent_sb.setup_test_users()
            persistent_snapshot = await persistent_sb.snapshot()
            logger.info(
                "verify: persistent sandbox booted (target=%s, snapshot=%s)",
                persistent_sb.target_url,
                persistent_snapshot,
            )
        except Exception as e:
            logger.warning(
                "verify: persistent sandbox boot failed: %s — falling back to per-hypothesis",
                e,
            )
            if persistent_sb is not None:
                try:
                    await persistent_sb.teardown()
                except Exception:
                    pass
            persistent_sb = None
            persistent_snapshot = None

    try:
        for hyp in triaged.accepted:
            if hyp.id in previously_confirmed:
                logger.info(
                    "verify: %s — skipping (already confirmed in prior run)", hyp.id
                )
                append_decision(
                    run_dir,
                    stage="verify",
                    action="skip",
                    result="previously_confirmed",
                    hypothesis_id=hyp.id,
                    artifact=findings_path,
                )
                continue
            hyp_dir = verifications_dir / hyp.id
            error_path = hyp_dir / "error.log"
            iter_files = sorted(hyp_dir.glob("iter_*.py")) if hyp_dir.exists() else []
            # Only a clean iteration checkpoint is a terminal non-confirmation.
            # Exceptions take precedence even if iterations were written first.
            if hyp_dir.exists() and iter_files and not error_path.exists():
                logger.info(
                    "verify: %s — skipping (already attempted, no confirm). "
                    "Use --from verify to retry.",
                    hyp.id,
                )
                append_decision(
                    run_dir,
                    stage="verify",
                    action="skip",
                    result="previously_attempted_not_confirmed",
                    hypothesis_id=hyp.id,
                    artifact=hyp_dir,
                )
                continue
            if hyp_dir.exists():
                retry_reason = (
                    "previous_error" if error_path.exists() else "incomplete_checkpoint"
                )
                retry_archive_dir, archived_path = _archive_hypothesis_artifacts(
                    run_dir,
                    hyp_dir,
                    retry_archive_dir,
                )
                logger.info(
                    "verify: %s — retrying %s checkpoint (archived to %s)",
                    hyp.id,
                    retry_reason,
                    archived_path,
                )
                append_decision(
                    run_dir,
                    stage="verify",
                    action="archive",
                    result=retry_reason,
                    hypothesis_id=hyp.id,
                    artifact=archived_path,
                )
            logger.info("verify: %s (%s)", hyp.id, hyp.bug_class.value)
            hyp_dir.mkdir(parents=True, exist_ok=True)

            # Restore baseline before each hypothesis to prevent state leakage.
            if persistent_sb is not None and persistent_snapshot is not None:
                try:
                    await persistent_sb.restore(persistent_snapshot)
                except Exception as e:
                    logger.warning(
                        "verify: persistent restore for %s failed: %s; "
                        "falling back to a fresh per-hypothesis sandbox",
                        hyp.id,
                        e,
                    )
                    try:
                        await persistent_sb.teardown()
                    finally:
                        shutil.rmtree(persistent_snapshot, ignore_errors=True)
                        persistent_sb = None
                        persistent_snapshot = None
            try:
                finding = await _verify_one(
                    hyp,
                    plugin_path,
                    plugin_zip,
                    triaged.plugin_slug,
                    config,
                    runtime,
                    poc_dir=hyp_dir,
                    developer=developer,
                    persistent_sb=persistent_sb,
                )
            except Exception as e:
                import traceback

                tb = traceback.format_exc()
                logger.exception("verify: hypothesis %s raised: %s", hyp.id, e)
                atomic_write_text(
                    hyp_dir / "error.log",
                    f"=== Exception during verify for {hyp.id} ===\n"
                    f"hypothesis: {hyp.bug_class.value} {hyp.file}:{hyp.line}\n"
                    f"sink: {hyp.sink}\n\n"
                    f"{tb}",
                )
                append_decision(
                    run_dir,
                    stage="verify",
                    action="error",
                    result="exception",
                    hypothesis_id=hyp.id,
                    reason=str(e),
                    artifact=hyp_dir / "error.log",
                )
                unresolved_errors.append((hyp.id, str(e)))
                continue
            # Detect silent failures — completed normally but no iter files were written.
            iter_files = sorted(hyp_dir.glob("iter_*.py"))
            if not iter_files:
                reason = "_verify_one returned without writing any PoC iterations"
                atomic_write_text(
                    hyp_dir / "error.log",
                    f"=== Silent failure for {hyp.id} ===\n"
                    f"_verify_one returned without raising an exception, but no iter files\n"
                    f"were written. This usually means SandboxManager.__aenter__() raised an\n"
                    f"exception that was caught silently OR propose_setup hung without raising,\n"
                    f"OR docker compose timed out internally.\n\n"
                    f"Inspect runs/{run_id}/trace.jsonl for poc_author entries (or absence) to\n"
                    f"diagnose. If `propose_setup for {hyp.id} failed` appears in the run logs\n"
                    f"that's the smoking gun.\n",
                )
                logger.warning(
                    "verify: hypothesis %s — no iter files written and no exception raised",
                    hyp.id,
                )
                append_decision(
                    run_dir,
                    stage="verify",
                    action="error",
                    result="silent_failure",
                    hypothesis_id=hyp.id,
                    reason=reason,
                    artifact=hyp_dir / "error.log",
                )
                unresolved_errors.append((hyp.id, reason))
                continue
            if finding is None:
                append_decision(
                    run_dir,
                    stage="verify",
                    action="reject",
                    result="not_confirmed",
                    hypothesis_id=hyp.id,
                    artifact=hyp_dir,
                )
                continue
            findings.append(finding)
            with findings_path.open("a") as output_file:
                output_file.write(finding.model_dump_json() + "\n")
            append_decision(
                run_dir,
                stage="verify",
                action="confirm",
                result=finding.poc_status.value,
                hypothesis_id=hyp.id,
                finding_id=finding.id,
                artifact=findings_path,
                details={"poc_script_path": finding.poc_script_path},
            )
    finally:
        # Tear down the persistent sandbox at end of scan.
        if persistent_sb is not None:
            try:
                await persistent_sb.teardown()
                logger.info("verify: persistent sandbox torn down")
            except Exception as e:
                logger.warning("verify: persistent sandbox teardown failed: %s", e)
        if persistent_snapshot is not None and persistent_snapshot.exists():
            try:
                shutil.rmtree(persistent_snapshot)
            except Exception:
                pass
        shutil.rmtree(plugin_zip_staging, ignore_errors=True)

    if unresolved_errors:
        raise VerifyStageError(unresolved_errors, findings)

    atomic_write_json(
        complete_path,
        {
            "status": "complete",
            "accepted_hypothesis_ids": [hyp.id for hyp in triaged.accepted],
            "finding_ids": [finding.id for finding in findings],
        },
    )
    logger.info("verify: %d findings confirmed -> %s", len(findings), findings_path)
    return findings
