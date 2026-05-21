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

from ..agents.developer import DeveloperAgent
from ..agents.poc_author import PoCAuthorAgent
from ..agents.runtime import AgentRuntime
from ..schemas.config import PipelineConfig
from ..schemas.finding import DedupStatus, Finding, PoCAttempt, PoCStatus
from ..schemas.hypothesis import Hypothesis, TriagedArtifact
from ..services.budget import BudgetTracker
from ..services.sandbox import SandboxManager
from ..services import verify_helpers

logger = logging.getLogger(__name__)

_XSS_CHECK_SRC = (_pkg_files("wpvulnhunt") / "poc_templates" / "xss_check.py").read_text()
_WP_LOGIN_SRC = (_pkg_files("wpvulnhunt") / "poc_templates" / "wp_login.py").read_text()


def _zip_plugin(plugin_path: str, slug: str) -> str:
    """Create a zip with the plugin folder at top level — wp plugin install expects this."""
    src = Path(plugin_path).resolve()
    staging = Path(tempfile.mkdtemp(prefix=f"wpvh-zip-{slug}-"))
    target = staging / slug
    shutil.copytree(src, target)
    out = shutil.make_archive(str(staging / slug), "zip", root_dir=str(staging), base_dir=slug)
    return out


def _next_finding_id() -> str:
    return f"f-{uuid.uuid4().hex[:10]}"


_WP_SETUP_ERROR_RE = re.compile(
    r"WordPress database error|Unknown column|Table .* doesn't exist|does not exist|"
    r"PHP Fatal error|Parse error|Warning:",
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

_SHELL_PAYLOAD_SEED_RE = re.compile(r"(?:\b(?:id|whoami|uname)\b\s*[;&|`$]|\$\(|`[^`]+`)", re.IGNORECASE)


def _setup_command_plants_exploit_payload(args: list[str], hyp: Hypothesis) -> str | None:
    """Detect setup that directly plants an exploit marker into storage.

    Setup is allowed to create normal plugin state, but a confirmed PoC should not be
    based on `wpdb->insert`/`wp db query` writing the malicious value directly into the
    column/file/option that the hypothesis later reads. This guard blocks obvious
    direct exploit-payload seeding across the common bug classes while allowing benign
    prerequisite rows/options.
    """
    command = " ".join(args)
    if not _DIRECT_STORAGE_WRITE_RE.search(command):
        return None
    if hyp.bug_class.value == "CWE-79" and _XSS_PAYLOAD_SEED_RE.search(command):
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
    blocked = [item for item in results if item.get("forbidden_payload_seed")]
    lines: list[str] = []
    for item in blocked:
        cmd = " ".join(item.get("args", [])[:10])
        reason = item.get("forbidden_payload_seed_reason") or "direct exploit payload seed"
        lines.append(f"- wp {cmd} ({reason})")
    return "\n".join(lines)


def _summarise_setup_results(results: list[dict]) -> str:
    lines: list[str] = []
    for item in results:
        status = "FAILED" if item.get("failed") else "OK"
        cmd = " ".join(item.get("args", [])[:8])
        output = (item.get("output") or item.get("stderr") or "").strip().replace("\n", " ")
        if len(output) > 500:
            output = output[:500] + "..."
        lines.append(f"{status}: wp {cmd} -> {output}")
    return "\n".join(lines)


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
        forbidden_reason = (
            _setup_command_plants_exploit_payload(args, hypothesis)
            if hypothesis is not None else None
        )
        try:
            rc, out, err = await sb.wp_cli._exec_result(*args)
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
            }
            results.append(result)
            log = logger.warning if failed or forbidden_reason else logger.info
            log("setup wp %s -> %s", " ".join(args[:6]), (combined or "").strip()[:160])
            if forbidden_reason:
                logger.warning("setup wp %s rejected for verification: %s",
                               " ".join(args[:6]), forbidden_reason)
        except Exception as e:
            logger.warning("setup wp %s failed: %s", " ".join(args[:6]), e)
            results.append({
                "args": args,
                "returncode": -1,
                "output": "",
                "stderr": str(e),
                "failed": True,
                "forbidden_payload_seed": bool(forbidden_reason),
                "forbidden_payload_seed_reason": forbidden_reason,
            })
    return results


# Tables referenced in raw SQL — used to seed schema diagnostics for the followup developer call.
_TABLE_RE = re.compile(
    r"\$wpdb->prefix\s*\.\s*['\"]([a-z0-9_]+)['\"]|"
    r"\b((?:wp_)?(?:aysquiz_|nf3_|nf_|wf|et_|elementor_|wcfm_|wc_|woocommerce_)[a-z0-9_]+)\b",
    re.IGNORECASE,
)


async def _collect_schema_diagnostics(sb: SandboxManager, commands: list[list[str]]) -> str:
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
                "if (in_array($t, $wpdb->get_col(\"SHOW TABLES\"))) { "
                "  $rows = $wpdb->get_results(\"DESCRIBE `$t`\", ARRAY_A); "
                "  echo $t . ': ' . json_encode(array_map(fn($r)=>$r['Field'].' '.$r['Type'],$rows)); "
                "} else { echo $t . ': (table does not exist)'; }"
            )
            res = await sb.wp_cli._eval(php)
            out_parts.append(res.strip())
        except Exception as e:
            out_parts.append(f"{tbl}: diagnostics failed ({e})")
    return "\n".join(out_parts)


def _read_code_slice(plugin_root: Path, rel_file: str, max_lines: int = 500) -> str | None:
    if not rel_file:
        return None
    candidate = plugin_root / rel_file
    if not candidate.is_file():
        # The hypothesis file path may be plugin-relative or include the wp-content prefix; try strip
        for prefix in ("wp-content/plugins/" + plugin_root.name + "/", plugin_root.name + "/"):
            if rel_file.startswith(prefix):
                candidate = plugin_root / rel_file[len(prefix):]
                if candidate.is_file():
                    break
    if not candidate.is_file():
        return None
    try:
        text = candidate.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    lines = text.splitlines()
    if len(lines) > max_lines:
        lines = lines[:max_lines] + [f"... [truncated at {max_lines} lines]"]
    return "\n".join(lines)


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
    plugin_version: str = "",
    # W3: when provided, skip sandbox boot/teardown — caller manages lifecycle
    persistent_sb: SandboxManager | None = None,
) -> Finding | None:
    verify_cfg = config.verify

    # W10: cache check (BEFORE we boot anything)
    cache_key: str | None = None
    if verify_cfg.cache_enabled:
        cache_key = verify_helpers.verify_cache_key(
            hyp, plugin_version,
            sandbox_image=config.sandbox.wordpress_image,
            verify_config=verify_cfg.model_dump(),
        )
        cached = verify_helpers.verify_cache_load(cache_key)
        if cached is not None:
            logger.info("verify: %s cache hit %s — reusing", hyp.id, cache_key)
            return cached

    poc_dir.mkdir(parents=True, exist_ok=True)
    # Drop the xss_check helper next to the PoC scripts so they can `from xss_check import ...`.
    (poc_dir / "xss_check.py").write_text(_XSS_CHECK_SRC)
    # Drop the wp_login helper too — robust GET-then-POST flow with the
    # `wordpress_test_cookie` handled. Eliminates "admin login failed" false
    # negatives caused by PoC scripts skipping the GET prime step.
    (poc_dir / "wp_login.py").write_text(_WP_LOGIN_SRC)
    attempts: list[PoCAttempt] = []
    last_evidence: dict = {}

    # W9 setup_callback — bound below once sandbox + developer are in scope.
    # Created as a closure so PoCAuthor can call it via the request_additional_setup tool.
    _w9_state = {"sb": None, "setup_plan_ref": None}

    async def _w9_setup_callback(description: str) -> str:
        sb_local = _w9_state["sb"]
        plan_ref = _w9_state["setup_plan_ref"]
        if sb_local is None or developer is None:
            return "[request_additional_setup] sandbox or developer not yet ready"
        try:
            from ..agents.developer import SetupPlan as _SetupPlan
            followup = await developer.propose_setup_followup(
                hypothesis=hyp,
                prior_plan=plan_ref or _SetupPlan(),
                last_iteration=0,
                last_stdout="",
                last_stderr="",
                last_error_log="",
                schema_diagnostics=f"PoC author requested additional setup:\n{description}",
            )
            if not followup or not followup.commands:
                return f"[request_additional_setup] developer returned 0 commands (rationale: {(followup.rationale if followup else 'none')!r})"
            applied_results = await _run_setup_commands(sb_local, followup.commands, hypothesis=hyp)
            setup_exec_results.extend(applied_results)
            if any(item.get("forbidden_payload_seed") for item in applied_results):
                return (
                    "[request_additional_setup] rejected: setup attempted to directly plant "
                    "the exploit payload into storage. Submit malicious input through the "
                    "real plugin entry point instead."
                )
            if plan_ref:
                plan_ref.commands.extend(followup.commands)
            cmd_summary = "; ".join(" ".join(c) for c in followup.commands[:5])
            return (f"[request_additional_setup] applied {len(followup.commands)} commands. "
                    f"Rationale: {followup.rationale or '(none)'}\nCommands: {cmd_summary}")
        except Exception as e:
            return f"[request_additional_setup] developer call failed: {e}"

    poc_author = PoCAuthorAgent(
        runtime, model=config.models.poc_author, plugin_root=plugin_path,
        setup_callback=_w9_setup_callback if config.verify.collaborative_dev_poc_loop else None,
    )
    setup_exec_results: list[dict] = []

    # Ask the developer expert what setup the sandbox needs for this hypothesis to be reachable.
    # Skip for AJAX / REST / admin-post entry points — those are hit directly
    # with default users and usually do not need extra state seeding.
    from ..agents.developer import SetupPlan
    setup_plan: SetupPlan = SetupPlan()
    entry = (hyp.entry_point or "").lower()
    is_direct_endpoint = (
        "wp_ajax_" in entry
        or "rest_api" in entry
        or "rest route" in entry
        or "admin_post" in entry
        or "admin-ajax" in entry
    )
    if developer is not None and not is_direct_endpoint:
        plugin_root = Path(plugin_path)
        code_slice = _read_code_slice(plugin_root, hyp.file)
        readme = _read_readme(plugin_root)
        try:
            setup_plan = await developer.propose_setup(
                hyp,
                plugin_slug=plugin_slug,
                code_slice=code_slice,
                readme_excerpt=readme,
            )
        except Exception as e:
            logger.warning("propose_setup for %s failed: %s", hyp.id, e)
    elif is_direct_endpoint:
        logger.info("verify: %s — skipping propose_setup (direct endpoint, default users sufficient)", hyp.id)

    # W3: persistent_sb is supplied when verify.run() is in persistent-sandbox mode.
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
                await _run_setup_commands(persistent_sb, setup_plan.commands, hypothesis=hyp),
            )
            yield persistent_sb
            return
        async with SandboxManager(
            config.sandbox,
            boot_timeout_s=max(config.sandbox_timeout_seconds, 180),
            poc_timeout_s=config.sandbox_timeout_seconds,
        ) as fresh_sb:
            await fresh_sb.install_plugin(plugin_zip)
            await fresh_sb.setup_test_users()
            setup_exec_results.extend(
                await _run_setup_commands(fresh_sb, setup_plan.commands, hypothesis=hyp),
            )
            yield fresh_sb

    async with _sb_ctx() as sb:
        # W9: bind the live sandbox + setup_plan into the W9 callback closure
        _w9_state["sb"] = sb
        _w9_state["setup_plan_ref"] = setup_plan

        # Build a plain-language setup summary the PoC author can act on.
        setup_summary = None
        if setup_plan.rationale or setup_plan.commands:
            cmd_lines = "\n".join(f"  - wp {' '.join(c)}" for c in setup_plan.commands)
            setup_summary = (
                f"The runner has just configured the sandbox before the PoC runs.\n"
                f"Reason: {setup_plan.rationale or '(none stated)'}\n"
                f"Commands executed:\n{cmd_lines}\n"
                f"You may use any state these commands established (created pages, "
                f"option values, seeded files). You are not required to use them — "
                f"if you have a better attack path, take it."
            )

        followups_used = 0
        followup_cap = 2  # bound the developer's re-setup attempts per hypothesis

        setup_failed = any(item.get("failed") for item in setup_exec_results)
        if setup_failed:
            setup_summary = (
                (setup_summary or "The initial sandbox setup ran before the PoC.")
                + "\n\nSETUP COMMAND WARNINGS:\n"
                + _summarise_setup_results(setup_exec_results)
            )
            if developer is not None and not is_direct_endpoint and followups_used < followup_cap:
                try:
                    diagnostics = await _collect_schema_diagnostics(sb, setup_plan.commands)
                    followup = await developer.propose_setup_followup(
                        hypothesis=hyp,
                        prior_plan=setup_plan,
                        last_iteration=0,
                        last_stdout=_summarise_setup_results(setup_exec_results),
                        last_stderr="",
                        last_error_log="",
                        schema_diagnostics=diagnostics,
                    )
                except Exception as e:
                    logger.warning("initial setup followup for %s failed: %s", hyp.id, e)
                    followup = None
                if followup and followup.commands:
                    followups_used += 1
                    logger.info("verify: %s repairing failed setup with %d commands (round %d/%d)",
                                hyp.id, len(followup.commands), followups_used, followup_cap)
                    repair_results = await _run_setup_commands(sb, followup.commands, hypothesis=hyp)
                    setup_exec_results.extend(repair_results)
                    setup_plan.commands.extend(followup.commands)
                    setup_summary += (
                        f"\n\nSETUP REPAIR before PoC iteration 1: {followup.rationale or '(no rationale)'}\n"
                        + _summarise_setup_results(repair_results)
                    )

        # W4: pre-fetch payload variants the PoC author can rotate through on retries
        payload_variant_pool = (
            verify_helpers.get_payload_variants(verify_cfg.payload_variant_cap)
            if verify_cfg.payload_variants else []
        )

        # Surface the credential table the sandbox provisioned. PoC author MUST
        # pick from this list rather than recalling credentials from system prompt.
        user_accounts = sb.baseline_user_accounts()

        for iteration in range(1, config.verify_max_iterations + 1):
            extra_ctx: dict = {"user_accounts": user_accounts}
            if setup_summary:
                extra_ctx["setup_summary"] = setup_summary
            # W4: surface the next variant to try on this iteration (PoC author can use or ignore)
            if payload_variant_pool and iteration > 1:
                idx = (iteration - 2) % len(payload_variant_pool)
                extra_ctx["suggested_payload_variant"] = payload_variant_pool[idx]
            script = await poc_author.write(
                hypothesis=hyp,
                target_url=sb.target_url,
                previous_attempts=attempts,
                extra_context=extra_ctx or None,
            )
            script_path = poc_dir / f"iter_{iteration}.py"
            script_path.write_text(script)

            result = await sb.run_poc(str(script_path))
            attempt = PoCAttempt(
                iteration=iteration,
                script_path=str(script_path),
                result=PoCStatus.SUCCESS if result.success else PoCStatus.FAILED,
                http_status=result.http_status,
                response_snippet=(result.response or "")[:500] or None,
                timing_seconds=result.elapsed,
                error_log_snippet=(result.error_log or "")[:500] or None,
                developer_analysis=None,  # PoC author re-evaluates with consult_developer in next iter
            )
            last_evidence = result.evidence

            if result.success:
                forbidden_setup = any(item.get("forbidden_payload_seed") for item in setup_exec_results)
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
                    logger.warning("verify: %s rejected tainted setup confirmation", hyp.id)
                    break
                # Confirmation re-run
                confirm = await sb.run_poc(str(script_path))
                attempt.result = PoCStatus.SUCCESS if confirm.success else PoCStatus.PARTIAL
                attempts.append(attempt)
                # R5: capture a screenshot of the sandbox state (gracefully no-ops if Playwright missing)
                # Coordinated with R4 — the screenshot lands at verifications/<id>/screenshots/, which
                # the report-stage bundler picks up automatically.
                if config.report.screenshot_capture:
                    screenshot_dir = poc_dir / "screenshots"
                    await verify_helpers.screenshot_url(
                        sb.target_url + "/wp-admin/",
                        screenshot_dir / f"{hyp.id}_admin.png",
                        timeout_s=verify_cfg.headless_browser_timeout_s,
                    )
                break

            attempts.append(attempt)

            # Failed iteration — ask the developer if it looks setup-shaped, before next PoC try.
            if (
                developer is not None
                and not is_direct_endpoint
                and followups_used < followup_cap
                and iteration < config.verify_max_iterations  # no point on the last iter
            ):
                try:
                    diagnostics = await _collect_schema_diagnostics(sb, setup_plan.commands)
                    followup = await developer.propose_setup_followup(
                        hypothesis=hyp,
                        prior_plan=setup_plan,
                        last_iteration=iteration,
                        last_stdout=result.response or "",
                        last_stderr=result.error_log or "",
                        last_error_log=result.error_log or "",
                        schema_diagnostics=diagnostics,
                    )
                except Exception as e:
                    logger.warning("propose_setup_followup for %s failed: %s", hyp.id, e)
                    followup = None
                if followup and followup.commands:
                    followups_used += 1
                    logger.info("verify: %s applying %d followup setup commands (round %d/%d)",
                                hyp.id, len(followup.commands), followups_used, followup_cap)
                    followup_results = await _run_setup_commands(sb, followup.commands, hypothesis=hyp)
                    setup_exec_results.extend(followup_results)
                    # Merge into the plan so future followups see full history.
                    setup_plan.commands.extend(followup.commands)
                    fu_lines = "\n".join(f"  - wp {' '.join(c)}" for c in followup.commands)
                    setup_summary = (
                        (setup_summary or "Setup state:") + "\n\n"
                        f"FOLLOWUP after iter {iteration}: {followup.rationale or '(no rationale)'}\n"
                        f"Additional commands executed:\n{fu_lines}"
                    )
                elif followup is not None:
                    # Developer returned 0 commands. Three possible meanings:
                    #   - "exploit_shape": setup is fine, the bug just didn't fire → early-exit.
                    #   - "poc_code":     the script crashed before reaching the exploit →
                    #                     keep iterating; the PoC author needs another shot.
                    #   - None / unset:   legacy behaviour, treat as exploit_shape.
                    fc = followup.failure_class
                    stderr_blob = (result.error_log or "")
                    poc_crashed = (
                        "Traceback (most recent call last)" in stderr_blob
                        or "JSONDecodeError" in stderr_blob
                        or "KeyError" in stderr_blob
                        or "IndexError" in stderr_blob
                        or "AttributeError" in stderr_blob
                    )
                    # Belt-and-braces: if the model said exploit_shape but stderr clearly
                    # shows a Python crash, prefer poc_code — a buggy script can't prove a
                    # bug doesn't exist.
                    if fc == "poc_code" or (fc != "exploit_shape" and poc_crashed) or (fc is None and poc_crashed):
                        logger.info(
                            "verify: %s iter %d failure classified as poc_code — "
                            "continuing iteration (rationale: %s)",
                            hyp.id, iteration, (followup.rationale or "(none)")[:200],
                        )
                        # fall through — let the PoC author try again next iteration
                    else:
                        logger.info(
                            "verify: %s early-exit after iter %d — followup classified failure as "
                            "exploit-shape (rationale: %s)",
                            hyp.id, iteration, (followup.rationale or "(none)")[:200],
                        )
                        break

        # W5: state introspection on persistent failure (still inside `async with` so sandbox is alive)
        any_succeeded = any(a.result in (PoCStatus.SUCCESS, PoCStatus.PARTIAL) for a in attempts)
        if not any_succeeded and verify_cfg.state_introspection_on_failure:
            try:
                await verify_helpers.dump_sandbox_state(sb, poc_dir / "state_dump")
            except Exception as e:
                logger.warning("verify: W5 state dump for %s failed: %s", hyp.id, e)

    successful = [a for a in attempts if a.result in (PoCStatus.SUCCESS, PoCStatus.PARTIAL)]
    if not successful:
        logger.info("verify: %s NOT confirmed after %d iterations", hyp.id, len(attempts))
        # W5: state introspection on persistent failure (best-effort; SandboxManager may already be torn down here)
        # Note: We exited the `async with SandboxManager` block, so live state-dump isn't possible
        # from this point. The introspection happens inline before the sandbox tears down — see below.
        # W6: emit to manual review queue if toggle on
        if verify_cfg.manual_review_handoff:
            verify_helpers.write_manual_scaffold(
                hyp, poc_dir, plugin_slug, "",
                attempts=attempts, setup_results=setup_exec_results,
            )
            verify_helpers.emit_to_manual_review_queue(
                hyp, poc_dir.parent.parent, reason=f"failed after {len(attempts)} iterations",
                attempts=[
                    a.model_dump(mode="json") if hasattr(a, "model_dump") else a
                    for a in attempts
                ],
                setup_results=setup_exec_results,
            )
        return None

    finding = Finding(
        id=_next_finding_id(),
        hypothesis=hyp,
        poc_status=successful[-1].result,
        poc_script_path=successful[-1].script_path,
        poc_attempts=attempts,
        evidence=last_evidence,
        confidence_runs=len(successful),
        dedup_status=DedupStatus.NOVEL,
        dedup_matches=[],
    )

    # W10: cache the confirmed finding
    if cache_key:
        verify_helpers.verify_cache_save(cache_key, finding)
    return finding


async def run(
    triaged: TriagedArtifact,
    plugin_path: str,
    config: PipelineConfig,
    budget: BudgetTracker,
    runtime: AgentRuntime,
    runs_root: str = "runs",
    run_id: str = "",
    developer: DeveloperAgent | None = None,
) -> list[Finding]:
    plugin_zip = _zip_plugin(plugin_path, triaged.plugin_slug)
    logger.info("verify: zipped plugin to %s", plugin_zip)

    # Thread plugin_version through to _verify_one for W10 cache keying.
    plugin_version = ""
    try:
        from ..schemas.intake import IntakeArtifact
        intake_path = Path(runs_root) / run_id / "intake.json"
        if intake_path.exists():
            plugin_version = IntakeArtifact.from_json_file(str(intake_path)).plugin_version
    except Exception:
        pass

    findings: list[Finding] = []
    verifications_dir = Path(runs_root) / run_id / "verifications"
    findings_path = Path(runs_root) / run_id / "findings.jsonl"
    findings_path.parent.mkdir(parents=True, exist_ok=True)

    # Per-hypothesis checkpoint: load any previously confirmed findings (so a
    # mid-list crash doesn't lose them) and skip hypotheses we've already attempted.
    # A hypothesis is "attempted" if its verifications/<hyp_id>/ directory contains
    # either iter_*.py (PoC iterations were written) or error.log (failure recorded).
    previously_confirmed: dict[str, Finding] = {}
    if findings_path.exists() and findings_path.stat().st_size > 0:
        for line in findings_path.read_text().splitlines():
            if not line.strip():
                continue
            try:
                f = Finding.model_validate_json(line)
                previously_confirmed[f.hypothesis.id] = f
            except Exception:
                pass  # malformed line — ignore, will be overwritten
        if previously_confirmed:
            logger.info("verify: resuming with %d previously confirmed findings",
                        len(previously_confirmed))
    findings.extend(previously_confirmed.values())

    # Open findings.jsonl in append mode after preserving prior content.
    # Re-write what we have so the file is the canonical source of truth.
    with findings_path.open("w") as f:
        for fnd in findings:
            f.write(fnd.model_dump_json() + "\n")

    # W3: persistent-sandbox path — boot one sandbox at scan level, snapshot baseline,
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
            await persistent_sb.install_plugin(plugin_zip)
            await persistent_sb.setup_test_users()
            persistent_snapshot = await persistent_sb.snapshot()
            logger.info("verify: W3 persistent-sandbox booted (target=%s, snapshot=%s)",
                        persistent_sb.target_url, persistent_snapshot)
        except Exception as e:
            logger.warning("verify: W3 persistent-sandbox boot failed: %s — falling back to per-hypothesis", e)
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
                logger.info("verify: %s — skipping (already confirmed in prior run)", hyp.id)
                continue
            hyp_dir = verifications_dir / hyp.id
            # Already-attempted check: if the dir has iter files or an error log, we
            # tried before and didn't confirm. Skip rather than re-spend.
            if hyp_dir.exists() and (
                list(hyp_dir.glob("iter_*.py")) or (hyp_dir / "error.log").exists()
            ):
                logger.info("verify: %s — skipping (already attempted, no confirm). "
                            "Delete %s to retry.", hyp.id, hyp_dir)
                continue
            logger.info("verify: %s (%s)", hyp.id, hyp.bug_class.value)
            hyp_dir.mkdir(parents=True, exist_ok=True)

            # W3: restore baseline before each hypothesis (skip leak between PoCs)
            if persistent_sb is not None and persistent_snapshot is not None:
                try:
                    await persistent_sb.restore(persistent_snapshot)
                except Exception as e:
                    logger.warning("verify: W3 restore for %s failed: %s — continuing without restore", hyp.id, e)
            try:
                finding = await _verify_one(
                    hyp, plugin_path, plugin_zip, triaged.plugin_slug,
                    config, runtime,
                    poc_dir=hyp_dir,
                    developer=developer,
                    plugin_version=plugin_version,
                    persistent_sb=persistent_sb,
                )
            except Exception as e:
                import traceback
                tb = traceback.format_exc()
                logger.exception("verify: hypothesis %s raised: %s", hyp.id, e)
                (hyp_dir / "error.log").write_text(
                    f"=== Exception during verify for {hyp.id} ===\n"
                    f"hypothesis: {hyp.bug_class.value} {hyp.file}:{hyp.line}\n"
                    f"sink: {hyp.sink}\n\n"
                    f"{tb}"
                )
                continue
            # Detect silent failures — completed normally but no iter files were written.
            iter_files = sorted(hyp_dir.glob("iter_*.py"))
            if not iter_files and not (hyp_dir / "error.log").exists():
                (hyp_dir / "error.log").write_text(
                    f"=== Silent failure for {hyp.id} ===\n"
                    f"_verify_one returned without raising an exception, but no iter files\n"
                    f"were written. This usually means SandboxManager.__aenter__() raised an\n"
                    f"exception that was caught silently OR propose_setup hung without raising,\n"
                    f"OR docker compose timed out internally.\n\n"
                    f"Inspect runs/{run_id}/trace.jsonl for poc_author entries (or absence) to\n"
                    f"diagnose. If `propose_setup for {hyp.id} failed` appears in the run logs\n"
                    f"that's the smoking gun.\n"
                )
                logger.warning("verify: hypothesis %s — no iter files written and no exception raised", hyp.id)
            if finding is None:
                continue
            findings.append(finding)
            with findings_path.open("a") as f:
                f.write(finding.model_dump_json() + "\n")
    finally:
        # W3: tear down persistent sandbox at end of scan
        if persistent_sb is not None:
            try:
                await persistent_sb.teardown()
                logger.info("verify: W3 persistent-sandbox torn down")
            except Exception as e:
                logger.warning("verify: W3 persistent-sandbox teardown failed: %s", e)
        if persistent_snapshot is not None and persistent_snapshot.exists():
            try:
                shutil.rmtree(persistent_snapshot)
            except Exception:
                pass

    logger.info("verify: %d findings confirmed -> %s", len(findings), findings_path)
    return findings
