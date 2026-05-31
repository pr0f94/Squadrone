"""Stage-5 verify helpers: headless browser check (W2), state introspection (W5),
manual-review handoff (W6), verify caching (W10).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from ..schemas.finding import Finding
from ..schemas.hypothesis import Hypothesis

logger = logging.getLogger(__name__)

VERIFY_CACHE_DIR = Path("cache/verify")
MANUAL_REVIEW_QUEUE = Path("cache/findings_for_manual_review.jsonl")


# ---------- W2: Headless browser execution check (Playwright, optional dep) ---------

# Sentinel injected into payloads — if it gets set on `window`, the script ran.
BROWSER_SENTINEL_GLOBAL = "__squadrone_xss_fired"


def make_browser_payload_marker() -> str:
    """Return a unique payload that, if executed, sets window.__squadrone_xss_fired."""
    nonce = hashlib.sha256(datetime.now(timezone.utc).isoformat().encode()).hexdigest()[:8]
    return f"<script>window.{BROWSER_SENTINEL_GLOBAL}_{nonce}=true;</script>"


async def screenshot_url(url: str, output_path: Path, timeout_s: int = 15,
                          full_page: bool = True) -> bool:
    """R5: Take a screenshot of the rendered page. Returns True on success.
    Same Playwright dependency as W2; gracefully no-ops if Playwright not installed.
    """
    try:
        from playwright.async_api import async_playwright  # type: ignore
    except ImportError:
        logger.warning("R5: playwright not installed — skipping screenshot")
        return False
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()
            try:
                await page.goto(url, timeout=timeout_s * 1000)
                await asyncio.sleep(0.5)
                await page.screenshot(path=str(output_path), full_page=full_page)
                logger.info("R5: screenshot → %s", output_path)
            finally:
                await browser.close()
        return True
    except Exception as e:
        logger.warning("R5: screenshot failed for %s: %s", url, e)
        return False


async def check_xss_executes(url: str, sentinel_var: str, timeout_s: int = 15) -> bool | None:
    """Use Playwright to fetch `url` and check whether `sentinel_var` got set on window.

    Returns:
    - True   = sentinel set, script executed
    - False  = page rendered but sentinel not set
    - None   = Playwright unavailable / fetch failed (graceful degradation)

    Playwright is a heavy optional dep. Install with:
        pip install playwright && playwright install chromium
    """
    try:
        from playwright.async_api import async_playwright  # type: ignore
    except ImportError:
        logger.warning("W2: playwright not installed — skipping headless check (pip install playwright)")
        return None

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context()
            page = await context.new_page()
            try:
                await page.goto(url, timeout=timeout_s * 1000)
            except Exception as e:
                logger.warning("W2: page.goto(%s) failed: %s", url, e)
                await browser.close()
                return None
            # Allow inline + stored scripts a moment to run
            await asyncio.sleep(0.5)
            try:
                value = await page.evaluate(f"() => window.{sentinel_var} === true")
            except Exception:
                value = False
            await browser.close()
            return bool(value)
    except Exception as e:
        logger.warning("W2: headless check failed: %s", e)
        return None


# ---------- W5: state introspection on failure --------------------------------------

async def dump_sandbox_state(sb, dump_dir: Path) -> None:
    """Dump DB tables of interest, apache log, uploads listing into dump_dir.
    Best-effort: each piece is wrapped so a failure on one doesn't skip the others.
    """
    dump_dir.mkdir(parents=True, exist_ok=True)
    try:
        # WP options + posts (recent rows)
        if sb.wp_cli is not None:
            options = await sb.wp_cli._exec("option", "list", "--format=json", "--allow-root", check=False)
            (dump_dir / "wp_options.json").write_text(options or "")
            posts = await sb.wp_cli._exec("post", "list", "--format=json", "--posts_per_page=20", check=False)
            (dump_dir / "wp_posts_recent.json").write_text(posts or "")
            users = await sb.wp_cli._exec("user", "list", "--format=json", check=False)
            (dump_dir / "wp_users.json").write_text(users or "")
    except Exception as e:
        (dump_dir / "wp_cli_dump_error.log").write_text(f"{e}")
    try:
        # Apache error log (best-effort — paths vary by image)
        log_paths = ["/var/log/apache2/error.log", "/var/log/httpd/error_log"]
        for lp in log_paths:
            try:
                tail = await sb.wp_cli._docker_exec(["tail", "-n", "200", lp])
                if tail:
                    (dump_dir / "apache_error.log").write_text(tail)
                    break
            except Exception:
                continue
    except Exception:
        pass
    try:
        # uploads dir listing
        ls = await sb.wp_cli._docker_exec(["find", "/var/www/html/wp-content/uploads", "-type", "f", "-printf", "%T@ %s %p\\n"])
        if ls:
            (dump_dir / "uploads_listing.txt").write_text(ls)
    except Exception:
        pass
    logger.info("verify: state dump → %s", dump_dir)


# ---------- W6: manual-review queue handoff -----------------------------------------

def emit_to_manual_review_queue(
    hyp: Hypothesis,
    run_dir: Path,
    reason: str,
    *,
    attempts: list | None = None,
    setup_results: list[dict] | None = None,
    verifier_notes: dict | None = None,
) -> None:
    """Append a structured entry to the global manual-review queue.

    Generates a sandbox scaffold under run_dir/verifications/<hyp_id>/manual_scaffold/
    that the user can `cd` into and iterate by hand.
    """
    MANUAL_REVIEW_QUEUE.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "queued_at": datetime.now(timezone.utc).isoformat(),
        "hypothesis_id": hyp.id,
        "bug_class": hyp.bug_class.value,
        "file": hyp.file,
        "line": hyp.line,
        "sink": hyp.sink,
        "reason": reason,
        "run_dir": str(run_dir),
        "scaffold_path": str(run_dir / "verifications" / hyp.id / "manual_scaffold"),
        "attempts": attempts or [],
        "setup_results": setup_results or [],
        "verifier_notes": verifier_notes or {},
    }
    with MANUAL_REVIEW_QUEUE.open("a") as f:
        f.write(json.dumps(entry) + "\n")
    logger.info("verify: hypothesis %s emitted to manual review queue", hyp.id)


def write_manual_scaffold(
    hyp: Hypothesis,
    hyp_dir: Path,
    plugin_slug: str,
    target_url: str,
    *,
    attempts: list | None = None,
    setup_results: list[dict] | None = None,
    handoff_reason: str | None = None,
) -> None:
    """Write a minimal docker-compose + README scaffold the user can take over."""
    scaffold = hyp_dir / "manual_scaffold"
    scaffold.mkdir(parents=True, exist_ok=True)
    attempt_lines = []
    for attempt in attempts or []:
        attempt_lines.append(
            f"- iter {getattr(attempt, 'iteration', '?')}: "
            f"{getattr(getattr(attempt, 'result', ''), 'value', getattr(attempt, 'result', ''))} "
            f"http={getattr(attempt, 'http_status', None)} "
            f"script={getattr(attempt, 'script_path', '')}"
        )
    setup_lines = []
    for item in setup_results or []:
        status = "FAILED" if item.get("failed") else "OK"
        blocked = " REJECTED" if item.get("forbidden_payload_seed") else ""
        setup_lines.append(f"- {status}{blocked}: wp {' '.join(item.get('args', []))}")
    if attempts:
        pickup_note = (
            f"See `iter_*.py` files alongside this scaffold. Each failed in some way; "
            f"check stdout in trace.jsonl.\n\n"
        )
    else:
        pickup_note = (
            "No automated PoC iterations were recorded for this handoff.\n\n"
        )

    (scaffold / "README.md").write_text(
        f"# Manual review handoff: {hyp.id}\n\n"
        f"{handoff_reason or 'Auto-pipeline failed to confirm this hypothesis after the configured iteration cap.'}\n\n"
        f"- **Bug class:** {hyp.bug_class.value}\n"
        f"- **File:** {hyp.file}:{hyp.line}\n"
        f"- **Sink:** `{hyp.sink}`\n"
        f"- **Reasoning:** {hyp.reasoning}\n"
        f"- **Preconditions:** {hyp.preconditions}\n\n"
        f"## Setup commands\n"
        f"{chr(10).join(setup_lines) if setup_lines else '- none recorded'}\n\n"
        f"## Failed PoC iterations\n"
        f"{chr(10).join(attempt_lines) if attempt_lines else '- none recorded'}\n\n"
        f"{pickup_note}"
        f"## To pick up manually\n"
        f"1. Look at the standing `manual_reviews/<plugin>/sandbox/` if it exists, or follow that pattern\n"
        f"2. The auto-pipeline left findings under `runs/<id>/verifications/{hyp.id}/`\n"
        f"3. If `state_dump/` exists (W5), inspect it for clues about why the PoC didn't fire\n"
    )
    (scaffold / "context.json").write_text(json.dumps({
        "plugin_slug": plugin_slug,
        "target_url": target_url,
        "hypothesis": hyp.model_dump(mode="json"),
        "attempts": [
            a.model_dump(mode="json") if hasattr(a, "model_dump") else a
            for a in (attempts or [])
        ],
        "setup_results": setup_results or [],
    }, indent=2))


# ---------- W10: verify caching ------------------------------------------------------

def verify_cache_key(hyp: Hypothesis, plugin_version: str, sandbox_image: str,
                     verify_config: dict) -> str:
    payload = json.dumps({
        "hyp": hyp.model_dump(mode="json"),
        "version": plugin_version,
        "sandbox_image": sandbox_image,
        "cfg": verify_config,
    }, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def verify_cache_load(key: str) -> Finding | None:
    p = VERIFY_CACHE_DIR / f"{key}.json"
    if not p.exists():
        return None
    try:
        return Finding.model_validate_json(p.read_text())
    except (OSError, ValueError):
        return None


def verify_cache_save(key: str, finding: Finding) -> None:
    VERIFY_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    (VERIFY_CACHE_DIR / f"{key}.json").write_text(finding.model_dump_json(indent=2))


# ---------- W4: payload variants -----------------------------------------------------

# A short pre-curated list of XSS payload variants for W4. The PoC author is given these
# as additional options to try when its primary payload fails.
XSS_PAYLOAD_VARIANTS = [
    # Single-quote breakout
    "evil'><svg onload=alert(1)>",
    # Double-quote breakout
    'evil"><svg onload=alert(1)>',
    # Tag breakout in HTML text
    "<script>alert(1)</script>",
    # Event handler in attribute (works on unquoted attrs)
    " onfocus=alert(1) autofocus ",
    # JS context: close string + statement
    "';alert(1);//",
    # SVG-onload polyglot
    '"><svg/onload=alert(1)>',
]


def get_payload_variants(cap: int = 6) -> list[str]:
    """Return up to `cap` XSS payload variants for W4."""
    return XSS_PAYLOAD_VARIANTS[:cap]
