"""SandboxManager — async context manager that boots an isolated WP+DB sandbox."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
import socket
import statistics
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import httpx
from jinja2 import Template
from pydantic import BaseModel, Field, ValidationError

from ..schemas.config import SandboxConfig
from ..schemas.observation import PoCObservation
from ..schemas.taxonomy import KNOWN_CWE_REGISTRY
from .roles import UNKNOWN_ATTACKER_ROLE, normalize_attacker_role
from .wp_cli import WPCli

logger = logging.getLogger(__name__)

_PORT_MIN = 8100
_PORT_MAX = 8200
_PROJECT_PREFIX = "squadrone"
_DOCKER_DIR = Path(__file__).resolve().parents[3] / "docker"
_PORT_ALLOC_LOCK = asyncio.Lock()
_PLUGIN_SLUG_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,199}\Z")
WORDPRESS_WEB_USER = "www-data"


def validate_plugin_slug(plugin_slug: str) -> str:
    """Return a slug that is safe to use as one plugin-directory component."""
    if not isinstance(plugin_slug, str) or not _PLUGIN_SLUG_RE.fullmatch(plugin_slug):
        raise ValueError(
            "plugin slug must contain only lowercase ASCII letters, digits, "
            "hyphens, and underscores, and must start with a letter or digit"
        )
    return plugin_slug


class SandboxRunResult(BaseModel):
    success: bool
    output: str
    elapsed: float
    http_status: Optional[int] = None
    response: Optional[str] = None
    error_log: Optional[str] = None
    evidence: dict = Field(default_factory=dict)
    observation: Optional[PoCObservation] = None
    validation_reason: str = ""


POC_RESULT_PREFIX = "SQUADRONE_RESULT="

_ALLOWED_ORACLES: dict[str, set[str]] = {
    bug_class.name: set(profile.allowed_oracles)
    for bug_class, profile in KNOWN_CWE_REGISTRY.items()
    if profile.allowed_oracles
}


def _parse_poc_observation(stdout: str) -> tuple[PoCObservation | None, str]:
    nonempty_lines = [line for line in stdout.splitlines() if line.strip()]
    payload_lines = [
        line for line in nonempty_lines if line.startswith(POC_RESULT_PREFIX)
    ]
    if not payload_lines:
        return None, f"missing final {POC_RESULT_PREFIX}<json> observation"
    if len(payload_lines) != 1:
        return None, "PoC emitted more than one structured result observation"
    payload_line = payload_lines[0]
    if nonempty_lines[-1] != payload_line:
        return None, "structured result observation is not the final output line"
    raw = payload_line[len(POC_RESULT_PREFIX) :].strip()
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, f"invalid observation JSON: {exc}"
    try:
        return PoCObservation.model_validate(payload), ""
    except ValidationError as exc:
        return None, f"observation schema validation failed: {exc}"


def validate_confirmation_observations(
    first: PoCObservation,
    confirmation: PoCObservation,
) -> tuple[bool, str]:
    """Require the clean rerun to prove the same security claim."""
    if first.oracle != confirmation.oracle:
        return False, "confirmation used a different oracle"
    first_role = normalize_attacker_role(first.attacker_role)
    confirmation_role = normalize_attacker_role(confirmation.attacker_role)
    if UNKNOWN_ATTACKER_ROLE in {first_role, confirmation_role}:
        return False, "confirmation used an unrecognized attacker role"
    if first_role != confirmation_role:
        return False, "confirmation used a different attacker role"
    first_method = str(first.request.get("method") or "").strip().upper()
    confirmation_method = str(confirmation.request.get("method") or "").strip().upper()
    if first_method != confirmation_method:
        return False, "confirmation used a different request method"
    first_url = str(first.request.get("url") or "").strip()
    confirmation_url = str(confirmation.request.get("url") or "").strip()
    if first_url != confirmation_url:
        return False, "confirmation targeted a different request URL"
    first_impact = first.impact.model_dump(exclude={"description"})
    confirmation_impact = confirmation.impact.model_dump(exclude={"description"})
    if first_impact != confirmation_impact:
        return False, "confirmation reported different CIA impact dimensions"
    return True, "clean rerun reproduced the same oracle, role, request, and CIA impact"


def _number_list(value: object) -> list[float]:
    if not isinstance(value, list):
        return []
    out: list[float] = []
    for item in value:
        if isinstance(item, int | float) and not isinstance(item, bool):
            out.append(float(item))
    return out


def validate_poc_observation(
    observation: PoCObservation,
    expected_bug_class: str | None = None,
    expected_attacker_role: str | None = None,
) -> tuple[bool, str]:
    """Validate measurements without trusting a model-authored success string."""
    if observation.verdict != "vulnerable":
        return False, "PoC reported not_vulnerable"
    if not observation.attacker_role.strip():
        return False, "attacker_role is empty"
    if not str(observation.request.get("method") or "").strip():
        return False, "request.method is missing"
    request_url = str(observation.request.get("url") or "").strip()
    if not request_url:
        return False, "request.url is missing"
    if urlparse(request_url).hostname not in {"localhost", "127.0.0.1", "::1"}:
        return False, "request.url is not a local sandbox target"
    if expected_attacker_role:
        observed_role = normalize_attacker_role(observation.attacker_role)
        required_role = normalize_attacker_role(expected_attacker_role)
        if required_role == UNKNOWN_ATTACKER_ROLE:
            return False, "source review has an unrecognized attacker role"
        if observed_role == UNKNOWN_ATTACKER_ROLE:
            return False, "PoC reported an unrecognized attacker role"
        if observed_role != required_role:
            return False, (
                f"PoC used attacker role {observation.attacker_role!r}; "
                f"source review requires {expected_attacker_role!r}"
            )
    if not observation.impact.description.strip():
        return False, "impact.description is empty"
    if {
        observation.impact.confidentiality,
        observation.impact.integrity,
        observation.impact.availability,
    } == {"none"}:
        return (
            False,
            "no confidentiality, integrity, or availability impact was observed",
        )

    if expected_bug_class:
        allowed = _ALLOWED_ORACLES.get(expected_bug_class)
        if not allowed:
            return False, f"no automatic oracle is defined for {expected_bug_class}"
        if observation.oracle not in allowed:
            return False, (
                f"oracle {observation.oracle!r} cannot prove {expected_bug_class}; "
                f"expected one of {sorted(allowed)}"
            )

    attack = observation.attack
    control = observation.control
    if attack.get("observed") is not True:
        return False, "attack observation did not record observed=true"
    if control.get("observed") is not False:
        return False, "negative control did not record observed=false"

    oracle = observation.oracle
    if oracle == "timing":
        attack_samples = _number_list(attack.get("samples_seconds"))
        control_samples = _number_list(control.get("samples_seconds"))
        if len(attack_samples) < 3 or len(control_samples) < 3:
            return (
                False,
                "timing oracle requires at least three attack and three control samples",
            )
        attack_median = statistics.median(attack_samples)
        control_median = statistics.median(control_samples)
        if attack_median - control_median < 3.0 or attack_median < max(
            2.0, control_median * 2.0
        ):
            return False, (
                "timing differential is too small "
                f"(attack median={attack_median:.2f}s, control median={control_median:.2f}s)"
            )
    elif oracle == "response_marker":
        marker = str(attack.get("marker") or "")
        if len(marker) < 8 or attack.get("marker_present") is not True:
            return (
                False,
                "response-marker oracle lacks a unique marker observed in the attack response",
            )
        if control.get("marker_present") is not False:
            return False, "negative-control response also contains the marker"
    elif oracle == "state_change":
        if (
            "before" not in attack
            or "after" not in attack
            or attack.get("before") == attack.get("after")
        ):
            return False, "state-change oracle does not show a before/after difference"
        if control.get("before") != control.get("after"):
            return False, "negative control also changed state"
    elif oracle == "authorization":
        if attack.get("allowed") is not True or control.get("allowed") is not False:
            return (
                False,
                "authorization oracle does not show attack allowed and control denied",
            )
        if not str(attack.get("privileged_effect") or "").strip():
            return False, "authorization oracle lacks the privileged effect"
    elif oracle == "cross_object_access":
        attacker_user_id = str(attack.get("attacker_user_id") or "").strip()
        owner_user_id = str(attack.get("owner_user_id") or "").strip()
        if not attacker_user_id or not owner_user_id:
            return False, "cross-object oracle lacks attacker and owner identifiers"
        if attacker_user_id == owner_user_id:
            return False, "cross-object oracle used the object's owner as attacker"
        if (
            attack.get("secret_present") is not True
            or control.get("secret_present") is not False
        ):
            return (
                False,
                "cross-object oracle lacks a private marker absent from the control",
            )
    elif oracle == "callback":
        if (
            int(attack.get("hit_count") or 0) < 1
            or int(control.get("hit_count") or 0) != 0
        ):
            return (
                False,
                "callback oracle did not observe attack-only server-side callbacks",
            )
        marker = str(attack.get("marker") or "")
        if len(marker) < 8 or attack.get("marker_present") is not True:
            return False, "callback oracle did not capture a unique sensitive marker"
        if control.get("marker_present") is not False:
            return False, "negative-control callback also captured the sensitive marker"
    elif oracle == "browser_execution":
        if attack.get("executed") is not True or control.get("executed") is not False:
            return (
                False,
                "browser oracle did not observe attack-only JavaScript execution",
            )
    elif oracle == "file_effect":
        path = str(attack.get("path") or "")
        marker_hash = str(
            attack.get("marker_sha256") or attack.get("file_sha256") or ""
        )
        if (
            not path
            or attack.get("exists") is not True
            or re.fullmatch(r"[0-9a-fA-F]{64}", marker_hash) is None
        ):
            return False, "file oracle lacks an observed path and SHA-256 marker"
        if control.get("exists") is not False:
            return False, "negative control produced the same file effect"

    return True, "structured attack observation passed its independent oracle"


def _alloc_port() -> int:
    for port in range(_PORT_MIN, _PORT_MAX + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError(f"no free port in {_PORT_MIN}-{_PORT_MAX}")


async def _run(
    *cmd: str, cwd: Optional[str] = None, check: bool = True
) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        cwd=cwd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    out = stdout.decode("utf-8", errors="replace")
    err = stderr.decode("utf-8", errors="replace")
    if check and proc.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} exited {proc.returncode}: {err.strip()}")
    return proc.returncode or 0, out, err


class SandboxManager:
    """Boots a fresh WordPress + MariaDB stack and tears it down on exit."""

    def __init__(
        self, config: SandboxConfig, boot_timeout_s: int = 60, poc_timeout_s: int = 120
    ):
        self.config = config
        self.boot_timeout_s = boot_timeout_s
        self.poc_timeout_s = poc_timeout_s
        self.port: int = 0
        self.project: str = ""
        self.workdir: Optional[Path] = None
        self.container_name: str = ""
        self.target_url: str = ""
        self.wp_cli: Optional[WPCli] = None
        self._booted = False

    # ── lifecycle ────────────────────────────────────────────────

    async def __aenter__(self) -> "SandboxManager":
        try:
            await self.boot()
        except BaseException:
            await self.teardown()
            raise
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.teardown()

    async def boot(self) -> None:
        if self._booted:
            return
        async with _PORT_ALLOC_LOCK:
            self.port = _alloc_port()
            self.project = f"{_PROJECT_PREFIX}-{uuid.uuid4().hex[:8]}"
            self.container_name = f"{self.project}-wordpress-1"
            self.target_url = f"http://localhost:{self.port}"
            self.workdir = Path(tempfile.mkdtemp(prefix=f"{self.project}-"))

            template = Template((_DOCKER_DIR / "docker-compose.yml.j2").read_text())
            rendered = template.render(
                port=self.port,
                wp_url=self.target_url,
                wp_title="Squadrone Sandbox",
                wp_admin_user=self.config.wp_admin_user,
                wp_admin_pass=self.config.wp_admin_pass,
                wp_admin_email=self.config.wp_admin_email,
            )
            (self.workdir / "docker-compose.yml").write_text(rendered)
            shutil.copy(_DOCKER_DIR / "wp-init.sh", self.workdir / "wp-init.sh")
            (self.workdir / "wp-init.sh").chmod(0o755)

            logger.info("sandbox boot project=%s port=%d", self.project, self.port)
            await _run(
                "docker",
                "compose",
                "-p",
                self.project,
                "up",
                "-d",
                cwd=str(self.workdir),
            )

        await self._wait_for_wordpress()
        self.wp_cli = WPCli(self.container_name)
        # wp-init.sh may not have completed `wp core install` by the time the port answers;
        # ensure it has, then we are ready.
        await self._ensure_wp_installed()
        self._booted = True

    async def teardown(self) -> None:
        if not self.project:
            return
        try:
            logger.info("sandbox teardown project=%s", self.project)
            await _run(
                "docker",
                "compose",
                "-p",
                self.project,
                "down",
                "-v",
                cwd=str(self.workdir) if self.workdir else None,
                check=False,
            )
        finally:
            if self.workdir and self.workdir.exists():
                shutil.rmtree(self.workdir, ignore_errors=True)
            self._booted = False

    # ── snapshot + restore ──────────────────────────────────────────────────

    @property
    def db_container_name(self) -> str:
        return f"{self.project}-db-1"

    async def snapshot(self) -> Path:
        """Capture DB + wp-content to a temp directory. Returns the snapshot path.

        Capturing all of wp-content prevents a failed or successful PoC from
        contaminating a later attempt through files outside uploads.
        """
        if not self._booted:
            raise RuntimeError("snapshot called before sandbox booted")
        snap_dir = Path(tempfile.mkdtemp(prefix=f"{self.project}-snap-"))
        # DB dump
        rc, dump, err = await _run(
            "docker",
            "exec",
            self.db_container_name,
            "mariadb-dump",
            "-uwpuser",
            "-pwppass",
            "--add-drop-database",
            "--databases",
            "wordpress",
            check=False,
        )
        if rc != 0 or not dump.strip():
            shutil.rmtree(snap_dir, ignore_errors=True)
            raise RuntimeError(
                f"snapshot database dump failed (rc={rc}): {err.strip()[:200]}"
            )
        (snap_dir / "db.sql").write_text(dump)
        # Full wp-content archive, including the installed plugin and uploads.
        await _run(
            "docker",
            "exec",
            self.container_name,
            "sh",
            "-c",
            "mkdir -p /var/www/html/wp-content && "
            "tar czf /tmp/squadrone_wp_content.tar.gz -C /var/www/html wp-content",
        )
        await _run(
            "docker",
            "cp",
            f"{self.container_name}:/tmp/squadrone_wp_content.tar.gz",
            str(snap_dir / "wp-content.tar.gz"),
        )
        content_tar = snap_dir / "wp-content.tar.gz"
        if not content_tar.exists() or content_tar.stat().st_size == 0:
            shutil.rmtree(snap_dir, ignore_errors=True)
            raise RuntimeError("snapshot wp-content archive is missing or empty")
        logger.info("sandbox snapshot → %s (db=%d bytes)", snap_dir, len(dump))
        return snap_dir

    async def restore(self, snap_dir: Path) -> None:
        """Restore DB and all of wp-content from a previous snapshot."""
        if not self._booted:
            raise RuntimeError("restore called before sandbox booted")
        db_sql_path = snap_dir / "db.sql"
        if not db_sql_path.exists() or db_sql_path.stat().st_size == 0:
            raise RuntimeError(f"restore snapshot has no database dump: {snap_dir}")
        sql_bytes = db_sql_path.read_bytes()
        proc = await asyncio.create_subprocess_exec(
            "docker",
            "exec",
            "-i",
            self.db_container_name,
            "mariadb",
            "-uwpuser",
            "-pwppass",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _stdout, _stderr = await proc.communicate(sql_bytes)
        if proc.returncode != 0:
            raise RuntimeError(
                "restore database import failed: "
                + (_stderr.decode(errors="replace") or "")[:200]
            )

        content_tar = snap_dir / "wp-content.tar.gz"
        if not content_tar.exists() or content_tar.stat().st_size == 0:
            raise RuntimeError(
                f"restore snapshot has no wp-content archive: {snap_dir}"
            )
        await _run(
            "docker",
            "cp",
            str(content_tar),
            f"{self.container_name}:/tmp/squadrone_wp_content.tar.gz",
        )
        await _run(
            "docker",
            "exec",
            self.container_name,
            "sh",
            "-c",
            "rm -rf /var/www/html/wp-content && "
            "tar xzf /tmp/squadrone_wp_content.tar.gz -C /var/www/html",
        )
        logger.info("sandbox restore from %s — done", snap_dir)

    # ── helpers ─────────────────────────────────────────────────

    async def _wait_for_wordpress(self) -> None:
        """Wait for Apache to answer (any HTTP status) — pre-install it returns 302."""
        deadline = time.time() + self.boot_timeout_s
        url = f"{self.target_url}/wp-login.php"
        async with httpx.AsyncClient(timeout=5.0) as client:
            while time.time() < deadline:
                try:
                    r = await client.get(url)
                    if r.status_code in (200, 302):
                        return
                except (httpx.HTTPError, OSError):
                    pass
                await asyncio.sleep(2)
        raise RuntimeError(
            f"WordPress not reachable at {url} within {self.boot_timeout_s}s"
        )

    async def _ensure_wp_installed(self) -> None:
        """Make sure wp-cli is installed and `wp core install` has been run."""
        # 1. Install wp-cli inside container if missing.
        rc, _, _ = await _run(
            "docker",
            "exec",
            self.container_name,
            "sh",
            "-c",
            "command -v wp >/dev/null 2>&1",
            check=False,
        )
        if rc != 0:
            await _run(
                "docker",
                "exec",
                self.container_name,
                "sh",
                "-c",
                "curl -sSLo /usr/local/bin/wp "
                "https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar "
                "&& chmod +x /usr/local/bin/wp",
            )

        # 2. Wait for db to be reachable from wp-cli's perspective.
        deadline = time.time() + self.boot_timeout_s
        while time.time() < deadline:
            rc, _, _ = await _run(
                "docker",
                "exec",
                self.container_name,
                "wp",
                "--allow-root",
                "db",
                "check",
                check=False,
            )
            if rc == 0:
                break
            await asyncio.sleep(2)

        # 3. Run wp core install if not already installed.
        rc, _, _ = await _run(
            "docker",
            "exec",
            self.container_name,
            "wp",
            "--allow-root",
            "core",
            "is-installed",
            check=False,
        )
        if rc != 0:
            await _run(
                "docker",
                "exec",
                self.container_name,
                "wp",
                "--allow-root",
                "core",
                "install",
                f"--url={self.target_url}",
                "--title=Squadrone Sandbox",
                f"--admin_user={self.config.wp_admin_user}",
                f"--admin_password={self.config.wp_admin_pass}",
                f"--admin_email={self.config.wp_admin_email}",
                "--skip-email",
            )

    # ── operations ──────────────────────────────────────────────

    async def install_plugin(self, zip_path: str, plugin_slug: str) -> None:
        """Install one scanned plugin with production-like filesystem ownership.

        Run both extraction and activation as the WordPress web-service identity.
        This matches a web-admin install without broadening package modes, and it
        also gives activation-created runtime state the identity that later HTTP
        requests use.
        """
        assert self.wp_cli is not None
        slug = validate_plugin_slug(plugin_slug)
        dest = f"/tmp/squadrone-{slug}.zip"
        await _run("docker", "cp", zip_path, f"{self.container_name}:{dest}")
        await self.wp_cli.install_plugin(dest, user=WORDPRESS_WEB_USER)
        await self._fire_admin_init()

    async def _fire_admin_init(self) -> None:
        """Trigger admin_init in a real admin context after plugin activation.

        Many plugins (events-manager, woocommerce, et al.) defer their dbDelta()
        table creation to admin_init rather than the activation hook itself —
        because WP_ADMIN must be defined during WP bootstrap (not after), this
        cannot be faked via `wp eval do_action('admin_init')`. The reliable
        workaround is to actually log in as admin and visit /wp-admin/ once via
        curl from inside the container, which gives a real admin request lifecycle.
        """
        try:
            login_cmd = (
                "curl -s -c /tmp/squadrone_cookies.txt "
                "-d 'log=admin&pwd=password&wp-submit=Log+In&testcookie=1' "
                "-b 'wordpress_test_cookie=WP+Cookie+check' "
                "http://localhost/wp-login.php -o /dev/null"
            )
            await _run(
                "docker",
                "exec",
                self.container_name,
                "sh",
                "-c",
                login_cmd,
                check=False,
            )
            visit_cmd = (
                "curl -s -b /tmp/squadrone_cookies.txt "
                "http://localhost/wp-admin/ -o /dev/null -w '%{http_code}'"
            )
            _, status, _ = await _run(
                "docker",
                "exec",
                self.container_name,
                "sh",
                "-c",
                visit_cmd,
                check=False,
            )
            logger.info("post-install admin_init: GET /wp-admin/ -> %s", status.strip())
        except Exception as e:
            logger.warning("post-install admin_init dispatch failed: %s", e)

    # Baseline (non-admin) user accounts always created at sandbox boot. All five
    # default WordPress roles are covered so PoCs can pick the lowest-privilege
    # account that satisfies their hypothesis preconditions. Passwords are
    # uniform "password" for ease; the admin password comes from sandbox config.
    BASELINE_USERS: list[tuple[str, str]] = [
        ("subscriber_user", "subscriber"),
        ("customer_user", "customer"),
        ("contributor_user", "contributor"),
        ("author_user", "author"),
        ("editor_user", "editor"),
    ]

    async def setup_test_users(self) -> None:
        assert self.wp_cli is not None
        for login, role in self.BASELINE_USERS:
            try:
                await self.wp_cli.create_user(login, role, password="password")
            except Exception as e:
                logger.warning(
                    "create_user %s/%s failed (may already exist): %s", login, role, e
                )

    def baseline_user_accounts(self) -> list[dict]:
        """Return the credential table for users provisioned at sandbox boot.

        Used by verify.py to surface a structured `user_accounts` block to the
        PoC author so it picks credentials from a known table instead of
        recalling them from the system prompt (which can drift).
        """
        accounts = [
            {
                "login": self.config.wp_admin_user,
                "password": self.config.wp_admin_pass,
                "role": "administrator",
            }
        ]
        for login, role in self.BASELINE_USERS:
            accounts.append({"login": login, "password": "password", "role": role})
        return accounts

    async def run_poc(
        self,
        script_path: str,
        *,
        expected_bug_class: str | None = None,
        expected_attacker_role: str | None = None,
    ) -> SandboxRunResult:
        start = time.time()
        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable,
                script_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self.poc_timeout_s,
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                elapsed = time.time() - start
                return SandboxRunResult(
                    success=False,
                    output="",
                    elapsed=elapsed,
                    error_log=f"PoC timed out after {self.poc_timeout_s}s",
                )
        except Exception as e:
            return SandboxRunResult(
                success=False,
                output="",
                elapsed=time.time() - start,
                error_log=f"PoC exec failed: {e}",
            )

        elapsed = time.time() - start
        out = stdout.decode("utf-8", errors="replace")
        err = stderr.decode("utf-8", errors="replace")
        observation, parse_reason = _parse_poc_observation(out)
        if proc.returncode != 0:
            success = False
            validation_reason = f"PoC process exited {proc.returncode}"
        elif observation is None:
            success = False
            validation_reason = parse_reason
        else:
            success, validation_reason = validate_poc_observation(
                observation,
                expected_bug_class=expected_bug_class,
                expected_attacker_role=expected_attacker_role,
            )

        http_status = None
        m = re.search(r"\bstatus[=:]\s*(\d{3})\b", out, re.IGNORECASE)
        if m:
            http_status = int(m.group(1))

        wp_error_log = ""
        if self.wp_cli is not None:
            try:
                wp_error_log = await self.wp_cli.get_error_log()
            except Exception:
                pass

        error_log = err
        if wp_error_log:
            error_log = (error_log + "\n--- wp debug.log ---\n" + wp_error_log).strip()

        return SandboxRunResult(
            success=success,
            output=out,
            elapsed=elapsed,
            http_status=http_status,
            response=out[-2000:] if out else None,
            error_log=error_log or None,
            observation=observation,
            validation_reason=validation_reason,
            evidence={
                "observation": observation.model_dump(mode="json")
                if observation
                else None,
                "validation_reason": validation_reason,
                "stdout_tail": out[-500:],
                "returncode": proc.returncode,
            },
        )
