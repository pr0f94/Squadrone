"""SandboxManager — async context manager that boots an isolated WP+DB sandbox."""

from __future__ import annotations

import asyncio
import logging
import re
import shutil
import socket
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Optional

import httpx
from jinja2 import Template
from pydantic import BaseModel

from ..schemas.config import SandboxConfig
from .wp_cli import WPCli

logger = logging.getLogger(__name__)

_PORT_MIN = 8100
_PORT_MAX = 8200
_PROJECT_PREFIX = "squadrone"
_DOCKER_DIR = Path(__file__).resolve().parents[3] / "docker"
_PORT_ALLOC_LOCK = asyncio.Lock()


class SandboxRunResult(BaseModel):
    success: bool
    output: str
    elapsed: float
    http_status: Optional[int] = None
    response: Optional[str] = None
    error_log: Optional[str] = None
    evidence: dict = {}


def _alloc_port() -> int:
    for port in range(_PORT_MIN, _PORT_MAX + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError(f"no free port in {_PORT_MIN}-{_PORT_MAX}")


async def _run(*cmd: str, cwd: Optional[str] = None, check: bool = True) -> tuple[int, str, str]:
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

    def __init__(self, config: SandboxConfig, boot_timeout_s: int = 60, poc_timeout_s: int = 120):
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
                "docker", "compose", "-p", self.project, "up", "-d",
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
                "docker", "compose", "-p", self.project, "down", "-v",
                cwd=str(self.workdir) if self.workdir else None,
                check=False,
            )
        finally:
            if self.workdir and self.workdir.exists():
                shutil.rmtree(self.workdir, ignore_errors=True)
            self._booted = False

    # ── W3: snapshot + restore for persistent-sandbox mode ──────────────────

    @property
    def db_container_name(self) -> str:
        return f"{self.project}-db-1"

    async def snapshot(self) -> Path:
        """Capture DB + uploads dir to a temp directory. Returns the snapshot path.

        DB is dumped via mariadb-dump in the db container; uploads are tarred from
        the wordpress container. Both are restorable via restore().
        """
        if not self._booted:
            raise RuntimeError("snapshot called before sandbox booted")
        snap_dir = Path(tempfile.mkdtemp(prefix=f"{self.project}-snap-"))
        # DB dump
        rc, dump, err = await _run(
            "docker", "exec", self.db_container_name,
            "mariadb-dump", "-uwpuser", "-pwppass",
            "--add-drop-database", "--databases", "wordpress",
            check=False,
        )
        if rc != 0:
            logger.warning("snapshot: mariadb-dump rc=%d err=%s", rc, err.strip()[:200])
        (snap_dir / "db.sql").write_text(dump)
        # Uploads tar (best-effort — may not exist on a freshly-installed WP)
        await _run(
            "docker", "exec", self.container_name,
            "sh", "-c",
            "mkdir -p /var/www/html/wp-content/uploads && "
            "tar czf /tmp/squadrone_uploads.tar.gz -C /var/www/html/wp-content uploads || true",
            check=False,
        )
        await _run(
            "docker", "cp",
            f"{self.container_name}:/tmp/squadrone_uploads.tar.gz",
            str(snap_dir / "uploads.tar.gz"),
            check=False,
        )
        logger.info("sandbox snapshot → %s (db=%d bytes)", snap_dir, len(dump))
        return snap_dir

    async def restore(self, snap_dir: Path) -> None:
        """Restore DB + uploads from a previous snapshot()."""
        if not self._booted:
            raise RuntimeError("restore called before sandbox booted")
        db_sql_path = snap_dir / "db.sql"
        if not db_sql_path.exists():
            logger.warning("restore: no db.sql at %s — skipping DB restore", snap_dir)
        else:
            sql_bytes = db_sql_path.read_bytes()
            proc = await asyncio.create_subprocess_exec(
                "docker", "exec", "-i", self.db_container_name,
                "mariadb", "-uwpuser", "-pwppass",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _stdout, _stderr = await proc.communicate(sql_bytes)
            if proc.returncode != 0:
                logger.warning("restore: mariadb rc=%d stderr=%s",
                               proc.returncode, (_stderr.decode(errors='replace') or '')[:200])

        uploads_tar = snap_dir / "uploads.tar.gz"
        if uploads_tar.exists() and uploads_tar.stat().st_size > 0:
            await _run(
                "docker", "cp", str(uploads_tar),
                f"{self.container_name}:/tmp/squadrone_uploads.tar.gz",
                check=False,
            )
            await _run(
                "docker", "exec", self.container_name,
                "sh", "-c",
                "rm -rf /var/www/html/wp-content/uploads && "
                "tar xzf /tmp/squadrone_uploads.tar.gz -C /var/www/html/wp-content",
                check=False,
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
        raise RuntimeError(f"WordPress not reachable at {url} within {self.boot_timeout_s}s")

    async def _ensure_wp_installed(self) -> None:
        """Make sure wp-cli is installed and `wp core install` has been run."""
        # 1. Install wp-cli inside container if missing.
        rc, _, _ = await _run(
            "docker", "exec", self.container_name,
            "sh", "-c", "command -v wp >/dev/null 2>&1",
            check=False,
        )
        if rc != 0:
            await _run(
                "docker", "exec", self.container_name,
                "sh", "-c",
                "curl -sSLo /usr/local/bin/wp "
                "https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar "
                "&& chmod +x /usr/local/bin/wp",
            )

        # 2. Wait for db to be reachable from wp-cli's perspective.
        deadline = time.time() + self.boot_timeout_s
        while time.time() < deadline:
            rc, _, _ = await _run(
                "docker", "exec", self.container_name,
                "wp", "--allow-root", "db", "check",
                check=False,
            )
            if rc == 0:
                break
            await asyncio.sleep(2)

        # 3. Run wp core install if not already installed.
        rc, _, _ = await _run(
            "docker", "exec", self.container_name,
            "wp", "--allow-root", "core", "is-installed",
            check=False,
        )
        if rc != 0:
            await _run(
                "docker", "exec", self.container_name,
                "wp", "--allow-root", "core", "install",
                f"--url={self.target_url}",
                "--title=Squadrone Sandbox",
                f"--admin_user={self.config.wp_admin_user}",
                f"--admin_password={self.config.wp_admin_pass}",
                f"--admin_email={self.config.wp_admin_email}",
                "--skip-email",
            )

    # ── operations ──────────────────────────────────────────────

    async def install_plugin(self, zip_path: str) -> None:
        assert self.wp_cli is not None
        dest = f"/tmp/{Path(zip_path).name}"
        await _run("docker", "cp", zip_path, f"{self.container_name}:{dest}")
        await self.wp_cli.install_plugin(dest)
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
            await _run("docker", "exec", self.container_name, "sh", "-c", login_cmd, check=False)
            visit_cmd = (
                "curl -s -b /tmp/squadrone_cookies.txt "
                "http://localhost/wp-admin/ -o /dev/null -w '%{http_code}'"
            )
            _, status, _ = await _run("docker", "exec", self.container_name, "sh", "-c", visit_cmd, check=False)
            logger.info("post-install admin_init: GET /wp-admin/ -> %s", status.strip())
        except Exception as e:
            logger.warning("post-install admin_init dispatch failed: %s", e)

    # Baseline (non-admin) user accounts always created at sandbox boot. All five
    # default WordPress roles are covered so PoCs can pick the lowest-privilege
    # account that satisfies their hypothesis preconditions. Passwords are
    # uniform "password" for ease; the admin password comes from sandbox config.
    BASELINE_USERS: list[tuple[str, str]] = [
        ("subscriber_user", "subscriber"),
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
                logger.warning("create_user %s/%s failed (may already exist): %s", login, role, e)

    def baseline_user_accounts(self) -> list[dict]:
        """Return the credential table for users provisioned at sandbox boot.

        Used by verify.py to surface a structured `user_accounts` block to the
        PoC author so it picks credentials from a known table instead of
        recalling them from the system prompt (which can drift).
        """
        accounts = [{
            "login": self.config.wp_admin_user,
            "password": self.config.wp_admin_pass,
            "role": "administrator",
        }]
        for login, role in self.BASELINE_USERS:
            accounts.append({"login": login, "password": "password", "role": role})
        return accounts

    async def run_poc(self, script_path: str) -> SandboxRunResult:
        start = time.time()
        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable, script_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=self.poc_timeout_s,
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
        success = proc.returncode == 0 and "SUCCESS" in out and "FAILURE" not in out

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
            evidence={"stdout_tail": out[-500:], "returncode": proc.returncode},
        )
