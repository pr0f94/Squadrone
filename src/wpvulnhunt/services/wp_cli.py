"""WP-CLI wrapper — every method shells out to `docker exec <container> wp --allow-root ...`."""

from __future__ import annotations

import asyncio
import json
import logging
import shlex

logger = logging.getLogger(__name__)


class WPCliError(RuntimeError):
    pass


class WPCli:
    """Executes WP-CLI commands inside the running sandbox container."""

    def __init__(self, container_name: str):
        self.container = container_name

    async def _exec_result(self, *args: str) -> tuple[int, str, str]:
        cmd = ["docker", "exec", self.container, "wp", "--allow-root", *args]
        logger.debug("wp-cli: %s", " ".join(shlex.quote(c) for c in cmd))
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        out = stdout.decode("utf-8", errors="replace")
        err = stderr.decode("utf-8", errors="replace")
        return proc.returncode or 0, out, err

    async def _exec(self, *args: str, check: bool = True) -> str:
        rc, out, err = await self._exec_result(*args)
        if check and rc != 0:
            raise WPCliError(f"wp {' '.join(args)} exited {rc}: {err.strip()}")
        return out

    async def _eval(self, php: str) -> str:
        return await self._exec("eval", php)

    async def create_user(self, login: str, role: str, password: str = "password") -> None:
        email = f"{login}@test.local"
        await self._exec(
            "user", "create", login, email,
            f"--role={role}",
            f"--user_pass={password}",
            "--porcelain",
        )

    async def install_plugin(self, zip_path: str) -> None:
        await self._exec("plugin", "install", zip_path, "--activate", "--force")

    async def activate_plugin(self, slug: str) -> None:
        await self._exec("plugin", "activate", slug)

    async def get_option(self, option_name: str) -> str:
        return (await self._exec("option", "get", option_name)).strip()

    async def set_option(self, option_name: str, value: str) -> None:
        await self._exec("option", "update", option_name, value)

    async def get_query_log(self) -> list[str]:
        out = await self._eval("echo json_encode(array_map(function($q){return $q[0];}, (array)$GLOBALS['wpdb']->queries));")
        try:
            data = json.loads(out)
            return data if isinstance(data, list) else []
        except json.JSONDecodeError:
            return []

    async def get_error_log(self) -> str:
        proc = await asyncio.create_subprocess_exec(
            "docker", "exec", self.container,
            "sh", "-c", "cat /var/www/html/wp-content/debug.log 2>/dev/null || true",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        return stdout.decode("utf-8", errors="replace")

    async def db_query(self, sql: str) -> list[dict]:
        php = (
            "global $wpdb; "
            f"$rows = $wpdb->get_results({json.dumps(sql)}, ARRAY_A); "
            "echo json_encode($rows ?: []);"
        )
        out = await self._eval(php)
        try:
            data = json.loads(out)
            return data if isinstance(data, list) else []
        except json.JSONDecodeError:
            return []

    async def get_posts(self, post_type: str = "post") -> list[dict]:
        out = await self._exec(
            "post", "list",
            f"--post_type={post_type}",
            "--format=json",
        )
        try:
            data = json.loads(out)
            return data if isinstance(data, list) else []
        except json.JSONDecodeError:
            return []
