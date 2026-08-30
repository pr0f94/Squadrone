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

    _RECONCILED_USERS_PREFIX = "SQUADRONE_RECONCILED_USERS="
    _ROLE_CAPABILITIES_PREFIX = "SQUADRONE_ROLE_CAPABILITIES="
    ELEVATED_CAPABILITIES = (
        "activate_plugins",
        "add_users",
        "create_sites",
        "create_users",
        "delete_plugins",
        "delete_sites",
        "delete_themes",
        "delete_users",
        "edit_dashboard",
        "edit_files",
        "edit_plugins",
        "edit_theme_options",
        "edit_themes",
        "edit_users",
        "export",
        "import",
        "install_plugins",
        "install_themes",
        "list_users",
        "manage_network",
        "manage_network_options",
        "manage_network_plugins",
        "manage_network_themes",
        "manage_network_users",
        "manage_options",
        "manage_privacy_options",
        "manage_sites",
        "promote_users",
        "remove_users",
        "resume_plugins",
        "resume_themes",
        "setup_network",
        "switch_themes",
        "unfiltered_upload",
        "update_core",
        "update_plugins",
        "update_themes",
        "upgrade_network",
    )

    def __init__(self, container_name: str):
        self.container = container_name

    async def _exec_result(
        self,
        *args: str,
        user: str | None = None,
        wp_user: str | None = None,
    ) -> tuple[int, str, str]:
        """Run WP-CLI with independent OS and WordPress user identities."""
        cmd = ["docker", "exec"]
        if user is not None:
            cmd.extend(("--user", user))
        cmd.extend((self.container, "wp"))
        if user is None or user in {"root", "0"}:
            cmd.append("--allow-root")
        if wp_user is not None:
            cmd.append(f"--user={wp_user}")
        cmd.extend(args)
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

    async def _exec_result_with_stdin(
        self,
        *args: str,
        stdin_text: str,
        user: str | None = None,
        wp_user: str | None = None,
    ) -> tuple[int, str, str]:
        """Run WP-CLI with private input that is never placed in argv or logs."""
        cmd = ["docker", "exec", "-i"]
        if user is not None:
            cmd.extend(("--user", user))
        cmd.extend((self.container, "wp"))
        if user is None or user in {"root", "0"}:
            cmd.append("--allow-root")
        if wp_user is not None:
            cmd.append(f"--user={wp_user}")
        cmd.extend(args)
        logger.debug(
            "wp-cli (private stdin): %s", " ".join(shlex.quote(c) for c in cmd)
        )
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate(stdin_text.encode("utf-8"))
        out = stdout.decode("utf-8", errors="replace")
        err = stderr.decode("utf-8", errors="replace")
        return proc.returncode or 0, out, err

    async def _exec(
        self,
        *args: str,
        check: bool = True,
        user: str | None = None,
        wp_user: str | None = None,
    ) -> str:
        rc, out, err = await self._exec_result(
            *args,
            user=user,
            wp_user=wp_user,
        )
        if check and rc != 0:
            raise WPCliError(f"wp {' '.join(args)} exited {rc}: {err.strip()}")
        return out

    async def _eval(self, php: str) -> str:
        return await self._exec("eval", php)

    async def create_user(self, login: str, role: str, password: str) -> None:
        state = await self.reconcile_users(
            [
                {
                    "login": login,
                    "password": password,
                    "role": role,
                    "email": f"{login}@test.local",
                    "forbidden_core_caps": (
                        []
                        if role == "administrator"
                        else list(self.ELEVATED_CAPABILITIES)
                    ),
                }
            ]
        )
        inspected = (state.get("users") or {}).get(login)
        if (
            not isinstance(inspected, dict)
            or inspected.get("authenticated") is not True
        ):
            raise WPCliError(
                f"failed to create or authenticate WordPress user {login!r}"
            )

    async def role_capabilities(self) -> dict[str, frozenset[str]]:
        """Return the currently registered role definitions as a trusted ceiling."""
        php = (
            "$result = []; foreach ((array) wp_roles()->roles as $name => $role) { "
            "$caps = array_keys(array_filter((array) ($role['capabilities'] ?? []))); "
            "sort($caps); $result[(string) $name] = $caps; } ksort($result); "
            "echo 'SQUADRONE_ROLE_CAPABILITIES=' . wp_json_encode($result);"
        )
        rc, out, err = await self._exec_result("eval", php)
        if rc != 0:
            raise WPCliError(
                "failed to inspect WordPress role capabilities: "
                + (err or out).strip()[:300]
            )
        payload_line = next(
            (
                line
                for line in reversed(out.splitlines())
                if line.startswith(self._ROLE_CAPABILITIES_PREFIX)
            ),
            "",
        )
        if not payload_line:
            raise WPCliError("role capability inspection returned no structured state")
        try:
            state = json.loads(
                payload_line.removeprefix(self._ROLE_CAPABILITIES_PREFIX)
            )
        except json.JSONDecodeError as exc:
            raise WPCliError(
                "role capability inspection returned invalid JSON"
            ) from exc
        if not isinstance(state, dict) or not all(
            isinstance(role, str)
            and isinstance(capabilities, list)
            and all(isinstance(capability, str) for capability in capabilities)
            for role, capabilities in state.items()
        ):
            raise WPCliError("role capability inspection returned an invalid shape")
        return {role: frozenset(capabilities) for role, capabilities in state.items()}

    async def reconcile_users(self, accounts: list[dict[str, object]]) -> dict:
        """Create/update test users and prove their credentials and authority.

        Passwords travel over stdin rather than Docker/WP-CLI argv. Existing
        reserved test logins are updated when necessary, so a failed create can
        never cause an unverified password to be advertised to a PoC author.
        """
        required_fields = {
            "login",
            "password",
            "role",
            "email",
            "forbidden_core_caps",
        }
        for account in accounts:
            if (
                set(account) != required_fields
                or not all(
                    isinstance(account[field], str) and account[field]
                    for field in ("login", "password", "role", "email")
                )
                or not (
                    isinstance(account["forbidden_core_caps"], list)
                    and all(
                        isinstance(capability, str) and capability
                        for capability in account["forbidden_core_caps"]
                    )
                )
            ):
                raise ValueError(
                    "reconcile_users accounts require non-empty login, password, "
                    "role, and email strings plus a forbidden-core-capability list"
                )

        # Keep this program free of interpolated account data: the JSON payload,
        # including credentials, is supplied only through php://stdin.
        elevated_php = ", ".join(
            json.dumps(capability) for capability in self.ELEVATED_CAPABILITIES
        )
        php = (
            "$expected = json_decode(file_get_contents('php://stdin'), true); "
            "if (!is_array($expected)) { WP_CLI::error('invalid user specification'); } "
            "$registered = wp_roles(); $role_names = array_keys($registered->roles); "
            f"$privileged_names = [{elevated_php}]; "
            "$roles = []; $users = []; foreach ($expected as $account) { "
            "$login = (string) ($account['login'] ?? ''); "
            "$password = (string) ($account['password'] ?? ''); "
            "$role = (string) ($account['role'] ?? ''); "
            "$email = (string) ($account['email'] ?? ''); "
            "$roles[$role] = $registered->is_role($role); "
            "if (!$roles[$role]) { $users[$login] = null; continue; } "
            "$user = get_user_by('login', $login); $user_id = $user ? (int) $user->ID : 0; "
            "if (!$user) { $result = wp_insert_user(['user_login' => $login, "
            "'user_pass' => $password, 'user_email' => $email, 'role' => $role]); "
            "} else { $update = ['ID' => $user_id]; "
            "if (!wp_check_password($password, $user->user_pass, $user_id)) { "
            "$update['user_pass'] = $password; } "
            "$current_roles = array_values((array) $user->roles); sort($current_roles); "
            "if ($current_roles !== [$role]) { $update['role'] = $role; } "
            "$result = count($update) > 1 ? wp_update_user($update) : $user_id; } "
            "if (is_wp_error($result)) { $users[$login] = ['error' => "
            "(string) $result->get_error_message()]; continue; } } "
            "$authenticated_users = []; foreach ($expected as $account) { "
            "$login = (string) ($account['login'] ?? ''); "
            "$password = (string) ($account['password'] ?? ''); "
            "$role = (string) ($account['role'] ?? ''); "
            "if (!$roles[$role] || isset($users[$login]['error'])) { continue; } "
            "$user = get_user_by('login', $login); "
            "if (!$user) { $users[$login] = ['error' => 'user reload failed']; continue; } "
            "$user_id = (int) $user->ID; clean_user_cache($user_id); "
            "$user = get_user_by('id', $user_id); "
            "if (!$user) { $users[$login] = ['error' => 'user reload failed']; continue; } "
            "$authentication = wp_authenticate($login, $password); "
            "$authenticated_users[$login] = !is_wp_error($authentication) && "
            "(int) $authentication->ID === $user_id; } "
            "foreach ($expected as $account) { "
            "$login = (string) ($account['login'] ?? ''); "
            "$password = (string) ($account['password'] ?? ''); "
            "$role = (string) ($account['role'] ?? ''); "
            "$forbidden_core = array_values((array) "
            "($account['forbidden_core_caps'] ?? [])); "
            "if (!$roles[$role] || isset($users[$login]['error'])) { continue; } "
            "$user = get_user_by('login', $login); "
            "if (!$user) { $users[$login] = ['error' => 'final user reload failed']; "
            "continue; } $user_id = (int) $user->ID; clean_user_cache($user_id); "
            "$user = get_user_by('id', $user_id); "
            "if (!$user) { $users[$login] = ['error' => 'final user reload failed']; "
            "continue; } $authenticated = ($authenticated_users[$login] ?? false) "
            "&& wp_check_password($password, $user->user_pass, $user_id); "
            "$user_roles = array_values((array) $user->roles); sort($user_roles); "
            "$raw_caps = []; foreach ((array) $user->caps as $cap => $granted) { "
            "$raw_caps[(string) $cap] = (bool) $granted; } ksort($raw_caps); "
            "$allcaps = array_keys(array_filter((array) $user->allcaps)); "
            "$allcaps = array_values(array_diff($allcaps, $role_names)); sort($allcaps); "
            "$role_object = get_role($role); $role_caps = $role_object "
            "? array_keys(array_filter((array) $role_object->capabilities)) : []; "
            "sort($role_caps); $individual_excess = []; "
            "foreach ($raw_caps as $cap => $granted) { "
            "if ($granted && !in_array($cap, $role_names, true) && "
            "!in_array($cap, $role_caps, true)) { $individual_excess[] = $cap; } } "
            "sort($individual_excess); $privileged = []; "
            "foreach ($privileged_names as $cap) { "
            "if ($user->has_cap($cap)) { $privileged[] = $cap; } } sort($privileged); "
            "$core_excess = []; foreach ($forbidden_core as $cap) { "
            "if ($user->has_cap($cap)) { $core_excess[] = (string) $cap; } } "
            "sort($core_excess); $network_super_admin = "
            "is_multisite() && is_super_admin($user_id); "
            "$authority_exceeds = $network_super_admin || count($core_excess) > 0 "
            "|| ($role !== 'administrator' && count($individual_excess) > 0) "
            "|| ($role !== 'administrator' && count($privileged) > 0); "
            "$users[$login] = ['id' => $user_id, 'login' => (string) $user->user_login, "
            "'roles' => $user_roles, 'authenticated' => $authenticated, "
            "'caps' => $raw_caps, 'allcaps' => $allcaps, "
            "'privileged_caps' => $privileged, "
            "'unexpected_effective_core_caps' => $core_excess, "
            "'unexpected_individual_caps' => $individual_excess, "
            "'network_super_admin' => $network_super_admin, "
            "'authority_exceeds_baseline' => $authority_exceeds]; } "
            "echo 'SQUADRONE_RECONCILED_USERS=' . wp_json_encode(["
            "'roles' => $roles, 'users' => $users]);"
        )
        rc, out, err = await self._exec_result_with_stdin(
            "eval",
            php,
            stdin_text=json.dumps(accounts, separators=(",", ":")),
        )
        if rc != 0:
            raise WPCliError(
                "failed to reconcile sandbox users: " + (err or out).strip()[:300]
            )
        payload_line = next(
            (
                line
                for line in reversed(out.splitlines())
                if line.startswith(self._RECONCILED_USERS_PREFIX)
            ),
            "",
        )
        if not payload_line:
            raise WPCliError("sandbox user reconciliation returned no structured state")
        try:
            state = json.loads(payload_line.removeprefix(self._RECONCILED_USERS_PREFIX))
        except json.JSONDecodeError as exc:
            raise WPCliError(
                "sandbox user reconciliation returned invalid JSON"
            ) from exc
        if not isinstance(state, dict):
            raise WPCliError("sandbox user reconciliation returned an invalid shape")
        return state

    async def install_plugin(
        self,
        zip_path: str,
        *,
        user: str | None = None,
        wp_user: str | None = None,
    ) -> None:
        await self._exec(
            "plugin",
            "install",
            zip_path,
            "--activate",
            "--force",
            user=user,
            wp_user=wp_user,
        )

    async def activate_plugin(self, slug: str) -> None:
        await self._exec("plugin", "activate", slug)

    async def get_option(self, option_name: str) -> str:
        return (await self._exec("option", "get", option_name)).strip()

    async def set_option(self, option_name: str, value: str) -> None:
        await self._exec("option", "update", option_name, value)

    async def get_query_log(self) -> list[str]:
        out = await self._eval(
            "echo json_encode(array_map(function($q){return $q[0];}, (array)$GLOBALS['wpdb']->queries));"
        )
        try:
            data = json.loads(out)
            return data if isinstance(data, list) else []
        except json.JSONDecodeError:
            return []

    async def get_error_log(self) -> str:
        proc = await asyncio.create_subprocess_exec(
            "docker",
            "exec",
            self.container,
            "sh",
            "-c",
            "cat /var/www/html/wp-content/debug.log 2>/dev/null || true",
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
            "post",
            "list",
            f"--post_type={post_type}",
            "--format=json",
        )
        try:
            data = json.loads(out)
            return data if isinstance(data, list) else []
        except json.JSONDecodeError:
            return []
