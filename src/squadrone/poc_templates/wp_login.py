"""wp_login — robust WordPress login helper for PoC scripts.

WordPress's `wp-login.php` requires the `wordpress_test_cookie` to be set
in the session cookie jar BEFORE the credentials POST, otherwise the login
is silently rejected (returns 200 with the login form re-rendered, not a
redirect to wp-admin). The cookie is set by GETting `wp-login.php` once
before the POST.

Hand-rolling the login flow in a PoC script is the most common source of
"admin login failed" false negatives — always import this helper instead.

Usage:

    from wp_login import wp_login

    session = requests.Session()
    result = wp_login(
        session,
        "http://localhost:8100",
        "verified_login",
        "verified_password",
    )
    if not result.success:
        print(f"[-] FAILURE: {result.reason}")
        return
    # ... now `session` is authenticated; use it for subsequent requests ...

The helper sets cookies in the supplied session so subsequent requests
inherit the authenticated state. It returns a `LoginResult` with `success`
(bool), `reason` (str), and a measured `identity` (`WPIdentity`) on success::

    result.identity.user_id
    result.identity.login
    result.identity.roles

Multiple admin-bar markers are checked so the "logged in" detection survives
WordPress UI variations across versions, but UI markers alone never establish
success: every successful result is bound to WordPress's current-user REST
response.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class WPIdentity:
    """Identity measured from WordPress's authenticated current-user endpoint."""

    user_id: int
    login: str
    roles: tuple[str, ...] = ()


@dataclass(frozen=True)
class LoginResult:
    success: bool
    reason: str
    identity: WPIdentity | None = None


@dataclass(frozen=True)
class RestNonceResult:
    success: bool
    nonce: str
    reason: str


_AUTH_MARKERS = (
    "wp-admin-bar-my-account",  # admin bar list-item ID, present on every admin page
    "wp-admin-bar-user-info",  # user-info sub-item, same context
    "wpadminbar",  # the admin bar's root div ID
    "wp_logout_url",  # JS global available on admin pages
    "adminmenumain",  # the side admin menu's container
)

_LOGIN_FAIL_RE = re.compile(
    r'class=["\']error|login_error|<strong>Error</strong>', re.IGNORECASE
)


def _has_wordpress_login_cookie(session) -> bool:
    """Return whether WordPress issued an authenticated-session cookie."""
    try:
        cookies = session.cookies
        names = (
            cookies.keys() if hasattr(cookies, "keys") else (c.name for c in cookies)
        )
        return any(str(name).startswith("wordpress_logged_in_") for name in names)
    except (AttributeError, TypeError):
        return False


def _normalize_roles(value: object) -> tuple[tuple[str, ...] | None, str]:
    """Normalize supplied WordPress role slugs and reject malformed evidence."""
    if not isinstance(value, list) or not value:
        return None, "current-user REST roles were not a nonempty list"

    roles: list[str] = []
    for raw_role in value:
        if not isinstance(raw_role, str) or not raw_role.strip():
            return None, "current-user REST roles contained an empty role"
        role = raw_role.strip().casefold()
        if role not in roles:
            roles.append(role)
    return tuple(roles), ""


def _measure_current_user_identity(
    session,
    base_url: str,
    username: str,
    nonce: str,
    timeout: int,
) -> tuple[WPIdentity | None, str]:
    """Measure and validate the WordPress identity bound to a session."""
    try:
        response = session.get(
            f"{base_url}/?rest_route=/wp/v2/users/me&context=edit",
            headers={"X-WP-Nonce": nonce},
            timeout=timeout,
        )
    except Exception as e:
        return None, f"current-user REST request failed: {e}"
    if response.status_code != 200:
        return None, f"current-user REST request returned HTTP {response.status_code}"
    try:
        identity = json.loads(response.text)
    except (TypeError, ValueError):
        return None, "current-user REST response was not JSON"
    if not isinstance(identity, dict):
        return None, "current-user REST response was not an object"

    user_id = identity.get("id")
    if isinstance(user_id, bool) or not isinstance(user_id, int) or user_id <= 0:
        return None, "current-user REST response lacked a positive numeric user ID"

    login = identity.get("username")
    if not isinstance(login, str) or not login.strip():
        return None, "current-user REST response lacked a login"
    login = login.strip()

    expected = username.strip().casefold()
    reported = {login.casefold()}
    email = identity.get("email")
    if isinstance(email, str) and email.strip():
        reported.add(email.strip().casefold())
    if expected not in reported:
        return None, "current-user REST identity did not match requested credentials"

    if "roles" in identity:
        roles, roles_reason = _normalize_roles(identity["roles"])
        if roles is None:
            return None, roles_reason
    else:
        roles = ()
    return (
        WPIdentity(user_id=user_id, login=login, roles=roles),
        "current-user REST identity matched requested credentials",
    )


def wp_login(
    session, base_url: str, username: str, password: str, timeout: int = 20
) -> LoginResult:
    """Log in to WordPress and confirm the session is authenticated.

    Returns LoginResult(success=True) only when:
      1. The POST to wp-login.php didn't redirect us back to itself with an error
      2. A subsequent GET to /wp-admin/ either contains a recognised logged-in
         marker or a redirected low-privilege session retains an authenticated
         cookie
      3. A valid REST nonce and /users/me response bind the session to the
         requested positive WordPress user ID and login

    Cookies are stored in `session`; subsequent requests on the same session
    inherit the authenticated state.
    """
    # Step 1: prime the session with `wordpress_test_cookie` by GETting wp-login.php.
    try:
        login_page = session.get(f"{base_url}/wp-login.php", timeout=timeout)
    except Exception as e:
        return LoginResult(False, f"GET wp-login.php failed: {e}")
    if login_page.status_code != 200:
        return LoginResult(
            False, f"GET wp-login.php returned HTTP {login_page.status_code}"
        )

    # Step 2: POST credentials with redirect_to=/wp-admin/.
    try:
        resp = session.post(
            f"{base_url}/wp-login.php",
            data={
                "log": username,
                "pwd": password,
                "wp-submit": "Log In",
                "redirect_to": f"{base_url}/wp-admin/",
                "testcookie": "1",
            },
            timeout=timeout,
            allow_redirects=True,
        )
    except Exception as e:
        return LoginResult(False, f"POST wp-login.php failed: {e}")

    # If WP sent us back to login.php with an error, the credentials were rejected.
    if "wp-login.php" in resp.url and _LOGIN_FAIL_RE.search(resp.text):
        return LoginResult(False, f"WordPress rejected credentials for {username!r}")

    # Step 3: probe /wp-admin/ to confirm authentication actually took.
    try:
        probe = session.get(f"{base_url}/wp-admin/", timeout=timeout)
    except Exception as e:
        return LoginResult(False, f"GET /wp-admin/ failed after login: {e}")
    if probe.status_code != 200:
        return LoginResult(
            False, f"GET /wp-admin/ returned HTTP {probe.status_code} after login"
        )

    has_ui_marker = any(marker in probe.text for marker in _AUTH_MARKERS)
    if not has_ui_marker:
        # Security/membership plugins commonly redirect lower-privilege users away
        # from wp-admin even after a valid login. Only continue when WordPress has
        # issued an authenticated cookie; the REST checks below remain mandatory.
        if not _has_wordpress_login_cookie(session):
            return LoginResult(
                False, "GET /wp-admin/ returned 200 but no auth marker found in body"
            )

    nonce = wp_rest_nonce(session, base_url, timeout=timeout)
    if not nonce.success:
        return LoginResult(False, nonce.reason)
    identity, identity_reason = _measure_current_user_identity(
        session,
        base_url,
        username,
        nonce.nonce,
        timeout,
    )
    if identity is None:
        return LoginResult(False, identity_reason)

    reason = f"authenticated as {identity.login} (user ID {identity.user_id})"
    if not has_ui_marker:
        reason += "; wp-admin UI was redirected"
    return LoginResult(True, reason, identity)


def wp_rest_nonce(session, base_url: str, timeout: int = 20) -> RestNonceResult:
    """Fetch a `wp_rest` nonce for an already authenticated session."""
    try:
        response = session.get(
            f"{base_url}/wp-admin/admin-ajax.php?action=rest-nonce",
            timeout=timeout,
        )
    except Exception as e:
        return RestNonceResult(False, "", f"REST nonce request failed: {e}")
    if response.status_code != 200:
        return RestNonceResult(
            False,
            "",
            f"REST nonce request returned HTTP {response.status_code}",
        )
    nonce = response.text.strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{6,32}", nonce):
        return RestNonceResult(False, "", "REST nonce response was not a nonce")
    return RestNonceResult(True, nonce, "wp_rest nonce acquired")
