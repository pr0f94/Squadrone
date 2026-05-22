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
    result = wp_login(session, "http://localhost:8100", "admin", "password")
    if not result.success:
        print(f"[-] FAILURE: {result.reason}")
        return
    # ... now `session` is authenticated; use it for subsequent requests ...

The helper sets cookies in the supplied session so subsequent requests
inherit the authenticated state. It returns a `LoginResult` with `success`
(bool) and `reason` (str). Multiple admin-bar markers are checked so the
"logged in" detection survives WordPress UI variations across versions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class LoginResult:
    success: bool
    reason: str


_AUTH_MARKERS = (
    "wp-admin-bar-my-account",   # admin bar list-item ID, present on every admin page
    "wp-admin-bar-user-info",    # user-info sub-item, same context
    "wpadminbar",                # the admin bar's root div ID
    "wp_logout_url",             # JS global available on admin pages
    "adminmenumain",             # the side admin menu's container
)

_LOGIN_FAIL_RE = re.compile(r'class=["\']error|login_error|<strong>Error</strong>', re.IGNORECASE)


def wp_login(session, base_url: str, username: str, password: str, timeout: int = 20) -> LoginResult:
    """Log in to WordPress and confirm the session is authenticated.

    Returns LoginResult(success=True) only when:
      1. The POST to wp-login.php didn't redirect us back to itself with an error
      2. A subsequent GET to /wp-admin/ returns 200 with a recognised
         logged-in marker in the body

    Cookies are stored in `session`; subsequent requests on the same session
    inherit the authenticated state.
    """
    # Step 1: prime the session with `wordpress_test_cookie` by GETting wp-login.php.
    try:
        login_page = session.get(f"{base_url}/wp-login.php", timeout=timeout)
    except Exception as e:
        return LoginResult(False, f"GET wp-login.php failed: {e}")
    if login_page.status_code != 200:
        return LoginResult(False, f"GET wp-login.php returned HTTP {login_page.status_code}")

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
        return LoginResult(False, f"GET /wp-admin/ returned HTTP {probe.status_code} after login")

    if not any(marker in probe.text for marker in _AUTH_MARKERS):
        # 200 but none of the auth markers found — session isn't authenticated.
        return LoginResult(False, "GET /wp-admin/ returned 200 but no auth marker found in body")

    return LoginResult(True, f"authenticated as {username}")
