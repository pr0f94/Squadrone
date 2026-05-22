"""Unit tests for wp_login helper.

The helper is delivered as a POC-side module, so we import it as a path.
The tests use a fake `Session` to assert the GET-then-POST flow without
hitting a real WordPress.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from dataclasses import dataclass


def _load_wp_login_module():
    src = Path(__file__).resolve().parents[2] / "src/squadrone/poc_templates/wp_login.py"
    spec = importlib.util.spec_from_file_location("wp_login_test", src)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["wp_login_test"] = mod
    spec.loader.exec_module(mod)
    return mod


WP_LOGIN = _load_wp_login_module()


@dataclass
class _Resp:
    status_code: int
    text: str
    url: str = ""


class FakeSession:
    """Records every HTTP call and returns canned responses by URL pattern."""

    def __init__(self, responses: dict):
        self.responses = responses
        self.calls = []

    def get(self, url, timeout=None):
        self.calls.append(("GET", url))
        return self._resolve(url)

    def post(self, url, data=None, timeout=None, allow_redirects=True):
        self.calls.append(("POST", url, dict(data or {})))
        return self._resolve(url, post_url=url)

    def _resolve(self, url, post_url=None):
        for pattern, resp_factory in self.responses.items():
            if pattern in url:
                return resp_factory(self, url, post_url)
        return _Resp(status_code=404, text="", url=url)


# ----- successful login --------------------------------------------------

def test_successful_admin_login():
    session = FakeSession({
        # GET /wp-login.php — sets test cookie (we just return 200)
        "wp-login.php": lambda s, u, p: _Resp(
            200, "login form",
            url="http://localhost:8100/wp-admin/" if len(s.calls) > 1 else u,
        ),
        # GET /wp-admin/ after login — return admin bar markers
        "wp-admin": lambda s, u, p: _Resp(
            200,
            '<html><body><div id="wpadminbar"><li id="wp-admin-bar-my-account">'
            "...</li></div></body></html>",
            url="http://localhost:8100/wp-admin/",
        ),
    })
    result = WP_LOGIN.wp_login(session, "http://localhost:8100", "admin", "password")
    assert result.success
    assert "admin" in result.reason
    # Should have made: GET /wp-login.php (prime), POST /wp-login.php (creds), GET /wp-admin/ (probe)
    methods = [(m, u.split("/")[-1] or "wp-admin") for (m, u, *_) in session.calls]
    assert methods[0][0] == "GET"
    assert "wp-login" in session.calls[0][1]
    assert session.calls[1][0] == "POST"
    assert "wp-login" in session.calls[1][1]
    assert session.calls[-1][0] == "GET"
    assert "wp-admin" in session.calls[-1][1]


# ----- rejected credentials ----------------------------------------------

def test_login_error_returned_in_body():
    session = FakeSession({
        "wp-login.php": lambda s, u, p: _Resp(
            200,
            '<div id="login_error">Invalid username</div>',
            url="http://localhost:8100/wp-login.php",
        ),
    })
    result = WP_LOGIN.wp_login(session, "http://localhost:8100", "admin", "wrongpass")
    assert not result.success
    assert "rejected" in result.reason.lower()


# ----- no auth marker after login ----------------------------------------

def test_wp_admin_returns_200_but_no_auth_marker():
    """Some auth bypasses leave session 'partially' authenticated.
    The helper must NOT report success if the admin bar isn't there."""
    seq = []

    def factory(s, url, post_url):
        seq.append(url)
        if "wp-login.php" in url:
            return _Resp(200, "login form", url="http://localhost:8100/wp-admin/")
        if "wp-admin" in url:
            return _Resp(200, "<html>welcome guest</html>", url=url)
        return _Resp(404, "", url=url)

    session = FakeSession({"http": factory})
    result = WP_LOGIN.wp_login(session, "http://localhost:8100", "admin", "password")
    assert not result.success
    assert "no auth marker" in result.reason.lower()


# ----- GET wp-login.php fails (network) ----------------------------------

def test_get_login_page_network_error():
    class Boom(FakeSession):
        def get(self, url, timeout=None):
            if "wp-login.php" in url:
                raise ConnectionError("cant reach")
            return super().get(url, timeout=timeout)

    session = Boom({})
    result = WP_LOGIN.wp_login(session, "http://localhost:8100", "admin", "password")
    assert not result.success
    assert "GET wp-login.php failed" in result.reason


# ----- POST wp-login.php fails (network) ---------------------------------

def test_post_credentials_network_error():
    class Boom(FakeSession):
        def post(self, url, data=None, timeout=None, allow_redirects=True):
            raise ConnectionError("post died")

    session = Boom({"wp-login.php": lambda s, u, p: _Resp(200, "login form", url=u)})
    result = WP_LOGIN.wp_login(session, "http://localhost:8100", "admin", "password")
    assert not result.success
    assert "POST wp-login.php failed" in result.reason


# ----- recognises multiple admin-bar marker variants ---------------------

def test_recognises_wpadminbar_marker_alone():
    """Older WP versions may only emit the root #wpadminbar div, not the LI."""
    session = FakeSession({
        "wp-login.php": lambda s, u, p: _Resp(200, "form", url="http://localhost:8100/wp-admin/"),
        "wp-admin": lambda s, u, p: _Resp(
            200,
            '<div id="wpadminbar"></div>',  # only the root marker, no LI
            url="http://localhost:8100/wp-admin/",
        ),
    })
    result = WP_LOGIN.wp_login(session, "http://localhost:8100", "admin", "password")
    assert result.success
