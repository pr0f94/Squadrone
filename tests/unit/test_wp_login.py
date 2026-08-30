"""Unit tests for wp_login helper.

The helper is delivered as a POC-side module, so we import it as a path.
The tests use a fake `Session` to assert the GET-then-POST flow without
hitting a real WordPress.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest


def _load_wp_login_module():
    src = (
        Path(__file__).resolve().parents[2] / "src/squadrone/poc_templates/wp_login.py"
    )
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
        self.get_headers = []
        self.cookies = {}

    def get(self, url, headers=None, timeout=None):
        self.calls.append(("GET", url))
        self.get_headers.append((url, dict(headers or {})))
        return self._resolve(url)

    def post(self, url, data=None, timeout=None, allow_redirects=True):
        self.calls.append(("POST", url, dict(data or {})))
        return self._resolve(url, post_url=url)

    def _resolve(self, url, post_url=None):
        for pattern, resp_factory in self.responses.items():
            if pattern in url:
                return resp_factory(self, url, post_url)
        return _Resp(status_code=404, text="", url=url)


def _authenticated_session(
    *,
    login: str = "admin",
    user_id: object = 1,
    roles: object = ("administrator",),
    email: str = "admin@example.test",
    admin_body: str = '<div id="wpadminbar"></div>',
    nonce_body: str = "abc123def0",
    identity_status: int = 200,
    identity_overrides: dict | None = None,
) -> FakeSession:
    identity = {"id": user_id, "username": login, "email": email}
    if roles is not _ROLES_OMITTED:
        identity["roles"] = list(roles) if isinstance(roles, tuple) else roles
    identity.update(identity_overrides or {})

    def factory(session, url, post_url):
        if "wp-login.php" in url:
            if session.calls[-1][0] == "POST":
                session.cookies["wordpress_logged_in_testhash"] = "signed-session"
            return _Resp(200, "login form", url="http://localhost:8100/wp-admin/")
        if "admin-ajax.php" in url:
            return _Resp(200, nonce_body, url=url)
        if "rest_route=/wp/v2/users/me" in url:
            return _Resp(identity_status, json.dumps(identity), url=url)
        if "wp-admin" in url:
            return _Resp(200, admin_body, url=url)
        return _Resp(404, "", url=url)

    return FakeSession({"http": factory})


_ROLES_OMITTED = object()


# ----- successful login --------------------------------------------------


def test_successful_admin_login():
    session = _authenticated_session()
    result = WP_LOGIN.wp_login(session, "http://localhost:8100", "admin", "password")

    assert result.success
    assert "admin" in result.reason
    assert result.identity == WP_LOGIN.WPIdentity(
        user_id=1,
        login="admin",
        roles=("administrator",),
    )
    # Prime, submit credentials, probe wp-admin, obtain a nonce, then bind the
    # session to WordPress's measured current user.
    methods = [(m, u.split("/")[-1] or "wp-admin") for (m, u, *_) in session.calls]
    assert methods[0][0] == "GET"
    assert "wp-login" in session.calls[0][1]
    assert session.calls[1][0] == "POST"
    assert "wp-login" in session.calls[1][1]
    assert session.calls[2] == ("GET", "http://localhost:8100/wp-admin/")
    assert session.calls[-2] == (
        "GET",
        "http://localhost:8100/wp-admin/admin-ajax.php?action=rest-nonce",
    )
    assert session.calls[-1] == (
        "GET",
        "http://localhost:8100/?rest_route=/wp/v2/users/me&context=edit",
    )
    assert session.get_headers[-1][1] == {"X-WP-Nonce": "abc123def0"}


# ----- rejected credentials ----------------------------------------------


def test_login_error_returned_in_body():
    session = FakeSession(
        {
            "wp-login.php": lambda s, u, p: _Resp(
                200,
                '<div id="login_error">Invalid username</div>',
                url="http://localhost:8100/wp-login.php",
            ),
        }
    )
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


def test_low_privilege_login_uses_cookie_and_nonce_when_wp_admin_is_redirected():
    def factory(session, url, post_url):
        if "wp-login.php" in url:
            if session.calls[-1][0] == "POST":
                session.cookies["wordpress_logged_in_testhash"] = "signed-session"
            return _Resp(200, "login form", url="http://localhost:8100/wp-admin/")
        if "admin-ajax.php" in url:
            return _Resp(200, "abc123def0", url=url)
        if "rest_route=/wp/v2/users/me" in url:
            return _Resp(
                200,
                '{"id": 7, "username": "subscriber_user", '
                '"email": "subscriber@example.test", '
                '"roles": ["subscriber"]}',
                url=url,
            )
        if "wp-admin" in url:
            return _Resp(200, "<html>membership landing page</html>", url=url)
        return _Resp(404, "", url=url)

    session = FakeSession({"http": factory})

    result = WP_LOGIN.wp_login(
        session,
        "http://localhost:8100",
        "subscriber_user",
        "password",
    )

    assert result.success
    assert "redirected" in result.reason
    assert result.identity == WP_LOGIN.WPIdentity(
        user_id=7,
        login="subscriber_user",
        roles=("subscriber",),
    )
    assert session.calls[-2] == (
        "GET",
        "http://localhost:8100/wp-admin/admin-ajax.php?action=rest-nonce",
    )
    assert session.calls[-1] == (
        "GET",
        "http://localhost:8100/?rest_route=/wp/v2/users/me&context=edit",
    )
    assert session.get_headers[-1][1] == {"X-WP-Nonce": "abc123def0"}


def test_redirected_login_rejects_a_different_authenticated_identity():
    def factory(session, url, post_url):
        if "wp-login.php" in url:
            if session.calls[-1][0] == "POST":
                session.cookies["wordpress_logged_in_testhash"] = "signed-session"
            return _Resp(200, "login form", url="http://localhost:8100/wp-admin/")
        if "admin-ajax.php" in url:
            return _Resp(200, "abc123def0", url=url)
        if "rest_route=/wp/v2/users/me" in url:
            return _Resp(
                200,
                '{"id": 9, "username": "different_user", '
                '"email": "different@example.test"}',
                url=url,
            )
        if "wp-admin" in url:
            return _Resp(200, "<html>membership landing page</html>", url=url)
        return _Resp(404, "", url=url)

    session = FakeSession({"http": factory})

    result = WP_LOGIN.wp_login(
        session,
        "http://localhost:8100",
        "subscriber_user",
        "password",
    )

    assert not result.success
    assert "identity did not match" in result.reason
    assert result.identity is None


def test_identity_roles_are_normalized_and_deduplicated():
    session = _authenticated_session(
        roles=[" Subscriber ", "CUSTOM_ROLE", "subscriber"]
    )

    result = WP_LOGIN.wp_login(session, "http://localhost:8100", "admin", "password")

    assert result.success
    assert result.identity is not None
    assert result.identity.roles == ("subscriber", "custom_role")


def test_identity_roles_may_be_omitted():
    session = _authenticated_session(roles=_ROLES_OMITTED)

    result = WP_LOGIN.wp_login(session, "http://localhost:8100", "admin", "password")

    assert result.success
    assert result.identity is not None
    assert result.identity.roles == ()


@pytest.mark.parametrize("user_id", [0, -1, True, "7", None])
def test_login_rejects_non_positive_or_non_numeric_current_user_id(user_id):
    session = _authenticated_session(user_id=user_id)

    result = WP_LOGIN.wp_login(session, "http://localhost:8100", "admin", "password")

    assert not result.success
    assert result.identity is None
    assert "positive numeric user ID" in result.reason


@pytest.mark.parametrize(
    "roles",
    [[], ["subscriber", ""], ["subscriber", "   "], "subscriber", None],
)
def test_login_rejects_malformed_supplied_roles(roles):
    session = _authenticated_session(roles=roles)

    result = WP_LOGIN.wp_login(session, "http://localhost:8100", "admin", "password")

    assert not result.success
    assert result.identity is None
    assert "roles" in result.reason


def test_login_rejects_missing_current_user_login():
    session = _authenticated_session(identity_overrides={"username": ""})

    result = WP_LOGIN.wp_login(session, "http://localhost:8100", "admin", "password")

    assert not result.success
    assert result.identity is None
    assert "lacked a login" in result.reason


def test_email_credential_is_bound_to_the_measured_account_login():
    session = _authenticated_session(login="site_admin", email="admin@example.test")

    result = WP_LOGIN.wp_login(
        session,
        "http://localhost:8100",
        "admin@example.test",
        "password",
    )

    assert result.success
    assert result.identity is not None
    assert result.identity.login == "site_admin"
    assert result.identity.user_id == 1


def test_admin_marker_does_not_bypass_failed_rest_nonce():
    session = _authenticated_session(nonce_body="<html>login</html>")

    result = WP_LOGIN.wp_login(session, "http://localhost:8100", "admin", "password")

    assert not result.success
    assert result.identity is None
    assert "not a nonce" in result.reason


def test_admin_marker_does_not_bypass_failed_current_user_probe():
    session = _authenticated_session(identity_status=403)

    result = WP_LOGIN.wp_login(session, "http://localhost:8100", "admin", "password")

    assert not result.success
    assert result.identity is None
    assert "HTTP 403" in result.reason


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
    session = _authenticated_session(admin_body='<div id="wpadminbar"></div>')

    result = WP_LOGIN.wp_login(session, "http://localhost:8100", "admin", "password")

    assert result.success
    assert result.identity is not None


def test_fetches_rest_nonce_for_authenticated_session():
    session = FakeSession(
        {
            "admin-ajax.php": lambda s, u, p: _Resp(200, "abc123def0", url=u),
        }
    )

    result = WP_LOGIN.wp_rest_nonce(session, "http://localhost:8100")

    assert result.success
    assert result.nonce == "abc123def0"
    assert session.calls == [
        (
            "GET",
            "http://localhost:8100/wp-admin/admin-ajax.php?action=rest-nonce",
        ),
    ]


def test_rejects_non_nonce_rest_response():
    session = FakeSession(
        {
            "admin-ajax.php": lambda s, u, p: _Resp(200, "<html>login</html>", url=u),
        }
    )

    result = WP_LOGIN.wp_rest_nonce(session, "http://localhost:8100")

    assert not result.success
    assert "not a nonce" in result.reason
