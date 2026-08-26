from __future__ import annotations

import ast

from squadrone.agents.poc_author import _BUG_CLASS_TEMPLATE, _render_template
from squadrone.schemas import BugClass


def test_all_poc_templates_render_as_valid_python() -> None:
    template_names = set(_BUG_CLASS_TEMPLATE.values())

    for template_name in template_names:
        rendered = _render_template(
            template_name,
            target_url="http://127.0.0.1",
            ajax_action="test_action",
            injectable_param="id",
            test_username="subscriber_user",
            test_password="password",
            extra_params="",
            attacker_role="subscriber",
        )
        ast.parse(rendered, filename=template_name)


def test_missing_authentication_uses_state_change_template() -> None:
    assert (
        _BUG_CLASS_TEMPLATE[BugClass.MISSING_AUTH_CRITICAL_FUNCTION.value]
        == "state_change.py.j2"
    )


def test_unmapped_cwe_has_no_automatic_template() -> None:
    from squadrone.agents.poc_author import _select_template

    assert _select_template("CWE-1234") is None
