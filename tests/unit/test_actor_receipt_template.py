from __future__ import annotations

import re
from importlib.resources import files

from jinja2 import StrictUndefined, Template, meta

_TEMPLATE_PATH = files("squadrone.docker") / "squadrone-actor-receipt.php.j2"


def _render_template() -> str:
    return Template(
        _TEMPLATE_PATH.read_text(),
        undefined=StrictUndefined,
    ).render(
        trace_token="ab" * 16,
        receipt_secret="cd" * 32,
        php_object_canary_class=(
            "SquadroneObjectCanary_0123456789abcdef0123456789abcdef"
        ),
    )


def test_actor_receipt_template_renders_the_signed_identity_contract() -> None:
    rendered = _render_template()

    assert "{{" not in rendered
    assert "$trace_token = '" + ("ab" * 16) + "';" in rendered
    assert "$receipt_secret_hex = '" + ("cd" * 32) + "';" in rendered
    assert (
        "$php_object_canary_class = "
        "'SquadroneObjectCanary_0123456789abcdef0123456789abcdef';"
    ) in rendered
    assert "hash_equals($trace_token, $request_trace_token)" in rendered
    assert "HTTP_X_SQUADRONE_REQUEST_NONCE" in rendered
    assert "HTTP_X_SQUADRONE_REQUEST_DIGEST" in rendered
    assert '"SQUADRONE-REQUEST-V1\\0"' in rendered
    assert "hash_equals($computed_request_digest, $request_digest)" in rendered
    assert "add_action(" in rendered
    assert "'init'" in rendered
    assert "PHP_INT_MIN" in rendered
    assert "header_register_callback" in rendered
    assert "X-Squadrone-Actor-Receipt: " in rendered
    assert "hash_hmac('sha256', $encoded_payload, $receipt_secret, false)" in rendered
    assert "bin2hex(random_bytes(16))" in rendered

    payload_source = re.search(
        r"\$payload = array\((.*?)\n\s*\);",
        rendered,
        flags=re.DOTALL,
    )
    assert payload_source is not None
    assert re.findall(r"'([a-z_]+)'\s*=>", payload_source.group(1)) == [
        "v",
        "trace_token",
        "nonce",
        "request_nonce",
        "request_digest",
        "user_id",
        "roles",
        "method",
        "path",
    ]
    assert "$_GET" not in payload_source.group(1)
    assert "$_POST" not in payload_source.group(1)
    assert "$_COOKIE" not in payload_source.group(1)
    assert "receipt_secret" not in payload_source.group(1)


def test_actor_receipt_template_uses_request_metadata_without_query_values() -> None:
    rendered = _render_template()

    assert "HTTP_X_SQUADRONE_TRACE_TOKEN" in rendered
    assert "REQUEST_METHOD" in rendered
    assert "REQUEST_URI" in rendered
    assert "file_get_contents('php://input')" in rendered
    assert "foreach (array('?', '#') as $separator)" in rendered
    assert "sort($roles, SORT_STRING);" in rendered
    assert "if ($user_id < 0)" in rendered
    assert "headers_sent()" in rendered


def test_actor_receipt_uses_proxy_binding_only_for_strict_multipart_ingress() -> None:
    rendered = _render_template()

    assert "HTTP_X_SQUADRONE_REQUEST_BINDING" in rendered
    assert "isset($_SERVER['CONTENT_TYPE'])" in rendered
    assert r"/\Amultipart\/form-data(?:\s*;|\s*\z)/iD" in rendered
    assert '"SQUADRONE-REQUEST-BINDING-V1\\0"' in rendered

    binding_source = re.search(
        r"\$computed_request_binding = hash_hmac\((.*?)\n\s*\);",
        rendered,
        flags=re.DOTALL,
    )
    assert binding_source is not None
    binding_contract = binding_source.group(1)
    assert re.findall(
        r"\. \$(method|request_uri|request_nonce|request_digest)",
        binding_contract,
    ) == ["method", "request_uri", "request_nonce", "request_digest"]
    assert "$receipt_secret" in binding_contract
    assert "hash_equals($computed_request_binding, $request_binding)" in rendered

    verification_source = re.search(
        r"if \(\$is_multipart\) \{(.*?)\n\s*\} else \{(.*?)\n\s*\}\n\n"
        r"\s*\$path_end",
        rendered,
        flags=re.DOTALL,
    )
    assert verification_source is not None
    multipart_branch, ordinary_branch = verification_source.groups()
    assert "if (! $binding_valid)" in multipart_branch
    assert "return;" in multipart_branch
    assert "file_get_contents('php://input')" not in multipart_branch
    assert "file_get_contents('php://input')" in ordinary_branch
    assert "hash_equals($computed_request_digest, $request_digest)" in ordinary_branch
    assert "$binding_valid" not in ordinary_branch


def test_actor_receipt_freezes_identity_before_header_emission() -> None:
    rendered = _render_template()

    init_hook = rendered.index("add_action(")
    receipt_callback = rendered.index("@header_register_callback(")
    assert init_hook < receipt_callback
    assert "static function () use (&$ingress_identity)" in rendered
    assert "&$ingress_identity" in rendered
    assert "$ingress_identity['user_id']" in rendered
    assert "$ingress_identity['roles']" in rendered

    header_callback = rendered[receipt_callback:]
    assert "get_current_user_id()" not in header_callback
    assert "wp_get_current_user()" not in header_callback


def test_actor_receipt_bridges_only_the_inert_canarys_one_shot_receipt() -> None:
    rendered = _render_template()

    remove = rendered.index("header_remove('X-Squadrone-PHP-Object-Receipt')")
    consume = rendered.index("'consumeReceipt'")
    emit = rendered.index("'X-Squadrone-PHP-Object-Receipt: '")
    assert remove < consume < emit
    assert "class_exists($php_object_canary_class, false)" in rendered
    assert "SquadroneObjectCanary_[0-9a-f]{32}" in rendered
    assert "sqpobj1\\.[0-9a-f]{64}\\.[0-9a-f]{64}" in rendered
    assert "resetReceipt" not in rendered
    assert "sqpobjt1" not in rendered
    assert "generation_id" not in rendered
    assert "expected_receipt" not in rendered


def test_actor_receipt_template_has_no_ssrf_oracle_state_or_extra_variables() -> None:
    rendered = _render_template()
    lowered = rendered.casefold()

    for forbidden in (
        "ssrf",
        "squadrone_ssrf",
        "attack_token",
        "control_token",
        "marker",
        "ledger",
    ):
        assert forbidden not in lowered

    source = _TEMPLATE_PATH.read_text()
    environment = Template(source, undefined=StrictUndefined).environment
    undeclared = environment.parse(source)

    assert meta.find_undeclared_variables(undeclared) == {
        "php_object_canary_class",
        "receipt_secret",
        "trace_token",
    }
