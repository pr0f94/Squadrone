from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import time
from collections.abc import Sequence
from typing import Any
from urllib.parse import quote_from_bytes

import httpx
import pytest

from squadrone.poc_proxy import (
    PHP_OBJECT_RECEIPT_HEADER,
    PhpObjectArm,
    PhpObjectProxyObservation,
    PhpObjectRewritePolicy,
    PhpObjectSurfacePhase,
    PocProxySupervisor,
    canonical_request_digest,
    classify_request_sentinels,
)
from squadrone.services.php_object_oracle import PhpObjectOracle


_ORIGIN = "http://localhost:8123"
_PATH = "/wp-admin/admin-ajax.php"
_CLASS_NAME = "SquadroneObjectCanary_" + "a" * 32
_SECRET = bytes.fromhex("41" * 32)


def _oracle() -> PhpObjectOracle:
    oracle = PhpObjectOracle(
        callsite_path="/var/www/html/wp-content/plugins/example/source.php",
        callsite_start_line=10,
        callsite_end_line=20,
        callsite_source_sha256="b" * 64,
        class_name=_CLASS_NAME,
        receipt_secret=_SECRET,
    )
    oracle.begin_generation()
    return oracle


async def _unchanged_surface(
    phase: PhpObjectSurfacePhase,
    arm: PhpObjectArm,
) -> None:
    del phase, arm


def _policy(
    *,
    method: str = "POST",
    path: str = _PATH,
    object_field: str = "payload",
    dispatch: tuple[tuple[str, str, str], ...] = (("form", "action", "demo"),),
) -> PhpObjectRewritePolicy:
    return PhpObjectRewritePolicy(
        method=method,
        path=path,
        object_location="form",
        object_field=object_field,
        dispatch=dispatch,
    )


class _RecordingProxy(PocProxySupervisor):
    def __init__(
        self,
        oracle: PhpObjectOracle,
        responses: Sequence[tuple[list[tuple[str, str]], bytes]],
        *,
        policy: PhpObjectRewritePolicy | None = None,
        delay: float = 0,
        surface_attestor: Any = _unchanged_surface,
    ) -> None:
        super().__init__(
            _ORIGIN,
            trace_token="parent-trace-token",
            trace_salt=bytes.fromhex("31" * 32),
            php_object_oracle=oracle,
            php_object_policy=policy or _policy(),
            php_object_surface_attestor=surface_attestor,
        )
        self.responses = list(responses)
        self.forwarded: list[dict[str, Any]] = []
        self.delay = delay

    async def _forward(
        self,
        method: str,
        url: str,
        headers: list[tuple[str, str]],
        body: bytes,
        nonce: str,
        request_digest: str,
        record: dict[str, object],
        *,
        credential_free_headers: list[tuple[str, str]] | None = None,
    ) -> tuple[httpx.Response, bytes]:
        del nonce, record
        if self.delay:
            await asyncio.sleep(self.delay)
        self.forwarded.append(
            {
                "method": method,
                "url": url,
                "headers": list(headers),
                "body": body,
                "request_digest": request_digest,
                "credential_free_headers": credential_free_headers,
            }
        )
        response_headers, response_body = self.responses.pop(0)
        return (
            httpx.Response(202, headers=response_headers, content=response_body),
            response_body,
        )


class _MemoryWriter:
    def __init__(self) -> None:
        self.chunks: list[bytes] = []

    def writelines(self, chunks: list[bytes]) -> None:
        self.chunks.extend(chunks)

    def write(self, chunk: bytes) -> None:
        self.chunks.append(chunk)

    async def drain(self) -> None:
        return None

    @property
    def value(self) -> bytes:
        return b"".join(self.chunks)


async def _execute(
    proxy: PocProxySupervisor,
    body: bytes,
    *,
    method: str = "POST",
    raw_target: str = _PATH,
    extra_headers: Sequence[tuple[str, str]] = (),
) -> tuple[httpx.Response | None, bytes, int, str]:
    path = raw_target.partition("?")[0]
    headers: list[tuple[str, str]] = [
        ("Host", "localhost:8123"),
        ("Accept", "*/*"),
        ("User-Agent", "authored-client"),
    ]
    if method not in {"GET", "HEAD"} or body:
        headers.extend(
            [
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Content-Length", str(len(body))),
            ]
        )
    headers.extend(extra_headers)
    raw_headers = "\r\n".join(f"{name}: {value}" for name, value in headers)
    sentinel_flags, sentinel_categories = classify_request_sentinels(
        raw_target.encode("ascii"),
        raw_headers.encode("latin-1"),
        body,
    )
    async with proxy._forward_lock:
        return await proxy._execute_accepted_request(
            method=method,
            url=_ORIGIN + raw_target,
            path=path,
            raw_target=raw_target,
            headers=headers,
            body=body,
            sentinel_flags=sentinel_flags,
            sentinel_categories=sentinel_categories,
        )


def _arm_body(oracle: PhpObjectOracle, arm: str, *, prefix: bytes = b"") -> bytes:
    token = oracle.public_context()[f"{arm}_token"].encode("ascii")
    return prefix + b"action=demo&payload=" + token


def _receipt_headers(oracle: PhpObjectOracle) -> list[tuple[str, str]]:
    return [(PHP_OBJECT_RECEIPT_HEADER, oracle.private_expected_receipt)]


def _private_values(oracle: PhpObjectOracle) -> tuple[str, ...]:
    context = oracle.public_context()
    return (
        *oracle.private_redaction_values(),
        oracle.generation_id,
        context["attack_token"],
        context["control_token"],
    )


def test_policy_is_exact_bounded_and_redacted() -> None:
    policy = _policy()

    assert repr(policy) == "PhpObjectRewritePolicy(<redacted>)"
    assert policy.dispatch == (("form", "action", "demo"),)
    for kwargs in (
        {"method": "post"},
        {"path": "https://example.test/route"},
        {"path": "/route?x=1"},
        {"object_field": "payload[]"},
        {"dispatch": (("header", "action", "demo"),)},
        {"dispatch": (("form", "payload", "demo"),)},
        {"dispatch": (("form", "a.b", "demo"),)},
    ):
        with pytest.raises(ValueError):
            _policy(**kwargs)  # type: ignore[arg-type]


def test_constructor_requires_one_unfinished_oracle_and_matching_policy() -> None:
    oracle = _oracle()
    with pytest.raises(ValueError, match="configured together"):
        PocProxySupervisor(
            _ORIGIN,
            trace_token="token",
            php_object_oracle=oracle,
        )
    with pytest.raises(ValueError, match="inert PHP object transport"):
        PocProxySupervisor(
            _ORIGIN,
            trace_token="token",
            credential_free=True,
            php_object_oracle=oracle,
            php_object_policy=_policy(),
            php_object_surface_attestor=_unchanged_surface,
        )
    with pytest.raises(ValueError, match="surface attestor is required"):
        PocProxySupervisor(
            _ORIGIN,
            trace_token="token",
            php_object_oracle=oracle,
            php_object_policy=_policy(),
        )

    context = oracle.public_context()
    started_ns = time.monotonic_ns()
    oracle.attest_execution(
        generation_id=oracle.generation_id,
        attack_token=context["attack_token"],
        control_token=context["control_token"],
        attack_receipt=oracle.private_expected_receipt,
        control_receipt=None,
        execution_started_monotonic_ns=started_ns,
        execution_finished_monotonic_ns=started_ns,
        attested_monotonic_ns=time.monotonic_ns(),
    )
    with pytest.raises(ValueError, match="already finalized"):
        PocProxySupervisor(
            _ORIGIN,
            trace_token="token",
            php_object_oracle=oracle,
            php_object_policy=_policy(),
            php_object_surface_attestor=_unchanged_surface,
        )


@pytest.mark.asyncio
async def test_exact_attack_and_control_rewrite_wire_bytes_and_take_observation() -> (
    None
):
    oracle = _oracle()
    private_values = _private_values(oracle)
    unrelated = b"keep=%2f%2F+literal&"
    proxy = _RecordingProxy(
        oracle,
        [(_receipt_headers(oracle), b"attack ok"), ([], b"control ok")],
    )

    attack = await _execute(proxy, _arm_body(oracle, "attack", prefix=unrelated))
    control = await _execute(proxy, _arm_body(oracle, "control", prefix=unrelated))

    assert attack[0] is not None and control[0] is not None
    assert proxy.php_object_complete is True
    assert len(proxy.forwarded) == 2
    expected_attack = (
        unrelated
        + b"action=demo&payload="
        + quote_from_bytes(oracle.private_attack_payload, safe="").encode("ascii")
    )
    expected_control = (
        unrelated
        + b"action=demo&payload="
        + quote_from_bytes(oracle.private_control_payload, safe="").encode("ascii")
    )
    assert proxy.forwarded[0]["body"] == expected_attack
    assert proxy.forwarded[1]["body"] == expected_control
    assert proxy.forwarded[0]["request_digest"] == canonical_request_digest(
        "POST", _PATH, expected_attack
    )
    assert proxy.forwarded[1]["request_digest"] == canonical_request_digest(
        "POST", _PATH, expected_control
    )
    for forwarded in proxy.forwarded:
        assert forwarded["credential_free_headers"] is None
        forwarded_headers = forwarded["headers"]
        assert ("User-Agent", "authored-client") in forwarded_headers

    records = proxy.trace_records
    assert [record["php_object_arm"] for record in records] == [
        "attack",
        "control",
    ]
    assert records[0]["php_object_original_envelope_sha256"] == records[1][
        "php_object_original_envelope_sha256"
    ]
    assert records[0]["request_digest"] != records[1]["request_digest"]
    assert records[0]["response_php_object_receipt_present"] is True
    assert records[0]["response_php_object_receipt_sha256"] == hashlib.sha256(
        oracle.private_expected_receipt.encode("ascii")
    ).hexdigest()
    assert records[1]["response_php_object_receipt_present"] is False

    serialized_records = json.dumps(records, sort_keys=True)
    assert all(value not in serialized_records for value in private_values)
    observation = proxy.take_php_object_observation()
    assert isinstance(observation, PhpObjectProxyObservation)
    assert repr(observation) == "PhpObjectProxyObservation(<redacted>)"
    assert observation.generation_id == oracle.generation_id
    assert observation.attack_receipt == oracle.private_expected_receipt
    assert observation.control_receipt is None
    assert proxy.take_php_object_observation() is None


@pytest.mark.asyncio
async def test_authenticated_arms_preserve_credentials_and_bind_header_parity() -> None:
    oracle = _oracle()
    credentials = (
        ("Cookie", "wordpress_logged_in=opaque-session"),
        ("Authorization", "Basic opaque-authorization"),
    )
    proxy = _RecordingProxy(
        oracle,
        [(_receipt_headers(oracle), b"attack"), ([], b"control")],
    )

    attack = await _execute(
        proxy,
        _arm_body(oracle, "attack"),
        extra_headers=credentials,
    )
    control = await _execute(
        proxy,
        _arm_body(oracle, "control"),
        extra_headers=credentials,
    )

    assert attack[0] is not None and control[0] is not None
    assert proxy.php_object_complete is True
    for forwarded in proxy.forwarded:
        assert all(header in forwarded["headers"] for header in credentials)

    drift_oracle = _oracle()
    drift_proxy = _RecordingProxy(
        drift_oracle,
        [(_receipt_headers(drift_oracle), b"attack"), ([], b"unused")],
    )
    assert (
        await _execute(
            drift_proxy,
            _arm_body(drift_oracle, "attack"),
            extra_headers=(("Cookie", "session=one"),),
        )
    )[0] is not None
    drift = await _execute(
        drift_proxy,
        _arm_body(drift_oracle, "control"),
        extra_headers=(("Cookie", "session=two"),),
    )
    assert drift[0] is None
    assert drift_proxy.fatal_error == "php_object_arm_envelope_mismatch"
    assert len(drift_proxy.forwarded) == 1


@pytest.mark.parametrize(
    "body_template",
    [
        b"action=demo&&payload={token}",
        b"action=demo&broken&payload={token}",
        b"action=demo=other&payload={token}",
        b"action=%GG&payload={token}",
        b"action=demo&payload={token}&",
        b"action=demo&pay%00load=x&payload={token}",
    ],
)
@pytest.mark.asyncio
async def test_malformed_form_shapes_fail_before_forwarding(
    body_template: bytes,
) -> None:
    oracle = _oracle()
    token = oracle.public_context()["attack_token"].encode("ascii")
    proxy = _RecordingProxy(oracle, [(_receipt_headers(oracle), b"ok")])

    response, _body, status, detail = await _execute(
        proxy, body_template.replace(b"{token}", token)
    )

    assert response is None
    assert (status, detail) == (403, "PHP object request was rejected")
    assert proxy.forwarded == []
    assert proxy.fatal_error is not None


@pytest.mark.parametrize(
    "body_builder",
    [
        lambda token: b"action=demo&payload=x&payload=" + token,
        lambda token: b"action=demo&payload%5B%5D=" + token,
        lambda token: b"action=demo&pay.load=" + token,
        lambda token: b"action=demo&payload=" + token + b"&other=" + token,
        lambda token: b"action=demo&action=demo&payload=" + token,
        lambda token: b"action=wrong&payload=" + token,
        lambda token: b"action=demo&payload=" + token.replace(b"s", b"%2573", 1),
    ],
)
@pytest.mark.asyncio
async def test_alias_duplicate_dispatch_and_token_smuggling_are_rejected(
    body_builder: Any,
) -> None:
    oracle = _oracle()
    token = oracle.public_context()["attack_token"].encode("ascii")
    proxy = _RecordingProxy(oracle, [(_receipt_headers(oracle), b"ok")])

    response, _body, status, _detail = await _execute(proxy, body_builder(token))

    assert response is None
    assert status == 403
    assert proxy.forwarded == []


@pytest.mark.asyncio
async def test_php_dot_space_and_bracket_destination_aliases_are_rejected() -> None:
    for aliased_name in (b"pay.load", b"pay+load", b"pay_load%5Bvalue%5D"):
        oracle = _oracle()
        token = oracle.public_context()["attack_token"].encode("ascii")
        proxy = _RecordingProxy(
            oracle,
            [(_receipt_headers(oracle), b"unused")],
            policy=_policy(object_field="pay_load"),
        )

        result = await _execute(
            proxy,
            b"action=demo&" + aliased_name + b"=" + token,
        )

        assert result[0] is None
        assert result[2] == 403
        assert proxy.fatal_error == "php_object_protected_field_alias"


@pytest.mark.parametrize(
    "raw_target",
    [
        _PATH + "?payload={token}",
        _PATH + "?pay%6coad={token}",
    ],
)
@pytest.mark.asyncio
async def test_destination_token_is_rejected_from_query(raw_target: str) -> None:
    oracle = _oracle()
    token = oracle.public_context()["attack_token"]
    proxy = _RecordingProxy(oracle, [(_receipt_headers(oracle), b"ok")])

    result = await _execute(
        proxy,
        b"action=demo&payload=benign",
        raw_target=raw_target.format(token=token),
    )

    assert result[0] is None
    assert result[2] == 403
    assert proxy.forwarded == []


@pytest.mark.parametrize(
    "encoded_object",
    [
        b'O:8:"stdClass":0:{}',
        quote_from_bytes(b'O:8:"stdClass":0:{}', safe="").encode("ascii"),
        quote_from_bytes(b'O:8:"stdClass":0:{}', safe="").encode("ascii") + b"%",
        quote_from_bytes(
            quote_from_bytes(b'O:8:"stdClass":0:{}', safe="").encode("ascii"),
            safe="",
        ).encode("ascii"),
        base64.b64encode(b'O:8:"stdClass":0:{}'),
        b'O:8:"stdClass":0:{}'.hex().encode("ascii"),
        base64.b64encode(base64.b64encode(b'C:4:"Demo":0:{}')),
    ],
)
@pytest.mark.asyncio
async def test_child_supplied_object_material_is_rejected_in_nested_encodings(
    encoded_object: bytes,
) -> None:
    oracle = _oracle()
    proxy = _RecordingProxy(oracle, [([], b"unused")])

    result = await _execute(proxy, b"action=demo&value=" + encoded_object)

    assert result[0] is None
    assert result[2] == 403
    assert proxy.fatal_error == "php_object_child_serialization_rejected"
    assert proxy.forwarded == []


@pytest.mark.asyncio
async def test_exact_method_route_and_query_dispatch_are_enforced() -> None:
    oracle = _oracle()
    token = oracle.public_context()["attack_token"].encode("ascii")
    policy = _policy(dispatch=(("query", "action", "demo"),))
    proxy = _RecordingProxy(
        oracle,
        [(_receipt_headers(oracle), b"ok")],
        policy=policy,
    )

    success = await _execute(
        proxy,
        b"payload=" + token,
        raw_target=_PATH + "?action=demo",
    )

    assert success[0] is not None
    assert len(proxy.forwarded) == 1

    for method, target in (("GET", _PATH + "?action=demo"), ("POST", "/other")):
        failed_oracle = _oracle()
        failed_proxy = _RecordingProxy(
            failed_oracle,
            [(_receipt_headers(failed_oracle), b"unused")],
            policy=policy,
        )
        failed_token = failed_oracle.public_context()["attack_token"].encode("ascii")
        result = await _execute(
            failed_proxy,
            b"payload=" + failed_token,
            method=method,
            raw_target=target,
        )
        assert result[0] is None
        assert failed_proxy.forwarded == []


@pytest.mark.asyncio
async def test_attack_must_be_first_and_control_must_be_immediate() -> None:
    control_first_oracle = _oracle()
    control_first = _RecordingProxy(control_first_oracle, [([], b"unused")])
    result = await _execute(
        control_first, _arm_body(control_first_oracle, "control")
    )
    assert result[0] is None
    assert control_first.fatal_error == "php_object_control_out_of_order"

    oracle = _oracle()
    proxy = _RecordingProxy(
        oracle,
        [(_receipt_headers(oracle), b"attack ok"), ([], b"unused")],
    )
    assert (await _execute(proxy, _arm_body(oracle, "attack")))[0] is not None
    interrupted = await _execute(proxy, b"action=demo&payload=benign")
    assert interrupted[0] is None
    assert proxy.fatal_error == "php_object_control_not_immediate"
    assert proxy.php_object_complete is False
    assert proxy.take_php_object_observation() is None


@pytest.mark.asyncio
async def test_benign_preproof_requests_are_allowed_before_ordered_arms() -> None:
    oracle = _oracle()
    proxy = _RecordingProxy(
        oracle,
        [
            ([], b"nonce bootstrap"),
            (_receipt_headers(oracle), b"attack"),
            ([], b"control"),
        ],
    )

    preproof = await _execute(
        proxy,
        b"",
        method="GET",
        raw_target="/wp-login.php",
    )
    attack = await _execute(proxy, _arm_body(oracle, "attack"))
    control = await _execute(proxy, _arm_body(oracle, "control"))

    assert all(result[0] is not None for result in (preproof, attack, control))
    assert [record["php_object_arm"] for record in proxy.trace_records] == [
        None,
        "attack",
        "control",
    ]
    assert proxy.php_object_complete is True


@pytest.mark.parametrize(
    ("method", "target"),
    [
        ("GET", "/wp-login.php"),
        ("HEAD", "/wp-admin/"),
        ("GET", "/wp-admin/admin-ajax.php?action=rest-nonce"),
        ("GET", "/?rest_route=/wp/v2/users/me&context=edit"),
    ],
)
@pytest.mark.asyncio
async def test_token_free_preflight_allows_only_bounded_unambiguous_reads(
    method: str,
    target: str,
) -> None:
    oracle = _oracle()
    proxy = _RecordingProxy(oracle, [([], b"bootstrap")])

    result = await _execute(proxy, b"", method=method, raw_target=target)

    assert result[0] is not None
    assert proxy.trace_records[0]["php_object_arm"] is None
    assert proxy.forwarded[0]["body"] == b""


@pytest.mark.asyncio
async def test_token_free_preflight_rejects_and_redacts_unexpected_receipt() -> None:
    oracle = _oracle()
    proxy = _RecordingProxy(
        oracle,
        [(_receipt_headers(oracle), b"bootstrap response")],
    )

    response, response_body, status, reason = await _execute(
        proxy,
        b"",
        method="GET",
        raw_target="/wp-login.php",
    )

    assert response is None
    assert response_body == b""
    assert status == 502
    assert reason == "trusted response header is invalid"
    assert proxy.fatal_error == "unexpected_php_object_receipt"
    rendered_trace = json.dumps(proxy.records, sort_keys=True)
    for private_value in _private_values(oracle):
        assert private_value not in rendered_trace


@pytest.mark.parametrize(
    ("method", "target", "body"),
    [
        ("POST", "/plugin-mutation", b"action=change&value=benign"),
        ("PUT", "/wp-login.php", b""),
        ("DELETE", "/resource", b""),
        ("GET", "/bootstrap", b"nonempty"),
        ("GET", "/bootstrap?x=1&x=2", b""),
        ("GET", "/bootstrap?x.y=1&x_y=2", b""),
        ("GET", "/bootstrap?item%5B0%5D=1", b""),
        ("GET", "/bootstrap?redirect_to=/plugin-mutation", b""),
        ("GET", "/bootstrap?", b""),
    ],
)
@pytest.mark.asyncio
async def test_token_free_preflight_rejects_mutation_redirects_and_aliases(
    method: str,
    target: str,
    body: bytes,
) -> None:
    oracle = _oracle()
    proxy = _RecordingProxy(oracle, [([], b"unused")])

    result = await _execute(proxy, body, method=method, raw_target=target)

    assert result[0] is None
    assert result[2] == 403
    assert proxy.forwarded == []
    assert proxy.fatal_error is not None


@pytest.mark.asyncio
async def test_preflight_count_and_login_post_are_bounded() -> None:
    oracle = _oracle()
    proxy = _RecordingProxy(oracle, [([], b"ok")] * 17)
    for _index in range(16):
        assert (
            await _execute(proxy, b"", method="GET", raw_target="/wp-login.php")
        )[0] is not None

    overflow = await _execute(
        proxy,
        b"",
        method="GET",
        raw_target="/wp-login.php",
    )
    assert overflow[0] is None
    assert proxy.fatal_error == "php_object_preflight_request_limit_exceeded"
    assert len(proxy.forwarded) == 16

    login_oracle = _oracle()
    login_proxy = _RecordingProxy(login_oracle, [([], b"ok"), ([], b"unused")])
    assert (
        await _execute(login_proxy, _login_body(), raw_target="/wp-login.php")
    )[0] is not None
    replay = await _execute(
        login_proxy,
        _login_body(),
        raw_target="/wp-login.php",
    )
    assert replay[0] is None
    assert login_proxy.fatal_error == "php_object_login_preflight_replayed"
    assert len(login_proxy.forwarded) == 1


def _login_body(*, redirect: bytes | None = None) -> bytes:
    redirect_value = (
        b"http%3A%2F%2Flocalhost%3A8123%2Fwp-admin%2F"
        if redirect is None
        else redirect
    )
    return (
        b"log=verified_login&pwd=verified_password&wp-submit=Log+In"
        b"&redirect_to="
        + redirect_value
        + b"&testcookie=1"
    )


@pytest.mark.asyncio
async def test_exact_standard_wordpress_login_post_is_the_only_mutating_preflight() -> (
    None
):
    oracle = _oracle()
    login_body = _login_body()
    proxy = _RecordingProxy(
        oracle,
        [([], b"login redirect"), (_receipt_headers(oracle), b"attack")],
    )

    login = await _execute(proxy, login_body, raw_target="/wp-login.php")
    attack = await _execute(proxy, _arm_body(oracle, "attack"))

    assert login[0] is not None and attack[0] is not None
    assert proxy.forwarded[0]["body"] == login_body
    assert proxy.trace_records[0]["php_object_arm"] is None
    serialized = json.dumps(proxy.trace_records[0], sort_keys=True)
    assert "verified_login" not in serialized
    assert "verified_password" not in serialized


@pytest.mark.parametrize(
    "login_body",
    [
        b"log=user&pwd=password&wp-submit=Log+In&testcookie=1",
        _login_body() + b"&extra=1",
        _login_body() + b"&log=other",
        _login_body(redirect=b"http%3A%2F%2Fevil.example%2Fwp-admin%2F"),
        _login_body(redirect=b"http%3A%2F%2Flocalhost%3A8123%2Fplugin%2F"),
        _login_body(redirect=b"http%3A%2F%2Flocalhost%3A8123%2Fwp-admin%2F%3Fx%3D1"),
        _login_body().replace(b"testcookie=1", b"testcookie=0"),
        _login_body().replace(b"wp-submit=Log+In", b"wp-submit=Login"),
        _login_body().replace(b"log=verified_login", b"log="),
        _login_body().replace(b"pwd=verified_password", b"pwd="),
    ],
)
@pytest.mark.asyncio
async def test_login_preflight_rejects_shape_value_and_redirect_drift(
    login_body: bytes,
) -> None:
    oracle = _oracle()
    proxy = _RecordingProxy(oracle, [([], b"unused")])

    result = await _execute(proxy, login_body, raw_target="/wp-login.php")

    assert result[0] is None
    assert result[2] == 403
    assert proxy.forwarded == []


@pytest.mark.asyncio
async def test_surface_attestor_brackets_each_arm_in_exact_order() -> None:
    oracle = _oracle()
    calls: list[tuple[str, str]] = []

    async def attest(phase: PhpObjectSurfacePhase, arm: PhpObjectArm) -> None:
        calls.append((phase, arm))

    proxy = _RecordingProxy(
        oracle,
        [(_receipt_headers(oracle), b"attack"), ([], b"control")],
        surface_attestor=attest,
    )

    await _execute(proxy, _arm_body(oracle, "attack"))
    await _execute(proxy, _arm_body(oracle, "control"))

    assert calls == [
        ("before", "attack"),
        ("after", "attack"),
        ("before", "control"),
        ("after", "control"),
    ]
    assert proxy.php_object_complete is True


@pytest.mark.parametrize("failed_phase", ["before", "after"])
@pytest.mark.asyncio
async def test_surface_attestation_failure_is_stable_redacted_and_fail_closed(
    failed_phase: str,
) -> None:
    oracle = _oracle()
    calls: list[tuple[str, str]] = []

    async def fail(phase: PhpObjectSurfacePhase, arm: PhpObjectArm) -> None:
        calls.append((phase, arm))
        if phase == failed_phase:
            raise RuntimeError("private surface path and digest")

    proxy = _RecordingProxy(
        oracle,
        [(_receipt_headers(oracle), b"attack")],
        surface_attestor=fail,
    )

    result = await _execute(proxy, _arm_body(oracle, "attack"))

    assert result[0] is None
    assert result[2:] == (502, "PHP object surface attestation failed")
    assert proxy.fatal_error == "php_object_surface_attestation_failed"
    assert proxy.php_object_complete is False
    assert len(proxy.forwarded) == (0 if failed_phase == "before" else 1)
    serialized = json.dumps(proxy.trace_records, sort_keys=True)
    assert "private surface path" not in serialized


@pytest.mark.asyncio
async def test_after_surface_check_runs_only_after_receipt_validation() -> None:
    oracle = _oracle()
    calls: list[tuple[str, str]] = []

    async def attest(phase: PhpObjectSurfacePhase, arm: PhpObjectArm) -> None:
        calls.append((phase, arm))

    proxy = _RecordingProxy(
        oracle,
        [([], b"missing receipt")],
        surface_attestor=attest,
    )

    result = await _execute(proxy, _arm_body(oracle, "attack"))

    assert result[0] is None
    assert proxy.fatal_error == "missing_php_object_receipt"
    assert calls == [("before", "attack")]


@pytest.mark.asyncio
async def test_surface_attestor_rejects_non_async_or_value_returning_callbacks() -> (
    None
):
    async def returns_value(
        phase: PhpObjectSurfacePhase,
        arm: PhpObjectArm,
    ) -> None:
        del phase, arm
        return False  # type: ignore[return-value]

    for attestor in (returns_value, lambda _phase, _arm: None):
        oracle = _oracle()
        proxy = _RecordingProxy(
            oracle,
            [(_receipt_headers(oracle), b"unused")],
            surface_attestor=attestor,
        )

        result = await _execute(proxy, _arm_body(oracle, "attack"))

        assert result[0] is None
        assert proxy.fatal_error == "php_object_surface_attestation_failed"
        assert proxy.forwarded == []


@pytest.mark.asyncio
async def test_cancelled_surface_attestation_latches_the_same_stable_failure() -> None:
    async def cancel(
        phase: PhpObjectSurfacePhase,
        arm: PhpObjectArm,
    ) -> None:
        del phase, arm
        raise asyncio.CancelledError

    oracle = _oracle()
    proxy = _RecordingProxy(
        oracle,
        [(_receipt_headers(oracle), b"unused")],
        surface_attestor=cancel,
    )

    with pytest.raises(asyncio.CancelledError):
        await _execute(proxy, _arm_body(oracle, "attack"))

    assert proxy.fatal_error == "php_object_surface_attestation_failed"
    assert proxy.forwarded == []
    assert proxy.php_object_complete is False


@pytest.mark.asyncio
async def test_serialization_lock_orders_concurrent_attack_and_control() -> None:
    oracle = _oracle()
    proxy = _RecordingProxy(
        oracle,
        [(_receipt_headers(oracle), b"attack ok"), ([], b"control ok")],
        delay=0.01,
    )

    attack_task = asyncio.create_task(_execute(proxy, _arm_body(oracle, "attack")))
    await asyncio.sleep(0)
    control_task = asyncio.create_task(_execute(proxy, _arm_body(oracle, "control")))
    attack, control = await asyncio.gather(attack_task, control_task)

    assert attack[0] is not None and control[0] is not None
    assert proxy.php_object_complete is True
    assert [record["php_object_arm"] for record in proxy.trace_records] == [
        "attack",
        "control",
    ]


@pytest.mark.parametrize(
    ("attack_headers", "expected_error"),
    [
        ([], "missing_php_object_receipt"),
        (
            [(PHP_OBJECT_RECEIPT_HEADER, "not-a-receipt")],
            "malformed_php_object_receipt",
        ),
        (
            [(PHP_OBJECT_RECEIPT_HEADER, "sqpobj1." + "0" * 64 + "." + "1" * 64)],
            "mismatched_php_object_receipt",
        ),
        (
            [
                (PHP_OBJECT_RECEIPT_HEADER, "sqpobj1." + "0" * 64 + "." + "1" * 64),
                (PHP_OBJECT_RECEIPT_HEADER, "sqpobj1." + "2" * 64 + "." + "3" * 64),
            ],
            "duplicate_php_object_receipt",
        ),
    ],
)
@pytest.mark.asyncio
async def test_attack_requires_one_exact_private_receipt(
    attack_headers: list[tuple[str, str]],
    expected_error: str,
) -> None:
    oracle = _oracle()
    proxy = _RecordingProxy(oracle, [(attack_headers, b"response")])

    result = await _execute(proxy, _arm_body(oracle, "attack"))

    assert result[0] is None
    assert result[2:] == (502, "trusted response header is invalid")
    assert proxy.fatal_error == expected_error
    serialized = json.dumps(proxy.trace_records)
    assert all(value not in serialized for _name, value in attack_headers)


@pytest.mark.asyncio
async def test_control_receipt_replay_and_post_control_request_fail_closed() -> None:
    replay_oracle = _oracle()
    replay_proxy = _RecordingProxy(
        replay_oracle,
        [
            (_receipt_headers(replay_oracle), b"attack"),
            (_receipt_headers(replay_oracle), b"control"),
        ],
    )
    assert (
        await _execute(replay_proxy, _arm_body(replay_oracle, "attack"))
    )[0] is not None
    replay = await _execute(replay_proxy, _arm_body(replay_oracle, "control"))
    assert replay[0] is None
    assert replay_proxy.fatal_error == "control_php_object_receipt_present"

    oracle = _oracle()
    proxy = _RecordingProxy(
        oracle,
        [(_receipt_headers(oracle), b"attack"), ([], b"control"), ([], b"late")],
    )
    await _execute(proxy, _arm_body(oracle, "attack"))
    await _execute(proxy, _arm_body(oracle, "control"))
    late = await _execute(proxy, b"action=demo&payload=benign")
    assert late[0] is None
    assert proxy.fatal_error == "php_object_request_after_control"
    assert proxy.php_object_complete is False
    assert proxy.take_php_object_observation() is None


@pytest.mark.asyncio
async def test_private_material_reflection_fails_and_receipt_is_stripped_from_child() -> (
    None
):
    for reflected_body_factory in (
        lambda value: value.private_attack_payload,
        lambda value: base64.b64encode(value.private_receipt_secret),
    ):
        reflected_oracle = _oracle()
        reflected_proxy = _RecordingProxy(
            reflected_oracle,
            [
                (
                    _receipt_headers(reflected_oracle),
                    reflected_body_factory(reflected_oracle),
                )
            ],
        )
        reflected = await _execute(
            reflected_proxy, _arm_body(reflected_oracle, "attack")
        )
        assert reflected[0] is None
        assert reflected_proxy.fatal_error == "php_object_private_material_reflected"

    oracle = _oracle()
    proxy = _RecordingProxy(oracle, [(_receipt_headers(oracle), b"safe")])
    response, response_body, _status, _detail = await _execute(
        proxy, _arm_body(oracle, "attack")
    )
    assert response is not None
    writer = _MemoryWriter()
    await proxy._send_response(
        writer,  # type: ignore[arg-type]
        response,
        response_body,
    )
    assert PHP_OBJECT_RECEIPT_HEADER.casefold().encode("ascii") not in (
        writer.value.lower()
    )
    assert oracle.private_expected_receipt.encode("ascii") not in writer.value


@pytest.mark.asyncio
async def test_policy_disabled_preserves_existing_proxy_behavior() -> None:
    class _DisabledProxy(PocProxySupervisor):
        def __init__(self) -> None:
            super().__init__(
                _ORIGIN,
                trace_token="token",
                trace_salt=bytes.fromhex("31" * 32),
            )
            self.forwarded_body = b""

        async def _forward(
            self,
            method: str,
            url: str,
            headers: list[tuple[str, str]],
            body: bytes,
            nonce: str,
            request_digest: str,
            record: dict[str, object],
            *,
            credential_free_headers: list[tuple[str, str]] | None = None,
        ) -> tuple[httpx.Response, bytes]:
            del (
                method,
                url,
                headers,
                nonce,
                request_digest,
                record,
                credential_free_headers,
            )
            self.forwarded_body = body
            return httpx.Response(200, content=b"ok"), b"ok"

    proxy = _DisabledProxy()
    object_body = b'action=demo&payload=O:8:"stdClass":0:{}'

    result = await _execute(proxy, object_body)

    assert result[0] is not None
    assert proxy.forwarded_body == object_body
    assert "php_object_arm" not in proxy.trace_records[0]
