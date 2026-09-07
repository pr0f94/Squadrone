from __future__ import annotations

import hashlib
import time
from copy import deepcopy
from typing import Any

import httpx
import pytest

from squadrone.poc_proxy import (
    PHP_OBJECT_RECEIPT_HEADER,
    PhpObjectRewritePolicy,
    PocProxySupervisor,
    classify_request_sentinels,
)
from squadrone.schemas.php_object_gadget import (
    PhpObjectGadgetDirectPathEffectBinding,
    PhpObjectGadgetObject,
    PhpObjectGadgetProperty,
    PhpObjectGadgetRecipe,
    PhpObjectGadgetSourceAnchor,
    PhpObjectGadgetValue,
)
from squadrone.services.php_object_gadget_oracle import (
    PhpObjectGadgetOracle,
    PhpObjectGadgetRuntimeBinding,
    php_object_gadget_recipe_sha256,
)
from squadrone.services.php_object_oracle import PhpObjectOracle
from squadrone.services.sandbox import validate_php_object_gadget_http_trace


_ORIGIN = "http://localhost:8123"
_PATH = "/wp-admin/admin-ajax.php"
_TRACE_TOKEN = "53" * 32


def _recipe() -> PhpObjectGadgetRecipe:
    effect = PhpObjectGadgetSourceAnchor(
        file="gadget.php",
        line=4,
        source_code="unlink($this->path);",
    )
    return PhpObjectGadgetRecipe(
        gadget_object=PhpObjectGadgetObject(
            class_name="ReviewedGadget",
            class_anchor=PhpObjectGadgetSourceAnchor(
                file="gadget.php",
                line=1,
                source_code="class ReviewedGadget",
            ),
            trigger="__destruct",
            trigger_declaring_class="ReviewedGadget",
            trigger_anchor=PhpObjectGadgetSourceAnchor(
                file="gadget.php",
                line=3,
                source_code=("function __destruct() {\n    unlink($this->path);\n}"),
            ),
            properties=(
                PhpObjectGadgetProperty(
                    name="path",
                    declaring_class="ReviewedGadget",
                    visibility="public",
                    value=PhpObjectGadgetValue(
                        kind="capability",
                        capability="ephemeral_file_path",
                    ),
                ),
            ),
        ),
        effect_binding=PhpObjectGadgetDirectPathEffectBinding(
            effect_property="path",
            access="property",
            effect_anchor=effect,
        ),
    )


def _gadget_oracle() -> PhpObjectGadgetOracle:
    primitive = PhpObjectOracle(
        callsite_path="/var/www/html/wp-content/plugins/example/source.php",
        callsite_start_line=10,
        callsite_end_line=12,
        callsite_source_sha256="11" * 32,
        class_name="SquadroneObjectCanary_" + "a" * 32,
        receipt_secret=bytes.fromhex("22" * 32),
    )
    generation = primitive.begin_generation()
    context = primitive.public_context()
    now = time.monotonic_ns()
    primitive_snapshot = primitive.attest_execution(
        generation_id=generation,
        attack_token=context["attack_token"],
        control_token=context["control_token"],
        attack_receipt=primitive.private_expected_receipt,
        control_receipt=None,
        execution_started_monotonic_ns=now,
        execution_finished_monotonic_ns=now,
        attested_monotonic_ns=time.monotonic_ns(),
    )
    recipe = _recipe()
    oracle = PhpObjectGadgetOracle(
        recipe=recipe,
        primitive_snapshot=primitive_snapshot,
        attack_token=context["attack_token"],
        control_token=context["control_token"],
        runtime_binding=PhpObjectGadgetRuntimeBinding(
            schema_version=1,
            mode="php_object_gadget_file_delete",
            effect="file_delete",
            effect_binding_kind="direct_path",
            recipe_sha256=php_object_gadget_recipe_sha256(recipe),
            source_inventory_sha256="33" * 32,
            reflection_sha256="44" * 32,
            source_file_count=1,
            source_anchor_count=3,
            property_count=1,
            all_effect_sinks_accounted=True,
        ),
    )
    oracle.begin_generation()
    return oracle


def _policy(
    *,
    object_field: str = "payload",
    action: str = "demo",
) -> PhpObjectRewritePolicy:
    return PhpObjectRewritePolicy(
        method="POST",
        path=_PATH,
        object_location="form",
        object_field=object_field,
        dispatch=(("form", "action", action),),
    )


class _NaturalProxy(PocProxySupervisor):
    def __init__(
        self,
        oracle: PhpObjectGadgetOracle,
        *,
        gadget_attestor: Any,
        surface_attestor: Any,
        response_headers: list[tuple[str, str]] | None = None,
        policy: PhpObjectRewritePolicy | None = None,
    ) -> None:
        super().__init__(
            _ORIGIN,
            trace_token="trace-token",
            trace_salt=bytes.fromhex("55" * 32),
            php_object_gadget_oracle=oracle,
            php_object_policy=policy or _policy(),
            php_object_surface_attestor=surface_attestor,
            php_object_gadget_arm_attestor=gadget_attestor,
            credential_free=True,
        )
        self.forwarded: list[bytes] = []
        self.credential_free_headers: list[list[tuple[str, str]]] = []
        self.response_headers = response_headers or []

    async def _forward(self, *args: Any, **kwargs: Any) -> tuple[httpx.Response, bytes]:
        body = args[3]
        self.forwarded.append(body)
        self.credential_free_headers.append(kwargs["credential_free_headers"])
        return httpx.Response(200, headers=self.response_headers), b"ok"


async def _execute(  # type: ignore[no-untyped-def]
    proxy: PocProxySupervisor,
    body: bytes,
    *,
    method: str = "POST",
    raw_target: str = _PATH,
    extra_headers: list[tuple[str, str]] | None = None,
):
    headers = [("Host", "localhost:8123")]
    if body:
        headers.extend(
            [
                ("Content-Type", "application/x-www-form-urlencoded"),
                ("Content-Length", str(len(body))),
            ]
        )
    headers.extend(extra_headers or [])
    raw_headers = "\r\n".join(f"{name}: {value}" for name, value in headers)
    flags, categories = classify_request_sentinels(
        raw_target.encode("ascii"),
        raw_headers.encode("ascii"),
        body,
    )
    path = raw_target.partition("?")[0]
    async with proxy._forward_lock:
        return await proxy._execute_accepted_request(
            method=method,
            url=_ORIGIN + raw_target,
            path=path,
            raw_target=raw_target,
            headers=headers,
            body=body,
            sentinel_flags=flags,
            sentinel_categories=categories,
        )


def _arm_body(oracle: PhpObjectGadgetOracle, arm: str) -> bytes:
    token = oracle.public_context()[f"{arm}_token"].encode("ascii")
    return b"action=demo&payload=" + token


def _give_arm_body(oracle: PhpObjectGadgetOracle, arm: str, *, first: str) -> bytes:
    token = oracle.public_context()[f"{arm}_token"].encode("ascii")
    return (
        b"action=give_process_donation&give-form-id=17"
        b"&give-form-title=Community+Fund&give-amount=25.00"
        + b"&give_first="
        + first.encode("ascii")
        + b"&give_email=donor%40example.test&give_company_name="
        + token
    )


@pytest.mark.asyncio
async def test_natural_proxy_rewrites_both_arms_and_keeps_separate_timing() -> None:
    oracle = _gadget_oracle()
    calls: list[tuple[str, str, str]] = []

    async def gadget(phase: str, arm: str) -> None:
        calls.append(("gadget", phase, arm))

    async def surface(phase: str, arm: str) -> None:
        calls.append(("surface", phase, arm))

    proxy = _NaturalProxy(
        oracle,
        gadget_attestor=gadget,
        surface_attestor=surface,
    )
    assert (await _execute(proxy, _arm_body(oracle, "attack")))[2] == 0
    assert (await _execute(proxy, _arm_body(oracle, "control")))[2] == 0

    assert proxy.forwarded[0] != proxy.forwarded[1]
    assert b"O%3A" in proxy.forwarded[0]
    assert b"a%3A" in proxy.forwarded[1]
    assert (
        proxy.credential_free_headers
        == [
            [
                ("Accept", "*/*"),
                ("User-Agent", "Squadrone-Trusted-PoC/1"),
                ("Content-Type", "application/x-www-form-urlencoded"),
            ]
        ]
        * 2
    )
    assert [record["credential_free_transport"] for record in proxy.records] == [
        True,
        True,
    ]
    assert calls == [
        ("gadget", "before", "attack"),
        ("surface", "before", "attack"),
        ("surface", "after", "attack"),
        ("gadget", "after", "attack"),
        ("gadget", "before", "control"),
        ("surface", "before", "control"),
        ("surface", "after", "control"),
        ("gadget", "after", "control"),
    ]
    observation = proxy.take_php_object_gadget_observation()
    assert observation is not None
    assert proxy.take_php_object_gadget_observation() is None
    assert proxy.take_php_object_observation() is None


@pytest.mark.asyncio
async def test_natural_proxy_accepts_one_get_and_give_shaped_extra_form_fields() -> (
    None
):
    oracle = _gadget_oracle()

    async def unchanged(_phase: str, _arm: str) -> None:
        return None

    policy = _policy(
        object_field="give_company_name",
        action="give_process_donation",
    )
    proxy = _NaturalProxy(
        oracle,
        gadget_attestor=unchanged,
        surface_attestor=unchanged,
        policy=policy,
    )

    preflight = await _execute(proxy, b"", method="GET", raw_target="/donate/")
    attack = await _execute(proxy, _give_arm_body(oracle, "attack", first="Ada"))
    control = await _execute(proxy, _give_arm_body(oracle, "control", first="Ada"))

    assert all(result[0] is not None for result in (preflight, attack, control))
    accepted, reason, transport, _evidence = _validate_gadget_trace(
        oracle,
        proxy.records,
        policy=policy,
    )
    assert accepted is True, reason
    assert transport is not None
    assert transport.attack_sequence == 2
    assert transport.control_sequence == 3


@pytest.mark.asyncio
async def test_natural_proxy_rejects_changed_extra_form_value() -> None:
    oracle = _gadget_oracle()

    async def unchanged(_phase: str, _arm: str) -> None:
        return None

    policy = _policy(
        object_field="give_company_name",
        action="give_process_donation",
    )
    proxy = _NaturalProxy(
        oracle,
        gadget_attestor=unchanged,
        surface_attestor=unchanged,
        policy=policy,
    )

    attack = await _execute(proxy, _give_arm_body(oracle, "attack", first="Ada"))
    control = await _execute(proxy, _give_arm_body(oracle, "control", first="Grace"))

    assert attack[0] is not None
    assert control[0] is None and control[2] == 403
    assert proxy.fatal_error == "php_object_arm_envelope_mismatch"
    assert len(proxy.forwarded) == 1


@pytest.mark.asyncio
async def test_natural_proxy_rejects_login_and_additional_preflight_requests() -> None:
    async def unchanged(_phase: str, _arm: str) -> None:
        return None

    login_oracle = _gadget_oracle()
    login_proxy = _NaturalProxy(
        login_oracle,
        gadget_attestor=unchanged,
        surface_attestor=unchanged,
    )
    login_body = (
        b"log=user&pwd=password&wp-submit=Log+In"
        b"&redirect_to=http%3A%2F%2Flocalhost%3A8123%2Fwp-admin%2F"
        b"&testcookie=1"
    )
    login = await _execute(login_proxy, login_body, raw_target="/wp-login.php")
    assert login[0] is None and login[2] == 403
    assert login_proxy.fatal_error == "php_object_mutating_preflight_rejected"
    assert login_proxy.forwarded == []

    read_oracle = _gadget_oracle()
    read_proxy = _NaturalProxy(
        read_oracle,
        gadget_attestor=unchanged,
        surface_attestor=unchanged,
    )
    first = await _execute(read_proxy, b"", method="GET", raw_target="/donate/")
    extra = await _execute(read_proxy, b"", method="GET", raw_target="/nonce/")
    assert first[0] is not None
    assert extra[0] is None and extra[2] == 403
    assert read_proxy.fatal_error == "php_object_preflight_request_limit_exceeded"
    assert len(read_proxy.forwarded) == 1


@pytest.mark.parametrize(
    "header",
    [
        ("Cookie", "wordpress_logged_in=fake"),
        ("Authorization", "Bearer fake"),
    ],
)
@pytest.mark.asyncio
async def test_natural_proxy_rejects_raw_credentials(
    header: tuple[str, str],
) -> None:
    oracle = _gadget_oracle()

    async def unchanged(_phase: str, _arm: str) -> None:
        return None

    proxy = _NaturalProxy(
        oracle,
        gadget_attestor=unchanged,
        surface_attestor=unchanged,
    )
    result = await _execute(
        proxy,
        _arm_body(oracle, "attack"),
        extra_headers=[header],
    )

    assert result[0] is None and result[2] == 403
    assert proxy.fatal_error == "credential_capable_request"
    assert proxy.forwarded == []


@pytest.mark.asyncio
async def test_natural_proxy_rejects_undeclared_query_and_nonadjacent_arms() -> None:
    async def unchanged(_phase: str, _arm: str) -> None:
        return None

    query_oracle = _gadget_oracle()
    query_proxy = _NaturalProxy(
        query_oracle,
        gadget_attestor=unchanged,
        surface_attestor=unchanged,
    )
    query = await _execute(
        query_proxy,
        _arm_body(query_oracle, "attack"),
        raw_target=_PATH + "?extra=1",
    )
    assert query[0] is None and query[2] == 403
    assert query_proxy.fatal_error == "php_object_undeclared_query_field"
    assert query_proxy.forwarded == []

    adjacent_oracle = _gadget_oracle()
    adjacent_proxy = _NaturalProxy(
        adjacent_oracle,
        gadget_attestor=unchanged,
        surface_attestor=unchanged,
    )
    attack = await _execute(adjacent_proxy, _arm_body(adjacent_oracle, "attack"))
    interposed = await _execute(
        adjacent_proxy,
        b"",
        method="GET",
        raw_target="/donate/",
    )
    assert attack[0] is not None
    assert interposed[0] is None and interposed[2] == 403
    assert adjacent_proxy.fatal_error == "php_object_control_not_immediate"
    assert len(adjacent_proxy.forwarded) == 1


@pytest.mark.asyncio
async def test_natural_callback_failure_is_not_surface_drift() -> None:
    oracle = _gadget_oracle()

    async def fail(_phase: str, _arm: str) -> None:
        raise RuntimeError("private state mismatch")

    async def surface(_phase: str, _arm: str) -> None:
        return None

    proxy = _NaturalProxy(
        oracle,
        gadget_attestor=fail,
        surface_attestor=surface,
    )
    result = await _execute(proxy, _arm_body(oracle, "attack"))

    assert result[2] == 502
    assert proxy.fatal_error == "php_object_gadget_attestation_failed"
    assert proxy.forwarded == []


@pytest.mark.asyncio
async def test_natural_proxy_rejects_any_inert_canary_receipt() -> None:
    oracle = _gadget_oracle()

    async def unchanged(_phase: str, _arm: str) -> None:
        return None

    proxy = _NaturalProxy(
        oracle,
        gadget_attestor=unchanged,
        surface_attestor=unchanged,
        response_headers=[(PHP_OBJECT_RECEIPT_HEADER, "sqpobj1." + "1" * 129)],
    )
    result = await _execute(proxy, _arm_body(oracle, "attack"))

    assert result[2] == 502
    assert proxy.fatal_error == "natural_gadget_php_object_receipt_present"


def test_natural_and_inert_oracles_are_mutually_exclusive() -> None:
    gadget = _gadget_oracle()
    with pytest.raises(ValueError, match="mutually exclusive"):
        PocProxySupervisor(
            _ORIGIN,
            trace_token="token",
            php_object_oracle=object(),  # type: ignore[arg-type]
            php_object_gadget_oracle=gadget,
            php_object_policy=_policy(),
        )


def _gadget_trace_record(
    oracle: PhpObjectGadgetOracle,
    arm: str,
    sequence: int,
) -> dict[str, object]:
    request_nonce = f"{sequence:064x}"
    request_digest = f"{sequence + 16:064x}"
    record: dict[str, object] = {
        "trace_version": 1,
        "record_type": "request",
        "forward_state": "completed",
        "forward_error": None,
        "terminal": False,
        "origin": _ORIGIN,
        "method": "POST",
        "path": _PATH,
        "php_object_arm": arm,
        "php_object_generation_sha256": hashlib.sha256(
            oracle.generation_id.encode("ascii")
        ).hexdigest(),
        "sequence": sequence,
        "status_code": 200,
        "php_object_original_envelope_sha256": "aa" * 32,
        "php_object_rewritten_body_sha256": hashlib.sha256(
            oracle.private_attack_payload
            if arm == "attack"
            else oracle.private_control_payload
        ).hexdigest(),
        "response_php_object_receipt_present": False,
        "response_php_object_receipt_sha256": None,
        "fields": [
            {
                "location": "form",
                "name": "action",
                "kind": "scalar",
                "value_sha256": "33" * 32,
                "contains_squadrone_sentinel": False,
                "tracked_capabilities": [],
            },
            {
                "location": "form",
                "name": "payload",
                "kind": "scalar",
                "value_sha256": "44" * 32,
                "contains_squadrone_sentinel": False,
                "tracked_capabilities": ["ephemeral_file_path"],
            },
        ],
        "parameter_shape": [
            {"location": "form", "name": "action", "kind": "scalar", "count": 1},
            {"location": "form", "name": "payload", "kind": "scalar", "count": 1},
        ],
        "request_tracked_capabilities_in_headers": [],
        "request_nonce": request_nonce,
        "request_digest": request_digest,
        "credential_free_transport": True,
        "response_actor_receipt": "untrusted-in-process-receipt",
        "response_actor_receipt_truncated": False,
    }
    return record


def _add_extra_form_field(record: dict[str, object], value_sha256: str) -> None:
    fields = record["fields"]
    assert isinstance(fields, list)
    fields.append(
        {
            "location": "form",
            "name": "give_first",
            "kind": "scalar",
            "value_sha256": value_sha256,
            "contains_squadrone_sentinel": False,
            "tracked_capabilities": [],
        }
    )
    record["parameter_shape"] = [
        {"location": "form", "name": "action", "kind": "scalar", "count": 1},
        {
            "location": "form",
            "name": "give_first",
            "kind": "scalar",
            "count": 1,
        },
        {"location": "form", "name": "payload", "kind": "scalar", "count": 1},
    ]


def _validate_gadget_trace(
    oracle: PhpObjectGadgetOracle,
    records: list[dict[str, object]],
    *,
    expected_attacker_role: str = "unauthenticated",
    poc_bundle_manifest_sha256: str = "bc" * 32,
    poc_bundle_source_file_count: int = 2,
    policy: PhpObjectRewritePolicy | None = None,
):  # type: ignore[no-untyped-def]
    return validate_php_object_gadget_http_trace(
        records,
        target_url=_ORIGIN,
        receipt_secret=b"not-used-by-natural-proof",
        trace_token=_TRACE_TOKEN,
        policy=policy or _policy(),
        oracle=oracle,
        script_sha256="bb" * 32,
        poc_bundle_manifest_sha256=poc_bundle_manifest_sha256,
        poc_bundle_source_file_count=poc_bundle_source_file_count,
        expected_attacker_role=expected_attacker_role,
        surface_attestations=(
            ("before", "attack"),
            ("after", "attack"),
            ("before", "control"),
            ("after", "control"),
        ),
        trace_error="",
    )


def test_natural_trace_binds_credential_free_transport_not_actor_receipt() -> None:
    oracle = _gadget_oracle()
    records = [
        _gadget_trace_record(oracle, "attack", 1),
        _gadget_trace_record(oracle, "control", 2),
    ]

    accepted, reason, transport, _evidence = _validate_gadget_trace(
        oracle,
        records,
    )

    assert accepted is True, reason
    assert transport is not None
    assert transport.script_sha256 == "bb" * 32
    assert transport.poc_bundle_manifest_sha256 == "bc" * 32
    assert transport.poc_bundle_source_file_count == 2
    assert transport.attack_sequence == 1
    assert transport.control_sequence == 2
    assert transport.actor_role == "unauthenticated"
    assert (
        transport.attack_payload_sha256
        == hashlib.sha256(oracle.private_attack_payload).hexdigest()
    )
    assert (
        transport.control_payload_sha256
        == hashlib.sha256(oracle.private_control_payload).hexdigest()
    )
    assert transport.attack_control_envelopes_equal is True
    assert transport.rewritten_payloads_differ is True
    assert transport.ephemeral_path_capability_exact is True
    assert transport.executable_surface_bound is True


def test_natural_trace_binds_extra_form_field_signatures() -> None:
    oracle = _gadget_oracle()
    attack = _gadget_trace_record(oracle, "attack", 1)
    control = _gadget_trace_record(oracle, "control", 2)
    _add_extra_form_field(attack, "55" * 32)
    _add_extra_form_field(control, "55" * 32)

    accepted, reason, transport, _evidence = _validate_gadget_trace(
        oracle,
        [attack, control],
    )
    assert accepted is True, reason
    assert transport is not None

    control_fields = control["fields"]
    assert isinstance(control_fields, list)
    extra = next(field for field in control_fields if field["name"] == "give_first")
    extra["value_sha256"] = "66" * 32
    accepted, reason, transport, evidence = _validate_gadget_trace(
        oracle,
        [attack, control],
    )
    assert accepted is False
    assert "attack/control binding" in reason
    assert transport is None
    assert evidence == {}


@pytest.mark.parametrize(
    "records",
    ["extra_preflight", "nonadjacent_arms", "preflight_after_attack"],
)
def test_natural_trace_rejects_extra_preflight_and_nonadjacent_arms(
    records: str,
) -> None:
    oracle = _gadget_oracle()
    attack = _gadget_trace_record(oracle, "attack", 1)
    control = _gadget_trace_record(oracle, "control", 2)
    if records == "extra_preflight":
        supplied = [
            {**attack, "php_object_arm": None},
            {**attack, "sequence": 2, "php_object_arm": None},
            {**attack, "sequence": 3},
            {**control, "sequence": 4},
        ]
    elif records == "nonadjacent_arms":
        supplied = [attack, {**control, "sequence": 3}]
    else:
        supplied = [attack, control, {**attack, "sequence": 3, "php_object_arm": None}]

    accepted, reason, transport, evidence = _validate_gadget_trace(
        oracle,
        supplied,
    )
    assert accepted is False
    assert "trace is incomplete" in reason
    assert transport is None
    assert evidence == {}


@pytest.mark.parametrize(
    ("manifest_sha256", "source_file_count"),
    (("not-a-digest", 2), ("bc" * 32, 0), ("bc" * 32, 33)),
)
def test_natural_trace_rejects_invalid_isolated_bundle_identity(
    manifest_sha256: str,
    source_file_count: int,
) -> None:
    oracle = _gadget_oracle()
    records = [
        _gadget_trace_record(oracle, "attack", 1),
        _gadget_trace_record(oracle, "control", 2),
    ]

    accepted, reason, transport, evidence = _validate_gadget_trace(
        oracle,
        records,
        poc_bundle_manifest_sha256=manifest_sha256,
        poc_bundle_source_file_count=source_file_count,
    )

    assert accepted is False
    assert "bundle identity is invalid" in reason
    assert transport is None
    assert evidence == {}


@pytest.mark.parametrize(
    ("mutation", "reason_fragment"),
    (
        ("replayed_request_nonce", "attack/control binding"),
        ("authenticated_role", "requires an unauthenticated actor"),
        ("credential_capable", "trace is malformed"),
        ("extra_auth_field", "request field shape is not exact"),
        ("extra_query_field", "undeclared query field"),
        ("capability_header", "path escaped its field"),
        ("extra_record", "HTTP trace is incomplete"),
    ),
)
def test_natural_trace_rejects_replay_role_capability_and_extra_record(
    mutation: str,
    reason_fragment: str,
) -> None:
    oracle = _gadget_oracle()
    attack = _gadget_trace_record(oracle, "attack", 1)
    control = _gadget_trace_record(oracle, "control", 2)
    records = [attack, control]
    if mutation == "replayed_request_nonce":
        control["request_nonce"] = attack["request_nonce"]
    elif mutation == "credential_capable":
        control["credential_free_transport"] = False
    elif mutation == "extra_auth_field":
        fields = control["fields"]
        assert isinstance(fields, list)
        fields.append(
            {
                "location": "form",
                "name": "api_key",
                "kind": "scalar",
                "value_sha256": "55" * 32,
                "contains_squadrone_sentinel": False,
                "tracked_capabilities": [],
            }
        )
    elif mutation == "extra_query_field":
        fields = control["fields"]
        assert isinstance(fields, list)
        fields.append(
            {
                "location": "query",
                "name": "extra",
                "kind": "scalar",
                "value_sha256": "55" * 32,
                "contains_squadrone_sentinel": False,
                "tracked_capabilities": [],
            }
        )
    elif mutation == "capability_header":
        attack["request_tracked_capabilities_in_headers"] = ["ephemeral_file_path"]
    elif mutation == "extra_record":
        extra = deepcopy(control)
        extra["sequence"] = 3
        records.append(extra)

    accepted, reason, transport, evidence = _validate_gadget_trace(
        oracle,
        records,
        expected_attacker_role=(
            "administrator" if mutation == "authenticated_role" else "unauthenticated"
        ),
    )

    assert accepted is False
    assert reason_fragment in reason
    assert transport is None
    assert evidence == {}
