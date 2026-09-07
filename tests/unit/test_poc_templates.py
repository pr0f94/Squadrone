from __future__ import annotations

import ast
from types import SimpleNamespace

import pytest

from squadrone.agents.poc_author import (
    _BUG_CLASS_TEMPLATE,
    _OPEN_CWE_TEMPLATE,
    _infer_injectable_parameter,
    _parse_entry_point_transport,
    _render_template,
    _select_template,
)
from squadrone.agents.prompts_io import load_prompt
from squadrone.schemas import (
    BugClass,
    CIAImpact,
    Confidence,
    Hypothesis,
    PoCObservation,
)
from squadrone.schemas.finding import PoCAttempt, PoCStatus


def test_all_poc_templates_render_as_valid_python() -> None:
    template_names = {*_BUG_CLASS_TEMPLATE.values(), _OPEN_CWE_TEMPLATE}

    for template_name in template_names:
        rendered = _render_template(
            template_name,
            bug_class="CWE-1234",
            target_url="http://127.0.0.1",
            ajax_action="test_action",
            injectable_param="id",
            test_username="subscriber_user",
            test_password="password",
            extra_params="",
            attacker_role="subscriber",
            request_method="POST",
            request_route="/wp-admin/admin-ajax.php",
            request_dispatch={"form:action": "test_action"},
            ssrf_attack_url=(
                "http://host.docker.internal:49152/_squadrone/ssrf/" + "ab" * 32
            ),
            ssrf_control_url=(
                "http://host.docker.internal:49152/_squadrone/ssrf/" + "cd" * 32
            ),
        )
        ast.parse(rendered, filename=template_name)


def test_entry_point_transport_parses_explicit_http_route_and_query_dispatch() -> None:
    assert _parse_entry_point_transport(
        "POST /wp-admin/admin.php?page=spiffy-calendar&tab=event_edit"
    ) == {
        "method": "POST",
        "route": "/wp-admin/admin.php",
        "dispatch": {
            "query:page": "spiffy-calendar",
            "query:tab": "event_edit",
        },
    }


@pytest.mark.parametrize(
    ("source", "taint_path", "sink_code", "expected"),
    [
        (
            "The get_content_url query parameter on the REST route",
            ["request", "wp_remote_get"],
            "wp_remote_get($url)",
            "get_content_url",
        ),
        (
            "Public POST data",
            ["$_POST['event_id']", "update_event"],
            "update_event($id)",
            "event_id",
        ),
        ("Request data", ["request", "sink"], "process($value)", "id"),
    ],
)
def test_injectable_parameter_seed_uses_only_explicit_structured_names(
    source: str,
    taint_path: list[str],
    sink_code: str,
    expected: str,
) -> None:
    hypothesis = Hypothesis(
        id="parameter-seed",
        specialist="injection_files",
        bug_class=BugClass.SSRF,
        entry_point="GET /wp-json/example/v1/fetch",
        file="plugin.php",
        line=20,
        sink="request sink",
        sink_code=sink_code,
        taint_path=taint_path,
        reasoning="A request reaches a protected server-side sink.",
        confidence=Confidence.HIGH,
        preconditions="subscriber",
        affected_versions="<= 1.0",
        evidence_summary={"source": source},
    )

    assert _infer_injectable_parameter(hypothesis) == expected


@pytest.mark.parametrize(
    ("entry_point", "route", "action"),
    [
        ("wp_ajax_update_record", "/wp-admin/admin-ajax.php", "update_record"),
        (
            "wp_ajax_nopriv_public_record",
            "/wp-admin/admin-ajax.php",
            "public_record",
        ),
        ("admin_post_save_record", "/wp-admin/admin-post.php", "save_record"),
        (
            "admin_post_nopriv_public_save",
            "/wp-admin/admin-post.php",
            "public_save",
        ),
    ],
)
def test_entry_point_transport_parses_wordpress_hook_forms(
    entry_point: str,
    route: str,
    action: str,
) -> None:
    assert _parse_entry_point_transport(entry_point) == {
        "method": "POST",
        "route": route,
        "dispatch": {"form:action": action},
    }


@pytest.mark.parametrize(
    "entry_point",
    [
        "update_record_callback",
        "POST https://example.test/wp-admin/admin.php?page=demo",
        "POST //example.test/wp-admin/admin.php?page=demo",
        "POST /wp-admin/admin.php?page=one&page=two",
        "POST /wp-admin/admin.php?page",
        "POST /a/../upload",
        "POST /a//upload",
        "POST /upload?name=%FF",
        "POST /upload?name=%00",
    ],
)
def test_entry_point_transport_falls_back_without_live_route_guesses(
    entry_point: str,
) -> None:
    parsed = _parse_entry_point_transport(entry_point)
    assert parsed == {"method": "", "route": "", "dispatch": {}}


@pytest.mark.asyncio
async def test_idor_author_seeds_transport_from_entry_point_structure() -> None:
    captured = {}

    class FakeRuntime:
        async def run(self, **kwargs):
            captured.update(kwargs)
            return SimpleNamespace(output="import requests\n")

    from squadrone.agents.poc_author import PoCAuthorAgent

    author = PoCAuthorAgent(FakeRuntime(), model="test-model")
    await author.write(
        hypothesis=Hypothesis(
            id="idor-http-entry",
            specialist="authorization_workflows",
            bug_class=BugClass.IDOR,
            entry_point=(
                "POST /wp-admin/admin.php?page=spiffy-calendar&tab=event_edit"
            ),
            file="plugin.php",
            line=20,
            sink="owner-unbound update",
            taint_path=["request object ID", "database update"],
            reasoning="A user can update a record owned by a different user.",
            confidence=Confidence.HIGH,
            preconditions="subscriber",
            affected_versions="<= 1.0",
        ),
        target_url="http://127.0.0.1:8100",
        previous_attempts=[],
    )

    author_input = captured["messages"][1]["content"]
    assert 'METHOD = "POST"' in author_input
    assert 'ROUTE = "/wp-admin/admin.php"' in author_input
    assert '"query:page": "spiffy-calendar"' in author_input
    assert '"query:tab": "event_edit"' in author_input
    assert 'ACTION = "POST /wp-admin/admin.php' not in author_input


def test_idor_template_is_fail_closed_and_does_not_probe_candidate_ids() -> None:
    rendered = _render_template(
        "idor.py.j2",
        target_url="http://127.0.0.1",
        ajax_action="test_action",
        injectable_param="id",
        test_username="subscriber_user",
        test_password="password",
        extra_params="",
        attacker_role="subscriber",
        request_method="POST",
        request_route="/wp-admin/admin.php",
        request_dispatch={
            "query:page": "spiffy-calendar",
            "query:tab": "event_edit",
        },
    )

    assert "candidate_ids" not in rendered
    assert 'verdict="not_vulnerable"' in rendered
    assert '"object_id": ATTACK_OBJECT_ID' in rendered
    assert '"object_id": CONTROL_OBJECT_ID' in rendered
    assert '"control_basis": CONTROL_BASIS' in rendered
    assert '"legitimate_access_succeeded"' in rendered
    assert '"observed": False if' not in rendered
    assert 'METHOD = "POST"' in rendered
    assert 'ROUTE = "/wp-admin/admin.php"' in rendered
    assert '"query:page": "spiffy-calendar"' in rendered
    assert '"query:tab": "event_edit"' in rendered
    assert 'ACTION = "POST /wp-admin/admin.php' not in rendered
    assert '"object_location": "form"' in rendered
    assert '"dispatch": DISPATCH' in rendered
    assert '"object_value_template": ""' in rendered
    assert '"marker_field": ""' in rendered
    assert '"owner_field": ""' in rendered
    assert '"csrf_fields": []' in rendered
    assert 'OBJECT_PROVENANCE = ""' in rendered
    assert "OWNER_FILTERED_COLLECTION_PROTECTION_REQUEST_FINGERPRINT" in rendered
    assert "OBJECT_BOUND_PROTECTION_REQUEST_FINGERPRINT" in rendered
    assert "attack_write_measurements" in rendered
    assert "control_write_measurements" in rendered
    assert '**(attack_write_measurements if ACCESS_TYPE == "write" else {})' in rendered
    assert (
        '**(control_write_measurements if ACCESS_TYPE == "write" else {})' in rendered
    )

    tree = ast.parse(rendered)
    assignments = {
        node.targets[0].id: node.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
    }

    collection_protection = assignments[
        "OWNER_FILTERED_COLLECTION_PROTECTION_REQUEST_FINGERPRINT"
    ]
    object_protection = assignments["OBJECT_BOUND_PROTECTION_REQUEST_FINGERPRINT"]
    assert isinstance(collection_protection, ast.Dict)
    assert isinstance(object_protection, ast.Dict)
    collection_keys = {
        key.value for key in collection_protection.keys if isinstance(key, ast.Constant)
    }
    object_keys = {
        key.value for key in object_protection.keys if isinstance(key, ast.Constant)
    }
    assert collection_keys == {
        "scope",
        "method",
        "route",
        "dispatch",
        "csrf_fields",
    }
    assert "scope" in object_keys
    assert {
        "object_parameter",
        "object_type",
        "object_location",
    } <= object_keys

    for assignment_name, marker_name, before_name, after_name in (
        (
            "attack_write_measurements",
            "ATTACK_MARKER",
            "attack_before",
            "attack_after",
        ),
        (
            "control_write_measurements",
            "CONTROL_MARKER",
            "control_before",
            "control_after",
        ),
    ):
        measurements = assignments[assignment_name]
        assert isinstance(measurements, ast.Dict)
        values = {
            key.value: value
            for key, value in zip(measurements.keys, measurements.values, strict=True)
            if isinstance(key, ast.Constant)
        }
        assert {
            "write_effect",
            "baseline_marker",
            "before",
            "after",
            "write_marker_present_before",
            "write_marker_present_after",
            "observer_user_id",
            "observer_role",
            "observer_request_fingerprint",
        } <= values.keys()
        before_expression = ast.unparse(values["write_marker_present_before"])
        assert marker_name in before_expression
        assert before_name in before_expression
        assert "BASELINE" not in before_expression
        after_expression = ast.unparse(values["write_marker_present_after"])
        assert marker_name in after_expression
        assert after_name in after_expression
        assert "BASELINE" not in after_expression

    assert '"before_marker_present":' not in rendered
    assert '"after_marker_present":' not in rendered

    emit_call = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "emit_result"
    )
    keywords = {item.arg: item.value for item in emit_call.keywords if item.arg}
    attack = keywords["attack"]
    control = keywords["control"]
    assert isinstance(attack, ast.Dict)
    assert isinstance(control, ast.Dict)
    attack_keys = {key.value for key in attack.keys if isinstance(key, ast.Constant)}
    control_keys = {key.value for key in control.keys if isinstance(key, ast.Constant)}
    assert "control_basis" not in attack_keys
    assert "control_basis" in control_keys
    assert {
        "request_fingerprint",
        "object_provenance",
        "identity_verified",
        "owner_verified",
        "authorization_expected",
        "observed_value",
    } <= attack_keys & control_keys
    assert {"protection_basis", "protection_observed"} <= attack_keys
    assert {
        "protection_request_fingerprint",
        "owner_request_fingerprint",
    } <= attack_keys


def test_missing_authentication_uses_state_change_template() -> None:
    assert (
        _BUG_CLASS_TEMPLATE[BugClass.MISSING_AUTH_CRITICAL_FUNCTION.value]
        == "state_change.py.j2"
    )


@pytest.mark.parametrize("bug_class", ["CWE-1234", "CWE-9999"])
def test_unmapped_cwe_uses_one_generic_template(bug_class: str) -> None:
    assert _select_template(bug_class) == _OPEN_CWE_TEMPLATE


@pytest.mark.parametrize(
    "bug_class",
    [
        BugClass.OPEN_REDIRECT.value,
        BugClass.MISSING_RATE_LIMIT.value,
        BugClass.RESOURCE_EXHAUSTION.value,
    ],
)
def test_known_nonautomated_cwe_does_not_use_open_fallback(bug_class: str) -> None:
    assert _select_template(bug_class) is None


@pytest.mark.parametrize("bug_class", ["CWE-0", "CWE-01", "cwe-1234", "unknown"])
def test_invalid_cwe_does_not_use_open_fallback(bug_class: str) -> None:
    assert _select_template(bug_class) is None


def test_open_cwe_template_is_fail_closed_and_does_not_send_a_request() -> None:
    rendered = _render_template(
        _OPEN_CWE_TEMPLATE,
        bug_class="CWE-1234",
        target_url="http://127.0.0.1",
        request_method="POST",
        request_route="/wp-admin/admin-ajax.php",
        request_dispatch={"form:action": "example"},
        test_username="subscriber_user",
        test_password="password",
        attacker_role="subscriber",
    )

    ast.parse(rendered)
    assert 'BUG_CLASS = "CWE-1234"' in rendered
    assert 'verdict="not_vulnerable"' in rendered
    assert 'oracle="response_marker"' in rendered
    assert "session.get(" not in rendered
    assert "session.post(" not in rendered
    assert "session.request(" not in rendered


@pytest.mark.asyncio
async def test_open_cwe_author_receives_generic_cross_layer_guidance() -> None:
    captured = {}

    class FakeRuntime:
        async def run(self, **kwargs):
            captured.update(kwargs)
            return SimpleNamespace(output="import requests\n")

    from squadrone.agents.poc_author import PoCAuthorAgent

    author = PoCAuthorAgent(FakeRuntime(), model="test-model")
    script = await author.write(
        hypothesis=Hypothesis(
            id="open-cwe-test",
            specialist="authentication",
            bug_class=BugClass("CWE-1234"),
            entry_point="POST /wp-admin/admin-ajax.php?action=example",
            file="plugin.php",
            line=10,
            sink="protected operation",
            taint_path=["request", "protected operation"],
            reasoning="Untrusted input reaches a protected operation.",
            confidence=Confidence.HIGH,
            preconditions="subscriber",
            affected_versions="<= 1.0",
        ),
        target_url="http://127.0.0.1:8100",
        previous_attempts=[],
    )

    prompt = captured["messages"][1]["content"]
    assert script == "import requests"
    assert f"TEMPLATE ({_OPEN_CWE_TEMPLATE})" in prompt
    assert 'BUG_CLASS = "CWE-1234"' in prompt
    assert "OPEN-CWE FALLBACK" in prompt
    assert "do not infer an exploit shape from the CWE number alone" in prompt


def test_file_upload_template_measures_before_and_after_file_state() -> None:
    rendered = _render_template(
        "file_upload.py.j2",
        target_url="http://127.0.0.1",
        ajax_action="test_action",
        test_username="subscriber_user",
        test_password="password",
        attacker_role="subscriber",
    )

    assert rendered.index("attack_before =") < rendered.index("session.post(")
    assert rendered.index("control_before =") < rendered.index("session.post(")
    assert rendered.index("session.post(") < rendered.index("attack_after =")
    assert '"before_exists": attack_pre["exists"]' in rendered
    assert '"after_exists": attack_post["exists"]' in rendered
    assert '"before_sha256": attack_pre["sha256"]' in rendered
    assert '"marker_sha256": attack_post["sha256"]' in rendered
    assert '"before_exists": control_pre["exists"]' in rendered
    assert '"after_sha256": control_post["sha256"]' in rendered


@pytest.mark.asyncio
async def test_retry_prompt_includes_exact_validator_rejection(tmp_path) -> None:
    script_path = tmp_path / "iter_1.py"
    script_path.write_text("import requests\n")
    reported = PoCObservation(
        verdict="vulnerable",
        oracle="response_marker",
        attacker_role="unauthenticated",
        request={"method": "POST", "url": "http://127.0.0.1:8100/test"},
        attack={"observed": True, "marker": "child-claim", "marker_present": True},
        control={"observed": False, "marker_present": False},
        impact=CIAImpact(integrity="low", description="Child-declared effect."),
    )
    attempt = PoCAttempt(
        iteration=1,
        script_path=str(script_path),
        result=PoCStatus.FAILED,
        response_snippet=(
            "SQUADRONE_RESULT={\"verdict\":\"vulnerable\"}\n"
            "instantiated=true"
        ),
        error_log_snippet="the callback was proven",
        developer_analysis="the canary was proven to instantiate",
        observation=reported,
        validation_reason="response-marker oracle requires attack.marker",
    )
    captured = {}

    class FakeRuntime:
        async def run(self, **kwargs):
            captured.update(kwargs)
            return SimpleNamespace(output="import requests\n")

    async def setup_callback(_description: str) -> str:
        return "setup applied"

    from squadrone.agents.poc_author import PoCAuthorAgent

    author = PoCAuthorAgent(
        FakeRuntime(), model="test-model", setup_callback=setup_callback
    )
    await author.write(
        hypothesis=Hypothesis(
            id="sqli-test",
            specialist="injection_files",
            bug_class=BugClass.SQLI,
            entry_point="test_action",
            file="plugin.php",
            line=10,
            sink="query",
            taint_path=["request", "query"],
            reasoning="Unsanitized request input reaches a SQL query.",
            confidence=Confidence.HIGH,
            preconditions="unauthenticated",
            affected_versions="<= 1.0",
        ),
        target_url="http://127.0.0.1:8100",
        previous_attempts=[attempt],
    )

    retry_prompt = captured["messages"][-1]["content"]

    assert (
        "validator_rejection: response-marker oracle requires attack.marker"
        in retry_prompt
    )
    assert "phase=attack result=failed" in retry_prompt
    assert "runner_observation=rejected" in retry_prompt
    assert "reported_oracle=response_marker" in retry_prompt
    assert "none of its success declarations are established" in retry_prompt
    assert "SQUADRONE_RESULT=" not in retry_prompt
    assert "instantiated=true" not in retry_prompt
    assert "the callback was proven" not in retry_prompt
    assert "the canary was proven" not in retry_prompt
    assert "withheld after rejected child observation" in retry_prompt
    assert "import requests" in retry_prompt
    assert captured["force_finalise_allowed_tools"] == {"request_additional_setup"}


@pytest.mark.asyncio
async def test_internal_python_retry_retains_only_new_setup_tool_feedback() -> None:
    calls = []

    class FakeRuntime:
        async def run(self, **kwargs):
            calls.append(kwargs)
            if len(calls) == 1:
                feedback = await kwargs["tool_handlers"]["request_additional_setup"](
                    {"description": "create two ownership-distinct records"}
                )
                assert '"foreign_id":41' in feedback
                return SimpleNamespace(output="the setup is ready, but this is prose")
            return SimpleNamespace(output="import requests\n")

    async def setup_callback(_description: str) -> str:
        return (
            "[request_additional_setup] applied 1 permitted command.\n"
            'OK: wp eval -> {"foreign_id":41,"control_id":42}'
        )

    from squadrone.agents.poc_author import PoCAuthorAgent

    author = PoCAuthorAgent(
        FakeRuntime(), model="test-model", setup_callback=setup_callback
    )
    script = await author.write(
        hypothesis=Hypothesis(
            id="idor-setup-retry",
            specialist="authorization_workflows",
            bug_class=BugClass.IDOR,
            entry_point="wp_ajax_update_record",
            file="plugin.php",
            line=20,
            sink="owner-unbound update",
            taint_path=["request object ID", "database update"],
            reasoning="A low-privilege user can update another owner's record.",
            confidence=Confidence.HIGH,
            preconditions="subscriber",
            affected_versions="<= 1.0",
        ),
        target_url="http://127.0.0.1:8100",
        previous_attempts=[],
        extra_context={"setup_summary": "INITIAL_CANONICAL_SETUP_STATE"},
    )

    assert script == "import requests"
    assert len(calls) == 2
    retry_messages = "\n".join(message["content"] for message in calls[1]["messages"])
    assert retry_messages.count("INITIAL_CANONICAL_SETUP_STATE") == 1
    assert retry_messages.count('"foreign_id":41,"control_id":42') == 1
    assert "AUTHORITATIVE SETUP FEEDBACK FROM THE PRIOR TOOL TURN" in retry_messages


@pytest.mark.asyncio
async def test_poc_author_wires_bounded_plugin_discovery_tools(tmp_path) -> None:
    source = tmp_path / "bootstrap.php"
    source.write_text("<?php\nfunction install_defaults() {}\n")
    captured = {}

    class FakeRuntime:
        async def run(self, **kwargs):
            captured.update(kwargs)
            return SimpleNamespace(output="import requests\n")

    async def setup_callback(_description: str) -> str:
        return "setup applied"

    from squadrone.agents.poc_author import PoCAuthorAgent

    author = PoCAuthorAgent(
        FakeRuntime(),
        model="test-model",
        plugin_root=str(tmp_path),
        setup_callback=setup_callback,
    )
    await author.write(
        hypothesis=Hypothesis(
            id="setup-discovery-test",
            specialist="authorization_workflows",
            bug_class=BugClass.MISSING_AUTH_CRITICAL_FUNCTION,
            entry_point="public_action",
            file="bootstrap.php",
            line=2,
            sink="state change",
            taint_path=["request", "state change"],
            reasoning="A public request reaches a protected state change.",
            confidence=Confidence.HIGH,
            preconditions="unauthenticated",
            affected_versions="<= 1.0",
        ),
        target_url="http://127.0.0.1:8100",
        previous_attempts=[],
    )

    advertised = {tool["function"]["name"]: tool for tool in captured["tools"]}
    assert {"grep_plugin", "glob_plugin", "read_plugin_file"} <= advertised.keys()
    assert advertised["grep_plugin"]["function"]["parameters"]["required"] == [
        "pattern"
    ]
    assert advertised["glob_plugin"]["function"]["parameters"]["required"] == [
        "pattern"
    ]

    handlers = captured["tool_handlers"]
    assert handlers["grep_plugin"].__self__ is author.plugin_tools
    assert handlers["glob_plugin"].__self__ is author.plugin_tools
    assert handlers["read_plugin_file"].__self__ is author.plugin_tools
    assert "install_defaults" in handlers["grep_plugin"](
        {"pattern": "install_defaults", "path_glob": "**/*.php"}
    )
    assert "bootstrap.php" in handlers["glob_plugin"]({"pattern": "**/*.php"})
    assert captured["force_finalise_allowed_tools"] == {"request_additional_setup"}
    assert captured["max_iterations"] == 12
    assert captured["force_finalise_after"] == 8


def test_poc_author_prompt_documents_response_marker_measurement_contract() -> None:
    prompt = load_prompt("poc_author")

    assert "`attack.marker`" in prompt
    assert "`attack.marker_present`" in prompt
    assert "`control.marker_present`" in prompt
    assert "Do not emit\n`attack.response_marker`" in prompt


def test_php_include_template_and_prompt_use_fail_closed_trusted_oracle() -> None:
    attack_path = "/var/lib/squadrone/php-include/" + "a" * 64 + ".php"
    control_path = "/var/lib/squadrone/php-include/" + "b" * 64 + ".php"
    rendered = _render_template(
        "path_traversal.py.j2",
        target_url="http://127.0.0.1",
        ajax_action="example_dispatch",
        injectable_param="source",
        test_username="",
        test_password="",
        attacker_role="unauthenticated",
        request_method="POST",
        request_route="/wp-admin/admin-ajax.php",
        request_dispatch={"form:action": "example_dispatch"},
        php_include_destination_location="query",
        php_include_attack_path=attack_path,
        php_include_control_path=control_path,
        php_include_header_name="X-Squadrone-PHP-Include-Receipt",
        php_include_unauthenticated=True,
    )

    ast.parse(rendered)
    assert attack_path in rendered
    assert control_path in rendered
    assert "derive the traversal value from the cited PHP sink" in rendered
    assert 'verdict="not_vulnerable"' in rendered
    assert "session.request(" not in rendered
    assert "wp-config.php" not in rendered
    assert rendered.count('"attacker_user_id": "anonymous"') == 2
    assert rendered.count('"identity_verified": True') == 2
    assert '"attacker_user_id": 0' not in rendered
    assert '"attacker_user_id": None' not in rendered
    assert "must begin with ``/..``" in rendered
    assert "not\n    bare ``..``" in rendered

    prompt = load_prompt("poc_author")
    assert "`TRUSTED_PHP_INCLUDE_ORACLE`" in prompt
    assert "`destination_value`" in prompt
    assert "absent-sibling control" in prompt
    assert "not an attacker-controlled file write" in prompt
    assert "begin the traversal with `/..`" in prompt
    assert "not bare `..`" in prompt
    assert 'literal JSON string `"anonymous"`' in prompt
    assert 'never use\n  `0`, `"0"`, `null`/`None`, `"guest"`, or a username' in prompt
    assert "measured from `login.identity.user_id`" in prompt
    assert "origin plus that path-only route in `request.url`" in prompt
    assert "do not include a query\n  string or fragment" in prompt


def test_authenticated_php_include_template_requires_measured_positive_actor_id() -> (
    None
):
    rendered = _render_template(
        "path_traversal.py.j2",
        target_url="http://127.0.0.1",
        injectable_param="source",
        attacker_role="subscriber",
        request_method="POST",
        request_route="/wp-admin/admin-ajax.php",
        request_dispatch={"form:action": "example_dispatch"},
        php_include_destination_location="query",
        php_include_attack_path=("/var/lib/squadrone/php-include/" + "a" * 64 + ".php"),
        php_include_control_path=(
            "/var/lib/squadrone/php-include/" + "b" * 64 + ".php"
        ),
        php_include_header_name="X-Squadrone-PHP-Include-Receipt",
        php_include_unauthenticated=False,
    )

    ast.parse(rendered)
    assert rendered.count('"attacker_user_id": None') == 2
    assert rendered.count('"identity_verified": False') == 2
    assert "measured positive" in rendered
    assert "login.identity.user_id" in rendered


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("attacker_role", "actor_contract"),
    [
        (
            "unauthenticated",
            "both attack and control must emit attacker_user_id as the literal "
            'JSON string "anonymous" (never 0, "0", null/None, "guest", or a '
            "username), with identity_verified=true",
        ),
        (
            "subscriber",
            "both attack and control must emit the same positive WordPress user ID "
            "measured from login.identity.user_id",
        ),
    ],
)
async def test_php_include_author_context_states_exact_actor_and_path_contract(
    attacker_role: str,
    actor_contract: str,
) -> None:
    captured = {}

    class FakeRuntime:
        async def run(self, **kwargs):
            captured.update(kwargs)
            return SimpleNamespace(output="import requests\n")

    from squadrone.agents.poc_author import PoCAuthorAgent

    author = PoCAuthorAgent(FakeRuntime(), model="test-model")
    await author.write(
        hypothesis=Hypothesis(
            id="php-include-actor-contract",
            specialist="injection_files",
            bug_class=BugClass.PATH_TRAVERSAL,
            entry_point="POST /wp-admin/admin-ajax.php?action=example_dispatch",
            file="plugin.php",
            line=20,
            sink="request-controlled PHP include",
            sink_code="require_once(BASE . '/view-' . $source . '.php');",
            taint_path=["$_GET['source']", "require_once"],
            reasoning="A request-controlled path reaches a PHP include.",
            confidence=Confidence.HIGH,
            preconditions=attacker_role,
            affected_versions="<= 1.0",
            evidence_summary={"attacker_role": attacker_role},
        ),
        target_url="http://127.0.0.1:8100",
        previous_attempts=[],
        extra_context={
            "attacker_role": attacker_role,
            "php_include_oracle": {
                "attack_path": ("/var/lib/squadrone/php-include/" + "a" * 64 + ".php"),
                "control_path": ("/var/lib/squadrone/php-include/" + "b" * 64 + ".php"),
                "attack_basename": "a" * 64 + ".php",
                "control_basename": "b" * 64 + ".php",
                "header_name": "X-Squadrone-PHP-Include-Receipt",
            },
        },
    )

    user_prompt = captured["messages"][1]["content"]
    trusted_context = user_prompt.split("TRUSTED_PHP_INCLUDE_ORACLE", 1)[1]
    assert actor_contract in trusted_context
    assert (
        "traversal must begin with /.. (a separator followed by a parent segment), "
        "not bare .."
    ) in trusted_context
    assert "do not add a redundant separator when the sink already supplies one" in (
        trusted_context
    )


def test_poc_author_prompt_accounts_for_wordpress_xss_input_transforms() -> None:
    prompt = load_prompt("poc_author")

    assert "WordPress applies request slashing" in prompt
    assert "unless\n  the handler calls `wp_unslash`" in prompt
    assert "quote-free numeric sentinel" in prompt
    assert "Do not use\n  `String.fromCharCode(...)`" in prompt


def test_poc_author_prompt_nests_request_transport_in_emit_result() -> None:
    prompt = load_prompt("poc_author")

    assert '`request={"method": <real method>, "url": <real URL>}`' in prompt
    assert "Never pass `method` or `url` as top-level" in prompt
    assert "they exist only inside `request`" in prompt


def test_poc_author_prompt_documents_authorization_measurement_contract() -> None:
    prompt = load_prompt("poc_author")

    assert "`attack.allowed`" in prompt
    assert "`attack.privileged_effect`" in prompt
    assert "`control.allowed`" in prompt
    assert "successful benign-control login a prerequisite" in prompt
    assert "failed login or rejected credential is a setup failure" in prompt
    assert "control account/object exists" in prompt
    assert "reached the comparable prerequisite state" in prompt
    assert "genuinely\nunauthenticated control" in prompt
    assert "created through the same public\nworkflow remains valid" in prompt


def test_poc_author_prompt_documents_cross_object_measurement_contract() -> None:
    prompt = load_prompt("poc_author")

    assert "attacker-owned object as\n  the preferred" in prompt
    assert "That legitimate request should succeed" in prompt
    assert "not that the HTTP request failed" in prompt
    assert "exact returned IDs and\n  markers" in prompt
    assert "zero or multiple matches" in prompt
    assert "through its exact claimed owner" in prompt
    assert "must not be the sole observer" in prompt
    assert "an overwrite\n  alone does not prove availability impact" in prompt
    assert "generic `response_marker` does not prove" in prompt
    assert "`object_provenance`" in prompt
    assert "`match_count=1`" in prompt
    assert "`request_fingerprint`" in prompt
    assert "`object_location`" in prompt
    assert "`object_value_template`" in prompt
    assert "`marker_field`" in prompt
    assert "`owner_field`" in prompt
    assert "`csrf_fields`" in prompt
    assert "causal request order must then be exactly" in prompt
    assert "`protection_visible_marker`" in prompt
    assert "server-signed WordPress identity receipt" in prompt
    assert "`attack.protection_request_fingerprint`" in prompt
    assert "`attack.owner_request_fingerprint`" in prompt
    assert "`observer_request_fingerprint`" in prompt
    assert "`baseline_marker`" in prompt
    assert "`baseline_marker` created by trusted setup" in prompt
    assert "Do not create a sentinel-bearing baseline through a target HTTP" in prompt
    assert (
        'collection declares `scope="owner_filtered_collection"`, omits all '
        "three object\n  fields" in prompt
    )
    assert '`scope="owner_filtered_collection"`' in prompt
    assert '`scope="object"`' in prompt
    assert (
        "Never disguise a collection\n  search/filter as an object selector" in prompt
    )
    assert "must not carry a `SQUADRONE_` proof\n  sentinel" in prompt
    assert "and is objectless" in prompt
    assert "refer only to\nthat arm's `marker`" in prompt
    assert "never to its `baseline_marker`" in prompt
    assert (
        "`write_marker_present_before=false` and "
        "`write_marker_present_after=true`" in prompt
    )
    assert (
        "`write_marker_present_before=true` and\n"
        "`write_marker_present_after=false`" in prompt
    )
    assert "legacy names `before_marker_present` and" in prompt
    assert "accepted only when replaying old artifacts" in prompt
    assert "new\nPoCs must not emit them" in prompt
    assert "`identity_verified=true`" in prompt
    assert "`authorization_expected=false`" in prompt
    assert "`protection_observed=true`" in prompt
    assert "`control_basis=attacker_owned`" in prompt
    assert "`control_basis=public`" in prompt
    assert "`control_basis=authorized_actor`" in prompt
    assert "`attack.availability_probe`" in prompt
    assert "legacy flat availability Boolean fields" in prompt
    assert "at most low availability" in prompt


def test_poc_author_prompt_preserves_denied_response_status_codes() -> None:
    prompt = load_prompt("poc_author")

    assert "`requests.Response` is falsey for HTTP 4xx/5xx" in prompt
    assert "`response.status_code if response else 0`" in prompt
    assert "`response is not None`" in prompt


def test_poc_author_prompt_documents_file_effect_measurement_contract() -> None:
    prompt = load_prompt("poc_author")

    assert "snapshot the deterministic attack and control\n  paths" in prompt
    assert "set confidentiality and availability to\n  `none`" in prompt
    assert "`before_exists=false`, `after_exists=true`" in prompt
    assert "different measured\n  `before_sha256`" in prompt
    assert "must remain distinct after URL\n  decoding and path normalization" in prompt
    assert "query or fragment differences do not make" in prompt
    assert (
        "already contained\n  the attack payload before the request is not proof"
        in prompt
    )
    assert "`attack.before_exists`, `attack.after_exists`" in prompt
    assert "`control.before_exists`, and\n  `control.after_exists`" in prompt
    assert "legacy aliases\n  remain valid only for this post-request value" in prompt
    assert "only a request-induced hash change proves an overwrite" in prompt
    assert "unchanged pre-seeded file must produce `not_vulnerable`" in prompt
    assert "HTTP 200 alone does not prove that a URL-mapped file exists" in prompt
    assert "front controller may return a generic catch-all page" in prompt
    assert "prefer `response_marker`" in prompt


def test_poc_author_prompt_constrains_synthetic_credentials() -> None:
    prompt = load_prompt("poc_author")

    assert "constraints found in the rendered\n  form or source" in prompt
    assert "`minlength`, `maxlength`, `pattern`" in prompt
    assert "deterministic 8–16 character ASCII username" in prompt
    assert "deterministic across clean-run replays" in prompt


def test_poc_author_prompt_preserves_dynamic_form_field_identity() -> None:
    prompt = load_prompt("poc_author")

    assert "preserve each field's exact rendered `name` as the POST\n  key" in prompt
    assert "derive its semantic identity, value, and constraints" in prompt
    assert "`data-key`, source-defined normalization, or normalized" in prompt
    assert "indexed/form-ID suffixes" in prompt
    assert "must receive its semantic value rather than a generic placeholder" in prompt
    assert "do not append a conflicting\n  fallback duplicate" in prompt


def test_poc_author_prompt_recognizes_dynamic_forms_without_style_markers() -> None:
    prompt = load_prompt("poc_author")

    assert "stable hidden form identifiers" in prompt
    assert "coherent family of expected fields" in prompt
    assert "Do not require CSS classes or mode markers" in prompt


def test_poc_author_prompt_surfaces_form_validation_errors() -> None:
    prompt = load_prompt("poc_author")

    assert "returns 2xx but the expected object was not created" in prompt
    assert "inspect the returned form for validation errors" in prompt
    assert "structured attack/control diagnostics" in prompt
    assert "Rule out invalid\n  synthetic input" in prompt


def test_poc_author_prompt_requires_boundary_isolating_ssrf_control() -> None:
    prompt = load_prompt("poc_author")

    assert "SSRF, local-resource, and scheme-bypass findings" in prompt
    assert "preserve the request method, endpoint, payload structure" in prompt
    assert "changing only the validation or security-boundary\n  dimension" in prompt
    assert "rejected destination, host, or scheme" in prompt
    assert (
        "demonstrably inaccessible protected resource through the same path" in prompt
    )
    assert "different accessible local resource is not a negative control" in prompt
    assert "When `TRUSTED_SSRF_ORACLE` is supplied" in prompt
    assert "Never request either oracle URL directly" in prompt
    assert "marker\n  is withheld by the verifier" in prompt
    assert "The parent binds it to the captured HTTP response" in prompt


def test_ssrf_template_uses_only_verifier_owned_destination_urls() -> None:
    oracle_base = "http://host.docker.internal:49152/_squadrone/ssrf/"
    attack_url = oracle_base + "ab" * 32
    control_url = oracle_base + "cd" * 32

    rendered = _render_template(
        "ssrf.py.j2",
        target_url="http://localhost:8100",
        ajax_action="",
        injectable_param="target_url",
        test_username="subscriber_user",
        test_password="password",
        attacker_role="subscriber",
        request_method="GET",
        request_route="/wp-json/example/v1/fetch",
        request_dispatch={},
        ssrf_attack_url=attack_url,
        ssrf_control_url=control_url,
    )

    ast.parse(rendered)
    assert repr(attack_url) in rendered or f'"{attack_url}"' in rendered
    assert repr(control_url) in rendered or f'"{control_url}"' in rendered
    assert "http.server" not in rendered
    assert "0.0.0.0" not in rendered
    assert "SQUADRONE_SSRF_[0-9a-f]{64}" in rendered
    assert 'oracle="response_marker"' in rendered
    assert '"destination_parameter": DESTINATION_PARAMETER' in rendered


@pytest.mark.asyncio
async def test_poc_author_surfaces_ssrf_urls_but_no_expected_marker() -> None:
    captured = {}

    class FakeRuntime:
        async def run(self, **kwargs):
            captured.update(kwargs)
            return SimpleNamespace(output="import requests\n")

    from squadrone.agents.poc_author import PoCAuthorAgent

    oracle_base = "http://host.docker.internal:49152/_squadrone/ssrf/"
    attack_url = oracle_base + "ab" * 32
    control_url = oracle_base + "cd" * 32
    author = PoCAuthorAgent(FakeRuntime(), model="test-model")
    script = await author.write(
        hypothesis=Hypothesis(
            id="ssrf-oracle-context",
            specialist="injection_files",
            bug_class=BugClass.SSRF,
            entry_point="GET /wp-json/example/v1/fetch",
            file="plugin.php",
            line=20,
            sink="wp_remote_get",
            sink_code="wp_remote_get($url)",
            taint_path=["REST target_url", "wp_remote_get"],
            reasoning="A Subscriber reads a response reachable only by the server.",
            confidence=Confidence.HIGH,
            preconditions="subscriber",
            affected_versions="<= 1.0",
        ),
        target_url="http://localhost:8100",
        previous_attempts=[],
        extra_context={
            "attacker_role": "subscriber",
            "ssrf_oracle": {
                "schema_version": 1,
                "attack_url": attack_url,
                "control_url": control_url,
            },
        },
    )

    assert script == "import requests"
    user_prompt = "\n".join(
        message["content"]
        for message in captured["messages"]
        if message["role"] == "user"
    )
    assert attack_url in user_prompt
    assert control_url in user_prompt
    assert "expected response marker is deliberately withheld" in user_prompt
    assert "marker_sha256" not in user_prompt
    assert "ssrf_oracle_marker" not in user_prompt


def test_poc_author_prompt_requests_source_grounded_missing_setup_before_poc() -> None:
    prompt = load_prompt("poc_author")

    assert "`request_additional_setup(description)`" in prompt
    assert "authoritative setup results" in prompt
    assert "before emitting a PoC" in prompt
    assert "Do not assume\n  that plugin reactivation" in prompt
    assert "RETAINED COMMITTED SETUP STATE" in prompt
    assert "LATEST SETUP ROUND" in prompt
    assert "earlier committed objects still exist" in prompt
    assert "smallest incremental repair" in prompt
    assert "fetch nonce/token values\n  through the normal rendered workflow" in prompt


def test_poc_author_prompt_requires_bounded_setup_source_discovery() -> None:
    prompt = load_prompt("poc_author")

    assert "`grep_plugin(pattern, path_glob?, max_results?" in prompt
    assert "`glob_plugin(pattern, max_results?)`" in prompt
    assert "use bounded `grep_plugin` searches early" in prompt
    assert "installer, setup, bootstrap, or default-object APIs" in prompt
    assert "before prescribing direct metadata edits or plugin lifecycle" in prompt
    assert "normal source-defined setup API" in prompt
    assert "measurable benign postcondition" in prompt


def test_poc_author_prompt_requires_clean_run_determinism() -> None:
    prompt = load_prompt("poc_author")

    assert "request URL" in prompt
    assert "deterministic\n  across separate process launches" in prompt
    assert "Do not build those values from `uuid`" in prompt
    assert "fixed\n  per-script sentinel" in prompt


def test_poc_author_prompt_preserves_sound_proof_after_setup_repair() -> None:
    prompt = " ".join(load_prompt("poc_author").split())

    assert "Adjust only what the authoritative feedback requires" in prompt
    assert "payload or transport itself was disproved" in prompt
    assert "latest setup round committed a repaired prerequisite" in prompt
    assert "no exploit-shape defect was identified" in prompt
    assert "preserve the prior payload, oracle, and strongest proof strategy" in prompt


def test_poc_author_prompt_requires_execution_only_upload_markers() -> None:
    prompt = " ".join(load_prompt("poc_author").split())

    assert "executable-extension upload" in prompt
    assert "same submitted bytes for the executable attack" in prompt
    assert "construct the expected execution marker at runtime" in prompt
    assert "exact value is absent from those submitted bytes" in prompt
    assert "control with different content" in prompt
    assert "proves only file write/retrieval" in prompt
    assert "Do not stop at a `file_effect` result" in prompt
    assert "Use `response_marker`" in prompt
    assert "Claim high CIA impact only when" in prompt


@pytest.mark.asyncio
async def test_poc_author_receives_runner_target_and_confirmed_lower_bound() -> None:
    captured = {}

    class FakeRuntime:
        async def run(self, **kwargs):
            captured.update(kwargs)
            return SimpleNamespace(output="import requests")

    from squadrone.agents.poc_author import PoCAuthorAgent

    author = PoCAuthorAgent(FakeRuntime(), model="test-model")
    script = await author.write(
        hypothesis=Hypothesis(
            id="full-compromise-target",
            specialist="injection_files",
            bug_class=BugClass.ARBITRARY_FILE_WRITE,
            entry_point="POST /upload",
            file="plugin.php",
            line=20,
            sink="copy",
            taint_path=["request", "copy"],
            reasoning="An executable upload can run server-side code.",
            confidence=Confidence.HIGH,
            preconditions="subscriber",
            affected_versions="<= 1.0",
        ),
        target_url="http://localhost:8100",
        previous_attempts=[],
        extra_context={
            "verification_target": {
                "confidentiality": "high",
                "integrity": "high",
                "availability": "high",
            },
            "verified_partial_proof": {
                "status": "confirmed_lower_bound",
                "oracle": "file_effect",
                "unmet_dimensions": {
                    "confidentiality": "none",
                    "availability": "none",
                },
            },
            "executable_upload_oracle": {
                "mode": "post_upload_challenge_v1",
                "payload_environment": "SQUADRONE_EXEC_UPLOAD_PAYLOAD_B64",
                "attack_filename_environment": (
                    "SQUADRONE_EXEC_UPLOAD_ATTACK_FILENAME"
                ),
                "control_filename_environment": (
                    "SQUADRONE_EXEC_UPLOAD_CONTROL_FILENAME"
                ),
                "challenge_parameter": "squadrone_challenge",
                "response_prefix": "SQUADRONE_UPLOAD_EXEC_V1:",
                "response_derivation": (
                    "implemented by the exact parent-generated PHP payload; "
                    "the child must not reconstruct or alter those bytes"
                ),
            },
        },
    )

    assert script == "import requests"
    user_prompt = captured["messages"][1]["content"]
    assert "RUNNER VERIFICATION TARGET" in user_prompt
    assert "RUNNER-CONFIRMED LOWER-BOUND PROOF" in user_prompt
    assert '"oracle": "file_effect"' in user_prompt
    assert '"confidentiality": "none"' in user_prompt
    assert "one bounded refinement strategy" in user_prompt
    assert "TRUSTED_EXECUTABLE_UPLOAD_ORACLE" in user_prompt
    assert "SQUADRONE_EXEC_UPLOAD_PAYLOAD_B64" in user_prompt
    assert "SQUADRONE_EXEC_UPLOAD_ATTACK_FILENAME" in user_prompt
    assert "SQUADRONE_EXEC_UPLOAD_CONTROL_FILENAME" in user_prompt
    assert "Do not probe either URL" in user_prompt
    assert "verdict=not_vulnerable" in user_prompt
    assert "observed=false, marker_present=false, and uploaded_url" in user_prompt
    assert "fresh challenge after the process exits" in user_prompt


def test_poc_author_prompt_requires_parent_attested_executable_uploads() -> None:
    prompt = " ".join(load_prompt("poc_author").split())

    assert "`TRUSTED_EXECUTABLE_UPLOAD_ORACLE`" in prompt
    assert "parent-owned handoff" in prompt
    assert "base64 payload and `.php`/`.txt` filenames" in prompt
    assert "exactly two source-route requests in attack-then-control order" in prompt
    assert "Do not request either returned URL" in prompt
    assert "`verdict=not_vulnerable`, `oracle=response_marker`" in prompt
    assert "the exact server-returned `uploaded_url`" in prompt
    assert "Do not report a status, identity, actor ID" in prompt
    assert "Only that parent attestation can produce" in prompt
