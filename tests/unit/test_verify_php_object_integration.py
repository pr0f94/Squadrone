from __future__ import annotations

import ast
import hashlib
import json
import time
from dataclasses import replace
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
import requests

from squadrone.agents.developer import SetupPlan
from squadrone.agents.poc_author import (
    PHP_OBJECT_INERT_IMPACT_DESCRIPTION,
    PoCAuthorAgent,
    _render_template,
)
from squadrone.agents.prompts_io import load_prompt
from squadrone.schemas import (
    BugClass,
    CIAImpact,
    Confidence,
    Hypothesis,
    PipelineConfig,
    PoCObservation,
    SecurityOutcome,
)
from squadrone.schemas.php_object_gadget import PhpObjectGadgetRecipe
from squadrone.schemas.hypothesis import TriagedArtifact
from squadrone.schemas.taxonomy import get_known_cwe_profile
from squadrone.services.php_object_oracle import (
    PhpObjectCallsite,
    PhpObjectOracle,
    PhpObjectOracleSnapshot,
)
from squadrone.services.sandbox import SandboxRunResult
from squadrone.stages import verify as verify_stage
from squadrone.stages.verify import (
    _bounded_php_object_observation,
    _expected_php_object_callsite,
    _expected_php_object_http_transport,
    _validate_php_object_confirmation_snapshots,
)

_INSTALLED_CALLSITE_ARGS: dict[str, Any] = {
    "callsite_path": (
        "/var/www/html/wp-content/plugins/generic-plugin/includes/storage.php"
    ),
    "callsite_start_line": 3,
    "callsite_end_line": 3,
    "callsite_source_sha256": "22" * 32,
}


def _rendered_php_object_template() -> str:
    return _render_template(
        "php_object_instantiation.py.j2",
        target_url="http://localhost:8123",
        request_method="POST",
        request_route="/wp-admin/admin-ajax.php",
        request_dispatch={"form:action": "process_submission"},
        php_object_field="object_blob",
        php_object_location="form",
        php_object_attack_token="sqpobjt1." + "a" * 64,
        php_object_control_token="sqpobjt1." + "b" * 64,
        php_object_impact_description=PHP_OBJECT_INERT_IMPACT_DESCRIPTION,
        test_username="",
        test_password="",
        attacker_role="unauthenticated",
    )


def _template_helper_namespace(rendered: str) -> dict[str, Any]:
    """Load only inert imports and helper definitions from a rendered template."""
    tree = ast.parse(rendered)
    body: list[ast.stmt] = []
    for node in tree.body:
        if isinstance(node, (ast.ClassDef, ast.FunctionDef)):
            body.append(node)
        elif isinstance(node, ast.Import) and all(
            alias.name == "requests" for alias in node.names
        ):
            body.append(node)
        elif isinstance(node, ast.ImportFrom) and node.module in {
            "copy",
            "decimal",
            "html.parser",
            "urllib.parse",
        }:
            body.append(node)
    namespace: dict[str, Any] = {}
    helper_module = ast.Module(body=body, type_ignores=[])
    exec(compile(helper_module, "<php-object-template-helpers>", "exec"), namespace)
    return namespace


def _hypothesis(
    *,
    evidence_source: str = "POST company containing object bytes",
    usable_gadget: object = True,
) -> Hypothesis:
    return Hypothesis(
        id="generic-object-ingress",
        specialist="injection_files",
        bug_class=BugClass.PHP_OBJECT_INJECTION,
        entry_point="wp_ajax_nopriv_process_submission",
        file="includes/storage.php",
        line=3,
        sink="metadata update that can deserialize a prior stored value",
        sink_code="return update_metadata($kind, $id, $key, $value, '');",
        taint_path=[
            "process_submission() receives and normalizes the whole POST array",
            "RequestAdapter::hydrate_request() reads post_data[company]",
            "the value reaches update_metadata()",
        ],
        reasoning="A reviewed whole-request adapter carries the named form value.",
        confidence=Confidence.HIGH,
        preconditions="Unauthenticated access to the public action.",
        affected_versions="<= 1.0.0",
        security_outcome=SecurityOutcome(
            integrity="high",
            description=(
                "A shipped natural gadget can change protected server-side state."
            ),
        ),
        evidence_summary={
            "attacker_role": "unauthenticated",
            "source": evidence_source,
            "reachable_path": (
                "process_submission -> RequestAdapter::hydrate_request -> "
                "update_metadata"
            ),
            "proof_gaps": (
                "Trusted reproduction of the shipped natural gadget's concrete "
                "server-side state change."
            ),
            "usable_gadget": usable_gadget,
        },
    )


def _direct_gadget_recipe() -> PhpObjectGadgetRecipe:
    return PhpObjectGadgetRecipe.model_validate(
        {
            "gadget_object": {
                "class_name": "ReviewedFileGadget",
                "class_anchor": {
                    "file": "includes/gadget.php",
                    "line": 1,
                    "source_code": "class ReviewedFileGadget {",
                },
                "trigger": "__destruct",
                "trigger_declaring_class": "ReviewedFileGadget",
                "trigger_anchor": {
                    "file": "includes/gadget.php",
                    "line": 2,
                    "source_code": (
                        "public function __destruct() {\n"
                        "    unlink($this->path);\n"
                        "}"
                    ),
                },
                "properties": [
                    {
                        "name": "path",
                        "declaring_class": "ReviewedFileGadget",
                        "visibility": "protected",
                        "value": {
                            "kind": "capability",
                            "capability": "ephemeral_file_path",
                        },
                    }
                ],
            },
            "effect_binding": {
                "kind": "direct_path",
                "effect_property": "path",
                "access": "property",
                "effect_anchor": {
                    "file": "includes/gadget.php",
                    "line": 3,
                    "source_code": "unlink($this->path);",
                },
            },
        }
    )


def _whole_post_plugin(tmp_path: Path, *, unrelated_field: bool = False) -> Path:
    root = tmp_path / "generic-plugin"
    storage = root / "includes" / "storage.php"
    handler = root / "includes" / "handler.php"
    storage.parent.mkdir(parents=True)
    storage.write_text(
        "<?php\n"
        "function persist_value($kind, $id, $key, $value) {\n"
        "    return update_metadata($kind, $id, $key, $value, '');\n"
        "}\n"
    )
    reader = "unrelated_reader" if unrelated_field else "hydrate_request"
    reader_class = "UnrelatedAdapter" if unrelated_field else "RequestAdapter"
    reader_parameter = "clean" if unrelated_field else "request"
    handler.write_text(
        "<?php\n"
        "add_action('wp_ajax_nopriv_process_submission', 'process_submission');\n"
        "function process_submission() {\n"
        "    $clean = normalize_input($_POST);\n"
        "    $request = ['post_data' => $clean];\n"
        f"    {reader_class}::{reader}($request);\n"
        "}\n"
        f"class {reader_class} {{\n"
        f"public static function {reader}(${reader_parameter}) {{\n"
        f"    return ${reader_parameter}['post_data']['company'];\n"
        "}\n}\n"
    )
    return root


def _metadata_read_callsite(
    tmp_path: Path,
    expression: str,
) -> tuple[Hypothesis, Path, Path]:
    root = _whole_post_plugin(tmp_path)
    source = root / "includes" / "storage.php"
    source.write_text(
        "<?php\n"
        "function read_stored_value($kind, $id, $key) {\n"
        f"    {expression}\n"
        "}\n"
    )
    hypothesis = _hypothesis().model_copy(
        update={
            "line": 3,
            "sink": "direct keyed metadata read",
            "sink_code": expression,
        }
    )
    return hypothesis, root, source


@pytest.mark.asyncio
async def test_run_routes_natural_recipe_away_from_shared_persistent_sandbox(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    ordinary = _hypothesis().model_copy(update={"id": "ordinary-object"})
    natural = _hypothesis().model_copy(
        update={
            "id": "natural-object",
            "php_object_gadget_recipe": _direct_gadget_recipe(),
        }
    )
    triaged = TriagedArtifact(
        plugin_slug="generic-plugin",
        accepted=[ordinary, natural],
        rejected=[],
        merged=[],
    )
    plugin_root = _whole_post_plugin(tmp_path)
    constructor_kwargs: list[dict[str, object]] = []
    routed: list[tuple[str, object | None]] = []

    class FakePersistentSandbox:
        target_url = "http://localhost:8123"

        def __init__(self, *_args: object, **kwargs: object) -> None:
            constructor_kwargs.append(dict(kwargs))

        async def boot(self) -> None:
            return None

        async def install_plugin(self, *_args: object) -> None:
            return None

        async def setup_test_users(self) -> None:
            return None

        async def snapshot(self) -> Path:
            path = tmp_path / "persistent-baseline"
            path.mkdir()
            return path

        async def restore(self, _snapshot: Path) -> None:
            return None

        async def teardown(self) -> None:
            return None

    async def fake_verify_one(
        hypothesis: Hypothesis,
        *_args: object,
        poc_dir: Path,
        persistent_sb: object | None = None,
        **_kwargs: object,
    ) -> None:
        routed.append((hypothesis.id, persistent_sb))
        poc_dir.mkdir(parents=True, exist_ok=True)
        (poc_dir / "iter_1.py").write_text("# checked\n", encoding="utf-8")
        return None

    monkeypatch.setattr(verify_stage, "SandboxManager", FakePersistentSandbox)
    monkeypatch.setattr(
        verify_stage,
        "_zip_plugin",
        lambda *_args: (str(tmp_path / "plugin.zip"), None),
    )
    monkeypatch.setattr(verify_stage, "_verify_one", fake_verify_one)
    monkeypatch.setattr(
        verify_stage,
        "_php_object_gadget_oracle_enabled_for_hypotheses",
        lambda hypotheses, *_args: any(
            item.php_object_gadget_recipe is not None for item in hypotheses
        ),
    )
    config = PipelineConfig.from_yaml("tests/fixtures/pipeline.yaml")
    config.verify.persistent_sandbox = True

    await verify_stage.run(
        triaged,
        str(plugin_root),
        config,
        cast(Any, object()),
        cast(Any, object()),
        runs_root=str(tmp_path / "runs"),
        run_id="route-natural",
    )

    assert len(constructor_kwargs) == 1
    assert constructor_kwargs[0]["php_object_gadget_oracle_enabled"] is False
    assert constructor_kwargs[0]["php_object_gadget_directory_constants"] == frozenset()
    assert [item[0] for item in routed] == ["ordinary-object", "natural-object"]
    assert routed[0][1] is not None
    assert routed[1][1] is None


def test_php_object_transport_resolves_plain_post_field_through_reviewed_adapter(
    tmp_path: Path,
) -> None:
    hypothesis = _hypothesis()
    root = _whole_post_plugin(tmp_path)

    assert _expected_php_object_http_transport(
        hypothesis,
        root,
        "generic-plugin",
    ) == {
        "method": "POST",
        "route": "/wp-admin/admin-ajax.php",
        "dispatch": {"form:action": "process_submission"},
        "object_field": "company",
        "object_location": "form",
    }


def test_php_object_callsite_binds_exact_reviewed_file_bytes_and_sink_lines(
    tmp_path: Path,
) -> None:
    hypothesis = _hypothesis()
    root = _whole_post_plugin(tmp_path)
    source = root / "includes" / "storage.php"

    callsite = _expected_php_object_callsite(hypothesis, root)

    assert callsite == PhpObjectCallsite(
        relative_path="includes/storage.php",
        start_line=3,
        end_line=3,
        source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
    )

    expression_only = hypothesis.model_copy(
        update={
            "sink_code": "update_metadata($kind, $id, $key, $value, '')",
        }
    )
    assert _expected_php_object_callsite(expression_only, root) == PhpObjectCallsite(
        relative_path="includes/storage.php",
        start_line=3,
        end_line=3,
        source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
    )


@pytest.mark.parametrize(
    "expression",
    [
        "return get_metadata($kind, $id, $key, true);",
        "return get_metadata('give_customer', 7, '_prefix', false);",
        "return get_metadata('give_customer', '7', '_prefix');",
        "return \\get_metadata('give_customer', -7, '_prefix');",
        "return get_metadata('give_customer', 0x10, '0.0', true);",
        "return get_metadata('give_customer', 0b10, '00', false);",
        "return get_metadata('give_customer', 7, '0e0', true);",
    ],
)
def test_php_object_callsite_accepts_direct_keyed_wordpress_metadata_reads(
    tmp_path: Path,
    expression: str,
) -> None:
    hypothesis, root, source = _metadata_read_callsite(tmp_path, expression)

    assert _expected_php_object_callsite(hypothesis, root) == PhpObjectCallsite(
        relative_path="includes/storage.php",
        start_line=3,
        end_line=3,
        source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
    )


@pytest.mark.parametrize(
    "expression",
    [
        "return get_metadata($kind, $id);",
        "return get_metadata($kind, $id, $key, true, $extra);",
        "return get_metadata($kind, $id, '', true);",
        'return get_metadata($kind, $id, "", true);',
        "return get_metadata($kind, $id, '0', true);",
        'return get_metadata($kind, $id, "0", true);',
        "return get_metadata($kind, $id, 0, false);",
        "return get_metadata($kind, $id, 0.0, false);",
        "return get_metadata($kind, $id, false, false);",
        "return get_metadata($kind, $id, null, false);",
        "return get_metadata($kind, $id, [], false);",
        "return get_metadata($kind, $id, array( ), false);",
        "return get_metadata('', $id, $key, true);",
        "return get_metadata(['give_customer'], $id, $key, true);",
        "return get_metadata($kind, 'not-numeric', $key, true);",
        "return get_metadata($kind, 0.5, $key, true);",
        "return get_metadata($kind, [1], $key, true);",
        r'return get_metadata($kind, "\x66oo", $key, true);',
        r'return get_metadata("\x30", $id, $key, true);',
        r'return get_metadata($kind, $id, "\x30", true);',
        "return get_metadata($kind, '0x10', $key, true);",
        'return get_metadata($kind, "0b10", $key, true);',
        "return get_metadata($kind, '0o10', $key, true);",
        "return $store->get_metadata($kind, $id, $key, true);",
        "return Store::get_metadata($kind, $id, $key, true);",
        "return Vendor\\get_metadata($kind, $id, $key, true);",
        "return \\Vendor\\get_metadata($kind, $id, $key, true);",
        "return get_metadata_raw($kind, $id, $key, true);",
        "return new get_metadata($kind, $id, $key, true);",
        "return new \\get_metadata($kind, $id, $key, true);",
        (
            "return get_metadata(meta_type: $kind, object_id: $id, "
            "meta_key: $key, single: true);"
        ),
        "return get_metadata(...$arguments);",
    ],
)
def test_php_object_callsite_rejects_non_core_or_unkeyed_metadata_read_forms(
    tmp_path: Path,
    expression: str,
) -> None:
    hypothesis, root, _source = _metadata_read_callsite(tmp_path, expression)

    assert _expected_php_object_callsite(hypothesis, root) is None


def test_php_object_callsite_rejects_metadata_function_declaration(
    tmp_path: Path,
) -> None:
    root = _whole_post_plugin(tmp_path)
    source = root / "includes" / "storage.php"
    declaration = "function &get_metadata($kind, $id, $key) {"
    source.write_text(f"<?php\n{declaration}\n    return null;\n}}\n")
    hypothesis = _hypothesis().model_copy(
        update={"line": 2, "sink_code": declaration}
    )

    assert _expected_php_object_callsite(hypothesis, root) is None


def test_php_object_callsite_requires_global_metadata_function_in_namespaces(
    tmp_path: Path,
) -> None:
    root = _whole_post_plugin(tmp_path)
    source = root / "includes" / "storage.php"
    source.write_text(
        "<?php\n"
        "namespace Vendor\\Storage;\n"
        "function read_value($kind, $id, $key) {\n"
        "    return get_metadata($kind, $id, $key, true);\n"
        "}\n"
    )
    hypothesis = _hypothesis().model_copy(
        update={
            "line": 4,
            "sink_code": "return get_metadata($kind, $id, $key, true);",
        }
    )

    assert _expected_php_object_callsite(hypothesis, root) is None

    qualified = "return \\get_metadata($kind, $id, $key, true);"
    source.write_text(
        "<?php\n"
        "namespace Vendor\\Storage;\n"
        "function read_value($kind, $id, $key) {\n"
        f"    {qualified}\n"
        "}\n"
    )
    qualified_hypothesis = hypothesis.model_copy(update={"sink_code": qualified})

    assert _expected_php_object_callsite(
        qualified_hypothesis,
        root,
    ) == PhpObjectCallsite(
        relative_path="includes/storage.php",
        start_line=4,
        end_line=4,
        source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
    )


def test_php_object_callsite_rejects_conflicting_global_function_import(
    tmp_path: Path,
) -> None:
    root = _whole_post_plugin(tmp_path)
    source = root / "includes" / "storage.php"
    expression = "return get_metadata($kind, $id, $key, true);"
    source.write_text(
        "<?php\n"
        "use function Vendor\\safe_read as get_metadata;\n"
        "function read_value($kind, $id, $key) {\n"
        f"    {expression}\n"
        "}\n"
    )
    hypothesis = _hypothesis().model_copy(
        update={"line": 4, "sink_code": expression}
    )

    assert _expected_php_object_callsite(hypothesis, root) is None


def test_php_object_callsite_rejects_wrong_file_line_and_source_quote(
    tmp_path: Path,
) -> None:
    hypothesis = _hypothesis()
    root = _whole_post_plugin(tmp_path)

    assert (
        _expected_php_object_callsite(hypothesis.model_copy(update={"line": 2}), root)
        is None
    )
    assert (
        _expected_php_object_callsite(
            hypothesis.model_copy(update={"file": "includes/handler.php"}), root
        )
        is None
    )
    assert (
        _expected_php_object_callsite(
            hypothesis.model_copy(update={"sink_code": "unserialize($value);"}), root
        )
        is None
    )


@pytest.mark.parametrize(
    "source_line",
    [
        "// update_metadata($kind, $id, $key, $value, '');",
        "$text = \"update_metadata($kind, $id, $key, $value, '');\";",
        "safe_update_metadata($kind, $id, $key, $value, '');",
        "maybe_update_metadata($kind, $id, $key, $value, '');",
        (
            "update_metadata($kind, $id, $key, $value, ''); "
            "update_metadata($kind, $id, $key, $value, '');"
        ),
    ],
)
def test_php_object_callsite_rejects_masked_or_ambiguous_expression_matches(
    tmp_path: Path,
    source_line: str,
) -> None:
    hypothesis = _hypothesis().model_copy(
        update={"sink_code": "update_metadata($kind, $id, $key, $value, '');"}
    )
    root = _whole_post_plugin(tmp_path)
    source = root / "includes" / "storage.php"
    source.write_text(
        "<?php\n"
        "function persist_value($kind, $id, $key, $value) {\n"
        f"    {source_line}\n"
        "}\n"
    )

    assert _expected_php_object_callsite(hypothesis, root) is None


@pytest.mark.parametrize(
    "source",
    [
        (
            "<?php\n"
            "/* a multiline comment starts here\n"
            "update_metadata($kind, $id, $key, $value, '');\n"
            "*/\n"
        ),
        (
            "<?php\n"
            "$text = \"a multiline string starts here\n"
            "update_metadata($kind, $id, $key, $value, '');\n"
            "\";\n"
        ),
    ],
)
def test_php_object_callsite_preserves_masking_state_before_the_cited_line(
    tmp_path: Path,
    source: str,
) -> None:
    hypothesis = _hypothesis().model_copy(
        update={
            "line": 3,
            "sink_code": "update_metadata($kind, $id, $key, $value, '');",
        }
    )
    root = _whole_post_plugin(tmp_path)
    (root / "includes" / "storage.php").write_text(source)

    assert _expected_php_object_callsite(hypothesis, root) is None


def test_php_object_callsite_rejects_quote_lines_absent_from_source(
    tmp_path: Path,
) -> None:
    hypothesis = _hypothesis().model_copy(
        update={
            "sink_code": (
                "update_metadata(\n"
                "$kind, $id, $key, $value, '' )"
            ),
        }
    )
    root = _whole_post_plugin(tmp_path)

    assert _expected_php_object_callsite(hypothesis, root) is None


@pytest.mark.parametrize(
    "sink_code",
    [
        "update_metadata($kind, $id, $key, $value, '');\n   \n",
        "\n   \nupdate_metadata($kind, $id, $key, $value, '');",
    ],
)
def test_php_object_callsite_rejects_whitespace_only_boundary_lines(
    tmp_path: Path,
    sink_code: str,
) -> None:
    root = _whole_post_plugin(tmp_path)
    hypothesis = _hypothesis().model_copy(update={"sink_code": sink_code})

    assert _expected_php_object_callsite(hypothesis, root) is None


def test_php_object_callsite_does_not_normalize_semantic_string_whitespace(
    tmp_path: Path,
) -> None:
    root = _whole_post_plugin(tmp_path)
    source = root / "includes" / "storage.php"
    source.write_text(
        "<?php\n"
        "function persist_value($kind, $id, $value) {\n"
        "    return update_metadata($kind, $id, 'a  b', $value, '');\n"
        "}\n"
    )
    hypothesis = _hypothesis().model_copy(
        update={
            "sink_code": "update_metadata($kind, $id, 'a b', $value, '');",
        }
    )

    assert _expected_php_object_callsite(hypothesis, root) is None


@pytest.mark.parametrize(
    ("source", "line"),
    [
        (
            "<?php\n"
            "$document = <<<PAYLOAD\n"
            "update_metadata($kind, $id, $key, $value, '');\n"
            "PAYLOAD;\n",
            3,
        ),
        (
            "<?php\n"
            "$document = <<<\"PAYLOAD\"\n"
            "update_metadata($kind, $id, $key, $value, '');\n"
            "PAYLOAD;\n",
            3,
        ),
        (
            "<?php\n"
            "$document = <<<'PAYLOAD'\n"
            "update_metadata($kind, $id, $key, $value, '');\n"
            "PAYLOAD;\n",
            3,
        ),
        (
            "<?php\n"
            "$output = `update_metadata($kind, $id, $key, $value, '');`;\n",
            2,
        ),
        (
            "<?php\n"
            "?>\n"
            "update_metadata($kind, $id, $key, $value, '');\n"
            "<?php\n",
            3,
        ),
        (
            "<?php\n"
            "// closing a line comment also closes PHP ?>\n"
            "update_metadata($kind, $id, $key, $value, '');\n",
            3,
        ),
        (
            "<?xml version=\"1.0\"?>\n"
            "update_metadata($kind, $id, $key, $value, '');\n",
            2,
        ),
    ],
)
def test_php_object_callsite_rejects_sink_text_outside_php_code(
    tmp_path: Path,
    source: str,
    line: int,
) -> None:
    root = _whole_post_plugin(tmp_path)
    (root / "includes" / "storage.php").write_text(source)
    hypothesis = _hypothesis().model_copy(
        update={
            "line": line,
            "sink_code": "update_metadata($kind, $id, $key, $value, '');",
        }
    )

    assert _expected_php_object_callsite(hypothesis, root) is None


@pytest.mark.parametrize(
    ("source", "line"),
    [
        (
            "<?php\n"
            "$document = <<<PAYLOAD\n"
            "LABEL-like text\n"
            "    PAYLOAD;\n"
            "update_metadata($kind, $id, $key, $value, '');\n",
            5,
        ),
        (
            "<?php\n"
            "$output = `printf 'safe\\`text'`;\n"
            "update_metadata($kind, $id, $key, $value, '');\n",
            3,
        ),
        (
            "<?php\n"
            "$value = 1;\n"
            "?>\n"
            "<p>inline HTML</p>\n"
            "<?php\n"
            "update_metadata($kind, $id, $key, $value, '');\n",
            6,
        ),
        (
            "<?PHP\n"
            "update_metadata($kind, $id, $key, $value, '');\n"
            "?>\n",
            2,
        ),
        (
            "<?php\n"
            "$text = \"?> <<<LABEL\";\n"
            "/* ?> <<<BLOCK */\n"
            "// <<<LINE\n"
            "update_metadata($kind, $id, $key, $value, '');\n",
            5,
        ),
        (
            "<?= update_metadata($kind, $id, $key, $value, ''); ?>\n",
            1,
        ),
    ],
)
def test_php_object_callsite_accepts_real_sink_after_document_lexical_forms(
    tmp_path: Path,
    source: str,
    line: int,
) -> None:
    root = _whole_post_plugin(tmp_path)
    source_file = root / "includes" / "storage.php"
    source_file.write_text(source)
    hypothesis = _hypothesis().model_copy(
        update={
            "line": line,
            "sink_code": "update_metadata($kind, $id, $key, $value, '');",
        }
    )

    assert _expected_php_object_callsite(hypothesis, root) == PhpObjectCallsite(
        relative_path="includes/storage.php",
        start_line=line,
        end_line=line,
        source_sha256=hashlib.sha256(source_file.read_bytes()).hexdigest(),
    )


def test_php_object_callsite_does_not_close_heredoc_on_label_prefix(
    tmp_path: Path,
) -> None:
    root = _whole_post_plugin(tmp_path)
    source_file = root / "includes" / "storage.php"
    source_file.write_text(
        "<?php\n"
        "$document = <<<LABEL\n"
        "LABELx\n"
        "update_metadata($kind, $id, $key, $value, '');\n"
        "LABEL;\n"
        "update_metadata($kind, $id, $key, $value, '');\n"
    )

    sink_code = "update_metadata($kind, $id, $key, $value, '');"
    inside = _hypothesis().model_copy(
        update={"line": 4, "sink_code": sink_code}
    )
    assert _expected_php_object_callsite(inside, root) is None

    reachable = _hypothesis().model_copy(
        update={"line": 6, "sink_code": sink_code}
    )
    assert _expected_php_object_callsite(reachable, root) == PhpObjectCallsite(
        relative_path="includes/storage.php",
        start_line=6,
        end_line=6,
        source_sha256=hashlib.sha256(source_file.read_bytes()).hexdigest(),
    )


@pytest.mark.parametrize(
    ("source", "line"),
    [
        (
            "<?php\n"
            "$document = <<<PAYLOAD\n"
            "update_metadata($kind, $id, $key, $value, '');\n",
            3,
        ),
        (
            "<?php\n"
            "$output = `update_metadata($kind, $id, $key, $value, '');\n",
            2,
        ),
    ],
)
def test_php_object_callsite_rejects_unterminated_document_lexical_forms(
    tmp_path: Path,
    source: str,
    line: int,
) -> None:
    root = _whole_post_plugin(tmp_path)
    (root / "includes" / "storage.php").write_text(source)
    hypothesis = _hypothesis().model_copy(
        update={
            "line": line,
            "sink_code": "update_metadata($kind, $id, $key, $value, '');",
        }
    )

    assert _expected_php_object_callsite(hypothesis, root) is None


def test_php_object_transport_rejects_literal_field_only_in_unrelated_function(
    tmp_path: Path,
) -> None:
    root = _whole_post_plugin(tmp_path, unrelated_field=True)

    assert (
        _expected_php_object_http_transport(
            _hypothesis(),
            root,
            "generic-plugin",
        )
        is None
    )


def test_php_object_transport_rejects_ambiguous_described_fields(
    tmp_path: Path,
) -> None:
    root = _whole_post_plugin(tmp_path)
    hypothesis = _hypothesis(
        evidence_source="POST company and POST nickname can contain object bytes"
    )

    assert (
        _expected_php_object_http_transport(
            hypothesis,
            root,
            "generic-plugin",
        )
        is None
    )


@pytest.mark.parametrize("usable_gadget", [False, None, "true"])
def test_php_object_transport_requires_exact_reviewed_usable_gadget(
    tmp_path: Path,
    usable_gadget: object,
) -> None:
    root = _whole_post_plugin(tmp_path)

    assert (
        _expected_php_object_http_transport(
            _hypothesis(usable_gadget=usable_gadget),
            root,
            "generic-plugin",
        )
        is None
    )


def test_php_object_transport_rejects_missing_usable_gadget_fact(
    tmp_path: Path,
) -> None:
    root = _whole_post_plugin(tmp_path)
    hypothesis = _hypothesis()
    evidence = dict(hypothesis.evidence_summary)
    evidence.pop("usable_gadget")

    assert (
        _expected_php_object_http_transport(
            hypothesis.model_copy(update={"evidence_summary": evidence}),
            root,
            "generic-plugin",
        )
        is None
    )


def test_php_object_transport_supports_exact_direct_plugin_post(tmp_path: Path) -> None:
    root = tmp_path / "generic-plugin"
    source = root / "direct.php"
    source.parent.mkdir(parents=True)
    source.write_text("<?php\n$payload = $_POST['payload'];\nunserialize($payload);\n")
    hypothesis = _hypothesis(
        evidence_source="POST payload containing object bytes"
    ).model_copy(
        update={
            "entry_point": (
                "POST /wp-content/plugins/generic-plugin/direct.php?mode=submit"
            ),
            "file": "direct.php",
            "line": 3,
            "sink_code": "unserialize($payload);",
            "taint_path": ["$_POST['payload']", "unserialize($payload)"],
        }
    )

    assert _expected_php_object_http_transport(
        hypothesis,
        root,
        "generic-plugin",
    ) == {
        "method": "POST",
        "route": "/wp-content/plugins/generic-plugin/direct.php",
        "dispatch": {"query:mode": "submit"},
        "object_field": "payload",
        "object_location": "form",
    }
    assert (
        _expected_php_object_http_transport(
            hypothesis,
            root,
            "different-plugin",
        )
        is None
    )


def _observation() -> PoCObservation:
    fingerprint = {
        "method": "POST",
        "route": "/wp-admin/admin-ajax.php",
        "object_field": "company",
        "object_location": "form",
        "dispatch": {"form:action": "process_submission"},
    }
    return PoCObservation(
        verdict="vulnerable",
        oracle="object_instantiation",
        attacker_role="unauthenticated",
        request={
            "method": "POST",
            "url": "http://localhost:8123/wp-admin/admin-ajax.php",
        },
        attack={
            "observed": True,
            "instantiated": True,
            "effect": "verifier_inert_canary_wakeup",
            "attacker_user_id": "anonymous",
            "identity_verified": True,
            "request_fingerprint": dict(fingerprint),
        },
        control={
            "observed": False,
            "instantiated": False,
            "effect": "verifier_inert_canary_wakeup",
            "attacker_user_id": "anonymous",
            "identity_verified": True,
            "request_fingerprint": dict(fingerprint),
        },
        impact=CIAImpact(
            confidentiality="none",
            integrity="low",
            availability="none",
            description=PHP_OBJECT_INERT_IMPACT_DESCRIPTION,
        ),
    )


def test_php_object_observation_is_strictly_bounded_to_inert_canary() -> None:
    observation = _observation()
    assert _bounded_php_object_observation(observation)[0] is True

    rce_claim = observation.model_copy(deep=True)
    rce_claim.impact.integrity = "high"
    rce_claim.impact.description = "Arbitrary code execution"
    accepted, reason = _bounded_php_object_observation(rce_claim)
    assert accepted is False
    assert "impact bound" in reason

    natural_gadget_claim = observation.model_copy(deep=True)
    natural_gadget_claim.attack["natural_gadget"] = "claimed_chain"
    accepted, reason = _bounded_php_object_observation(natural_gadget_claim)
    assert accepted is False
    assert "unsupported claims" in reason

    private_receipt_claim = observation.model_copy(deep=True)
    private_receipt_claim.attack["receipt"] = "self-reported"
    assert _bounded_php_object_observation(private_receipt_claim)[0] is False


def _attest_generation(oracle: PhpObjectOracle) -> PhpObjectOracleSnapshot:
    generation_id = oracle.begin_generation()
    context = oracle.public_context()
    started = time.monotonic_ns()
    expected_receipt = oracle.private_expected_receipt
    finished = time.monotonic_ns()
    return oracle.attest_execution(
        generation_id=generation_id,
        attack_token=context["attack_token"],
        control_token=context["control_token"],
        attack_receipt=expected_receipt,
        control_receipt=None,
        execution_started_monotonic_ns=started,
        execution_finished_monotonic_ns=finished,
        attested_monotonic_ns=time.monotonic_ns(),
    )


def test_php_object_clean_replay_requires_stable_tokens_and_fresh_private_state() -> (
    None
):
    oracle = PhpObjectOracle(**_INSTALLED_CALLSITE_ARGS)
    public_context = oracle.public_context()
    first = _attest_generation(oracle)
    confirmation = _attest_generation(oracle)

    assert oracle.public_context() == public_context
    accepted, reason = _validate_php_object_confirmation_snapshots(
        first,
        confirmation,
    )
    assert accepted is True, reason
    assert first.execution.attack_token_sha256 == (
        confirmation.execution.attack_token_sha256
    )
    assert first.execution.control_token_sha256 == (
        confirmation.execution.control_token_sha256
    )
    assert first.generation_id_sha256 != confirmation.generation_id_sha256
    assert first.execution.proof_sha256 != confirmation.execution.proof_sha256
    assert first.execution.attack_payload_sha256 != (
        confirmation.execution.attack_payload_sha256
    )
    assert first.execution.control_payload_sha256 != (
        confirmation.execution.control_payload_sha256
    )
    assert first.execution.expected_receipt_sha256 != (
        confirmation.execution.expected_receipt_sha256
    )

    accepted, reason = _validate_php_object_confirmation_snapshots(first, first)
    assert accepted is False
    assert "reused private" in reason

    different_oracle = _attest_generation(PhpObjectOracle(**_INSTALLED_CALLSITE_ARGS))
    accepted, reason = _validate_php_object_confirmation_snapshots(
        first,
        different_oracle,
    )
    assert accepted is False
    assert "canary identity or authored arm tokens" in reason

    malformed = replace(confirmation, generation_id_sha256="0" * 64)
    assert _validate_php_object_confirmation_snapshots(first, malformed)[0] is False


@pytest.mark.asyncio
async def test_php_object_author_sees_only_stable_opaque_tokens_and_policy() -> None:
    captured: dict[str, object] = {}

    class FakeRuntime:
        async def run(self, **kwargs: object) -> SimpleNamespace:
            captured.update(kwargs)
            return SimpleNamespace(output="import requests\n")

    attack_token = "sqpobjt1." + "a" * 64
    control_token = "sqpobjt1." + "b" * 64
    transport = {
        "method": "POST",
        "route": "/wp-admin/admin-ajax.php",
        "dispatch": {"form:action": "process_submission"},
        "object_field": "company",
        "object_location": "form",
    }
    script = await PoCAuthorAgent(
        cast(Any, FakeRuntime()),
        model="test-model",
    ).write(
        hypothesis=_hypothesis(),
        target_url="http://localhost:8123",
        previous_attempts=[],
        extra_context={
            "attacker_role": "unauthenticated",
            "php_object_oracle": {
                "mode": "php_object",
                "attack_token": attack_token,
                "control_token": control_token,
            },
            "php_object_http_transport": transport,
        },
    )

    assert script == "import requests"
    messages = captured["messages"]
    assert isinstance(messages, list)
    prompt = "\n".join(str(message["content"]) for message in messages)
    assert attack_token in prompt
    assert control_token in prompt
    assert json.dumps(transport, sort_keys=True) in prompt
    assert "allow_redirects=False" in prompt
    assert "bounded GET/HEAD reads" in prompt
    assert "do not send any other POST or mutating preflight" in prompt
    assert "authoritative SANDBOX SETUP" in prompt
    assert "Select exactly one coherent source-grounded form" in prompt
    assert "Leaving either decision undecided must fail closed" in prompt
    assert "SOURCE_COMPLETE_FORM_FIELDS" in prompt
    assert "SOURCE_ADDITIONAL_FORM_FIELDS" in prompt
    assert "SOURCE_OMIT_RENDERED_FORM_FIELDS" in prompt
    assert "explicit empty list only when source proves" in prompt
    assert "Presence, hidden type, or server-side consumption" in prompt
    assert "does not prove that a control must be non-empty" in prompt
    assert "reviewed server source explicitly rejects" in prompt
    assert "presence-required field that validly carries an empty value" in prompt
    assert "part of the final sink-reaching request envelope" in prompt
    assert "never add fields merely because a handler ignores or tolerates them" in prompt
    assert "rendered-form adjustment variables as None in direct mode" in prompt
    assert "preserving valid empty values" in prompt
    assert "preliminary or validation-only branch before the sink" in prompt
    assert "parser, bootstrap validation, session isolation" in prompt
    assert "do not replace its helpers or create a parallel request path" in prompt
    assert "Build the complete baseline before overlaying dispatch" in prompt
    assert "attack response Set-Cookie cannot alter control" in prompt
    assert "managed setup tools before script execution" in prompt
    assert "impact description verbatim" in prompt
    assert "SquadroneObjectCanary_" not in prompt
    assert "sqpobj1." not in prompt
    assert 'O:32:"' not in prompt


def test_php_object_author_prompt_requires_generic_form_bootstrap_contract() -> None:
    prompt = load_prompt("poc_author")
    normalized = " ".join(prompt.split())

    assert "exact public page URL and stable form identity" in normalized
    assert "select exactly one coherent source-grounded form" in normalized
    assert "hidden and other non-submit successful controls" in normalized
    assert "reusable nonce" in normalized
    assert "deterministic, semantically valid value" in normalized
    assert "complete ordered source-required `(name, value)` baseline" in normalized
    assert (
        "Preserve duplicate controls, exact rendered names, and valid empty values"
        in normalized
    )
    assert "does not by itself prove that it must be non-empty" in normalized
    assert "Put a field in `REQUIRED_FORM_FIELDS` only when" in normalized
    assert "reviewed server source explicitly rejects" in normalized
    assert "`SOURCE_ADDITIONAL_FORM_FIELDS`" in normalized
    assert "part of the final sink-reaching request envelope" in normalized
    assert "absent from the selected form" in normalized
    assert "preserving valid empty values" in normalized
    assert "Never add arbitrary fields merely because a handler" in normalized
    assert "presence-required field that validly carries an empty value" in normalized
    assert "rendered-form adjustment variables as `None` in direct mode" in normalized
    assert "`SOURCE_OMIT_RENDERED_FORM_FIELDS`" in normalized
    assert "preliminary or validation-only branch before the sink" in normalized
    assert "Never omit form identity" in normalized
    assert "complete baseline form before overlaying" in normalized
    assert "sparse dispatch-plus-token scaffold" in normalized
    assert "response `Set-Cookie` state from attack cannot alter" in normalized
    assert "scaffold's parser, bootstrap validation, session isolation" in normalized
    assert "do not replace those helpers or write a parallel request path" in normalized


def test_php_object_template_uses_two_consecutive_non_redirecting_requests() -> None:
    attack_token = "sqpobjt1." + "a" * 64
    control_token = "sqpobjt1." + "b" * 64
    rendered = _rendered_php_object_template()

    ast.parse(rendered)
    assert rendered.count("session.request(") == 2
    assert rendered.count("allow_redirects=False") == 3
    assert "FORM_BOOTSTRAP_REQUIRED = None" in rendered
    assert "SOURCE_ADDITIONAL_FORM_FIELDS = None" in rendered
    assert "SOURCE_OMIT_RENDERED_FORM_FIELDS = None" in rendered
    assert "expected exactly one coherent source-grounded form" in rendered
    assert "successful, non-submit controls" in rendered
    assert "reusable form nonce is missing or ambiguous" in rendered
    assert "single bounded\n# public form/nonce GET" in rendered
    assert rendered.index("form = _bootstrap_form(bootstrap_session)") < rendered.index(
        "for typed_name, exact_value in DISPATCH.items()"
    )
    assert rendered.index("for typed_name, exact_value in DISPATCH.items()") < (
        rendered.index("attack_form = _replace_field")
    )
    assert rendered.index("attack_form = _replace_field") < rendered.index(
        "attack_session = _clone_bootstrapped_session"
    )
    assert rendered.index("control_session = _clone_bootstrapped_session") < (
        rendered.index("attack_response =")
    )
    assert rendered.index("attack_response =") < rendered.index("control_response =")
    assert attack_token in rendered
    assert control_token in rendered
    assert 'oracle="object_instantiation"' in rendered
    assert '"effect": "verifier_inert_canary_wakeup"' in rendered
    assert '"csrf_fields"' not in rendered
    assert '"receipt":' not in rendered
    assert '"generation":' not in rendered
    assert PHP_OBJECT_INERT_IMPACT_DESCRIPTION in rendered


def test_php_object_template_fails_closed_on_undecided_or_sparse_direct_form() -> (
    None
):
    helpers = _template_helper_namespace(_rendered_php_object_template())
    bootstrap = helpers["_bootstrap_form"]

    class NoHttpSession:
        def __init__(self) -> None:
            self.calls = 0

        def get(self, *_args: object, **_kwargs: object) -> None:
            self.calls += 1
            raise AssertionError("bootstrap validation must precede HTTP")

    session = NoHttpSession()
    helpers["SOURCE_ADDITIONAL_FORM_FIELDS"] = None
    helpers["SOURCE_OMIT_RENDERED_FORM_FIELDS"] = None
    helpers["FORM_BOOTSTRAP_REQUIRED"] = None
    with pytest.raises(RuntimeError, match="explicitly decide"):
        bootstrap(session)
    assert session.calls == 0

    helpers["FORM_BOOTSTRAP_REQUIRED"] = False
    helpers["SOURCE_COMPLETE_FORM_FIELDS"] = None
    with pytest.raises(RuntimeError, match="source-complete form fields"):
        bootstrap(session)
    assert session.calls == 0

    helpers["SOURCE_COMPLETE_FORM_FIELDS"] = []
    assert bootstrap(session) == []
    helpers["SOURCE_COMPLETE_FORM_FIELDS"] = [
        ("optional_context", ""),
        ("semantic_value", "ready"),
    ]
    assert bootstrap(session) == [
        ("optional_context", ""),
        ("semantic_value", "ready"),
    ]
    assert session.calls == 0

    helpers["SOURCE_ADDITIONAL_FORM_FIELDS"] = []
    with pytest.raises(RuntimeError, match="direct form mode"):
        bootstrap(session)
    helpers["SOURCE_ADDITIONAL_FORM_FIELDS"] = None
    helpers["SOURCE_OMIT_RENDERED_FORM_FIELDS"] = []
    with pytest.raises(RuntimeError, match="direct form mode"):
        bootstrap(session)
    assert session.calls == 0


def test_php_object_template_harvests_one_complete_source_grounded_form() -> None:
    helpers = _template_helper_namespace(_rendered_php_object_template())
    complete = helpers["_complete_rendered_form"]
    rendered_form = """
        <form>
          <input type="hidden" name="fixture_id" value="form-7">
          <input type="hidden" name="csrf_token" value="decoy">
        </form>
        <form>
          <input type="hidden" name="fixture_id" value="form-7">
          <input type="hidden" name="csrf_token" value="nonce-7">
          <input type="hidden" name="metadata" value="alpha">
          <input type="hidden" name="metadata" value="beta">
          <input type="hidden" name="optional_context" value="">
          <input type="hidden" name="preliminary_step" value="validate">
          <input type="hidden" name="operation" value="process">
          <input type="email" name="contact_email" required
                 minlength="6" maxlength="80" value="">
          <input type="number" name="quantity" required min="2" max="5" value="">
          <input type="text" name="object_blob" required value="">
          <input type="checkbox" name="terms" value="yes" checked required>
          <input type="checkbox" name="ignored" value="no">
          <select name="tier" required>
            <option value="basic" selected>Basic</option>
          </select>
          <textarea name="notes">hello</textarea>
          <input type="submit" name="submit_action" value="Submit">
        </form>
    """
    arguments = (
        rendered_form,
        {"fixture_id": "form-7"},
        ["csrf_token", "contact_email", "quantity", "object_blob"],
        ["csrf_token"],
        ["contact_email", "quantity"],
        {"contact_email": "researcher@example.test", "quantity": "3"},
        [("presence_required_empty", "")],
        ["preliminary_step"],
        {"operation", "object_blob"},
    )

    pairs = complete(*arguments)

    assert [(name, value) for name, value in pairs if name == "metadata"] == [
        ("metadata", "alpha"),
        ("metadata", "beta"),
    ]
    assert ("fixture_id", "form-7") in pairs
    assert ("csrf_token", "nonce-7") in pairs
    assert ("contact_email", "researcher@example.test") in pairs
    assert ("quantity", "3") in pairs
    assert ("terms", "yes") in pairs
    assert ("tier", "basic") in pairs
    assert ("notes", "hello") in pairs
    assert ("optional_context", "") in pairs
    assert ("presence_required_empty", "") in pairs
    assert ("object_blob", "") in pairs
    assert not any(
        name in {"ignored", "preliminary_step", "submit_action"}
        for name, _value in pairs
    )

    invalid_email = (
        *arguments[:5],
        {"contact_email": "invalid", "quantity": "3"},
        *arguments[6:],
    )
    with pytest.raises(RuntimeError, match="valid email"):
        complete(*invalid_email)

    invalid_number = (
        *arguments[:5],
        {"contact_email": "researcher@example.test", "quantity": "9"},
        *arguments[6:],
    )
    with pytest.raises(RuntimeError, match="above its maximum"):
        complete(*invalid_number)


def test_php_object_template_rejects_ambiguous_or_browser_only_forms() -> None:
    helpers = _template_helper_namespace(_rendered_php_object_template())
    select_form = helpers["_select_source_grounded_form"]
    identity = {"fixture_id": "form-9"}
    coherent = ["contact_email"]
    ordinary = """
        <form>
          <input type="hidden" name="fixture_id" value="form-9">
          <input type="email" name="contact_email" value="a@example.test">
        </form>
    """

    with pytest.raises(RuntimeError, match="exactly one"):
        select_form(ordinary + ordinary, identity, coherent)

    patterned = ordinary.replace(
        'name="contact_email"',
        'name="contact_email" pattern=".+@.+"',
    )
    with pytest.raises(RuntimeError, match="unsupported browser-only"):
        select_form(patterned, identity, coherent)

    disabled_container = ordinary.replace(
        '<input type="email"',
        '<fieldset disabled><input type="email"',
    ).replace("</form>", "</fieldset></form>")
    with pytest.raises(RuntimeError, match="unsupported browser-only"):
        select_form(disabled_container, identity, coherent)


def test_php_object_template_rejects_unproven_rendered_form_adjustments() -> None:
    helpers = _template_helper_namespace(_rendered_php_object_template())
    complete = helpers["_complete_rendered_form"]
    rendered_form = """
        <form>
          <input type="hidden" name="fixture_id" value="form-11">
          <input type="hidden" name="optional_context" value="">
          <input type="text" name="required_context" required value="ready">
          <input type="text" name="object_blob" value="">
        </form>
    """
    common = (
        rendered_form,
        {"fixture_id": "form-11"},
        ["object_blob"],
        [],
        [],
        {},
    )

    with pytest.raises(RuntimeError, match="already has a rendered control"):
        complete(
            *common,
            [("optional_context", "replacement")],
            [],
            {"object_blob"},
        )
    with pytest.raises(RuntimeError, match="not a successful rendered control"):
        complete(*common, [], ["missing_context"], {"object_blob"})
    with pytest.raises(RuntimeError, match="required rendered form control"):
        complete(*common, [], ["required_context"], {"object_blob"})


def test_php_object_template_protects_harvested_identity_and_nonce_before_get() -> (
    None
):
    helpers = _template_helper_namespace(_rendered_php_object_template())

    class NoHttpSession:
        calls = 0

        def get(self, *_args: object, **_kwargs: object) -> None:
            self.calls += 1
            raise AssertionError("invalid bootstrap must not perform HTTP")

    helpers.update(
        {
            "TARGET": "http://localhost:8123",
            "OBJECT_FIELD": "object_blob",
            "DISPATCH": {"form:operation": "process"},
            "FORM_BOOTSTRAP_REQUIRED": True,
            "SOURCE_COMPLETE_FORM_FIELDS": None,
            "PUBLIC_FORM_URL": "http://localhost:8123/public-form",
            "FORM_IDENTITY": {"fixture_id": "form-7"},
            "COHERENT_FORM_FIELDS": ["csrf_token", "object_blob"],
            "REUSABLE_CSRF_FIELDS": ["csrf_token"],
            "REQUIRED_FORM_FIELDS": [],
            "FORM_FIELD_VALUES": {"csrf_token": "replacement"},
            "SOURCE_ADDITIONAL_FORM_FIELDS": [],
            "SOURCE_OMIT_RENDERED_FORM_FIELDS": [],
        }
    )
    session = NoHttpSession()

    with pytest.raises(RuntimeError, match="configuration is incomplete"):
        helpers["_bootstrap_form"](session)
    assert session.calls == 0


def test_php_object_template_protects_late_bound_and_identity_adjustments_before_get() -> (
    None
):
    helpers = _template_helper_namespace(_rendered_php_object_template())

    class NoHttpSession:
        calls = 0

        def get(self, *_args: object, **_kwargs: object) -> None:
            self.calls += 1
            raise AssertionError("invalid bootstrap must not perform HTTP")

    helpers.update(
        {
            "TARGET": "http://localhost:8123",
            "OBJECT_FIELD": "object_blob",
            "DISPATCH": {"form:operation": "process"},
            "FORM_BOOTSTRAP_REQUIRED": True,
            "SOURCE_COMPLETE_FORM_FIELDS": None,
            "PUBLIC_FORM_URL": "http://localhost:8123/public-form",
            "FORM_IDENTITY": {"fixture_id": "form-7"},
            "COHERENT_FORM_FIELDS": ["workflow_marker", "object_blob"],
            "REUSABLE_CSRF_FIELDS": [],
            "REQUIRED_FORM_FIELDS": [],
            "FORM_FIELD_VALUES": {},
            "SOURCE_ADDITIONAL_FORM_FIELDS": [("object_blob", "")],
            "SOURCE_OMIT_RENDERED_FORM_FIELDS": [],
        }
    )
    session = NoHttpSession()

    with pytest.raises(RuntimeError, match="configuration is incomplete"):
        helpers["_bootstrap_form"](session)
    assert session.calls == 0

    helpers["SOURCE_ADDITIONAL_FORM_FIELDS"] = []
    helpers["SOURCE_OMIT_RENDERED_FORM_FIELDS"] = ["fixture_id"]
    with pytest.raises(RuntimeError, match="configuration is incomplete"):
        helpers["_bootstrap_form"](session)
    assert session.calls == 0

    helpers["SOURCE_ADDITIONAL_FORM_FIELDS"] = [("workflow_marker", "ready")]
    helpers["SOURCE_OMIT_RENDERED_FORM_FIELDS"] = []
    with pytest.raises(RuntimeError, match="configuration is incomplete"):
        helpers["_bootstrap_form"](session)
    assert session.calls == 0

    helpers["SOURCE_ADDITIONAL_FORM_FIELDS"] = []
    helpers["SOURCE_OMIT_RENDERED_FORM_FIELDS"] = [["malformed"]]
    with pytest.raises(RuntimeError, match="configuration is incomplete"):
        helpers["_bootstrap_form"](session)
    assert session.calls == 0

    helpers["SOURCE_OMIT_RENDERED_FORM_FIELDS"] = ["stage", "stage"]
    with pytest.raises(RuntimeError, match="configuration is incomplete"):
        helpers["_bootstrap_form"](session)
    assert session.calls == 0


def test_php_object_template_isolates_attack_set_cookie_from_control_session() -> (
    None
):
    helpers = _template_helper_namespace(_rendered_php_object_template())
    clone_session = helpers["_clone_bootstrapped_session"]
    source = requests.Session()
    source.headers["X-Workflow"] = "bootstrapped"
    source.cookies.set(
        "workflow",
        "ready",
        domain="example.test",
        path="/",
    )

    attack = clone_session(source)
    control = clone_session(source)
    request = requests.Request("POST", "http://example.test/proof")
    attack_before = attack.prepare_request(request).headers.get("Cookie")
    control_before = control.prepare_request(request).headers.get("Cookie")

    assert attack_before == control_before == "workflow=ready"
    assert attack.headers == control.headers
    assert attack.cookies is not control.cookies
    response_headers = Message()
    response_headers.add_header(
        "Set-Cookie", "workflow=attack-response; Path=/"
    )
    response_headers.add_header("Set-Cookie", "attack_only=1; Path=/")
    response_raw = SimpleNamespace(
        _original_response=SimpleNamespace(msg=response_headers)
    )
    requests.cookies.extract_cookies_to_jar(
        attack.cookies,
        attack.prepare_request(request),
        response_raw,
    )
    attack.headers["X-Workflow"] = "attack-mutated"

    attack_after = attack.prepare_request(request).headers.get("Cookie")
    control_after = control.prepare_request(request).headers.get("Cookie")
    assert attack_after == "workflow=attack-response; attack_only=1"
    assert control_after == "workflow=ready"
    assert control.headers["X-Workflow"] == "bootstrapped"
    assert source.cookies.get("workflow", domain="example.test", path="/") == "ready"


def test_php_object_template_unauthenticated_arm_clones_omit_cookies() -> None:
    rendered = _rendered_php_object_template()
    helpers = _template_helper_namespace(rendered)
    clone_session = helpers["_clone_bootstrapped_session"]
    source = requests.Session()
    source.headers["Cookie"] = "manual=credential"
    source.cookies.set("workflow", "ready", domain="example.test", path="/")

    unauthenticated = clone_session(source, include_cookies=False)
    authenticated = clone_session(source)
    request = requests.Request("POST", "http://example.test/proof")

    assert unauthenticated.prepare_request(request).headers.get("Cookie") is None
    assert authenticated.prepare_request(request).headers.get("Cookie") is not None
    assert "include_cookies=not unauthenticated_actor" in rendered


def test_php_object_taxonomy_uses_only_trusted_object_oracle() -> None:
    profile = get_known_cwe_profile(BugClass.PHP_OBJECT_INJECTION)
    assert profile is not None
    assert profile.poc_template == "php_object_instantiation.py.j2"
    assert profile.allowed_oracles == frozenset({"object_instantiation"})
    assert profile.template_fit == "exact"


@pytest.mark.asyncio
async def test_verify_records_primitive_but_does_not_promote_full_finding(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    hypothesis = _hypothesis()
    plugin_root = _whole_post_plugin(tmp_path)
    transport = _expected_php_object_http_transport(
        hypothesis,
        plugin_root,
        "generic-plugin",
    )
    assert transport is not None
    author_contexts: list[dict[str, object]] = []

    class FakePoCAuthor:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        async def write(self, **kwargs: object) -> str:
            extra_context = kwargs["extra_context"]
            assert isinstance(extra_context, dict)
            author_contexts.append(dict(extra_context))
            return "import requests\n"

    class FakeSandbox:
        target_url = "http://localhost:8123"

        def __init__(self) -> None:
            self.oracle: PhpObjectOracle | None = None
            self.prepared_callsite: PhpObjectCallsite | None = None
            self.prepare_calls = 0
            self.run_calls: list[dict[str, object]] = []
            self.snapshot_calls = 0
            self.restart_calls = 0

        def baseline_user_accounts(self) -> list[dict[str, object]]:
            return []

        async def prepare_php_object_oracle(
            self,
            callsite: PhpObjectCallsite,
        ) -> dict[str, str]:
            self.prepare_calls += 1
            assert isinstance(callsite, PhpObjectCallsite)
            self.prepared_callsite = callsite
            self.oracle = PhpObjectOracle(
                callsite_path=(
                    "/var/www/html/wp-content/plugins/generic-plugin/"
                    + callsite.relative_path
                ),
                callsite_start_line=callsite.start_line,
                callsite_end_line=callsite.end_line,
                callsite_source_sha256=callsite.source_sha256,
            )
            return self.oracle.public_context()

        async def snapshot(self) -> Path:
            self.snapshot_calls += 1
            path = tmp_path / f"snapshot-{self.snapshot_calls}"
            path.mkdir()
            return path

        async def restore(self, _snapshot: Path) -> None:
            return None

        async def restart_wordpress_runtime(self) -> None:
            self.restart_calls += 1

        async def run_poc(
            self,
            _script_path: str,
            **kwargs: object,
        ) -> SandboxRunResult:
            self.run_calls.append(dict(kwargs))
            assert self.oracle is not None
            snapshot = _attest_generation(self.oracle)
            result = SandboxRunResult(
                success=True,
                output="sanitized output",
                elapsed=0,
                response="sanitized response",
                evidence={"run": len(self.run_calls)},
                observation=_observation(),
                validation_reason="trusted object receipt and wire trace matched",
            )
            result.retain_trusted_php_object_snapshot(snapshot)
            return result

    monkeypatch.setattr(verify_stage, "PoCAuthorAgent", FakePoCAuthor)
    config = PipelineConfig.from_yaml("tests/fixtures/pipeline.yaml")
    config.verify_max_iterations = 1
    config.report.screenshot_capture = False
    config.verify.state_introspection_on_failure = False
    sandbox = FakeSandbox()

    verification_dir = tmp_path / hypothesis.id
    finding = await verify_stage._verify_one(
        hypothesis,
        str(plugin_root),
        str(tmp_path / "plugin.zip"),
        "generic-plugin",
        config,
        cast(Any, object()),
        verification_dir,
        persistent_sb=cast(Any, sandbox),
    )

    assert finding is None
    assert sandbox.prepare_calls == 1
    assert sandbox.prepared_callsite == _expected_php_object_callsite(
        hypothesis,
        plugin_root,
    )
    assert sandbox.restart_calls == 1
    assert len(sandbox.run_calls) == 2
    assert all(call["expected_php_object"] is True for call in sandbox.run_calls)
    assert all(
        call["expected_php_object_transport"] == transport for call in sandbox.run_calls
    )
    assert all(
        call["expected_http_transport"] == transport for call in sandbox.run_calls
    )
    assert sandbox.oracle is not None
    assert author_contexts == [
        {
            "user_accounts": [],
            "attacker_role": "unauthenticated",
            "test_username": "",
            "test_password": "",
            "php_object_oracle": sandbox.oracle.public_context(),
            "php_object_http_transport": transport,
        }
    ]
    primitive_path = (
        verification_dir / verify_stage.PHP_OBJECT_PRIMITIVE_CONFIRMATION_FILENAME
    )
    primitive = json.loads(primitive_path.read_text())
    assert primitive["status"] == "primitive_confirmed"
    assert primitive["finding_promoted"] is False
    assert primitive["promotion_policy"] is None
    assert primitive["source_gadget_reviewed"] is True
    assert primitive["clean_state_executions"] == 2
    assert primitive["oracle_observation"] == {
        "confidentiality": "none",
        "integrity": "low",
        "availability": "none",
        "description": PHP_OBJECT_INERT_IMPACT_DESCRIPTION,
    }
    assert primitive["source_reviewed_outcome"] == (
        hypothesis.security_outcome.model_dump(mode="json")
    )
    assert (
        primitive["unmet_proof_requirement"]
        == (hypothesis.evidence_summary["proof_gaps"])
    )
    assert "cannot reproduce" in primitive["reason"]
    attempts = json.loads((verification_dir / "attempts.json").read_text())
    assert attempts["status"] == "primitive_confirmed"
    assert {
        attempt["proof_kind"] for attempt in attempts["attempts"]
    } == {"php_object_primitive"}
    assert verify_stage._attempt_checkpoint_state(verification_dir) == (
        "primitive_confirmed"
    )

    incomplete_attempts = json.loads(json.dumps(attempts))
    incomplete_attempts["attempts"] = incomplete_attempts["attempts"][1:]
    (verification_dir / "attempts.json").write_text(json.dumps(incomplete_attempts))
    assert verify_stage._attempt_checkpoint_state(verification_dir) == "incomplete"
    (verification_dir / "attempts.json").write_text(json.dumps(attempts))

    incomplete_primitive = json.loads(json.dumps(primitive))
    incomplete_primitive["clean_state_executions"] = 1
    primitive_path.write_text(json.dumps(incomplete_primitive))
    assert verify_stage._attempt_checkpoint_state(verification_dir) == "incomplete"
    primitive_path.write_text(json.dumps(primitive))

    natural_path = (
        verification_dir / verify_stage.PHP_OBJECT_NATURAL_CONFIRMATION_FILENAME
    )
    natural_path.write_text("{}")
    assert verify_stage._attempt_checkpoint_state(verification_dir) == "incomplete"
    natural_path.unlink()
    assert verify_stage._attempt_checkpoint_state(verification_dir) == (
        "primitive_confirmed"
    )

    persisted = primitive_path.read_text() + json.dumps(attempts)
    public_context = sandbox.oracle.public_context()
    assert public_context["attack_token"] not in persisted
    assert public_context["control_token"] not in persisted


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scenario",
    ["promoted", "gate_rejected", "natural_first_failed", "natural_replay_failed"],
)
async def test_verify_promotes_only_after_two_natural_gadget_executions(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    scenario: str,
) -> None:
    recipe = _direct_gadget_recipe()
    hypothesis = _hypothesis().model_copy(
        update={"php_object_gadget_recipe": recipe}
    )
    plugin_root = _whole_post_plugin(tmp_path)
    transport = _expected_php_object_http_transport(
        hypothesis,
        plugin_root,
        "generic-plugin",
    )
    assert transport is not None

    class FakePoCAuthor:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        async def write(self, **_kwargs: object) -> str:
            return "import requests\n"

    class FakeSandbox:
        target_url = "http://localhost:8123"

        def __init__(self) -> None:
            self.oracle: PhpObjectOracle | None = None
            self.run_calls = 0
            self.snapshot_calls = 0

        def baseline_user_accounts(self) -> list[dict[str, object]]:
            return []

        async def prepare_php_object_oracle(
            self,
            callsite: PhpObjectCallsite,
        ) -> dict[str, str]:
            self.oracle = PhpObjectOracle(
                callsite_path=(
                    "/var/www/html/wp-content/plugins/generic-plugin/"
                    + callsite.relative_path
                ),
                callsite_start_line=callsite.start_line,
                callsite_end_line=callsite.end_line,
                callsite_source_sha256=callsite.source_sha256,
            )
            return self.oracle.public_context()

        async def snapshot(self) -> Path:
            self.snapshot_calls += 1
            path = tmp_path / f"promotion-snapshot-{self.snapshot_calls}"
            path.mkdir()
            return path

        async def restore(self, _snapshot: Path) -> None:
            return None

        async def restart_wordpress_runtime(self) -> None:
            return None

        async def run_poc(
            self,
            _script_path: str,
            **_kwargs: object,
        ) -> SandboxRunResult:
            self.run_calls += 1
            assert self.oracle is not None
            result = SandboxRunResult(
                success=True,
                output="sanitized primitive output",
                elapsed=0,
                response="sanitized primitive response",
                evidence={"primitive_run": self.run_calls},
                observation=_observation(),
            )
            result.retain_trusted_php_object_snapshot(
                _attest_generation(self.oracle)
            )
            return result

    def natural_result(label: str) -> SandboxRunResult:
        observation = PoCObservation(
            verdict="vulnerable",
            oracle="file_effect",
            attacker_role="unauthenticated",
            request={
                "method": "POST",
                "url": "http://localhost:8123/wp-admin/admin-ajax.php",
                "transport_contract_sha256": "66" * 32,
            },
            attack={
                "observed": True,
                "effect": "verifier_owned_temporary_file_deleted",
                "target_path_sha256": "77" * 32,
                "target_content_sha256": "88" * 32,
                "source_recipe_sha256": "99" * 32,
                "collateral_paths_unchanged": True,
            },
            control={
                "observed": False,
                "effect": "verifier_owned_temporary_file_deleted",
                "target_path_sha256": "77" * 32,
                "target_content_sha256": "88" * 32,
                "source_recipe_sha256": "99" * 32,
                "target_preserved": True,
            },
            impact=CIAImpact(
                confidentiality="none",
                integrity="low",
                availability="none",
                description=verify_stage.PHP_OBJECT_NATURAL_IMPACT_DESCRIPTION,
            ),
        )
        return SandboxRunResult(
            success=True,
            output=(
                'SQUADRONE_RESULT={"oracle":"object_instantiation",'
                '"verdict":"vulnerable"}\n'
            ),
            elapsed=0,
            response=(
                'SQUADRONE_RESULT={"oracle":"object_instantiation",'
                '"verdict":"vulnerable"}\n'
            ),
            evidence={
                "natural_run": label,
                "stdout_tail": (
                    '"oracle":"object_instantiation",'
                    '"verdict":"vulnerable"}'
                ),
                "observation": observation.model_dump(mode="json"),
            },
            observation=observation,
        )

    replay_calls: list[dict[str, object]] = []

    async def fake_natural_replay(
        _sandbox: object,
        **kwargs: object,
    ) -> verify_stage._PhpObjectNaturalReplay:
        replay_calls.append(dict(kwargs))
        if scenario == "natural_first_failed":
            return verify_stage._PhpObjectNaturalReplay(
                first_result=SandboxRunResult(
                    success=False,
                    output="natural gadget did not reproduce",
                    elapsed=0,
                    validation_reason="synthetic natural first-run failure",
                ),
                first_snapshot=None,
                confirmation_result=None,
                confirmation_snapshot=None,
                confirmed=False,
                reason="synthetic natural first-run failure",
            )
        if scenario == "natural_replay_failed":
            return verify_stage._PhpObjectNaturalReplay(
                first_result=natural_result("first"),
                first_snapshot=cast(Any, object()),
                confirmation_result=SandboxRunResult(
                    success=False,
                    output="natural gadget did not reproduce on replay",
                    elapsed=0,
                    validation_reason="synthetic natural replay failure",
                ),
                confirmation_snapshot=None,
                confirmed=False,
                reason="synthetic natural replay failure",
            )
        return verify_stage._PhpObjectNaturalReplay(
            first_result=natural_result("first"),
            first_snapshot=cast(Any, object()),
            confirmation_result=natural_result("confirmation"),
            confirmation_snapshot=cast(Any, object()),
            confirmed=True,
            reason="matched",
        )

    natural_marker: dict[str, object] = {
        "schema_version": 1,
        "status": "confirmed",
        "proof_kind": "php_object_natural",
        "hypothesis_id": hypothesis.id,
    }
    validated: list[object] = []

    def fake_validate(finding: object) -> tuple[bool, str]:
        validated.append(finding)
        return (
            (True, "valid")
            if scenario != "gate_rejected"
            else (False, "synthetic promotion rejection")
        )

    monkeypatch.setattr(verify_stage, "PoCAuthorAgent", FakePoCAuthor)
    monkeypatch.setattr(
        verify_stage,
        "validate_php_object_gadget_recipe_sources",
        lambda *_args: None,
    )
    monkeypatch.setattr(
        verify_stage,
        "_run_php_object_natural_replay",
        fake_natural_replay,
    )
    monkeypatch.setattr(
        verify_stage,
        "_php_object_natural_confirmation_payload",
        lambda *_args: natural_marker,
    )
    monkeypatch.setattr(
        verify_stage,
        "validate_php_object_natural_finding_confirmation",
        fake_validate,
    )
    config = PipelineConfig.from_yaml("tests/fixtures/pipeline.yaml")
    config.verify_max_iterations = 1
    config.report.screenshot_capture = False
    config.verify.state_introspection_on_failure = False
    sandbox = FakeSandbox()
    verification_dir = tmp_path / hypothesis.id

    verification = verify_stage._verify_one(
        hypothesis,
        str(plugin_root),
        str(tmp_path / "plugin.zip"),
        "generic-plugin",
        config,
        cast(Any, object()),
        verification_dir,
        persistent_sb=cast(Any, sandbox),
    )
    if scenario == "gate_rejected":
        with pytest.raises(RuntimeError, match="synthetic promotion rejection"):
            await verification
        assert len(validated) == 1
        assert not (
            verification_dir
            / verify_stage.PHP_OBJECT_PRIMITIVE_CONFIRMATION_FILENAME
        ).exists()
        assert not (
            verification_dir
            / verify_stage.PHP_OBJECT_NATURAL_CONFIRMATION_FILENAME
        ).exists()
        attempts = json.loads((verification_dir / "attempts.json").read_text())
        assert attempts["status"] == "in_progress"
        return

    finding = await verification
    if scenario in {"natural_first_failed", "natural_replay_failed"}:
        assert finding is None
        assert validated == []
        primitive = json.loads(
            (
                verification_dir
                / verify_stage.PHP_OBJECT_PRIMITIVE_CONFIRMATION_FILENAME
            ).read_text()
        )
        assert primitive["finding_promoted"] is False
        assert "synthetic natural" in primitive["reason"]
        assert not (
            verification_dir
            / verify_stage.PHP_OBJECT_NATURAL_CONFIRMATION_FILENAME
        ).exists()
        attempts = json.loads((verification_dir / "attempts.json").read_text())
        assert attempts["status"] == "primitive_confirmed"
        natural_attempts = [
            attempt
            for attempt in attempts["attempts"]
            if attempt["proof_kind"] == "php_object_natural"
        ]
        assert natural_attempts
        assert [attempt["result"] for attempt in natural_attempts] == (
            ["failed"]
            if scenario == "natural_first_failed"
            else ["success", "failed"]
        )
        return

    assert finding is not None
    assert finding.confidence_runs == 2
    assert finding.verified_impact == CIAImpact(
        confidentiality="none",
        integrity="low",
        availability="none",
        description=verify_stage.PHP_OBJECT_NATURAL_IMPACT_DESCRIPTION,
    )
    assert finding.hypothesis.security_outcome.integrity == "low"
    assert len(replay_calls) == 1
    assert replay_calls[0]["recipe"] is recipe
    assert validated == [finding]
    natural_attempts = [
        attempt
        for attempt in finding.poc_attempts
        if attempt.proof_kind == "php_object_natural"
    ]
    assert all(attempt.response_snippet is None for attempt in natural_attempts)
    assert all(attempt.error_log_snippet is None for attempt in natural_attempts)
    for key in ("first_run", "confirmation_run"):
        natural_evidence = cast(dict[str, object], finding.evidence[key])
        assert natural_evidence["stdout_tail"] == ""
        assert "SQUADRONE_RESULT=" not in json.dumps(natural_evidence)
        assert "object_instantiation" not in json.dumps(natural_evidence)
    assert [
        (attempt.proof_kind, attempt.phase, attempt.result.value)
        for attempt in finding.poc_attempts
    ] == [
        ("php_object_primitive", "attack", "success"),
        ("php_object_primitive", "confirmation", "success"),
        ("php_object_natural", "attack", "success"),
        ("php_object_natural", "confirmation", "success"),
    ]
    primitive = json.loads(
        (
            verification_dir
            / verify_stage.PHP_OBJECT_PRIMITIVE_CONFIRMATION_FILENAME
        ).read_text()
    )
    assert primitive["finding_promoted"] is True
    assert primitive["clean_state_executions"] == 2
    assert primitive["unmet_proof_requirement"] is None
    assert json.loads(
        (
            verification_dir
            / verify_stage.PHP_OBJECT_NATURAL_CONFIRMATION_FILENAME
        ).read_text()
    ) == natural_marker
    attempts = json.loads((verification_dir / "attempts.json").read_text())
    assert attempts["status"] == "confirmed"


@pytest.mark.asyncio
async def test_parent_oracle_rejection_outranks_child_success_declaration(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A missing trusted receipt must stay failed across every feedback surface."""
    hypothesis = _hypothesis()
    plugin_root = _whole_post_plugin(tmp_path)
    author_histories: list[list[dict[str, object]]] = []
    developer_feedback: list[str] = []
    developer_error_feedback: list[tuple[str, str]] = []

    class FakePoCAuthor:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        async def write(self, **kwargs: object) -> str:
            previous = cast(list[Any], kwargs["previous_attempts"])
            author_histories.append(
                [attempt.model_dump(mode="json") for attempt in previous]
            )
            return "import requests\n"

    class AdversarialDeveloper:
        async def propose_setup(self, *_args: object, **_kwargs: object) -> SetupPlan:
            return SetupPlan()

        async def propose_setup_followup(self, **kwargs: object) -> SetupPlan:
            developer_feedback.append(str(kwargs["last_stdout"]))
            developer_error_feedback.append(
                (str(kwargs["last_stderr"]), str(kwargs["last_error_log"]))
            )
            return SetupPlan(
                failure_class="exploit_shape",
                rationale="The canary was proven to instantiate.",
                commands=[],
            )

    class FakeSandbox:
        target_url = "http://localhost:8123"
        wp_cli = None

        def setup_http_context(self) -> verify_stage.SetupHttpContext:
            return verify_stage.SetupHttpContext.from_wordpress_origins(
                internal_connect_origin=(
                    verify_stage.SandboxManager.INTERNAL_WORDPRESS_ORIGIN
                ),
                canonical_wordpress_origin=self.target_url,
            )

        def baseline_user_accounts(self) -> list[dict[str, object]]:
            return []

        async def prepare_php_object_oracle(
            self,
            _callsite: PhpObjectCallsite,
        ) -> dict[str, str]:
            return {"mode": "php_object"}

        async def snapshot(self) -> Path:
            snapshot = tmp_path / f"snapshot-{time.monotonic_ns()}"
            snapshot.mkdir()
            return snapshot

        async def restore(self, _snapshot: Path) -> None:
            return None

        async def restart_wordpress_runtime(self) -> None:
            return None

        async def run_poc(
            self,
            _script_path: str,
            **_kwargs: object,
        ) -> SandboxRunResult:
            observation = _observation()
            child_line = "SQUADRONE_RESULT=" + observation.model_dump_json()
            return SandboxRunResult(
                success=False,
                output="instantiated=true\n" + child_line,
                response=child_line,
                error_log="runtime diagnostic\n" + child_line,
                elapsed=0,
                observation=observation,
                validation_reason=(
                    "Trusted parent PHP object diagnostic: attack policy accepted; "
                    "attack payload privately rewritten; upstream response received; "
                    "required attack receipt missing; instantiation/control remain "
                    "unestablished."
                ),
            )

    monkeypatch.setattr(verify_stage, "PoCAuthorAgent", FakePoCAuthor)
    config = PipelineConfig.from_yaml("tests/fixtures/pipeline.yaml")
    config.verify_max_iterations = 2
    config.report.screenshot_capture = False
    config.verify.state_introspection_on_failure = False
    verification_dir = tmp_path / hypothesis.id

    finding = await verify_stage._verify_one(
        hypothesis,
        str(plugin_root),
        str(tmp_path / "plugin.zip"),
        "generic-plugin",
        config,
        cast(Any, object()),
        verification_dir,
        developer=cast(Any, AdversarialDeveloper()),
        persistent_sb=cast(Any, FakeSandbox()),
    )

    assert finding is None
    assert len(author_histories) == 2
    assert author_histories[0] == []
    assert author_histories[1][0]["observation"] is None
    rejected = cast(dict, author_histories[1][0]["rejected_observation"])
    assert rejected["verdict"] == "vulnerable"
    assert developer_feedback == [
        "AUTHORITATIVE RUNNER VERDICT: FAILED\n"
        "AUTHORITATIVE VALIDATION REASON: Trusted parent PHP object diagnostic: "
        "attack policy accepted; attack payload privately rewritten; upstream "
        "response received; required attack receipt missing; instantiation/control "
        "remain unestablished.\n"
        "REJECTED CHILD OBSERVATION: the PoC emitted a machine self-report, but "
        "none of its success declarations are established measurements.\n"
        "REPORTED ORACLE TYPE (diagnostic only): object_instantiation\n"
        "OTHER CHILD OUTPUT: withheld because the runner rejected the observation; "
        "consult only the authoritative validation reason."
    ]
    assert "SQUADRONE_RESULT=" not in developer_feedback[0]
    assert "instantiated" not in developer_feedback[0]
    assert developer_error_feedback == [("", "")]

    attempts = json.loads((verification_dir / "attempts.json").read_text())
    assert attempts["status"] == "not_confirmed"
    assert len(attempts["attempts"]) == 2
    for attempt in attempts["attempts"]:
        assert attempt["result"] == "failed"
        assert attempt["observation"] is None
        assert attempt["rejected_observation"]["verdict"] == "vulnerable"
        assert "SQUADRONE_RESULT=" not in (attempt["response_snippet"] or "")
        assert "SQUADRONE_RESULT=" not in (attempt["error_log_snippet"] or "")
        assert "Trusted parent PHP object diagnostic" in attempt["validation_reason"]
        assert "required attack receipt missing" in attempt["validation_reason"]
    assert attempts["attempts"][0]["developer_analysis"].startswith(
        "UNTRUSTED DEVELOPER CLASSIFICATION ONLY; the runner failure remains "
        "authoritative: classification=exploit_shape"
    )
    assert "canary was proven" not in json.dumps(attempts)
    assert not (
        verification_dir / verify_stage.PHP_OBJECT_PRIMITIVE_CONFIRMATION_FILENAME
    ).exists()


def test_transport_incomplete_runtime_failure_stays_actionable_in_feedback() -> None:
    runtime_error = (
        "Traceback (most recent call last):\n"
        "RuntimeError: rendered form bootstrap failed"
    )
    result = SandboxRunResult(
        success=False,
        output="",
        elapsed=0.1,
        error_log=runtime_error,
        validation_reason=(
            "PoC process exited 1 before PHP object transport completed"
        ),
        evidence={
            "php_object_oracle_error": "transport_incomplete",
            "php_object_oracle_failure_reason": (
                "php_object_transport_incomplete"
            ),
        },
    )

    feedback = verify_stage._runner_failure_feedback(result)
    assert "PoC process exited 1 before PHP object transport completed" in feedback
    assert "expected attack/control transport did not complete" in feedback
    assert "not classified as executable-surface drift" in feedback
    assert "surface_attestation_failed" not in feedback
    assert "rendered form bootstrap failed" in (
        verify_stage._runner_failure_error_feedback(result)
    )
    assert "expected attack/control transport did not complete" in (
        verify_stage._attempt_response_snippet(result) or ""
    )
    assert verify_stage._attempt_error_log_snippet(result) == runtime_error
