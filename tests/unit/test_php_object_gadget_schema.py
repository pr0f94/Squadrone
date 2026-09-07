from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError

from squadrone.agents.prompts_io import load_prompt
from squadrone.schemas.hypothesis import (
    Confidence,
    Hypothesis,
    HypothesesArtifact,
    TriagedArtifact,
)
from squadrone.schemas.php_object_gadget import (
    PhpObjectGadgetRecipe,
    PhpObjectGadgetValue,
)
from squadrone.schemas.taxonomy import BugClass, critic_evidence_contract_for
from squadrone.stages.triage import (
    _validate_critic_accounting,
    validate_php_object_gadget_recipe_sources,
)


_PLUGIN_SOURCE = r"""<?php
namespace Vendor;

final class Cleaner {
    protected $files = array();
    protected $generation = null;

    public function __destruct() {
        $this->destroyFiles();
    }

    private function destroyFiles() {
        foreach ($this->files as $file) {
            @\unlink($file);
        }
        \strlen('safe filler');
        $handle = \opendir(CACHE_ROOT);
        while (($sibling = \readdir($handle)) !== false) {
            if (\strpos($sibling, '__demo_'.$this->generation.'_') === 0) {
                \unlink(CACHE_ROOT.$sibling);
            }
        }
        \closedir($handle);
    }
}

function process_submission() {
    unserialize($_POST['serialized_payload']);
}
"""


def _recipe_payload(
    *,
    helper_source: str | None = None,
    guard_source: str | None = None,
    guarded_effect_line: int = 20,
) -> dict[str, object]:
    helper_source = (
        helper_source
        or r"""private function destroyFiles() {
        foreach ($this->files as $file) {
            @\unlink($file);
        }
        \strlen('safe filler');
        $handle = \opendir(CACHE_ROOT);
        while (($sibling = \readdir($handle)) !== false) {
            if (\strpos($sibling, '__demo_'.$this->generation.'_') === 0) {
                \unlink(CACHE_ROOT.$sibling);
            }
        }
        \closedir($handle);
    }"""
    )
    guard_source = (
        guard_source
        or r"""if (\strpos($sibling, '__demo_'.$this->generation.'_') === 0) {
                \unlink(CACHE_ROOT.$sibling);
            }"""
    )
    return {
        "schema_version": 1,
        "effect": "file_delete",
        "effect_sink": "unlink",
        "gadget_object": {
            "class_name": "Vendor\\Cleaner",
            "class_anchor": {
                "file": "vendor/cleaner.php",
                "line": 4,
                "source_code": "final class Cleaner {",
            },
            "trigger": "__destruct",
            "trigger_declaring_class": "Vendor\\Cleaner",
            "trigger_anchor": {
                "file": "vendor/cleaner.php",
                "line": 8,
                "source_code": """public function __destruct() {
        $this->destroyFiles();
    }""",
            },
            "properties": [
                {
                    "name": "files",
                    "declaring_class": "Vendor\\Cleaner",
                    "visibility": "protected",
                    "value": {
                        "kind": "list",
                        "items": [
                            {
                                "kind": "capability",
                                "capability": "ephemeral_file_path",
                            }
                        ],
                    },
                },
                {
                    "name": "generation",
                    "declaring_class": "Vendor\\Cleaner",
                    "visibility": "protected",
                    "value": {"kind": "opaque_generation_id"},
                },
            ],
        },
        "effect_binding": {
            "kind": "direct_path",
            "effect_property": "files",
            "access": "list_item",
            "effect_variable": "file",
            "iteration_anchor": {
                "file": "vendor/cleaner.php",
                "line": 13,
                "source_code": r"""foreach ($this->files as $file) {
            @\unlink($file);
        }""",
            },
            "effect_anchor": {
                "file": "vendor/cleaner.php",
                "line": 14,
                "source_code": r"@\unlink($file);",
            },
        },
        "helper_anchors": [
            {
                "symbol": "Vendor\\Cleaner::destroyFiles",
                "anchor": {
                    "file": "vendor/cleaner.php",
                    "line": 12,
                    "source_code": helper_source,
                },
            }
        ],
        "guarded_effect_anchors": [
            {
                "anchor": {
                    "file": "vendor/cleaner.php",
                    "line": guarded_effect_line,
                    "source_code": r"\unlink(CACHE_ROOT.$sibling);",
                },
                "guard_anchor": {
                    "file": "vendor/cleaner.php",
                    "line": 19,
                    "source_code": guard_source,
                },
                "guard_property": "generation",
                "directory_constant": "CACHE_ROOT",
                "basename_prefix": "__demo_",
                "basename_suffix": "_",
            }
        ],
    }


def _recipe(
    *,
    helper_source: str | None = None,
    guard_source: str | None = None,
    guarded_effect_line: int = 20,
) -> PhpObjectGadgetRecipe:
    return PhpObjectGadgetRecipe.model_validate(
        _recipe_payload(
            helper_source=helper_source,
            guard_source=guard_source,
            guarded_effect_line=guarded_effect_line,
        )
    )


def _hypothesis(recipe: PhpObjectGadgetRecipe | None = None) -> Hypothesis:
    return Hypothesis(
        id="poi-1",
        specialist="injection_files",
        bug_class=BugClass.PHP_OBJECT_INJECTION,
        entry_point="process_submission",
        file="vendor/cleaner.php",
        line=28,
        sink="unserialize",
        sink_code="unserialize($_POST['serialized_payload']);",
        taint_path=["$_POST['serialized_payload']", "unserialize"],
        reasoning="External serialized bytes reach a shipped file-delete gadget.",
        confidence=Confidence.HIGH,
        affected_versions="<=1.0",
        evidence_summary={"usable_gadget": True},
        php_object_gadget_recipe=recipe,
    )


def _write_plugin(tmp_path: Path, source: str = _PLUGIN_SOURCE) -> Path:
    plugin_root = tmp_path / "plugin"
    source_file = plugin_root / "vendor" / "cleaner.php"
    source_file.parent.mkdir(parents=True)
    source_file.write_text(source, encoding="utf-8")
    return plugin_root


def _tcpdf_fixture(tmp_path: Path) -> tuple[Path, PhpObjectGadgetRecipe]:
    tcpdf_lines = [""] * 7888
    replacements = {
        137: "class TCPDF {",
        200: "    protected $imagekeys = array();",
        201: "    protected $file_id = null;",
        1879: "    public function __construct() {}",
        2036: "    public function __destruct() {",
        2037: "        // cleanup",
        2038: "        $this->_destroy(true);",
        2039: "    }",
        7835: "    protected static $cleaned_ids = array();",
        7843: (
            "    public function _destroy($destroyall=false, $preserve_objcopy=false) {"
        ),
        7844: "        if (isset(self::$cleaned_ids[$this->file_id])) {",
        7845: "            $destroyall = false;",
        7846: "        }",
        7847: "        if ($destroyall AND !$preserve_objcopy && isset($this->file_id)) {",
        7848: "            self::$cleaned_ids[$this->file_id] = true;",
        7849: "            // remove all temporary files",
        7850: "            if ($handle = @opendir(K_PATH_CACHE)) {",
        7851: "                while (false !== ($file_name = readdir($handle))) {",
        7852: (
            "                    if (strpos($file_name, '__tcpdf_'.$this->file_id.'_') === 0) {"
        ),
        7853: "                        unlink(K_PATH_CACHE.$file_name);",
        7854: "                    }",
        7855: "                }",
        7856: "                closedir($handle);",
        7857: "            }",
        7858: "            if (isset($this->imagekeys)) {",
        7859: "                foreach ($this->imagekeys as $file) {",
        7860: (
            "                    if (strpos($file, K_PATH_CACHE) === 0 && "
            "TCPDF_STATIC::file_exists($file)) {"
        ),
        7861: "                        @unlink($file);",
        7862: "                    }",
        7863: "                }",
        7864: "            }",
        7865: "        }",
        7866: "        $preserve = array(",
        7867: "            'file_id',",
        7868: "            'state',",
        7869: "            'bufferlen',",
        7870: "            'buffer',",
        7871: "            'cached_files',",
        7872: "            'imagekeys',",
        7873: "            'sign',",
        7874: "            'signature_data',",
        7875: "            'signature_max_length',",
        7876: "            'byterange_string',",
        7877: "            'tsa_timestamp',",
        7878: "            'tsa_data'",
        7879: "        );",
        7880: "        foreach (array_keys(get_object_vars($this)) as $val) {",
        7881: "            if ($destroyall OR !in_array($val, $preserve)) {",
        7882: (
            "                if ((!$preserve_objcopy OR ($val != 'objcopy')) AND "
            "($val != 'file_id') AND isset($this->$val)) {"
        ),
        7883: "                    unset($this->$val);",
        7884: "                }",
        7885: "            }",
        7886: "        }",
        7887: "    }",
        7888: "}",
    }
    for line, content in replacements.items():
        tcpdf_lines[line - 1] = content
    tcpdf_source = "\n".join(tcpdf_lines) + "\n"

    static_lines = [""] * 1886
    static_replacements = {
        1874: "class TCPDF_STATIC {",
        1875: "    public static function file_exists($filename) {",
        1876: "        if (preg_match('|^https?://|', $filename) == 1) {",
        1877: "            return self::url_exists($filename);",
        1878: "        }",
        1879: "        if (strpos($filename, '://')) {",
        1880: (
            "            return false; // only support http and https wrappers "
            "for security reasons"
        ),
        1881: "        }",
        1882: "        return @file_exists($filename);",
        1883: "    }",
        1886: "}",
    }
    for line, content in static_replacements.items():
        static_lines[line - 1] = content
    static_source = "\n".join(static_lines) + "\n"

    plugin_root = tmp_path / "give"
    tcpdf_file = plugin_root / "vendor" / "tecnickcom" / "tcpdf" / "tcpdf.php"
    static_file = tcpdf_file.parent / "include" / "tcpdf_static.php"
    static_file.parent.mkdir(parents=True)
    tcpdf_file.write_text(tcpdf_source, encoding="utf-8")
    static_file.write_text(static_source, encoding="utf-8")

    destroy_source = "\n".join(tcpdf_lines[7842:7887])
    static_helper_source = "\n".join(static_lines[1874:1883])
    recipe = PhpObjectGadgetRecipe.model_validate(
        {
            "schema_version": 1,
            "effect": "file_delete",
            "effect_sink": "unlink",
            "gadget_object": {
                "class_name": "TCPDF",
                "class_anchor": {
                    "file": "vendor/tecnickcom/tcpdf/tcpdf.php",
                    "line": 137,
                    "source_code": "class TCPDF {",
                },
                "trigger": "__destruct",
                "trigger_declaring_class": "TCPDF",
                "trigger_anchor": {
                    "file": "vendor/tecnickcom/tcpdf/tcpdf.php",
                    "line": 2036,
                    "source_code": "\n".join(tcpdf_lines[2035:2039]),
                },
                "properties": [
                    {
                        "name": "imagekeys",
                        "declaring_class": "TCPDF",
                        "visibility": "protected",
                        "value": {
                            "kind": "list",
                            "items": [
                                {
                                    "kind": "capability",
                                    "capability": "ephemeral_file_path",
                                }
                            ],
                        },
                    },
                    {
                        "name": "file_id",
                        "declaring_class": "TCPDF",
                        "visibility": "protected",
                        "value": {"kind": "opaque_generation_id"},
                    },
                ],
            },
            "effect_binding": {
                "kind": "direct_path",
                "effect_property": "imagekeys",
                "access": "list_item",
                "effect_variable": "file",
                "iteration_anchor": {
                    "file": "vendor/tecnickcom/tcpdf/tcpdf.php",
                    "line": 7859,
                    "source_code": "\n".join(tcpdf_lines[7858:7863]),
                },
                "effect_anchor": {
                    "file": "vendor/tecnickcom/tcpdf/tcpdf.php",
                    "line": 7861,
                    "source_code": "@unlink($file);",
                },
                "local_path_check": {
                    "guard_anchor": {
                        "file": "vendor/tecnickcom/tcpdf/tcpdf.php",
                        "line": 7860,
                        "source_code": "\n".join(tcpdf_lines[7859:7862]),
                    },
                    "directory_constant": "K_PATH_CACHE",
                    "helper_symbol": "TCPDF_STATIC::file_exists",
                },
            },
            "helper_anchors": [
                {
                    "symbol": "TCPDF::_destroy",
                    "anchor": {
                        "file": "vendor/tecnickcom/tcpdf/tcpdf.php",
                        "line": 7843,
                        "source_code": destroy_source,
                    },
                },
                {
                    "symbol": "TCPDF_STATIC::file_exists",
                    "contract": "local_path_exists",
                    "anchor": {
                        "file": ("vendor/tecnickcom/tcpdf/include/tcpdf_static.php"),
                        "line": 1875,
                        "source_code": static_helper_source,
                    },
                },
            ],
            "guarded_effect_anchors": [
                {
                    "anchor": {
                        "file": "vendor/tecnickcom/tcpdf/tcpdf.php",
                        "line": 7853,
                        "source_code": "unlink(K_PATH_CACHE.$file_name);",
                    },
                    "guard_anchor": {
                        "file": "vendor/tecnickcom/tcpdf/tcpdf.php",
                        "line": 7852,
                        "source_code": "\n".join(tcpdf_lines[7851:7854]),
                    },
                    "guard_property": "file_id",
                    "directory_constant": "K_PATH_CACHE",
                    "basename_prefix": "__tcpdf_",
                    "basename_suffix": "_",
                }
            ],
        }
    )
    return plugin_root, recipe


def test_recipe_accepts_one_object_path_capability_and_opaque_guard() -> None:
    recipe = _recipe()

    assert recipe.schema_version == 1
    assert recipe.effect_binding.kind == "direct_path"
    assert recipe.gadget_object.properties[0].visibility == "protected"
    assert recipe.gadget_object.properties[1].value.kind == "opaque_generation_id"
    assert recipe.guarded_effect_anchors[0].guard_property == "generation"


@pytest.mark.parametrize(
    "unsafe_value",
    [
        "/tmp/target",
        "..%2ftarget",
        'O:7:"Cleaner":0:{}',
        "Vendor\\Cleaner::run",
        "system",
    ],
)
def test_recipe_rejects_raw_paths_serialization_and_callbacks(
    unsafe_value: str,
) -> None:
    with pytest.raises(ValidationError):
        PhpObjectGadgetValue(kind="string", value=unsafe_value)


@pytest.mark.parametrize("kind", ["object", "reference", "callback"])
def test_recipe_has_no_nested_object_reference_or_callback_kind(kind: str) -> None:
    with pytest.raises(ValidationError):
        PhpObjectGadgetValue.model_validate({"kind": kind, "value": "anything"})


def test_recipe_rejects_raw_serialized_payload_field() -> None:
    payload = _recipe_payload()
    payload["serialized_payload"] = 'O:7:"Cleaner":0:{}'

    with pytest.raises(ValidationError, match="extra_forbidden"):
        PhpObjectGadgetRecipe.model_validate(payload)


@pytest.mark.parametrize("capability_count", [0, 2])
def test_recipe_requires_exactly_one_path_capability(capability_count: int) -> None:
    payload = _recipe_payload()
    properties = payload["gadget_object"]["properties"]  # type: ignore[index]
    properties[0]["value"]["items"] = [  # type: ignore[index]
        {"kind": "capability", "capability": "ephemeral_file_path"}
        for _ in range(capability_count)
    ]

    with pytest.raises(ValidationError, match="exactly one ephemeral_file_path"):
        PhpObjectGadgetRecipe.model_validate(payload)


def test_recipe_rejects_unaccounted_unlink_in_complete_helper(tmp_path: Path) -> None:
    helper = _recipe_payload()["helper_anchors"][0]["anchor"]["source_code"]  # type: ignore[index]
    helper = str(helper).replace(
        r"\strlen('safe filler');",
        r"\unlink($unaccounted);",
    )

    source = _PLUGIN_SOURCE.replace(
        r"\strlen('safe filler');",
        r"\unlink($unaccounted);",
    )
    recipe = _recipe(helper_source=helper)
    plugin_root = _write_plugin(tmp_path, source)

    error = validate_php_object_gadget_recipe_sources(plugin_root, recipe)

    assert error is not None
    assert "every reachable unlink" in error


def test_recipe_rejects_guard_not_bound_to_opaque_property() -> None:
    payload = _recipe_payload()
    payload["guarded_effect_anchors"][0]["guard_property"] = "files"  # type: ignore[index]

    with pytest.raises(ValidationError, match="opaque_generation_id property"):
        PhpObjectGadgetRecipe.model_validate(payload)


def test_recipe_rejects_trigger_declared_on_a_different_class() -> None:
    payload = _recipe_payload()
    payload["gadget_object"]["trigger_declaring_class"] = "Vendor\\ParentCleaner"  # type: ignore[index]

    with pytest.raises(ValidationError, match="trigger on the serialized class"):
        PhpObjectGadgetRecipe.model_validate(payload)


def test_recipe_rejects_guard_with_unconditional_escape() -> None:
    payload = _recipe_payload()
    guarded = payload["guarded_effect_anchors"][0]  # type: ignore[index]
    guarded["guard_anchor"]["source_code"] = (  # type: ignore[index]
        r"if (\strpos($sibling, '__demo_'.$this->generation.'_') === 0 || true) {"
        "\n"
        r"                \unlink(CACHE_ROOT.$sibling);"
        "\n"
        "            }"
    )

    with pytest.raises(ValidationError, match="guard condition must exactly bind"):
        PhpObjectGadgetRecipe.model_validate(payload)


def test_hypothesis_recipe_is_optional_but_family_and_evidence_bound() -> None:
    historical = _hypothesis()
    assert historical.php_object_gadget_recipe is None

    payload = _hypothesis(_recipe()).model_dump(mode="json")
    payload["bug_class"] = BugClass.IDOR.value
    with pytest.raises(ValidationError, match="valid only for CWE-502"):
        Hypothesis.model_validate(payload)

    payload["bug_class"] = BugClass.PHP_OBJECT_INJECTION.value
    payload["evidence_summary"]["usable_gadget"] = "true"
    with pytest.raises(ValidationError, match="usable_gadget=true"):
        Hypothesis.model_validate(payload)


def test_source_binding_accepts_exact_plugin_local_recipe(tmp_path: Path) -> None:
    plugin_root = _write_plugin(tmp_path)
    recipe = _recipe()

    assert validate_php_object_gadget_recipe_sources(plugin_root, recipe) is None

    hypothesis = _hypothesis(recipe)
    _validate_critic_accounting(
        HypothesesArtifact(plugin_slug="demo", hypotheses=[hypothesis]),
        TriagedArtifact(
            plugin_slug="demo",
            accepted=[hypothesis],
            rejected=[],
            merged=[],
        ),
        plugin_path=str(plugin_root),
    )


def test_give_3141_tcpdf_direct_path_recipe_binds_exact_reviewed_lines(
    tmp_path: Path,
) -> None:
    plugin_root, recipe = _tcpdf_fixture(tmp_path)

    error = validate_php_object_gadget_recipe_sources(plugin_root, recipe)

    assert error is None
    assert recipe.effect_binding.kind == "direct_path"
    assert recipe.effect_binding.effect_anchor.line == 7861
    assert recipe.effect_binding.local_path_check is not None
    assert recipe.effect_binding.local_path_check.guard_anchor.line == 7860
    assert recipe.guarded_effect_anchors[0].guard_anchor.line == 7852
    assert recipe.guarded_effect_anchors[0].anchor.line == 7853
    local_helper = next(
        helper
        for helper in recipe.helper_anchors
        if helper.contract == "local_path_exists"
    )
    assert local_helper.anchor.file == (
        "vendor/tecnickcom/tcpdf/include/tcpdf_static.php"
    )
    assert local_helper.anchor.line == 1875


def test_source_binding_rejects_non_array_static_marker_default(
    tmp_path: Path,
) -> None:
    plugin_root, recipe = _tcpdf_fixture(tmp_path)
    tcpdf_file = plugin_root / "vendor" / "tecnickcom" / "tcpdf" / "tcpdf.php"
    source = tcpdf_file.read_text(encoding="utf-8").replace(
        "protected static $cleaned_ids = array();",
        "protected static $cleaned_ids = null;",
    )
    tcpdf_file.write_text(source, encoding="utf-8")

    error = validate_php_object_gadget_recipe_sources(plugin_root, recipe)

    assert error is not None
    assert "native-array declaration" in error


def test_source_binding_rejects_dynamic_braced_class_static_mutation(
    tmp_path: Path,
) -> None:
    plugin_root, recipe = _tcpdf_fixture(tmp_path)
    payload = recipe.model_dump(mode="json")
    helper = next(
        item
        for item in payload["helper_anchors"]
        if item["symbol"] == "TCPDF::_destroy"
    )
    helper["anchor"]["source_code"] = helper["anchor"]["source_code"].replace(
        "// remove all temporary files",
        "self::${'cleaned_ids'} = array();",
    )
    changed_recipe = PhpObjectGadgetRecipe.model_validate(payload)
    tcpdf_file = plugin_root / "vendor" / "tecnickcom" / "tcpdf" / "tcpdf.php"
    source = tcpdf_file.read_text(encoding="utf-8").replace(
        "// remove all temporary files",
        "self::${'cleaned_ids'} = array();",
    )
    tcpdf_file.write_text(source, encoding="utf-8")

    error = validate_php_object_gadget_recipe_sources(plugin_root, changed_recipe)

    assert error is not None
    assert "dynamic" in error


def test_local_path_exists_contract_rejects_changed_fallthrough_parameter(
    tmp_path: Path,
) -> None:
    _, recipe = _tcpdf_fixture(tmp_path)
    payload = recipe.model_dump(mode="json")
    helper = next(
        item
        for item in payload["helper_anchors"]
        if item["contract"] == "local_path_exists"
    )
    helper["anchor"]["source_code"] = helper["anchor"]["source_code"].replace(
        "@file_exists($filename)",
        "@file_exists($other)",
    )

    with pytest.raises(ValidationError, match="same-parameter local file_exists"):
        PhpObjectGadgetRecipe.model_validate(payload)


def test_source_binding_rejects_changed_installed_source(tmp_path: Path) -> None:
    plugin_root = _write_plugin(
        tmp_path,
        _PLUGIN_SOURCE.replace(r"@\unlink($file);", r"@\unlink($different);"),
    )

    error = validate_php_object_gadget_recipe_sources(plugin_root, _recipe())

    assert error is not None
    assert "does not match" in error


def test_source_binding_rejects_plugin_tree_symlink(tmp_path: Path) -> None:
    plugin_root = tmp_path / "plugin"
    vendor = plugin_root / "vendor"
    vendor.mkdir(parents=True)
    outside = tmp_path / "outside.php"
    outside.write_text(_PLUGIN_SOURCE, encoding="utf-8")
    (vendor / "cleaner.php").symlink_to(outside)

    error = validate_php_object_gadget_recipe_sources(plugin_root, _recipe())

    assert error is not None
    assert "symlink" in error


def test_source_binding_rejects_cross_class_same_method_decoy(tmp_path: Path) -> None:
    payload = _recipe_payload()
    helper_source = payload["helper_anchors"][0]["anchor"]["source_code"]  # type: ignore[index]
    source = _PLUGIN_SOURCE + f"\nclass Decoy {{\n    {helper_source}\n}}\n"
    helper_line = len(_PLUGIN_SOURCE.splitlines()) + 3
    payload["helper_anchors"][0]["anchor"]["line"] = helper_line  # type: ignore[index]
    payload["effect_binding"]["iteration_anchor"]["line"] = helper_line + 1  # type: ignore[index]
    payload["effect_binding"]["effect_anchor"]["line"] = helper_line + 2  # type: ignore[index]
    payload["guarded_effect_anchors"][0]["guard_anchor"]["line"] = (  # type: ignore[index]
        helper_line + 7
    )
    payload["guarded_effect_anchors"][0]["anchor"]["line"] = helper_line + 8  # type: ignore[index]
    recipe = PhpObjectGadgetRecipe.model_validate(payload)
    plugin_root = _write_plugin(tmp_path, source)

    error = validate_php_object_gadget_recipe_sources(plugin_root, recipe)

    assert error is not None
    assert "method anchor is outside declared class" in error
    assert "Cleaner" in error


def test_source_binding_does_not_dispatch_this_call_to_decoy_class(
    tmp_path: Path,
) -> None:
    payload = _recipe_payload()
    helper_source = payload["helper_anchors"][0]["anchor"]["source_code"]  # type: ignore[index]
    source = _PLUGIN_SOURCE + f"\nclass Decoy {{\n    {helper_source}\n}}\n"
    helper_line = len(_PLUGIN_SOURCE.splitlines()) + 3
    payload["helper_anchors"][0]["symbol"] = "Vendor\\Decoy::destroyFiles"  # type: ignore[index]
    payload["helper_anchors"][0]["anchor"]["line"] = helper_line  # type: ignore[index]
    payload["effect_binding"]["iteration_anchor"]["line"] = helper_line + 1  # type: ignore[index]
    payload["effect_binding"]["effect_anchor"]["line"] = helper_line + 2  # type: ignore[index]
    payload["guarded_effect_anchors"][0]["guard_anchor"]["line"] = (  # type: ignore[index]
        helper_line + 7
    )
    payload["guarded_effect_anchors"][0]["anchor"]["line"] = helper_line + 8  # type: ignore[index]
    recipe = PhpObjectGadgetRecipe.model_validate(payload)
    plugin_root = _write_plugin(tmp_path, source)

    error = validate_php_object_gadget_recipe_sources(plugin_root, recipe)

    assert error is not None
    assert "unresolved or ambiguous helper method call" in error


def test_source_binding_rejects_unselected_lifecycle_hook(tmp_path: Path) -> None:
    source = _PLUGIN_SOURCE.replace(
        "    }\n}\n\nfunction process_submission",
        "    }\n\n    public function __wakeup() {\n"
        "    }\n}\n\nfunction process_submission",
    )
    plugin_root = _write_plugin(tmp_path, source)

    error = validate_php_object_gadget_recipe_sources(plugin_root, _recipe())

    assert error is not None
    assert "exactly the selected deserialization lifecycle hook" in error


@pytest.mark.parametrize(
    "magic_method",
    [
        "public function __toString() { \\unlink('/tmp/unreviewed'); return ''; }",
        "public function __set($name, $value) { \\unlink('/tmp/unreviewed'); }",
        "public function __unset($name) { \\unlink('/tmp/unreviewed'); }",
    ],
)
def test_source_binding_rejects_unreviewed_invokable_magic_hooks(
    tmp_path: Path,
    magic_method: str,
) -> None:
    source = _PLUGIN_SOURCE.replace(
        r"\strlen('safe filler');",
        r"\strlen($this);",
    ).replace(
        "    }\n}\n\nfunction process_submission",
        f"    }}\n\n    {magic_method}\n}}\n\nfunction process_submission",
    )
    helper = _recipe_payload()["helper_anchors"][0]["anchor"]["source_code"]  # type: ignore[index]
    helper = str(helper).replace(r"\strlen('safe filler');", r"\strlen($this);")
    plugin_root = _write_plugin(tmp_path, source)

    error = validate_php_object_gadget_recipe_sources(
        plugin_root,
        _recipe(helper_source=helper),
    )

    assert error is not None
    assert "unreviewed invokable magic hooks" in error


@pytest.mark.parametrize(
    ("mutation", "error_fragment"),
    [
        ("$this->path = '/etc/passwd';", "effect property is mutated or aliased"),
        (
            "foreach (['/etc/passwd'] as $this->path) {}",
            "effect property is rebound",
        ),
        ("[$this->path] = ['/etc/passwd'];", "effect property is rebound"),
        (
            "$name = 'path'; $this->{$name} = '/etc/passwd';",
            "dynamic object mutation or alias",
        ),
        (
            "$alias = ($this); $alias->path = '/etc/passwd';",
            "dynamic object mutation or alias",
        ),
    ],
)
def test_source_binding_rejects_direct_property_rebinding_before_sink(
    tmp_path: Path,
    mutation: str,
    error_fragment: str,
) -> None:
    old_block = r"""foreach ($this->files as $file) {
            @\unlink($file);
        }"""
    new_block = (
        mutation
        + "\n"
        + r"            @\unlink($this->path);"
        + "\n        // line-preserving filler"
    )
    source = _PLUGIN_SOURCE.replace(
        "protected $files = array();",
        "protected $path = null;",
    ).replace(old_block, new_block)
    payload = _recipe_payload(
        helper_source=str(
            _recipe_payload()["helper_anchors"][0]["anchor"]["source_code"]  # type: ignore[index]
        ).replace(old_block, new_block)
    )
    effect_property = payload["gadget_object"]["properties"][0]  # type: ignore[index]
    effect_property["name"] = "path"  # type: ignore[index]
    effect_property["value"] = {  # type: ignore[index]
        "kind": "capability",
        "capability": "ephemeral_file_path",
    }
    binding = payload["effect_binding"]  # type: ignore[assignment]
    binding["effect_property"] = "path"  # type: ignore[index]
    binding["access"] = "property"  # type: ignore[index]
    binding.pop("effect_variable")  # type: ignore[union-attr]
    binding.pop("iteration_anchor")  # type: ignore[union-attr]
    binding["effect_anchor"]["source_code"] = r"@\unlink($this->path);"  # type: ignore[index]
    recipe = PhpObjectGadgetRecipe.model_validate(payload)
    plugin_root = _write_plugin(tmp_path, source)

    error = validate_php_object_gadget_recipe_sources(plugin_root, recipe)

    assert error is not None
    assert error_fragment in error


def test_source_binding_rejects_multiline_property_destructuring(
    tmp_path: Path,
) -> None:
    old_block = r"""foreach ($this->files as $file) {
            @\unlink($file);
        }"""
    new_block = r"""[
            $this->path
        ] = ['/etc/passwd'];
            @\unlink($this->path);
        // line-preserving filler"""
    source = _PLUGIN_SOURCE.replace(
        "protected $files = array();",
        "protected $path = null;",
    ).replace(old_block, new_block)
    helper = _recipe_payload()["helper_anchors"][0]["anchor"]["source_code"]  # type: ignore[index]
    payload = _recipe_payload(helper_source=str(helper).replace(old_block, new_block))
    effect_property = payload["gadget_object"]["properties"][0]  # type: ignore[index]
    effect_property["name"] = "path"  # type: ignore[index]
    effect_property["value"] = {  # type: ignore[index]
        "kind": "capability",
        "capability": "ephemeral_file_path",
    }
    binding = payload["effect_binding"]  # type: ignore[assignment]
    binding["effect_property"] = "path"  # type: ignore[index]
    binding["access"] = "property"  # type: ignore[index]
    binding.pop("effect_variable")  # type: ignore[union-attr]
    binding.pop("iteration_anchor")  # type: ignore[union-attr]
    binding["effect_anchor"] = {  # type: ignore[index]
        "file": "vendor/cleaner.php",
        "line": 16,
        "source_code": r"@\unlink($this->path);",
    }
    guarded = payload["guarded_effect_anchors"][0]  # type: ignore[index]
    guarded["guard_anchor"]["line"] = 21  # type: ignore[index]
    guarded["anchor"]["line"] = 22  # type: ignore[index]
    recipe = PhpObjectGadgetRecipe.model_validate(payload)
    plugin_root = _write_plugin(tmp_path, source)

    error = validate_php_object_gadget_recipe_sources(plugin_root, recipe)

    assert error is not None
    assert "effect property is rebound" in error


@pytest.mark.parametrize(
    ("mutation", "error_fragment"),
    [
        (
            r"$alias =& $file; $alias = '/tmp/other-target';",
            "effect variable is mutated or aliased",
        ),
        (r"$file[0] = '/';", "effect variable is mutated or aliased"),
        (
            r"foreach (['/tmp/other-target'] as $file) {}",
            "effect variable is rebound",
        ),
        (r"[$file] = ['/tmp/other-target'];", "effect variable is rebound"),
    ],
)
def test_source_binding_rejects_list_item_alias_or_indexed_write(
    tmp_path: Path,
    mutation: str,
    error_fragment: str,
) -> None:
    old_block = r"""foreach ($this->files as $file) {
            @\unlink($file);
        }"""
    new_block = (
        f"foreach ($this->files as $file) {{ {mutation}\n"
        r"            @\unlink($file);"
        "\n        }"
    )
    source = _PLUGIN_SOURCE.replace(old_block, new_block)
    helper = _recipe_payload()["helper_anchors"][0]["anchor"]["source_code"]  # type: ignore[index]
    helper = str(helper).replace(old_block, new_block)
    payload = _recipe_payload(helper_source=helper)
    payload["effect_binding"]["iteration_anchor"]["source_code"] = new_block  # type: ignore[index]
    recipe = PhpObjectGadgetRecipe.model_validate(payload)
    plugin_root = _write_plugin(tmp_path, source)

    error = validate_php_object_gadget_recipe_sources(plugin_root, recipe)

    assert error is not None
    assert error_fragment in error


@pytest.mark.parametrize(
    "changed_signature",
    [
        "private function destroyFiles(&$candidate)",
        "private function &destroyFiles()",
    ],
)
def test_source_binding_rejects_by_reference_helper_declaration(
    tmp_path: Path,
    changed_signature: str,
) -> None:
    source = _PLUGIN_SOURCE.replace(
        "private function destroyFiles()",
        changed_signature,
    )
    helper = _recipe_payload()["helper_anchors"][0]["anchor"]["source_code"]  # type: ignore[index]
    helper = str(helper).replace(
        "private function destroyFiles()",
        changed_signature,
    )
    plugin_root = _write_plugin(tmp_path, source)

    error = validate_php_object_gadget_recipe_sources(
        plugin_root,
        _recipe(helper_source=helper),
    )

    assert error is not None
    assert "by-reference returns or parameters" in error


def test_source_binding_rejects_builtin_output_parameter_mutation(
    tmp_path: Path,
) -> None:
    original = "private function destroyFiles() {"
    changed = (
        "private function destroyFiles() { "
        r"\preg_match('/(.*)/', '/etc/passwd', $this->files);"
    )
    source = _PLUGIN_SOURCE.replace(original, changed)
    helper = _recipe_payload()["helper_anchors"][0]["anchor"]["source_code"]  # type: ignore[index]
    helper = str(helper).replace(original, changed)
    plugin_root = _write_plugin(tmp_path, source)

    error = validate_php_object_gadget_recipe_sources(
        plugin_root,
        _recipe(helper_source=helper),
    )

    assert error is not None
    assert "non-allowlisted function call 'preg_match'" in error


@pytest.mark.parametrize(
    "operator",
    ["??=", "**=", "<<=", ">>=", "&=", "|=", "^="],
)
def test_source_binding_rejects_complete_compound_assignment_family(
    tmp_path: Path,
    operator: str,
) -> None:
    original = "private function destroyFiles() {"
    changed = (
        f"private function destroyFiles() {{ $this->files[1] {operator} "
        "'/etc/passwd';"
    )
    source = _PLUGIN_SOURCE.replace(original, changed)
    helper = _recipe_payload()["helper_anchors"][0]["anchor"]["source_code"]  # type: ignore[index]
    helper = str(helper).replace(original, changed)
    plugin_root = _write_plugin(tmp_path, source)

    error = validate_php_object_gadget_recipe_sources(
        plugin_root,
        _recipe(helper_source=helper),
    )

    assert error is not None
    assert "effect property is mutated or aliased" in error


def test_source_binding_rejects_nested_index_property_write(tmp_path: Path) -> None:
    original = "private function destroyFiles() {"
    changed = (
        "private function destroyFiles() { $keys = [1]; "
        "$this->files[$keys[0]] = '/etc/passwd';"
    )
    source = _PLUGIN_SOURCE.replace(original, changed)
    helper = _recipe_payload()["helper_anchors"][0]["anchor"]["source_code"]  # type: ignore[index]
    helper = str(helper).replace(original, changed)
    plugin_root = _write_plugin(tmp_path, source)

    error = validate_php_object_gadget_recipe_sources(
        plugin_root,
        _recipe(helper_source=helper),
    )

    assert error is not None
    assert "effect property is mutated or aliased" in error


def test_source_binding_rejects_unqualified_namespaced_builtin(tmp_path: Path) -> None:
    source = _PLUGIN_SOURCE.replace(
        r"\strlen('safe filler');", "strlen('safe filler');"
    )
    helper = _recipe_payload()["helper_anchors"][0]["anchor"]["source_code"]  # type: ignore[index]
    helper = str(helper).replace(
        r"\strlen('safe filler');",
        "strlen('safe filler');",
    )
    plugin_root = _write_plugin(tmp_path, source)

    error = validate_php_object_gadget_recipe_sources(
        plugin_root,
        _recipe(helper_source=helper),
    )

    assert error is not None
    assert "can be shadowed in namespace 'Vendor'" in error


def test_source_binding_rejects_quoted_callable_syntax(tmp_path: Path) -> None:
    source = _PLUGIN_SOURCE.replace(r"\strlen('safe filler');", "'unlink'($file);")
    helper = _recipe_payload()["helper_anchors"][0]["anchor"]["source_code"]  # type: ignore[index]
    helper = str(helper).replace(r"\strlen('safe filler');", "'unlink'($file);")
    plugin_root = _write_plugin(tmp_path, source)

    error = validate_php_object_gadget_recipe_sources(
        plugin_root,
        _recipe(helper_source=helper),
    )

    assert error is not None
    assert "indirect callable expression" in error


def test_source_binding_rejects_compound_class_static_mutation(
    tmp_path: Path,
) -> None:
    mutation = "self::$cleaned_ids[$this->generation]++;"
    source = _PLUGIN_SOURCE.replace(r"\strlen('safe filler');", mutation)
    helper = _recipe_payload()["helper_anchors"][0]["anchor"]["source_code"]  # type: ignore[index]
    helper = str(helper).replace(r"\strlen('safe filler');", mutation)
    plugin_root = _write_plugin(tmp_path, source)

    error = validate_php_object_gadget_recipe_sources(
        plugin_root,
        _recipe(helper_source=helper),
    )

    assert error is not None
    assert "class-static write" in error


def test_source_binding_rejects_unlink_after_closed_fake_guard(tmp_path: Path) -> None:
    source = _PLUGIN_SOURCE.replace(
        r"if (\strpos($sibling, '__demo_'.$this->generation.'_') === 0) {"
        "\n"
        r"                \unlink(CACHE_ROOT.$sibling);"
        "\n"
        "            }",
        r"if (\strpos($sibling, '__demo_'.$this->generation.'_') === 0) {}"
        "\n"
        r"            \unlink(CACHE_ROOT.$sibling);",
    )
    helper = _recipe_payload()["helper_anchors"][0]["anchor"]["source_code"]  # type: ignore[index]
    helper = str(helper).replace(
        r"if (\strpos($sibling, '__demo_'.$this->generation.'_') === 0) {"
        "\n"
        r"                \unlink(CACHE_ROOT.$sibling);"
        "\n"
        "            }",
        r"if (\strpos($sibling, '__demo_'.$this->generation.'_') === 0) {}"
        "\n"
        r"            \unlink(CACHE_ROOT.$sibling);",
    )
    recipe = _recipe(
        helper_source=helper,
        guard_source=(
            r"if (\strpos($sibling, '__demo_'.$this->generation.'_') === 0) {}"
            "\n"
            r"            \unlink(CACHE_ROOT.$sibling);"
        ),
        guarded_effect_line=20,
    )
    plugin_root = _write_plugin(tmp_path, source)

    error = validate_php_object_gadget_recipe_sources(plugin_root, recipe)

    assert error == "guard anchor must quote one complete braced if region"


@pytest.mark.parametrize(
    "dangerous_line",
    ["system('id');", "file_put_contents('marker', 'x');"],
)
def test_source_binding_rejects_mixed_unlink_and_other_effects(
    tmp_path: Path,
    dangerous_line: str,
) -> None:
    source = _PLUGIN_SOURCE.replace(r"\strlen('safe filler');", dangerous_line)
    helper = _recipe_payload()["helper_anchors"][0]["anchor"]["source_code"]  # type: ignore[index]
    helper = str(helper).replace(r"\strlen('safe filler');", dangerous_line)
    recipe = _recipe(helper_source=helper)
    plugin_root = _write_plugin(tmp_path, source)

    error = validate_php_object_gadget_recipe_sources(plugin_root, recipe)

    assert error is not None
    assert "non-allowlisted function call" in error


@pytest.mark.parametrize(
    "unresolved_line",
    ["$this->unreviewedHelper();", "$this->$method();"],
)
def test_source_binding_rejects_unresolved_or_dynamic_helpers(
    tmp_path: Path,
    unresolved_line: str,
) -> None:
    source = _PLUGIN_SOURCE.replace(r"\strlen('safe filler');", unresolved_line)
    helper = _recipe_payload()["helper_anchors"][0]["anchor"]["source_code"]  # type: ignore[index]
    helper = str(helper).replace(r"\strlen('safe filler');", unresolved_line)
    recipe = _recipe(helper_source=helper)
    plugin_root = _write_plugin(tmp_path, source)

    error = validate_php_object_gadget_recipe_sources(plugin_root, recipe)

    assert error is not None
    assert "unresolved" in error or "dynamic callback" in error


def test_php_object_prompts_and_taxonomy_expose_closed_recipe_contract() -> None:
    specialist = " ".join(load_prompt("specialists/injection_files").split())
    critic = " ".join(load_prompt("critic").split())
    methodology = " ".join(load_prompt("_wp_idioms").split())
    contract = critic_evidence_contract_for(BugClass.PHP_OBJECT_INJECTION)

    for prompt in (specialist, critic):
        assert "php_object_gadget_recipe" in prompt
        assert "ephemeral_file_path" in prompt
        assert "opaque_generation_id" in prompt
        assert "guarded_effect_anchors" in prompt
        assert "complete braced" in prompt
        assert "dynamic" in prompt and "unresolved" in prompt
        assert "raw" in prompt and "nested objects" in prompt
    assert "zero-offset prefix test" in critic
    assert "does not require whole-string equality" in critic
    assert "natural-gadget proof recipe" in methodology
    assert "parent-derived opaque generation ID" in methodology
    assert any(
        "account for every unlink" in requirement
        for requirement in contract.acceptance_requirements
    )


def test_recipe_rejects_duplicate_php_map_keys() -> None:
    with pytest.raises(ValidationError, match="duplicate PHP keys"):
        PhpObjectGadgetValue.model_validate(
            {
                "kind": "map",
                "entries": [
                    {"key": 1, "value": {"kind": "null"}},
                    {"key": "1", "value": {"kind": "null"}},
                ],
            }
        )


def test_recipe_rejects_excessive_value_depth() -> None:
    payload = _recipe_payload()
    properties = payload["gadget_object"]["properties"]  # type: ignore[index]
    value: dict[str, object] = {
        "kind": "capability",
        "capability": "ephemeral_file_path",
    }
    for _ in range(5):
        value = {"kind": "list", "items": [value]}
    properties[0]["value"] = value  # type: ignore[index]

    with pytest.raises(ValidationError, match="cannot exceed depth"):
        PhpObjectGadgetRecipe.model_validate(payload)


def test_recipe_payload_helper_returns_independent_data() -> None:
    first = _recipe_payload()
    second = deepcopy(first)
    second["effect"] = "not_allowed"

    with pytest.raises(ValidationError):
        PhpObjectGadgetRecipe.model_validate(second)
    assert PhpObjectGadgetRecipe.model_validate(first).effect == "file_delete"
