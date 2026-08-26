from __future__ import annotations

from squadrone.schemas import EntryPoint, ReconArtifact
from squadrone.services.coverage import (
    build_coverage_artifact,
    merge_deterministic_coverage,
)


def test_coverage_inventories_callbacks_storage_outputs_and_built_js(tmp_path):
    (tmp_path / "build").mkdir()
    (tmp_path / "vendor").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "add_action('wp_ajax_nopriv_demo_save', 'demo_save');\n"
        "register_rest_route(\n"
        "    'demo/v1',\n"
        "    '/item',\n"
        "    ['callback' => 'demo_read']\n"
        ");\n"
        "register_block_type('demo/item', ['render_callback' => 'demo_render']);\n"
        "function demo_save() { update_option('demo', $_POST['value']); }\n"
        "function demo_read() { global $wpdb; return $wpdb->get_var('SELECT secret'); }\n"
        "function demo_render() { echo get_option('demo'); }\n"
        "// system($_GET['cmd']);\n"
        "/* file($_GET['path']); */\n"
    )
    (tmp_path / "build" / "app.js").write_text("target.innerHTML = payload;\n")
    (tmp_path / "build" / "minified.js").write_text(
        "x" * 2_000 + "new Function('return payload')();\n"
    )
    (tmp_path / "vendor" / "library.php").write_text("<?php system($_GET['cmd']);\n")
    (tmp_path / "tests" / "fixture.php").write_text("<?php shell_exec($_GET['cmd']);\n")

    artifact, callbacks, sinks = build_coverage_artifact(tmp_path)

    callback_types = {callback["type"] for callback in callbacks}
    assert {"ajax_nopriv", "rest_route", "block"} <= callback_types
    assert "build/app.js" in artifact.production_files
    assert "vendor/library.php" in artifact.dependency_files
    assert "tests/fixture.php" not in artifact.production_files
    assert "tests/fixture.php" not in artifact.dependency_files
    assert any(
        item.type == "dom_html" and item.file == "build/app.js"
        for item in artifact.items
    )
    minified = next(
        item
        for item in artifact.items
        if item.type == "javascript_eval" and item.file == "build/minified.js"
    )
    assert minified.column > 2_000
    assert "Function(" in minified.snippet
    assert not any(
        item.type in {"command_execution", "file_read"} and item.file == "plugin.php"
        for item in artifact.items
    )
    assert any(
        item.kind == "storage_write" and item.name == "update_option"
        for item in artifact.items
    )
    assert any(
        item.kind == "entry_point" and item.type == "block" for item in artifact.items
    )
    assert all(
        "xss_lifecycle" in item.review_areas
        for item in artifact.items
        if item.kind == "entry_point"
    )
    assert any(sink["type"] == "sql_query" for sink in sinks)
    assert not any(
        item.type in {"option_read", "object_read", "output"} for item in artifact.items
    )


def test_registry_routes_authorization_storage_surfaces_without_losing_xss(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "update_option('demo', $_POST['value']);\n"
        "update_post_meta($_POST['id'], 'demo', $_POST['value']);\n"
    )

    artifact, _, _ = build_coverage_artifact(tmp_path)

    storage_items = {
        item.type: item
        for item in artifact.items
        if item.type in {"option_write", "object_write"}
    }
    assert set(storage_items) == {"option_write", "object_write"}
    for item in storage_items.values():
        assert "authorization_workflows" in item.review_areas
        assert "xss_lifecycle" in item.review_areas


def test_weak_crypto_and_randomness_primitives_are_reviewed_only_when_executable(
    tmp_path,
):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "// md5($commented); rand();\n"
        "/* sha1($commented); uniqid(); */\n"
        "$example = 'md5($string) mt_rand() sha1($string)';\n"
        "$digest = md5($secret);\n"
        "$legacy = sha1($token);\n"
        "$backup = uniqid('backup-', true);\n"
        "$pin = mt_rand(100000, 999999);\n"
        "$roll = rand();\n"
        "$fraction = lcg_value();\n"
    )

    artifact, _, _ = build_coverage_artifact(tmp_path)

    primitive_items = [
        item
        for item in artifact.items
        if item.type in {"weak_crypto_primitive", "non_cryptographic_randomness"}
    ]
    assert {(item.type, item.name) for item in primitive_items} == {
        ("weak_crypto_primitive", "md5"),
        ("weak_crypto_primitive", "sha1"),
        ("non_cryptographic_randomness", "uniqid"),
        ("non_cryptographic_randomness", "mt_rand"),
        ("non_cryptographic_randomness", "rand"),
        ("non_cryptographic_randomness", "lcg_value"),
    }
    assert all(item.review_areas == ["authentication"] for item in primitive_items)
    assert {item.line for item in primitive_items} == {5, 6, 7, 8, 9, 10}


def test_coverage_ids_are_stable_for_same_source(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\nadd_action('wp_ajax_demo', 'demo');\n"
        "function demo() { file_put_contents($_POST['path'], $_POST['data']); }\n"
    )

    first, _, _ = build_coverage_artifact(tmp_path)
    second, _, _ = build_coverage_artifact(tmp_path)

    assert [item.model_dump() for item in first.items] == [
        item.model_dump() for item in second.items
    ]


def test_merge_normalizes_and_deduplicates_surveyor_and_static_routes(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "register_rest_route('demo/v1', '/thing', [\n"
        "  'callback' => 'demo_thing',\n"
        "]);\n"
        "function demo_thing() { return true; }\n"
    )
    coverage, callbacks, sinks = build_coverage_artifact(tmp_path)
    recon = ReconArtifact(
        plugin_slug="demo",
        entry_points=[
            EntryPoint(
                type="rest_route",
                name="demo/v1/thing",
                file="plugin.php",
                line=2,
                handler_function="demo_thing",
                requires_auth=False,
                has_nonce_check=False,
                has_capability_check=False,
                source="surveyor",
            )
        ],
        sinks=[],
        entry_to_sink_paths={},
        raw_grep_hits={},
    )

    merge_deterministic_coverage(recon, tmp_path, coverage, callbacks, sinks)

    assert len(recon.entry_points) == 1
    assert recon.entry_points[0].name == "demo/v1/thing"
    entry_items = [item for item in coverage.items if item.kind == "entry_point"]
    assert len(entry_items) == 1


def test_coverage_inventories_unguarded_top_level_php_dispatcher(tmp_path):
    connector = tmp_path / "lib" / "php" / "connector.php"
    connector.parent.mkdir(parents=True)
    connector.write_text(
        "<?php\n"
        "require './autoload.php';\n"
        "$options = ['url' => $_SERVER['PHP_SELF']];\n"
        "$connector = new DemoConnector($options);\n"
        "$connector->run();\n"
    )

    coverage, callbacks, sinks = build_coverage_artifact(tmp_path)

    callback = next(
        callback for callback in callbacks if callback["type"] == "direct_php"
    )
    assert callback["name"] == "lib/php/connector.php"
    assert callback["file"] == "lib/php/connector.php"

    entry_item = next(
        item
        for item in coverage.items
        if item.kind == "entry_point" and item.type == "direct_php"
    )
    assert entry_item.name == "lib/php/connector.php"
    assert entry_item.file == "lib/php/connector.php"
    assert "injection_files" in entry_item.review_areas

    recon = ReconArtifact(
        plugin_slug="demo",
        entry_points=[],
        sinks=[],
        entry_to_sink_paths={},
        raw_grep_hits={},
    )
    merge_deterministic_coverage(recon, tmp_path, coverage, callbacks, sinks)

    direct_entry = next(
        entry for entry in recon.entry_points if entry.type == "direct_php"
    )
    assert direct_entry.name == "lib/php/connector.php"
    assert direct_entry.requires_auth is False
    assert direct_entry.access_known is True
    assert direct_entry.has_nonce_check is False
    assert direct_entry.has_capability_check is False


def test_coverage_keeps_delegated_front_controller_as_access_unknown(tmp_path):
    (tmp_path / "front-controller.php").write_text(
        "<?php\n"
        "require __DIR__ . '/autoload.php';\n"
        "$application = new Application();\n"
        "$application->run();\n"
    )

    coverage, callbacks, sinks = build_coverage_artifact(tmp_path)

    callback = next(
        callback for callback in callbacks if callback["type"] == "direct_php_candidate"
    )
    assert callback["name"] == "front-controller.php"
    entry_item = next(
        item
        for item in coverage.items
        if item.kind == "entry_point" and item.type == "direct_php_candidate"
    )
    assert "injection_files" in entry_item.review_areas

    recon = ReconArtifact(
        plugin_slug="demo",
        entry_points=[],
        sinks=[],
        entry_to_sink_paths={},
        raw_grep_hits={},
    )
    merge_deterministic_coverage(recon, tmp_path, coverage, callbacks, sinks)

    candidate = next(
        entry for entry in recon.entry_points if entry.type == "direct_php_candidate"
    )
    assert candidate.requires_auth is False
    assert candidate.access_known is False
    assert candidate.confidence == "medium"


def test_coverage_rejects_include_only_view_and_non_code_signals(tmp_path):
    templates = tmp_path / "templates"
    templates.mkdir()
    (templates / "settings.php").write_text(
        "<?php\n$tab = $_GET['tab'];\n$notice->run();\necho $tab;\n"
    )
    (tmp_path / "examples.php").write_text(
        "<?php\n"
        "$example = \"require './autoload.php'; $_GET; $app->run();\";\n"
        "// require './autoload.php'; $_GET; $app->run();\n"
    )
    (tmp_path / "late-include.php").write_text(
        "<?php\n$application->run();\nrequire './autoload.php';\n"
    )

    coverage, callbacks, _ = build_coverage_artifact(tmp_path)

    direct_types = {"direct_php", "direct_php_candidate"}
    assert not any(callback["type"] in direct_types for callback in callbacks)
    assert not any(item.type in direct_types for item in coverage.items)


def test_coverage_rejects_guarded_or_nested_php_dispatchers(tmp_path):
    (tmp_path / "guarded.php").write_text(
        "<?php\n"
        "if (!defined('ABSPATH')) { exit; }\n"
        "require './autoload.php';\n"
        "$connector = new DemoConnector($options);\n"
        "$connector->run();\n"
    )
    (tmp_path / "uninstall.php").write_text(
        "<?php\n"
        "if (!defined('WP_UNINSTALL_PLUGIN')) { die; }\n"
        "require './autoload.php';\n"
        "$uninstaller->run();\n"
    )
    (tmp_path / "class-handler.php").write_text(
        "<?php\n"
        "require './autoload.php';\n"
        "class Handler {\n"
        "    public function dispatch() {\n"
        "        $connector = new DemoConnector();\n"
        "        $connector->run();\n"
        "    }\n"
        "}\n"
    )
    (tmp_path / "function-handler.php").write_text(
        "<?php\n"
        "require './autoload.php';\n"
        "function dispatch() {\n"
        "    $connector = new DemoConnector();\n"
        "    $connector->run();\n"
        "}\n"
    )

    coverage, callbacks, _ = build_coverage_artifact(tmp_path)

    direct_types = {"direct_php", "direct_php_candidate"}
    assert not any(callback["type"] in direct_types for callback in callbacks)
    assert not any(item.type in direct_types for item in coverage.items)


def test_inline_php_comment_does_not_create_command_execution_sink(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "$config = []; // driver for accessing the file system($path)\n"
        "system($command);\n"
    )

    coverage, _, sinks = build_coverage_artifact(tmp_path)

    command_items = [
        item for item in coverage.items if item.type == "command_execution"
    ]
    assert [(item.name, item.file, item.line) for item in command_items] == [
        ("system", "plugin.php", 3),
    ]
    assert [
        (sink["function"], sink["file"], sink["line"])
        for sink in sinks
        if sink["type"] == "command_execution"
    ] == [("system", "plugin.php", 3)]
