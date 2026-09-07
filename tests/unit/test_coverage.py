from __future__ import annotations

import re

from squadrone.schemas import EntryPoint, ReconArtifact
from squadrone.agents._specialist_base import _requires_dynamic_key_trace
from squadrone.services.coverage import (
    build_coverage_artifact,
    merge_deterministic_coverage,
)
from squadrone.stages.recon import RIPGREP_PATTERNS


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


def test_implicit_metadata_deserialization_surface_is_narrow_and_routed(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "update_metadata('post', $object_id, 'payload', $replacement);\n"
        "UPDATE_METADATA('user', $user_id, 'payload', $replacement);\n"
        "update_post_meta($object_id, 'payload', $replacement);\n"
        "get_metadata('post', $object_id, 'payload', true);\n"
        "get_post_meta($object_id, 'payload', true);\n"
        "// update_metadata('post', $object_id, 'commented', $value);\n"
        'echo "update_metadata(inside a string)";\n'
    )

    artifact, _, sinks = build_coverage_artifact(tmp_path)

    implicit = [
        item for item in artifact.items if item.type == "implicit_deserialization"
    ]
    assert [(item.line, item.name) for item in implicit] == [
        (2, "update_metadata"),
        (3, "UPDATE_METADATA"),
    ]
    assert all(item.kind == "sink" for item in implicit)
    assert all(item.review_areas == ["injection_files"] for item in implicit)
    assert [
        (sink["line"], sink["function"])
        for sink in sinks
        if sink["type"] == "implicit_deserialization"
    ] == [(2, "update_metadata"), (3, "UPDATE_METADATA")]


def test_recon_grep_tracks_only_direct_implicit_metadata_anchor():
    pattern = re.compile(RIPGREP_PATTERNS["implicit_deserialization"])

    assert pattern.search("UPDATE_METADATA('post', $id, $key, $value)")
    assert not pattern.search("update_post_meta($id, $key, $value)")
    assert not pattern.search("get_metadata('post', $id, $key, true)")


def test_dynamic_sql_identity_crud_routes_to_authorization_without_broad_sql_routing(
    tmp_path,
):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "function inspect_records($record_id, $status) {\n"
        "  global $wpdb;\n"
        "  $wpdb->get_row($wpdb->prepare(\n"
        "    'SELECT * FROM records WHERE record_id=%d', $record_id\n"
        "  ));\n"
        "  $wpdb->get_results('SELECT * FROM records WHERE record_id=' . $record_id);\n"
        "  $wpdb->get_var($wpdb->prepare(\n"
        "    'SELECT COUNT(*) AS total FROM records WHERE record_id=%d', $record_id\n"
        "  ));\n"
        "  $wpdb->get_results($wpdb->prepare(\n"
        "    'SELECT * FROM records WHERE record_id=%d', 7\n"
        "  ));\n"
        "  $wpdb->get_results($wpdb->prepare(\n"
        "    'SELECT * FROM records WHERE status=%s', $status\n"
        "  ));\n"
        "  $wpdb->query($wpdb->prepare(\n"
        "    'INSERT INTO records SET record_id=%d', $record_id\n"
        "  ));\n"
        "}\n"
    )

    artifact, _, _ = build_coverage_artifact(tmp_path)

    sql_items = [item for item in artifact.items if item.type == "sql_query"]
    routed = ["authorization_workflows" in item.review_areas for item in sql_items]
    assert routed == [True, True, False, False, False, False]
    assert all("injection_files" in item.review_areas for item in sql_items)


def test_bare_sql_variables_resolve_assignments_in_the_same_function(
    tmp_path,
):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "function persist_record($title) {\n"
        "  global $wpdb;\n"
        "  if (!current_user_can('edit_posts')) { return; }\n"
        "  $record_id = absint($_POST['record_id']);\n"
        "  $sql = $wpdb->prepare(\n"
        "    'INSERT INTO records SET record_id=%d',\n"
        "    $record_id\n"
        "  );\n"
        "  $wpdb->get_results($sql);\n"
        "  $sql = $wpdb->prepare(\n"
        "    'UPDATE records SET title=%s WHERE record_id=%d',\n"
        "    $title,\n"
        "    $record_id\n"
        "  );\n"
        "  $wpdb->get_results($sql);\n"
        "}\n"
        "function execute_unresolved_query() {\n"
        "  global $wpdb;\n"
        "  $wpdb->get_results($sql);\n"
        "}\n"
    )

    artifact, _, _ = build_coverage_artifact(tmp_path)

    sql_items = [item for item in artifact.items if item.type == "sql_query"]
    routed = ["authorization_workflows" in item.review_areas for item in sql_items]
    assert routed == [False, True, False]
    assert all(item.snippet == "$wpdb->get_results($sql)" for item in sql_items)


def test_bare_sql_and_where_variables_consider_all_branch_assignments(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "function branch_on_record($record_id, $status, $by_id) {\n"
        "  global $wpdb;\n"
        "  if ($by_id) {\n"
        "    $sql = $wpdb->prepare(\n"
        "      'SELECT * FROM records WHERE record_id=%d', $record_id\n"
        "    );\n"
        "  } else {\n"
        "    $sql = $wpdb->prepare(\n"
        "      'SELECT * FROM records WHERE status=%s', $status\n"
        "    );\n"
        "  }\n"
        "  $wpdb->get_results($sql);\n"
        "  if ($by_id) {\n"
        "    $where = ['record_id' => $record_id];\n"
        "  } else {\n"
        "    $where = ['status' => $status];\n"
        "  }\n"
        "  $wpdb->delete('records', $where);\n"
        "}\n"
    )

    artifact, _, _ = build_coverage_artifact(tmp_path)

    sql_items = [
        item for item in artifact.items if item.type in {"sql_query", "sql_write"}
    ]
    assert len(sql_items) == 2
    assert all("authorization_workflows" in item.review_areas for item in sql_items)


def test_sequential_sql_and_where_reuse_resets_earlier_identity_assignments(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "function reuse_query_variables($record_id, $status) {\n"
        "  global $wpdb;\n"
        "  $sql = $wpdb->prepare(\n"
        "    'SELECT * FROM records WHERE record_id=%d', $record_id\n"
        "  );\n"
        "  $wpdb->get_results($sql);\n"
        "  $sql = $wpdb->prepare(\n"
        "    'SELECT * FROM records WHERE status=%s', $status\n"
        "  );\n"
        "  $wpdb->get_results($sql);\n"
        "  $where = ['record_id' => $record_id];\n"
        "  $wpdb->delete('records', $where);\n"
        "  $where = ['record_id' => 7];\n"
        "  $wpdb->delete('records', $where);\n"
        "}\n"
    )

    artifact, _, _ = build_coverage_artifact(tmp_path)

    sql_items = [
        item for item in artifact.items if item.type in {"sql_query", "sql_write"}
    ]
    routed = ["authorization_workflows" in item.review_areas for item in sql_items]
    assert routed == [True, False, True, False]


def test_sql_identity_routing_handles_bulk_aggregate_and_safe_identity_shapes(
    tmp_path,
):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "function inspect_identity_shapes($record_id, $record_ids, $user_id, $user_ID, $migration_row) {\n"
        "  global $wpdb;\n"
        "  $wpdb->get_results($wpdb->prepare(\n"
        "    'SELECT record_id, COUNT(*) AS total FROM records WHERE record_id=%d', $record_id\n"
        "  ));\n"
        "  $wpdb->get_results($wpdb->prepare(\n"
        "    'SELECT * FROM records WHERE record_id IN (%d, %d)', 7, $record_ids[0]\n"
        "  ));\n"
        "  $wpdb->get_results('SELECT * FROM records WHERE record_id IN (1, 2)');\n"
        "  $wpdb->get_results($wpdb->prepare(\n"
        "    'SELECT * FROM records WHERE user_id=%d', $user_id\n"
        "  ));\n"
        "  $wpdb->get_results($wpdb->prepare(\n"
        "    'SELECT * FROM records WHERE user_id=%d', $user_ID\n"
        "  ));\n"
        "  $wpdb->get_results($wpdb->prepare(\n"
        "    'SELECT * FROM records WHERE user_id=%d', get_current_user_id()\n"
        "  ));\n"
        "  $wpdb->get_results($wpdb->prepare(\n"
        "    'DELETE FROM records WHERE record_id=%d', $migration_row->record_id\n"
        "  ));\n"
        "}\n"
    )

    artifact, _, _ = build_coverage_artifact(tmp_path)

    sql_items = [item for item in artifact.items if item.type == "sql_query"]
    routed = ["authorization_workflows" in item.review_areas for item in sql_items]
    # Unknown internal identifiers and unproven variables remain conservative
    # candidates; the specialist proves reachability. A fixed list and a direct
    # WordPress current-user call cannot select a different object.
    assert routed == [True, True, False, True, True, False, True]


def test_sql_object_access_area_does_not_leak_to_adjacent_safe_items(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "function inspect_one_record($record_id) {\n"
        "  global $wpdb;\n"
        "  $wpdb->get_row('SELECT * FROM records WHERE record_id=1');\n"
        "  $wpdb->get_row($wpdb->prepare(\n"
        "    'SELECT * FROM records WHERE record_id=%d', $record_id\n"
        "  ));\n"
        "  $wpdb->get_row('SELECT * FROM records WHERE record_id=2');\n"
        "}\n"
    )

    artifact, _, _ = build_coverage_artifact(tmp_path)

    sql_items = [item for item in artifact.items if item.type == "sql_query"]
    routed = ["authorization_workflows" in item.review_areas for item in sql_items]
    assert routed == [False, True, False]
    assert all("injection_files" in item.review_areas for item in sql_items)


def test_wpdb_update_and_delete_route_only_dynamic_identity_where_maps(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "function mutate_records($record_id, $title) {\n"
        "  global $wpdb;\n"
        "  $wpdb->update(\n"
        "    'records', ['title' => $title], ['record_id' => $record_id]\n"
        "  );\n"
        "  $wpdb->delete('records', ['record_id' => 7]);\n"
        "  $where = ['record_id' => $record_id];\n"
        "  $wpdb->delete('records', $where);\n"
        "  $wpdb->insert('records', ['record_id' => $record_id]);\n"
        "}\n"
    )

    artifact, _, _ = build_coverage_artifact(tmp_path)

    sql_writes = [item for item in artifact.items if item.type == "sql_write"]
    routed = ["authorization_workflows" in item.review_areas for item in sql_writes]
    assert routed == [True, False, True, False]
    assert all("injection_files" in item.review_areas for item in sql_writes)
    assert all("xss_lifecycle" in item.review_areas for item in sql_writes)


def test_multiline_fixed_write_calls_keep_complete_snippets_and_ordinary_batches(
    tmp_path,
):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "update_user_meta(\n"
        "    $user_id,\n"
        "    // This literal remains a fixed field despite layout and comments.\n"
        "    'display_name',\n"
        "    $display_name,\n"
        ");\n"
        "wp_update_user([\n"
        "    'ID' => $user_id,\n"
        "    'user_url' => $url,\n"
        "]);\n"
    )

    artifact, _, _ = build_coverage_artifact(tmp_path)

    writes = [item for item in artifact.items if item.kind == "storage_write"]
    assert {item.name for item in writes} == {"update_user_meta", "wp_update_user"}
    assert all("\n" in item.snippet and item.snippet.endswith(")") for item in writes)
    assert all(not _requires_dynamic_key_trace([item]) for item in writes)


def test_non_call_php_surface_keeps_the_full_source_line(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n$path = $_GET['path']; require_once $path;\n"
    )

    artifact, _, _ = build_coverage_artifact(tmp_path)

    dynamic_include = next(
        item for item in artifact.items if item.type == "dynamic_include"
    )
    assert dynamic_include.snippet == "$path = $_GET['path']; require_once $path;"


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
