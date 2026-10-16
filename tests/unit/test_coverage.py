from __future__ import annotations

import re

from squadrone.schemas import EntryPoint, ReconArtifact
from squadrone.agents._specialist_base import (
    _requires_dynamic_key_trace,
    _requires_variable_php_include_trace,
)
from squadrone.services.coverage import (
    build_coverage_artifact,
    merge_deterministic_coverage,
)
from squadrone.stages.recon import RIPGREP_PATTERNS, _filter_included


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


def test_coverage_inventories_php_eval_and_extended_file_apis(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "eval($_POST['code']);\n"
        "EVAL\n"
        "    ($_REQUEST['other_code']);\n"
        "wp_handle_sideload($_FILES['archive'], []);\n"
        "wp_upload_bits($name, null, $bytes);\n"
        "$wp_filesystem->put_contents($path, $bytes);\n"
        "$wp_filesystem->get_contents($path);\n"
        "$wp_filesystem->get_contents_array($path);\n"
        "readgzfile($path);\n"
        "fpassthru($handle);\n"
        "new SplFileObject($path);\n"
        "// eval($_GET['commented']);\n"
        "/* wp_upload_bits('ignored', null, $bytes); */\n"
        '$example = "readgzfile($path)";\n'
    )

    artifact, _, sinks = build_coverage_artifact(tmp_path)

    relevant = [
        item
        for item in artifact.items
        if item.type in {"php_code_execution", "file_upload", "file_write", "file_read"}
    ]
    assert {(item.type, item.name.lower()) for item in relevant} == {
        ("php_code_execution", "eval"),
        ("file_upload", "wp_handle_sideload"),
        ("file_upload", "wp_upload_bits"),
        ("file_write", "put_contents"),
        ("file_read", "get_contents"),
        ("file_read", "get_contents_array"),
        ("file_read", "readgzfile"),
        ("file_read", "fpassthru"),
        ("file_read", "splfileobject"),
    }
    assert sum(item.type == "php_code_execution" for item in relevant) == 2
    assert all(item.kind == "sink" for item in relevant)
    assert all(item.review_areas == ["injection_files"] for item in relevant)
    assert {
        (sink["type"], sink["function"].lower())
        for sink in sinks
        if sink["type"]
        in {"php_code_execution", "file_upload", "file_write", "file_read"}
    } == {(item.type, item.name.lower()) for item in relevant}


def test_coverage_detects_expression_form_php_includes(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "include __DIR__ . '/views/' . $template . '.php';\n"
        "require dirname(__FILE__) . '/modules/'\n"
        "    . $module . '.php';\n"
        "include_once plugin_dir_path(__FILE__) . $_GET['partial'];\n"
        "include('fixed-parenthesized.php');\n"
        "include 'fixed-unparenthesized.php';\n"
        "// require __DIR__ . $commented;\n"
        "/* include_once __DIR__ . $also_commented; */\n"
        '$example = "include __DIR__ . $inside_string";\n'
    )

    artifact, _, sinks = build_coverage_artifact(tmp_path)

    includes = [item for item in artifact.items if item.type == "dynamic_include"]
    assert [(item.line, item.name.lower()) for item in includes] == [
        (2, "include"),
        (3, "require"),
        (5, "include_once"),
        (6, "include"),
    ]
    assert "$template" in includes[0].snippet
    assert "$module" in includes[1].snippet
    assert "\n" in includes[1].snippet
    assert "$_GET['partial']" in includes[2].snippet
    assert includes[3].snippet == "include('fixed-parenthesized.php');"
    assert all(_requires_variable_php_include_trace(item) for item in includes[:3])
    assert not _requires_variable_php_include_trace(includes[3])
    assert [(sink["line"], sink["function"].lower()) for sink in sinks] == [
        (2, "include"),
        (3, "require"),
        (5, "include_once"),
        (6, "include"),
    ]


def test_recon_grep_tracks_extended_file_and_php_code_surfaces():
    write_pattern = re.compile(RIPGREP_PATTERNS["file_put_contents"])
    upload_pattern = re.compile(RIPGREP_PATTERNS["move_uploaded_file"])
    read_pattern = re.compile(RIPGREP_PATTERNS["file_reads"])
    delete_pattern = re.compile(RIPGREP_PATTERNS["unlink"])
    include_pattern = re.compile(RIPGREP_PATTERNS["include_require"])
    eval_pattern = re.compile(RIPGREP_PATTERNS["eval"])

    assert write_pattern.search("$wp_filesystem->put_contents($path, $bytes)")
    assert upload_pattern.search("wp_handle_sideload($file, $overrides)")
    assert upload_pattern.search("wp_upload_bits($name, null, $bytes)")
    assert read_pattern.search("$wp_filesystem->get_contents_array($path)")
    assert read_pattern.search("new SplFileObject($path)")
    assert delete_pattern.search("wp_delete_file($path)")
    assert include_pattern.search("require __DIR__ . '/' . $module")
    assert eval_pattern.search("EVAL\n    ($code)")


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


def test_merge_routes_legacy_surveyor_eval_sink_to_injection_review(tmp_path):
    (tmp_path / "plugin.php").write_text("<?php\n$callable($value);\n")
    coverage, callbacks, sinks = build_coverage_artifact(tmp_path)
    recon = ReconArtifact(
        plugin_slug="demo",
        entry_points=[],
        sinks=[
            {
                "type": "eval",
                "function": "eval",
                "file": "plugin.php",
                "line": 2,
                "tainted_args": ["$value"],
            }
        ],
        entry_to_sink_paths={},
        raw_grep_hits={},
    )

    merge_deterministic_coverage(recon, tmp_path, coverage, callbacks, sinks)

    item = next(item for item in coverage.items if item.type == "eval")
    assert item.review_areas == ["injection_files"]


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


def test_command_execution_covers_extended_calls_and_bounded_backticks(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "exec($command); \\shell_exec($other);\n"
        "pcntl_exec\n"
        "    ('/bin/sh', ['-c', $command]);\n"
        "EXPECT_POPEN($command);\n"
        "$output = `printf '# not a PHP comment // either'`;\n"
        "function exec($value) { return $value; }\n"
        "$runner->exec($command);\n"
        "Runner::exec($command);\n"
        "Tools\\exec($command);\n"
        "// system($commented); `whoami`;\n"
        "/* passthru($commented); `id`; */\n"
        'echo "popen($inside_string) and `uname`";\n'
        "$too_long = `" + ("x" * 2_001) + "`;\n"
        "$heredoc = <<<TEXT\n`not a command`; system($fake); eval($fake);\n"
        "wp_handle_upload($_FILES['fake'], []);\nTEXT;\n"
        "$nowdoc = <<<'TEXT'\n`also not a command`; shell_exec($fake);\nTEXT;\n"
        "?><script>const template = `not PHP command execution`;</script>\n"
    )

    coverage, _, sinks = build_coverage_artifact(tmp_path)

    command_items = [
        item for item in coverage.items if item.type == "command_execution"
    ]
    assert [(item.name.lower(), item.line) for item in command_items] == [
        ("exec", 2),
        ("shell_exec", 2),
        ("pcntl_exec", 3),
        ("expect_popen", 5),
        ("backtick", 6),
    ]
    assert "// either" in command_items[-1].snippet
    assert [
        (sink["function"].lower(), sink["line"])
        for sink in sinks
        if sink["type"] == "command_execution"
    ] == [(item.name.lower(), item.line) for item in command_items]
    assert not any(item.type == "php_code_execution" for item in coverage.items)
    assert not any(item.type == "file_upload" for item in coverage.items)


def test_flexible_heredoc_closer_does_not_hide_later_execution_surface(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "$examples = [<<<END\n"
        "system($not_code); eval($not_code); `not code`;\n"
        "END, 'next'];\n"
        "system($real_command);\n"
    )

    coverage, _, _ = build_coverage_artifact(tmp_path)

    command_items = [
        item for item in coverage.items if item.type == "command_execution"
    ]
    assert [(item.name.lower(), item.line) for item in command_items] == [("system", 5)]
    assert not any(item.type == "php_code_execution" for item in coverage.items)


def test_flexible_heredoc_closer_allows_continued_php_expressions(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "$map = [<<<KEY\n"
        "label\n"
        "KEY => 'value'];\n"
        "$choice = $condition ? <<<TEXT\n"
        "selected\n"
        "TEXT : 'fallback';\n"
        "system($real_command);\n"
    )

    coverage, _, _ = build_coverage_artifact(tmp_path)

    commands = [item for item in coverage.items if item.type == "command_execution"]
    assert [(item.name.lower(), item.line) for item in commands] == [("system", 8)]
    assert not any(item.type == "php_code_execution" for item in coverage.items)


def test_backtick_shell_text_is_not_reclassified_as_nested_php_sinks(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "$output = `echo system($fake) file_put_contents($path, $data)`;\n"
        "$other = `echo ?> /tmp/example`;\n"
        "system($real_command);\n"
    )

    coverage, _, _ = build_coverage_artifact(tmp_path)

    commands = [item for item in coverage.items if item.type == "command_execution"]
    assert [(item.name.lower(), item.line) for item in commands] == [
        ("backtick", 2),
        ("backtick", 3),
        ("system", 4),
    ]
    assert not any(item.type == "file_write" for item in coverage.items)


def test_php_line_comment_close_tag_prevents_template_backtick_false_positives(
    tmp_path,
):
    (tmp_path / "plugin.php").write_text(
        "<?php // comment closes with the tag ?>\n"
        "<script>const first = `not a shell command`;</script>\n"
        "<?php # another comment ?>\n"
        "<script>const second = `still not a shell command`;</script>\n"
        "<?php $actual = `id`;\n"
    )

    coverage, _, _ = build_coverage_artifact(tmp_path)

    commands = [item for item in coverage.items if item.type == "command_execution"]
    assert [(item.name, item.line, item.snippet) for item in commands] == [
        ("backtick", 5, "`id`")
    ]


def test_php_inventory_masks_html_and_javascript_template_regions(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "$ordinary = true;\n"
        "?>\n"
        "<script>eval(value); call_user_func(callback); system(command);</script>\n"
        "<?php\n"
        "system($real_command);\n"
    )

    coverage, _, _ = build_coverage_artifact(tmp_path)

    execution = [
        item
        for item in coverage.items
        if item.type in {"command_execution", "php_code_execution", "dynamic_callable"}
    ]
    assert [(item.type, item.name.lower(), item.line) for item in execution] == [
        ("command_execution", "system", 6)
    ]


def test_high_risk_php_surfaces_allow_newline_before_opening_parenthesis(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "wp_handle_upload\n($_FILES['archive'], []);\n"
        "file_put_contents\n($path, $bytes);\n"
        "$process = new Process\n($arguments);\n"
        "call_user_func\n($callback, $argument);\n"
        "unzip_file\n($archive, $destination);\n"
    )

    coverage, _, _ = build_coverage_artifact(tmp_path)

    assert {
        (item.type, item.name)
        for item in coverage.items
        if item.type
        in {
            "file_upload",
            "file_write",
            "command_wrapper",
            "dynamic_callable",
            "archive_extract",
        }
    } == {
        ("file_upload", "wp_handle_upload"),
        ("file_write", "file_put_contents"),
        ("command_wrapper", "Process"),
        ("dynamic_callable", "call_user_func"),
        ("archive_extract", "unzip_file"),
    }


def test_file_object_methods_require_a_filesystem_like_receiver(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "$order->move($state);\n"
        "$model->copy();\n"
        "$wp_filesystem->copy($source, $destination);\n"
        "$this->storage->move($source, $destination);\n"
    )

    coverage, _, _ = build_coverage_artifact(tmp_path)

    writes = [item for item in coverage.items if item.type == "file_write"]
    assert [(item.name, item.line) for item in writes] == [("copy", 4), ("move", 5)]


def test_filesystem_adapters_and_wp_filesystem_delete_are_file_impacts(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "$filesystem->write($path, $contents);\n"
        "$adapter->writeStream($path, $stream);\n"
        "$this->storage->write($other_path, $contents);\n"
        "$wp_filesystem->delete($target);\n"
        "$this->filesystem->delete($other_target);\n"
        "$writer->write($not_proved_file, $contents);\n"
        "$cache->delete($key);\n"
    )

    coverage, _, sinks = build_coverage_artifact(tmp_path)

    impacts = [
        item
        for item in coverage.items
        if item.type in {"file_write", "file_delete"}
    ]
    assert [(item.type, item.name, item.line) for item in impacts] == [
        ("file_write", "write", 2),
        ("file_write", "writeStream", 3),
        ("file_write", "write", 4),
        ("file_delete", "delete", 5),
        ("file_delete", "delete", 6),
    ]
    assert {
        (sink["type"], sink["function"], sink["line"])
        for sink in sinks
        if sink["type"] in {"file_write", "file_delete"}
    } == {(item.type, item.name, item.line) for item in impacts}


def test_fopen_literal_read_mode_is_not_classified_as_file_write(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "$read = fopen($path, 'rb');\n"
        "$write = fopen($path, 'w');\n"
        "$update = fopen($path, 'r+');\n"
        "$dynamic = fopen($path, $mode);\n"
    )

    coverage, _, _ = build_coverage_artifact(tmp_path)

    fopen_items = [item for item in coverage.items if item.name.lower() == "fopen"]
    assert [(item.type, item.line) for item in fopen_items] == [
        ("file_read", 2),
        ("file_write", 3),
        ("file_write", 4),
        ("file_write", 5),
    ]


def test_ziparchive_constructor_is_anchor_and_extract_to_is_sink(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "$zip = new ZipArchive();\n"
        "$zip->open($archive);\n"
        "$zip->extractTo($destination);\n"
        "$phar = new PharData($archive);\n"
        "$phar->extractTo($other_destination);\n"
    )

    coverage, _, sinks = build_coverage_artifact(tmp_path)

    archive_items = [item for item in coverage.items if item.type == "archive_extract"]
    assert [(item.name, item.kind, item.line) for item in archive_items] == [
        ("ZipArchive", "review_anchor", 2),
        ("extractTo", "sink", 4),
        ("PharData", "review_anchor", 5),
        ("extractTo", "sink", 6),
    ]
    assert [
        (sink["function"], sink["line"])
        for sink in sinks
        if sink["type"] == "archive_extract"
    ] == [("extractTo", 4), ("extractTo", 6)]


def test_request_selected_variable_call_is_a_bounded_review_anchor(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "add_action('wp_ajax_nopriv_dynamic', 'dynamic_handler');\n"
        "add_action('wp_ajax_nopriv_safe', 'safe_handler');\n"
        "add_action('wp_ajax_nopriv_case', 'case_handler');\n"
        "function dynamic_handler() {\n"
        "  $fn = sanitize_key($_POST['fn']);\n"
        "  $fn($_POST['argument']);\n"
        "}\n"
        "function safe_handler() {\n"
        "  $fn = 'trim';\n"
        "  $fn($_POST['value']);\n"
        "  $model->copy(); $item->touch(); $query->fwrite();\n"
        "}\n"
        "function case_handler() {\n"
        "  $Fn = sanitize_key($_POST['fn']);\n"
        "  $fn($_POST['value']);\n"
        "}\n"
    )

    coverage, _, sinks = build_coverage_artifact(tmp_path)

    dynamic = [
        item
        for item in coverage.items
        if item.type == "dynamic_callable" and item.name == "fn"
    ]
    assert len(dynamic) == 1
    assert dynamic[0].kind == "review_anchor"
    assert "$_POST['fn']" in dynamic[0].snippet
    assert not any(sink["function"] == "fn" for sink in sinks)
    entries = {
        item.handler_function: item
        for item in coverage.items
        if item.kind == "entry_point"
    }
    assert "injection_files" in entries["dynamic_handler"].review_areas
    assert "injection_files" not in entries["safe_handler"].review_areas
    assert "injection_files" not in entries["case_handler"].review_areas


def test_direct_request_array_callables_are_bounded_review_anchors(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "add_action('wp_ajax_nopriv_direct', 'direct_handler');\n"
        "add_action('wp_ajax_nopriv_parenthesized', 'parenthesized_handler');\n"
        "add_action('wp_ajax_nopriv_safe', 'safe_handler');\n"
        "function direct_handler() {\n"
        "  $_GET['fn']($_GET['argument']);\n"
        "}\n"
        "function parenthesized_handler() {\n"
        "  ($_POST['fn'])($_POST['argument']);\n"
        "}\n"
        "function safe_handler() {\n"
        "  $callbacks['trim']($_POST['value']);\n"
        "  // $_REQUEST['fn']($_REQUEST['value']);\n"
        "  $example = \"$_COOKIE['fn']($_COOKIE['value'])\";\n"
        "}\n"
    )

    coverage, _, sinks = build_coverage_artifact(tmp_path)

    direct = [
        item
        for item in coverage.items
        if item.type == "dynamic_callable" and item.name == "request_callable"
    ]
    assert [(item.kind, item.line) for item in direct] == [
        ("review_anchor", 6),
        ("review_anchor", 9),
    ]
    assert all("$_" in item.snippet for item in direct)
    assert not any(sink["function"] == "request_callable" for sink in sinks)
    entries = {
        item.handler_function: item
        for item in coverage.items
        if item.kind == "entry_point"
    }
    assert "injection_files" in entries["direct_handler"].review_areas
    assert "injection_files" in entries["parenthesized_handler"].review_areas
    assert "injection_files" not in entries["safe_handler"].review_areas


def test_request_selected_callback_apis_require_a_tainted_callback(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "add_action('wp_ajax_nopriv_map', 'map_handler');\n"
        "add_action('wp_ajax_nopriv_sort', 'sort_handler');\n"
        "add_action('wp_ajax_nopriv_safe', 'safe_handler');\n"
        "function map_handler() {\n"
        "  return array_map($_POST['callback'], ['value']);\n"
        "}\n"
        "function sort_handler() {\n"
        "  $callback = sanitize_key($_GET['callback']);\n"
        "  usort($items, $callback);\n"
        "}\n"
        "function safe_handler() {\n"
        "  $callback = 'strcasecmp';\n"
        "  usort($items, $callback);\n"
        "  $collection->array_map($_POST['callback'], $items);\n"
        "}\n"
    )

    coverage, _, sinks = build_coverage_artifact(tmp_path)

    callbacks = [
        item
        for item in coverage.items
        if item.type == "dynamic_callable" and item.name in {"array_map", "usort"}
    ]
    assert [(item.name, item.kind, item.line) for item in callbacks] == [
        ("array_map", "review_anchor", 6),
        ("usort", "review_anchor", 10),
    ]
    assert "$_GET['callback']" in callbacks[1].snippet
    assert not any(sink["function"] in {"array_map", "usort"} for sink in sinks)
    entries = {
        item.handler_function: item
        for item in coverage.items
        if item.kind == "entry_point"
    }
    assert "injection_files" in entries["map_handler"].review_areas
    assert "injection_files" in entries["sort_handler"].review_areas
    assert "injection_files" not in entries["safe_handler"].review_areas


def test_fixed_command_callbacks_require_request_derived_callback_data(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "add_action('wp_ajax_nopriv_map_command', 'map_command');\n"
        "add_action('wp_ajax_nopriv_shutdown_command', 'shutdown_command');\n"
        "add_action('wp_ajax_nopriv_filter_command', 'filter_command');\n"
        "add_action('wp_ajax_nopriv_safe_callbacks', 'safe_callbacks');\n"
        "function map_command() {\n"
        "  return array_map('system', $_POST['commands']);\n"
        "}\n"
        "function shutdown_command() {\n"
        "  register_shutdown_function('shell_exec', $_GET['command']);\n"
        "}\n"
        "function filter_command() {\n"
        "  $commands = $_REQUEST['commands'];\n"
        "  return array_filter($commands, 'exec');\n"
        "}\n"
        "function safe_callbacks() {\n"
        "  $fixed = ['date'];\n"
        "  array_map('system', $fixed);\n"
        "  array_map('system', ['$_POST[commands]']);\n"
        "  array_map('trim', $_POST['values']);\n"
        "  register_shutdown_function('passthru', 'date');\n"
        "  register_shutdown_function('proc_open', $_GET['incomplete']);\n"
        "  array_map('popen', $_POST['commands']);\n"
        "  preg_replace_callback('/.+/', 'system', $_POST['subject']);\n"
        "  set_error_handler('system');\n"
        "}\n"
    )

    coverage, _, sinks = build_coverage_artifact(tmp_path)

    commands = [item for item in coverage.items if item.type == "command_execution"]
    assert [(item.name, item.kind, item.line) for item in commands] == [
        ("system", "sink", 7),
        ("shell_exec", "sink", 10),
        ("exec", "sink", 14),
    ]
    assert "$_REQUEST['commands']" in commands[2].snippet
    assert {
        (sink["function"], sink["line"])
        for sink in sinks
        if sink["type"] == "command_execution"
    } == {("system", 7), ("shell_exec", 10), ("exec", 14)}
    entries = {
        item.handler_function: item
        for item in coverage.items
        if item.kind == "entry_point"
    }
    for handler in {"map_command", "shutdown_command", "filter_command"}:
        assert "injection_files" in entries[handler].review_areas
    assert "injection_files" not in entries["safe_callbacks"].review_areas


def test_request_selected_callable_assignments_do_not_cross_closure_scopes(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "function outer_handler() {\n"
        "  $fn = 'trim';\n"
        "  $nested = function () {\n"
        "    $fn = $_POST['nested_fn'];\n"
        "    $fn($_POST['nested_value']);\n"
        "  };\n"
        "  $fn($_POST['outer_value']);\n"
        "  usort($items, $callback);\n"
        "}\n"
        "$callback = 'strcasecmp';\n"
        "$nested = function () { $callback = $_POST['callback']; };\n"
        "usort($items, $callback);\n"
    )

    coverage, _, _ = build_coverage_artifact(tmp_path)

    dynamic = [item for item in coverage.items if item.type == "dynamic_callable"]
    assert [(item.name, item.line) for item in dynamic] == [("fn", 6)]


def test_request_selected_method_dispatch_is_a_bounded_review_anchor(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "add_action('wp_ajax_nopriv_dispatch', 'dispatch_handler');\n"
        "add_action('wp_ajax_nopriv_static', 'static_handler');\n"
        "add_action('wp_ajax_nopriv_direct_method', 'direct_method_handler');\n"
        "add_action('wp_ajax_nopriv_safe_dispatch', 'safe_dispatch_handler');\n"
        "function dispatch_handler() {\n"
        "  $method = sanitize_key($_POST['method']);\n"
        "  $this->$method($_POST['argument']);\n"
        "}\n"
        "function static_handler() {\n"
        "  $class = sanitize_text_field($_POST['class']);\n"
        "  $method = 'run';\n"
        "  $class::$method($_POST['argument']);\n"
        "}\n"
        "function direct_method_handler() {\n"
        "  $this->{sanitize_key($_POST['method'])}($_POST['argument']);\n"
        "}\n"
        "function safe_dispatch_handler() {\n"
        "  $method = 'render';\n"
        "  $this->$method($_POST['value']);\n"
        "}\n"
    )

    coverage, _, sinks = build_coverage_artifact(tmp_path)

    dynamic = [
        item
        for item in coverage.items
        if item.type == "dynamic_callable"
        and item.name in {"method", "class", "request_method"}
    ]
    assert [(item.name, item.kind, item.line) for item in dynamic] == [
        ("method", "review_anchor", 8),
        ("class", "review_anchor", 13),
        ("request_method", "review_anchor", 16),
    ]
    assert not any(sink["function"] in {"method", "class"} for sink in sinks)
    entries = {
        item.handler_function: item
        for item in coverage.items
        if item.kind == "entry_point"
    }
    assert "injection_files" in entries["dispatch_handler"].review_areas
    assert "injection_files" in entries["static_handler"].review_areas
    assert "injection_files" in entries["direct_method_handler"].review_areas
    assert "injection_files" not in entries["safe_dispatch_handler"].review_areas


def test_indirect_execution_archive_and_upload_policy_surfaces(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "$process = new Symfony\\Component\\Process\\Process($arguments);\n"
        "$shell = Process::fromShellCommandline($command);\n"
        "WP_CLI::runcommand($command);\n"
        "$process->mustRun();\n"
        "call_user_func($callback, $argument);\n"
        "forward_static_call_array($callback, $arguments);\n"
        "$reflector = new ReflectionFunction($callback);\n"
        "$reflector->invoke($argument);\n"
        "unzip_file($archive, $destination);\n"
        "$zip = new PclZip($archive);\n"
        "$zip->extract(PCLZIP_OPT_PATH, $destination);\n"
        "$tar = new Archive_Tar($archive);\n"
        "$tar->extractModify($destination, $remove_path);\n"
        "stream_copy_to_stream($source, $destination);\n"
        "$wp_filesystem->move($source, $destination);\n"
        "$wp_filesystem->copy($source, $destination);\n"
        "add_filter('upload_mimes', 'allow_custom_mimes');\n"
        "add_filter('wp_handle_upload_prefilter', 'inspect_upload');\n"
        "add_filter('the_content', 'ordinary_filter');\n"
        "// add_filter('mime_types', 'commented');\n"
        "$example = \"add_filter('upload_dir', 'inside_string')\";\n"
    )

    coverage, _, sinks = build_coverage_artifact(tmp_path)

    by_type = {
        surface_type: [
            item.name for item in coverage.items if item.type == surface_type
        ]
        for surface_type in {
            "command_wrapper",
            "dynamic_callable",
            "archive_extract",
            "file_write",
            "upload_policy",
        }
    }
    assert by_type["command_wrapper"] == [
        "Process",
        "Process",
        "WP_CLI",
        "mustRun",
    ]
    assert by_type["dynamic_callable"] == [
        "call_user_func",
        "forward_static_call_array",
        "ReflectionFunction",
        "invoke",
    ]
    assert by_type["archive_extract"] == [
        "unzip_file",
        "PclZip",
        "extract",
        "Archive_Tar",
        "extractModify",
    ]
    assert by_type["file_write"] == [
        "stream_copy_to_stream",
        "move",
        "copy",
    ]
    assert by_type["upload_policy"] == [
        "upload_mimes",
        "wp_handle_upload_prefilter",
    ]
    assert all(
        item.review_areas == ["injection_files"]
        for item in coverage.items
        if item.type in by_type
    )
    assert {
        (sink["type"], sink["function"]) for sink in sinks if sink["type"] in by_type
    } == {
        (item.type, item.name)
        for item in coverage.items
        if item.type in by_type and item.kind == "sink"
    }
    assert any(
        item.kind == "review_anchor"
        for item in coverage.items
        if item.type in {"command_wrapper", "dynamic_callable", "archive_extract"}
    )


def test_aliased_symfony_process_constructor_routes_to_focused_review(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "use Symfony\\Component\\Process\\Process as Runner;\n"
        "add_action('wp_ajax_nopriv_run_alias', 'run_alias');\n"
        "function run_alias() {\n"
        "  $command = sanitize_text_field($_POST['command']);\n"
        "  return (new Runner($command))->run();\n"
        "}\n"
    )
    (tmp_path / "decoys.php").write_text(
        "<?php\n"
        "use Vendor\\Tools\\Runner;\n"
        "new Runner($ordinary_argument);\n"
        "// use Symfony\\Component\\Process\\Process as CommentRunner;\n"
        "// new CommentRunner($command);\n"
        "$example = 'use Symfony\\\\Component\\\\Process\\\\Process as StringRunner;';\n"
        "new StringRunner($ordinary_argument);\n"
    )

    coverage, _, sinks = build_coverage_artifact(tmp_path)

    wrappers = [
        item
        for item in coverage.items
        if item.type == "command_wrapper" and item.name != "Process"
    ]
    assert [(item.name, item.kind, item.line) for item in wrappers] == [
        ("Runner", "review_anchor", 6)
    ]
    assert "$command" in wrappers[0].snippet
    assert "->run()" in wrappers[0].snippet
    assert not any(sink["function"] == "Runner" for sink in sinks)
    entry = next(
        item
        for item in coverage.items
        if item.kind == "entry_point" and item.handler_function == "run_alias"
    )
    assert "injection_files" in entry.review_areas


def test_entry_points_route_to_injection_only_for_high_signal_callback_code(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "add_action('wp_ajax_upload_raw', 'upload_raw');\n"
        "add_action('wp_ajax_run_object', 'run_object');\n"
        "add_action('wp_ajax_save_title', 'save_title');\n"
        "function upload_raw() { $bytes = file_get_contents('php://input'); }\n"
        "function run_object() { $runner->exec($_POST['task']); }\n"
        "function save_title() { update_option('title', $_POST['title']); }\n"
    )
    (tmp_path / "unresolved-risk.php").write_text(
        "<?php\n"
        "add_action('wp_ajax_unknown_upload', 'missing_upload_handler');\n"
        "$file = $_FILES['archive'];\n"
    )
    (tmp_path / "unresolved-clean.php").write_text(
        "<?php\n"
        "add_action('wp_ajax_unknown_clean', 'missing_clean_handler');\n"
        "$value = get_option('ordinary');\n"
    )

    coverage, _, _ = build_coverage_artifact(tmp_path)

    entries = {
        item.handler_function: item
        for item in coverage.items
        if item.kind == "entry_point"
    }
    assert "injection_files" in entries["upload_raw"].review_areas
    assert "injection_files" in entries["missing_upload_handler"].review_areas
    assert "injection_files" not in entries["run_object"].review_areas
    assert "injection_files" not in entries["save_title"].review_areas
    assert "injection_files" not in entries["missing_clean_handler"].review_areas


def test_entry_point_focused_routing_prefers_same_file_duplicate_definition(tmp_path):
    (tmp_path / "a.php").write_text(
        "<?php\nfunction save() { update_option('ordinary', 'fixed'); }\n"
    )
    (tmp_path / "b.php").write_text(
        "<?php\n"
        "add_action('wp_ajax_nopriv_danger', 'save');\n"
        "function save() { system($_POST['command']); }\n"
    )

    coverage, callbacks, sinks = build_coverage_artifact(tmp_path)

    danger = next(
        item
        for item in coverage.items
        if item.kind == "entry_point" and item.name == "wp_ajax_nopriv_danger"
    )
    assert "injection_files" in danger.review_areas

    recon = ReconArtifact(
        plugin_slug="demo",
        entry_points=[],
        sinks=[],
        entry_to_sink_paths={},
        raw_grep_hits={},
    )
    merge_deterministic_coverage(recon, tmp_path, coverage, callbacks, sinks)

    merged = next(
        entry for entry in recon.entry_points if entry.name == "wp_ajax_nopriv_danger"
    )
    assert merged.file == "b.php"
    assert merged.line == 3
    assert "system($_POST['command'])" in (merged.body_slice or "")


def test_merge_never_resolves_php_callback_to_same_named_javascript_function(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\nadd_action('wp_ajax_nopriv_missing', 'missing_handler');\n"
    )
    (tmp_path / "app.js").write_text(
        "function missing_handler() { return 'javascript only'; }\n"
    )
    coverage, callbacks, sinks = build_coverage_artifact(tmp_path)
    recon = ReconArtifact(
        plugin_slug="demo",
        entry_points=[],
        sinks=[],
        entry_to_sink_paths={},
        raw_grep_hits={},
    )

    merge_deterministic_coverage(recon, tmp_path, coverage, callbacks, sinks)

    merged = next(
        entry for entry in recon.entry_points if entry.name == "wp_ajax_nopriv_missing"
    )
    assert merged.file == "plugin.php"
    assert merged.line == 2
    assert merged.confidence == "medium"
    assert merged.body_slice is None


def test_callback_definition_resolution_honours_php_case_insensitivity(tmp_path):
    (tmp_path / "register.php").write_text(
        "<?php\nadd_action('wp_ajax_nopriv_case', 'Handle_Request');\n"
    )
    (tmp_path / "handler.php").write_text(
        "<?php\nfunction handle_request() { system($_POST['command']); }\n"
    )

    coverage, callbacks, sinks = build_coverage_artifact(tmp_path)
    entry = next(
        item
        for item in coverage.items
        if item.kind == "entry_point" and item.name == "wp_ajax_nopriv_case"
    )
    assert "injection_files" in entry.review_areas
    recon = ReconArtifact(
        plugin_slug="demo",
        entry_points=[],
        sinks=[],
        entry_to_sink_paths={},
        raw_grep_hits={},
    )

    merge_deterministic_coverage(recon, tmp_path, coverage, callbacks, sinks)

    merged = next(
        item for item in recon.entry_points if item.name == "wp_ajax_nopriv_case"
    )
    assert merged.file == "handler.php"
    assert merged.line == 2
    assert merged.confidence == "high"
    assert "system($_POST['command'])" in (merged.body_slice or "")


def test_persistent_sql_operands_follow_exact_local_assignments(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "function query_from_option() {\n"
        "  global $wpdb;\n"
        "  $column = get_option('report_column');\n"
        "  $sql = 'SELECT * FROM reports ORDER BY ' . $column;\n"
        "  return $wpdb->get_results($sql);\n"
        "}\n"
        "function direct_meta_operand($post_id) {\n"
        "  global $wpdb;\n"
        "  return $wpdb->query('SELECT * FROM reports WHERE tag = ' . get_post_meta($post_id, 'tag', true));\n"
        "}\n"
        "function custom_table_operand() {\n"
        "  global $wpdb;\n"
        "  $stored_column = $wpdb->get_var('SELECT column_name FROM report_settings LIMIT 1');\n"
        "  $query = 'SELECT * FROM reports ORDER BY ' . $stored_column;\n"
        "  return $wpdb->get_results($query);\n"
        "}\n"
    )

    coverage, _, _ = build_coverage_artifact(tmp_path)

    persistent = [
        item for item in coverage.items if item.type == "persistent_sql_operand"
    ]
    assert [(item.name, item.line) for item in persistent] == [
        ("get_option", 4),
        ("get_post_meta", 10),
        ("get_var", 14),
    ]
    assert all(item.kind == "storage_read" for item in persistent)
    assert all(item.review_areas == ["injection_files"] for item in persistent)


def test_persistent_sql_getters_require_global_calls_and_include_core_fields(
    tmp_path,
):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "function global_and_core_reads($post_id) {\n"
        "  global $wpdb;\n"
        "  $global_sort = \\get_option('global_sort');\n"
        "  $post_sort = get_post_field('post_title', $post_id, 'raw');\n"
        "  $sql = 'SELECT * FROM reports ORDER BY ' . $global_sort . ', ' . $post_sort;\n"
        "  return $wpdb->get_results($sql);\n"
        "}\n"
        "function receiver_decoys() {\n"
        "  global $wpdb;\n"
        "  $first = $cache->get_option('sort');\n"
        "  $second = Settings::get_site_option('sort');\n"
        "  $third = $repository->get_post_field('post_title');\n"
        "  $sql = 'SELECT * FROM reports ORDER BY ' . $first . $second . $third;\n"
        "  return $wpdb->get_results($sql);\n"
        "}\n"
    )

    coverage, _, _ = build_coverage_artifact(tmp_path)

    persistent = [
        item for item in coverage.items if item.type == "persistent_sql_operand"
    ]
    assert [(item.name, item.line) for item in persistent] == [
        ("get_option", 4),
        ("get_post_field", 5),
    ]


def test_persistent_sql_operands_follow_interpolating_heredoc_variables(
    tmp_path,
):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "function bare_heredoc_query($post_id) {\n"
        "  global $wpdb;\n"
        "  $sort = get_option('report_sort');\n"
        "  $direction = get_post_meta($post_id, 'report_direction', true);\n"
        "  $sql = <<<SQL\n"
        "SELECT * FROM reports\n"
        "ORDER BY {$sort} {$direction}\n"
        "SQL;\n"
        "  return $wpdb->get_results($sql);\n"
        "}\n"
        "function quoted_heredoc_query() {\n"
        "  global $wpdb;\n"
        "  $column = get_option('report_column');\n"
        '  $sql = <<<"QUERY"\n'
        "SELECT {$column} FROM reports\n"
        "QUERY;\n"
        "  return $wpdb->get_results($sql);\n"
        "}\n"
    )

    coverage, _, _ = build_coverage_artifact(tmp_path)

    persistent = [
        item for item in coverage.items if item.type == "persistent_sql_operand"
    ]
    assert [(item.name, item.line) for item in persistent] == [
        ("get_option", 4),
        ("get_post_meta", 5),
        ("get_option", 14),
    ]


def test_persistent_sql_operands_follow_complex_values_in_heredocs(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "function complex_heredoc_query($post_id) {\n"
        "  global $wpdb;\n"
        "  $this->sort = get_option('report_sort');\n"
        "  $parts['direction'] = get_post_meta($post_id, 'direction', true);\n"
        "  $parts[-1] = get_site_option('fallback_sort');\n"
        "  $sql = <<<SQL\n"
        "SELECT * FROM reports\n"
        "ORDER BY {$this->sort} {$parts['direction']} {$parts[-1]}\n"
        "SQL;\n"
        "  return $wpdb->get_results($sql);\n"
        "}\n"
    )

    coverage, _, _ = build_coverage_artifact(tmp_path)

    persistent = [
        item for item in coverage.items if item.type == "persistent_sql_operand"
    ]
    assert [(item.name, item.line) for item in persistent] == [
        ("get_option", 4),
        ("get_post_meta", 5),
        ("get_site_option", 6),
    ]


def test_persistent_sql_operands_follow_double_quoted_interpolation(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "function interpolated_query($post_id) {\n"
        "  global $wpdb;\n"
        "  $sort = get_option('report_sort');\n"
        "  $this->direction = get_post_meta($post_id, 'direction', true);\n"
        "  $parts['column'] = get_site_option('report_column');\n"
        "  $parts[-1] = get_transient('fallback_sort');\n"
        '  $sql = "SELECT * FROM reports ORDER BY $sort, {$this->direction}, '
        "{$parts['column']}, {$parts[-1]}\";\n"
        "  return $wpdb->get_results($sql);\n"
        "}\n"
    )

    coverage, _, _ = build_coverage_artifact(tmp_path)

    persistent = [
        item for item in coverage.items if item.type == "persistent_sql_operand"
    ]
    assert [(item.name, item.line) for item in persistent] == [
        ("get_option", 4),
        ("get_post_meta", 5),
        ("get_site_option", 6),
        ("get_transient", 7),
    ]


def test_single_quoted_and_escaped_string_values_are_not_persistent_operands(
    tmp_path,
):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "function literal_string_queries() {\n"
        "  global $wpdb;\n"
        "  $stored = get_option('unrelated_value');\n"
        "  $this->stored = get_site_option('unrelated_property');\n"
        "  $parts['stored'] = get_option('unrelated_array');\n"
        "  $single = 'SELECT $stored, {$this->stored}, {$parts[\"stored\"]}';\n"
        '  $escaped = "SELECT \\$stored, {\\$this->stored}, '
        "{\\$parts['stored']}\";\n"
        "  $wpdb->get_results($single);\n"
        "  return $wpdb->get_results($escaped);\n"
        "}\n"
    )

    coverage, _, _ = build_coverage_artifact(tmp_path)

    assert not any(item.type == "persistent_sql_operand" for item in coverage.items)


def test_nowdoc_and_escaped_heredoc_variables_are_not_persistent_operands(
    tmp_path,
):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "function literal_queries() {\n"
        "  global $wpdb;\n"
        "  $stored = get_option('unrelated_value');\n"
        "  $this->stored = get_site_option('unrelated_property');\n"
        "  $parts['stored'] = get_option('unrelated_array');\n"
        "  $nowdoc = <<<'SQL'\n"
        "SELECT * FROM reports WHERE value = '{$stored}'\n"
        "ORDER BY {$this->stored}, {$parts['stored']}\n"
        "SQL;\n"
        "  $escaped = <<<SQL\n"
        "SELECT * FROM reports WHERE value = '\\$stored'\n"
        "ORDER BY {\\$this->stored}, {\\$parts['stored']}\n"
        "SQL;\n"
        "  $wpdb->get_results($nowdoc);\n"
        "  return $wpdb->get_results($escaped);\n"
        "}\n"
    )

    coverage, _, _ = build_coverage_artifact(tmp_path)

    assert not any(item.type == "persistent_sql_operand" for item in coverage.items)


def test_non_sql_heredoc_contents_do_not_create_persistent_sql_surfaces(
    tmp_path,
):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "function render_debug_text() {\n"
        "  global $wpdb;\n"
        "  $stored = get_option('debug_value');\n"
        "  $message = <<<TEXT\n"
        "Example only: $stored\n"
        "$wpdb->get_results($stored);\n"
        "get_option('literal_example');\n"
        "TEXT;\n"
        "  echo esc_html($message);\n"
        "}\n"
    )

    coverage, _, _ = build_coverage_artifact(tmp_path)

    assert not any(item.type == "sql_query" for item in coverage.items)
    assert not any(item.type == "persistent_sql_operand" for item in coverage.items)


def test_persistent_sql_operands_follow_simple_property_and_array_lvalues(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "function property_query() {\n"
        "  global $wpdb;\n"
        "  $this->sql = 'SELECT * FROM reports ORDER BY ' . get_option('property_sort');\n"
        "  return $wpdb->get_results($this->sql);\n"
        "}\n"
        "function array_query() {\n"
        "  global $wpdb;\n"
        "  $queries['report'] = 'SELECT * FROM reports ORDER BY ' . get_option('array_sort');\n"
        "  return $wpdb->get_results($queries['report']);\n"
        "}\n"
    )

    coverage, _, _ = build_coverage_artifact(tmp_path)

    persistent = [
        item for item in coverage.items if item.type == "persistent_sql_operand"
    ]
    assert [(item.name, item.line) for item in persistent] == [
        ("get_option", 4),
        ("get_option", 9),
    ]


def test_persistent_sql_operands_follow_intermediate_property_and_array_values(
    tmp_path,
):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "function chained_complex_query($post_id) {\n"
        "  global $wpdb;\n"
        "  $this->raw_sort = get_option('report_sort');\n"
        "  $parts['sort'] = $this->raw_sort;\n"
        "  $parts[0] = get_post_meta($post_id, 'direction', true);\n"
        "  $this->sql = 'SELECT * FROM reports ORDER BY ' . $parts['sort'] . ' ' . $parts[0];\n"
        "  return $wpdb->get_results($this->sql);\n"
        "}\n"
    )

    coverage, _, _ = build_coverage_artifact(tmp_path)

    persistent = [
        item for item in coverage.items if item.type == "persistent_sql_operand"
    ]
    assert [(item.name, item.line) for item in persistent] == [
        ("get_option", 4),
        ("get_post_meta", 6),
    ]


def test_persistent_sql_operands_keep_php_variable_case_distinct(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "function case_sensitive_query() {\n"
        "  global $wpdb;\n"
        "  $Sort = get_option('primary_sort');\n"
        "  $sort = get_option('secondary_sort');\n"
        "  $sql = 'SELECT * FROM reports ORDER BY ' . $Sort . ', ' . $sort;\n"
        "  return $wpdb->get_results($sql);\n"
        "}\n"
    )

    coverage, _, _ = build_coverage_artifact(tmp_path)

    persistent = [
        item for item in coverage.items if item.type == "persistent_sql_operand"
    ]
    assert [(item.name, item.line) for item in persistent] == [
        ("get_option", 4),
        ("get_option", 5),
    ]


def test_persistent_sql_operands_keep_property_array_and_this_case_distinct(
    tmp_path,
):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "function case_sensitive_complex_query() {\n"
        "  global $wpdb;\n"
        "  $this->Sort = get_option('property_sort');\n"
        "  $parts['Sort'] = get_option('key_sort');\n"
        "  $Parts[0] = get_option('array_sort');\n"
        "  $This->sort = get_option('object_sort');\n"
        "  $sql = <<<SQL\n"
        "SELECT * FROM reports\n"
        "ORDER BY {$this->sort}, {$parts['sort']}, {$parts[0]}\n"
        "SQL;\n"
        "  return $wpdb->get_results($sql);\n"
        "}\n"
    )

    coverage, _, _ = build_coverage_artifact(tmp_path)

    assert not any(item.type == "persistent_sql_operand" for item in coverage.items)


def test_persistent_sql_operands_trace_exact_mixed_case_values(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "function matching_case_query() {\n"
        "  global $wpdb;\n"
        "  $this->Sort = get_option('property_sort');\n"
        "  $Parts['Sort'] = get_option('array_sort');\n"
        "  $This = get_site_option('capitalized_local');\n"
        "  $sql = 'SELECT * FROM reports ORDER BY ' . $this->Sort . ', ' . $Parts['Sort'] . ', ' . $This;\n"
        "  return $wpdb->get_results($sql);\n"
        "}\n"
    )

    coverage, _, _ = build_coverage_artifact(tmp_path)

    persistent = [
        item for item in coverage.items if item.type == "persistent_sql_operand"
    ]
    assert [(item.name, item.line) for item in persistent] == [
        ("get_option", 4),
        ("get_option", 5),
        ("get_site_option", 6),
    ]


def test_persistent_sql_operands_follow_numeric_array_lvalues(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "function numeric_array_query() {\n"
        "  global $wpdb;\n"
        "  $queries[ 0 ] = 'SELECT * FROM reports ORDER BY ' . get_option('numeric_sort');\n"
        "  return $wpdb->get_results($queries[0]);\n"
        "}\n"
    )

    coverage, _, _ = build_coverage_artifact(tmp_path)

    persistent = [
        item for item in coverage.items if item.type == "persistent_sql_operand"
    ]
    assert [(item.name, item.line) for item in persistent] == [
        ("get_option", 4),
    ]


def test_prepared_property_and_array_queries_are_not_second_order_anchors(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "function prepared_property() {\n"
        "  global $wpdb;\n"
        "  $this->sql = $wpdb->prepare('SELECT * FROM reports WHERE value = %s', get_option('property_value'));\n"
        "  return $wpdb->get_results($this->sql);\n"
        "}\n"
        "function prepared_array() {\n"
        "  global $wpdb;\n"
        "  $queries['report'] = $wpdb->prepare('SELECT * FROM reports WHERE value = %s', get_option('array_value'));\n"
        "  return $wpdb->get_results($queries['report']);\n"
        "}\n"
    )

    coverage, _, _ = build_coverage_artifact(tmp_path)

    assert not any(item.type == "persistent_sql_operand" for item in coverage.items)


def test_prepared_queries_with_intermediate_complex_values_remain_excluded(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "function prepared_complex_query($post_id) {\n"
        "  global $wpdb;\n"
        "  $this->needle = get_option('property_value');\n"
        "  $params['needle'] = get_post_meta($post_id, 'array_value', true);\n"
        "  $params[-1] = get_site_option('numeric_value');\n"
        "  $this->sql = $wpdb->prepare(\n"
        "    'SELECT * FROM reports WHERE a = %s AND b = %s AND c = %s',\n"
        "    $this->needle,\n"
        "    $params['needle'],\n"
        "    $params[-1]\n"
        "  );\n"
        "  return $wpdb->get_results($this->sql);\n"
        "}\n"
    )

    coverage, _, _ = build_coverage_artifact(tmp_path)

    assert not any(item.type == "persistent_sql_operand" for item in coverage.items)


def test_complete_prepare_still_detects_raw_persistent_query_text(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "function prepared_interpolation() {\n"
        "  global $wpdb;\n"
        "  $sort = get_option('report_sort');\n"
        '  $sql = $wpdb->prepare("SELECT * FROM reports ORDER BY {$sort}");\n'
        "  return $wpdb->get_results($sql);\n"
        "}\n"
        "function prepared_concatenation($status) {\n"
        "  global $wpdb;\n"
        "  $column = get_site_option('report_column');\n"
        "  $sql = $wpdb->prepare('SELECT * FROM reports WHERE status = %s ORDER BY ' . $column, $status);\n"
        "  return $wpdb->get_results($sql);\n"
        "}\n"
        "function prepared_direct_getter($status) {\n"
        "  global $wpdb;\n"
        "  $sql = $wpdb->prepare('SELECT * FROM reports WHERE status = %s ORDER BY ' . get_option('direct_sort'), $status);\n"
        "  return $wpdb->get_results($sql);\n"
        "}\n"
    )

    coverage, _, _ = build_coverage_artifact(tmp_path)

    persistent = [
        item for item in coverage.items if item.type == "persistent_sql_operand"
    ]
    assert [(item.name, item.line) for item in persistent] == [
        ("get_option", 4),
        ("get_site_option", 10),
        ("get_option", 16),
    ]


def test_prepare_placeholder_values_and_fixed_query_text_remain_excluded(tmp_path):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "function safely_prepared_values() {\n"
        "  global $wpdb;\n"
        "  $string = get_option('stored_string');\n"
        "  $integer = get_option('stored_integer');\n"
        "  $float = get_option('stored_float');\n"
        "  $identifier = get_option('stored_identifier');\n"
        "  $sql = $wpdb->prepare(\n"
        "    'SELECT * FROM reports WHERE a = %s AND b = %d AND c = %f ORDER BY %i',\n"
        "    $string, $integer, $float, $identifier\n"
        "  );\n"
        "  $wpdb->get_results($sql);\n"
        "  $fixed = $wpdb->prepare('SELECT * FROM reports WHERE status = \\'active\\'');\n"
        "  return $wpdb->get_results($fixed);\n"
        "}\n"
    )

    coverage, _, _ = build_coverage_artifact(tmp_path)

    assert not any(item.type == "persistent_sql_operand" for item in coverage.items)


def test_persistent_sql_operand_detects_unsafe_suffix_after_prepared_fragment(
    tmp_path,
):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "function query_with_unsafe_suffix($status) {\n"
        "  global $wpdb;\n"
        "  $sort = get_option('report_sort');\n"
        "  $sql = $wpdb->prepare('SELECT * FROM reports WHERE status = %s', $status) . ' ORDER BY ' . $sort;\n"
        "  return $wpdb->get_results($sql);\n"
        "}\n"
    )

    coverage, _, _ = build_coverage_artifact(tmp_path)

    persistent = [
        item for item in coverage.items if item.type == "persistent_sql_operand"
    ]
    assert [(item.name, item.line) for item in persistent] == [("get_option", 4)]


def test_persistent_sql_operand_detects_compound_append_after_prepared_base(
    tmp_path,
):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "function query_with_compound_suffix($status) {\n"
        "  global $wpdb;\n"
        "  $sql = $wpdb->prepare('SELECT * FROM reports WHERE status = %s', $status);\n"
        "  $sql .= ' ORDER BY ' . get_option('report_sort');\n"
        "  return $wpdb->get_results($sql);\n"
        "}\n"
    )

    coverage, _, _ = build_coverage_artifact(tmp_path)

    persistent = [
        item for item in coverage.items if item.type == "persistent_sql_operand"
    ]
    assert [(item.name, item.line) for item in persistent] == [("get_option", 5)]


def test_persistent_sql_operands_exclude_prepared_unrelated_and_cross_function_reads(
    tmp_path,
):
    (tmp_path / "plugin.php").write_text(
        "<?php\n"
        "function prepared_query() {\n"
        "  global $wpdb;\n"
        "  $stored = get_option('stored_value');\n"
        "  $sql = $wpdb->prepare('SELECT * FROM reports WHERE value = %s', $stored);\n"
        "  return $wpdb->get_results($sql);\n"
        "}\n"
        "function unrelated_read($id) {\n"
        "  global $wpdb;\n"
        "  $unused = get_option('unused');\n"
        "  $sql = 'SELECT * FROM reports WHERE id = ' . $id;\n"
        "  return $wpdb->get_results($sql);\n"
        "}\n"
        "function load_column() { return get_option('column'); }\n"
        "function separate_function($column) {\n"
        "  global $wpdb;\n"
        "  $sql = 'SELECT * FROM reports ORDER BY ' . $column;\n"
        "  return $wpdb->get_results($sql);\n"
        "}\n"
        "function string_and_comment($id) {\n"
        "  global $wpdb;\n"
        "  // $column = get_option('commented');\n"
        "  $example = \"get_option('inside_string')\";\n"
        "  return $wpdb->get_results('SELECT * FROM reports WHERE id = ' . $id);\n"
        "}\n"
    )

    coverage, _, _ = build_coverage_artifact(tmp_path)

    assert not any(item.type == "persistent_sql_operand" for item in coverage.items)


def test_recon_grep_tracks_execution_archive_upload_and_persistent_surfaces():
    shell = re.compile(RIPGREP_PATTERNS["shell_exec"])
    dynamic = re.compile(RIPGREP_PATTERNS["dynamic_callables"])
    wrapper = re.compile(RIPGREP_PATTERNS["command_wrappers"])
    archive = re.compile(RIPGREP_PATTERNS["archive_extract"])
    upload_policy = re.compile(RIPGREP_PATTERNS["upload_policy"])
    persistent = re.compile(RIPGREP_PATTERNS["persistent_reads"])
    writes = re.compile(RIPGREP_PATTERNS["file_put_contents"])

    assert shell.search("pcntl_exec('/bin/sh', $args)")
    assert shell.search(" expect_popen($command)")
    assert not shell.search("$runner->exec($command)")
    assert not shell.search("Runner::exec($command)")
    assert dynamic.search("call_user_func_array($callback, $arguments)")
    assert wrapper.search("new Symfony\\Component\\Process\\Process($arguments)")
    assert wrapper.search("WP_CLI::launch($command)")
    assert archive.search("new PclZip($archive)")
    assert archive.search("unzip_file($archive, $destination)")
    assert archive.search("$archive->extract(PCLZIP_OPT_PATH, $destination)")
    assert upload_policy.search("add_filter('upload_mimes', $callback)")
    assert persistent.search("get_post_meta($post_id, 'column', true)")
    assert writes.search("stream_copy_to_stream($source, $destination)")
    assert writes.search("$wp_filesystem->move($source, $destination)")


def test_recon_php_execution_navigation_excludes_javascript_and_caps_noise():
    included = {"plugin.php", "build/app.js"}
    mixed_backticks = [
        "plugin.php:10:$value = `id`;",
        "build/app.js:20:const value = `template`;",
    ]

    assert _filter_included("php_backticks", mixed_backticks, included) == [
        "plugin.php:10:$value = `id`;"
    ]
    persistent_hits = [
        f"plugin.php:{index}:get_option('value_{index}')" for index in range(1, 2_010)
    ]
    assert len(_filter_included("persistent_reads", persistent_hits, included)) == 2_000
