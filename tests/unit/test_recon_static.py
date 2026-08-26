from __future__ import annotations

from pathlib import Path

from squadrone.services import recon_helpers


def test_extract_static_callbacks_and_edges(tmp_path: Path):
    plugin = tmp_path / "plugin"
    plugin.mkdir()
    (plugin / "plugin.php").write_text(
        "<?php\n"
        "add_action('wp_ajax_demo_save', [$this, 'save_demo']);\n"
        "add_action('wp_ajax_nopriv_public_ping', 'public_ping');\n"
        "add_shortcode('demo', 'render_demo');\n"
        "register_rest_route('demo/v1', '/thing', array('methods' => 'POST', 'callback' => array($this, 'rest_thing')));\n"
        "function public_ping() { helper_call(); }\n"
        "function render_demo() { return helper_call(); }\n"
        "function helper_call() { return 'ok'; }\n"
    )

    callbacks = recon_helpers.extract_static_callbacks(plugin)
    names = {c["name"]: c for c in callbacks}

    assert names["wp_ajax_demo_save"]["type"] == "ajax_priv"
    assert names["wp_ajax_demo_save"]["handler_function"] == "save_demo"
    assert names["wp_ajax_nopriv_public_ping"]["type"] == "ajax_nopriv"
    assert names["wp_ajax_nopriv_public_ping"]["handler_function"] == "public_ping"
    assert names["demo"]["type"] == "shortcode"
    assert any(c["type"] == "rest_route" and c["handler_function"] == "rest_thing" for c in callbacks)

    edges = recon_helpers.trace_static_call_edges(plugin, callbacks)
    assert any(e["caller"] == "public_ping" and e["callee"] == "helper_call" for e in edges)


def test_static_edges_follow_helpers_and_keep_ambiguous_method_definitions(tmp_path: Path):
    plugin = tmp_path / "plugin"
    plugin.mkdir()
    (plugin / "api.php").write_text(
        "<?php\n"
        "class Demo_API {\n"
        "  public function register() {\n"
        "    register_rest_route('demo/v1', '/upload', [\n"
        "      'methods' => 'POST',\n"
        "      'callback' => [$this, 'rest_upload'],\n"
        "    ]);\n"
        "  }\n"
        "\n"
        "  public function rest_upload() {\n"
        "    return $this->prepare_upload();\n"
        "  }\n"
        "\n"
        "  private function prepare_upload() {\n"
        "    return $this->files->upload_file('/tmp/input');\n"
        "  }\n"
        "}\n"
    )
    (plugin / "files-a.php").write_text(
        "<?php\nclass Files_A {\n  public function upload_file($path) { return $path; }\n}\n"
    )
    (plugin / "files-b.php").write_text(
        "<?php\nclass Files_B {\n  public function upload_file($path) { copy($path, '/tmp/out'); }\n}\n"
    )

    callbacks = recon_helpers.extract_static_callbacks(plugin)
    edges = recon_helpers.trace_static_call_edges(plugin, callbacks)

    assert any(
        edge["caller"] == "rest_upload"
        and edge["callee"] == "prepare_upload"
        and edge["callee_file"] == "api.php"
        for edge in edges
    )
    upload_definitions = {
        edge["callee_file"]
        for edge in edges
        if edge["caller"] == "prepare_upload" and edge["callee"] == "upload_file"
    }
    assert upload_definitions == {"files-a.php", "files-b.php"}
