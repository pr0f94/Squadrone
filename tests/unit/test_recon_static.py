from __future__ import annotations

from pathlib import Path

from wpvulnhunt.services import recon_helpers


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
