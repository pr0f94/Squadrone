from __future__ import annotations

from squadrone.schemas import EntryPoint, ReconArtifact, Sink
from squadrone.schemas.hypothesis import BugClass
from squadrone.services.wp_leads import generate_wp_leads


def test_generate_wp_leads_finds_missing_cap_state_change(tmp_path):
    plugin = tmp_path / "demo"
    plugin.mkdir()
    (plugin / "demo.php").write_text(
        "<?php\n"
        "add_action('wp_ajax_demo_save', 'demo_save');\n"
        "function demo_save() {\n"
        "  update_option('demo_flag', $_POST['flag']);\n"
        "}\n"
    )
    recon = ReconArtifact(
        plugin_slug="demo",
        entry_points=[
            EntryPoint(
                type="ajax_priv",
                name="wp_ajax_demo_save",
                file="demo.php",
                line=2,
                handler_function="demo_save",
                requires_auth=True,
                has_nonce_check=True,
                has_capability_check=False,
            )
        ],
        sinks=[
            Sink(
                type="state_change",
                function="update_option",
                file="demo.php",
                line=4,
                tainted_args=["$_POST['flag']"],
            )
        ],
        entry_to_sink_paths={"wp_ajax_demo_save": ["demo.php:2 -> demo.php:4"]},
        raw_grep_hits={},
    )

    leads = generate_wp_leads(recon, str(plugin))

    assert len(leads) == 1
    assert leads[0].specialist == "deterministic_wp_lead"
    assert leads[0].bug_class == BugClass.MISSING_CAP_CHECK
    assert leads[0].sink_code == "update_option('demo_flag', $_POST['flag']);"
    assert leads[0].evidence_summary["pre_verification_lead"] is True


def test_generate_wp_leads_skips_non_security_sink(tmp_path):
    plugin = tmp_path / "demo"
    plugin.mkdir()
    (plugin / "demo.php").write_text("<?php\nfunction demo() { esc_html($_GET['x']); }\n")
    recon = ReconArtifact(
        plugin_slug="demo",
        entry_points=[
            EntryPoint(
                type="ajax_priv",
                name="wp_ajax_demo",
                file="demo.php",
                line=2,
                handler_function="demo",
                requires_auth=True,
                has_nonce_check=True,
                has_capability_check=False,
            )
        ],
        sinks=[
            Sink(
                type="escape",
                function="esc_html",
                file="demo.php",
                line=2,
                tainted_args=["$_GET['x']"],
            )
        ],
        entry_to_sink_paths={"wp_ajax_demo": ["demo.php:2"]},
        raw_grep_hits={},
    )

    assert generate_wp_leads(recon, str(plugin)) == []
