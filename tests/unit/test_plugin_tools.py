"""Unit tests for plugin-scoped exploration tools (grep / glob / read)."""

from __future__ import annotations

import pytest
from pathlib import Path

from squadrone.agents.plugin_tools import PluginToolHandlers
from squadrone.agents.prompts_io import load_prompt


@pytest.fixture
def fake_plugin(tmp_path: Path) -> Path:
    """Minimal fake plugin tree exercising real-world cases:
    - PHP entry point with a sink
    - included class file
    - JS file
    - bundled vendor/ subtree that remains inspectable
    - long file for line-range slicing
    - binary-extension file that must be refused
    """
    root = tmp_path / "fake-plugin"
    root.mkdir()
    (root / "fake-plugin.php").write_text(
        "<?php\n"
        "add_action('wp_ajax_save', 'fp_save');\n"
        "function fp_save() {\n"
        "  global $wpdb;\n"
        "  $id = $_POST['id'];\n"
        '  $wpdb->query("DELETE FROM x WHERE id={$id}");\n'
        "}\n"
    )
    (root / "includes").mkdir()
    (root / "includes" / "helper.php").write_text(
        "<?php\n"
        "class FP_Helper {\n"
        "  public function save($x) {\n"
        "    file_put_contents('/tmp/y', $x);\n"
        "  }\n"
        "}\n"
    )
    (root / "assets").mkdir()
    (root / "assets" / "main.js").write_text("console.log('fp');\n")
    (root / "assets" / "minified.js").write_text(
        "x" * 70_000 + "new Function('return 1')();\n"
    )

    # Bundled vendor code remains inspectable for reachable dependency paths.
    (root / "vendor").mkdir()
    (root / "vendor" / "noise.php").write_text("<?php $wpdb->query('noise');\n")

    # Long file for slicing
    long_body = "\n".join(f"// line {i}" for i in range(1, 1001))
    (root / "long.php").write_text(f"<?php\n{long_body}\n")

    # Binary-extension — must be refused on read
    (root / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)

    return root


# ----- init guards ---------------------------------------------------------


def test_rejects_non_directory(tmp_path):
    f = tmp_path / "not-a-dir"
    f.write_text("hi")
    with pytest.raises(ValueError):
        PluginToolHandlers(plugin_root=f)


# ----- grep_plugin ---------------------------------------------------------


def test_grep_finds_sink(fake_plugin):
    h = PluginToolHandlers(plugin_root=fake_plugin)
    out = h.grep_plugin({"pattern": r"\$wpdb->query"})
    assert "fake-plugin.php" in out
    assert "DELETE FROM x" in out
    # Bundled dependencies remain inspectable when plugin code reaches them.
    assert "vendor/noise.php" in out


def test_grep_no_matches(fake_plugin):
    h = PluginToolHandlers(plugin_root=fake_plugin)
    out = h.grep_plugin({"pattern": "this_string_appears_nowhere"})
    assert "0 matches" in out


def test_grep_invalid_regex(fake_plugin):
    h = PluginToolHandlers(plugin_root=fake_plugin)
    out = h.grep_plugin({"pattern": "[unclosed"})
    assert out.startswith("[grep_plugin] invalid regex")


def test_grep_missing_pattern(fake_plugin):
    h = PluginToolHandlers(plugin_root=fake_plugin)
    out = h.grep_plugin({})
    assert "missing required" in out


def test_grep_path_glob_filters(fake_plugin):
    h = PluginToolHandlers(plugin_root=fake_plugin)
    # Restrict to includes/ — should not hit fake-plugin.php
    out = h.grep_plugin(
        {"pattern": "file_put_contents", "path_glob": "includes/**/*.php"}
    )
    assert "includes/helper.php" in out
    assert "fake-plugin.php" not in out


@pytest.mark.parametrize("path_glob", ["../**/*.php", "/etc/*.php"])
def test_grep_refuses_escaping_path_glob(fake_plugin, path_glob):
    h = PluginToolHandlers(plugin_root=fake_plugin)

    out = h.grep_plugin({"pattern": "secret", "path_glob": path_glob})

    assert "refused" in out


def test_grep_does_not_follow_external_symlinks(fake_plugin):
    outside_file = fake_plugin.parent / "outside.php"
    outside_file.write_text("<?php $external_secret = 'file-secret';\n")
    outside_dir = fake_plugin.parent / "outside-dir"
    outside_dir.mkdir()
    (outside_dir / "nested.php").write_text("<?php $external_secret = 'dir-secret';\n")
    (fake_plugin / "outside-link.php").symlink_to(outside_file)
    (fake_plugin / "outside-dir-link").symlink_to(
        outside_dir,
        target_is_directory=True,
    )
    h = PluginToolHandlers(plugin_root=fake_plugin)

    default_out = h.grep_plugin({"pattern": "external_secret"})
    direct_file_out = h.grep_plugin(
        {"pattern": "external_secret", "path_glob": "outside-link.php"}
    )
    linked_dir_out = h.grep_plugin(
        {"pattern": "external_secret", "path_glob": "outside-dir-link/**/*.php"}
    )

    assert "file-secret" not in default_out
    assert "file-secret" not in direct_file_out
    assert "dir-secret" not in linked_dir_out


def test_grep_case_insensitive(fake_plugin):
    h = PluginToolHandlers(plugin_root=fake_plugin)
    out_cs = h.grep_plugin({"pattern": "ADD_ACTION"})
    out_ci = h.grep_plugin({"pattern": "ADD_ACTION", "case_insensitive": True})
    assert "0 matches" in out_cs
    assert "fake-plugin.php" in out_ci


def test_grep_context_lines(fake_plugin):
    h = PluginToolHandlers(plugin_root=fake_plugin)
    out = h.grep_plugin({"pattern": r"file_put_contents", "context_lines": 1})
    # Context line marker present
    assert ">" in out
    # Surrounding lines included
    assert "public function save" in out


def test_grep_max_results_cap(fake_plugin):
    h = PluginToolHandlers(plugin_root=fake_plugin)
    out = h.grep_plugin({"pattern": "line", "max_results": 3})
    # Should cap at 3 hits even though many lines match
    body_lines = [line for line in out.splitlines() if line.startswith("long.php:")]
    assert len(body_lines) == 3


def test_grep_centers_long_minified_line_on_match(fake_plugin):
    h = PluginToolHandlers(plugin_root=fake_plugin)

    out = h.grep_plugin({"pattern": r"new Function\("})

    assert "assets/minified.js:1:70001:" in out
    assert "new Function('return 1')" in out
    assert len(out) < 5000


# ----- glob_plugin ---------------------------------------------------------


def test_glob_basic(fake_plugin):
    h = PluginToolHandlers(plugin_root=fake_plugin)
    out = h.glob_plugin({"pattern": "**/*.php"})
    assert "fake-plugin.php" in out
    assert "includes/helper.php" in out
    assert "vendor/noise.php" in out


def test_glob_no_matches(fake_plugin):
    h = PluginToolHandlers(plugin_root=fake_plugin)
    out = h.glob_plugin({"pattern": "**/*.nonexistent"})
    assert "0 paths match" in out


def test_glob_reports_directories(fake_plugin):
    h = PluginToolHandlers(plugin_root=fake_plugin)

    out = h.glob_plugin({"pattern": "*"})

    assert "assets/" in out
    assert "includes/" in out
    assert "fake-plugin.php" in out


def test_glob_reports_hidden_only_and_empty_directories(fake_plugin):
    hidden_only = fake_plugin / "runtime-files"
    hidden_only.mkdir()
    (hidden_only / ".gitkeep").write_text("")
    (fake_plugin / "empty-runtime-files").mkdir()
    h = PluginToolHandlers(plugin_root=fake_plugin)

    parent_out = h.glob_plugin({"pattern": "runtime-files*"})
    recursive_out = h.glob_plugin({"pattern": "runtime-files/**"})
    children_out = h.glob_plugin({"pattern": "runtime-files/*"})

    assert "runtime-files/" in parent_out
    assert "runtime-files/" in recursive_out
    assert "runtime-files/.gitkeep" in children_out
    assert "empty-runtime-files/" in h.glob_plugin({"pattern": "empty-runtime-files*"})


def test_glob_refuses_absolute(fake_plugin):
    h = PluginToolHandlers(plugin_root=fake_plugin)
    out = h.glob_plugin({"pattern": "/etc/passwd"})
    assert "refused" in out


def test_glob_refuses_traversal(fake_plugin):
    h = PluginToolHandlers(plugin_root=fake_plugin)
    out = h.glob_plugin({"pattern": "../**/*"})
    assert "refused" in out


def test_glob_omits_external_symlinks(fake_plugin):
    outside_file = fake_plugin.parent / "outside.php"
    outside_file.write_text("<?php echo 'secret';\n")
    outside_dir = fake_plugin.parent / "outside-dir"
    outside_dir.mkdir()
    (outside_dir / "nested.php").write_text("<?php echo 'nested-secret';\n")
    (fake_plugin / "outside-link.php").symlink_to(outside_file)
    (fake_plugin / "outside-dir-link").symlink_to(
        outside_dir,
        target_is_directory=True,
    )
    h = PluginToolHandlers(plugin_root=fake_plugin)

    out = h.glob_plugin({"pattern": "**/*"})
    linked_dir_out = h.glob_plugin({"pattern": "outside-dir-link/**/*.php"})

    assert "outside-link.php" not in out
    assert "outside-dir-link" not in out
    assert "nested.php" not in linked_dir_out


def test_glob_missing_pattern(fake_plugin):
    h = PluginToolHandlers(plugin_root=fake_plugin)
    assert "missing required" in h.glob_plugin({})


# ----- read_plugin_file ----------------------------------------------------


def test_read_basic(fake_plugin):
    h = PluginToolHandlers(plugin_root=fake_plugin)
    out = h.read_plugin_file({"path": "fake-plugin.php"})
    assert "add_action('wp_ajax_save'" in out
    # Header reports line count
    assert "lines 1-" in out


def test_read_line_range(fake_plugin):
    h = PluginToolHandlers(plugin_root=fake_plugin)
    out = h.read_plugin_file({"path": "long.php", "start_line": 100, "end_line": 105})
    assert "// line 99" in out  # line 100 is "// line 99" (line 1 is "<?php")
    assert "// line 104" in out
    assert "// line 200" not in out


def test_read_line_range_is_recorded_for_coverage_evidence(fake_plugin):
    h = PluginToolHandlers(plugin_root=fake_plugin)

    h.read_plugin_file({"path": "long.php", "start_line": 100, "end_line": 105})

    assert h.was_read("long.php", 100)
    assert h.was_read("long.php", 105)
    assert not h.was_read("long.php", 106)


def test_read_evidence_uses_canonical_path_and_rejects_out_of_range(fake_plugin):
    h = PluginToolHandlers(plugin_root=fake_plugin)

    output = h.read_plugin_file({"path": "./long.php", "start_line": 1999})

    assert "beyond the end" in output
    assert not h.was_read("long.php", 1999)

    h.read_plugin_file({"path": "./long.php", "start_line": 10, "end_line": 12})
    assert h.was_read("long.php", 10)


def test_minified_line_requires_reading_the_target_column(fake_plugin):
    h = PluginToolHandlers(plugin_root=fake_plugin)

    initial = h.read_plugin_file({"path": "assets/minified.js", "start_line": 1})

    assert "new Function" not in initial
    assert h.was_read("assets/minified.js", 1, 1)
    assert not h.was_read("assets/minified.js", 1, 70_005)

    window = h.read_plugin_file(
        {
            "path": "assets/minified.js",
            "start_line": 1,
            "start_column": 69_950,
            "max_chars": 200,
        }
    )

    assert "new Function('return 1')" in window
    assert h.was_read("assets/minified.js", 1, 70_005)


def test_read_max_lines_truncates(fake_plugin):
    h = PluginToolHandlers(plugin_root=fake_plugin)
    out = h.read_plugin_file({"path": "long.php", "max_lines": 10})
    assert "[truncated" in out
    assert "Re-call with start_line=" in out


def test_read_traversal_refused(fake_plugin):
    h = PluginToolHandlers(plugin_root=fake_plugin)
    out = h.read_plugin_file({"path": "../etc/passwd"})
    assert "refused" in out


@pytest.mark.parametrize("target_is_directory", [False, True])
def test_read_external_symlink_refused(fake_plugin, target_is_directory):
    if target_is_directory:
        outside = fake_plugin.parent / "outside-dir"
        outside.mkdir()
        target = outside / "secret.php"
        target.write_text("<?php echo 'dir-secret';\n")
        link = fake_plugin / "outside-link"
        link.symlink_to(outside, target_is_directory=True)
        requested_path = "outside-link/secret.php"
    else:
        target = fake_plugin.parent / "outside.php"
        target.write_text("<?php echo 'file-secret';\n")
        link = fake_plugin / "outside-link.php"
        link.symlink_to(target)
        requested_path = "outside-link.php"
    h = PluginToolHandlers(plugin_root=fake_plugin)

    out = h.read_plugin_file({"path": requested_path})

    assert "refused" in out
    assert "secret';" not in out


def test_read_not_found(fake_plugin):
    h = PluginToolHandlers(plugin_root=fake_plugin)
    out = h.read_plugin_file({"path": "does/not/exist.php"})
    assert "not found" in out


def test_read_refuses_binary_extension(fake_plugin):
    h = PluginToolHandlers(plugin_root=fake_plugin)
    out = h.read_plugin_file({"path": "logo.png"})
    assert "not a recognised text file" in out


def test_read_missing_path(fake_plugin):
    h = PluginToolHandlers(plugin_root=fake_plugin)
    assert "missing required" in h.read_plugin_file({})


# ----- read_plugin_ranges --------------------------------------------------


def test_read_ranges_returns_requested_order_and_records_exact_evidence(fake_plugin):
    h = PluginToolHandlers(plugin_root=fake_plugin)
    ranges = [
        {"path": "includes/helper.php", "start_line": 3, "end_line": 4},
        {"path": "fake-plugin.php", "start_line": 5, "end_line": 6},
    ]

    first = h.read_plugin_ranges({"ranges": ranges})
    second_handler = PluginToolHandlers(plugin_root=fake_plugin)
    second = second_handler.read_plugin_ranges({"ranges": ranges})

    assert first == second
    assert first.index("includes/helper.php") < first.index("fake-plugin.php")
    assert "file_put_contents" in first
    assert "$wpdb->query" in first
    assert h.was_read("includes/helper.php", 3)
    assert h.was_read("includes/helper.php", 4)
    assert not h.was_read("includes/helper.php", 5)
    assert h.was_read("fake-plugin.php", 5)
    assert h.was_read("fake-plugin.php", 6)


def test_read_ranges_refuses_more_than_eight_without_recording_evidence(fake_plugin):
    h = PluginToolHandlers(plugin_root=fake_plugin)
    ranges = [
        {"path": "long.php", "start_line": line, "end_line": line}
        for line in range(1, 10)
    ]

    output = h.read_plugin_ranges({"ranges": ranges})

    assert "exceeds the hard cap of 8" in output
    assert not h.was_read("long.php", 1)


def test_read_ranges_aggregate_cap_records_only_returned_columns(fake_plugin):
    h = PluginToolHandlers(plugin_root=fake_plugin)

    output = h.read_plugin_ranges(
        {
            "ranges": [
                {
                    "path": "assets/minified.js",
                    "start_line": 1,
                    "end_line": 1,
                },
                {"path": "fake-plugin.php", "start_line": 1, "end_line": 1},
            ]
        }
    )

    assert len(output.encode("utf-8")) <= 60_000
    assert "aggregate output truncated at 60000 bytes" in output
    assert h.was_read("assets/minified.js", 1, 1)
    assert not h.was_read("assets/minified.js", 1, 70_005)
    assert not h.was_read("fake-plugin.php", 1)


def test_read_ranges_continues_after_safe_per_range_errors(fake_plugin):
    outside = fake_plugin.parent / "secret.php"
    outside.write_text("<?php echo 'secret';\n")
    (fake_plugin / "secret-link.php").symlink_to(outside)
    h = PluginToolHandlers(plugin_root=fake_plugin)

    output = h.read_plugin_ranges(
        {
            "ranges": [
                {"path": "../secret.php", "start_line": 1, "end_line": 1},
                {"path": "secret-link.php", "start_line": 1, "end_line": 1},
                {"path": "long.php", "start_line": "bad", "end_line": 4},
                {"path": "includes/helper.php", "start_line": 2, "end_line": 2},
            ]
        }
    )

    assert output.count("resolves outside plugin root") == 2
    assert "`start_line` must be an integer" in output
    assert "class FP_Helper" in output
    assert "echo 'secret'" not in output
    assert h.was_read("includes/helper.php", 2)


def test_read_ranges_caps_each_range_at_500_lines(fake_plugin):
    h = PluginToolHandlers(plugin_root=fake_plugin)

    output = h.read_plugin_ranges(
        {"ranges": [{"path": "long.php", "start_line": 1, "end_line": 800}]}
    )

    assert "range capped at 500 lines" in output
    assert "continue with start_line=501" in output
    assert h.was_read("long.php", 500)
    assert not h.was_read("long.php", 501)


@pytest.mark.parametrize(
    "args",
    [
        {},
        {"ranges": []},
        {"ranges": "not-an-array"},
        {"ranges": [None]},
        {"ranges": [{"path": "long.php", "start_line": 1}]},
    ],
)
def test_read_ranges_handles_malformed_arguments_without_raising(fake_plugin, args):
    output = PluginToolHandlers(plugin_root=fake_plugin).read_plugin_ranges(args)

    assert output.startswith("[read_plugin_ranges]")


# ----- public wiring -------------------------------------------------------


def test_tool_definitions_shape(fake_plugin):
    h = PluginToolHandlers(plugin_root=fake_plugin)
    defs = h.tool_definitions()
    names = [d["function"]["name"] for d in defs]
    assert names == [
        "grep_plugin",
        "glob_plugin",
        "read_plugin_file",
        "read_plugin_ranges",
    ]
    ranges_schema = defs[-1]["function"]["parameters"]["properties"]["ranges"]
    assert ranges_schema["maxItems"] == 8


@pytest.mark.parametrize(
    "reviewer",
    ["injection_files", "xss_lifecycle", "authentication"],
)
def test_focused_specialists_prefer_multi_range_reads(reviewer):
    prompt = load_prompt(f"specialists/{reviewer}")

    assert "prefer one `read_plugin_ranges` call" in prompt


def test_tool_handlers_callable(fake_plugin):
    h = PluginToolHandlers(plugin_root=fake_plugin)
    handlers = h.tool_handlers()
    assert set(handlers.keys()) == {
        "grep_plugin",
        "glob_plugin",
        "read_plugin_file",
        "read_plugin_ranges",
    }
    # Each handler accepts a dict and returns a string
    for name, fn in handlers.items():
        out = fn({})
        assert isinstance(out, str)
