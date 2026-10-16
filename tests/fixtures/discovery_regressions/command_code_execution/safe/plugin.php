<?php
/* Synthetic negative control. This is not third-party plugin source. */

add_action('wp_ajax_nopriv_render_diagnostic_help', 'render_diagnostic_help');

function render_diagnostic_help() {
    // system($_POST['host']);
    $example = "shell_exec($_POST['command'])";
    $runner = new Diagnostic_Runner();
    $documentation = <<<TEXT
system($_POST['heredoc']); eval($_POST['heredoc']);
TEXT;
    return $runner->exec(['ping', '-c', '1', '127.0.0.1']) . $example;
}

class Diagnostic_Runner {
    public function exec(array $arguments) {
        return implode(' ', $arguments);
    }
}
