<?php
/* Synthetic negative control. This is not third-party plugin source. */

add_action('wp_ajax_nopriv_render_upload_help', 'render_upload_help');

function render_upload_help() {
    // move_uploaded_file($_FILES['package']['tmp_name'], '/tmp/package.php');
    $example = "wp_handle_upload($_FILES['package'], ['test_form' => false])";
    $policy_example = "add_filter('upload_mimes', 'allow_everything')";
    return esc_html($example . $policy_example);
}
