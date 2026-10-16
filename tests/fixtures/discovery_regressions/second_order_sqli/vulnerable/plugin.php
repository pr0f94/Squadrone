<?php
/* Synthetic regression fixture. This is not third-party plugin source. */

add_action('wp_ajax_nopriv_store_sort', 'store_sort');
add_action('wp_ajax_nopriv_list_records', 'list_records');

function store_sort() {
    update_option('demo_sort', $_POST['sort']);
}

function list_records() {
    global $wpdb;
    $stored_sort = get_option('demo_sort');
    $query = "SELECT id, title FROM {$wpdb->posts} ORDER BY " . $stored_sort;
    return $wpdb->get_results($query);
}
