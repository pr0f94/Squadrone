<?php
/* Synthetic prepared-query control. This is not third-party plugin source. */

add_action('wp_ajax_nopriv_store_record_id', 'store_record_id');
add_action('wp_ajax_nopriv_read_record', 'read_record');

function store_record_id() {
    update_option('demo_record_id', absint($_POST['record_id']));
}

function read_record() {
    global $wpdb;
    $stored_id = get_option('demo_record_id');
    $query = $wpdb->prepare(
        "SELECT id, title FROM {$wpdb->posts} WHERE id = %d",
        $stored_id
    );
    return $wpdb->get_results($query);
}
