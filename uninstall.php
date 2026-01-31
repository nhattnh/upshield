<?php
/**
 * Fired when the plugin is uninstalled.
 */

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

global $wpdb;

// Delete options
delete_option('upshield_options');
delete_option('upshield_waf_settings');
delete_option('upshield_db_version');
delete_option('upshield_wizard_completed');
delete_option('upshield_activated_time');

// Delete transients
delete_transient('upshield_threat_intel_cache');
delete_transient('upshield_stats_cache');

// Drop custom tables
$tables = [
    $wpdb->prefix . 'upshield_traffic_log',
    $wpdb->prefix . 'upshield_blocked_ips',
    $wpdb->prefix . 'upshield_whitelist',
    $wpdb->prefix . 'upshield_blacklist',
    $wpdb->prefix . 'upshield_temp_blocks',
    $wpdb->prefix . 'upshield_stats',
    $wpdb->prefix . 'upshield_scan_results',
];

foreach ($tables as $table) {
    $wpdb->query("DROP TABLE IF EXISTS {$table}");
}

// Clear scheduled hooks
wp_clear_scheduled_hook('upshield_file_scan_event');
wp_clear_scheduled_hook('upshield_malware_scan_event');
wp_clear_scheduled_hook('upshield_threat_intel_sync');
wp_clear_scheduled_hook('upshield_cleanup_logs');
wp_clear_scheduled_hook('upshield_aggregate_stats');

// Remove early blocker file if exists
$mu_plugin_file = WPMU_PLUGIN_DIR . '/upshield-early-blocker.php';
if (file_exists($mu_plugin_file)) {
    @unlink($mu_plugin_file);
}
