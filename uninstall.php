<?php
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}
global $wpdb;
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}malroot_findings" );
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}malroot_quarantine" );
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}malroot_connections" );
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}malroot_alerts" );
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}malroot_logins" );
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}malroot_baseline" );

delete_option( 'malroot_admin_whitelist' );
delete_option( 'malroot_muplugin_allowlist' );
delete_option( 'malroot_last_scan' );
delete_option( 'malroot_settings' );
delete_option( 'malroot_blocked_email_domains' );
delete_option( 'malroot_baseline_built' );
delete_option( 'malroot_locked_ips' );

wp_clear_scheduled_hook( 'malroot_daily_scan' );
