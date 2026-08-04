<?php
/**
 * Plugin bootstrapper. Creates DB tables on activation and wires admin pages.
 */
if ( ! defined( 'ABSPATH' ) ) { exit; }

class Malroot_Loader {

	public static function activate() {
		global $wpdb;
		$charset_collate = $wpdb->get_charset_collate();
		$findings_table  = $wpdb->prefix . 'malroot_findings';

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		dbDelta( "CREATE TABLE {$findings_table} (
			id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
			scan_id BIGINT UNSIGNED NOT NULL,
			module VARCHAR(40) NOT NULL,
			rule_id VARCHAR(20) NOT NULL,
			severity ENUM('info','low','medium','high','critical') NOT NULL,
			target VARCHAR(500) NOT NULL,
			summary TEXT NOT NULL,
			details LONGTEXT,
			status ENUM('open','acknowledged','fixed','ignored') NOT NULL DEFAULT 'open',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			KEY idx_scan (scan_id),
			KEY idx_severity (severity),
			KEY idx_status (status)
		) {$charset_collate};" );

		$quarantine_table = $wpdb->prefix . 'malroot_quarantine';
		dbDelta( "CREATE TABLE {$quarantine_table} (
			id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
			item_type VARCHAR(20) NOT NULL,
			target VARCHAR(500) NOT NULL,
			payload_json LONGTEXT NOT NULL,
			status ENUM('quarantined','restored') NOT NULL DEFAULT 'quarantined',
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			KEY idx_type (item_type),
			KEY idx_status (status)
		) {$charset_collate};" );

		$conn_table = $wpdb->prefix . 'malroot_connections';
		dbDelta( "CREATE TABLE {$conn_table} (
			id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
			domain VARCHAR(255) NOT NULL,
			url TEXT NOT NULL,
			method VARCHAR(10) NOT NULL DEFAULT 'GET',
			caller VARCHAR(500),
			first_seen DATETIME NOT NULL,
			last_seen DATETIME NOT NULL,
			hit_count INT UNSIGNED NOT NULL DEFAULT 1,
			KEY idx_domain (domain),
			KEY idx_last (last_seen)
		) {$charset_collate};" );

		$alert_table = $wpdb->prefix . 'malroot_alerts';
		dbDelta( "CREATE TABLE {$alert_table} (
			id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
			event_type VARCHAR(50) NOT NULL,
			severity ENUM('info','low','medium','high','critical') NOT NULL,
			summary TEXT NOT NULL,
			context LONGTEXT,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			KEY idx_severity (severity),
			KEY idx_created (created_at)
		) {$charset_collate};" );

		$logins_table = $wpdb->prefix . 'malroot_logins';
		dbDelta( "CREATE TABLE {$logins_table} (
			id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
			attempted_login VARCHAR(60) NOT NULL,
			ip VARCHAR(45) NOT NULL,
			ua VARCHAR(500),
			success TINYINT(1) NOT NULL DEFAULT 0,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			KEY idx_ip (ip),
			KEY idx_login (attempted_login),
			KEY idx_created (created_at)
		) {$charset_collate};" );

		$baseline_table = $wpdb->prefix . 'malroot_baseline';
		dbDelta( "CREATE TABLE {$baseline_table} (
			id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
			path VARCHAR(500) NOT NULL,
			sha CHAR(32) NOT NULL,
			size BIGINT UNSIGNED NOT NULL,
			last_seen DATETIME NOT NULL,
			KEY idx_path (path(191))
		) {$charset_collate};" );

		// Default options.
		// Use a false sentinel rather than a falsy test: an allowlist that is
		// legitimately empty must not be mistaken for one that was never set,
		// or re-activating the plugin would silently clear operator settings.
		if ( false === get_option( 'malroot_admin_whitelist', false ) ) {
			update_option( 'malroot_admin_whitelist', [] );
		}
		if ( false === get_option( 'malroot_last_scan', false ) ) {
			update_option( 'malroot_last_scan', 0 );
		}
		if ( false === get_option( Malroot_Hardening::OPT, false ) ) {
			update_option( Malroot_Hardening::OPT, Malroot_Hardening::defaults() );
		}
		if ( ! get_option( 'malroot_settings' ) ) {
			update_option( 'malroot_settings', [
				'realtime_block_admin'   => 1,
				'realtime_scan_options'  => 1,
				'auto_quarantine_critical' => 0,
				'admin_guard'              => 1,
				'admin_guard_autoremediate' => 1,
				'alert_email'            => get_option( 'admin_email' ),
				'slack_webhook'          => '',
				'scheduled_scans'        => 1,
				'monitor_outbound'       => 1,
				'geoip_enabled'          => 0,
			] );
		}

		// Build the self-integrity manifest so we can detect tampering
		Malroot_Self_Integrity::build_manifest();

		// Schedule daily scan
		if ( ! wp_next_scheduled( 'malroot_daily_scan' ) ) {
			wp_schedule_event( time() + 60, 'daily', 'malroot_daily_scan' );
		}
	}

	public static function deactivate() {
		wp_clear_scheduled_hook( 'malroot_daily_scan' );
	}

	public static function init() {
		Malroot_Realtime::register();
		Malroot_Admin_Guard::register();
		Malroot_Login_Security::register();
		Malroot_Spam_Shield::register();
		Malroot_Ajax::register();
		Malroot_Self_Integrity::register();
		Malroot_TwoFactor::register();
		Malroot_Hardening::register();

		add_action( 'malroot_daily_scan', [ __CLASS__, 'run_full_scan' ] );

		if ( is_admin() ) {
			Malroot_Admin::register();
		}
	}

	/**
	 * Run a full scan and return the scan ID.
	 */
	public static function run_full_scan() {
		$scan_id = time();
		Malroot_Logger::info( 'Starting full scan', [ 'scan_id' => $scan_id ] );

		$scanners = [
			new Malroot_Scanner_Files(),
			new Malroot_Scanner_Database(),
			new Malroot_Scanner_Users(),
			new Malroot_Scanner_Triggers(),
			new Malroot_Scanner_REST(),
			new Malroot_Scanner_MuPlugins(),
			new Malroot_Scanner_BotCloak(),
			new Malroot_Scanner_Backdoor(),
			new Malroot_Scanner_Integrity(),
		];

		foreach ( $scanners as $scanner ) {
			try {
				$scanner->set_scan_id( $scan_id );
				$scanner->run();
			} catch ( Throwable $e ) {
				Malroot_Logger::error( 'Scanner failed: ' . get_class( $scanner ), [
					'error'   => $e->getMessage(),
					'scan_id' => $scan_id,
				] );
			}
		}

		update_option( 'malroot_last_scan', $scan_id );

		// Sweep unapproved administrators. The door hooks and the per-request
		// watchdog both miss idle accounts — an injected admin that never logs in
		// is invisible to them — so the scan is where those get caught.
		if ( class_exists( 'Malroot_Admin_Guard' ) ) {
			try {
				Malroot_Admin_Guard::sweep( $scan_id );
			} catch ( Throwable $e ) {
				Malroot_Logger::error( 'Admin Guard sweep failed', [
					'error'   => $e->getMessage(),
					'scan_id' => $scan_id,
				] );
			}
		}

		// Auto-quarantine critical findings if the operator opted in
		$settings = (array) get_option( 'malroot_settings', [] );
		if ( ! empty( $settings['auto_quarantine_critical'] ) ) {
			$findings = Malroot_Findings::get_by_scan( $scan_id );
			foreach ( $findings as $f ) {
				if ( $f->severity === 'critical' && $f->status === 'open' ) {
					Malroot_Quarantine::quarantine_finding( $f->id );
				}
			}
		}

		// Alert if anything bad turned up
		Malroot_Alerting::alert_after_scan( $scan_id );

		return $scan_id;
	}
}
