<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * One-click incident response.
 *
 * Replays the manual cleanup we did on allfirstnations.com.au:
 *   1. DROP TRIGGER after_insert_comment (any malicious INSERT-into-users trigger)
 *   2. Delete users matching known malware login names
 *   3. Delete sc_* options + transients
 *   4. Remove _sc_bot_only / _sc_bot_type postmeta
 *   5. Clear all session_tokens (force re-login)
 *   6. Detect system-control in active_plugins (reported only — never auto-deactivated)
 *
 * Returns a structured report.
 *
 * Every step calls the quarantine layer, so each removal is reversible.
 */
class Malroot_Incident_Response {

	public static function run( $confirm_token ) {
		if ( $confirm_token !== self::token() ) {
			return new WP_Error( 'bad_token', __( 'Confirmation token mismatch.', 'malroot-security' ) );
		}

		$report = [
			'steps' => [],
			'started_at' => current_time( 'mysql' ),
		];

		$report['steps']['triggers']  = self::drop_admin_injection_triggers();
		$report['steps']['users']     = self::remove_known_bad_users();
		$report['steps']['options']   = self::remove_sc_options();
		$report['steps']['postmeta']  = self::remove_sc_postmeta();
		$report['steps']['sessions']  = self::clear_sessions();
		$report['steps']['plugins']   = self::detect_system_control_active_plugin();

		$report['finished_at'] = current_time( 'mysql' );

		Malroot_Alerting::alert(
			'high',
			'incident_response_run',
			'One-click incident response executed',
			$report
		);
		Malroot_Logger::info( 'Incident response complete', $report );

		return $report;
	}

	public static function token() {
		// Daily-rotating token to prevent CSRF-replay via a stale link
		return wp_hash( 'malroot_ir_' . gmdate( 'Y-m-d' ) );
	}

	/* ---------------------------------------------------------------- */

	private static function drop_admin_injection_triggers() {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows = $wpdb->get_results( $wpdb->prepare(
			"SELECT TRIGGER_NAME, ACTION_STATEMENT FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = %s",
			$wpdb->dbname
		) );
		$dropped = [];
		foreach ( (array) $rows as $t ) {
			$body = (string) $t->ACTION_STATEMENT;
			$looks_bad =
				   preg_match( '/INSERT\s+INTO\s+`?[^`\s]*_users`?/i', $body )
				|| preg_match( '/INSERT\s+INTO\s+`?[^`\s]*_usermeta`?/i', $body )
				|| preg_match( '/(administrator|wp_capabilities|wp_user_level)/i', $body );
			if ( ! $looks_bad ) continue;
			$result = Malroot_Quarantine::quarantine_finding(
				self::synthesise_trigger_finding( $t->TRIGGER_NAME )
			);
			$dropped[] = [
				'name'   => $t->TRIGGER_NAME,
				'result' => is_wp_error( $result ) ? $result->get_error_message() : 'dropped',
			];
		}
		return $dropped;
	}

	private static function synthesise_trigger_finding( $trigger_name ) {
		// Insert a synthetic finding row so the existing quarantine pipeline can act on it.
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->insert(
			$wpdb->prefix . 'malroot_findings',
			[
				'scan_id'  => time(),
				'module'   => 'incident-response',
				'rule_id'  => 'IR-TRIG',
				'severity' => 'critical',
				'target'   => 'trigger:' . $trigger_name,
				'summary'  => 'Auto-dropped by Incident Response',
				'details'  => '',
				'status'   => 'open',
			],
			[ '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s' ]
		);
		return (int) $wpdb->insert_id;
	}

	private static function remove_known_bad_users() {
		global $wpdb;
		$bad = [ 'newsfeed', 'system_control', 'wpadmin', 'wordpress_administrator', 'wp_admin', 'acfmain', 'defino' ];
		$removed = [];
		foreach ( $bad as $login ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$ids = $wpdb->get_col( $wpdb->prepare(
				"SELECT ID FROM {$wpdb->users} WHERE user_login = %s",
				$login
			) );
			foreach ( $ids as $id ) {
				if ( get_current_user_id() === (int) $id ) {
					$removed[] = [ 'user' => $login, 'id' => $id, 'result' => 'skipped (self)' ];
					continue;
				}
				$finding_id = self::synthesise_user_finding( $login, (int) $id );
				$result = Malroot_Quarantine::quarantine_finding( $finding_id );
				$removed[] = [
					'user'   => $login,
					'id'     => (int) $id,
					'result' => is_wp_error( $result ) ? $result->get_error_message() : 'quarantined',
				];
			}
		}
		return $removed;
	}

	private static function synthesise_user_finding( $login, $id ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->insert( $wpdb->prefix . 'malroot_findings', [
			'scan_id'  => time(),
			'module'   => 'incident-response',
			'rule_id'  => 'IR-USER',
			'severity' => 'critical',
			'target'   => "users:{$login}#{$id}",
			'summary'  => 'Auto-quarantined by Incident Response',
			'details'  => '',
			'status'   => 'open',
		], [ '%d','%s','%s','%s','%s','%s','%s','%s' ] );
		return (int) $wpdb->insert_id;
	}

	private static function remove_sc_options() {
		global $wpdb;
		$names = [ 'sc_api_key', 'sc_sec_key', 'sc_panel_url', 'sc_site_id', 'sc_is_active', 'sc_plugin_install_blocked', 'sc_display_links' ];
		$removed = [];
		foreach ( $names as $name ) {
			if ( get_option( $name, null ) !== null ) {
				$finding_id = self::synthesise_option_finding( $name );
				$res = Malroot_Quarantine::quarantine_finding( $finding_id );
				$removed[] = [ 'option' => $name, 'result' => is_wp_error( $res ) ? $res->get_error_message() : 'removed' ];
			}
		}
		// Transients
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared
		$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_sc_%' OR option_name LIKE '_transient_timeout_sc_%'" );
		$removed[] = [ 'transients' => 'sc_*', 'result' => 'cleared' ];
		return $removed;
	}

	private static function synthesise_option_finding( $option_name ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->insert( $wpdb->prefix . 'malroot_findings', [
			'scan_id'  => time(),
			'module'   => 'incident-response',
			'rule_id'  => 'IR-OPT',
			'severity' => 'critical',
			'target'   => 'options:' . $option_name,
			'summary'  => 'Auto-quarantined by Incident Response',
			'details'  => '',
			'status'   => 'open',
		], [ '%d','%s','%s','%s','%s','%s','%s','%s' ] );
		return (int) $wpdb->insert_id;
	}

	private static function remove_sc_postmeta() {
		global $wpdb;
		$keys = [ '_sc_bot_only', '_sc_bot_type' ];
		$removed = [];
		foreach ( $keys as $key ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$count = (int) $wpdb->get_var( $wpdb->prepare(
				"SELECT COUNT(*) FROM {$wpdb->postmeta} WHERE meta_key = %s", $key
			) );
			if ( $count === 0 ) continue;
			$finding_id = self::synthesise_postmeta_finding( $key );
			$res = Malroot_Quarantine::quarantine_finding( $finding_id );
			$removed[] = [ 'meta_key' => $key, 'count' => $count, 'result' => is_wp_error( $res ) ? $res->get_error_message() : 'removed' ];
		}
		return $removed;
	}

	private static function synthesise_postmeta_finding( $meta_key ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->insert( $wpdb->prefix . 'malroot_findings', [
			'scan_id'  => time(),
			'module'   => 'incident-response',
			'rule_id'  => 'IR-PM',
			'severity' => 'critical',
			'target'   => 'postmeta:' . $meta_key,
			'summary'  => 'Auto-quarantined by Incident Response',
			'details'  => '',
			'status'   => 'open',
		], [ '%d','%s','%s','%s','%s','%s','%s','%s' ] );
		return (int) $wpdb->insert_id;
	}

	private static function clear_sessions() {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->usermeta} WHERE meta_key = 'session_tokens'" );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->delete( $wpdb->usermeta, [ 'meta_key' => 'session_tokens' ], [ '%s' ] );
		return [ 'rows_cleared' => $count, 'note' => 'all users will need to re-login' ];
	}

	/**
	 * Detect (but do NOT deactivate) any system-control plugin in active_plugins.
	 *
	 * Per WordPress.org guidelines, a plugin must not change the activation
	 * status of other plugins — that is the user's decision. We only report
	 * what we found so the administrator can deactivate and delete it from
	 * the Plugins screen themselves.
	 */
	private static function detect_system_control_active_plugin() {
		$active = (array) get_option( 'active_plugins', [] );
		$found  = [];
		foreach ( $active as $slug ) {
			if ( strpos( $slug, 'system-control' ) !== false ) {
				$found[] = [
					'plugin' => $slug,
					'result' => 'detected — deactivate it manually from the Plugins screen',
				];
			}
		}
		return $found;
	}
}
