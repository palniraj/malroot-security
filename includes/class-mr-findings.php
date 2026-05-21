<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Lightweight data layer for findings.
 */
class MR_Findings {

	public static function table() {
		global $wpdb;
		return $wpdb->prefix . 'malroot_findings';
	}

	public static function record( array $finding ) {
		global $wpdb;
		$defaults = [
			'scan_id'  => 0,
			'module'   => '',
			'rule_id'  => '',
			'severity' => 'info',
			'target'   => '',
			'summary'  => '',
			'details'  => '',
			'status'   => 'open',
		];
		$row = wp_parse_args( $finding, $defaults );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->insert(
			self::table(),
			$row,
			[ '%d', '%s', '%s', '%s', '%s', '%s', '%s', '%s' ]
		);
		return $wpdb->insert_id;
	}

	public static function get_open( $limit = 200 ) {
		global $wpdb;
		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
		return $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT * FROM {$table} WHERE status = 'open' ORDER BY FIELD(severity,'critical','high','medium','low','info'), id DESC LIMIT %d",
				$limit
			)
		);
	}

	public static function get_by_scan( $scan_id ) {
		global $wpdb;
		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
		return $wpdb->get_results(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"SELECT * FROM {$table} WHERE scan_id = %d ORDER BY FIELD(severity,'critical','high','medium','low','info'), id DESC",
				$scan_id
			)
		);
	}

	public static function counts_by_severity( $scan_id = 0 ) {
		global $wpdb;
		$table  = self::table();
		$where  = $scan_id ? $wpdb->prepare( 'WHERE scan_id = %d', $scan_id ) : "WHERE status='open'";
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
		$rows   = $wpdb->get_results( "SELECT severity, COUNT(*) AS c FROM {$table} {$where} GROUP BY severity" );
		$counts = [ 'critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0 ];
		foreach ( $rows as $r ) {
			$counts[ $r->severity ] = (int) $r->c;
		}
		return $counts;
	}

	public static function security_score( $scan_id = 0 ) {
		$c = self::counts_by_severity( $scan_id );
		$score = 100;
		$score -= $c['critical'] * 20;
		$score -= $c['high']     * 10;
		$score -= $c['medium']   * 5;
		$score -= $c['low']      * 2;
		return max( 0, $score );
	}
}
