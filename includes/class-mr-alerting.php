<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Alerting: store every alert in DB, send to email + Slack.
 *
 * Critical alerts go out instantly. Lower severities are batched into a
 * daily digest (handled by the scheduled scan path).
 */
class MR_Alerting {

	public static function table() {
		global $wpdb;
		return $wpdb->prefix . 'malroot_alerts';
	}

	/**
	 * Record + dispatch a single alert.
	 */
	public static function alert( $severity, $event_type, $summary, array $context = [] ) {
		global $wpdb;

		// Deduplicate: if we sent the same alert in the last 24h, only record (don't dispatch)
		$dedup_window = 24 * HOUR_IN_SECONDS;
		$since        = gmdate( 'Y-m-d H:i:s', time() - $dedup_window );
		$recent       = $wpdb->get_var( $wpdb->prepare(
			"SELECT COUNT(*) FROM " . self::table() . "
			 WHERE event_type = %s AND summary = %s AND created_at > %s",
			$event_type, $summary, $since
		) );

		$wpdb->insert(
			self::table(),
			[
				'event_type' => $event_type,
				'severity'   => $severity,
				'summary'    => $summary,
				'context'    => wp_json_encode( $context ),
				'created_at' => current_time( 'mysql' ),
			],
			[ '%s', '%s', '%s', '%s', '%s' ]
		);
		MR_Logger::warning( 'Alert: ' . $summary, $context );

		// Critical and HIGH alerts dispatch immediately, but only if not a duplicate
		if ( in_array( $severity, [ 'critical', 'high' ], true ) && (int) $recent === 0 ) {
			self::dispatch( $severity, $event_type, $summary, $context );
		}
	}

	/**
	 * Send digest after a scan completes.
	 */
	public static function alert_after_scan( $scan_id ) {
		$counts = MR_Findings::counts_by_severity( $scan_id );
		$bad    = $counts['critical'] + $counts['high'];
		if ( $bad === 0 ) {
			return;
		}

		// Build a fingerprint of the current findings so we can compare to last scan
		$findings = MR_Findings::get_by_scan( $scan_id );
		$fingerprint_parts = [];
		foreach ( $findings as $f ) {
			if ( in_array( $f->severity, [ 'critical', 'high' ], true ) && $f->status === 'open' ) {
				$fingerprint_parts[] = $f->rule_id . '|' . $f->target;
			}
		}
		sort( $fingerprint_parts );
		$fingerprint = md5( implode( "\n", $fingerprint_parts ) );

		// If nothing changed since the last alert, skip the email
		$last_fingerprint = get_option( 'malroot_last_alert_fingerprint', '' );
		if ( $fingerprint === $last_fingerprint ) {
			return;
		}
		update_option( 'malroot_last_alert_fingerprint', $fingerprint, false );

		$score   = MR_Findings::security_score( $scan_id );
		$summary = sprintf(
			__( 'Scan complete on %s — %d critical, %d high. Score %d/100.', 'malroot-security' ),
			parse_url( home_url(), PHP_URL_HOST ),
			$counts['critical'],
			$counts['high'],
			$score
		);

		$top = array_slice(
			array_filter( $findings, function( $f ) {
				return in_array( $f->severity, [ 'critical', 'high' ], true );
			} ),
			0, 10
		);

		self::dispatch(
			$counts['critical'] > 0 ? 'critical' : 'high',
			'scan_complete',
			$summary,
			[ 'top_findings' => $top, 'dashboard' => admin_url( 'admin.php?page=malroot-security' ) ]
		);
	}

	/**
	 * Send a test email to confirm delivery is working.
	 * Returns true on success, WP_Error on failure.
	 */
	public static function send_test_email( $to ) {
		$site    = parse_url( home_url(), PHP_URL_HOST );
		$subject = sprintf( '[Malroot TEST] Email delivery check — %s', $site );
		$body    = implode( "\n", [
			'This is a test email from Malroot Security.',
			'',
			'If you received this, email alerts are working correctly.',
			'',
			'Site:    ' . home_url(),
			'Time:    ' . current_time( 'mysql' ),
			'Version: ' . MALROOT_VERSION,
			'',
			'You will receive alerts for:',
			'  - Critical findings (immediately)',
			'  - High findings (immediately)',
			'  - New scan findings (when findings change)',
			'  - 2FA failures',
			'  - Admin logins from new locations',
		] );

		$sent = wp_mail( $to, $subject, $body );
		if ( ! $sent ) {
			global $phpmailer;
			$error = isset( $phpmailer ) && $phpmailer instanceof PHPMailer\PHPMailer\PHPMailer
				? $phpmailer->ErrorInfo
				: 'wp_mail() returned false. Check your server mail configuration.';
			return new WP_Error( 'mail_failed', $error );
		}
		return true;
	}

	/* ---------------------------------------------------------------- */

	private static function dispatch( $severity, $event_type, $summary, array $context ) {
		$settings = (array) get_option( 'malroot_settings', [] );

		// Email
		$to = $settings['alert_email'] ?? get_option( 'admin_email' );
		if ( $to ) {
			$site    = parse_url( home_url(), PHP_URL_HOST );
			$subject = sprintf( '[Malroot %s] %s', strtoupper( $severity ), $site );
			$body    = self::format_email( $severity, $event_type, $summary, $context );
			wp_mail( $to, $subject, $body );
		}

		// Slack
		$webhook = $settings['slack_webhook'] ?? '';
		if ( $webhook ) {
			$payload = [
				'text' => sprintf(
					'*[Malroot %s]* %s — %s',
					strtoupper( $severity ),
					parse_url( home_url(), PHP_URL_HOST ),
					$summary
				),
			];
			wp_remote_post( $webhook, [
				'timeout'  => 5,
				'blocking' => false,
				'headers'  => [ 'Content-Type' => 'application/json' ],
				'body'     => wp_json_encode( $payload ),
			] );
		}
	}

	private static function format_email( $severity, $event_type, $summary, array $context ) {
		$lines = [];
		$lines[] = '[Malroot ' . strtoupper( $severity ) . '] ' . parse_url( home_url(), PHP_URL_HOST );
		$lines[] = '';
		$lines[] = $summary;
		$lines[] = '';
		$lines[] = 'Event:    ' . $event_type;
		$lines[] = 'Severity: ' . $severity;
		$lines[] = 'Time:     ' . current_time( 'mysql' );
		if ( ! empty( $context['top_findings'] ) ) {
			$lines[] = '';
			$lines[] = 'Top findings:';
			foreach ( $context['top_findings'] as $f ) {
				$lines[] = sprintf( '  [%s] %s — %s', strtoupper( $f->severity ), $f->rule_id, $f->summary );
				$lines[] = '         target: ' . $f->target;
			}
			unset( $context['top_findings'] );
		}
		if ( ! empty( $context ) ) {
			$lines[] = '';
			$lines[] = 'Context:';
			foreach ( $context as $k => $v ) {
				if ( is_scalar( $v ) ) {
					$lines[] = sprintf( '  %s: %s', $k, $v );
				} else {
					$lines[] = sprintf( '  %s: %s', $k, wp_json_encode( $v ) );
				}
			}
		}
		return implode( "\n", $lines );
	}
}
