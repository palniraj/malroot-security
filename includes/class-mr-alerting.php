<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Alerting: store every alert in DB, send to email + Slack.
 *
 * Critical alerts go out instantly. Lower severities are batched into a
 * daily digest (handled by the scheduled scan path).
 */
class Malroot_Alerting {

	public static function table() {
		global $wpdb;
		return $wpdb->prefix . 'malroot_alerts';
	}

	/* ---------------------------------------------------------------- */
	/*  Alert preferences (Settings → Alerting)                         */
	/* ---------------------------------------------------------------- */

	/** Numeric rank so severities can be compared. Higher = more serious. */
	private static function severity_rank( $severity ) {
		$map = [ 'info' => 0, 'low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4 ];
		return $map[ strtolower( (string) $severity ) ] ?? 0;
	}

	/**
	 * Lowest severity the operator wants emailed/sent.
	 * 'critical' | 'high' (default) | 'medium'
	 */
	private static function min_dispatch_severity() {
		$s   = (array) get_option( 'malroot_settings', [] );
		$val = isset( $s['alert_min_severity'] ) ? (string) $s['alert_min_severity'] : 'high';
		return in_array( $val, [ 'critical', 'high', 'medium' ], true ) ? $val : 'high';
	}

	/**
	 * Whether a given event type is allowed to notify at all. Lets the operator
	 * silence noisy, low-value events (e.g. routine admin logins) without
	 * turning off genuine security alerts.
	 */
	private static function event_notifications_enabled( $event_type ) {
		$s = (array) get_option( 'malroot_settings', [] );

		// Routine login-activity events: off by default. These are informational,
		// not signs of compromise, and were the main source of alert fatigue.
		$login_events = [ 'admin_login_new_origin', 'login_lockout' ];
		if ( in_array( $event_type, $login_events, true ) ) {
			return ! empty( $s['alert_login_activity'] );
		}
		return true;
	}

	/**
	 * Should this alert be dispatched (emailed/Slacked)? Combines the severity
	 * floor with the per-event toggle. Recording to the Alerts log is unaffected.
	 */
	private static function should_dispatch( $severity, $event_type ) {
		if ( ! self::event_notifications_enabled( $event_type ) ) {
			return false;
		}
		return self::severity_rank( $severity ) >= self::severity_rank( self::min_dispatch_severity() );
	}

	/**
	 * Record + dispatch a single alert.
	 */
	public static function alert( $severity, $event_type, $summary, array $context = [] ) {
		global $wpdb;

		// Deduplicate: if we sent the same alert in the last 24h, only record (don't dispatch)
		$dedup_window = 24 * HOUR_IN_SECONDS;
		$since        = gmdate( 'Y-m-d H:i:s', time() - $dedup_window );
		$table        = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
		$recent       = $wpdb->get_var( $wpdb->prepare(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			"SELECT COUNT(*) FROM {$table}
			 WHERE event_type = %s AND summary = %s AND created_at > %s",
			$event_type, $summary, $since
		) );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
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
		Malroot_Logger::warning( 'Alert: ' . $summary, $context );

		// Dispatch only if the alert clears the operator's severity floor, the
		// event type is enabled, and it isn't a duplicate of a recent alert.
		if ( self::should_dispatch( $severity, $event_type ) && (int) $recent === 0 ) {
			self::dispatch( $severity, $event_type, $summary, $context );
		}
	}

	/**
	 * Send digest after a scan completes.
	 */
	public static function alert_after_scan( $scan_id ) {
		$counts = Malroot_Findings::counts_by_severity( $scan_id );

		// Respect the operator's severity floor for the scan digest too. If they
		// only want critical alerts, a high-only scan should stay quiet.
		if ( self::min_dispatch_severity() === 'critical' ) {
			$bad = $counts['critical'];
		} else {
			$bad = $counts['critical'] + $counts['high'];
		}
		if ( $bad === 0 ) {
			return;
		}

		// Build a fingerprint of the current findings so we can compare to last scan
		$findings = Malroot_Findings::get_by_scan( $scan_id );
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

		$score   = Malroot_Findings::security_score( $scan_id );
		$summary = sprintf(
			/* translators: 1: site name, 2: number of urgent issues, 3: number of important issues */
			__( 'A security check just finished on %1$s. It found %2$d urgent and %3$d important issue(s) that need a look.', 'malroot-security' ),
			wp_parse_url( home_url(), PHP_URL_HOST ),
			$counts['critical'],
			$counts['high']
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
			[
				'top_findings' => $top,
				'score'        => $score,
				'dashboard'    => admin_url( 'admin.php?page=malroot-security' ),
			]
		);
	}

	/**
	 * Send a test email to confirm delivery is working.
	 * Returns true on success, WP_Error on failure.
	 */
	public static function send_test_email( $to ) {
		$site    = wp_parse_url( home_url(), PHP_URL_HOST );
		$subject = sprintf( '[Malroot TEST] Email delivery check — %s', $site );
		$min   = self::min_dispatch_severity();
		$level = 'critical' === $min
			? __( 'urgent issues only', 'malroot-security' )
			: ( 'medium' === $min
				? __( 'urgent, important and medium issues', 'malroot-security' )
				: __( 'urgent and important issues', 'malroot-security' ) );
		$login = ! empty( ( (array) get_option( 'malroot_settings', [] ) )['alert_login_activity'] )
			? __( 'on', 'malroot-security' )
			: __( 'off', 'malroot-security' );

		$body = implode( "\n", [
			__( 'This is a test email from Malroot Security.', 'malroot-security' ),
			'',
			__( 'If you received this, email alerts are working correctly.', 'malroot-security' ),
			'',
			/* translators: %s: the website URL */
			sprintf( __( 'Website: %s', 'malroot-security' ), home_url() ),
			/* translators: %s: current date and time */
			sprintf( __( 'Time: %s', 'malroot-security' ), current_time( 'mysql' ) ),
			'',
			/* translators: %s: which severities are emailed (e.g. "urgent and important issues") */
			sprintf( __( 'With your current settings you will be emailed about: %s.', 'malroot-security' ), $level ),
			/* translators: %s: "on" or "off" */
			sprintf( __( 'Routine login-activity notifications are: %s.', 'malroot-security' ), $login ),
			'',
			__( 'You can change what you get notified about under Malroot → Settings → Alerting.', 'malroot-security' ),
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
			$site    = wp_parse_url( home_url(), PHP_URL_HOST );
			$prefix  = 'critical' === strtolower( $severity )
				? __( 'Urgent security alert', 'malroot-security' )
				: __( 'Security alert', 'malroot-security' );
			$subject = sprintf( '%s — %s', $prefix, $site );
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
					wp_parse_url( home_url(), PHP_URL_HOST ),
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

	/**
	 * Build a plain-language email a non-technical site owner can understand.
	 * Technical detail (rule IDs, targets, raw context) is intentionally left
	 * out of the email; it's all available on the dashboard for developers.
	 */
	private static function format_email( $severity, $event_type, $summary, array $context ) {
		$site      = wp_parse_url( home_url(), PHP_URL_HOST );
		$dashboard = $context['dashboard'] ?? admin_url( 'admin.php?page=malroot-security' );

		$headline = self::severity_headline( $severity );

		$lines   = [];
		$lines[] = $headline;
		$lines[] = str_repeat( '=', strlen( $headline ) );
		$lines[] = '';
		/* translators: %s: the website URL */
		$lines[] = sprintf( __( 'Website: %s', 'malroot-security' ), $site );
		$lines[] = '';
		$lines[] = $summary;

		if ( isset( $context['score'] ) ) {
			$lines[] = '';
			$lines[] = sprintf(
				/* translators: %d: security score out of 100 */
				__( 'Current safety score: %d out of 100.', 'malroot-security' ),
				(int) $context['score']
			);
		}

		// Turn each finding into a plain "what it is / what to do" block.
		if ( ! empty( $context['top_findings'] ) && class_exists( 'Malroot_Plain_Language' ) ) {
			$lines[] = '';
			$lines[] = __( "What we found", 'malroot-security' );
			$lines[] = '-------------';
			$n = 0;
			foreach ( $context['top_findings'] as $f ) {
				$n++;
				$card  = Malroot_Plain_Language::translate( $f );
				$title = isset( $card['title'] ) ? wp_strip_all_tags( $card['title'] ) : $f->summary;
				$what  = isset( $card['what'] ) ? wp_strip_all_tags( $card['what'] ) : '';
				$do    = isset( $card['action'] ) ? wp_strip_all_tags( $card['action'] ) : '';

				$lines[] = '';
				$lines[] = sprintf( '%d) %s', $n, $title );
				if ( $what ) {
					$lines[] = '   ' . $what;
				}
				if ( $do ) {
					$lines[] = '   ' . __( 'What to do:', 'malroot-security' ) . ' ' . $do;
				}
			}
		} elseif ( ! empty( $context['top_findings'] ) ) {
			$lines[] = '';
			foreach ( $context['top_findings'] as $f ) {
				$lines[] = '- ' . $f->summary;
			}
		}

		$lines[] = '';
		$lines[] = __( 'Open your security dashboard to review and fix these:', 'malroot-security' );
		$lines[] = $dashboard;
		$lines[] = '';
		$lines[] = __( 'This is an automated message from Malroot Security.', 'malroot-security' );

		return implode( "\n", $lines );
	}

	/** Friendly, non-alarming subject-line-style headline per severity. */
	private static function severity_headline( $severity ) {
		switch ( strtolower( $severity ) ) {
			case 'critical':
				return __( 'Urgent: your website needs attention', 'malroot-security' );
			case 'high':
				return __( 'Important: please review your website security', 'malroot-security' );
			case 'medium':
				return __( 'Heads up: a security item to review', 'malroot-security' );
			default:
				return __( 'Website security update', 'malroot-security' );
		}
	}
}
