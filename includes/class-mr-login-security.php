<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Login security module.
 *
 *  - Records every successful + failed login (IP, UA, time)
 *  - Throttles failed logins per IP (default 5 attempts → 30 min lockout)
 *  - Flags logins from automated tools (curl/wget/python-requests/aiohttp)
 *  - Alerts when an admin signs in from a new country/ASN compared to history
 *
 * Stored in wp_malroot_logins. The data is the seed for our bot/abuse
 * heuristics over time.
 */
class MR_Login_Security {

	const TABLE      = 'malroot_logins';
	const LOCKED_OPT = 'malroot_locked_ips';

	private static $automated_ua_patterns = [
		'/^curl\//i',
		'/^Wget\//i',
		'/python-requests/i',
		'/python-urllib/i',
		'/aiohttp/i',
		'/Go-http-client/i',
		'/PostmanRuntime/i',
		'/HeadlessChrome/i',
		'/PhantomJS/i',
	];

	public static function table() {
		global $wpdb;
		return $wpdb->prefix . self::TABLE;
	}

	public static function register() {
		add_action( 'wp_login',          [ __CLASS__, 'on_login_ok' ],     10, 2 );
		add_action( 'wp_login_failed',   [ __CLASS__, 'on_login_failed' ] );
		add_filter( 'authenticate',      [ __CLASS__, 'enforce_lockout' ], 30, 3 );
	}

	private static function get_blocked_logins() {
		$defaults = [ 'newsfeed', 'system_control', 'system-control', 'wpadmin', 'wordpress_administrator', 'wp_admin', 'acfmain', 'defino' ];
		$custom   = (array) get_option( 'malroot_blocked_logins', [] );
		return array_unique( array_merge( $defaults, $custom ) );
	}

	private static function get_failure_threshold() {
		$s = (array) get_option( 'malroot_settings', [] );
		return (int) ( $s['login_threshold'] ?? 5 );
	}

	/* ---------------------------------------------------------------- */
	/*  Recording                                                       */
	/* ---------------------------------------------------------------- */

	public static function on_login_ok( $user_login, $user ) {
		$ip = self::ip();
		$ua = self::ua();
		self::record( $user_login, $ip, $ua, true );
		self::clear_failures_for_ip( $ip );

		// Automated-tool login is always suspicious for an admin
		if ( $user instanceof WP_User && in_array( 'administrator', (array) $user->roles, true ) ) {
			if ( self::is_automated_ua( $ua ) ) {
				MR_Alerting::alert(
					'critical',
					'admin_login_automated_ua',
					"Administrator '{$user_login}' logged in with automated user-agent",
					[ 'ip' => $ip, 'ua' => $ua ]
				);
			}

			// Geo / ASN delta check — alert when admin logs in from a new IP block
			if ( self::is_new_login_origin( $user->ID, $ip ) ) {
				$geo = MR_GeoIP::lookup( $ip );
				$location = $geo ? trim( ( $geo['city'] ? $geo['city'] . ', ' : '' ) . $geo['country_name'] ) : 'unknown location';
				MR_Alerting::alert(
					'high',
					'admin_login_new_origin',
					"Administrator '{$user_login}' logged in from a new origin: {$location}",
					[ 'ip' => $ip, 'ua' => $ua, 'user_id' => $user->ID, 'geo' => $geo ]
				);
			}
		}
	}

	public static function on_login_failed( $user_login ) {
		$ip = self::ip();
		self::record( (string) $user_login, $ip, self::ua(), false );

		$count = self::failures_in_window( $ip, 15 * MINUTE_IN_SECONDS );
		$threshold = (int) apply_filters( 'malroot_login_failure_threshold', self::get_failure_threshold() );

		if ( $count >= $threshold ) {
			self::lock_ip( $ip, 30 * MINUTE_IN_SECONDS );
			MR_Alerting::alert(
				'high',
				'login_lockout',
				"IP {$ip} locked for 30 min after {$count} failed logins",
				[ 'ip' => $ip, 'last_login' => $user_login ]
			);
		}
	}

	private static function record( $login, $ip, $ua, $success ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->insert( self::table(), [
			'attempted_login' => substr( (string) $login, 0, 60 ),
			'ip'              => substr( $ip, 0, 45 ),
			'ua'              => substr( $ua, 0, 500 ),
			'success'         => $success ? 1 : 0,
			'created_at'      => current_time( 'mysql' ),
		], [ '%s', '%s', '%s', '%d', '%s' ] );
	}

	/* ---------------------------------------------------------------- */
	/*  Lockout                                                         */
	/* ---------------------------------------------------------------- */

	public static function enforce_lockout( $user, $username, $password ) {
		if ( is_wp_error( $user ) || ! $username ) {
			$ip = self::ip();
			$locked = (array) get_option( self::LOCKED_OPT, [] );
			if ( isset( $locked[ $ip ] ) && $locked[ $ip ] > time() ) {
				return new WP_Error(
					'malroot_locked',
					sprintf(
						/* translators: %d: minutes remaining */
						__( 'Too many failed login attempts. Try again in %d minutes.', 'malroot-security' ),
						(int) ceil( ( $locked[ $ip ] - time() ) / 60 )
					)
				);
			}
		}
		return $user;
	}

	private static function failures_in_window( $ip, $seconds ) {
		global $wpdb;
		$since = gmdate( 'Y-m-d H:i:s', time() - $seconds );
		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
		return (int) $wpdb->get_var( $wpdb->prepare(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			"SELECT COUNT(*) FROM {$table} WHERE ip = %s AND success = 0 AND created_at > %s",
			$ip, $since
		) );
	}

	private static function lock_ip( $ip, $seconds ) {
		$locked         = (array) get_option( self::LOCKED_OPT, [] );
		$locked[ $ip ]  = time() + $seconds;
		// prune expired entries to keep the option small
		$locked = array_filter( $locked, function( $until ) { return $until > time(); } );
		update_option( self::LOCKED_OPT, $locked, false );
	}

	private static function clear_failures_for_ip( $ip ) {
		$locked = (array) get_option( self::LOCKED_OPT, [] );
		if ( isset( $locked[ $ip ] ) ) {
			unset( $locked[ $ip ] );
			update_option( self::LOCKED_OPT, $locked, false );
		}
	}

	/* ---------------------------------------------------------------- */
	/*  Heuristics                                                      */
	/* ---------------------------------------------------------------- */

	public static function is_automated_ua( $ua ) {
		if ( ! $ua ) {
			return true; // empty UA is itself suspicious
		}
		foreach ( self::$automated_ua_patterns as $rx ) {
			if ( preg_match( $rx, $ua ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Considered "new origin" when no successful login from the same /16 IPv4 (or /48 IPv6) block exists
	 * for this user in the last 90 days.
	 */
	private static function is_new_login_origin( $user_id, $ip ) {
		global $wpdb;
		if ( ! $ip ) return false;
		$prefix = self::ip_prefix( $ip );
		$since  = gmdate( 'Y-m-d H:i:s', time() - 90 * DAY_IN_SECONDS );
		$table  = self::table();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
		$count = (int) $wpdb->get_var( $wpdb->prepare(
			// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			"SELECT COUNT(*) FROM {$table}
			 JOIN {$wpdb->users} u ON u.user_login = {$table}.attempted_login
			 WHERE u.ID = %d AND success = 1 AND ip LIKE %s AND created_at > %s",
			// phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$user_id,
			$wpdb->esc_like( $prefix ) . '%',
			$since
		) );
		return $count <= 1; // 1 because the current login is already inserted
	}

	private static function ip_prefix( $ip ) {
		// IPv4: keep first two octets. IPv6: first 4 hextets.
		if ( false !== strpos( $ip, '.' ) ) {
			$parts = explode( '.', $ip );
			return ( $parts[0] ?? '' ) . '.' . ( $parts[1] ?? '' ) . '.';
		}
		$parts = explode( ':', $ip );
		return implode( ':', array_slice( $parts, 0, 4 ) );
	}

	private static function ip() {
		if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
			$first = explode( ',', $_SERVER['HTTP_X_FORWARDED_FOR'] )[0];
			return sanitize_text_field( wp_unslash( trim( $first ) ) );
		}
		if ( ! empty( $_SERVER['HTTP_X_REAL_IP'] ) ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
			return sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_REAL_IP'] ) );
		}
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		return isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
	}

	private static function ua() {
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		return isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
	}
}
