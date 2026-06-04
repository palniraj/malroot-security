<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Real-time protection hooks. Loads on every request.
 *
 * - Blocks user creation with known-malware logins (newsfeed, system_control...)
 * - Alerts when a new administrator is created without admin context
 * - Scans option values for known malware patterns before they save
 * - Logs every outbound HTTP request via the WP HTTP API
 */
class Malroot_Realtime {

	private static $blocked_logins = [
		'newsfeed', 'newsfood', 'wp_feed', 'wppanel', 'wp-panel',
		'system_control', 'system-control', 'wpadmin',
		'wordpress_administrator', 'wp_admin', 'acfmain', 'defino',
	];

	private static $option_signatures = [
		'/eval\s*\(\s*(base64_decode|gzinflate|str_rot13)/' => 'PHP eval() of decoded payload',
		'/(superfuckingpanel|hihatbar\.com|logsmetrics\.com|host-stats\.io)/i' => 'Known malicious C2 domain',
		'/wpcode_snippets.*?(eval|wp_create_user|set_role)/s' => 'WPCode-style code injection',
		'/dns\.google\/resolve.*?type=txt/' => 'DNS exfiltration pattern',
	];

	public static function register() {
		$settings = (array) get_option( 'malroot_settings', [] );

		// 1) Block bad-login user inserts
		add_filter( 'pre_user_login', [ __CLASS__, 'block_bad_login' ] );

		// 2) Alert on new administrator
		if ( ! empty( $settings['realtime_block_admin'] ) ) {
			add_action( 'set_user_role', [ __CLASS__, 'on_role_change' ], 10, 3 );
			add_action( 'user_register', [ __CLASS__, 'on_user_register' ], 10, 1 );
		}

		// 3) Scan options before they save
		if ( ! empty( $settings['realtime_scan_options'] ) ) {
			add_filter( 'pre_update_option', [ __CLASS__, 'scan_option_value' ], 10, 3 );
			add_filter( 'pre_add_option',    [ __CLASS__, 'scan_option_value' ], 10, 3 );
		}

		// 4) Outbound monitor
		if ( ! empty( $settings['monitor_outbound'] ) ) {
			add_filter( 'pre_http_request', [ __CLASS__, 'log_outbound' ], 10, 3 );
		}

		// 5) Track plugin/theme updates so we can verify the next scan's findings
		add_action( 'upgrader_process_complete', [ __CLASS__, 'on_upgrade_complete' ], 10, 2 );
	}

	/* ---------------------------------------------------------------- */
	/*  Track legitimate updates so the verifier can correlate them     */
	/* ---------------------------------------------------------------- */

	public static function on_upgrade_complete( $upgrader, $hook_extra ) {
		$type = $hook_extra['type'] ?? '';

		if ( $type === 'plugin' ) {
			$known = (array) get_option( 'malroot_known_updates', [] );
			$slugs = $hook_extra['plugins'] ?? [];
			if ( ! is_array( $slugs ) ) $slugs = [ $slugs ];
			foreach ( $slugs as $plugin_file ) {
				$slug = strtok( (string) $plugin_file, '/' );
				if ( $slug ) {
					$known[ $slug ] = time();
				}
			}
			update_option( 'malroot_known_updates', $known, false );
		}

		if ( $type === 'theme' ) {
			$known = (array) get_option( 'malroot_known_theme_updates', [] );
			$slugs = $hook_extra['themes'] ?? [];
			if ( ! is_array( $slugs ) ) $slugs = [ $slugs ];
			foreach ( $slugs as $slug ) {
				if ( $slug ) {
					$known[ $slug ] = time();
				}
			}
			update_option( 'malroot_known_theme_updates', $known, false );
		}

		if ( $type === 'core' ) {
			update_option( 'malroot_core_updated_at', time(), false );
		}
	}

	/* ---------------------------------------------------------------- */
	/*  Block bad logins                                                */
	/* ---------------------------------------------------------------- */

	public static function block_bad_login( $login ) {
		$blocked = array_merge(
			[ 'newsfeed', 'newsfood', 'wp_feed', 'wppanel', 'wp-panel', 'system_control', 'system-control', 'wpadmin', 'wordpress_administrator', 'wp_admin', 'acfmain', 'defino' ],
			(array) get_option( 'malroot_blocked_logins', [] )
		);
		if ( in_array( strtolower( (string) $login ), array_map( 'strtolower', $blocked ), true ) ) {
			Malroot_Alerting::alert( 'critical', 'blocked_user_creation',
				"Refused to create user with malware-associated login '{$login}'",
				[ 'attempted_login' => $login, 'ip' => self::ip() ]
			);
			return ''; // empty login causes wp_insert_user to fail
		}
		return $login;
	}

	/* ---------------------------------------------------------------- */
	/*  Admin creation watcher                                          */
	/* ---------------------------------------------------------------- */

	public static function on_role_change( $user_id, $new_role, $old_roles ) {
		if ( $new_role !== 'administrator' ) {
			return;
		}
		if ( in_array( 'administrator', (array) $old_roles, true ) ) {
			return; // already was admin
		}
		$u = get_userdata( $user_id );
		if ( ! $u ) {
			return;
		}
		$context = [
			'user_id'    => $user_id,
			'user_login' => $u->user_login,
			'user_email' => $u->user_email,
			'ip'         => self::ip(),
			'is_rest'    => defined( 'REST_REQUEST' ) && REST_REQUEST,
			'is_xmlrpc'  => defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST,
			'admin_session' => is_user_logged_in() && current_user_can( 'manage_options' ),
		];
		$severity = $context['admin_session'] ? 'medium' : 'critical';
		Malroot_Alerting::alert(
			$severity,
			'new_administrator',
			"New administrator '{$u->user_login}' created",
			$context
		);
	}

	public static function on_user_register( $user_id ) {
		$u = get_userdata( $user_id );
		if ( ! $u ) return;
		// Catch users registered via REST API specifically
		if ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			Malroot_Alerting::alert(
				'high',
				'rest_user_register',
				"User '{$u->user_login}' was created via REST API",
				[ 'user_id' => $user_id, 'email' => $u->user_email, 'ip' => self::ip() ]
			);
		}
	}

	/* ---------------------------------------------------------------- */
	/*  Option content scanner                                          */
	/* ---------------------------------------------------------------- */

	public static function scan_option_value( $value, $option, $old_value = null ) {
		// Only inspect text-y values
		if ( ! is_string( $value ) && ! is_array( $value ) ) {
			return $value;
		}
		$haystack = is_string( $value ) ? $value : maybe_serialize( $value );
		if ( ! $haystack || strlen( $haystack ) > 500000 ) {
			return $value; // skip huge blobs
		}
		// Skip our own options
		if ( strpos( $option, 'malroot_' ) === 0 ) {
			return $value;
		}
		foreach ( self::$option_signatures as $regex => $label ) {
			if ( preg_match( $regex, $haystack ) ) {
				Malroot_Alerting::alert(
					'critical',
					'option_payload_blocked',
					"Refused to save option '{$option}' containing malware pattern: {$label}",
					[ 'option' => $option, 'pattern' => $label, 'ip' => self::ip() ]
				);
				// Return the OLD value so the malicious update never lands
				return $old_value !== null ? $old_value : $value;
			}
		}
		return $value;
	}

	/* ---------------------------------------------------------------- */
	/*  Outbound HTTP monitor                                           */
	/* ---------------------------------------------------------------- */

	public static function log_outbound( $preempt, $args, $url ) {
		if ( ! is_string( $url ) ) {
			return $preempt;
		}
		$host = wp_parse_url( $url, PHP_URL_HOST );
		if ( ! $host ) {
			return $preempt;
		}
		// Whitelist common WP hosts (not exhaustive — anything else gets logged)
		$safe = [
			'api.wordpress.org',
			'downloads.wordpress.org',
			'wordpress.org',
			'translate.wordpress.org',
			'public-api.wordpress.com',
			'gravatar.com',
			'secure.gravatar.com',
			's.w.org',
			'fonts.googleapis.com',
			'fonts.gstatic.com',
			'localhost',
			'127.0.0.1',
			// Automattic / WordPress.com
			'pixel.wp.com',
			'translate.wordpress.com',
			// WooCommerce
			'woocommerce.com',
			'api.woocommerce.com',
			'woo.com',
			// Stripe
			'api.stripe.com',
			'js.stripe.com',
			'stripe.com',
			// Jetpack / Automattic
			'jetpack.wordpress.com',
			'jetpack.com',
			'akismet.com',
			'api.akismet.com',
			// Yoast
			'yoast.com',
			'my.yoast.com',
			// Google
			'www.google.com',
			'www.googleapis.com',
			'oauth2.googleapis.com',
			// Mailchimp
			'api.mailchimp.com',
			'mandrillapp.com',
		];

		// Also skip self-traffic (Malroot's own bot-cloak scanner hits the homepage)
		$home_host = wp_parse_url( home_url(), PHP_URL_HOST );
		if ( $host === $home_host ) {
			return $preempt;
		}
		foreach ( $safe as $s ) {
			if ( $host === $s || substr( $host, -(strlen( $s ) + 1) ) === '.' . $s ) {
				return $preempt;
			}
		}

		global $wpdb;
		$table = $wpdb->prefix . 'malroot_connections';
		$now   = current_time( 'mysql' );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
		$existing_id = $wpdb->get_var( $wpdb->prepare(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			"SELECT id FROM {$table} WHERE domain = %s AND url = %s LIMIT 1",
			$host, substr( $url, 0, 1000 )
		) );

		if ( $existing_id ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
			$wpdb->query( $wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"UPDATE {$table} SET hit_count = hit_count + 1, last_seen = %s WHERE id = %d",
				$now, $existing_id
			) );
		} else {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->insert( $table, [
				'domain'     => $host,
				'url'        => substr( $url, 0, 1000 ),
				'method'     => $args['method'] ?? 'GET',
				'caller'     => self::caller_path(),
				'first_seen' => $now,
				'last_seen'  => $now,
				'hit_count'  => 1,
			], [ '%s','%s','%s','%s','%s','%s','%d' ] );

			// Known-bad domains alert immediately
			$bad = [ 'superfuckingpanel.info', 'hihatbar.com', 'logsmetrics.com', 'host-stats.io', 'jforvexan.shop', 'talvexoni.shop', 'ak2yy.com' ];
			foreach ( $bad as $b ) {
				if ( $host === $b || substr( $host, -strlen( $b ) - 1 ) === '.' . $b ) {
					Malroot_Alerting::alert(
						'critical',
						'outbound_to_c2',
						"Outbound HTTP request to known malicious domain {$host}",
						[ 'url' => $url, 'caller' => self::caller_path(), 'ip' => self::ip() ]
					);
					break;
				}
			}
		}
		return $preempt;
	}

	private static function caller_path() {
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_debug_backtrace
		$trace = debug_backtrace( DEBUG_BACKTRACE_IGNORE_ARGS, 8 );
		foreach ( $trace as $f ) {
			if ( ! empty( $f['file'] ) && false === strpos( $f['file'], '/wp-includes/' ) && false === strpos( $f['file'], '/malroot-security/' ) ) {
				return ltrim( str_replace( ABSPATH, '', $f['file'] ), '/' ) . ':' . ( $f['line'] ?? '?' );
			}
		}
		return '';
	}

	private static function ip() {
		if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			$xff   = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) );
			$first = explode( ',', $xff )[0];
			return trim( $first );
		}
		return isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
	}
}
