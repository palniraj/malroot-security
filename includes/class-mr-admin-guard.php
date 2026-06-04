<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Admin Guard — allowlist-based administrator enforcement.
 *
 * Why this exists:
 *   Rogue admins like `newsfeed`, `wp_feed`, `newsfood` and the five identical
 *   `wppanel` accounts are NOT created through WordPress. They are written
 *   straight into wp_users by a MySQL trigger or a direct-SQL backdoor, so the
 *   normal creation hooks (pre_user_login, user_register, set_user_role) never
 *   fire. A login-name blocklist can never win this race — the attacker just
 *   renames the account.
 *
 * The fix is to invert the model:
 *   - We keep an ALLOWLIST of administrators the operator trusts.
 *   - "Door" hooks auto-approve any admin that an already-approved admin creates
 *     through wp-admin, and neutralise admins elevated WITHOUT an approved
 *     session (REST / XML-RPC / programmatic).
 *   - A per-request "watchdog" on init catches admins that bypassed every hook
 *     (direct SQL / trigger injection): on the first request such an account
 *     makes, it is demoted, its sessions destroyed, and the request blocked —
 *     so the injected row can never actually be used.
 *
 * Safety rails (so we can never lock the real owner out):
 *   - The allowlist is seeded on first run from the CURRENT administrators,
 *     excluding any that already look rogue (no email, wordpress.com url,
 *     duplicate login, known-bad name). This approves the legitimate owner but
 *     not an already-present injected admin.
 *   - Enforcement only runs once seeding has happened.
 *   - Auto-remediation never removes the last approved administrator. If no
 *     approved admin would remain, it alerts instead of demoting.
 *   - WP-CLI is always trusted.
 */
class Malroot_Admin_Guard {

	const APPROVED_IDS_OPT = 'malroot_admin_approved_ids';
	const WHITELIST_OPT    = 'malroot_admin_whitelist'; // emails (shared with Users scanner)
	const SEEDED_OPT       = 'malroot_admin_guard_seeded';

	/** Known rogue-admin login names seen across the sites we manage. */
	private static $known_bad_logins = [
		'newsfeed', 'newsfood', 'wp_feed', 'wppanel', 'wp-panel',
		'system_control', 'system-control', 'wpadmin',
		'wordpress_administrator', 'wp_admin', 'acfmain', 'defino',
	];

	/* ---------------------------------------------------------------- */
	/*  Bootstrap                                                       */
	/* ---------------------------------------------------------------- */

	public static function register() {
		// Seed the allowlist as early as roles are available. init:0 runs before
		// the watchdog (init:2) and before any normal admin role change.
		add_action( 'init', [ __CLASS__, 'maybe_seed' ], 0 );

		if ( ! self::is_enabled() ) {
			return;
		}

		// Door: elevation through any code path that uses the WordPress APIs.
		add_action( 'set_user_role', [ __CLASS__, 'on_role_event' ], 1, 3 );
		add_action( 'add_user_role', [ __CLASS__, 'on_role_event' ], 1, 2 );
		add_action( 'user_register', [ __CLASS__, 'on_role_event' ], 1, 1 );

		// Watchdog: catches admins injected by direct SQL / triggers that never
		// touched a WordPress hook. Runs on every request, but is a no-op for
		// logged-out visitors and approved admins (no DB queries on the hot path).
		add_action( 'init', [ __CLASS__, 'guard_current_request' ], 2 );
	}

	public static function is_enabled() {
		$s = (array) get_option( 'malroot_settings', [] );
		return ! isset( $s['admin_guard'] ) || ! empty( $s['admin_guard'] );
	}

	public static function autoremediate() {
		$s = (array) get_option( 'malroot_settings', [] );
		return ! isset( $s['admin_guard_autoremediate'] ) || ! empty( $s['admin_guard_autoremediate'] );
	}

	/* ---------------------------------------------------------------- */
	/*  Seeding                                                         */
	/* ---------------------------------------------------------------- */

	/**
	 * Seed the allowlist from the current, clean-looking administrators.
	 * Runs once. Excludes anything that already matches a rogue signature so an
	 * already-compromised site does not approve its attacker.
	 */
	public static function maybe_seed() {
		if ( get_option( self::SEEDED_OPT ) ) {
			return;
		}

		$admins = get_users( [ 'role' => 'administrator' ] );

		// Count logins so we can refuse to approve injected duplicates.
		$login_counts = [];
		foreach ( $admins as $a ) {
			$l = strtolower( $a->user_login );
			$login_counts[ $l ] = ( $login_counts[ $l ] ?? 0 ) + 1;
		}

		$ids    = [];
		$emails = (array) get_option( self::WHITELIST_OPT, [] );
		foreach ( $admins as $a ) {
			if ( self::looks_rogue( $a ) ) {
				continue;
			}
			if ( ( $login_counts[ strtolower( $a->user_login ) ] ?? 0 ) > 1 ) {
				continue; // duplicate login name == direct-SQL injection
			}
			$ids[] = (int) $a->ID;
			if ( ! empty( $a->user_email ) ) {
				$emails[] = strtolower( $a->user_email );
			}
		}

		update_option( self::APPROVED_IDS_OPT, array_values( array_unique( $ids ) ), false );
		update_option( self::WHITELIST_OPT, array_values( array_unique( array_map( 'strtolower', $emails ) ) ) );
		update_option( self::SEEDED_OPT, time(), false );

		if ( class_exists( 'Malroot_Logger' ) ) {
			Malroot_Logger::info( 'Admin Guard seeded approved administrators', [
				'approved_ids'    => $ids,
				'approved_emails' => $emails,
			] );
		}
	}

	/* ---------------------------------------------------------------- */
	/*  Allowlist helpers                                               */
	/* ---------------------------------------------------------------- */

	public static function is_approved( $user ) {
		if ( ! $user || empty( $user->ID ) ) {
			return false;
		}
		$ids = array_map( 'intval', (array) get_option( self::APPROVED_IDS_OPT, [] ) );
		if ( in_array( (int) $user->ID, $ids, true ) ) {
			return true;
		}
		$email = strtolower( (string) $user->user_email );
		if ( $email ) {
			$wl = array_map( 'strtolower', (array) get_option( self::WHITELIST_OPT, [] ) );
			if ( in_array( $email, $wl, true ) ) {
				return true;
			}
		}
		return false;
	}

	public static function approve( $user_id ) {
		$ids   = array_map( 'intval', (array) get_option( self::APPROVED_IDS_OPT, [] ) );
		$ids[] = (int) $user_id;
		update_option( self::APPROVED_IDS_OPT, array_values( array_unique( $ids ) ), false );

		$u = get_userdata( $user_id );
		if ( $u && $u->user_email ) {
			$wl   = (array) get_option( self::WHITELIST_OPT, [] );
			$wl[] = strtolower( $u->user_email );
			update_option( self::WHITELIST_OPT, array_values( array_unique( array_map( 'strtolower', $wl ) ) ) );
		}
	}

	/** Number of current administrators that are on the allowlist. */
	private static function approved_admin_count() {
		$n = 0;
		foreach ( get_users( [ 'role' => 'administrator' ] ) as $a ) {
			if ( self::is_approved( $a ) ) {
				$n++;
			}
		}
		return $n;
	}

	private static function performed_by_approved_admin() {
		if ( ! is_user_logged_in() ) {
			return false;
		}
		$cur = wp_get_current_user();
		if ( ! $cur || ! $cur->ID || ! user_can( $cur, 'manage_options' ) ) {
			return false;
		}
		return self::is_approved( $cur );
	}

	private static function looks_rogue( $u ) {
		if ( empty( $u->user_email ) || $u->user_email === 'admin@example.com' ) {
			return true;
		}
		if ( $u->user_url === 'https://wordpress.com' && false === strpos( home_url(), 'wordpress.com' ) ) {
			return true;
		}
		if ( in_array( strtolower( $u->user_login ), self::$known_bad_logins, true ) ) {
			return true;
		}
		if ( class_exists( 'Malroot_Spam_Shield' ) && Malroot_Spam_Shield::login_matches_spam_pattern( $u->user_login ) ) {
			return true;
		}
		return false;
	}

	/* ---------------------------------------------------------------- */
	/*  Door enforcement                                                */
	/* ---------------------------------------------------------------- */

	public static function on_role_event( $user_id, $role = '', $old_roles = [] ) {
		self::enforce_on( (int) $user_id );
	}

	private static function enforce_on( $user_id ) {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return; // trusted server context
		}
		if ( ! get_option( self::SEEDED_OPT ) ) {
			return; // never enforce before the allowlist is seeded
		}
		$u = get_userdata( $user_id );
		if ( ! $u || ! in_array( 'administrator', (array) $u->roles, true ) ) {
			return;
		}
		if ( self::is_approved( $u ) ) {
			return;
		}

		// An already-approved admin promoting someone through wp-admin is a
		// legitimate action — auto-approve the new admin.
		if ( self::performed_by_approved_admin() ) {
			self::approve( $user_id );
			Malroot_Alerting::alert(
				'medium',
				'admin_guard_approved',
				"New administrator '{$u->user_login}' approved (created by an approved admin)",
				[ 'user_id' => $user_id, 'approved_by' => get_current_user_id() ]
			);
			return;
		}

		// Otherwise the admin role was granted without a trusted session.
		self::neutralize( $user_id, 'administrator role granted without an approved admin session' );
	}

	/* ---------------------------------------------------------------- */
	/*  Per-request watchdog (catches direct-SQL / trigger injection)   */
	/* ---------------------------------------------------------------- */

	public static function guard_current_request() {
		if ( ! is_user_logged_in() ) {
			return; // hot path: logged-out traffic costs nothing
		}
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return;
		}
		if ( ! get_option( self::SEEDED_OPT ) ) {
			return;
		}
		$u = wp_get_current_user();
		if ( ! $u || ! in_array( 'administrator', (array) $u->roles, true ) ) {
			return;
		}
		if ( self::is_approved( $u ) ) {
			return;
		}

		// An unapproved administrator is actively authenticated. This account was
		// almost certainly injected by SQL/trigger (it bypassed every hook).
		$demoted = self::neutralize( $u->ID, 'active session of an unapproved administrator' );

		if ( $demoted ) {
			wp_logout();
			if ( wp_doing_ajax() || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) {
				wp_die(
					esc_html__( 'Access blocked by Malroot Admin Guard.', 'malroot-security' ),
					'',
					[ 'response' => 403 ]
				);
			}
			wp_safe_redirect( home_url( '/' ) );
			exit;
		}
	}

	/* ---------------------------------------------------------------- */
	/*  Remediation                                                     */
	/* ---------------------------------------------------------------- */

	/**
	 * Demote + lock out an unapproved administrator.
	 * Returns true if the account was actually demoted.
	 */
	private static function neutralize( $user_id, $reason ) {
		$u = get_userdata( $user_id );
		if ( ! $u ) {
			return false;
		}

		$ctx = [
			'user_id'    => (int) $user_id,
			'user_login' => $u->user_login,
			'user_email' => $u->user_email,
			'reason'     => $reason,
			'ip'         => self::ip(),
		];

		self::record_finding( $u, $reason );

		// Fail-safe: never strip the last approved administrator.
		if ( self::autoremediate() && self::approved_admin_count() >= 1 ) {
			$wpu = new WP_User( $user_id );
			$wpu->set_role( '' ); // remove every role / capability
			if ( class_exists( 'WP_Session_Tokens' ) ) {
				WP_Session_Tokens::get_instance( $user_id )->destroy_all();
			}
			update_user_meta( $user_id, 'malroot_neutralized', current_time( 'mysql' ) );

			Malroot_Alerting::alert(
				'critical',
				'admin_guard_neutralized',
				"Unapproved administrator '{$u->user_login}' was automatically demoted and signed out",
				$ctx
			);
			return true;
		}

		Malroot_Alerting::alert(
			'critical',
			'admin_guard_detected',
			"Unapproved administrator '{$u->user_login}' detected (auto-remediation off, or no approved admin remains)",
			$ctx
		);
		return false;
	}

	private static function record_finding( $u, $reason ) {
		if ( ! class_exists( 'Malroot_Findings' ) ) {
			return;
		}
		Malroot_Findings::record( [
			'scan_id'  => time(),
			'module'   => 'admin-guard',
			'rule_id'  => 'AG-001',
			'severity' => 'critical',
			'target'   => "users:{$u->user_login}#{$u->ID}",
			'summary'  => 'Unapproved administrator neutralised by Admin Guard',
			'details'  => $reason,
		] );
	}

	private static function ip() {
		if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			$xff = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) );
			return trim( explode( ',', $xff )[0] );
		}
		return isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
	}
}
