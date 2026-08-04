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

	/** Scan currently in progress, so findings group with it in the dashboard. */
	private static $scan_id = 0;

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

		// Turnstile: refuse to authenticate an unapproved administrator at all.
		// The watchdog above only fires once a session already exists, so on its
		// own it lets an injected admin complete one login before being caught.
		add_filter( 'authenticate', [ __CLASS__, 'block_unapproved_login' ], 99, 1 );

		// Capability floor: even if a session is somehow established, an
		// unapproved administrator holds no administrative capability. This closes
		// the window between authentication and the init:2 watchdog.
		add_filter( 'user_has_cap', [ __CLASS__, 'strip_unapproved_caps' ], 99, 4 );
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
			self::repair_allowlist();
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

	/**
	 * Keep the allowlist internally consistent after seeding.
	 *
	 * Seeding is a one-shot: once SEEDED_OPT is set, maybe_seed() used to return
	 * immediately forever. That made any later loss of the email allowlist
	 * permanent and silent. On cityagecare.com the live state was
	 * malroot_admin_approved_ids = [1] with malroot_admin_whitelist = [] — the
	 * two disagreed, which disabled the email fallback in is_approved() and left
	 * the old Users-scanner rule UA-012 (gated on a non-empty whitelist) dead.
	 *
	 * This repair is deliberately one-directional: emails are only ever derived
	 * FROM already-approved user IDs. It can restore the owner's own address, and
	 * it can never promote an unapproved account into the allowlist. Stale IDs
	 * for deleted users are dropped.
	 *
	 * Throttled to once an hour so the init hot path stays cheap.
	 */
	private static function repair_allowlist() {
		if ( get_transient( 'malroot_allowlist_checked' ) ) {
			return;
		}
		set_transient( 'malroot_allowlist_checked', 1, HOUR_IN_SECONDS );

		$ids = array_map( 'intval', (array) get_option( self::APPROVED_IDS_OPT, [] ) );
		if ( empty( $ids ) ) {
			return; // nothing approved: enforcement is already inert, leave it alone
		}

		$live_ids = [];
		$emails   = [];
		foreach ( $ids as $id ) {
			$u = get_userdata( $id );
			if ( ! $u ) {
				continue; // user was deleted
			}
			$live_ids[] = (int) $u->ID;
			if ( ! empty( $u->user_email ) ) {
				$emails[] = strtolower( $u->user_email );
			}
		}

		if ( empty( $live_ids ) ) {
			return; // refuse to empty the allowlist automatically
		}

		$current_wl = array_map( 'strtolower', (array) get_option( self::WHITELIST_OPT, [] ) );
		$missing    = array_diff( $emails, $current_wl );

		if ( $live_ids !== $ids ) {
			update_option( self::APPROVED_IDS_OPT, array_values( array_unique( $live_ids ) ), false );
		}

		if ( ! empty( $missing ) ) {
			$merged = array_values( array_unique( array_merge( $current_wl, $emails ) ) );
			update_option( self::WHITELIST_OPT, $merged );

			if ( class_exists( 'Malroot_Logger' ) ) {
				Malroot_Logger::info( 'Admin Guard repaired the approved-admin email allowlist', [
					'restored' => array_values( $missing ),
				] );
			}
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
	/*  Turnstile: refuse the login outright                            */
	/* ---------------------------------------------------------------- */

	/**
	 * Deny authentication for administrators that are not on the allowlist.
	 *
	 * Runs late on the `authenticate` chain, so the password has already been
	 * verified by the time we see a WP_User. Returning a WP_Error stops the login
	 * before any session token or auth cookie is issued.
	 *
	 * @param null|WP_User|WP_Error $user
	 * @return null|WP_User|WP_Error
	 */
	public static function block_unapproved_login( $user ) {
		if ( ! $user instanceof WP_User ) {
			return $user; // wrong credentials, or another filter already objected
		}
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return $user;
		}
		if ( ! get_option( self::SEEDED_OPT ) ) {
			return $user; // never enforce before the allowlist exists
		}
		if ( ! in_array( 'administrator', (array) $user->roles, true ) ) {
			return $user; // non-admin logins are not our concern
		}
		if ( self::is_approved( $user ) ) {
			return $user;
		}

		self::log_login_attempt( $user );

		Malroot_Alerting::alert(
			'critical',
			'admin_guard_login_blocked',
			"Blocked a login attempt by unapproved administrator '{$user->user_login}'",
			[
				'user_id'    => (int) $user->ID,
				'user_login' => $user->user_login,
				'user_email' => $user->user_email,
				'ip'         => self::ip(),
			]
		);

		return new WP_Error(
			'malroot_admin_not_approved',
			__( 'This account is not an approved administrator. Sign-in has been blocked by Malroot Security.', 'malroot-security' )
		);
	}

	private static function log_login_attempt( $user ) {
		global $wpdb;
		$table = $wpdb->prefix . 'malroot_logins';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->insert( $table, [
			'attempted_login' => $user->user_login,
			'ip'              => self::ip(),
			'ua'              => isset( $_SERVER['HTTP_USER_AGENT'] )
				? substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ), 0, 500 )
				: '',
			'success'         => 0,
		], [ '%s', '%s', '%s', '%d' ] );
	}

	/* ---------------------------------------------------------------- */
	/*  Capability floor                                                */
	/* ---------------------------------------------------------------- */

	/**
	 * Strip every capability from an unapproved administrator.
	 *
	 * Defence in depth for the window between a session being established and
	 * the init:2 watchdog running — and for any code path that reads
	 * capabilities before `init` at all.
	 *
	 * @param array   $allcaps
	 * @param array   $caps
	 * @param array   $args
	 * @param WP_User $user
	 * @return array
	 */
	public static function strip_unapproved_caps( $allcaps, $caps, $args, $user ) {
		if ( empty( $user->ID ) || empty( $allcaps['administrator'] ) ) {
			return $allcaps; // only administrators are in scope
		}
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			return $allcaps;
		}

		static $cache = [];
		$id = (int) $user->ID;

		if ( ! isset( $cache[ $id ] ) ) {
			// Resolve once per request per user. Guarded so a capability check
			// triggered from inside this filter cannot recurse.
			$cache[ $id ] = true;
			if ( get_option( self::SEEDED_OPT ) ) {
				$cache[ $id ] = self::is_approved( $user );
			}
		}

		if ( $cache[ $id ] ) {
			return $allcaps;
		}

		return []; // no role, no capabilities
	}

	/* ---------------------------------------------------------------- */
	/*  Dormant-account sweep                                           */
	/* ---------------------------------------------------------------- */

	/**
	 * Neutralise unapproved administrators that are sitting idle.
	 *
	 * This is the gap that let nine rogue admins survive on cityagecare.com for
	 * five weeks: the door hooks only fire at creation time (and were bypassed
	 * entirely, since the accounts were not created through the WordPress API),
	 * and the watchdog only fires for an account that is actively logged in.
	 * Eight of the nine had never logged in, so nothing ever looked at them.
	 *
	 * Called at the end of a full scan. Honours the admin_guard_autoremediate
	 * setting and the "never strip the last approved administrator" rail.
	 *
	 * @return array{checked:int,neutralised:int,detected:int}
	 */
	public static function sweep( $scan_id = 0 ) {
		$result = [ 'checked' => 0, 'neutralised' => 0, 'detected' => 0 ];

		if ( ! self::is_enabled() || ! get_option( self::SEEDED_OPT ) ) {
			return $result;
		}

		// Attribute anything we record to the scan that invoked us, otherwise the
		// findings land under their own timestamp and the dashboard — which lists
		// by scan id — never shows them.
		self::$scan_id = (int) $scan_id;

		global $wpdb;
		$cap_key = $wpdb->get_blog_prefix() . 'capabilities';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$ids = $wpdb->get_col( $wpdb->prepare(
			"SELECT u.ID FROM {$wpdb->users} u
			   INNER JOIN {$wpdb->usermeta} m ON m.user_id = u.ID
			  WHERE m.meta_key = %s AND m.meta_value LIKE %s",
			$cap_key,
			'%administrator%'
		) );

		$current = get_current_user_id();

		foreach ( $ids as $id ) {
			$id = (int) $id;
			$u  = get_userdata( $id );
			if ( ! $u ) {
				continue;
			}
			$result['checked']++;

			if ( self::is_approved( $u ) ) {
				continue;
			}
			if ( $id === $current ) {
				continue; // never act on the operator running the scan
			}

			$result['detected']++;
			if ( self::neutralize( $id, 'unapproved administrator found by scheduled sweep (account was idle)' ) ) {
				$result['neutralised']++;
			}
		}

		if ( $result['detected'] > 0 && class_exists( 'Malroot_Logger' ) ) {
			Malroot_Logger::warning( 'Admin Guard sweep finished', $result );
		}

		self::$scan_id = 0;

		return $result;
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
			'scan_id'  => self::$scan_id ? self::$scan_id : time(),
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
