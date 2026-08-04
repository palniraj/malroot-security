<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Administrator account scanner.
 *
 * DESIGN NOTE (why this was rewritten)
 * ------------------------------------
 * The first version of this scanner was a list of literal signatures taken from
 * one earlier incident: exact login names ('newsfeed', 'wp_admin', ...), a
 * pre-2010 registration date, an empty email, and 'https://wordpress.com' as
 * the user_url. That approach failed on cityagecare.com, where nine rogue
 * administrators were present and only ONE was reported:
 *
 *   w2s_c428304169fc@wp2shell.local    wp2_c52f1a@wp2shell.invalid
 *   w2s_839aa0a75f4c@wp2shell.local    wp2_d14707fa7fb3@wp2shell.invalid
 *   wp_admin_e38341@local.host         yun_11@wp2shell.invalid
 *   site_admin (ops.notice@example.com)  user (user@wordpress.org)
 *   bbp_support_agent (no email)  <-- the only one the old rules caught
 *
 * Every literal rule missed, because the attacker randomises the login name and
 * supplies a syntactically valid email. 'wp_admin_e38341' is not equal to
 * 'wp_admin', so the exact-match denylist did nothing.
 *
 * Meanwhile the plugin ALREADY knew the answer: Admin Guard had seeded
 * malroot_admin_approved_ids = [1] on 2026-06-09, six weeks before the attack.
 * Nothing ever compared the live administrator list against it.
 *
 * So the primary rule here is now an ALLOWLIST DIFF (UA-001), not a signature.
 * Any administrator that is not approved is reported, whatever it is called.
 * The behavioural rules below are independent corroborating signals, so a
 * single evasion does not produce a silent miss.
 *
 * Roles are read straight from usermeta rather than via get_users(), so an
 * account cannot hide behind a filtered user query.
 */
class Malroot_Scanner_Users extends Malroot_Scanner_Base {

	protected $module = 'users';

	/**
	 * Domains that can never receive mail, so can never belong to a real person.
	 * RFC 2606 / RFC 6761 reserved TLDs, RFC 6762 mDNS, plus the reserved
	 * example.* second-level domains and the wordpress.org placeholder that
	 * WordPress' own sample data uses.
	 */
	private static $undeliverable_domains = [
		'example.com', 'example.net', 'example.org', 'wordpress.org',
	];

	private static $undeliverable_tlds = [
		'local', 'invalid', 'test', 'example', 'localhost', 'internal', 'lan',
	];

	/** Legacy literal names — kept only as an extra signal, never the primary one. */
	private static $known_bad = [
		'newsfeed', 'newsfood', 'wp_feed', 'wppanel', 'wp-panel',
		'system_control', 'system-control', 'wpadmin',
		'wordpress_administrator', 'wp_admin', 'acfmain', 'defino',
	];

	public function run() {
		global $wpdb;

		$admins = $this->get_administrators();
		if ( empty( $admins ) ) {
			return;
		}

		$this->check_duplicate_logins();

		$seeded    = (int) get_option( 'malroot_admin_guard_seeded', 0 );
		$has_guard = class_exists( 'Malroot_Admin_Guard' ) && $seeded > 0;

		// If the allowlist has never been seeded we cannot tell approved from
		// rogue, so say so loudly instead of failing quietly.
		if ( ! $has_guard ) {
			$this->record(
				'UA-014',
				'high',
				'users:allowlist',
				'Administrator allowlist has never been established, so unauthorised admins cannot be detected',
				'Open Malroot > Settings and confirm your administrator list to enable allowlist checking.'
			);
		}

		$this->check_registration_burst( $admins );
		$this->check_disabled_leftovers();

		foreach ( $admins as $u ) {
			$label = "users:{$u->user_login}#{$u->ID}";

			// ---- UA-001: the primary rule. Not on the allowlist. ----------
			$approved = $has_guard ? Malroot_Admin_Guard::is_approved( $u ) : true;
			if ( ! $approved ) {
				$this->record(
					'UA-001',
					'critical',
					$label,
					"Administrator '{$u->user_login}' is not on the approved administrator list",
					$this->context( $u, [
						'approved_admin_ids' => implode( ',', array_map( 'intval', (array) get_option( 'malroot_admin_approved_ids', [] ) ) ),
					] )
				);
			}

			// ---- UA-002: email cannot receive mail -------------------------
			$bad_domain = $this->undeliverable_email_reason( $u->user_email );
			if ( $bad_domain ) {
				$this->record(
					'UA-002',
					'high',
					$label,
					"Administrator email address cannot receive mail ({$bad_domain})",
					$this->context( $u )
				);
			}

			// ---- UA-003: appeared after the guard started watching ---------
			if ( $has_guard && ! $approved && $u->user_registered
				&& strtotime( $u->user_registered ) > $seeded ) {
				$this->record(
					'UA-003',
					'critical',
					$label,
					'Administrator was created after security monitoring began and was never approved',
					$this->context( $u, [
						'monitoring_since' => gmdate( 'Y-m-d H:i:s', $seeded ),
					] )
				);
			}

			// ---- UA-005: machine-generated login name ----------------------
			$pattern = $this->machine_generated_reason( $u->user_login );
			if ( $pattern ) {
				$this->record(
					'UA-005',
					'medium',
					$label,
					"Administrator login name looks machine-generated ({$pattern})",
					$this->context( $u )
				);
			}

			// ---- UA-006: full privileges, never used -----------------------
			if ( ! $approved && $this->never_logged_in( $u->ID ) && ! $this->has_content( $u->ID ) ) {
				$this->record(
					'UA-006',
					'medium',
					$label,
					'Administrator has never logged in and has never created content',
					$this->context( $u )
				);
			}

			// ---- Legacy signals, retained ---------------------------------
			if ( in_array( strtolower( $u->user_login ), self::$known_bad, true ) ) {
				$this->record( 'UA-010', 'critical', $label, 'Known malware admin name found', $this->context( $u ) );
			}

			if ( $u->user_registered && strtotime( $u->user_registered ) < strtotime( '2010-01-01' ) ) {
				$this->record( 'UA-008', 'high', $label, 'Administrator registered with implausible date', $this->context( $u ) );
			}

			if ( empty( $u->user_email ) || $u->user_email === 'admin@example.com' ) {
				$this->record( 'UA-011', 'high', $label, 'Administrator without a real email address', $this->context( $u ) );
			}

			if ( $u->user_url === 'https://wordpress.com' && false === strpos( home_url(), 'wordpress.com' ) ) {
				$this->record( 'UA-013', 'medium', $label, "Administrator user_url is generic 'https://wordpress.com' — common malware default", $this->context( $u ) );
			}
		}
	}

	/* ------------------------------------------------------------------ */
	/*  Collection                                                        */
	/* ------------------------------------------------------------------ */

	/**
	 * Read administrators straight from usermeta.
	 *
	 * get_users() runs through pre_get_users / user_query filters, which
	 * malware can hook to hide an account from both wp-admin and any scanner
	 * that trusts the API. The capabilities meta is the underlying truth.
	 */
	private function get_administrators() {
		global $wpdb;

		$cap_key = $wpdb->get_blog_prefix() . 'capabilities';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows = $wpdb->get_results( $wpdb->prepare(
			"SELECT u.ID, u.user_login, u.user_email, u.user_url, u.user_registered
			   FROM {$wpdb->users} u
			   INNER JOIN {$wpdb->usermeta} m ON m.user_id = u.ID
			  WHERE m.meta_key = %s
			    AND m.meta_value LIKE %s
			  ORDER BY u.user_registered ASC",
			$cap_key,
			'%administrator%'
		) );

		return $rows ? $rows : [];
	}

	/* ------------------------------------------------------------------ */
	/*  Rules                                                             */
	/* ------------------------------------------------------------------ */

	private function check_duplicate_logins() {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$dupes = $wpdb->get_results(
			"SELECT user_login, COUNT(*) AS c FROM {$wpdb->users} GROUP BY user_login HAVING c > 1"
		);
		foreach ( $dupes as $d ) {
			$this->record(
				'UA-009',
				'critical',
				"users:{$d->user_login}",
				"Duplicate user_login '{$d->user_login}' ({$d->c} rows) — only possible via direct DB or trigger injection",
				''
			);
		}
	}

	/**
	 * Accounts Malroot has already stripped of their role but which still exist.
	 *
	 * Admin Guard neutralises a rogue administrator by removing its role, which
	 * stops it immediately. The account itself stays until it is deleted. Because
	 * it is no longer an administrator, none of the rules above look at it, so a
	 * later scan reported the site clean while the account sat in the Users list
	 * showing role "None" and no email. That is alarming to find by hand and it
	 * leaves something an attacker could try to re-elevate.
	 */
	private function check_disabled_leftovers() {
		global $wpdb;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.SlowDBQuery.slow_db_query_meta_key
		$rows = $wpdb->get_results( $wpdb->prepare(
			"SELECT u.ID, u.user_login, u.user_email, m.meta_value AS disabled_at
			   FROM {$wpdb->usermeta} m
			   INNER JOIN {$wpdb->users} u ON u.ID = m.user_id
			  WHERE m.meta_key = %s
			  ORDER BY u.ID",
			'malroot_neutralized'
		) );

		foreach ( (array) $rows as $r ) {
			$u = get_userdata( (int) $r->ID );
			if ( ! $u ) {
				continue;
			}
			// If the operator has since approved it, this is settled.
			if ( class_exists( 'Malroot_Admin_Guard' ) && Malroot_Admin_Guard::is_approved( $u ) ) {
				continue;
			}
			$this->record(
				'UA-007',
				'medium',
				"users:{$u->user_login}#{$u->ID}",
				'Account was disabled by Malroot but has not been deleted yet',
				sprintf(
					'user_id=%d; user_login=%s; disabled_at=%s; current_roles=%s',
					(int) $u->ID,
					$u->user_login,
					$r->disabled_at,
					$u->roles ? implode( ',', (array) $u->roles ) : '(none)'
				)
			);
		}
	}

	/**
	 * Several administrators appearing in a short window is a strong signal.
	 * A real site adds admins one at a time, months apart.
	 */
	private function check_registration_burst( array $admins ) {
		$window   = 7 * DAY_IN_SECONDS;
		$min_size = 3;

		$times = [];
		foreach ( $admins as $u ) {
			if ( $u->user_registered ) {
				$times[] = [ 'ts' => strtotime( $u->user_registered ), 'login' => $u->user_login ];
			}
		}
		if ( count( $times ) < $min_size ) {
			return;
		}
		usort( $times, static function ( $a, $b ) { return $a['ts'] <=> $b['ts']; } );

		$best = [];
		foreach ( $times as $i => $t ) {
			$group = [ $t ];
			for ( $j = $i + 1; $j < count( $times ); $j++ ) {
				if ( $times[ $j ]['ts'] - $t['ts'] <= $window ) {
					$group[] = $times[ $j ];
				} else {
					break;
				}
			}
			if ( count( $group ) > count( $best ) ) {
				$best = $group;
			}
		}

		if ( count( $best ) >= $min_size ) {
			$logins = implode( ', ', wp_list_pluck( $best, 'login' ) );
			$this->record(
				'UA-004',
				'high',
				'users:burst',
				sprintf(
					'%d administrator accounts were created within %d days of each other',
					count( $best ),
					(int) ( $window / DAY_IN_SECONDS )
				),
				"accounts={$logins}; first=" . gmdate( 'Y-m-d H:i:s', $best[0]['ts'] )
					. '; last=' . gmdate( 'Y-m-d H:i:s', end( $best )['ts'] )
			);
		}
	}

	/**
	 * Returns a human reason when an email address provably cannot receive mail.
	 */
	private function undeliverable_email_reason( $email ) {
		$email = strtolower( trim( (string) $email ) );
		if ( '' === $email || false === strpos( $email, '@' ) ) {
			return '';
		}
		$domain = substr( $email, strpos( $email, '@' ) + 1 );
		if ( '' === $domain ) {
			return '';
		}

		if ( in_array( $domain, self::$undeliverable_domains, true ) ) {
			return "{$domain} is a reserved example domain";
		}

		$parts = explode( '.', $domain );
		$tld   = end( $parts );
		if ( in_array( $tld, self::$undeliverable_tlds, true ) ) {
			return ".{$tld} is a reserved, non-routable suffix";
		}

		return '';
	}

	/**
	 * Detects the random-token login names automated tooling produces.
	 * Deliberately conservative: a run of 6+ hex characters, or 8+ characters
	 * with no vowel, is very unlikely in a name a human chose.
	 */
	private function machine_generated_reason( $login ) {
		$login = (string) $login;

		if ( preg_match( '/[0-9a-f]{6,}/i', $login, $m ) ) {
			return "contains a {$m[0]} style random token";
		}
		// Trailing digit-and-letter salt, e.g. 'wp2_c52f1a'
		if ( preg_match( '/[_-][a-z0-9]{5,}\d[a-z0-9]*$/i', $login )
			&& preg_match( '/\d/', $login ) && ! preg_match( '/[aeiou]{2}/i', $login ) ) {
			return 'ends in a random-looking salt';
		}
		if ( preg_match( '/^[a-z0-9]{8,}$/i', $login ) && ! preg_match( '/[aeiou]/i', $login ) ) {
			return 'no vowels, likely generated';
		}
		return '';
	}

	private function never_logged_in( $user_id ) {
		// Wordfence Login Security records this; use it when available.
		$wfls = get_user_meta( $user_id, 'wfls-last-login', true );
		if ( ! empty( $wfls ) ) {
			return false;
		}
		if ( get_user_meta( $user_id, 'malroot_last_login', true ) ) {
			return false;
		}

		// Fall back to our own login log.
		global $wpdb;
		$table = $wpdb->prefix . 'malroot_logins';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
		if ( ! $exists ) {
			return true;
		}
		$u = get_userdata( $user_id );
		if ( ! $u ) {
			return true;
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$hits = (int) $wpdb->get_var( $wpdb->prepare(
			"SELECT COUNT(*) FROM {$table} WHERE attempted_login = %s AND success = 1",
			$u->user_login
		) );
		return 0 === $hits;
	}

	private function has_content( $user_id ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		return (int) $wpdb->get_var( $wpdb->prepare(
			"SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_author = %d",
			$user_id
		) ) > 0;
	}

	/* ------------------------------------------------------------------ */
	/*  Helpers                                                           */
	/* ------------------------------------------------------------------ */

	private function context( $u, array $extra = [] ) {
		$ctx = [
			'user_id'         => (int) $u->ID,
			'user_login'      => $u->user_login,
			'user_email'      => $u->user_email ?: '(empty)',
			'user_registered' => $u->user_registered,
		];
		foreach ( $extra as $k => $v ) {
			$ctx[ $k ] = $v;
		}
		$out = [];
		foreach ( $ctx as $k => $v ) {
			$out[] = "{$k}={$v}";
		}
		return implode( '; ', $out );
	}
}
