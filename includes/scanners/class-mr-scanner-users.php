<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Detects the rogue admin patterns we saw on allfirstnations.com.au:
 *  - multiple users with the same login (newsfeed × 3)
 *  - admin role with backdated registration timestamp
 *  - admin not in operator-supplied whitelist
 *  - users without a real email address
 */
class Malroot_Scanner_Users extends Malroot_Scanner_Base {

	protected $module = 'users';

	public function run() {
		global $wpdb;

		// 1) Duplicate login names — should be impossible via WP UI.
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

		// 2) Hardcoded malware login names from known attacks.
		$known_bad = [ 'newsfeed', 'system_control', 'wpadmin', 'wordpress_administrator', 'wp_admin', 'acfmain', 'defino' ];
		foreach ( $known_bad as $bad ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$id = (int) $wpdb->get_var( $wpdb->prepare( "SELECT ID FROM {$wpdb->users} WHERE user_login = %s LIMIT 1", $bad ) );
			if ( $id > 0 ) {
				$this->record(
					'UA-010',
					'critical',
					"users:{$bad}#{$id}",
					"Known malware admin name found",
					"user_id={$id}"
				);
			}
		}

		// 3) Administrators
		$admins = get_users( [ 'role' => 'administrator', 'fields' => [ 'ID', 'user_login', 'user_email', 'user_registered', 'user_url' ] ] );
		$site_install_time = (int) get_option( 'siteurl_first_seen', 0 );
		$whitelist = (array) get_option( 'malroot_admin_whitelist', [] );

		foreach ( $admins as $u ) {
			// 3a) Backdated registration. WordPress can't predate the install.
			if ( $u->user_registered && strtotime( $u->user_registered ) < strtotime( '2010-01-01' ) ) {
				$this->record(
					'UA-008',
					'high',
					"users:{$u->user_login}#{$u->ID}",
					'Administrator registered with implausible date',
					"user_registered={$u->user_registered}"
				);
			}

			// 3b) Empty email or matches a generic placeholder
			if ( empty( $u->user_email ) || $u->user_email === 'admin@example.com' ) {
				$this->record(
					'UA-011',
					'high',
					"users:{$u->user_login}#{$u->ID}",
					'Administrator without a real email address',
					'email=' . ( $u->user_email ?: '(empty)' )
				);
			}

			// 3c) Whitelist enforcement (only flagged if whitelist is configured)
			if ( ! empty( $whitelist ) && $u->user_email && ! in_array( strtolower( $u->user_email ), array_map( 'strtolower', $whitelist ), true ) ) {
				$this->record(
					'UA-012',
					'medium',
					"users:{$u->user_login}#{$u->ID}",
					'Administrator email not in approved whitelist',
					"email={$u->user_email}"
				);
			}

			// 3d) Suspicious user_url like https://wordpress.com on a non-wordpress.com site
			if ( $u->user_url === 'https://wordpress.com' && false === strpos( home_url(), 'wordpress.com' ) ) {
				$this->record(
					'UA-013',
					'medium',
					"users:{$u->user_login}#{$u->ID}",
					"Administrator user_url is generic 'https://wordpress.com' — common malware default",
					'user_url=' . $u->user_url
				);
			}
		}
	}
}
