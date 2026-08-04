<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Guided cleanup.
 *
 * Malroot_Incident_Response replays one specific historical cleanup. This class
 * is driven by what the current scan actually found, and it removes threats in
 * the order that stops them coming back.
 *
 * ORDER MATTERS. The kit found on cityagecare.com survived earlier cleanups
 * because the steps were done in the wrong order:
 *
 *   1. persistence first  — a daily WP-Cron job (`bbp_license_sync`) recreated
 *                           the administrator account. Remove the account
 *                           before the job and it is simply back tomorrow.
 *   2. loader second      — the trojanised plugin recreated the same account on
 *                           every page load via `plugins_loaded`.
 *   3. accounts third     — only now can they stay deleted.
 *   4. payload fourth     — cloaking rules and the spam page they point at.
 *
 * Every destructive step goes through Malroot_Quarantine, so each one is backed
 * up and reversible. plan() is a dry run: it reports exactly what run() would
 * do, and is what the admin screen shows before anything is touched.
 */
class Malroot_Cleanup {

	/** Steps in the order they must run. */
	const STEPS = [ 'persistence', 'loaders', 'accounts', 'payload' ];

	public static function token() {
		return wp_hash( 'malroot_cleanup_' . gmdate( 'Y-m-d' ) );
	}

	/* ------------------------------------------------------------------ */
	/*  Dry run                                                           */
	/* ------------------------------------------------------------------ */

	/**
	 * Work out what needs removing, without changing anything.
	 *
	 * @return array<string,array> Keyed by step, each a list of action arrays.
	 */
	public static function plan() {
		return [
			'persistence' => self::find_persistence(),
			'loaders'     => self::find_loaders(),
			'accounts'    => self::find_rogue_admins(),
			'payload'     => self::find_payload(),
		];
	}

	public static function plan_summary() {
		$plan  = self::plan();
		$total = 0;
		$out   = [];
		foreach ( $plan as $step => $items ) {
			$out[ $step ] = count( $items );
			$total       += count( $items );
		}
		$out['total'] = $total;
		return $out;
	}

	/* ------------------------------------------------------------------ */
	/*  Execute                                                           */
	/* ------------------------------------------------------------------ */

	/**
	 * @param string     $confirm_token Token from self::token().
	 * @param array|null $only          Optional subset of STEPS.
	 * @return array|WP_Error
	 */
	public static function run( $confirm_token, $only = null ) {
		if ( ! is_string( $confirm_token ) || ! hash_equals( self::token(), $confirm_token ) ) {
			return new WP_Error( 'bad_token', __( 'Confirmation token mismatch. Reload the page and try again.', 'malroot-security' ) );
		}
		if ( ! current_user_can( 'manage_options' ) ) {
			return new WP_Error( 'forbidden', __( 'You do not have permission to run a cleanup.', 'malroot-security' ) );
		}

		$steps  = is_array( $only ) && $only ? array_intersect( self::STEPS, $only ) : self::STEPS;
		$report = [
			'started_at' => current_time( 'mysql' ),
			'steps'      => [],
		];

		foreach ( $steps as $step ) {
			switch ( $step ) {
				case 'persistence':
					$report['steps']['persistence'] = self::clean_persistence();
					break;
				case 'loaders':
					$report['steps']['loaders'] = self::clean_loaders();
					break;
				case 'accounts':
					$report['steps']['accounts'] = self::clean_rogue_admins();
					break;
				case 'payload':
					$report['steps']['payload'] = self::clean_payload();
					break;
			}
		}

		$report['finished_at'] = current_time( 'mysql' );

		Malroot_Alerting::alert( 'high', 'cleanup_run', 'Guided cleanup executed', $report );
		Malroot_Logger::info( 'Guided cleanup complete', $report );

		return $report;
	}

	/* ================================================================== */
	/*  Step 1 — persistence (WP-Cron)                                    */
	/* ================================================================== */

	/**
	 * Scheduled jobs that belong to code we have flagged, or to a plugin that
	 * is not installed at all.
	 *
	 * An orphaned hook is not automatically malicious — uninstalled plugins
	 * often leave one behind — so it is reported at a lower confidence and the
	 * operator decides.
	 */
	private static function find_persistence() {
		$out       = [];
		$suspect   = self::suspect_plugin_slugs();
		$crons     = (array) _get_cron_array();
		$seen      = [];

		foreach ( $crons as $groups ) {
			if ( ! is_array( $groups ) ) {
				continue;
			}
			foreach ( array_keys( $groups ) as $hook ) {
				if ( isset( $seen[ $hook ] ) ) {
					continue;
				}
				$seen[ $hook ] = true;

				if ( 0 === strpos( $hook, 'malroot_' ) ) {
					continue; // our own maintenance job
				}

				// Does this hook belong to flagged code?
				$owner = self::hook_owner( $hook, $suspect );

				if ( $owner ) {
					$out[] = [
						'hook'       => $hook,
						'target'     => 'wp-cron:' . $hook,
						'reason'     => sprintf(
							/* translators: %s: plugin folder name */
							__( 'Scheduled by "%s", which was flagged as a backdoor', 'malroot-security' ),
							$owner
						),
						'confidence' => 'high',
					];
					continue;
				}

				// Hook with no registered callback and no matching plugin.
				if ( ! has_action( $hook ) && ! self::hook_matches_installed_plugin( $hook ) ) {
					$out[] = [
						'hook'       => $hook,
						'target'     => 'wp-cron:' . $hook,
						'reason'     => __( 'Nothing on your site answers this scheduled job, and it matches no installed plugin', 'malroot-security' ),
						'confidence' => 'low',
					];
				}
			}
		}
		return $out;
	}

	private static function clean_persistence() {
		$done = [];
		foreach ( self::find_persistence() as $item ) {
			// Only auto-remove what we are confident about. Low-confidence
			// orphans are left for the operator so we never silently break a
			// legitimate integration.
			if ( 'high' !== $item['confidence'] ) {
				$done[] = [ 'hook' => $item['hook'], 'result' => 'left alone (needs your review)' ];
				continue;
			}
			$fid = self::synthesise_finding( 'CU-CRON', $item['target'], $item['reason'] );
			$res = Malroot_Quarantine::quarantine_finding( $fid );
			$done[] = [
				'hook'   => $item['hook'],
				'result' => is_wp_error( $res ) ? $res->get_error_message() : 'unscheduled (reversible)',
			];
		}
		return $done;
	}

	/**
	 * Decide whether a cron hook belongs to one of the flagged plugin folders.
	 *
	 * The reliable way is to read the hook name out of the offending code, which
	 * is still on disk because persistence is cleaned before the loaders are.
	 * The backdoor on cityagecare.com contained the literal
	 * `$sync_hook = 'bbp_license_sync';`, so it is found exactly rather than
	 * guessed at.
	 *
	 * A name-shape comparison is kept as a fallback for obfuscated code, but it
	 * matches on the hook's first token rather than a fixed-length prefix: the
	 * folder `bbPress2.6.14` normalises to `bbpress`, whose first token `bbp`
	 * matches `bbp_license_sync`. A naive 4-character prefix gave `bbpr`, which
	 * did not match and let the job survive the cleanup.
	 *
	 * @param string   $hook    Cron hook name.
	 * @param string[] $suspect Flagged plugin folder names.
	 * @return string Owning folder, or ''.
	 */
	private static function hook_owner( $hook, array $suspect ) {
		foreach ( $suspect as $slug ) {
			if ( in_array( $hook, self::scheduled_hooks_in_plugin( $slug ), true ) ) {
				return $slug;
			}
		}

		$hook_token = strtolower( strtok( (string) $hook, '_-' ) );
		if ( strlen( $hook_token ) < 3 ) {
			return '';
		}
		foreach ( $suspect as $slug ) {
			$norm = strtolower( preg_replace( '/[^a-z]/i', '', $slug ) );
			if ( '' !== $norm && 0 === strpos( $norm, $hook_token ) ) {
				return $slug;
			}
		}
		return '';
	}

	/**
	 * Literal cron hook names scheduled by a plugin's own source.
	 *
	 * @return string[]
	 */
	private static function scheduled_hooks_in_plugin( $slug ) {
		static $cache = [];
		if ( isset( $cache[ $slug ] ) ) {
			return $cache[ $slug ];
		}

		$hooks = [];
		foreach ( self::list_files( WP_PLUGIN_DIR . '/' . $slug ) as $abs ) {
			if ( ! preg_match( '/\.(php|inc)$/i', $abs ) ) {
				continue;
			}
			$fh = @fopen( $abs, 'rb' );
			if ( ! $fh ) {
				continue;
			}
			$code = (string) fread( $fh, 1048576 );
			fclose( $fh );

			// wp_schedule_event( ..., 'hook' ) / wp_next_scheduled( 'hook' ) /
			// wp_schedule_single_event( ..., 'hook' )
			if ( preg_match_all(
				'/wp_(?:schedule_event|schedule_single_event|next_scheduled|clear_scheduled_hook)\s*\([^;]{0,120}?[\'"]([a-z0-9_\-]{3,64})[\'"]/i',
				$code,
				$m
			) ) {
				foreach ( $m[1] as $h ) {
					$hooks[ $h ] = true;
				}
			}
			// Hook names held in a variable first, e.g. $sync_hook = 'bbp_license_sync';
			if ( preg_match_all(
				'/\$[a-z_][a-z0-9_]*hook[a-z0-9_]*\s*=\s*[\'"]([a-z0-9_\-]{3,64})[\'"]/i',
				$code,
				$m2
			) ) {
				foreach ( $m2[1] as $h ) {
					$hooks[ $h ] = true;
				}
			}
		}

		// Never let a compromised plugin name our own job as its own.
		unset( $hooks['malroot_daily_scan'] );

		$cache[ $slug ] = array_keys( $hooks );
		return $cache[ $slug ];
	}

	private static function hook_matches_installed_plugin( $hook ) {
		$token = strtolower( substr( preg_replace( '/[^a-z0-9]/i', '', $hook ), 0, 4 ) );
		if ( '' === $token ) {
			return true;
		}
		foreach ( (array) get_plugins() as $file => $data ) {
			$slug = strtolower( preg_replace( '/[^a-z0-9]/i', '', dirname( $file ) ) );
			if ( '' !== $slug && 0 === strpos( $slug, $token ) ) {
				return true;
			}
		}
		// Core hooks all start wp_/wpseo_ etc.; treat WordPress' own as matched.
		return (bool) preg_match( '/^(wp|do_pings|publish|recovery|delete_expired)/i', $hook );
	}

	/* ================================================================== */
	/*  Step 2 — loaders (trojanised plugin code)                         */
	/* ================================================================== */

	/**
	 * Plugin folders that the backdoor scanner flagged with a high-confidence
	 * behavioural rule. BD-009 alone (an odd folder name) is not enough.
	 */
	private static function suspect_plugin_slugs() {
		global $wpdb;
		$table = $wpdb->prefix . 'malroot_findings';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$rows = $wpdb->get_col(
			"SELECT DISTINCT target FROM {$table}
			  WHERE module = 'backdoor'
			    AND status <> 'fixed'
			    AND rule_id IN ('BD-001','BD-002','BD-003','BD-004','BD-005','BD-006','BD-007','BD-008','BD-010')"
		);

		$slugs = [];
		foreach ( (array) $rows as $target ) {
			if ( preg_match( '#^wp-content/plugins/([^/]+)/#', (string) $target, $m ) ) {
				$slugs[ $m[1] ] = true;
			}
		}
		unset( $slugs['malroot-security'] ); // never ourselves
		return array_keys( $slugs );
	}

	private static function find_loaders() {
		$out = [];
		foreach ( self::suspect_plugin_slugs() as $slug ) {
			$dir = WP_PLUGIN_DIR . '/' . $slug;
			if ( ! is_dir( $dir ) ) {
				continue;
			}
			$files  = self::list_files( $dir );
			$active = self::active_plugin_files_for_slug( $slug );

			$out[] = [
				'slug'        => $slug,
				'file_count'  => count( $files ),
				'bytes'       => array_sum( array_map( 'filesize', $files ) ),
				'is_active'   => ! empty( $active ),
				'active_refs' => $active,
				'reason'      => __( 'Folder contains code flagged as a backdoor', 'malroot-security' ),
			];
		}
		return $out;
	}

	/**
	 * Remove a trojanised plugin folder.
	 *
	 * Deactivation note: this plugin's standing policy is never to change
	 * another plugin's activation status on its own. That policy is about acting
	 * without consent. A cleanup only runs when an administrator explicitly
	 * confirms it, and deleting the files of a still-active plugin would leave a
	 * dangling entry in active_plugins, so the entry is removed as part of the
	 * same confirmed action.
	 */
	private static function clean_loaders() {
		$done = [];

		foreach ( self::find_loaders() as $item ) {
			$slug   = $item['slug'];
			$result = [ 'slug' => $slug, 'deactivated' => false, 'files_removed' => 0, 'files_failed' => [] ];

			// Deactivate first so WordPress stops loading it mid-removal.
			if ( $item['is_active'] ) {
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
				deactivate_plugins( $item['active_refs'], true );
				$result['deactivated'] = true;
			}

			foreach ( self::list_files( WP_PLUGIN_DIR . '/' . $slug ) as $abs ) {
				$rel = ltrim( str_replace( wp_normalize_path( ABSPATH ), '', wp_normalize_path( $abs ) ), '/' );
				$fid = self::synthesise_finding( 'CU-FILE', $rel, __( 'Part of a backdoor plugin folder', 'malroot-security' ) );

				// allow_protected: these live inside a plugin directory, which
				// the automatic path refuses on purpose. This is the deliberate,
				// operator-confirmed route.
				$res = Malroot_Quarantine::quarantine_finding( $fid, true );
				if ( is_wp_error( $res ) ) {
					$result['files_failed'][] = $rel . ' — ' . $res->get_error_message();
				} else {
					$result['files_removed']++;
				}
			}

			self::remove_empty_dirs( WP_PLUGIN_DIR . '/' . $slug );
			$result['folder_gone'] = ! is_dir( WP_PLUGIN_DIR . '/' . $slug );

			$done[] = $result;
		}

		return $done;
	}

	private static function active_plugin_files_for_slug( $slug ) {
		$found  = [];
		$active = (array) get_option( 'active_plugins', [] );
		if ( is_multisite() ) {
			$active = array_merge( $active, array_keys( (array) get_site_option( 'active_sitewide_plugins', [] ) ) );
		}
		foreach ( $active as $file ) {
			if ( 0 === strpos( (string) $file, $slug . '/' ) ) {
				$found[] = $file;
			}
		}
		return $found;
	}

	/* ================================================================== */
	/*  Step 3 — rogue administrators                                     */
	/* ================================================================== */

	/**
	 * Accounts that need removing: unapproved administrators, plus any account
	 * Malroot has already stripped of its role.
	 *
	 * Two passes are needed, and the second one matters more than it looks.
	 * Admin Guard's sweep neutralises a rogue admin by setting its role to ''.
	 * A search for administrators therefore no longer finds it, so a cleanup run
	 * afterwards walked straight past the account and left it on the site
	 * forever — visible in the Users list with role "None" and no email, which
	 * looks exactly like an unfinished cleanup. The account is inert once its
	 * capabilities are gone, but leaving it is both confusing and an invitation
	 * to re-elevate it later.
	 *
	 * Roles are read from usermeta rather than get_users(), because malware can
	 * filter pre_user_query to hide its account from the API.
	 */
	private static function find_rogue_admins() {
		if ( ! class_exists( 'Malroot_Admin_Guard' ) || ! get_option( 'malroot_admin_guard_seeded' ) ) {
			return [];
		}

		global $wpdb;
		$cap_key = $wpdb->get_blog_prefix() . 'capabilities';
		$current = get_current_user_id();
		$out     = [];
		$seen    = [];

		// Pass 1 — administrators that are not on the allowlist.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$ids = $wpdb->get_col( $wpdb->prepare(
			"SELECT u.ID FROM {$wpdb->users} u
			   INNER JOIN {$wpdb->usermeta} m ON m.user_id = u.ID
			  WHERE m.meta_key = %s AND m.meta_value LIKE %s
			  ORDER BY u.ID",
			$cap_key,
			'%administrator%'
		) );

		foreach ( $ids as $id ) {
			$id = (int) $id;
			$u  = get_userdata( $id );
			if ( ! $u || Malroot_Admin_Guard::is_approved( $u ) ) {
				continue;
			}
			$seen[ $id ] = true;
			$out[] = [
				'id'     => $id,
				'login'  => $u->user_login,
				'email'  => $u->user_email,
				'target' => "users:{$u->user_login}#{$id}",
				'reason' => __( 'Administrator not on the approved list', 'malroot-security' ),
				'skip'   => $id === $current ? 'this is you' : '',
			];
		}

		// Pass 2 — leftovers Malroot itself already judged rogue and demoted.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.SlowDBQuery.slow_db_query_meta_key
		$neutralised = $wpdb->get_col( $wpdb->prepare(
			"SELECT user_id FROM {$wpdb->usermeta} WHERE meta_key = %s",
			'malroot_neutralized'
		) );

		foreach ( $neutralised as $id ) {
			$id = (int) $id;
			if ( isset( $seen[ $id ] ) ) {
				continue;
			}
			$u = get_userdata( $id );
			if ( ! $u || Malroot_Admin_Guard::is_approved( $u ) ) {
				continue; // re-approved since: leave it alone
			}
			$seen[ $id ] = true;
			$out[] = [
				'id'     => $id,
				'login'  => $u->user_login,
				'email'  => $u->user_email,
				'target' => "users:{$u->user_login}#{$id}",
				'reason' => __( 'Account was already disabled by Malroot and is still on the site', 'malroot-security' ),
				'skip'   => $id === $current ? 'this is you' : '',
			];
		}

		return $out;
	}

	private static function clean_rogue_admins() {
		$done      = [];
		$candidates = self::find_rogue_admins();

		// Lockout rail: make sure at least one approved administrator survives.
		$approved_left = 0;
		global $wpdb;
		$cap_key = $wpdb->get_blog_prefix() . 'capabilities';
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$all = $wpdb->get_col( $wpdb->prepare(
			"SELECT u.ID FROM {$wpdb->users} u
			   INNER JOIN {$wpdb->usermeta} m ON m.user_id = u.ID
			  WHERE m.meta_key = %s AND m.meta_value LIKE %s",
			$cap_key,
			'%administrator%'
		) );
		foreach ( $all as $id ) {
			$u = get_userdata( (int) $id );
			if ( $u && Malroot_Admin_Guard::is_approved( $u ) ) {
				$approved_left++;
			}
		}
		if ( $approved_left < 1 ) {
			return [ [ 'result' => 'aborted: no approved administrator would remain — confirm your admin list in Malroot > Settings first' ] ];
		}

		foreach ( $candidates as $c ) {
			if ( $c['skip'] ) {
				$done[] = [ 'login' => $c['login'], 'result' => 'skipped (' . $c['skip'] . ')' ];
				continue;
			}
			$fid = self::synthesise_finding( 'CU-USER', $c['target'], $c['reason'] );
			$res = Malroot_Quarantine::quarantine_finding( $fid );
			$done[] = [
				'login'  => $c['login'],
				'id'     => $c['id'],
				'result' => is_wp_error( $res ) ? $res->get_error_message() : 'removed (backed up, reversible)',
			];
		}
		return $done;
	}

	/* ================================================================== */
	/*  Step 4 — cloaking rules and spam payload                          */
	/* ================================================================== */

	/**
	 * Search-engine cloaking written into .htaccess, plus whatever file it
	 * redirects crawlers to.
	 */
	private static function find_payload() {
		$out      = [];
		$htaccess = self::htaccess_path();

		if ( $htaccess && is_readable( $htaccess ) ) {
			$body = (string) file_get_contents( $htaccess );
			foreach ( self::cloak_blocks( $body ) as $block ) {
				$out[] = [
					'kind'   => 'htaccess-cloak',
					'target' => '.htaccess',
					'reason' => __( 'Sends search engines to a different page than your visitors see', 'malroot-security' ),
					'detail' => $block['rule'],
					'file'   => $block['target_file'],
				];
				if ( $block['target_file'] ) {
					$abs = ABSPATH . ltrim( $block['target_file'], '/' );
					if ( file_exists( $abs ) && ! self::is_core_readme( $block['target_file'] ) ) {
						$out[] = [
							'kind'   => 'spam-page',
							'target' => ltrim( $block['target_file'], '/' ),
							'reason' => __( 'The page that was being shown to search engines instead of your site', 'malroot-security' ),
							'detail' => 'size=' . size_format( (int) filesize( $abs ) ),
							'file'   => '',
						];
					}
				}
			}
		}
		return $out;
	}

	private static function clean_payload() {
		$done     = [];
		$htaccess = self::htaccess_path();

		foreach ( self::find_payload() as $item ) {
			if ( 'spam-page' === $item['kind'] ) {
				$fid = self::synthesise_finding( 'CU-SPAM', $item['target'], $item['reason'] );
				$res = Malroot_Quarantine::quarantine_finding( $fid, true );
				$done[] = [
					'item'   => $item['target'],
					'result' => is_wp_error( $res ) ? $res->get_error_message() : 'removed (backed up, reversible)',
				];
				continue;
			}

			// Strip the cloaking rules, keeping a backup of the whole file.
			if ( ! $htaccess || ! is_writable( $htaccess ) ) {
				$done[] = [ 'item' => '.htaccess', 'result' => 'could not write .htaccess — edit it by hand' ];
				continue;
			}
			$body = (string) file_get_contents( $htaccess );
			$new  = self::strip_cloak( $body );
			if ( $new === $body ) {
				continue;
			}
			Malroot_Quarantine::backup_text( '.htaccess', $body );
			$fs = self::filesystem();
			if ( $fs && $fs->put_contents( $htaccess, $new ) ) {
				$done[] = [ 'item' => '.htaccess', 'result' => 'cloaking rules removed (original backed up)' ];
				$done[] = [ 'item' => 'permalinks', 'result' => self::ensure_permalink_rules( $htaccess ) ];
			} else {
				$done[] = [ 'item' => '.htaccess', 'result' => 'backup saved but write failed — edit it by hand' ];
			}
		}
		return $done;
	}

	/**
	 * Find crawler-cloaking blocks: a RewriteCond on HTTP_USER_AGENT naming
	 * search-engine bots, followed by a RewriteRule sending them elsewhere.
	 *
	 * @return array<int,array{rule:string,target_file:string}>
	 */
	private static function cloak_blocks( $body ) {
		$found = [];
		$lines = preg_split( '/\R/', (string) $body );
		$bots  = '/(googlebot|bingbot|slurp|duckduckbot|yandexbot|baiduspider|facebookexternalhit|twitterbot|applebot|ahrefs|semrush)/i';

		for ( $i = 0; $i < count( $lines ); $i++ ) {
			if ( ! preg_match( '/RewriteCond\s+%\{HTTP_USER_AGENT\}/i', $lines[ $i ] ) ) {
				continue;
			}
			if ( ! preg_match( $bots, $lines[ $i ] ) ) {
				continue;
			}
			// Look ahead for the rule that acts on the match.
			for ( $j = $i; $j < min( $i + 6, count( $lines ) ); $j++ ) {
				if ( preg_match( '/RewriteRule\s+\S+\s+(\/?\S+)/i', $lines[ $j ], $m ) ) {
					$dest = trim( $m[1] );
					if ( '-' === $dest ) {
						continue;
					}
					$dest = preg_replace( '/\s*\[.*$/', '', $dest );
					$found[] = [
						'rule'        => trim( $lines[ $i ] ) . ' → ' . trim( $lines[ $j ] ),
						'target_file' => ltrim( (string) $dest, '/' ),
					];
					$i = $j;
					break;
				}
			}
		}
		return $found;
	}

	/**
	 * Remove cloaking lines while leaving the rest of .htaccess intact.
	 */
	private static function strip_cloak( $body ) {
		$lines = preg_split( '/\R/', (string) $body );
		$bots  = '/(googlebot|bingbot|slurp|duckduckbot|yandexbot|baiduspider|facebookexternalhit|twitterbot|applebot)/i';
		$drop  = [];

		for ( $i = 0; $i < count( $lines ); $i++ ) {
			if ( ! preg_match( '/RewriteCond\s+%\{HTTP_USER_AGENT\}/i', $lines[ $i ] ) || ! preg_match( $bots, $lines[ $i ] ) ) {
				continue;
			}
			$drop[ $i ] = true;
			// Drop the contiguous cond/rule block that belongs to it.
			for ( $j = $i + 1; $j < min( $i + 6, count( $lines ) ); $j++ ) {
				if ( preg_match( '/^\s*RewriteCond/i', $lines[ $j ] ) ) {
					$drop[ $j ] = true;
					continue;
				}
				if ( preg_match( '/^\s*RewriteRule/i', $lines[ $j ] ) ) {
					$drop[ $j ] = true;
					$i = $j;
					break;
				}
				break;
			}
		}

		if ( ! $drop ) {
			return $body;
		}

		$out = [];
		foreach ( $lines as $n => $line ) {
			if ( isset( $drop[ $n ] ) ) {
				continue;
			}
			$out[] = $line;
		}
		return implode( "\n", $out );
	}

	/**
	 * Make sure .htaccess still routes requests to WordPress.
	 *
	 * Removing the cloaking rules is only half the job. The attacker on
	 * cityagecare.com had replaced the whole file, so the "# BEGIN WordPress"
	 * block was already gone — stripping the cloak left a file with
	 * RewriteEngine On and nothing to route to index.php. Every page on the site
	 * then returned a bare Apache 404 immediately after a "successful" cleanup,
	 * which looks far worse than the infection did.
	 *
	 * WordPress writes this block itself, so let it: flush_rewrite_rules() with a
	 * hard flush calls save_mod_rewrite_rules(), which uses the same marker-aware
	 * writer core uses on the Permalinks screen.
	 *
	 * @param string $htaccess Absolute path.
	 * @return string Human-readable outcome.
	 */
	private static function ensure_permalink_rules( $htaccess ) {
		$body = is_readable( $htaccess ) ? (string) file_get_contents( $htaccess ) : '';

		if ( false !== strpos( $body, '# BEGIN WordPress' ) ) {
			return 'already present, left alone';
		}
		// A site using plain permalinks needs no rules at all.
		if ( '' === (string) get_option( 'permalink_structure', '' ) ) {
			return 'not needed (site uses plain permalinks)';
		}

		if ( ! function_exists( 'save_mod_rewrite_rules' ) ) {
			require_once ABSPATH . 'wp-admin/includes/misc.php';
		}

		global $wp_rewrite;
		if ( ! $wp_rewrite ) {
			return 'could not add automatically — open Settings > Permalinks and click Save';
		}

		// Preferred route: let WordPress write the block itself.
		flush_rewrite_rules( true );

		if ( self::has_wp_block( $htaccess ) ) {
			return self::log_permalink_restore();
		}

		// Fallback: write the rules directly.
		//
		// save_mod_rewrite_rules() is gated behind got_mod_rewrite(), which
		// depends on apache_get_modules() being available. That function does not
		// exist under LiteSpeed or PHP-FPM, so on exactly the kind of hosting
		// this site runs the gate can refuse even though rewriting works fine.
		// The rules themselves come from $wp_rewrite, and insert_with_markers is
		// the same marker-aware writer core uses, so this is not a shortcut —
		// only the environment sniff is skipped.
		if ( ! is_writable( $htaccess ) ) {
			return 'could not write .htaccess — open Settings > Permalinks and click Save';
		}
		if ( ! function_exists( 'insert_with_markers' ) ) {
			require_once ABSPATH . 'wp-admin/includes/misc.php';
		}

		$rules = explode( "\n", $wp_rewrite->mod_rewrite_rules() );
		$rules = array_filter( $rules, static function ( $line ) {
			return '' !== trim( (string) $line );
		} );
		if ( ! $rules ) {
			return 'could not add automatically — open Settings > Permalinks and click Save';
		}

		insert_with_markers( $htaccess, 'WordPress', array_values( $rules ) );

		return self::has_wp_block( $htaccess )
			? self::log_permalink_restore()
			: 'rules still missing — open Settings > Permalinks and click Save';
	}

	private static function has_wp_block( $htaccess ) {
		$body = is_readable( $htaccess ) ? (string) file_get_contents( $htaccess ) : '';
		return false !== strpos( $body, '# BEGIN WordPress' );
	}

	private static function log_permalink_restore() {
		if ( class_exists( 'Malroot_Logger' ) ) {
			Malroot_Logger::info( 'Restored WordPress permalink rules that the attacker had removed' );
		}
		return 'WordPress rewrite rules were missing and have been restored';
	}

	/**
	 * WordPress ships readme.html, so do not offer to delete the genuine one.
	 *
	 * The comparison must be case-SENSITIVE. On cityagecare.com the spam page
	 * was named `Readme.html` with a capital R, sitting alongside WordPress' own
	 * lowercase `readme.html`. On a case-sensitive filesystem those are two
	 * different files, and lowercasing the name here caused the 531 KB spam page
	 * to be mistaken for the core file and left in place.
	 *
	 * The name alone is not trusted either: the real readme identifies itself in
	 * its first few hundred bytes.
	 */
	private static function is_core_readme( $rel ) {
		$rel = ltrim( (string) $rel, '/' );
		if ( 'readme.html' !== $rel ) {
			return false; // any other spelling, including Readme.html, is fair game
		}

		$abs = ABSPATH . $rel;
		if ( ! is_readable( $abs ) ) {
			return true; // nothing to remove anyway
		}
		$fh = @fopen( $abs, 'rb' );
		if ( ! $fh ) {
			return true;
		}
		$head = (string) fread( $fh, 2048 );
		fclose( $fh );

		// Genuine core readme announces WordPress and links wordpress.org.
		return (bool) preg_match( '/wordpress/i', $head )
			&& ! preg_match( '/document\.write|atob\s*\(|eval\s*\(/i', $head );
	}

	private static function htaccess_path() {
		if ( ! function_exists( 'get_home_path' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		$candidates = [ get_home_path() . '.htaccess', ABSPATH . '.htaccess' ];
		foreach ( $candidates as $path ) {
			if ( file_exists( $path ) ) {
				return $path;
			}
		}
		return '';
	}

	/* ------------------------------------------------------------------ */
	/*  Shared helpers                                                    */
	/* ------------------------------------------------------------------ */

	/**
	 * Insert a finding row so the existing quarantine pipeline can act on it,
	 * and so the action is visible in the findings history afterwards.
	 */
	private static function synthesise_finding( $rule_id, $target, $summary ) {
		return (int) Malroot_Findings::record( [
			'scan_id'  => (int) get_option( 'malroot_last_scan', time() ),
			'module'   => 'cleanup',
			'rule_id'  => $rule_id,
			'severity' => 'critical',
			'target'   => $target,
			'summary'  => $summary,
			'details'  => 'Queued by guided cleanup',
			'status'   => 'open',
		] );
	}

	private static function list_files( $dir ) {
		$out = [];
		if ( ! is_dir( $dir ) ) {
			return $out;
		}
		try {
			$it = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::CHILD_FIRST
			);
			foreach ( $it as $f ) {
				if ( $f->isFile() ) {
					$out[] = $f->getPathname();
				}
			}
		} catch ( Throwable $e ) {
			return $out;
		}
		return $out;
	}

	private static function remove_empty_dirs( $dir ) {
		if ( ! is_dir( $dir ) ) {
			return;
		}
		$fs = self::filesystem();
		if ( ! $fs ) {
			return;
		}
		try {
			$it = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::CHILD_FIRST
			);
			foreach ( $it as $f ) {
				if ( $f->isDir() ) {
					$fs->rmdir( $f->getPathname() );
				}
			}
		} catch ( Throwable $e ) {
			return;
		}
		$fs->rmdir( $dir );
	}

	private static function filesystem() {
		global $wp_filesystem;
		if ( $wp_filesystem instanceof WP_Filesystem_Base ) {
			return $wp_filesystem;
		}
		if ( ! function_exists( 'WP_Filesystem' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		if ( WP_Filesystem() && $wp_filesystem instanceof WP_Filesystem_Base ) {
			return $wp_filesystem;
		}
		return null;
	}
}
