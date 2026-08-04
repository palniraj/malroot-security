<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Auto-quarantine: safely neutralise findings without losing data.
 *
 * - Files: move into a private quarantine directory inside this plugin,
 *   protected by .htaccess from HTTP access.
 * - DB options: back up to quarantine table, then delete.
 * - DB users: demote to "subscriber", null the password, prefix login with
 *   "QUARANTINED_". Original row backed up so it can be restored.
 * - MySQL triggers: back up the DDL, then DROP TRIGGER.
 *
 * Every action is reversible via restore().
 */
class Malroot_Quarantine {

	const STATUS_OPEN     = 'open';
	const STATUS_QUARANT  = 'quarantined';
	const STATUS_RESTORED = 'restored';

	public static function table() {
		global $wpdb;
		return $wpdb->prefix . 'malroot_quarantine';
	}

	public static function dir() {
		// Backed up file contents are stored in the database (see record_log),
		// not on disk. This method is kept only for backward compatibility with
		// any older quarantine records that still reference an on-disk copy.
		$uploads = wp_upload_dir();
		if ( empty( $uploads['basedir'] ) ) {
			return '';
		}
		return $uploads['basedir'] . '/malroot-security/quarantine';
	}

	/**
	 * Is this path part of WordPress core, an installed plugin, or an
	 * installed theme?
	 *
	 * Files that belong to real, installed software must never be destroyed by
	 * an automated or one-click "remove everything" action — a single false
	 * positive (e.g. a heuristic matching legitimate plugin code) would
	 * otherwise take the whole site down. Such findings are surfaced for the
	 * operator to handle deliberately (deactivate / reinstall the plugin),
	 * not bulk-deleted.
	 *
	 * mu-plugins are intentionally NOT treated as protected: a self-healing
	 * loader dropped into mu-plugins is a known malware persistence trick and
	 * must stay removable.
	 *
	 * @param string $rel_path Path relative to ABSPATH (as stored in findings).
	 * @return string|false  A label ('wordpress-core'|'plugin'|'theme') or false.
	 */
	public static function protected_software_kind( $rel_path ) {
		$abs = wp_normalize_path( ABSPATH . ltrim( (string) $rel_path, '/' ) );

		// WordPress core directories.
		$core_dirs = [
			wp_normalize_path( ABSPATH . 'wp-admin' ) . '/',
			wp_normalize_path( ABSPATH . WPINC ) . '/',
		];
		foreach ( $core_dirs as $dir ) {
			if ( strpos( $abs, $dir ) === 0 ) {
				return 'wordpress-core';
			}
		}

		// Installed plugins — but only files that live *inside* a plugin's own
		// sub-directory. A stray file dropped directly into /plugins/ is not a
		// real plugin and stays removable.
		if ( defined( 'WP_PLUGIN_DIR' ) ) {
			$plugins_dir = wp_normalize_path( WP_PLUGIN_DIR ) . '/';
			if ( strpos( $abs, $plugins_dir ) === 0 ) {
				$inner = substr( $abs, strlen( $plugins_dir ) );
				if ( strpos( $inner, '/' ) !== false ) {
					return 'plugin';
				}
			}
		}

		// Installed themes (covers the default themes dir and any registered
		// theme roots).
		$theme_roots = [];
		if ( function_exists( 'get_theme_root' ) ) {
			$theme_roots[] = get_theme_root();
		}
		if ( defined( 'WP_CONTENT_DIR' ) ) {
			$theme_roots[] = WP_CONTENT_DIR . '/themes';
		}
		foreach ( array_unique( $theme_roots ) as $root ) {
			$root = wp_normalize_path( $root ) . '/';
			if ( strpos( $abs, $root ) === 0 ) {
				$inner = substr( $abs, strlen( $root ) );
				if ( strpos( $inner, '/' ) !== false ) {
					return 'theme';
				}
			}
		}

		return false;
	}

	/**
	 * Quarantine a finding by ID. Routes to the right handler based on the
	 * finding's target string.
	 *
	 * @param int  $finding_id      Finding row ID.
	 * @param bool $allow_protected When false (the default, used by automated
	 *                              and bulk actions), files belonging to WP
	 *                              core / installed plugins / installed themes
	 *                              are refused so a false positive cannot break
	 *                              the site. A deliberate, individually
	 *                              confirmed removal may pass true.
	 * @return true|WP_Error
	 */
	public static function quarantine_finding( $finding_id, $allow_protected = false ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$f = $wpdb->get_row( $wpdb->prepare(
			"SELECT * FROM {$wpdb->prefix}malroot_findings WHERE id = %d", $finding_id
		) );
		if ( ! $f ) {
			return new WP_Error( 'not_found', __( 'Finding not found.', 'malroot-security' ) );
		}
		if ( $f->status === 'fixed' ) {
			return new WP_Error( 'already_fixed', __( 'Finding already fixed.', 'malroot-security' ) );
		}

		$target = (string) $f->target;
		$ok = false;
		$type = '';

		// Route by target prefix
		if ( strpos( $target, 'options:' ) === 0 ) {
			$ok = self::quarantine_option( substr( $target, 8 ) );
			$type = 'option';
		} elseif ( strpos( $target, 'users:' ) === 0 ) {
			$ok = self::quarantine_user( $target );
			$type = 'user';
		} elseif ( strpos( $target, 'trigger:' ) === 0 ) {
			$ok = self::quarantine_trigger( substr( $target, 8 ) );
			$type = 'trigger';
		} elseif ( strpos( $target, 'event:' ) === 0 ) {
			$ok = self::quarantine_event( substr( $target, 6 ) );
			$type = 'event';
		} elseif ( strpos( $target, 'wp-cron:' ) === 0 ) {
			$ok = self::quarantine_cron_hook( substr( $target, 8 ) );
			$type = 'wp-cron';
		} elseif ( strpos( $target, 'postmeta:' ) === 0 ) {
			$ok = self::quarantine_postmeta_key( substr( $target, 9 ) );
			$type = 'postmeta';
		} elseif ( strpos( $target, 'rest:' ) === 0 ) {
			// REST routes can't be force-removed at runtime; mark for review
			return new WP_Error( 'manual_action', __( 'REST routes cannot be auto-quarantined. Disable the plugin that registers them.', 'malroot-security' ) );
		} else {
			// Treat as a file path relative to ABSPATH
			$ok = self::quarantine_file( $target, $allow_protected );
			$type = 'file';
		}

		if ( is_wp_error( $ok ) ) {
			return $ok;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->update(
			$wpdb->prefix . 'malroot_findings',
			[ 'status' => 'fixed' ],
			[ 'id' => $f->id ],
			[ '%s' ],
			[ '%d' ]
		);
		Malroot_Logger::info( 'Quarantined finding', [ 'finding_id' => $finding_id, 'type' => $type, 'target' => $target ] );
		return true;
	}

	/* ---------------------------------------------------------------- */
	/*  File handler                                                    */
	/* ---------------------------------------------------------------- */

	private static function quarantine_file( $rel_path, $allow_protected = false ) {
		$rel_path = ltrim( $rel_path, '/' );

		// Safety gate: never let an automated or bulk action destroy a file
		// that belongs to WordPress core, an installed plugin, or an installed
		// theme. A heuristic false positive on legitimate code would otherwise
		// blank out a required class file and take the whole site down.
		if ( ! $allow_protected ) {
			$kind = self::protected_software_kind( $rel_path );
			if ( $kind ) {
				$labels = [
					'wordpress-core' => __( 'WordPress core', 'malroot-security' ),
					'plugin'         => __( 'an installed plugin', 'malroot-security' ),
					'theme'          => __( 'an installed theme', 'malroot-security' ),
				];
				$label = $labels[ $kind ] ?? __( 'installed software', 'malroot-security' );
				return new WP_Error(
					'protected_software',
					sprintf(
						/* translators: 1: file path, 2: software type, e.g. "an installed plugin" */
						__( '%1$s is part of %2$s and was not removed automatically. Removing files from installed software can break your site. If you believe this file is malicious, deactivate and reinstall that plugin/theme from a clean source instead.', 'malroot-security' ),
						esc_html( $rel_path ),
						$label
					)
				);
			}
		}

		$abs = ABSPATH . $rel_path;
		if ( ! file_exists( $abs ) ) {
			return new WP_Error( 'no_file', __( 'File no longer exists.', 'malroot-security' ) );
		}

		// Large files are recorded, not copied into the database.
		//
		// Backups are stored base64-encoded in a LONGTEXT column, which adds
		// about a third to the size. Cleaning the kit from cityagecare.com put
		// 58 MB into this table and took a 17 MB database export to 76 MB — a
		// single 16 MB reverse-shell toolkit became 21 MB of base64, and the
		// duplicate below made it 43 MB. That bloats every future backup, slows
		// exports, and risks max_allowed_packet failures on re-import.
		//
		// Nobody wants to restore a 16 MB attack toolkit, so above the threshold
		// the file's identity is preserved (hash, size, permissions) and the
		// bytes are not. Anything genuinely needed can be recovered from the
		// operator's own site backup using the hash to confirm it is the same
		// file.
		$size = (int) @filesize( $abs );
		if ( $size > self::max_backup_bytes() ) {
			self::record_log( 'file', $rel_path, [
				'content_b64' => '',
				'size'        => $size,
				'sha256'      => @hash_file( 'sha256', $abs ),
				'perms'       => @fileperms( $abs ) & 0777,
				'method'      => 'metadata-only+delete',
				'note'        => sprintf(
					'File was %s, above the %s backup limit. Identity recorded; contents not stored.',
					size_format( $size ),
					size_format( self::max_backup_bytes() )
				),
			] );

			wp_delete_file( $abs );

			if ( file_exists( $abs ) ) {
				return new WP_Error(
					'move_failed',
					sprintf(
						/* translators: %s: file path */
						__( 'Recorded %s but could not delete it automatically (it is owned by a different system user). Use your hosting file manager or FTP to delete it.', 'malroot-security' ),
						esc_html( $rel_path )
					)
				);
			}
			return true;
		}

		// Back the file up into the database (base64), then delete it from disk.
		//
		// We deliberately do NOT move or copy the file into the uploads folder
		// or the plugin folder, and we never write a PHP stub over it: storing
		// code-containing files under those locations is not permitted, and
		// quarantined files would be publicly readable there. Keeping the
		// backup as inert data in a private DB table avoids all of that while
		// still allowing a full restore.
		$contents = self::read_file_contents( $abs );
		if ( $contents === false ) {
			return new WP_Error(
				'read_failed',
				sprintf(
					/* translators: %s: file path */
					__( 'Could not read %s to back it up. Use your hosting file manager or FTP to remove it manually.', 'malroot-security' ),
					esc_html( $rel_path )
				)
			);
		}

		self::record_log( 'file', $rel_path, [
			'content_b64' => base64_encode( $contents ),
			'size'        => strlen( $contents ),
			'perms'       => @fileperms( $abs ) & 0777,
			'method'      => 'db-backup+delete',
		] );

		// Delete using the WordPress filesystem helper.
		wp_delete_file( $abs );

		if ( file_exists( $abs ) ) {
			// Deletion failed — almost always because the file is owned by a
			// different system user than PHP. We have a safe backup in the DB,
			// but the operator must remove the live file themselves.
			return new WP_Error(
				'move_failed',
				sprintf(
					/* translators: %s: file path */
					__( 'Backed up %s, but could not delete it automatically (it is owned by a different system user). Use your hosting file manager or FTP to delete it.', 'malroot-security' ),
					esc_html( $rel_path )
				)
			);
		}

		return true;
	}

	/**
	 * Read a file's raw bytes via the WordPress filesystem API.
	 *
	 * @return string|false
	 */
	private static function read_file_contents( $abs ) {
		$fs = self::filesystem();
		if ( $fs ) {
			$data = $fs->get_contents( $abs );
			if ( $data !== false ) {
				return $data;
			}
		}
		return false;
	}

	/**
	 * Initialise and return the WP_Filesystem instance, or null if unavailable.
	 */
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

	/* ---------------------------------------------------------------- */
	/*  Option handler                                                  */
	/* ---------------------------------------------------------------- */

	private static function quarantine_option( $option_name ) {
		$value = get_option( $option_name, null );
		if ( $value === null ) {
			return new WP_Error( 'no_option', __( 'Option no longer exists.', 'malroot-security' ) );
		}
		self::record_log( 'option', $option_name, [ 'value' => maybe_serialize( $value ) ] );
		delete_option( $option_name );
		return true;
	}

	private static function quarantine_postmeta_key( $meta_key ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows = $wpdb->get_results( $wpdb->prepare(
			"SELECT post_id, meta_value FROM {$wpdb->postmeta} WHERE meta_key = %s",
			$meta_key
		), ARRAY_A );
		self::record_log( 'postmeta', $meta_key, [ 'rows' => $rows ] );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- deleting by the indexed meta_key column; not a WP_Query meta_value lookup.
		$wpdb->delete( $wpdb->postmeta, [ 'meta_key' => $meta_key ], [ '%s' ] );
		return true;
	}

	/* ---------------------------------------------------------------- */
	/*  User handler                                                    */
	/* ---------------------------------------------------------------- */

	private static function quarantine_user( $target ) {
		// Target format: "users:LOGIN#ID" or "users:LOGIN"
		$rest = substr( $target, 6 );
		$id = 0;
		$login = $rest;
		if ( strpos( $rest, '#' ) !== false ) {
			list( $login, $id ) = explode( '#', $rest, 2 );
			$id = (int) $id;
		}
		global $wpdb;
		if ( $id ) {
			$users = [ get_userdata( $id ) ];
		} else {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$user_ids = $wpdb->get_col( $wpdb->prepare(
				"SELECT ID FROM {$wpdb->users} WHERE user_login = %s", $login
			) );
			$users = array_filter( array_map( 'get_userdata', $user_ids ) );
		}
		if ( ! $users ) {
			return new WP_Error( 'no_user', __( 'User no longer exists.', 'malroot-security' ) );
		}

		require_once ABSPATH . 'wp-admin/includes/user.php';

		foreach ( $users as $u ) {
			if ( ! $u ) continue;
			// Don't ever quarantine the user running this action
			if ( get_current_user_id() === (int) $u->ID ) {
				return new WP_Error( 'self', __( 'Refusing to quarantine yourself.', 'malroot-security' ) );
			}
			// Back up everything we need to restore the user later
			$backup = [
				'ID'              => $u->ID,
				'user_login'      => $u->user_login,
				'user_pass'       => $u->user_pass,
				'user_email'      => $u->user_email,
				'user_registered' => $u->user_registered,
				'roles'           => $u->roles,
				'meta'            => get_user_meta( $u->ID ),
			];
			self::record_log( 'user', $u->user_login . '#' . $u->ID, [ 'backup' => $backup ] );

			// Reassign the user's content to user 1 so deletion is safe
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			wp_delete_user( $u->ID, 1 );
		}
		return true;
	}

	/* ---------------------------------------------------------------- */
	/*  Trigger / event handler                                         */
	/* ---------------------------------------------------------------- */

	private static function quarantine_trigger( $trigger_name ) {
		global $wpdb;
		$dbname = $wpdb->dbname;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$row = $wpdb->get_row( $wpdb->prepare(
			"SELECT TRIGGER_NAME, EVENT_OBJECT_TABLE, ACTION_TIMING, EVENT_MANIPULATION, ACTION_STATEMENT
			 FROM information_schema.TRIGGERS
			 WHERE TRIGGER_SCHEMA = %s AND TRIGGER_NAME = %s",
			$dbname, $trigger_name
		) );
		if ( ! $row ) {
			return new WP_Error( 'no_trigger', __( 'Trigger no longer exists.', 'malroot-security' ) );
		}
		self::record_log( 'trigger', $trigger_name, [ 'definition' => (array) $row ] );

		// Identifier needs to be quoted; trigger names cannot contain backticks.
		$safe_name = preg_replace( '/[^A-Za-z0-9_]/', '', $trigger_name );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.SchemaChange
		$wpdb->query( "DROP TRIGGER IF EXISTS `{$safe_name}`" );
		return true;
	}

	/**
	 * Unschedule a WP-Cron hook.
	 *
	 * Distinct from quarantine_event(), which drops a MySQL EVENT. Malware far
	 * more commonly persists through WP-Cron: the backdoor found on
	 * cityagecare.com registered a daily `bbp_license_sync` job that recreated
	 * its administrator account. Deleting the account and the files without
	 * clearing this job means the account simply comes back the next day, which
	 * is why "we cleaned it and it returned" is such a common experience.
	 *
	 * The full schedule is backed up first, so it can be reinstated.
	 *
	 * @param string $hook Cron hook name.
	 * @return true|WP_Error
	 */
	private static function quarantine_cron_hook( $hook ) {
		$hook = trim( (string) $hook );
		if ( '' === $hook ) {
			return new WP_Error( 'no_hook', __( 'No cron hook given.', 'malroot-security' ) );
		}

		// Never let this be turned against our own scheduled scan.
		if ( 0 === strpos( $hook, 'malroot_' ) ) {
			return new WP_Error( 'refused', __( 'Refusing to unschedule Malroot\'s own maintenance job.', 'malroot-security' ) );
		}

		$crons   = (array) _get_cron_array();
		$backup  = [];
		$removed = 0;

		foreach ( $crons as $timestamp => $groups ) {
			if ( ! is_array( $groups ) || ! isset( $groups[ $hook ] ) ) {
				continue;
			}
			foreach ( (array) $groups[ $hook ] as $key => $event ) {
				$backup[] = [
					'timestamp' => $timestamp,
					'schedule'  => $event['schedule'] ?? false,
					'interval'  => $event['interval'] ?? null,
					'args'      => $event['args'] ?? [],
				];
				$removed++;
			}
		}

		if ( 0 === $removed ) {
			return new WP_Error( 'no_hook', __( 'That scheduled job no longer exists.', 'malroot-security' ) );
		}

		self::record_log( 'wp-cron', $hook, [ 'events' => $backup ] );

		// Remove every occurrence, whatever arguments it was scheduled with.
		foreach ( $backup as $event ) {
			wp_unschedule_event( $event['timestamp'], $hook, (array) $event['args'] );
		}
		// Belt and braces: clears any occurrence the loop above missed.
		wp_clear_scheduled_hook( $hook );

		return true;
	}

	private static function quarantine_event( $event_name ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$row = $wpdb->get_row( $wpdb->prepare(
			"SELECT EVENT_NAME, EVENT_DEFINITION, STATUS
			 FROM information_schema.EVENTS
			 WHERE EVENT_SCHEMA = %s AND EVENT_NAME = %s",
			$wpdb->dbname, $event_name
		) );
		if ( ! $row ) {
			return new WP_Error( 'no_event', __( 'Event no longer exists.', 'malroot-security' ) );
		}
		self::record_log( 'event', $event_name, [ 'definition' => (array) $row ] );
		$safe_name = preg_replace( '/[^A-Za-z0-9_]/', '', $event_name );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.SchemaChange
		$wpdb->query( "DROP EVENT IF EXISTS `{$safe_name}`" );
		return true;
	}

	/* ---------------------------------------------------------------- */
	/*  Backup log + restore                                            */
	/* ---------------------------------------------------------------- */

	/**
	 * Back up arbitrary text before it is rewritten in place.
	 *
	 * Used when a file must be edited rather than removed — stripping cloaking
	 * rules out of .htaccess, for example, where deleting the whole file would
	 * break permalinks. Restores through the normal 'file' path.
	 *
	 * @param string $rel_path Path relative to ABSPATH, for the record.
	 * @param string $contents Original contents.
	 */
	public static function backup_text( $rel_path, $contents ) {
		self::record_log( 'file', ltrim( (string) $rel_path, '/' ), [
			'content_b64' => base64_encode( (string) $contents ),
			'size'        => strlen( (string) $contents ),
			'method'      => 'edit-in-place-backup',
		] );
	}

	/**
	 * Largest file whose contents are copied into the database.
	 * Filterable so an operator with different priorities can change it.
	 */
	public static function max_backup_bytes() {
		return (int) apply_filters( 'malroot_max_backup_bytes', 2 * 1024 * 1024 );
	}

	private static function record_log( $type, $target, array $payload ) {
		global $wpdb;
		$json = wp_json_encode( $payload );

		// Do not store the same backup twice.
		//
		// Running a cleanup a second time previously appended another full copy
		// of every file. On cityagecare.com that stored a 21 MB base64 blob
		// twice, accounting for 43 MB of a 58 MB table. A repeated removal of
		// identical content adds nothing recoverable, so refresh the timestamp on
		// the existing record instead.
		$fingerprint = hash( 'sha256', $type . '|' . $target . '|' . $json );
		$table       = self::table();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
		$existing = $wpdb->get_var( $wpdb->prepare(
			"SELECT id FROM {$table} WHERE item_type = %s AND target = %s AND SHA2(CONCAT(item_type,'|',target,'|',payload_json),256) = %s LIMIT 1",
			$type,
			$target,
			$fingerprint
		) );

		if ( $existing ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->update(
				$table,
				[ 'status' => self::STATUS_QUARANT, 'created_at' => current_time( 'mysql' ) ],
				[ 'id' => (int) $existing ],
				[ '%s', '%s' ],
				[ '%d' ]
			);
			return;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->insert(
			self::table(),
			[
				'item_type'    => $type,
				'target'       => $target,
				'payload_json' => $json,
				'status'       => self::STATUS_QUARANT,
				'created_at'   => current_time( 'mysql' ),
			],
			[ '%s', '%s', '%s', '%s', '%s' ]
		);
	}

	public static function restore( $quarantine_id ) {
		global $wpdb;
		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
		$row = $wpdb->get_row( $wpdb->prepare(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			"SELECT * FROM {$table} WHERE id = %d", $quarantine_id
		) );
		if ( ! $row ) {
			return new WP_Error( 'no_row', __( 'Quarantine record not found.', 'malroot-security' ) );
		}
		if ( $row->status === self::STATUS_RESTORED ) {
			return new WP_Error( 'already', __( 'Already restored.', 'malroot-security' ) );
		}
		$payload = json_decode( $row->payload_json, true );

		switch ( $row->item_type ) {
			case 'file':
				$abs = ABSPATH . ltrim( $row->target, '/' );

				// Metadata-only record: the file was too large to copy into the
				// database. Refuse rather than writing an empty file over the
				// path, which is what an empty content_b64 would otherwise do.
				if ( isset( $payload['content_b64'] ) && '' === $payload['content_b64'] ) {
					return new WP_Error(
						'metadata_only',
						sprintf(
							/* translators: 1: file size, 2: sha256 hash */
							__( 'This file was %1$s, too large to keep a copy of, so only its identity was recorded (SHA-256 %2$s). Restore it from your own site backup if you need it.', 'malroot-security' ),
							isset( $payload['size'] ) ? size_format( (int) $payload['size'] ) : __( 'very large', 'malroot-security' ),
							esc_html( substr( (string) ( $payload['sha256'] ?? '' ), 0, 16 ) )
						)
					);
				}

				// Current format: contents are stored (base64) in the DB.
				if ( ! empty( $payload['content_b64'] ) ) {
					$bytes = base64_decode( $payload['content_b64'] );
					if ( $bytes === false ) {
						return new WP_Error( 'missing', __( 'Quarantined backup is corrupt.', 'malroot-security' ) );
					}
					$fs = self::filesystem();
					if ( ! $fs ) {
						return new WP_Error( 'restore_failed', __( 'Could not access the filesystem to restore this file.', 'malroot-security' ) );
					}
					$fs->mkdir( dirname( $abs ) );
					if ( ! $fs->put_contents( $abs, $bytes ) ) {
						return new WP_Error( 'restore_failed', sprintf(
							/* translators: %s: file path */
							__( 'Could not restore %s — filesystem permission issue. Check that the destination folder is writable.', 'malroot-security' ),
							esc_html( $row->target )
						) );
					}
					if ( ! empty( $payload['perms'] ) ) {
						$fs->chmod( $abs, (int) $payload['perms'] );
					}
					break;
				}

				// Legacy format: an on-disk copy under the old quarantine dir.
				if ( ! empty( $payload['dest'] ) && file_exists( $payload['dest'] ) ) {
					$bytes = self::read_file_contents( $payload['dest'] );
					$fs    = self::filesystem();
					if ( $bytes !== false && $fs ) {
						$fs->mkdir( dirname( $abs ) );
						if ( $fs->put_contents( $abs, $bytes ) ) {
							wp_delete_file( $payload['dest'] );
							break;
						}
					}
				}

				return new WP_Error( 'missing', __( 'Quarantined backup is no longer available.', 'malroot-security' ) );

			case 'option':
				update_option( $row->target, maybe_unserialize( $payload['value'] ?? '' ) );
				break;

			case 'postmeta':
				foreach ( (array) ( $payload['rows'] ?? [] ) as $r ) {
					// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- restoring previously quarantined rows.
					$wpdb->insert( $wpdb->postmeta, [
						'post_id'    => (int) $r['post_id'],
						'meta_key'   => $row->target, // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- INSERT column name, not a WP_Query meta lookup.
						'meta_value' => $r['meta_value'], // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_value -- INSERT column name, not a WP_Query meta lookup.
					], [ '%d', '%s', '%s' ] );
				}
				break;

			case 'wp-cron':
				foreach ( (array) ( $payload['events'] ?? [] ) as $event ) {
					$args = (array) ( $event['args'] ?? [] );
					if ( ! empty( $event['schedule'] ) ) {
						wp_schedule_event( (int) $event['timestamp'], $event['schedule'], $row->target, $args );
					} else {
						wp_schedule_single_event( (int) $event['timestamp'], $row->target, $args );
					}
				}
				break;

			case 'user':
				return new WP_Error( 'manual', __( 'User restore is manual: see backup payload in the quarantine table.', 'malroot-security' ) );

			case 'trigger':
			case 'event':
				return new WP_Error( 'manual', __( 'Trigger/event restore is manual: see backup payload in the quarantine table.', 'malroot-security' ) );
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->update( self::table(), [ 'status' => self::STATUS_RESTORED ], [ 'id' => $row->id ] );
		return true;
	}
}
