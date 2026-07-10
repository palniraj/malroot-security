<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * File integrity baseline.
 *
 *  - On first scan, hashes every PHP/JS/HT* file under the WP install
 *    and stores it in wp_malroot_baseline.
 *  - Subsequent scans compare current hashes against the baseline and
 *    flag NEW, MODIFIED, and DELETED files.
 *  - Operator can choose to "approve" the current state at any time
 *    which rewrites the baseline.
 */
class Malroot_Baseline {

	const TABLE = 'malroot_baseline';

	/** Option storing the plugin/theme/core versions captured at baseline time. */
	const VERSIONS_OPT = 'malroot_baseline_versions';

	public static function table() {
		global $wpdb;
		return $wpdb->prefix . self::TABLE;
	}

	/* ---------------------------------------------------------------- */
	/*  Component version tracking (update-churn suppression)           */
	/* ---------------------------------------------------------------- */

	/**
	 * Snapshot the installed version of WordPress core and every plugin/theme.
	 * Keyed as 'core', 'plugin:{slug}', 'theme:{slug}'.
	 */
	public static function capture_versions() {
		$versions = [ 'core' => get_bloginfo( 'version' ) ];

		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		foreach ( get_plugins() as $file => $data ) {
			$slug = strtok( (string) $file, '/' );
			if ( $slug ) {
				$versions[ 'plugin:' . $slug ] = (string) ( $data['Version'] ?? '' );
			}
		}

		if ( function_exists( 'wp_get_themes' ) ) {
			foreach ( wp_get_themes() as $slug => $theme ) {
				$versions[ 'theme:' . $slug ] = (string) $theme->get( 'Version' );
			}
		}

		return $versions;
	}

	/** Persist the current component versions as the accepted baseline (used on full rebuild). */
	public static function sync_versions() {
		update_option( self::VERSIONS_OPT, self::capture_versions(), false );
	}

	/**
	 * After a scan, advance the recorded version only for components whose
	 * version actually changed (their update churn was just accepted) and
	 * register any newly installed components. Components with an unchanged
	 * version keep their recorded version, so tampering within the SAME version
	 * still surfaces on the next scan. Does nothing if no baseline versions were
	 * ever captured — that requires a full snapshot first.
	 */
	public static function reconcile_versions() {
		$base = self::get_baseline_versions();
		if ( empty( $base ) ) {
			return;
		}
		$current = self::capture_versions();
		$changed = false;
		foreach ( $current as $key => $ver ) {
			if ( ! array_key_exists( $key, $base ) || $base[ $key ] !== $ver ) {
				$base[ $key ] = $ver;
				$changed = true;
			}
		}
		if ( $changed ) {
			update_option( self::VERSIONS_OPT, $base, false );
		}
	}

	public static function get_baseline_versions() {
		return (array) get_option( self::VERSIONS_OPT, [] );
	}

	/**
	 * Paths WordPress manages automatically, where churn is expected and benign:
	 *   - wp-content/languages: translation files updated by core/plugins/themes
	 *   - wp-content/upgrade:   temporary files during updates
	 * Changes here are never a meaningful attack signal on their own.
	 */
	public static function is_auto_managed_path( $rel_path ) {
		return (bool) preg_match( '#^wp-content/(languages|upgrade)/#', $rel_path );
	}

	/** Which component (core/plugin/theme) does a relative path belong to? */
	public static function component_key( $rel_path ) {
		if ( preg_match( '#^wp-content/plugins/([^/]+)/#', $rel_path, $m ) ) {
			return 'plugin:' . $m[1];
		}
		if ( preg_match( '#^wp-content/themes/([^/]+)/#', $rel_path, $m ) ) {
			return 'theme:' . $m[1];
		}
		if ( preg_match( '#^wp-(admin|includes)/#', $rel_path ) ) {
			return 'core';
		}
		// Core root files (index.php, wp-load.php, …) with no directory prefix.
		if ( false === strpos( $rel_path, '/' ) && preg_match( '/\.php$/i', $rel_path ) ) {
			return 'core';
		}
		return null;
	}

	/** Current installed version for a component key, or '' if unknown. */
	private static function current_version( $key ) {
		if ( 'core' === $key ) {
			return get_bloginfo( 'version' );
		}
		if ( 0 === strpos( $key, 'plugin:' ) ) {
			$slug = substr( $key, 7 );
			if ( ! function_exists( 'get_plugins' ) ) {
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
			}
			foreach ( get_plugins() as $file => $data ) {
				if ( strtok( (string) $file, '/' ) === $slug ) {
					return (string) ( $data['Version'] ?? '' );
				}
			}
			return '';
		}
		if ( 0 === strpos( $key, 'theme:' ) ) {
			$slug  = substr( $key, 6 );
			$theme = wp_get_theme( $slug );
			return $theme->exists() ? (string) $theme->get( 'Version' ) : '';
		}
		return '';
	}

	/**
	 * Is a file change explained by a legitimate version update of the plugin,
	 * theme, or core it belongs to? If the component's version differs from the
	 * one recorded at baseline time, the change is expected update churn — not
	 * tampering — and should be accepted silently.
	 *
	 * Returns false when we cannot be sure (unknown component, no recorded
	 * version), so the change still gets reviewed rather than blindly trusted.
	 */
	public static function is_expected_update_change( $rel_path ) {
		// WordPress-managed churn (translations, upgrade temp files).
		if ( self::is_auto_managed_path( $rel_path ) ) {
			return true;
		}
		$key = self::component_key( $rel_path );
		if ( ! $key ) {
			return false;
		}
		$base = self::get_baseline_versions();
		if ( empty( $base ) || ! array_key_exists( $key, $base ) ) {
			return false; // component wasn't recorded at baseline — be cautious
		}
		$current = self::current_version( $key );
		if ( '' === $current ) {
			return false;
		}
		return $current !== (string) $base[ $key ];
	}

	public static function exists() {
		global $wpdb;
		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" ) > 0;
	}

	/**
	 * Walk the filesystem and rebuild the baseline from scratch.
	 */
	public static function rebuild() {
		global $wpdb;
		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
		$wpdb->query( "TRUNCATE TABLE {$table}" );

		$count = 0;
		foreach ( self::iterate_files() as $path ) {
			$hash = @md5_file( $path );
			if ( ! $hash ) continue;
			$rel  = self::relpath( $path );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->insert( self::table(), [
				'path'      => $rel,
				'sha'       => $hash,
				'size'      => @filesize( $path ),
				'last_seen' => current_time( 'mysql' ),
			], [ '%s', '%s', '%d', '%s' ] );
			$count++;
		}
		update_option( 'malroot_baseline_built', current_time( 'mysql' ), false );
		// Record the versions of everything we just accepted, so future scans can
		// tell "this changed because of an update" apart from "this was tampered with".
		self::sync_versions();
		// Mark any open integrity findings as fixed since we just accepted the current state
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared
		$wpdb->query( "UPDATE {$wpdb->prefix}malroot_findings SET status='fixed' WHERE module='integrity' AND status='open'" );
		return $count;
	}

	/**
	 * Compare current state against the baseline. Returns
	 *   [ 'new' => [...rels], 'modified' => [...rels], 'deleted' => [...rels] ]
	 */
	public static function diff() {
		global $wpdb;
		$current = [];
		foreach ( self::iterate_files() as $path ) {
			$hash = @md5_file( $path );
			if ( ! $hash ) continue;
			$current[ self::relpath( $path ) ] = $hash;
		}

		$table = self::table();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
		$rows     = $wpdb->get_results( "SELECT path, sha FROM {$table}", OBJECT_K );
		$baseline = [];
		foreach ( $rows as $row ) {
			$baseline[ $row->path ] = $row->sha;
		}

		$new      = array_diff_key( $current, $baseline );
		$deleted  = array_diff_key( $baseline, $current );
		$modified = [];
		foreach ( $current as $rel => $sha ) {
			if ( isset( $baseline[ $rel ] ) && $baseline[ $rel ] !== $sha ) {
				$modified[ $rel ] = $sha;
			}
		}
		return [
			'new'      => array_keys( $new ),
			'modified' => array_keys( $modified ),
			'deleted'  => array_keys( $deleted ),
		];
	}

	/**
	 * Add or update a single file in the baseline (used when auto-accepting verified files).
	 */
	public static function add_to_baseline( $rel_path ) {
		global $wpdb;
		$abs = ABSPATH . ltrim( $rel_path, '/' );
		if ( ! file_exists( $abs ) ) return;
		$hash = @md5_file( $abs );
		if ( ! $hash ) return;

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
		$existing = $wpdb->get_var( $wpdb->prepare(
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared
			"SELECT id FROM " . self::table() . " WHERE path = %s", $rel_path
		) );
		if ( $existing ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->update( self::table(), [
				'sha'       => $hash,
				'size'      => @filesize( $abs ),
				'last_seen' => current_time( 'mysql' ),
			], [ 'id' => $existing ], [ '%s', '%d', '%s' ], [ '%d' ] );
		} else {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->insert( self::table(), [
				'path'      => $rel_path,
				'sha'       => $hash,
				'size'      => @filesize( $abs ),
				'last_seen' => current_time( 'mysql' ),
			], [ '%s', '%s', '%d', '%s' ] );
		}
	}

	/**
	 * Remove a file from the baseline (used when a file is legitimately deleted).
	 */
	public static function remove_from_baseline( $rel_path ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->delete( self::table(), [ 'path' => $rel_path ], [ '%s' ] );
	}

	private static function iterate_files() {
		$root = ABSPATH;
		$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ) );
		foreach ( $it as $f ) {
			if ( ! $f->isFile() ) continue;
			$path = $f->getPathname();

			if ( strpos( $path, '/_QUARANTINE_' ) !== false ) continue;
			if ( strpos( $path, '/uploads/malroot-security/' ) !== false ) continue;
			if ( strpos( $path, '/wp-content/uploads/' ) !== false ) continue; // user-supplied content; too noisy
			if ( strpos( $path, '/wp-content/cache/' ) !== false ) continue;
			if ( strpos( $path, '/wp-content/wflogs/' ) !== false ) continue;
			if ( strpos( $path, '/.git/' ) !== false ) continue;

			if ( ! preg_match( '/\.(php|phtml|phar|js|htaccess|htpasswd)$/i', $path ) && basename( $path ) !== '.htaccess' ) {
				continue;
			}
			if ( $f->getSize() > 5 * 1024 * 1024 ) continue;
			yield $path;
		}
	}

	private static function relpath( $abs ) {
		return ltrim( str_replace( ABSPATH, '', $abs ), '/' );
	}
}
