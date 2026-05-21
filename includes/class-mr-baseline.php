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
class MR_Baseline {

	const TABLE = 'malroot_baseline';

	public static function table() {
		global $wpdb;
		return $wpdb->prefix . self::TABLE;
	}

	public static function exists() {
		global $wpdb;
		return (int) $wpdb->get_var( "SELECT COUNT(*) FROM " . self::table() ) > 0;
	}

	/**
	 * Walk the filesystem and rebuild the baseline from scratch.
	 */
	public static function rebuild() {
		global $wpdb;
		$wpdb->query( "TRUNCATE TABLE " . self::table() );

		$count = 0;
		foreach ( self::iterate_files() as $path ) {
			$hash = @md5_file( $path );
			if ( ! $hash ) continue;
			$rel  = self::relpath( $path );
			$wpdb->insert( self::table(), [
				'path'      => $rel,
				'sha'       => $hash,
				'size'      => @filesize( $path ),
				'last_seen' => current_time( 'mysql' ),
			], [ '%s', '%s', '%d', '%s' ] );
			$count++;
		}
		update_option( 'malroot_baseline_built', current_time( 'mysql' ), false );
		// Mark any open integrity findings as fixed since we just accepted the current state
		global $wpdb;
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

		$rows     = $wpdb->get_results( "SELECT path, sha FROM " . self::table(), OBJECT_K );
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

		$existing = $wpdb->get_var( $wpdb->prepare(
			"SELECT id FROM " . self::table() . " WHERE path = %s", $rel_path
		) );
		if ( $existing ) {
			$wpdb->update( self::table(), [
				'sha'       => $hash,
				'size'      => @filesize( $abs ),
				'last_seen' => current_time( 'mysql' ),
			], [ 'id' => $existing ], [ '%s', '%d', '%s' ], [ '%d' ] );
		} else {
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
		$wpdb->delete( self::table(), [ 'path' => $rel_path ], [ '%s' ] );
	}

	private static function iterate_files() {
		$root = ABSPATH;
		$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ) );
		foreach ( $it as $f ) {
			if ( ! $f->isFile() ) continue;
			$path = $f->getPathname();

			if ( strpos( $path, '/_QUARANTINE_' ) !== false ) continue;
			if ( strpos( $path, '/wp-content/uploads/malroot-quarantine/' ) !== false ) continue;
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
