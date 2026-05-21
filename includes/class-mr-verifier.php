<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * File verifier.
 *
 * For a given file path, returns a verdict:
 *   - 'safe'      : verified by an authoritative source (WP.org, plugin checksum)
 *   - 'probably'  : matches a recent plugin/theme update window
 *   - 'unknown'   : no signal either way
 *   - 'malicious' : matches a known malware signature
 *
 * Used by the Simple View to decide whether to offer "Accept" or "Quarantine".
 */
class MR_Verifier {

	const VERDICT_SAFE      = 'safe';
	const VERDICT_PROBABLY  = 'probably';
	const VERDICT_UNKNOWN   = 'unknown';
	const VERDICT_MALICIOUS = 'malicious';

	/**
	 * Verify a file. Returns:
	 *   [ 'verdict' => 'safe', 'reason' => 'Matches official WordPress core checksum', 'evidence' => '...' ]
	 */
	public static function verify( $rel_path ) {
		$abs = ABSPATH . ltrim( $rel_path, '/' );
		if ( ! file_exists( $abs ) ) {
			return self::result( self::VERDICT_UNKNOWN, __( 'File no longer exists.', 'malroot-security' ) );
		}

		// 1) Highest priority: malware signature check.
		// If the file content matches a known malware pattern, nothing else matters.
		$mal = self::scan_for_malware( $abs );
		if ( $mal ) {
			return self::result( self::VERDICT_MALICIOUS,
				sprintf( __( 'File contains malware pattern: %s', 'malroot-security' ), $mal ),
				$mal
			);
		}

		// 2) WordPress core checksum check.
		if ( preg_match( '#^wp-(admin|includes)/#', $rel_path ) || in_array( $rel_path, self::core_root_files(), true ) ) {
			$core = self::verify_against_wp_core( $rel_path, $abs );
			if ( $core ) return $core;
		}

		// 3) Plugin checksum check.
		if ( preg_match( '#^wp-content/plugins/([^/]+)/#', $rel_path, $m ) ) {
			$plugin = self::verify_against_plugin_checksum( $m[1], $rel_path, $abs );
			if ( $plugin ) return $plugin;

			// 4) Fallback: was this plugin updated recently?
			$recent = self::was_plugin_updated_recently( $m[1] );
			if ( $recent ) {
				return self::result( self::VERDICT_PROBABLY,
					sprintf( __( 'Plugin "%s" was updated recently — change is likely from that update.', 'malroot-security' ), $m[1] )
				);
			}
		}

		// 5) Theme: check if the active theme was updated recently.
		if ( preg_match( '#^wp-content/themes/([^/]+)/#', $rel_path, $m ) ) {
			$recent = self::was_theme_updated_recently( $m[1] );
			if ( $recent ) {
				return self::result( self::VERDICT_PROBABLY,
					sprintf( __( 'Theme "%s" was updated recently — change is likely from that update.', 'malroot-security' ), $m[1] )
				);
			}
		}

		// 6) PHP file in /uploads/ is always suspicious regardless
		if ( strpos( $rel_path, 'wp-content/uploads/' ) !== false && preg_match( '/\.(php|phtml|phar)$/i', $rel_path ) ) {
			return self::result( self::VERDICT_MALICIOUS,
				__( 'PHP files should never exist in the uploads folder.', 'malroot-security' )
			);
		}

		return self::result( self::VERDICT_UNKNOWN,
			__( 'Could not verify this file. Manual review recommended.', 'malroot-security' )
		);
	}

	/* ---------------------------------------------------------------- */
	/*  Layer 1: Malware signatures                                     */
	/* ---------------------------------------------------------------- */

	private static function scan_for_malware( $abs ) {
		if ( filesize( $abs ) > 5 * 1024 * 1024 ) return null;
		if ( ! preg_match( '/\.(php|phtml|phar|js|htaccess)$/i', $abs ) && basename( $abs ) !== '.htaccess' ) {
			return null;
		}
		$content = @file_get_contents( $abs );
		if ( ! $content ) return null;

		$signatures = [
			'WSO/FilesMan webshell'         => '/(FilesMan|get_footer_sq)/',
			'gzinflate(base64_decode) eval' => '/eval\s*\(\s*gzinflate\s*\(\s*base64_decode/',
			'?stream= dropper'              => '/\$_GET\s*\[\s*[\'\"]stream[\'\"]\s*\].*?curl_exec/s',
			'unauthenticated upload form'   => '/is_uploaded_file\s*\([^)]*\$_FILES.*move_uploaded_file/s',
			'system-control C2'             => '/(SC_PANEL_URL|superfuckingpanel|SC_REST_NAMESPACE)/',
			'eval(base64_decode($_)'        => '/eval\s*\(\s*(base64_decode|gzinflate|str_rot13)\s*\(\s*@?\$_(GET|POST|REQUEST|COOKIE)/',
			'preg_replace /e modifier'      => '/preg_replace\s*\(\s*[\'\"][^\'\"]*\/e[^\'\"]*[\'\"]/',
			'create_function backdoor'      => '/create_function\s*\(\s*[\'\"]?\s*[\'\"]?\s*,\s*\$_/',
			'String.fromCharCode redirect'  => '/<script[^>]*>[^<]*String\.fromCharCode\s*\(\s*60/',
		];
		foreach ( $signatures as $name => $regex ) {
			if ( preg_match( $regex, $content ) ) {
				return $name;
			}
		}
		return null;
	}

	/* ---------------------------------------------------------------- */
	/*  Layer 2: WordPress core checksum                                */
	/* ---------------------------------------------------------------- */

	private static function verify_against_wp_core( $rel_path, $abs ) {
		$checksums = self::get_wp_core_checksums();
		if ( ! $checksums ) return null;
		// API returns paths relative to ABSPATH, sometimes with leading slash
		$key = $rel_path;
		if ( ! isset( $checksums[ $key ] ) ) return null;

		$file_md5 = @md5_file( $abs );
		if ( ! $file_md5 ) return null;

		if ( $file_md5 === $checksums[ $key ] ) {
			return self::result( self::VERDICT_SAFE,
				__( 'Matches official WordPress core checksum.', 'malroot-security' ),
				'wp-core: ' . $key
			);
		}
		return self::result( self::VERDICT_MALICIOUS,
			__( 'WordPress core file has been modified — checksum does not match.', 'malroot-security' ),
			'expected ' . $checksums[ $key ] . ' got ' . $file_md5
		);
	}

	private static function get_wp_core_checksums() {
		$cache_key = 'malroot_core_checksums_' . get_bloginfo( 'version' );
		$cached    = get_transient( $cache_key );
		if ( $cached ) return $cached;

		$resp = wp_remote_get(
			sprintf( 'https://api.wordpress.org/core/checksums/1.0/?version=%s&locale=%s',
				get_bloginfo( 'version' ),
				get_locale()
			),
			[ 'timeout' => 8 ]
		);
		if ( is_wp_error( $resp ) ) return [];
		$body = json_decode( wp_remote_retrieve_body( $resp ), true );
		$checksums = $body['checksums'] ?? [];
		// Some locales nest under language code
		if ( $checksums && ! is_string( reset( $checksums ) ) && is_array( reset( $checksums ) ) ) {
			$checksums = reset( $checksums );
		}
		if ( $checksums ) {
			set_transient( $cache_key, $checksums, DAY_IN_SECONDS );
		}
		return $checksums;
	}

	/* ---------------------------------------------------------------- */
	/*  Layer 3: Plugin checksum                                        */
	/* ---------------------------------------------------------------- */

	private static function verify_against_plugin_checksum( $slug, $rel_path, $abs ) {
		// Get the plugin's installed version from the local plugin headers
		$plugin_file = WP_PLUGIN_DIR . '/' . $slug . '/' . $slug . '.php';
		if ( ! file_exists( $plugin_file ) ) {
			// Try to locate any PHP file with a Plugin Name header
			$candidates = glob( WP_PLUGIN_DIR . '/' . $slug . '/*.php' ) ?: [];
			foreach ( $candidates as $c ) {
				$head = file_get_contents( $c, false, null, 0, 8192 );
				if ( $head && preg_match( '/Plugin Name:/i', $head ) ) {
					$plugin_file = $c;
					break;
				}
			}
		}
		if ( ! file_exists( $plugin_file ) ) return null;

		if ( ! function_exists( 'get_plugin_data' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$data = get_plugin_data( $plugin_file, false, false );
		$version = $data['Version'] ?? '';
		if ( ! $version ) return null;

		$checksums = self::get_plugin_checksums( $slug, $version );
		if ( ! $checksums ) return null;

		$path_in_plugin = preg_replace( '#^wp-content/plugins/' . preg_quote( $slug, '#' ) . '/#', '', $rel_path );
		if ( ! isset( $checksums[ $path_in_plugin ] ) ) return null;

		$file_md5 = @md5_file( $abs );
		if ( ! $file_md5 ) return null;

		// API returns array of acceptable hashes
		$expected = (array) $checksums[ $path_in_plugin ];
		if ( in_array( $file_md5, $expected, true ) ) {
			return self::result( self::VERDICT_SAFE,
				sprintf( __( 'Matches official %s plugin checksum (v%s).', 'malroot-security' ), $slug, $version ),
				$slug . '@' . $version
			);
		}
		return self::result( self::VERDICT_MALICIOUS,
			sprintf( __( 'Plugin %s file has been modified — does not match official v%s.', 'malroot-security' ), $slug, $version ),
			'expected ' . implode( ',', $expected ) . ' got ' . $file_md5
		);
	}

	private static function get_plugin_checksums( $slug, $version ) {
		$cache_key = 'malroot_plugin_checksums_' . md5( $slug . '@' . $version );
		$cached    = get_transient( $cache_key );
		if ( $cached !== false ) return $cached;

		$resp = wp_remote_get(
			sprintf( 'https://downloads.wordpress.org/plugin-checksums/%s/%s.json', $slug, $version ),
			[ 'timeout' => 8 ]
		);
		if ( is_wp_error( $resp ) || wp_remote_retrieve_response_code( $resp ) !== 200 ) {
			set_transient( $cache_key, [], HOUR_IN_SECONDS );
			return [];
		}
		$body = json_decode( wp_remote_retrieve_body( $resp ), true );
		$files = $body['files'] ?? [];
		$flat  = [];
		foreach ( $files as $path => $info ) {
			$flat[ $path ] = $info['md5'] ?? '';
		}
		set_transient( $cache_key, $flat, DAY_IN_SECONDS );
		return $flat;
	}

	/* ---------------------------------------------------------------- */
	/*  Layer 4: Recent update windows                                  */
	/* ---------------------------------------------------------------- */

	private static function was_plugin_updated_recently( $slug ) {
		$updated = (array) get_option( 'malroot_known_updates', [] );
		if ( ! isset( $updated[ $slug ] ) ) return false;
		return ( time() - (int) $updated[ $slug ] ) < DAY_IN_SECONDS;
	}

	private static function was_theme_updated_recently( $slug ) {
		$updated = (array) get_option( 'malroot_known_theme_updates', [] );
		if ( ! isset( $updated[ $slug ] ) ) return false;
		return ( time() - (int) $updated[ $slug ] ) < DAY_IN_SECONDS;
	}

	/* ---------------------------------------------------------------- */

	private static function core_root_files() {
		return [
			'index.php', 'wp-activate.php', 'wp-blog-header.php',
			'wp-comments-post.php', 'wp-config-sample.php', 'wp-cron.php',
			'wp-links-opml.php', 'wp-load.php', 'wp-login.php', 'wp-mail.php',
			'wp-settings.php', 'wp-signup.php', 'wp-trackback.php', 'xmlrpc.php',
		];
	}

	private static function result( $verdict, $reason, $evidence = '' ) {
		return [
			'verdict'  => $verdict,
			'reason'   => $reason,
			'evidence' => $evidence,
		];
	}
}
