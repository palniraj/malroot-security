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
class Malroot_Verifier {

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
			// The file is gone. If the current official plugin version no longer
			// ships it, the removal is expected (an update dropped it).
			if ( self::is_expected_plugin_deletion( $rel_path ) ) {
				return self::result( self::VERDICT_PROBABLY,
					__( 'This file was removed and the current official plugin version no longer includes it — this is an expected update change.', 'malroot-security' )
				);
			}
			// Otherwise a file that should exist is missing — likely an
			// incomplete/interrupted update. Reinstalling restores it.
			return self::result( self::VERDICT_UNKNOWN,
				__( 'A file that this plugin/theme normally ships is missing. This usually means an update did not finish. Reinstall the plugin/theme to restore it — there is nothing to delete.', 'malroot-security' )
			);
		}

		$content = self::read_code( $abs );

		// 0) Unambiguous backdoor signatures. These strings never appear in
		// legitimate code, so they override everything — even a checksum.
		if ( $content !== null ) {
			$strong = self::strong_backdoor_signal( $content );
			if ( $strong ) {
				return self::result( self::VERDICT_MALICIOUS,
					/* translators: %s: name of the malware pattern */
					sprintf( __( 'File contains a known backdoor pattern: %s', 'malroot-security' ), $strong ),
					$strong
				);
			}
		}

		// 1) WordPress core checksum — authoritative. A match is definitively
		// safe; a mismatch on a core file is definitively bad.
		if ( preg_match( '#^wp-(admin|includes)/#', $rel_path ) || in_array( $rel_path, self::core_root_files(), true ) ) {
			$core = self::verify_against_wp_core( $rel_path, $abs );
			if ( $core ) return $core;
		}

		// 2) Plugin checksum — authoritative for plugins hosted on WordPress.org.
		if ( preg_match( '#^wp-content/plugins/([^/]+)/#', $rel_path, $m ) ) {
			$plugin = self::verify_against_plugin_checksum( $m[1], $rel_path, $abs );
			if ( $plugin ) return $plugin;
		}

		// 3) A PHP file inside /uploads/ is never legitimate.
		if ( strpos( $rel_path, 'wp-content/uploads/' ) !== false && preg_match( '/\.(php|phtml|phar)$/i', $rel_path ) ) {
			return self::result( self::VERDICT_MALICIOUS,
				__( 'PHP files should never exist in the uploads folder.', 'malroot-security' )
			);
		}

		// 4) Explained by a legitimate version update (or a recent update window)?
		if ( class_exists( 'Malroot_Baseline' ) && Malroot_Baseline::is_expected_update_change( $rel_path ) ) {
			return self::result( self::VERDICT_PROBABLY,
				__( 'The plugin/theme this file belongs to was updated — the change matches that update.', 'malroot-security' )
			);
		}
		if ( preg_match( '#^wp-content/plugins/([^/]+)/#', $rel_path, $m ) && self::was_plugin_updated_recently( $m[1] ) ) {
			return self::result( self::VERDICT_PROBABLY,
				/* translators: %s: plugin slug */
				sprintf( __( 'Plugin "%s" was updated recently — change is likely from that update.', 'malroot-security' ), $m[1] )
			);
		}
		if ( preg_match( '#^wp-content/themes/([^/]+)/#', $rel_path, $m ) && self::was_theme_updated_recently( $m[1] ) ) {
			return self::result( self::VERDICT_PROBABLY,
				/* translators: %s: theme slug */
				sprintf( __( 'Theme "%s" was updated recently — change is likely from that update.', 'malroot-security' ), $m[1] )
			);
		}

		// 5) Deep content analysis for anything still unverified. This reads the
		// actual code and scores it, so we can tell "looks like normal code" from
		// "contains obfuscated/backdoor-like code" instead of guessing.
		if ( $content !== null ) {
			$assess = self::assess_content( $content );
			if ( $assess['score'] >= 5 ) {
				return self::result( self::VERDICT_MALICIOUS,
					__( 'Code analysis found strong signs of malicious code: ', 'malroot-security' ) . implode( '; ', $assess['signals'] ),
					implode( ',', $assess['signals'] ),
					$assess
				);
			}
			if ( empty( $assess['signals'] ) ) {
				return self::result( self::VERDICT_PROBABLY,
					__( 'Code analysis found no suspicious patterns — this looks like normal code (for example a plugin/theme file you or an update changed).', 'malroot-security' ),
					'',
					$assess
				);
			}
			return self::result( self::VERDICT_UNKNOWN,
				__( 'Could not verify from an official source. Code analysis noted: ', 'malroot-security' ) . implode( '; ', $assess['signals'] ) . __( '. Manual review recommended.', 'malroot-security' ),
				'',
				$assess
			);
		}

		return self::result( self::VERDICT_UNKNOWN,
			__( 'Could not verify this file. Manual review recommended.', 'malroot-security' )
		);
	}

	/** Read a code-like file for analysis, or null if it isn't one / is too big. */
	private static function read_code( $abs ) {
		if ( ! is_file( $abs ) || filesize( $abs ) > 5 * 1024 * 1024 ) {
			return null;
		}
		if ( ! preg_match( '/\.(php|phtml|phar|js|htaccess)$/i', $abs ) && basename( $abs ) !== '.htaccess' ) {
			return null;
		}
		$content = @file_get_contents( $abs );
		return $content === false ? null : $content;
	}

	/* ---------------------------------------------------------------- */
	/*  Layer 1: Malware signatures                                     */
	/* ---------------------------------------------------------------- */

	/**
	 * Patterns that are effectively never present in legitimate code. A single
	 * match is enough to call a file malicious, ahead of any checksum. Kept
	 * deliberately tight to avoid false positives on real plugin/theme code.
	 */
	private static function strong_backdoor_signal( $content ) {
		$signatures = [
			'WSO/FilesMan webshell'          => '/(FilesMan|get_footer_sq|c99shell|r57shell|b374k)/',
			'eval(gzinflate(base64_decode))' => '/eval\s*\(\s*gzinflate\s*\(\s*base64_decode/',
			'eval() of request input'        => '/(eval|assert)\s*\(\s*(base64_decode|gzinflate|str_rot13|gzuncompress)?\s*\(?\s*@?\$_(GET|POST|REQUEST|COOKIE|SERVER)/',
			'request-driven code execution'  => '/\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*@?\$_(GET|POST|REQUEST|COOKIE)/',
			'?stream= dropper'               => '/\$_GET\s*\[\s*[\'\"]stream[\'\"]\s*\].*?curl_exec/s',
			'system-control C2'              => '/(SC_PANEL_URL|superfuckingpanel|SC_REST_NAMESPACE)/',
			'create_function backdoor'       => '/create_function\s*\(\s*[\'\"]?\s*[\'\"]?\s*,\s*\$_/',
			'variable-function on request'   => '/\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/',
			'String.fromCharCode redirect'   => '/<script[^>]*>[^<]*String\.fromCharCode\s*\(\s*60/',
		];
		foreach ( $signatures as $name => $regex ) {
			if ( preg_match( $regex, $content ) ) {
				return $name;
			}
		}
		return null;
	}

	/**
	 * Scored content analysis. Reads the code and tallies suspicious traits.
	 * Weaker than strong_backdoor_signal (these traits CAN appear in legitimate
	 * code), so it runs only after authoritative checks fail, and a high total
	 * — not any single hit — is what marks a file malicious.
	 *
	 * @return array { score:int, signals:string[] }
	 */
	public static function assess_content( $content ) {
		$score   = 0;
		$signals = [];
		$add = static function ( $points, $label ) use ( &$score, &$signals ) {
			$score += $points;
			$signals[] = $label;
		};

		// Real /e modifier: a delimited pattern whose modifier list contains 'e'
		// e.g. preg_replace('/foo/e', ...) or "#bar#ei". The delimiter after the
		// opening quote must reappear before the modifiers, so ordinary strings
		// like 'edit' or "example" can never match.
		if ( preg_match( '/\bpreg_replace\s*\(\s*([\'"])([#\/~!@%|])(?:(?!\2).)*\2[a-zA-Z]*e[a-zA-Z]*\1/s', $content ) ) {
			$add( 4, __( 'preg_replace with /e (runs code)', 'malroot-security' ) );
		}
		if ( preg_match( '/\b(eval|assert)\s*\(/', $content ) ) {
			$add( 3, __( 'uses eval()/assert()', 'malroot-security' ) );
		}
		if ( preg_match( '/\bgzinflate\s*\(|\bgzuncompress\s*\(|\bstr_rot13\s*\(/', $content ) ) {
			$add( 2, __( 'decompresses/obfuscates code at runtime', 'malroot-security' ) );
		}
		// Long base64 blob (common malware payload carrier).
		if ( preg_match( '/[\'"][A-Za-z0-9+\/]{300,}={0,2}[\'"]/', $content ) ) {
			$add( 3, __( 'contains a large encoded blob', 'malroot-security' ) );
		}
		if ( preg_match_all( '/base64_decode\s*\(/', $content ) >= 2 ) {
			$add( 2, __( 'repeated base64 decoding', 'malroot-security' ) );
		}
		// Long chr()/concatenation chains used to hide strings.
		if ( preg_match_all( '/chr\s*\(\s*\d+\s*\)/', $content ) >= 8 ) {
			$add( 2, __( 'builds hidden strings with chr()', 'malroot-security' ) );
		}
		if ( preg_match( '/\bmove_uploaded_file\s*\(/', $content ) && preg_match( '/\$_FILES/', $content ) && ! preg_match( '/wp_handle_upload|check_admin_referer|wp_verify_nonce|current_user_can/', $content ) ) {
			$add( 3, __( 'accepts file uploads without WordPress permission checks', 'malroot-security' ) );
		}
		if ( preg_match( '/\bfile_put_contents\s*\([^)]*\.(php|phtml)/i', $content ) ) {
			$add( 2, __( 'writes PHP files at runtime', 'malroot-security' ) );
		}
		if ( preg_match( '/\b(edoced_46esab|etalfnizg|noitcnuf_etaerc)\b/', $content ) ) {
			$add( 3, __( 'reversed function names (obfuscation)', 'malroot-security' ) );
		}
		// Excessive goto labels — a classic obfuscator signature.
		if ( preg_match_all( '/goto\s+\w+;/', $content ) >= 5 ) {
			$add( 2, __( 'heavy goto-based obfuscation', 'malroot-security' ) );
		}

		return [ 'score' => $score, 'signals' => $signals ];
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

	/** Resolve a plugin slug's installed version from its header, or '' if unknown. */
	private static function installed_plugin_version( $slug ) {
		$plugin_file = WP_PLUGIN_DIR . '/' . $slug . '/' . $slug . '.php';
		if ( ! file_exists( $plugin_file ) ) {
			$candidates = glob( WP_PLUGIN_DIR . '/' . $slug . '/*.php' ) ?: [];
			foreach ( $candidates as $c ) {
				$head = file_get_contents( $c, false, null, 0, 8192 );
				if ( $head && preg_match( '/Plugin Name:/i', $head ) ) {
					$plugin_file = $c;
					break;
				}
			}
		}
		if ( ! file_exists( $plugin_file ) ) return '';

		if ( ! function_exists( 'get_plugin_data' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$data = get_plugin_data( $plugin_file, false, false );
		return (string) ( $data['Version'] ?? '' );
	}

	/**
	 * Is a "deleted" file legitimately absent because the current official plugin
	 * version no longer ships it? Authoritative for WordPress.org plugins and
	 * needs no local baseline history — we ask WordPress.org what the current
	 * version is supposed to contain.
	 *
	 * Returns:
	 *   true  → the file is not part of the current official version (update removed it)
	 *   false → we can't confirm (not a .org plugin, no manifest), OR the file
	 *           SHOULD exist in this version but is missing (worth flagging)
	 */
	public static function is_expected_plugin_deletion( $rel_path ) {
		if ( ! preg_match( '#^wp-content/plugins/([^/]+)/(.+)$#', $rel_path, $m ) ) {
			return false;
		}
		$slug           = $m[1];
		$path_in_plugin = $m[2];

		$version = self::installed_plugin_version( $slug );
		if ( '' === $version ) return false;

		$checksums = self::get_plugin_checksums( $slug, $version );
		if ( empty( $checksums ) ) return false; // no official manifest to compare against

		// If the current version's manifest doesn't list this file, it was
		// legitimately dropped by the update.
		return ! array_key_exists( $path_in_plugin, $checksums );
	}

	private static function verify_against_plugin_checksum( $slug, $rel_path, $abs ) {
		$version = self::installed_plugin_version( $slug );
		if ( '' === $version ) return null;

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
    /* translators: %s is replaced with dynamic content */
				sprintf( __( 'Matches official %1$s plugin checksum (v%2$s).', 'malroot-security' ), $slug, $version ),
				$slug . '@' . $version
			);
		}
		return self::result( self::VERDICT_MALICIOUS,
   /* translators: %s is replaced with dynamic content */
			sprintf( __( 'Plugin %1$s file has been modified — does not match official v%2$s.', 'malroot-security' ), $slug, $version ),
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

	private static function result( $verdict, $reason, $evidence = '', $assessment = null ) {
		return [
			'verdict'    => $verdict,
			'reason'     => $reason,
			'evidence'   => $evidence,
			'assessment' => $assessment,
		];
	}
}
