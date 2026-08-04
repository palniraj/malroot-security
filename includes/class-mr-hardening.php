<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Hardening — close the doors the attack actually came through.
 *
 * These are chosen from evidence rather than from a generic checklist. On
 * cityagecare.com the Wordfence hit log showed 444 requests to /xmlrpc.php plus
 * roughly 470 more across path variants (/blog/xmlrpc.php, /wp/xmlrpc.php …).
 * XML-RPC's system.multicall lets an attacker try many passwords in a single
 * request, which sidesteps login rate limiting entirely. That endpoint was the
 * most probable way in, so switching it off is the single highest-value change.
 *
 * Every measure is a toggle and every one is reversible. Nothing here deletes
 * data. The .htaccess guard is the only one that touches disk, and it writes to
 * the uploads folder only.
 */
class Malroot_Hardening {

	const OPT = 'malroot_hardening';

	/** Defaults. XML-RPC is on because it was the observed attack surface. */
	public static function defaults() {
		return [
			'disable_xmlrpc'        => 1,
			'block_php_in_uploads'  => 1,
			'disable_file_editor'   => 1,
			'block_user_enum'       => 1,
			'hide_wp_version'       => 1,
		];
	}

	public static function settings() {
		$saved = get_option( self::OPT, null );
		if ( ! is_array( $saved ) ) {
			$saved = [];
		}
		return array_merge( self::defaults(), $saved );
	}

	public static function enabled( $key ) {
		$s = self::settings();
		return ! empty( $s[ $key ] );
	}

	/* ------------------------------------------------------------------ */

	public static function register() {
		$s = self::settings();

		if ( ! empty( $s['disable_xmlrpc'] ) ) {
			// Turn the endpoint off, and strip the advertising header so
			// scanners stop being pointed at it.
			add_filter( 'xmlrpc_enabled', '__return_false' );
			add_filter( 'wp_headers', [ __CLASS__, 'remove_pingback_header' ] );
			add_filter( 'bloginfo_url', [ __CLASS__, 'blank_pingback_url' ], 10, 2 );
			add_action( 'init', [ __CLASS__, 'block_xmlrpc_request' ], 0 );
			// Refuse XML-RPC authentication outright, so even a reachable
			// endpoint cannot be used to test credentials.
			add_filter( 'xmlrpc_methods', [ __CLASS__, 'strip_pingback_methods' ] );
		}

		if ( ! empty( $s['disable_file_editor'] ) ) {
			// An attacker who reaches wp-admin uses the built-in editor to write
			// a shell without needing FTP. Removing the capability is enough;
			// we avoid defining constants so nothing conflicts with wp-config.
			add_filter( 'map_meta_cap', [ __CLASS__, 'deny_file_edit_caps' ], 10, 2 );
		}

		if ( ! empty( $s['block_user_enum'] ) ) {
			add_filter( 'rest_endpoints', [ __CLASS__, 'restrict_rest_users' ] );
			add_action( 'template_redirect', [ __CLASS__, 'block_author_scan' ] );
		}

		if ( ! empty( $s['hide_wp_version'] ) ) {
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', '__return_empty_string' );
		}

		if ( ! empty( $s['block_php_in_uploads'] ) ) {
			// Cheap check; only writes when the guard is missing.
			add_action( 'admin_init', [ __CLASS__, 'ensure_uploads_guard' ] );
		}
	}

	/* ------------------------------------------------------------------ */
	/*  XML-RPC                                                           */
	/* ------------------------------------------------------------------ */

	public static function remove_pingback_header( $headers ) {
		if ( is_array( $headers ) ) {
			unset( $headers['X-Pingback'] );
		}
		return $headers;
	}

	public static function blank_pingback_url( $output, $show ) {
		return ( 'pingback_url' === $show ) ? '' : $output;
	}

	public static function strip_pingback_methods( $methods ) {
		if ( ! is_array( $methods ) ) {
			return $methods;
		}
		foreach ( [ 'pingback.ping', 'pingback.extensions.getPingbacks', 'system.multicall' ] as $m ) {
			unset( $methods[ $m ] );
		}
		return $methods;
	}

	/**
	 * Stop the request before WordPress parses the XML body.
	 */
	public static function block_xmlrpc_request() {
		if ( ! defined( 'XMLRPC_REQUEST' ) || ! XMLRPC_REQUEST ) {
			return;
		}
		if ( class_exists( 'Malroot_Alerting' ) ) {
			Malroot_Alerting::alert(
				'low',
				'xmlrpc_blocked',
				'Blocked an XML-RPC request',
				[ 'ip' => self::ip() ]
			);
		}
		status_header( 403 );
		nocache_headers();
		exit( 'XML-RPC is disabled on this site.' );
	}

	/* ------------------------------------------------------------------ */
	/*  File editor                                                       */
	/* ------------------------------------------------------------------ */

	public static function deny_file_edit_caps( $caps, $cap ) {
		if ( in_array( $cap, [ 'edit_plugins', 'edit_themes', 'edit_files' ], true ) ) {
			return [ 'do_not_allow' ];
		}
		return $caps;
	}

	/* ------------------------------------------------------------------ */
	/*  User enumeration                                                  */
	/* ------------------------------------------------------------------ */

	/**
	 * Require authentication for the REST users collection.
	 *
	 * Anonymous listing hands an attacker a ready-made username list, which is
	 * what turns a password spray into a targeted one. Logged-in requests are
	 * unaffected, so the block editor keeps working.
	 */
	public static function restrict_rest_users( $endpoints ) {
		if ( ! is_array( $endpoints ) ) {
			return $endpoints;
		}
		$guard = static function () {
			return current_user_can( 'list_users' )
				? true
				: new WP_Error(
					'malroot_rest_forbidden',
					__( 'Authentication required.', 'malroot-security' ),
					[ 'status' => 401 ]
				);
		};
		foreach ( [ '/wp/v2/users', '/wp/v2/users/(?P<id>[\d]+)' ] as $route ) {
			if ( empty( $endpoints[ $route ] ) ) {
				continue;
			}
			foreach ( $endpoints[ $route ] as $i => $handler ) {
				// Route arrays also carry non-numeric metadata keys such as
				// 'schema', which have no 'methods' entry.
				if ( ! is_array( $handler ) || ! isset( $handler['methods'] ) ) {
					continue;
				}
				$methods = $handler['methods'];
				$is_read = is_string( $methods )
					? false !== strpos( $methods, 'GET' )
					: ( isset( $methods['GET'] ) || in_array( 'GET', (array) $methods, true ) );
				if ( $is_read ) {
					$endpoints[ $route ][ $i ]['permission_callback'] = $guard;
				}
			}
		}
		return $endpoints;
	}

	/** Block /?author=1 probing, which maps user IDs to login names. */
	public static function block_author_scan() {
		if ( is_admin() || is_user_logged_in() ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! isset( $_GET['author'] ) ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( ! is_numeric( wp_unslash( $_GET['author'] ) ) ) {
			return;
		}
		status_header( 403 );
		nocache_headers();
		exit( 'Forbidden' );
	}

	/* ------------------------------------------------------------------ */
	/*  Uploads guard                                                     */
	/* ------------------------------------------------------------------ */

	/**
	 * Deny direct execution of PHP inside wp-content/uploads.
	 *
	 * Uploads is world-writable by design and publicly reachable, which makes
	 * it the usual landing spot for a dropped shell. Serving PHP from there is
	 * never legitimate.
	 *
	 * Only applies on Apache/LiteSpeed. On nginx the equivalent rule belongs in
	 * the server config, so we report that instead of pretending it worked.
	 */
	public static function ensure_uploads_guard() {
		if ( get_transient( 'malroot_uploads_guard_checked' ) ) {
			return;
		}
		set_transient( 'malroot_uploads_guard_checked', 1, DAY_IN_SECONDS );

		$uploads = wp_get_upload_dir();
		if ( empty( $uploads['basedir'] ) || ! is_dir( $uploads['basedir'] ) ) {
			return;
		}
		if ( ! self::is_apache() ) {
			update_option( 'malroot_uploads_guard_status', 'unsupported-server', false );
			return;
		}

		$file = trailingslashit( $uploads['basedir'] ) . '.htaccess';

		$rules = [
			'<FilesMatch "\.(?i:php|php3|php4|php5|php7|php8|phtml|phar|pl|py|cgi|shtml)$">',
			"\t<IfModule mod_authz_core.c>",
			"\t\tRequire all denied",
			"\t</IfModule>",
			"\t<IfModule !mod_authz_core.c>",
			"\t\tOrder Allow,Deny",
			"\t\tDeny from all",
			"\t</IfModule>",
			'</FilesMatch>',
		];

		// insert_with_markers() is WordPress' own .htaccess editor — the same
		// routine core uses for permalinks. It manages the BEGIN/END markers,
		// leaves any other rules in the file untouched, and writes directly.
		//
		// WP_Filesystem is deliberately not used here: it refuses "direct" mode
		// whenever the file owner differs from the PHP process user, which is
		// common on shared hosting and made this guard silently fail.
		if ( ! function_exists( 'insert_with_markers' ) ) {
			require_once ABSPATH . 'wp-admin/includes/misc.php';
		}

		if ( ! file_exists( $file ) && ! is_writable( dirname( $file ) ) ) {
			update_option( 'malroot_uploads_guard_status', 'uploads-not-writable', false );
			return;
		}
		if ( file_exists( $file ) && ! is_writable( $file ) ) {
			update_option( 'malroot_uploads_guard_status', 'htaccess-not-writable', false );
			return;
		}

		$ok = insert_with_markers( $file, 'Malroot uploads guard', $rules );

		update_option( 'malroot_uploads_guard_status', $ok ? 'active' : 'write-failed', false );
		if ( $ok && class_exists( 'Malroot_Logger' ) ) {
			Malroot_Logger::info( 'Wrote uploads PHP-execution guard', [ 'file' => $file ] );
		}
	}

	private static function is_apache() {
		$sw = isset( $_SERVER['SERVER_SOFTWARE'] )
			? strtolower( sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) )
			: '';
		return ( false !== strpos( $sw, 'apache' ) || false !== strpos( $sw, 'litespeed' ) );
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

	private static function ip() {
		if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			$xff = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) );
			return trim( explode( ',', $xff )[0] );
		}
		return isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
	}
}
