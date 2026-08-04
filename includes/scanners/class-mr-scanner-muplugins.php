<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * mu-plugins scanner. mu-plugins auto-load on every request and don't need
 * activation — the perfect persistence niche the system-control attacker used.
 *
 * Anything that's not on the operator-supplied allowlist is flagged.
 */
class Malroot_Scanner_MuPlugins extends Malroot_Scanner_Base {

	protected $module = 'muplugins';

	public function run() {
		$dir = WPMU_PLUGIN_DIR;
		if ( ! is_dir( $dir ) ) {
			return;
		}

		$allowlist = (array) get_option( 'malroot_muplugin_allowlist', [
			'index.php',
			'.htaccess',
			'00-afn-security.php',
		] );

		// Well-known must-use plugins dropped in by reputable hosts and plugins.
		// These are legitimate infrastructure, not self-healing malware, so we
		// don't flag them. (mu-plugins that WRITE files at runtime are still
		// caught by the SH-007 checks below, even if named like these.)
		$known_good = [
			'hostinger-php-error-reporting.php',
			'hostinger-preview-domain.php',
			'hostinger-auto-updates.php',
			'hostinger-easy-onboarding.php',
			'hostinger-login-notification.php',
			'wp-staging-optimizer.php',
			'automation-by-installatron.php',
			'endurance-page-cache.php',
			'kinsta-mu-plugins.php',
			'wpcomsh-loader.php',
			'wpe-cache-plugin.php',
			'wpengine-common',
			'cloudways-plugin.php',
		];
		$known_good_prefixes = [ 'hostinger-', 'wpe-', 'wpengine' ];

		$it = new DirectoryIterator( $dir );
		foreach ( $it as $f ) {
			if ( $f->isDot() ) {
				continue;
			}
			$name = $f->getFilename();
			if ( in_array( $name, $allowlist, true ) || in_array( $name, $known_good, true ) ) {
				continue;
			}
			foreach ( $known_good_prefixes as $prefix ) {
				if ( 0 === strpos( $name, $prefix ) ) {
					continue 2;
				}
			}
			$path = $f->getPathname();
			$is_php = $f->isFile() && preg_match( '/\.php$/i', $name );

			// Zero-byte mu-plugin: the textbook self-healing loader stub
			// (sc-loader.php was 0 bytes between page loads).
			if ( $is_php && $f->getSize() === 0 ) {
				$this->record(
					'SH-007',
					'critical',
					"muplugins:{$name}",
					'Zero-byte mu-plugin file — self-healing loader stub pattern',
					$path
				);
				continue;
			}

			if ( $is_php ) {
				// Read the file and look for "create file" or "copy from .sc-backup" patterns.
				$content = @file_get_contents( $path );
				if ( $content && preg_match( '/(file_put_contents|copy\s*\(|@?fwrite\s*\()/', $content ) ) {
					$this->record(
						'SH-007',
						'critical',
						"muplugins:{$name}",
						'mu-plugin writes files at runtime — typical of self-healing rootkits',
						substr( $content, 0, 400 )
					);
					continue;
				}
				$this->record(
					'SH-006',
					'medium',
					"muplugins:{$name}",
					'Unrecognised mu-plugin (not on allowlist)',
					'size=' . $f->getSize()
				);
			}
		}
	}
}
