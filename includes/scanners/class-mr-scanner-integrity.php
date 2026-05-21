<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * File integrity scanner.
 *
 * On first run it builds a baseline. Subsequent runs diff against the
 * baseline and emit findings for new/modified/deleted PHP, JS and
 * .htaccess files.
 */
class MR_Scanner_Integrity extends MR_Scanner_Base {

	protected $module = 'integrity';

	public function run() {
		if ( ! MR_Baseline::exists() ) {
			$count = MR_Baseline::rebuild();
			$this->record(
				'INT-INIT',
				'info',
				'baseline',
    /* translators: %s is replaced with dynamic content */
				sprintf( __( 'Initial integrity baseline created (%d files).', 'malroot-security' ), $count ),
				''
			);
			return;
		}

		$diff = MR_Baseline::diff();

		// New files: auto-accept anything that's verified-safe (matches WordPress.org or plugin checksum)
		foreach ( array_slice( $diff['new'], 0, 500 ) as $rel ) {
			// Skip Malroot's own files — they change on every plugin update
			if ( strpos( $rel, 'wp-content/plugins/malroot-security/' ) !== false ) {
				MR_Baseline::add_to_baseline( $rel );
				continue;
			}
			// Verify the file. If it matches an official checksum, silently update the baseline.
			$verdict = MR_Verifier::verify( $rel );
			if ( $verdict['verdict'] === MR_Verifier::VERDICT_SAFE ) {
				MR_Baseline::add_to_baseline( $rel );
				continue; // No finding — this is a legitimate update
			}
			if ( $verdict['verdict'] === MR_Verifier::VERDICT_MALICIOUS ) {
				$this->record( 'INT-NEW', 'critical', $rel, $verdict['reason'], $verdict['evidence'] );
				continue;
			}

			$severity = preg_match( '/\.(php|phtml|phar)$/i', $rel ) ? 'high' : 'medium';
			if ( preg_match( '#^wp-(admin|includes)/#', $rel ) ) {
				$severity = 'critical';
			}
			$this->record( 'INT-NEW', $severity, $rel, 'New file appeared since last baseline', '' );
		}

		// Modified files: same auto-accept logic
		foreach ( array_slice( $diff['modified'], 0, 500 ) as $rel ) {
			if ( strpos( $rel, 'wp-content/plugins/malroot-security/' ) !== false ) {
				MR_Baseline::add_to_baseline( $rel );
				continue;
			}
			$verdict = MR_Verifier::verify( $rel );
			if ( $verdict['verdict'] === MR_Verifier::VERDICT_SAFE ) {
				MR_Baseline::add_to_baseline( $rel );
				continue;
			}
			if ( $verdict['verdict'] === MR_Verifier::VERDICT_MALICIOUS ) {
				$this->record( 'INT-MOD', 'critical', $rel, $verdict['reason'], $verdict['evidence'] );
				continue;
			}

			$severity = 'medium';
			if ( preg_match( '#^wp-(admin|includes)/#', $rel ) ) {
				$severity = 'critical';
			}
			if ( preg_match( '#wp-config\.php$#', $rel ) || preg_match( '#\.htaccess$#', $rel ) ) {
				$severity = 'high';
			}
			$this->record( 'INT-MOD', $severity, $rel, 'File modified since last baseline', '' );
		}

		// Deleted files: low severity (legitimate plugin uninstalls are common)
		foreach ( array_slice( $diff['deleted'], 0, 500 ) as $rel ) {
			if ( strpos( $rel, 'wp-content/plugins/malroot-security/' ) !== false ) {
				MR_Baseline::remove_from_baseline( $rel );
				continue;
			}
			$this->record( 'INT-DEL', 'low', $rel, 'File deleted since last baseline', '' );
		}
	}
}
