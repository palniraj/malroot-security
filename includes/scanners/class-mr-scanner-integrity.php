<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * File integrity scanner.
 *
 * On first run it builds a baseline. Subsequent runs diff against the
 * baseline and emit findings for new/modified/deleted PHP, JS and
 * .htaccess files.
 */
class Malroot_Scanner_Integrity extends Malroot_Scanner_Base {

	protected $module = 'integrity';

	public function run() {
		if ( ! Malroot_Baseline::exists() ) {
			$count = Malroot_Baseline::rebuild();
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

		$diff = Malroot_Baseline::diff();

		// New files: auto-accept anything that's verified-safe (matches WordPress.org or plugin checksum)
		foreach ( array_slice( $diff['new'], 0, 500 ) as $rel ) {
			// Skip Malroot's own files — they change on every plugin update
			if ( strpos( $rel, 'wp-content/plugins/malroot-security/' ) !== false ) {
				Malroot_Baseline::add_to_baseline( $rel );
				continue;
			}
			// Verify the file. Malware always wins, regardless of version.
			$verdict = Malroot_Verifier::verify( $rel );
			if ( $verdict['verdict'] === Malroot_Verifier::VERDICT_MALICIOUS ) {
				$this->record( 'INT-NEW', 'critical', $rel, $verdict['reason'], $verdict['evidence'] );
				continue;
			}
			// Official checksum match, or the owning plugin/theme/core was updated
			// (its version changed) → this is legitimate update churn. Accept it.
			if ( $verdict['verdict'] === Malroot_Verifier::VERDICT_SAFE
				|| Malroot_Baseline::is_expected_update_change( $rel ) ) {
				Malroot_Baseline::add_to_baseline( $rel );
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
				Malroot_Baseline::add_to_baseline( $rel );
				continue;
			}
			$verdict = Malroot_Verifier::verify( $rel );
			if ( $verdict['verdict'] === Malroot_Verifier::VERDICT_MALICIOUS ) {
				$this->record( 'INT-MOD', 'critical', $rel, $verdict['reason'], $verdict['evidence'] );
				continue;
			}
			// Official checksum match, or the owning component's version changed
			// (legitimate update) → accept silently.
			if ( $verdict['verdict'] === Malroot_Verifier::VERDICT_SAFE
				|| Malroot_Baseline::is_expected_update_change( $rel ) ) {
				Malroot_Baseline::add_to_baseline( $rel );
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

		// Deleted files. An update that removes old files is the most common
		// cause. We can confirm this authoritatively for WordPress.org plugins
		// (the file isn't in the current official version), or by version change
		// for any component. Only flag deletions we genuinely can't explain.
		foreach ( array_slice( $diff['deleted'], 0, 2000 ) as $rel ) {
			if ( strpos( $rel, 'wp-content/plugins/malroot-security/' ) !== false
				|| Malroot_Baseline::is_expected_update_change( $rel )
				|| Malroot_Verifier::is_expected_plugin_deletion( $rel ) ) {
				Malroot_Baseline::remove_from_baseline( $rel );
				continue;
			}
			$this->record( 'INT-DEL', 'low', $rel, 'File deleted since last baseline', '' );
		}

		// Advance recorded versions for components that were just updated (whose
		// churn we accepted above), so future scans resume tamper detection for
		// them. Never touches unchanged components.
		Malroot_Baseline::reconcile_versions();
	}
}
