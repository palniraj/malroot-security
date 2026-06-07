<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * AJAX handlers for the async scan and quarantine actions.
 *
 * The scan is split into one AJAX call per scanner module so the browser
 * can show a live progress bar without the page timing out.
 */
class Malroot_Ajax {

	public static function register() {
		$actions = [
			'malroot_scan_step',
			'malroot_scan_finalise',
			'malroot_quarantine_finding',
			'malroot_rebuild_baseline',
		];
		foreach ( $actions as $action ) {
			add_action( 'wp_ajax_' . $action, [ __CLASS__, str_replace( 'malroot_', 'handle_', $action ) ] );
		}
	}

	/* ---------------------------------------------------------------- */
	/*  Step: run one scanner module                                    */
	/* ---------------------------------------------------------------- */

	public static function handle_scan_step() {
		check_ajax_referer( 'malroot_ajax', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Forbidden' );
		}

		$step    = sanitize_key( wp_unslash( $_POST['step'] ?? '' ) );
		$scan_id = (int) ( isset( $_POST['scan_id'] ) ? sanitize_text_field( wp_unslash( $_POST['scan_id'] ) ) : 0 );

		if ( ! $scan_id ) {
			$scan_id = time();
		}

		// phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
		@set_time_limit( 120 );

		$map = [
			'files'     => 'Malroot_Scanner_Files',
			'database'  => 'Malroot_Scanner_Database',
			'users'     => 'Malroot_Scanner_Users',
			'triggers'  => 'Malroot_Scanner_Triggers',
			'rest'      => 'Malroot_Scanner_REST',
			'muplugins' => 'Malroot_Scanner_MuPlugins',
			'botcloak'  => 'Malroot_Scanner_BotCloak',
			'integrity' => 'Malroot_Scanner_Integrity',
		];

		if ( ! isset( $map[ $step ] ) ) {
			wp_send_json_error( 'Unknown step: ' . $step );
		}

		$class = $map[ $step ];
		try {
			$scanner = new $class();
			$scanner->set_scan_id( $scan_id );
			$scanner->run();
		} catch ( Throwable $e ) {
			// Don't abort the whole scan for one module failure
			Malroot_Logger::error( 'Scanner step failed: ' . $step, [ 'error' => $e->getMessage() ] );
		}

		wp_send_json_success( [ 'scan_id' => $scan_id, 'step' => $step ] );
	}

	/* ---------------------------------------------------------------- */
	/*  Finalise: save scan ID, run auto-quarantine, return results     */
	/* ---------------------------------------------------------------- */

	public static function handle_scan_finalise() {
		check_ajax_referer( 'malroot_ajax', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Forbidden' );
		}

		$scan_id = (int) ( isset( $_POST['scan_id'] ) ? sanitize_text_field( wp_unslash( $_POST['scan_id'] ) ) : 0 );
		if ( ! $scan_id ) {
			wp_send_json_error( 'No scan ID' );
		}

		update_option( 'malroot_last_scan', $scan_id );

		// Auto-quarantine critical findings if enabled
		$settings = (array) get_option( 'malroot_settings', [] );
		if ( ! empty( $settings['auto_quarantine_critical'] ) ) {
			foreach ( Malroot_Findings::get_by_scan( $scan_id ) as $f ) {
				if ( $f->severity === 'critical' && $f->status === 'open' ) {
					Malroot_Quarantine::quarantine_finding( $f->id );
				}
			}
		}

		Malroot_Alerting::alert_after_scan( $scan_id );

		$findings = Malroot_Findings::get_by_scan( $scan_id );
		$counts   = Malroot_Findings::counts_by_severity( $scan_id );
		$score    = Malroot_Findings::security_score( $scan_id );

		// Serialise findings for JS
		$out = [];
		foreach ( $findings as $f ) {
			$out[] = [
				'id'       => (int) $f->id,
				'module'   => $f->module,
				'rule_id'  => $f->rule_id,
				'severity' => $f->severity,
				'target'   => $f->target,
				'summary'  => $f->summary,
				'details'  => $f->details,
				'status'   => $f->status,
			];
		}

		wp_send_json_success( [
			'scan_id'  => $scan_id,
			'counts'   => $counts,
			'score'    => $score,
			'findings' => $out,
		] );
	}

	/* ---------------------------------------------------------------- */
	/*  Rebuild baseline via AJAX                                       */
	/* ---------------------------------------------------------------- */

	public static function handle_rebuild_baseline() {
		check_ajax_referer( 'malroot_ajax', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Forbidden' );
		}
		// phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
		@set_time_limit( 300 );
		$count = Malroot_Baseline::rebuild();
		wp_send_json_success( [ 'count' => $count ] );
	}

	/* ---------------------------------------------------------------- */
	/*  Quarantine a single finding via AJAX                            */
	/* ---------------------------------------------------------------- */

	public static function handle_quarantine_finding() {
		check_ajax_referer( 'malroot_quarantine', 'nonce' );
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( 'Forbidden' );
		}

		// A single file move/zero can be slow on busy shared hosts; give it room.
		// phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
		@set_time_limit( 60 );

		$id     = (int) ( isset( $_POST['finding_id'] ) ? sanitize_text_field( wp_unslash( $_POST['finding_id'] ) ) : 0 );
		// A single, individually-confirmed removal may act on files inside
		// installed software (the operator read that specific finding and
		// chose to remove it). The bulk loop never sets this flag, so a
		// one-click "remove everything" can never destroy core/plugin/theme
		// files.
		$allow_protected = ! empty( $_POST['allow_protected'] );
		$result = Malroot_Quarantine::quarantine_finding( $id, $allow_protected );

		if ( is_wp_error( $result ) ) {
			wp_send_json_error( $result->get_error_message() );
		}
		wp_send_json_success( [ 'id' => $id ] );
	}
}
