<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

class MR_Admin {

	public static function register() {
		add_action( 'admin_menu',                            [ __CLASS__, 'menu' ] );
		add_action( 'admin_enqueue_scripts',                 [ __CLASS__, 'enqueue' ] );
		add_action( 'admin_post_malroot_run_scan',           [ __CLASS__, 'handle_run_scan' ] );
		add_action( 'admin_post_malroot_quarantine',         [ __CLASS__, 'handle_quarantine' ] );
		add_action( 'admin_post_malroot_restore',            [ __CLASS__, 'handle_restore' ] );
		add_action( 'admin_post_malroot_save_settings',      [ __CLASS__, 'handle_save_settings' ] );
		add_action( 'admin_post_malroot_run_incident',       [ __CLASS__, 'handle_run_incident' ] );
		add_action( 'admin_post_malroot_rebuild_baseline',   [ __CLASS__, 'handle_rebuild_baseline' ] );
		add_action( 'admin_post_malroot_spam_dryrun',        [ __CLASS__, 'handle_spam_dryrun' ] );
		add_action( 'admin_post_malroot_spam_delete',        [ __CLASS__, 'handle_spam_delete' ] );
		add_action( 'admin_post_malroot_accept_finding',     [ __CLASS__, 'handle_accept_finding' ] );
		add_action( 'admin_post_malroot_ignore_finding',     [ __CLASS__, 'handle_ignore_finding' ] );
		add_action( 'admin_post_malroot_export_findings',    [ __CLASS__, 'handle_export_findings' ] );
		add_action( 'admin_post_malroot_test_email',         [ __CLASS__, 'handle_test_email' ] );
	}

	public static function enqueue( $hook ) {
		if ( strpos( $hook, 'malroot' ) === false ) {
			return;
		}
		wp_enqueue_style(
			'malroot-admin',
			MALROOT_URL . 'assets/css/malroot-admin.css',
			[],
			MALROOT_VERSION
		);
		wp_enqueue_script(
			'malroot-admin',
			MALROOT_URL . 'assets/js/malroot-admin.js',
			[ 'jquery' ],
			MALROOT_VERSION,
			true
		);
		wp_localize_script( 'malroot-admin', 'malrootAdmin', [
			'ajaxUrl'         => admin_url( 'admin-ajax.php' ),
			'nonce'           => wp_create_nonce( 'malroot_ajax' ),
			'quarantineNonce' => wp_create_nonce( 'malroot_quarantine' ),
			'scanId'          => 0,
			'i18n'            => [
				'scanning'      => __( 'Scanning…', 'malroot-security' ),
				'pleaseWait'    => __( 'Scan in progress. This may take up to 60 seconds.', 'malroot-security' ),
				'finalising'    => __( 'Finalising results…', 'malroot-security' ),
				'runScan'       => __( 'Run Full Scan Now', 'malroot-security' ),
				'error'         => __( 'Scan failed. Please try again.', 'malroot-security' ),
				'clean'         => __( 'No findings. Your site looks clean.', 'malroot-security' ),
				'findings'      => __( 'Findings', 'malroot-security' ),
				'snapshotting'  => __( 'Taking snapshot…', 'malroot-security' ),
				'updateSnapshot'=> __( 'Update Snapshot', 'malroot-security' ),
    /* translators: %s is replaced with dynamic content */
				'snapshotDone'  => __( 'Snapshot updated (%d files). Running a fresh scan…', 'malroot-security' ),
				'stepFiles'     => __( 'Scanning files…', 'malroot-security' ),
				'stepDatabase'  => __( 'Scanning database…', 'malroot-security' ),
				'stepUsers'     => __( 'Checking users…', 'malroot-security' ),
				'stepTriggers'  => __( 'Checking MySQL triggers…', 'malroot-security' ),
				'stepRest'      => __( 'Auditing REST routes…', 'malroot-security' ),
				'stepMuPlugins' => __( 'Checking mu-plugins…', 'malroot-security' ),
				'stepBotCloak'  => __( 'Bot-cloak check…', 'malroot-security' ),
				'stepIntegrity' => __( 'File integrity check…', 'malroot-security' ),
			],
		] );
	}

	public static function menu() {
		$cap = 'manage_options';
		add_menu_page( __( 'Malroot Security', 'malroot-security' ), __( 'Malroot', 'malroot-security' ), $cap, 'malroot-security', [ __CLASS__, 'render_dashboard' ], 'dashicons-shield-alt', 3 );
		add_submenu_page( 'malroot-security', __( 'Findings', 'malroot-security' ),     __( 'Findings', 'malroot-security' ),     $cap, 'malroot-security',             [ __CLASS__, 'render_dashboard' ] );
		add_submenu_page( 'malroot-security', __( 'Quarantine', 'malroot-security' ),   __( 'Quarantine', 'malroot-security' ),   $cap, 'malroot-quarantine',           [ __CLASS__, 'render_quarantine' ] );
		add_submenu_page( 'malroot-security', __( 'Connections', 'malroot-security' ),  __( 'Connections', 'malroot-security' ),  $cap, 'malroot-connections',          [ __CLASS__, 'render_connections' ] );
		add_submenu_page( 'malroot-security', __( 'Logins', 'malroot-security' ),       __( 'Logins', 'malroot-security' ),       $cap, 'malroot-logins',               [ __CLASS__, 'render_logins' ] );
		add_submenu_page( 'malroot-security', __( 'Spam Cleanup', 'malroot-security' ), __( 'Spam Cleanup', 'malroot-security' ), $cap, 'malroot-spam',                 [ __CLASS__, 'render_spam' ] );
		add_submenu_page( 'malroot-security', __( 'Incident Response', 'malroot-security' ), __( 'Incident Response', 'malroot-security' ), $cap, 'malroot-incident',  [ __CLASS__, 'render_incident' ] );
		add_submenu_page( 'malroot-security', __( 'Alerts', 'malroot-security' ),       __( 'Alerts', 'malroot-security' ),       $cap, 'malroot-alerts',               [ __CLASS__, 'render_alerts' ] );
		add_submenu_page( 'malroot-security', __( 'Settings', 'malroot-security' ),     __( 'Settings', 'malroot-security' ),     $cap, 'malroot-settings',             [ __CLASS__, 'render_settings' ] );
	}

	/* ---------------------------------------------------------------- */
	/*  Action handlers                                                 */
	/* ---------------------------------------------------------------- */

	public static function handle_run_scan() {
		if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Forbidden.', 403 );
		check_admin_referer( 'malroot_run_scan' );
		// phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
		@set_time_limit( 300 );
		MR_Loader::run_full_scan();
		wp_safe_redirect( admin_url( 'admin.php?page=malroot-security&scanned=1' ) );
		exit;
	}

	public static function handle_quarantine() {
		if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Forbidden.', 403 );
		check_admin_referer( 'malroot_quarantine' );
		$id = (int) ( isset( $_POST['finding_id'] ) ? sanitize_text_field( wp_unslash( $_POST['finding_id'] ) ) : 0 );
		$result = MR_Quarantine::quarantine_finding( $id );
		$args = is_wp_error( $result ) ? [ 'mr_error' => urlencode( $result->get_error_message() ) ] : [ 'mr_quarantined' => 1 ];
		wp_safe_redirect( add_query_arg( $args, admin_url( 'admin.php?page=malroot-security' ) ) );
		exit;
	}

	public static function handle_restore() {
		if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Forbidden.', 403 );
		check_admin_referer( 'malroot_restore' );
		$id = (int) ( isset( $_POST['quarantine_id'] ) ? sanitize_text_field( wp_unslash( $_POST['quarantine_id'] ) ) : 0 );
		$result = MR_Quarantine::restore( $id );
		$args = is_wp_error( $result ) ? [ 'mr_error' => urlencode( $result->get_error_message() ) ] : [ 'mr_restored' => 1 ];
		wp_safe_redirect( add_query_arg( $args, admin_url( 'admin.php?page=malroot-quarantine' ) ) );
		exit;
	}

	public static function handle_save_settings() {
		if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Forbidden.', 403 );
		check_admin_referer( 'malroot_save_settings' );
		$current = (array) get_option( 'malroot_settings', [] );
		$new = [
			'realtime_block_admin'     => empty( $_POST['realtime_block_admin'] ) ? 0 : 1,
			'realtime_scan_options'    => empty( $_POST['realtime_scan_options'] ) ? 0 : 1,
			'auto_quarantine_critical' => empty( $_POST['auto_quarantine_critical'] ) ? 0 : 1,
			'monitor_outbound'         => empty( $_POST['monitor_outbound'] ) ? 0 : 1,
			'scheduled_scans'          => empty( $_POST['scheduled_scans'] ) ? 0 : 1,
			'require_2fa_admins'       => empty( $_POST['require_2fa_admins'] ) ? 0 : 1,
			'alert_email'              => sanitize_email( wp_unslash( $_POST['alert_email'] ?? '' ) ),
			'slack_webhook'            => esc_url_raw( wp_unslash( $_POST['slack_webhook'] ?? '' ) ),
			'login_threshold'          => max( 3, min( 20, (int) ( isset( $_POST['login_threshold'] ) ? sanitize_text_field( wp_unslash( $_POST['login_threshold'] ) ) : 5 ) ) ),
		];
		update_option( 'malroot_settings', array_merge( $current, $new ) );

		// Custom blocked logins
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$blocked_logins = array_filter( array_map( 'sanitize_user', explode( "\n", wp_unslash( $_POST['blocked_logins'] ?? '' ) ) ) );
		update_option( 'malroot_blocked_logins', array_values( $blocked_logins ) );

		// Custom blocked email domains
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$blocked_domains = array_filter( array_map( 'sanitize_text_field', explode( "\n", wp_unslash( $_POST['blocked_email_domains'] ?? '' ) ) ) );
		update_option( 'malroot_blocked_email_domains', array_values( $blocked_domains ) );

		// Schedule / unschedule
		if ( $new['scheduled_scans'] ) {
			if ( ! wp_next_scheduled( 'malroot_daily_scan' ) ) {
				wp_schedule_event( time() + 60, 'daily', 'malroot_daily_scan' );
			}
		} else {
			wp_clear_scheduled_hook( 'malroot_daily_scan' );
		}

		wp_safe_redirect( admin_url( 'admin.php?page=malroot-settings&mr_saved=1' ) );
		exit;
	}

	/* ---------------------------------------------------------------- */
	/*  Pages                                                           */
	/* ---------------------------------------------------------------- */

	public static function render_dashboard() {
		$last     = (int) get_option( 'malroot_last_scan', 0 );
		$findings = $last ? MR_Findings::get_by_scan( $last ) : [];
		$counts   = MR_Findings::counts_by_severity( $last );
		$score    = MR_Findings::security_score( $last );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$view     = isset( $_GET['view'] ) && sanitize_key( wp_unslash( $_GET['view'] ) ) === 'expert' ? 'expert' : 'simple';
		?>
		<div class="wrap malroot-wrap">
			<h1>Malroot Security <span class="malroot-version">v<?php echo esc_html( MALROOT_VERSION ); ?></span></h1>
			<p class="malroot-tagline"><?php esc_html_e( 'Catches the WordPress malware that file-based scanners miss: database-resident backdoors, rogue admins, malicious triggers, and self-healing rootkits.', 'malroot-security' ); ?></p>

			<?php self::flash_messages(); ?>

			<div class="malroot-action-bar">
				<button id="malroot-scan-btn" class="button button-primary button-large">
					<?php esc_html_e( 'Run Full Scan Now', 'malroot-security' ); ?>
				</button>
				<?php if ( $last ) : ?>
					<span class="malroot-last-scan">
						<?php
						/* translators: %s: human-readable time difference (e.g. "5 minutes") */
						printf( esc_html__( 'Last scan: %s ago', 'malroot-security' ), esc_html( human_time_diff( $last ) ) );
						?>
					</span>
				<?php endif; ?>
				<button id="malroot-snapshot-btn" class="button button-secondary"
					title="<?php esc_attr_e( 'Run after updating plugins or WordPress core', 'malroot-security' ); ?>">
					<?php esc_html_e( 'Update Snapshot', 'malroot-security' ); ?>
				</button>
				<?php if ( $last ) : ?>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline">
						<input type="hidden" name="action" value="malroot_export_findings" />
						<?php wp_nonce_field( 'malroot_export_findings' ); ?>
						<button type="submit" class="button button-secondary">
							<?php esc_html_e( 'Export CSV', 'malroot-security' ); ?>
						</button>
					</form>
					<span class="malroot-view-toggle">
						<?php esc_html_e( 'View:', 'malroot-security' ); ?>
						<a href="<?php echo esc_url( add_query_arg( 'view', 'simple', admin_url( 'admin.php?page=malroot-security' ) ) ); ?>"
						   class="<?php echo $view === 'simple' ? 'active' : ''; ?>">
							<?php esc_html_e( 'Simple', 'malroot-security' ); ?>
						</a> |
						<a href="<?php echo esc_url( add_query_arg( 'view', 'expert', admin_url( 'admin.php?page=malroot-security' ) ) ); ?>"
						   class="<?php echo $view === 'expert' ? 'active' : ''; ?>">
							<?php esc_html_e( 'Expert', 'malroot-security' ); ?>
						</a>
					</span>
				<?php endif; ?>
			</div>

			<div id="malroot-progress-wrap">
				<div id="malroot-scan-status"><?php esc_html_e( 'Starting scan…', 'malroot-security' ); ?></div>
				<div id="malroot-progress-bar-bg"><div id="malroot-progress-bar-inner"></div></div>
			</div>

			<div id="malroot-results-wrap">
				<?php if ( $last ) : ?>
					<?php self::render_score_tiles( $score, $counts ); ?>
					<?php if ( $view === 'simple' ) : ?>
						<?php self::render_simple_view( $findings ); ?>
					<?php else : ?>
						<?php self::render_findings_table( $findings ); ?>
					<?php endif; ?>
				<?php else : ?>
					<div class="mr-empty"><?php esc_html_e( 'No scans yet. Click "Run Full Scan Now" to start.', 'malroot-security' ); ?></div>
				<?php endif; ?>
			</div>
		</div>
		<?php
	}

	private static function render_simple_view( $findings ) {
		// Filter out info-level findings and already-fixed items for simple view
		$open = array_filter( $findings, function( $f ) {
			return $f->status !== 'fixed' && $f->severity !== 'info';
		} );

		if ( empty( $open ) ) {
			echo '<div class="malroot-clean-notice"><span class="dashicons dashicons-yes-alt"></span> ';
			esc_html_e( 'Great news — no security issues found. Your site looks clean.', 'malroot-security' );
			echo '</div>';
			return;
		}

		// Separate integrity findings from real security findings
		$integrity_only = array_filter( $open, fn( $f ) => $f->module === 'integrity' );
		$real_threats   = array_filter( $open, fn( $f ) => $f->module !== 'integrity' );

		// If ALL open findings are integrity-only, show a single smart banner
		if ( ! empty( $integrity_only ) && empty( $real_threats ) ) {
			self::render_integrity_update_banner( $integrity_only );
			return;
		}

		// If there are real threats AND some integrity findings, show the banner
		// below the real threats (don't mix them in the urgent list)
		if ( ! empty( $real_threats ) ) {
			$urgent  = array_filter( $real_threats, fn( $f ) => in_array( $f->severity, [ 'critical', 'high' ], true ) );
			$review  = array_filter( $real_threats, fn( $f ) => in_array( $f->severity, [ 'medium', 'low' ], true ) );

			if ( $urgent ) {
				echo '<h2 style="color:#dc3232;margin-top:24px">🚨 ' . esc_html__( 'Action required', 'malroot-security' ) . ' <span style="font-size:14px;font-weight:normal;color:#666">(' . count( $urgent ) . ')</span></h2>';
				echo '<p style="color:#555">' . esc_html__( 'These issues need your attention now. Click the button on each card to fix it.', 'malroot-security' ) . '</p>';
				foreach ( $urgent as $f ) {
					self::render_plain_card( $f );
				}
			}
			if ( $review ) {
				echo '<h2 style="color:#ffb900;margin-top:32px">👀 ' . esc_html__( 'Worth reviewing', 'malroot-security' ) . ' <span style="font-size:14px;font-weight:normal;color:#666">(' . count( $review ) . ')</span></h2>';
				echo '<p style="color:#555">' . esc_html__( 'These are lower-priority findings. Review them when you have time.', 'malroot-security' ) . '</p>';
				foreach ( $review as $f ) {
					self::render_plain_card( $f );
				}
			}
		}

		// Show integrity banner at the bottom if there are also real threats
		if ( ! empty( $integrity_only ) ) {
			self::render_integrity_update_banner( $integrity_only );
		}
	}

	private static function render_integrity_update_banner( $integrity_findings ) {
		// Verify EVERY changed file before deciding whether it's safe to accept.
		// This is the security-critical step: never trust the user's memory.
		$verified_safe = [];
		$probably_safe = [];
		$unknown       = [];
		$malicious     = [];

		foreach ( $integrity_findings as $f ) {
			$v = MR_Verifier::verify( $f->target );
			$f->_verdict = $v;
			switch ( $v['verdict'] ) {
				case MR_Verifier::VERDICT_SAFE:      $verified_safe[] = $f; break;
				case MR_Verifier::VERDICT_PROBABLY:  $probably_safe[] = $f; break;
				case MR_Verifier::VERDICT_MALICIOUS: $malicious[]     = $f; break;
				default:                             $unknown[]       = $f;
			}
		}

		// Render verified malicious findings as critical cards FIRST
		// (these were hiding inside what looked like a routine update)
		if ( $malicious ) {
			echo '<h2 style="color:#dc3232;margin-top:24px">🚨 ' . esc_html__( 'Verified malware found in changed files', 'malroot-security' ) . ' <span style="font-size:14px;font-weight:normal;color:#666">(' . count( $malicious ) . ')</span></h2>';
			echo '<p style="color:#555">' . esc_html__( 'Malroot checked these files against trusted sources and found malicious content. Do NOT click "Accept Changes" — these need to be removed.', 'malroot-security' ) . '</p>';
			foreach ( $malicious as $f ) {
				self::render_malicious_integrity_card( $f );
			}
		}

		// Verified safe banner — only show "Accept" for these
		$accept_count = count( $verified_safe ) + count( $probably_safe );
		if ( $accept_count ) {
			?>
			<div style="border:1px solid #46b450;background:#ecf7ed;border-radius:4px;padding:20px;margin-top:24px">
				<div style="display:flex;align-items:flex-start;gap:12px">
					<span style="font-size:28px;line-height:1">✅</span>
					<div style="flex:1">
						<div style="font-size:16px;font-weight:600;margin-bottom:8px;color:#1e4620">
							<?php
							printf(
								esc_html(
									/* translators: %d: number of file changes verified as safe */
									_n(
										'%d file change verified as safe',
										'%d file changes verified as safe',
										$accept_count,
										'malroot-security'
									)
								),
								(int) $accept_count
							);
							?>
						</div>
						<p style="font-size:13px;color:#444;margin:0 0 8px">
							<?php
							$safe_n     = count( $verified_safe );
							$probably_n = count( $probably_safe );
							$bits = [];
							if ( $safe_n ) {
								/* translators: %d: number of files matching official WordPress.org checksums */
								$bits[] = sprintf( esc_html__( '%d match official WordPress.org checksums', 'malroot-security' ), $safe_n );
							}
							if ( $probably_n ) {
								/* translators: %d: number of files matching a recent plugin/theme update */
								$bits[] = sprintf( esc_html__( '%d match a recent plugin/theme update', 'malroot-security' ), $probably_n );
							}
							echo esc_html( implode( '; ', $bits ) . '.' );
							?>
						</p>
						<p style="font-size:13px;color:#555;margin:0 0 16px">
							<?php esc_html_e( 'These files are verified safe. Click "Accept" to update your security snapshot for these files only.', 'malroot-security' ); ?>
						</p>
						<button id="malroot-snapshot-btn" class="button button-primary" style="background:#46b450;border-color:#388e3c">
							✓ <?php esc_html_e( 'Accept Verified Safe Changes', 'malroot-security' ); ?>
						</button>
						<details style="margin-top:12px">
							<summary style="cursor:pointer;font-size:12px;color:#666"><?php esc_html_e( 'Show what was verified', 'malroot-security' ); ?></summary>
							<ul style="margin:8px 0 0 16px;font-size:12px;color:#555">
								<?php foreach ( $verified_safe as $f ) : ?>
									<li>✅ <code><?php echo esc_html( basename( $f->target ) ); ?></code> — <?php echo esc_html( $f->_verdict['reason'] ); ?></li>
								<?php endforeach; ?>
								<?php foreach ( $probably_safe as $f ) : ?>
									<li>⚠️ <code><?php echo esc_html( basename( $f->target ) ); ?></code> — <?php echo esc_html( $f->_verdict['reason'] ); ?></li>
								<?php endforeach; ?>
							</ul>
						</details>
					</div>
				</div>
			</div>
			<?php
		}

		// Unknown files — show as separate cards needing manual review
		if ( $unknown ) {
			echo '<h2 style="color:#ffb900;margin-top:24px">🤔 ' . esc_html__( 'Files needing your review', 'malroot-security' ) . ' <span style="font-size:14px;font-weight:normal;color:#666">(' . count( $unknown ) . ')</span></h2>';
			echo '<p style="color:#555">' . esc_html__( 'Malroot could not automatically verify these files. Please confirm whether you made these changes.', 'malroot-security' ) . '</p>';
			foreach ( $unknown as $f ) {
				self::render_unknown_integrity_card( $f );
			}
		}
	}

	private static function render_malicious_integrity_card( $f ) {
		?>
		<div style="border-left:4px solid #dc3232;background:#fef7f7;border:1px solid #f5b7b1;border-left:4px solid #dc3232;border-radius:4px;padding:20px;margin-bottom:16px">
			<div style="display:flex;align-items:flex-start;gap:12px">
				<span style="font-size:28px;line-height:1">🦠</span>
				<div style="flex:1">
					<div style="font-size:16px;font-weight:600;margin-bottom:8px;color:#a00">
						<?php esc_html_e( 'Malware detected — this is NOT a legitimate update', 'malroot-security' ); ?>
					</div>
					<div style="font-size:13px;color:#444;margin-bottom:8px">
						<?php
						printf(
							/* translators: %s: file path */
							esc_html__( 'The file %s contains malicious code.', 'malroot-security' ),
							'<code>' . esc_html( $f->target ) . '</code>'
						);
						?>
					</div>
					<div style="background:#fff;border:1px solid #f5b7b1;border-radius:3px;padding:10px 12px;font-size:13px;color:#555;margin-bottom:12px">
						<strong><?php esc_html_e( 'What Malroot found:', 'malroot-security' ); ?></strong>
						<?php echo esc_html( $f->_verdict['reason'] ); ?>
					</div>
					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
						<input type="hidden" name="action" value="malroot_quarantine" />
						<input type="hidden" name="finding_id" value="<?php echo (int) $f->id; ?>" />
						<?php wp_nonce_field( 'malroot_quarantine' ); ?>
						<button type="submit" class="button button-primary"
							style="background:#dc3232;border-color:#a00;text-shadow:none"
							onclick="return confirm('<?php esc_attr_e( 'Remove this malicious file? It will be moved to the Quarantine page so you can restore it if needed.', 'malroot-security' ); ?>')">
							🗑️ <?php esc_html_e( 'Remove Malware', 'malroot-security' ); ?>
						</button>
					</form>
				</div>
			</div>
		</div>
		<?php
	}

	private static function render_unknown_integrity_card( $f ) {
		?>
		<div style="border-left:4px solid #ffb900;background:#fffbe6;border:1px solid #ffe082;border-left:4px solid #ffb900;border-radius:4px;padding:20px;margin-bottom:16px">
			<div style="display:flex;align-items:flex-start;gap:12px">
				<span style="font-size:28px;line-height:1">🤔</span>
				<div style="flex:1">
					<div style="font-size:16px;font-weight:600;margin-bottom:8px">
						<?php
						$which = $f->rule_id === 'INT-NEW' ? __( 'New file — origin unknown', 'malroot-security' ) : __( 'Modified file — origin unknown', 'malroot-security' );
						echo esc_html( $which );
						?>
					</div>
					<div style="font-size:13px;color:#444;margin-bottom:8px">
						<code><?php echo esc_html( $f->target ); ?></code>
					</div>
					<div style="background:#fff;border:1px solid #ffe082;border-radius:3px;padding:10px 12px;font-size:13px;color:#555;margin-bottom:12px">
						<strong><?php esc_html_e( 'Why this needs review:', 'malroot-security' ); ?></strong>
						<?php echo esc_html( $f->_verdict['reason'] ); ?>
					</div>
					<div style="font-size:13px;color:#555;margin-bottom:12px">
						<strong><?php esc_html_e( 'Did you make this change?', 'malroot-security' ); ?></strong>
						<?php esc_html_e( 'For example, did you upload a custom file, edit a theme, or use a developer tool?', 'malroot-security' ); ?>
					</div>
					<div style="display:flex;gap:8px;flex-wrap:wrap">
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline">
							<input type="hidden" name="action" value="malroot_accept_finding" />
							<input type="hidden" name="finding_id" value="<?php echo (int) $f->id; ?>" />
							<?php wp_nonce_field( 'malroot_accept_finding' ); ?>
							<button type="submit" class="button" style="background:#fff">
								✓ <?php esc_html_e( 'I made this change — accept it', 'malroot-security' ); ?>
							</button>
						</form>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline">
							<input type="hidden" name="action" value="malroot_quarantine" />
							<input type="hidden" name="finding_id" value="<?php echo (int) $f->id; ?>" />
							<?php wp_nonce_field( 'malroot_quarantine' ); ?>
							<button type="submit" class="button" style="background:#fff;color:#a00">
								🗑️ <?php esc_html_e( 'I did NOT make this change — remove it', 'malroot-security' ); ?>
							</button>
						</form>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline">
							<input type="hidden" name="action" value="malroot_ignore_finding" />
							<input type="hidden" name="finding_id" value="<?php echo (int) $f->id; ?>" />
							<?php wp_nonce_field( 'malroot_ignore_finding' ); ?>
							<button type="submit" class="button button-link" style="color:#888">
								<?php esc_html_e( 'Ignore', 'malroot-security' ); ?>
							</button>
						</form>
						<a href="<?php echo esc_url( add_query_arg( 'view', 'expert', admin_url( 'admin.php?page=malroot-security' ) ) ); ?>" class="button">
							🔍 <?php esc_html_e( 'View file details', 'malroot-security' ); ?>
						</a>
					</div>
				</div>
			</div>
		</div>
		<?php
	}

	private static function render_plain_card( $f ) {
		$pl = MR_Plain_Language::translate( $f );
		$sev_colors = [
			'critical' => '#dc3232',
			'high'     => '#dc3232',
			'medium'   => '#ffb900',
			'low'      => '#888',
		];
		$border_color = $sev_colors[ $f->severity ] ?? '#ccd0d4';
		?>
		<div style="border-left:4px solid <?php echo esc_attr( $border_color ); ?>;background:#fff;border:1px solid #e0e0e0;border-left:4px solid <?php echo esc_attr( $border_color ); ?>;border-radius:4px;padding:20px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,.06)">
			<div style="display:flex;align-items:flex-start;gap:12px">
				<span style="font-size:28px;line-height:1"><?php echo esc_html( $pl['icon'] ); ?></span>
				<div style="flex:1">
					<div style="font-size:16px;font-weight:600;margin-bottom:8px"><?php echo wp_kses_post( $pl['title'] ); ?></div>

					<div style="font-size:13px;color:#444;margin-bottom:8px;line-height:1.6">
						<?php echo wp_kses_post( $pl['what'] ); ?>
					</div>

					<?php if ( $pl['why_bad'] ) : ?>
					<div style="background:#fff8e1;border:1px solid #ffe082;border-radius:3px;padding:10px 12px;font-size:13px;color:#555;margin-bottom:12px;line-height:1.5">
						<strong><?php esc_html_e( 'Why this matters:', 'malroot-security' ); ?></strong>
						<?php echo wp_kses_post( $pl['why_bad'] ); ?>
					</div>
					<?php endif; ?>

					<div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap">
						<div style="font-size:13px;color:#555;flex:1">
							<strong><?php esc_html_e( 'What to do:', 'malroot-security' ); ?></strong>
							<?php echo wp_kses_post( $pl['action'] ); ?>
						</div>

						<?php if ( $pl['action_type'] === 'quarantine' && $f->status !== 'fixed' ) : ?>
							<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="flex-shrink:0">
								<input type="hidden" name="action" value="malroot_quarantine" />
								<input type="hidden" name="finding_id" value="<?php echo (int) $f->id; ?>" />
								<?php wp_nonce_field( 'malroot_quarantine' ); ?>
								<button type="submit"
									class="button button-primary"
									style="background:#dc3232;border-color:#a00;text-shadow:none"
									onclick="return confirm('<?php esc_attr_e( 'This will safely remove the item. You can restore it from the Quarantine page if needed. Continue?', 'malroot-security' ); ?>')">
									<?php
									if ( $f->module === 'users' ) {
										esc_html_e( 'Remove Account', 'malroot-security' );
									} elseif ( $f->module === 'triggers' ) {
										esc_html_e( 'Fix Now', 'malroot-security' );
									} elseif ( $f->module === 'database' ) {
										esc_html_e( 'Clean Up', 'malroot-security' );
									} elseif ( $f->module === 'integrity' ) {
										esc_html_e( 'Quarantine File', 'malroot-security' );
									} else {
										esc_html_e( 'Remove File', 'malroot-security' );
									}
									?>
								</button>
							</form>
						<?php elseif ( $pl['action_type'] === 'rebuild_baseline' ) : ?>
							<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="flex-shrink:0">
								<input type="hidden" name="action" value="malroot_rebuild_baseline" />
								<?php wp_nonce_field( 'malroot_rebuild_baseline' ); ?>
								<button type="submit" class="button button-primary">
									<?php esc_html_e( 'Update Snapshot', 'malroot-security' ); ?>
								</button>
							</form>
						<?php elseif ( $pl['action_type'] === 'manual' ) : ?>
							<span style="font-size:12px;color:#888;background:#f6f7f7;padding:4px 10px;border-radius:3px;border:1px solid #ddd">
								<?php esc_html_e( 'Manual action needed', 'malroot-security' ); ?>
							</span>
						<?php elseif ( $f->status === 'fixed' ) : ?>
							<span style="color:#46b450;font-weight:600">✓ <?php esc_html_e( 'Fixed', 'malroot-security' ); ?></span>
						<?php endif; ?>
					</div>

					<details style="margin-top:12px">
						<summary style="cursor:pointer;font-size:11px;color:#999"><?php esc_html_e( 'Technical details (for developers)', 'malroot-security' ); ?></summary>
						<div style="font-size:11px;color:#666;margin-top:6px;padding:8px;background:#f6f7f7;border-radius:3px">
							<code><?php echo esc_html( $f->rule_id ); ?></code> · <?php echo esc_html( $f->module ); ?> · <code><?php echo esc_html( $f->target ); ?></code>
							<?php if ( $f->summary ) : ?>
								<br><?php echo esc_html( $f->summary ); ?>
							<?php endif; ?>
						</div>
					</details>
				</div>
			</div>
		</div>
		<?php
	}

	public static function render_quarantine() {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}malroot_quarantine ORDER BY id DESC LIMIT 200" );
		$type_icons = [];
		?>
		<div class="wrap malroot-wrap">
			<h1><?php esc_html_e( 'Quarantine', 'malroot-security' ); ?></h1>
			<p class="malroot-tagline"><?php esc_html_e( 'Items neutralised by Malroot. Files are moved to a private folder; options/triggers/users are removed but their original payloads are stored here for restore.', 'malroot-security' ); ?></p>
			<?php self::flash_messages(); ?>
			<?php if ( empty( $rows ) ) : ?>
				<div class="mr-empty"><?php esc_html_e( 'Nothing quarantined yet.', 'malroot-security' ); ?></div>
			<?php else : ?>
			<table class="widefat mr-data-table">
				<thead><tr>
					<th style="width:100px"><?php esc_html_e( 'Type', 'malroot-security' ); ?></th>
					<th><?php esc_html_e( 'Target', 'malroot-security' ); ?></th>
					<th style="width:110px"><?php esc_html_e( 'Status', 'malroot-security' ); ?></th>
					<th style="width:160px"><?php esc_html_e( 'When', 'malroot-security' ); ?></th>
					<th style="width:90px"><?php esc_html_e( 'Action', 'malroot-security' ); ?></th>
				</tr></thead>
				<tbody>
				<?php foreach ( $rows as $r ) : ?>
					<tr>
						<td>
							<span class="mr-quarantine-type mr-quarantine-type-<?php echo esc_attr( $r->item_type ); ?>">
								<?php echo esc_html( $r->item_type ); ?>
							</span>
						</td>
						<td><code class="mr-truncate" style="max-width:400px" title="<?php echo esc_attr( $r->target ); ?>"><?php echo esc_html( $r->target ); ?></code></td>
						<td><span class="mr-badge mr-badge-<?php echo esc_attr( $r->status ); ?>"><?php echo esc_html( $r->status ); ?></span></td>
						<td style="font-size:12px;color:#666"><?php echo esc_html( $r->created_at ); ?></td>
						<td>
							<?php if ( $r->status === 'quarantined' && in_array( $r->item_type, [ 'file', 'option', 'postmeta' ], true ) ) : ?>
								<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
									<input type="hidden" name="action" value="malroot_restore" />
									<input type="hidden" name="quarantine_id" value="<?php echo (int) $r->id; ?>" />
									<?php wp_nonce_field( 'malroot_restore' ); ?>
									<button type="submit" class="button button-small" onclick="return confirm('<?php esc_attr_e( 'Restore this item?', 'malroot-security' ); ?>')">
										↩ <?php esc_html_e( 'Restore', 'malroot-security' ); ?>
									</button>
								</form>
							<?php elseif ( $r->status === 'quarantined' ) : ?>
								<span style="font-size:11px;color:#888"><?php esc_html_e( 'Manual restore', 'malroot-security' ); ?></span>
							<?php endif; ?>
						</td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
			<?php endif; ?>
		</div>
		<?php
	}

	public static function render_connections() {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}malroot_connections ORDER BY last_seen DESC LIMIT 500" );
		?>
		<div class="wrap malroot-wrap">
			<h1><?php esc_html_e( 'Outbound Connections', 'malroot-security' ); ?></h1>
			<p class="malroot-tagline"><?php esc_html_e( 'Every external HTTP request your site has made (excluding well-known WordPress hosts).', 'malroot-security' ); ?></p>
			<?php if ( empty( $rows ) ) : ?>
				<div class="mr-empty"><?php esc_html_e( 'No external connections recorded yet.', 'malroot-security' ); ?></div>
			<?php else : ?>
			<table class="widefat mr-data-table">
				<thead><tr>
					<th><?php esc_html_e( 'Domain', 'malroot-security' ); ?></th>
					<th style="width:70px"><?php esc_html_e( 'Method', 'malroot-security' ); ?></th>
					<th style="width:50px"><?php esc_html_e( 'Hits', 'malroot-security' ); ?></th>
					<th><?php esc_html_e( 'Caller', 'malroot-security' ); ?></th>
					<th style="width:160px"><?php esc_html_e( 'Last seen', 'malroot-security' ); ?></th>
				</tr></thead>
				<tbody>
				<?php foreach ( $rows as $r ) : ?>
					<tr>
						<td>
							<strong style="font-size:13px"><?php echo esc_html( $r->domain ); ?></strong>
						</td>
						<td><span class="mr-badge mr-badge-<?php echo esc_attr( strtolower( $r->method ) ); ?>"><?php echo esc_html( $r->method ); ?></span></td>
						<td style="text-align:center;font-weight:600"><?php echo (int) $r->hit_count; ?></td>
						<td>
							<?php if ( $r->caller ) : ?>
								<code class="mr-ua-truncate" title="<?php echo esc_attr( $r->caller ); ?>"><?php echo esc_html( $r->caller ); ?></code>
							<?php else : ?>
								<span style="color:#ccc">—</span>
							<?php endif; ?>
						</td>
						<td style="font-size:12px;color:#666"><?php echo esc_html( $r->last_seen ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
			<?php endif; ?>
		</div>
		<?php
	}

	public static function render_alerts() {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}malroot_alerts ORDER BY id DESC LIMIT 200" );
		// Human-readable event labels
		$event_labels = [
			'scan_complete'          => 'Scan completed',
			'new_administrator'      => 'New admin created',
			'admin_login_new_origin' => 'Admin login — new location',
			'admin_login_automated_ua' => 'Admin login — automated tool',
			'login_lockout'          => 'IP locked out',
			'2fa_enabled'            => '2FA enabled',
			'2fa_disabled'           => '2FA disabled',
			'2fa_failed'             => '2FA failed attempt',
			'2fa_recovery_used'      => '2FA recovery code used',
			'blocked_user_creation'  => 'Blocked user creation',
			'outbound_to_c2'         => 'Outbound to C2 host',
			'option_payload_blocked' => 'Malware option blocked',
			'rest_user_register'     => 'REST user registration',
			'incident_response_run'  => 'Incident response run',
			'spam_honeypot'          => 'Spam honeypot triggered',
		];
		?>
		<div class="wrap malroot-wrap">
			<h1><?php esc_html_e( 'Alerts', 'malroot-security' ); ?></h1>
			<p class="malroot-tagline"><?php esc_html_e( 'Security events detected by Malroot\'s real-time monitors.', 'malroot-security' ); ?></p>
			<?php if ( empty( $rows ) ) : ?>
				<div class="mr-empty"><?php esc_html_e( 'No alerts. Everything looks quiet.', 'malroot-security' ); ?></div>
			<?php else : ?>
			<table class="widefat mr-data-table">
				<thead><tr>
					<th style="width:90px"><?php esc_html_e( 'Severity', 'malroot-security' ); ?></th>
					<th style="width:200px"><?php esc_html_e( 'Event', 'malroot-security' ); ?></th>
					<th><?php esc_html_e( 'Summary', 'malroot-security' ); ?></th>
					<th style="width:160px"><?php esc_html_e( 'When', 'malroot-security' ); ?></th>
				</tr></thead>
				<tbody>
				<?php foreach ( $rows as $r ) : ?>
					<tr>
						<td><span class="mr-badge mr-badge-<?php echo esc_attr( $r->severity ); ?>"><?php echo esc_html( strtoupper( $r->severity ) ); ?></span></td>
						<td>
							<div class="mr-alert-event-label"><?php echo esc_html( $event_labels[ $r->event_type ] ?? ucwords( str_replace( '_', ' ', $r->event_type ) ) ); ?></div>
							<div><span class="mr-alert-event"><?php echo esc_html( $r->event_type ); ?></span></div>
						</td>
						<td>
							<?php echo esc_html( $r->summary ); ?>
							<?php if ( $r->context ) : ?>
								<details class="malroot-details"><summary><?php esc_html_e( 'context', 'malroot-security' ); ?></summary>
									<pre><?php echo esc_html( $r->context ); ?></pre>
								</details>
							<?php endif; ?>
						</td>
						<td style="font-size:12px;color:#666"><?php echo esc_html( $r->created_at ); ?></td>
					</tr>
				<?php endforeach; ?>
				</tbody>
			</table>
			<?php endif; ?>
		</div>
		<?php
	}

	public static function render_settings() {
		$s = (array) get_option( 'malroot_settings', [] );
		?>
		<div class="wrap malroot-wrap">
			<h1><?php esc_html_e( 'Malroot Settings', 'malroot-security' ); ?></h1>
			<?php self::flash_messages(); ?>
			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="malroot_save_settings" />
				<?php wp_nonce_field( 'malroot_save_settings' ); ?>

				<div class="mr-settings-section">
					<div class="mr-settings-section-header"><?php esc_html_e( 'Real-time Protection', 'malroot-security' ); ?></div>
					<table class="form-table">
						<tr><th><?php esc_html_e( 'Admin creation alerts', 'malroot-security' ); ?></th>
							<td><label><input type="checkbox" name="realtime_block_admin" value="1" <?php checked( ! empty( $s['realtime_block_admin'] ) ); ?>> <?php esc_html_e( 'Alert when a new administrator is created (especially via REST/XML-RPC).', 'malroot-security' ); ?></label></td></tr>
						<tr><th><?php esc_html_e( 'Option injection blocking', 'malroot-security' ); ?></th>
							<td><label><input type="checkbox" name="realtime_scan_options" value="1" <?php checked( ! empty( $s['realtime_scan_options'] ) ); ?>> <?php esc_html_e( 'Block option saves containing eval/base64/known C2 strings.', 'malroot-security' ); ?></label></td></tr>
						<tr><th><?php esc_html_e( 'Outbound connection monitor', 'malroot-security' ); ?></th>
							<td><label><input type="checkbox" name="monitor_outbound" value="1" <?php checked( ! empty( $s['monitor_outbound'] ) ); ?>> <?php esc_html_e( 'Log every external HTTP request and alert on known C2 hosts.', 'malroot-security' ); ?></label></td></tr>
					</table>
				</div>

				<div class="mr-settings-section">
					<div class="mr-settings-section-header"><?php esc_html_e( 'Scanning', 'malroot-security' ); ?></div>
					<table class="form-table">
						<tr><th><?php esc_html_e( 'Auto-quarantine critical findings', 'malroot-security' ); ?></th>
							<td><label><input type="checkbox" name="auto_quarantine_critical" value="1" <?php checked( ! empty( $s['auto_quarantine_critical'] ) ); ?>> <?php esc_html_e( 'After every scan, automatically quarantine any critical finding.', 'malroot-security' ); ?></label></td></tr>
						<tr><th><?php esc_html_e( 'Daily background scan', 'malroot-security' ); ?></th>
							<td><label><input type="checkbox" name="scheduled_scans" value="1" <?php checked( ! empty( $s['scheduled_scans'] ) ); ?>> <?php esc_html_e( 'Run a full scan once a day via WP-Cron.', 'malroot-security' ); ?></label></td></tr>
					</table>
				</div>

				<div class="mr-settings-section">
					<div class="mr-settings-section-header"><?php esc_html_e( 'Login Security', 'malroot-security' ); ?></div>
					<table class="form-table">
						<tr><th><?php esc_html_e( 'Require 2FA for administrators', 'malroot-security' ); ?></th>
							<td><label><input type="checkbox" name="require_2fa_admins" value="1" <?php checked( ! empty( $s['require_2fa_admins'] ) ); ?>>
								<?php esc_html_e( 'Lock administrators out of all admin pages until they have set up 2FA on their profile.', 'malroot-security' ); ?></label>
								<p class="description"><?php esc_html_e( 'Each user configures 2FA from Users → Profile → Two-Factor Authentication.', 'malroot-security' ); ?></p>
							</td></tr>
						<tr><th><?php esc_html_e( 'Blocked usernames', 'malroot-security' ); ?></th>
							<td>
								<textarea name="blocked_logins" rows="4" class="large-text code" placeholder="newsfeed&#10;system_control&#10;wpadmin"><?php
									$blocked = (array) get_option( 'malroot_blocked_logins', [] );
									echo esc_textarea( implode( "\n", $blocked ) );
								?></textarea>
								<p class="description"><?php esc_html_e( 'One username per line. These logins will be blocked from being created or logging in.', 'malroot-security' ); ?></p>
							</td></tr>
						<tr><th><?php esc_html_e( 'Blocked email domains', 'malroot-security' ); ?></th>
							<td>
								<textarea name="blocked_email_domains" rows="4" class="large-text code" placeholder="inboxmailer.org&#10;fringmail.com"><?php
									$domains = (array) get_option( 'malroot_blocked_email_domains', [] );
									echo esc_textarea( implode( "\n", $domains ) );
								?></textarea>
								<p class="description"><?php esc_html_e( 'One domain per line. Registrations and logins from these email domains will be blocked.', 'malroot-security' ); ?></p>
							</td></tr>
						<tr><th><?php esc_html_e( 'Login failure threshold', 'malroot-security' ); ?></th>
							<td>
								<input type="number" name="login_threshold" min="3" max="20" value="<?php echo (int) ( $s['login_threshold'] ?? 5 ); ?>" style="width:80px">
								<span class="description"><?php esc_html_e( 'failed attempts before 30-minute IP lockout.', 'malroot-security' ); ?></span>
							</td></tr>
					</table>
				</div>

				<div class="mr-settings-section">
					<div class="mr-settings-section-header"><?php esc_html_e( 'Alerting', 'malroot-security' ); ?></div>
					<table class="form-table">
						<tr><th><?php esc_html_e( 'Alert email', 'malroot-security' ); ?></th>
							<td>
								<input type="email" class="regular-text" name="alert_email" value="<?php echo esc_attr( $s['alert_email'] ?? '' ); ?>">
								<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline;margin-left:8px">
									<input type="hidden" name="action" value="malroot_test_email" />
									<?php wp_nonce_field( 'malroot_test_email' ); ?>
									<button type="submit" class="button button-secondary"><?php esc_html_e( 'Send test email', 'malroot-security' ); ?></button>
								</form>
								<p class="description"><?php esc_html_e( 'Critical and high alerts are sent immediately. Scan digests are sent when new findings appear.', 'malroot-security' ); ?></p>
							</td></tr>
						<tr><th><?php esc_html_e( 'Slack webhook URL', 'malroot-security' ); ?></th>
							<td><input type="url" class="regular-text" name="slack_webhook" value="<?php echo esc_attr( $s['slack_webhook'] ?? '' ); ?>" placeholder="https://hooks.slack.com/services/..."></td></tr>
					</table>
				</div>

				<p><button type="submit" class="button button-primary button-large"><?php esc_html_e( 'Save settings', 'malroot-security' ); ?></button></p>
			</form>
		</div>
		<?php
	}

	/* ---------------------------------------------------------------- */
	/*  Helpers                                                         */
	/* ---------------------------------------------------------------- */

	private static function flash_messages() {
		// phpcs:disable WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['scanned'] ) ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Scan complete.', 'malroot-security' ) . '</p></div>';
		}
		if ( isset( $_GET['mr_baseline_built'] ) ) {
			echo '<div class="notice notice-success is-dismissible"><p>' .
				sprintf(
					/* translators: %d: number of files in the security snapshot */
					esc_html__( 'Security snapshot updated (%d files). Future scans will compare against this new baseline.', 'malroot-security' ),
					(int) $_GET['mr_baseline_built']
				) . '</p></div>';
		}
		if ( isset( $_GET['mr_quarantined'] ) ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Item safely removed and backed up in Quarantine.', 'malroot-security' ) . '</p></div>';
		}
		if ( isset( $_GET['mr_restored'] ) ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Item restored successfully.', 'malroot-security' ) . '</p></div>';
		}
		if ( isset( $_GET['mr_saved'] ) ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Settings saved.', 'malroot-security' ) . '</p></div>';
		}
		if ( isset( $_GET['mr_test_sent'] ) ) {
			echo '<div class="notice notice-success is-dismissible"><p>' .
				sprintf(
					/* translators: %s: email address the test was sent to */
					esc_html__( 'Test email sent to %s. Check your inbox (and spam folder).', 'malroot-security' ),
					'<strong>' . esc_html( urldecode( sanitize_text_field( wp_unslash( $_GET['mr_test_sent'] ) ) ) ) . '</strong>'
				) . '</p></div>';
		}
		if ( isset( $_GET['mr_accepted'] ) ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Change accepted. Your security snapshot has been updated for that file.', 'malroot-security' ) . '</p></div>';
		}
		if ( isset( $_GET['mr_ignored'] ) ) {
			echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Finding marked as ignored. It will not appear in future open lists.', 'malroot-security' ) . '</p></div>';
		}
		if ( isset( $_GET['mr_error'] ) ) {
			echo '<div class="notice notice-error is-dismissible"><p>' . esc_html( urldecode( sanitize_text_field( wp_unslash( $_GET['mr_error'] ) ) ) ) . '</p></div>';
		}
		// phpcs:enable WordPress.Security.NonceVerification.Recommended
	}

	private static function render_score_tiles( $score, $counts ) {
		$score_color = $score >= 90 ? '#46b450' : ( $score >= 70 ? '#ffb900' : '#dc3232' );
		?>
		<div class="malroot-tiles">
			<div class="malroot-tile malroot-tile-score">
				<div class="malroot-tile-label"><?php esc_html_e( 'Security Score', 'malroot-security' ); ?></div>
				<div class="malroot-tile-value" style="color:<?php echo esc_attr( $score_color ); ?>"><?php echo (int) $score; ?></div>
			</div>
			<?php
			$sev_colors = [ 'critical' => '#dc3232', 'high' => '#dc3232', 'medium' => '#ffb900', 'low' => '#888', 'info' => '#888' ];
			foreach ( $sev_colors as $sev => $color ) :
				$c = (int) ( $counts[ $sev ] ?? 0 );
			?>
			<div class="malroot-tile">
				<div class="malroot-tile-label"><?php echo esc_html( ucfirst( $sev ) ); ?></div>
				<div class="malroot-tile-value" style="color:<?php echo $c > 0 ? esc_attr( $color ) : '#1d2327'; ?>"><?php echo esc_html( (string) $c ); ?></div>
			</div>
			<?php endforeach; ?>
		</div>
		<?php
	}

	private static function render_findings_table( $findings ) {
		if ( empty( $findings ) ) {
			echo '<div class="malroot-clean-notice"><span class="dashicons dashicons-yes-alt"></span>' . esc_html__( 'No findings. Your site looks clean.', 'malroot-security' ) . '</div>';
			return;
		}
		$open = array_filter( $findings, fn( $f ) => $f->status === 'open' );
		?>
		<h2 style="margin-top:20px"><?php esc_html_e( 'Findings', 'malroot-security' ); ?> <span style="font-size:14px;font-weight:400;color:#666">(<?php echo count( $open ); ?> open / <?php echo count( $findings ); ?> total)</span></h2>
		<table class="widefat malroot-findings-table mr-data-table">
			<thead><tr>
				<th style="width:90px"><?php esc_html_e( 'Severity', 'malroot-security' ); ?></th>
				<th style="width:90px"><?php esc_html_e( 'Module', 'malroot-security' ); ?></th>
				<th style="width:80px"><?php esc_html_e( 'Rule', 'malroot-security' ); ?></th>
				<th><?php esc_html_e( 'Target', 'malroot-security' ); ?></th>
				<th><?php esc_html_e( 'Summary', 'malroot-security' ); ?></th>
				<th style="width:130px"><?php esc_html_e( 'Action', 'malroot-security' ); ?></th>
			</tr></thead>
			<tbody>
				<?php foreach ( $findings as $f ) :
					$sev = $f->severity ?? 'info';
					$not_open = $f->status !== 'open';
				?>
					<tr style="<?php echo $not_open ? 'opacity:.5' : ''; ?>">
						<td><span class="mr-badge mr-badge-<?php echo esc_attr( $sev ); ?>"><?php echo esc_html( $sev ); ?></span></td>
						<td style="font-size:12px;color:#666"><?php echo esc_html( $f->module ); ?></td>
						<td><code style="font-size:11px"><?php echo esc_html( $f->rule_id ); ?></code></td>
						<td><code class="malroot-target"><?php echo esc_html( $f->target ); ?></code></td>
						<td>
							<?php echo esc_html( $f->summary ); ?>
							<?php if ( $f->details ) : ?>
								<details class="malroot-details"><summary><?php esc_html_e( 'Show details', 'malroot-security' ); ?></summary>
									<pre><?php echo esc_html( $f->details ); ?></pre>
								</details>
							<?php endif; ?>
						</td>
						<td>
							<?php if ( $f->status === 'fixed' ) : ?>
								<span class="malroot-fixed">✓ <?php esc_html_e( 'Fixed', 'malroot-security' ); ?></span>
							<?php elseif ( $f->status === 'ignored' ) : ?>
								<span style="color:#bbb;font-size:11px"><?php esc_html_e( 'Ignored', 'malroot-security' ); ?></span>
							<?php elseif ( strpos( $f->target, 'rest:' ) !== 0 ) : ?>
								<div style="display:flex;flex-direction:column;gap:4px">
									<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
										<input type="hidden" name="action" value="malroot_quarantine" />
										<input type="hidden" name="finding_id" value="<?php echo (int) $f->id; ?>" />
										<?php wp_nonce_field( 'malroot_quarantine' ); ?>
										<button type="submit" class="button button-small mr-btn-danger" style="width:100%"
											onclick="return confirm('<?php esc_attr_e( 'Quarantine this item?', 'malroot-security' ); ?>')">
											<?php esc_html_e( 'Quarantine', 'malroot-security' ); ?>
										</button>
									</form>
									<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
										<input type="hidden" name="action" value="malroot_ignore_finding" />
										<input type="hidden" name="finding_id" value="<?php echo (int) $f->id; ?>" />
										<?php wp_nonce_field( 'malroot_ignore_finding' ); ?>
										<button type="submit" class="button button-small" style="width:100%;color:#888">
											<?php esc_html_e( 'Ignore', 'malroot-security' ); ?>
										</button>
									</form>
								</div>
							<?php else : ?>
								<span style="font-size:11px;color:#888"><?php esc_html_e( 'Manual', 'malroot-security' ); ?></span>
							<?php endif; ?>
						</td>
					</tr>
				<?php endforeach; ?>
			</tbody>
		</table>
		<?php
	}

	/* ---------------------------------------------------------------- */
	/*  v0.3 handlers                                                   */
	/* ---------------------------------------------------------------- */

	public static function handle_run_incident() {
		if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Forbidden.', 403 );
		check_admin_referer( 'malroot_run_incident' );

		$token = sanitize_text_field( wp_unslash( $_POST['token'] ?? '' ) );
		$report = MR_Incident_Response::run( $token );

		if ( is_wp_error( $report ) ) {
			$args = [ 'mr_error' => urlencode( $report->get_error_message() ) ];
		} else {
			set_transient( 'malroot_last_ir_report', $report, HOUR_IN_SECONDS );
			$args = [ 'mr_ir_done' => 1 ];
		}
		wp_safe_redirect( add_query_arg( $args, admin_url( 'admin.php?page=malroot-incident' ) ) );
		exit;
	}

	public static function handle_rebuild_baseline() {
		if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Forbidden.', 403 );
		check_admin_referer( 'malroot_rebuild_baseline' );
		// phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
		@set_time_limit( 300 );
		$count = MR_Baseline::rebuild();
		wp_safe_redirect( add_query_arg(
			[ 'mr_baseline_built' => $count ],
			admin_url( 'admin.php?page=malroot-security' )
		) );
		exit;
	}

	public static function handle_accept_finding() {
		if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Forbidden.', 403 );
		check_admin_referer( 'malroot_accept_finding' );

		global $wpdb;
		$id = (int) ( isset( $_POST['finding_id'] ) ? sanitize_text_field( wp_unslash( $_POST['finding_id'] ) ) : 0 );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$f = $wpdb->get_row( $wpdb->prepare(
			"SELECT * FROM {$wpdb->prefix}malroot_findings WHERE id = %d", $id
		) );
		if ( ! $f ) {
			wp_safe_redirect( add_query_arg( [ 'mr_error' => urlencode( 'Finding not found.' ) ], admin_url( 'admin.php?page=malroot-security' ) ) );
			exit;
		}

		// Only allow accepting integrity findings — never anything else
		if ( $f->module !== 'integrity' ) {
			wp_safe_redirect( add_query_arg( [ 'mr_error' => urlencode( 'Only integrity findings can be accepted this way.' ) ], admin_url( 'admin.php?page=malroot-security' ) ) );
			exit;
		}

		// Update the baseline for just this file
		$abs = ABSPATH . ltrim( $f->target, '/' );
		if ( file_exists( $abs ) ) {
			$hash = @md5_file( $abs );
			$baseline_table = $wpdb->prefix . 'malroot_baseline';
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter
			$wpdb->query( $wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
				"DELETE FROM {$baseline_table} WHERE path = %s", $f->target
			) );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->insert( $baseline_table, [
				'path'      => $f->target,
				'sha'       => $hash,
				'size'      => @filesize( $abs ),
				'last_seen' => current_time( 'mysql' ),
			], [ '%s', '%s', '%d', '%s' ] );
		} else {
			// File was deleted; remove it from baseline
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->query( $wpdb->prepare(
				"DELETE FROM {$wpdb->prefix}malroot_baseline WHERE path = %s", $f->target
			) );
		}

		// Mark the finding as fixed
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->update(
			$wpdb->prefix . 'malroot_findings',
			[ 'status' => 'fixed' ],
			[ 'id' => $f->id ],
			[ '%s' ],
			[ '%d' ]
		);

		MR_Logger::info( 'User accepted integrity finding', [ 'finding_id' => $id, 'target' => $f->target ] );

		wp_safe_redirect( add_query_arg( [ 'mr_accepted' => 1 ], admin_url( 'admin.php?page=malroot-security' ) ) );
		exit;
	}

	/**
	 * Mark a finding as 'ignored' — keeps it in history but hides from open lists.
	 */
	public static function handle_ignore_finding() {
		if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Forbidden.', 403 );
		check_admin_referer( 'malroot_ignore_finding' );

		global $wpdb;
		$id = (int) ( isset( $_POST['finding_id'] ) ? sanitize_text_field( wp_unslash( $_POST['finding_id'] ) ) : 0 );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->update(
			$wpdb->prefix . 'malroot_findings',
			[ 'status' => 'ignored' ],
			[ 'id' => $id ],
			[ '%s' ],
			[ '%d' ]
		);
		MR_Logger::info( 'User ignored finding', [ 'finding_id' => $id ] );
		wp_safe_redirect( add_query_arg( [ 'mr_ignored' => 1 ], admin_url( 'admin.php?page=malroot-security' ) ) );
		exit;
	}

	/**
	 * Export the latest scan's findings as CSV.
	 */
	public static function handle_export_findings() {
		if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Forbidden.', 403 );
		check_admin_referer( 'malroot_export_findings' );

		$last     = (int) get_option( 'malroot_last_scan', 0 );
		$findings = $last ? MR_Findings::get_by_scan( $last ) : [];

		$site = sanitize_title( wp_parse_url( home_url(), PHP_URL_HOST ) );
		$file = sprintf( 'malroot-findings-%s-%s.csv', $site, gmdate( 'Y-m-d' ) );

		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="' . $file . '"' );

		$out = fopen( 'php://output', 'w' );
		fputcsv( $out, [ 'severity', 'module', 'rule', 'target', 'summary', 'status', 'created_at' ] );
		foreach ( $findings as $f ) {
			fputcsv( $out, [
				$f->severity,
				$f->module,
				$f->rule_id,
				$f->target,
				$f->summary,
				$f->status,
				$f->created_at,
			] );
		}
  // phpcs:ignore WordPress.WP.AlternativeFunctions
		fclose( $out );
		exit;
	}

	public static function handle_test_email() {
		if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Forbidden.', 403 );
		check_admin_referer( 'malroot_test_email' );

		$settings = (array) get_option( 'malroot_settings', [] );
		$to = sanitize_email( $settings['alert_email'] ?? get_option( 'admin_email' ) );

		if ( ! $to ) {
			wp_safe_redirect( add_query_arg( [ 'mr_error' => urlencode( 'No alert email configured.' ) ], admin_url( 'admin.php?page=malroot-settings' ) ) );
			exit;
		}

		$result = MR_Alerting::send_test_email( $to );

		if ( is_wp_error( $result ) ) {
			wp_safe_redirect( add_query_arg( [
				'mr_error' => urlencode( 'Email failed: ' . $result->get_error_message() ),
			], admin_url( 'admin.php?page=malroot-settings' ) ) );
		} else {
			wp_safe_redirect( add_query_arg( [
				'mr_test_sent' => urlencode( $to ),
			], admin_url( 'admin.php?page=malroot-settings' ) ) );
		}
		exit;
	}

	public static function handle_spam_dryrun() {
		if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Forbidden.', 403 );
		check_admin_referer( 'malroot_spam_dryrun' );
		$result = MR_Spam_Shield::bulk_cleanup( true );
		set_transient( 'malroot_spam_dryrun', $result, HOUR_IN_SECONDS );
		wp_safe_redirect( admin_url( 'admin.php?page=malroot-spam&mr_spam_dryrun=1' ) );
		exit;
	}

	public static function handle_spam_delete() {
		if ( ! current_user_can( 'manage_options' ) ) wp_die( 'Forbidden.', 403 );
		check_admin_referer( 'malroot_spam_delete' );
		// phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
		@set_time_limit( 300 );
		$result = MR_Spam_Shield::bulk_cleanup( false );
		wp_safe_redirect( add_query_arg( [ 'mr_spam_deleted' => (int) $result['count'] ], admin_url( 'admin.php?page=malroot-spam' ) ) );
		exit;
	}

	/* ---------------------------------------------------------------- */
	/*  v0.3 pages                                                      */
	/* ---------------------------------------------------------------- */

	public static function render_logins() {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows = $wpdb->get_results( "SELECT * FROM {$wpdb->prefix}malroot_logins ORDER BY id DESC LIMIT 200" );
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Login Activity', 'malroot-security' ); ?></h1>
			<p><?php esc_html_e( 'Successful and failed logins from the last 200 attempts. Failed attempts trigger an IP lockout after 5 in 15 minutes.', 'malroot-security' ); ?></p>
			<table class="widefat striped">
				<thead><tr>
					<th><?php esc_html_e( 'Result', 'malroot-security' ); ?></th>
					<th><?php esc_html_e( 'Login', 'malroot-security' ); ?></th>
					<th><?php esc_html_e( 'IP', 'malroot-security' ); ?></th>
					<th><?php esc_html_e( 'Location', 'malroot-security' ); ?></th>
					<th><?php esc_html_e( 'User-Agent', 'malroot-security' ); ?></th>
					<th><?php esc_html_e( 'When', 'malroot-security' ); ?></th>
				</tr></thead>
				<tbody>
				<?php foreach ( $rows as $r ) :
					$is_auto = MR_Login_Security::is_automated_ua( $r->ua );
					$location = MR_GeoIP::label( $r->ip );
				?>
					<tr>
						<td><?php echo $r->success ? '<span style="color:#46b450">✓ OK</span>' : '<span style="color:#dc3232">✗ FAIL</span>'; ?></td>
						<td><code><?php echo esc_html( $r->attempted_login ); ?></code></td>
						<td><code><?php echo esc_html( $r->ip ); ?></code></td>
						<td><?php echo $location ? esc_html( $location ) : '<span style="color:#bbb">—</span>'; ?></td>
						<td>
							<?php if ( $is_auto ) : ?>
								<span style="color:#dc3232;font-weight:bold"><?php esc_html_e( 'AUTOMATED', 'malroot-security' ); ?></span>
							<?php endif; ?>
							<code style="font-size:11px"><?php echo esc_html( substr( $r->ua, 0, 120 ) ); ?></code>
						</td>
						<td><?php echo esc_html( $r->created_at ); ?></td>
					</tr>
				<?php endforeach; ?>
				<?php if ( empty( $rows ) ) : ?>
					<tr><td colspan="6"><?php esc_html_e( 'No login attempts recorded yet.', 'malroot-security' ); ?></td></tr>
				<?php endif; ?>
				</tbody>
			</table>
		</div>
		<?php
	}

	public static function render_spam() {
		$dryrun = get_transient( 'malroot_spam_dryrun' );
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Spam Cleanup', 'malroot-security' ); ?></h1>
			<p><?php esc_html_e( 'Find and remove subscriber accounts that match known spam patterns. Run a dry run first to see what would be deleted.', 'malroot-security' ); ?></p>

			<?php self::flash_messages(); ?>
			<?php if ( isset( $_GET['mr_spam_deleted'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
				<div class="notice notice-success is-dismissible"><p>
					<?php
					/* translators: %d: number of spam subscriber accounts deleted */
					printf( esc_html__( 'Deleted %d spam subscriber accounts.', 'malroot-security' ), (int) $_GET['mr_spam_deleted'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
					?>
				</p></div>
			<?php endif; ?>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline">
				<input type="hidden" name="action" value="malroot_spam_dryrun" />
				<?php wp_nonce_field( 'malroot_spam_dryrun' ); ?>
				<button type="submit" class="button button-primary"><?php esc_html_e( 'Dry Run', 'malroot-security' ); ?></button>
			</form>

			<?php if ( $dryrun && ! empty( $dryrun['sample'] ) ) : ?>
				<div style="margin-top:20px;border:1px solid #ccd0d4;background:#fff;padding:20px">
					<p><strong><?php
					/* translators: %d: number of spam users that would be deleted */
					printf( esc_html__( 'Dry run: %d spam users would be deleted.', 'malroot-security' ), (int) $dryrun['count'] ); ?></strong></p>
					<table class="widefat striped">
						<thead><tr><th><?php esc_html_e( 'ID', 'malroot-security' ); ?></th><th><?php esc_html_e( 'Login', 'malroot-security' ); ?></th><th><?php esc_html_e( 'Email', 'malroot-security' ); ?></th></tr></thead>
						<tbody>
						<?php foreach ( $dryrun['sample'] as $u ) : ?>
							<tr><td><?php echo (int) $u->ID; ?></td><td><code><?php echo esc_html( $u->user_login ); ?></code></td><td><?php echo esc_html( $u->user_email ); ?></td></tr>
						<?php endforeach; ?>
						</tbody>
					</table>
					<p style="margin-top:15px"><em><?php esc_html_e( 'Showing first 25 matches.', 'malroot-security' ); ?></em></p>

					<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:15px">
						<input type="hidden" name="action" value="malroot_spam_delete" />
						<?php wp_nonce_field( 'malroot_spam_delete' ); ?>
						<button type="submit" class="button button-link-delete" onclick="return confirm('Delete <?php echo (int) $dryrun['count']; ?> users? Their content reassigns to admin.')">
							<?php
							/* translators: %d: number of users to delete */
							printf( esc_html__( 'Delete %d users', 'malroot-security' ), (int) $dryrun['count'] );
							?>
						</button>
					</form>
				</div>
			<?php elseif ( $dryrun ) : ?>
				<p style="margin-top:20px"><strong><?php esc_html_e( 'No spam users found.', 'malroot-security' ); ?></strong></p>
			<?php endif; ?>
		</div>
		<?php
	}

	public static function render_incident() {
		$last_report = get_transient( 'malroot_last_ir_report' );
		?>
		<div class="wrap">
			<h1><?php esc_html_e( 'Incident Response', 'malroot-security' ); ?></h1>
			<p><?php esc_html_e( 'One-click runs the cleanup we developed for the system-control / newsfeed attack. Every action is reversible via the Quarantine page.', 'malroot-security' ); ?></p>

			<?php self::flash_messages(); ?>
			<?php if ( isset( $_GET['mr_ir_done'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
				<div class="notice notice-success is-dismissible"><p><?php esc_html_e( 'Incident response complete. See report below.', 'malroot-security' ); ?></p></div>
			<?php endif; ?>

			<div style="border:2px solid #dc3232;background:#fef7f7;padding:20px;margin:20px 0">
				<h2 style="margin-top:0;color:#dc3232"><?php esc_html_e( 'Run Cleanup', 'malroot-security' ); ?></h2>
				<p><?php esc_html_e( 'This will:', 'malroot-security' ); ?></p>
				<ul style="list-style:disc;margin-left:20px">
					<li><?php esc_html_e( 'Drop any MySQL trigger that injects users (e.g. after_insert_comment)', 'malroot-security' ); ?></li>
					<li><?php esc_html_e( 'Quarantine users with malware login names (newsfeed, system_control, etc.)', 'malroot-security' ); ?></li>
					<li><?php esc_html_e( 'Quarantine sc_* options + clear sc_ transients', 'malroot-security' ); ?></li>
					<li><?php esc_html_e( 'Quarantine _sc_bot_only / _sc_bot_type postmeta', 'malroot-security' ); ?></li>
					<li><?php esc_html_e( 'Clear all session_tokens (forces every user to log in again)', 'malroot-security' ); ?></li>
					<li><?php esc_html_e( 'Strip system-control from active_plugins', 'malroot-security' ); ?></li>
				</ul>
				<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:15px">
					<input type="hidden" name="action" value="malroot_run_incident" />
					<input type="hidden" name="token" value="<?php echo esc_attr( MR_Incident_Response::token() ); ?>" />
					<?php wp_nonce_field( 'malroot_run_incident' ); ?>
					<button type="submit" class="button button-primary button-hero" style="background:#dc3232;border-color:#a00;text-shadow:none" onclick="return confirm('Run full incident response now? Every change is reversible from the Quarantine page.')">
						<?php esc_html_e( 'Run Incident Response', 'malroot-security' ); ?>
					</button>
				</form>
			</div>

			<?php if ( $last_report && is_array( $last_report ) ) : ?>
				<h2><?php esc_html_e( 'Last Run Report', 'malroot-security' ); ?></h2>
				<div class="malroot-ir-report">
					<?php foreach ( $last_report['steps'] as $step_name => $items ) : ?>
						<div class="malroot-ir-step">
							<div class="malroot-ir-step-title"><?php echo esc_html( ucfirst( $step_name ) ); ?></div>
							<?php if ( empty( $items ) ) : ?>
								<div class="malroot-ir-item"><span class="malroot-ir-skip">—</span> <?php esc_html_e( 'Nothing to do.', 'malroot-security' ); ?></div>
							<?php elseif ( is_array( $items ) ) : ?>
								<?php foreach ( $items as $item ) :
									if ( ! is_array( $item ) ) {
										echo '<div class="malroot-ir-item">' . esc_html( wp_json_encode( $item ) ) . '</div>';
										continue;
									}
									$result = $item['result'] ?? '';
									$label  = $item['user'] ?? $item['option'] ?? $item['meta_key'] ?? $item['name'] ?? $item['transients'] ?? '';
									$icon_class = ( $result === 'quarantined' || $result === 'dropped' || $result === 'removed' || $result === 'cleared' )
										? 'malroot-ir-ok' : ( strpos( $result, 'skip' ) !== false ? 'malroot-ir-skip' : 'malroot-ir-err' );
									$icon = ( $icon_class === 'malroot-ir-ok' ) ? '✓' : ( $icon_class === 'malroot-ir-skip' ? '—' : '✗' );
								?>
									<div class="malroot-ir-item">
										<span class="<?php echo esc_attr( $icon_class ); ?>"><?php echo esc_html( $icon ); ?></span>
										<strong><?php echo esc_html( $label ); ?></strong>
										<span style="color:#666;font-size:12px"><?php echo esc_html( $result ); ?></span>
										<?php if ( isset( $item['id'] ) ) : ?>
											<span style="color:#aaa;font-size:11px">(ID <?php echo (int) $item['id']; ?>)</span>
										<?php endif; ?>
									</div>
								<?php endforeach; ?>
							<?php else : ?>
								<div class="malroot-ir-item"><?php echo esc_html( wp_json_encode( $items ) ); ?></div>
							<?php endif; ?>
						</div>
					<?php endforeach; ?>
					<p style="margin-top:12px;font-size:12px;color:#888">
						<?php printf(
							/* translators: %1$s: start time, %2$s: finish time */
							esc_html__( 'Started: %1$s — Finished: %2$s', 'malroot-security' ),
							esc_html( $last_report['started_at'] ?? '' ),
							esc_html( $last_report['finished_at'] ?? '' )
						); ?>
					</p>
				</div>
			<?php endif; ?>
		</div>
		<?php
	}
}
