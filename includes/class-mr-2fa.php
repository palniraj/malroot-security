<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Two-factor authentication module.
 *
 * - User-meta keys:
 *     malroot_2fa_secret      base32 TOTP secret
 *     malroot_2fa_enabled     "1" once user has confirmed their first code
 *     malroot_2fa_recovery    serialised array of one-time recovery codes
 *
 * - Flow:
 *     1. User opens Profile → "Two-Factor Authentication" section.
 *     2. They click "Enable 2FA" → sees QR code + 8 recovery codes.
 *     3. They scan QR with their authenticator and enter a 6-digit code to confirm.
 *     4. From then on, every login requires the 6-digit code (or one recovery code).
 *
 * - Site-wide enforcement:
 *     Setting malroot_settings.require_2fa_admins makes 2FA mandatory for any
 *     administrator. They can still log in once to set it up, but until they do
 *     they can't access any other admin page.
 */
class Malroot_TwoFactor {

	const META_SECRET   = 'malroot_2fa_secret';
	const META_ENABLED  = 'malroot_2fa_enabled';
	const META_RECOVERY = 'malroot_2fa_recovery';

	const NONCE_FIELD       = 'malroot_2fa_nonce';
	const TRANSIENT_PREFIX  = 'malroot_2fa_pending_';

	public static function register() {
		add_action( 'show_user_profile',           [ __CLASS__, 'render_profile_section' ] );
		add_action( 'edit_user_profile',           [ __CLASS__, 'render_profile_section' ] );
		// Accept both GET (Enable 2FA link) and POST (Verify form submit)
		add_action( 'admin_post_malroot_2fa_setup',[ __CLASS__, 'handle_setup' ] );
		add_action( 'admin_post_malroot_2fa_disable', [ __CLASS__, 'handle_disable' ] );

		// Login flow
		add_filter( 'wp_authenticate_user', [ __CLASS__, 'intercept_login' ], 30, 2 );
		add_action( 'login_form_malroot_2fa',        [ __CLASS__, 'render_2fa_form' ] );
		add_action( 'login_form_malroot_2fa_verify', [ __CLASS__, 'handle_2fa_verify' ] );
		add_filter( 'authenticate', [ __CLASS__, 'check_2fa_post' ], 99, 3 );

		// Enforcement: admins without 2FA see only the profile page
		add_action( 'admin_init', [ __CLASS__, 'enforce_admin_setup' ] );
	}

	/* ---------------------------------------------------------------- */
	/*  Profile UI                                                       */
	/* ---------------------------------------------------------------- */

	public static function render_profile_section( $user ) {
		if ( ! current_user_can( 'edit_user', $user->ID ) ) {
			return;
		}
		$enabled = (bool) get_user_meta( $user->ID, self::META_ENABLED, true );
		$pending = get_transient( self::TRANSIENT_PREFIX . $user->ID );
		?>
		<h2 id="malroot-2fa"><?php esc_html_e( 'Two-Factor Authentication (Malroot)', 'malroot-security' ); ?></h2>

		<?php if ( isset( $_GET['mr_2fa_enabled'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
			<div class="notice notice-success inline"><p>✓ <?php esc_html_e( '2FA enabled successfully.', 'malroot-security' ); ?></p></div>
		<?php elseif ( isset( $_GET['mr_2fa_disabled'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
			<div class="notice notice-warning inline"><p><?php esc_html_e( '2FA has been disabled.', 'malroot-security' ); ?></p></div>
		<?php elseif ( isset( $_GET['mr_2fa_error'] ) ) : // phpcs:ignore WordPress.Security.NonceVerification.Recommended ?>
			<div class="notice notice-error inline"><p><?php echo esc_html( sanitize_text_field( wp_unslash( $_GET['mr_2fa_error'] ) ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.MissingUnslash ?></p></div>
		<?php endif; ?>

		<table class="form-table">
			<tr>
				<th><?php esc_html_e( 'Status', 'malroot-security' ); ?></th>
				<td>
					<?php if ( $enabled ) : ?>
						<span style="color:#46b450;font-weight:600">✓ <?php esc_html_e( 'Enabled', 'malroot-security' ); ?></span>
						<a href="<?php echo esc_url( wp_nonce_url(
							admin_url( 'admin-post.php?action=malroot_2fa_disable&user_id=' . $user->ID ),
							'malroot_2fa_disable_' . $user->ID
						) ); ?>"
							class="button button-link-delete" style="margin-left:12px"
							onclick="return confirm('<?php esc_attr_e( 'Disable 2FA for this account?', 'malroot-security' ); ?>')">
							<?php esc_html_e( 'Disable 2FA', 'malroot-security' ); ?>
						</a>
					<?php elseif ( $pending ) : ?>
						<span style="color:#ffb900;font-weight:600">⏳ <?php esc_html_e( 'Setup in progress — finish below', 'malroot-security' ); ?></span>
					<?php else : ?>
						<span style="color:#dc3232"><?php esc_html_e( 'Not enabled', 'malroot-security' ); ?></span>
						<a href="<?php echo esc_url( wp_nonce_url(
							admin_url( 'admin-post.php?action=malroot_2fa_setup&user_id=' . $user->ID ),
							'malroot_2fa_setup_' . $user->ID
						) ); ?>"
							class="button button-primary" style="margin-left:12px">
							<?php esc_html_e( 'Enable 2FA', 'malroot-security' ); ?>
						</a>
					<?php endif; ?>
				</td>
			</tr>
		</table>
		<?php
		// If we just generated a setup, show QR + recovery
		if ( $pending && ! $enabled ) {
			self::render_setup_screen( $user, $pending );
		}
	}

	private static function render_setup_screen( $user, $pending ) {
		$secret  = $pending['secret'];
		$codes   = $pending['recovery'];
		$account = $user->user_login . '@' . wp_parse_url( home_url(), PHP_URL_HOST );
		$issuer  = get_bloginfo( 'name' );
		$url     = Malroot_TOTP::otpauth_url( $secret, $account, $issuer );
		$qr_src  = 'https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=' . rawurlencode( $url );

		// The verify form MUST be outside the WP profile <form>.
		// We render it via admin_footer so it appears after the profile form closes.
		add_action( 'admin_footer', function () use ( $user, $secret, $codes, $qr_src ) {
			?>
			<div id="malroot-2fa-setup" style="border:2px solid #2271b1;background:#f0f6fc;border-radius:6px;padding:24px;margin:20px 0;max-width:680px">
				<h3 style="margin-top:0;color:#1d4ed8">🔐 <?php esc_html_e( 'Set up your authenticator', 'malroot-security' ); ?></h3>
				<div style="display:flex;gap:24px;flex-wrap:wrap;align-items:flex-start">
					<div>
						<img src="<?php echo esc_url( $qr_src ); ?>" alt="QR code" width="180" height="180" style="border:1px solid #ddd;background:#fff;padding:6px;display:block"/>
					</div>
					<div style="flex:1;min-width:240px">
						<p style="margin-top:0"><strong><?php esc_html_e( 'Step 1', 'malroot-security' ); ?></strong> — <?php esc_html_e( 'Install Google Authenticator, Authy, or any TOTP app.', 'malroot-security' ); ?></p>
						<p><strong><?php esc_html_e( 'Step 2', 'malroot-security' ); ?></strong> — <?php esc_html_e( 'Scan the QR code, or enter this secret manually:', 'malroot-security' ); ?></p>
						<code style="font-size:14px;letter-spacing:2px;background:#fff;padding:4px 8px;border:1px solid #ccd0d4;display:inline-block;margin-bottom:12px"><?php echo esc_html( $secret ); ?></code>
						<p><strong><?php esc_html_e( 'Step 3', 'malroot-security' ); ?></strong> — <?php esc_html_e( 'Enter the 6-digit code from the app:', 'malroot-security' ); ?></p>
						<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:flex;gap:8px;align-items:center">
							<input type="hidden" name="action" value="malroot_2fa_setup" />
							<input type="hidden" name="user_id" value="<?php echo (int) $user->ID; ?>" />
							<input type="hidden" name="confirm" value="1" />
							<?php wp_nonce_field( 'malroot_2fa_setup_' . $user->ID ); ?>
							<input type="text" name="code" inputmode="numeric" pattern="\d{6}" maxlength="6"
								placeholder="000000"
								style="font-size:20px;letter-spacing:6px;width:130px;text-align:center;padding:6px"
								autocomplete="one-time-code" required autofocus />
							<button type="submit" class="button button-primary button-large">
								<?php esc_html_e( 'Verify and Enable', 'malroot-security' ); ?>
							</button>
						</form>
					</div>
				</div>
				<div style="background:#fff;border:1px solid #ffe082;border-radius:4px;padding:12px;margin-top:16px">
					<strong>⚠️ <?php esc_html_e( 'Save these recovery codes now', 'malroot-security' ); ?></strong>
					<p style="font-size:12px;color:#666;margin:4px 0 8px"><?php esc_html_e( 'Each code works only once. Store them somewhere safe — you\'ll need one if you lose your phone.', 'malroot-security' ); ?></p>
					<pre style="background:#f6f7f7;padding:10px;border-radius:3px;font-size:13px;letter-spacing:2px;margin:0;column-count:2"><?php echo esc_html( implode( "\n", $codes ) ); ?></pre>
				</div>
			</div>
			<script>
			(function () {
				// Move the setup card to be a sibling of the profile form, not inside it.
				// This ensures the verify form submits to admin-post.php correctly.
				var card = document.getElementById('malroot-2fa-setup');
				if (!card) return;
				var profileForm = document.getElementById('your-profile');
				if (profileForm && profileForm.parentNode) {
					profileForm.parentNode.insertBefore(card, profileForm.nextSibling);
				}
				// Scroll to it
				card.scrollIntoView({ behavior: 'smooth', block: 'start' });
			}());
			</script>
			<?php
		} );

		// Show a placeholder inside the profile form so the user sees something
		// before the footer JS moves the real card into position.
		?>
		<div style="border:1px solid #2271b1;background:#f0f6fc;border-radius:4px;padding:16px;margin-top:12px;max-width:680px">
			<p style="margin:0;color:#1d4ed8">
				⏳ <?php esc_html_e( 'Setup card loading below — scroll down to see the QR code and enter your verification code.', 'malroot-security' ); ?>
			</p>
		</div>
		<?php
	}

	/* ---------------------------------------------------------------- */
	/*  Setup / disable handlers                                         */
	/* ---------------------------------------------------------------- */

	public static function handle_setup() {
		$user_id = (int) ( isset( $_REQUEST['user_id'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['user_id'] ) ) : 0 );
		if ( ! current_user_can( 'edit_user', $user_id ) ) wp_die( 'Forbidden.', 403 );
		check_admin_referer( 'malroot_2fa_setup_' . $user_id );

		// Step 2: confirming the code from the authenticator
		if ( ! empty( $_POST['confirm'] ) ) {
			$pending = get_transient( self::TRANSIENT_PREFIX . $user_id );
			if ( ! $pending ) {
				wp_safe_redirect( add_query_arg( 'mr_2fa_error', urlencode( 'Setup expired. Please click "Enable 2FA" again.' ), self::profile_url( $user_id ) ) );
				exit;
			}
			$code = sanitize_text_field( wp_unslash( $_POST['code'] ?? '' ) );
			if ( ! Malroot_TOTP::verify( $pending['secret'], $code ) ) {
				wp_safe_redirect( add_query_arg( 'mr_2fa_error', urlencode( 'Invalid code. Make sure your phone clock is correct.' ), self::profile_url( $user_id ) . '#malroot-2fa' ) );
				exit;
			}
			update_user_meta( $user_id, self::META_SECRET, $pending['secret'] );
			update_user_meta( $user_id, self::META_RECOVERY, $pending['recovery'] );
			update_user_meta( $user_id, self::META_ENABLED, 1 );
			delete_transient( self::TRANSIENT_PREFIX . $user_id );

			Malroot_Alerting::alert( 'medium', '2fa_enabled',
				"User '" . wp_get_current_user()->user_login . "' enabled 2FA",
				[ 'user_id' => $user_id ]
			);

			wp_safe_redirect( add_query_arg( 'mr_2fa_enabled', 1, self::profile_url( $user_id ) . '#malroot-2fa' ) );
			exit;
		}

		// Step 1: generate secret + recovery codes
		$secret   = Malroot_TOTP::generate_secret();
		$recovery = self::generate_recovery_codes();
		set_transient( self::TRANSIENT_PREFIX . $user_id, [
			'secret'   => $secret,
			'recovery' => $recovery,
		], 30 * MINUTE_IN_SECONDS );

		wp_safe_redirect( self::profile_url( $user_id ) . '#malroot-2fa' );
		exit;
	}

	public static function handle_disable() {
		$user_id = (int) ( isset( $_REQUEST['user_id'] ) ? sanitize_text_field( wp_unslash( $_REQUEST['user_id'] ) ) : 0 );
		if ( ! current_user_can( 'edit_user', $user_id ) ) wp_die( 'Forbidden.', 403 );
		check_admin_referer( 'malroot_2fa_disable_' . $user_id );

		delete_user_meta( $user_id, self::META_SECRET );
		delete_user_meta( $user_id, self::META_RECOVERY );
		delete_user_meta( $user_id, self::META_ENABLED );

		Malroot_Alerting::alert( 'high', '2fa_disabled',
			"User ID {$user_id} had 2FA disabled by " . wp_get_current_user()->user_login,
			[ 'user_id' => $user_id ]
		);

		wp_safe_redirect( add_query_arg( 'mr_2fa_disabled', 1, self::profile_url( $user_id ) . '#malroot-2fa' ) );
		exit;
	}

	private static function profile_url( $user_id ) {
		return get_current_user_id() === $user_id
			? admin_url( 'profile.php' )
			: admin_url( 'user-edit.php?user_id=' . $user_id );
	}

	private static function generate_recovery_codes( $count = 8 ) {
		$codes = [];
		for ( $i = 0; $i < $count; $i++ ) {
			$codes[] = strtoupper( substr( str_replace( [ '/', '+', '=' ], '', base64_encode( random_bytes( 6 ) ) ), 0, 8 ) );
		}
		return $codes;
	}

	/* ---------------------------------------------------------------- */
	/*  Login flow                                                       */
	/* ---------------------------------------------------------------- */

	/**
	 * After username+password verify, intercept and demand the 2FA code.
	 */
	public static function intercept_login( $user, $password ) {
		if ( is_wp_error( $user ) || ! $user instanceof WP_User ) {
			return $user;
		}
		if ( ! get_user_meta( $user->ID, self::META_ENABLED, true ) ) {
			return $user;
		}

		// Don't intercept if we're on the 2FA verify action — that's handled separately
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		$action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : '';
		if ( $action === 'malroot_2fa_verify' || $action === 'malroot_2fa' ) {
			return $user;
		}

		// Don't intercept if the 2FA nonce is present (shouldn't happen but safety)
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( isset( $_POST[ self::NONCE_FIELD ] ) ) {
			return $user;
		}

		// Stash a pending login token and redirect to the 2FA challenge
		$token = wp_generate_password( 32, false );
		// Use update_option directly to avoid object cache issues with transients
		$transient_key = 'malroot_2fa_login_' . $token;
		$data = [
			'user_id' => $user->ID,
			'expires' => time() + 10 * MINUTE_IN_SECONDS,
		];
		set_transient( $transient_key, $data, 10 * MINUTE_IN_SECONDS );

		$redirect = wp_login_url();
		$redirect = add_query_arg( [
			'action'        => 'malroot_2fa',
			'malroot_token' => $token,
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
			'redirect_to'   => esc_url_raw( isset( $_REQUEST['redirect_to'] ) ? wp_unslash( $_REQUEST['redirect_to'] ) : admin_url() ),
		], $redirect );
		wp_safe_redirect( $redirect );
		exit;
	}

	public static function render_2fa_form() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$token   = isset( $_GET['malroot_token'] ) ? sanitize_text_field( wp_unslash( $_GET['malroot_token'] ) ) : '';
		$pending = get_transient( 'malroot_2fa_login_' . $token );
		if ( ! $pending ) {
			wp_die( esc_html__( 'Login session expired. Please log in again.', 'malroot-security' ) );
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$redirect_to = esc_url_raw( isset( $_GET['redirect_to'] ) ? wp_unslash( $_GET['redirect_to'] ) : admin_url() );
		login_header( __( 'Two-Factor Authentication', 'malroot-security' ) );
		?>
		<style>
		#loginform { max-width: 340px; }
		.malroot-2fa-code { font-size:24px; letter-spacing:8px; text-align:center; width:100%; padding:10px; }
		</style>
		<form method="post" id="loginform" action="<?php echo esc_url( wp_login_url() ); ?>">
			<p style="margin-bottom:1.2em;color:#555;line-height:1.5">
				<?php esc_html_e( 'Enter the 6-digit code from your authenticator app, or one of your recovery codes.', 'malroot-security' ); ?>
			</p>
			<p>
				<label for="malroot_2fa_code"><?php esc_html_e( 'Authentication code', 'malroot-security' ); ?></label>
				<input type="text" id="malroot_2fa_code" name="malroot_2fa_code"
					class="input malroot-2fa-code"
					inputmode="numeric"
					autocomplete="one-time-code"
					autofocus required
					placeholder="000000"
					maxlength="8" />
			</p>
			<input type="hidden" name="malroot_token" value="<?php echo esc_attr( $token ); ?>" />
			<input type="hidden" name="redirect_to" value="<?php echo esc_attr( $redirect_to ); ?>" />
			<input type="hidden" name="action" value="malroot_2fa_verify" />
			<?php wp_nonce_field( 'malroot_2fa_login', self::NONCE_FIELD ); ?>
			<p class="submit">
				<input type="submit" class="button button-primary button-large" style="width:100%" value="<?php esc_attr_e( 'Verify', 'malroot-security' ); ?>"/>
			</p>
		</form>
		<p style="text-align:center;margin-top:1em">
			<a href="<?php echo esc_url( wp_login_url() ); ?>">&larr; <?php esc_html_e( 'Back to login', 'malroot-security' ); ?></a>
		</p>
		<?php
		login_footer();
		exit;
	}

	/**
	 * Handle the 2FA verification POST — this is a dedicated action, not
	 * the normal authenticate filter, so we can call wp_set_auth_cookie directly.
	 */
	public static function handle_2fa_verify() {
		// This fires on login_form_malroot_2fa_verify
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotValidated
		if ( $_SERVER['REQUEST_METHOD'] !== 'POST' ) {
			// GET request to this action = show the form (shouldn't happen but handle gracefully)
			wp_safe_redirect( wp_login_url() );
			exit;
		}
		if ( empty( $_POST[ self::NONCE_FIELD ] ) ) {
			self::show_2fa_error( __( 'Security check failed (no nonce). Please try again.', 'malroot-security' ) );
			return;
		}
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		if ( ! wp_verify_nonce( wp_unslash( $_POST[ self::NONCE_FIELD ] ), 'malroot_2fa_login' ) ) {
			self::show_2fa_error( __( 'Security check failed (nonce invalid). Please log in again.', 'malroot-security' ) );
			return;
		}
		$token   = isset( $_POST['malroot_token'] ) ? sanitize_text_field( wp_unslash( $_POST['malroot_token'] ) ) : '';
		if ( ! $token ) {
			self::show_2fa_error( __( 'Missing login token. Please log in again.', 'malroot-security' ) );
			return;
		}
		$pending = get_transient( 'malroot_2fa_login_' . $token );
		if ( ! $pending || ! is_array( $pending ) || empty( $pending['user_id'] ) ) {
			self::show_2fa_error( __( 'Login session expired. Please log in again from the start.', 'malroot-security' ) );
			return;
		}
		$user_obj = get_userdata( $pending['user_id'] );
		if ( ! $user_obj ) {
			self::show_2fa_error( __( 'User not found.', 'malroot-security' ) );
			return;
		}

		$code   = trim( sanitize_text_field( wp_unslash( $_POST['malroot_2fa_code'] ?? '' ) ) );
		$secret = get_user_meta( $user_obj->ID, self::META_SECRET, true );

		// 1) TOTP code
		if ( $secret && Malroot_TOTP::verify( $secret, $code ) ) {
			self::complete_login( $user_obj, $token );
			return;
		}

		// 2) Recovery code
		$recovery = (array) get_user_meta( $user_obj->ID, self::META_RECOVERY, true );
		$upper    = strtoupper( $code );
		if ( $recovery && in_array( $upper, $recovery, true ) ) {
			$recovery = array_values( array_diff( $recovery, [ $upper ] ) );
			update_user_meta( $user_obj->ID, self::META_RECOVERY, $recovery );
			Malroot_Alerting::alert( 'medium', '2fa_recovery_used',
				"Recovery code used by '{$user_obj->user_login}'",
				[ 'user_id' => $user_obj->ID, 'remaining' => count( $recovery ) ]
			);
			self::complete_login( $user_obj, $token );
			return;
		}

		Malroot_Alerting::alert( 'high', '2fa_failed',
			"Failed 2FA attempt for '{$user_obj->user_login}'",
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
			[ 'user_id' => $user_obj->ID, 'ip' => isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '' ]
		);
		self::show_2fa_error( __( 'Invalid authentication code. Please try again.', 'malroot-security' ) );
	}

	private static function complete_login( $user_obj, $token ) {
		delete_transient( 'malroot_2fa_login_' . $token );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$redirect_to = esc_url_raw( isset( $_POST['redirect_to'] ) ? wp_unslash( $_POST['redirect_to'] ) : admin_url() );
		wp_set_auth_cookie( $user_obj->ID, false );
		// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- intentionally firing core hook
		do_action( 'wp_login', $user_obj->user_login, $user_obj );
		wp_safe_redirect( $redirect_to );
		exit;
	}

	private static function show_2fa_error( $message ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$token       = isset( $_POST['malroot_token'] ) ? sanitize_text_field( wp_unslash( $_POST['malroot_token'] ) ) : '';
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$redirect_to = esc_url_raw( isset( $_POST['redirect_to'] ) ? wp_unslash( $_POST['redirect_to'] ) : admin_url() );
		login_header( __( 'Two-Factor Authentication', 'malroot-security' ) );
		?>
		<div id="login_error" style="margin-bottom:1em"><?php echo esc_html( $message ); ?></div>
		<form method="post" id="loginform" action="<?php echo esc_url( wp_login_url() ); ?>">
			<p>
				<label for="malroot_2fa_code"><?php esc_html_e( 'Authentication code', 'malroot-security' ); ?></label>
				<input type="text" id="malroot_2fa_code" name="malroot_2fa_code"
					class="input" style="font-size:24px;letter-spacing:8px;text-align:center;width:100%;padding:10px"
					inputmode="numeric" autocomplete="one-time-code" autofocus required placeholder="000000" maxlength="8" />
			</p>
			<input type="hidden" name="malroot_token" value="<?php echo esc_attr( $token ); ?>" />
			<input type="hidden" name="redirect_to" value="<?php echo esc_attr( $redirect_to ); ?>" />
			<input type="hidden" name="action" value="malroot_2fa_verify" />
			<?php wp_nonce_field( 'malroot_2fa_login', self::NONCE_FIELD ); ?>
			<p class="submit">
				<input type="submit" class="button button-primary button-large" style="width:100%" value="<?php esc_attr_e( 'Verify', 'malroot-security' ); ?>"/>
			</p>
		</form>
		<p style="text-align:center;margin-top:1em">
			<a href="<?php echo esc_url( wp_login_url() ); ?>">&larr; <?php esc_html_e( 'Back to login', 'malroot-security' ); ?></a>
		</p>
		<?php
		login_footer();
		exit;
	}

	/**
	 * Validate the code POSTed from the 2FA form.
	 * @deprecated kept for backward compat but no longer used in the main flow
	 */
	public static function check_2fa_post( $user, $username, $password ) {
		return $user; // no-op — login is now handled by handle_2fa_verify
	}

	/* ---------------------------------------------------------------- */
	/*  Site-wide enforcement                                            */
	/* ---------------------------------------------------------------- */

	public static function enforce_admin_setup() {
		$settings = (array) get_option( 'malroot_settings', [] );
		if ( empty( $settings['require_2fa_admins'] ) ) {
			return;
		}
		$user = wp_get_current_user();
		if ( ! $user || ! $user->ID ) return;
		if ( ! in_array( 'administrator', (array) $user->roles, true ) ) return;
		if ( get_user_meta( $user->ID, self::META_ENABLED, true ) ) return;

		// Allow access only to profile.php and the admin-post 2FA setup
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		$current = isset( $_SERVER['REQUEST_URI'] ) ? wp_basename( wp_parse_url( wp_unslash( $_SERVER['REQUEST_URI'] ), PHP_URL_PATH ) ) : '';
		$allowed = [ 'profile.php', 'admin-post.php', 'admin-ajax.php' ];
		if ( in_array( $current, $allowed, true ) ) return;

		wp_safe_redirect( add_query_arg( 'malroot_force_2fa', 1, admin_url( 'profile.php#malroot-2fa' ) ) );
		exit;
	}
}
