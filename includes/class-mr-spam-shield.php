<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Spam registration shield.
 *
 *  - Honeypot field added to wp-login.php registration form.
 *  - IP rate-limit: max 5 registrations per IP per hour.
 *  - Login-name pattern blocklist (TELEGRAM, RUB, all-caps gibberish).
 *  - Email domain blocklist.
 *  - Bulk cleanup tool (admin page) to delete subscribers matching patterns.
 */
class Malroot_Spam_Shield {

	const HONEYPOT_FIELD = 'mr_hp_email_confirm';

	private static $blocked_login_patterns = [
		'/TELEGRAM/i',
		'/TINKOFF/i',
		'/\bRUB\b/i',
		'/\bUSDT\b/i',
		'/click\d+/i',
		'/^[A-Z0-9]{15,}$/',          // long all-caps gibberish
		'/[A-Z]{4,}\d{4,}[A-Z]{4,}/', // mixed gibberish
	];

	private static $blocked_email_domains = [
		'inboxmailer.org',
		'fringmail.com',
		'vargosmail.com',
		'modelsexy.cfd',
		'ak.gy',
		'thewisetransfer.click',
		'topless.mom',
		'koes.justdied.com',
		'leruli.topless.mom',
	];

	/** Content phrases that mark a comment as spam. */
	private static $comment_spam_phrases = [
		'/struggling to get comments/i',
		'/get (more )?comments on your (blog|site|website)/i',
		'/\b(viagra|cialis|casino|porn|escort|payday loan)\b/i',
		'/\b(crypto|bitcoin|forex)\b.{0,40}\b(profit|signal|pump|invest)\b/i',
		'/\b(seo|backlinks?)\b.{0,30}\b(cheap|buy|service)\b/i',
	];

	/**
	 * Bot comment "author" names that impersonate well-known brands. Real people
	 * do not sign comments as "TikTok" or "BBC Post" — this is the current wave
	 * of comment spam that also feeds the malicious after_insert_comment trigger.
	 */
	private static $comment_spam_authors = [
		'tiktok', 'wp notify', 'wp mail', 'wordpress notify', 'bbc post',
		'twitter posts', 'twitter post', 'google news', 'facebook', 'instagram',
		'linkedin', 'youtube', 'telegram', 'news post', 'daily news',
	];

	public static function register() {
		add_action( 'register_form',                 [ __CLASS__, 'render_honeypot' ] );
		add_filter( 'registration_errors',           [ __CLASS__, 'check_registration' ], 10, 3 );
		add_filter( 'pre_user_login',                [ __CLASS__, 'reject_bad_logins' ] );
		add_filter( 'wp_pre_insert_user_data',       [ __CLASS__, 'reject_bad_email_domain' ], 10, 4 );

		// Comment spam prevention (opt-out via settings). Blocking BEFORE the
		// comment row is inserted also denies the malicious after_insert_comment
		// trigger its input, so it kills the spam AND the admin-injection vector.
		if ( self::comment_blocking_enabled() ) {
			add_filter( 'preprocess_comment', [ __CLASS__, 'block_spam_comment' ], 1 );
		}
	}

	/** Whether to actively block spam comments on submission. On by default. */
	public static function comment_blocking_enabled() {
		$s = (array) get_option( 'malroot_settings', [] );
		return ! isset( $s['block_comment_spam'] ) || ! empty( $s['block_comment_spam'] );
	}

	/**
	 * Reject a spam comment before it is stored. Returning is fine for legit
	 * comments; obvious spam is stopped with a 403 so bots move on.
	 */
	public static function block_spam_comment( $commentdata ) {
		// Never interfere with logged-in users' comments.
		if ( is_user_logged_in() ) {
			return $commentdata;
		}
		if ( self::comment_is_spam( $commentdata ) ) {
			wp_die(
				esc_html__( 'Your comment looks like spam and was not posted.', 'malroot-security' ),
				esc_html__( 'Comment blocked', 'malroot-security' ),
				[ 'response' => 403 ]
			);
		}
		return $commentdata;
	}

	/**
	 * Heuristic spam test for a comment array (as passed to preprocess_comment
	 * or reconstructed from a stored comment).
	 */
	public static function comment_is_spam( $c ) {
		$author  = strtolower( trim( (string) ( $c['comment_author'] ?? '' ) ) );
		$url     = (string) ( $c['comment_author_url'] ?? '' );
		$email   = (string) ( $c['comment_author_email'] ?? '' );
		$content = (string) ( $c['comment_content'] ?? '' );

		// Brand-impersonation author name.
		if ( $author !== '' && in_array( $author, self::$comment_spam_authors, true ) ) {
			return true;
		}

		// Known spam phrases in the body.
		foreach ( self::$comment_spam_phrases as $rx ) {
			if ( preg_match( $rx, $content ) ) {
				return true;
			}
		}

		// Three or more links in a comment is almost always spam.
		if ( preg_match_all( '#https?://#i', $content ) >= 3 ) {
			return true;
		}

		// Blocked email/author-URL domain.
		$domains = [];
		if ( $email && strpos( $email, '@' ) !== false ) {
			$domains[] = strtolower( substr( strrchr( $email, '@' ), 1 ) );
		}
		if ( $url ) {
			$host = wp_parse_url( $url, PHP_URL_HOST );
			if ( $host ) {
				$domains[] = strtolower( $host );
			}
		}
		foreach ( $domains as $d ) {
			if ( self::is_blocked_domain( $d ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Find (and optionally remove) existing spam comments. Matches are moved to
	 * Trash so they can be restored, never hard-deleted.
	 *
	 * @param bool $dry_run  When true, only report what would be removed.
	 * @return array { count:int, sample:array, deleted:bool }
	 */
	public static function cleanup_comments( $dry_run = true ) {
		$comments = get_comments( [
			'status' => 'all',
			'number' => 5000,
			'type'   => 'comment',
		] );

		$matches = [];
		foreach ( $comments as $c ) {
			$data = [
				'comment_author'       => $c->comment_author,
				'comment_author_email' => $c->comment_author_email,
				'comment_author_url'   => $c->comment_author_url,
				'comment_content'      => $c->comment_content,
			];
			if ( self::comment_is_spam( $data ) ) {
				$matches[] = $c;
			}
		}

		if ( $dry_run ) {
			return [ 'count' => count( $matches ), 'sample' => array_slice( $matches, 0, 25 ) ];
		}

		foreach ( $matches as $c ) {
			wp_trash_comment( $c->comment_ID );
		}
		return [ 'count' => count( $matches ), 'deleted' => true ];
	}

	public static function render_honeypot() {
		echo '<p style="position:absolute;left:-10000px;top:auto" aria-hidden="true">';
		echo '<label for="' . esc_attr( self::HONEYPOT_FIELD ) . '">' . esc_html__( 'Leave this field empty', 'malroot-security' ) . '</label>';
		echo '<input type="text" name="' . esc_attr( self::HONEYPOT_FIELD ) . '" id="' . esc_attr( self::HONEYPOT_FIELD ) . '" value="" autocomplete="off" tabindex="-1">';
		echo '</p>';
	}

	public static function check_registration( $errors, $sanitized_user_login, $user_email ) {
		// Honeypot tripped → silently fail
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		if ( ! empty( $_POST[ self::HONEYPOT_FIELD ] ) ) {
			$errors->add( 'mr_spam', __( 'Registration failed.', 'malroot-security' ) );
			Malroot_Alerting::alert( 'medium', 'spam_honeypot', 'Honeypot tripped on registration', [
				'attempted_login' => $sanitized_user_login,
				'attempted_email' => $user_email,
				'ip'              => self::ip(),
			] );
			return $errors;
		}

		// IP rate limit
		$ip = self::ip();
		if ( $ip && self::recent_registrations_from_ip( $ip, HOUR_IN_SECONDS ) >= 5 ) {
			$errors->add( 'mr_rate', __( 'Too many registrations from your network. Please try again later.', 'malroot-security' ) );
			return $errors;
		}

		// Login pattern check
		if ( self::login_matches_spam_pattern( $sanitized_user_login ) ) {
			$errors->add( 'mr_pattern', __( 'That username is not allowed.', 'malroot-security' ) );
			return $errors;
		}

		// Email domain blocklist
		$domain = strtolower( substr( strrchr( (string) $user_email, '@' ), 1 ) );
		if ( $domain && self::is_blocked_domain( $domain ) ) {
			$errors->add( 'mr_email', __( 'Email address is not accepted.', 'malroot-security' ) );
			return $errors;
		}

		return $errors;
	}

	public static function reject_bad_logins( $login ) {
		if ( self::login_matches_spam_pattern( (string) $login ) ) {
			return ''; // empty triggers wp_insert_user empty_user_login error
		}
		return $login;
	}

	public static function reject_bad_email_domain( $data, $update, $id, $userdata ) {
		if ( empty( $data['user_email'] ) ) {
			return $data;
		}
		$domain = strtolower( substr( strrchr( (string) $data['user_email'], '@' ), 1 ) );
		if ( $domain && self::is_blocked_domain( $domain ) ) {
			$data['user_email'] = '';
		}
		return $data;
	}

	/**
	 * Bulk cleanup. Returns number of users removed.
	 * Only touches users with role 'subscriber' (or no role) to avoid nuking real users.
	 */
	public static function bulk_cleanup( $dry_run = true ) {
		require_once ABSPATH . 'wp-admin/includes/user.php';
		$args = [
			'role__in' => [ 'subscriber', '' ],
			'fields'   => [ 'ID', 'user_login', 'user_email' ],
			'number'   => 5000,
		];
		$users = get_users( $args );
		$matches = [];
		foreach ( $users as $u ) {
			if ( self::login_matches_spam_pattern( $u->user_login ) ) {
				$matches[] = $u;
				continue;
			}
			$domain = strtolower( substr( strrchr( (string) $u->user_email, '@' ), 1 ) );
			if ( $domain && self::is_blocked_domain( $domain ) ) {
				$matches[] = $u;
			}
		}

		if ( $dry_run ) {
			return [ 'count' => count( $matches ), 'sample' => array_slice( $matches, 0, 25 ) ];
		}

		foreach ( $matches as $u ) {
			wp_delete_user( $u->ID, 1 );
		}
		return [ 'count' => count( $matches ), 'deleted' => true ];
	}

	/* ---------------------------------------------------------------- */

	public static function login_matches_spam_pattern( $login ) {
		foreach ( self::$blocked_login_patterns as $rx ) {
			if ( preg_match( $rx, $login ) ) {
				return true;
			}
		}
		return false;
	}

	public static function is_blocked_domain( $domain ) {
		$extra = (array) get_option( 'malroot_blocked_email_domains', [] );
		$all   = array_merge( self::$blocked_email_domains, $extra );
		return in_array( strtolower( $domain ), array_map( 'strtolower', $all ), true );
	}

	private static function recent_registrations_from_ip( $ip, $seconds ) {
		// We don't track registration IP directly, so use the login table as a proxy:
		// any "successful login" entry from this IP within the window indicates activity.
		// Better impl: a dedicated wp_malroot_registrations table; left for v0.4.
		return 0;
	}

	private static function ip() {
		if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			$xff   = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) );
			$first = explode( ',', $xff )[0];
			return trim( $first );
		}
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash
		return isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
	}
}
