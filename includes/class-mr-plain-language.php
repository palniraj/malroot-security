<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Plain-language translator.
 *
 * Converts every technical finding (rule_id, module, target, summary) into
 * a human-readable title, explanation, and recommended action that a
 * non-technical WordPress site owner can understand and act on.
 */
class Malroot_Plain_Language {

	/**
	 * Returns a plain-language card for a finding row.
	 *
	 * @param object $f  Finding row from wp_malroot_findings.
	 * @return array {
	 *   icon        string  emoji icon
	 *   title       string  one-line plain title
	 *   what        string  what this means in plain English
	 *   why_bad     string  why this is a problem
	 *   action      string  what the user should do
	 *   action_type string  'quarantine' | 'rebuild_baseline' | 'manual' | 'info'
	 *   safe_to_fix bool    whether one-click fix is safe
	 * }
	 */
	public static function translate( $f ) {
		$rule   = $f->rule_id ?? '';
		$module = $f->module  ?? '';
		$target = $f->target  ?? '';
		$sev    = $f->severity ?? 'info';

		// ----------------------------------------------------------------
		// Integrity findings — most common after a plugin update
		// ----------------------------------------------------------------
		if ( $module === 'integrity' ) {
			if ( $rule === 'INT-INIT' ) {
				return [
					'icon'        => '📸',
					'title'       => __( 'Security snapshot created', 'malroot-security' ),
					'what'        => __( 'Malroot has taken a photo of all your website files. Future scans will compare against this photo to spot anything that changes unexpectedly.', 'malroot-security' ),
					'why_bad'     => '',
					'action'      => __( 'Nothing to do — this is good news.', 'malroot-security' ),
					'action_type' => 'info',
					'safe_to_fix' => false,
				];
			}
			if ( $rule === 'INT-NEW' ) {
				$is_core = preg_match( '#^wp-(admin|includes)/#', $target );
				return [
					'icon'        => $is_core ? '🚨' : '📄',
					'title'       => $is_core
						? __( 'Unexpected new file in WordPress core', 'malroot-security' )
						: __( 'New file appeared on your site', 'malroot-security' ),
					'what'        => sprintf(
						/* translators: %s: file path */
						__( 'A file called <code>%s</code> appeared on your site since the last security snapshot.', 'malroot-security' ),
						esc_html( basename( $target ) )
					),
					'why_bad'     => $is_core
						? __( 'Hackers often hide malicious files inside WordPress core folders because they look legitimate. This file was not there before.', 'malroot-security' )
						: __( 'If you did not add this file yourself (e.g. by installing a plugin or theme), it may have been placed there by an attacker.', 'malroot-security' ),
					'action'      => __( 'If you recently updated a plugin or theme, click "Update Snapshot" to accept this change. If you did not make any changes, click "Quarantine" to safely remove it.', 'malroot-security' ),
					'action_type' => 'quarantine',
					'safe_to_fix' => true,
				];
			}
			if ( $rule === 'INT-MOD' ) {
				$is_config = preg_match( '#wp-config\.php|\.htaccess#', $target );
				return [
					'icon'        => $is_config ? '🚨' : '✏️',
					'title'       => $is_config
						? __( 'Critical configuration file was changed', 'malroot-security' )
						: __( 'A file on your site was modified', 'malroot-security' ),
					'what'        => sprintf(
						/* translators: %s: file path */
						__( 'The file <code>%s</code> has been changed since your last security snapshot.', 'malroot-security' ),
						esc_html( basename( $target ) )
					),
					'why_bad'     => $is_config
						? __( 'Your site\'s configuration file controls database access and security settings. Unexpected changes here are a serious warning sign.', 'malroot-security' )
						: __( 'If you did not update a plugin or theme recently, this change was not made by you — which means someone else may have modified it.', 'malroot-security' ),
					'action'      => __( 'If you recently updated a plugin, theme, or WordPress itself, click "Update Snapshot" — this is normal. If you did not make any changes, investigate the file content and consider clicking "Quarantine".', 'malroot-security' ),
					'action_type' => 'quarantine',
					'safe_to_fix' => ! $is_config,
				];
			}
			if ( $rule === 'INT-DEL' ) {
				return [
					'icon'        => '🗑️',
					'title'       => __( 'A file was deleted from your site', 'malroot-security' ),
					'what'        => sprintf(
						/* translators: %s: file path */
						__( 'The file <code>%s</code> no longer exists.', 'malroot-security' ),
						esc_html( basename( $target ) )
					),
					'why_bad'     => __( 'This is usually normal (e.g. you uninstalled a plugin). It is only a concern if you did not delete anything recently.', 'malroot-security' ),
					'action'      => __( 'If you recently uninstalled a plugin or theme, click "Update Snapshot". Otherwise, check whether the file was important.', 'malroot-security' ),
					'action_type' => 'rebuild_baseline',
					'safe_to_fix' => true,
				];
			}
		}

		// ----------------------------------------------------------------
		// Trigger findings
		// ----------------------------------------------------------------
		if ( $module === 'triggers' ) {
			return [
				'icon'        => '💣',
				'title'       => __( 'Hidden trap found in your database', 'malroot-security' ),
				'what'        => __( 'A hidden instruction was found inside your database that automatically creates a secret admin account whenever someone posts a specific comment on your site.', 'malroot-security' ),
				'why_bad'     => __( 'This is a classic hacker persistence trick. Even if you delete the fake admin accounts, they come back automatically. This is how the "newsfeed" admin kept reappearing on your site.', 'malroot-security' ),
				'action'      => __( 'Click "Fix Now" to permanently remove this trap. This is safe and will not affect your content.', 'malroot-security' ),
				'action_type' => 'quarantine',
				'safe_to_fix' => true,
			];
		}

		// ----------------------------------------------------------------
		// User findings
		// ----------------------------------------------------------------
		if ( $module === 'users' ) {
			if ( $rule === 'UA-010' || $rule === 'UA-009' ) {
				return [
					'icon'        => '👤',
					'title'       => __( 'Fake admin account found', 'malroot-security' ),
					'what'        => sprintf(
						/* translators: %s: username */
						__( 'An administrator account called <strong>%s</strong> exists on your site. This account was not created by you — it was created by malware.', 'malroot-security' ),
						esc_html( preg_replace( '/#\d+$/', '', str_replace( 'users:', '', $target ) ) )
					),
					'why_bad'     => __( 'Hackers use fake admin accounts to log back into your site even after you think you\'ve cleaned it up. This account gives them full control of your website.', 'malroot-security' ),
					'action'      => __( 'Click "Remove Account" to permanently delete this fake admin. Your real content will not be affected.', 'malroot-security' ),
					'action_type' => 'quarantine',
					'safe_to_fix' => true,
				];
			}
			if ( $rule === 'UA-011' ) {
				return [
					'icon'        => '⚠️',
					'title'       => __( 'Admin account has no email address', 'malroot-security' ),
					'what'        => __( 'One of your administrator accounts does not have a real email address. Legitimate accounts always have an email.', 'malroot-security' ),
					'why_bad'     => __( 'Fake accounts created by malware often have no email because they are created programmatically, not through the normal registration process.', 'malroot-security' ),
					'action'      => __( 'If you recognise this account, add a real email address to it. If you do not recognise it, click "Remove Account".', 'malroot-security' ),
					'action_type' => 'quarantine',
					'safe_to_fix' => false,
				];
			}
			if ( $rule === 'UA-013' ) {
				return [
					'icon'        => '⚠️',
					'title'       => __( 'Admin account looks suspicious', 'malroot-security' ),
					'what'        => __( 'An administrator account has a generic website URL (https://wordpress.com) that malware commonly uses as a default.', 'malroot-security' ),
					'why_bad'     => __( 'Real admin accounts created by site owners have your site\'s URL or no URL at all. This pattern is a common sign of a machine-created account.', 'malroot-security' ),
					'action'      => __( 'Check if you recognise this account. If not, click "Remove Account".', 'malroot-security' ),
					'action_type' => 'quarantine',
					'safe_to_fix' => false,
				];
			}
		}

		// ----------------------------------------------------------------
		// File findings
		// ----------------------------------------------------------------
		if ( $module === 'files' ) {
			if ( in_array( $rule, [ 'MAL-005', 'MAL-EVAL' ], true ) ) {
				return [
					'icon'        => '🦠',
					'title'       => __( 'Hacker tool found on your site', 'malroot-security' ),
					'what'        => sprintf(
						/* translators: %s: file path */
						__( 'A file called <code>%s</code> is a hacker\'s remote control tool (called a "webshell"). It lets an attacker control your entire website from anywhere in the world.', 'malroot-security' ),
						esc_html( basename( $target ) )
					),
					'why_bad'     => __( 'With this file on your site, an attacker can read your database, steal customer data, send spam emails, and install more malware — all without needing your password.', 'malroot-security' ),
					'action'      => __( 'Click "Remove File" immediately. This is the most dangerous type of finding.', 'malroot-security' ),
					'action_type' => 'quarantine',
					'safe_to_fix' => true,
				];
			}
			if ( $rule === 'MAL-004' ) {
				return [
					'icon'        => '🦠',
					'title'       => __( 'Hidden backdoor found', 'malroot-security' ),
					'what'        => sprintf(
						/* translators: %s: file path */
						__( 'A file called <code>%s</code> is a backdoor that can download and run any malicious code from the internet on your server.', 'malroot-security' ),
						esc_html( basename( $target ) )
					),
					'why_bad'     => __( 'This file is like a hidden door into your server. An attacker can use it to take over your site at any time.', 'malroot-security' ),
					'action'      => __( 'Click "Remove File" immediately.', 'malroot-security' ),
					'action_type' => 'quarantine',
					'safe_to_fix' => true,
				];
			}
			if ( $rule === 'MAL-006' ) {
				return [
					'icon'        => '📤',
					'title'       => __( 'Unauthorised file upload form found', 'malroot-security' ),
					'what'        => sprintf(
						/* translators: %s: file path */
						__( 'A file called <code>%s</code> lets anyone on the internet upload files to your server without a password.', 'malroot-security' ),
						esc_html( basename( $target ) )
					),
					'why_bad'     => __( 'An attacker can use this to upload more malware, deface your site, or steal your data.', 'malroot-security' ),
					'action'      => __( 'Click "Remove File" immediately.', 'malroot-security' ),
					'action_type' => 'quarantine',
					'safe_to_fix' => true,
				];
			}
			if ( $rule === 'FI-001' ) {
				return [
					'icon'        => '📄',
					'title'       => __( 'PHP file found in your uploads folder', 'malroot-security' ),
					'what'        => sprintf(
						/* translators: %s: file path */
						__( 'A PHP code file called <code>%s</code> was found in your uploads folder. Only images, PDFs, and documents should be in this folder — never code files.', 'malroot-security' ),
						esc_html( basename( $target ) )
					),
					'why_bad'     => __( 'Hackers often hide malicious code in the uploads folder because it is publicly accessible and rarely checked.', 'malroot-security' ),
					'action'      => __( 'Click "Remove File". If this was a legitimate file, contact your developer.', 'malroot-security' ),
					'action_type' => 'quarantine',
					'safe_to_fix' => true,
				];
			}
			if ( $rule === 'FI-002' ) {
				return [
					'icon'        => '🔑',
					'title'       => __( 'Your database password is exposed', 'malroot-security' ),
					'what'        => sprintf(
						/* translators: %s: file path */
						__( 'A copy of your site\'s configuration file (including your database password) is publicly accessible at <code>%s</code>.', 'malroot-security' ),
						esc_html( $target )
					),
					'why_bad'     => __( 'Anyone who finds this file can access your entire database, including customer orders, passwords, and personal data.', 'malroot-security' ),
					'action'      => __( 'Click "Remove File" immediately, then change your database password in your hosting control panel.', 'malroot-security' ),
					'action_type' => 'quarantine',
					'safe_to_fix' => true,
				];
			}
			if ( $rule === 'FI-003' ) {
				return [
					'icon'        => '🗄️',
					'title'       => __( 'Database backup is publicly accessible', 'malroot-security' ),
					'what'        => sprintf(
						/* translators: %s: file path */
						__( 'A database backup file (<code>%s</code>) is sitting in a publicly accessible folder on your server.', 'malroot-security' ),
						esc_html( basename( $target ) )
					),
					'why_bad'     => __( 'This file contains your entire database — customer data, orders, email addresses, and hashed passwords. Anyone can download it.', 'malroot-security' ),
					'action'      => __( 'Click "Move to Safety" to remove it from public access. Store backups outside your website folder.', 'malroot-security' ),
					'action_type' => 'quarantine',
					'safe_to_fix' => true,
				];
			}
			if ( $rule === 'SH-008' ) {
				return [
					'icon'        => '🕵️',
					'title'       => __( 'Hidden malware folder found', 'malroot-security' ),
					'what'        => __( 'A hidden folder containing PHP code was found on your server. Hidden folders (starting with a dot) are invisible in most file managers, which is why hackers use them.', 'malroot-security' ),
					'why_bad'     => __( 'This is likely a backup copy of malware that reinstalls itself automatically if you delete the main infection. This is how the "system-control" malware persisted on your site.', 'malroot-security' ),
					'action'      => __( 'Click "Remove Folder" to permanently delete it.', 'malroot-security' ),
					'action_type' => 'quarantine',
					'safe_to_fix' => true,
				];
			}
		}

		// ----------------------------------------------------------------
		// Database findings
		// ----------------------------------------------------------------
		if ( $module === 'database' ) {
			if ( $rule === 'DB-SC' ) {
				return [
					'icon'        => '🔧',
					'title'       => __( 'Malware settings still in database', 'malroot-security' ),
					'what'        => __( 'Settings left behind by the "system-control" malware are still stored in your database. The malware itself may be gone, but these settings remain.', 'malroot-security' ),
					'why_bad'     => __( 'These settings could be used to reconnect to the attacker\'s control panel if the malware is reinstalled.', 'malroot-security' ),
					'action'      => __( 'Click "Clean Up" to remove these leftover settings.', 'malroot-security' ),
					'action_type' => 'quarantine',
					'safe_to_fix' => true,
				];
			}
			if ( in_array( $rule, [ 'DB-001', 'DB-002', 'DB-005', 'DB-006' ], true ) ) {
				return [
					'icon'        => '💉',
					'title'       => __( 'Malicious code found in your database', 'malroot-security' ),
					'what'        => __( 'Hidden PHP code was found stored inside your database. This is a sophisticated attack where the malware hides in your content rather than in files, making it harder to detect.', 'malroot-security' ),
					'why_bad'     => __( 'This code can create fake admin accounts, redirect your visitors to scam sites, or steal customer data — all without leaving any trace in your files.', 'malroot-security' ),
					'action'      => __( 'Click "Quarantine" to safely remove this code. Malroot will keep a backup in case you need to review it.', 'malroot-security' ),
					'action_type' => 'quarantine',
					'safe_to_fix' => true,
				];
			}
			if ( $rule === 'DB-004' ) {
				return [
					'icon'        => '🌐',
					'title'       => __( 'Known hacker domain found in your database', 'malroot-security' ),
					'what'        => __( 'A domain name associated with known hacking activity was found stored in your database.', 'malroot-security' ),
					'why_bad'     => __( 'This domain is used by attackers to control hacked websites. Its presence means your site may be communicating with an attacker\'s server.', 'malroot-security' ),
					'action'      => __( 'Click "Quarantine" to remove this entry, then run a full scan to check for related malware.', 'malroot-security' ),
					'action_type' => 'quarantine',
					'safe_to_fix' => true,
				];
			}
		}

		// ----------------------------------------------------------------
		// REST API findings
		// ----------------------------------------------------------------
		if ( $module === 'rest' ) {
			$ns = esc_html( str_replace( 'rest:', '', $target ) );

			// RT-007: the endpoint belongs to a plugin the site actually has
			// installed. Low priority, reassuring wording.
			if ( $rule === 'RT-007' ) {
				return [
					'icon'        => '🔌',
					'title'       => __( 'Installed plugin exposes a sensitive API endpoint', 'malroot-security' ),
					'what'        => sprintf(
						/* translators: %s: namespace */
						__( 'The API endpoint <code>%s</code> belongs to one of your installed, active plugins. It handles sensitive actions, so we list it here for your awareness.', 'malroot-security' ),
						$ns
					),
					'why_bad'     => __( 'This is not a sign of a hack. It only matters if you no longer trust or use the plugin that owns this endpoint.', 'malroot-security' ),
					'action'      => __( 'No action needed unless you do not recognise the plugin. Keep it updated to the latest version.', 'malroot-security' ),
					'action_type' => 'info',
					'safe_to_fix' => false,
				];
			}

			// RT-001 / RT-006: namespace could NOT be matched to any installed plugin.
			return [
				'icon'        => '🔌',
				'title'       => __( 'Unknown API endpoint not linked to any installed plugin', 'malroot-security' ),
				'what'        => sprintf(
					/* translators: %s: namespace */
					__( 'An API endpoint called <code>%s</code> is registered on your site, but it does not match any plugin you have installed.', 'malroot-security' ),
					$ns
				),
				'why_bad'     => __( 'Malicious code sometimes creates hidden API endpoints that let attackers control your site remotely without logging in. Because this one has no matching plugin, it is worth checking.', 'malroot-security' ),
				'action'      => __( 'Review your installed plugins. If you cannot account for this endpoint, treat your site as possibly compromised and run a full scan and cleanup.', 'malroot-security' ),
				'action_type' => 'manual',
				'safe_to_fix' => false,
			];
		}

		// ----------------------------------------------------------------
		// mu-plugin findings
		// ----------------------------------------------------------------
		if ( $module === 'muplugins' ) {
			// SH-007 = writes files at runtime / zero-byte stub → genuine
			// self-healing malware pattern. SH-006 = simply not on the allowlist,
			// which is very often a legitimate host/plugin must-use plugin.
			if ( $rule === 'SH-006' ) {
				return [
					'icon'        => '🧩',
					'title'       => __( 'Unrecognised must-use plugin', 'malroot-security' ),
					'what'        => sprintf(
						/* translators: %s: mu-plugin file name */
						__( 'A must-use plugin (<code>%s</code>) is present that Malroot does not recognise. Must-use plugins load automatically. Hosts (e.g. Hostinger, WP Engine, Kinsta) and plugins (e.g. WP Staging, Installatron) legitimately place files here.', 'malroot-security' ),
						esc_html( str_replace( 'muplugins:', '', $target ) )
					),
					'why_bad'     => __( 'This is only a concern if you do not recognise it. It is not, by itself, a sign of malware.', 'malroot-security' ),
					'action'      => __( 'If it belongs to your host or a plugin you use, leave it. If you do not recognise it, view the file details before removing.', 'malroot-security' ),
					'action_type' => 'manual',
					'safe_to_fix' => false,
				];
			}
			return [
				'icon'        => '🔄',
				'title'       => __( 'Self-reinstalling malware component found', 'malroot-security' ),
				'what'        => __( 'A file was found in a special WordPress folder (mu-plugins) that automatically loads on every page visit and can reinstall malware that you have already deleted.', 'malroot-security' ),
				'why_bad'     => __( 'This is how malware "comes back" after you think you\'ve cleaned it. The file in mu-plugins acts like a watchdog that restores the infection.', 'malroot-security' ),
				'action'      => __( 'Click "Remove File" to stop the reinstall loop.', 'malroot-security' ),
				'action_type' => 'quarantine',
				'safe_to_fix' => true,
			];
		}

		// ----------------------------------------------------------------
		// Bot-cloak findings
		// ----------------------------------------------------------------
		if ( $module === 'botcloak' ) {
			return [
				'icon'        => '🤖',
				'title'       => __( 'Your site shows different content to Google', 'malroot-security' ),
				'what'        => __( 'When Google visits your site, it sees different content than what your real visitors see. This is called "cloaking" and is used to hide spam links from humans while showing them to search engines.', 'malroot-security' ),
				'why_bad'     => __( 'Google will penalise your site for this, causing your search rankings to drop. Your site may also be blacklisted by Google, making it invisible in search results.', 'malroot-security' ),
				'action'      => __( 'Run the Incident Response to clean up the malware causing this. Then submit your site to Google Search Console for review.', 'malroot-security' ),
				'action_type' => 'manual',
				'safe_to_fix' => false,
			];
		}

		// ----------------------------------------------------------------
		// Fallback for anything not specifically mapped
		// ----------------------------------------------------------------
		return [
			'icon'        => '⚠️',
   /* translators: %s is replaced with dynamic content */
			'title'       => sprintf( __( 'Security issue detected (%s)', 'malroot-security' ), esc_html( $rule ) ),
			'what'        => esc_html( $f->summary ?? '' ),
			'why_bad'     => __( 'This finding was flagged by Malroot\'s security scanner as potentially dangerous.', 'malroot-security' ),
			'action'      => $sev === 'critical' || $sev === 'high'
				? __( 'Click "Quarantine" to safely remove this item, or contact your developer for advice.', 'malroot-security' )
				: __( 'Review this finding and take action if needed.', 'malroot-security' ),
			'action_type' => 'quarantine',
			'safe_to_fix' => false,
		];
	}
}
