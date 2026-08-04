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
			$who = esc_html( preg_replace( '/#\d+$/', '', str_replace( 'users:', '', $target ) ) );

			// UA-001 is the primary rule: the account is not on the approved list.
			if ( $rule === 'UA-001' ) {
				return [
					'icon'        => '🚨',
					'title'       => __( 'Administrator you never approved', 'malroot-security' ),
					'what'        => sprintf(
						/* translators: %s: username */
						__( 'The account <strong>%s</strong> has full administrator access to your website, but it is not on your approved administrator list.', 'malroot-security' ),
						$who
					),
					'why_bad'     => __( 'An administrator can change any page, read every customer record, add more accounts, and install software. Malroot recorded who your real administrators were, and this account is not one of them — so either someone added it without permission, or it was created by malware.', 'malroot-security' ),
					'action'      => __( 'If you do not recognise this account, click "Remove Account". If it belongs to a colleague or developer you trust, open Malroot > Settings and add them to the approved list instead.', 'malroot-security' ),
					'action_type' => 'quarantine',
					'safe_to_fix' => true,
				];
			}
			if ( $rule === 'UA-002' ) {
				return [
					'icon'        => '📭',
					'title'       => __( 'Admin account uses an email that cannot receive mail', 'malroot-security' ),
					'what'        => sprintf(
						/* translators: %s: username */
						__( 'The administrator <strong>%s</strong> has an email address on a domain that can never receive email — for example one ending in .local, .invalid, or example.com.', 'malroot-security' ),
						$who
					),
					'why_bad'     => __( 'A real person needs a working email address to reset their password or receive notifications. Addresses like these are typed in automatically by hacking tools, which need to fill the field but do not care about replies.', 'malroot-security' ),
					'action'      => __( 'Click "Remove Account". No genuine team member would use an address that cannot receive mail.', 'malroot-security' ),
					'action_type' => 'quarantine',
					'safe_to_fix' => true,
				];
			}
			if ( $rule === 'UA-003' ) {
				return [
					'icon'        => '🚨',
					'title'       => __( 'Admin account appeared after monitoring started', 'malroot-security' ),
					'what'        => sprintf(
						/* translators: %s: username */
						__( 'The administrator <strong>%s</strong> was added to your site after Malroot began watching, and it was never approved through your WordPress dashboard.', 'malroot-security' ),
						$who
					),
					'why_bad'     => __( 'When you add an administrator normally, Malroot sees it happen and approves it automatically. This account skipped that entirely, which means it was written straight into your database rather than created through WordPress.', 'malroot-security' ),
					'action'      => __( 'Treat this as a confirmed break-in. Click "Remove Account", then change your hosting and database passwords, because whoever did this had direct access to your database.', 'malroot-security' ),
					'action_type' => 'quarantine',
					'safe_to_fix' => true,
				];
			}
			if ( $rule === 'UA-004' ) {
				return [
					'icon'        => '📈',
					'title'       => __( 'Several admin accounts created at once', 'malroot-security' ),
					'what'        => __( 'Multiple administrator accounts were created within a few days of each other.', 'malroot-security' ),
					'why_bad'     => __( 'Real websites gain administrators slowly — one person joins, then maybe another months later. A cluster appearing together is the signature of an automated attack script creating spare keys so it can get back in after you remove one.', 'malroot-security' ),
					'action'      => __( 'Review every account listed here. Remove the ones you do not recognise, then change your passwords.', 'malroot-security' ),
					'action_type' => 'manual',
					'safe_to_fix' => false,
				];
			}
			if ( $rule === 'UA-005' ) {
				return [
					'icon'        => '🎲',
					'title'       => __( 'Admin username looks computer-generated', 'malroot-security' ),
					'what'        => sprintf(
						/* translators: %s: username */
						__( 'The administrator name <strong>%s</strong> contains a random string of letters and numbers.', 'malroot-security' ),
						$who
					),
					'why_bad'     => __( 'Attack tools generate a random name for each account so that no two hacked sites look the same, which defeats security plugins that only search for a fixed list of known bad names. People choose names they can remember.', 'malroot-security' ),
					'action'      => __( 'Check whether you recognise this account. If not, click "Remove Account".', 'malroot-security' ),
					'action_type' => 'quarantine',
					'safe_to_fix' => false,
				];
			}
			if ( $rule === 'UA-006' ) {
				return [
					'icon'        => '💤',
					'title'       => __( 'Unused admin account sitting idle', 'malroot-security' ),
					'what'        => sprintf(
						/* translators: %s: username */
						__( 'The administrator <strong>%s</strong> has never signed in and has never written any content, yet it holds full control of your site.', 'malroot-security' ),
						$who
					),
					'why_bad'     => __( 'This is what a spare key looks like. Attackers create accounts and leave them untouched so they blend in, then use them weeks later once you have stopped looking. An unused administrator has no legitimate purpose.', 'malroot-security' ),
					'action'      => __( 'Click "Remove Account". If you created it for someone who has not started yet, give them a lower role until they do.', 'malroot-security' ),
					'action_type' => 'quarantine',
					'safe_to_fix' => true,
				];
			}
			if ( $rule === 'UA-007' ) {
				return [
					'icon'        => '🚫',
					'title'       => __( 'Disabled account still needs deleting', 'malroot-security' ),
					'what'        => sprintf(
						/* translators: %s: username */
						__( 'Malroot already took away all of <strong>%s</strong>\'s permissions, so it cannot do anything. The account itself is still on your site.', 'malroot-security' ),
						$who
					),
					'why_bad'     => __( 'It is harmless as it stands, which is why it was left rather than deleted straight away. It is worth finishing the job: an empty account with no email is confusing to find later, and it is one less thing for an attacker to try to switch back on.', 'malroot-security' ),
					'action'      => __( 'Click "Remove Account" to delete it for good. If it turns out to belong to someone you trust, add them in Malroot > Settings and give them their role back instead.', 'malroot-security' ),
					'action_type' => 'quarantine',
					'safe_to_fix' => true,
				];
			}
			if ( $rule === 'UA-014' ) {
				return [
					'icon'        => '⚙️',
					'title'       => __( 'Approved administrator list has not been set up', 'malroot-security' ),
					'what'        => __( 'Malroot does not yet have a record of which administrators you trust, so it cannot tell a genuine admin apart from one added by an attacker.', 'malroot-security' ),
					'why_bad'     => __( 'This is the single most useful check Malroot performs on user accounts. Without it, a rogue administrator with a normal-looking name and email will not be reported.', 'malroot-security' ),
					'action'      => __( 'Open Malroot > Settings and confirm your administrator list. It takes a moment and switches this protection on.', 'malroot-security' ),
					'action_type' => 'manual',
					'safe_to_fix' => false,
				];
			}
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
		// Behavioural backdoor findings
		// ----------------------------------------------------------------
		if ( $module === 'backdoor' ) {
			$file = esc_html( basename( str_replace( 'plugins:', '', $target ) ) );
			$folder = esc_html( str_replace( 'plugins:', '', $target ) );

			$cards = [
				'BD-001' => [
					'icon'    => '🚨',
					'title'   => __( 'A plugin is creating secret admin accounts', 'malroot-security' ),
					'what'    => __( 'This file contains instructions to build a new administrator account on your site by itself, with no one clicking anything.', 'malroot-security' ),
					'why_bad' => __( 'This is why deleting the fake admin never works — the code simply makes it again on the next page load, or on a daily schedule. You have to remove this file, not just the account.', 'malroot-security' ),
					'action'  => __( 'Click "Remove File". Then delete the accounts it created and change your passwords.', 'malroot-security' ),
					'fix'     => true,
				],
				'BD-002' => [
					'icon'    => '🙈',
					'title'   => __( 'A plugin is hiding user accounts from you', 'malroot-security' ),
					'what'    => __( 'This file changes the list of users WordPress shows you, so that one specific account never appears.', 'malroot-security' ),
					'why_bad' => __( 'You cannot remove an account you cannot see. This is how an attacker keeps a way in while your Users page looks completely normal.', 'malroot-security' ),
					'action'  => __( 'Click "Remove File", then re-check your Users page — accounts you have never seen before may now appear.', 'malroot-security' ),
					'fix'     => true,
				],
				'BD-003' => [
					'icon'    => '🫥',
					'title'   => __( 'A plugin is hiding itself from your Plugins page', 'malroot-security' ),
					'what'    => __( 'This file removes its own entry from your list of installed plugins.', 'malroot-security' ),
					'why_bad' => __( 'No honest plugin hides. This exists so you cannot find or deactivate it, and it often hides pending-update warnings too, so your site looks healthy.', 'malroot-security' ),
					'action'  => __( 'Click "Remove File". Check your Plugins page afterwards for entries that were previously invisible.', 'malroot-security' ),
					'fix'     => true,
				],
				'BD-004' => [
					'icon'    => '🦠',
					'title'   => __( 'A plugin runs code fetched from the internet', 'malroot-security' ),
					'what'    => sprintf(
						/* translators: %s: file name */
						__( 'The file <code>%s</code> downloads instructions from somewhere else and runs them on your server.', 'malroot-security' ),
						$file
					),
					'why_bad' => __( 'Whoever controls that remote address controls your website. They can change what it does at any moment without touching your site again, which is why nothing looks wrong until it is too late.', 'malroot-security' ),
					'action'  => __( 'Click "Remove File" immediately. This is a live remote control channel into your server.', 'malroot-security' ),
					'fix'     => true,
				],
				'BD-005' => [
					'icon'    => '🧩',
					'title'   => __( 'A plugin file is deliberately scrambled', 'malroot-security' ),
					'what'    => __( 'The instructions in this file have been encoded so they cannot be read normally, and are unpacked only while the page is loading.', 'malroot-security' ),
					'why_bad' => __( 'Legitimate plugins have no reason to hide what they do. Scrambling exists purely to get past security scanners that search for recognisable words.', 'malroot-security' ),
					'action'  => __( 'Click "Remove File" unless you know exactly why this file is encoded.', 'malroot-security' ),
					'fix'     => true,
				],
				'BD-006' => [
					'icon'    => '🧩',
					'title'   => __( 'A plugin file was run through an obfuscation tool', 'malroot-security' ),
					'what'    => __( 'This file carries the signature of a tool whose only purpose is to make code unreadable.', 'malroot-security' ),
					'why_bad' => __( 'These tools are marketed specifically for slipping code past malware scanners. Genuine plugins ship readable code.', 'malroot-security' ),
					'action'  => __( 'Click "Remove File".', 'malroot-security' ),
					'fix'     => true,
				],
				'BD-007' => [
					'icon'    => '⚙️',
					'title'   => __( 'A program that runs server commands is in your plugin folder', 'malroot-security' ),
					'what'    => sprintf(
						/* translators: %s: file name */
						__( '<code>%s</code> is not website code — it is a program that issues commands directly to the server operating system.', 'malroot-security' ),
						$file
					),
					'why_bad' => __( 'Files like this are used to open a lasting connection out to the attacker, which slips past firewalls because your own server starts the conversation. WordPress plugins never need this.', 'malroot-security' ),
					'action'  => __( 'Click "Remove File", then ask your host to check for unexpected running processes and outbound connections.', 'malroot-security' ),
					'fix'     => true,
				],
				'BD-008' => [
					'icon'    => '🕵️',
					'title'   => __( 'A plugin hides when it thinks it is being inspected', 'malroot-security' ),
					'what'    => __( 'This file checks whether it is running inside a testing environment or under developer tools, and disappears if it thinks it is being watched.', 'malroot-security' ),
					'why_bad' => __( 'Only malware behaves this way. It is designed so that when you or your developer go looking, everything appears fine.', 'malroot-security' ),
					'action'  => __( 'Click "Remove File". Treat the whole plugin folder as compromised.', 'malroot-security' ),
					'fix'     => true,
				],
				'BD-009' => [
					'icon'    => '📦',
					'title'   => __( 'A plugin folder was uploaded by hand', 'malroot-security' ),
					'what'    => sprintf(
						/* translators: %s: folder name */
						__( 'The folder <code>%s</code> does not match the name of the plugin inside it, which means it was not installed through WordPress.', 'malroot-security' ),
						$folder
					),
					'why_bad' => __( 'Attackers upload a renamed copy of a well-known plugin so the folder looks familiar in your file manager, while extra files hide inside it. It also means WordPress will never offer updates for it.', 'malroot-security' ),
					'action'  => __( 'Compare this folder against a fresh copy of the real plugin. If you did not upload it yourself, remove the whole folder and reinstall the plugin from your Plugins page.', 'malroot-security' ),
					'fix'     => false,
				],
				'BD-010' => [
					'icon'    => '🗂️',
					'title'   => __( 'A hidden file manager is installed on your site', 'malroot-security' ),
					'what'    => sprintf(
						/* translators: %s: file name */
						__( '<code>%s</code> lets anyone who knows the right web address and password create, edit and delete files anywhere on your server.', 'malroot-security' ),
						$file
					),
					'why_bad' => __( 'This is a complete control panel for your server, sitting outside WordPress with its own password. It is how an attacker returns after you clean up, and how they delete other people\'s malware to keep your site to themselves.', 'malroot-security' ),
					'action'  => __( 'Click "Remove File" immediately, then change every password: hosting, database, FTP and WordPress.', 'malroot-security' ),
					'fix'     => true,
				],
			];

			if ( isset( $cards[ $rule ] ) ) {
				$c = $cards[ $rule ];
				return [
					'icon'        => $c['icon'],
					'title'       => $c['title'],
					'what'        => $c['what'],
					'why_bad'     => $c['why_bad'],
					'action'      => $c['action'],
					'action_type' => $c['fix'] ? 'quarantine' : 'manual',
					'safe_to_fix' => $c['fix'],
				];
			}
		}

		// ----------------------------------------------------------------
		// Admin Guard findings
		// ----------------------------------------------------------------
		if ( $module === 'admin-guard' ) {
			return [
				'icon'        => '🛡️',
				'title'       => __( 'Unapproved administrator was shut down', 'malroot-security' ),
				'what'        => sprintf(
					/* translators: %s: username */
					__( 'The account <strong>%s</strong> had administrator access without being on your approved list. Malroot has removed its access and signed it out.', 'malroot-security' ),
					esc_html( preg_replace( '/#\d+$/', '', str_replace( 'users:', '', $target ) ) )
				),
				'why_bad'     => __( 'The account itself still exists but can no longer change anything. It was almost certainly created by an attacker, because it never went through the normal WordPress process of one administrator adding another.', 'malroot-security' ),
				'action'      => __( 'Delete the account to finish the job, then change your hosting and database passwords. If this was a colleague, add them to the approved list in Malroot > Settings and restore their role.', 'malroot-security' ),
				'action_type' => 'quarantine',
				'safe_to_fix' => true,
			];
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
