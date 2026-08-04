<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Behavioural backdoor scanner for plugin / theme / mu-plugin code.
 *
 * WHY THIS EXISTS
 * ---------------
 * Malroot_Scanner_Files matches a fixed list of literal signatures taken from
 * one earlier incident. On cityagecare.com a complete backdoor kit was shipped
 * inside a directory called `bbPress2.6.14` and every single file evaded it:
 *
 *   sodium_compat.php     eval('?>' . $remote)      -- MAL-EVAL needs eval(base64_decode
 *   Node-manager.php      "\x73\x68\x65\x6c\x6c..." -- no plaintext shell_exec to match
 *   renge2.php  (3.8 MB)  base64 chunks + obfuscator
 *   bbpress.php           wp_create_user + set_role('administrator')
 *   deploy-all.sh (16 MB) never opened: not a .php extension, over the size cap
 *
 * Signature lists lose this game by design — the attacker only has to rename a
 * function or split a string. So these rules describe BEHAVIOUR that no
 * legitimate plugin in a normal install exhibits:
 *
 *   creating administrators, hiding rows from the user list, hiding itself from
 *   the plugin list, executing code it did not ship with, refusing to run under
 *   a debugger, or carrying shell scripts and binaries.
 *
 * False positives are managed by excluding vendored cryptography libraries
 * (phpseclib legitimately eval()s generated arithmetic) and by requiring the
 * specific evasive form rather than the mere presence of a hook. User Role
 * Editor filters the user list by ROLE, which is legitimate; the backdoor
 * injected a hardcoded literal username, which is not.
 */
class Malroot_Scanner_Backdoor extends Malroot_Scanner_Base {

	protected $module = 'backdoor';

	/** Read at most this much of any single file. */
	const READ_BYTES = 1048576; // 1 MB is far past any header/banner/eval

	/**
	 * Vendored libraries that legitimately generate and evaluate code, or that
	 * ship dense escape sequences. Excluded from the obfuscation rules only.
	 */
	private static $library_paths = [
		'/vendor/', '/third-party/', '/node_modules/', '/lib/composer/',
		'phpseclib', 'paragonie', 'sodium_compat/autoload', 'symfony', 'guzzle',
		'/simplepie/', '/requests/',
	];

	public function run() {
		foreach ( $this->roots() as $root ) {
			if ( is_dir( $root ) ) {
				$this->scan_tree( $root );
			}
		}
		$this->check_plugin_slugs();
	}

	private function roots() {
		$roots = [ WP_CONTENT_DIR . '/plugins', WP_CONTENT_DIR . '/themes' ];
		if ( defined( 'WPMU_PLUGIN_DIR' ) ) {
			$roots[] = WPMU_PLUGIN_DIR;
		}
		return $roots;
	}

	/* ------------------------------------------------------------------ */
	/*  Tree walk                                                         */
	/* ------------------------------------------------------------------ */

	private function scan_tree( $root ) {
		try {
			$it = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::LEAVES_ONLY
			);
		} catch ( Throwable $e ) {
			return;
		}

		foreach ( $it as $file ) {
			if ( ! $file->isFile() ) {
				continue;
			}
			$path = $file->getPathname();
			if ( $this->is_excluded( $path ) ) {
				continue;
			}

			// Executables and shell scripts never belong in plugin code, and
			// they are exactly what the size/extension filters used to miss.
			if ( $this->check_non_php_payload( $path, $file->getSize() ) ) {
				continue;
			}

			if ( ! preg_match( '/\.(php|phtml|phar|inc)$/i', $path ) ) {
				continue;
			}

			$code = $this->read_head( $path );
			if ( '' === $code ) {
				continue;
			}

			$rel     = $this->relpath( $path );
			$is_lib  = $this->is_library_path( $path );

			$this->check_admin_factory( $rel, $code );
			$this->check_user_list_hiding( $rel, $code );
			$this->check_plugin_list_hiding( $rel, $code );
			$this->check_anti_analysis( $rel, $code );
			$this->check_remote_file_control( $rel, $code, $is_lib );

			if ( ! $is_lib ) {
				$this->check_dynamic_execution( $rel, $code );
				$this->check_obfuscation( $rel, $code );
			}
		}
	}

	/* ------------------------------------------------------------------ */
	/*  Rules                                                             */
	/* ------------------------------------------------------------------ */

	/**
	 * BD-001 — code that manufactures an administrator.
	 * This is the persistence mechanism that makes deleting the account
	 * pointless: the plugin simply recreates it on the next page load or cron.
	 */
	private function check_admin_factory( $rel, $code ) {
		$creates = preg_match( '/\b(wp_create_user|wp_insert_user)\s*\(/i', $code );
		if ( ! $creates ) {
			return;
		}
		$elevates = preg_match( '/set_role\s*\(\s*[\'"]administrator[\'"]/i', $code )
			|| preg_match( '/add_role\s*\(\s*[\'"]administrator[\'"]/i', $code )
			|| preg_match( '/[\'"]administrator[\'"]\s*=>\s*(true|1)/i', $code )
			|| preg_match( '/[\'"]role[\'"]\s*=>\s*[\'"]administrator[\'"]/i', $code );

		if ( ! $elevates ) {
			return;
		}

		// A user-management plugin doing this from an admin screen is expected.
		// Doing it from a hook that fires on every request is not.
		$autonomous = preg_match( '/add_action\s*\(\s*[\'"](plugins_loaded|init|wp_loaded|wp_head|shutdown|upgrader_process_complete)[\'"]/i', $code )
			|| preg_match( '/wp_schedule_event|wp_next_scheduled/i', $code );

		$this->record(
			'BD-001',
			'critical',
			$rel,
			$autonomous
				? 'Code creates an administrator account automatically, without anyone asking it to'
				: 'Code creates an administrator account',
			$this->evidence( $code, [
				'/\b(wp_create_user|wp_insert_user)\s*\([^;]{0,120}/i',
				'/set_role\s*\(\s*[\'"]administrator[\'"]\s*\)/i',
				'/wp_schedule_event\s*\([^;]{0,80}/i',
			] )
		);
	}

	/**
	 * BD-002 — rewriting the user query to hide specific accounts.
	 * Filtering by role (as User Role Editor does) is legitimate. Splicing a
	 * hardcoded login name into query_where is how a backdoor hides its own
	 * account from the Users screen.
	 */
	private function check_user_list_hiding( $rel, $code ) {
		if ( ! preg_match( '/query_where/i', $code ) ) {
			return;
		}
		if ( ! preg_match( '/user_login/i', $code ) ) {
			return;
		}
		// Require an inequality against a login, i.e. "hide this one row".
		if ( ! preg_match( '/user_login[^;]{0,40}(!=|<>|NOT\s+IN|NOT\s+LIKE)/i', $code )
			&& ! preg_match( '/(!=|<>)\s*[\'"]?\s*\.?\s*\$this->/i', $code ) ) {
			return;
		}

		$this->record(
			'BD-002',
			'critical',
			$rel,
			'Code alters the user list query to hide a specific account from you',
			$this->evidence( $code, [
				'/[^;\n]{0,80}query_where[^;\n]{0,160}/i',
			] )
		);
	}

	/** BD-003 — removing itself from the installed-plugins list. */
	private function check_plugin_list_hiding( $rel, $code ) {
		$hooks = preg_match( '/(pre_current_active_plugins|all_plugins|show_advanced_plugins)/i', $code );
		if ( ! $hooks ) {
			return;
		}
		if ( ! preg_match( '/unset\s*\(|remove\s*\(/i', $code ) ) {
			return;
		}
		$self = preg_match( '/plugin_basename\s*\(\s*__FILE__\s*\)/i', $code )
			|| preg_match( '/\$wp_list_table->items/i', $code );
		if ( ! $self ) {
			return;
		}

		$this->record(
			'BD-003',
			'critical',
			$rel,
			'Code removes itself from your Plugins list so you cannot see or deactivate it',
			$this->evidence( $code, [ '/[^;\n]{0,60}(pre_current_active_plugins|\$wp_list_table->items)[^;\n]{0,100}/i' ] )
		);
	}

	/**
	 * BD-004 — executing code the file did not ship with.
	 * Covers eval of a variable, of concatenation, and of a remote fetch —
	 * the forms a literal `eval(base64_decode(` signature never sees.
	 */
	private function check_dynamic_execution( $rel, $code ) {
		$hits = [];

		// eval() whose argument is not a plain literal.
		if ( preg_match( '/\beval\s*\(\s*[\'"]\s*\?>\s*[\'"]\s*\./i', $code ) ) {
			$hits[] = 'eval() of content appended to a PHP close tag';
		}
		if ( preg_match( '/\beval\s*\(\s*\$[a-z_][a-z0-9_]*\s*\)/i', $code ) ) {
			$hits[] = 'eval() of a variable';
		}
		if ( preg_match( '/\beval\s*\([^;)]{0,80}(file_get_contents|curl_exec|fsockopen|fopen)/i', $code ) ) {
			$hits[] = 'eval() of downloaded content';
		}
		// Remote source feeding execution.
		if ( preg_match( '/(file_get_contents|curl_setopt|curl_init)\s*\(\s*[\'"]?\s*https?:\/\//i', $code )
			&& preg_match( '/\beval\s*\(/i', $code ) ) {
			$hits[] = 'downloads code from a URL and runs it';
		}
		// Variable function / callback indirection to a dangerous primitive.
		if ( preg_match( '/\$__?f\s*\[/', $code ) && preg_match( '/\\\\x[0-9a-f]{2}/i', $code ) ) {
			$hits[] = 'dispatch table of hex-encoded function names';
		}

		if ( empty( $hits ) ) {
			return;
		}

		$this->record(
			'BD-004',
			'critical',
			$rel,
			'Code runs instructions that are not part of the file: ' . implode( '; ', $hits ),
			$this->evidence( $code, [
				'/[^;\n]{0,60}\beval\s*\([^;\n]{0,100}/i',
				'/[^;\n]{0,40}https?:\/\/[^\s\'"]{0,80}/i',
			] )
		);
	}

	/** BD-005 / BD-006 — deliberate obfuscation. */
	private function check_obfuscation( $rel, $code ) {
		// Known obfuscator banners.
		if ( preg_match( '/(Smart Obfuscator|bypass\.pw|Obfuscated by|FOPO|phpjiami|Obfuskasi)/i', $code, $m ) ) {
			$this->record(
				'BD-006',
				'high',
				$rel,
				'File was deliberately scrambled to hide what it does (' . trim( $m[0] ) . ')',
				$this->evidence( $code, [ '/[^;\n]{0,60}(Smart Obfuscator|bypass\.pw|Obfuskasi)[^;\n]{0,60}/i' ] )
			);
			return;
		}

		// Dense hex escapes: legitimate code uses a handful, obfuscators use many.
		$hex = preg_match_all( '/\\\\x[0-9a-f]{2}/i', $code );
		if ( $hex >= 40 ) {
			$this->record(
				'BD-005',
				'high',
				$rel,
				"Function names in this file are written as {$hex} hex escape codes, which hides them from security scanners",
				'hex_escape_count=' . $hex
			);
			return;
		}

		// Long base64 built by concatenation, then decoded.
		if ( preg_match_all( '/\$[a-z_][a-z0-9_]*\s*\.=\s*[\'"][A-Za-z0-9+\/=]{3,}[\'"]\s*;/i', $code ) >= 20
			&& preg_match( '/base64_decode|gzinflate|gzuncompress|str_rot13/i', $code ) ) {
			$this->record(
				'BD-005',
				'high',
				$rel,
				'A large encoded payload is assembled piece by piece and then decoded at run time',
				'pattern=chunked base64 assembly'
			);
		}
	}

	/**
	 * BD-008 — refusing to run under analysis.
	 * Legitimate software does not check whether it is inside VMware or whether
	 * Xdebug is loaded and then serve a 404.
	 */
	private function check_anti_analysis( $rel, $code ) {
		$vm = preg_match( '/(vmware|virtualbox|vbox|qemu|xen)/i', $code )
			&& preg_match( '/php_uname/i', $code );
		$dbg = preg_match( '/xdebug_break|xdebug_is_debugger_active/i', $code );

		if ( ! $vm && ! $dbg ) {
			return;
		}
		// Must react by hiding, not merely report the environment.
		if ( ! preg_match( '/set_404|status_header\s*\(\s*404|die\s*\(|exit\s*\(/i', $code ) ) {
			return;
		}

		$this->record(
			'BD-008',
			'high',
			$rel,
			'Code detects virtual machines or debuggers and hides itself when it thinks it is being examined',
			$this->evidence( $code, [
				'/[^;\n]{0,60}(php_uname|xdebug_break)[^;\n]{0,80}/i',
			] )
		);
	}

	/**
	 * BD-010 — a file manager driven by the request.
	 *
	 * Taking a filesystem path or a user id straight out of $_POST/$_GET and
	 * then deleting, writing or moving it is the core capability of every
	 * webshell. It is also how the kit on this site removed rival malware while
	 * keeping its own account, via a hardcoded list of "protected" logins.
	 */
	private function check_remote_file_control( $rel, $code, $is_lib ) {
		if ( $is_lib ) {
			return;
		}
		// A path that originates in the request.
		$req_path = preg_match(
			'/\$_(POST|GET|REQUEST)\s*\[\s*[\'"][^\'"]*(file|path|dir|name|target)[^\'"]*[\'"]\s*\]/i',
			$code
		);
		if ( ! $req_path ) {
			return;
		}

		$destructive = [];
		if ( preg_match( '/@?\bunlink\s*\(/i', $code ) )                 { $destructive[] = 'deletes files'; }
		if ( preg_match( '/@?\b(rmdir|rename)\s*\(/i', $code ) )         { $destructive[] = 'removes or renames files'; }
		if ( preg_match( '/@?\bfile_put_contents\s*\(/i', $code ) )      { $destructive[] = 'writes files'; }
		if ( preg_match( '/@?\b(chmod|move_uploaded_file)\s*\(/i', $code ) ) { $destructive[] = 'changes permissions or accepts uploads'; }
		if ( preg_match( '/\bwp_delete_user\s*\(/i', $code ) )           { $destructive[] = 'deletes user accounts'; }

		if ( count( $destructive ) < 2 ) {
			return; // a single write is common and legitimate
		}

		// A hardcoded credential or a protected-account list turns this from a
		// plugin feature into a private control panel.
		$gated = preg_match( '/PROTECTED_ACCOUNTS|protected_accounts/i', $code )
			|| preg_match( '/\$[a-z_]*(pass|pwd|token|key)[a-z_]*\s*=\s*[\'"][^\'"]{8,}[\'"]\s*;/i', $code );

		$this->record(
			'BD-010',
			$gated ? 'critical' : 'high',
			$rel,
			'Code lets whoever sends the right request manage files on your server (' . implode( ', ', array_slice( $destructive, 0, 3 ) ) . ')'
				. ( $gated ? ' and is unlocked by a password built into the file' : '' ),
			$this->evidence( $code, [
				'/[^;\n]{0,50}\$_(POST|GET|REQUEST)\s*\[\s*[\'"][^\'"]*(file|path|dir|target)[^\'"]*[\'"][^;\n]{0,60}/i',
				'/[^;\n]{0,40}\b(unlink|file_put_contents|wp_delete_user)\s*\([^;\n]{0,60}/i',
				'/\$[a-z_]*(pass|token|key)[a-z_]*\s*=\s*[\'"][^\'"]{8,}[\'"]\s*;/i',
			] )
		);
	}

	/**
	 * BD-007 — shell scripts and compiled binaries inside plugin directories.
	 * Returns true when the file was handled, so the PHP rules are skipped.
	 */
	private function check_non_php_payload( $path, $size ) {
		$rel = $this->relpath( $path );

		// Vendored packages ship their own build tooling; that is expected.
		if ( $this->is_library_path( $path ) ) {
			return false;
		}

		if ( preg_match( '/\.(sh|bash|pl|py|elf|bin|so|out)$/i', $path ) ) {
			$this->record(
				'BD-007',
				'high',
				$rel,
				'A script that runs operating-system commands is stored in your plugin folder',
				'size=' . $size . '; type=' . strtolower( pathinfo( $path, PATHINFO_EXTENSION ) )
			);
			return true;
		}

		// Sniff magic bytes for a script or ELF binary regardless of extension.
		$fh = @fopen( $path, 'rb' );
		if ( ! $fh ) {
			return false;
		}
		$magic = (string) fread( $fh, 4 );
		fclose( $fh );

		if ( 0 === strpos( $magic, "\x7fELF" ) ) {
			$this->record(
				'BD-007',
				'critical',
				$rel,
				'A compiled program is hidden in your plugin folder',
				'size=' . $size . '; type=ELF executable'
			);
			return true;
		}
		if ( 0 === strpos( $magic, '#!/' ) && ! preg_match( '/\.(php|phtml|inc)$/i', $path ) ) {
			$this->record(
				'BD-007',
				'high',
				$rel,
				'A script that runs operating-system commands is stored in your plugin folder',
				'size=' . $size . '; type=shell script (detected by shebang)'
			);
			return true;
		}

		return false;
	}

	/**
	 * BD-009 — plugin directory name does not match the plugin it claims to be.
	 * A directory like `bbPress2.6.14` holding a plugin whose header says
	 * "bbPress" was placed there by hand, not installed from wordpress.org.
	 */
	private function check_plugin_slugs() {
		$dir = WP_CONTENT_DIR . '/plugins';
		if ( ! is_dir( $dir ) ) {
			return;
		}
		foreach ( (array) glob( $dir . '/*', GLOB_ONLYDIR ) as $plugin_dir ) {
			$slug = basename( $plugin_dir );
			if ( $this->is_excluded( $plugin_dir ) ) {
				continue;
			}
			// A version number or capital letters in a slug is the tell-tale of
			// a manually uploaded archive.
			$looks_hand_placed = (bool) preg_match( '/\d+\.\d+/', $slug ) || $slug !== strtolower( $slug );
			if ( ! $looks_hand_placed ) {
				continue;
			}

			$name = '';
			foreach ( (array) glob( $plugin_dir . '/*.php' ) as $php ) {
				$head = $this->read_head( $php, 4096 );
				if ( preg_match( '/^[\s*\/#]*Plugin Name:\s*(.+)$/mi', $head, $m ) ) {
					$name = trim( $m[1] );
					break;
				}
			}
			if ( '' === $name ) {
				continue;
			}

			$expected = strtolower( preg_replace( '/[^a-z0-9]+/i', '-', $name ) );
			$expected = trim( $expected, '-' );
			if ( strtolower( $slug ) === $expected ) {
				continue;
			}

			$this->record(
				'BD-009',
				'medium',
				'plugins:' . $slug,
				sprintf(
					'Plugin folder "%s" does not match the plugin it claims to be ("%s"), so it was uploaded by hand rather than installed normally',
					$slug,
					$name
				),
				"folder={$slug}; declared_name={$name}; expected_folder={$expected}"
			);
		}
	}

	/* ------------------------------------------------------------------ */
	/*  Helpers                                                           */
	/* ------------------------------------------------------------------ */

	private function read_head( $path, $bytes = self::READ_BYTES ) {
		$fh = @fopen( $path, 'rb' );
		if ( ! $fh ) {
			return '';
		}
		$data = (string) fread( $fh, $bytes );
		fclose( $fh );
		return $data;
	}

	/** Pull short illustrative excerpts so the finding is reviewable. */
	private function evidence( $code, array $patterns, $limit = 3 ) {
		$out = [];
		foreach ( $patterns as $rx ) {
			if ( preg_match( $rx, $code, $m ) ) {
				$line = trim( preg_replace( '/\s+/', ' ', $m[0] ) );
				if ( '' !== $line ) {
					$out[] = substr( $line, 0, 200 );
				}
			}
			if ( count( $out ) >= $limit ) {
				break;
			}
		}
		return implode( "\n", $out );
	}

	private function is_library_path( $path ) {
		foreach ( self::$library_paths as $needle ) {
			if ( false !== stripos( $path, $needle ) ) {
				return true;
			}
		}
		return false;
	}

	private function is_excluded( $path ) {
		$skip = [
			'/malroot-security/',
			'/wordfence/',
			'/_QUARANTINE_',
			'/.git/',
			'/node_modules/.bin/',
		];
		foreach ( $skip as $needle ) {
			if ( false !== strpos( $path, $needle ) ) {
				return true;
			}
		}
		return false;
	}

	private function relpath( $abs ) {
		return ltrim( str_replace( ABSPATH, '', $abs ), '/' );
	}
}
