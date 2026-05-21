<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * File-based scanner. Catches WSO shells, ?stream= droppers, PHP in uploads,
 * unauthenticated upload forms, hidden dot-directories with PHP, and leaked
 * wp-config copies — i.e. the file-side IoCs from the allfirstnations attack.
 */
class MR_Scanner_Files extends MR_Scanner_Base {

	protected $module = 'files';

	protected $signatures = [
		// rule_id, regex, severity, summary
		[ 'MAL-004', '/\$_GET\s*\[\s*[\'\"]stream[\'\"]\s*\].*?curl_exec/s',                'critical', 'Stream dropper backdoor: fetches arbitrary URL and eval()s response' ],
		[ 'MAL-005', '/(FilesMan|get_footer_sq|gzinflate\s*\(\s*base64_decode\s*\(\s*implode)/', 'critical', 'WSO/FilesMan webshell signature' ],
		[ 'MAL-006', '/is_uploaded_file\s*\([^)]*\$_FILES.*move_uploaded_file/s',            'critical', 'Unauthenticated file upload form' ],
		[ 'MAL-003', '/(SC_PANEL_URL|SC_PANEL_SECRET|superfuckingpanel|system-control\/v1)/', 'critical', 'system-control rogue plugin / C2 reference' ],
		[ 'MAL-008', '/(\.sc-backup|SC_Self_Protect|sc-loader)/',                            'critical', 'Self-healing mu-plugin loader pattern' ],
		[ 'MAL-EVAL','/eval\s*\(\s*(base64_decode|gzinflate|str_rot13|@?\$_(GET|POST|REQUEST|COOKIE))/', 'critical', 'eval() of decoded/encoded user input' ],
		[ 'MAL-PR-E','/preg_replace\s*\(\s*[\'\"][^\'\"]*\/e[^\'\"]*[\'\"]/',                'high',     'preg_replace with /e modifier (code execution)' ],
	];

	public function run() {
		$root = ABSPATH;

		// 1) Suspicious files anywhere
		$this->scan_for_signatures( $root );

		// 2) PHP files in uploads (always suspicious)
		$this->scan_uploads_for_php();

		// 3) Hidden dot-directories under wp-content with PHP files
		$this->scan_hidden_dirs( WP_CONTENT_DIR );

		// 4) Leaked wp-config copies anywhere
		$this->scan_for_leaked_config( $root );

		// 5) Public DB dumps
		$this->scan_for_db_dumps( WP_CONTENT_DIR );
	}

	protected function scan_for_signatures( $root ) {
		$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ) );
		foreach ( $it as $file ) {
			if ( ! $file->isFile() ) {
				continue;
			}
			$path = $file->getPathname();
			if ( ! preg_match( '/\.(php|phtml|phar)$/i', $path ) ) {
				continue;
			}
			// Skip our own plugin and Wordfence's signature DB.
			if ( $this->is_excluded_path( $path ) ) {
				continue;
			}
			if ( $file->getSize() > 5 * 1024 * 1024 ) {
				continue; // skip huge files
			}
			$content = @file_get_contents( $path );
			if ( ! $content ) {
				continue;
			}
			foreach ( $this->signatures as $sig ) {
				list( $rule_id, $regex, $severity, $summary ) = $sig;
				if ( preg_match( $regex, $content, $m ) ) {
					$snippet = isset( $m[0] ) ? substr( $m[0], 0, 400 ) : '';
					$this->record( $rule_id, $severity, $this->relpath( $path ), $summary, $snippet );
					break; // one finding per file is enough
				}
			}
		}
	}

	protected function scan_uploads_for_php() {
		$uploads = wp_get_upload_dir();
		$base    = $uploads['basedir'] ?? WP_CONTENT_DIR . '/uploads';
		if ( ! is_dir( $base ) ) {
			return;
		}
		$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $base, FilesystemIterator::SKIP_DOTS ) );
		foreach ( $it as $file ) {
			if ( ! $file->isFile() ) {
				continue;
			}
			$path = $file->getPathname();
			if ( $this->is_excluded_path( $path ) ) {
				continue;
			}
			if ( ! preg_match( '/\.(php|phtml|phar)$/i', $path ) ) {
				continue;
			}
			$size     = $file->getSize();
			$basename = basename( $path );
			// "Silence is golden" plugin index.php files are tiny and safe.
			if ( $basename === 'index.php' && $size < 200 ) {
				continue;
			}
			$severity = $size === 0 ? 'high' : 'critical';
			$summary  = $size === 0
				? 'Zero-byte PHP file in uploads — backdoor remnant'
				: 'PHP file in uploads — should never exist';
			$this->record( 'FI-001', $severity, $this->relpath( $path ), $summary, 'size=' . $size );
		}
	}

	protected function scan_hidden_dirs( $root ) {
		$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ) );
		foreach ( $it as $file ) {
			if ( ! $file->isDir() ) {
				continue;
			}
			$path = $file->getPathname();
			if ( $this->is_excluded_path( $path ) ) {
				continue;
			}
			$name = basename( $path );
			if ( $name[0] !== '.' || $name === '.' || $name === '..' ) {
				continue;
			}
			// Ignore well-known dot directories.
			if ( in_array( $name, [ '.git', '.svn', '.hg', '.well-known', '.cache' ], true ) ) {
				continue;
			}
			// Look inside for PHP.
			$inner = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $path, FilesystemIterator::SKIP_DOTS ) );
			foreach ( $inner as $f ) {
				if ( $f->isFile() && preg_match( '/\.php$/i', $f->getPathname() ) ) {
					$this->record(
						'SH-008',
						'critical',
						$this->relpath( $path ),
						'Hidden directory under wp-content contains PHP files',
						'first php: ' . $this->relpath( $f->getPathname() )
					);
					break;
				}
			}
		}
	}

	protected function scan_for_leaked_config( $root ) {
		$patterns = [ 'wp-config*.txt', 'wp-config*.bak', 'wp-config*.old', 'wp-config*.save', 'wp-config*.orig', 'wp-config*.swp' ];
		$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ) );
		foreach ( $it as $file ) {
			if ( ! $file->isFile() ) {
				continue;
			}
			if ( $this->is_excluded_path( $file->getPathname() ) ) {
				continue;
			}
			$basename = basename( $file->getPathname() );
			foreach ( $patterns as $pattern ) {
				if ( fnmatch( $pattern, $basename ) ) {
					$this->record(
						'FI-002',
						'critical',
						$this->relpath( $file->getPathname() ),
						'Leaked wp-config copy is web-accessible',
						'basename=' . $basename
					);
					break;
				}
			}
		}
	}

	protected function scan_for_db_dumps( $root ) {
		$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ) );
		foreach ( $it as $file ) {
			if ( ! $file->isFile() ) {
				continue;
			}
			$path = $file->getPathname();
			if ( $this->is_excluded_path( $path ) ) {
				continue;
			}
			if ( preg_match( '/\.(sql|sql\.gz|sql\.bz2)$/i', $path ) ) {
				$this->record(
					'FI-003',
					'critical',
					$this->relpath( $path ),
					'SQL dump file inside web-accessible directory',
					'size=' . $file->getSize()
				);
			}
		}
	}

	protected function relpath( $abs ) {
		return ltrim( str_replace( ABSPATH, '', $abs ), '/' );
	}

	/**
	 * Skip paths that are known-safe or are forensic copies the operator
	 * already moved out of the live tree (e.g. our own _QUARANTINE_* folders).
	 */
	protected function is_excluded_path( $path ) {
		$excluded_substrings = [
			'/malroot-security/',
			'/wordfence/',
			'/vendor/composer/installers/',
			'/_QUARANTINE_',          // forensic quarantine
			'/_DEPLOY-PACKAGE/',      // deploy staging
			'/.sc-backup',            // already-known backup of malware
		];
		foreach ( $excluded_substrings as $needle ) {
			if ( strpos( $path, $needle ) !== false ) {
				return true;
			}
		}
		return false;
	}
}
