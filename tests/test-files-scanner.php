<?php
/**
 * Standalone smoke test for MR_Scanner_Files.
 * Run: php wp-content/plugins/malroot-security/tests/test-files-scanner.php
 *
 * It stubs out the WP functions the scanner uses, then walks the real
 * /var/www/html/may19 tree and prints findings to STDOUT.
 *
 * Note: this test points at the plugin's parent WordPress install. Because
 * the malicious files were quarantined earlier, the tree is now CLEAN, so
 * we expect zero critical findings under the working tree but findings
 * inside _QUARANTINE_*. We exclude that folder from the scan to mirror
 * what would happen on a production install.
 */

if ( PHP_SAPI !== 'cli' ) {
	exit( "CLI only.\n" );
}

if ( ! defined( 'ABSPATH' ) )       { define( 'ABSPATH', dirname( __DIR__, 4 ) . '/' ); }
if ( ! defined( 'WP_CONTENT_DIR' ) ){ define( 'WP_CONTENT_DIR', ABSPATH . 'wp-content' ); }

function wp_get_upload_dir() {
	return [ 'basedir' => WP_CONTENT_DIR . '/uploads' ];
}
function wp_json_encode( $x ) { return json_encode( $x ); }
function wp_parse_args( $a, $b ) { return array_merge( $b, $a ); }

class MR_Findings {
	public static $rows = [];
	public static function record( array $f ) { self::$rows[] = $f; return count( self::$rows ); }
}
class MR_Logger { public static function info() {} public static function error() {} public static function warning() {} }

require_once __DIR__ . '/../includes/scanners/class-mr-scanner-base.php';
require_once __DIR__ . '/../includes/scanners/class-mr-scanner-files.php';

$scanner = new MR_Scanner_Files();
$scanner->set_scan_id( 1 );

// Override scan paths so we walk the tree but exclude the quarantine folder
class TestFilesScanner extends MR_Scanner_Files {
	public function run() {
		$root = ABSPATH;
		$this->scan_for_signatures_filtered( $root );
		$this->scan_uploads_for_php();
		$this->scan_for_leaked_config_filtered( $root );
	}
	private function scan_for_signatures_filtered( $root ) {
		$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ) );
		foreach ( $it as $file ) {
			$path = $file->getPathname();
			if ( strpos( $path, '/_QUARANTINE_' ) !== false ) continue;
			if ( ! $file->isFile() ) continue;
			if ( ! preg_match( '/\.(php|phtml|phar)$/i', $path ) ) continue;
			if ( strpos( $path, '/malroot-security/' ) !== false ) continue;
			if ( strpos( $path, '/wordfence/' ) !== false ) continue;
			if ( strpos( $path, '/vendor/composer/installers/' ) !== false ) continue;
			if ( $file->getSize() > 5*1024*1024 ) continue;
			$content = @file_get_contents( $path );
			if ( ! $content ) continue;
			$ref = new ReflectionClass( 'MR_Scanner_Files' );
			$prop = $ref->getProperty( 'signatures' );
			$prop->setAccessible( true );
			$sigs = $prop->getValue( $this );
			foreach ( $sigs as $sig ) {
				list( $rule_id, $regex, $severity, $summary ) = $sig;
				if ( preg_match( $regex, $content, $m ) ) {
					$this->record( $rule_id, $severity, ltrim( str_replace( ABSPATH, '', $path ), '/' ), $summary, substr( $m[0], 0, 200 ) );
					break;
				}
			}
		}
	}
	private function scan_for_leaked_config_filtered( $root ) {
		$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ) );
		foreach ( $it as $file ) {
			$path = $file->getPathname();
			if ( strpos( $path, '/_QUARANTINE_' ) !== false ) continue;
			if ( ! $file->isFile() ) continue;
			$basename = basename( $path );
			foreach ( [ 'wp-config*.txt', 'wp-config*.bak', 'wp-config*.old', 'wp-config*.save' ] as $pat ) {
				if ( fnmatch( $pat, $basename ) ) {
					$this->record( 'FI-002', 'critical', ltrim( str_replace( ABSPATH, '', $path ), '/' ), 'Leaked wp-config copy', $basename );
					break;
				}
			}
		}
	}
}

( new TestFilesScanner() )->set_scan_id( 1 );
( new TestFilesScanner() )->run();

echo "==== Malroot file scanner smoke test ====\n";
echo "Scan root: " . ABSPATH . "\n";
echo "Findings : " . count( MR_Findings::$rows ) . "\n\n";
foreach ( MR_Findings::$rows as $f ) {
	printf( "[%s] %s  %s\n  → %s\n", strtoupper( $f['severity'] ), $f['rule_id'], $f['target'], $f['summary'] );
}
if ( ! MR_Findings::$rows ) {
	echo "Working tree is clean (as expected after quarantine).\n";
}
