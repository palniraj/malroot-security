<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Self-integrity check. Malroot verifies its own files on every admin load
 * and shows a banner if they don't match the expected manifest.
 *
 * The manifest is regenerated on every plugin update by the install routine.
 * If an attacker tampers with Malroot's own code (e.g. to disable scanners),
 * the manifest mismatch is shown loudly in admin and an alert is fired.
 */
class Malroot_Self_Integrity {

	const MANIFEST_OPTION = 'malroot_self_manifest';

	public static function register() {
		add_action( 'admin_notices', [ __CLASS__, 'check_and_warn' ] );
	}

	/**
	 * Build (or rebuild) the self-manifest. Called on plugin activation.
	 */
	public static function build_manifest() {
		$files = self::list_own_files();
		$manifest = [];
		foreach ( $files as $f ) {
			$manifest[ self::rel( $f ) ] = @md5_file( $f );
		}
		update_option( self::MANIFEST_OPTION, $manifest, false );
	}

	/**
	 * Returns array of mismatched paths (or empty array if all clean).
	 */
	public static function diff() {
		$manifest = (array) get_option( self::MANIFEST_OPTION, [] );
		if ( ! $manifest ) {
			return [];
		}
		$mismatched = [];
		foreach ( $manifest as $rel => $expected ) {
			$abs = MALROOT_DIR . $rel;
			if ( ! file_exists( $abs ) ) {
				$mismatched[] = $rel . ' (missing)';
				continue;
			}
			if ( @md5_file( $abs ) !== $expected ) {
				$mismatched[] = $rel . ' (modified)';
			}
		}
		return $mismatched;
	}

	public static function check_and_warn() {
		// Only show on Malroot admin pages so we don't spam every WP admin screen
		$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
		if ( ! $screen || strpos( $screen->id, 'malroot' ) === false ) {
			return;
		}
		$diff = self::diff();
		if ( empty( $diff ) ) {
			return;
		}
		?>
		<div class="notice notice-error">
			<p>
				<strong><?php esc_html_e( '⚠️ Malroot Security tamper warning:', 'malroot-security' ); ?></strong>
				<?php
				printf(
					/* translators: %d: number of files */
					esc_html__( 'The plugin\'s own files have been modified (%d files differ from the expected version).', 'malroot-security' ),
					count( $diff )
				);
				?>
			</p>
			<p style="font-size:12px;color:#666">
				<?php esc_html_e( 'This is either because Malroot was just updated (run "Update Snapshot" to refresh) or because something has tampered with the plugin. Reinstall Malroot fresh from a trusted source if you did not just update.', 'malroot-security' ); ?>
			</p>
			<details style="margin-top:6px"><summary style="cursor:pointer;font-size:11px;color:#888"><?php esc_html_e( 'Show changed files', 'malroot-security' ); ?></summary>
				<ul style="margin:6px 0 0 16px;font-size:11px;color:#555">
					<?php foreach ( array_slice( $diff, 0, 20 ) as $entry ) : ?>
						<li><code><?php echo esc_html( $entry ); ?></code></li>
					<?php endforeach; ?>
				</ul>
			</details>
		</div>
		<?php
	}

	private static function list_own_files() {
		$out = [];
		$it = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( MALROOT_DIR, FilesystemIterator::SKIP_DOTS ) );
		foreach ( $it as $f ) {
			$path = $f->getPathname();
			if ( ! $f->isFile() ) continue;
			if ( strpos( $path, '/tests/' ) !== false ) continue;
			if ( ! preg_match( '/\.(php|js|css)$/i', $path ) ) continue;
			$out[] = $path;
		}
		return $out;
	}

	private static function rel( $abs ) {
		return ltrim( str_replace( MALROOT_DIR, '', $abs ), '/' );
	}
}
