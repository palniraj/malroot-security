<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Audits the REST API namespace registry. Flags non-allowlisted namespaces
 * with dangerous capabilities (user CRUD, file upload, db query).
 *
 * This is what catches the system-control/v1 namespace that the rogue
 * plugin used to expose full RCE on allfirstnations.com.au.
 */
class Malroot_Scanner_REST extends Malroot_Scanner_Base {

	protected $module = 'rest';

	private $known_safe_prefixes = [
		// WordPress core
		'wp/',
		'oembed/',
		'wp-block-editor/',
		'wp-site-health/',
		'wp-abilities/',         // WP 6.6+
		'batch/',                // WP core batch processing
		'root/',                 // WP core root REST namespace
		'/',                     // WP core REST root
		// WooCommerce
		'wc/',
		'wc-admin/',
		'wc-admin-email/',
		'wc-analytics/',
		'wc-blocks/',
		'wc-stripe/',
		'wc-telemetry/',
		'wccom-site/',           // WooCommerce.com connect
		'payments/',             // WooCommerce Payments
		// Themes
		'astra-sites/',
		'astra/',
		// Other common plugins
		'jetpack/',
		'akismet/',
		'yoast/',
		'wordfence/',
		'google-site-kit/',
		'mailchimp/',
		'mailchimp-for-wc/',
		'mailchimp-for-woocommerce/', // official "Mailchimp for WooCommerce" plugin slug (namespace mailchimp-for-woocommerce/v1)
		'mailpoet/',
		'contact-form-7/',
		'wpforms/',
		'elementor/',
		'pdf-embedder/',
		// Ourselves
		'malroot/',
	];

	public function run() {
		// REST routes are populated on rest_api_init; trigger it if needed.
		if ( ! did_action( 'rest_api_init' ) ) {
			rest_get_server();
		}

		$server = rest_get_server();
		if ( ! $server ) {
			return;
		}

		$routes = $server->get_routes();
		$by_namespace = [];
		foreach ( $routes as $route => $handlers ) {
			$ns = ltrim( $route, '/' );
			$ns = preg_replace( '#/.*$#', '', $ns ) . '/';
			$by_namespace[ $ns ][] = $route;
		}

		foreach ( $by_namespace as $ns => $ns_routes ) {
			if ( $this->is_safe_prefix( $ns ) ) {
				continue;
			}
			$severity = 'medium';
			$summary  = "Non-standard REST namespace '{$ns}' is registered";
			$dangerous = [];
			foreach ( $ns_routes as $r ) {
				$lc = strtolower( $r );
				if ( strpos( $lc, 'user' ) !== false )    { $dangerous[] = 'users'; }
				if ( strpos( $lc, 'file' ) !== false )    { $dangerous[] = 'files'; }
				if ( strpos( $lc, 'plugin' ) !== false )  { $dangerous[] = 'plugins'; }
				if ( strpos( $lc, 'theme' ) !== false )   { $dangerous[] = 'themes'; }
				if ( strpos( $lc, 'database' ) !== false ){ $dangerous[] = 'database'; }
				if ( strpos( $lc, 'update' ) !== false )  { $dangerous[] = 'update'; }
				if ( strpos( $lc, 'sync' ) !== false )    { $dangerous[] = 'sync'; }
				if ( strpos( $lc, 'execute' ) !== false ) { $dangerous[] = 'execute'; }
			}
			if ( $dangerous ) {
				$severity = 'critical';
				$summary .= ' with dangerous endpoints: ' . implode( ', ', array_unique( $dangerous ) );
			}
			$this->record(
				$dangerous ? 'RT-001' : 'RT-006',
				$severity,
				"rest:{$ns}",
				$summary,
				wp_json_encode( $ns_routes )
			);
		}
	}

	private function is_safe_prefix( $ns ) {
		foreach ( $this->known_safe_prefixes as $prefix ) {
			if ( strpos( $ns, $prefix ) === 0 ) {
				return true;
			}
		}
		return false;
	}
}
