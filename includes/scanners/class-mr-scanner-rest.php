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
		'my-jetpack/',            // Jetpack "My Jetpack" dashboard
		'jetpack-boost/',
		'jetpack-mu-wpcom/',
		'wpcom/',                 // Jetpack / WordPress.com connection
		'akismet/',
		'yoast/',
		'wordfence/',
		'google-site-kit/',
		'litespeed/',             // LiteSpeed Cache
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

			// Can we attribute this namespace to a plugin the operator actually
			// has installed and active? If so it is almost certainly a legitimate
			// integration (ShipStation, Pinterest, PayPal, Klaviyo, LiteSpeed …),
			// not an injected backdoor. Treat it as informational rather than
			// crying "unrecognised plugin" about the site's own software.
			$owner = $this->attributable_plugin( $ns );
			if ( ! $owner ) {
				// Token matching only works when the namespace resembles the
				// plugin slug. Plenty of plugins use an unrelated internal
				// prefix — wp-social registers 'wslu/v1' — so fall back to
				// asking the route itself which file declared its callback.
				$owner = $this->attributable_plugin_by_code( $routes, $ns_routes );
			}
			if ( $owner ) {
				// Only worth surfacing at all if it exposes sensitive endpoints,
				// and even then as a low-priority "review", never a critical.
				if ( $dangerous ) {
					$this->record(
						'RT-007',
						'low',
						"rest:{$ns}",
						sprintf(
							"REST namespace '%s' (registered by installed plugin '%s') exposes sensitive endpoints: %s",
							$ns,
							$owner,
							implode( ', ', array_unique( $dangerous ) )
						),
						wp_json_encode( $ns_routes )
					);
				}
				continue;
			}

			// Not attributable to any installed plugin — this is the case the
			// scanner exists for (e.g. the injected system-control/v1 namespace).
			$severity = 'medium';
			$summary  = "Non-standard REST namespace '{$ns}' is registered and does not match any installed plugin";
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

	/**
	 * Distinctive slugs of every active plugin (single-site + network).
	 * Cached per request.
	 */
	private $active_slugs_cache = null;
	private function active_plugin_slugs() {
		if ( null !== $this->active_slugs_cache ) {
			return $this->active_slugs_cache;
		}
		$files = (array) get_option( 'active_plugins', [] );
		if ( is_multisite() ) {
			$files = array_merge( $files, array_keys( (array) get_site_option( 'active_sitewide_plugins', [] ) ) );
		}
		$slugs = [];
		foreach ( $files as $file ) {
			$dir = dirname( (string) $file );
			$slug = ( $dir && '.' !== $dir ) ? $dir : basename( (string) $file, '.php' );
			$slugs[] = strtolower( $slug );
		}
		$this->active_slugs_cache = array_values( array_unique( array_filter( $slugs ) ) );
		return $this->active_slugs_cache;
	}

	/** Split a slug/namespace into meaningful tokens (>= 3 chars). */
	private function tokenize( $s ) {
		$parts = preg_split( '/[-_\/]+/', strtolower( trim( (string) $s ) ) );
		return array_values( array_filter( (array) $parts, static function ( $t ) {
			return strlen( $t ) >= 3;
		} ) );
	}

	/**
	 * If the namespace can be matched to an active plugin, return that plugin's
	 * slug; otherwise ''. Matching is by shared distinctive token, so e.g.
	 * 'my-jetpack/' → 'jetpack', 'litespeed/' → 'litespeed-cache',
	 * 'wc-shipstation/' → 'woocommerce-shipstation-integration',
	 * 'paypal/' → 'woocommerce-paypal-payments'. An injected namespace like
	 * 'system-control/' shares no token with any installed plugin, so it is
	 * still reported.
	 */
	private function attributable_plugin( $ns ) {
		$root      = strtolower( rtrim( $ns, '/' ) );
		$ns_tokens = $this->tokenize( $root );
		// 'wc' is WooCommerce's shorthand prefix (wc/, wc-admin/, wc-analytics/,
		// wc-push-notifications/ …). It's only two letters, so tokenizing drops
		// it — map the prefix to the 'woocommerce' token explicitly.
		if ( 'wc' === $root || 0 === strpos( $root, 'wc-' ) || 0 === strpos( $root, 'wc/' ) ) {
			$ns_tokens[] = 'woocommerce';
		}
		if ( empty( $ns_tokens ) ) {
			return '';
		}
		foreach ( $this->active_plugin_slugs() as $slug ) {
			$slug_tokens = $this->tokenize( $slug );
			if ( array_intersect( $ns_tokens, $slug_tokens ) ) {
				return $slug;
			}
		}
		return '';
	}

	/**
	 * Resolve a namespace to its owning plugin by reflecting on the registered
	 * route callbacks and asking PHP which file declared them.
	 *
	 * This is authoritative where token matching is only a guess: it is how we
	 * establish that 'wslu/' belongs to wp-social rather than to an attacker.
	 *
	 * The owning plugin must also be ACTIVE. A namespace whose callback lives
	 * somewhere unexpected — an inactive directory, mu-plugins, or the uploads
	 * folder — stays reported rather than being silently trusted.
	 *
	 * @return string Active plugin slug, or '' if it cannot be established.
	 */
	private function attributable_plugin_by_code( array $all_routes, array $ns_routes ) {
		$active = $this->active_plugin_slugs();

		foreach ( $ns_routes as $route ) {
			if ( empty( $all_routes[ $route ] ) || ! is_array( $all_routes[ $route ] ) ) {
				continue;
			}
			foreach ( $all_routes[ $route ] as $handler ) {
				if ( ! is_array( $handler ) ) {
					continue;
				}
				foreach ( [ 'callback', 'permission_callback' ] as $key ) {
					if ( empty( $handler[ $key ] ) ) {
						continue;
					}
					$file = $this->callback_file( $handler[ $key ] );
					if ( '' === $file ) {
						continue;
					}
					$slug = $this->plugin_slug_for_file( $file );
					if ( '' !== $slug && in_array( $slug, $active, true ) ) {
						return $slug;
					}
				}
			}
		}
		return '';
	}

	/** Absolute path of the file that declared a callable, or ''. */
	private function callback_file( $cb ) {
		try {
			if ( $cb instanceof Closure ) {
				$r = new ReflectionFunction( $cb );
			} elseif ( is_array( $cb ) && 2 === count( $cb ) ) {
				$class = is_object( $cb[0] ) ? get_class( $cb[0] ) : (string) $cb[0];
				if ( ! is_string( $cb[1] ) || ! class_exists( $class ) ) {
					return '';
				}
				$r = new ReflectionMethod( $class, $cb[1] );
			} elseif ( is_string( $cb ) && false !== strpos( $cb, '::' ) ) {
				$r = new ReflectionMethod( $cb );
			} elseif ( is_string( $cb ) && function_exists( $cb ) ) {
				$r = new ReflectionFunction( $cb );
			} elseif ( is_object( $cb ) && method_exists( $cb, '__invoke' ) ) {
				$r = new ReflectionMethod( $cb, '__invoke' );
			} else {
				return '';
			}
			$file = $r->getFileName();
			return $file ? (string) $file : '';
		} catch ( Throwable $e ) {
			return '';
		}
	}

	/** Map an absolute file path to the plugin directory slug that contains it. */
	private function plugin_slug_for_file( $file ) {
		$file    = wp_normalize_path( $file );
		$plugins = trailingslashit( wp_normalize_path( WP_PLUGIN_DIR ) );
		if ( 0 !== strpos( $file, $plugins ) ) {
			return '';
		}
		$slug = strtok( substr( $file, strlen( $plugins ) ), '/' );
		return $slug ? strtolower( $slug ) : '';
	}
}
