<?php
/**
 * Plugin Name:       Malroot Security
 * Plugin URI:        https://github.com/palniraj/malroot-security
 * Description:       WordPress malware scanner that inspects database, files, REST routes, MySQL triggers and mu-plugins. Removes hidden admins, backdoors and rootkits.
 * Version:           1.0.3
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            Niraj Pal
 * Author URI:        https://profiles.wordpress.org/nirajpal/
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       malroot-security
 * Domain Path:       /languages
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'MALROOT_VERSION',     '1.0.3' );
define( 'MALROOT_FILE',        __FILE__ );
define( 'MALROOT_DIR',         plugin_dir_path( __FILE__ ) );
define( 'MALROOT_URL',         plugin_dir_url( __FILE__ ) );
define( 'MALROOT_TEXTDOMAIN',  'malroot-security' );

require_once MALROOT_DIR . 'includes/class-mr-loader.php';
require_once MALROOT_DIR . 'includes/class-mr-logger.php';
require_once MALROOT_DIR . 'includes/class-mr-findings.php';
require_once MALROOT_DIR . 'includes/class-mr-quarantine.php';
require_once MALROOT_DIR . 'includes/class-mr-alerting.php';
require_once MALROOT_DIR . 'includes/class-mr-realtime.php';
require_once MALROOT_DIR . 'includes/class-mr-admin-guard.php';
require_once MALROOT_DIR . 'includes/class-mr-login-security.php';
require_once MALROOT_DIR . 'includes/class-mr-spam-shield.php';
require_once MALROOT_DIR . 'includes/class-mr-baseline.php';
require_once MALROOT_DIR . 'includes/class-mr-incident-response.php';
require_once MALROOT_DIR . 'includes/scanners/class-mr-scanner-base.php';
require_once MALROOT_DIR . 'includes/scanners/class-mr-scanner-files.php';
require_once MALROOT_DIR . 'includes/scanners/class-mr-scanner-database.php';
require_once MALROOT_DIR . 'includes/scanners/class-mr-scanner-users.php';
require_once MALROOT_DIR . 'includes/scanners/class-mr-scanner-triggers.php';
require_once MALROOT_DIR . 'includes/scanners/class-mr-scanner-rest.php';
require_once MALROOT_DIR . 'includes/scanners/class-mr-scanner-muplugins.php';
require_once MALROOT_DIR . 'includes/scanners/class-mr-scanner-botcloak.php';
require_once MALROOT_DIR . 'includes/scanners/class-mr-scanner-integrity.php';
require_once MALROOT_DIR . 'includes/class-mr-plain-language.php';
require_once MALROOT_DIR . 'includes/class-mr-verifier.php';
require_once MALROOT_DIR . 'includes/class-mr-self-integrity.php';
require_once MALROOT_DIR . 'includes/class-mr-geoip.php';
require_once MALROOT_DIR . 'includes/class-mr-totp.php';
require_once MALROOT_DIR . 'includes/class-mr-2fa.php';
require_once MALROOT_DIR . 'includes/class-mr-ajax.php';
require_once MALROOT_DIR . 'includes/admin/class-mr-admin.php';

register_activation_hook( __FILE__, [ 'Malroot_Loader', 'activate' ] );
register_deactivation_hook( __FILE__, [ 'Malroot_Loader', 'deactivate' ] );

add_action( 'plugins_loaded', [ 'Malroot_Loader', 'init' ] );
