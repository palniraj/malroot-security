<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Scans wp_options, wp_posts, wp_postmeta for malware-resident payloads.
 * Catches sc_* options, wpcode-style backdoors, and known C2 strings.
 */
class Malroot_Scanner_Database extends Malroot_Scanner_Base {

	protected $module = 'database';

	private $option_signatures = [
		// rule_id, regex over option_name OR option_value, severity, summary
		[ 'DB-SC',  'name', '/^sc_(api_key|sec_key|panel_url|site_id|is_active|plugin_install_blocked|display_links)$/', 'critical', 'system-control plugin option still present in DB' ],
		[ 'DB-001', 'value', '/eval\s*\(\s*(base64_decode|gzinflate|str_rot13)/',         'critical', 'PHP eval() of decoded payload stored in option' ],
		[ 'DB-002', 'value', '/(create_function|assert\s*\(\s*\$_)/',                     'critical', 'Suspicious code execution function in option value' ],
		[ 'DB-004', 'value', '/(superfuckingpanel|hihatbar\.com|logsmetrics\.com|host-stats\.io|jforvexan|talvexoni|ak2yy)/i', 'critical', 'Known malicious C2 domain in option value' ],
		[ 'DB-006', 'value', '/wpcode_snippets.*?(eval|base64_decode|wp_create_user|set_role)/s', 'critical', 'WPCode snippet containing code-execution patterns' ],
		[ 'DB-008', 'value', '/dns\.google\/resolve.*?type=txt/',                         'critical', 'DNS exfiltration via Google DNS API' ],
	];

	public function run() {
		global $wpdb;

		// 1) Scan options
		$batch_size = 500;
		$offset     = 0;
		while ( true ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
			$rows = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT option_id, option_name, option_value FROM {$wpdb->options} ORDER BY option_id LIMIT %d OFFSET %d",
					$batch_size,
					$offset
				)
			);
			if ( ! $rows ) {
				break;
			}
			foreach ( $rows as $row ) {
				foreach ( $this->option_signatures as $sig ) {
					list( $rule_id, $field, $regex, $severity, $summary ) = $sig;
					$haystack = $field === 'name' ? $row->option_name : (string) $row->option_value;
					if ( preg_match( $regex, $haystack, $m ) ) {
						$this->record(
							$rule_id,
							$severity,
							"options:{$row->option_name}",
							$summary,
							isset( $m[0] ) ? substr( (string) $m[0], 0, 400 ) : ''
						);
						break;
					}
				}
			}
			$offset += $batch_size;
		}

		// 2) Active plugins must not include system-control
		$active = (array) get_option( 'active_plugins', [] );
		foreach ( $active as $slug ) {
			if ( false !== strpos( $slug, 'system-control' ) ) {
				$this->record(
					'DB-AP',
					'critical',
					"options:active_plugins",
					'system-control listed in active_plugins',
					$slug
				);
			}
		}

		// 3) Bot-only post markers planted by the malware
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$bot_meta = $wpdb->get_var(
			"SELECT COUNT(*) FROM {$wpdb->postmeta} WHERE meta_key IN ('_sc_bot_only','_sc_bot_type')"
		);
		if ( (int) $bot_meta > 0 ) {
			$this->record(
				'DB-BOTMETA',
				'high',
				'postmeta:_sc_bot_only',
				'system-control bot-cloak post meta still present',
				"count={$bot_meta}"
			);
		}

		// 4) Suspicious post_content patterns (limited scan to keep it fast)
		$post_signatures = [
			[ 'DB-002', '/<script[^>]*>[^<]*String\.fromCharCode\s*\(\s*60/', 'critical', 'Obfuscated <script> with fromCharCode redirect' ],
			[ 'DB-008', '/dns\.google\/resolve.*?type=txt/',                  'critical', 'DNS exfiltration JS in post content' ],
		];
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows = $wpdb->get_results( "SELECT ID, post_title, post_content FROM {$wpdb->posts} WHERE post_status IN ('publish','private','draft') AND post_type IN ('post','page') AND CHAR_LENGTH(post_content) < 200000" );
		foreach ( $rows as $row ) {
			foreach ( $post_signatures as $sig ) {
				list( $rule_id, $regex, $severity, $summary ) = $sig;
				if ( preg_match( $regex, (string) $row->post_content, $m ) ) {
					$this->record(
						$rule_id,
						$severity,
						"posts:{$row->ID}",
						$summary,
						substr( $m[0], 0, 400 )
					);
				}
			}
		}
	}
}
