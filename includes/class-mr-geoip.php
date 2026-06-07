<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * GeoIP lookup with aggressive caching.
 *
 * Free API (ipapi.co — no key, 1k/day per IP block, 30k/month free tier).
 * Results cached in wp_options for 30 days per IP.
 */
class Malroot_GeoIP {

	const CACHE_PREFIX = 'malroot_geo_';
	const CACHE_TTL    = 30 * DAY_IN_SECONDS;

	/**
	 * Whether the optional third-party IP geolocation lookup is enabled.
	 * Off by default — the administrator must opt in from the Settings page.
	 */
	public static function is_enabled() {
		$settings = (array) get_option( 'malroot_settings', [] );
		return ! empty( $settings['geoip_enabled'] );
	}

	/**
	 * Returns: [ 'country' => 'AU', 'country_name' => 'Australia', 'city' => 'Sydney', 'flag' => '🇦🇺' ]
	 *          or null on failure / private IP.
	 */
	public static function lookup( $ip ) {
		if ( ! $ip || self::is_private_ip( $ip ) ) {
			return null;
		}

		// Opt-in only. IP geolocation sends the IP address to a third-party
		// service (ipapi.co), so it is disabled by default and only runs when
		// the administrator explicitly turns it on in Settings.
		if ( ! self::is_enabled() ) {
			return null;
		}

		// Cached?
		$cache_key = self::CACHE_PREFIX . md5( $ip );
		$cached    = get_transient( $cache_key );
		if ( is_array( $cached ) ) {
			return $cached;
		}
		// Negative cache: don't hammer the API for IPs we already failed on
		if ( $cached === 'fail' ) {
			return null;
		}

		// API call (3 second timeout, non-blocking would be ideal but we need the result)
		$resp = wp_remote_get(
			sprintf( 'https://ipapi.co/%s/json/', rawurlencode( $ip ) ),
			[ 'timeout' => 3, 'sslverify' => true, 'headers' => [ 'User-Agent' => 'Malroot Security/' . MALROOT_VERSION ] ]
		);
		if ( is_wp_error( $resp ) || wp_remote_retrieve_response_code( $resp ) !== 200 ) {
			set_transient( $cache_key, 'fail', HOUR_IN_SECONDS );
			return null;
		}
		$body = json_decode( wp_remote_retrieve_body( $resp ), true );
		if ( ! is_array( $body ) || empty( $body['country_code'] ) ) {
			set_transient( $cache_key, 'fail', HOUR_IN_SECONDS );
			return null;
		}
		$data = [
			'country'      => $body['country_code'],
			'country_name' => $body['country_name'] ?? $body['country_code'],
			'city'         => $body['city']         ?? '',
			'region'       => $body['region']       ?? '',
			'flag'         => self::flag_emoji( $body['country_code'] ),
		];
		set_transient( $cache_key, $data, self::CACHE_TTL );
		return $data;
	}

	/**
	 * Cheap one-line label for tables: "🇦🇺 Sydney, AU"
	 */
	public static function label( $ip ) {
		if ( ! $ip ) return '';
		// Friendly label for loopback / private IPs
		if ( in_array( $ip, [ '::1', '127.0.0.1' ], true ) ) {
			return '🏠 ' . __( 'Local', 'malroot-security' );
		}
		if ( self::is_private_ip( $ip ) ) {
			return '🏢 ' . __( 'Private network', 'malroot-security' );
		}
		$g = self::lookup( $ip );
		if ( ! $g ) return '';
		$bits = [];
		if ( $g['flag'] )    $bits[] = $g['flag'];
		if ( $g['city'] )    $bits[] = $g['city'];
		if ( $g['country'] ) $bits[] = $g['country'];
		return implode( ' ', $bits );
	}

	/**
	 * RegionalIndicator emoji from ISO country code.
	 */
	private static function flag_emoji( $cc ) {
		if ( strlen( $cc ) !== 2 ) return '';
		$cc = strtoupper( $cc );
		$out = '';
		for ( $i = 0; $i < 2; $i++ ) {
			$out .= mb_chr( 127397 + ord( $cc[ $i ] ), 'UTF-8' );
		}
		return $out;
	}

	private static function is_private_ip( $ip ) {
		// Loopback, RFC1918, link-local, etc.
		return ! filter_var(
			$ip,
			FILTER_VALIDATE_IP,
			FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
		);
	}
}
