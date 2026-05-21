<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * TOTP (Time-based One-Time Password) — RFC 6238.
 *
 * Pure PHP, no external dependencies. Compatible with Google Authenticator,
 * Authy, 1Password, Microsoft Authenticator, and any other RFC 6238 client.
 */
class Malroot_TOTP {

	const PERIOD = 30;     // seconds per code
	const DIGITS = 6;      // 6-digit codes
	const WINDOW = 1;      // accept codes from previous & next time-step (clock skew)

	/**
	 * Generate a fresh 80-bit base32 secret (16 chars).
	 */
	public static function generate_secret() {
		return self::base32_encode( random_bytes( 10 ) );
	}

	/**
	 * Verify a user-entered 6-digit code against the stored secret.
	 * Constant-time comparison prevents timing attacks.
	 */
	public static function verify( $secret, $code ) {
		if ( ! preg_match( '/^\d{6}$/', (string) $code ) ) {
			return false;
		}
		$key = self::base32_decode( $secret );
		if ( ! $key ) {
			return false;
		}
		$now = (int) floor( time() / self::PERIOD );
		for ( $i = -self::WINDOW; $i <= self::WINDOW; $i++ ) {
			$expected = self::generate_code( $key, $now + $i );
			if ( hash_equals( $expected, (string) $code ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Build the otpauth:// URL for QR-code display.
	 */
	public static function otpauth_url( $secret, $account, $issuer ) {
		return sprintf(
			'otpauth://totp/%s:%s?secret=%s&issuer=%s&period=%d&digits=%d&algorithm=SHA1',
			rawurlencode( $issuer ),
			rawurlencode( $account ),
			$secret,
			rawurlencode( $issuer ),
			self::PERIOD,
			self::DIGITS
		);
	}

	private static function generate_code( $key, $counter ) {
		// 8-byte big-endian counter
		$counter_bytes = pack( 'N*', 0 ) . pack( 'N*', $counter );
		$hash          = hash_hmac( 'sha1', $counter_bytes, $key, true );
		$offset        = ord( $hash[19] ) & 0x0f;
		$code = ( ( ord( $hash[ $offset ] )     & 0x7f ) << 24 )
		      | ( ( ord( $hash[ $offset + 1 ] ) & 0xff ) << 16 )
		      | ( ( ord( $hash[ $offset + 2 ] ) & 0xff ) << 8 )
		      |   ( ord( $hash[ $offset + 3 ] ) & 0xff );
		$code = $code % 1000000;
		return str_pad( (string) $code, self::DIGITS, '0', STR_PAD_LEFT );
	}

	/* ---------------------------------------------------------------- */
	/*  Base32 (RFC 4648) — Google Authenticator format                 */
	/* ---------------------------------------------------------------- */

	private static $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	public static function base32_encode( $bytes ) {
		$out = '';
		$buf = '';
		foreach ( str_split( $bytes ) as $b ) {
			$buf .= str_pad( decbin( ord( $b ) ), 8, '0', STR_PAD_LEFT );
		}
		foreach ( str_split( $buf, 5 ) as $chunk ) {
			$chunk = str_pad( $chunk, 5, '0', STR_PAD_RIGHT );
			$out  .= self::$alphabet[ bindec( $chunk ) ];
		}
		return $out;
	}

	public static function base32_decode( $str ) {
		$str = strtoupper( str_replace( ' ', '', $str ) );
		if ( ! preg_match( '/^[A-Z2-7]+=*$/', $str ) ) {
			return '';
		}
		$str = rtrim( $str, '=' );
		$buf = '';
		foreach ( str_split( $str ) as $c ) {
			$pos = strpos( self::$alphabet, $c );
			if ( $pos === false ) return '';
			$buf .= str_pad( decbin( $pos ), 5, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $buf, 8 ) as $chunk ) {
			if ( strlen( $chunk ) === 8 ) {
				$out .= chr( bindec( $chunk ) );
			}
		}
		return $out;
	}
}
