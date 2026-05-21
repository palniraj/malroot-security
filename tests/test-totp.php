<?php
// CLI smoke test for MR_TOTP
if ( ! defined( 'ABSPATH' ) ) { define( 'ABSPATH', '/tmp/' ); }
require __DIR__ . '/../includes/class-mr-totp.php';

$secret = MR_TOTP::generate_secret();
echo "Secret: $secret\n";

$bytes = MR_TOTP::base32_decode( $secret );
$re    = MR_TOTP::base32_encode( $bytes );
echo "Encode/decode round-trip: " . ( $re === $secret ? "OK" : "FAIL ($re != $secret)" ) . "\n";

echo "URL: " . MR_TOTP::otpauth_url( $secret, 'alice@example.com', 'Acme Corp' ) . "\n";

$ref = new ReflectionClass( 'MR_TOTP' );
$m = $ref->getMethod( 'generate_code' );
$m->setAccessible( true );
$code = $m->invoke( null, $bytes, (int) floor( time() / 30 ) );
echo "Code: $code (verify=" . ( MR_TOTP::verify( $secret, $code ) ? 'OK' : 'FAIL' ) . ")\n";
echo "Wrong code: " . ( MR_TOTP::verify( $secret, '000000' ) ? 'FAIL accepted' : 'OK rejected' ) . "\n";

// Known test vector from RFC 6238 (key "12345678901234567890" base32-encoded)
$test_secret = MR_TOTP::base32_encode( '12345678901234567890' );
$counter     = (int) floor( 59 / 30 );  // T = 59 seconds
$test_code   = $m->invoke( null, '12345678901234567890', $counter );
echo "RFC 6238 test (T=59): $test_code (expected 287082)\n";
