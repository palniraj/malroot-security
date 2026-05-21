<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

class MR_Logger {

	public static function info( $message, $context = [] ) {
		self::write( 'INFO', $message, $context );
	}

	public static function warning( $message, $context = [] ) {
		self::write( 'WARN', $message, $context );
	}

	public static function error( $message, $context = [] ) {
		self::write( 'ERROR', $message, $context );
	}

	private static function write( $level, $message, $context ) {
		if ( ! defined( 'WP_DEBUG_LOG' ) || ! WP_DEBUG_LOG ) {
			return;
		}
		$line = sprintf(
			'[Malroot %s] %s %s',
			$level,
			$message,
			$context ? wp_json_encode( $context ) : ''
		);
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		error_log( $line );
	}
}
