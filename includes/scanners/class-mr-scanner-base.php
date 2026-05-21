<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

abstract class Malroot_Scanner_Base {

	protected $scan_id = 0;
	protected $module  = 'base';

	public function set_scan_id( $scan_id ) {
		$this->scan_id = (int) $scan_id;
	}

	abstract public function run();

	protected function record( $rule_id, $severity, $target, $summary, $details = '' ) {
		Malroot_Findings::record( [
			'scan_id'  => $this->scan_id,
			'module'   => $this->module,
			'rule_id'  => $rule_id,
			'severity' => $severity,
			'target'   => is_string( $target ) ? $target : wp_json_encode( $target ),
			'summary'  => $summary,
			'details'  => is_string( $details ) ? $details : wp_json_encode( $details ),
		] );
	}
}
