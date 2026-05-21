<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * MySQL trigger / event scanner.
 *
 * WordPress core never installs triggers. Anything we find is suspect.
 * This is what catches the after_insert_comment trigger that recreated
 * the 'newsfeed' admin on every spam comment on allfirstnations.com.au.
 */
class MR_Scanner_Triggers extends MR_Scanner_Base {

	protected $module = 'triggers';

	public function run() {
		global $wpdb;

		$dbname = $wpdb->dbname;

		// Triggers
		$triggers = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT TRIGGER_NAME, EVENT_OBJECT_TABLE, ACTION_STATEMENT
				 FROM information_schema.TRIGGERS
				 WHERE TRIGGER_SCHEMA = %s",
				$dbname
			)
		);
		foreach ( (array) $triggers as $t ) {
			$action = (string) $t->ACTION_STATEMENT;
			$severity = 'high';
			$rule_id  = 'TR-001';
			$summary  = "MySQL trigger '{$t->TRIGGER_NAME}' on table {$t->EVENT_OBJECT_TABLE}";

			// Look for dangerous statements inside the trigger body.
			if ( preg_match( '/INSERT\s+INTO\s+`?[^`\s]*_users`?/i', $action ) ) {
				$severity = 'critical';
				$rule_id  = 'TR-002';
				$summary .= ' — INSERTs into users table (admin re-injection pattern)';
			}
			if ( preg_match( '/INSERT\s+INTO\s+`?[^`\s]*_usermeta`?/i', $action ) ) {
				$severity = 'critical';
				$rule_id  = 'TR-002';
				$summary .= ' — INSERTs into usermeta (capability injection pattern)';
			}
			if ( preg_match( '/(administrator|wp_capabilities|wp_user_level)/i', $action ) ) {
				$severity = 'critical';
				$rule_id  = 'TR-005';
				$summary .= ' — references admin role';
			}

			$this->record(
				$rule_id,
				$severity,
				"trigger:{$t->TRIGGER_NAME}",
				$summary,
				substr( $action, 0, 800 )
			);
		}

		// Events (the other place attackers can hide periodic SQL)
		$events = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT EVENT_NAME, EVENT_DEFINITION, STATUS
				 FROM information_schema.EVENTS
				 WHERE EVENT_SCHEMA = %s",
				$dbname
			)
		);
		foreach ( (array) $events as $e ) {
			$this->record(
				'TR-004',
				'high',
				"event:{$e->EVENT_NAME}",
				"MySQL EVENT '{$e->EVENT_NAME}' (status={$e->STATUS})",
				substr( (string) $e->EVENT_DEFINITION, 0, 800 )
			);
		}
	}
}
