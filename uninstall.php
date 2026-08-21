<?php
/**
 * uninstall.php — what "delete this plugin" actually deletes.
 *
 * WordPress runs this only on an explicit DELETE from the plugins screen, never on
 * deactivate. That split is the whole design:
 *
 *   deactivate  keeps everything, because the site's identity must survive being switched
 *               off and on again. Deleting the key there would silently give the site a NEW
 *               DID on reactivation, and every agent that recorded the old one would be
 *               talking to a stranger with no way to notice.
 *   uninstall   removes it, because the person asked. Leaving an Ed25519 private key and a
 *               list of every agent that ever visited in the database of a site that
 *               removed the plugin is not tidiness, it is a liability the owner did not
 *               agree to keep.
 *
 * @package Muretai\AgentEntry
 */

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

global $wpdb;

// The key first, so an interrupted uninstall never leaves the seed behind as the last
// surviving artifact.
delete_option('muretai_agent_entry_seed');
delete_option('muretai_agent_entry_card_envelope');
delete_option('muretai_agent_entry_enabled');
delete_option('muretai_agent_entry_name');
delete_option('muretai_agent_entry_description');
delete_option('muretai_agent_entry_reply');

foreach (['muretai_ledger', 'muretai_replay', 'muretai_pins'] as $table) {
    // Table names cannot be parameterised; the value is a literal from this file, not input.
    $wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->prefix . $table);
}

// The per-minute rate counters are transients, which expire on their own but are worth
// clearing so an uninstall leaves nothing at all.
$wpdb->query(
    "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_muretai\_rate\_%'"
    . " OR option_name LIKE '\_transient\_timeout\_muretai\_rate\_%'"
);

$timestamp = wp_next_scheduled('muretai_agent_entry_resign');
if ($timestamp) {
    wp_unschedule_event($timestamp, 'muretai_agent_entry_resign');
}
