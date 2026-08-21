<?php
/**
 * Plugin Name:       Agent Entry
 * Plugin URI:        https://github.com/muretai/agent-entry-wordpress
 * Description:       Let AI agents talk to this site directly. Publishes a signed Agent Card and answers signed messages inline — no account, no API key, no third party in the middle.
 * Version:           0.1.0
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Author:            muretai
 * Author URI:        https://muretai.com
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       muretai-agent-entry
 *
 * WHAT THIS PLUGIN DOES, in one paragraph. It gives the site a cryptographic identity (an
 * Ed25519 key, generated here and never leaving this server) and four HTTP routes: a plain
 * Agent Card, a signed copy of that card proving the key owns this origin, and a POST door
 * that verifies an inbound signed message and answers with a signed reply in the same HTTP
 * response. An agent that has only this site's URL can therefore establish who it is
 * talking to and hold a conversation, with no platform account, no API key, and nobody in
 * between. The wire format is the same one two other implementations already speak, held
 * byte-identical by a shared set of golden vectors.
 *
 * WHAT IT DOES NOT DO. It does not bring traffic. A door makes the site REACHABLE, not
 * FINDABLE: agents still arrive the way they do today — a search result, a link, a person
 * telling them where to go.
 *
 * @package Muretai\AgentEntry
 */

namespace Muretai\AgentEntry;

if (!defined('ABSPATH')) {
    exit;
}

define('MURETAI_AGENT_ENTRY_VERSION', '0.1.0');
define('MURETAI_AGENT_ENTRY_FILE', __FILE__);

require_once __DIR__ . '/includes/class-wire.php';
require_once __DIR__ . '/includes/class-store.php';
require_once __DIR__ . '/includes/class-entry.php';
require_once __DIR__ . '/includes/class-wpdb-store.php';
require_once __DIR__ . '/includes/class-plugin.php';

/**
 * The sodium extension carries Ed25519 and has shipped with PHP since 7.2. If it is
 * missing the plugin cannot sign anything, so it says so plainly and stays inert rather
 * than half-working: a door that serves a card it cannot back with a signature is worse
 * than no door, because a visitor would fetch it, fail to verify, and learn nothing about
 * why.
 */
if (!function_exists('sodium_crypto_sign_detached')) {
    add_action('admin_notices', static function (): void {
        echo '<div class="notice notice-error"><p><strong>Agent Entry</strong> needs PHP\'s '
            . 'sodium extension for Ed25519 signatures, and it is not available on this '
            . 'server. The plugin is inactive until it is enabled.</p></div>';
    });
    return;
}

register_activation_hook(__FILE__, [Plugin::class, 'activate']);
register_deactivation_hook(__FILE__, [Plugin::class, 'deactivate']);

Plugin::boot();
