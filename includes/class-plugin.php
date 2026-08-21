<?php
/**
 * Plugin.php — the WordPress half: routing, key custody, re-signing, signposts, admin.
 *
 * ROUTING, and why it is not a rewrite rule. The three card paths live under
 * `/.well-known/`, and the door is a POST to the site's own front page. Rewrite rules can
 * be made to cover the first, but they are fragile in exactly the situations a plugin
 * cannot control: permalinks set to "Plain", another plugin flushing rules, a host with
 * its own `.well-known` handling. So the door is hooked at `plugins_loaded` — the earliest
 * point at which `$wpdb` exists — and answers from `$_SERVER['REQUEST_URI']` directly. A
 * request we do not own is left completely alone: no output, no side effect, WordPress
 * proceeds exactly as it would with this plugin deactivated.
 *
 * KEY CUSTODY. The seed is generated on activation and lives on the merchant's own server,
 * because the alternative — a plugin author holding a key for every site that installs it
 * — makes that author the custodian for all of them. It is read from a `wp-config.php`
 * constant if one is defined (the recommended home: outside the database, outside a
 * database dump) and otherwise from a non-autoloaded option. It is never printed, never
 * logged, and never sent anywhere.
 *
 * THE 6-HOUR CLOCK. A visitor rejects a signed card envelope older than six hours, so
 * WP-Cron re-mints it hourly. This is the mechanical reason a static file cannot be an
 * Agent Entry: the bytes expire and something holding the key has to replace them.
 *
 * @package Muretai\AgentEntry
 */

namespace Muretai\AgentEntry;

if (!defined('ABSPATH')) {
    exit;
}

require_once __DIR__ . '/class-wire.php';
require_once __DIR__ . '/class-entry.php';
require_once __DIR__ . '/class-wpdb-store.php';

final class Plugin
{
    public const OPT_SEED = 'muretai_agent_entry_seed';
    public const OPT_NAME = 'muretai_agent_entry_name';
    public const OPT_DESCRIPTION = 'muretai_agent_entry_description';
    public const OPT_ENABLED = 'muretai_agent_entry_enabled';
    public const OPT_REPLY = 'muretai_agent_entry_reply';
    public const CRON_HOOK = 'muretai_agent_entry_resign';

    /** @var Plugin|null */
    private static $instance = null;

    /** @var Entry|null built lazily; null when the plugin has no usable key */
    private $entry = null;

    /** @var WpdbStore|null */
    private $store = null;

    public static function boot(): Plugin
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct()
    {
        // `init`, not `plugins_loaded`. Answering as early as possible is tempting — and
        // it was the first thing tried — but `plugins_loaded` is too early to ASK OTHER
        // PLUGINS ANYTHING. WooCommerce's class exists by then, so the card correctly
        // advertised a catalogue skill, while `wc_get_products()` quietly returned nothing
        // because its data stores are not registered until WooCommerce's own `init`. The
        // door therefore answered "a human will read it" to a perfectly good shopping
        // question, and every layer looked healthy.
        //
        // `init` is still long before any output (`template_redirect` and rendering come
        // later), so nothing is lost but a few microseconds on requests we do not own —
        // and those still return on the first line of maybeAnswer().
        add_action('init', [$this, 'maybeAnswer'], 20);
        add_action('send_headers', [$this, 'sendLinkHeader']);
        add_action('wp_head', [$this, 'printLinkTag']);
        add_action(self::CRON_HOOK, [$this, 'cronResign']);
        add_action('admin_menu', [$this, 'adminMenu']);
        add_action('admin_init', [$this, 'registerSettings']);
    }

    // ---------------------------------------------------------------- lifecycle

    public static function activate(): void
    {
        WpdbStore::install();
        if (self::readSeed() === null) {
            // A fresh key, generated here and kept here. No network call, no registration,
            // nothing to accept: the DID this produces IS the site's identity from the
            // moment it exists.
            update_option(self::OPT_SEED, bin2hex(Wire::newSeed()), false);
        }
        if (get_option(self::OPT_ENABLED, null) === null) {
            update_option(self::OPT_ENABLED, '1', true);
        }
        if (!wp_next_scheduled(self::CRON_HOOK)) {
            wp_schedule_event(time() + 60, 'hourly', self::CRON_HOOK);
        }
    }

    public static function deactivate(): void
    {
        $ts = wp_next_scheduled(self::CRON_HOOK);
        if ($ts) {
            wp_unschedule_event($ts, self::CRON_HOOK);
        }
        // The seed and the ledger deliberately SURVIVE deactivation. Deleting the key would
        // silently change the site's identity on the next activation, and every peer that
        // recorded the old DID would be talking to a stranger. Uninstall removes them, on
        // an explicit request.
    }

    /**
     * The seed, in raw bytes, or null when there is none.
     *
     * A `MURETAI_AGENT_ENTRY_SEED` constant in wp-config.php wins over the option, and is
     * the recommended home: it keeps the key out of the database and therefore out of
     * every database dump, staging clone and backup that gets copied around.
     */
    public static function readSeed(): ?string
    {
        $hex = null;
        if (defined('MURETAI_AGENT_ENTRY_SEED') && is_string(MURETAI_AGENT_ENTRY_SEED)) {
            $hex = MURETAI_AGENT_ENTRY_SEED;
        } else {
            $opt = get_option(self::OPT_SEED, '');
            if (is_string($opt) && $opt !== '') {
                $hex = $opt;
            }
        }
        if (!is_string($hex) || !preg_match('/^[0-9a-fA-F]{64}$/', trim($hex))) {
            return null;
        }
        $raw = hex2bin(strtolower(trim($hex)));
        return $raw === false ? null : $raw;
    }

    // ---------------------------------------------------------------- the entry

    private function store(): WpdbStore
    {
        if ($this->store === null) {
            $this->store = new WpdbStore();
        }
        return $this->store;
    }

    /** The configured Entry, or null when disabled or unkeyed. */
    public function entry(): ?Entry
    {
        if ($this->entry !== null) {
            return $this->entry;
        }
        if (get_option(self::OPT_ENABLED, '1') !== '1') {
            return null;
        }
        $seed = self::readSeed();
        if ($seed === null) {
            return null;
        }
        $this->entry = new Entry($seed, self::siteBaseUrl(), [
            'name' => (string) get_option(self::OPT_NAME, get_bloginfo('name')),
            'description' => (string) get_option(self::OPT_DESCRIPTION, get_bloginfo('description')),
            'store' => $this->store(),
            'responder' => [$this, 'respond'],
            // A skill is a PROMISE. WooCommerce::skills() returns none when WooCommerce is
            // inactive, so the card never advertises a catalogue the door cannot search.
            'skills' => WooCommerce::skills(),
        ]);
        return $this->entry;
    }

    /**
     * The URL a visitor dials. It must be the PUBLIC address, because the card names it and
     * a visitor refuses a card that names anything else — behind a proxy or a CDN a wrong
     * value here fails every verification with a message about ownership.
     */
    public static function siteBaseUrl(): string
    {
        return rtrim(home_url('/'), '/');
    }

    /**
     * What the site says back. The default is a plain acknowledgement, editable in admin.
     *
     * The reply is deliberately NOT a model call: a plugin that reached for an LLM on every
     * inbound message would hand a stranger the site's API bill. Sites that want a
     * generated answer filter `muretai_agent_entry_reply` and take that decision
     * explicitly.
     *
     * @param array $env the VERIFIED envelope: peer_did, text, context_id, account, ...
     */
    public function respond(array $env): string
    {
        $default = (string) get_option(self::OPT_REPLY, '');
        if ($default === '') {
            $default = 'Thanks for your message. It reached '
                . get_bloginfo('name') . ' and a human will read it.';
        }
        // The catalogue answers first when it can, and returns null when the question was
        // not a shopping question — answering "no products matched" to "what are your
        // opening hours?" is worse than not answering at all.
        $catalogue = WooCommerce::answer($env);
        if (is_string($catalogue) && $catalogue !== '') {
            $default = $catalogue;
        }
        /**
         * Filter the reply this site sends an agent.
         *
         * @param string $reply the text that will be SIGNED and returned.
         * @param array  $env   the verified inbound envelope.
         */
        return (string) apply_filters('muretai_agent_entry_reply', $default, $env);
    }

    // ---------------------------------------------------------------- routing

    /**
     * Answer if this request is ours; otherwise return and let WordPress carry on.
     */
    public function maybeAnswer(): void
    {
        if (php_sapi_name() === 'cli') {
            return;
        }
        $entry = $this->entry();
        if ($entry === null) {
            return;
        }
        $method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
        $uri = $_SERVER['REQUEST_URI'] ?? '/';
        $path = parse_url($uri, PHP_URL_PATH);
        if (!is_string($path)) {
            return;
        }
        // A GET on the door is the SITE's front page, not ours — the method split is the
        // whole reason the site keeps its home page while the door lives at the same URI.
        if (!$entry->owns($path)) {
            return;
        }
        if (($method === 'GET' || $method === 'HEAD') && $path === self::doorPathOf($entry)) {
            return;
        }

        $body = '';
        if ($method === 'POST') {
            $body = (string) file_get_contents('php://input');
        }
        $headers = [];
        foreach ($_SERVER as $k => $v) {
            if (strncmp($k, 'HTTP_', 5) === 0) {
                $headers[strtolower(str_replace('_', '-', substr($k, 5)))] = (string) $v;
            }
        }
        // CONTENT_TYPE AND CONTENT_LENGTH ARE NOT PREFIXED. PHP (following CGI) puts them in
        // $_SERVER WITHOUT the `HTTP_` prefix, so the loop above — which is the obvious way
        // to write this — silently drops the one header the door uses to tell an agent
        // message apart from the site's own form POSTs. Missing them meant the door fell
        // through on EVERY request and answered nobody, while every unit test passed because
        // those call handle() with headers already assembled. Found by running a live check
        // against a real install, which is the only place this is visible.
        foreach (['CONTENT_TYPE' => 'content-type', 'CONTENT_LENGTH' => 'content-length'] as $k => $name) {
            if (isset($_SERVER[$k]) && $_SERVER[$k] !== '') {
                $headers[$name] = (string) $_SERVER[$k];
            }
        }

        // The query string rides along so the door can refuse to claim WordPress's own
        // query-multiplexed routes (`?wc-api=`, `?wc-ajax=`, `?rest_route=`) — see the
        // query gate in Entry::route().
        $query = parse_url($uri, PHP_URL_QUERY);
        [$status, $respHeaders, $respBody] = $entry->handle($method, $path, $headers, $body,
            is_string($query) ? $query : '');
        if ($status === 404 && $respBody === '') {
            return;                       // not ours after all: leave the request alone
        }

        status_header($status);
        foreach ($respHeaders as $name => $value) {
            header($name . ': ' . $value);
        }
        // nocache_headers() would add its own Cache-Control and contradict ours.
        echo $respBody;
        exit;
    }

    private static function doorPathOf(Entry $entry): string
    {
        $mount = $entry->mount();
        return $mount === '' ? '/' : $mount;
    }

    // ---------------------------------------------------------------- signposts

    /**
     * The `Link` header, on every page the site serves.
     *
     * Header and HTML tag both exist because each is blind where the other sees: a client
     * that only issues HEAD never parses HTML, and a client that renders a page may never
     * look at the headers. Shipping one is a coin flip on which kind of caller arrived.
     */
    public function sendLinkHeader(): void
    {
        $entry = $this->entry();
        if ($entry === null || headers_sent()) {
            return;
        }
        header('Link: ' . $entry->linkHeaderValue(), false);
    }

    public function printLinkTag(): void
    {
        $entry = $this->entry();
        if ($entry === null) {
            return;
        }
        printf(
            '<link rel="%s" href="%s" />' . "\n",
            esc_attr(Entry::LINK_REL),
            esc_url(home_url('/.well-known/agent-card.json'))
        );
    }

    // ---------------------------------------------------------------- cron

    /**
     * Re-mint the signed card envelope, hourly.
     *
     * A visitor rejects an envelope older than six hours, so an hourly job leaves five
     * hours of slack for a site whose cron is irregular — and WP-Cron IS irregular: it
     * only runs when someone visits. A site with no traffic for six hours would serve a
     * stale envelope, which is why the admin screen shows the envelope's age rather than
     * assuming the job ran.
     */
    public function cronResign(): void
    {
        $entry = $this->entry();
        if ($entry === null) {
            return;
        }
        $entry->remintCardEnvelope();
        $this->store()->sweepReplay();
    }

    // ---------------------------------------------------------------- admin

    public function adminMenu(): void
    {
        add_options_page(
            'Agent Entry',
            'Agent Entry',
            'manage_options',
            'muretai-agent-entry',
            [$this, 'renderAdmin']
        );
    }

    public function registerSettings(): void
    {
        register_setting('muretai_agent_entry', self::OPT_ENABLED);
        register_setting('muretai_agent_entry', self::OPT_NAME);
        register_setting('muretai_agent_entry', self::OPT_DESCRIPTION);
        register_setting('muretai_agent_entry', self::OPT_REPLY);

        // THE PLAIN CARD AND THE SIGNED CARD MUST AGREE, ALWAYS.
        //
        // The plain card is built fresh on every request while the signed envelope is
        // cached for an hour, so renaming the site in this screen would leave a visitor
        // fetching a new name and a signature over the old one — the two documents
        // disagreeing for up to an hour, which reads exactly like tampering. Anything that
        // changes the card's CONTENT therefore drops the cached envelope, and the next
        // request re-mints it.
        foreach ([self::OPT_NAME, self::OPT_DESCRIPTION] as $opt) {
            add_action("update_option_{$opt}", [$this, 'invalidateCardEnvelope'], 10, 0);
        }
    }

    /** Drop the cached signed card so the next request re-mints it over the new content. */
    public function invalidateCardEnvelope(): void
    {
        delete_option('muretai_agent_entry_card_envelope');
        $this->entry = null;
    }

    /**
     * The admin screen answers three questions a site owner actually has: what is my
     * address, is the door really answering, and is anything else fighting me for the
     * card path.
     */
    public function renderAdmin(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }
        $entry = $this->entry();
        $cardUrl = home_url('/.well-known/agent-card.json');
        echo '<div class="wrap"><h1>Agent Entry</h1>';

        if ($entry === null) {
            echo '<div class="notice notice-error"><p>';
            echo 'This site has no usable key, or the entry is switched off. ';
            echo 'Deactivate and reactivate the plugin to generate one.';
            echo '</p></div>';
        } else {
            echo '<h2>Your address</h2><table class="widefat striped"><tbody>';
            printf('<tr><th scope="row">DID</th><td><code>%s</code></td></tr>',
                esc_html($entry->did()));
            printf('<tr><th scope="row">Card</th><td><a href="%s"><code>%s</code></a></td></tr>',
                esc_url($cardUrl), esc_html($cardUrl));
            printf('<tr><th scope="row">Door</th><td><code>POST %s</code></td></tr>',
                esc_html($entry->baseUrl() . '/'));
            echo '</tbody></table>';

            $this->renderHealth($entry, $cardUrl);
        }

        echo '<h2>Settings</h2><form method="post" action="options.php">';
        settings_fields('muretai_agent_entry');
        echo '<table class="form-table"><tbody>';
        printf(
            '<tr><th scope="row">Answer agents</th><td><label><input type="checkbox" '
            . 'name="%s" value="1" %s /> Serve the card and answer signed messages</label></td></tr>',
            esc_attr(self::OPT_ENABLED),
            checked(get_option(self::OPT_ENABLED, '1'), '1', false)
        );
        printf(
            '<tr><th scope="row">Public name</th><td><input type="text" class="regular-text" '
            . 'name="%s" value="%s" /></td></tr>',
            esc_attr(self::OPT_NAME),
            esc_attr((string) get_option(self::OPT_NAME, get_bloginfo('name')))
        );
        printf(
            '<tr><th scope="row">Description</th><td><input type="text" class="regular-text" '
            . 'name="%s" value="%s" /></td></tr>',
            esc_attr(self::OPT_DESCRIPTION),
            esc_attr((string) get_option(self::OPT_DESCRIPTION, get_bloginfo('description')))
        );
        printf(
            '<tr><th scope="row">Reply</th><td><textarea name="%s" rows="3" class="large-text">%s</textarea>'
            . '<p class="description">What the site says back. Developers can replace this '
            . 'per message with the <code>muretai_agent_entry_reply</code> filter.</p></td></tr>',
            esc_attr(self::OPT_REPLY),
            esc_textarea((string) get_option(self::OPT_REPLY, ''))
        );
        echo '</tbody></table>';
        submit_button();
        echo '</form>';

        $this->renderVisitors();
        $this->renderCdnNote();
        echo '</div>';
    }

    /**
     * Is the door really answering, and is it OURS?
     *
     * Both questions need a real HTTP request, because everything else is this plugin
     * agreeing with itself. The DID comparison is the part that matters: another plugin
     * that also claims `/.well-known/agent-card.json` (several AI-discovery plugins do)
     * would serve a card that is not ours, and a site owner has no way to notice except by
     * being told.
     */
    private function renderHealth(Entry $entry, string $cardUrl): void
    {
        echo '<h2>Is it working?</h2>';
        // `sslverify` is deliberately LEFT ALONE (i.e. verification stays on). Turning it
        // off to make a self-signed staging cert stop complaining would teach the plugin to
        // accept any certificate for its own identity check, which is the one request that
        // most needs to be talking to the real site.
        $res = wp_remote_get($cardUrl, ['timeout' => 5]);
        if (is_wp_error($res)) {
            printf('<div class="notice notice-warning inline"><p>Could not fetch the card '
                . 'from this server (%s). This is often a loopback restriction on the host '
                . 'rather than a broken door: check the card URL in a browser.</p></div>',
                esc_html($res->get_error_message()));
            return;
        }
        $code = (int) wp_remote_retrieve_response_code($res);
        $served = json_decode((string) wp_remote_retrieve_body($res), true);
        $servedDid = is_array($served) ? ($served['did'] ?? null) : null;

        if ($code !== 200) {
            printf('<div class="notice notice-error inline"><p>The card path answered '
                . 'HTTP %d. Some hosts and security plugins block <code>/.well-known/</code>; '
                . 'that path must reach WordPress for agents to find this site.</p></div>',
                $code);
            return;
        }
        if ($servedDid === $entry->did()) {
            echo '<div class="notice notice-success inline"><p>The door is answering, and '
                . 'the card served at that URL is this site\'s.</p></div>';
        } else {
            printf('<div class="notice notice-error inline"><p><strong>Another plugin is '
                . 'serving the agent card.</strong> The card at that URL names '
                . '<code>%s</code>, not this site\'s <code>%s</code>. Two plugins claiming '
                . 'the same path is a conflict a visitor cannot resolve — deactivate one of '
                . 'them.</p></div>',
                esc_html(is_string($servedDid) ? $servedDid : 'no DID at all'),
                esc_html($entry->did()));
        }

        $env = $this->store()->getCardEnvelope();
        if ($env === null) {
            echo '<p>The signed card has not been minted yet; it is created on the first '
                . 'request for it.</p>';
        } else {
            $ageH = (time() - (int) $env['ts']) / 3600;
            $msg = sprintf('The signed card is %.1f hours old.', $ageH);
            if ($ageH > 5) {
                printf('<div class="notice notice-warning inline"><p>%s A visitor rejects '
                    . 'one older than 6 hours. WP-Cron only runs when someone visits the '
                    . 'site, so a very quiet site can fall behind — a real cron job calling '
                    . '<code>wp-cron.php</code> fixes it permanently.</p></div>',
                    esc_html($msg));
            } else {
                printf('<p>%s</p>', esc_html($msg));
            }
        }
    }

    private function renderVisitors(): void
    {
        $store = $this->store();
        $rows = $store->recentAccounts(10);
        printf('<h2>Agents that have visited (%d)</h2>', $store->countAccounts());
        if ($rows === []) {
            echo '<p>None yet. Every agent that sends a signed message appears here — the '
                . 'first message from a stranger IS their account, so there is no signup '
                . 'step to wait for.</p>';
            return;
        }
        echo '<table class="widefat striped"><thead><tr><th>Agent</th><th>Messages</th>'
            . '<th>First seen</th><th>Last seen</th></tr></thead><tbody>';
        foreach ($rows as $r) {
            printf('<tr><td><code>%s</code></td><td>%d</td><td>%s</td><td>%s</td></tr>',
                esc_html((string) $r['did']),
                (int) $r['messages'],
                esc_html(gmdate('Y-m-d H:i', (int) $r['first_seen'])),
                esc_html(gmdate('Y-m-d H:i', (int) $r['last_seen'])));
        }
        echo '</tbody></table>';
    }

    /**
     * The CDN warning, which is here because it cost three days on a live site.
     *
     * Cloudflare's Browser Integrity Check is a ZONE SETTING, on by default on the free
     * plan, and it 403s clients whose user agent looks automated — which is every agent.
     * The site owner sees nothing wrong, because a browser sails through.
     */
    private function renderCdnNote(): void
    {
        echo '<h2>If you use a CDN</h2><p>A CDN in front of this site can refuse agents '
            . 'while serving humans perfectly. On Cloudflare the setting is '
            . '<strong>Browser Integrity Check</strong> (on by default on the free plan): '
            . 'it rejects clients whose user agent looks automated, which is all of them. '
            . 'Add an exception for this site matching on <em>host, method and path only</em> '
            . ' — never on user agent, which is the thing being wrongly judged.</p>'
            . '<p><strong>Do not test with <code>curl</code>.</strong> It sends its own '
            . 'user agent and passes checks that block a real agent, so a green '
            . '<code>curl</code> proves nothing about whether agents can reach you.</p>';
    }
}
