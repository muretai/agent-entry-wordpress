<?php
/**
 * Entry.php — the door, as an HTTP state machine with no WordPress in it.
 *
 * WHY THIS SHAPE. The whole request contract is one pure function:
 *
 *     handle($method, $path, $headers, $body) -> [status, headers, body]
 *
 * which is deliberately the same signature the Node twin exposes as
 * `handleRequestAsync`. Keeping WordPress out of this file buys two things: the ladder
 * below can be driven by a test with no CMS booted, and the WordPress adapter shrinks to
 * "collect the request, call this, emit the response" — small enough to read in one sitting
 * and therefore small enough to audit.
 *
 * All mutable state lives behind the Store interface (see class-store.php): the ledger, the
 * replay set, the device->owner pins and the rate counters. That is not an abstraction for
 * its own sake — it is the same seam core's own backlog (T105) identified for serverless,
 * and here it is what lets WordPress put the state in `$wpdb` while a test keeps it in an
 * array.
 *
 * THE ROUTES, and the one that surprises people:
 *
 *   GET|HEAD  <mount>/.well-known/agent-card.json      the plain card
 *   GET|HEAD  <mount>/.well-known/agent.json           THE SAME BYTES (legacy alias)
 *   GET|HEAD  <mount>/.well-known/agent-card.sig.json  the signed envelope
 *   POST      <mount>                                  the door
 *   OPTIONS   any of the above                         204 + per-resource Allow + CORS
 *   anything else                                      404, for every method
 *
 * `GET <mount>` is NOT ours. On WordPress the site's front page lives there and stays the
 * site's; the entry answers the POST at the same URI. HTTP's primary cache key is
 * method+URI (RFC 9111 s4), so `GET /` and `POST /` are distinct cache entries by
 * construction. The alternative — one URI serving a human page or agent JSON depending on
 * the Accept header — is one missing `Vary: Accept` away from a CDN serving agent JSON to
 * every human visitor. A method split cannot have that bug.
 *
 * A POST to a path we do not own is 404, NOT 405: telling a prober "wrong method" would
 * confirm the path exists. A door we DO own answers 405 to a method it does not take,
 * because that address is published in a signed card and there is nothing to conceal.
 *
 * @package Muretai\AgentEntry
 */

namespace Muretai\AgentEntry;

if (!defined('ABSPATH') && !defined('MURETAI_AGENT_ENTRY_STANDALONE')) {
    exit;
}

require_once __DIR__ . '/class-wire.php';
require_once __DIR__ . '/class-store.php';

/**
 * One Agent Entry: an identity, a card, and the request ladder.
 */
final class Entry
{
    // JSON-RPC error codes. The standard set plus this protocol's own, and every one of
    // them travels as HTTP 200 with a JSON-RPC error body: a protocol verdict is not a
    // transport failure. Only 400 (unparseable) and 413 (too large) are non-200, because
    // at that point there is no JSON-RPC envelope to answer inside.
    public const E_PARSE = -32700;
    public const E_INVALID_REQUEST = -32600;
    public const E_METHOD_NOT_FOUND = -32601;
    public const E_INVALID_PARAMS = -32602;
    public const E_INTERNAL = -32603;
    public const E_UNAUTHENTICATED = -32001;
    public const E_REPLAY = -32002;
    public const E_WRONG_RECIPIENT = -32003;
    public const E_RATE_LIMITED = -32004;
    public const E_TEXT_TOO_LARGE = -32005;

    /** The door-pointer link relation, for an agent handed nothing but a domain. */
    public const LINK_REL = 'https://muretai.net/rel/agent-entry';

    /** Re-mint the signed card envelope at most this often. */
    public const CARD_SIG_REFRESH_S = 3600;

    /** @var string 32-byte Ed25519 seed. THE PRIVATE KEY. Never logged, never returned. */
    private $seed;

    /** @var string this entry's did:key */
    private $did;

    /** @var string the canonical base URL a visitor dials, e.g. https://shop.example */
    private $baseUrl;

    /** @var string the path prefix this entry answers at ('' for a bare origin) */
    private $mount;

    /** @var array the plain Agent Card */
    private $card;

    /** @var Store */
    private $store;

    /** @var callable(array):mixed given a verified envelope, returns the reply text */
    private $responder;

    /** @var int replies per minute per account (0 disables the tier) */
    private $ratePerMin;

    /** @var int replies per minute for the whole entry */
    private $ratePerMinTotal;

    /** @var array|null AE-30: the site's own order of its ways in, validated; null = not configured */
    private $prefer;

    /** @var array<string,true> devices already warned about an unverifiable P-256 owner */
    private $p256Unbound = [];

    /** The kinds a visitor can take into a site, and the conditions a site may attach.
     *  Must match PREFER_KINDS / PREFER_WHEN in the JS module and the Python twin. */
    public const PREFER_KINDS = ['page', 'card', 'mcp'];
    public const PREFER_WHEN = ['person', 'alone', 'key', 'no-key', 'token', 'browser'];

    /**
     * @param string        $seed      32 raw bytes.
     * @param string        $baseUrl   the URL visitors dial; MAY carry a path.
     * @param array         $options   name, description, version, skills, responder, store,
     *                                 ratePerMin, ratePerMinTotal.
     */
    public function __construct(string $seed, string $baseUrl, array $options = [])
    {
        if (strlen($seed) !== SODIUM_CRYPTO_SIGN_SEEDBYTES) {
            throw new \InvalidArgumentException('seed must be 32 bytes');
        }
        $this->seed = $seed;
        $this->did = Wire::didFromSeed($seed);
        [$this->baseUrl, $this->mount] = self::canonicalBaseUrl($baseUrl);
        $this->store = $options['store'] ?? new MemoryStore();
        $this->responder = $options['responder'] ?? static function (array $env): string {
            return 'Thanks for the message. A human will read it.';
        };
        $this->ratePerMin = (int) ($options['ratePerMin'] ?? 60);
        $this->ratePerMinTotal = (int) ($options['ratePerMinTotal'] ?? 600);
        // AE-30: validated BEFORE the card exists, so an invalid order never becomes a
        // published statement — the same posture as a bad base URL.
        $this->prefer = self::validatePrefer($options['prefer'] ?? null);
        $this->card = $this->buildCard($options);
    }

    /**
     * The exact `agentEntry.prefer` this entry may publish, or InvalidArgumentException (AE-30).
     *
     * VALIDATED, NEVER REWRITTEN: this goes on a SIGNED card, and a card that says something
     * the operator did not write is a worse card than none — so an unknown kind, an unknown
     * condition or a stray key refuses the whole declaration instead of trimming it. Null
     * means "not configured": no `prefer` key at all, which keeps an already-deployed
     * entry's bytes unchanged.
     *
     * @param mixed $prefer
     */
    public static function validatePrefer($prefer): ?array
    {
        if ($prefer === null) {
            return null;
        }
        if (!is_array($prefer) || $prefer === [] || array_keys($prefer) !== range(0, count($prefer) - 1)) {
            throw new \InvalidArgumentException('agentEntry.prefer must be a non-empty list of "page" | "card" | "mcp" or {kind, when}');
        }
        foreach ($prefer as $e) {
            if (is_string($e)) {
                if (!in_array($e, self::PREFER_KINDS, true)) {
                    throw new \InvalidArgumentException('agentEntry.prefer: unknown kind ' . json_encode($e));
                }
                continue;
            }
            if (!is_array($e) || $e === [] || array_keys($e) === range(0, count($e) - 1)) {
                throw new \InvalidArgumentException('agentEntry.prefer: an entry must be a kind or {kind, when}');
            }
            if (!isset($e['kind']) || !in_array($e['kind'], self::PREFER_KINDS, true)) {
                throw new \InvalidArgumentException('agentEntry.prefer: unknown kind ' . json_encode($e['kind'] ?? null));
            }
            if (array_key_exists('when', $e) && !in_array($e['when'], self::PREFER_WHEN, true)) {
                throw new \InvalidArgumentException('agentEntry.prefer: unknown condition ' . json_encode($e['when']));
            }
            $stray = array_diff(array_keys($e), ['kind', 'when']);
            if ($stray !== []) {
                throw new \InvalidArgumentException('agentEntry.prefer: unexpected key(s) ' . implode(', ', $stray));
            }
        }
        return $prefer;
    }

    public function did(): string
    {
        return $this->did;
    }

    public function mount(): string
    {
        return $this->mount;
    }

    public function baseUrl(): string
    {
        return $this->baseUrl;
    }

    /**
     * Split a base URL into the canonical form a card names and the path this entry
     * answers at. A trailing slash is dropped so `https://h/support/` and
     * `https://h/support` are one address; a bare origin yields mount ''.
     *
     * @return array{0:string,1:string} [canonical base URL, mount path]
     */
    public static function canonicalBaseUrl(string $url): array
    {
        $url = rtrim(trim($url), '/');
        $parts = parse_url($url);
        if (!isset($parts['scheme'], $parts['host'])) {
            throw new \InvalidArgumentException("baseUrl must be absolute: {$url}");
        }
        $origin = $parts['scheme'] . '://' . $parts['host']
            . (isset($parts['port']) ? ':' . $parts['port'] : '');
        $path = rtrim($parts['path'] ?? '', '/');
        return [$origin . $path, $path];
    }

    // ---------------------------------------------------------------- the card

    private function buildCard(array $o): array
    {
        $card = [
            'protocolVersion' => Wire::PROTOCOL_VERSION,
            'name' => (string) ($o['name'] ?? 'Agent Entry'),
            'description' => (string) ($o['description'] ?? ''),
            'url' => $this->baseUrl,
            'did' => $this->did,
            'version' => (string) ($o['version'] ?? '1'),
            'capabilities' => ['streaming' => false, 'pushNotifications' => false],
            'defaultInputModes' => ['text/plain'],
            'defaultOutputModes' => ['text/plain'],
            'skills' => $o['skills'] ?? [],
            // TWO SPELLINGS, ONE FACT. `agentEntry` is the spelling the specification
            // defines — nothing about resolving an agent endpoint should depend on a
            // vendor name. `muretai` stays beside it, byte-identical, because a consumer
            // already deployed against the old key cannot be reached by any change here.
            // A producer MUST emit `agentEntry`; a consumer MUST accept either.
            // AE-30: the site's order of its ways in rides on the NEUTRAL key only; the
            // alias stays `open_door` alone, so an old consumer comparing the two aliases
            // byte for byte keeps passing.
            'agentEntry' => array_merge(['open_door' => true],
                $this->prefer !== null ? ['prefer' => $this->prefer] : []),
            'muretai' => ['open_door' => true],
            'securitySchemes' => [
                'did-key-ed25519' => [
                    'type' => 'http',
                    'scheme' => 'did-key-ed25519',
                    'description' => 'Sign the six canonical fields with your did:key '
                        . 'Ed25519 seed and POST the message here.',
                    'agentEntry' => [
                        'scheme' => 'did-key-ed25519',
                        'instruction' => 'POST a JSON-RPC message/send whose metadata '
                            . 'carries {from, to, sig, timestamp}.',
                        'in' => 'body',
                        'recipient' => $this->did,
                        'endpoint' => $this->baseUrl . '/',
                        'identity' => 'did:key:z + base58btc(0xed01 || <32-byte Ed25519 '
                            . 'public key>)',
                        'signedFields' => ['contextId', 'from', 'messageId', 'text',
                            'timestamp', 'to'],
                        'canonicalization' => 'JSON with keys sorted by code point, '
                            . 'separators "," and ":", non-ASCII literal, UTF-8',
                        'signature' => 'Ed25519 over the canonical bytes, base64 with '
                            . 'padding',
                        'timestamp' => 'integer epoch seconds, within '
                            . Wire::CLOCK_WINDOW_S . 's',
                    ],
                ],
            ],
            'security' => [['did-key-ed25519' => []]],
        ];
        if (!empty($o['domains'])) {
            $card['domains'] = array_values($o['domains']);
        }
        return $card;
    }

    /** The plain card bytes. Identical at the canonical path and the legacy alias. */
    public function cardBytes(): string
    {
        return Wire::jsonBytes($this->card);
    }

    /**
     * The signed card envelope, re-minted at most hourly.
     *
     * A CONSUMER REJECTS AN ENVELOPE OLDER THAN 6 H, so this is a freshness window rather
     * than a cache tweak: without it a saved copy would still "prove" ownership to whoever
     * holds the origin next. It is also the reason a purely static file cannot be a
     * conformant door — something must hold the key and re-sign this, which on WordPress
     * is WP-Cron.
     */
    public function cardEnvelopeBytes(): string
    {
        $cached = $this->store->getCardEnvelope();
        $now = time();
        if ($cached !== null && isset($cached['ts'])
            && ($now - (int) $cached['ts']) < self::CARD_SIG_REFRESH_S
            && ($now - (int) $cached['ts']) >= 0
            && self::envelopeMatches($cached['bytes'], $this->card)) {
            return $cached['bytes'];
        }
        $env = Wire::makeCardEnvelope($this->seed, $this->card, $now);
        $bytes = Wire::jsonBytes($env);
        $this->store->putCardEnvelope($now, $bytes);
        return $bytes;
    }

    /**
     * Does a cached envelope still sign THE CARD WE WOULD SERVE NOW?
     *
     * The plain card is rebuilt on every request while the signed one is cached for an
     * hour, so anything that changes the card's content leaves the two documents
     * disagreeing until the cache expires — and a visitor trusts the SIGNED one, so the
     * change is invisible to every agent for up to an hour while looking correct to the
     * site owner.
     *
     * An earlier fix watched the two settings fields, which was too narrow: activating
     * WooCommerce adds a `skills` entry without touching any option this plugin owns, and
     * that is exactly what happened on a real install — the catalogue answered questions
     * perfectly while the signed card advertised no catalogue at all. Comparing the CONTENT
     * cannot miss a cause, so it compares the content.
     *
     * @param mixed $bytes the cached envelope as served.
     */
    private static function envelopeMatches($bytes, array $card): bool
    {
        if (!is_string($bytes) || $bytes === '') {
            return false;
        }
        $decoded = json_decode($bytes, true);
        if (!is_array($decoded) || !is_array($decoded['card'] ?? null)) {
            return false;
        }
        try {
            return Wire::canonicalJson($decoded['card']) === Wire::canonicalJson($card);
        } catch (\Throwable $e) {
            return false;                      // unreadable cache: re-mint rather than serve
        }
    }

    /** Force a fresh envelope regardless of cache age (what WP-Cron calls). */
    public function remintCardEnvelope(): string
    {
        $now = time();
        $bytes = Wire::jsonBytes(Wire::makeCardEnvelope($this->seed, $this->card, $now));
        $this->store->putCardEnvelope($now, $bytes);
        return $bytes;
    }

    // ---------------------------------------------------------------- routing

    private function cardPath(): string
    {
        return $this->mount . '/.well-known/agent-card.json';
    }

    private function legacyCardPath(): string
    {
        return $this->mount . '/.well-known/agent.json';
    }

    private function sigPath(): string
    {
        return $this->mount . '/.well-known/agent-card.sig.json';
    }

    private function doorPath(): string
    {
        return $this->mount === '' ? '/' : $this->mount;
    }

    /** True when this entry owns the path at all (any method). */
    public function owns(string $path): bool
    {
        $path = self::normalisePath($path);
        return in_array($path, [$this->cardPath(), $this->legacyCardPath(),
            $this->sigPath(), $this->doorPath()], true);
    }

    private static function normalisePath(string $path): string
    {
        $path = explode('?', $path, 2)[0];
        if ($path === '') {
            return '/';
        }
        if ($path !== '/' && substr($path, -1) === '/') {
            $path = rtrim($path, '/');
            if ($path === '') {
                $path = '/';
            }
        }
        return $path;
    }

    /**
     * What `Allow:` may truthfully say about this path, or null when we do not own it.
     *
     * RFC 9110 s10.2.1 makes `Allow` a statement about the target RESOURCE, so it differs
     * per path. The door's answer is the UNION of what the site serves there (WordPress
     * keeps GET/HEAD on its own front page) and what this entry adds (POST), because
     * listing only the POST half would deny a GET the site plainly answers.
     */
    private function allowFor(string $path): ?string
    {
        $path = self::normalisePath($path);
        if (in_array($path, [$this->cardPath(), $this->legacyCardPath(), $this->sigPath()], true)) {
            return 'GET, HEAD, OPTIONS';
        }
        if ($path === $this->doorPath()) {
            return 'GET, HEAD, POST, OPTIONS';
        }
        return null;
    }

    /**
     * CORS, deliberately minimal and deliberately WITHOUT credentials.
     *
     * A browser-resident agent needs the preflight to succeed or it can read neither a
     * card nor a signed reply, so the origin is `*`. `Access-Control-Allow-Credentials` is
     * the one header that would turn `*` into a hole, and it is never emitted: authority
     * here comes from an Ed25519 signature INSIDE the body, never from a cookie, a header
     * credential or a session, so there is no ambient authority for a cross-origin page to
     * borrow — and therefore no CSRF surface either.
     */
    private function corsHeaders(?string $allow = null): array
    {
        return [
            'Access-Control-Allow-Origin' => '*',
            // Merged, never appended: two Allow-Methods lines on one response is a bug in
            // itself, and a response saying `Allow: POST, OPTIONS` beside
            // `Access-Control-Allow-Methods: GET, POST, OPTIONS` contradicts itself.
            'Access-Control-Allow-Methods' => $allow ?? 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers' => 'Content-Type',
            'Access-Control-Max-Age' => '600',
        ];
    }

    /** The `Link` signpost naming the card, for a caller handed only a domain. */
    public function linkHeaderValue(): string
    {
        return '<' . $this->mount . '/.well-known/agent-card.json>; rel="' . self::LINK_REL . '"';
    }

    /**
     * The whole request contract.
     *
     * @param string $method  HTTP method, upper case.
     * @param string $path    request path (query string ignored).
     * @param array  $headers lower-cased header name => value.
     * @param string $body    raw request bytes.
     * @return array{0:int,1:array,2:string} [status, headers, body]
     */
    public function handle(string $method, string $path, array $headers, string $body,
                           string $query = ''): array
    {
        // A BLANKET GUARD, so a stranger always gets a status line.
        //
        // Everything below is written to refuse rather than throw, but "written to" is not
        // "proved to": this runs inside WordPress on an `init` hook with no try around it,
        // so ONE escaping exception is a WP fatal — an HTTP 500, a stack trace wherever
        // WP_DEBUG_DISPLAY is on, and an error-log line carrying absolute server paths, all
        // from an unauthenticated POST. Two such throws were found by audit before this
        // plugin was ever published (a byte-truncation landing mid-UTF-8, and a JSON-RPC
        // `id` the canonicaliser refuses); both are fixed at their source above, and this
        // exists for the third one nobody has found yet.
        //
        // The fallback body is a hand-written literal, never a canonicalised structure,
        // because the whole point is that it cannot itself throw.
        try {
            return $this->route($method, $path, $headers, $body, $query);
        } catch (\Throwable $e) {
            return [500, ['Content-Type' => 'application/json; charset=utf-8'],
                '{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"Internal error"}}'];
        }
    }

    /** The actual routing. Called only through `handle()`, which owns the guard. */
    private function route(string $method, string $path, array $headers, string $body,
                           string $query): array
    {
        $method = strtoupper($method);
        $path = self::normalisePath($path);
        $allow = $this->allowFor($path);

        if ($method === 'OPTIONS') {
            // 404 FIRST — the same answer GET and POST give an address we do not own.
            // An OPTIONS that 204s where GET 404s is a path oracle.
            if ($allow === null) {
                return $this->json(404, ['error' => 'not found']);
            }
            return [204, ['Allow' => $allow] + $this->corsHeaders($allow), ''];
        }

        if ($method === 'GET' || $method === 'HEAD') {
            if ($path === $this->cardPath() || $path === $this->legacyCardPath()) {
                // IDENTICAL BYTES on both paths. The legacy alias is not a redirect and
                // not a second rendering: a fetcher that falls back to it must get the
                // same document it would have got from the canonical path.
                return $this->bytes(200, $this->cardBytes(), $method, $allow);
            }
            if ($path === $this->sigPath()) {
                return $this->bytes(200, $this->cardEnvelopeBytes(), $method, $allow);
            }
            // The door's GET belongs to the site (WordPress renders its own page there),
            // and every other path is not ours. Both fall through to the caller.
            return [404, [], ''];
        }

        if ($method === 'POST') {
            if ($path !== $this->doorPath()) {
                // 404, NOT 405. Answering "method not allowed" would confirm the path
                // exists to someone who only guessed at it.
                return $this->json(404, ['error' => 'not found']);
            }
            // THE DOOR SHARES ITS URI WITH THE SITE, AND THE SITE POSTS THERE TOO.
            //
            // The method split gives `GET /` to the site and `POST /` to the door, which is
            // correct for a site whose only POSTs are agent messages — and wrong for almost
            // every real WordPress site. WooCommerce's classic checkout is the case that
            // matters: `POST /?wc-ajax=add_to_cart` has the path `/`, so it lands here, and
            // a form-encoded body is not JSON. Answering it at all — even with a polite 400 —
            // breaks add-to-cart, coupons, order review and checkout on exactly the shops
            // this plugin is for.
            //
            // So the door claims a POST only when the caller has SAID it is one of ours.
            // Anything else gets the fall-through sentinel and WordPress handles the request
            // exactly as it would with this plugin deactivated, which is what the README
            // promises. The cost is that a JSON-RPC client sending the wrong Content-Type
            // gets the site's page instead of a protocol error; the alternative cost is a
            // broken shop, and a correct client always sends `application/json`.
            //
            // A QUERY STRING ALSO MEANS THE POST IS NOT OURS — checked first, because the
            // Content-Type gate alone is not enough. WordPress multiplexes whole APIs over
            // the root path by query string, and one of them takes JSON: WooCommerce
            // Stripe's only webhook endpoint is `/?wc-api=wc_stripe`, delivered as
            // `application/json`. The Content-Type gate claimed it, and the door answered
            // HTTP 200 with `{"error":{"code":-32601,...},"id":"evt_..."}` — measured on a
            // live install. Stripe records a 200 as delivered and never retries, so every
            // payment event on such a shop would be lost SILENTLY. A door POST can never
            // carry a query string: the address an agent dials is the signed card's `url`,
            // byte-exact, and no query ever appears in one (the visitor's card walk drops
            // any query it was handed — verified against the reference client). Referral
            // and campaign links (`/?utm_source=`, `/?ref=`) are unaffected by this gate
            // for the other reason: a clicked link arrives with GET, and no GET is ever
            // ours. The two kinds of traffic are disjoint by construction.
            if ($query !== '') {
                return [404, [], ''];
            }
            if (!self::looksLikeAgentMessage($headers, $body)) {
                return [404, [], ''];
            }
            return $this->handlePost($headers, $body);
        }

        if ($allow !== null) {
            // A method we do not take, on an address published in a signed card. RFC 9110
            // s15.5.6 requires `Allow` on a 405, and there is nothing to conceal here.
            return [405, ['Allow' => $allow] + $this->corsHeaders($allow),
                Wire::jsonBytes(['error' => 'method not allowed'])];
        }
        return $this->json(404, ['error' => 'not found']);
    }

    /**
     * The JSON-RPC `id` we are willing to ECHO, or null.
     *
     * The id is the one value a stranger controls that we copy straight back into a
     * response, and this response is canonicalised — so a value the canonicaliser refuses
     * turns into an uncaught throw and an HTTP 500 at the METHOD-CHECK rung, before any
     * signature is examined. `{"id": 1.0}`, `{"id": 1e20}`, `{"id": 0.00001}` and
     * `{"id": 9223372036854775807}` all do it: PHP ints run to 64 bits while this wire
     * stops at ±(2**53−1), and every whole-valued float is refused because Python, PHP and
     * JavaScript spell it three different ways.
     *
     * Worse on the SUCCESS path: the ladder would already have booked the account and burnt
     * the messageId before serialisation failed, so the sender gets no reply and their retry
     * earns −32002.
     *
     * Both sibling implementations already carry this guard (`safeId` in the JS twin,
     * `_safe_id` in the Python one) with the same failure recorded as measured. This is the
     * PHP twin catching up, not a new idea.
     *
     * @param mixed $id
     * @return string|int|null
     */
    private static function safeId($id)
    {
        if (is_string($id)) {
            // A string id is echoed, but it is still a stranger's bytes: cap it, and make
            // sure the cap cannot land mid-character (see truncateUtf8).
            return self::truncateUtf8($id, 256);
        }
        if (is_int($id) && $id <= Wire::MAX_SAFE_INT && $id >= -Wire::MAX_SAFE_INT) {
            return $id;
        }
        // Floats, out-of-range integers, booleans, arrays, objects: JSON-RPC allows a null
        // id, so answering with one is correct rather than merely safe.
        return null;
    }

    /**
     * Truncate to at most `$max` BYTES without splitting a UTF-8 character.
     *
     * `substr()` counts bytes, so truncating attacker-controlled text mid-character leaves
     * a lone lead byte. That string then reaches the canonicaliser, which refuses invalid
     * UTF-8 by design — and the refusal is an exception on the error path, i.e. an
     * unauthenticated remote HTTP 500 from a ~90-byte POST. The door's own contract says a
     * protocol verdict is HTTP 200 and that junk costs the recipient nothing; this keeps
     * that true.
     */
    private static function truncateUtf8(string $s, int $max): string
    {
        if (strlen($s) <= $max) {
            return $s;
        }
        $cut = substr($s, 0, $max);
        // Drop any trailing bytes that form an incomplete sequence. At most 3 can.
        for ($i = 0; $i < 4 && $cut !== ''; $i++) {
            if (preg_match('//u', $cut)) {
                return $cut;
            }
            $cut = substr($cut, 0, -1);
        }
        return $cut;
    }

    /**
     * Is this POST addressed to the DOOR, or is it the site's own traffic?
     *
     * Two gates here, and a third — the query-string gate — upstream in `route()`. The
     * Content-Type gate is what lets WooCommerce's form-encoded AJAX through untouched; the
     * body gate is what stops a JSON POST from some other plugin's REST-ish endpoint being
     * answered as a malformed agent message; the query gate is what keeps JSON webhooks
     * multiplexed over the root path (`?wc-api=wc_stripe`) out of the door entirely.
     *
     * Deliberately CHEAP and deliberately BEFORE `handlePost`: this runs on every POST the
     * site receives, including its own, so it must not cost the site anything. The body cap
     * is re-checked inside `handlePost` — this pre-scan only refuses to CLAIM the request.
     */
    private static function looksLikeAgentMessage(array $headers, string $body): bool
    {
        $ctype = '';
        foreach ($headers as $k => $v) {
            if (strtolower($k) === 'content-type') {
                $ctype = strtolower((string) $v);
                break;
            }
        }
        // `application/json`, plus its `+json` suffix forms and any `; charset=` parameter.
        if (strpos($ctype, 'application/json') === false && strpos($ctype, '+json') === false) {
            return false;
        }
        // CONTENT-TYPE ALONE DECIDES HERE, and the body is deliberately NOT inspected.
        //
        // A caller that sent `application/json` to this URI — with no query string, which
        // `route()` has already checked — has said it is talking to a JSON API, and the only
        // query-less JSON API at the site root is this door. So we CLAIM it, and a malformed
        // body then earns a proper -32700 instead of silently rendering the home page at a
        // confused client. Peeking at the body first was the earlier attempt, and it turned
        // every unparseable request into a 200 HTML page, which is the least useful answer
        // possible for the client most likely to need a clear error.
        //
        // "The only JSON API at the site root" was ONCE the claim made without the
        // query-string qualifier, and it was wrong: WooCommerce Stripe's webhook endpoint is
        // the site root plus `?wc-api=wc_stripe`, and it takes JSON. That is why the query
        // gate in `route()` runs before this one and is not folded into it.
        //
        // The site's own form traffic is unaffected either way: WordPress form posts are
        // `application/x-www-form-urlencoded` or `multipart/form-data`.
        return $body !== '';
    }

    private function bytes(int $status, string $body, string $method, ?string $allow): array
    {
        $headers = [
            'Content-Type' => 'application/json; charset=utf-8',
            'Content-Length' => (string) strlen($body),
            'Cache-Control' => 'no-store',
        ] + $this->corsHeaders($allow);
        if ($allow !== null) {
            $headers['Allow'] = $allow;
        }
        return [$status, $headers, $method === 'HEAD' ? '' : $body];
    }

    private function json(int $status, array $payload): array
    {
        $body = Wire::jsonBytes($payload);
        return [$status, [
            'Content-Type' => 'application/json; charset=utf-8',
            'Content-Length' => (string) strlen($body),
        ] + $this->corsHeaders(), $body];
    }

    private function rpcError($id, int $code, string $message, $data = null): array
    {
        $err = ['code' => $code, 'message' => $message];
        if ($data !== null) {
            $err['data'] = $data;
        }
        // A PROTOCOL VERDICT IS HTTP 200. The request was understood and answered; the
        // answer is "no". Reserving non-200 for transport failures is what lets a client
        // tell "your signature is wrong" apart from "the server fell over".
        return $this->json(200, ['jsonrpc' => '2.0', 'id' => $id, 'error' => $err]);
    }

    // ---------------------------------------------------------------- the POST ladder

    /**
     * The verification ladder, in an order that is itself load-bearing.
     *
     * Cheap structural checks come first so that junk costs the recipient nothing, and the
     * TEXT CAP is checked before any crypto so an oversized message is refused without a
     * signature verification. Then the signature. Then — and only then — the replay table.
     *
     * THE ORDER OF THE LAST TWO IS A SECURITY PROPERTY, not tidiness. The replay table is
     * state an authenticated sender depends on, so a caller who has proved nothing must
     * not be able to write into it. Ahead of the verify, a stranger could burn a messageId
     * its real sender was about to use; because the table is capped and evicts oldest
     * first, they could also flood past the cap to discard genuine entries and re-open
     * real messages to replay — and invalid signatures are not rate limited, so that flood
     * is free. The cost of the correct order is one Ed25519 verify spent on a replayed but
     * VALID message, which an attacker must first have obtained.
     */
    private function handlePost(array $headers, string $body): array
    {
        // 1. the body cap, before parsing.
        if (strlen($body) > Wire::MAX_BODY_BYTES) {
            return [413, ['Content-Type' => 'application/json; charset=utf-8']
                + $this->corsHeaders(), Wire::jsonBytes(['error' => 'request body too large'])];
        }

        // 2. parseable JSON object. There is no JSON-RPC envelope to answer inside, so
        //    this is one of the two non-200 answers.
        $req = json_decode($body, true);
        if (!is_array($req)) {
            return [400, ['Content-Type' => 'application/json; charset=utf-8']
                + $this->corsHeaders(), Wire::jsonBytes([
                    'jsonrpc' => '2.0', 'id' => null,
                    'error' => ['code' => self::E_PARSE, 'message' => 'Parse error'],
                ])];
        }
        $id = self::safeId($req['id'] ?? null);

        // 3. the method.
        $method = $req['method'] ?? null;
        if ($method !== 'message/send') {
            return $this->rpcError($id, self::E_METHOD_NOT_FOUND,
                'Method not found: ' . (is_string($method)
                    ? self::truncateUtf8($method, 48) : 'none'));
        }

        // 4. the params/message shape.
        $params = $req['params'] ?? null;
        $msg = is_array($params) ? ($params['message'] ?? null) : null;
        if (!is_array($msg)) {
            return $this->rpcError($id, self::E_INVALID_PARAMS, 'params.message is required');
        }
        $text = self::extractText($msg);
        $messageId = $msg['messageId'] ?? null;
        $contextId = $msg['contextId'] ?? null;
        if (!is_string($messageId)
            || ($contextId !== null && !is_string($contextId)) || $text === null) {
            return $this->rpcError($id, self::E_INVALID_PARAMS, 'malformed message');
        }
        // 4b. THE messageId BOUND, before the pattern below runs over it. The id is the
        //     replay table's key and was bounded only by the 1 MiB body cap. The store
        //     hashes it, so the KEY was never the exposure — the REQUEST was.
        if (strlen($messageId) > Wire::MAX_MESSAGE_ID_BYTES) {
            return $this->rpcError($id, self::E_INVALID_PARAMS,
                'messageId is over the ' . Wire::MAX_MESSAGE_ID_BYTES . '-byte limit');
        }
        // 4c. `Wire::messageIdOk` and not `$messageId === ''`: a WHITESPACE-ONLY id is not
        //     a message id either. It is a SIGNED field and the replay table's key, and
        //     this door used to answer three spaces with a signed reply and a customer row
        //     while the Python reference refused the identical bytes — the same double-book
        //     class the rest of this ladder exists to close. `trim()` is NOT the rule (its
        //     byte list is a fourth answer, narrower than either reference's); see
        //     Wire::messageIdOk for the 29 code points and who strips what.
        if (!Wire::messageIdOk($messageId)) {
            return $this->rpcError($id, self::E_INVALID_PARAMS, 'malformed message');
        }

        // 5. THE TEXT CAP, BEFORE ANY CRYPTO. An oversized message must cost the
        //    recipient nothing — refusing it after a signature verification would make
        //    the cap an invitation rather than a defence.
        if (strlen($text) > Wire::MAX_TEXT_BYTES) {
            return $this->rpcError($id, self::E_TEXT_TOO_LARGE,
                'text exceeds ' . Wire::MAX_TEXT_BYTES . ' bytes');
        }

        $meta = is_array($msg['metadata'] ?? null) ? $msg['metadata'] : [];
        $from = $meta['from'] ?? null;
        $to = $meta['to'] ?? null;
        $sig = $meta['sig'] ?? null;

        // 6. the signing envelope must be complete. A PARTIAL envelope (from/to present,
        //    sig stripped) is a downgrade attempt, not a walk-in.
        if (!is_string($from) || !is_string($to) || !is_string($sig) || $sig === '') {
            return $this->rpcError($id, self::E_UNAUTHENTICATED,
                'missing signing envelope (from/to/sig)');
        }

        // 7. addressed to someone else. Checked BEFORE decoding `from`, so a junk DID in a
        //    misaddressed message never reaches the base58 decoder.
        if ($to !== $this->did) {
            return $this->rpcError($id, self::E_WRONG_RECIPIENT,
                'not addressed to me: ' . self::truncateUtf8($to, 24));
        }

        // 8. an INTEGER epoch inside the clock window, in BOTH directions: a future
        //    timestamp is as unusable as a stale one. Integer is the contract, not a
        //    preference — a float renders through Python's repr and no other language
        //    reproduces those bytes.
        $ts = $meta['timestamp'] ?? null;
        if (!is_int($ts) || abs(time() - $ts) > Wire::CLOCK_WINDOW_S) {
            return $this->rpcError($id, self::E_REPLAY,
                'timestamp out of range (clock skew or replay)');
        }

        // 9. the signature, under the key DERIVED FROM `from`. With did:key the DID is the
        //    key, so there is no lookup and no resolver to be poisoned.
        if (!Wire::verifyEnvelope($from, $to, $messageId, $contextId, $ts, $text, $sig)) {
            return $this->rpcError($id, self::E_UNAUTHENTICATED, 'signature does not match');
        }

        // 10. the replay table — AFTER the verify. See the docblock above: the order is
        //     the property, not the check.
        if (!$this->store->seenMessage($messageId, Wire::REPLAY_TTL_S)) {
            return $this->rpcError($id, self::E_REPLAY,
                'duplicate messageId (replay) detected');
        }

        // 11. THE ACCOUNT LAYER (T102). An OPTIONAL countersigned v2 binding in
        //     `metadata.binding` collapses an owner's device DIDs to ONE account, so a
        //     person's phone and laptop are one customer. Absent binding: the device DID,
        //     byte-identical to a door that never heard of bindings. PRESENT-but-invalid:
        //     FAIL CLOSED, with the same -32001 the signature answers and no ledger row —
        //     never a silent downgrade to unbound, which would let anyone strip a binding
        //     they could not forge and still be served.
        //
        //     Here and not earlier: it reads and WRITES the pin table, which is state an
        //     authenticated sender depends on, so the signature and the replay check come
        //     first. Here and not later: the ceilings below and the row above must be
        //     spent on the ACCOUNT, or an owner's devices each get their own.
        $acct = $this->resolveAccount($meta['binding'] ?? null, $from);
        if (!$acct['ok']) {
            return $this->rpcError($id, self::E_UNAUTHENTICATED, $acct['reason']);
        }
        $account = $acct['account'];
        $ownerDid = $account !== $from ? $account : null;

        // 12. the rate ceilings. Being attributable is not being bounded: a signature
        //     identifies a sender, it does not stop them, and the reply may cost far more
        //     than the verify did.
        if ($this->ratePerMinTotal > 0
            && !$this->store->allowRate('__total__', $this->ratePerMinTotal)) {
            return $this->rpcError($id, self::E_RATE_LIMITED,
                'this entry is at its reply ceiling; try again shortly');
        }
        if ($this->ratePerMin > 0 && !$this->store->allowRate($account, $this->ratePerMin)) {
            return $this->rpcError($id, self::E_RATE_LIMITED,
                'you are at your reply ceiling; try again shortly');
        }

        // 13. FIRST CONTACT IS ACCOUNT CREATION. There is no signup form: the sender just
        //     proved control of a key, which is strictly more than an email link proves.
        //     Keyed by the ACCOUNT — the owner when a binding proved one — so sibling
        //     devices are one customer and not three strangers.
        $row = $this->store->noteContact($account);

        $env = [
            // `peer_did` STAYS the device that signed; `owner_did` is the account it
            // proved, or null when unbound. Both facts are honest and the schema says
            // which is which — collapsing them would lose the device a message came from.
            'peer_did' => $from,
            'owner_did' => $ownerDid,
            'text' => $text,
            'context_id' => $contextId,
            'message_id' => $messageId,
            'timestamp' => $ts,
            'verified' => true,
            'account' => $row,
        ];

        try {
            $answer = call_user_func($this->responder, $env);
        } catch (\Throwable $e) {
            // The responder's exception text NEVER reaches the caller: it carries paths,
            // field names and values, and the caller has proved nothing that entitles
            // them to any of it. A status line, though, is always owed.
            return $this->rpcError($id, self::E_INTERNAL, 'Internal error',
                'the site backend failed to answer');
        }

        $replyText = is_array($answer) ? (string) ($answer['text'] ?? '') : (string) $answer;
        if (strlen($replyText) > Wire::MAX_TEXT_BYTES) {
            $replyText = self::truncateUtf8($replyText, Wire::MAX_TEXT_BYTES);
        }

        return $this->json(200, [
            'jsonrpc' => '2.0',
            'id' => $id,
            'result' => $this->signedReply($from, $replyText, $contextId, $messageId),
        ]);
    }

    // ---------------------------------------------------------------- the account layer

    /**
     * The ACCOUNT (owner) DID this message belongs to — the PHP twin of
     * `resolveAccount` in the JavaScript door and `_resolve_account` in the Python
     * reference. Returns ['ok' => true, 'account' => $did] or ['ok' => false, 'reason' => …].
     *
     * ABSENT binding -> the device DID, byte-identical to before this rung existed.
     * PRESENT binding -> every check must hold or it fails closed with a distinct reason.
     * The cheap structural pins produce those reasons; the two SIGNATURES are left to
     * `Wire::verifyDeviceBindingV2`, the one contract all three implementations
     * re-implement and must never disagree about.
     *
     * TOFU, and A PIN NEVER MOVES: the first valid binding pins device->owner; a later
     * binding for the same device naming a DIFFERENT owner is refused, because there is no
     * legitimate re-ownership — a new owner means a new device key. On that first pin an
     * earlier UNBOUND row for the device folds into the owner row ONCE, never the reverse,
     * or stripping a binding would become a way to read an owner's history.
     *
     * @param mixed $binding
     * @return array{ok:bool,account?:string,reason?:string}
     */
    private function resolveAccount($binding, string $from): array
    {
        if ($binding === null) {
            return ['ok' => true, 'account' => $from];
        }
        // json_decode(assoc) renders BOTH a JSON object and a JSON array as a PHP array, so
        // a populated list is the one shape that can still be told apart. A JSON `[]`
        // therefore reads here as an empty object and is refused one line lower for its
        // `typ` instead — a different REASON STRING from the twins, never a different
        // verdict: -32001 and no row, either way.
        if (!is_array($binding)
            || ($binding !== [] && array_keys($binding) === range(0, count($binding) - 1))) {
            return ['ok' => false, 'reason' => 'attached device binding is malformed'];
        }
        if (($binding['typ'] ?? null) !== Wire::BINDING_V2_TYP) {
            return ['ok' => false, 'reason' => 'attached device binding has an unsupported typ'];
        }
        $rootDid = $binding['rootDid'] ?? null;
        if (!is_string($rootDid) || $rootDid === '') {
            return ['ok' => false, 'reason' => 'attached device binding names no owner'];
        }
        if (($binding['deviceDid'] ?? null) !== $from) {
            // The anti-copy pin: a binding lifted off another device's message.
            return ['ok' => false, 'reason' => 'device binding does not name the sender'];
        }
        // NORMALISE an integer-valued float before verifying. JSON has one number type: a
        // sender writing `1.0` — or any JavaScript runtime re-serialising a Number —
        // produces a float here, while `JSON.parse` in the JS twin yields the Number 1.
        // Refusing it here and accepting it there made the SAME POST create a customer on
        // one implementation and 401 on the other. A TRUE fraction stays refused by all
        // three: it cannot be canonicalised identically outside Python.
        $ts = self::intEpoch($binding['ts'] ?? null);
        $validUntil = self::intEpoch($binding['validUntil'] ?? null);
        if ($ts === null || $validUntil === null) {
            return ['ok' => false, 'reason' => 'device binding timestamps must be integers'];
        }
        $binding['ts'] = $ts;
        $binding['validUntil'] = $validUntil;
        $now = time();
        if ($ts > $now + Wire::CLOCK_WINDOW_S) {
            return ['ok' => false, 'reason' => 'device binding ts is in the future'];
        }
        if ($validUntil !== 0 && $now > $validUntil) {
            return ['ok' => false, 'reason' => 'device binding has expired'];
        }
        try {
            $ownerCurve = Wire::didKeyCurve($rootDid);
        } catch (\Throwable $e) {
            return ['ok' => false, 'reason' => 'device binding owner DID is unparseable'];
        }
        // A P-256 owner root on a host with no OpenSSL: the only unverifiable part is the
        // OWNER signature, and the two honest outcomes are "unbound" or "rejected".
        // Rejecting would refuse an envelope-valid message for a gap on OUR side, so this
        // takes the Python reference's documented posture exactly — treat the sender as
        // UNBOUND (never merged unverified), and say so once. With OpenSSL present, which
        // is every stock PHP build, the binding is fully verified as the JS door verifies
        // it and this branch never runs.
        if ($ownerCurve === 'p256' && !Wire::p256Available()) {
            $this->noteP256Unbound($from);
            return ['ok' => true, 'account' => $from];
        }
        if (!Wire::verifyDeviceBindingV2($binding, $now, $from)) {
            return ['ok' => false, 'reason' => 'device binding does not verify'];
        }
        $pinned = $this->store->getDeviceOwner($from);
        if ($pinned !== null && $pinned !== $rootDid) {
            return ['ok' => false, 'reason' => 'device is already bound to a different owner '
                . '(a device DID is never re-owned — a new owner means a new device key)'];
        }
        if ($pinned === null) {
            // The store refuses to MOVE a pin, so a false here means a concurrent request
            // pinned this device to somebody else between the read above and this write.
            // PHP has no lock to hold across the two, so the store's refusal is the lock,
            // and losing the race fails closed with the same reason it would have read.
            if (!$this->store->putDeviceOwner($from, $rootDid)) {
                return ['ok' => false, 'reason' => 'device is already bound to a different owner '
                    . '(a device DID is never re-owned — a new owner means a new device key)'];
            }
            $this->foldDeviceIntoOwner($from, $rootDid);
        }
        return ['ok' => true, 'account' => $rootDid];
    }

    /**
     * When a device that ALREADY has an unbound ledger row first proves its owner, move
     * that row's history onto the owner — ONCE, and never the reverse.
     */
    private function foldDeviceIntoOwner(string $deviceDid, string $ownerDid): void
    {
        $devRow = $this->store->getAccount($deviceDid);
        if ($devRow === null) {
            return;
        }
        $this->store->putAccount($deviceDid, null);
        $ownerRow = $this->store->getAccount($ownerDid);
        if ($ownerRow === null) {
            $devRow['did'] = $ownerDid;
            $this->store->putAccount($ownerDid, $devRow);
            return;
        }
        $ownerRow['messages'] = (int) ($ownerRow['messages'] ?? 0)
            + (int) ($devRow['messages'] ?? 0);
        $ownerRow['first_seen'] = min((int) $ownerRow['first_seen'], (int) $devRow['first_seen']);
        $this->store->putAccount($ownerDid, $ownerRow);
    }

    /** Say once per device that a P-256 owner binding could not be verified on this host.
     *  Bounded, because the key is attacker-chosen. */
    private function noteP256Unbound(string $deviceDid): void
    {
        if (isset($this->p256Unbound[$deviceDid])) {
            return;
        }
        if (count($this->p256Unbound) > 512) {
            $this->p256Unbound = [];
        }
        $this->p256Unbound[$deviceDid] = true;
        error_log('muretai agent entry: ' . substr($deviceDid, 0, 24)
            . '… presents a P-256 owner binding but this PHP has no OpenSSL — treating the '
            . 'sender as UNBOUND (never merging unverified).');
    }

    /**
     * An integer epoch, or null. Accepts an integer-valued float (JSON has one number type,
     * and a JavaScript re-serialisation yields one) and normalises it; refuses a true
     * fraction, a non-number, and any magnitude this wire cannot render — the same bound
     * `Number.isSafeInteger` applies in the JS twin.
     *
     * @param mixed $v
     */
    private static function intEpoch($v): ?int
    {
        if (is_int($v)) {
            return ($v >= -Wire::MAX_SAFE_INT && $v <= Wire::MAX_SAFE_INT) ? $v : null;
        }
        if (is_float($v) && is_finite($v) && floor($v) === $v
            && $v >= -Wire::MAX_SAFE_INT && $v <= Wire::MAX_SAFE_INT) {
            return (int) $v;
        }
        return null;
    }

    /**
     * Our own signed answer, in the same HTTP response. One round trip: no callback, no
     * webhook, nothing for the visitor to keep listening on.
     */
    private function signedReply(string $toDid, string $text, ?string $contextId,
                                 string $replyTo): array
    {
        $messageId = Wire::newId();
        $ts = time();
        $sig = Wire::signEnvelope($this->seed, $contextId, $this->did, $messageId, $text,
            $ts, $toDid);
        return [
            'kind' => 'message',
            'role' => 'agent',
            'messageId' => $messageId,
            'contextId' => $contextId,
            'parts' => [['kind' => 'text', 'text' => $text]],
            'metadata' => [
                'from' => $this->did,
                'to' => $toDid,
                'sig' => $sig,
                'timestamp' => $ts,
                'replyTo' => $replyTo,
            ],
        ];
    }

    /** Concatenate the text parts of an A2A message, or null when the shape is wrong. */
    private static function extractText(array $msg): ?string
    {
        $parts = $msg['parts'] ?? null;
        if (!is_array($parts)) {
            return null;
        }
        $out = '';
        foreach ($parts as $part) {
            if (!is_array($part)) {
                return null;
            }
            if (($part['kind'] ?? '') === 'text') {
                if (!is_string($part['text'] ?? null)) {
                    return null;
                }
                $out .= $part['text'];
            }
        }
        return $out;
    }
}
