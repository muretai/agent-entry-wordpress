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
        $this->card = $this->buildCard($options);
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
            'agentEntry' => ['open_door' => true],
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
            && ($now - (int) $cached['ts']) >= 0) {
            return $cached['bytes'];
        }
        $env = Wire::makeCardEnvelope($this->seed, $this->card, $now);
        $bytes = Wire::jsonBytes($env);
        $this->store->putCardEnvelope($now, $bytes);
        return $bytes;
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
    public function handle(string $method, string $path, array $headers, string $body): array
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
        $id = $req['id'] ?? null;
        if (is_array($id)) {
            $id = null;
        }

        // 3. the method.
        $method = $req['method'] ?? null;
        if ($method !== 'message/send') {
            return $this->rpcError($id, self::E_METHOD_NOT_FOUND,
                'Method not found: ' . (is_string($method) ? substr($method, 0, 48) : 'none'));
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
        if (!is_string($messageId) || $messageId === ''
            || ($contextId !== null && !is_string($contextId)) || $text === null) {
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
                'not addressed to me: ' . substr($to, 0, 24));
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

        // 11. the rate ceilings. Being attributable is not being bounded: a signature
        //     identifies a sender, it does not stop them, and the reply may cost far more
        //     than the verify did.
        if ($this->ratePerMinTotal > 0
            && !$this->store->allowRate('__total__', $this->ratePerMinTotal)) {
            return $this->rpcError($id, self::E_RATE_LIMITED,
                'this entry is at its reply ceiling; try again shortly');
        }
        if ($this->ratePerMin > 0 && !$this->store->allowRate($from, $this->ratePerMin)) {
            return $this->rpcError($id, self::E_RATE_LIMITED,
                'you are at your reply ceiling; try again shortly');
        }

        // 12. FIRST CONTACT IS ACCOUNT CREATION. There is no signup form: the sender just
        //     proved control of a key, which is strictly more than an email link proves.
        $row = $this->store->noteContact($from);

        $env = [
            'peer_did' => $from,
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
            $replyText = substr($replyText, 0, Wire::MAX_TEXT_BYTES);
        }

        return $this->json(200, [
            'jsonrpc' => '2.0',
            'id' => $id,
            'result' => $this->signedReply($from, $replyText, $contextId, $messageId),
        ]);
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
