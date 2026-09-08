<?php
/**
 * Wire.php — the byte contract, in PHP.
 *
 * WHY THIS FILE EXISTS SEPARATELY FROM WORDPRESS. Everything here is pure PHP with no
 * WordPress symbol in sight, because these are the bytes two other implementations
 * already agreed on: the JavaScript door `muretai-agent-entry.mjs` in the agent-entry
 * repository, and the Python reference `python/shared/` in agent-seam — the same bytes,
 * whose home is https://github.com/muretai/agent-seam. A third implementation earns
 * nothing by being clever: it must produce THE SAME BYTES or the signature it makes is
 * worthless to every existing verifier. Keeping this file WordPress-free means it can be
 * tested in a bare `php -f` run against the same golden vectors the other two are held
 * to (vendored here as tests/wire_vectors.json, pinned by tests/VENDOR.json), without
 * booting a CMS.
 *
 * The four things that are easy to get wrong, and are therefore stated here once:
 *
 *   1. CANONICAL JSON. Keys sorted by UNICODE CODE POINT, separators `,` and `:` with no
 *      spaces, non-ASCII emitted LITERALLY (never \u-escaped — most hand-rolled
 *      canonicalizers escape it and are then wrong for every Japanese message on the
 *      network), and an escape set of exactly the seven shorthands plus `\u00xx` for
 *      other controls. `/` and DEL (0x7F) are NOT escaped. PHP's json_encode is wrong on
 *      several of these by default, so this file does not use it for signed bytes.
 *
 *   2. THE SIX SIGNED FIELDS, frozen: contextId, from, messageId, text, timestamp, to.
 *      Nothing else is signed. `timestamp` passes through AS GIVEN and is never coerced,
 *      because the type on the wire IS the type in the signed bytes.
 *
 *   3. did:key = 'did:key:z' + base58btc(0xed01 || 32-byte Ed25519 public key). base58btc
 *      is written out here rather than approximated, because "encode base58 by hand" is
 *      exactly the step that produces a DID nobody else resolves.
 *
 *   4. INTEGERS. PHP ints are 64-bit while the wire contract is +/-(2**53-1), the range
 *      JavaScript can hold without silent rounding. Anything outside it is refused rather
 *      than signed into bytes only PHP can reproduce.
 *
 * @package Muretai\AgentEntry
 */

namespace Muretai\AgentEntry;

if (!defined('ABSPATH') && !defined('MURETAI_AGENT_ENTRY_STANDALONE')) {
    // Loaded outside both WordPress and the test harness: refuse rather than run.
    exit;
}

/**
 * The wire contract: canonical JSON, Ed25519, did:key, and the signed envelopes.
 *
 * Every method is static and side-effect free. This class holds no key material; a seed
 * is passed in per call so the caller decides where it lives.
 */
final class Wire
{
    /** A2A protocol version this entry speaks. */
    public const PROTOCOL_VERSION = '0.2';

    /** `text` ceiling, checked BEFORE any crypto so an oversized message costs nothing. */
    public const MAX_TEXT_BYTES = 65536;

    /** Whole-body ceiling. Larger bodies are refused at the transport with 413. */
    public const MAX_BODY_BYTES = 1048576;

    /** Accepted clock skew, seconds, in either direction. */
    public const CLOCK_WINDOW_S = 300;

    /** How long a messageId is remembered against replay. */
    public const REPLAY_TTL_S = 600;

    /** The signed card envelope's version + type discriminators. */
    public const CARD_ENVELOPE_VERSION = 1;
    public const CARD_ENVELOPE_TYPE = 'agentcard';

    /** The largest/smallest integer that survives a round trip through every language
     *  on this wire (JavaScript's Number.MAX_SAFE_INTEGER). */
    public const MAX_SAFE_INT = 9007199254740991;

    /** base58btc alphabet (Bitcoin ordering). */
    private const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

    /** Guard on the O(n^2) base58 decode: it runs BEFORE any signature check, so an
     *  unbounded `from` field would be free CPU for a stranger. A DID is ~48 chars. */
    private const MAX_B58_LEN = 512;

    // ---------------------------------------------------------------- canonical JSON

    /**
     * Canonical JSON for `$value`, as a UTF-8 string — the bytes that get signed.
     *
     * Accepts arrays (list or map), strings, ints, floats, bools and null. A PHP array is
     * treated as a JSON array when its keys are exactly 0..n-1, and as an object
     * otherwise; pass an explicit stdClass to force an object, and Wire::emptyObject()
     * for `{}` (a bare empty array would otherwise render `[]`).
     *
     * @param mixed $value
     * @throws \InvalidArgumentException when the value cannot be rendered identically in
     *         Python and JavaScript — refusing beats signing bytes only PHP can verify.
     */
    public static function canonicalJson($value): string
    {
        return self::encodeValue($value);
    }

    /** A marker for an EMPTY JSON object, which a PHP array cannot express. */
    public static function emptyObject(): \stdClass
    {
        return new \stdClass();
    }

    /** @param mixed $v */
    private static function encodeValue($v): string
    {
        if ($v === null) {
            return 'null';
        }
        if (is_bool($v)) {
            return $v ? 'true' : 'false';
        }
        if (is_int($v)) {
            if ($v > self::MAX_SAFE_INT || $v < -self::MAX_SAFE_INT) {
                // Not a formatting mismatch — SILENT DATA CORRUPTION on the JS side.
                throw new \InvalidArgumentException(
                    'canonicalJson: integer outside +/-(2**53-1): ' . $v
                );
            }
            return (string) $v;
        }
        if (is_float($v)) {
            return self::encodeFloat($v);
        }
        if (is_string($v)) {
            return self::encodeString($v);
        }
        if ($v instanceof \stdClass) {
            return self::encodeObject(get_object_vars($v));
        }
        if (is_array($v)) {
            return self::isList($v)
                ? '[' . implode(',', array_map([self::class, 'encodeValue'], $v)) . ']'
                : self::encodeObject($v);
        }
        throw new \InvalidArgumentException('canonicalJson: cannot encode ' . gettype($v));
    }

    /** True when the array is a JSON ARRAY (keys exactly 0..n-1, in order). */
    private static function isList(array $a): bool
    {
        if ($a === []) {
            return true;
        }
        return array_keys($a) === range(0, count($a) - 1);
    }

    private static function encodeObject(array $map): string
    {
        $keys = array_keys($map);
        foreach ($keys as $k) {
            if (!is_string($k)) {
                // A PHP array silently turns "1" into int 1; a JSON object key is a
                // string. Refusing beats emitting a key the other twins would not.
                throw new \InvalidArgumentException(
                    'canonicalJson: object key is not a string: ' . var_export($k, true)
                );
            }
        }
        usort($keys, [self::class, 'codePointCompare']);
        $parts = [];
        foreach ($keys as $k) {
            $parts[] = self::encodeString($k) . ':' . self::encodeValue($map[$k]);
        }
        return '{' . implode(',', $parts) . '}';
    }

    /**
     * Compare two strings by UNICODE CODE POINT — Python's `str` sort order, and what the
     * JS twin's codePointCompare does. `strcmp` compares BYTES, which agrees for ASCII
     * and diverges the moment a key is non-ASCII; UTF-8 byte order happens to match code
     * point order, but this is spelled out rather than relied on by accident.
     */
    private static function codePointCompare(string $a, string $b): int
    {
        $ca = self::codePoints($a);
        $cb = self::codePoints($b);
        $n = min(count($ca), count($cb));
        for ($i = 0; $i < $n; $i++) {
            if ($ca[$i] !== $cb[$i]) {
                return $ca[$i] < $cb[$i] ? -1 : 1;
            }
        }
        return count($ca) <=> count($cb);
    }

    /** @return int[] the string's code points, in order. */
    private static function codePoints(string $s): array
    {
        $out = [];
        $len = strlen($s);
        for ($i = 0; $i < $len;) {
            $c = ord($s[$i]);
            if ($c < 0x80) {
                $out[] = $c;
                $i += 1;
            } elseif ($c < 0xe0) {
                $out[] = (($c & 0x1f) << 6) | (ord($s[$i + 1]) & 0x3f);
                $i += 2;
            } elseif ($c < 0xf0) {
                $out[] = (($c & 0x0f) << 12) | ((ord($s[$i + 1]) & 0x3f) << 6)
                       | (ord($s[$i + 2]) & 0x3f);
                $i += 3;
            } else {
                $out[] = (($c & 0x07) << 18) | ((ord($s[$i + 1]) & 0x3f) << 12)
                       | ((ord($s[$i + 2]) & 0x3f) << 6) | (ord($s[$i + 3]) & 0x3f);
                $i += 4;
            }
        }
        return $out;
    }

    /**
     * The escape set is exactly Python's: the seven shorthands, every other control
     * character below 0x20 as lowercase `\u00xx`, and NOTHING else. Non-ASCII is emitted
     * literally (ensure_ascii=False); `/` and DEL are not escaped.
     */
    private static function encodeString(string $s): string
    {
        if (!preg_match('/[\x00-\x1f"\\\\]/', $s)) {
            self::assertEncodable($s);
            return '"' . $s . '"';
        }
        self::assertEncodable($s);
        static $short = [
            "\"" => '\\"', "\\" => '\\\\', "\x08" => '\\b', "\x0c" => '\\f',
            "\n" => '\\n', "\r" => '\\r', "\t" => '\\t',
        ];
        $out = '"';
        $len = strlen($s);
        for ($i = 0; $i < $len; $i++) {
            $ch = $s[$i];
            if (isset($short[$ch])) {
                $out .= $short[$ch];
                continue;
            }
            $o = ord($ch);
            if ($o < 0x20) {
                $out .= sprintf('\\u%04x', $o);        // lowercase hex, like Python
            } else {
                $out .= $ch;                            // includes '/' and DEL
            }
        }
        return $out . '"';
    }

    /**
     * Refuse text that is not valid UTF-8. Python's `.encode("utf-8")` RAISES on a lone
     * surrogate while other runtimes substitute U+FFFD, which would sign different bytes
     * than the sender believes were signed.
     */
    private static function assertEncodable(string $s): void
    {
        if (!self::isValidUtf8($s)) {
            throw new \InvalidArgumentException('canonicalJson: string is not valid UTF-8');
        }
    }

    private static function isValidUtf8(string $s): bool
    {
        return (bool) preg_match('//u', $s);
    }

    private static function encodeFloat(float $n): string
    {
        if (is_nan($n) || is_infinite($n)) {
            // Not JSON (RFC 8259), and no two languages agree on a spelling.
            throw new \InvalidArgumentException('canonicalJson: non-finite number');
        }
        if ($n == floor($n)) {
            // EVERY whole-valued float is refused, at any magnitude, and the magnitude is
            // exactly why the test is unconditional. Python spells float 1.0 as "1.0" and
            // int 1 as "1"; above 1e16 Python switches to "1e+16" while PHP's var_export
            // still writes "10000000000000000.0" and JavaScript writes the bare digits.
            // Three spellings of one value, so the only safe answer is to refuse and let
            // the caller send an integer. (An earlier version bounded this test by
            // MAX_SAFE_INT and therefore let 1e+16 through — caught by the
            // `exponent-threshold` vector.)
            throw new \InvalidArgumentException(
                'canonicalJson: use an integer, not a whole float (Python spells 1.0 '
                . 'differently from 1, and 1e+16 differently again)'
            );
        }
        if (abs($n) < 1e-4) {
            // Python's repr switches to exponent notation below 1e-4; PHP does not.
            throw new \InvalidArgumentException(
                'canonicalJson: float too small to render identically'
            );
        }
        $rendered = var_export($n, true);
        if (strpos($rendered, 'e') !== false || strpos($rendered, 'E') !== false) {
            throw new \InvalidArgumentException(
                'canonicalJson: float needs exponent notation, which Python and '
                . 'JavaScript spell differently — use an integer'
            );
        }
        return $rendered;
    }

    // ---------------------------------------------------------------- base58btc + did:key

    /** Raw bytes -> base58btc. */
    public static function b58encode(string $data): string
    {
        $digits = [0];
        $len = strlen($data);
        for ($i = 0; $i < $len; $i++) {
            $carry = ord($data[$i]);
            for ($j = 0; $j < count($digits); $j++) {
                $carry += $digits[$j] << 8;
                $digits[$j] = $carry % 58;
                $carry = intdiv($carry, 58);
            }
            while ($carry > 0) {
                $digits[] = $carry % 58;
                $carry = intdiv($carry, 58);
            }
        }
        // `$digits` is little-endian and always holds at least one element, so a value of
        // ZERO renders as the single digit 0 -> '1'. That '1' is not a leading-zero-byte
        // marker and must not be emitted as one, or "\x00" would encode as "11".
        $isZero = true;
        foreach ($digits as $d) {
            if ($d !== 0) {
                $isZero = false;
                break;
            }
        }
        $out = '';
        if (!$isZero) {
            for ($i = count($digits) - 1; $i >= 0; $i--) {
                $out .= self::B58[$digits[$i]];
            }
        }
        // Each LEADING ZERO BYTE is one '1' character, preserved exactly.
        $pad = 0;
        for ($i = 0; $i < $len && $data[$i] === "\x00"; $i++) {
            $pad++;
        }
        return str_repeat('1', $pad) . $out;
    }

    /** base58btc -> raw bytes. Throws on a bad character or an over-long input. */
    public static function b58decode(string $s): string
    {
        if (strlen($s) > self::MAX_B58_LEN) {
            throw new \InvalidArgumentException('base58 input too long');
        }
        $bytes = [0];
        $len = strlen($s);
        for ($i = 0; $i < $len; $i++) {
            $p = strpos(self::B58, $s[$i]);
            if ($p === false) {
                throw new \InvalidArgumentException('base58: bad character');
            }
            $carry = $p;
            for ($j = 0; $j < count($bytes); $j++) {
                $carry += $bytes[$j] * 58;
                $bytes[$j] = $carry & 0xff;
                $carry >>= 8;
            }
            while ($carry > 0) {
                $bytes[] = $carry & 0xff;
                $carry >>= 8;
            }
        }
        $out = '';
        for ($i = count($bytes) - 1; $i >= 0; $i--) {
            $out .= chr($bytes[$i]);
        }
        $out = ltrim($out, "\x00");
        $pad = 0;
        for ($i = 0; $i < $len && $s[$i] === '1'; $i++) {
            $pad++;
        }
        return str_repeat("\x00", $pad) . $out;
    }

    /** 32-byte Ed25519 public key -> `did:key:z…`. */
    public static function didFromPublicKey(string $pub): string
    {
        if (strlen($pub) !== 32) {
            throw new \InvalidArgumentException('an ed25519 public key is 32 bytes');
        }
        return 'did:key:z' . self::b58encode("\xed\x01" . $pub);
    }

    /** `did:key:z…` -> the 32-byte Ed25519 public key. With did:key the DID IS the key,
     *  so this is the whole "key lookup" — no network, no resolver. */
    public static function publicKeyFromDid(string $did): string
    {
        if (strncmp($did, 'did:key:z', 9) !== 0) {
            throw new \InvalidArgumentException('unsupported DID method');
        }
        $raw = self::b58decode(substr($did, 9));
        if (strlen($raw) !== 34 || $raw[0] !== "\xed" || $raw[1] !== "\x01") {
            throw new \InvalidArgumentException('not an ed25519 did:key');
        }
        return substr($raw, 2);
    }

    /** The 32-byte public key a seed controls. */
    public static function publicKeyFromSeed(string $seed): string
    {
        if (strlen($seed) !== SODIUM_CRYPTO_SIGN_SEEDBYTES) {
            throw new \InvalidArgumentException('an ed25519 seed is 32 bytes');
        }
        $pair = sodium_crypto_sign_seed_keypair($seed);
        return sodium_crypto_sign_publickey($pair);
    }

    /** The did:key a seed controls. */
    public static function didFromSeed(string $seed): string
    {
        return self::didFromPublicKey(self::publicKeyFromSeed($seed));
    }

    // ---------------------------------------------------------------- signing

    /**
     * The SIX frozen signed fields, canonicalized. Nothing else is signed: replyTo, auto,
     * group and the rest ride as UNSIGNED metadata. `timestamp` is passed through as
     * given and never coerced.
     *
     * @param mixed $timestamp
     */
    public static function signingPayload(
        ?string $contextId,
        string $from,
        string $messageId,
        string $text,
        $timestamp,
        string $to
    ): string {
        return self::canonicalJson([
            'contextId' => $contextId,
            'from' => $from,
            'messageId' => $messageId,
            'text' => $text,
            'timestamp' => $timestamp,
            'to' => $to,
        ]);
    }

    /** base64 (standard alphabet, WITH padding) of the signature over the six fields. */
    public static function signEnvelope(
        string $seed,
        ?string $contextId,
        string $from,
        string $messageId,
        string $text,
        $timestamp,
        string $to
    ): string {
        $payload = self::signingPayload($contextId, $from, $messageId, $text, $timestamp, $to);
        $pair = sodium_crypto_sign_seed_keypair($seed);
        $secret = sodium_crypto_sign_secretkey($pair);
        return base64_encode(sodium_crypto_sign_detached($payload, $secret));
    }

    /**
     * Verify a message envelope against the DID that claims to have sent it.
     *
     * Returns false rather than throwing on ANY malformed input: this runs on bytes a
     * stranger chose, and a parse error and a bad signature are the same answer to the
     * only question being asked.
     *
     * @param mixed $timestamp
     */
    /**
     * The bytes of a standard-base64 signature that has EXACTLY ONE spelling, or null.
     *
     * `base64_decode($s, true)` refuses characters outside the alphabet, which is most of
     * the way — but not all of it, and the remainder is the part nobody expects. A 64-byte
     * signature encodes to 88 characters ending `==`, so its final data character carries
     * six bits of which the decoder reads two and DISCARDS FOUR. All sixteen characters
     * sharing those two bits decode to the identical signature, so one signature had
     * sixteen names, and a peer that logs or de-duplicates by the literal `sig` string saw
     * sixteen messages where there was one. Measured against this plugin on PHP 7.4 and
     * 8.3: the wire vectors' `sig-not-canonical-base64` case, which is exactly such a
     * sibling, verified TRUE here while the JavaScript, Python, Go and Rust references all
     * refused it. That is a split in the contract, not a cosmetic difference.
     *
     * The rule the other four settled on, character for character: the standard alphabet
     * with at most two trailing `=`, a length that is a multiple of 4, and — the leg that
     * actually makes the mapping one-to-one — the decoded bytes must RE-ENCODE to the
     * string that arrived. The encoder writes those spare bits as zero, so re-encoding
     * names the one member of the family a standard encoder would have produced.
     */
    private static function strictB64(?string $value): ?string
    {
        if ($value === null || $value === '' || strlen($value) % 4 !== 0) {
            return null;
        }
        if (preg_match('/\A[A-Za-z0-9+\/]*={0,2}\z/', $value) !== 1) {
            return null;
        }
        $raw = base64_decode($value, true);
        if ($raw === false || base64_encode($raw) !== $value) {
            return null;
        }
        return $raw;
    }

    public static function verifyEnvelope(
        string $from,
        string $to,
        string $messageId,
        ?string $contextId,
        $timestamp,
        string $text,
        ?string $sigB64
    ): bool {
        if ($sigB64 === null || $sigB64 === '') {
            return false;
        }
        try {
            $pub = self::publicKeyFromDid($from);
            $sig = self::strictB64($sigB64);
            if ($sig === null || strlen($sig) !== SODIUM_CRYPTO_SIGN_BYTES) {
                return false;
            }
            $payload = self::signingPayload($contextId, $from, $messageId, $text, $timestamp, $to);
            return sodium_crypto_sign_verify_detached($sig, $payload, $pub);
        } catch (\Throwable $e) {
            return false;
        }
    }

    // ---------------------------------------------------------------- the card envelope

    /** The canonical bytes a card envelope signs over. */
    public static function cardEnvelopePayload(array $card, int $ts): string
    {
        return self::canonicalJson([
            'card' => $card,
            'ts' => $ts,
            'typ' => self::CARD_ENVELOPE_TYPE,
            'v' => self::CARD_ENVELOPE_VERSION,
        ]);
    }

    /**
     * Wrap `$card` in the signed envelope served at /.well-known/agent-card.sig.json.
     *
     * `$ts` MUST be an integer epoch: a consumer rejects an envelope older than 6 h (and
     * one dated in the future), so this is a freshness window rather than a cache tweak —
     * without it a saved copy would still "prove" ownership to whoever holds the origin
     * next. That is also why a static file cannot be a door: something must re-sign this.
     */
    public static function makeCardEnvelope(string $seed, array $card, int $ts): array
    {
        $payload = self::cardEnvelopePayload($card, $ts);
        $pair = sodium_crypto_sign_seed_keypair($seed);
        $secret = sodium_crypto_sign_secretkey($pair);
        return [
            'v' => self::CARD_ENVELOPE_VERSION,
            'typ' => self::CARD_ENVELOPE_TYPE,
            'card' => $card,
            'ts' => $ts,
            'sig' => base64_encode(sodium_crypto_sign_detached($payload, $secret)),
        ];
    }

    // ---------------------------------------------------------------- misc

    /** A fresh 32-byte seed from the system CSPRNG. */
    public static function newSeed(): string
    {
        return random_bytes(SODIUM_CRYPTO_SIGN_SEEDBYTES);
    }

    /** A random message/context id, in the shape the other twins emit. */
    public static function newId(): string
    {
        return bin2hex(random_bytes(16));
    }

    /**
     * Serve JSON as the bytes a peer reads. Uses canonical encoding so the card served at
     * two paths is byte-identical at both, which the contract requires of the legacy
     * `/agent.json` alias.
     */
    public static function jsonBytes($value): string
    {
        return self::canonicalJson($value);
    }
}
