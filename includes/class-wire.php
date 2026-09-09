<?php
/**
 * seam.php — the byte contract, in PHP.
 *
 * The fifth reference implementation. It is here for the same reason Go and Rust are: a
 * contract with one implementation is a program, and every split this repository has
 * caught was found by a second implementation disagreeing with the first. This one was
 * written for the WordPress plugin and lived there, which meant the seam's own suite
 * never ran it — so when `js/seam.mjs` was found accepting a small-order signature on
 * Node 22 (2026-09-09), answering "is PHP exposed too?" meant going to another
 * repository. That is the wrong shape for a question about the contract.
 *
 * The plugin now vendors this file and adds its own `ABSPATH` guard as a recorded
 * transform. Nothing here knows about WordPress.
 *
 * WHY THIS FILE KNOWS NOTHING ABOUT ITS CONSUMER. Everything here is pure PHP, because
 * these are the bytes four other implementations already agreed on: `js/seam.mjs`,
 * `python/shared/`, `go/seam.go` and `rust/src/lib.rs`. A fifth implementation earns
 * nothing by being clever: it must produce THE SAME BYTES or the signature it makes is
 * worthless to every existing verifier. Staying framework-free means it runs in a bare
 * `php php/conformance.php` against the same golden vectors the other four are held to,
 * without booting anything — and it means the WordPress plugin can vendor it whole and
 * add its own guard, rather than the contract having to know a CMS exists.
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

    /**
     * `messageId` ceiling, in UTF-8 BYTES — the same number and the same unit as
     * `MAX_MESSAGE_ID_BYTES` in the JavaScript door.
     *
     * The id is the replay table's KEY and was bounded only by the 1 MiB body cap, so a
     * stranger could hand the door most of a megabyte of key per request and it would be
     * held for REPLAY_TTL_S. `WpdbStore::seenMessage` hashes the id to a fixed width, so
     * the KEY is safe here — but a hash bounds the key, not the REQUEST, and the shape
     * gate is what says how big a messageId may be.
     *
     * A DOOR-LOCAL RULE, stated rather than hidden: the seam pins MAX_TEXT_BYTES and
     * MAX_BODY_BYTES and not this, so until an agent-seam release adds it the Python
     * reference still accepts an id all three doors refuse — a divergence chosen
     * knowingly, and one that errs towards refusing.
     */
    public const MAX_MESSAGE_ID_BYTES = 256;

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
            if (!self::ed25519WireOk($pub, $sig)) {
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

    // ------------------------------------------------- device-key binding v2 (T102)
    //
    // THE ACCOUNT LAYER. A message may carry a countersigned DeviceKeyBinding v2 in
    // `metadata.binding`, proving that the DEVICE DID which signed it belongs to an OWNER
    // DID — which is how one person's phone, laptop and watch are one customer rather than
    // three strangers. This is the third implementation of
    // shared/keybinding.verify_device_binding_v2 (Python) / `verifyDeviceBindingV2`
    // (JavaScript) — Go and Rust carry no binding, so three is the whole set — and it is
    // byte-pinned by the `bindingV2` group of this repository's own vectors.
    //
    // TWO SIGNATURES OVER THE SAME BYTES: the OWNER (root) signs, and the DEVICE
    // countersigns. The countersignature is the whole point of v2 — without it a foreign
    // owner could claim someone else's device by signing a statement about it. `typ` lives
    // INSIDE the signed bytes (domain separation), and ts/validUntil are INTEGERS because a
    // float's repr is bytes only Python reproduces.

    /** `typ` of the countersigned account binding (shared/keybinding.BINDING_V2_TYP). */
    public const BINDING_V2_TYP = 'muretai/devicebinding/2';

    /**
     * SPKI DER prefix for a P-256 public key carrying a COMPRESSED SEC1 point (33 bytes):
     * SEQUENCE { SEQUENCE { id-ecPublicKey, prime256v1 }, BIT STRING (34) }. OpenSSL accepts
     * compressed points on both PHP baselines this plugin supports (measured: 1.1.1 under
     * php:7.4 and 3.x under php:8.3), so the did:key point embeds directly and no point
     * decompression — which would need GMP, absent from stock builds — is required.
     */
    private const P256_SPKI_PREFIX =
        "\x30\x39\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d"
        . "\x03\x01\x07\x03\x22\x00";

    /** The longest ASN.1 DER an ECDSA-P-256 signature can be: SEQUENCE of two INTEGERs of
     *  at most 33 content bytes each (32 plus the 0x00 a high bit forces) plus tag+length.
     *  A ceiling, not an equality: r and s shrink when they have leading zero bytes. */
    private const MAX_P256_DER_SIG_BYTES = 72;

    /** True when this host can verify a P-256 (ES256) signature at all. Stock PHP builds
     *  carry ext-openssl, but it is a compile-time option, so this is a question and not an
     *  assumption — see Entry::resolveAccount for what a "no" costs. */
    public static function p256Available(): bool
    {
        return extension_loaded('openssl')
            && function_exists('openssl_verify')
            && function_exists('openssl_pkey_get_public');
    }

    /**
     * `did:key:z…` -> ['curve' => 'ed25519'|'p256', 'key' => raw bytes].
     *
     * The curve-agnostic sibling of `publicKeyFromDid`, which stays Ed25519-only on
     * purpose: the message envelope is always Ed25519 and the conformance walk asserts a
     * p256 DID is REFUSED there. Only the BINDING has a second curve, because an owner root
     * may be a Secure Enclave / WebAuthn key.
     *
     * @return array{curve:string,key:string}
     */
    public static function decodeDidKey(string $did): array
    {
        if (strncmp($did, 'did:key:z', 9) !== 0) {
            throw new \InvalidArgumentException('unsupported DID method');
        }
        $raw = self::b58decode(substr($did, 9));
        if (strlen($raw) === 34 && $raw[0] === "\xed" && $raw[1] === "\x01") {
            return ['curve' => 'ed25519', 'key' => substr($raw, 2)];    // 0xed01
        }
        if (strlen($raw) === 35 && $raw[0] === "\x80" && $raw[1] === "\x24") {
            return ['curve' => 'p256', 'key' => substr($raw, 2)];       // varint(0x1200)
        }
        throw new \InvalidArgumentException('unsupported did:key multicodec');
    }

    /** The curve a did:key names, for a caller that needs the curve before the key. */
    public static function didKeyCurve(string $did): string
    {
        return self::decodeDidKey($did)['curve'];
    }

    /** One ASN.1 DER INTEGER from a fixed-width big-endian ECDSA component. */
    private static function derInteger(string $b): string
    {
        $b = ltrim($b, "\x00");
        if ($b === '') {
            $b = "\x00";
        }
        if ((ord($b[0]) & 0x80) !== 0) {
            $b = "\x00" . $b;               // DER INTEGERs are signed; keep it positive
        }
        return "\x02" . chr(strlen($b)) . $b;
    }

    /**
     * Verify an ES256 signature over `$message` for a 33-byte compressed P-256 point.
     * Accepts BOTH encodings clients emit, exactly as the two references do: raw r||s (64
     * bytes, WebCrypto / IEEE P1363) and ASN.1 DER (Secure Enclave / WebAuthn). Never
     * throws.
     */
    private static function p256Verify(string $compPoint, string $signature, string $message): bool
    {
        if (strlen($compPoint) !== 33 || !self::p256Available()) {
            return false;
        }
        $pem = "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode(self::P256_SPKI_PREFIX . $compPoint), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
        $key = @openssl_pkey_get_public($pem);
        if ($key === false) {
            while (@openssl_error_string() !== false) {
                // Drain the queue: a failure here must not surface on someone else's verify.
            }
            return false;
        }
        if (strlen($signature) === 64) {
            $seq = self::derInteger(substr($signature, 0, 32)) . self::derInteger(substr($signature, 32));
            $signature = "\x30" . chr(strlen($seq)) . $seq;
        }
        $ok = @openssl_verify($message, $signature, $key, OPENSSL_ALGO_SHA256);
        while (@openssl_error_string() !== false) {
            // As above: openssl_verify() pushes onto the same queue for a malformed DER.
        }
        if (PHP_VERSION_ID < 80000 && is_resource($key)) {
            openssl_free_key($key);
        }
        return $ok === 1;
    }

    /** The byte-level gate every Ed25519 verification here opens with — the twin of
     *  `_ed25519_wire_ok` in agent-seam's python/shared/crypto.py and `ed25519WireOk` in
     *  js/seam.mjs, carrying the same fourteen encodings.
     *
     *  libsodium already refuses these, and has done so deliberately for years — measured
     *  here on 1.0.22, `sodium_crypto_sign_verify_detached` refuses the identity point
     *  while verifying a genuine signature through the same call. So this file was never
     *  exposed. It is added anyway, because "the host refuses it" is exactly what was
     *  believed about the JavaScript twin until 2026-09-09, when `node:crypto` was measured
     *  answering FALSE on Node 26.5.1 and TRUE on Node 22.23.2 for these same bytes, at the
     *  same reported OpenSSL. One implementation that asks its host is one implementation
     *  whose verdict is a property of the host.
     *
     *  Four refusals: the public key and the signature's R component are each refused as a
     *  small-order encoding, and each refused when y is not reduced below p — a decoder that
     *  masks y to 255 bits would otherwise read two spellings as one point. */
    private static function ed25519WireOk(string $pub, string $sig): bool
    {
        static $small = [
            // y = 0 (x = +-sqrt(-1)) -- order 4
            '0000000000000000000000000000000000000000000000000000000000000000' => 1,
            '0000000000000000000000000000000000000000000000000000000000000080' => 1,
            // y = 1 (x = 0) -- order 1: the IDENTITY, the element that signs everything
            '0100000000000000000000000000000000000000000000000000000000000000' => 1,
            '0100000000000000000000000000000000000000000000000000000000000080' => 1,
            // order 8
            '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05' => 1,
            '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85' => 1,
            // order 8 (the other one)
            'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a' => 1,
            'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa' => 1,
            // y = p-1 (x = 0) -- order 2
            'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f' => 1,
            'ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' => 1,
            // y = p, i.e. y == 0 -- the NON-CANONICAL spelling of the order-4 point
            'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f' => 1,
            'edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' => 1,
            // y = p+1, i.e. y == 1 -- the NON-CANONICAL spelling of the IDENTITY
            'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f' => 1,
            'eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' => 1,
        ];
        if (strlen($pub) !== 32 || strlen($sig) < 32) {
            return false;
        }
        $r = substr($sig, 0, 32);
        if (isset($small[bin2hex($pub)]) || isset($small[bin2hex($r)])) {
            return false;
        }
        return self::yReduced($pub) && self::yReduced($r);
    }

    /** True when the little-endian y of a 32-byte point, with the sign bit cleared, is
     *  below p = 2^255 - 19. No bignum extension: the top byte is masked and the value is
     *  compared against p byte by byte from the most significant end. */
    private static function yReduced(string $point): bool
    {
        $p = "\xed\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
           . "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f";
        $y = $point;
        $y[31] = chr(ord($y[31]) & 0x7f);
        for ($i = 31; $i >= 0; $i--) {
            $a = ord($y[$i]);
            $b = ord($p[$i]);
            if ($a !== $b) {
                return $a < $b;
            }
        }
        return false;   // equal to p is not reduced
    }

    /** Curve-dispatching signature verify against a did:key — a binding's owner may be
     *  Ed25519 OR P-256; the device is always Ed25519. Total and fail-closed. */
    private static function verifyDidSig(string $did, string $signature, string $message): bool
    {
        try {
            $k = self::decodeDidKey($did);
            if ($k['curve'] === 'ed25519') {
                return strlen($signature) === SODIUM_CRYPTO_SIGN_BYTES
                    && self::ed25519WireOk($k['key'], $signature)
                    && sodium_crypto_sign_verify_detached($signature, $message, $k['key']);
            }
            return self::p256Verify($k['key'], $signature, $message);
        } catch (\Throwable $e) {
            return false;
        }
    }

    /** The canonical bytes BOTH keys sign (shared/keybinding._binding_v2_payload). Keys are
     *  sorted by code point, so the order written here is irrelevant; the emitted bytes are
     *  {"deviceDid":…,"rootDid":…,"ts":…,"typ":…,"validUntil":…}. */
    public static function bindingV2Payload(string $rootDid, string $deviceDid, int $ts,
                                            int $validUntil): string
    {
        return self::canonicalJson([
            'typ' => self::BINDING_V2_TYP,
            'rootDid' => $rootDid,
            'deviceDid' => $deviceDid,
            'ts' => $ts,
            'validUntil' => $validUntil,
        ]);
    }

    /** An integer this wire can render — the same bound `canonicalJson` enforces, and the
     *  same predicate as JavaScript's `Number.isSafeInteger`. @param mixed $v */
    private static function isSafeInt($v): bool
    {
        return is_int($v) && $v >= -self::MAX_SAFE_INT && $v <= self::MAX_SAFE_INT;
    }

    /**
     * Verify a v2 binding. TOTAL on untrusted input: returns false, never throws — this
     * runs on wire metadata a stranger chose.
     *
     * ALL of these must hold, in this order (the cheap structural pins before any crypto):
     * `typ` matches; rootDid and deviceDid are non-empty strings; ts and validUntil are
     * INTEGERS inside the safe range; `$expectedDeviceDid`, when given, equals deviceDid
     * (the anti-copy pin — a binding lifted off another sender's message fails); `$now`
     * given and validUntil non-zero -> not expired; the OWNER signed the canonical five
     * fields; the DEVICE countersigned the same bytes.
     *
     * Both signature lengths are BOUNDED before they reach a verifier. The device is always
     * Ed25519, so its countersignature is exactly 64 bytes and anything else is not a
     * countersignature. The owner is the one signature here that is not always 64: a
     * Secure-Enclave owner emits ~70-72 bytes of DER, so the bound is read per curve from
     * the owner's own did:key (junk there throws, and the enclosing catch answers false).
     *
     * @param mixed $binding a decoded JSON object: an array, or a stdClass
     * @param int|float|null $now epoch seconds, or null to skip the expiry check
     */
    public static function verifyDeviceBindingV2($binding, $now = null,
                                                 ?string $expectedDeviceDid = null): bool
    {
        try {
            if ($binding instanceof \stdClass) {
                $binding = get_object_vars($binding);
            }
            if (!is_array($binding)) {
                return false;
            }
            if (($binding['typ'] ?? null) !== self::BINDING_V2_TYP) {
                return false;
            }
            $rootDid = $binding['rootDid'] ?? null;
            $deviceDid = $binding['deviceDid'] ?? null;
            $ts = $binding['ts'] ?? null;
            $validUntil = $binding['validUntil'] ?? null;
            if (!is_string($rootDid) || $rootDid === '') {
                return false;
            }
            if (!is_string($deviceDid) || $deviceDid === '') {
                return false;
            }
            if (!self::isSafeInt($ts) || !self::isSafeInt($validUntil)) {
                return false;
            }
            if ($expectedDeviceDid !== null && $deviceDid !== $expectedDeviceDid) {
                return false;
            }
            if ($now !== null && $validUntil !== 0 && $now > $validUntil) {
                return false;
            }
            $sig = self::strictB64(is_string($binding['sig'] ?? null) ? $binding['sig'] : null);
            $deviceSig = self::strictB64(
                is_string($binding['deviceSig'] ?? null) ? $binding['deviceSig'] : null);
            if ($sig === null || $deviceSig === null) {
                return false;
            }
            if (strlen($deviceSig) !== SODIUM_CRYPTO_SIGN_BYTES) {
                return false;
            }
            $ownerCurve = self::decodeDidKey($rootDid)['curve'];
            if ($ownerCurve === 'ed25519'
                ? strlen($sig) !== SODIUM_CRYPTO_SIGN_BYTES
                : strlen($sig) > self::MAX_P256_DER_SIG_BYTES) {
                return false;
            }
            $payload = self::bindingV2Payload($rootDid, $deviceDid, $ts, $validUntil);
            return self::verifyDidSig($rootDid, $sig, $payload)
                && self::verifyDidSig($deviceDid, $deviceSig, $payload);
        } catch (\Throwable $e) {
            return false;
        }
    }

    /** Sign a v2 binding with an owner seed and a device seed. TESTS AND TOOLING ONLY — a
     *  door verifies bindings, it never mints them — but a verifier nobody can produce
     *  input for is a verifier nobody can prove says yes. */
    public static function makeDeviceBindingV2(string $ownerSeed, string $deviceSeed,
                                               int $ts, int $validUntil): array
    {
        $rootDid = self::didFromSeed($ownerSeed);
        $deviceDid = self::didFromSeed($deviceSeed);
        $payload = self::bindingV2Payload($rootDid, $deviceDid, $ts, $validUntil);
        $ownerSecret = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($ownerSeed));
        $deviceSecret = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($deviceSeed));
        return [
            'typ' => self::BINDING_V2_TYP,
            'rootDid' => $rootDid,
            'deviceDid' => $deviceDid,
            'ts' => $ts,
            'validUntil' => $validUntil,
            'sig' => base64_encode(sodium_crypto_sign_detached($payload, $ownerSecret)),
            'deviceSig' => base64_encode(sodium_crypto_sign_detached($payload, $deviceSecret)),
        ];
    }

    // ------------------------------------------------------- the messageId shape rule

    /**
     * PYTHON'S WHITESPACE SET, code point for code point. `str.strip()` (which
     * `shared/protocol.message_id_ok` applies) strips exactly these; PHP's `trim()` strips
     * a DIFFERENT and much narrower set, and the difference is not cosmetic:
     *
     *   - PHP's default list is " \t\n\r\0\x0B" — BYTES. It misses FORM FEED (0x0c), which
     *     both other implementations strip, misses every non-ASCII space, and strips NUL,
     *     which neither of the others does.
     *   - Python additionally strips 0x1c-0x1f (the file/group/record/unit separators) and
     *     0x85 (NEL); JavaScript's `trim()` does not.
     *   - JavaScript additionally strips 0xfeff (the BOM / zero-width no-break space);
     *     Python does not.
     *   - NEITHER strips 0x200b (ZERO WIDTH SPACE), so `"\u{200b}"` is a legal messageId on
     *     all three. It looks empty and is not; that is the contract, not an oversight.
     *
     * So `trim($id) === ''` would have been a fourth answer. This list is Python's, because
     * Python is the reference the other two are being aligned to.
     */
    private const PY_STRIP_CODEPOINTS = [
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x85, 0xa0,
        0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007,
        0x2008, 0x2009, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000,
    ];

    /**
     * True when `$messageId` can key the replay table — the PHP twin of
     * `shared/protocol.message_id_ok`, whose whole body is
     * `isinstance(message_id, str) and bool(message_id.strip())`.
     *
     * WHY WHITESPACE IS NOT A MESSAGE ID. It is a SIGNED field and the dedup key. An id of
     * three spaces was accepted here and by the JavaScript door — each answering with a
     * signed reply and minting a customer row — while the Python reference refused it; the
     * same bytes, two verdicts, which is the double-book class this contract exists to
     * close. It is also a usable dedup key on the side that accepts it and not a message at
     * all on the side that does not, so the replay table itself disagrees.
     *
     * @param mixed $messageId
     */
    public static function messageIdOk($messageId): bool
    {
        if (!is_string($messageId) || $messageId === '') {
            return false;
        }
        if (!self::isValidUtf8($messageId)) {
            // Not decodable text, so not whitespace either: this gate says yes and the
            // canonicaliser refuses it a step later, where the refusal names the real
            // reason. `codePoints` below assumes well-formed UTF-8.
            return true;
        }
        foreach (self::codePoints($messageId) as $cp) {
            if (!in_array($cp, self::PY_STRIP_CODEPOINTS, true)) {
                return true;            // one non-whitespace code point is enough
            }
        }
        return false;                   // empty once stripped: `bool("".strip())` is False
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
