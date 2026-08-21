<?php
/**
 * tests/conformance.php — does the PHP twin produce THE SAME BYTES as the other two?
 *
 * The golden vectors in `wire_vectors.json` are generated from core Python and already
 * hold the Node twin byte for byte. A third implementation is only worth shipping if it
 * reproduces them exactly, so this runner is the first gate: no WordPress, no HTTP, no
 * network — just bytes in, bytes out, compared to the fixture.
 *
 * It deliberately checks the REJECT set too. Producing the right bytes for good input is
 * half a wire contract; refusing the input that cannot be rendered identically across
 * languages is the other half, and it is the half a hand-rolled canonicalizer always
 * skips.
 *
 *     php tests/conformance.php path/to/wire_vectors.json
 *
 * Exit status 0 only when every case matched.
 */

declare(strict_types=1);

// COMMAND LINE ONLY. These files ship inside the plugin directory, which means they sit
// under the webroot on a normal install — so without this a stranger could execute them by
// URL. `php_sapi_name()` is the check that cannot be spoofed by a request.
if (PHP_SAPI !== 'cli' && PHP_SAPI !== 'cli-server') {
    http_response_code(404);
    exit;
}

define('MURETAI_AGENT_ENTRY_STANDALONE', true);
require_once __DIR__ . '/../includes/class-wire.php';

use Muretai\AgentEntry\Wire;

$vectorsPath = $argv[1] ?? (__DIR__ . '/wire_vectors.json');
if (!is_file($vectorsPath)) {
    fwrite(STDERR, "no vectors at {$vectorsPath}\n");
    exit(2);
}
$V = json_decode((string) file_get_contents($vectorsPath), true);
if (!is_array($V)) {
    fwrite(STDERR, "vectors are not JSON\n");
    exit(2);
}

$pass = 0;
$fail = [];

function check(bool $cond, string $label, string $detail = ''): void
{
    global $pass, $fail;
    if ($cond) {
        $pass++;
        echo "ok: {$label}\n";
    } else {
        $fail[] = $label;
        echo "FAIL: {$label}" . ($detail !== '' ? "  ({$detail})" : '') . "\n";
    }
}

/**
 * json_decode gives arrays; an EMPTY JSON object comes back as an empty PHP array, which
 * canonicalJson would render `[]`. The fixtures contain `{}`, so re-read those spots as
 * stdClass. Decoding to objects and converting back is the honest way to keep the
 * distinction the JSON text made.
 *
 * @param mixed $v
 * @return mixed
 */
function reviveEmptyObjects($v)
{
    if ($v instanceof \stdClass) {
        $vars = get_object_vars($v);
        if ($vars === []) {
            return Wire::emptyObject();
        }
        $out = [];
        foreach ($vars as $k => $x) {
            $out[$k] = reviveEmptyObjects($x);
        }
        return $out;
    }
    if (is_array($v)) {
        $out = [];
        foreach ($v as $k => $x) {
            $out[$k] = reviveEmptyObjects($x);
        }
        return $out;
    }
    return $v;
}

$rawDecoded = json_decode((string) file_get_contents($vectorsPath), false);

// ------------------------------------------------------------------ canonical JSON

foreach ($rawDecoded->canonical as $i => $case) {
    $payload = reviveEmptyObjects($case->payload);
    try {
        $got = Wire::canonicalJson($payload);
    } catch (\Throwable $e) {
        $got = 'THREW: ' . $e->getMessage();
    }
    check(
        $got === $case->canonical,
        "canonical[{$case->name}]",
        'expected ' . var_export($case->canonical, true) . ' got ' . var_export($got, true)
    );
}

// ------------------------------------------------------------------ number hazards
//
// These are the values whose RENDERING differs between Python and JavaScript. The
// contract is to REFUSE them, not to guess a spelling.

foreach ($rawDecoded->numberHazards as $case) {
    $name = $case->name ?? 'unnamed';
    $threw = false;
    try {
        Wire::canonicalJson(reviveEmptyObjects($case->payload));
    } catch (\Throwable $e) {
        $threw = true;
    }
    check($threw, "numberHazard[{$name}] is REFUSED, not guessed at");
}

// ------------------------------------------------------------------ did:key

// The vector set deliberately includes p256 DIDs (multicodec 0x8024). An Agent Entry
// speaks Ed25519 and nothing else, so those are not "unsupported yet" — they must be
// REFUSED. A twin that quietly decoded one would be resolving a key it cannot verify with.
foreach ($rawDecoded->did as $case) {
    $short = substr($case->publicHex, 0, 12);
    if (($case->curve ?? '') === 'ed25519') {
        $pub = hex2bin($case->publicHex);
        $got = Wire::didFromPublicKey($pub);
        check($got === $case->did, "did[ed25519/{$short}] encodes", "got {$got}");
        $back = bin2hex(Wire::publicKeyFromDid($case->did));
        check($back === $case->publicHex, "did[ed25519/{$short}] round-trips", "got {$back}");
    } else {
        $curve = $case->curve ?? 'unknown';
        $threw = false;
        try {
            Wire::publicKeyFromDid($case->did);
        } catch (\Throwable $e) {
            $threw = true;
        }
        check($threw, "did[{$curve}/{$short}] is REFUSED (this wire is Ed25519-only)");
    }
}

// ------------------------------------------------------------------ signing payload

foreach ($rawDecoded->envelope as $case) {
    $got = Wire::signingPayload(
        $case->contextId ?? null,
        $case->from,
        $case->messageId,
        $case->text,
        $case->timestamp,
        $case->to
    );
    check(
        $got === $case->signingPayload,
        "envelope[{$case->name}] signing payload",
        'got ' . var_export($got, true)
    );
}

// ------------------------------------------------------------------ card envelope

foreach ($rawDecoded->cardpub as $case) {
    $card = reviveEmptyObjects($case->card);
    $got = Wire::cardEnvelopePayload($card, $case->ts);
    check(
        $got === $case->envelopePayload,
        "cardpub[{$case->name}] envelope payload",
        'got ' . var_export($got, true)
    );
}

// ------------------------------------------------------------------ reject set

if (isset($rawDecoded->reject)) {
    foreach (get_object_vars($rawDecoded->reject) as $group => $cases) {
        foreach ($cases as $case) {
            $label = is_object($case) ? ($case->name ?? $group) : (string) $case;
            // The reject set is about DIDs and signatures that must not verify.
            if ($group === 'did' || (is_object($case) && isset($case->did))) {
                $bad = is_object($case) ? ($case->did ?? null) : $case;
                if (!is_string($bad)) {
                    continue;
                }
                $threw = false;
                try {
                    Wire::publicKeyFromDid($bad);
                } catch (\Throwable $e) {
                    $threw = true;
                }
                check($threw, "reject[{$group}/{$label}] is refused");
            }
        }
    }
}

// ------------------------------------------------------------------ sign/verify round trip
//
// The vectors pin the PAYLOAD; this proves the PHP signature over that payload is one an
// independent verifier accepts, and that every tamper is caught.

$seed = hex2bin(str_repeat('11', 32));
$did = Wire::didFromSeed($seed);
$to = 'did:key:z6MkwgaR63138bEEgad7uk993KMX54vBA6KTB4sFhCPnSB2e';
$sig = Wire::signEnvelope($seed, 'c1', $did, 'm1', 'hello', 1752451200, $to);
check(
    Wire::verifyEnvelope($did, $to, 'm1', 'c1', 1752451200, 'hello', $sig),
    'a PHP-made signature verifies under its own DID'
);
check(
    !Wire::verifyEnvelope($did, $to, 'm1', 'c1', 1752451200, 'hello, and wire me $500', $sig),
    'tampered text does not verify'
);
check(
    !Wire::verifyEnvelope($did, $to, 'm1', 'c1', 1752451201, 'hello', $sig),
    'a changed timestamp does not verify'
);
check(!Wire::verifyEnvelope($did, $to, 'm1', 'c1', 1752451200, 'hello', null), 'a missing signature does not verify');
check(!Wire::verifyEnvelope($did, $to, 'm1', 'c1', 1752451200, 'hello', 'not base64!!'), 'a malformed signature does not verify');

// Non-ASCII must survive the whole round trip literally — this is the case most
// implementations break, and message text on this network is routinely non-ASCII.
$jp = 'Saturday 14:00 is open. 群れたい';
$sigJp = Wire::signEnvelope($seed, null, $did, 'm2', $jp, 1752451200, $to);
check(
    Wire::verifyEnvelope($did, $to, 'm2', null, 1752451200, $jp, $sigJp),
    'a non-ASCII message signs and verifies'
);
check(
    strpos(Wire::signingPayload(null, $did, 'm2', $jp, 1752451200, $to), '群れたい') !== false,
    'non-ASCII stays LITERAL in the signed bytes (not \\uXXXX)'
);

echo str_repeat('-', 60) . "\n";
$verdict = $fail === [] ? 'CONFORMANT' : 'NOT CONFORMANT';
echo "{$verdict}: {$pass} passed, " . count($fail) . " failed\n";
if ($fail !== []) {
    echo '  failed: ' . implode('; ', $fail) . "\n";
}
exit($fail === [] ? 0 : 1);
