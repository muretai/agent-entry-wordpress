<?php
/**
 * tests/conformance.php — does the PHP twin produce THE SAME BYTES as the other two?
 *
 * The golden vectors are agent-seam's vectors/wire_vectors.json, vendored here as
 * `tests/wire_vectors.json` at the commit in tests/VENDOR.json (tests/check_vendor.php
 * holds the copy to that pin). They already hold the JavaScript door and the Python
 * reference byte for byte. A third implementation is only worth shipping if it
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
 * A vendored group, read BY NAME and floored.
 *
 * Every check in this file lives inside a `foreach` over a group of `tests/wire_vectors.json`,
 * and a `foreach` over nothing passes. That file is not ours: it arrives by re-vendoring from
 * agent-seam, so a group can be renamed, emptied or shortened upstream without a line of this
 * plugin changing — and the suite would keep printing CONFORMANT over the cases it no longer
 * walks. It has happened here: the message half of the reject set was skipped for the whole
 * life of this runner and looked exactly like a half that passed.
 *
 * So a group is taken by NAME (a rename is a recorded failure, not a silent zero) and counted
 * against what the pinned vendor carries today. Growth upstream is welcome and silent;
 * shrinkage is not. A missing or short group is reported as a failure and the walk that
 * follows gets an empty list, so the suite still runs to the end and reports everything.
 *
 * @param mixed $vectors
 * @return array<int, mixed>
 */
function vectorGroup($vectors, string $path, int $floor): array
{
    $node = $vectors;
    $seen = '';
    foreach (explode('.', $path) as $key) {
        $seen = $seen === '' ? $key : "{$seen}.{$key}";
        if (!($node instanceof \stdClass) || !property_exists($node, $key)) {
            check(false, "the vectors carry the `{$path}` group",
                "no `{$seen}` — a re-vendor renamed or dropped it, and a walk over a missing "
                . 'group checks nothing');
            return [];
        }
        $node = $node->$key;
    }
    if (!is_array($node)) {
        check(false, "`{$path}` is a list of cases", 'got ' . gettype($node));
        return [];
    }
    check(count($node) >= $floor, "`{$path}` still carries at least {$floor} case(s)",
        'got ' . count($node) . ' — a re-vendor shortened the group, and every check in the '
        . 'walk below would have passed over nothing');
    return $node;
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

foreach (vectorGroup($rawDecoded, 'canonical', 14) as $i => $case) {
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

foreach (vectorGroup($rawDecoded, 'numberHazards', 8) as $case) {
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
foreach (vectorGroup($rawDecoded, 'did', 10) as $case) {
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

foreach (vectorGroup($rawDecoded, 'envelope', 4) as $case) {
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

foreach (vectorGroup($rawDecoded, 'cardpub', 2) as $case) {
    $card = reviveEmptyObjects($case->card);
    $got = Wire::cardEnvelopePayload($card, $case->ts);
    check(
        $got === $case->envelopePayload,
        "cardpub[{$case->name}] envelope payload",
        'got ' . var_export($got, true)
    );
}

// ------------------------------------------------------------------ device binding v2
//
// THE ACCOUNT LAYER, which this plugin shipped a pin table for and never filled. A message
// may carry a countersigned DeviceKeyBinding v2 proving the DEVICE key that signed it
// belongs to an OWNER; the other two doors refuse a present-but-INVALID one with -32001 and
// mint no row, and this door used to answer it with a signed reply and a customer row.
//
// These vectors are the same ones that hold the JavaScript door and the Python reference,
// so they are the cross-implementation half. The MINT check is the sharpest of them: the
// seeds are in the fixture, Ed25519 is deterministic, so PHP's own signatures over the
// canonical payload must come out byte-identical to the recorded ones — a canonicaliser
// that put one field in the wrong place could not pass it.

// `isset` on a vendored group is itself a check that cannot fail: rename `bindingV2`
// upstream and this whole block — the account layer — disappears without a word. Say so.
check(isset($rawDecoded->bindingV2),
    'the vectors carry the `bindingV2` group this suite walks',
    'a re-vendor renamed or dropped it, and the account layer would go unchecked in silence');
if (isset($rawDecoded->bindingV2)) {
    $bv = $rawDecoded->bindingV2;
    $checkNow = $bv->checkNow;
    vectorGroup($rawDecoded, 'bindingV2.cases', 2);
    $otherDid = 'did:key:z6MkwgaR63138bEEgad7uk993KMX54vBA6KTB4sFhCPnSB2e';

    foreach ($bv->cases as $case) {
        $n = $case->name;
        $got = Wire::bindingV2Payload($case->rootDid, $case->deviceDid, $case->ts,
            $case->validUntil);
        check($got === $case->bindingPayload, "bindingV2[{$n}] signed payload",
            'got ' . var_export($got, true));

        // The control that keeps every refusal below honest: a GENUINE binding must verify.
        check(Wire::verifyDeviceBindingV2($case->binding, $checkNow, $case->deviceDid),
            "bindingV2[{$n}] verifies — this suite can still say YES");

        // Re-mint from the fixture's own seeds: both signatures byte-for-byte.
        $minted = Wire::makeDeviceBindingV2(hex2bin($case->ownerSeed),
            hex2bin($case->deviceSeed), $case->ts, $case->validUntil);
        check($minted['sig'] === $case->binding->sig,
            "bindingV2[{$n}] PHP re-mints the OWNER signature byte for byte",
            'got ' . $minted['sig']);
        check($minted['deviceSig'] === $case->binding->deviceSig,
            "bindingV2[{$n}] PHP re-mints the DEVICE countersignature byte for byte",
            'got ' . $minted['deviceSig']);

        // The anti-copy pin: this binding lifted onto another sender's message.
        check(!Wire::verifyDeviceBindingV2($case->binding, $checkNow, $otherDid),
            "bindingV2[{$n}] is refused when it does not name the sender");

        // Each signature must be CHECKED, not merely present. One flipped byte in either.
        foreach (['sig', 'deviceSig'] as $field) {
            $tampered = clone $case->binding;
            $raw = base64_decode($case->binding->$field, true);
            $raw[0] = chr(ord($raw[0]) ^ 0x01);
            $tampered->$field = base64_encode($raw);
            check(!Wire::verifyDeviceBindingV2($tampered, $checkNow, $case->deviceDid),
                "bindingV2[{$n}] with a tampered `{$field}` is refused");
        }

        // ...and one flipped byte in the SIGNED fields, which no signature then covers.
        $moved = clone $case->binding;
        $moved->ts = $case->ts + 1;
        check(!Wire::verifyDeviceBindingV2($moved, $checkNow, $case->deviceDid),
            "bindingV2[{$n}] with a moved `ts` is refused");
    }

    // EXPIRY is `now > validUntil`, and `validUntil: 0` means no expiry at all — the two
    // spellings the twins agree on, and the difference between a binding that lapses and
    // one that never does.
    foreach ($bv->cases as $case) {
        $n = $case->name;
        if ($case->validUntil === 0) {
            check(Wire::verifyDeviceBindingV2($case->binding, $checkNow + 10 * 365 * 86400,
                $case->deviceDid), "bindingV2[{$n}] validUntil 0 never expires");
            continue;
        }
        check(Wire::verifyDeviceBindingV2($case->binding, $case->validUntil, $case->deviceDid),
            "bindingV2[{$n}] is still valid ON its validUntil second");
        check(!Wire::verifyDeviceBindingV2($case->binding, $case->validUntil + 1,
            $case->deviceDid), "bindingV2[{$n}] is expired one second later");
    }

    // THE EXPECTED DEVICE COMES FROM THE CASE, never from the binding. `expectedDeviceDid`
    // was added upstream in 0.3.1 for `binding-lifted-to-another-device`, whose binding is
    // BYTE-IDENTICAL to a valid one — only the caller's expectation differs. A loop that
    // passed no expectation (this one, until now) or that read the device DID off the
    // binding could never fail that case, which is the anti-copy pin the whole field exists
    // for: a binding lifted onto another sender's message must not verify.
    foreach (vectorGroup($rawDecoded, 'bindingV2.reject', 4) as $case) {
        $expected = $case->expectedDeviceDid ?? null;
        check(!Wire::verifyDeviceBindingV2($case->input, $checkNow, $expected),
            "bindingV2 reject[{$case->name}] is refused"
            . ($expected === null ? '' : ' (as a binding for someone else\'s device)'));
    }
}

// --------------------------------------------------- a P-256 OWNER root (no vectors yet)
//
// The vendored fixtures carry Ed25519 owners only, so this branch would otherwise ship
// unexercised. An owner root MAY be P-256: that is the whole reason the hierarchy exists —
// a Secure Enclave / WebAuthn key is ES256 and cannot sign the Ed25519 wire itself, so it
// signs a binding and a software device key does the day-to-day signing. The JavaScript
// door verifies such an owner natively; the Python reference verifies it when the optional
// `cryptography` backend is present and treats it as UNBOUND when it is not.
//
// Minted in process, because a fixture cannot be: there is no P-256 seed in the vectors.
// The point is not the key, it is that the two encodings a real client emits — ASN.1 DER
// from a Secure Enclave, raw r||s from WebCrypto — both verify, and that a tamper does not.
// (Checked against the JavaScript door directly while this was written: it returns the same
// four answers for these very bytes.)

if (Wire::p256Available()) {
    $devSeed = hex2bin(str_repeat('18', 32));
    $deviceDid = Wire::didFromSeed($devSeed);
    $ec = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC,
        'curve_name' => 'prime256v1']);
    $det = openssl_pkey_get_details($ec);
    $x = str_pad($det['ec']['x'], 32, "\0", STR_PAD_LEFT);
    $y = str_pad($det['ec']['y'], 32, "\0", STR_PAD_LEFT);
    // SEC1 point compression: the parity of Y, then X. did:key multicodec 0x1200 = p256-pub.
    $rootDid = 'did:key:z' . Wire::b58encode("\x80\x24" . chr(2 + (ord($y[31]) & 1)) . $x);
    $ts = 1784273681;
    $payload = Wire::bindingV2Payload($rootDid, $deviceDid, $ts, 0);
    openssl_sign($payload, $der, $ec, OPENSSL_ALGO_SHA256);
    $devSecret = sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair($devSeed));
    $p256 = [
        'typ' => Wire::BINDING_V2_TYP, 'rootDid' => $rootDid, 'deviceDid' => $deviceDid,
        'ts' => $ts, 'validUntil' => 0, 'sig' => base64_encode($der),
        'deviceSig' => base64_encode(sodium_crypto_sign_detached($payload, $devSecret)),
    ];
    check(Wire::didKeyCurve($rootDid) === 'p256',
        'a p256 did:key is read as p256 by the BINDING decoder');
    check(Wire::verifyDeviceBindingV2($p256, $ts, $deviceDid),
        'a P-256 owner binding with an ASN.1 DER signature verifies');

    // The same signature as raw r||s (IEEE P1363 / WebCrypto), which must also verify.
    $i = 2 + ((ord($der[1]) & 0x80) ? (ord($der[1]) & 0x7f) : 0);
    $rs = '';
    for ($n = 0; $n < 2; $n++) {
        $len = ord($der[$i + 1]);
        $rs .= str_pad(ltrim(substr($der, $i + 2, $len), "\0"), 32, "\0", STR_PAD_LEFT);
        $i += 2 + $len;
    }
    $raw = $p256;
    $raw['sig'] = base64_encode($rs);
    check(strlen($rs) === 64 && Wire::verifyDeviceBindingV2($raw, $ts, $deviceDid),
        'the SAME P-256 signature as raw r||s (64 bytes) verifies too');

    $tampered = $p256;
    $bytes = base64_decode($tampered['sig'], true);
    $bytes[10] = chr(ord($bytes[10]) ^ 0x01);
    $tampered['sig'] = base64_encode($bytes);
    check(!Wire::verifyDeviceBindingV2($tampered, $ts, $deviceDid),
        'a tampered P-256 owner signature is refused');

    $foreign = $p256;
    $foreign['deviceSig'] = $p256['sig'];       // the owner's signature, not the device's
    check(!Wire::verifyDeviceBindingV2($foreign, $ts, $deviceDid),
        'a P-256 owner cannot countersign for the device (the device is always Ed25519)');
} else {
    echo "skip: no OpenSSL here, so the P-256 owner branch was not exercised\n";
}

// ------------------------------------------------------------------ reject set

// THE MESSAGE HALF, which this walk used to skip entirely. Every case below is an object
// carrying `input` rather than a bare `did`, so the DID-shaped branch further down passed
// over all of them in silence — a group nobody drives looks exactly like a group that
// passes. Driving them found a real defect: `sig-not-canonical-base64` VERIFIED here on
// PHP 7.4 and 8.3 while the four other references refused it, because `base64_decode`
// tolerates the four bits a padded signature's last character discards. Wire::strictB64
// closes it; this loop is what stops it coming back.
foreach (vectorGroup($rawDecoded, 'reject.message', 9) as $case) {
    $i = $case->input;
    // The recipient is named by US, from the case or from the message's SIGNED `to` —
    // never from an unsigned field. `wire-names-its-own-recipient` carries a
    // `recipientDid` equal to its own `to` precisely so that reading it off the wire
    // compares the message against itself and always agrees.
    $me = (isset($case->verifierNamesNoRecipient) && $case->verifierNamesNoRecipient)
        ? '' : ($case->recipientDid ?? $i->to);
    $verified = Wire::verifyEnvelope(
        $i->from, $me, $i->messageId, $i->contextId ?? null,
        $i->timestamp, $i->text, $i->sig ?? null
    );
    check(!$verified, "reject[message/{$case->name}] is refused");
}

// The control that keeps the loop above honest: one envelope signed HERE, which must
// verify. Without it, a verifyEnvelope that answered false to everything would report
// every case refused and look perfect. It reads no vector, so it runs unconditionally —
// it used to sit inside an `isset($rawDecoded->reject->message)` guard, which meant an
// upstream rename of `reject` deleted the walk AND the control that proves the walk means
// something, leaving the suite to print CONFORMANT over neither.
$ctlSeed = str_repeat("\x2b", 32);
$ctlFrom = Wire::didFromSeed($ctlSeed);
$ctlTo = Wire::didFromSeed(str_repeat("\x3c", 32));
$ctlSig = Wire::signEnvelope($ctlSeed, null, $ctlFrom, 'control-1', 'hello', 1757000000, $ctlTo);
check(
    Wire::verifyEnvelope($ctlFrom, $ctlTo, 'control-1', null, 1757000000, 'hello', $ctlSig),
    'this suite can still say YES — an envelope signed here verifies, so the refusals '
    . 'above are refusals and not a verifier that answers false to everything'
);

// ------------------------------------------------- the rest of the reject set, BY NAME
//
// WHAT USED TO BE HERE was a generic walk over `get_object_vars($rawDecoded->reject)` with a
// DID-shaped guard inside it: `if ($group === 'did' || isset($case->did))`. It drove the
// three `did` cases and walked SEVEN more in total silence — `cardpub` (3), `invite` (2),
// `claim` (2) — because those cases carry `envelope` or `input` and never a bare `did`. The
// guard was never true for any of them, in any vendored version. A group nobody drives
// prints exactly like a group that passes, and the generic shape made that invisible:
// adding a group upstream added silence, not coverage.
//
// So the reject set is a LEDGER now. Every group the vendored file carries is named here and
// accounted for — driven, or declared out of this door's reach with the reason it is out of
// reach. A rename, an addition or a removal upstream fails the census immediately instead of
// quietly changing what runs.

// Guarded, because the census is the one place a missing `reject` would be a PHP fatal
// rather than a named failure — and a runner that dies has not reported the rest of what it
// knows. An absent group becomes an empty census, which the check below names.
$rejectGroups = isset($rawDecoded->reject) && $rawDecoded->reject instanceof \stdClass
    ? array_keys(get_object_vars($rawDecoded->reject))
    : [];
sort($rejectGroups);
$expectedRejectGroups = ['cardpub', 'claim', 'did', 'encoding', 'invite', 'keystate', 'message'];
check(
    $rejectGroups === $expectedRejectGroups,
    'the reject set carries exactly the groups this suite accounts for',
    'got [' . implode(', ', $rejectGroups) . '], accounted for ['
        . implode(', ', $expectedRejectGroups) . '] — drive the new group below or say '
        . 'in one line why this door cannot'
);

// --- did (3): the did:key codec. Driven.
foreach (vectorGroup($rawDecoded, 'reject.did', 3) as $case) {
    $threw = false;
    try {
        Wire::publicKeyFromDid($case->did);
    } catch (\Throwable $e) {
        $threw = true;
    }
    check($threw, "reject[did/{$case->name}] is refused");
}

// --- cardpub (3): the card envelope, driven at last.
//
// This plugin PUBLISHES card envelopes and never consumes one, so there is no product
// verifier to call. The visitor's side is composed here from the door's own pieces —
// `cardEnvelopePayload` for the bytes, `publicKeyFromDid` for the key — exactly as
// tests/check-live.php composes it against a live door. What the three cases pin is that
// the payload builder binds the card body and `ts` tightly enough that a flipped signature
// character, another signer, or a tampered body cannot be made to verify under the DID the
// CALLER asked for (`expectedDid`, at the top level of the case, because whose card was
// asked for is the caller's idea and never the envelope's).
$verifyCardEnvelope = function ($envelope, string $expectedDid): bool {
    try {
        $card = reviveEmptyObjects($envelope->card);
        if (!is_array($card)) {
            return false;
        }
        $payload = Wire::cardEnvelopePayload($card, $envelope->ts);
        $pub = Wire::publicKeyFromDid($expectedDid);
        $raw = base64_decode((string) ($envelope->sig ?? ''), true);
        if ($raw === false || strlen($raw) !== SODIUM_CRYPTO_SIGN_BYTES) {
            return false;
        }
        return sodium_crypto_sign_verify_detached($raw, $payload, $pub);
    } catch (\Throwable $e) {
        return false;
    }
};

foreach (vectorGroup($rawDecoded, 'reject.cardpub', 3) as $case) {
    // The refusal must be the SIGNATURE and nothing cheaper. Each of these envelopes names
    // the DID the caller asked for, so a verifier that only compared the two strings would
    // accept all three — assert the bait is really there before asserting the refusal.
    check(
        ($case->envelope->card->did ?? null) === $case->expectedDid,
        "reject[cardpub/{$case->name}] names the did the caller asked for, so only the "
        . 'signature can refuse it'
    );
    check(
        !$verifyCardEnvelope($case->envelope, $case->expectedDid),
        "reject[cardpub/{$case->name}] is refused"
    );
}

// ...and the control, the same duty the message walk owes: a card envelope this door MAKES
// must verify under that composition, and must stop verifying the moment the body moves.
// Without both, "all three refused" would only mean the composition refuses everything.
$cpSeed = str_repeat("\x5d", 32);
$cpDid = Wire::didFromSeed($cpSeed);
$cpCard = ['did' => $cpDid, 'name' => 'Control', 'url' => 'https://control.example/'];
$cpEnvelope = json_decode((string) json_encode(Wire::makeCardEnvelope($cpSeed, $cpCard, 1757000000)));
check(
    $verifyCardEnvelope($cpEnvelope, $cpDid),
    'this suite can still say YES about a card envelope — one signed here verifies, so the '
    . 'cardpub refusals above are refusals and not a verifier that answers false to everything'
);
$cpTampered = json_decode((string) json_encode(Wire::makeCardEnvelope($cpSeed, $cpCard, 1757000000)));
$cpTampered->card->url = 'https://attacker.example/';
check(
    !$verifyCardEnvelope($cpTampered, $cpDid),
    'the signed card envelope binds the card BODY: moving `url` after signing stops it verifying'
);

// --- claim (2): named one at a time, because they are refused for different reasons and
// only one of those reasons belongs to this door.
$claimByName = [];
foreach (vectorGroup($rawDecoded, 'reject.claim', 2) as $case) {
    $claimByName[$case->name] = $case;
}
$verifyClaimMessage = function ($case): bool {
    $m = $case->input->message;
    return Wire::verifyEnvelope(
        $m->from, $m->to, $m->messageId, $m->contextId ?? null,
        $m->timestamp, $m->text, $m->sig ?? null
    );
};
$claimsNamed = isset($claimByName['claim-unsigned'], $claimByName['claim-unknown-nonce']);
check(
    $claimsNamed,
    'the claim reject cases are the two this suite names',
    'got [' . implode(', ', array_keys($claimByName)) . ']'
);
if ($claimsNamed) {
    check(
        !$verifyClaimMessage($claimByName['claim-unsigned']),
        'reject[claim/claim-unsigned] is refused: a claim carrying an all-zero signature '
        . 'never gets as far as writing trust'
    );
    // AND THE ONE THIS DOOR CANNOT REFUSE, said out loud rather than walked over. The
    // message inside `claim-unknown-nonce` is VALIDLY signed; the rejection the vector
    // demands comes from a one-time nonce THIS device issued, which is receiver state a
    // door that extends no invites never holds. Asserting `!verifyEnvelope` here would go
    // red for a reason unrelated to the code — the shape that makes a walk over the wrong
    // field look like coverage. So pin what is actually true: the crypto says yes.
    check(
        $verifyClaimMessage($claimByName['claim-unknown-nonce']),
        'reject[claim/claim-unknown-nonce] is NOT a crypto refusal — its message verifies, '
        . 'so the rejection this vector demands is nonce state, not a signature'
    );
}

// --- invite (2), encoding, keystate: NOT DRIVEN HERE, and named so that saying so costs a
// line each. These are `echo`, not `check()`: a check that always passes because it asserts
// nothing is the very defect this section was rewritten to remove. The census above is what
// keeps the list honest — a group that appears upstream fails it until it is driven or
// declared.
echo "skip: reject[invite] (2 cases) — shared/invite.verify_invite judges a signed invite at "
    . "the case's `checkNow`, and this plugin has no invite entry point at all; writing the "
    . "invite payload in this file would be a second implementation testing itself\n";
echo "skip: reject[encoding] — raw document BYTES refused at the parse boundary, an "
    . "object-shaped group ({note, accept, refuse}), not a duty of a door that verifies one "
    . "envelope at a time\n";
echo "skip: reject[keystate] — the key-rotation state machine, object-shaped and stateful; "
    . "this door holds one seed and no rotation history\n";

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

// ------------------------------------------------------------------ the count floor
//
// THE LAST THING THAT CAN GO WRONG SILENTLY. Every check above is reached by walking a file
// this repository does not own, and a suite that runs NOTHING prints CONFORMANT exactly as
// loudly as one that runs everything — `0 passed, 0 failed` is a green verdict. The group
// floors upstream catch a group that shrinks; this catches the whole run collapsing for a
// reason no single group would notice: a vendored file that parses to an empty object, an
// early `exit` slipped into a helper, a walk accidentally nested inside a false branch.
//
// Only ONE branch of this file is environment-dependent — the five P-256 owner checks, which
// need OpenSSL — so the floor is stated for both worlds rather than guessed at with a margin.
// Raising it when checks are added is a one-line, deliberate act, and that is the point.
$ran = $pass + count($fail);
$floor = Wire::p256Available() ? 114 : 109;
check(
    $ran >= $floor,
    "the suite ran at least {$floor} checks",
    "ran {$ran} — checks went missing rather than failing, which is the one way this runner "
        . 'can report CONFORMANT while proving nothing'
);

echo str_repeat('-', 60) . "\n";
$verdict = $fail === [] ? 'CONFORMANT' : 'NOT CONFORMANT';
echo "{$verdict}: {$pass} passed, " . count($fail) . " failed\n";
if ($fail !== []) {
    echo '  failed: ' . implode('; ', $fail) . "\n";
}
exit($fail === [] ? 0 : 1);
