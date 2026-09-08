<?php
/**
 * tests/regression.php — the bugs an audit found before this plugin was ever published.
 *
 * Each case here is a defect that was REAL in the first cut, reproduced as a test so it
 * cannot come back. They are grouped by what they would have cost a site owner.
 *
 *     php tests/regression.php
 *
 * Exit status 0 only when every case passes.
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
require_once __DIR__ . '/../includes/class-entry.php';

use Muretai\AgentEntry\Entry;
use Muretai\AgentEntry\MemoryStore;
use Muretai\AgentEntry\Wire;

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

function newEntry(): Entry
{
    return new Entry(hex2bin(str_repeat('2b', 32)), 'https://shop.example', [
        'name' => 'Regression Shop',
        'store' => new MemoryStore(),
        'responder' => static fn(array $env): string => 'answered',
    ]);
}

$JSON = ['content-type' => 'application/json'];

// ===================================================================== the shop-breaker
//
// THE WORST BUG THIS PLUGIN HAD. The door owns `POST /`, and so does WooCommerce: its
// classic checkout posts form-encoded bodies to `/?wc-ajax=<action>`, whose PATH is `/`.
// The first cut answered those with HTTP 400 and exited, which breaks add-to-cart,
// coupons, order review and checkout on exactly the shops this plugin is for — while the
// README promised "GET / is still your site; only POST / is the door".
//
// The contract is the SENTINEL: `[404, [], '']` is how this class tells the WordPress
// adapter "not mine, carry on". Anything else means the plugin claimed the request.

echo "--- 1. the site's own POSTs must fall through, not be answered ---\n";

$entry = newEntry();

$wooBodies = [
    'add_to_cart' => 'product_sku=&product_id=42&quantity=1',
    'apply_coupon' => 'security=abc123&coupon_code=SAVE10',
    'update_order_review' => 'security=abc123&payment_method=cod&country=JP&post_data=x%3D1',
    'checkout' => 'billing_first_name=Ada&billing_last_name=Lovelace&payment_method=cod',
];
foreach ($wooBodies as $name => $body) {
    [$status, $headers, $out] = $entry->handle(
        'POST', '/', ['content-type' => 'application/x-www-form-urlencoded'], $body);
    check($status === 404 && $out === '',
        "WooCommerce {$name} (form-encoded POST /) falls through to the site",
        "got status {$status}, body " . substr($out, 0, 80));
}

// A multipart upload posted to the front page — same shape, different plugin.
[$status, , $out] = $entry->handle('POST', '/',
    ['content-type' => 'multipart/form-data; boundary=----x'], "------x\r\nstuff\r\n");
check($status === 404 && $out === '', 'a multipart POST to / falls through',
    "got {$status}");

// A body with no Content-Type at all (some clients omit it).
[$status, , $out] = $entry->handle('POST', '/', [], 'a=1&b=2');
check($status === 404 && $out === '', 'a POST with no Content-Type falls through',
    "got {$status}");

// JSON POSTs multiplexed over the root path BY QUERY STRING. The Content-Type gate alone
// claimed these — measured: WooCommerce Stripe's webhook endpoint is `/?wc-api=wc_stripe`,
// delivered as `application/json`, and the door answered it HTTP 200 / -32601 with the
// Stripe event id echoed as the JSON-RPC id. Stripe records the 200 as delivered and never
// retries: every payment event lost, silently. A door POST never carries a query string
// (the dialled address is the signed card's `url`, byte-exact), so ANY query string means
// "not ours".
$stripeEvent = json_encode(['id' => 'evt_1', 'object' => 'event',
    'type' => 'payment_intent.succeeded', 'data' => ['object' => ['id' => 'pi_1']]]);
[$status, , $out] = $entry->handle('POST', '/', $JSON, $stripeEvent, 'wc-api=wc_stripe');
check($status === 404 && $out === '',
    'a Stripe-shaped JSON webhook (POST /?wc-api=wc_stripe) falls through to the site',
    "got status {$status}, body " . substr($out, 0, 80));

[$status, , $out] = $entry->handle('POST', '/', $JSON,
    json_encode(['title' => 'x']), 'rest_route=/wp/v2/posts');
check($status === 404 && $out === '',
    'a plain-permalink REST write (POST /?rest_route=...) falls through to the site',
    "got status {$status}, body " . substr($out, 0, 80));

[$status, , $out] = $entry->handle('POST', '/',
    ['content-type' => 'application/x-www-form-urlencoded'],
    'product_id=42&quantity=1', 'wc-ajax=add_to_cart');
check($status === 404 && $out === '',
    'wc-ajax with its real query string falls through (both gates agree)',
    "got status {$status}");

// The query gate must cost the site's OTHER traffic nothing. A clicked referral or
// campaign link arrives with GET, and no GET is ever the door's — so tagged links reach
// the site (and its analytics) exactly as before. And a cache-busting query on a card
// fetch must not change the card: the GET branch never consults the query at all.
[$status, , $out] = $entry->handle('GET', '/', [], '', 'utm_source=newsletter&ref=partner42');
check($status === 404 && $out === '',
    'a tracking-tagged link (GET /?utm_source=...&ref=...) falls through to the site',
    "got status {$status}, body " . substr($out, 0, 80));

[, , $plainCard] = $entry->handle('GET', '/.well-known/agent-card.json', [], '');
[$status, , $busted] = $entry->handle('GET', '/.well-known/agent-card.json', [], '', 'v=123');
check($status === 200 && $busted === $plainCard,
    'a cache-busting query on the card fetch serves the identical card bytes',
    "got status {$status}");

// ...and the door must still ANSWER a real agent, or the fix broke the product.
$sender = hex2bin(str_repeat('5c', 32));
$fromDid = Wire::didFromSeed($sender);
$ts = time();
$mid = 'reg-' . bin2hex(random_bytes(6));
$sig = Wire::signEnvelope($sender, 'c1', $fromDid, $mid, 'hello', $ts, $entry->did());
$agentBody = json_encode([
    'jsonrpc' => '2.0', 'id' => 1, 'method' => 'message/send',
    'params' => ['message' => [
        'kind' => 'message', 'role' => 'user', 'messageId' => $mid, 'contextId' => 'c1',
        'parts' => [['kind' => 'text', 'text' => 'hello']],
        'metadata' => ['from' => $fromDid, 'to' => $entry->did(), 'sig' => $sig,
                       'timestamp' => $ts],
    ]],
]);
[$status, , $out] = $entry->handle('POST', '/', $JSON, $agentBody);
$parsed = json_decode($out, true);
check($status === 200 && isset($parsed['result']),
    'a real signed agent message is still answered', "status {$status}, body "
    . substr($out, 0, 120));

// ===================================================================== remote 500s
//
// Two ways an unauthenticated stranger could turn the door into an HTTP 500. Both are
// worse than they look: the door's own contract says a protocol verdict is HTTP 200, so a
// 500 is indistinguishable from "the server fell over", and on the SUCCESS path the second
// one booked the account and burnt the messageId before dying.

echo "\n--- 2. no unauthenticated input may produce a 500 ---\n";

// (a) a JSON-RPC id the canonicaliser refuses. PHP ints run to 64 bits; this wire stops at
//     +/-(2**53-1), and every whole-valued float is refused because three languages spell
//     it three ways.
$badIds = [
    'float' => '1.0',
    'exponent' => '1e20',
    'tiny-float' => '0.00001',
    'int-beyond-2^53' => '9223372036854775807',
    'negative-beyond' => '-9223372036854775807',
    'bool' => 'true',
    'object' => '{"a":1}',
    'array' => '[1,2]',
];
foreach ($badIds as $name => $literal) {
    $body = '{"jsonrpc":"2.0","id":' . $literal . ',"method":"message/send","params":{}}';
    [$status, , $out] = $entry->handle('POST', '/', $JSON, $body);
    $ok = $status === 200 && json_decode($out, true) !== null;
    check($ok, "a {$name} JSON-RPC id is answered, not fatal",
        "status {$status}, body " . substr($out, 0, 100));
}

// (b) attacker-controlled text truncated mid-UTF-8. The reflected `method` and `to` values
//     were cut with substr(), which counts BYTES — leaving a lone lead byte that the
//     canonicaliser refuses, as an exception, on the error path.
$multibyte = str_repeat('あ', 40);              // 3 bytes each: any byte cut splits one
[$status, , $out] = $entry->handle('POST', '/', $JSON,
    json_encode(['jsonrpc' => '2.0', 'id' => 'x', 'method' => $multibyte, 'params' => []],
        JSON_UNESCAPED_UNICODE));
check($status === 200 && json_decode($out, true) !== null,
    'a multibyte `method` name is answered, not fatal (byte-truncation bug)',
    "status {$status}, body " . substr($out, 0, 100));

$longMultibyteDid = 'did:key:z' . str_repeat('ま', 30);
$body = json_encode(['jsonrpc' => '2.0', 'id' => 'y', 'method' => 'message/send',
    'params' => ['message' => [
        'kind' => 'message', 'role' => 'user', 'messageId' => 'm-utf8', 'contextId' => null,
        'parts' => [['kind' => 'text', 'text' => 'hi']],
        'metadata' => ['from' => $fromDid, 'to' => $longMultibyteDid, 'sig' => 'AAAA',
                       'timestamp' => time()],
    ]]], JSON_UNESCAPED_UNICODE);
[$status, , $out] = $entry->handle('POST', '/', $JSON, $body);
$parsed = json_decode($out, true);
check($status === 200 && isset($parsed['error']['code'])
      && $parsed['error']['code'] === Entry::E_WRONG_RECIPIENT,
    'a multibyte `to` DID is refused with -32003, not fatal',
    "status {$status}, body " . substr($out, 0, 120));

// (c) the blanket guard: whatever else throws, a stranger still gets a status line.
$throwing = new Entry(hex2bin(str_repeat('2b', 32)), 'https://shop.example', [
    'store' => new MemoryStore(),
    'responder' => static function (array $env) { throw new \RuntimeException('backend down'); },
]);
$ts2 = time();
$mid2 = 'reg2-' . bin2hex(random_bytes(6));
$sig2 = Wire::signEnvelope($sender, null, $fromDid, $mid2, 'hello', $ts2, $throwing->did());
$body2 = json_encode(['jsonrpc' => '2.0', 'id' => 3, 'method' => 'message/send',
    'params' => ['message' => [
        'kind' => 'message', 'role' => 'user', 'messageId' => $mid2, 'contextId' => null,
        'parts' => [['kind' => 'text', 'text' => 'hello']],
        'metadata' => ['from' => $fromDid, 'to' => $throwing->did(), 'sig' => $sig2,
                       'timestamp' => $ts2],
    ]]]);
[$status, , $out] = $throwing->handle('POST', '/', $JSON, $body2);
$parsed = json_decode($out, true);
check($status === 200 && ($parsed['error']['code'] ?? null) === Entry::E_INTERNAL,
    'a throwing responder answers -32603, and leaks nothing about why',
    "status {$status}, body " . substr($out, 0, 120));
check(strpos($out, 'backend down') === false,
    'the backend exception TEXT never reaches the caller');

// ===================================================================== still conformant
//
// The fixes above must not have quietly changed the contract.

// ============================================== the two cards must never disagree
//
// The plain card is rebuilt every request; the signed one is cached for an hour. Anything
// that changes the card's CONTENT — a rename, or simply activating WooCommerce, which adds
// a skill without touching any option this plugin owns — left the two disagreeing until the
// cache expired. A visitor trusts the SIGNED card, so the change was invisible to every
// agent while looking perfectly correct to the site owner. Found on a live install.

echo "\n--- 3. the signed card always signs the card actually being served ---\n";

$store = new MemoryStore();
$mk = static function (array $skills) use ($store): Entry {
    return new Entry(hex2bin(str_repeat('2b', 32)), 'https://shop.example', [
        'name' => 'Regression Shop', 'store' => $store, 'skills' => $skills,
        'responder' => static fn(array $e): string => 'answered',
    ]);
};

$before = $mk([]);
[, , $env1] = $before->handle('GET', '/.well-known/agent-card.sig.json', [], '');
$signed1 = json_decode($env1, true);
check(($signed1['card']['skills'] ?? null) === [], 'the signed card starts with no skills');

// The same store, a new request, and now the site has a catalogue.
$after = $mk([['id' => 'product-search', 'name' => 'Search the catalogue']]);
[, , $plain] = $after->handle('GET', '/.well-known/agent-card.json', [], '');
[, , $env2] = $after->handle('GET', '/.well-known/agent-card.sig.json', [], '');
$signed2 = json_decode($env2, true);
$plainSkills = json_decode($plain, true)['skills'] ?? null;
check($plainSkills === $signed2['card']['skills'] ?? null,
    'the signed card re-mints when the card content changes (it is not stale)',
    'plain ' . json_encode($plainSkills) . ' vs signed '
    . json_encode($signed2['card']['skills'] ?? null));
check(($signed2['card']['skills'][0]['id'] ?? null) === 'product-search',
    'the newly added skill is inside the SIGNED card, which is the one visitors trust');

echo "\n--- 4. the routes still behave ---\n";

[$status, $h, $out] = $entry->handle('GET', '/.well-known/agent-card.json', [], '');
check($status === 200 && (json_decode($out, true)['did'] ?? null) === $entry->did(),
    'the card is still served');
[$s2, , $legacy] = $entry->handle('GET', '/.well-known/agent.json', [], '');
check($s2 === 200 && $legacy === $out, 'the legacy alias is still byte-identical');
[$status, , $out] = $entry->handle('GET', '/', [], '');
check($status === 404 && $out === '', 'GET / still belongs to the site');
[$status, $h, ] = $entry->handle('OPTIONS', '/', [], '');
check($status === 204 && strpos($h['Allow'] ?? '', 'POST') !== false,
    'OPTIONS / still advertises the door');
[$status, , ] = $entry->handle('POST', '/not-a-route', $JSON, '{}');
check($status === 404, 'POST to an unowned path is still 404');

echo "\n--- 5. AE-30: the site's order of its ways in ---\n";

$declared = [['kind' => 'page', 'when' => 'no-key'], 'card', 'mcp'];
$withOrder = new Entry(hex2bin(str_repeat('2b', 32)), 'https://shop.example', [
    'name' => 'Regression Shop', 'store' => new MemoryStore(), 'prefer' => $declared,
    'responder' => static fn(array $e): string => 'answered',
]);
[, , $plain] = $withOrder->handle('GET', '/.well-known/agent-card.json', [], '');
$card = json_decode($plain, true);
check(($card['agentEntry']['prefer'] ?? null) === $declared,
    'a declared order is published verbatim under agentEntry.prefer',
    json_encode($card['agentEntry'] ?? null));
check(($card['agentEntry']['open_door'] ?? null) === true, 'open_door still true beside it');
check(!isset($card['muretai']['prefer']), 'the legacy muretai alias carries no prefer');
[, , $env] = $withOrder->handle('GET', '/.well-known/agent-card.sig.json', [], '');
$signed = json_decode($env, true);
check(($signed['card']['agentEntry']['prefer'] ?? null) === $declared,
    'the SIGNED card carries the same order');

[, , $plainUnset] = newEntry()->handle('GET', '/.well-known/agent-card.json', [], '');
check(!array_key_exists('prefer', json_decode($plainUnset, true)['agentEntry'] ?? []),
    'no prefer key at all when not configured');

foreach ([
    ['teleport'],
    [['kind' => 'mcp', 'when' => 'full-moon']],
    [['kind' => 'card', 'extra' => 1]],
    [],
    'card',
] as $bad) {
    $refused = false;
    try {
        new Entry(hex2bin(str_repeat('2b', 32)), 'https://shop.example', [
            'store' => new MemoryStore(), 'prefer' => $bad,
            'responder' => static fn(array $e): string => 'answered',
        ]);
    } catch (\InvalidArgumentException $e) {
        $refused = true;
    }
    check($refused, 'an invalid order refuses to start: ' . json_encode($bad));
}

// ===================================================================== the account layer
//
// AE-BINDING: THE RUNG THAT WAS NOT THERE. `metadata.binding` carries a countersigned
// DeviceKeyBinding v2 proving the device key that signed a message belongs to an OWNER.
// Both reference doors treat a PRESENT-but-INVALID binding as fail-closed: -32001, and no
// ledger row. This one never looked at the field at all — so a forged binding was answered
// with a signed reply and a customer row here and refused with no row on the other two,
// which is the double-book class the whole contract exists to close. It also meant a site
// migrating off the Node door silently lost the account layer: an owner's phone and laptop
// went back to being two strangers.
//
// The pin table (`wp_muretai_pins`), `getDeviceOwner` and `putDeviceOwner` were all already
// shipped and were called by nothing.

echo "\n--- 6. the account layer: a device binding is checked, or it is not a rung ---\n";

/** Build a signed message body; `$meta` merges into (and can add `binding` to) the envelope. */
function bindingBody(string $senderSeed, string $entryDid, string $mid, array $meta = [],
                     string $text = 'hello', ?int $ts = null): string
{
    $ts = $ts ?? time();
    $from = Wire::didFromSeed($senderSeed);
    $sig = Wire::signEnvelope($senderSeed, null, $from, $mid, $text, $ts, $entryDid);
    return json_encode(['jsonrpc' => '2.0', 'id' => 1, 'method' => 'message/send',
        'params' => ['message' => [
            'kind' => 'message', 'role' => 'user', 'messageId' => $mid, 'contextId' => null,
            'parts' => [['kind' => 'text', 'text' => $text]],
            'metadata' => array_merge(
                ['from' => $from, 'to' => $entryDid, 'sig' => $sig, 'timestamp' => $ts],
                $meta),
        ]]], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
}

/** A fresh entry plus the MemoryStore behind it, so a test can read the ledger and pins. */
function entryWithStore(): array
{
    $store = new MemoryStore();
    return [new Entry(hex2bin(str_repeat('2b', 32)), 'https://shop.example', [
        'name' => 'Regression Shop', 'store' => $store,
        'responder' => static fn(array $env): string => 'answered',
    ]), $store];
}

$ownerSeed = hex2bin(str_repeat('17', 32));
$owner2Seed = hex2bin(str_repeat('19', 32));
$devSeed = hex2bin(str_repeat('18', 32));
$dev2Seed = hex2bin(str_repeat('1a', 32));
$ownerDid = Wire::didFromSeed($ownerSeed);
$owner2Did = Wire::didFromSeed($owner2Seed);
$devDid = Wire::didFromSeed($devSeed);
$dev2Did = Wire::didFromSeed($dev2Seed);

$mid = static fn(): string => 'bind-' . bin2hex(random_bytes(8));

// (a) a VALID binding: the row is the OWNER's, the device is pinned, and the answer is a
//     real signed reply. Without this the refusals below would prove only that the rung
//     refuses everything.
[$e, $store] = entryWithStore();
$binding = Wire::makeDeviceBindingV2($ownerSeed, $devSeed, time() - 60, 0);
[$st, , $out] = $e->handle('POST', '/', $JSON,
    bindingBody($devSeed, $e->did(), $mid(), ['binding' => $binding]));
$parsed = json_decode($out, true);
check($st === 200 && isset($parsed['result']['metadata']['sig']),
    'a VALID binding is answered with a signed reply', substr($out, 0, 140));
check(array_keys($store->ledger()) === [$ownerDid],
    'the customer row is the OWNER, and there is no second row for the device',
    json_encode(array_keys($store->ledger())));
check($store->getDeviceOwner($devDid) === $ownerDid,
    'the device is pinned to that owner (the pin table is finally written)');

// (b) SIBLING DEVICES ARE ONE CUSTOMER — the entire reason this rung exists.
$binding2 = Wire::makeDeviceBindingV2($ownerSeed, $dev2Seed, time() - 60, 0);
$e->handle('POST', '/', $JSON,
    bindingBody($dev2Seed, $e->did(), $mid(), ['binding' => $binding2]));
$ledger = $store->ledger();
check(array_keys($ledger) === [$ownerDid] && (int) $ledger[$ownerDid]['messages'] === 2,
    'a second device of the same owner is the SAME customer, message 2 of 1 row',
    json_encode($ledger));

// (c) A FORGED binding fails CLOSED: -32001, no reply, and — the part that matters — no
//     row at all. Not the owner's (it was never proved) and not the device's either: a
//     silent downgrade to unbound would make stripping the signature the way in.
foreach ([
    'tampered owner signature' => static function (array $b) {
        $raw = base64_decode($b['sig'], true);
        $raw[0] = chr(ord($raw[0]) ^ 0x01);
        $b['sig'] = base64_encode($raw);
        return $b;
    },
    'missing countersignature' => static function (array $b) {
        unset($b['deviceSig']);
        return $b;
    },
    'unsupported typ' => static function (array $b) {
        $b['typ'] = 'muretai/devicebinding/1';
        return $b;
    },
    // HALF A SECOND PAST ITS OWN ts, so the refusal cannot come from the signature: a
    // door that merely cast the float to an int would find the signature verifies and
    // let this through. A true fraction is bytes only Python can render, and all three
    // implementations refuse it — while `1784273681.0`, the INTEGER spelled as a float,
    // is normalised and accepted by all three (case (i) below).
    'a true fraction for ts' => static function (array $b) {
        $b['ts'] = $b['ts'] + 0.5;
        return $b;
    },
    // THE v1 GAP v2 EXISTS TO CLOSE: an owner signature that is perfectly genuine, and a
    // countersignature from a device that is not the sender. Without the countersignature
    // check a foreign owner claims somebody else's device.
    'a countersignature from the WRONG device' => static function (array $b) {
        $payload = Wire::bindingV2Payload($b['rootDid'], $b['deviceDid'], $b['ts'],
            $b['validUntil']);
        $other = sodium_crypto_sign_secretkey(
            sodium_crypto_sign_seed_keypair(hex2bin(str_repeat('1a', 32))));
        $b['deviceSig'] = base64_encode(sodium_crypto_sign_detached($payload, $other));
        return $b;
    },
    'an expired binding' => static function (array $b) {
        $b['validUntil'] = time() - 1;
        return $b;
    },
    'a ts in the future' => static function (array $b) {
        $b['ts'] = time() + 4000;
        return $b;
    },
] as $what => $break) {
    [$e2, $store2] = entryWithStore();
    $good = Wire::makeDeviceBindingV2($ownerSeed, $devSeed, time() - 60, 0);
    [$st, , $out] = $e2->handle('POST', '/', $JSON,
        bindingBody($devSeed, $e2->did(), $mid(), ['binding' => $break($good)]));
    $parsed = json_decode($out, true);
    check($st === 200 && ($parsed['error']['code'] ?? null) === Entry::E_UNAUTHENTICATED
          && !isset($parsed['result']),
        "a binding with {$what} is refused -32001, with no signed reply",
        substr($out, 0, 160));
    check($store2->ledger() === [],
        "a binding with {$what} mints NO customer row — not the owner's, not the device's",
        json_encode($store2->ledger()));
    check($store2->getDeviceOwner($devDid) === null,
        "a binding with {$what} pins nothing");
}

// (d) A BINDING LIFTED OFF SOMEBODY ELSE'S MESSAGE. Genuine bytes, wrong sender.
[$e3, $store3] = entryWithStore();
$othersBinding = Wire::makeDeviceBindingV2($ownerSeed, $dev2Seed, time() - 60, 0);
[$st, , $out] = $e3->handle('POST', '/', $JSON,
    bindingBody($devSeed, $e3->did(), $mid(), ['binding' => $othersBinding]));
$parsed = json_decode($out, true);
check(($parsed['error']['code'] ?? null) === Entry::E_UNAUTHENTICATED
      && $store3->ledger() === [],
    'a genuine binding for ANOTHER device is refused and books nobody', substr($out, 0, 160));

// (e) A PIN NEVER MOVES. A device DID is never re-owned: a new owner means a new device
//     key. The store refuses to move the pin and the ladder refuses the message.
[$e4, $store4] = entryWithStore();
$e4->handle('POST', '/', $JSON, bindingBody($devSeed, $e4->did(), $mid(),
    ['binding' => Wire::makeDeviceBindingV2($ownerSeed, $devSeed, time() - 60, 0)]));
$steal = Wire::makeDeviceBindingV2($owner2Seed, $devSeed, time() - 30, 0);
[$st, , $out] = $e4->handle('POST', '/', $JSON,
    bindingBody($devSeed, $e4->did(), $mid(), ['binding' => $steal]));
$parsed = json_decode($out, true);
check(($parsed['error']['code'] ?? null) === Entry::E_UNAUTHENTICATED,
    'a VALID binding to a SECOND owner is refused: a pin never moves', substr($out, 0, 200));
check($store4->getDeviceOwner($devDid) === $ownerDid,
    'the original pin still stands after the attempt');
check(!isset($store4->ledger()[$owner2Did]),
    'the second owner is booked nowhere', json_encode(array_keys($store4->ledger())));

// (f) THE FOLD. A device that already has an unbound row moves its history to the owner
//     once — and never the reverse, or stripping a binding would read an owner's history.
[$e5, $store5] = entryWithStore();
$e5->handle('POST', '/', $JSON, bindingBody($devSeed, $e5->did(), $mid()));
check(array_keys($store5->ledger()) === [$devDid],
    'an unbound device books itself, as it always did');
$e5->handle('POST', '/', $JSON, bindingBody($devSeed, $e5->did(), $mid(),
    ['binding' => Wire::makeDeviceBindingV2($ownerSeed, $devSeed, time() - 60, 0)]));
$ledger = $store5->ledger();
check(array_keys($ledger) === [$ownerDid] && (int) $ledger[$ownerDid]['messages'] === 2,
    'on the first pin the device row FOLDS into the owner: one row, both messages',
    json_encode($ledger));

// (g) NO BINDING IS BYTE-IDENTICAL TO BEFORE. The rung must be invisible to every visitor
//     that does not carry one.
[$e6, $store6] = entryWithStore();
[$st, , $out] = $e6->handle('POST', '/', $JSON, bindingBody($devSeed, $e6->did(), $mid()));
check($st === 200 && isset(json_decode($out, true)['result'])
      && array_keys($store6->ledger()) === [$devDid],
    'a message with NO binding is answered and booked under the device, as before');

// (h) A MALFORMED binding — a string, a number, a list — is refused, never ignored.
foreach (['a string' => 'muretai/devicebinding/2', 'a number' => 7, 'a list' => [1, 2],
          'an empty object' => []] as $what => $junk) {
    [$e7, $store7] = entryWithStore();
    [, , $out] = $e7->handle('POST', '/', $JSON,
        bindingBody($devSeed, $e7->did(), $mid(), ['binding' => $junk]));
    $parsed = json_decode($out, true);
    check(($parsed['error']['code'] ?? null) === Entry::E_UNAUTHENTICATED
          && $store7->ledger() === [],
        "a binding that is {$what} is refused -32001 and books nobody", substr($out, 0, 160));
}

// (i) `ts` SPELLED AS AN INTEGER-VALUED FLOAT. JSON has one number type: a JavaScript
//     re-serialisation writes `1784273681.0`, and `JSON.parse` on the other side reads the
//     integer back. Refusing it here while the twin accepts it is the very divergence this
//     rung is meant to close (ISSUE(agent-entry-binding-float-ts-divergence)), so the float
//     spelling of an INTEGER is normalised and the binding verifies. A true fraction is
//     still refused, above.
[$e8, $store8] = entryWithStore();
$ts = time() - 60;
$body = bindingBody($devSeed, $e8->did(), $mid(),
    ['binding' => Wire::makeDeviceBindingV2($ownerSeed, $devSeed, $ts, 0)]);
$floatBody = str_replace('"ts":' . $ts . ',', '"ts":' . $ts . '.0,', $body);
check($floatBody !== $body, '(the float-ts fixture really did change the bytes)');
[, , $out] = $e8->handle('POST', '/', $JSON, $floatBody);
check(isset(json_decode($out, true)['result'])
      && array_keys($store8->ledger()) === [$ownerDid],
    'a binding whose ts is spelled 1784273681.0 verifies and books the OWNER',
    substr($out, 0, 160));

// ===================================================================== the messageId shape
//
// A WHITESPACE-ONLY messageId. It is a SIGNED field and the replay table's key. Python
// refuses it (`shared/protocol.message_id_ok` is `bool(message_id.strip())`); this door and
// the JavaScript one accepted it, answered with a signed reply and minted a customer row.
// Same bytes, two verdicts — and a dedup key on one side that is not a message at all on
// the other.
//
// PHP's own `trim()` is NOT the rule and would have been a FOURTH answer: its default list
// is " \t\n\r\0\x0B" — BYTES — so it misses FORM FEED, misses every non-ASCII space, and
// strips NUL, which neither reference does. Wire::messageIdOk carries Python's code point
// set literally.

echo "\n--- 7. a whitespace-only messageId is not a messageId ---\n";

$refusedIds = [
    'empty' => '',
    'one space' => ' ',
    'three spaces' => '   ',
    'tab' => "\t",
    'newline' => "\n",
    'CR' => "\r",
    'vertical tab' => "\x0b",
    'form feed (which PHP trim() does NOT strip)' => "\x0c",
    'U+00A0 no-break space (which PHP trim() does NOT strip)' => "\u{00a0}",
    'U+2028 line separator' => "\u{2028}",
    'U+3000 ideographic space' => "\u{3000}",
    'U+0085 NEL (Python strips it; JS trim() does not)' => "\u{0085}",
    'U+001C file separator (Python strips it; JS trim() does not)' => "\x1c",
    'a mixture of them' => " \t\n\u{3000}",
];
foreach ($refusedIds as $what => $id) {
    [$e9, $store9] = entryWithStore();
    [$st, , $out] = $e9->handle('POST', '/', $JSON,
        bindingBody($devSeed, $e9->did(), $id));
    $parsed = json_decode($out, true);
    check($st === 200 && isset($parsed['error']) && !isset($parsed['result']),
        "a messageId that is {$what} is refused, with no signed reply",
        substr($out, 0, 140));
    check($store9->ledger() === [],
        "a messageId that is {$what} mints no customer row");
    // ...and it never reached the replay table either. `seenMessage` answering TRUE now is
    // the proof that nothing was remembered under this key: a refused message must not be
    // able to burn an id, and an id that is not a message must not be a dedup key.
    check($store9->seenMessage($id, 600),
        "a messageId that is {$what} never became a replay-table key");
}

// The other half, or the rule above would be "refuse everything". These are ids Python
// KEEPS, so this door must keep them too — U+200B is the interesting one: it looks empty,
// neither `str.strip()` nor `String.prototype.trim()` removes it, and all three
// implementations therefore accept it.
$keptIds = [
    'an ordinary id' => 'm-1',
    'U+200B zero width space (stripped by nobody)' => "\u{200b}",
    'U+FEFF BOM (stripped by JS trim(), NOT by Python strip())' => "\u{feff}",
    'content with whitespace around it' => "  m-2\t",
    'a non-ASCII id' => '群れたい',
];
foreach ($keptIds as $what => $id) {
    [$e10, $store10] = entryWithStore();
    [$st, , $out] = $e10->handle('POST', '/', $JSON, bindingBody($devSeed, $e10->did(), $id));
    check($st === 200 && isset(json_decode($out, true)['result']),
        "a messageId that is {$what} is accepted and answered", substr($out, 0, 140));
    check(array_keys($store10->ledger()) === [$devDid],
        "a messageId that is {$what} books its sender");
}

// THE LENGTH BOUND. `messageId` is the replay table's key and was bounded only by the 1 MiB
// body cap, so a stranger could hand the door most of a megabyte of key per request and have
// it held for the replay TTL. `WpdbStore::seenMessage` hashes the id, which bounds the KEY
// and not the REQUEST — the shape gate is what has to say how long an id may be. The number
// and the unit (UTF-8 BYTES) are the JavaScript door's MAX_MESSAGE_ID_BYTES.
[$e12, $store12] = entryWithStore();
$atLimit = str_repeat('a', Wire::MAX_MESSAGE_ID_BYTES);
[$st, , $out] = $e12->handle('POST', '/', $JSON, bindingBody($devSeed, $e12->did(), $atLimit));
check($st === 200 && isset(json_decode($out, true)['result']),
    'a messageId of exactly ' . Wire::MAX_MESSAGE_ID_BYTES . ' bytes is accepted',
    substr($out, 0, 140));

foreach ([
    'one byte over' => str_repeat('a', Wire::MAX_MESSAGE_ID_BYTES + 1),
    'a quarter megabyte' => str_repeat('a', 262144),
    // BYTES, not characters: 100 of these are 300 bytes. A character count would let a
    // non-ASCII sender past a bound an ASCII sender is held to.
    'multibyte, under the limit in CHARACTERS but over it in bytes' => str_repeat('あ', 100),
] as $what => $id) {
    [$e13, $store13] = entryWithStore();
    [$st, , $out] = $e13->handle('POST', '/', $JSON, bindingBody($devSeed, $e13->did(), $id));
    $parsed = json_decode($out, true);
    check($st === 200 && isset($parsed['error']) && !isset($parsed['result']),
        "a messageId {$what} is refused, with no signed reply", substr($out, 0, 140));
    check($store13->ledger() === [], "a messageId {$what} mints no customer row");
    check($store13->seenMessage($id, 600),
        "a messageId {$what} never became a replay-table key");
}

// The id is kept VERBATIM, never trimmed: it is inside the signed payload, so normalising
// it would change the bytes the signature covers and the reply would name an id the sender
// never sent.
[$e11, ] = entryWithStore();
$padded = "  m-pad\t";
[, , $out] = $e11->handle('POST', '/', $JSON, bindingBody($devSeed, $e11->did(), $padded));
check((json_decode($out, true)['result']['metadata']['replyTo'] ?? null) === $padded,
    'an accepted messageId is echoed back VERBATIM, never trimmed');

echo "\n" . str_repeat('-', 60) . "\n";
$verdict = $fail === [] ? 'PASS' : 'FAIL';
echo "{$verdict}: {$pass} passed, " . count($fail) . " failed\n";
if ($fail !== []) {
    foreach ($fail as $f) {
        echo "  - {$f}\n";
    }
}
exit($fail === [] ? 0 : 1);
