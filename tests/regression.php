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

echo "\n" . str_repeat('-', 60) . "\n";
$verdict = $fail === [] ? 'PASS' : 'FAIL';
echo "{$verdict}: {$pass} passed, " . count($fail) . " failed\n";
if ($fail !== []) {
    foreach ($fail as $f) {
        echo "  - {$f}\n";
    }
}
exit($fail === [] ? 0 : 1);
