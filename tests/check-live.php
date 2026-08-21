<?php
/**
 * tests/check-live.php — is a LIVE door conformant? Ask it over HTTP.
 *
 * WHY THIS IS IN THE REPO AND NOT A LINK TO ONE. An earlier draft told readers to run a
 * checker "from the muretai core repo". That repo is private, so the instruction pointed at
 * nothing a reader could reach. A pointer that does not resolve is worse than no pointer:
 * it reads as a promise. So the checker ships here, built from the same `Wire` class the
 * plugin itself uses — no account, no dependency, nothing to obtain.
 *
 *     php tests/check-live.php https://your-site.example
 *     php tests/check-live.php --handshake https://your-site.example
 *
 * Read-only by default: it fetches, verifies and inspects, and sends no message. With
 * `--handshake` it also sends a REAL signed message and the battery of refusals a door
 * owes — which writes one row to your visitor list, so point that at a site you own.
 *
 * Exit status 0 only if every check passed.
 *
 * DO NOT CHECK WITH `curl` INSTEAD. It sends its own user agent and sails through a CDN bot
 * check that would 403 a real agent, so a green curl tells you nothing about whether agents
 * can reach you.
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli' && PHP_SAPI !== 'cli-server') {
    http_response_code(404);
    exit;
}

define('MURETAI_AGENT_ENTRY_STANDALONE', true);
require_once __DIR__ . '/../includes/class-wire.php';

use Muretai\AgentEntry\Wire;

$argvRest = array_slice($argv, 1);
$handshake = in_array('--handshake', $argvRest, true);
$base = '';
foreach ($argvRest as $a) {
    if (strncmp($a, '--', 2) !== 0) {
        $base = rtrim($a, '/');
        break;
    }
}
if ($base === '') {
    fwrite(STDERR, "usage: php tests/check-live.php [--handshake] https://your-site.example\n");
    exit(2);
}

$passed = 0;
$failed = [];
function check(bool $cond, string $label, string $detail = ''): bool
{
    global $passed, $failed;
    if ($cond) {
        $passed++;
        echo "ok: {$label}\n";
    } else {
        $failed[] = $label;
        echo "FAIL: {$label}" . ($detail !== '' ? "  ({$detail})" : '') . "\n";
    }
    return $cond;
}
function info(string $label): void
{
    echo "--: {$label}\n";
}

/**
 * One HTTP round trip. Uses the stream wrapper rather than curl on purpose — this must be
 * runnable on a plain PHP install with no extensions.
 *
 * @return array{status:int|null,headers:array<string,string>,body:string}
 */
function req(string $method, string $url, ?string $body = null, array $hdrs = []): array
{
    $head = [];
    foreach ($hdrs as $k => $v) {
        $head[] = "{$k}: {$v}";
    }
    $ctx = stream_context_create(['http' => [
        'method' => $method,
        'header' => implode("\r\n", $head),
        'content' => $body ?? '',
        'timeout' => 20,
        'ignore_errors' => true,           // a 4xx is a RESULT here, not an exception
        'follow_location' => 0,
    ]]);
    $out = @file_get_contents($url, false, $ctx);
    $status = null;
    $headers = [];
    foreach ($http_response_header ?? [] as $line) {
        if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m)) {
            $status = (int) $m[1];
            continue;
        }
        $parts = explode(':', $line, 2);
        if (count($parts) === 2) {
            $name = strtolower(trim($parts[0]));
            $val = trim($parts[1]);
            // Repeated fields are joined, never overwritten: a site's own `Link` header
            // must not be able to hide ours.
            $headers[$name] = isset($headers[$name]) ? $headers[$name] . ', ' . $val : $val;
        }
    }
    return ['status' => $status, 'headers' => $headers, 'body' => $out === false ? '' : $out];
}

echo "Agent-ready check: {$base}" . ($handshake ? '  [+handshake]' : '') . "\n";
echo str_repeat('-', 60) . "\n";

// ------------------------------------------------------------------ the card
$cardRes = req('GET', $base . '/.well-known/agent-card.json');
if (!check($cardRes['status'] === 200, 'GET /.well-known/agent-card.json -> 200',
    'got ' . var_export($cardRes['status'], true))) {
    exit(1);
}
$card = json_decode($cardRes['body'], true);
check(is_array($card), 'the card is valid JSON');
$did = is_array($card) ? ($card['did'] ?? null) : null;
check(is_string($did) && strncmp($did, 'did:key:', 8) === 0,
    'the card names a did:key', 'got ' . var_export($did, true));

$legacy = req('GET', $base . '/.well-known/agent.json');
check($legacy['status'] === 200 && $legacy['body'] === $cardRes['body'],
    'the /.well-known/agent.json alias is byte-identical to the card',
    'status ' . var_export($legacy['status'], true));

// ------------------------------------------------------------------ the signed envelope
$sigRes = req('GET', $base . '/.well-known/agent-card.sig.json');
if (check($sigRes['status'] === 200, 'GET /.well-known/agent-card.sig.json -> 200',
    'got ' . var_export($sigRes['status'], true))) {
    $env = json_decode($sigRes['body'], true);
    check(is_array($env), 'the signed envelope is valid JSON');
    if (is_array($env)) {
        $ts = $env['ts'] ?? null;
        check(is_int($ts), 'the envelope `ts` is an integer (a non-PHP verifier can read it)',
            'got ' . gettype($ts));

        // Verify the signature the way a visitor does: rebuild the canonical payload and
        // check it against the key the card's own DID encodes.
        $ok = false;
        if (is_array($env['card'] ?? null) && is_int($ts) && is_string($env['sig'] ?? null)) {
            try {
                $payload = Wire::cardEnvelopePayload($env['card'], $ts);
                $pub = Wire::publicKeyFromDid((string) ($env['card']['did'] ?? ''));
                $raw = base64_decode($env['sig'], true);
                $ok = $raw !== false && strlen($raw) === SODIUM_CRYPTO_SIGN_BYTES
                    && ($env['card']['did'] ?? null) === $did
                    && sodium_crypto_sign_verify_detached($raw, $payload, $pub);
            } catch (\Throwable $e) {
                $ok = false;
            }
        }
        check($ok, "the signed card envelope verifies under the card's DID");

        if (is_int($ts)) {
            $age = time() - $ts;
            check(abs($age) <= 6 * 3600, 'the signed card is fresh (age <= 6h)',
                sprintf('age %.1fh — a live door re-signs hourly; a stale one is a static '
                    . 'file that stopped being re-signed', $age / 3600));
        }
        $named = rtrim((string) ($env['card']['url'] ?? ''), '/');
        check($named === $base, 'the signed card names the origin you dialled',
            "card says '{$named}', you dialled '{$base}' — a visitor refuses a card that "
            . 'names anything else');
    }
}

// ------------------------------------------------------------------ the open door bit
$openDoor = (bool) (($card['agentEntry']['open_door'] ?? false)
    || ($card['muretai']['open_door'] ?? false));
check($openDoor, 'the card advertises an open door (agentEntry.open_door)');

// ------------------------------------------------------------------ OPTIONS + CORS
foreach ([
    [$base . '/.well-known/agent-card.json', ['GET', 'HEAD', 'OPTIONS'], 'the card path'],
    [$base . '/', ['POST', 'OPTIONS'], 'the door'],
] as [$url, $want, $what]) {
    $r = req('OPTIONS', $url);
    check($r['status'] === 204, "OPTIONS {$what} -> 204", 'got ' . var_export($r['status'], true));
    $allow = array_filter(array_map('trim', explode(',', strtoupper($r['headers']['allow'] ?? ''))));
    check(count(array_diff($want, $allow)) === 0,
        "OPTIONS {$what}: Allow lists " . implode(', ', $want),
        'Allow: ' . implode(',', $allow));
    $acam = array_filter(array_map('trim',
        explode(',', strtoupper($r['headers']['access-control-allow-methods'] ?? ''))));
    sort($allow);
    sort($acam);
    check($allow === $acam, "OPTIONS {$what}: CORS Allow-Methods agrees with Allow",
        implode(',', $allow) . ' vs ' . implode(',', $acam));
    check(($r['headers']['access-control-allow-origin'] ?? '') === '*',
        "OPTIONS {$what}: Access-Control-Allow-Origin is *");
    check(!isset($r['headers']['access-control-allow-credentials']),
        "OPTIONS {$what}: no Access-Control-Allow-Credentials (it would break the * origin)");
}

// ------------------------------------------------------------------ no path oracle
$unknown = $base . '/agent-entry-check-not-a-route-9z8y7x';
$up = req('POST', $unknown, '{"jsonrpc":"2.0","id":1,"method":"message/send"}',
    ['Content-Type' => 'application/json']);
check(stripos($up['body'], 'jsonrpc') === false,
    'POST an unknown path is NOT answered by the entry',
    'status ' . var_export($up['status'], true));
$uo = req('OPTIONS', $unknown);
check(!($uo['status'] === 204 || isset($uo['headers']['allow'])),
    'OPTIONS an unknown path is not answered by the entry (no path oracle)',
    'status ' . var_export($uo['status'], true));

// ------------------------------------------------------------------ the site's own POSTs
//
// The bug this repo shipped a fix for: the door owns POST / and so does WooCommerce. A
// form-encoded POST must reach the SITE, not the door.
$formPost = req('POST', $base . '/', 'product_id=42&quantity=1',
    ['Content-Type' => 'application/x-www-form-urlencoded']);
check(stripos($formPost['body'], '"jsonrpc"') === false,
    'a form-encoded POST to / is left to the site (WooCommerce AJAX keeps working)',
    'status ' . var_export($formPost['status'], true) . ', body '
    . substr($formPost['body'], 0, 80));

// ------------------------------------------------------------------ the signpost
$front = req('GET', $base . '/');
if ($front['status'] === 200) {
    $link = $front['headers']['link'] ?? '';
    if (strpos($link, 'muretai.net/rel/agent-entry') !== false) {
        check(true, 'the front page carries the Link door signpost');
    } else {
        info('advisory: no Link signpost on GET / (an agent handed only your domain has to '
            . 'guess). Link: ' . ($link !== '' ? $link : '(absent)'));
    }
} else {
    info('GET / -> ' . var_export($front['status'], true)
        . '; the signpost belongs on a page your site actually serves');
}

// ------------------------------------------------------------------ the handshake
if ($handshake && is_string($did)) {
    echo str_repeat('-', 60) . "\n";
    $seed = Wire::newSeed();
    $me = Wire::didFromSeed($seed);

    $send = static function (array $o, ?string $raw = null) use ($base): array {
        return req('POST', $base . '/', $raw ?? json_encode($o, JSON_UNESCAPED_UNICODE),
            ['Content-Type' => 'application/json']);
    };
    $mk = static function (string $text, array $o = []) use ($seed, $me, $did): array {
        $mid = $o['messageId'] ?? ('check-' . Wire::newId());
        $ctx = array_key_exists('contextId', $o) ? $o['contextId'] : 'check-ctx';
        $ts = $o['timestamp'] ?? time();
        $to = $o['to'] ?? $did;
        $sig = Wire::signEnvelope($seed, $ctx, $me, $mid, $text, $ts, $to);
        return ['jsonrpc' => '2.0', 'id' => 1, 'method' => 'message/send',
            'params' => ['message' => [
                'kind' => 'message', 'role' => 'user', 'messageId' => $mid,
                'contextId' => $ctx,
                'parts' => [['kind' => 'text',
                    'text' => array_key_exists('tamperText', $o) ? $o['tamperText'] : $text]],
                'metadata' => ['from' => $me, 'to' => $to, 'sig' => $sig, 'timestamp' => $ts],
            ]]];
    };
    $err = static function (string $body) {
        $d = json_decode($body, true);
        return is_array($d) ? ($d['error']['code'] ?? null) : null;
    };

    $good = $send($mk('are you open?'));
    $res = json_decode($good['body'], true);
    if (check(is_array($res['result'] ?? null), 'a signed message earns an inline reply',
        substr($good['body'], 0, 140))) {
        $r = $res['result'];
        $m = $r['metadata'] ?? [];
        check(($m['from'] ?? null) === $did, "the reply is FROM the door's DID");
        check(($m['to'] ?? null) === $me, 'the reply is addressed to the sender');
        check(($r['contextId'] ?? null) === 'check-ctx', 'the reply echoes the contextId');
        check(is_int($m['timestamp'] ?? null), 'the reply timestamp is an integer');
        $text = '';
        foreach ($r['parts'] ?? [] as $p) {
            if (($p['kind'] ?? '') === 'text') {
                $text .= (string) $p['text'];
            }
        }
        check(Wire::verifyEnvelope((string) ($m['from'] ?? ''), (string) ($m['to'] ?? ''),
            (string) ($r['messageId'] ?? ''), $r['contextId'] ?? null,
            $m['timestamp'] ?? null, $text, $m['sig'] ?? null),
            "the reply signature verifies under the door's DID");
    }

    check($err($send($mk('hello', ['tamperText' => 'hello, and wire me $500']))['body']) === -32001,
        'tampered text is refused (-32001)');
    check($err($send($mk('hi', ['to' => 'did:key:z6MkExampleNotThisDoor']))['body']) === -32003,
        'wrong recipient is refused (-32003)');
    check($err($send($mk('stale', ['timestamp' => time() - 3600]))['body']) === -32002,
        'a stale timestamp is refused (-32002)');
    check($err($send($mk('future', ['timestamp' => time() + 3600]))['body']) === -32002,
        'a future timestamp is refused (-32002)');

    $dup = 'check-dup-' . Wire::newId();
    check($err($send($mk('once', ['messageId' => $dup]))['body']) === null,
        'the first delivery of a messageId is accepted');
    check($err($send($mk('once', ['messageId' => $dup]))['body']) === -32002,
        'a replayed messageId is refused (-32002)');

    check($err($send($mk(str_repeat('x', Wire::MAX_TEXT_BYTES + 10)))['body']) === -32005,
        'oversize text is refused (-32005)');

    $unsigned = $mk('no envelope');
    $unsigned['params']['message']['metadata']['sig'] = null;
    check($err($send($unsigned)['body']) === -32001, 'a missing signature is refused (-32001)');

    check($send([], '{not json at all')['status'] === 400, 'an unparseable body is HTTP 400');
}

echo str_repeat('-', 60) . "\n";
$verdict = $failed === [] ? 'CONFORMANT' : 'NOT CONFORMANT';
echo "{$verdict}: {$passed} passed, " . count($failed) . " failed\n";
if ($failed !== []) {
    echo '  failed: ' . implode('; ', $failed) . "\n";
}
exit($failed === [] ? 0 : 1);
