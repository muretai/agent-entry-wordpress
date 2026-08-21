<?php
/**
 * tests/serve.php — run the PHP door under PHP's built-in server, with no WordPress.
 *
 * This exists so the door can be judged the way a stranger judges it: over HTTP, by
 * `tests/check-live.php`, before any CMS is involved. If the contract is wrong it is
 * wrong here, and finding that out does not require a database.
 *
 *     AGENT_ENTRY_SEED_HEX=<64 hex> AGENT_ENTRY_BASE_URL=http://127.0.0.1:8099 \
 *       php -S 127.0.0.1:8099 tests/serve.php
 *
 * The state is a MemoryStore, so it lives exactly as long as one php -S process. That is
 * fine for a conformance run and is precisely what the WordPress build replaces.
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

// PHP's built-in server runs this file per request, so the store must outlive the request.
// A file-backed singleton keeps the replay set and ledger across requests the way the
// WordPress database will.
final class FileStore extends \stdClass implements \Muretai\AgentEntry\Store
{
    private $path;
    private $data;

    public function __construct(string $path)
    {
        $this->path = $path;
        $raw = is_file($path) ? (string) file_get_contents($path) : '';
        $decoded = $raw === '' ? null : json_decode($raw, true);
        $this->data = is_array($decoded) ? $decoded
            : ['replay' => [], 'ledger' => [], 'pins' => [], 'rate' => [], 'card' => null];
    }

    private function flush(): void
    {
        file_put_contents($this->path, json_encode($this->data), LOCK_EX);
    }

    public function seenMessage(string $messageId, int $ttl): bool
    {
        $now = time();
        foreach ($this->data['replay'] as $id => $exp) {
            if ($exp <= $now) {
                unset($this->data['replay'][$id]);
            }
        }
        if (isset($this->data['replay'][$messageId]) && $this->data['replay'][$messageId] > $now) {
            return false;
        }
        $this->data['replay'][$messageId] = $now + $ttl;
        $this->flush();
        return true;
    }

    public function noteContact(string $did): array
    {
        $now = time();
        if (!isset($this->data['ledger'][$did])) {
            $this->data['ledger'][$did] = ['did' => $did, 'messages' => 0,
                'first_seen' => $now, 'last_seen' => $now, 'new' => true];
        } else {
            $this->data['ledger'][$did]['new'] = false;
        }
        $this->data['ledger'][$did]['messages']++;
        $this->data['ledger'][$did]['last_seen'] = $now;
        $this->flush();
        return $this->data['ledger'][$did];
    }

    public function getAccount(string $did): ?array
    {
        return $this->data['ledger'][$did] ?? null;
    }

    public function getDeviceOwner(string $deviceDid): ?string
    {
        return $this->data['pins'][$deviceDid] ?? null;
    }

    public function putDeviceOwner(string $deviceDid, string $ownerDid): bool
    {
        if (isset($this->data['pins'][$deviceDid])
            && $this->data['pins'][$deviceDid] !== $ownerDid) {
            return false;
        }
        $this->data['pins'][$deviceDid] = $ownerDid;
        $this->flush();
        return true;
    }

    public function allowRate(string $key, int $perMin): bool
    {
        $minute = intdiv(time(), 60);
        $slot = $key . '@' . $minute;
        $this->data['rate'][$slot] = ($this->data['rate'][$slot] ?? 0) + 1;
        $this->flush();
        return $this->data['rate'][$slot] <= $perMin;
    }

    public function getCardEnvelope(): ?array
    {
        return $this->data['card'];
    }

    public function putCardEnvelope(int $ts, string $bytes): void
    {
        $this->data['card'] = ['ts' => $ts, 'bytes' => $bytes];
        $this->flush();
    }
}

$seedHex = getenv('AGENT_ENTRY_SEED_HEX') ?: str_repeat('a1', 32);
$baseUrl = getenv('AGENT_ENTRY_BASE_URL') ?: 'http://127.0.0.1:8099';
$statePath = getenv('AGENT_ENTRY_STATE') ?: (sys_get_temp_dir() . '/agent-entry-state.json');

$entry = new Entry(hex2bin($seedHex), $baseUrl, [
    'name' => 'Example Studio',
    'description' => 'A photography studio that answers agents directly.',
    'store' => new FileStore($statePath),
    'responder' => static function (array $env): string {
        return 'Saturday 14:00 is open. 12000 JPY for a 60-minute shoot.';
    },
]);

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$body = (string) file_get_contents('php://input');
$headers = [];
foreach ($_SERVER as $k => $v) {
    if (strncmp($k, 'HTTP_', 5) === 0) {
        $headers[strtolower(str_replace('_', '-', substr($k, 5)))] = $v;
    }
}
// Not `HTTP_`-prefixed: PHP follows CGI and puts these two in $_SERVER bare. The door reads
// content-type to tell an agent message from the site's own form POSTs, so dropping it here
// makes the door answer nobody.
foreach (['CONTENT_TYPE' => 'content-type', 'CONTENT_LENGTH' => 'content-length'] as $k => $name) {
    if (isset($_SERVER[$k]) && $_SERVER[$k] !== '') {
        $headers[$name] = (string) $_SERVER[$k];
    }
}

[$status, $respHeaders, $respBody] = $entry->handle($method, $path, $headers, $body);

// A path this entry does not own falls through to "the site". Under php -S there is no
// site, so stand in for one: the front page gets a page WITH the Link signpost (which is
// what the WordPress plugin adds to the real theme), everything else is a plain 404.
if ($status === 404 && $respBody === '' && ($method === 'GET' || $method === 'HEAD')) {
    if ($path === '/' || $path === '') {
        header('Content-Type: text/html; charset=utf-8');
        header('Link: ' . $entry->linkHeaderValue());
        http_response_code(200);
        echo "<!doctype html><html><head><title>Example Studio</title></head><body>\n";
        echo "<p>Example Studio. An agent can talk to this site directly: fetch\n";
        echo "<code>/.well-known/agent-card.json</code> and POST a signed message to <code>/</code>.</p>\n";
        echo "</body></html>\n";
        exit;
    }
    http_response_code(404);
    header('Content-Type: application/json; charset=utf-8');
    echo Wire::jsonBytes(['error' => 'not found']);
    exit;
}

http_response_code($status);
foreach ($respHeaders as $name => $value) {
    header($name . ': ' . $value);
}
echo $respBody;
