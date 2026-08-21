<?php
/**
 * tests/emit_for_python.php — signatures for ANOTHER language to check.
 *
 * `conformance.php` proves this implementation agrees with the fixtures. That is not the
 * same as proving it agrees with the OTHER implementations: a shared misreading of the
 * spec would satisfy both. So this script signs a few messages and a card envelope and
 * prints them as JSON, for core's Python verifier to accept or reject. The non-ASCII case
 * matters most — literal UTF-8 in the signed bytes is the rule most implementations break,
 * and message text on this network is routinely non-ASCII.
 *
 *     php tests/emit_for_python.php > /tmp/php_emitted.json
 *     # then, in the core repo, verify with shared.crypto + shared.cardpub
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
$seed = hex2bin(str_repeat('7a', 32));
$did  = Wire::didFromSeed($seed);
$to   = 'did:key:z6MkwgaR63138bEEgad7uk993KMX54vBA6KTB4sFhCPnSB2e';
$cases = [];
foreach ([['c1','hello',1752451200],[null,'Saturday 14:00 is open. 群れたい',1752451300],['c3','',1752451400]] as $i => $c) {
    [$ctx,$text,$ts] = $c;
    $cases[] = ['contextId'=>$ctx,'from'=>$did,'to'=>$to,'messageId'=>"m{$i}",
                'text'=>$text,'timestamp'=>$ts,
                'sig'=>Wire::signEnvelope($seed,$ctx,$did,"m{$i}",$text,$ts,$to)];
}
$card = ['did'=>$did,'name'=>'Example Studio','url'=>'https://studio.example','version'=>'1'];
$env  = Wire::makeCardEnvelope($seed, $card, 1784273681);
echo json_encode(['did'=>$did,'messages'=>$cases,'cardEnvelope'=>$env],
    JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES), "\n";
