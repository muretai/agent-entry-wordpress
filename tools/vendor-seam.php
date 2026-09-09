<?php
/**
 * tools/vendor-seam.php — pull the PHP seam and the golden vectors from agent-seam.
 *
 * The PHP wire implementation's HOME is https://github.com/muretai/agent-seam, at
 * `php/seam.php`, beside the JavaScript, Python, Go and Rust references. It lived in this
 * plugin until 2026-09-09, and that was the wrong shape: the seam's own suite never ran
 * PHP, so when the JavaScript reference was found accepting a small-order Ed25519
 * signature on Node 22, "is PHP exposed too?" was a question about another repository.
 *
 * So this file is a PULLER. It reads a tag out of an agent-seam checkout with `git show`
 * — never off disk, so an uncommitted edit there cannot travel — writes the copies here,
 * and records what it took in tests/VENDOR.json. It never writes into agent-seam.
 *
 *     php tools/vendor-seam.php --ref v0.3.4
 *     php tools/vendor-seam.php --ref v0.3.4 --seam ../agent-seam
 *
 * ONE TRANSFORM, and it is recorded in the pin. WordPress plugin files sit under the
 * webroot, so `includes/class-wire.php` opens with the ABSPATH guard that refuses to run
 * when loaded outside WordPress and outside the test harness. agent-seam has no business
 * knowing that, so the guard is added HERE, on the way in, and `tests/check_vendor.php`
 * applies the same transform before it compares. A transform nobody can reproduce is a
 * pin that cannot be checked.
 */

declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

$ROOT = dirname(__DIR__);

$ref = null;
$seam = getenv('MURETAI_AGENT_SEAM') ?: '../agent-seam';
for ($i = 1; $i < $argc; $i++) {
    if ($argv[$i] === '--ref' && isset($argv[$i + 1])) { $ref = $argv[++$i]; continue; }
    if ($argv[$i] === '--seam' && isset($argv[$i + 1])) { $seam = $argv[++$i]; continue; }
}
if ($ref === null) {
    fwrite(STDERR, "usage: php tools/vendor-seam.php --ref <tag> [--seam <path>]\n");
    exit(2);
}
if (!preg_match('#^(?:/|[A-Za-z]:[\\\\/])#', $seam)) {
    $seam = $ROOT . '/' . $seam;
}
$resolved = realpath($seam);
if ($resolved === false || !file_exists($resolved . '/.git')) {
    fwrite(STDERR, "no agent-seam checkout at {$seam}\n");
    exit(2);
}
$seam = $resolved;

/** @return array{0:int,1:string} */
function git(string $dir, array $args): array
{
    $cmd = 'git -C ' . escapeshellarg($dir);
    foreach ($args as $a) { $cmd .= ' ' . escapeshellarg($a); }
    $out = [];
    $st = 0;
    exec($cmd . ' 2>/dev/null', $out, $st);
    return [$st, implode("\n", $out) . (count($out) ? "\n" : '')];
}

[$st, $commit] = git($seam, ['rev-parse', $ref . '^{commit}']);
if ($st !== 0) {
    fwrite(STDERR, "{$seam} has no ref {$ref}\n");
    exit(2);
}
$commit = trim($commit);
[, $date] = git($seam, ['log', '-1', '--format=%ad', '--date=short', $commit]);
$date = trim($date);
[, $pkg] = git($seam, ['show', "{$commit}:package.json"]);
$version = (string) (json_decode($pkg, true)['version'] ?? '');
if ($version === '') {
    fwrite(STDERR, "could not read agent-seam's version at {$ref}\n");
    exit(2);
}

/** The ABSPATH guard, added on the way in. `check_vendor.php` applies the identical
 *  transform before comparing, so the two cannot drift apart silently. */
function wordpressGuard(string $src): string
{
    $anchor = "namespace Muretai\\AgentEntry;\n\n";
    if (strpos($src, $anchor) === false) {
        fwrite(STDERR, "the namespace declaration is not where the transform expects it — refusing to guess\n");
        exit(3);
    }
    $guard = "if (!defined('ABSPATH') && !defined('MURETAI_AGENT_ENTRY_STANDALONE')) {\n"
        . "    // Loaded outside both WordPress and the test harness: refuse rather than run.\n"
        . "    exit;\n}\n\n";
    return str_replace($anchor, $anchor . $guard, $src);
}

$PLAN = [
    'includes/class-wire.php' => ['source' => 'php/seam.php', 'transform' => 'wordpress-guard'],
    'tests/wire_vectors.json' => ['source' => 'vectors/wire_vectors.json'],
];

$files = [];
foreach ($PLAN as $local => $spec) {
    [$st, $bytes] = git($seam, ['show', "{$commit}:{$spec['source']}"]);
    if ($st !== 0 || $bytes === '') {
        fwrite(STDERR, "{$commit} has no {$spec['source']}\n");
        exit(2);
    }
    if (($spec['transform'] ?? null) === 'wordpress-guard') {
        $bytes = wordpressGuard($bytes);
    }
    file_put_contents($ROOT . '/' . $local, $bytes);
    $entry = ['source' => $spec['source'], 'sha256' => hash('sha256', $bytes)];
    if (isset($spec['transform'])) { $entry['transform'] = $spec['transform']; }
    $files[$local] = $entry;
    printf("  %-26s <- %-28s%s %s\n", $local, $spec['source'],
        isset($spec['transform']) ? " [{$spec['transform']}]" : '', substr($entry['sha256'], 0, 12));
}

$pin = [
    '_' => 'Written by php tools/vendor-seam.php --ref <tag>. Never edit the copies in place: '
        . 'tests/check_vendor.php holds them to these digests with no agent-seam checkout present, '
        . 'and re-derives them from the recorded commit when one is there. The PHP wire '
        . 'implementation lives in agent-seam at php/seam.php; the ABSPATH guard is added here by '
        . 'the recorded transform, which check_vendor.php applies identically before comparing.',
    'from' => 'agent-seam',
    'repository' => 'https://github.com/muretai/agent-seam',
    'ref' => $ref,
    'commit' => $commit,
    'version' => $version,
    'date' => $date,
    'files' => $files,
];
file_put_contents($ROOT . '/tests/VENDOR.json',
    json_encode($pin, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
echo "  wrote tests/VENDOR.json  ({$ref} = " . substr($commit, 0, 7) . ", agent-seam {$version})\n";
echo "next: php tests/check_vendor.php && php tests/conformance.php && php tests/regression.php\n";
