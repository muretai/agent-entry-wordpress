<?php
/**
 * tests/check_vendor.php — the vendored golden vectors are still the bytes the pin records.
 *
 * `tests/wire_vectors.json` is not this plugin's file. It is agent-seam's
 * vectors/wire_vectors.json — the golden vectors every implementation of Agent Entry is
 * held to — copied here at one commit and pinned in tests/VENDOR.json: the upstream commit,
 * its version and date, and the sha256 of the copy as written. The copy is edited only
 * upstream and re-taken here, never changed in place. Two copies of one contract drift, and
 * a drift here is silent: nothing throws, conformance.php simply starts proving the PHP twin
 * against bytes nobody else is held to. This is the alarm on this side of the copy, and it
 * needs NOTHING outside this repository to sound.
 *
 * WHAT IT CHECKS
 *   pin      tests/VENDOR.json has the expected shape and lists every copy this repository
 *            must carry (the list is pinned HERE, so a pin that names nothing checks nothing
 *            and fails, rather than passing by omission)
 *   digest   every file the pin names is on disk and hashes to the sha256 recorded for it
 *   sibling  ONLY when an agent-seam checkout is beside this one (../agent-seam, or wherever
 *            $MURETAI_AGENT_SEAM points) and has the pinned commit: `git show
 *            <commit>:<source>` produces every vendored byte — so a pin cannot name a commit
 *            it was not taken from — and how many commits behind that checkout's HEAD the pin
 *            is. No sibling, or a sibling without that commit, is one `skip:` line and exit 0:
 *            never a failure, never silence.
 *
 * Nothing here writes anywhere, and the sibling is read only through `git show` of a
 * committed object — what sits in its working tree does not matter.
 *
 *     php tests/check_vendor.php
 *     MURETAI_AGENT_SEAM=/path/to/agent-seam php tests/check_vendor.php
 *
 * Exit status 0 only when every check passed.
 */

declare(strict_types=1);

// COMMAND LINE ONLY. These files ship inside the plugin directory, which means they sit
// under the webroot on a normal install — so without this a stranger could execute them by
// URL. `php_sapi_name()` is the check that cannot be spoofed by a request.
if (PHP_SAPI !== 'cli' && PHP_SAPI !== 'cli-server') {
    http_response_code(404);
    exit;
}

$ROOT = dirname(__DIR__);
$PIN = __DIR__ . '/VENDOR.json';

/** The one transform this plugin applies to a vendored file: plugin files sit under the
 *  webroot, so the wire implementation opens with a guard refusing to run when loaded
 *  outside WordPress and outside the test harness. agent-seam has no business knowing
 *  that, so the guard is added on the way in — and re-derived here, from the same anchor,
 *  so the puller and the checker cannot drift apart. */
function applyWordpressGuard(string $src): string
{
    $anchor = "namespace Muretai\\AgentEntry;\n\n";
    if (strpos($src, $anchor) === false) {
        return $src;   // no anchor: let the comparison fail loudly rather than guess
    }
    $guard = "if (!defined('ABSPATH') && !defined('MURETAI_AGENT_ENTRY_STANDALONE')) {\n"
        . "    // Loaded outside both WordPress and the test harness: refuse rather than run.\n"
        . "    exit;\n}\n\n";
    return str_replace($anchor, $anchor . $guard, $src);
}

/** The copies this repository must carry, by the path VENDOR.json lists them under. */
$EXPECTED = ['includes/class-wire.php', 'tests/wire_vectors.json'];

$pass = 0;
$fail = [];
$pin = null;

function check(bool $cond, string $label, string $detail = ''): bool
{
    global $pass, $fail;
    if ($cond) {
        $pass++;
        echo "ok: {$label}\n";
    } else {
        $fail[] = $label;
        echo "FAIL: {$label}" . ($detail !== '' ? "  ({$detail})" : '') . "\n";
    }
    return $cond;
}

function report(): void
{
    global $pass, $fail, $EXPECTED, $pin;
    echo str_repeat('-', 60) . "\n";
    if ($fail !== []) {
        echo 'FAILED: ' . count($fail) . ' of ' . ($pass + count($fail)) . " checks\n";
        echo '  failed: ' . implode('; ', $fail) . "\n";
        echo "A drift here is not cosmetic: these are the vectors every implementation is held\n"
            . "to, and a copy that is not upstream's bytes proves nothing about this twin.\n";
        exit(1);
    }
    // A count nobody asserts is a count that can quietly fall: readable + shape, then
    // listed + present + sha256 for every expected copy.
    $floor = 2 + 3 * count($EXPECTED);
    if ($pass < $floor) {
        echo "FAILED: only {$pass} checks ran, and at least {$floor} were expected. Read the rows above.\n";
        exit(1);
    }
    echo "OK: {$pass} checks — tests/wire_vectors.json is agent-seam's vectors/wire_vectors.json as vendored at "
        . $pin['ref'] . ' (' . substr($pin['commit'], 0, 7) . ', agent-seam ' . $pin['version'] . ").\n";
    exit(0);
}

/**
 * Run git in $dir with no shell in between: [exit status, stdout as raw bytes].
 *
 * Stdout is read whole and binary-safe — `exec()` would strip line endings, and a
 * byte-for-byte comparison cannot afford that. Stderr goes nowhere: a missing commit or
 * path is a RESULT here, reported by the caller, not noise on the terminal.
 *
 * @param string[] $args
 * @return array{0:int,1:string}
 */
function git(string $dir, array $args): array
{
    $null = PHP_OS_FAMILY === 'Windows' ? 'NUL' : '/dev/null';
    $spec = [0 => ['file', $null, 'r'], 1 => ['pipe', 'w'], 2 => ['file', $null, 'a']];
    $pipes = [];
    $proc = @proc_open(array_merge(['git', '-C', $dir], $args), $spec, $pipes);
    if (!is_resource($proc)) {
        return [127, ''];
    }
    $out = stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    return [proc_close($proc), $out === false ? '' : $out];
}

// ---------------------------------------------------------------- the pin

$raw = @file_get_contents($PIN);
$pin = is_string($raw) ? json_decode($raw, true) : null;
if (!check(is_array($pin), 'pin/VENDOR.json-readable', "{$PIN} is missing or is not JSON")) {
    report();
}

$files = $pin['files'] ?? null;
check(
    ($pin['from'] ?? null) === 'agent-seam'
        && is_string($pin['ref'] ?? null) && $pin['ref'] !== ''
        && is_string($pin['commit'] ?? null) && preg_match('/^[0-9a-f]{40}$/', $pin['commit']) === 1
        && is_string($pin['version'] ?? null)
        && is_array($files) && $files !== [],
    'pin/VENDOR.json-shape',
    'VENDOR.json must carry from=agent-seam, a ref, a 40-hex commit, a version and a non-empty files map'
);
if (!is_array($files)) {
    $files = [];
}
foreach ($EXPECTED as $p) {
    check(isset($files[$p]), "pin/{$p}-listed", "VENDOR.json does not list {$p}");
}

// ---------------------------------------------------------------- the digests

foreach ($files as $p => $v) {
    $p = (string) $p;
    $local = $ROOT . '/' . $p;
    if (!check(is_file($local), "pin/{$p}-present", "{$p} is named by VENDOR.json but is not on disk")) {
        continue;
    }
    $want = strtolower((string) ($v['sha256'] ?? ''));
    $got = (string) hash_file('sha256', $local);
    check(
        $got === $want && $want !== '',
        "pin/{$p}-sha256",
        'on disk ' . substr($got, 0, 12) . ', VENDOR.json says ' . substr($want, 0, 12)
            . ' — edited in place? re-take the copy from agent-seam at a tag and update the pin'
    );
}
if ($fail !== []) {
    report();
}

// ---------------------------------------------------------------- the sibling, when it is there
//
// Resolved against the repository root, like the JS door's twin check: a relative
// MURETAI_AGENT_SEAM means "relative to this plugin", not to wherever php was started.

$env = getenv('MURETAI_AGENT_SEAM');
$sibling = is_string($env) && $env !== '' ? $env : '../agent-seam';
if (!preg_match('#^(?:/|[A-Za-z]:[\\\\/])#', $sibling)) {
    $sibling = $ROOT . '/' . $sibling;
}
$resolved = realpath($sibling);
if ($resolved !== false) {
    $sibling = $resolved;
}
$commit = (string) $pin['commit'];
$short = substr($commit, 0, 7);

if (!file_exists($sibling . '/.git')) {
    echo "  skip: no agent-seam checkout at {$sibling} — the pin was verified by digest only"
        . " (set MURETAI_AGENT_SEAM to check the recorded commit too)\n";
} else {
    [$status] = git($sibling, ['cat-file', '-e', $commit . '^{commit}']);
    if ($status === 127) {
        echo "  skip: git could not be run, so {$sibling} was not consulted — the pin was verified by digest only\n";
    } elseif ($status !== 0) {
        echo "  skip: {$sibling} has no commit {$short} — the pin was verified by digest only"
            . " (fetch there, or point MURETAI_AGENT_SEAM at a checkout that has it)\n";
    } else {
        foreach ($files as $p => $v) {
            $p = (string) $p;
            $source = (string) ($v['source'] ?? '');
            [$st, $theirs] = git($sibling, ['show', "{$commit}:{$source}"]);
            // A recorded transform is applied HERE, identically to the way
            // tools/vendor-seam.php applies it on the way in. A transform only the puller
            // knows how to perform is a pin nobody can check: the digest would still hold
            // the copy to itself, and the sibling half — the half that proves the bytes
            // came from the commit the pin names — would report a lie every time.
            if ($st === 0 && ($v['transform'] ?? null) === 'wordpress-guard') {
                $theirs = applyWordpressGuard($theirs);
            }
            $mine = (string) file_get_contents($ROOT . '/' . $p);
            check(
                $st === 0 && $theirs === $mine,
                "sibling/{$p}-is-what-{$short}-produces",
                $st !== 0
                    ? "{$short} has no {$source}"
                    : "the pin lies: {$source} at {$short} is " . substr(hash('sha256', $theirs), 0, 12)
                        . ', the copy here is ' . substr(hash('sha256', $mine), 0, 12)
            );
        }
        [, $behind] = git($sibling, ['rev-list', '--count', "{$commit}..HEAD"]);
        [, $head] = git($sibling, ['rev-parse', '--short', 'HEAD']);
        echo "  sibling: {$sibling} — pin {$pin['ref']} ({$short}) is " . trim($behind)
            . ' commit(s) behind its HEAD ' . trim($head) . "\n";
    }
}

report();
