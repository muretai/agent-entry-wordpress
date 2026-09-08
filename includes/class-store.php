<?php
/**
 * Store.php — every piece of state the door keeps, behind one seam.
 *
 * WHY A SEAM AT ALL. Four structures decide security answers, and each fails differently
 * when it evaporates:
 *
 *   - the LEDGER (DID -> account row). The site's customer list, and the only reason a
 *     returning visitor is recognised as the same customer rather than a new stranger.
 *     Losing it is a business loss, not a security one.
 *   - the REPLAY set (messageId -> expiry). Read synchronously on every message. Losing it
 *     re-opens every message inside the freshness window to replay.
 *   - the DEVICE->OWNER pins. Losing them resets the account layer to trust-on-first-use,
 *     so a device pinned to owner A can be re-claimed by owner B.
 *   - the RATE counters. Losing them lifts the ceiling.
 *
 * On WordPress all four go in the database, which is why the seam exists: MemoryStore
 * below is for tests, WpdbStore is what the plugin actually runs, and a third
 * implementation (Redis, an object cache) can be dropped in without touching the ladder in
 * class-entry.php. The interface is deliberately the same shape core's own backlog
 * proposed for serverless runtimes (T105): getAccount / putAccount / getDeviceOwner /
 * putDeviceOwner / seenMessage.
 *
 * @package Muretai\AgentEntry
 */

namespace Muretai\AgentEntry;

if (!defined('ABSPATH') && !defined('MURETAI_AGENT_ENTRY_STANDALONE')) {
    exit;
}

/**
 * The state a door needs between requests.
 */
interface Store
{
    /**
     * Remember `$messageId` for `$ttl` seconds.
     *
     * @return bool TRUE when the id was NEW (and is now remembered), FALSE when it is a
     *              replay. The test and the remember MUST be atomic: two concurrent
     *              requests carrying one id must not both be told "new".
     */
    public function seenMessage(string $messageId, int $ttl): bool;

    /** Record contact from `$did`, creating the account row on first contact. */
    public function noteContact(string $did): array;

    /** The account row for `$did`, or null. */
    public function getAccount(string $did): ?array;

    /**
     * Write the account row for `$did` — or DELETE it, when `$row` is null.
     *
     * The one caller is the fold that runs when a device with an existing UNBOUND row
     * first proves its owner (Entry::foldDeviceIntoOwner): the device's history moves to
     * the owner and the device row goes. `noteContact` still owns the ordinary path, so
     * nothing else in the plugin writes a row by hand.
     */
    public function putAccount(string $did, ?array $row): void;

    /** The owner a device DID is pinned to, or null when unpinned. */
    public function getDeviceOwner(string $deviceDid): ?string;

    /** Pin a device to an owner. Must REFUSE to move an existing pin. */
    public function putDeviceOwner(string $deviceDid, string $ownerDid): bool;

    /** @return bool true when `$key` is under `$perMin` in the current minute. */
    public function allowRate(string $key, int $perMin): bool;

    /** The cached signed card envelope: ['ts' => int, 'bytes' => string] or null. */
    public function getCardEnvelope(): ?array;

    public function putCardEnvelope(int $ts, string $bytes): void;
}

/**
 * An in-memory Store. For tests and for a single short-lived process only — a WordPress
 * request ends and takes this with it, which is exactly the cold-start failure the
 * database-backed store exists to avoid.
 */
final class MemoryStore implements Store
{
    private $replay = [];
    private $ledger = [];
    private $pins = [];
    private $rate = [];
    private $cardEnvelope = null;

    public function seenMessage(string $messageId, int $ttl): bool
    {
        $now = time();
        foreach ($this->replay as $id => $exp) {
            if ($exp <= $now) {
                unset($this->replay[$id]);
            }
        }
        if (isset($this->replay[$messageId]) && $this->replay[$messageId] > $now) {
            return false;
        }
        $this->replay[$messageId] = $now + $ttl;
        return true;
    }

    public function noteContact(string $did): array
    {
        $now = time();
        if (!isset($this->ledger[$did])) {
            $this->ledger[$did] = ['did' => $did, 'messages' => 0,
                'first_seen' => $now, 'last_seen' => $now, 'new' => true];
        } else {
            $this->ledger[$did]['new'] = false;
        }
        $this->ledger[$did]['messages']++;
        $this->ledger[$did]['last_seen'] = $now;
        return $this->ledger[$did];
    }

    public function getAccount(string $did): ?array
    {
        return $this->ledger[$did] ?? null;
    }

    public function putAccount(string $did, ?array $row): void
    {
        if ($row === null) {
            unset($this->ledger[$did]);
            return;
        }
        $this->ledger[$did] = $row;
    }

    public function getDeviceOwner(string $deviceDid): ?string
    {
        return $this->pins[$deviceDid] ?? null;
    }

    public function putDeviceOwner(string $deviceDid, string $ownerDid): bool
    {
        if (isset($this->pins[$deviceDid]) && $this->pins[$deviceDid] !== $ownerDid) {
            return false;                 // no re-ownership, ever
        }
        $this->pins[$deviceDid] = $ownerDid;
        return true;
    }

    public function allowRate(string $key, int $perMin): bool
    {
        $minute = intdiv(time(), 60);
        $slot = $key . '@' . $minute;
        $this->rate[$slot] = ($this->rate[$slot] ?? 0) + 1;
        return $this->rate[$slot] <= $perMin;
    }

    public function getCardEnvelope(): ?array
    {
        return $this->cardEnvelope;
    }

    public function putCardEnvelope(int $ts, string $bytes): void
    {
        $this->cardEnvelope = ['ts' => $ts, 'bytes' => $bytes];
    }

    /** Test helper: the whole ledger. */
    public function ledger(): array
    {
        return $this->ledger;
    }
}
