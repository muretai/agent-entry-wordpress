<?php
/**
 * WpdbStore.php — the door's state, in the site's own database.
 *
 * The one interesting method here is `seenMessage`, and the interesting part of it is
 * ATOMICITY. Two concurrent requests carrying the same messageId must not both be told
 * "new"; if they can be, the replay defence is decorative under exactly the load an
 * attacker would generate. PHP has no shared memory between requests, so the atomicity has
 * to come from the database:
 *
 *   1. DELETE the row for THIS id if it has expired (so an id may be reused after its TTL)
 *   2. INSERT IGNORE the id
 *   3. it was new if and only if step 2 inserted a row
 *
 * A PRIMARY KEY on `message_id` makes step 2 the atomic test-and-set. The residual race is
 * between 1 and 2, and it resolves the safe way: the loser is told "replay" and retries,
 * rather than the loser being told "new" and a replay getting through.
 *
 * The replay table is also swept in bulk by WP-Cron, because deleting only the row you
 * looked at leaves every id nobody asked about again to accumulate forever.
 *
 * @package Muretai\AgentEntry
 */

namespace Muretai\AgentEntry;

if (!defined('ABSPATH')) {
    exit;
}

require_once __DIR__ . '/class-store.php';

final class WpdbStore implements Store
{
    /** Option holding the cached signed card envelope. Not autoloaded: it is only read on
     *  a request for the signed card, and it is large. */
    private const OPT_CARD_ENVELOPE = 'muretai_agent_entry_card_envelope';

    /** @var \wpdb */
    private $db;

    public function __construct($wpdb = null)
    {
        $this->db = $wpdb ?: $GLOBALS['wpdb'];
    }

    public function ledgerTable(): string
    {
        return $this->db->prefix . 'muretai_ledger';
    }

    public function replayTable(): string
    {
        return $this->db->prefix . 'muretai_replay';
    }

    public function pinTable(): string
    {
        return $this->db->prefix . 'muretai_pins';
    }

    /**
     * Create the tables. Called on activation and safe to re-run (dbDelta is idempotent).
     *
     * `message_id` is varchar(191) rather than 255 because a PRIMARY KEY on a utf8mb4
     * column is capped at 767 bytes on older MySQL, and 191*4 is the largest that fits.
     * A messageId is a short opaque token, so the limit costs nothing.
     */
    public static function install(): void
    {
        global $wpdb;
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $charset = $wpdb->get_charset_collate();
        $p = $wpdb->prefix;

        dbDelta("CREATE TABLE {$p}muretai_ledger (
            did varchar(191) NOT NULL,
            messages bigint(20) unsigned NOT NULL DEFAULT 0,
            first_seen bigint(20) unsigned NOT NULL DEFAULT 0,
            last_seen bigint(20) unsigned NOT NULL DEFAULT 0,
            PRIMARY KEY (did),
            KEY last_seen (last_seen)
        ) {$charset};");

        dbDelta("CREATE TABLE {$p}muretai_replay (
            message_id varchar(191) NOT NULL,
            expires bigint(20) unsigned NOT NULL DEFAULT 0,
            PRIMARY KEY (message_id),
            KEY expires (expires)
        ) {$charset};");

        dbDelta("CREATE TABLE {$p}muretai_pins (
            device_did varchar(191) NOT NULL,
            owner_did varchar(191) NOT NULL,
            pinned_at bigint(20) unsigned NOT NULL DEFAULT 0,
            PRIMARY KEY (device_did)
        ) {$charset};");
    }

    public function seenMessage(string $messageId, int $ttl): bool
    {
        $now = time();
        $t = $this->replayTable();
        // Step 1: this id, but only if it has already expired.
        $this->db->query($this->db->prepare(
            "DELETE FROM {$t} WHERE message_id = %s AND expires <= %d", $messageId, $now
        ));
        // Step 2: the atomic test-and-set. INSERT IGNORE turns the duplicate-key error
        // into "0 rows affected", which is exactly the answer we want.
        $this->db->query($this->db->prepare(
            "INSERT IGNORE INTO {$t} (message_id, expires) VALUES (%s, %d)",
            $messageId, $now + $ttl
        ));
        return (int) $this->db->rows_affected === 1;
    }

    /** Bulk expiry, for WP-Cron. Looking up one id only ever deletes that id. */
    public function sweepReplay(): int
    {
        $t = $this->replayTable();
        $this->db->query($this->db->prepare("DELETE FROM {$t} WHERE expires <= %d", time()));
        return (int) $this->db->rows_affected;
    }

    public function noteContact(string $did): array
    {
        $now = time();
        $t = $this->ledgerTable();
        // One statement, so a returning visitor cannot race themselves into two rows.
        $this->db->query($this->db->prepare(
            "INSERT INTO {$t} (did, messages, first_seen, last_seen) VALUES (%s, 1, %d, %d)
             ON DUPLICATE KEY UPDATE messages = messages + 1, last_seen = %d",
            $did, $now, $now, $now
        ));
        $row = $this->getAccount($did);
        if ($row === null) {
            return ['did' => $did, 'messages' => 1, 'first_seen' => $now,
                'last_seen' => $now, 'new' => true];
        }
        $row['new'] = ((int) $row['messages']) === 1;
        return $row;
    }

    public function getAccount(string $did): ?array
    {
        $t = $this->ledgerTable();
        $row = $this->db->get_row($this->db->prepare(
            "SELECT did, messages, first_seen, last_seen FROM {$t} WHERE did = %s", $did
        ), ARRAY_A);
        if (!is_array($row)) {
            return null;
        }
        return [
            'did' => (string) $row['did'],
            'messages' => (int) $row['messages'],
            'first_seen' => (int) $row['first_seen'],
            'last_seen' => (int) $row['last_seen'],
        ];
    }

    /** The whole ledger, newest contact first — what the admin screen shows. */
    public function recentAccounts(int $limit = 25): array
    {
        $t = $this->ledgerTable();
        $rows = $this->db->get_results($this->db->prepare(
            "SELECT did, messages, first_seen, last_seen FROM {$t}
             ORDER BY last_seen DESC LIMIT %d", $limit
        ), ARRAY_A);
        return is_array($rows) ? $rows : [];
    }

    public function countAccounts(): int
    {
        $t = $this->ledgerTable();
        return (int) $this->db->get_var("SELECT COUNT(*) FROM {$t}");
    }

    public function getDeviceOwner(string $deviceDid): ?string
    {
        $t = $this->pinTable();
        $owner = $this->db->get_var($this->db->prepare(
            "SELECT owner_did FROM {$t} WHERE device_did = %s", $deviceDid
        ));
        return $owner === null ? null : (string) $owner;
    }

    public function putDeviceOwner(string $deviceDid, string $ownerDid): bool
    {
        $t = $this->pinTable();
        // INSERT IGNORE, never UPDATE: a pin that can move is not a pin. A device already
        // claimed by owner A must not become owner B's on a later request, which is the
        // whole property this table exists to hold.
        $this->db->query($this->db->prepare(
            "INSERT IGNORE INTO {$t} (device_did, owner_did, pinned_at) VALUES (%s, %s, %d)",
            $deviceDid, $ownerDid, time()
        ));
        if ((int) $this->db->rows_affected === 1) {
            return true;
        }
        return $this->getDeviceOwner($deviceDid) === $ownerDid;
    }

    /**
     * A per-minute counter in the object cache. Deliberately NOT a database table: a rate
     * bound that costs a write per request is its own denial of service, and losing a
     * counter fails OPEN for one minute, which is a bounded and acceptable loss.
     */
    public function allowRate(string $key, int $perMin): bool
    {
        $slot = 'muretai_rate_' . md5($key . '@' . intdiv(time(), 60));
        $n = (int) get_transient($slot);
        $n++;
        set_transient($slot, $n, 120);
        return $n <= $perMin;
    }

    public function getCardEnvelope(): ?array
    {
        $v = get_option(self::OPT_CARD_ENVELOPE, null);
        if (!is_array($v) || !isset($v['ts'], $v['bytes'])) {
            return null;
        }
        return ['ts' => (int) $v['ts'], 'bytes' => (string) $v['bytes']];
    }

    public function putCardEnvelope(int $ts, string $bytes): void
    {
        update_option(self::OPT_CARD_ENVELOPE, ['ts' => $ts, 'bytes' => $bytes], false);
    }
}
