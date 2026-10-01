<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\WordPress;

if (!defined('ABSPATH')) {
    exit;
}

use Anonympins\Fingerprint\Store\IStore;

// Polyfill for ARRAY_A if loaded outside standard WordPress lifecycle
if (!defined('ARRAY_A')) {
    define('ARRAY_A', 'ARRAY_A');
}

/**
 * Persistent IStore adapter for WordPress backed by the global $wpdb database object.
 * Stores device sessions, challenge nonces, and PoW states without
 * requiring external memory stores such as Redis or APCu.
 */
class WpDbStore implements IStore
{
    /** @var \wpdb|object|null */
    private $db;
    private string $table;

    public function __construct($db = null)
    {
        global $wpdb;
        $this->db = $db ?? $wpdb;
        $prefix = (is_object($this->db) && isset($this->db->prefix)) ? $this->db->prefix : 'wp_';
        $this->table = $prefix . 'fingerprint_store';
    }

    /**
     * Creates the storage table if it does not exist yet.
     */
    public function ensureTable(): void
    {
        if (!$this->db || !method_exists($this->db, 'get_charset_collate')) {
            return;
        }

        $charsetCollate = $this->db->get_charset_collate();
        $sql = "CREATE TABLE IF NOT EXISTS {$this->table} (
            `key_id` VARCHAR(191) NOT NULL,
            `value` LONGTEXT NOT NULL,
            `expires_at` BIGINT UNSIGNED NULL,
            PRIMARY KEY (`key_id`),
            KEY `expires_idx` (`expires_at`)
        ) {$charsetCollate};";

        // Safely load dbDelta if ABSPATH is defined
        if (!function_exists('dbDelta') && defined('ABSPATH')) {
            $upgradeFile = ABSPATH . 'wp-admin/includes/upgrade.php';
            if (file_exists($upgradeFile)) {
                require_once $upgradeFile;
            }
        }

        if (function_exists('dbDelta')) {
            dbDelta($sql);
        } elseif (method_exists($this->db, 'query')) {
            $this->db->query($sql);
        }
    }

    public function get(string $key)
    {
        if (!$this->db || !method_exists($this->db, 'prepare')) {
            return null;
        }

        $sql = $this->db->prepare(
            "SELECT `value`, `expires_at` FROM {$this->table} WHERE `key_id` = %s",
            $key
        );
        $outputType = defined('ARRAY_A') ? \ARRAY_A : 'ARRAY_A';
        $row = $this->db->get_row($sql, $outputType);

        if (!$row) {
            return null;
        }

        if ($row['expires_at'] !== null && (int)$row['expires_at'] < time()) {
            $this->delete($key);
            return null;
        }

        $decoded = json_decode((string)$row['value'], true);
        return (json_last_error() === JSON_ERROR_NONE) ? $decoded : $row['value'];
    }

    public function set(string $key, $value, ?int $ttl = null): void
    {
        if (!$this->db || !method_exists($this->db, 'replace')) {
            return;
        }

        $expiresAt = ($ttl !== null && $ttl > 0) ? (time() + $ttl) : null;
        $serialized = is_scalar($value) && !is_bool($value)
            ? (string)$value
            : json_encode($value, JSON_UNESCAPED_SLASHES);

        $this->db->replace(
            $this->table,
            [
                'key_id'     => $key,
                'value'      => $serialized,
                'expires_at' => $expiresAt
            ],
            ['%s', '%s', $expiresAt !== null ? '%d' : null]
        );
    }

    public function has(string $key): bool
    {
        return $this->get($key) !== null;
    }

    public function delete(string $key): void
    {
        if (!$this->db || !method_exists($this->db, 'delete')) {
            return;
        }

        $this->db->delete(
            $this->table,
            ['key_id' => $key],
            ['%s']
        );
    }

    public function clear(): void
    {
        if (!$this->db || !method_exists($this->db, 'query')) {
            return;
        }
        $this->db->query("TRUNCATE TABLE {$this->table}");
    }

    /**
     * Purges expired records (invoked by periodic WP-Cron).
     */
    public function pruneExpired(): int
    {
        if (!$this->db || !method_exists($this->db, 'prepare')) {
            return 0;
        }

        $now = time();
        $deleted = $this->db->query(
            $this->db->prepare("DELETE FROM {$this->table} WHERE `expires_at` IS NOT NULL AND `expires_at` < %d", $now)
        );
        return is_numeric($deleted) ? (int)$deleted : 0;
    }

    /**
     * Returns the total number of records currently stored.
     */
    public function getTotalCount(): int
    {
        if (!$this->db || !method_exists($this->db, 'get_var')) {
            return 0;
        }
        $count = $this->db->get_var("SELECT COUNT(*) FROM `{$this->table}`");
        return is_numeric($count) ? (int)$count : 0;
    }

    /**
     * Returns the number of expired records awaiting cron deletion.
     */
    public function getExpiredCount(): int
    {
        if (!$this->db || !method_exists($this->db, 'get_var') || !method_exists($this->db, 'prepare')) {
            return 0;
        }
        $now = time();
        $count = $this->db->get_var(
            $this->db->prepare("SELECT COUNT(*) FROM `{$this->table}` WHERE expires_at IS NOT NULL AND expires_at < %d", $now)
        );
        return is_numeric($count) ? (int)$count : 0;
    }
}