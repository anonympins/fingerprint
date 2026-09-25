<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\WordPress;

if (!defined('ABSPATH')) {
    exit;
}

use Anonympins\Fingerprint\Store\IStore;

// Polyfill pour ARRAY_A si chargé hors du cycle de vie standard de WordPress
if (!defined('ARRAY_A')) {
    define('ARRAY_A', 'ARRAY_A');
}

/**
 * Adaptateur IStore persistant pour WordPress exploitant l'objet $wpdb.
 * Permet de stocker les sessions d'appareils, nonces et états de PoW
 * sans dépendre d'une extension mémoire comme Redis ou APCu.
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
     * Crée la table de stockage si elle n'existe pas encore.
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

        // Chargement sécurisé de dbDelta si ABSPATH est présent
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
     * Nettoie les lignes expirées (appelé par le WP-Cron périodique).
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
}