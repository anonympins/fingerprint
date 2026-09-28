<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Store;

/**
 * In-memory implementation of the IStore interface.
 * Suitable for local development, tests, or single-instance deployments.
 */
class InMemoryStore implements IStore
{
    /**
     * @var array<string, array{value: mixed, expiresAt: int|null}>
     */
    private array $data = [];

    /**
     * Retrieves the value associated with the given key.
     * If the stored item has expired, it is deleted and null is returned.
     *
     * @param string $key The key to look up.
     * @return mixed The stored value, or null if the key is missing or expired.
     */
    public function get(string $key)
    {
        if (!isset($this->data[$key])) {
            return null;
        }

        $item = $this->data[$key];
        if ($item['expiresAt'] !== null && $item['expiresAt'] < time()) { // Active expiration check
            $this->delete($key); // Delete expired item
            return null;
        }

        return $item['value'];
    }

    /**
     * Stores a value under the given key, with an optional TTL (in seconds).
     * If `$ttl` is null, the item never expires.
     *
     * @param string $key The key to store the value under.
     * @param mixed $value The value to store.
     * @param int|null $ttl Optional time-to-live in seconds.
     * @return void
     */
    public function set(string $key, $value, ?int $ttl = null): void
    {
        $expiresAt = $ttl !== null ? time() + $ttl : null;

        $this->data[$key] = ['value' => $value, 'expiresAt' => $expiresAt];
    }

    /**
     * Checks whether the given key exists and has not expired.
     * Expired items are deleted on access.
     *
     * @param string $key The key to check.
     * @return bool True if the key exists and is valid, false otherwise.
     */
    public function has(string $key): bool
    {
        if (!isset($this->data[$key])) {
            return false;
        }

        $item = $this->data[$key];
        if ($item['expiresAt'] !== null && $item['expiresAt'] < time()) {
            $this->delete($key);
            return false;
        }

        return true;
    }

    /**
     * Deletes the value associated with the given key.
     * Does nothing if the key does not exist.
     *
     * @param string $key The key to delete.
     * @return void
     */
    public function delete(string $key): void
    {
        unset($this->data[$key]);
    }

    /**
     * Clears all data from the store. Useful for test isolation.
     */
    public function clear(): void
    {
        $this->data = [];
    }
}