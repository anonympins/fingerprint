<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Store;

/**
 * Interface for a persistent storage adapter (device data, challenge nonces, tickets).
 */
interface IStore
{
    /**
     * Retrieves a value associated with a key.
     * @param string $key
     * @return mixed|null
     */
    public function get(string $key);

    /**
     * Stores a value associated with a key, with an optional TTL.
     * @param string $key
     * @param mixed $value
     * @param int|null $ttl Time to live in seconds.
     * @return void
     */
    public function set(string $key, $value, ?int $ttl = null): void;

    /**
     * Checks whether a key exists in storage.
     * @param string $key
     * @return bool
     */
    public function has(string $key): bool;

    /**
     * Deletes a key from storage.
     * @param string $key
     * @return void
     */
    public function delete(string $key): void;

    /**
     * Clears all keys from storage.
     * @return void
     */
    public function clear(): void;
}