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

    public function get(string $key)
    {
        if (!isset($this->data[$key])) {
            return null;
        }

        $item = $this->data[$key];
        if ($item['expiresAt'] !== null && $item['expiresAt'] < time()) {
            $this->delete($key); // Delete expired item
            return null;
        }

        return $item['value'];
    }

    public function set(string $key, $value, ?int $ttl = null): void
    {
        $expiresAt = $ttl !== null ? time() + $ttl : null;

        $this->data[$key] = ['value' => $value, 'expiresAt' => $expiresAt];
    }

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

    public function delete(string $key): void
    {
        unset($this->data[$key]);
    }

    /**
     * Clears all data from the store. Useful for testing.
     */
    public function clear(): void
    {
        $this->data = [];
    }
}