<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Store;

/**
 * Implémentation en mémoire de l'interface IStore.
 * Utile pour le développement ou les applications à instance unique sans persistance externe.
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
            $this->delete($key); // Supprime l'élément expiré
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
     * Efface toutes les données du store. Utile pour les tests.
     */
    public function clear(): void
    {
        $this->data = [];
    }
}