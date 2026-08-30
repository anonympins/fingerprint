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
        // En PHP, on travaille avec des tableaux, donc pas de conversion de Set nécessaire,
        // mais on s'assure que la valeur est un tableau si elle contient des clés comme 'ips'.
        if (is_array($value) && isset($value['ips']) && $value['ips'] instanceof \SplFixedArray) {
            $value['ips'] = $value['ips']->toArray();
        }

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