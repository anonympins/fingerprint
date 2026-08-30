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

        // Gère la conversion des tableaux en Set pour 'ips' comme dans la version JS
        if (is_array($item['value']) && isset($item['value']['ips']) && is_array($item['value']['ips'])) {
            $item['value']['ips'] = new \SplFixedArray(count($item['value']['ips']));
            foreach ($item['value']['ips'] as $i => $ip) {
                $item['value']['ips'][$i] = $ip;
            }
        }

        return $item['value'];
    }

    public function set(string $key, $value, ?int $ttl = null): void
    {
        $expiresAt = $ttl !== null ? time() + $ttl : null;

        // Gère la conversion des Set en tableaux pour 'ips' comme dans la version JS
        if (is_object($value) && property_exists($value, 'ips') && $value->ips instanceof \SplFixedArray) {
            $value->ips = $value->ips->toArray();
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
}