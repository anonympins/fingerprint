<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Store;

/**
 * Adaptateur de stockage Redis pour le moteur Fingerprint.
 * Compatible avec phpredis et predis.
 */
class RedisStore implements IStore
{
    /**
     * @var mixed Une instance de \Redis ou de \Predis\Client
     */
    private $redis;

    /**
     * @param mixed $redis Client Redis déjà configuré et connecté
     */
    public function __construct($redis)
    {
        $this->redis = $redis;
    }

    public function get(string $key)
    {
        $value = $this->redis->get($key);
        if ($value === false || $value === null) {
            return null;
        }
        return json_decode($value, true);
    }

    public function set(string $key, $value, ?int $ttl = null): void
    {
        $stringValue = json_encode($value);
        if ($ttl !== null && $ttl > 0) {
            $this->redis->setex($key, $ttl, $stringValue);
        } else {
            $this->redis->set($key, $stringValue);
        }
    }

    public function has(string $key): bool
    {
        return (bool)$this->redis->exists($key);
    }

    public function delete(string $key): void
    {
        $this->redis->del($key);
    }
}