<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Store;

/**
 * Redis storage adapter for the Fingerprint engine.
 * Compatible with phpredis and predis clients.
 */
class RedisStore implements IStore
{
    /**
     * @var mixed An instance of \Redis or \Predis\Client
     */
    private $redis;

    /**
     * @var InMemoryStore
     */
    private InMemoryStore $fallbackStore;

    /**
     * @var bool
     */
    private bool $isDown = false;

    /**
     * @var float
     */
    private float $lastReconnectAttempt = 0.0;

    /**
     * @param mixed $redis Pre-configured and connected Redis client instance.
     */
    public function __construct($redis)
    {
        $this->redis = $redis;
        $this->fallbackStore = new InMemoryStore();
    }

    private function checkConnection(): void
    {
        if (!$this->isDown) {
            return;
        }

        $now = microtime(true);
        // Retry connection every 5 seconds
        if ($now - $this->lastReconnectAttempt > 5.0) {
            $this->lastReconnectAttempt = $now;
            try {
                if (method_exists($this->redis, 'ping')) {
                    $this->redis->ping();
                } else {
                    $this->redis->exists('connection_test');
                }
                $this->isDown = false;
            } catch (\Throwable $e) {
                $this->isDown = true;
            }
        }
    }

    public function get(string $key)
    {
        $this->checkConnection();
        if ($this->isDown) {
            return $this->fallbackStore->get($key);
        }
        try {
            $value = $this->redis->get($key);
            if ($value === false || $value === null) {
                return null;
            }
            return json_decode($value, true);
        } catch (\Throwable $e) {
            $this->isDown = true;
            $this->lastReconnectAttempt = microtime(true);
            return $this->fallbackStore->get($key);
        }
    }

    public function set(string $key, $value, ?int $ttl = null): void
    {
        $this->checkConnection();
        if ($this->isDown) {
            $this->fallbackStore->set($key, $value, $ttl);
            return;
        }
        try {
            $stringValue = json_encode($value);
            if ($ttl !== null && $ttl > 0) {
                $this->redis->setex($key, $ttl, $stringValue);
            } else {
                $this->redis->set($key, $stringValue);
            }
        } catch (\Throwable $e) {
            $this->isDown = true;
            $this->lastReconnectAttempt = microtime(true);
            $this->fallbackStore->set($key, $value, $ttl);
        }
    }

    public function has(string $key): bool
    {
        $this->checkConnection();
        if ($this->isDown) {
            return $this->fallbackStore->has($key);
        }
        try {
            return (bool)$this->redis->exists($key);
        } catch (\Throwable $e) {
            $this->isDown = true;
            $this->lastReconnectAttempt = microtime(true);
            return $this->fallbackStore->has($key);
        }
    }

    public function delete(string $key): void
    {
        $this->fallbackStore->delete($key);
        $this->checkConnection();
        if ($this->isDown) {
            return;
        }
        try {
            $this->redis->del($key);
        } catch (\Throwable $e) {
            $this->isDown = true;
            $this->lastReconnectAttempt = microtime(true);
        }
    }

    public function clear(): void
    {
        $this->fallbackStore->clear();
        $this->checkConnection();
        if ($this->isDown) return;
        try {
            $this->redis->flushdb();
        } catch (\Throwable $e) {
            $this->isDown = true;
        }
    }
}