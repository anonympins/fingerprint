<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Store;

/**
 * Adaptateur de stockage MongoDB pour le moteur Fingerprint.
 * Utilise la bibliothèque officielle mongodb/mongodb.
 */
class MongoDbStore implements IStore
{
    /**
     * @var \MongoDB\Collection
     */
    private $collection;

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
     * @param \MongoDB\Collection $collection Collection dédiée au stockage des empreintes
     */
    public function __construct($collection)
    {
        $this->collection = $collection;
        $this->fallbackStore = new InMemoryStore();
    }

    private function checkConnection(): void
    {
        if (!$this->isDown) {
            return;
        }

        $now = microtime(true);
        if ($now - $this->lastReconnectAttempt > 5.0) {
            $this->lastReconnectAttempt = $now;
            try {
                $this->collection->findOne([], ['projection' => ['_id' => 1]]);
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
            $doc = $this->collection->findOne(['_id' => $key]);
            if (!$doc) {
                return null;
            }

            // Vérification d'expiration active pour bypasser le délai de 60s du démon de MongoDB
            if (isset($doc['expiresAt'])) {
                $expiresAt = $doc['expiresAt'];
                if ($expiresAt instanceof \MongoDB\BSON\UTCDateTime) {
                    $expiresAtMs = $expiresAt->toDateTime()->getTimestamp() * 1000;
                    $nowMs = (int)(microtime(true) * 1000);
                    if ($expiresAtMs < $nowMs) {
                        $this->delete($key);
                        return null;
                    }
                }
            }

            return isset($doc['value']) ? json_decode($doc['value'], true) : null;
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
            $doc = [
                '_id' => $key,
                'value' => json_encode($value),
            ];

            if ($ttl !== null && $ttl > 0) {
                $doc['expiresAt'] = new \MongoDB\BSON\UTCDateTime((time() + $ttl) * 1000);
            }

            $this->collection->replaceOne(
                ['_id' => $key],
                $doc,
                ['upsert' => true]
            );
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
            $doc = $this->collection->findOne(
                ['_id' => $key],
                ['projection' => ['expiresAt' => 1]]
            );

            if (!$doc) {
                return false;
            }

            if (isset($doc['expiresAt']) && $doc['expiresAt'] instanceof \MongoDB\BSON\UTCDateTime) {
                $expiresAtMs = $doc['expiresAt']->toDateTime()->getTimestamp() * 1000;
                $nowMs = (int)(microtime(true) * 1000);
                if ($expiresAtMs < $nowMs) {
                    $this->delete($key);
                    return false;
                }
            }

            return true;
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
            $this->collection->deleteOne(['_id' => $key]);
        } catch (\Throwable $e) {
            $this->isDown = true;
            $this->lastReconnectAttempt = microtime(true);
        }
    }

    /**
     * Automatise la configuration de l'index TTL nécessaire dans MongoDB.
     */
    public function init(): void
    {
        try {
            $this->collection->createIndex(
                ['expiresAt' => 1],
                ['expireAfterSeconds' => 0]
            );
        } catch (\Throwable $e) {
            $this->isDown = true;
            $this->lastReconnectAttempt = microtime(true);
        }
    }
}