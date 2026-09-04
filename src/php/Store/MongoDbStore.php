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
     * @param \MongoDB\Collection $collection Collection dédiée au stockage des empreintes
     */
    public function __construct($collection)
    {
        $this->collection = $collection;
    }

    public function get(string $key)
    {
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
    }

    public function set(string $key, $value, ?int $ttl = null): void
    {
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
    }

    public function has(string $key): bool
    {
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
    }

    public function delete(string $key): void
    {
        $this->collection->deleteOne(['_id' => $key]);
    }

    /**
     * Automatise la configuration de l'index TTL nécessaire dans MongoDB.
     */
    public function init(): void
    {
        $this->collection->createIndex(
            ['expiresAt' => 1],
            ['expireAfterSeconds' => 0]
        );
    }
}