<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Store;

/**
 * Manages the global store singleton instance for the application.
 */
class StoreManager
{
    private static ?IStore $store = null;

    /**
     * Returns the current global store instance.
     * Lazily instantiates an InMemoryStore if no store has been configured yet.
     *
     * @return IStore The active store instance.
     */
    public static function getStore(): IStore
    {
        if (self::$store === null) {
            self::$store = new InMemoryStore();
        }
        return self::$store;
    }

    /**
     * Replaces the active store with an externally provided IStore implementation.
     * Typically used at bootstrap to plug in a persistent store (Redis, database, etc.).
     *
     * @param IStore $externalStore The external store implementation to use.
     * @return void
     */
    public static function configureStore(IStore $externalStore): void
    {
        self::$store = $externalStore;
    }

    /**
     * Sets the active store instance. Useful for dependency injection and testing.
     *
     * @param mixed $store
     */
    public static function setStore($store): void
    {
        self::$store = $store;
    }
}