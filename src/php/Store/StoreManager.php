<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Store;

/**
 * Manages the global store singleton instance for the application.
 */
class StoreManager
{
    private static ?IStore $store = null;

    public static function getStore(): IStore
    {
        if (self::$store === null) {
            self::$store = new InMemoryStore();
        }
        return self::$store;
    }

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