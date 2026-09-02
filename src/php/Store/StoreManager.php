<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Store;

/**
 * Gère l'instance du store global.
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
     * Définit l'instance active du store (utile pour l'injection de dépendances et les tests).
     *
     * @param mixed $store
     */
    public static function setStore($store): void
    {
        self::$store = $store;
    }
}