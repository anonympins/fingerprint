<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Store;

/**
 * Interface pour un système de stockage persistant.
 * Utilisé pour stocker les données des appareils, les secrets des challenges, etc.
 */
interface IStore
{
    /**
     * Récupère une valeur associée à une clé.
     * @param string $key
     * @return mixed|null
     */
    public function get(string $key);

    /**
     * Stocke une valeur associée à une clé, avec une durée de vie optionnelle.
     * @param string $key
     * @param mixed $value
     * @param int|null $ttl Durée de vie en secondes.
     * @return void
     */
    public function set(string $key, $value, ?int $ttl = null): void;

    /**
     * Vérifie si une clé existe dans le stockage.
     * @param string $key
     * @return bool
     */
    public function has(string $key): bool;

    /**
     * Supprime une clé du stockage.
     * @param string $key
     * @return void
     */
    public function delete(string $key): void;
}