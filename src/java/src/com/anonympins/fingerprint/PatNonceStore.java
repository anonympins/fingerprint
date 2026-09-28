package com.anonympins.fingerprint;

/**
 * Interface du magasin d'état anti-rejeu des nonces.
 */
public interface PatNonceStore {
    /**
     * Vérifie si un nonce a déjà été consommé.
     *
     * @param nonceHex Nonce encodé en hexadécimal.
     * @return true si le nonce existe déjà (rejeu).
     */
    boolean exists(String nonceHex);

    /**
     * Enregistre un nonce avec une durée de validité (TTL).
     *
     * @param nonceHex Nonce encodé en hexadécimal.
     * @param ttlSeconds Durée de rétention en secondes.
     */
    void set(String nonceHex, long ttlSeconds);
}