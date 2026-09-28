package com.anonympins.fingerprint;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Moteur de validation des Private Access Tokens (PAT).
 * Contrôle l'anti-rejeu et accorde le bypass instantané à score 0.0 sans calcul PoW.
 */
public class PatValidator {
    private final Map<String, PublicKey> trustedKeys;
    private final PublicKey defaultPublicKey;
    private final PatNonceStore nonceStore;
    private final long nonceTtlSeconds;

    public PatValidator(Map<String, PublicKey> trustedKeys, PublicKey defaultPublicKey,
                        PatNonceStore nonceStore, long nonceTtlSeconds) {
        this.trustedKeys = trustedKeys != null ? new HashMap<>(trustedKeys) : new HashMap<>();
        this.defaultPublicKey = defaultPublicKey;
        this.nonceStore = nonceStore;
        this.nonceTtlSeconds = nonceTtlSeconds > 0 ? nonceTtlSeconds : 86400L;
    }

    public PatValidator(Map<String, PublicKey> trustedKeys, PatNonceStore nonceStore) {
        this(trustedKeys, null, nonceStore, 86400L);
    }

    /**
     * Évalue les en-têtes HTTP de la requête et accorde le bypass zéro-friction si un jeton PAT est valide.
     *
     * @param headers En-têtes HTTP reçus.
     * @return Résultat d'évaluation.
     */
    public PatValidationResult processRequestHeaders(Map<String, String> headers) {
        List<byte[]> rawTokens = PatUtils.extractTokens(headers);
        if (rawTokens.isEmpty()) {
            return PatValidationResult.notApplicable();
        }

        for (byte[] rawToken : rawTokens) {
            PrivateAccessToken parsedToken = PatUtils.parseToken(rawToken);
            if (parsedToken == null) {
                continue;
            }

            String nonceHex = parsedToken.getNonceHex();
            if (nonceStore != null && nonceStore.exists(nonceHex)) {
                // Rejeu détecté : rejet immédiat du jeton consommé
                continue;
            }

            PublicKey key = resolveKey(parsedToken.getTokenKeyIdHex());
            if (key == null) {
                continue;
            }

            boolean isValid = PatUtils.verifySignature(parsedToken, key);
            if (isValid) {
                if (nonceStore != null) {
                    nonceStore.set(nonceHex, nonceTtlSeconds);
                }
                return PatValidationResult.createBypass();
            }
        }

        return PatValidationResult.notApplicable();
    }

    private PublicKey resolveKey(String keyIdHex) {
        if (keyIdHex == null) return defaultPublicKey;
        PublicKey key = trustedKeys.get(keyIdHex);
        if (key == null) {
            key = trustedKeys.get(keyIdHex.toLowerCase());
        }
        return key != null ? key : defaultPublicKey;
    }
}