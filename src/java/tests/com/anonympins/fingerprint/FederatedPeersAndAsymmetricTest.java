package com.anonympins.fingerprint;

import com.anonympins.fingerprint.utils.ChallengeUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

public class FederatedPeersAndAsymmetricTest {

    private IStore store;

    @BeforeEach
    public void setUp() {
        store = new InMemoryStore();
        System.clearProperty("ED25519_PRIVATE_KEY");
        System.clearProperty("ED25519_PUBLIC_KEY");
    }

    @AfterEach
    public void tearDown() {
        System.clearProperty("ED25519_PRIVATE_KEY");
        System.clearProperty("ED25519_PUBLIC_KEY");
    }

    @Test
    public void testDefaultPropertiesUseAsymmetricTickets() {
        FingerprintProperties properties = new FingerprintProperties();
        // Vérifie que l'option useAsymmetricTickets est bien à true par défaut
        assertTrue(properties.isUseAsymmetricTickets(), "useAsymmetricTickets doit être à true par défaut");
    }

    @Test
    public void testAutoKeyGenerationOnEngineInitialization() {
        Map<String, Object> config = new HashMap<>();
        config.put("useAsymmetricTickets", true);

        assertNull(System.getProperty("ED25519_PRIVATE_KEY"));
        assertNull(System.getProperty("ED25519_PUBLIC_KEY"));

        // L'initialisation de l'engine doit déclencher l'autogénération des clés Ed25519
        new FingerprintEngine(config, store);

        String generatedPrivateKey = System.getProperty("ED25519_PRIVATE_KEY");
        String generatedPublicKey = System.getProperty("ED25519_PUBLIC_KEY");

        assertNotNull(generatedPrivateKey, "La clé privée aurait dû être générée automatiquement");
        assertNotNull(generatedPublicKey, "La clé publique aurait dû être générée automatiquement");
        assertTrue(generatedPrivateKey.contains("BEGIN PRIVATE KEY"), "La clé générée doit être au format PEM PKCS8");
        assertTrue(generatedPublicKey.contains("BEGIN PUBLIC KEY"), "La clé générée doit être au format PEM SPKI");
    }

    @Test
    public void testShareThreatIntelAsymmetricVerification() {
        Map<String, Object> config = new HashMap<>();
        config.put("useAsymmetricTickets", true);

        // Initialiser l'engine pour générer les clés Ed25519 éphémères
        new FingerprintEngine(config, store);

        String publicKey = System.getProperty("ED25519_PUBLIC_KEY");
        assertNotNull(publicKey);

        // Préparation de l'identité ZKP bannie simulée
        String zkpY = "3b5379916d2b3882253c42885956a350";
        long timestamp = System.currentTimeMillis();
        String msg = timestamp + ":" + zkpY;

        // Générer une signature asymétrique Ed25519 avec la clé privée générée à la volée
        String signature = "";
        try {
            String privateKeyPem = System.getProperty("ED25519_PRIVATE_KEY")
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] keyBytes = Base64.getDecoder().decode(privateKeyPem);
            java.security.spec.PKCS8EncodedKeySpec spec = new java.security.spec.PKCS8EncodedKeySpec(keyBytes);
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance("Ed25519");
            java.security.PrivateKey privateKey = kf.generatePrivate(spec);

            java.security.Signature sig = java.security.Signature.getInstance("Ed25519");
            sig.initSign(privateKey);
            sig.update(msg.getBytes(StandardCharsets.UTF_8));
            signature = HexFormat.of().formatHex(sig.sign());
        } catch (Exception e) {
            fail("Échec de la génération de la signature : " + e.getMessage());
        }

        // Préparer les paramètres coopératifs simulant la requête de synchronisation du pair émetteur
        Map<String, String> params = new HashMap<>();
        params.put("coop_op", "share_threat_intel");
        params.put("zkpY", zkpY);
        params.put("timestamp", String.valueOf(timestamp));
        params.put("signature_ed25519", signature);

        // Passage de la clé publique de l'engine dans le profil de config du récepteur
        config.put("ed25519_public_key", publicKey);

        // Simulation du traitement de la requête coopérative de Threat Intel par le destinataire
        Map<String, Object> res = ChallengeUtils.handleCooperativeRequest(params, "127.0.0.1", config);

        assertNotNull(res);
        assertEquals("synchronized", res.get("status"), "La menace doit être vérifiée asymétriquement et synchronisée");
        assertTrue(store.has("banned-zkp-y:" + zkpY), "La clé publique ZKP du terminal banni doit être stockée");
    }
}