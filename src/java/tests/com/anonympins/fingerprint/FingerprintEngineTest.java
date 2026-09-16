package com.anonympins.fingerprint;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

public class FingerprintEngineTest {
    private final File configDir = new File("config");
    private final File keyFile = new File(configDir, "ed25519_key.json");

    @BeforeEach
    public void setUp() {
        System.clearProperty("ED25519_PRIVATE_KEY");
        System.clearProperty("ED25519_PUBLIC_KEY");
        if (keyFile.exists()) {
            keyFile.delete();
        }
    }

    @AfterEach
    public void tearDown() {
        if (keyFile.exists()) {
            keyFile.delete();
        }
    }
    @Test
    public void testTrivialEngineUsageAndSecurityConfigInjection() {
        // 1. Initialisation triviale du Store (InMemoryStore par défaut)
        IStore store = new InMemoryStore();

        // 2. Définition et injection d'une configuration de sécurité personnalisée
        Map<String, Object> securityConfig = new HashMap<>();

        // Injection de seuils de suspicion sur-mesure (Thresholds)
        Map<String, Object> customThresholds = new HashMap<>();
        customThresholds.put("low", 15);
        customThresholds.put("medium", 40);
        customThresholds.put("high", 70);
        customThresholds.put("block", 90);
        securityConfig.put("thresholds", customThresholds);

        // Injection de poids spécifiques sur les indicateurs de suspicion (Weights)
        Map<String, Object> customWeights = new HashMap<>();
        customWeights.put("botScore", 1.5);
        customWeights.put("inconsistencyScore", 0.8);
        securityConfig.put("weights", customWeights);

        securityConfig.put("verbose", false);
        securityConfig.put("dryRun", false);

        // Instanciation de l'engine de manière très simple
        FingerprintEngine engine = new FingerprintEngine(securityConfig, store);

        // Validation que la configuration a bien été injectée et prise en compte
        assertEquals(15, engine.getThresholds().get("low"));
        assertEquals(90, engine.getThresholds().get("block"));
        assertEquals(1.5, ((Number) engine.getWeights().get("botScore")).doubleValue());
        assertEquals(0.8, ((Number) engine.getWeights().get("inconsistencyScore")).doubleValue());

        // 3. Utilisation triviale par l'utilisateur final pour évaluer une requête entrante
        Map<String, String> headers = new HashMap<>();
        headers.put("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
        headers.put("host", "localhost:8080");

        RequestContext context = new RequestContext(
            "192.168.1.100",
            "/api/v1/resource",
            headers,
            new HashMap<>(), // aucun paramètre de requête
            null,            // corps de message vide
            new HashMap<>(), // aucun cookie existant (nouvel utilisateur)
            "HTTP/1.1"
        );

        // Appel direct d'une unique méthode pour obtenir la décision de sécurité
        Map<String, Object> decision = engine.processRequest(context);

        // On s'assure que l'engine produit une réponse exploitable directement
        assertNotNull(decision);
        assertTrue(decision.containsKey("score"));
        assertTrue(decision.containsKey("action"));
    }

    @Test
    public void testAccessEngineFromServletFilter() {
        IStore store = new InMemoryStore();
        FingerprintEngine engine = new FingerprintEngine(new HashMap<>(), store);
        
        // Instanciation du filtre avec notre engine
        FingerprintServletFilter filter = new FingerprintServletFilter(engine);

        // Validation que l'utilisateur final peut récupérer trivialement l'instance active
        assertNotNull(filter.getEngine());
        assertSame(engine, filter.getEngine(), "L'instance retournée par le middleware doit être identique à celle injectée");
    }

    @Test
    public void testAccessEngineFromWebFluxFilter() {
        IStore store = new InMemoryStore();
        FingerprintEngine engine = new FingerprintEngine(new HashMap<>(), store);
        
        // Instanciation du filtre réactif avec notre engine
        FingerprintWebFluxFilter filter = new FingerprintWebFluxFilter(engine);

        // Validation que l'utilisateur final peut récupérer trivialement l'instance active
        assertNotNull(filter.getEngine());
        assertSame(engine, filter.getEngine(), "L'instance retournée par le middleware WebFlux doit être identique à celle injectée");
    }

    @Test
    public void testEd25519KeyAutoGenerationAndPersistence() {
        Map<String, Object> config = new HashMap<>();
        config.put("ed25519", "auto");

        IStore mockStore = new InMemoryStore();
        new FingerprintEngine(config, mockStore);

        String privKey = System.getProperty("ED25519_PRIVATE_KEY");
        String pubKey = System.getProperty("ED25519_PUBLIC_KEY");

        assertNotNull(privKey);
        assertNotNull(pubKey);
        assertTrue(keyFile.exists());
    }

    @Test
    public void testEd25519KeyLoadingFromDisk() throws IOException {
        if (!configDir.exists()) {
            configDir.mkdirs();
        }
        String dummyJson = "{\n" +
                "  \"privateKey\": \"-----BEGIN PRIVATE KEY-----\\ndummy-java-private\\n-----END PRIVATE KEY-----\",\n" +
                "  \"publicKey\": \"-----BEGIN PUBLIC KEY-----\\ndummy-java-public\\n-----END PUBLIC KEY-----\"\n" +
                "}";
        Files.writeString(keyFile.toPath(), dummyJson);

        Map<String, Object> config = new HashMap<>();
        config.put("ed25519", "auto");

        IStore mockStore = new InMemoryStore();
        new FingerprintEngine(config, mockStore);

        assertEquals("-----BEGIN PRIVATE KEY-----\ndummy-java-private\n-----END PRIVATE KEY-----", System.getProperty("ED25519_PRIVATE_KEY"));
        assertEquals("-----BEGIN PUBLIC KEY-----\ndummy-java-public\n-----END PUBLIC KEY-----", System.getProperty("ED25519_PUBLIC_KEY"));
    }

}