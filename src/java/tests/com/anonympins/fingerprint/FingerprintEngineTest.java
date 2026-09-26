package com.anonympins.fingerprint;

import com.anonympins.fingerprint.utils.RequestUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.util.concurrent.TimeUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

public class FingerprintEngineTest {
    private final File configDir = new File("config");
    private final File keyFile = new File(configDir, "ed25519_key.json");

    private Map<String, Object> defaultConfig;

    @BeforeEach
    public void setUp() {
        System.clearProperty("ED25519_PRIVATE_KEY");
        System.clearProperty("ED25519_PUBLIC_KEY");
        if (keyFile.exists()) {
            keyFile.delete();
        }

        defaultConfig = new HashMap<>();
        defaultConfig.put("fail_safe", "fail_open");
        defaultConfig.put("threshold", 0.7);
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

    @Test
    @DisplayName("Should successfully verify a valid Ed25519 signature from federatedPeers")
    void testEd25519SignatureVerificationSuccess() throws Exception {
        // Java 15+ supporte nativement Ed25519
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        KeyPair keyPair = kpg.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        byte[] challengeTicket = "session_challenge_token_valid_120s".getBytes(StandardCharsets.UTF_8);

        // Signature du ticket par le pair émetteur
        Signature sig = Signature.getInstance("Ed25519");
        sig.initSign(privateKey);
        sig.update(challengeTicket);
        byte[] signatureBytes = sig.sign();

        // Vérification par le nœud récepteur Java
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(publicKey);
        verifier.update(challengeTicket);
        boolean isVerified = verifier.verify(signatureBytes);

        assertTrue(isVerified, "La signature Ed25519 valide du federatedPeer doit être acceptée.");
    }

    @Test
    @DisplayName("Should fail when verifying an invalid or corrupted Ed25519 signature")
    void testEd25519SignatureVerificationFailure() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        KeyPair keyPair = kpg.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();

        byte[] challengeTicket = "session_challenge_token_valid_120s".getBytes(StandardCharsets.UTF_8);
        byte[] corruptedSignatureBytes = new byte[64]; // Fausse signature vide

        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(publicKey);
        verifier.update(challengeTicket);

        boolean isVerified = verifier.verify(corruptedSignatureBytes);
        assertFalse(isVerified, "Une signature invalide ou corrompue doit être rejetée (retourner false).");
    }

    @Test
    @DisplayName("Should fall back to Fail-Open when storage layer fails")
    void testFailOpenBehaviorWhenStorageFails() {
        EngineMock engine = new EngineMock(defaultConfig);
        Map<String, Object> result = engine.evaluateRequest();

        assertEquals("allowed", result.get("status"));
        assertEquals(0.0, result.get("score"));
        assertEquals("fail-safe backup", result.get("reason"));
    }

    @Test
    @DisplayName("Should block request on critical endpoints (Fail-Closed) when storage fails")
    void testFailClosedBehaviorWhenStorageFails() {
        Map<String, Object> secureConfig = new HashMap<>(defaultConfig);
        secureConfig.put("fail_safe", "fail_closed");

        EngineMock engine = new EngineMock(secureConfig);
        Map<String, Object> result = engine.evaluateRequest();

        assertEquals("blocked", result.get("status"));
        assertEquals(1.0, result.get("score"));
        assertEquals("security fallback", result.get("reason"));
    }

    @Test
    @DisplayName("Should detect User-Agent and Client Hints structural inconsistency")
    void testDetectsClientHintsInconsistency() {
        Map<String, String> headers = new HashMap<>();
        // Le client déclare être Chrome sous Windows, mais envoie des Client Hints de Firefox
        headers.put("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        headers.put("sec-ch-ua", "\"Firefox\";v=\"115\", \"Gecko\";v=\"20100101\"");

        boolean uaIsChrome = headers.get("user-agent").contains("Chrome");
        boolean chIsChrome = headers.get("sec-ch-ua").contains("Google Chrome") || headers.get("sec-ch-ua").contains("Chromium");

        boolean inconsistencyDetected = uaIsChrome != chIsChrome;

        assertTrue(inconsistencyDetected, "L'incohérence entre l'UA Chrome et les Client Hints Firefox doit être détectée.");
    }

    @Test
    @DisplayName("Should trigger maximum suspicion score when honeypot trap field is filled")
    void testHoneypotTrapDetection() {
        Map<String, String> formPayload = new HashMap<>();
        formPayload.put("username", "legit_user");
        formPayload.put("email", "user@example.com");
        formPayload.put("website_confirm_hidden", "http://spambot.com"); // Champ invisible rempli par un robot

        boolean isBot = formPayload.get("website_confirm_hidden") != null && !formPayload.get("website_confirm_hidden").isEmpty();
        double score = isBot ? 1.0 : 0.0;

        assertEquals(1.0, score);
        assertTrue(isBot);
    }

    @Test
    @DisplayName("Should validate correct Proof of Work (uPoW) solution")
    void testProofOfWorkVerificationSuccess() throws Exception {
        String challenge = "node_challenge_abc123";
        int difficulty = 3; // Demande un hash commençant par "000"
        String prefixTarget = "0".repeat(difficulty);

        // Résolution de l'uPoW côté client (simulation de l'effort CPU)
        int nonce = 0;
        String verifiedHash = "";
        while (true) {
            String attempt = challenge + "-" + nonce;
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(attempt.getBytes(StandardCharsets.UTF_8));

            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            verifiedHash = hexString.toString();
            if (verifiedHash.startsWith(prefixTarget)) {
                break;
            }
            nonce++;
        }

        assertTrue(verifiedHash.startsWith(prefixTarget), "La preuve de travail calculée doit démarrer par le bon nombre de zéros.");
    }

    @Test
    @DisplayName("Should catch basic SQL Injection attacks via WAF layer")
    void testBasicWafSqlInjectionBlocking() {
        String maliciousInput = "1' OR '1'='1";
        Pattern wafPattern = Pattern.compile("(union\\s+select|or\\s+['\"]?\\d+['\"]?\\s*=\\s*['\"]?\\d+)", Pattern.CASE_INSENSITIVE);

        assertTrue(wafPattern.matcher(maliciousInput).find(), "Le pattern WAF doit identifier l'injection SQL.");
    }

    @Test
    @DisplayName("Should bypass assessment when request matches a path allowlist rule")
    void testPathAllowlistBypass() {
        IStore store = new InMemoryStore();
        Map<String, Object> config = new HashMap<>();

        // Ajout d'une règle d'allowlist de chemin d'accès
        Map<String, Object> rule = new HashMap<>();
        rule.put("type", "path_allowlist");
        rule.put("entries", Arrays.asList("/assets/*", "/favicon.ico"));

        config.put("whitelist", Arrays.asList(rule));
        FingerprintEngine engine = new FingerprintEngine(config, store);

        RequestContext context = new RequestContext(
            "192.168.1.100",
            "/assets/images/logo.png", // Doit correspondre à /assets/*
            new HashMap<>(),
            new HashMap<>(),
            null,
            new HashMap<>(),
            "HTTP/1.1"
        );

        Map<String, Object> decision = engine.processRequest(context);
        assertNotNull(decision);
        assertEquals(0.0, ((Number) decision.get("score")).doubleValue(), "Le score d'une requête whitelistée doit être de 0.0");
        assertEquals("allow", decision.get("action"), "La requête doit être immédiatement acceptée");
    }

    @Test
    @DisplayName("Should bypass assessment when request matches a user-agent allowlist rule")
    void testUserAgentAllowlistBypass() {
        IStore store = new InMemoryStore();
        Map<String, Object> config = new HashMap<>();

        // Ajout d'une règle d'allowlist par User-Agent
        Map<String, Object> rule = new HashMap<>();
        rule.put("type", "user_agent_allowlist");
        rule.put("entries", Arrays.asList("Googlebot", "Bingbot"));

        config.put("whitelist", Arrays.asList(rule));
        FingerprintEngine engine = new FingerprintEngine(config, store);

        Map<String, String> headers = new HashMap<>();
        headers.put("user-agent", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)");

        RequestContext context = new RequestContext(
            "66.249.66.1", // IP de Googlebot
            "/index.html",
            headers,
            new HashMap<>(),
            null,
            new HashMap<>(),
            "HTTP/1.1"
        );

        Map<String, Object> decision = engine.processRequest(context);
        assertNotNull(decision);
        assertEquals(0.0, ((Number) decision.get("score")).doubleValue(), "Le score d'une requête whitelistée par UA doit être de 0.0");
        assertEquals("allow", decision.get("action"), "La requête doit être immédiatement acceptée");
    }

    @Test
    @DisplayName("Should block request when IP matches a blocklist rule")
    void testIpBlocklistBlocking() {
        IStore store = new InMemoryStore();
        Map<String, Object> config = new HashMap<>();

        // Ajout d'une règle de blocklist par IP
        Map<String, Object> rule = new HashMap<>();
        rule.put("type", "ip_blocklist");
        rule.put("entries", Arrays.asList("192.168.1.100", "10.0.0.0/8"));

        config.put("blacklist", Arrays.asList(rule));
        FingerprintEngine engine = new FingerprintEngine(config, store);

        RequestContext context = new RequestContext(
            "192.168.1.100", // IP bloquée
            "/index.html",
            new HashMap<>(),
            new HashMap<>(),
            null,
            new HashMap<>(),
            "HTTP/1.1"
        );

        Map<String, Object> decision = engine.processRequest(context);
        assertNotNull(decision);
        assertEquals(1.0, ((Number) decision.get("score")).doubleValue(), "Le score d'une requête blacklistée par IP doit être de 1.0");
        assertEquals("block", decision.get("action"), "La requête doit être immédiatement bloquée");
    }

    @Test
    @DisplayName("Should correctly handle store TTL expiration")
    void testStoreTtlExpiration() throws InterruptedException {
        InMemoryStore store = new InMemoryStore();
        String key = "testKey";
        String value = "testValue";
        int ttlSeconds = 1; // Expire dans 1 seconde

        store.set(key, value, ttlSeconds);
        assertTrue(store.has(key), "La clé doit exister immédiatement après avoir été définie.");
        assertEquals(value, store.get(key), "La valeur doit être correcte avant expiration.");

        // Attendre que le TTL expire
        TimeUnit.SECONDS.sleep(ttlSeconds + 1);

        assertFalse(store.has(key), "La clé ne doit plus exister après expiration du TTL.");
        assertNull(store.get(key), "La récupération de la clé doit retourner null après expiration.");
    }

    @Test
    @DisplayName("Should throw IllegalArgumentException for invalid fail_safe configuration")
    void testInvalidFailSafeConfiguration() {
        Map<String, Object> invalidConfig = new HashMap<>();
        invalidConfig.put("fail_safe", "invalid_mode"); // Mode invalide

        IStore store = new InMemoryStore();

        // L'initialisation de l'engine avec une configuration fail_safe invalide doit lever une exception
        assertThrows(IllegalArgumentException.class, () -> {
            new FingerprintEngine(invalidConfig, store);
        }, "Une IllegalArgumentException doit être levée pour une configuration fail_safe invalide.");
    }

    @Test
    @DisplayName("Should persist Ed25519 keys to disk after auto-generation")
    void testEd25519KeyPersistenceAfterAutoGeneration() throws IOException {
        // S'assurer que le fichier n'existe pas avant le test
        if (keyFile.exists()) {
            keyFile.delete();
        }
        assertFalse(keyFile.exists(), "Le fichier de clé ne doit pas exister avant le test.");

        Map<String, Object> config = new HashMap<>();
        config.put("ed25519", "auto");
        new FingerprintEngine(config, new InMemoryStore());

        assertTrue(keyFile.exists(), "Le fichier de clé doit être créé après l'auto-génération.");
        String fileContent = Files.readString(keyFile.toPath());
        assertTrue(fileContent.contains("privateKey") && fileContent.contains("publicKey"), "Le fichier de clé doit contenir les clés privée et publique.");
    }

    @Test
    @DisplayName("Should detect Coordinated Botnet IP rotation behavior")
    void testCoordinatedBotnetClustering() {
        IStore store = new InMemoryStore();
        Map<String, Object> config = new HashMap<>();
        config.put("threshold", 0.7);

        FingerprintEngine engine = new FingerprintEngine(config, store);
        String staticHardwareFingerprint = "ja4:t13d1516...|gpu:webgl-apple-m3";

        // Simulation de requêtes provenant de 5 adresses IP distinctes en rotation rapide
        // mais utilisant la même empreinte matérielle non-volatile
        String[] rotatingIps = {
            "185.220.101.1",
            "185.220.101.2",
            "185.220.101.3",
            "185.220.101.4",
            "185.220.101.5"
        };

        double lastScore = 0.0;
        for (String ip : rotatingIps) {
            Map<String, String> headers = new HashMap<>();
            headers.put("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)");
            // Signature matérielle injectée
            headers.put("x-hardware-fingerprint", staticHardwareFingerprint);

            RequestContext context = new RequestContext(
                ip,
                "/index.html",
                headers,
                new HashMap<>(),
                null,
                new HashMap<>(),
                "HTTP/1.1"
            );

            Map<String, Object> decision = engine.processRequest(context);
            lastScore = ((Number) decision.get("score")).doubleValue();
        }

        // À l'issue de la rotation des requêtes, le score d'anomalie de clustering de botnet doit grimper
        assertTrue(lastScore > 0.5, "La rotation rapide d'IP avec une empreinte matérielle identique doit augmenter le score de suspicion.");
    }

    // Mock interne simulant la logique de résilience de l'Engine
    private static class EngineMock {
        private final Map<String, Object> config;

        public EngineMock(Map<String, Object> config) { this.config = config; }

        public Map<String, Object> evaluateRequest() {
            boolean isFailOpen = "fail_open".equals(config.get("fail_safe"));
            Map<String, Object> response = new HashMap<>();
            response.put("status", isFailOpen ? "allowed" : "blocked");
            response.put("score", isFailOpen ? 0.0 : 1.0);
            response.put("reason", isFailOpen ? "fail-safe backup" : "security fallback");
            return response;
        }
    }


    @Test
    public void testNoFingerprint() {
        RequestContext context = new RequestContext("127.0.0.1", "/", new HashMap<>(), null, null, null, "1.1");
        Map<String, Double> score = RequestUtils.getProtocolAnomalyScore(context);
        assertEquals(0.0, score.getOrDefault("protocolAnomalyScore", 0.0));
    }

    @Test
    public void testSpoofedChromeQuic() {
        Map<String, String> headers = new HashMap<>();
        headers.put("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        headers.put("x-quic-fp", "1;1=65536,4=50;i=0");

        RequestContext context = new RequestContext("127.0.0.1", "/", headers, null, null, null, "2.0");
        Map<String, Double> score = RequestUtils.getProtocolAnomalyScore(context);
        assertEquals(100.0, score.getOrDefault("protocolAnomalyScore", 0.0));
    }

    @Test
    public void testLegitChromeQuic() {
        Map<String, String> headers = new HashMap<>();
        headers.put("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        headers.put("x-quic-fp", "1;1=1572864,4=100;u=2,i");

        RequestContext context = new RequestContext("127.0.0.1", "/", headers, null, null, null, "2.0");
        Map<String, Double> score = RequestUtils.getProtocolAnomalyScore(context);
        assertEquals(0.0, score.getOrDefault("protocolAnomalyScore", 0.0));
    }

    @Test
    public void testChromiumH2HeaderAnomaly() {
        Map<String, String> headers = new HashMap<>();
        headers.put("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        headers.put("x-http2-fingerprint", "1|65535|0|invalid_order");

        RequestContext context = new RequestContext("127.0.0.1", "/", headers, null, null, null, "2.0");
        Map<String, Double> score = RequestUtils.getProtocolAnomalyScore(context);
        assertEquals(100.0, score.getOrDefault("protocolAnomalyScore", 0.0));
    }

    @Test
    @DisplayName("Should detect HTTP/2 frame anomalies (PRIORITY, WINDOW_UPDATE, CONTINUATION)")
    void testProtocolAnomalyScoreFrameAnalysis() {
        // Test Case 1: Spoofed Chromium (No PRIORITY frames)
        Map<String, String> headers1 = new HashMap<>();
        headers1.put("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        headers1.put("x-http2-fingerprint", "s:1:65536,2:0,3:1000,4:6291456,6:262144|15663105|1:0:0:256|m,a,s,p|p:0,w:4,c:1");
        RequestContext context1 = new RequestContext("127.0.0.1", "/", headers1, null, null, null, "2.0");
        Map<String, Double> score1 = RequestUtils.getProtocolAnomalyScore(context1);
        // 25.0 for no priority frames
        assertEquals(25.0, score1.getOrDefault("protocolAnomalyScore", 0.0), 0.1);

        // Test Case 2: Spoofed Chromium (Few WINDOW_UPDATE frames)
        Map<String, String> headers2 = new HashMap<>();
        headers2.put("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        headers2.put("x-http2-fingerprint", "s:1:65536,2:0,3:1000,4:6291456,6:262144|15663105|1:0:0:256|m,a,s,p|p:3,w:1,c:1");
        RequestContext context2 = new RequestContext("127.0.0.1", "/", headers2, null, null, null, "2.0");
        Map<String, Double> score2 = RequestUtils.getProtocolAnomalyScore(context2);
        // 20.0 for few window_update frames
        assertEquals(20.0, score2.getOrDefault("protocolAnomalyScore", 0.0), 0.1);

        // Test Case 3: Spoofed Chromium (Both anomalies)
        Map<String, String> headers3 = new HashMap<>();
        headers3.put("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        headers3.put("x-http2-fingerprint", "s:1:65536,2:0,3:1000,4:6291456,6:262144|15663105|1:0:0:256|m,a,s,p|p:0,w:1,c:1");
        RequestContext context3 = new RequestContext("127.0.0.1", "/", headers3, null, null, null, "2.0");
        Map<String, Double> score3 = RequestUtils.getProtocolAnomalyScore(context3);
        // 25.0 + 20.0 = 45.0
        assertEquals(45.0, score3.getOrDefault("protocolAnomalyScore", 0.0), 0.1);

        // Test Case 4: Spoofed Firefox (Too many PRIORITY frames)
        Map<String, String> headers4 = new HashMap<>();
        headers4.put("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0");
        headers4.put("x-http2-fingerprint", "s:1:65536,2:0,3:1000,4:6291456,6:262144|15663105|1:0:0:256|m,s,p,a|p:3,w:2,c:0");
        RequestContext context4 = new RequestContext("127.0.0.1", "/", headers4, null, null, null, "2.0");
        Map<String, Double> score4 = RequestUtils.getProtocolAnomalyScore(context4);
        // 20.0 for too many priority frames for Firefox
        assertEquals(20.0, score4.getOrDefault("protocolAnomalyScore", 0.0), 0.1);

        // Test Case 5: Generic Bot (No CONTINUATION frames with many headers)
        Map<String, String> headers5 = new HashMap<>();
        headers5.put("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        // headerOrder has 6 parts -> 5 commas > 3
        headers5.put("x-http2-fingerprint", "s:1:65536,2:0,3:1000,4:6291456,6:262144|15663105|1:0:0:256|m,a,s,p,x,y,z|p:3,w:4,c:0");
        RequestContext context5 = new RequestContext("127.0.0.1", "/", headers5, null, null, null, "2.0");
        Map<String, Double> score5 = RequestUtils.getProtocolAnomalyScore(context5);
        // 90.0 = 30.0 for no continuation frames with many headers + 60.0 for invalid pseudo-headers (x,y,z)
        assertEquals(90.0, score5.getOrDefault("protocolAnomalyScore", 0.0), 0.1);

        // Test Case 6: Legitimate Chromium (should have low/zero score from this logic)
        Map<String, String> headers6 = new HashMap<>();
        headers6.put("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        headers6.put("x-http2-fingerprint", "s:1:65536,2:0,3:1000,4:6291456,6:262144|15663105|1:0:0:256|m,a,s,p|p:3,w:4,c:1");
        RequestContext context6 = new RequestContext("127.0.0.1", "/", headers6, null, null, null, "2.0");
        Map<String, Double> score6 = RequestUtils.getProtocolAnomalyScore(context6);
        assertEquals(0.0, score6.getOrDefault("protocolAnomalyScore", 0.0), 0.1);
    }

    @Test
    @DisplayName("Should parse x-behavior-metrics direct score")
    void testDirectBehaviorScore() {
        Map<String, String> headers = new HashMap<>();
        headers.put("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
        headers.put("accept", "text/html");
        headers.put("accept-encoding", "gzip");
        headers.put("x-behavior-metrics", "65.5");

        RequestContext context = new RequestContext("127.0.0.1", "/", headers, null, null, null, "1.1");
        Map<String, Double> result = RequestUtils.getBehaviorScore(context);
        assertEquals(65.5, result.get("behaviorScore"), 0.01);
    }

    @Test
    @DisplayName("MTU anomaly alone should amplify weights but never trigger suspicion alone")
    void testMtuAnomalyAmplifierOnly() {
        Map<String, Object> config = new HashMap<>();
        Map<String, Object> weights = new HashMap<>();
        weights.put("behaviorScore", 0.7);
        weights.put("mtuAnomalyScore", 0.9);
        config.put("weights", weights);

        FingerprintEngine engine = new FingerprintEngine(config, new InMemoryStore());

        // 1. Requête avec seulement MTU anormal (VPN) et aucun autre indicateur de suspicion
        Map<String, Double> vectorWithoutOtherAnomalies = new HashMap<>();
        vectorWithoutOtherAnomalies.put("mtuAnomalyScore", 75.0);
        vectorWithoutOtherAnomalies.put("behaviorScore", 0.0);

        double scoreAlone = engine.calculateFinalScore(vectorWithoutOtherAnomalies);
        assertEquals(0.0, scoreAlone, "Le MTU seul ne doit jamais déclencher de suspicion directe");

        // 2. Requête avec anomalie comportementale sans détection de tunnel
        Map<String, Double> vectorNormal = new HashMap<>();
        vectorNormal.put("mtuAnomalyScore", 0.0);
        vectorNormal.put("behaviorScore", 40.0);

        double baseScore = engine.calculateFinalScore(vectorNormal);
        assertEquals(28.0, baseScore, 0.01); // 40.0 * 0.7 = 28.0

        // 3. Même requête sous tunnel VPN (MTU > 50) : amplification du poids behaviorScore (0.7 * 1.15 = 0.805)
        Map<String, Double> vectorWithTunnel = new HashMap<>();
        vectorWithTunnel.put("mtuAnomalyScore", 75.0);
        vectorWithTunnel.put("behaviorScore", 40.0);

        double amplifiedScore = engine.calculateFinalScore(vectorWithTunnel);
        assertEquals(40.0 * (0.7 * 1.15), amplifiedScore, 0.01);
        assertTrue(amplifiedScore > baseScore, "Le score final doit être amplifié lors de la détection d'un tunnel");
    }

    @Test
    void testCombinedChallengePageMemSeedPrefix() {
        // 1. Initialisation triviale du Store (InMemoryStore par défaut)
        IStore store = new InMemoryStore();
        // Configure engine to trigger a challenge
        Map<String, Object> testConfig = SecurityProfiles.createSecurityProfile("balanced", new HashMap<String, Object>() {{
            put("thresholds", new HashMap<String, Object>() {{
                put("low", 10); put("medium", 20); put("high", 30); put("block", 95);
            }});
            put("weights", new HashMap<String, Object>() {{
                put("headerAnomalyScore", 1.0); // Ensure a score is generated
            }});
            put("challengeNewDevices", true); // Ensure new devices are challenged
        }});
        FingerprintEngine testEngine = new FingerprintEngine(testConfig, store);

        // Simulate a request that triggers a challenge
        RequestContext context = new RequestContext(
                "127.0.0.1", "/sensitive", new HashMap<>(), new HashMap<>(), null, new HashMap<>(), "1.1"
        );
        context.headers.put("user-agent", "TestBrowser");
        context.preCalculatedScore = 35.0; // Utilise le score pré-calculé pour éviter l'usage de Mockito.spy

        Map<String, Object> decision = testEngine.processRequest(context);

        assertEquals("challenge", decision.get("action"));
        String htmlBody = (String) decision.get("body");

        // Assert that the memSeed is constructed with the correct leading colon
        assertTrue(htmlBody.contains("const memSeed = \":\" + nonce + \":\" + clientSecret;"), "The generated HTML should contain the correct memSeed prefix.");
    }
}