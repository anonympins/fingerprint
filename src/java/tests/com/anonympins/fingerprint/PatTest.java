package com.anonympins.fingerprint;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.security.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.*;

class PatTest {
    private KeyPair keyPair;
    private PatNonceStore inMemoryStore;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        keyPair = kpg.generateKeyPair();

        Map<String, Long> storage = new ConcurrentHashMap<>();
        inMemoryStore = new PatNonceStore() {
            @Override
            public boolean exists(String nonceHex) {
                Long exp = storage.get(nonceHex);
                if (exp == null) return false;
                if (System.currentTimeMillis() > exp) {
                    storage.remove(nonceHex);
                    return false;
                }
                return true;
            }

            @Override
            public void set(String nonceHex, long ttlSeconds) {
                storage.put(nonceHex, System.currentTimeMillis() + (ttlSeconds * 1000));
            }
        };
    }

    private byte[] createTestToken(int tokenType, KeyPair kp, byte[] customKeyId) throws Exception {
        SecureRandom random = new SecureRandom();
        byte[] nonce = new byte[32];
        random.nextBytes(nonce);

        byte[] challengeDigest = new byte[32];
        random.nextBytes(challengeDigest);

        byte[] tokenKeyId = customKeyId != null ? customKeyId : new byte[32];
        if (customKeyId == null) {
            random.nextBytes(tokenKeyId);
        }

        ByteBuffer signedBuffer = ByteBuffer.allocate(98);
        signedBuffer.putShort((short) tokenType);
        signedBuffer.put(nonce);
        signedBuffer.put(challengeDigest);
        signedBuffer.put(tokenKeyId);
        byte[] signedData = signedBuffer.array();

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(kp.getPrivate());
        sig.update(signedData);
        byte[] signature = sig.sign();

        ByteBuffer tokenBuffer = ByteBuffer.allocate(signedData.length + signature.length);
        tokenBuffer.put(signedData);
        tokenBuffer.put(signature);
        return tokenBuffer.array();
    }

    @Test
    void testHeaderExtraction() throws Exception {
        byte[] rawToken = createTestToken(0x0001, keyPair, null);
        String b64 = Base64.getEncoder().encodeToString(rawToken);

        Map<String, String> headersAuth = Collections.singletonMap("Authorization", "PrivateToken token=\"" + b64 + "\"");
        List<byte[]> tokensAuth = PatUtils.extractTokens(headersAuth);
        assertEquals(1, tokensAuth.size());
        assertArrayEquals(rawToken, tokensAuth.get(0));

        Map<String, String> headersPst = Collections.singletonMap("Sec-Private-State-Token", b64);
        List<byte[]> tokensPst = PatUtils.extractTokens(headersPst);
        assertEquals(1, tokensPst.size());
        assertArrayEquals(rawToken, tokensPst.get(0));
    }

    @Test
    void testBinaryParsing() throws Exception {
        byte[] keyId = new byte[32];
        Arrays.fill(keyId, (byte) 0xAA);
        byte[] rawToken = createTestToken(0x0001, keyPair, keyId);

        PrivateAccessToken parsed = PatUtils.parseToken(rawToken);
        assertNotNull(parsed);
        assertEquals(1, parsed.getTokenType());
        assertEquals(32, parsed.getNonce().length);
        assertEquals(PatUtils.bytesToHex(keyId), parsed.getTokenKeyIdHex());
        assertEquals(256, parsed.getAuthenticator().length); // Signature RSA-2048
    }

    @Test
    void testSignatureVerificationAndTamperRejection() throws Exception {
        byte[] rawToken = createTestToken(0x0001, keyPair, null);
        PrivateAccessToken parsed = PatUtils.parseToken(rawToken);
        assertNotNull(parsed);

        assertTrue(PatUtils.verifySignature(parsed, keyPair.getPublic()));

        // Jeton altéré
        byte[] tamperedData = parsed.getSignedData();
        tamperedData[10] ^= 0xFF;
        PrivateAccessToken tamperedToken = new PrivateAccessToken(
                parsed.getTokenType(), parsed.getNonce(), parsed.getChallengeDigest(),
                parsed.getTokenKeyId(), parsed.getAuthenticator(), tamperedData
        );

        assertFalse(PatUtils.verifySignature(tamperedToken, keyPair.getPublic()));
    }

    @Test
    void testZeroFrictionBypassAndAntiReplay() throws Exception {
        byte[] keyId = new byte[32];
        Arrays.fill(keyId, (byte) 0x42);
        byte[] rawToken = createTestToken(0x0001, keyPair, keyId);

        Map<String, PublicKey> trusted = new HashMap<>();
        trusted.put(PatUtils.bytesToHex(keyId), keyPair.getPublic());
        PatValidator validator = new PatValidator(trusted, inMemoryStore);

        String b64 = Base64.getEncoder().encodeToString(rawToken);
        Map<String, String> reqHeaders = Collections.singletonMap("Authorization", "PrivateToken token=\"" + b64 + "\"");

        // Premier passage : validé avec score 0.0
        PatValidationResult firstPass = validator.processRequestHeaders(reqHeaders);
        assertTrue(firstPass.isVerified());
        assertEquals("next", firstPass.getAction());
        assertEquals(0.0, firstPass.getScore());
        assertEquals(100.0, firstPass.getVector().get("pat_verified"));

        // Deuxième passage (rejeu du même nonce) : refusé
        PatValidationResult secondPass = validator.processRequestHeaders(reqHeaders);
        assertFalse(secondPass.isVerified());
    }

    @Test
    void testPatDoesNotProtectCondemnedTerminal() throws Exception {
        byte[] keyId = new byte[32];
        Arrays.fill(keyId, (byte) 0x11);
        byte[] rawToken = createTestToken(0x0001, keyPair, keyId);
        String b64 = Base64.getEncoder().encodeToString(rawToken);

        Map<String, PublicKey> trusted = new HashMap<>();
        trusted.put(PatUtils.bytesToHex(keyId), keyPair.getPublic());
        PatValidator validator = new PatValidator(trusted, inMemoryStore);

        InMemoryStore store = new InMemoryStore();
        Map<String, Object> config = new HashMap<>();
        config.put("patValidator", validator);
        FingerprintEngine engine = new FingerprintEngine(config, store);

        // Condamnation préalable du terminal
        String deviceId = "condemned-dev-xyz";
        Map<String, Object> deviceData = new HashMap<>();
        deviceData.put("condemned", true);
        deviceData.put("initialDeviceHash", "static-hash");
        store.set("device:" + deviceId, deviceData, 3600);

        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "PrivateToken token=\"" + b64 + "\"");
        headers.put("user-agent", "Mozilla/5.0");

        Map<String, String> cookies = new HashMap<>();
        cookies.put("device_id", deviceId);

        RequestContext context = new RequestContext("1.2.3.4", "/", headers, new HashMap<>(), null, cookies, "1.1");
        Map<String, Object> decision = engine.processRequest(context);

        // Le token PAT ne protège pas : blocage immédiat
        assertEquals("block", decision.get("action"));
        assertEquals(403, decision.get("status"));
    }

    @Test
    void testPatDoesNotProtectCertainAttack() throws Exception {
        byte[] keyId = new byte[32];
        Arrays.fill(keyId, (byte) 0x22);
        byte[] rawToken = createTestToken(0x0001, keyPair, keyId);
        String b64 = Base64.getEncoder().encodeToString(rawToken);

        Map<String, PublicKey> trusted = new HashMap<>();
        trusted.put(PatUtils.bytesToHex(keyId), keyPair.getPublic());
        PatValidator validator = new PatValidator(trusted, inMemoryStore);

        InMemoryStore store = new InMemoryStore();
        Map<String, Object> config = new HashMap<>();
        config.put("patValidator", validator);
        config.put("honeypot", Collections.singletonMap("paths", Collections.singletonList("/admin-trap")));
        FingerprintEngine engine = new FingerprintEngine(config, store);

        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "PrivateToken token=\"" + b64 + "\"");
        headers.put("user-agent", "Mozilla/5.0");
        headers.put("x-request-uri", "/admin-trap"); // Déclenche un honeypot certain (score = 100)

        RequestContext context = new RequestContext("1.2.3.4", "/admin-trap", headers, new HashMap<>(), null, new HashMap<>(), "1.1");
        Map<String, Object> decision = engine.processRequest(context);

        // Blocage immédiat
        assertEquals("block", decision.get("action"));
        assertEquals(403, decision.get("status"));
    }

    @Test
    void testPatValidExemptsFromPowComputation() throws Exception {
        byte[] keyId = new byte[32];
        Arrays.fill(keyId, (byte) 0x33);
        byte[] rawToken = createTestToken(0x0001, keyPair, keyId);
        String b64 = Base64.getEncoder().encodeToString(rawToken);

        Map<String, PublicKey> trusted = new HashMap<>();
        trusted.put(PatUtils.bytesToHex(keyId), keyPair.getPublic());
        PatValidator validator = new PatValidator(trusted, inMemoryStore);

        InMemoryStore store = new InMemoryStore();
        Map<String, Object> config = new HashMap<>();
        config.put("patValidator", validator);
        Map<String, Object> thresholds = new HashMap<>();
        thresholds.put("low", 10);
        thresholds.put("medium", 40);
        thresholds.put("high", 60);
        thresholds.put("block", 95);
        config.put("thresholds", thresholds);

        FingerprintEngine engine = new FingerprintEngine(config, store);

        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "PrivateToken token=\"" + b64 + "\"");
        headers.put("user-agent", "curl/7.0"); // Déclencherait normalement un challenge PoW

        RequestContext context = new RequestContext("1.2.3.4", "/", headers, new HashMap<>(), null, new HashMap<>(), "1.1");
        Map<String, Object> decision = engine.processRequest(context);

        // Dispensation immédiate du PoW
        assertEquals("next", decision.get("action"));
        assertEquals(0.0, ((Number) decision.get("score")).doubleValue());
        Map<?, ?> vec = (Map<?, ?>) decision.get("vector");
        assertNotNull(vec);
        assertEquals(100.0, ((Number) vec.get("pat_verified")).doubleValue());
    }
}