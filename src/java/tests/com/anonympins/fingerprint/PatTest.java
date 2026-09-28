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
}