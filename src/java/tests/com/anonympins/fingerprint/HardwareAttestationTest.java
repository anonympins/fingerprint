package com.anonympins.fingerprint;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

public class HardwareAttestationTest {

    private InMemoryStore store;
    private KeyPair ecKeyPair;

    @BeforeEach
    public void setUp() throws Exception {
        store = new InMemoryStore();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        ecKeyPair = kpg.generateKeyPair();
    }

    private byte[] toUnsigned32ByteArray(BigInteger val) {
        byte[] src = val.toByteArray();
        byte[] dest = new byte[32];
        if (src.length > 32) {
            System.arraycopy(src, src.length - 32, dest, 0, 32);
        } else {
            System.arraycopy(src, 0, dest, 32 - src.length, src.length);
        }
        return dest;
    }

    private Map<String, Object> createEcJwk(PublicKey publicKey) {
        ECPublicKey ecPub = (ECPublicKey) publicKey;
        ECPoint point = ecPub.getW();
        byte[] xBytes = toUnsigned32ByteArray(point.getAffineX());
        byte[] yBytes = toUnsigned32ByteArray(point.getAffineY());

        Map<String, Object> jwk = new HashMap<>();
        jwk.put("kty", "EC");
        jwk.put("crv", "P-256");
        jwk.put("x", Base64.getUrlEncoder().withoutPadding().encodeToString(xBytes));
        jwk.put("y", Base64.getUrlEncoder().withoutPadding().encodeToString(yBytes));
        return jwk;
    }

    private String base64UrlEncode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }

    @Test
    public void testAppleAppAttestValidAssertionIncrementsCounter() throws Exception {
        long storedCounter = 10;
        int newCounter = 11;

        byte[] rpIdHash = new byte[32];
        Arrays.fill(rpIdHash, (byte) 0xAA);
        byte flags = 0x01;

        ByteBuffer authBuf = ByteBuffer.allocate(37);
        authBuf.put(rpIdHash);
        authBuf.put(flags);
        authBuf.putInt(newCounter);
        byte[] authData = authBuf.array();

        byte[] clientDataHash = MessageDigest.getInstance("SHA-256")
                .digest("session_id:192.168.1.10".getBytes(StandardCharsets.UTF_8));

        byte[] signedData = new byte[authData.length + clientDataHash.length];
        System.arraycopy(authData, 0, signedData, 0, authData.length);
        System.arraycopy(clientDataHash, 0, signedData, authData.length, clientDataHash.length);

        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(ecKeyPair.getPrivate());
        ecdsa.update(signedData);
        byte[] signature = ecdsa.sign();

        ByteBuffer assertionBuf = ByteBuffer.allocate(authData.length + signature.length);
        assertionBuf.put(authData);
        assertionBuf.put(signature);
        byte[] assertionRaw = assertionBuf.array();

        boolean valid = HardwareAttestation.verifyAppleAppAttestAssertion(
                ecKeyPair.getPublic(),
                assertionRaw,
                clientDataHash,
                storedCounter
        );

        assertTrue(valid, "L'assertion signée par le Secure Enclave doit être valide avec un compteur incrémenté.");
    }

    @Test
    public void testAppleAppAttestRejectsStaleOrReplayedCounter() throws Exception {
        long storedCounter = 15;
        int replayedCounter = 15; // Même compteur (rejeu)

        byte[] rpIdHash = new byte[32];
        Arrays.fill(rpIdHash, (byte) 0xAA);
        byte flags = 0x01;

        ByteBuffer authBuf = ByteBuffer.allocate(37);
        authBuf.put(rpIdHash);
        authBuf.put(flags);
        authBuf.putInt(replayedCounter);
        byte[] authData = authBuf.array();

        byte[] clientDataHash = MessageDigest.getInstance("SHA-256")
                .digest("session_id:127.0.0.1".getBytes(StandardCharsets.UTF_8));

        byte[] signedData = new byte[authData.length + clientDataHash.length];
        System.arraycopy(authData, 0, signedData, 0, authData.length);
        System.arraycopy(clientDataHash, 0, signedData, authData.length, clientDataHash.length);

        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(ecKeyPair.getPrivate());
        ecdsa.update(signedData);
        byte[] signature = ecdsa.sign();

        ByteBuffer assertionBuf = ByteBuffer.allocate(authData.length + signature.length);
        assertionBuf.put(authData);
        assertionBuf.put(signature);
        byte[] assertionRaw = assertionBuf.array();

        boolean valid = HardwareAttestation.verifyAppleAppAttestAssertion(
                ecKeyPair.getPublic(),
                assertionRaw,
                clientDataHash,
                storedCounter
        );

        assertFalse(valid, "Une assertion dont le compteur n'est pas strictement supérieur doit être rejetée.");
    }

    @Test
    public void testGooglePlayIntegrityValidToken() {
        String expectedNonce = "replay-nonce-456";
        String packageName = "com.anonympins.app";

        String headerJson = "{\"alg\":\"ES256\"}";
        String payloadJson = "{"
                + "\"requestDetails\":{\"nonce\":\"" + expectedNonce + "\",\"timestampMillis\":\"" + System.currentTimeMillis() + "\"},"
                + "\"appIntegrity\":{\"packageName\":\"" + packageName + "\"},"
                + "\"deviceIntegrity\":{\"deviceRecognitionVerdict\":[\"MEETS_STRONG_INTEGRITY\",\"MEETS_DEVICE_INTEGRITY\"]}"
                + "}";

        String token = base64UrlEncode(headerJson.getBytes(StandardCharsets.UTF_8))
                + "." + base64UrlEncode(payloadJson.getBytes(StandardCharsets.UTF_8))
                + "." + base64UrlEncode("mock_signature".getBytes(StandardCharsets.UTF_8));

        HardwareAttestation.AttestationResult result = HardwareAttestation.verifyPlayIntegrityJws(
                token, packageName, expectedNonce, 180000L
        );

        assertTrue(result.isVerified(), "Le verdict Google Play Integrity avec intégrité matérielle doit être validé.");
        assertEquals("google_play_integrity_strong", result.getType());
    }

    @Test
    public void testGooglePlayIntegrityRejectsMismatchPackageOrStaleNonce() {
        String headerJson = "{\"alg\":\"ES256\"}";
        String payloadJson = "{"
                + "\"requestDetails\":{\"nonce\":\"expected-nonce\",\"timestampMillis\":\"" + System.currentTimeMillis() + "\"},"
                + "\"appIntegrity\":{\"packageName\":\"com.fraudulent.repack\"},"
                + "\"deviceIntegrity\":{\"deviceRecognitionVerdict\":[\"MEETS_STRONG_INTEGRITY\"]}"
                + "}";

        String token = base64UrlEncode(headerJson.getBytes(StandardCharsets.UTF_8))
                + "." + base64UrlEncode(payloadJson.getBytes(StandardCharsets.UTF_8))
                + "." + base64UrlEncode("dummy_sig".getBytes(StandardCharsets.UTF_8));

        HardwareAttestation.AttestationResult resBadPkg = HardwareAttestation.verifyPlayIntegrityJws(
                token, "com.anonympins.app", "expected-nonce", 180000L
        );
        assertFalse(resBadPkg.isVerified(), "Un nom de package différent doit invalider le token.");

        HardwareAttestation.AttestationResult resBadNonce = HardwareAttestation.verifyPlayIntegrityJws(
                token, "com.fraudulent.repack", "wrong-nonce", 180000L
        );
        assertFalse(resBadNonce.isVerified(), "Un nonce inattendu doit invalider le token.");
    }

    @Test
    public void testDbscProofVerificationSuccess() throws Exception {
        String sessionId = "session_device_123";
        String origin = "https://example.com";
        String nonce = "dbsc_nonce_abc";

        Map<String, Object> jwk = createEcJwk(ecKeyPair.getPublic());

        String headerJson = "{\"typ\":\"dbsc+jwt\",\"alg\":\"ES256\"}";
        String payloadJson = "{"
                + "\"sub\":\"" + sessionId + "\","
                + "\"aud\":\"" + origin + "\","
                + "\"nonce\":\"" + nonce + "\","
                + "\"iat\":" + (System.currentTimeMillis() / 1000) + ","
                + "\"exp\":" + ((System.currentTimeMillis() / 1000) + 300)
                + "}";

        String signingInput = base64UrlEncode(headerJson.getBytes(StandardCharsets.UTF_8))
                + "." + base64UrlEncode(payloadJson.getBytes(StandardCharsets.UTF_8));

        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(ecKeyPair.getPrivate());
        ecdsa.update(signingInput.getBytes(StandardCharsets.US_ASCII));
        byte[] derSignature = ecdsa.sign();

        String dbscJwt = signingInput + "." + base64UrlEncode(derSignature);

        boolean isValid = HardwareAttestation.verifyDbscProof(dbscJwt, jwk, sessionId, origin, nonce);
        assertTrue(isValid, "La signature DBSC dérivée du JWK matériel doit être validée.");
    }

    @Test
    public void testDbscProofFailsOnSessionOrOriginMismatch() throws Exception {
        String sessionId = "legit_session";
        String origin = "https://example.com";
        String nonce = "valid_nonce";
        Map<String, Object> jwk = createEcJwk(ecKeyPair.getPublic());

        String headerJson = "{\"typ\":\"dbsc+jwt\",\"alg\":\"ES256\"}";
        String payloadJson = "{\"sub\":\"" + sessionId + "\",\"aud\":\"" + origin + "\",\"nonce\":\"" + nonce + "\"}";
        String signingInput = base64UrlEncode(headerJson.getBytes(StandardCharsets.UTF_8))
                + "." + base64UrlEncode(payloadJson.getBytes(StandardCharsets.UTF_8));

        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(ecKeyPair.getPrivate());
        ecdsa.update(signingInput.getBytes(StandardCharsets.US_ASCII));
        String dbscJwt = signingInput + "." + base64UrlEncode(ecdsa.sign());

        assertFalse(HardwareAttestation.verifyDbscProof(dbscJwt, jwk, "stolen_session", origin, nonce),
                "La preuve doit échouer si le sub ne correspond pas à la session revendiquée.");
        assertFalse(HardwareAttestation.verifyDbscProof(dbscJwt, jwk, sessionId, "https://attacker.com", nonce),
                "La preuve doit échouer si l'aud ne correspond pas à l'origin reçue.");
    }

    @Test
    public void testEngineOrchestratesDbscHardwareBypass() throws Exception {
        String deviceId = "active_hardware_device";
        String origin = "https://example.com";
        String nonce = "dbsc_active_nonce";

        Map<String, Object> jwk = createEcJwk(ecKeyPair.getPublic());

        Map<String, Object> sessionRecord = new HashMap<>();
        sessionRecord.put("jwk", jwk);
        store.set("dbsc-session:" + deviceId, sessionRecord, 3600);
        store.set("dbsc-nonce:" + deviceId, nonce, 300);

        String headerJson = "{\"typ\":\"dbsc+jwt\",\"alg\":\"ES256\"}";
        String payloadJson = "{\"sub\":\"" + deviceId + "\",\"aud\":\"" + origin + "\",\"nonce\":\"" + nonce + "\"}";
        String signingInput = base64UrlEncode(headerJson.getBytes(StandardCharsets.UTF_8))
                + "." + base64UrlEncode(payloadJson.getBytes(StandardCharsets.UTF_8));

        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(ecKeyPair.getPrivate());
        ecdsa.update(signingInput.getBytes(StandardCharsets.US_ASCII));
        String dbscJwt = signingInput + "." + base64UrlEncode(ecdsa.sign());

        Map<String, String> headers = new HashMap<>();
        headers.put("sec-session-response", dbscJwt);
        headers.put("origin", origin);

        Map<String, String> cookies = new HashMap<>();
        cookies.put("device_id", deviceId);

        FingerprintEngine engine = new FingerprintEngine(new HashMap<>(), store);
        RequestContext context = new RequestContext("1.2.3.4", "/", headers, new HashMap<>(), null, cookies, "1.1");

        Map<String, Object> decision = engine.processRequest(context);
        assertEquals("next", decision.get("action"));
        assertEquals(0.0, ((Number) decision.get("score")).doubleValue());
        assertNull(store.get("dbsc-nonce:" + deviceId), "Le nonce DBSC doit être consommé et purgé.");
    }

    @Test
    public void testAppleAppAttestRegistrationAndEngineAssertionFlow() throws Exception {
        String deviceId = "ios_hardware_client";
        String keyId = "test_apple_key_id";
        long storedCounter = 0;
        int newCounter = 1;

        // Enregistrement manuel de la clé publique de l'appareil comme après validation de registration
        Map<String, Object> appAttestRecord = new HashMap<>();
        appAttestRecord.put("pubkey_der", Base64.getEncoder().encodeToString(ecKeyPair.getPublic().getEncoded()));
        appAttestRecord.put("counter", storedCounter);
        store.set("app-attest:" + keyId, appAttestRecord, 86400);

        // Préparation de l'assertion signée par la Secure Enclave
        byte[] rpIdHash = new byte[32];
        Arrays.fill(rpIdHash, (byte) 0xBB);
        byte flags = 0x01;

        ByteBuffer authBuf = ByteBuffer.allocate(37);
        authBuf.put(rpIdHash);
        authBuf.put(flags);
        authBuf.putInt(newCounter);
        byte[] authData = authBuf.array();

        byte[] clientDataHash = MessageDigest.getInstance("SHA-256")
                .digest((deviceId + ":1.2.3.4").getBytes(StandardCharsets.UTF_8));

        byte[] signedData = new byte[authData.length + clientDataHash.length];
        System.arraycopy(authData, 0, signedData, 0, authData.length);
        System.arraycopy(clientDataHash, 0, signedData, authData.length, clientDataHash.length);

        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(ecKeyPair.getPrivate());
        ecdsa.update(signedData);
        byte[] signature = ecdsa.sign();

        ByteBuffer assertionBuf = ByteBuffer.allocate(authData.length + signature.length);
        assertionBuf.put(authData);
        assertionBuf.put(signature);
        String assertionB64 = Base64.getEncoder().encodeToString(assertionBuf.array());

        Map<String, String> headers = new HashMap<>();
        headers.put("x-apple-app-attest", "{\"keyId\":\"" + keyId + "\",\"assertion\":\"" + assertionB64 + "\"}");
        Map<String, String> cookies = Collections.singletonMap("device_id", deviceId);

        FingerprintEngine engine = new FingerprintEngine(new HashMap<>(), store);
        RequestContext context = new RequestContext("1.2.3.4", "/", headers, new HashMap<>(), null, cookies, "1.1");
        Map<String, Object> decision = engine.processRequest(context);

        assertEquals("next", decision.get("action"));
        assertEquals(0.0, ((Number) decision.get("score")).doubleValue());
        Map<?, ?> vec = (Map<?, ?>) decision.get("vector");
        assertEquals(100.0, ((Number) vec.get("hw_apple_secure_enclave")).doubleValue());
    }
}