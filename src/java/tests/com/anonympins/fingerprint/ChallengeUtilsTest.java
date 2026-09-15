package com.anonympins.fingerprint;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

public class ChallengeUtilsTest {

    private final String secret = "my-secret-key-32-chars-long-minimum-for-testing";

    @BeforeEach
    public void setUp() {
        System.setProperty("POW_SECRET", secret);
    }

    @Test
    public void testCalculateCpuTarget() {
        Map<String, Object> config = new HashMap<>();
        Map<String, Object> cpu = new HashMap<>();
        cpu.put("minDifficultyBits", 8);
        cpu.put("maxDifficultyBits", 24);
        config.put("cpu", cpu);

        // Test suspicion basse (factor 0.0) -> la cible doit être large (facile)
        String targetLow = ChallengeUtils.calculateCpuTarget(0.0, config);
        BigInteger targetLowInt = new BigInteger(targetLow, 16);
        BigInteger expectedLow = BigInteger.ONE.shiftLeft(256 - 8);
        assertEquals(expectedLow, targetLowInt);

        // Test suspicion élevée (factor 1.0) -> la cible doit être petite (difficile)
        String targetHigh = ChallengeUtils.calculateCpuTarget(1.0, config);
        BigInteger targetHighInt = new BigInteger(targetHigh, 16);
        BigInteger expectedHigh = BigInteger.ONE.shiftLeft(256 - 24);
        assertEquals(expectedHigh, targetHighInt);
    }

    @Test
    public void testCreateCpuChallengeBaseBlock() {
        String nonce = "test-nonce";
        String clientSecret = "test-secret";
        String fingerprint = "ua:chrome|gpu:nvidia|cvs:canvas-hash";

        String baseBlock = ChallengeUtils.createCpuChallengeBaseBlock(nonce, clientSecret, fingerprint);
        
        // Les composants de l'empreinte doivent être triés par ordre alphabétique
        String expected = nonce + ":" + clientSecret + ":cvs:canvas-hash|gpu:nvidia|ua:chrome:";
        assertEquals(expected, baseBlock);
    }

    @Test
    public void testVerifyZkpProof() throws Exception {
        BigInteger p = new BigInteger("115792089237316195423570985008687907853269984665640564039457584007908834671663");
        BigInteger g = BigInteger.valueOf(2);
        BigInteger x = new BigInteger("12345678901234567890"); // Clé privée simulant l'empreinte
        BigInteger y = g.modPow(x, p); // Clé publique

        BigInteger v = new BigInteger("98765432109876543210"); // Secret aléatoire
        BigInteger t = g.modPow(v, p); // Engagement

        String cStr = g.toString() + y.toString() + t.toString();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = md.digest(cStr.getBytes(StandardCharsets.UTF_8));
        BigInteger c = new BigInteger(1, hashBytes).mod(p);
        BigInteger s = v.add(c.multiply(x)).mod(p.subtract(BigInteger.ONE));

        String yHex = y.toString(16);
        String tHex = t.toString(16);
        String sHex = s.toString(16);

        assertTrue(ChallengeUtils.verifyZkpProof(yHex, tHex, sHex));
        assertFalse(ChallengeUtils.verifyZkpProof(yHex, tHex, s.add(BigInteger.ONE).toString(16)));
    }

    @Test
    public void testStatelessTicket() {
        Map<String, Object> payload = new HashMap<>();
        payload.put("originalIp", "127.0.0.1");
        payload.put("deviceId", "dev-123");
        payload.put("expiry", System.currentTimeMillis() + 3600000L);

        String ticket = ChallengeUtils.generateStatelessTicket(payload, secret);
        assertNotNull(ticket);
        assertTrue(ticket.contains("."));

        Map<String, Object> parsed = ChallengeUtils.parseStatelessTicket(ticket, secret);
        assertNotNull(parsed);
        assertEquals("127.0.0.1", parsed.get("originalIp"));
        assertEquals("dev-123", parsed.get("deviceId"));
    }

    @Test
    public void testIsTicketValid() {
        String ip = "127.0.0.1";
        long expiry = System.currentTimeMillis() + 3600000L;
        
        // Ticket hérité / classique avec signature HMAC
        String expectedSig = RequestUtils.hmacSha256(ip + ":" + expiry, secret);
        String validLegacyTicket = expiry + ":" + expectedSig;

        assertTrue(ChallengeUtils.isTicketValid(ip, validLegacyTicket, "", "", secret, false, null, ""));
        assertFalse(ChallengeUtils.isTicketValid("192.168.1.1", validLegacyTicket, "", "", secret, false, null, ""));

        // Ticket expiré
        long expiredTime = System.currentTimeMillis() - 1000L;
        String expiredSig = RequestUtils.hmacSha256(ip + ":" + expiredTime, secret);
        String expiredTicket = expiredTime + ":" + expiredSig;
        assertFalse(ChallengeUtils.isTicketValid(ip, expiredTicket, "", "", secret, false, null, ""));
    }

    @Test
    public void testVerifyMemoryPoWLegacy() {
        String nonce = "test-nonce-mem";
        String clientSecret = "test-secret-mem";
        int difficulty = 1; // 1 Mo de difficulté
        
        // Calcul exact de la solution attendue (côté client/solveur)
        int size = difficulty * 1024 * 1024;
        int iterations = size / 16;
        int[] buffer = new int[size / 4];
        String seed = ":" + nonce + ":" + clientSecret;
        int h = 0;
        for (byte b : seed.getBytes(StandardCharsets.UTF_8)) {
            h += b;
        }
        for (int i = 0; i < buffer.length; i++) {
            h = h ^ i;
            h = h * 1597334677;
            buffer[i] = h;
        }
        int finalHash = 0;
        int addr = buffer.length > 0 ? buffer[0] % buffer.length : 0;
        if (addr < 0) addr = Math.abs(addr);
        for (int i = 0; i < iterations; i++) {
            addr = buffer[addr] % buffer.length;
            if (addr < 0) addr = Math.abs(addr);
            finalHash ^= addr;
        }

        assertTrue(ChallengeUtils.verifyMemoryPoW(nonce, String.valueOf(finalHash), difficulty, clientSecret));
        assertFalse(ChallengeUtils.verifyMemoryPoW(nonce, String.valueOf(finalHash + 1), difficulty, clientSecret));
    }

    @Test
    public void testPlaceholderMethods() {
        // Validation du placeholder de validation de Proof of Space
        assertTrue(ChallengeUtils.verifySpacePoW("nonce", "sol", new ArrayList<>(), "seed", "secret"));

        // Validation du placeholder de validation de GPU PoW
        assertTrue(ChallengeUtils.verifyGpuPow("seed", 100, "sol"));

        // Validation du rate limiter
        assertTrue(ChallengeUtils.checkChallengeRateLimit("127.0.0.1"));
    }
}