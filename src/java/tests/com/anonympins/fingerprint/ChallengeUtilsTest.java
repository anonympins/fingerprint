package com.anonympins.fingerprint;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class ChallengeUtilsTest {

    private final String secret = "my-secret-key-32-chars-long-minimum-for-testing";

    private InMemoryStore store;

    @BeforeEach
    public void setUp() {


        store = new InMemoryStore();

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
    public void testVerifyGpuPowSuccess() {
        String seed = "gpu-test-seed-xyz";
        int difficulty = 8; // requiert que le premier octet soit égal à 0x00

        // Brute-force rapide d'une solution valide pour le test
        String validSolution = null;
        for (int i = 0; i < 10000; i++) {
            String candidate = "sol-" + i;
            if (ChallengeUtils.verifyGpuPow(seed, difficulty, candidate)) {
                validSolution = candidate;
                break;
            }
        }

        assertNotNull(validSolution, "Une solution aurait dû être trouvée avec une difficulté de 8 en moins de 10k itérations");
        assertTrue(ChallengeUtils.verifyGpuPow(seed, difficulty, validSolution));
    }

    @Test
    public void testVerifyGpuPowFailure() {
        String seed = "gpu-test-seed-xyz";
        // On teste une fausse solution
        assertFalse(ChallengeUtils.verifyGpuPow(seed, 8, "wrong-solution-unlikely-to-have-8-leading-zeros"));
    }

    @Test
    public void testVerifySpacePoWSuccess() {
        String nonce = "space-challenge-nonce";
        String seed = "space-test-seed";
        String secret = "space-test-secret";
        int k = 4; // Nombre minimal de preuves requis
        int spaceSize = 8192;

        // Simulation de la génération de preuves côté client
        List<String> proofs = new ArrayList<>();
        for (int i = 0; i < k; i++) {
            String challengeKey = nonce + ":" + i;
            long hashVal = Long.parseUnsignedLong(FingerprintBuilder.cyrb53(challengeKey, 0)) & 0xFFFFFFFFL;
            int challengedIndex = (int) (hashVal % spaceSize);
            proofs.add(FingerprintBuilder.cyrb53(seed + ":" + secret + ":" + challengedIndex, 0));
        }

        // Génération de la solution attendue
        String combined = String.join("|", proofs);
        String validSolution = FingerprintBuilder.cyrb53(combined + ":" + secret, 0);

        assertTrue(ChallengeUtils.verifySpacePoW(nonce, validSolution, proofs, seed, secret));
    }

    @Test
    public void testVerifySpacePoWFailure() {
        String nonce = "space-challenge-nonce";
        String seed = "space-test-seed";
        String secret = "space-test-secret";
        List<String> invalidProofs = Arrays.asList("p1", "p2", "p3", "p4");

        assertFalse(ChallengeUtils.verifySpacePoW(nonce, "bad-solution", invalidProofs, seed, secret));
    }

    @Test
    public void testCheckChallengeRateLimit() {
        String ip = "192.168.1.100";

        // 10 premières demandes autorisées
        for (int i = 0; i < 10; i++) {
            assertTrue(ChallengeUtils.checkChallengeRateLimit(ip));
        }

        // La 11e demande doit échouer (limite atteinte)
        assertFalse(ChallengeUtils.checkChallengeRateLimit(ip));

        // Une autre IP doit être indépendante et réussir
        assertTrue(ChallengeUtils.checkChallengeRateLimit("192.168.1.101"));
    }


    // Helper to generate valid signatures (mimics client-side logic)
    private String generateCoopSig(String op, String nodeId, String clientSecret, String... extraParams) {
        StringBuilder msg = new StringBuilder(clientSecret + ":" + op + ":" + nodeId);
        for (String param : extraParams) {
            msg.append(":").append(param);
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(msg.toString().getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void testCooperativeRequestHandlingWithSignatures() {
        // 1. Setup: Define test data
        String nodeIdA = "node-alpha";
        String nodeIdB = "node-beta";
        String clientSecretA = "secret-alpha-for-node-a";
        String clientSecretB = "secret-beta-for-node-b";
        String seedA = "seed-for-alpha";
        String seedB = "seed-for-beta";
        int blockIdx = 42;
        String reqId = "req-12345";
        String blockData = "0102030405060708090a0b0c0d0e0f"; // Hex string representing block data

        String clientIp = "127.0.0.1";
        Map<String, Object> config = new HashMap<>();

        // Store challenge contexts for both nodes (crucial for signature verification)
        store.set("secret:" + nodeIdA, new HashMap<String, Object>() {{ put("clientSecret", clientSecretA); }}, 300);
        store.set("secret:" + nodeIdB, new HashMap<String, Object>() {{ put("clientSecret", clientSecretB); }}, 300);

        // --- Test 1: Successful Registration (Node A) ---
        String sigA_register = generateCoopSig("register", nodeIdA, clientSecretA, seedA);
        Map<String, String> paramsRegisterA = new HashMap<String, String>() {{
            put("coop_op", "register"); put("node_id", nodeIdA); put("seed", seedA); put("coop_sig", sigA_register);
        }};
        Map<String, Object> resRegisterA = ChallengeUtils.handleCooperativeRequest(paramsRegisterA, clientIp, config);
        assertEquals("registered", resRegisterA.get("status"), "Node A should register successfully.");

        // --- Test 2: Successful Registration (Node B) ---
        String sigB_register = generateCoopSig("register", nodeIdB, clientSecretB, seedB);
        Map<String, String> paramsRegisterB = new HashMap<String, String>() {{
            put("coop_op", "register"); put("node_id", nodeIdB); put("seed", seedB); put("coop_sig", sigB_register);
        }};
        Map<String, Object> resRegisterB = ChallengeUtils.handleCooperativeRequest(paramsRegisterB, clientIp, config);
        assertEquals("registered", resRegisterB.get("status"), "Node B should register successfully.");

        // --- Test 3: Failed Registration (Invalid Signature) ---
        Map<String, String> paramsInvalidSig = new HashMap<>(paramsRegisterA);
        paramsInvalidSig.put("coop_sig", "invalid-signature");
        Map<String, Object> resInvalidSig = ChallengeUtils.handleCooperativeRequest(paramsInvalidSig, clientIp, config);
        assertEquals("Invalid cooperative signature", resInvalidSig.get("error"), "Registration with invalid signature should fail.");

        // --- Test 4: Successful Block Request (Node A requests from Node B) ---
        String sigA_requestBlock = generateCoopSig("request_peer_block", nodeIdA, clientSecretA, nodeIdB, String.valueOf(blockIdx), reqId);
        Map<String, String> paramsRequestBlock = new HashMap<String, String>() {{
            put("coop_op", "request_peer_block"); put("node_id", nodeIdA); put("peer_id", nodeIdB);
            put("block_idx", String.valueOf(blockIdx)); put("req_id", reqId); put("coop_sig", sigA_requestBlock);
        }};
        Map<String, Object> resRequestBlock = ChallengeUtils.handleCooperativeRequest(paramsRequestBlock, clientIp, config);
        assertEquals("queued", resRequestBlock.get("status"), "Block request should be queued.");

        // --- Test 5: Failed Block Request (Invalid Signature) ---
        paramsInvalidSig = new HashMap<>(paramsRequestBlock);
        paramsInvalidSig.put("coop_sig", "invalid-signature");
        resInvalidSig = ChallengeUtils.handleCooperativeRequest(paramsInvalidSig, clientIp, config);
        assertEquals("Invalid cooperative signature", resInvalidSig.get("error"), "Block request with invalid signature should fail.");

        // --- Test 6: Successful Poll Requests (Node B polls for requests) ---
        String sigB_pollRequests = generateCoopSig("poll_requests", nodeIdB, clientSecretB);
        Map<String, String> paramsPollRequests = new HashMap<String, String>() {{
            put("coop_op", "poll_requests"); put("node_id", nodeIdB); put("coop_sig", sigB_pollRequests);
        }};
        Map<String, Object> resPollRequests = ChallengeUtils.handleCooperativeRequest(paramsPollRequests, clientIp, config);
        List<Map<String, Object>> requests = (List<Map<String, Object>>) resPollRequests.get("requests");
        assertNotNull(requests);
        assertEquals(1, requests.size(), "Node B should receive 1 request.");
        assertEquals(reqId, requests.get(0).get("req_id"));
        assertEquals(nodeIdA, requests.get(0).get("requester_id"));
        assertEquals(blockIdx, requests.get(0).get("block_idx"));

        // --- Test 7: Failed Poll Requests (Invalid Signature) ---
        paramsInvalidSig = new HashMap<>(paramsPollRequests);
        paramsInvalidSig.put("coop_sig", "invalid-signature");
        resInvalidSig = ChallengeUtils.handleCooperativeRequest(paramsInvalidSig, clientIp, config);
        assertEquals("Invalid cooperative signature", resInvalidSig.get("error"), "Poll requests with invalid signature should fail.");

        // --- Test 8: Successful Respond Block (Node B responds to Node A) ---
        String sigB_respondBlock = generateCoopSig("respond_block", nodeIdB, clientSecretB, nodeIdA, reqId, blockData);
        Map<String, String> paramsRespondBlock = new HashMap<String, String>() {{
            put("coop_op", "respond_block"); put("node_id", nodeIdB); put("requester_id", nodeIdA);
            put("req_id", reqId); put("block_data", blockData); put("coop_sig", sigB_respondBlock);
        }};
        Map<String, Object> resRespondBlock = ChallengeUtils.handleCooperativeRequest(paramsRespondBlock, clientIp, config);
        assertEquals("delivered", resRespondBlock.get("status"), "Block response should be delivered.");

        // --- Test 9: Failed Respond Block (Invalid Signature) ---
        paramsInvalidSig = new HashMap<>(paramsRespondBlock);
        paramsInvalidSig.put("coop_sig", "invalid-signature");
        resInvalidSig = ChallengeUtils.handleCooperativeRequest(paramsInvalidSig, clientIp, config);
        assertEquals("Invalid cooperative signature", resInvalidSig.get("error"), "Respond block with invalid signature should fail.");

        // --- Test 10: Successful Poll Response (Node A polls for response) ---
        String sigA_pollResponse = generateCoopSig("poll_response", nodeIdA, clientSecretA, reqId);
        Map<String, String> paramsPollResponse = new HashMap<String, String>() {{
            put("coop_op", "poll_response"); put("node_id", nodeIdA); put("req_id", reqId); put("coop_sig", sigA_pollResponse);
        }};
        Map<String, Object> resPollResponse = ChallengeUtils.handleCooperativeRequest(paramsPollResponse, clientIp, config);
        assertEquals("ready", resPollResponse.get("status"), "Node A should receive the block data.");
        assertEquals(blockData, resPollResponse.get("block_data"));

        // --- Test 11: Failed Poll Response (Invalid Signature) ---
        paramsInvalidSig = new HashMap<>(paramsPollResponse);
        paramsInvalidSig.put("coop_sig", "invalid-signature");
        resInvalidSig = ChallengeUtils.handleCooperativeRequest(paramsInvalidSig, clientIp, config);
        assertEquals("Invalid cooperative signature", resInvalidSig.get("error"), "Poll response with invalid signature should fail.");

        // --- Test 12: Invalid/Expired node_id ---
        Map<String, String> paramsExpiredNode = new HashMap<String, String>() {{
            put("coop_op", "register"); put("node_id", "non-existent-node"); put("coop_sig", "any-sig");
        }};
        Map<String, Object> resExpiredNode = ChallengeUtils.handleCooperativeRequest(paramsExpiredNode, clientIp, config);
        assertEquals("Invalid or expired node_id", resExpiredNode.get("error"), "Request with non-existent node_id should fail.");

        // --- Test 13: Missing node_id ---
        Map<String, String> paramsMissingNodeId = new HashMap<String, String>() {{
            put("coop_op", "register"); put("coop_sig", "any-sig");
        }};
        Map<String, Object> resMissingNodeId = ChallengeUtils.handleCooperativeRequest(paramsMissingNodeId, clientIp, config);
        assertEquals("Missing node_id", resMissingNodeId.get("error"), "Request without node_id should fail.");

        // --- Test 14: Invalid cooperative operation ---
        Map<String, String> paramsInvalidOp = new HashMap<String, String>() {{
            put("coop_op", "unknown_op"); put("node_id", nodeIdA); put("coop_sig", "any-sig");
        }};
        Map<String, Object> resInvalidOp = ChallengeUtils.handleCooperativeRequest(paramsInvalidOp, clientIp, config);
        assertEquals("Invalid cooperative operation", resInvalidOp.get("error"), "Request with unknown operation should fail.");
    }
}