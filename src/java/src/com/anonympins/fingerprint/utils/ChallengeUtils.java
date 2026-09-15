package com.anonympins.fingerprint.utils;

import com.anonympins.fingerprint.FingerprintBuilder;
import com.anonympins.fingerprint.IStore;
import com.anonympins.fingerprint.InMemoryStore;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Classe utilitaire pour la génération et la vérification des challenges Proof-of-Work (PoW, uPoW, ZKP, etc.).
 */
public class ChallengeUtils {

    private static final String DEFAULT_FALLBACK_SECRET = "fallback-dev-secret-32-chars-minimum";
    private static final Map<String, List<Long>> IP_REQUEST_LOGS = new java.util.concurrent.ConcurrentHashMap<>();
    private static final int MAX_REQUESTS_PER_WINDOW = 10;
    private static final long WINDOW_MS = 60000; // 1 minute
    private static IStore store = new InMemoryStore();

    public static void setStore(IStore externalStore) {
        store = externalStore;
    }

    @SuppressWarnings("unchecked")
    public static String calculateCpuTarget(double suspicionFactor, Map<String, Object> securityConfig) {
        Map<String, Object> cpuConfig = (Map<String, Object>) (securityConfig != null ? securityConfig.getOrDefault("cpu", new HashMap<>()) : new HashMap<>());
        int minBits = ((Number) cpuConfig.getOrDefault("minDifficultyBits", 8)).intValue();
        int maxBits = ((Number) cpuConfig.getOrDefault("maxDifficultyBits", 22)).intValue();
        
        double totalBits = minBits + suspicionFactor * (maxBits - minBits);
        if (totalBits <= 0) {
            return "f".repeat(64);
        }
        
        int shift = 256 - (int) Math.floor(totalBits);
        BigInteger target = BigInteger.ONE.shiftLeft(shift);
        StringBuilder hex = new StringBuilder(target.toString(16));
        while (hex.length() < 64) {
            hex.insert(0, "0");
        }
        return hex.toString();
    }

    public static String createCpuChallengeBaseBlock(String nonce, String clientSecret, String fingerprint) {
        String[] parts = fingerprint != null ? fingerprint.split("\\|") : new String[0];
        List<String> filteredParts = new ArrayList<>();
        for (String part : parts) {
            if (!part.isEmpty()) {
                filteredParts.add(part);
            }
        }
        Collections.sort(filteredParts);
        String sortedFingerprint = String.join("|", filteredParts);
        return nonce + ":" + clientSecret + ":" + sortedFingerprint + ":";
    }

    public static float hashSeedToFloat(String seed) {
        int hash = 0;
        for (int i = 0; i < seed.length(); i++) {
            hash = (hash << 5) - hash + seed.charAt(i);
        }
        return (float) (Math.abs(hash % 1000000) / 1000000.0);
    }

    public static String getPowSecret() {
        String secret = System.getenv("POW_SECRET");
        if (secret == null || secret.isEmpty()) {
            secret = System.getProperty("POW_SECRET");
        }
        return (secret != null && !secret.isEmpty()) ? secret : DEFAULT_FALLBACK_SECRET;
    }

    public static boolean verifyZkpProof(String yStr, String tStr, String sStr) {
        try {
            BigInteger y = new BigInteger(yStr, 16);
            BigInteger t = new BigInteger(tStr, 16);
            BigInteger s = new BigInteger(sStr, 16);

            BigInteger ZKP_P = new BigInteger("115792089237316195423570985008687907853269984665640564039457584007908834671663");
            BigInteger ZKP_G = BigInteger.valueOf(2);

            String cStr = ZKP_G.toString() + y.toString() + t.toString();
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = md.digest(cStr.getBytes(StandardCharsets.UTF_8));
            BigInteger c = new BigInteger(1, hashBytes).mod(ZKP_P);

            BigInteger left = ZKP_G.modPow(s, ZKP_P);
            BigInteger y_c = y.modPow(c, ZKP_P);
            BigInteger right = t.multiply(y_c).mod(ZKP_P);

            return left.equals(right);
        } catch (Exception e) {
            return false;
        }
    }

    public static String generateStatelessTicket(Map<String, Object> payload, String secret) {
        String privateKeyPem = System.getenv("ED25519_PRIVATE_KEY");
        if (privateKeyPem == null || privateKeyPem.isEmpty()) {
            privateKeyPem = System.getProperty("ED25519_PRIVATE_KEY");
        }
        if (privateKeyPem != null && !privateKeyPem.isEmpty()) {
            try {
                String cleanKey = privateKeyPem.replace("\\n", "\n")
                                               .replace("-----BEGIN PRIVATE KEY-----", "")
                                               .replace("-----END PRIVATE KEY-----", "")
                                               .replaceAll("\\s+", "");
                byte[] keyBytes = Base64.getDecoder().decode(cleanKey);
                java.security.spec.PKCS8EncodedKeySpec spec = new java.security.spec.PKCS8EncodedKeySpec(keyBytes);
                java.security.KeyFactory kf = java.security.KeyFactory.getInstance("Ed25519");
                java.security.PrivateKey privateKey = kf.generatePrivate(spec);
                
                String json = simpleJsonStringify(payload);
                byte[] serialized = json.getBytes(StandardCharsets.UTF_8);
                java.security.Signature sig = java.security.Signature.getInstance("Ed25519");
                sig.initSign(privateKey);
                sig.update(serialized);
                byte[] signatureBytes = sig.sign();
                return "ed25519." + base64UrlEncode(serialized) + "." + base64UrlEncode(signatureBytes);
            } catch (Exception e) {
                System.err.println("[ChallengeUtils] Ed25519 signing failed: " + e.getMessage());
            }
        }
        try {
            String json = simpleJsonStringify(payload);
            byte[] keyBytes = MessageDigest.getInstance("SHA-256").digest(secret.getBytes(StandardCharsets.UTF_8));
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
            byte[] ivBytes = new byte[12];
            java.security.SecureRandom secureRandom = new java.security.SecureRandom();
            secureRandom.nextBytes(ivBytes);
            javax.crypto.spec.GCMParameterSpec gcmSpec = new javax.crypto.spec.GCMParameterSpec(128, ivBytes);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
            byte[] encryptedBytes = cipher.doFinal(json.getBytes(StandardCharsets.UTF_8));

            byte[] ivAndEncrypted = new byte[ivBytes.length + encryptedBytes.length];
            System.arraycopy(ivBytes, 0, ivAndEncrypted, 0, ivBytes.length);
            System.arraycopy(encryptedBytes, 0, ivAndEncrypted, ivBytes.length, encryptedBytes.length);

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(keyBytes, "HmacSHA256"));
            byte[] signatureBytes = mac.doFinal(ivAndEncrypted);

            return base64UrlEncode(ivBytes) + "." + base64UrlEncode(encryptedBytes) + "." + base64UrlEncode(signatureBytes);
        } catch (Exception e) {
            throw new RuntimeException("Stateless ticket generation failed", e);
        }
    }

    public static Map<String, Object> parseStatelessTicket(String ticket, String secret) {
        if (ticket == null || !ticket.contains(".")) {
            return null;
        }
        if (ticket.startsWith("ed25519.")) {
            String[] parts = ticket.split("\\.");
            if (parts.length != 3) {
                return null;
            }
            try {
                byte[] payloadBytes = base64UrlDecode(parts[1]);
                byte[] signature = base64UrlDecode(parts[2]);
                
                String ed25519PubKey = System.getenv("ED25519_PUBLIC_KEY");
                if (ed25519PubKey == null || ed25519PubKey.isEmpty()) {
                    ed25519PubKey = System.getProperty("ED25519_PUBLIC_KEY");
                }
                if (ed25519PubKey == null || ed25519PubKey.isEmpty()) {
                    System.err.println("[ChallengeUtils] ED25519_PUBLIC_KEY is not defined in environment.");
                    return null;
                }
                String cleanKey = ed25519PubKey.replace("\\n", "\n")
                                               .replace("-----BEGIN PUBLIC KEY-----", "")
                                               .replace("-----END PUBLIC KEY-----", "")
                                               .replaceAll("\\s+", "");
                byte[] keyBytes = Base64.getDecoder().decode(cleanKey);
                java.security.spec.X509EncodedKeySpec spec = new java.security.spec.X509EncodedKeySpec(keyBytes);
                java.security.KeyFactory kf = java.security.KeyFactory.getInstance("Ed25519");
                java.security.PublicKey publicKey = kf.generatePublic(spec);
                
                java.security.Signature sig = java.security.Signature.getInstance("Ed25519");
                sig.initVerify(publicKey);
                sig.update(payloadBytes);
                if (sig.verify(signature)) {
                    return simpleJsonParse(new String(payloadBytes, StandardCharsets.UTF_8));
                }
                return null;
            } catch (Exception e) {
                System.err.println("[ChallengeUtils] Ed25519 verification failed: " + e.getMessage());
                return null;
            }
        }
        String[] parts = ticket.split("\\.");
        if (parts.length != 3) {
            return null;
        }
        try {
            byte[] ivBytes = base64UrlDecode(parts[0]);
            byte[] encryptedBytes = base64UrlDecode(parts[1]);
            byte[] signatureBytes = base64UrlDecode(parts[2]);

            byte[] keyBytes = MessageDigest.getInstance("SHA-256").digest(secret.getBytes(StandardCharsets.UTF_8));
            SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");

            byte[] ivAndEncrypted = new byte[ivBytes.length + encryptedBytes.length];
            System.arraycopy(ivBytes, 0, ivAndEncrypted, 0, ivBytes.length);
            System.arraycopy(encryptedBytes, 0, ivAndEncrypted, ivBytes.length, encryptedBytes.length);

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(keyBytes, "HmacSHA256"));
            byte[] expectedSignature = mac.doFinal(ivAndEncrypted);

            if (!MessageDigest.isEqual(signatureBytes, expectedSignature)) {
                return null;
            }

                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                javax.crypto.spec.GCMParameterSpec gcmSpec = new javax.crypto.spec.GCMParameterSpec(128, ivBytes);
                cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

            return simpleJsonParse(new String(decryptedBytes, StandardCharsets.UTF_8));
        } catch (Exception e) {
            return null;
        }
    }

    public static boolean isTicketValid(String ip, String ticket, String deviceId, String deviceHash, String secret, boolean allowCrossNetworkRoaming, IStore store, String zkpProof) {
        if (ip == null || ticket == null || ticket.isEmpty()) {
            return false;
        }

        Map<String, Object> ticketData = parseStatelessTicket(ticket, secret);
        if (ticketData != null) {
            Long expiry = ((Number) ticketData.get("expiry")).longValue();
            String originalIp = (String) ticketData.get("originalIp");
            String storedDeviceId = (String) ticketData.getOrDefault("deviceId", "");
            String storedDeviceHash = (String) ticketData.getOrDefault("deviceHash", "");

            if (expiry == null || System.currentTimeMillis() > expiry) {
                return false;
            }

            if (storedDeviceHash != null && storedDeviceHash.startsWith("zkp:")) {
                String expectedY = storedDeviceHash.substring(4);
                if (zkpProof != null && !zkpProof.isEmpty()) {
                    String[] zkpParts = zkpProof.split(":");
                    if (zkpParts.length == 3 && zkpParts[0].equals(expectedY)) {
                        if (verifyZkpProof(zkpParts[0], zkpParts[1], zkpParts[2])) {
                            return true;
                        }
                    }
                }
                return false;
            }

            if (ip.equals(originalIp)) {
                return true;
            }

            String currentSubnet = RequestUtils.getIpSubnet(ip, 24, 48);
            String originalSubnet = RequestUtils.getIpSubnet(originalIp, 24, 48);
            if (currentSubnet != null && originalSubnet != null && currentSubnet.equals(originalSubnet)) {
                return true;
            }

            if (!allowCrossNetworkRoaming) {
                return false;
            }

            return !deviceId.isEmpty() && deviceId.equals(storedDeviceId) && !deviceHash.isEmpty() && deviceHash.equals(storedDeviceHash);
        }

        if (store != null) {
            Object dbVal = store.get("ticket:" + ticket);
            if (dbVal instanceof Map) {
                @SuppressWarnings("unchecked")
                Map<String, Object> dbData = (Map<String, Object>) dbVal;
                String originalIp = (String) dbData.get("originalIp");
                String storedDeviceId = (String) dbData.getOrDefault("deviceId", "");
                String storedDeviceHash = (String) dbData.getOrDefault("deviceHash", "");
                Long expiry = dbData.get("expiry") != null ? ((Number) dbData.get("expiry")).longValue() : null;

                if (expiry != null && System.currentTimeMillis() > expiry) {
                    store.delete("ticket:" + ticket);
                    return false;
                }

                if (storedDeviceHash != null && storedDeviceHash.startsWith("zkp:")) {
                    String expectedY = storedDeviceHash.substring(4);
                    if (zkpProof != null && !zkpProof.isEmpty()) {
                        String[] zkpParts = zkpProof.split(":");
                        if (zkpParts.length == 3 && zkpParts[0].equals(expectedY)) {
                            if (verifyZkpProof(zkpParts[0], zkpParts[1], zkpParts[2])) {
                                return true;
                            }
                        }
                    }
                    return false;
                }

                if (ip.equals(originalIp)) {
                    return true;
                }

                String currentSubnet = RequestUtils.getIpSubnet(ip, 24, 48);
                String originalSubnet = RequestUtils.getIpSubnet(originalIp, 24, 48);
                if (currentSubnet != null && originalSubnet != null && currentSubnet.equals(originalSubnet)) {
                    return true;
                }

                if (!allowCrossNetworkRoaming) {
                    return false;
                }

                return !deviceId.isEmpty() && deviceId.equals(storedDeviceId) && !deviceHash.isEmpty() && deviceHash.equals(storedDeviceHash);
            }
        }

        if (ticket.contains(":")) {
            String[] parts = ticket.split(":");
            if (parts.length < 2) return false;
            try {
                long expiry = Long.parseLong(parts[0]);
                String sig = parts[1];
                if (System.currentTimeMillis() > expiry) {
                    return false;
                }
                String expectedSig = RequestUtils.hmacSha256(ip + ":" + expiry, secret);
                return MessageDigest.isEqual(expectedSig.getBytes(StandardCharsets.UTF_8), sig.getBytes(StandardCharsets.UTF_8));
            } catch (NumberFormatException e) {
                return false;
            }
        }

        return false;
    }

    public static boolean verifyMemoryPoW(String nonce, String solution, int difficulty, String clientSecret) {
        int maxAllowedMemDifficulty = 128;
        if (difficulty > maxAllowedMemDifficulty) {
            System.err.println("[Security] Memory PoW verification attempt with excessive difficulty: " + difficulty + "MB. Denied.");
            return false;
        }
        if (difficulty == 0) {
            return true;
        }
        if (solution == null || solution.isEmpty()) {
            return false;
        }

        if (solution.matches("^\\d+$")) {
            return verifyMemoryPoWLegacy(nonce, Integer.parseInt(solution), difficulty, clientSecret);
        }

        Map<String, Object> data = simpleJsonParse(solution);
        if (data == null || !data.containsKey("solution") || !data.containsKey("merkleRoot") || !data.containsKey("proofs")) {
            return false;
        }

        long sol = ((Number) data.get("solution")).longValue();
        String merkleRoot = (String) data.get("merkleRoot");
        @SuppressWarnings("unchecked")
        Map<String, Object> proofs = (Map<String, Object>) data.get("proofs");

        int numBlocks = difficulty * 256;
        String seed = ":" + nonce + ":" + clientSecret;

        List<Integer> challengedIndices = getChallengedIndices(seed, sol, numBlocks, 4);

        for (int b : challengedIndices) {
            String bStr = String.valueOf(b);
            @SuppressWarnings("unchecked")
            List<Object> proofList = (List<Object>) (proofs.containsKey(bStr) ? proofs.get(bStr) : proofs.get(b));
            if (proofList == null) return false;

            List<String> proof = new ArrayList<>();
            for (Object o : proofList) {
                proof.add(o.toString());
            }

            int[] block = new int[1024];
            long h = Long.parseUnsignedLong(FingerprintBuilder.cyrb53(seed + ":" + b, 0)) & 0xFFFFFFFFL;
            int hInt = (int) h;
            for (int i = 0; i < 1024; i++) {
                hInt = hInt ^ i;
                hInt = hInt * 1597334677;
                block[i] = hInt;
            }

            byte[] blockBytes = new byte[4096];
            for (int i = 0; i < 1024; i++) {
                int val = block[i];
                blockBytes[i * 4] = (byte) (val & 0xFF);
                blockBytes[i * 4 + 1] = (byte) ((val >> 8) & 0xFF);
                blockBytes[i * 4 + 2] = (byte) ((val >> 16) & 0xFF);
                blockBytes[i * 4 + 3] = (byte) ((val >> 24) & 0xFF);
            }

            String expectedLeaf;
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] hashBytes = md.digest(blockBytes);
                StringBuilder hexString = new StringBuilder();
                for (byte bByte : hashBytes) {
                    String hex = Integer.toHexString(0xff & bByte);
                    if (hex.length() == 1) hexString.append('0');
                    hexString.append(hex);
                }
                expectedLeaf = hexString.toString();
            } catch (NoSuchAlgorithmException e) {
                return false;
            }

            if (!verifyMerkleProof(expectedLeaf, b, proof, merkleRoot)) {
                return false;
            }
        }

        Map<Integer, int[]> blockCache = new HashMap<>();
        java.util.function.BiFunction<Integer, Integer, Integer> getBlockElement = (blockIdx, elementIdx) -> {
            if (!blockCache.containsKey(blockIdx)) {
                int[] block = new int[1024];
                long h = Long.parseUnsignedLong(FingerprintBuilder.cyrb53(seed + ":" + blockIdx, 0)) & 0xFFFFFFFFL;
                int hInt = (int) h;
                for (int i = 0; i < 1024; i++) {
                    hInt = hInt ^ i;
                    hInt = hInt * 1597334677;
                    block[i] = hInt;
                }
                blockCache.put(blockIdx, block);
            }
            return blockCache.get(blockIdx)[elementIdx];
        };

        int totalElements = numBlocks * 1024;
        long addr = totalElements > 0 ? Integer.toUnsignedLong(getBlockElement.apply(0, 0)) % totalElements : 0;
        long expectedSolution = 0;
        int iterations = 1024;
        for (int i = 0; i < iterations; i++) {
            int blockIdx = (int) (addr / 1024);
            int elementIdx = (int) (addr % 1024);
            addr = Integer.toUnsignedLong(getBlockElement.apply(blockIdx, elementIdx)) % totalElements;
            expectedSolution ^= addr;
        }

        return expectedSolution == sol;
    }

    private static List<Integer> getChallengedIndices(String seed, long solution, int numBlocks, int k) {
        List<Integer> indices = new ArrayList<>();
        long h = Long.parseUnsignedLong(FingerprintBuilder.cyrb53(seed + ":" + solution, 0)) & 0xFFFFFFFFL;
        int hInt = (int) h;
        for (int i = 0; i < k; i++) {
            hInt = hInt ^ i;
            hInt = hInt * 1597334677;
            indices.add(Math.abs(hInt) % numBlocks);
        }
        return indices;
    }

    private static boolean verifyMerkleProof(String leafHash, int index, List<String> proof, String root) {
        String currentHash = leafHash;
        int idx = index;
        for (String sibling : proof) {
            String combined = (idx % 2 == 0) ? currentHash + sibling : sibling + currentHash;
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] hashBytes = md.digest(hexToBytes(combined));
                StringBuilder hexString = new StringBuilder();
                for (byte b : hashBytes) {
                    String hex = Integer.toHexString(0xff & b);
                    if (hex.length() == 1) hexString.append('0');
                    hexString.append(hex);
                }
                currentHash = hexString.toString();
            } catch (Exception e) {
                return false;
            }
            idx /= 2;
        }
        return currentHash.equals(root);
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }

    private static boolean verifyMemoryPoWLegacy(String nonce, int solution, int difficulty, String clientSecret) {
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
        return finalHash == solution;
    }

    private static String base64UrlEncode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static byte[] base64UrlDecode(String str) {
        return Base64.getUrlDecoder().decode(str);
    }

    public static String simpleJsonStringify(Map<String, Object> map) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        boolean first = true;
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            if (!first) sb.append(",");
            first = false;
            sb.append("\"").append(entry.getKey()).append("\":");
            Object val = entry.getValue();
            if (val instanceof String) {
                sb.append("\"").append(val.toString().replace("\"", "\\\"")).append("\"");
            } else if (val instanceof Number || val instanceof Boolean) {
                sb.append(val);
            } else if (val == null) {
                sb.append("null");
            } else if (val instanceof Collection) {
                sb.append("[");
                boolean innerFirst = true;
                for (Object item : (Collection<?>) val) {
                    if (!innerFirst) sb.append(",");
                    innerFirst = false;
                    if (item instanceof String) {
                        sb.append("\"").append(item.toString().replace("\"", "\\\"")).append("\"");
                    } else {
                        sb.append(item);
                    }
                }
                sb.append("]");
            } else {
                sb.append("\"").append(val.toString().replace("\"", "\\\"")).append("\"");
            }
        }
        sb.append("}");
        return sb.toString();
    }

    public static Map<String, Object> simpleJsonParse(String json) {
        Map<String, Object> map = new HashMap<>();
        String trimmed = json.trim();
        if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
            trimmed = trimmed.substring(1, trimmed.length() - 1);
            int len = trimmed.length();
            boolean inQuotes = false;
            int bracketDepth = 0;
            int braceDepth = 0;
            StringBuilder currentToken = new StringBuilder();
            List<String> pairs = new ArrayList<>();
            for (int i = 0; i < len; i++) {
                char c = trimmed.charAt(i);
                if (c == '"' && (i == 0 || trimmed.charAt(i - 1) != '\\')) {
                    inQuotes = !inQuotes;
                }
                if (!inQuotes) {
                    if (c == '[') bracketDepth++;
                    else if (c == ']') bracketDepth--;
                    else if (c == '{') braceDepth++;
                    else if (c == '}') braceDepth--;
                }
                if (c == ',' && !inQuotes && bracketDepth == 0 && braceDepth == 0) {
                    pairs.add(currentToken.toString());
                    currentToken = new StringBuilder();
                } else {
                    currentToken.append(c);
                }
            }
            if (currentToken.length() > 0) {
                pairs.add(currentToken.toString());
            }

            for (String pair : pairs) {
                int colonIdx = pair.indexOf(':');
                if (colonIdx != -1) {
                    String key = pair.substring(0, colonIdx).trim();
                    if (key.startsWith("\"") && key.endsWith("\"")) {
                        key = key.substring(1, key.length() - 1);
                    }
                    String valStr = pair.substring(colonIdx + 1).trim();
                    Object val = parseValue(valStr);
                    map.put(key, val);
                }
            }
        }
        return map;
    }

    private static Object parseValue(String valStr) {
        if (valStr.startsWith("\"") && valStr.endsWith("\"")) {
            return valStr.substring(1, valStr.length() - 1);
        } else if (valStr.equals("true")) {
            return true;
        } else if (valStr.equals("false")) {
            return false;
        } else if (valStr.equals("null")) {
            return null;
        } else if (valStr.startsWith("[") && valStr.endsWith("]")) {
            List<Object> list = new ArrayList<>();
            String inside = valStr.substring(1, valStr.length() - 1).trim();
            if (!inside.isEmpty()) {
                boolean inQuotes = false;
                StringBuilder current = new StringBuilder();
                for (int i = 0; i < inside.length(); i++) {
                    char c = inside.charAt(i);
                    if (c == '"' && (i == 0 || inside.charAt(i - 1) != '\\')) {
                        inQuotes = !inQuotes;
                    }
                    if (c == ',' && !inQuotes) {
                        list.add(parseValue(current.toString().trim()));
                        current = new StringBuilder();
                    } else {
                        current.append(c);
                    }
                }
                if (current.length() > 0) {
                    list.add(parseValue(current.toString().trim()));
                }
            }
            return list;
        } else if (valStr.startsWith("{") && valStr.endsWith("}")) {
            return simpleJsonParse(valStr);
        } else {
            try {
                if (valStr.contains(".")) {
                    return Double.parseDouble(valStr);
                } else {
                    return Long.parseLong(valStr);
                }
            } catch (NumberFormatException e) {
                return valStr;
            }
        }
    }

    private static String sha256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    public static void registerCooperativeNode(String clientIp, String nodeId, String seed) {
        String subnet = RequestUtils.getIpSubnet(clientIp, 24, 48);
        if (subnet == null) {
            return;
        }
        String key = "coop-pospace:subnet:" + subnet;
        Map<String, Map<String, Object>> nodes = (Map<String, Map<String, Object>>) store.get(key);
        if (nodes == null) {
            nodes = new HashMap<>();
        }
        long now = System.currentTimeMillis() / 1000L;

        Map<String, Map<String, Object>> cleanedNodes = new HashMap<>();
        for (Map.Entry<String, Map<String, Object>> entry : nodes.entrySet()) {
            Map<String, Object> node = entry.getValue();
            long timestamp = ((Number) node.get("timestamp")).longValue();
            if (now - timestamp < 120) {
                cleanedNodes.put(entry.getKey(), node);
            }
        }

        Map<String, Object> nodeData = new HashMap<>();
        nodeData.put("nodeId", nodeId);
        nodeData.put("seed", seed);
        nodeData.put("timestamp", now);
        cleanedNodes.put(nodeId, nodeData);

        store.set(key, cleanedNodes, 120);
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> findPeerInSubnet(String clientIp, String excludeNodeId) {
        String subnet = RequestUtils.getIpSubnet(clientIp, 24, 48);
        if (subnet == null) {
            return null;
        }
        String key = "coop-pospace:subnet:" + subnet;
        Map<String, Map<String, Object>> nodes = (Map<String, Map<String, Object>>) store.get(key);
        if (nodes == null) {
            return null;
        }
        long now = System.currentTimeMillis() / 1000L;
        List<Map<String, Object>> activePeers = new ArrayList<>();
        for (Map.Entry<String, Map<String, Object>> entry : nodes.entrySet()) {
            String id = entry.getKey();
            Map<String, Object> node = entry.getValue();
            long timestamp = ((Number) node.get("timestamp")).longValue();
            if (!id.equals(excludeNodeId) && (now - timestamp) < 120) {
                activePeers.add(node);
            }
        }
        if (activePeers.isEmpty()) {
            return null;
        }
        int randomIndex = new Random().nextInt(activePeers.size());
        return activePeers.get(randomIndex);
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> handleCooperativeRequest(Map<String, String> params, String clientIp, Map<String, Object> config) {
        String op = params.get("coop_op");
        if (op == null) {
            return null;
        }

        if ("share_threat_intel".equals(op)) {
            List<String> peers = (List<String>) config.get("federatedPeers");
            if (peers != null && !peers.isEmpty()) {
                List<String> allowedHosts = new ArrayList<>();
                for (String url : peers) {
                    try {
                        java.net.URL parsedUrl = new java.net.URL(url);
                        allowedHosts.add(parsedUrl.getHost());
                    } catch (Exception e) {
                        allowedHosts.add(url);
                    }
                }
                if (!allowedHosts.contains(clientIp)) {
                    Map<String, Object> err = new HashMap<>();
                    err.put("error", "Unauthorized federation sender IP");
                    return err;
                }
            }

            String zkpY = params.getOrDefault("zkpY", "");
            String sigHmac = params.get("signature");
            String sigEd25519 = params.get("signature_ed25519");
            String timestampStr = params.get("timestamp");
            long timestamp = 0;
            if (timestampStr != null) {
                try {
                    timestamp = Long.parseLong(timestampStr);
                } catch (NumberFormatException e) {
                    System.err.println("[ChallengeUtils] Failed to parse timestamp: " + timestampStr);
                }
            }

            System.out.println("[ChallengeUtils] share_threat_intel request: zkpY=" + zkpY + ", timestamp=" + timestamp + ", sigHmac=" + sigHmac + ", sigEd25519=" + sigEd25519);

            if (zkpY.isEmpty() || timestamp == 0 || (sigHmac == null && sigEd25519 == null)) {
                Map<String, Object> err = new HashMap<>();
                err.put("error", "Missing threat intel parameters");
                System.err.println("[ChallengeUtils] Missing threat intel parameters (zkpY, timestamp or signature).");
                return err;
            }

            long now = System.currentTimeMillis();
            if (Math.abs(now - timestamp) > 300000) {
                Map<String, Object> err = new HashMap<>();
                err.put("error", "Message expired or clock skew too high");
                System.err.println("[ChallengeUtils] Message expired or clock skew too high. now=" + now + ", timestamp=" + timestamp);
                return err;
            }

            String msg = timestamp + ":" + zkpY;
            boolean verified = false;

            if (sigEd25519 != null && !sigEd25519.isEmpty()) {
                String publicKeyPem = (String) config.get("ed25519_public_key");
                if (publicKeyPem == null) {
                    publicKeyPem = System.getenv("ED25519_PUBLIC_KEY");
                }
                if (publicKeyPem == null) {
                    publicKeyPem = System.getProperty("ED25519_PUBLIC_KEY");
                }

                if (publicKeyPem != null && !publicKeyPem.isEmpty()) {
                    try {
                        String cleanKey = publicKeyPem.replace("\\n", "\n")
                                                       .replace("-----BEGIN PUBLIC KEY-----", "")
                                                       .replace("-----END PUBLIC KEY-----", "")
                                                       .replaceAll("\\s+", "");
                        byte[] keyBytes = Base64.getDecoder().decode(cleanKey);
                        java.security.spec.X509EncodedKeySpec spec = new java.security.spec.X509EncodedKeySpec(keyBytes);
                        java.security.KeyFactory kf = java.security.KeyFactory.getInstance("Ed25519");
                        java.security.PublicKey publicKey = kf.generatePublic(spec);
                        
                        java.security.Signature sig = java.security.Signature.getInstance("Ed25519");
                        sig.initVerify(publicKey);
                        sig.update(msg.getBytes(StandardCharsets.UTF_8));
                        if (sig.verify(HexFormat.of().parseHex(sigEd25519))) {
                            verified = true;
                            System.out.println("[ChallengeUtils] Ed25519 signature verified successfully.");
                        } else {
                            System.err.println("[ChallengeUtils] Ed25519 signature verification failed.");
                        }
                    } catch (Exception e) {
                        System.err.println("[ChallengeUtils] Ed25519 key loading/verification failed: " + e.getMessage());
                    }
                } else {
                    System.err.println("[ChallengeUtils] Missing Ed25519 public key.");
                }
            } else if (sigHmac != null) {
                String secret = params.get("federationSecret");
                if (secret == null) {
                    secret = (String) config.get("federationSecret");
                }
                if (secret == null) {
                    secret = getPowSecret();
                }
                String expectedSig = RequestUtils.hmacSha256(msg, secret);
                if (sigHmac.equals(expectedSig)) {
                    verified = true;
                } else {
                    System.err.println("[ChallengeUtils] HMAC signature mismatch. expected=" + expectedSig + ", got=" + sigHmac);
                }
            }

            if (!verified) {
                Map<String, Object> err = new HashMap<>();
                err.put("error", "Invalid federation signature");
                System.err.println("[ChallengeUtils] Federation signature verification failed.");
                return err;
            }

            store.set("banned-zkp-y:" + zkpY, true, 86400 * 30);
            Map<String, Object> res = new HashMap<>();
            res.put("status", "synchronized");
            return res;
        }

        String nodeId = params.getOrDefault("node_id", "");
        if (nodeId.isEmpty()) {
            Map<String, Object> err = new HashMap<>();
            err.put("error", "Missing node_id");
            return err;
        }

        Map<String, Object> challengeContext = (Map<String, Object>) store.get("secret:" + nodeId);
        if (challengeContext == null || challengeContext.get("clientSecret") == null) {
            Map<String, Object> err = new HashMap<>();
            err.put("error", "Invalid or expired node_id");
            return err;
        }

        String clientSecret = (String) challengeContext.get("clientSecret");
        String coopSig = params.getOrDefault("coop_sig", "");

        String expectedMsg = "";
        switch (op) {
            case "register":
                expectedMsg = clientSecret + ":register:" + nodeId + ":" + params.getOrDefault("seed", "");
                break;
            case "request_peer_block":
                expectedMsg = clientSecret + ":request_peer_block:" + nodeId + ":" + params.getOrDefault("peer_id", "") + ":" + params.getOrDefault("block_idx", "0") + ":" + params.getOrDefault("req_id", "");
                break;
            case "poll_requests":
                expectedMsg = clientSecret + ":poll_requests:" + nodeId;
                break;
            case "respond_block":
                expectedMsg = clientSecret + ":respond_block:" + nodeId + ":" + params.getOrDefault("requester_id", "") + ":" + params.getOrDefault("req_id", "") + ":" + params.getOrDefault("block_data", "");
                break;
            case "poll_response":
                expectedMsg = clientSecret + ":poll_response:" + nodeId + ":" + params.getOrDefault("req_id", "");
                break;
            default:
                Map<String, Object> err = new HashMap<>();
                err.put("error", "Invalid cooperative operation");
                return err;
        }

        String expectedSig = sha256(expectedMsg);
        if (expectedSig == null || !MessageDigest.isEqual(coopSig.getBytes(StandardCharsets.UTF_8), expectedSig.getBytes(StandardCharsets.UTF_8))) {
            Map<String, Object> err = new HashMap<>();
            err.put("error", "Invalid cooperative signature");
            return err;
        }

        Map<String, Object> res = new HashMap<>();
        switch (op) {
            case "register":
                String seed = params.getOrDefault("seed", "");
                registerCooperativeNode(clientIp, nodeId, seed);
                res.put("status", "registered");
                return res;

            case "request_peer_block":
                String peerId = params.getOrDefault("peer_id", "");
                int blockIdx = Integer.parseInt(params.getOrDefault("block_idx", "0"));
                String requestId = params.getOrDefault("req_id", "");
                if (peerId.isEmpty() || requestId.isEmpty()) {
                    res.put("error", "Invalid parameters");
                    return res;
                }

                String queueKey = "coop-mailbox:queue:" + peerId;
                List<Map<String, Object>> requests = (List<Map<String, Object>>) store.get(queueKey);
                if (requests == null) {
                    requests = new ArrayList<>();
                }
                Map<String, Object> requestItem = new HashMap<>();
                requestItem.put("req_id", requestId);
                requestItem.put("requester_id", nodeId);
                requestItem.put("block_idx", blockIdx);
                requests.add(requestItem);
                store.set(queueKey, requests, 30);
                res.put("status", "queued");
                return res;

            case "poll_requests":
                String pollQueueKey = "coop-mailbox:queue:" + nodeId;
                List<Map<String, Object>> polledRequests = (List<Map<String, Object>>) store.get(pollQueueKey);
                if (polledRequests == null) {
                    polledRequests = new ArrayList<>();
                }
                store.delete(pollQueueKey);
                res.put("requests", polledRequests);
                return res;

            case "respond_block":
                String requesterId = params.getOrDefault("requester_id", "");
                String respondRequestId = params.getOrDefault("req_id", "");
                String blockData = params.getOrDefault("block_data", "");
                if (requesterId.isEmpty() || respondRequestId.isEmpty()) {
                    res.put("error", "Invalid parameters");
                    return res;
                }

                String responseKey = "coop-mailbox:res:" + requesterId + ":" + respondRequestId;
                Map<String, Object> responseData = new HashMap<>();
                responseData.put("block_data", blockData);
                store.set(responseKey, responseData, 30);
                res.put("status", "delivered");
                return res;

            case "poll_response":
                String pollResponseRequestId = params.getOrDefault("req_id", "");
                String pollResponseKey = "coop-mailbox:res:" + nodeId + ":" + pollResponseRequestId;
                Map<String, Object> data = (Map<String, Object>) store.get(pollResponseKey);
                if (data != null) {
                    store.delete(pollResponseKey);
                    res.put("status", "ready");
                    res.put("block_data", data.get("block_data"));
                    return res;
                }
                res.put("status", "pending");
                return res;
        }
        return null;
    }

    /**
     * Valide un challenge Proof of Space (uPoW).
     *
     * @param nonce Le nonce du challenge.
     * @param solution La solution soumise.
     * @param proofs Les preuves associées.
     * @param seed La graine du challenge.
     * @param secret Le secret de sécurisation.
     * @return true si la preuve est valide.
     */
    public static boolean verifySpacePoW(String nonce, String solution, List<String> proofs, String seed, String secret) {
        if (nonce == null || solution == null || proofs == null || seed == null || secret == null) {
            return false;
        }
        int k = proofs.size();
        if (k < 4) return false;
        int spaceSize = 8192;

        for (int i = 0; i < k; i++) {
            String challengeKey = nonce + ":" + i;
            long hashVal = Long.parseUnsignedLong(FingerprintBuilder.cyrb53(challengeKey, 0)) & 0xFFFFFFFFL;
            int challengedIndex = (int) (hashVal % spaceSize);

            String expectedValue = FingerprintBuilder.cyrb53(seed + ":" + secret + ":" + challengedIndex, 0);

            if (!expectedValue.equals(proofs.get(i))) {
                return false;
            }
        }

        String combinedProofs = String.join("|", proofs);
        String expectedSolution = FingerprintBuilder.cyrb53(combinedProofs + ":" + secret, 0);
        return expectedSolution.equals(solution);
    }

    /**
     * Valide un challenge GPU PoW.
     *
     * @param seed La graine du challenge.
     * @param difficulty La difficulté requise (nombre de bits de poids fort à zéro).
     * @param solution La solution soumise.
     * @return true si la preuve est valide.
     */
    public static boolean verifyGpuPow(String seed, int difficulty, String solution) {
        if (seed == null || solution == null || difficulty < 0) {
            return false;
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest((seed + solution).getBytes(StandardCharsets.UTF_8));

            int zeroBits = 0;
            for (byte b : hash) {
                int leadingZeros = Integer.numberOfLeadingZeros(b & 0xFF) - 24;
                zeroBits += leadingZeros;
                if (leadingZeros < 8) {
                    break;
                }
            }
            return zeroBits >= difficulty;
        } catch (NoSuchAlgorithmException e) {
            return false;
        }
    }

    /**
     * Vérifie la limite de taux (rate limit) pour les demandes de challenge d'un client.
     *
     * @param clientIp L'adresse IP du client.
     * @return true si la requête est autorisée.
     */
    public static boolean checkChallengeRateLimit(String clientIp) {
        if (clientIp == null || clientIp.isEmpty()) {
            return false;
        }
        long now = System.currentTimeMillis();
        List<Long> timestamps = IP_REQUEST_LOGS.computeIfAbsent(clientIp, k -> Collections.synchronizedList(new ArrayList<>()));

        synchronized (timestamps) {
            timestamps.removeIf(t -> now - t > WINDOW_MS);

            if (timestamps.size() >= MAX_REQUESTS_PER_WINDOW) {
                return false;
            }
            timestamps.add(now);
            return true;
        }
    }

    private static Object decodeCBOR(byte[] buffer, int[] offset) {
        if (offset[0] >= buffer.length) throw new RuntimeException("End of CBOR");
        int initial = buffer[offset[0]++] & 0xFF;
        int major = initial >> 5;
        int val = initial & 0x1F;

        java.util.function.BiFunction<Integer, int[], Integer> readInt = (v, off) -> {
            if (v < 24) return v;
            if (v == 24) return buffer[off[0]++] & 0xFF;
            if (v == 25) {
                int b1 = buffer[off[0]++] & 0xFF;
                int b2 = buffer[off[0]++] & 0xFF;
                return (b1 << 8) | b2;
            }
            if (v == 26) {
                int b1 = buffer[off[0]++] & 0xFF;
                int b2 = buffer[off[0]++] & 0xFF;
                int b3 = buffer[off[0]++] & 0xFF;
                int b4 = buffer[off[0]++] & 0xFF;
                return (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;
            }
            throw new RuntimeException("Unsupported int size: " + v);
        };

        if (major == 0) {
            return readInt.apply(val, offset);
        } else if (major == 1) {
            return -1 - readInt.apply(val, offset);
        } else if (major == 2 || major == 3) {
            int len = readInt.apply(val, offset);
            byte[] bytes = new byte[len];
            System.arraycopy(buffer, offset[0], bytes, 0, len);
            offset[0] += len;
            if (major == 3) {
                return new String(bytes, StandardCharsets.UTF_8);
            }
            return bytes;
        } else if (major == 4) {
            int len = readInt.apply(val, offset);
            List<Object> list = new ArrayList<>();
            for (int i = 0; i < len; i++) {
                list.add(decodeCBOR(buffer, offset));
            }
            return list;
        } else if (major == 5) {
            int len = readInt.apply(val, offset);
            Map<Object, Object> map = new HashMap<>();
            for (int i = 0; i < len; i++) {
                Object k = decodeCBOR(buffer, offset);
                Object v = decodeCBOR(buffer, offset);
                map.put(k, v);
            }
            return map;
        }
        return null;
    }

    private static final String[] TRUSTED_HARDWARE_ROOTS = {
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIDHzCCAfegAwIBAgIJANCvWjvF+2O6MA0GCSqGSIb3DQEBCwUAMC0xKzApBgNV\n" +
        "BAMTIll1YmljbyBBdHRlc3RhdGlvbiBSb290IENBMB4XDTE0MDgwNDAwMDAwMFox\n" +
        "TSUxSDBGBgNVBAMMT1l1YmljbyBBdHRlc3RhdGlvbiBSb290IENBMSowKAYDVQQK\n" +
        "EyFZdWJpY28gQUIxDzANBgNVBAcTBVN0b2NraG9sbTELMAkGA1UEBhMCU0UwggEi\n" +
        "MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC6XW0d87g+N6kGgSgC/H9UfA2p\n" +
        "-----END CERTIFICATE-----",
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIB1DCCAXWgAwIBAgIEUI70WjAKBggqhkjOPQQDAjArMSkwJwYDVQQDEyBGSURP\n" +
        "IEFsbGlhbmNlIFJvb3QgQ0EgKFRlc3QpMB4XDTE0MDgxODA4MzA0NVoXDTM5MDgx\n" +
        "ODA4MzA0NVowKzEpMCcGA1UEAxMgRklETyBBbGxpYW5jZSBSb290IENBIChUZXN0\n" +
        "KTB2MBAGByqGSM49AgEGBSuBBAAiA2IABFv81Jm9M7AehfOIdpCH567gP0yqS40m\n" +
        "aN0j1a8n152G7n/nUf7J0j9F4pL9J2w1X8hN1N8f9Y3G9w8L29/m7/zX3O3n2e7/\n" +
        "g==\n" +
        "-----END CERTIFICATE-----"
    };

    @SuppressWarnings("unchecked")
    public static boolean verifyWebAuthnHardwareAnchor(Map<String, Object> anchor, Map<String, Object> deviceData) {
        if (anchor == null || !anchor.containsKey("type")) return false;

        try {
            String type = (String) anchor.get("type");
            byte[] clientDataHash = MessageDigest.getInstance("SHA-256")
                    .digest(Base64.getDecoder().decode((String) anchor.get("clientDataJSON")));

            if ("registration".equals(type)) {
                String publicKeyPem = (String) anchor.get("publicKey");
                String credentialId = (String) anchor.get("credentialId");
                String attestationObject = (String) anchor.get("attestationObject");

                if (publicKeyPem == null || credentialId == null || attestationObject == null) {
                    return false;
                }

                byte[] attestationBytes = Base64.getDecoder().decode(attestationObject);
                int[] offset = {0};
                Map<Object, Object> decoded = (Map<Object, Object>) decodeCBOR(attestationBytes, offset);

                if (decoded == null || !decoded.containsKey("fmt") || !decoded.containsKey("attStmt")) {
                    return false;
                }

                String fmt = (String) decoded.get("fmt");
                Map<Object, Object> attStmt = (Map<Object, Object>) decoded.get("attStmt");

                if (!"none".equals(fmt)) {
                    if (!attStmt.containsKey("x5c")) {
                        return false;
                    }
                    List<byte[]> x5c = (List<byte[]>) attStmt.get("x5c");
                    if (x5c == null || x5c.isEmpty()) return false;

                    java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
                    List<java.security.cert.X509Certificate> chain = new ArrayList<>();
                    for (byte[] der : x5c) {
                        chain.add((java.security.cert.X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(der)));
                    }

                    for (int i = 0; i < chain.size() - 1; i++) {
                        chain.get(i).verify(chain.get(i + 1).getPublicKey());
                    }

                    java.security.cert.X509Certificate rootCert = chain.get(chain.size() - 1);
                    boolean trusted = false;
                    for (String trustedRootPem : TRUSTED_HARDWARE_ROOTS) {
                        java.security.cert.X509Certificate trustedRoot = (java.security.cert.X509Certificate) cf.generateCertificate(
                                new java.io.ByteArrayInputStream(trustedRootPem.getBytes(StandardCharsets.UTF_8))
                        );
                        try {
                            rootCert.verify(trustedRoot.getPublicKey());
                            trusted = true;
                            break;
                        } catch (Exception e) {
                            if (Arrays.equals(rootCert.getSignature(), trustedRoot.getSignature())) {
                                trusted = true;
                                break;
                            }
                        }
                    }
                    if (!trusted) {
                        return false;
                    }
                }

                deviceData.put("webauthnPublicKey", publicKeyPem);
                deviceData.put("webauthnCredentialId", credentialId);
                return true;
            } else if ("assertion".equals(type)) {
                String storedPublicKeyPem = (String) deviceData.get("webauthnPublicKey");
                String storedCredentialId = (String) deviceData.get("webauthnCredentialId");

                if (storedPublicKeyPem == null || !storedCredentialId.equals(anchor.get("credentialId"))) {
                    return false;
                }

                byte[] authenticatorData = Base64.getDecoder().decode((String) anchor.get("authenticatorData"));
                byte[] signature = Base64.getDecoder().decode((String) anchor.get("signature"));

                byte[] verifyBuffer = new byte[authenticatorData.length + clientDataHash.length];
                System.arraycopy(authenticatorData, 0, verifyBuffer, 0, authenticatorData.length);
                System.arraycopy(clientDataHash, 0, verifyBuffer, authenticatorData.length, clientDataHash.length);

                String cleanPem = storedPublicKeyPem
                        .replace("-----BEGIN PUBLIC KEY-----", "")
                        .replace("-----END PUBLIC KEY-----", "")
                        .replaceAll("\\s+", "");
                byte[] keyBytes = Base64.getDecoder().decode(cleanPem);
                java.security.spec.X509EncodedKeySpec spec = new java.security.spec.X509EncodedKeySpec(keyBytes);
                java.security.KeyFactory kf = java.security.KeyFactory.getInstance("EC");
                java.security.PublicKey publicKey;
                try {
                    publicKey = kf.generatePublic(spec);
                } catch (Exception e) {
                    kf = java.security.KeyFactory.getInstance("RSA");
                    publicKey = kf.generatePublic(spec);
                }

                java.security.Signature sig = java.security.Signature.getInstance("SHA256withECDSA");
                try {
                    sig.initVerify(publicKey);
                } catch (Exception e) {
                    sig = java.security.Signature.getInstance("SHA256withRSA");
                    sig.initVerify(publicKey);
                }
                sig.update(verifyBuffer);
                return sig.verify(signature);
            }
        } catch (Exception e) {
            System.err.println("[WebAuthn-Server] Java verification failed: " + e.getMessage());
        }
        return false;
    }
}