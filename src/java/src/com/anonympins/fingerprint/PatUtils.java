package com.anonympins.fingerprint;

import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utilitaires d'extraction, parsing binaire et validation cryptographique RFC 9578.
 */
public final class PatUtils {
    private static final Pattern PRIVATE_TOKEN_PATTERN =
            Pattern.compile("token=(?:\"([^\"]+)\"|([a-zA-Z0-9_\\-+/=]+))", Pattern.CASE_INSENSITIVE);

    private PatUtils() {}

    /**
     * Extrait les jetons binaires des en-têtes HTTP (Authorization et Sec-Private-State-Token).
     */
    public static List<byte[]> extractTokens(Map<String, String> headers) {
        List<byte[]> tokens = new ArrayList<>();
        if (headers == null || headers.isEmpty()) {
            return tokens;
        }

        String authHeader = getHeaderIgnoreCase(headers, "Authorization");
        if (authHeader != null && authHeader.trim().toLowerCase().startsWith("privatetoken ")) {
            Matcher matcher = PRIVATE_TOKEN_PATTERN.matcher(authHeader);
            if (matcher.find()) {
                String rawB64 = matcher.group(1) != null ? matcher.group(1) : matcher.group(2);
                byte[] decoded = decodeBase64Safe(rawB64);
                if (decoded != null && decoded.length >= 98) {
                    tokens.add(decoded);
                }
            }
        }

        String pstHeader = getHeaderIgnoreCase(headers, "Sec-Private-State-Token");
        if (pstHeader != null && !pstHeader.trim().isEmpty()) {
            String[] parts = pstHeader.split(",");
            for (String part : parts) {
                String trimmed = part.trim();
                if (!trimmed.isEmpty()) {
                    byte[] decoded = decodeBase64Safe(trimmed);
                    if (decoded != null && decoded.length >= 98) {
                        tokens.add(decoded);
                    }
                }
            }
        }

        return tokens;
    }

    /**
     * Décode la structure binaire RFC 9578 d'un jeton :
     * Header fixe (98 octets) + Signature (authenticator).
     */
    public static PrivateAccessToken parseToken(byte[] binary) {
        if (binary == null || binary.length < 98) {
            return null;
        }

        ByteBuffer buffer = ByteBuffer.wrap(binary);
        int tokenType = buffer.getShort() & 0xFFFF;

        byte[] nonce = new byte[32];
        buffer.get(nonce);

        byte[] challengeDigest = new byte[32];
        buffer.get(challengeDigest);

        byte[] tokenKeyId = new byte[32];
        buffer.get(tokenKeyId);

        byte[] authenticator = new byte[buffer.remaining()];
        buffer.get(authenticator);

        if (authenticator.length == 0) {
            return null;
        }

        byte[] signedData = new byte[98];
        System.arraycopy(binary, 0, signedData, 0, 98);

        return new PrivateAccessToken(tokenType, nonce, challengeDigest, tokenKeyId, authenticator, signedData);
    }

    /**
     * Valide la signature cryptographique du jeton (Blind RSA-2048 / RSA-PSS / Ed25519).
     */
    public static boolean verifySignature(PrivateAccessToken token, PublicKey publicKey) {
        if (token == null || publicKey == null) {
            return false;
        }

        int tokenType = token.getTokenType();
        byte[] signedData = token.getSignedData();
        byte[] authenticator = token.getAuthenticator();

        try {
            // Blind RSA-2048 (0x0001) / Rate-Limited Blind RSA (0x0002)
            if (tokenType == 0x0001 || tokenType == 0x0002 || tokenType == 1 || tokenType == 2) {
                // 1. RSA-PSS avec SHA-384 (RFC 9577 Section 4)
                try {
                    Signature pssSha384 = Signature.getInstance("RSASSA-PSS");
                    pssSha384.setParameter(new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1));
                    pssSha384.initVerify(publicKey);
                    pssSha384.update(signedData);
                    if (pssSha384.verify(authenticator)) {
                        return true;
                    }
                } catch (Exception ignored) {}

                // 2. RSA-PSS avec SHA-256
                try {
                    Signature pssSha256 = Signature.getInstance("RSASSA-PSS");
                    pssSha256.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
                    pssSha256.initVerify(publicKey);
                    pssSha256.update(signedData);
                    if (pssSha256.verify(authenticator)) {
                        return true;
                    }
                } catch (Exception ignored) {}

                // 3. Fallback PKCS#1 v1.5 avec SHA-256
                try {
                    Signature pkcs1 = Signature.getInstance("SHA256withRSA");
                    pkcs1.initVerify(publicKey);
                    pkcs1.update(signedData);
                    if (pkcs1.verify(authenticator)) {
                        return true;
                    }
                } catch (Exception ignored) {}
            } else if (tokenType == 0x0003 || tokenType == 3) {
                // VOPRF / Ed25519
                try {
                    Signature ed25519 = Signature.getInstance("Ed25519");
                    ed25519.initVerify(publicKey);
                    ed25519.update(signedData);
                    return ed25519.verify(authenticator);
                } catch (Exception ignored) {}
            }
        } catch (Exception e) {
            return false;
        }

        return false;
    }

    public static byte[] decodeBase64Safe(String input) {
        if (input == null) return null;
        String normalized = input.trim().replace('-', '+').replace('_', '/');
        int remainder = normalized.length() % 4;
        if (remainder > 0) {
            normalized += "=".repeat(4 - remainder);
        }
        try {
            return Base64.getDecoder().decode(normalized);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    public static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }

    private static String getHeaderIgnoreCase(Map<String, String> headers, String target) {
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(target)) {
                return entry.getValue();
            }
        }
        return null;
    }
}