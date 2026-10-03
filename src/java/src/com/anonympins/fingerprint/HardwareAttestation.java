package com.anonympins.fingerprint;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.*;

/**
 * Moteur de validation d'attestation matérielle cryptographique pour le serveur Java :
 * 1. Apple App Attest (Secure Enclave)
 * 2. Google Play Integrity (Titan M / TEE)
 * 3. Device Bound Session Credentials (DBSC - W3C / TPM 2.0 / FIDO2)
 */
public class HardwareAttestation {

    public static class AttestationResult {
        private final boolean verified;
        private final String type;
        private final Map<String, Object> details;

        public AttestationResult(boolean verified, String type, Map<String, Object> details) {
            this.verified = verified;
            this.type = type;
            this.details = details != null ? details : Collections.emptyMap();
        }

        public boolean isVerified() { return verified; }
        public String getType() { return type; }
        public Map<String, Object> getDetails() { return details; }

        public static AttestationResult failed() {
            return new AttestationResult(false, "none", Collections.emptyMap());
        }
    }

    private static byte[] b64DecodeSafe(String input) {
        if (input == null) return new byte[0];
        String normalized = input.trim().replace('-', '+').replace('_', '/');
        int remainder = normalized.length() % 4;
        if (remainder > 0) {
            normalized += "=".repeat(4 - remainder);
        }
        return Base64.getDecoder().decode(normalized);
    }

    // ==========================================
    // 1. APPLE APP ATTEST (SECURE ENCLAVE)
    // ==========================================
    public static boolean verifyAppleAppAttestAssertion(
            PublicKey publicKey,
            byte[] assertionRaw,
            byte[] clientDataHash,
            long storedCounter
    ) {
        if (publicKey == null || assertionRaw == null || assertionRaw.length < 37) {
            return false;
        }
        try {
            byte[] authData = Arrays.copyOfRange(assertionRaw, 0, 37);
            byte[] signature = Arrays.copyOfRange(assertionRaw, 37, assertionRaw.length);

            // Monotonic counter (octets 33-37 en big-endian)
            ByteBuffer buffer = ByteBuffer.wrap(authData, 33, 4);
            long counter = buffer.getInt() & 0xFFFFFFFFL;
            if (counter <= storedCounter) {
                return false;
            }

            byte[] signedData = new byte[authData.length + clientDataHash.length];
            System.arraycopy(authData, 0, signedData, 0, authData.length);
            System.arraycopy(clientDataHash, 0, signedData, authData.length, clientDataHash.length);

            Signature ecdsa = Signature.getInstance("SHA256withECDSA");
            ecdsa.initVerify(publicKey);
            ecdsa.update(signedData);
            return ecdsa.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }

    // ==========================================
    // 2. GOOGLE PLAY INTEGRITY (TITAN M / TEE)
    // ==========================================
    public static AttestationResult verifyPlayIntegrityJws(
            String jwsToken,
            String expectedPackageName,
            String expectedNonce,
            long maxAgeMs
    ) {
        if (jwsToken == null || !jwsToken.contains(".")) {
            return AttestationResult.failed();
        }
        try {
            String[] parts = jwsToken.split("\\.");
            if (parts.length != 3) return AttestationResult.failed();

            String headerJson = new String(b64DecodeSafe(parts[0]), StandardCharsets.UTF_8);
            String payloadJson = new String(b64DecodeSafe(parts[1]), StandardCharsets.UTF_8);
            byte[] signature = b64DecodeSafe(parts[2]);

            tools.jackson.databind.ObjectMapper mapper = new tools.jackson.databind.ObjectMapper();
            Map<String, Object> header = mapper.readValue(headerJson, Map.class);
            Map<String, Object> payload = mapper.readValue(payloadJson, Map.class);

            // Validation de la chaîne de certificats Google x5c
            if (header.containsKey("x5c")) {
                List<String> x5c = (List<String>) header.get("x5c");
                if (x5c != null && !x5c.isEmpty()) {
                    byte[] certDer = Base64.getDecoder().decode(x5c.get(0));
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    X509Certificate cert = (X509Certificate) cf.generateCertificate(new java.io.ByteArrayInputStream(certDer));
                    
                    Signature ecdsa = Signature.getInstance("SHA256withECDSA");
                    ecdsa.initVerify(cert.getPublicKey());
                    ecdsa.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
                    if (!ecdsa.verify(signature)) {
                        return AttestationResult.failed();
                    }
                }
            }

            Map<String, Object> reqDetails = (Map<String, Object>) payload.get("requestDetails");
            if (reqDetails != null) {
                if (expectedNonce != null && !expectedNonce.equals(reqDetails.get("nonce"))) {
                    return AttestationResult.failed();
                }
                if (reqDetails.containsKey("timestampMillis")) {
                    long ts = Long.parseLong(reqDetails.get("timestampMillis").toString());
                    if (Math.abs(System.currentTimeMillis() - ts) > maxAgeMs) {
                        return AttestationResult.failed();
                    }
                }
            }

            if (expectedPackageName != null) {
                Map<String, Object> appInteg = (Map<String, Object>) payload.get("appIntegrity");
                if (appInteg == null || !expectedPackageName.equals(appInteg.get("packageName"))) {
                    return AttestationResult.failed();
                }
            }

            Map<String, Object> devInteg = (Map<String, Object>) payload.get("deviceIntegrity");
            if (devInteg != null) {
                List<String> verdicts = (List<String>) devInteg.get("deviceRecognitionVerdict");
                if (verdicts != null && (verdicts.contains("MEETS_STRONG_INTEGRITY") || verdicts.contains("MEETS_DEVICE_INTEGRITY"))) {
                    return new AttestationResult(true, "google_play_integrity_strong", payload);
                }
            }
        } catch (Exception ignored) {}
        return AttestationResult.failed();
    }

    // ==========================================
    // 3. DEVICE BOUND SESSION CREDENTIALS (DBSC)
    // ==========================================
    public static boolean verifyDbscProof(
            String dbscJwt,
            Map<String, Object> jwk,
            String expectedSessionId,
            String expectedOrigin,
            String expectedNonce
    ) {
        if (dbscJwt == null || !dbscJwt.contains(".") || jwk == null) {
            return false;
        }
        try {
            String[] parts = dbscJwt.split("\\.");
            if (parts.length != 3) return false;

            String payloadJson = new String(b64DecodeSafe(parts[1]), StandardCharsets.UTF_8);
            tools.jackson.databind.ObjectMapper mapper = new tools.jackson.databind.ObjectMapper();
            Map<String, Object> payload = mapper.readValue(payloadJson, Map.class);

            if (!expectedSessionId.equals(payload.get("sub"))) {
                return false;
            }
            if (expectedOrigin != null && !expectedOrigin.equals(payload.get("aud"))) {
                return false;
            }
            if (expectedNonce != null && !expectedNonce.equals(payload.get("nonce"))) {
                return false;
            }

            // Reconstruction de la clé publique ECDSA P-256 à partir du JWK matériel
            byte[] x = b64DecodeSafe((String) jwk.get("x"));
            byte[] y = b64DecodeSafe((String) jwk.get("y"));

            AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
            parameters.init(new java.security.spec.ECGenParameterSpec("secp256r1"));
            java.security.spec.ECParameterSpec ecParameters = parameters.getParameterSpec(java.security.spec.ECParameterSpec.class);
            ECPoint point = new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
            ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, ecParameters);
            PublicKey pubKey = KeyFactory.getInstance("EC").generatePublic(pubSpec);

            // Conversion IEEE P1363 vers DER si requis pour Java Signature
            byte[] rawSig = b64DecodeSafe(parts[2]);
            byte[] derSig = rawSig;
            if (rawSig.length == 64) {
                derSig = ieeeP1363ToDer(rawSig);
            }

            Signature ecdsa = Signature.getInstance("SHA256withECDSA");
            ecdsa.initVerify(pubKey);
            ecdsa.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
            return ecdsa.verify(derSig);
        } catch (Exception e) {
            return false;
        }
    }

    private static byte[] ieeeP1363ToDer(byte[] ieee) throws Exception {
        byte[] r = Arrays.copyOfRange(ieee, 0, 32);
        byte[] s = Arrays.copyOfRange(ieee, 32, 64);
        BigInteger rInt = new BigInteger(1, r);
        BigInteger sInt = new BigInteger(1, s);

        byte[] rBytes = rInt.toByteArray();
        byte[] sBytes = sInt.toByteArray();

        int totalLen = 4 + rBytes.length + sBytes.length;
        byte[] der = new byte[totalLen + 2];
        der[0] = 0x30; // SEQUENCE
        der[1] = (byte) totalLen;
        der[2] = 0x02; // INTEGER
        der[3] = (byte) rBytes.length;
        System.arraycopy(rBytes, 0, der, 4, rBytes.length);

        int sOffset = 4 + rBytes.length;
        der[sOffset] = 0x02; // INTEGER
        der[sOffset + 1] = (byte) sBytes.length;
        System.arraycopy(sBytes, 0, der, sOffset + 2, sBytes.length);

        return der;
    }
}