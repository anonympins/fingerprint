package com.anonympins.fingerprint;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.net.InetAddress;
import java.security.NoSuchAlgorithmException;
import java.util.stream.Collectors;
import java.net.UnknownHostException;

public class RequestUtils {

    public static Map<String, Double> getBehavioralIndicators(RequestContext context, Map<String, Object> deviceData) {
        Map<String, Double> result = new HashMap<>();
        double historyScore = 0.0;
        double rotationScore = 0.0;

        if (deviceData != null) {
            @SuppressWarnings("unchecked")
            Set<String> ips = (Set<String>) deviceData.get("ips");
            if (ips != null && ips.size() > 5) {
                rotationScore = Math.min(100.0, (ips.size() - 5) * 15.0);
            }

            @SuppressWarnings("unchecked")
            List<Map<String, Object>> history = (List<Map<String, Object>>) deviceData.get("requestHistory");
            if (history != null && history.size() > 50) {
                historyScore = 50.0;
            }
        }
        result.put("historyScore", historyScore);
        result.put("rotationScore", rotationScore);
        return result;
    }

    public static Map<String, Double> getHeaderAnomalies(RequestContext context) {
        Map<String, Double> result = new HashMap<>();
        double score = 0.0;
        String ua = context.getHeader("user-agent");
        String host = context.getHeader("host");
        if (ua == null || host == null) {
            score = 100.0;
        }
        result.put("headerAnomalyScore", score);
        return result;
    }

    public static Map<String, Double> getTlsSpoofingScore(RequestContext context) {
        Map<String, Double> result = new HashMap<>();
        double score = 0.0;
        if (context.tlsSessionId != null && context.tlsSessionId.length() < 10) {
            score = 50.0;
        }
        result.put("tlsSpoofingScore", score);
        return result;
    }

    public static Map<String, Double> getTimeInconsistencyScore(RequestContext context) {
        Map<String, Double> result = new HashMap<>();
        double score = 0.0;
        String clientTimeStr = context.getHeader("x-client-time");
        if (clientTimeStr != null) {
            try {
                long clientTime = Long.parseLong(clientTimeStr);
                long serverTime = System.currentTimeMillis();
                long diff = Math.abs(serverTime - clientTime);
                // Si l'écart dépasse 5 minutes, on calcule un score de suspicion proportionnel
                if (diff > 300000) {
                    score = Math.min(100.0, (diff - 300000) / 6000.0);
                }
            } catch (NumberFormatException e) {
                score = 50.0; // Format invalide suspect
            }
        }
        result.put("timeInconsistencyScore", score);
        return result;
    }

    public static Map<String, Double> getCrossLayerInconsistency(RequestContext context) {
        Map<String, Double> result = new HashMap<>();
        double score = 0.0;
        String userAgent = context.getHeader("user-agent");
        String secChUa = context.getHeader("sec-ch-ua");
        
        // Incohérence entre les informations d'un User-Agent classique et les Client Hints
        if (userAgent != null && secChUa != null) {
            boolean isChromeInUA = userAgent.contains("Chrome");
            boolean isChromeInCH = secChUa.contains("Chrome") || secChUa.contains("Google Chrome");
            if (isChromeInUA != isChromeInCH) {
                score = 80.0;
            }
        }
        result.put("crossLayerInconsistencyScore", score);
        return result;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Double> getRequestPatternScore(RequestContext context, Map<String, Object> deviceData, Map<String, Object> patternsConfig) {
        Map<String, Double> result = new HashMap<>();
        double score = 0.0;
        
        if (deviceData != null) {
            List<Map<String, Object>> history = (List<Map<String, Object>>) deviceData.get("requestHistory");
            if (history != null) {
                long now = System.currentTimeMillis();
                long lastRequest = (long) deviceData.getOrDefault("lastUpdate", now);
                long interval = now - lastRequest;
                
                // Détection de requêtes trop rapides
                if (interval < 100) {
                    score += 40.0;
                }
                
                Map<String, Object> currentReq = new HashMap<>();
                currentReq.put("timestamp", now);
                currentReq.put("path", context.getHeader("x-request-uri"));
                history.add(currentReq);
                if (history.size() > 10) {
                    history.remove(0);
                }
                
                // Détection d'un bot programmé (intervalles fixes / écart-type ultra-faible)
                if (history.size() >= 5) {
                    List<Long> intervals = new ArrayList<>();
                    for (int i = 1; i < history.size(); i++) {
                        long t1 = (long) history.get(i - 1).get("timestamp");
                        long t2 = (long) history.get(i).get("timestamp");
                        intervals.add(t2 - t1);
                    }
                    double mean = intervals.stream().mapToLong(Long::longValue).average().orElse(0.0);
                    double variance = intervals.stream()
                        .mapToDouble(val -> Math.pow(val - mean, 2))
                        .average()
                        .orElse(0.0);
                    double stdDev = Math.sqrt(variance);
                    if (stdDev < 50.0 && mean > 500.0) {
                        score += 50.0;
                    }
                }
            }
        }
        result.put("requestPatternScore", Math.min(100.0, score));
        return result;
    }

    public static Map<String, Double> getHoneypotScore(RequestContext context, Map<String, Object> honeypotConfig) {
        Map<String, Double> result = new HashMap<>();
        double score = 0.0;
        String requestPath = context.getHeader("x-request-uri");
        if (requestPath != null && honeypotConfig != null) {
            @SuppressWarnings("unchecked")
            List<String> paths = (List<String>) honeypotConfig.get("paths");
            if (paths != null) {
                for (String path : paths) {
                    if (requestPath.contains(path)) {
                        score = 100.0;
                        break;
                    }
                }
            }
        }
        result.put("honeypotScore", score);
        return result;
    }

    public static Map<String, Double> getBehaviorScore(RequestContext context) {
        Map<String, Double> result = new HashMap<>();
        double score = 0.0;
        // Détection de frameworks d'automatisation (Playwright, Puppeteer, Selenium, etc.)
        if (context.getHeader("x-automation-test") != null) {
            score += 90.0;
        }
        if (context.getHeader("accept") == null) {
            score += 30.0;
        }
        if (context.getHeader("accept-encoding") == null) {
            score += 20.0;
        }
        result.put("behaviorScore", Math.min(100.0, score));
        return result;
    }

    public static Map<String, Double> getBotScore(RequestContext context) {
        Map<String, Double> result = new HashMap<>();
        double score = 0.0;
        String ua = context.getHeader("user-agent");
        if (ua != null && (ua.contains("curl") || ua.contains("wget") || ua.contains("python-requests") || ua.contains("headless"))) {
            score = 100.0;
        }
        result.put("botScore", score);
        return result;
    }

    public static Map<String, Double> getClickVarianceScore(RequestContext context) {
        Map<String, Double> result = new HashMap<>();
        result.put("clickVarianceScore", 0.0);
        return result;
    }

    public static Map<String, Double> getClientHintsInconsistencyScore(RequestContext context) {
        Map<String, Double> result = new HashMap<>();
        double score = 0.0;
        String platform = context.getHeader("sec-ch-ua-platform");
        String ua = context.getHeader("user-agent");
        if (platform != null && ua != null) {
            if (platform.contains("Windows") && ua.contains("Macintosh")) {
                score = 100.0;
            }
        }
        result.put("clientHintsInconsistencyScore", score);
        return result;
    }

    public static Map<String, Double> getSubnetScore(IStore store, RequestContext context, String deviceId) {
        Map<String, Double> result = new HashMap<>();
        result.put("subnetScore", 0.0);
        return result;
    }

    public static String extractStablePart(String currentDeviceHash) {
        if (currentDeviceHash != null && currentDeviceHash.length() > 8) {
            return currentDeviceHash.substring(0, 8);
        }
        return currentDeviceHash != null ? currentDeviceHash : "";
    }

    public static Map<String, Double> getBotnetClusterScore(RequestContext context, String stableFpHash) {
        Map<String, Double> result = new HashMap<>();
        result.put("botnetClusterScore", 0.0);
        return result;
    }

    public static Map<String, Double> getTcpAnomalyScore(RequestContext context) {
        Map<String, Double> result = new HashMap<>();
        result.put("tcpAnomalyScore", 0.0);
        return result;
    }

    public static Map<String, Double> getQuicAnomalyScore(RequestContext context) {
        Map<String, Double> result = new HashMap<>();
        result.put("quicAnomalyScore", 0.0);
        return result;
    }

    public static Map<String, Double> getRenderingAnomalyScore(RequestContext context) {
        Map<String, Double> result = new HashMap<>();
        result.put("renderingAnomalyScore", 0.0);
        return result;
    }

    public static String getIpSubnet(String ip, int ipv4Prefix, int ipv6Prefix) {
        try {
            InetAddress addr = InetAddress.getByName(ip);
            byte[] bytes = addr.getAddress();
            if (bytes.length == 4) {
                if (ipv4Prefix < 0 || ipv4Prefix > 32) return null;
                byte[] mask = new byte[4];
                for (int i = 0; i < ipv4Prefix; i++) {
                    mask[i / 8] |= (byte) (1 << (7 - (i % 8)));
                }
                byte[] subnetBytes = new byte[4];
                for (int i = 0; i < 4; i++) {
                    subnetBytes[i] = (byte) (bytes[i] & mask[i]);
                }
                return InetAddress.getByAddress(subnetBytes).getHostAddress() + "/" + ipv4Prefix;
            } else if (bytes.length == 16) {
                if (ipv6Prefix < 0 || ipv6Prefix > 128) return null;
                byte[] mask = new byte[16];
                for (int i = 0; i < ipv6Prefix; i++) {
                    mask[i / 8] |= (byte) (1 << (7 - (i % 8)));
                }
                byte[] subnetBytes = new byte[16];
                for (int i = 0; i < 16; i++) {
                    subnetBytes[i] = (byte) (bytes[i] & mask[i]);
                }
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < 8; i++) {
                    int b1 = subnetBytes[i * 2] & 0xFF;
                    int b2 = subnetBytes[i * 2 + 1] & 0xFF;
                    int word = (b1 << 8) | b2;
                    sb.append(String.format("%04x", word));
                    if (i < 7) {
                        sb.append(":");
                    }
                }
                sb.append("/").append(ipv6Prefix);
                return sb.toString();
            }
        } catch (UnknownHostException e) {
            return null;
        }
        return null;
    }

    // Map IANA cipher suite names to their decimal IDs for JA3 calculation
    private static final Map<String, Integer> cipherSuiteMap = new HashMap<>();
    static {
        cipherSuiteMap.put("TLS_AES_128_GCM_SHA256", 4865);
        cipherSuiteMap.put("TLS_AES_256_GCM_SHA384", 4866);
        cipherSuiteMap.put("TLS_CHACHA20_POLY1305_SHA256", 4867);
        cipherSuiteMap.put("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 49195);
        cipherSuiteMap.put("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 49199);
        cipherSuiteMap.put("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 49196);
        cipherSuiteMap.put("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 49200);
        cipherSuiteMap.put("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", 52393);
        cipherSuiteMap.put("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 52392);
        cipherSuiteMap.put("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 49171);
        cipherSuiteMap.put("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", 49172);
        cipherSuiteMap.put("TLS_RSA_WITH_AES_128_GCM_SHA256", 156);
        cipherSuiteMap.put("TLS_RSA_WITH_AES_256_GCM_SHA384", 157);
        cipherSuiteMap.put("TLS_RSA_WITH_AES_128_CBC_SHA", 47);
        cipherSuiteMap.put("TLS_RSA_WITH_AES_256_CBC_SHA", 53);
        cipherSuiteMap.put("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", 49161);
        cipherSuiteMap.put("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", 49162);
        cipherSuiteMap.put("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", 158);
        cipherSuiteMap.put("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", 159);
        cipherSuiteMap.put("TLS_DHE_RSA_WITH_AES_128_CBC_SHA", 51);
        cipherSuiteMap.put("TLS_DHE_RSA_WITH_AES_256_CBC_SHA", 57);
        cipherSuiteMap.put("TLS_RSA_WITH_3DES_EDE_CBC_SHA", 10);
    }

    private static String md5Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            // Should not happen with MD5
            return null;
        }
    }

    /**
     * Extracts TLS fingerprints (JA3 and JA4) from request context.
     * Prioritizes headers from reverse proxies (x-ja4-hash) and falls back to JA3 calculation
     * from raw socket data if available.
     * @param context The request context.
     * @return An object containing JA3 and JA4 hashes.
     */
    public static Map<String, String> getTlsFingerprint(RequestContext context) {
        Map<String, String> tlsFingerprints = new HashMap<>();
        String ja3 = context.ja3;
        String ja4 = context.ja4;

        // 1. Prioritize JA4 hash from a trusted reverse proxy header.
        if (ja4 != null) {
            tlsFingerprints.put("ja4", ja4);
        }
        // 2. Prioritize JA3 hash from a trusted reverse proxy header.
        if (ja3 != null) {
            tlsFingerprints.put("ja3", ja3);
        }

        // 3. Fallback to calculating from raw ClientHello if available and if JA3 is not already set
        // This part would require a TLS ClientHello parser in Java, similar to the PHP/Python versions.
        // For simplicity, we assume raw ClientHello is passed as a header (X-JA3-Raw)
        // and contains comma-separated values as per JA3 spec.
        String ja3Raw = context.ja3Raw;
        if (ja3 == null && ja3Raw != null) {
            try {
                // JA3 string format: "TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats"
                // This is a simplified example. A full implementation would parse the raw TLS ClientHello bytes.
                // Assuming ja3Raw is already in the JA3 string format:
                tlsFingerprints.put("ja3", md5Hex(ja3Raw));
            } catch (Exception e) {
                // Could fail if ja3Raw is malformed.
            }
        }
        return tlsFingerprints;
    }

    public static String getCompositeDeviceHash(RequestContext context) {
        FingerprintBuilder srv = new FingerprintBuilder();
        
        // TLS Fingerprints
        Map<String, String> tlsFp = getTlsFingerprint(context);
        if (tlsFp.containsKey("ja3")) srv.add("ja3", tlsFp.get("ja3"));
        if (tlsFp.containsKey("ja4")) srv.add("ja4", tlsFp.get("ja4"));

        // Other headers
        String ua = context.getHeader("user-agent");
        if (ua != null) srv.add("ua", ua);

        return srv.toString();
    }

    public static double getIpReputationScore(IStore store, String clientIp) {
        return 0.0;
    }

    public static void updateSubnetMetrics(IStore store, RequestContext context, String deviceId, double finalScore) {
        // Met à jour les métriques de sous-réseau dans le store (par exemple le nombre de requêtes à haut risque par bloc CIDR)
    }

    /**
     * Calcule le HMAC-SHA256 d'une chaîne de données avec une clé secrète.
     * @param data La chaîne de données à signer.
     * @param key La clé secrète.
     * @return La signature HMAC-SHA256 en format hexadécimal.
     */
    public static String hmacSha256(String data, String key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(secretKeySpec);
            byte[] hmacBytes = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hmacBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            System.err.println("Error calculating HMAC-SHA256: " + e.getMessage());
            return null;
        }
    }
}