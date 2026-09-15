package com.anonympins.fingerprint;

import java.util.*;

public class FingerprintEngine {
    private final Map<String, Object> config;
    private final IStore store;
    private final BlockList allowlist;
    private final boolean verbose;
    private final boolean dryRun;
    private final Map<String, Object> thresholds;
    private final Map<String, Object> weights;

    @SuppressWarnings("unchecked")
    public FingerprintEngine(Map<String, Object> config, IStore store) {
        this.config = config != null ? config : new HashMap<>();
        this.store = store;
        this.thresholds = (Map<String, Object>) this.config.getOrDefault("thresholds", createDefaultThresholds());
        this.weights = (Map<String, Object>) this.config.getOrDefault("weights", new HashMap<String, Object>());
        this.verbose = Boolean.TRUE.equals(this.config.get("verbose"));
        this.dryRun = Boolean.TRUE.equals(this.config.get("dryRun"));
        this.allowlist = buildAllowlist();
    }

    public Map<String, Object> getThresholds() {
        return thresholds;
    }

    public Map<String, Object> getWeights() {
        return weights;
    }

    private Map<String, Object> createDefaultThresholds() {
        Map<String, Object> map = new HashMap<>();
        map.put("low", 20);
        map.put("medium", 45);
        map.put("high", 75);
        map.put("block", 95);
        return map;
    }

    @SuppressWarnings("unchecked")
    private BlockList buildAllowlist() {
        BlockList bl = new BlockList();
        List<Map<String, Object>> whitelistRules = (List<Map<String, Object>>) config.get("whitelist");
        if (whitelistRules == null) return bl;
        for (Map<String, Object> rule : whitelistRules) {
            if ("allowlist".equals(rule.get("type"))) {
                List<String> entries = (List<String>) rule.get("entries");
                if (entries != null) {
                    for (String entry : entries) {
                        bl.add(entry);
                    }
                }
            }
        }
        return bl;
    }

    public double calculateFinalScore(Map<String, Double> suspicionVector) {
        if (weights == null || weights.isEmpty()) {
            return 0.0;
        }
        double score = 0.0;
        for (Map.Entry<String, Object> entry : weights.entrySet()) {
            String key = entry.getKey();
            double weight = ((Number) entry.getValue()).doubleValue();
            score += suspicionVector.getOrDefault(key, 0.0) * weight;
        }
        return Math.min(100.0, score);
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> resolveRequestIdentity(RequestContext context, Map<String, Double> suspicionVector) {
        String existingDeviceId = context.cookies.get("device_id");
        String currentDeviceHash = RequestUtils.getCompositeDeviceHash(context);
        int pendingCookieTtl = 120;

        String deviceId = existingDeviceId;
        Map<String, Object> deviceData = null;
        Map<String, Object> newCookie = null;

        if (deviceId == null && context.tlsSessionId != null) {
            Object resumed = store.get("tls-session:" + context.tlsSessionId);
            if (resumed instanceof String) {
                deviceId = (String) resumed;
            }
        }

        if (deviceId != null) {
            Object stored = store.get("device:" + deviceId);
            if (stored instanceof Map) {
                deviceData = (Map<String, Object>) stored;
            }
        }

        if (deviceData == null) {
            Object pending = store.get("pending_cookie:" + context.clientIp);
            if (pending != null && existingDeviceId == null) {
                suspicionVector.put("cookieDroppingScore", 100.0);
            }

            deviceId = UUID.randomUUID().toString();
            boolean secureOption = "https".equalsIgnoreCase(context.getHeader("x-forwarded-proto")) 
                    || "https".equalsIgnoreCase(context.getHeader("x-url-scheme"));

            newCookie = new HashMap<>();
            newCookie.put("name", "device_id");
            newCookie.put("value", deviceId);
            Map<String, Object> options = new HashMap<>();
            options.put("httponly", true);
            options.put("secure", secureOption);
            options.put("samesite", "Strict");
            options.put("path", "/");
            if (secureOption) {
                options.put("partitioned", true);
            }
            if (config.containsKey("deviceIdCookieMaxAge")) {
                options.put("expires", System.currentTimeMillis() + ((Number) config.get("deviceIdCookieMaxAge")).longValue());
            }
            newCookie.put("options", options);

            context.cookies.put("device_id", deviceId);
            store.set("pending_cookie:" + context.clientIp, deviceId, pendingCookieTtl);

            deviceData = new HashMap<>();
            deviceData.put("initialDeviceHash", currentDeviceHash);
            deviceData.put("ips", new HashSet<>(Arrays.asList(context.clientIp)));
            deviceData.put("requestHistory", new ArrayList<Map<String, Object>>());
            deviceData.put("lastUpdate", System.currentTimeMillis());
            deviceData.put("lastFpHash", currentDeviceHash);
            deviceData.put("lastChangeTimestamp", 0L);
            deviceData.put("rapidChangeCount", 0);
            deviceData.put("highScoreCount", 0);
            deviceData.put("lastHighScoreTimestamp", 0L);
        } else {
            Set<String> ips = (Set<String>) deviceData.get("ips");
            if (ips == null) {
                ips = new HashSet<>();
                deviceData.put("ips", ips);
            }
            ips.add(context.clientIp);
        }

        if (deviceId != null && context.tlsSessionId != null) {
            store.set("tls-session:" + context.tlsSessionId, deviceId, 3600);
        }

        Map<String, Object> result = new HashMap<>();
        result.put("deviceId", deviceId);
        result.put("deviceData", deviceData);
        result.put("newCookie", newCookie);
        result.put("currentDeviceHash", currentDeviceHash); // Ajouter le hash au résultat
        return result;
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> processRequest(RequestContext context) {
        Map<String, Double> suspicionVector = new HashMap<>();
        
        // Check allowlists
        if (allowlist.check(context.clientIp)) {
            Map<String, Object> res = new HashMap<>();
            res.put("action", "next");
            res.put("score", 0.0);
            Map<String, Double> vec = new HashMap<>();
            vec.put("whitelisted", 100.0);
            res.put("vector", vec);
            return res;
        }

        Map<String, Object> identity = resolveRequestIdentity(context, suspicionVector);
        String deviceId = (String) identity.get("deviceId");
        Map<String, Object> deviceData = (Map<String, Object>) identity.get("deviceData");
        Map<String, Object> newCookie = (Map<String, Object>) identity.get("newCookie");
        String currentDeviceHash = (String) identity.get("currentDeviceHash"); // Récupérer le hash calculé

        // --- VALIDATION DE L'ANCRAGE MATÉRIEL WEBAUTHN ---
        String behaviorHeader = context.getHeader("x-behavior-metrics");
        if (behaviorHeader != null && deviceData != null) {
            try {
                Map<String, Object> metrics = ChallengeUtils.simpleJsonParse(behaviorHeader);
                if (metrics != null && metrics.containsKey("webauthnAnchor")) {
                    Map<String, Object> anchor = (Map<String, Object>) metrics.get("webauthnAnchor");
                    if (ChallengeUtils.verifyWebAuthnHardwareAnchor(anchor, deviceData)) {
                        deviceData.put("webauthnVerified", true);
                    }
                }
            } catch (Exception e) {
                // ignore
            }
        }

        if (deviceData != null && Boolean.TRUE.equals(deviceData.get("webauthnVerified"))) {
            Map<String, Object> res = new HashMap<>();
            res.put("action", "next");
            res.put("score", 0.0);
            Map<String, Double> vec = new HashMap<>();
            vec.put("webauthn_verified", 100.0);
            res.put("vector", vec);
            return res;
        }

        if (deviceData != null && Boolean.TRUE.equals(deviceData.get("condemned"))) {
            Map<String, Object> res = new HashMap<>();
            res.put("action", "block");
            res.put("status", 403);
            res.put("body", "Forbidden");
            res.put("score", 100.0);
            Map<String, Double> vec = new HashMap<>();
            vec.put("honeypotScore", 100.0);
            res.put("vector", vec);
            if (dryRun) {
                res.put("intendedAction", "block");
                res.put("action", "next");
                res.remove("status");
                res.remove("body");
            }
            return res;
        }

        // Gather metrics and scores
        double similarity = FingerprintBuilder.compare(deviceData != null ? (String) deviceData.get("initialDeviceHash") : "", currentDeviceHash);
        double inconsistencyScore = Math.min(100.0, Math.max(0.0, (1.0 - similarity) * 200.0));
        if (similarity < ((Number) config.getOrDefault("similarityThreshold", 0.7)).doubleValue()) {
            inconsistencyScore = 100.0;
        }

        Map<String, Double> behavioral = RequestUtils.getBehavioralIndicators(context, deviceData);
        double historyScore = behavioral.getOrDefault("historyScore", 0.0);
        double rotationScore = behavioral.getOrDefault("rotationScore", 0.0);

        double headerAnomalyScore = RequestUtils.getHeaderAnomalies(context).getOrDefault("headerAnomalyScore", 0.0);
        double tlsSpoofingScore = RequestUtils.getTlsSpoofingScore(context).getOrDefault("tlsSpoofingScore", 0.0);
        double timeInconsistencyScore = RequestUtils.getTimeInconsistencyScore(context).getOrDefault("timeInconsistencyScore", 0.0);
        double crossLayerInconsistencyScore = RequestUtils.getCrossLayerInconsistency(context).getOrDefault("crossLayerInconsistencyScore", 0.0);
        
        Map<String, Object> patternsConfig = (Map<String, Object>) config.getOrDefault("patterns", new HashMap<String, Object>());
        double requestPatternScore = RequestUtils.getRequestPatternScore(context, deviceData, patternsConfig).getOrDefault("requestPatternScore", 0.0);
        
        Map<String, Object> honeypotConfig = (Map<String, Object>) config.getOrDefault("honeypot", new HashMap<String, Object>());
        double honeypotScore = RequestUtils.getHoneypotScore(context, honeypotConfig).getOrDefault("honeypotScore", 0.0);
        
        double behaviorScore = RequestUtils.getBehaviorScore(context).getOrDefault("behaviorScore", 0.0);
        double botScore = RequestUtils.getBotScore(context).getOrDefault("botScore", 0.0);
        double clickVarianceScore = RequestUtils.getClickVarianceScore(context).getOrDefault("clickVarianceScore", 0.0);
        double clientHintsInconsistencyScore = RequestUtils.getClientHintsInconsistencyScore(context).getOrDefault("clientHintsInconsistencyScore", 0.0);
        double subnetScore = RequestUtils.getSubnetScore(store, context, deviceId).getOrDefault("subnetScore", 0.0);
        
        String stableFp = RequestUtils.extractStablePart(currentDeviceHash);
        String stableFpHash = FingerprintBuilder.cyrb53(stableFp, 0);
        double botnetClusterScore = RequestUtils.getBotnetClusterScore(context, stableFpHash).getOrDefault("botnetClusterScore", 0.0);

        double tcpAnomalyScore = RequestUtils.getTcpAnomalyScore(context).getOrDefault("tcpAnomalyScore", 0.0);
        double quicAnomalyScore = RequestUtils.getQuicAnomalyScore(context).getOrDefault("quicAnomalyScore", 0.0);
        double renderingAnomalyScore = RequestUtils.getRenderingAnomalyScore(context).getOrDefault("renderingAnomalyScore", 0.0);
        double ipReputationScore = RequestUtils.getIpReputationScore(store, context.clientIp);

        suspicionVector.put("inconsistencyScore", inconsistencyScore);
        suspicionVector.put("historyScore", historyScore);
        suspicionVector.put("rotationScore", rotationScore);
        suspicionVector.put("headerAnomalyScore", headerAnomalyScore);
        suspicionVector.put("tlsSpoofingScore", tlsSpoofingScore);
        suspicionVector.put("timeInconsistencyScore", timeInconsistencyScore);
        suspicionVector.put("crossLayerInconsistencyScore", crossLayerInconsistencyScore);
        suspicionVector.put("requestPatternScore", requestPatternScore);
        suspicionVector.put("honeypotScore", honeypotScore);
        suspicionVector.put("behaviorScore", behaviorScore);
        suspicionVector.put("botScore", botScore);
        suspicionVector.put("clickVarianceScore", clickVarianceScore);
        suspicionVector.put("clientHintsInconsistencyScore", clientHintsInconsistencyScore);
        suspicionVector.put("subnetScore", subnetScore);
        suspicionVector.put("botnetClusterScore", botnetClusterScore);
        suspicionVector.put("tcpAnomalyScore", tcpAnomalyScore);
        suspicionVector.put("quicAnomalyScore", quicAnomalyScore);
        suspicionVector.put("renderingAnomalyScore", renderingAnomalyScore);
        suspicionVector.put("ipReputationScore", ipReputationScore);

        double finalScore = calculateFinalScore(suspicionVector);

        // Update subnet metrics
        int lowThreshold = ((Number) thresholds.getOrDefault("low", 20)).intValue();
        if (finalScore > lowThreshold) {
            RequestUtils.updateSubnetMetrics(store, context, deviceId, finalScore);
        }

        int deviceTtl = 2592000; // 30 jours par défaut en secondes
        if (config.containsKey("deviceIdCookieMaxAge")) {
            deviceTtl = (int) (((Number) config.get("deviceIdCookieMaxAge")).longValue() / 1000);
        }
        store.set("device:" + deviceId, deviceData, deviceTtl);
        recordTrafficLog(context, finalScore, suspicionVector);

        Map<String, Object> response = new HashMap<>();
        response.put("score", finalScore);
        response.put("vector", suspicionVector);

        int blockThreshold = ((Number) thresholds.getOrDefault("block", 95)).intValue();
        int highThreshold = ((Number) thresholds.getOrDefault("high", 75)).intValue();
        int mediumThreshold = ((Number) thresholds.getOrDefault("medium", 45)).intValue();

        String action = "next";
        if (finalScore >= blockThreshold) {
            action = "block";
        } else if (finalScore >= highThreshold) {
            action = "challenge";
        } else if (finalScore >= mediumThreshold) {
            action = "flag";
        }

        response.put("action", action);
        if ("block".equals(action)) {
            response.put("status", 403);
            response.put("body", "Forbidden");
        }

        if (dryRun) {
            response.put("intendedAction", action);
            response.put("action", "next");
            response.remove("status");
            response.remove("body");
        }

        if (newCookie != null) {
            response.put("cookie", newCookie);
        }

        return response;
    }


    @SuppressWarnings("unchecked")
    private void recordTrafficLog(RequestContext context, double score, Map<String, Double> vector) {
        try {
            List<Map<String, Object>> logs = (List<Map<String, Object>>) store.get("traffic_logs");
            if (logs == null) {
                logs = new ArrayList<>();
            }
            Map<String, Object> log = new HashMap<>();
            log.put("type", score >= ((Number) thresholds.get("block")).doubleValue() ? "request_blocked" : "request_passed");
            log.put("deviceId", context.cookies.get("device_id"));
            log.put("clientIp", context.clientIp);
            log.put("score", score);
            log.put("vector", vector);
            log.put("timestamp", System.currentTimeMillis());
            logs.add(log);
            if (logs.size() > 10000) {
                logs.remove(0);
            }
            store.set("traffic_logs", logs, 86400 * 7); // 7 jours de rétention
        } catch (Exception e) {
            // fail-safe
        }
    }
}