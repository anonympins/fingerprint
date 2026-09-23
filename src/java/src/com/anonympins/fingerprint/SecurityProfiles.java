package com.anonympins.fingerprint;

import java.util.HashMap;
import java.util.Map;

/**
 * Définit les profils de sécurité prédéfinis pour la bibliothèque Fingerprint en Java.
 * Ces profils contiennent les poids des scores de suspicion et les seuils de déclenchement.
 */
public class SecurityProfiles {

    public static final Map<String, Map<String, Object>> PROFILES = new HashMap<>();

    static {
        // ==========================================
        // BALANCED PROFILE (Default)
        // ==========================================
        Map<String, Object> balanced = new HashMap<>();
        balanced.put("summary", "Balanced Profile (Default)");
        balanced.put("description", "A general-purpose configuration suitable for most websites, offering a good mix of security and user experience. It's sensitive enough to catch common bots without being overly aggressive towards legitimate users.");
        
        Map<String, Double> balancedWeights = new HashMap<>();
        balancedWeights.put("historyScore", 0.3);
        balancedWeights.put("rotationScore", 0.5);
        balancedWeights.put("headerAnomalyScore", 0.1);
        balancedWeights.put("requestPatternScore", 0.6);
        balancedWeights.put("inconsistencyScore", 0.8);
        balancedWeights.put("behaviorScore", 0.7);
        balancedWeights.put("honeypotScore", 1.0);
        balancedWeights.put("crossLayerInconsistencyScore", 0.4);
        balancedWeights.put("timeInconsistencyScore", 0.9);
        balancedWeights.put("tlsSpoofingScore", 0.8);
        balancedWeights.put("botScore", 1.0);
        balancedWeights.put("cookieDroppingScore", 0.9);
        balancedWeights.put("threatIntelScore", 0.4);
        balancedWeights.put("clientHintsInconsistencyScore", 0.7);
        balancedWeights.put("clickVarianceScore", 0.6);
        balancedWeights.put("subnetScore", 0.5);
        balancedWeights.put("botnetClusterScore", 0.6);
        balancedWeights.put("tcpAnomalyScore", 0.8);
        balancedWeights.put("protocolAnomalyScore", 0.8);
        balancedWeights.put("ipReputationScore", 0.5);
        balancedWeights.put("virtualizationScore", 0.8);
        balanced.put("weights", balancedWeights);

        Map<String, Integer> balancedThresholds = new HashMap<>();
        balancedThresholds.put("low", 20);
        balancedThresholds.put("medium", 45);
        balancedThresholds.put("high", 75);
        balancedThresholds.put("block", 95);
        balanced.put("thresholds", balancedThresholds);

        Map<String, Object> balancedPatterns = new HashMap<>();
        balancedPatterns.put("velocityThreshold", 800);
        balancedPatterns.put("burstThreshold", 1500);
        balancedPatterns.put("scrapeThreshold", 1000);
        balancedPatterns.put("historySize", 10);
        balancedPatterns.put("minSamples", 5);
        balancedPatterns.put("regularityThreshold", 50);
        balancedPatterns.put("benfordThreshold", 0.15);
        balancedPatterns.put("patternWeight", 80);
        balancedPatterns.put("decayFactor", 0.9);
        balancedPatterns.put("inactivityReset", 5000);
        balanced.put("patterns", balancedPatterns);

        balanced.put("wasm", true);
        balanced.put("filterWhitelist", 85.0);
        PROFILES.put("balanced", balanced);

        // ==========================================
        // STRICT PROFILE
        // ==========================================
        Map<String, Object> strict = new HashMap<>();
        strict.put("summary", "Strict Profile");
        strict.put("description", "An aggressive configuration for sensitive applications (e.g., financial services, admin panels). It uses lower suspicion thresholds and higher penalties for anomalies, prioritizing security over user convenience. All new devices are challenged by default.");
        
        Map<String, Double> strictWeights = new HashMap<>();
        strictWeights.put("historyScore", 0.4);
        strictWeights.put("rotationScore", 0.6);
        strictWeights.put("headerAnomalyScore", 0.2);
        strictWeights.put("requestPatternScore", 0.8);
        strictWeights.put("inconsistencyScore", 1.0);
        strictWeights.put("behaviorScore", 0.8);
        strictWeights.put("honeypotScore", 1.0);
        strictWeights.put("crossLayerInconsistencyScore", 0.6);
        strictWeights.put("timeInconsistencyScore", 1.0);
        strictWeights.put("tlsSpoofingScore", 1.0);
        strictWeights.put("botScore", 1.0);
        strictWeights.put("cookieDroppingScore", 1.0);
        strictWeights.put("threatIntelScore", 0.7);
        strictWeights.put("clientHintsInconsistencyScore", 0.9);
        strictWeights.put("clickVarianceScore", 0.7);
        strictWeights.put("subnetScore", 0.7);
        strictWeights.put("botnetClusterScore", 0.8);
        strictWeights.put("tcpAnomalyScore", 1.0);
        strictWeights.put("protocolAnomalyScore", 1.0);
        strict.put("weights", strictWeights);

        Map<String, Integer> strictThresholds = new HashMap<>();
        strictThresholds.put("low", 10);
        strictThresholds.put("medium", 35);
        strictThresholds.put("high", 65);
        strictThresholds.put("block", 90);
        strict.put("thresholds", strictThresholds);

        Map<String, Object> strictPatterns = new HashMap<>();
        strictPatterns.put("velocityThreshold", 1000);
        strictPatterns.put("burstThreshold", 1800);
        strictPatterns.put("scrapeThreshold", 1200);
        strictPatterns.put("historySize", 15);
        strictPatterns.put("minSamples", 4);
        strictPatterns.put("regularityThreshold", 40);
        strictPatterns.put("benfordThreshold", 0.12);
        strictPatterns.put("patternWeight", 90);
        strictPatterns.put("decayFactor", 0.85);
        strictPatterns.put("inactivityReset", 4000);
        strict.put("patterns", strictPatterns);

        strict.put("challengeNewDevices", true);
        strict.put("wasm", true);
        strict.put("filterWhitelist", true);
        PROFILES.put("strict", strict);

        // ==========================================
        // API PROFILE
        // ==========================================
        Map<String, Object> api = new HashMap<>();
        api.put("summary", "API Profile");
        api.put("description", "Optimized for protecting API endpoints. This profile is highly sensitive to request patterns (velocity, bursts) and less reliant on browser-specific behavioral metrics. It's designed to quickly identify and throttle scrapers and automated clients.");
        
        Map<String, Double> apiWeights = new HashMap<>();
        apiWeights.put("historyScore", 0.5);
        apiWeights.put("rotationScore", 0.5);
        apiWeights.put("headerAnomalyScore", 0.3);
        apiWeights.put("requestPatternScore", 1.0);
        apiWeights.put("inconsistencyScore", 0.7);
        apiWeights.put("behaviorScore", 0.2);
        apiWeights.put("honeypotScore", 1.0);
        apiWeights.put("crossLayerInconsistencyScore", 0.5);
        apiWeights.put("timeInconsistencyScore", 0.8);
        apiWeights.put("tlsSpoofingScore", 0.7);
        apiWeights.put("botScore", 0.5);
        apiWeights.put("cookieDroppingScore", 0.8);
        apiWeights.put("threatIntelScore", 0.5);
        apiWeights.put("clientHintsInconsistencyScore", 0.6);
        apiWeights.put("clickVarianceScore", 0.3);
        apiWeights.put("subnetScore", 0.8);
        apiWeights.put("botnetClusterScore", 0.7);
        apiWeights.put("tcpAnomalyScore", 0.8);
        apiWeights.put("protocolAnomalyScore", 0.8);
        api.put("weights", apiWeights);

        Map<String, Integer> apiThresholds = new HashMap<>();
        apiThresholds.put("low", 25);
        apiThresholds.put("medium", 50);
        apiThresholds.put("high", 80);
        apiThresholds.put("block", 95);
        api.put("thresholds", apiThresholds);

        Map<String, Object> apiPatterns = new HashMap<>();
        apiPatterns.put("velocityThreshold", 200);
        apiPatterns.put("burstThreshold", 500);
        apiPatterns.put("scrapeThreshold", 400);
        apiPatterns.put("historySize", 20);
        apiPatterns.put("minSamples", 8);
        apiPatterns.put("regularityThreshold", 20);
        apiPatterns.put("benfordThreshold", 0.18);
        apiPatterns.put("patternWeight", 85);
        apiPatterns.put("decayFactor", 0.9);
        apiPatterns.put("inactivityReset", 10000);
        api.put("patterns", apiPatterns);

        api.put("isApiRequest", "req.path.startsWith(\"/api/\") || req.headers.accept?.includes(\"application/json\")");
        api.put("wasm", true);
        api.put("filterWhitelist", 75.0);
        PROFILES.put("api", api);

        // ==========================================
        // BLOG PROFILE (Synchronisé)
        // ==========================================
        Map<String, Object> blog = new HashMap<>();
        blog.put("summary", "Blog Profile");
        blog.put("description", "Tuned for blogs and content-heavy websites. This profile focuses on detecting content scraping and comment spam by placing a high weight on request patterns and honeypot traps, while being more lenient on behavioral metrics typical of readers.");
        
        Map<String, Double> blogWeights = new HashMap<>();
        blogWeights.put("historyScore", 0.2);
        blogWeights.put("protocolAnomalyScore", 0.5);
        blogWeights.put("requestPatternScore", 0.8); // High weight to detect content scraping
        blogWeights.put("inconsistencyScore", 0.7);
        blogWeights.put("behaviorScore", 0.5); // Less emphasis on complex interactions
        blogWeights.put("honeypotScore", 1.0); // Crucial for comment spam
        blogWeights.put("crossLayerInconsistencyScore", 0.4);
        blogWeights.put("timeInconsistencyScore", 0.8);
        blogWeights.put("tlsSpoofingScore", 0.6); // Moins critique pour les blogs
        blogWeights.put("botScore", 0.8);
        blogWeights.put("cookieDroppingScore", 0.7);
        blogWeights.put("threatIntelScore", 0.3);
        blogWeights.put("clientHintsInconsistencyScore", 0.5);
        blogWeights.put("clickVarianceScore", 0.5);
        blogWeights.put("subnetScore", 0.4);
        blogWeights.put("ipReputationScore", 0.3); // NOUVEAU: Poids pour la réputation IP
        blogWeights.put("botnetClusterScore", 0.5); // NOUVEAU: Poids pour le clustering botnet
        blogWeights.put("tcpAnomalyScore", 0.5); // NEW: Anomalie de pile TCP/IP
        blogWeights.put("quicAnomalyScore", 0.5); // NOUVEAU: Poids pour l'anomalie QUIC
        blogWeights.put("renderingAnomalyScore", 0.5); // NOUVEAU: Poids pour l'anomalie de rendu
        blog.put("weights", blogWeights);

        Map<String, Integer> blogThresholds = new HashMap<>();
        blogThresholds.put("low", 25);
        blogThresholds.put("medium", 55);
        blogThresholds.put("high", 80);
        blogThresholds.put("block", 95);
        blog.put("thresholds", blogThresholds);

        Map<String, Object> blogPatterns = new HashMap<>();
        blogPatterns.put("velocityThreshold", 1000);
        blogPatterns.put("burstThreshold", 2000);
        blogPatterns.put("scrapeThreshold", 800);
        blogPatterns.put("historySize", 12);
        blogPatterns.put("minSamples", 5);
        blogPatterns.put("regularityThreshold", 60);
        blogPatterns.put("benfordThreshold", 0.16);
        blogPatterns.put("patternWeight", 85);
        blogPatterns.put("decayFactor", 0.92);
        blogPatterns.put("inactivityReset", 10000);
        blog.put("patterns", blogPatterns);

        blog.put("wasm", true);
        blog.put("filterWhitelist", 90.0);
        PROFILES.put("blog", blog);
    }

    public static Map<String, Object> createSecurityProfile(String profileName, Map<String, Object> overrides) {
        Map<String, Object> baseProfile = PROFILES.getOrDefault(profileName, PROFILES.get("balanced"));
        return deepMerge(baseProfile, overrides);
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> deepMerge(Map<String, Object> target, Map<String, Object> source) {
        Map<String, Object> output = new HashMap<>(target);
        for (Map.Entry<String, Object> entry : source.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            if (value instanceof Map && output.get(key) instanceof Map) {
                output.put(key, deepMerge((Map<String, Object>) output.get(key), (Map<String, Object>) value));
            } else {
                output.put(key, value);
            }
        }
        return output;
    }
}