package com.anonympins.fingerprint;

import com.anonympins.fingerprint.utils.ChallengeUtils;
import com.anonympins.fingerprint.utils.RequestUtils;

import java.util.*;

public class FingerprintEngine {
    private final Map<String, Object> config;
    private final IStore store;
    private final BlockList allowlist;
    private final BlockList blocklist;
    private final boolean verbose;
    private final boolean dryRun;
    private final Map<String, Object> thresholds;
    private final Map<String, Object> weights;

    private ProblemManager problemManager;
    @SuppressWarnings("unchecked")
    public FingerprintEngine(Map<String, Object> config, IStore store) {
        this.config = config != null ? config : new HashMap<>();

        Object failSafe = this.config.get("fail_safe");
        if (failSafe != null) {
            String fsStr = failSafe.toString();
            if (!"fail_open".equals(fsStr) && !"fail_closed".equals(fsStr)) {
                throw new IllegalArgumentException("Invalid fail_safe value: " + fsStr);
            }
        }

        this.store = store;
        this.thresholds = (Map<String, Object>) this.config.getOrDefault("thresholds", createDefaultThresholds());
        this.weights = (Map<String, Object>) this.config.getOrDefault("weights", createDefaultWeights());
        this.verbose = Boolean.TRUE.equals(this.config.get("verbose"));
        this.dryRun = Boolean.TRUE.equals(this.config.get("dryRun"));
        this.allowlist = buildAllowlist();
        this.blocklist = buildBlocklist();

        if (Boolean.TRUE.equals(this.config.get("reset"))) {
            resetStore();
        }

        // Bind Ed25519 keys if passed via config
        if (this.config.containsKey("ed25519_private_key")) {
            System.setProperty("ED25519_PRIVATE_KEY", (String) this.config.get("ed25519_private_key"));
        }
        if (this.config.containsKey("ed25519_public_key")) {
            System.setProperty("ED25519_PUBLIC_KEY", (String) this.config.get("ed25519_public_key"));
        }

        // Auto-generate Ed25519 key pair on load if indicated and keys are not set
        boolean useAsymmetric = Boolean.TRUE.equals(this.config.get("useAsymmetricTickets")) 
                || "auto".equals(this.config.get("ed25519"));
        String envPrivate = System.getenv("ED25519_PRIVATE_KEY");
        String propPrivate = System.getProperty("ED25519_PRIVATE_KEY");
        if (useAsymmetric && (envPrivate == null || envPrivate.isEmpty()) && (propPrivate == null || propPrivate.isEmpty())) {
            // Chemin vers le fichier de clés persistant
            java.io.File configDir = new java.io.File("config");
            java.io.File keyFile = new java.io.File(configDir, "ed25519_key.json");

            // Tenter de charger les clés existantes
            if (keyFile.exists()) {
                try {
                    String content = java.nio.file.Files.readString(keyFile.toPath());
                    String priv = extractJsonValue(content, "privateKey");
                    String pub = extractJsonValue(content, "publicKey");
                    if (priv != null && pub != null) {
                        System.setProperty("ED25519_PRIVATE_KEY", priv);
                        System.setProperty("ED25519_PUBLIC_KEY", pub);
                        if (verbose) {
                            System.out.println("[Fingerprint] Persistent Ed25519 keys loaded from disk.");
                        }
                    }
                } catch (Exception e) {
                    if (verbose) {
                        System.err.println("[Fingerprint] Failed to load persistent Ed25519 keys: " + e.getMessage());
                    }
                }
            } else {
                // Si le fichier n'existe pas, générer de nouvelles clés et les sauvegarder
                try {
                    java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance("Ed25519");
                    java.security.KeyPair kp = kpg.generateKeyPair();
                    String privPem = "-----BEGIN PRIVATE KEY-----\n" +
                            Base64.getMimeEncoder().encodeToString(kp.getPrivate().getEncoded()) +
                            "\n-----END PRIVATE KEY-----";
                    String pubPem = "-----BEGIN PUBLIC KEY-----\n" +
                            Base64.getMimeEncoder().encodeToString(kp.getPublic().getEncoded()) +
                            "\n-----END PUBLIC KEY-----";
                    System.setProperty("ED25519_PRIVATE_KEY", privPem);
                    System.setProperty("ED25519_PUBLIC_KEY", pubPem);
                    if (!configDir.exists()) {
                        configDir.mkdirs(); // Créer le répertoire 'config' si nécessaire
                    }
                    String json = "{\n  \"privateKey\": \"" + privPem.replace("\n", "\\n") + "\",\n  \"publicKey\": \"" + pubPem.replace("\n", "\\n") + "\"\n}";
                    java.nio.file.Files.writeString(keyFile.toPath(), json);
                    if (verbose) {
                        System.out.println("[Fingerprint] New persistent Ed25519 keys generated and saved to disk.");
                    }
                } catch (Exception e) {
                    if (verbose) {
                        System.err.println("[Fingerprint] Native Ed25519 key generation failed: " + e.getMessage());
                    }
                }
            }
        }
    }

    // Helper method to extract JSON values without external libraries
    private String extractJsonValue(String json, String key) {
        String search = "\"" + key + "\": \"";
        int start = json.indexOf(search);
        if (start == -1) return null;
        start += search.length();
        int end = json.indexOf("\"", start);
        if (end == -1) return null;
        return json.substring(start, end).replace("\\n", "\n");
    }

    public Map<String, Object> getThresholds() {
        return thresholds;
    }

    public Map<String, Object> getWeights() {
        return weights;
    }

    @SuppressWarnings("unchecked")
    public synchronized void updateConfig(Map<String, Object> newConfig) {
        if (newConfig == null) return;
        Map<String, Object> merged = SecurityProfiles.deepMerge(this.config, newConfig);
        this.config.clear();
        this.config.putAll(merged);

        Object newThresholds = this.config.get("thresholds");
        if (newThresholds instanceof Map) {
            this.thresholds.clear();
            this.thresholds.putAll((Map<String, Object>) newThresholds);
        }
        Object newWeights = this.config.get("weights");
        if (newWeights instanceof Map) {
            this.weights.clear();
            this.weights.putAll((Map<String, Object>) newWeights);
        }
    }

    /**
     * Réinitialise le store de persistance actif.
     */
    public void resetStore() {
        if (store != null) {
            try {
                store.clear();
            } catch (Exception e) {
                if (verbose) {
                    System.err.println("[FingerprintEngine] Failed to clear store: " + e.getMessage());
                }
            }
        }

            // Initialize ProblemManager if useful work is enabled
            if (Boolean.TRUE.equals(this.config.get("enableUsefulWork"))) {
                String usefulWorkConfigPath = (String) this.config.get("usefulWorkConfigPath");
                // Ensure ProblemManager is initialized with the correct path and store
                this.problemManager = ProblemManager.getInstance(usefulWorkConfigPath, store);
            }
    }

    private Map<String, Object> createDefaultThresholds() {
        Map<String, Object> map = new HashMap<>();
        map.put("low", 20);
        map.put("medium", 45);
        map.put("high", 75);
        map.put("block", 95);
        return map;
    }

    private Map<String, Object> createDefaultWeights() {
        Map<String, Object> map = new HashMap<>();
        map.put("historyScore", 0.3);
        map.put("rotationScore", 0.5);
        map.put("headerAnomalyScore", 0.1);
        map.put("requestPatternScore", 0.6);
        map.put("inconsistencyScore", 0.8);
        map.put("behaviorScore", 0.7);
        map.put("honeypotScore", 1.0);
        map.put("crossLayerInconsistencyScore", 0.4);
        map.put("timeInconsistencyScore", 0.9);
        map.put("tlsSpoofingScore", 0.8);
        map.put("botScore", 1.0);
        map.put("cookieDroppingScore", 0.9);
        map.put("threatIntelScore", 0.4);
        map.put("clientHintsInconsistencyScore", 0.7);
        map.put("clickVarianceScore", 0.6);
        map.put("subnetScore", 0.5);
        map.put("botnetClusterScore", 0.6);
        map.put("tcpAnomalyScore", 0.8);
        map.put("quicAnomalyScore", 0.8);
        map.put("renderingAnomalyScore", 0.8);
        map.put("ipReputationScore", 0.5);
        return map;
    }

    @SuppressWarnings("unchecked")
    private BlockList buildBlocklist() {
        BlockList bl = new BlockList();
        List<Map<String, Object>> whitelistRules = (List<Map<String, Object>>) config.get("whitelist");
        if (whitelistRules != null) {
            for (Map<String, Object> rule : whitelistRules) {
                if ("blocklist".equals(rule.get("type")) || "ip_blocklist".equals(rule.get("type"))) {
                    List<String> entries = (List<String>) rule.get("entries");
                    if (entries != null) {
                        for (String entry : entries) {
                            bl.add(entry);
                        }
                    }
                }
            }
        }
        List<Map<String, Object>> blacklistRules = (List<Map<String, Object>>) config.get("blacklist");
        if (blacklistRules != null) {
            for (Map<String, Object> rule : blacklistRules) {
                if ("blocklist".equals(rule.get("type")) || "ip_blocklist".equals(rule.get("type"))) {
                    List<String> entries = (List<String>) rule.get("entries");
                    if (entries != null) {
                        for (String entry : entries) {
                            bl.add(entry);
                        }
                    }
                }
            }
        }
        return bl;
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

    @SuppressWarnings("unchecked")
    private boolean isPathInAllowlist(String requestPath) {
        Object whitelistObj = config.get("whitelist");
        if (!(whitelistObj instanceof List)) {
            return false;
        }
        List<?> whitelistRules = (List<?>) whitelistObj;
        for (Object ruleObj : whitelistRules) {
            if (ruleObj instanceof Map) {
                Map<String, Object> rule = (Map<String, Object>) ruleObj;
                if ("path_allowlist".equals(rule.get("type"))) {
                    List<String> entries = (List<String>) rule.get("entries");
                    if (entries != null) {
                        for (String entry : entries) {
                            if (pathMatches(requestPath, entry)) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        return false;
    }

    private boolean pathMatches(String requestPath, String entry) {
        if (entry.endsWith("*")) {
            String base = entry.substring(0, entry.length() - 1);
            return requestPath.startsWith(base);
        } else {
            return requestPath.equals(entry);
        }
    }

    @SuppressWarnings("unchecked")
    private boolean isUserAgentInAllowlist(String userAgent) {
        if (userAgent == null) {
            return false;
        }
        Object whitelistObj = config.get("whitelist");
        if (!(whitelistObj instanceof List)) {
            return false;
        }
        List<?> whitelistRules = (List<?>) whitelistObj;
        for (Object ruleObj : whitelistRules) {
            if (ruleObj instanceof Map) {
                Map<String, Object> rule = (Map<String, Object>) ruleObj;
                String type = (String) rule.get("type");
                if ("user_agent_allowlist".equals(type) || "user_agent".equals(type)) {
                    List<String> entries = (List<String>) rule.get("entries");
                    if (entries != null) {
                        for (String entry : entries) {
                            try {
                                if (userAgent.equals(entry) || userAgent.contains(entry) || java.util.regex.Pattern.compile(entry).matcher(userAgent).find()) {
                                    return true;
                                }
                            } catch (Exception e) {
                                if (userAgent.contains(entry)) {
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
        return false;
    }

    private boolean hasCertainAttack(RequestContext context) {
        Map<String, Object> honeypotConfig = (Map<String, Object>) config.getOrDefault("honeypot", new HashMap<String, Object>());
        double honeypotScore = RequestUtils.getHoneypotScore(context, honeypotConfig).getOrDefault("honeypotScore", 0.0);
        if (honeypotScore >= 100.0) {
            return true;
        }
        double botScore = RequestUtils.getBotScore(context).getOrDefault("botScore", 0.0);
        if (botScore >= 100.0) {
            return true;
        }
        return false;
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
        if (context.resolvedIdentity != null) {
            return context.resolvedIdentity;
        }
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
        context.resolvedIdentity = result;
        return result;
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> processRequest(RequestContext context) {
        Map<String, Double> suspicionVector = new HashMap<>();

        // Check blocklist
        if (blocklist.check(context.clientIp)) {
            Map<String, Object> res = new HashMap<>();
            res.put("action", "block");
            res.put("status", 403);
            res.put("body", "Forbidden");
            res.put("score", 1.0);
            Map<String, Double> vec = new HashMap<>();
            vec.put("blocklisted", 1.0);
            res.put("vector", vec);
            return res;
        }

        String coopOp = null;
        Object rawCoopOp = context.queryParams.get("coop_op");
        if (rawCoopOp instanceof String) {
            coopOp = (String) rawCoopOp;
        } else if (rawCoopOp instanceof List && !((List<?>) rawCoopOp).isEmpty()) {
            coopOp = ((List<?>) rawCoopOp).get(0).toString();
        }

        if (coopOp != null) {
            Map<String, String> stringParams = new HashMap<>();
            context.queryParams.forEach((k, v) -> {
                if (v instanceof String) {
                    stringParams.put(k, (String) v);
                } else if (v instanceof List && !((List<?>) v).isEmpty()) {
                    stringParams.put(k, ((List<?>) v).get(0).toString());
                } else if (v != null) {
                    stringParams.put(k, v.toString());
                }
            });
            if (context.body != null) {
                context.body.forEach((k, v) -> {
                    if (v instanceof String) {
                        stringParams.put(k, (String) v);
                    } else if (v instanceof List && !((List<?>) v).isEmpty()) {
                        stringParams.put(k, ((List<?>) v).get(0).toString());
                    } else if (v != null) {
                        stringParams.put(k, v.toString());
                    }
                });
            }
            if (!stringParams.containsKey("signature") && context.getHeader("x-federation-signature") != null) {
                stringParams.put("signature", context.getHeader("x-federation-signature"));
            }
            if (!stringParams.containsKey("signature_ed25519") && context.getHeader("x-federation-signature-ed25519") != null) {
                stringParams.put("signature_ed25519", context.getHeader("x-federation-signature-ed25519"));
            }
            if (!stringParams.containsKey("timestamp") && context.getHeader("x-federation-timestamp") != null) {
                stringParams.put("timestamp", context.getHeader("x-federation-timestamp"));
            }
            Map<String, Object> result = ChallengeUtils.handleCooperativeRequest(stringParams, context.clientIp, config);
            Map<String, Object> res = new HashMap<>();
            res.put("action", "challenge");
            res.put("status", 200);
            res.put("body", result);
            return res;
        }
        
        // --- Interception et vérification des challenges Useful Work (uPoW) ---
        Object rawPowNonce = context.queryParams.get("pow_nonce");
        String powNonce = rawPowNonce instanceof String ? (String) rawPowNonce : null;
        Object rawPowType = context.queryParams.get("pow_type");
        String powType = rawPowType instanceof String ? (String) rawPowType : null;
        Object rawPowSolutionWorkResult = context.queryParams.get("pow_solution_work_result");
        String powSolutionWorkResult = rawPowSolutionWorkResult instanceof String ? (String) rawPowSolutionWorkResult : null;
        Object rawPowProblemId = context.queryParams.get("pow_problem_id");
        String powProblemId = rawPowProblemId instanceof String ? (String) rawPowProblemId : null;
        

        if (powNonce != null && "useful_work_task".equals(powType) && powSolutionWorkResult != null && powProblemId != null) {
            Object challengeContextObj = store.get("secret:" + powNonce);
            if (challengeContextObj instanceof Map) {
                try {
                    Map<String, Object> workResult = ChallengeUtils.simpleJsonParse(powSolutionWorkResult);
                    store.delete("secret:" + powNonce);
                    if (problemManager != null) {
                        problemManager.integrateSolution(powProblemId, workResult);

                        Map<String, Object> autotuningConfig = (Map<String, Object>) config.get("autotuning");
                        boolean autotuningEnabled = autotuningConfig != null && Boolean.TRUE.equals(autotuningConfig.get("enabled"));
                        
                        if ("security_auto_tuning".equals(powProblemId) && autotuningEnabled) {
                            Object paretoFrontObj = workResult.get("paretoFront");
                            if (paretoFrontObj instanceof List) {
                                List<Map<String, Object>> paretoFront = (List<Map<String, Object>>) paretoFrontObj;
                                if (!paretoFront.isEmpty()) {
                                    Map<String, Object> bestSolution = paretoFront.get(0);
                                    List<Object> objs0 = (List<Object>) bestSolution.get("objectives");
                                    double minDistance = Math.sqrt(
                                        Math.pow(Double.parseDouble(objs0.get(0).toString()), 2) + 
                                        Math.pow(Double.parseDouble(objs0.get(1).toString()), 2)
                                    );
                                    
                                    for (int i = 1; i < paretoFront.size(); i++) {
                                        Map<String, Object> item = paretoFront.get(i);
                                        List<Object> objsI = (List<Object>) item.get("objectives");
                                        double distance = Math.sqrt(
                                            Math.pow(Double.parseDouble(objsI.get(0).toString()), 2) + 
                                            Math.pow(Double.parseDouble(objsI.get(1).toString()), 2)
                                        );
                                        if (distance < minDistance) {
                                            minDistance = distance;
                                            bestSolution = item;
                                        }
                                    }
                                    
                                    if (bestSolution.containsKey("solution")) {
                                        updateConfig((Map<String, Object>) bestSolution.get("solution"));
                                        System.out.println("[FingerprintEngine] Useful Work auto-tuning applied successfully to live config.");
                                    }
                                }
                            }
                        }
                    }

                    String ticket = UUID.randomUUID().toString();
                    Map<String, Object> ticketData = new HashMap<>();
                    ticketData.put("ip", context.clientIp);
                    Map<String, Object> identity = resolveRequestIdentity(context, suspicionVector);
                    ticketData.put("deviceId", (String) identity.get("deviceId"));
                    store.set("ticket:" + ticket, ticketData, 3600);

                    Map<String, Object> redirectRes = new HashMap<>();
                    redirectRes.put("action", "redirect");
                    redirectRes.put("path", context.path);
                    return redirectRes;
                } catch (Exception e) {
                    if (verbose) {
                        System.err.println("[FingerprintEngine] Error processing useful work solution: " + e.getMessage());
                    }
                }
            }
        }

        // Check allowlists
        boolean whitelisted = allowlist.check(context.clientIp) || isPathInAllowlist(context.path) || isUserAgentInAllowlist(context.getHeader("user-agent"));
        if (whitelisted) {
            Object filterWhitelistObj = config.get("filterWhitelist");
            boolean bypassWhitelist = false;

            if (filterWhitelistObj instanceof Boolean) {
                if (Boolean.TRUE.equals(filterWhitelistObj) && hasCertainAttack(context)) {
                    bypassWhitelist = true;
                    if (verbose) {
                        System.out.println("[FingerprintEngine] Whitelisted request contains a certain attack - bypassing whitelist bypass");
                    }
                }
            } else if (filterWhitelistObj instanceof Number) {
                double maxIgnoredScore = ((Number) filterWhitelistObj).doubleValue();
                double calculatedScore = calculateScoreAndVector(context, suspicionVector);
                if (calculatedScore > maxIgnoredScore) {
                    bypassWhitelist = true;
                    if (verbose) {
                        System.out.println("[FingerprintEngine] Whitelisted request score (" + calculatedScore + ") exceeds filterWhitelist threshold (" + maxIgnoredScore + ") - bypassing whitelist");
                    }
                }
            }

            if (!bypassWhitelist) {
                Map<String, Object> res = new HashMap<>();
                res.put("action", "allow");
                res.put("score", 0.0);
                Map<String, Double> vec = new HashMap<>();
                vec.put("whitelisted", 100.0);
                res.put("vector", vec);
                return res;
            }
        }

        double finalScore = calculateScoreAndVector(context, suspicionVector);

        Map<String, Object> identity = resolveRequestIdentity(context, suspicionVector);
        String deviceId = (String) identity.get("deviceId");
        Map<String, Object> deviceData = (Map<String, Object>) identity.get("deviceData");
        Map<String, Object> newCookie = (Map<String, Object>) identity.get("newCookie");
            String currentDeviceHash = (String) identity.get("currentDeviceHash");

            // Ticket validation
            boolean hasValidTicket = false;
            String powCookie = context.cookies.get("pow_clearance");
            String zkpProof = context.getHeader("x-zkp-proof");
            if (zkpProof == null || zkpProof.isEmpty()) {
                Object rawZkp = context.queryParams.get("pow_zkp");
                if (rawZkp instanceof String) {
                    zkpProof = (String) rawZkp;
                } else if (rawZkp instanceof List && !((List<?>) rawZkp).isEmpty()) {
                    zkpProof = ((List<?>) rawZkp).get(0).toString();
                }
            }
            boolean allowRoaming = Boolean.TRUE.equals(config.get("allowCrossNetworkRoaming"));
            String powSecret = (String) config.getOrDefault("powSecret", ChallengeUtils.getPowSecret());
            if (powCookie != null) {
                hasValidTicket = ChallengeUtils.isTicketValid(context.clientIp, powCookie, deviceId, currentDeviceHash, powSecret, allowRoaming, store, zkpProof);
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

        // Update subnet metrics
        int mediumThreshold = ((Number) thresholds.getOrDefault("medium", 45)).intValue();
        int highThreshold = ((Number) thresholds.getOrDefault("high", 75)).intValue();
        int blockThreshold = ((Number) thresholds.getOrDefault("block", 95)).intValue();
        if (finalScore >= mediumThreshold && finalScore < blockThreshold) {
            RequestUtils.updateSubnetMetrics(store, context, deviceId, finalScore);
        }

            boolean mustReChallenge = finalScore >= mediumThreshold && hasValidTicket && finalScore > 0 && finalScore < blockThreshold;

            if (hasValidTicket && !mustReChallenge) {
                int deviceTtl = 2592000; // 30 jours par défaut en secondes
                if (config.containsKey("deviceIdCookieMaxAge")) {
                    deviceTtl = (int) (((Number) config.get("deviceIdCookieMaxAge")).longValue() / 1000);
                }
                store.set("device:" + deviceId, deviceData, deviceTtl);
                recordTrafficLog(context, finalScore, suspicionVector);

                Map<String, Object> response = new HashMap<>();
                response.put("score", 0.0);
                response.put("vector", suspicionVector);
                response.put("action", "next");
                if (newCookie != null) {
                    response.put("cookie", newCookie);
                }
                return response;
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


        String action = "next";
        if (finalScore >= blockThreshold) {
            action = "block";
            } else if (finalScore >= highThreshold || mustReChallenge) {
            action = "challenge";
        } else if (finalScore >= mediumThreshold) {
            action = "flag";
        }

        response.put("action", action);
        if ("block".equals(action)) {
            response.put("status", 403);
            response.put("body", "Forbidden");

            // Federated Threat Intelligence & ZKP Synchronization
            String zkpProof2 = context.getHeader("x-zkp-proof");
            if (zkpProof2 == null || zkpProof2.isEmpty()) {
                Object rawZkp = context.queryParams.get("pow_zkp");
                if (rawZkp instanceof String) {
                    zkpProof2 = (String) rawZkp;
                } else if (rawZkp instanceof List && !((List<?>) rawZkp).isEmpty()) {
                    zkpProof2 = ((List<?>) rawZkp).get(0).toString();
                }
            }
            if (zkpProof2 != null && !zkpProof2.isEmpty()) {
                String[] parts = zkpProof2.split(":");
                if (parts.length == 3) {
                    String zkpY = parts[0];
                    String zkpT = parts[1];
                    String zkpS = parts[2];
                    // 1. Valider cryptographiquement la preuve avant de bannir/diffuser
                    if (ChallengeUtils.verifyZkpProof(zkpY, zkpT, zkpS)) {
                        // 2. Dédoublonner : Ne diffuser que si la clé n'est pas déjà bannie
                        if (!store.has("banned-zkp-y:" + zkpY)) {
                            store.set("banned-zkp-y:" + zkpY, true, 86400 * 30);
                            broadcastBannedZkp(zkpY);
                        }
                    }
                }
            }
        } else if ("challenge".equals(action)) {
            response.put("status", 403);
            String nonce = UUID.randomUUID().toString().replace("-", "");
            String clientSecret = UUID.randomUUID().toString().replace("-", "");

            int lowThreshold = ((Number) thresholds.getOrDefault("low", 20)).intValue();

            double denominator = highThreshold - lowThreshold;
            double suspicionFactor = denominator == 0 ? 0.0 : (finalScore - lowThreshold) / denominator;
            suspicionFactor = Math.max(0.0, Math.min(1.5, suspicionFactor));

            int memDifficulty = (int) Math.round(suspicionFactor * 48);

            String originalFingerprint = RequestUtils.getCompositeDeviceHash(context);
            String baseBlock = ChallengeUtils.createCpuChallengeBaseBlock(nonce, clientSecret, originalFingerprint);

            Map<String, Object> cpuChallengeDetails = new HashMap<>();
            cpuChallengeDetails.put("nonce", nonce);
            cpuChallengeDetails.put("target", ChallengeUtils.calculateCpuTarget(suspicionFactor, config));
            cpuChallengeDetails.put("path", context.path);

            Map<String, Object> challengeContext = new HashMap<>();
            challengeContext.put("clientSecret", clientSecret);
            challengeContext.put("cpuTarget", cpuChallengeDetails.get("target"));
            challengeContext.put("suspicionScore", finalScore);
            challengeContext.put("fingerprint", originalFingerprint);
            challengeContext.put("memDifficulty", memDifficulty);
            challengeContext.put("baseBlock", baseBlock);
            challengeContext.put("originalPath", context.path);

            int challengeTtl = ((Number) config.getOrDefault("challengeTtl", 300)).intValue();
            store.set("secret:" + nonce, challengeContext, challengeTtl);

            if (deviceData != null) {
                deviceData.put("lastChallengeNonce", nonce);
                store.set("device:" + deviceId, deviceData, deviceTtl);
            }

            List<String> trapUrls = Arrays.asList(
                ChallengeUtils.generateTrapUrl(nonce),
                ChallengeUtils.generateTrapUrl(nonce)
            );

            String pageBody = ChallengeUtils.generateCombinedPoWChallengePage(
                cpuChallengeDetails,
                memDifficulty,
                clientSecret,
                config,
                trapUrls,
                originalFingerprint
            );
            response.put("body", pageBody);
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
    private void broadcastBannedZkp(String zkpY) {
        List<String> peers = (List<String>) config.get("federatedPeers");
        if (peers == null || peers.isEmpty()) return;

        long timestamp = System.currentTimeMillis();
        String msg = timestamp + ":" + zkpY;
        
        String signature = "";
        boolean isAsymmetric = false;
        
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
                
                java.security.Signature sig = java.security.Signature.getInstance("Ed25519");
                sig.initSign(privateKey);
                sig.update(msg.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                signature = HexFormat.of().formatHex(sig.sign());
                isAsymmetric = true;
            } catch (Exception e) {
                if (verbose) {
                    System.err.println("[Fingerprint] Asymmetric broadcast signing failed: " + e.getMessage());
                }
            }
        }

        if (!isAsymmetric) {
            String secret = (String) config.get("federationSecret");
            if (secret == null) {
                secret = ChallengeUtils.getPowSecret();
            }
            signature = RequestUtils.hmacSha256(msg, secret);
        }

        for (String peerUrl : peers) {
            asyncPost(peerUrl + "?coop_op=share_threat_intel", zkpY, isAsymmetric ? "" : signature, isAsymmetric ? signature : "", timestamp);
        }
    }

    private void asyncPost(String urlStr, String zkpY, String signature, String signatureEd25519, long timestamp) {
        new Thread(() -> {
            try {
                java.net.URL url = new java.net.URL(urlStr);
                java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("X-Federation-Signature", signature);
                conn.setRequestProperty("X-Federation-Signature-Ed25519", signatureEd25519);
                conn.setRequestProperty("X-Federation-Timestamp", String.valueOf(timestamp));
                conn.setDoOutput(true);
                conn.setConnectTimeout(500);
                conn.setReadTimeout(500);
                String json = "{\"zkpY\":\"" + zkpY + "\"}";
                try (java.io.OutputStream os = conn.getOutputStream()) {
                    os.write(json.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                }
                conn.getResponseCode();
                conn.disconnect();
            } catch (Exception e) {
                // Échec silencieux
            }
        }).start();
    }
    
    @SuppressWarnings("unchecked")
    private double calculateScoreAndVector(RequestContext context, Map<String, Double> suspicionVector) {
        if (context.preCalculatedScore != null) {
            if (context.preCalculatedVector != null) {
                suspicionVector.putAll(context.preCalculatedVector);
            }
            return context.preCalculatedScore;
        }

        Map<String, Object> identity = resolveRequestIdentity(context, suspicionVector);
        String deviceId = (String) identity.get("deviceId");
        Map<String, Object> deviceData = (Map<String, Object>) identity.get("deviceData");
        String currentDeviceHash = (String) identity.get("currentDeviceHash");

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
            suspicionVector.put("webauthn_verified", 100.0);
            context.preCalculatedScore = 0.0;
            context.preCalculatedVector = new HashMap<>(suspicionVector);
            return 0.0;
        }

        if (deviceData != null && Boolean.TRUE.equals(deviceData.get("condemned"))) {
            suspicionVector.put("honeypotScore", 100.0);
            context.preCalculatedScore = 100.0;
            context.preCalculatedVector = new HashMap<>(suspicionVector);
            return 100.0;
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
        double botnetClusterScore = RequestUtils.getBotnetClusterScore(store, context, stableFpHash).getOrDefault("botnetClusterScore", 0.0);

        double tcpAnomalyScore = RequestUtils.getTcpAnomalyScore(context).getOrDefault("tcpAnomalyScore", 0.0);
        double protocolAnomalyScore = RequestUtils.getProtocolAnomalyScore(context).getOrDefault("protocolAnomalyScore", 0.0);
        double renderingAnomalyScore = RequestUtils.getRenderingAnomalyScore(context).getOrDefault("renderingAnomalyScore", 0.0);
        double ipReputationScore = RequestUtils.getIpReputationScore(store, context.clientIp);
        double threatIntelScore = RequestUtils.getThreatIntelScore(store, context.zkpY).getOrDefault("threatIntelScore", 0.0);

        suspicionVector.put("threatIntelScore", threatIntelScore);
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
        suspicionVector.put("protocolAnomalyScore", protocolAnomalyScore);
        suspicionVector.put("renderingAnomalyScore", renderingAnomalyScore);
        suspicionVector.put("ipReputationScore", ipReputationScore);

        double finalScore = calculateFinalScore(suspicionVector);

        context.preCalculatedScore = finalScore;
        context.preCalculatedVector = new HashMap<>(suspicionVector);

        return finalScore;
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