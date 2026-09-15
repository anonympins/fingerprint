package com.anonympins.fingerprint;

import org.springframework.boot.context.properties.ConfigurationProperties;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Propriétés de configuration pour l'engine Fingerprint.
 */
@ConfigurationProperties(prefix = "fingerprint")
public class FingerprintProperties {
    private boolean enabled = false;
    private Thresholds thresholds = new Thresholds();
    private Weights weights = new Weights();
    private Honeypot honeypot = new Honeypot();
    private Cpu cpu = new Cpu();
    private boolean challengeNewDevices = false;
    private int challengeTtl = 300;
    private long deviceIdCookieMaxAge = 2592000000L; // 30 jours par défaut
    private boolean verbose = false;
    private boolean dryRun = false;
    private double similarityThreshold = 0.7;
    private Patterns patterns = new Patterns();
    private String challengePagePath;
    private boolean enableUsefulWork = false;
    private String usefulWorkConfigPath;
    private Map<String, Object> usefulWorkConfig = new HashMap<>();
    private boolean enableProofOfSpace = false;
    private Pospace pospace = new Pospace();
    private Autotuning autotuning = new Autotuning();
    private List<WhitelistRule> whitelist = new ArrayList<>();
    private boolean allowCrossNetworkRoaming = false;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Thresholds getThresholds() {
        return thresholds;
    }

    public void setThresholds(Thresholds thresholds) {
        this.thresholds = thresholds;
    }

    public Weights getWeights() {
        return weights;
    }

    public void setWeights(Weights weights) {
        this.weights = weights;
    }

    public Honeypot getHoneypot() {
        return honeypot;
    }

    public void setHoneypot(Honeypot honeypot) {
        this.honeypot = honeypot;
    }

    public Cpu getCpu() {
        return cpu;
    }

    public void setCpu(Cpu cpu) {
        this.cpu = cpu;
    }

    public boolean isChallengeNewDevices() {
        return challengeNewDevices;
    }

    public void setChallengeNewDevices(boolean challengeNewDevices) {
        this.challengeNewDevices = challengeNewDevices;
    }

    public int getChallengeTtl() {
        return challengeTtl;
    }

    public void setChallengeTtl(int challengeTtl) {
        this.challengeTtl = challengeTtl;
    }

    public long getDeviceIdCookieMaxAge() {
        return deviceIdCookieMaxAge;
    }

    public void setDeviceIdCookieMaxAge(long deviceIdCookieMaxAge) {
        this.deviceIdCookieMaxAge = deviceIdCookieMaxAge;
    }

    public boolean isVerbose() {
        return verbose;
    }

    public void setVerbose(boolean verbose) {
        this.verbose = verbose;
    }

    public boolean isDryRun() {
        return dryRun;
    }

    public void setDryRun(boolean dryRun) {
        this.dryRun = dryRun;
    }

    public double getSimilarityThreshold() {
        return similarityThreshold;
    }

    public void setSimilarityThreshold(double similarityThreshold) {
        this.similarityThreshold = similarityThreshold;
    }

    public Patterns getPatterns() {
        return patterns;
    }

    public void setPatterns(Patterns patterns) {
        this.patterns = patterns;
    }

    public String getChallengePagePath() {
        return challengePagePath;
    }

    public void setChallengePagePath(String challengePagePath) {
        this.challengePagePath = challengePagePath;
    }

    public boolean isEnableUsefulWork() {
        return enableUsefulWork;
    }

    public void setEnableUsefulWork(boolean enableUsefulWork) {
        this.enableUsefulWork = enableUsefulWork;
    }

    public String getUsefulWorkConfigPath() {
        return usefulWorkConfigPath;
    }

    public void setUsefulWorkConfigPath(String usefulWorkConfigPath) {
        this.usefulWorkConfigPath = usefulWorkConfigPath;
    }

    public Map<String, Object> getUsefulWorkConfig() {
        return usefulWorkConfig;
    }

    public void setUsefulWorkConfig(Map<String, Object> usefulWorkConfig) {
        this.usefulWorkConfig = usefulWorkConfig;
    }

    public boolean isEnableProofOfSpace() {
        return enableProofOfSpace;
    }

    public void setEnableProofOfSpace(boolean enableProofOfSpace) {
        this.enableProofOfSpace = enableProofOfSpace;
    }

    public Pospace getPospace() {
        return pospace;
    }

    public void setPospace(Pospace pospace) {
        this.pospace = pospace;
    }

    public Autotuning getAutotuning() {
        return autotuning;
    }

    public void setAutotuning(Autotuning autotuning) {
        this.autotuning = autotuning;
    }

    public List<WhitelistRule> getWhitelist() {
        return whitelist;
    }

    public void setWhitelist(List<WhitelistRule> whitelist) {
        this.whitelist = whitelist;
    }

    public boolean isAllowCrossNetworkRoaming() {
        return allowCrossNetworkRoaming;
    }

    public void setAllowCrossNetworkRoaming(boolean allowCrossNetworkRoaming) {
        this.allowCrossNetworkRoaming = allowCrossNetworkRoaming;
    }


    // --- SOUS-CLASSES DE PROPRIETES TYPÉES ---

    public static class Thresholds {
        private int low = 20;
        private int medium = 45;
        private int high = 75;
        private int block = 95;

        public int getLow() { return low; }
        public void setLow(int low) { this.low = low; }
        public int getMedium() { return medium; }
        public void setMedium(int medium) { this.medium = medium; }
        public int getHigh() { return high; }
        public void setHigh(int high) { this.high = high; }
        public int getBlock() { return block; }
        public void setBlock(int block) { this.block = block; }

        public Map<String, Object> toMap() {
            Map<String, Object> map = new HashMap<>();
            map.put("low", low);
            map.put("medium", medium);
            map.put("high", high);
            map.put("block", block);
            return map;
        }
    }

    public static class Weights {
        private double historyScore = 0.3;
        private double rotationScore = 0.5;
        private double headerAnomalyScore = 0.1;
        private double requestPatternScore = 0.6;
        private double inconsistencyScore = 0.8;
        private double behaviorScore = 0.7;
        private double honeypotScore = 1.0;
        private double crossLayerInconsistencyScore = 0.4;
        private double timeInconsistencyScore = 0.9;
        private double tlsSpoofingScore = 0.8;
        private double botScore = 1.0;
        private double cookieDroppingScore = 0.9;
        private double threatIntelScore = 0.4;
        private double clientHintsInconsistencyScore = 0.7;
        private double clickVarianceScore = 0.6;
        private double subnetScore = 0.5;
        private double botnetClusterScore = 0.6;
        private double tcpAnomalyScore = 0.8;
        private double quicAnomalyScore = 0.8;
        private double renderingAnomalyScore = 0.8;
        private double ipReputationScore = 0.5;

        public double getHistoryScore() { return historyScore; }
        public void setHistoryScore(double historyScore) { this.historyScore = historyScore; }
        public double getRotationScore() { return rotationScore; }
        public void setRotationScore(double rotationScore) { this.rotationScore = rotationScore; }
        public double getHeaderAnomalyScore() { return headerAnomalyScore; }
        public void setHeaderAnomalyScore(double headerAnomalyScore) { this.headerAnomalyScore = headerAnomalyScore; }
        public double getRequestPatternScore() { return requestPatternScore; }
        public void setRequestPatternScore(double requestPatternScore) { this.requestPatternScore = requestPatternScore; }
        public double getInconsistencyScore() { return inconsistencyScore; }
        public void setInconsistencyScore(double inconsistencyScore) { this.inconsistencyScore = inconsistencyScore; }
        public double getBehaviorScore() { return behaviorScore; }
        public void setBehaviorScore(double behaviorScore) { this.behaviorScore = behaviorScore; }
        public double getHoneypotScore() { return honeypotScore; }
        public void setHoneypotScore(double honeypotScore) { this.honeypotScore = honeypotScore; }
        public double getCrossLayerInconsistencyScore() { return crossLayerInconsistencyScore; }
        public void setCrossLayerInconsistencyScore(double crossLayerInconsistencyScore) { this.crossLayerInconsistencyScore = crossLayerInconsistencyScore; }
        public double getTimeInconsistencyScore() { return timeInconsistencyScore; }
        public void setTimeInconsistencyScore(double timeInconsistencyScore) { this.timeInconsistencyScore = timeInconsistencyScore; }
        public double getTlsSpoofingScore() { return tlsSpoofingScore; }
        public void setTlsSpoofingScore(double tlsSpoofingScore) { this.tlsSpoofingScore = tlsSpoofingScore; }
        public double getBotScore() { return botScore; }
        public void setBotScore(double botScore) { this.botScore = botScore; }
        public double getCookieDroppingScore() { return cookieDroppingScore; }
        public void setCookieDroppingScore(double cookieDroppingScore) { this.cookieDroppingScore = cookieDroppingScore; }
        public double getClientHintsInconsistencyScore() { return clientHintsInconsistencyScore; }
        public void setClientHintsInconsistencyScore(double clientHintsInconsistencyScore) { this.clientHintsInconsistencyScore = clientHintsInconsistencyScore; }
        public double getClickVarianceScore() { return clickVarianceScore; }
        public void setClickVarianceScore(double clickVarianceScore) { this.clickVarianceScore = clickVarianceScore; }
        public double getSubnetScore() { return subnetScore; }
        public void setSubnetScore(double subnetScore) { this.subnetScore = subnetScore; }
        public double getBotnetClusterScore() { return botnetClusterScore; }
        public void setBotnetClusterScore(double botnetClusterScore) { this.botnetClusterScore = botnetClusterScore; }
        public double getTcpAnomalyScore() { return tcpAnomalyScore; }
        public void setTcpAnomalyScore(double tcpAnomalyScore) { this.tcpAnomalyScore = tcpAnomalyScore; }
        public double getQuicAnomalyScore() { return quicAnomalyScore; }
        public void setQuicAnomalyScore(double quicAnomalyScore) { this.quicAnomalyScore = quicAnomalyScore; }
        public double getRenderingAnomalyScore() { return renderingAnomalyScore; }
        public void setRenderingAnomalyScore(double renderingAnomalyScore) { this.renderingAnomalyScore = renderingAnomalyScore; }
        public double getIpReputationScore() { return ipReputationScore; }
        public void setIpReputationScore(double ipReputationScore) { this.ipReputationScore = ipReputationScore; }
        public double getThreatIntelScore() { return threatIntelScore; }
        public void setThreatIntelScore(double threatIntelScore) { this.threatIntelScore = threatIntelScore; }

        public Map<String, Object> toMap() {
            Map<String, Object> map = new HashMap<>();
            map.put("historyScore", historyScore);
            map.put("rotationScore", rotationScore);
            map.put("headerAnomalyScore", headerAnomalyScore);
            map.put("requestPatternScore", requestPatternScore);
            map.put("inconsistencyScore", inconsistencyScore);
            map.put("behaviorScore", behaviorScore);
            map.put("honeypotScore", honeypotScore);
            map.put("crossLayerInconsistencyScore", crossLayerInconsistencyScore);
            map.put("timeInconsistencyScore", timeInconsistencyScore);
            map.put("tlsSpoofingScore", tlsSpoofingScore);
            map.put("botScore", botScore);
            map.put("cookieDroppingScore", cookieDroppingScore);
            map.put("threatIntelScore", threatIntelScore);
            map.put("clientHintsInconsistencyScore", clientHintsInconsistencyScore);
            map.put("clickVarianceScore", clickVarianceScore);
            map.put("subnetScore", subnetScore);
            map.put("botnetClusterScore", botnetClusterScore);
            map.put("tcpAnomalyScore", tcpAnomalyScore);
            map.put("quicAnomalyScore", quicAnomalyScore);
            map.put("threatIntelScore", threatIntelScore);
            map.put("renderingAnomalyScore", renderingAnomalyScore);
            map.put("ipReputationScore", ipReputationScore);
            return map;
        }
    }

    public static class Honeypot {
        private List<String> fields = new ArrayList<>();
        private List<String> trapUrls = new ArrayList<>();
        private boolean detectInjections = true;

        public List<String> getFields() { return fields; }
        public void setFields(List<String> fields) { this.fields = fields; }
        public List<String> getTrapUrls() { return trapUrls; }
        public void setTrapUrls(List<String> trapUrls) { this.trapUrls = trapUrls; }
        public boolean isDetectInjections() { return detectInjections; }
        public void setDetectInjections(boolean detectInjections) { this.detectInjections = detectInjections; }

        public Map<String, Object> toMap() {
            Map<String, Object> map = new HashMap<>();
            map.put("fields", fields);
            map.put("trapUrls", trapUrls);
            map.put("detectInjections", detectInjections);
            return map;
        }
    }

    public static class Cpu {
        private int minDifficultyBits = 8;
        private int maxDifficultyBits = 22;

        public int getMinDifficultyBits() { return minDifficultyBits; }
        public void setMinDifficultyBits(int minDifficultyBits) { this.minDifficultyBits = minDifficultyBits; }
        public int getMaxDifficultyBits() { return maxDifficultyBits; }
        public void setMaxDifficultyBits(int maxDifficultyBits) { this.maxDifficultyBits = maxDifficultyBits; }

        public Map<String, Object> toMap() {
            Map<String, Object> map = new HashMap<>();
            map.put("minDifficultyBits", minDifficultyBits);
            map.put("maxDifficultyBits", maxDifficultyBits);
            return map;
        }
    }

    public static class Patterns {
        private int velocityThreshold = 800;
        private int burstThreshold = 1500;
        private int scrapeThreshold = 1000;
        private int historySize = 10;
        private int minSamples = 5;
        private int regularityThreshold = 50;
        private double regularityRatio = 0.4;
        private double benfordThreshold = 0.15;
        private double benfordRatio = 0.3;
        private double enumerationRatio = 0.3;
        private int patternWeight = 80;
        private double decayFactor = 0.9;
        private int inactivityReset = 5000;

        public int getVelocityThreshold() { return velocityThreshold; }
        public void setVelocityThreshold(int velocityThreshold) { this.velocityThreshold = velocityThreshold; }
        public int getBurstThreshold() { return burstThreshold; }
        public void setBurstThreshold(int burstThreshold) { this.burstThreshold = burstThreshold; }
        public int getScrapeThreshold() { return scrapeThreshold; }
        public void setScrapeThreshold(int scrapeThreshold) { this.scrapeThreshold = scrapeThreshold; }
        public int getHistorySize() { return historySize; }
        public void setHistorySize(int historySize) { this.historySize = historySize; }
        public int getMinSamples() { return minSamples; }
        public void setMinSamples(int minSamples) { this.minSamples = minSamples; }
        public int getRegularityThreshold() { return regularityThreshold; }
        public void setRegularityThreshold(int regularityThreshold) { this.regularityThreshold = regularityThreshold; }
        public double getRegularityRatio() { return regularityRatio; }
        public void setRegularityRatio(double regularityRatio) { this.regularityRatio = regularityRatio; }
        public double getBenfordThreshold() { return benfordThreshold; }
        public void setBenfordThreshold(double benfordThreshold) { this.benfordThreshold = benfordThreshold; }
        public double getBenfordRatio() { return benfordRatio; }
        public void setBenfordRatio(double benfordRatio) { this.benfordRatio = benfordRatio; }
        public double getEnumerationRatio() { return enumerationRatio; }
        public void setEnumerationRatio(double enumerationRatio) { this.enumerationRatio = enumerationRatio; }
        public int getPatternWeight() { return patternWeight; }
        public void setPatternWeight(int patternWeight) { this.patternWeight = patternWeight; }
        public double getDecayFactor() { return decayFactor; }
        public void setDecayFactor(double decayFactor) { this.decayFactor = decayFactor; }
        public int getInactivityReset() { return inactivityReset; }
        public void setInactivityReset(int inactivityReset) { this.inactivityReset = inactivityReset; }

        public Map<String, Object> toMap() {
            Map<String, Object> map = new HashMap<>();
            map.put("velocityThreshold", velocityThreshold);
            map.put("burstThreshold", burstThreshold);
            map.put("scrapeThreshold", scrapeThreshold);
            map.put("historySize", historySize);
            map.put("minSamples", minSamples);
            map.put("regularityThreshold", regularityThreshold);
            map.put("regularityRatio", regularityRatio);
            map.put("benfordThreshold", benfordThreshold);
            map.put("benfordRatio", benfordRatio);
            map.put("enumerationRatio", enumerationRatio);
            map.put("patternWeight", patternWeight);
            map.put("decayFactor", decayFactor);
            map.put("inactivityReset", inactivityReset);
            return map;
        }
    }

    public static class Pospace {
        private int sizeMb = 100;
        private int numQueries = 10;
        private int coopTimeout = 15;

        public int getSizeMb() { return sizeMb; }
        public void setSizeMb(int sizeMb) { this.sizeMb = sizeMb; }
        public int getNumQueries() { return numQueries; }
        public void setNumQueries(int numQueries) { this.numQueries = numQueries; }
        public int getCoopTimeout() { return coopTimeout; }
        public void setCoopTimeout(int coopTimeout) { this.coopTimeout = coopTimeout; }

        public Map<String, Object> toMap() {
            Map<String, Object> map = new HashMap<>();
            map.put("sizeMb", sizeMb);
            map.put("numQueries", numQueries);
            map.put("coopTimeout", coopTimeout);
            return map;
        }
    }

    public static class Autotuning {
        private boolean enabled = false;
        private int minDataPoints = 200;
        private int maxDataPoints = 10000;
        private double validationTolerance = 0.15;
        private long interval = 30;
        private String savePath;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public int getMinDataPoints() { return minDataPoints; }
        public void setMinDataPoints(int minDataPoints) { this.minDataPoints = minDataPoints; }
        public int getMaxDataPoints() { return maxDataPoints; }
        public void setMaxDataPoints(int maxDataPoints) { this.maxDataPoints = maxDataPoints; }
        public double getValidationTolerance() { return validationTolerance; }
        public void setValidationTolerance(double validationTolerance) { this.validationTolerance = validationTolerance; }
        public long getInterval() { return interval; }
        public void setInterval(long interval) { this.interval = interval; }
        public String getSavePath() { return savePath; }
        public void setSavePath(String savePath) { this.savePath = savePath; }

        public Map<String, Object> toMap() {
            Map<String, Object> map = new HashMap<>();
            map.put("enabled", enabled);
            map.put("minDataPoints", minDataPoints);
            map.put("maxDataPoints", maxDataPoints);
            map.put("validationTolerance", validationTolerance);
            map.put("interval", interval);
            if (savePath != null) map.put("savePath", savePath);
            return map;
        }
    }

    public static class WhitelistRule {
        private String type;
        private List<String> entries = new ArrayList<>();
        private String userAgent;
        private String hostnameSuffix;

        public String getType() { return type; }
        public void setType(String type) { this.type = type; }
        public List<String> getEntries() { return entries; }
        public void setEntries(List<String> entries) { this.entries = entries; }
        public String getUserAgent() { return userAgent; }
        public void setUserAgent(String userAgent) { this.userAgent = userAgent; }
        public String getHostnameSuffix() { return hostnameSuffix; }
        public void setHostnameSuffix(String hostnameSuffix) { this.hostnameSuffix = hostnameSuffix; }

        public Map<String, Object> toMap() {
            Map<String, Object> map = new HashMap<>();
            if (type != null) map.put("type", type);
            if (entries != null) map.put("entries", entries);
            if (userAgent != null) map.put("userAgent", userAgent);
            if (hostnameSuffix != null) map.put("hostnameSuffix", hostnameSuffix);
            return map;
        }
    }
}