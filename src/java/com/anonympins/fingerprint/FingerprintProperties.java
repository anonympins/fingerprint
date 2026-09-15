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
    private Map<String, Object> thresholds = new HashMap<>();
    private Map<String, Object> weights = new HashMap<>();
    private Map<String, Object> honeypot = new HashMap<>();
    private Map<String, Object> cpu = new HashMap<>();
    private boolean challengeNewDevices = false;
    private int challengeTtl = 300;
    private long deviceIdCookieMaxAge = 2592000000L; // 30 jours par défaut
    private boolean verbose = false;
    private boolean dryRun = false;
    private double similarityThreshold = 0.7;
    private Map<String, Object> patterns = new HashMap<>();
    private String challengePagePath;
    private boolean enableUsefulWork = false;
    private String usefulWorkConfigPath;
    private Map<String, Object> usefulWorkConfig = new HashMap<>();
    private boolean enableProofOfSpace = false;
    private Map<String, Object> pospace = new HashMap<>();
    private Map<String, Object> autotuning = new HashMap<>();
    private List<Map<String, Object>> whitelist = new ArrayList<>();
    private boolean allowCrossNetworkRoaming = false;

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Map<String, Object> getThresholds() {
        return thresholds;
    }

    public void setThresholds(Map<String, Object> thresholds) {
        this.thresholds = thresholds;
    }

    public Map<String, Object> getWeights() {
        return weights;
    }

    public void setWeights(Map<String, Object> weights) {
        this.weights = weights;
    }

    public Map<String, Object> getHoneypot() {
        return honeypot;
    }

    public void setHoneypot(Map<String, Object> honeypot) {
        this.honeypot = honeypot;
    }

    public Map<String, Object> getCpu() {
        return cpu;
    }

    public void setCpu(Map<String, Object> cpu) {
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

    public Map<String, Object> getPatterns() {
        return patterns;
    }

    public void setPatterns(Map<String, Object> patterns) {
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

    public Map<String, Object> getPospace() {
        return pospace;
    }

    public void setPospace(Map<String, Object> pospace) {
        this.pospace = pospace;
    }

    public Map<String, Object> getAutotuning() {
        return autotuning;
    }

    public void setAutotuning(Map<String, Object> autotuning) {
        this.autotuning = autotuning;
    }

    public List<Map<String, Object>> getWhitelist() {
        return whitelist;
    }

    public void setWhitelist(List<Map<String, Object>> whitelist) {
        this.whitelist = whitelist;
    }

    public boolean isAllowCrossNetworkRoaming() {
        return allowCrossNetworkRoaming;
    }

    public void setAllowCrossNetworkRoaming(boolean allowCrossNetworkRoaming) {
        this.allowCrossNetworkRoaming = allowCrossNetworkRoaming;
    }
}