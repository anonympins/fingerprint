package com.anonympins.fingerprint;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Décision issue de l'évaluation du jeton PAT.
 */
public final class PatValidationResult {
    private final String action;
    private final double score;
    private final Map<String, Double> vector;
    private final boolean verified;

    public PatValidationResult(String action, double score, Map<String, Double> vector, boolean verified) {
        this.action = action;
        this.score = score;
        this.vector = vector != null ? Collections.unmodifiableMap(new HashMap<>(vector)) : Collections.emptyMap();
        this.verified = verified;
    }

    public static PatValidationResult createBypass() {
        Map<String, Double> vec = new HashMap<>();
        vec.put("pat_verified", 100.0);
        vec.put("privacy_pass", 100.0);
        return new PatValidationResult("next", 0.0, vec, true);
    }

    public static PatValidationResult notApplicable() {
        return new PatValidationResult("next", 0.0, Collections.emptyMap(), false);
    }

    public String getAction() {
        return action;
    }

    public double getScore() {
        return score;
    }

    public Map<String, Double> getVector() {
        return vector;
    }

    public boolean isVerified() {
        return verified;
    }
}