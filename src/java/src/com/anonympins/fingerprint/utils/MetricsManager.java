package com.anonympins.fingerprint.utils;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Gestionnaire de métriques thread-safe pour l'écosystème Java.
 */
public class MetricsManager {
    private static final Map<String, Double> counters = new ConcurrentHashMap<>();
    private static final Map<String, Double> observations = new ConcurrentHashMap<>();
    private static Map<String, Object> lastBestSolution = null;

    public static void incrementCounter(String name, Map<String, String> labels) {
        String fullName = name.startsWith("fingerprint_") ? name : "fingerprint_" + name;
        String key = buildKey(fullName, labels);
        counters.merge(key, 1.0, Double::sum);
    }

    public static void observeValue(String name, double value, Map<String, String> labels) {
        String fullName = name.startsWith("fingerprint_") ? name : "fingerprint_" + name;
        String key = buildKey(fullName, labels);
        observations.put(key, value);
    }

    /**
     * Récupère les valeurs d'une métrique spécifique sous forme de Map dynamique (labels -> valeur).
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Double> getMetric(String name, Map<String, Object> securityConfig) {
        Map<String, Double> result = new LinkedHashMap<>();
        String queryName = name.startsWith("fingerprint_") ? name : "fingerprint_" + name;

        if ("fingerprint_security_weight".equals(queryName)) {
            Map<String, Object> weights = (Map<String, Object>) securityConfig.get("weights");
            if (weights != null) {
                for (Map.Entry<String, Object> entry : weights.entrySet()) {
                    if (entry.getValue() instanceof Number) {
                        result.put(entry.getKey(), ((Number) entry.getValue()).doubleValue());
                    }
                }
            }
        } else if ("fingerprint_security_threshold".equals(queryName)) {
            Map<String, Object> thresholds = (Map<String, Object>) securityConfig.get("thresholds");
            if (thresholds != null) {
                for (Map.Entry<String, Object> entry : thresholds.entrySet()) {
                    if (entry.getValue() instanceof Number) {
                        result.put(entry.getKey(), ((Number) entry.getValue()).doubleValue());
                    }
                }
            }
        } else if ("fingerprint_autotuning_false_positive_rate".equals(queryName)) {
            if (lastBestSolution != null && lastBestSolution.containsKey("objectives")) {
                double[] objectives = (double[]) lastBestSolution.get("objectives");
                if (objectives != null && objectives.length > 0) {
                    result.put("fpr", objectives[0]);
                }
            }
        } else if ("fingerprint_autotuning_false_negative_rate".equals(queryName)) {
            if (lastBestSolution != null && lastBestSolution.containsKey("objectives")) {
                double[] objectives = (double[]) lastBestSolution.get("objectives");
                if (objectives != null && objectives.length > 1) {
                    result.put("fnr", objectives[1]);
                }
            }
        } else {
            // Recherche dans les compteurs enregistrés
            for (Map.Entry<String, Double> entry : counters.entrySet()) {
                if (entry.getKey().startsWith(queryName)) {
                    String labelsPart = extractLabelsKey(entry.getKey(), queryName);
                    result.put(labelsPart, entry.getValue());
                }
            }
            // Recherche dans les observations
            for (Map.Entry<String, Double> entry : observations.entrySet()) {
                if (entry.getKey().startsWith(queryName)) {
                    String labelsPart = extractLabelsKey(entry.getKey(), queryName);
                    result.put(labelsPart, entry.getValue());
                }
            }
        }
        return result;
    }

    private static String buildKey(String name, Map<String, String> labels) {
        if (labels == null || labels.isEmpty()) {
            return name + "{}";
        }
        TreeMap<String, String> sorted = new TreeMap<>(labels);
        StringBuilder sb = new StringBuilder(name).append("{");
        boolean first = true;
        for (Map.Entry<String, String> entry : sorted.entrySet()) {
            if (!first) sb.append(",");
            sb.append(entry.getKey()).append("=\"").append(entry.getValue()).append("\"");
            first = false;
        }
        sb.append("}");
        return sb.toString();
    }

    private static String extractLabelsKey(String key, String queryName) {
        if (key.length() <= queryName.length()) {
            return "value";
        }
        String labelsPart = key.substring(queryName.length());
        if (labelsPart.startsWith("{") && labelsPart.endsWith("}")) {
            labelsPart = labelsPart.substring(1, labelsPart.length() - 1);
        }
        return labelsPart.isEmpty() ? "value" : labelsPart;
    }

    public static void setLastBestSolution(Map<String, Object> solution) {
        lastBestSolution = solution;
    }
}