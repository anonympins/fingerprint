package com.anonympins.fingerprint;

import java.util.*;

/**
 * Implémentation concrète d'une tâche d'apprentissage fédéré (Classifieur de requêtes).
 */
public class RequestClassifierTask extends UpowModelTask {
    private final List<Double> weights = new ArrayList<>(Arrays.asList(0.1, -0.2, 0.8, 0.5));

    public RequestClassifierTask(String problemId, String modelPath, Map<String, Object> config) {
        super(problemId, modelPath, config);
    }

    @Override
    public Map<String, Object> dispatchTask(double suspicionFactor) {
        Map<String, Object> task = new HashMap<>();
        task.put("weights", new ArrayList<>(weights));
        List<List<Double>> inputs = Arrays.asList(
            Arrays.asList(1.0, 0.5, 0.0, 1.2),
            Arrays.asList(0.0, 1.0, -0.5, 0.8)
        );
        task.put("inputs", inputs);
        task.put("learningRate", config.getOrDefault("learningRate", 0.01));
        task.put("batchSize", config.getOrDefault("batchSize", 32));
        return task;
    }

    @Override
    public boolean verifySolution(Map<String, Object> taskContext, Map<String, Object> solution) {
        if (solution == null || !solution.containsKey("gradients")) {
            return false;
        }
        Object gradsObj = solution.get("gradients");
        if (!(gradsObj instanceof List)) {
            return false;
        }
        List<?> gradients = (List<?>) gradsObj;
        if (gradients.size() != weights.size()) {
            return false;
        }
        double maxGradientNorm = 10.0;
        for (Object grad : gradients) {
            if (!(grad instanceof Number)) {
                return false;
            }
            double val = ((Number) grad).doubleValue();
            if (Double.isNaN(val) || Math.abs(val) > maxGradientNorm) {
                return false;
            }
        }
        return true;
    }

    @Override
    public void integrateSolution(Map<String, Object> solution) {
        List<?> gradients = (List<?>) solution.get("gradients");
        double learningRate = ((Number) config.getOrDefault("learningRate", 0.01)).doubleValue();
        for (int i = 0; i < weights.size(); i++) {
            double grad = ((Number) gradients.get(i)).doubleValue();
            weights.set(i, weights.get(i) - learningRate * grad);
        }
    }

    @Override
    public Map<String, Object> getCurrentModelState() {
        Map<String, Object> state = new HashMap<>();
        state.put("weights", new ArrayList<>(weights));
        state.put("lastUpdate", System.currentTimeMillis());
        return state;
    }
}