package com.anonympins.fingerprint;

import java.util.Map;

/**
 * Abstract base class defining useful Proof-of-Work (uPoW) tasks based on ML training
 * or evaluation in Java.
 */
public abstract class UpowModelTask {
    protected final String problemId;
    protected final String modelPath;
    protected final Map<String, Object> config;

    public UpowModelTask(String problemId, String modelPath, Map<String, Object> config) {
        this.problemId = problemId;
        this.modelPath = modelPath;
        this.config = config;
    }

    public String getProblemId() {
        return problemId;
    }

    public String getModelAssetPath() {
        return modelPath;
    }

    /**
     * Generates task payload (weights, inputs, etc.) dispatched to the client.
     */
    public abstract Map<String, Object> dispatchTask(double suspicionFactor);

    /**
     * Verifies mathematical validity of solution gradients/weights returned 
     * by the client (anti-poisoning guards, gradient clipping).
     */
    public abstract boolean verifySolution(Map<String, Object> taskContext, Map<String, Object> solution);

    /**
     * Integrates validated gradients into global model weights (e.g. FedAvg).
     */
    public abstract void integrateSolution(Map<String, Object> solution);

    public abstract Map<String, Object> getCurrentModelState();
}