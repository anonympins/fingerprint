package com.anonympins.fingerprint;

import java.util.Map;

/**
 * Classe de base abstraite pour définir des tâches uPoW basées sur l'entraînement
 * ou l'évaluation de modèles d'apprentissage automatique en Java.
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
     * Génère la charge utile de travail (poids, inputs, etc.) à envoyer au client.
     */
    public abstract Map<String, Object> dispatchTask(double suspicionFactor);

    /**
     * Vérifie la validité mathématique de la solution (gradients/poids) retournée 
     * par le client (mures anti-empoisonnement, clipping).
     */
    public abstract boolean verifySolution(Map<String, Object> taskContext, Map<String, Object> solution);

    /**
     * Intègre les gradients validés dans le modèle maître (par exemple via FedAvg).
     */
    public abstract void integrateSolution(Map<String, Object> solution);

    public abstract Map<String, Object> getCurrentModelState();
}