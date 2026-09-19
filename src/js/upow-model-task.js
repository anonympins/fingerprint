import crypto from "node:crypto";

/**
 * Classe de base abstraite pour définir des tâches uPoW basées sur l'entraînement
 * ou l'évaluation de modèles IA (PyTorch exportés au format ONNX).
 */
export class UpowModelTask {
    constructor(problemId, modelPath, config = {}) {
        if (new.target === UpowModelTask) {
            throw new TypeError("Cannot construct UpowModelTask instances directly");
        }
        this.problemId = problemId;
        this.modelPath = modelPath;
        this.config = {
            batchSize: 32,
            learningRate: 0.01,
            validationTolerance: 0.15,
            ...config
        };
    }

    /**
     * Récupère l'identifiant du problème.
     * @returns {string}
     */
    getProblemId() {
        return this.problemId;
    }

    /**
     * Récupère le chemin réseau du modèle ONNX.
     * @returns {string}
     */
    getModelAssetPath() {
        return this.modelPath;
    }

    /**
     * Génère la charge utile de travail pour le client.
     * Envoie l'état actuel des poids du modèle et un lot de données (mini-batch) à traiter.
     * @param {number} suspicionFactor
     * @returns {object} Données à envoyer au client
     */
    dispatchTask(suspicionFactor) {
        throw new Error("Method 'dispatchTask(suspicionFactor)' must be implemented.");
    }

    /**
     * Vérifie la validité de la solution retournée par le client.
     * Implémente des gardes-fous contre l'empoisonnement (ex: vérification des gradients).
     * @param {object} taskContext 
     * @param {object} solution 
     * @returns {boolean}
     */
    verifySolution(taskContext, solution) {
        throw new Error("Method 'verifySolution(taskContext, solution)' must be implemented.");
    }

    /**
     * Intègre les gradients ou résultats validés dans le modèle global.
     * Par exemple : algorithme FedAvg (Federated Averaging).
     * @param {object} solution 
     */
    integrateSolution(solution) {
        throw new Error("Method 'integrateSolution(solution)' must be implemented.");
    }
}

/**
 * Exemple d'implémentation d'une tâche d'entraînement (Classifieur de requêtes suspectes)
 */
export class RequestClassifierTask extends UpowModelTask {
    constructor(modelPath, config) {
        super("request_classifier_nn", modelPath, config);
        // Poids initiaux du modèle (Réseau de neurones linéaire simple)
        this.weights = [0.1, -0.2, 0.8, 0.5]; 
    }

    dispatchTask(suspicionFactor) {
        // Génération de données d'entraînement anonymisées pour le client
        const inputs = [
            [1.0, 0.5, 0.0, 1.2],
            [0.0, 1.0, -0.5, 0.8]
        ];
        return {
            weights: [...this.weights],
            inputs: inputs,
            learningRate: this.config.learningRate,
            batchSize: this.config.batchSize
        };
    }

    verifySolution(taskContext, solution) {
        const gradients = solution?.gradients;
        if (!Array.isArray(gradients) || gradients.length !== this.weights.length) {
            return false;
        }
        // Anti-poisoning : s'assurer que les gradients ne contiennent pas de valeurs aberrantes (clipping)
        const maxGradientNorm = 10.0;
        for (const grad of gradients) {
            if (typeof grad !== 'number' || isNaN(grad) || Math.abs(grad) > maxGradientNorm) {
                return false;
            }
        }
        return true;
    }

    integrateSolution(solution) {
        const gradients = solution.gradients;
        for (let i = 0; i < this.weights.length; i++) {
            this.weights[i] -= this.config.learningRate * gradients[i];
        }
    }
}