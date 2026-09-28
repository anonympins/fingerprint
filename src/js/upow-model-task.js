import crypto from "node:crypto";

/**
 * Abstract base class defining useful Proof-of-Work (uPoW) tasks based on ML training
 * or inference validation (e.g. PyTorch models exported to ONNX format).
 */
export class UpowModelTask {
    /**
     * Creates a new UpowModelTask. This class is abstract and cannot be
     * instantiated directly.
     *
     * @param {string} problemId - The unique identifier of the problem.
     * @param {string} modelPath - The network asset path of the model.
     * @param {object} [config={}] - Optional configuration overrides.
     * @param {number} [config.batchSize=32] - Mini-batch size.
     * @param {number} [config.learningRate=0.01] - Learning rate.
     * @param {number} [config.validationTolerance=0.15] - Validation tolerance.
     * @throws {TypeError} If instantiated directly.
     */
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
     * Returns the unique problem identifier.
     * @returns {string}
     */
    getProblemId() {
        return this.problemId;
    }

    /**
     * Returns the network asset path of the model.
     * @returns {string}
     */
    getModelAssetPath() {
        return this.modelPath;
    }

    /**
     * Dispatches task workload to the client.
     * Transmits current model weights and mini-batch sample data.
     * @param {number} suspicionFactor
     * @returns {object} Task payload dispatched to client
     */
    dispatchTask(suspicionFactor) {
        throw new Error("Method 'dispatchTask(suspicionFactor)' must be implemented.");
    }

    /**
     * Validates solution returned by the client.
     * Implements anti-poisoning guards and gradient bounds checks.
     * @param {object} taskContext
     * @param {object} solution
     * @returns {boolean}
     */
    verifySolution(taskContext, solution) {
        throw new Error("Method 'verifySolution(taskContext, solution)' must be implemented.");
    }

    /**
     * Integrates validated gradients into global model weights (e.g. FedAvg).
     * @param {object} solution
     */
    integrateSolution(solution) {
        throw new Error("Method 'integrateSolution(solution)' must be implemented.");
    }
}

/**
 * Example training task implementation (suspicious request classifier).
 */
export class RequestClassifierTask extends UpowModelTask {
    /**
     * Creates a new RequestClassifierTask with an initial set of linear
     * neural network weights.
     *
     * @param {string} modelPath - The network asset path of the model.
     * @param {object} config - Configuration object (batch size, learning rate, etc.).
     */
    constructor(modelPath, config) {
        super("request_classifier_nn", modelPath, config);
        // Initial model weights (linear neural network)
        this.weights = [0.1, -0.2, 0.8, 0.5];
    }

    /**
     * Builds and returns the task payload sent to the client, including the
     * current model weights, an anonymized sample training batch, the learning
     * rate, and the batch size.
     *
     * @param {number} suspicionFactor - The suspicion factor for this request.
     * @returns {object} The task payload dispatched to the client.
     */
    dispatchTask(suspicionFactor) {
        // Anonymized sample training batch dispatched to client
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

    /**
     * Validates the solution returned by the client. Ensures the gradients
     * array has the expected length and applies an anti-poisoning guard by
     * rejecting any gradient whose absolute value exceeds a fixed threshold
     * (gradient clipping).
     *
     * @param {object} taskContext - The context of the dispatched task.
     * @param {object} solution - The solution returned by the client.
     * @returns {boolean} True if the solution is valid, false otherwise.
     */
    verifySolution(taskContext, solution) {
        const gradients = solution?.gradients;
        if (!Array.isArray(gradients) || gradients.length !== this.weights.length) {
            return false;
        }
        // Anti-poisoning guard: ensure gradients do not exceed threshold norms (gradient clipping)
        const maxGradientNorm = 10.0;
        for (const grad of gradients) {
            if (typeof grad !== 'number' || isNaN(grad) || Math.abs(grad) > maxGradientNorm) {
                return false;
            }
        }
        return true;
    }

    /**
     * Integrates the validated gradients into the global model weights using
     * a simple gradient descent update: w_i -= learningRate * grad_i.
     *
     * @param {object} solution - The validated solution containing gradients.
     */
    integrateSolution(solution) {
        const gradients = solution.gradients;
        for (let i = 0; i < this.weights.length; i++) {
            this.weights[i] -= this.config.learningRate * gradients[i];
        }
    }
}