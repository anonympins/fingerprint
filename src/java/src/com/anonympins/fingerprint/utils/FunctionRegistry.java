package com.anonympins.fingerprint.utils;

import java.util.HashMap;
import java.util.Map;
import java.util.function.BiFunction;

/**
 * Registry to expose optimization library functions in a controlled manner.
 * Allows calling them dynamically from problem configurations.
 */
public class FunctionRegistry {
    private static final Map<String, BiFunction<Object, Map<String, Object>, Double>> scoreFunctions = new HashMap<>();

    static {
        // Initialize with known score functions
        // Example: TSP distance calculation
        scoreFunctions.put("tsp.calculateEnergy", (solution, payload) -> {
            // Implement TSP distance calculation here
            // For now, a placeholder
            return 0.0;
        });

        // Example: Portfolio metrics calculation
        scoreFunctions.put("portfolio.calculateMetrics", (solution, payload) -> {
            // Implement portfolio metrics calculation here
            // For now, a placeholder
            return 0.0;
        });

        // Add other score functions as needed
    }

    /**
     * Retrieves a score function from the registry.
     *
     * @param name The name of the score function.
     * @return The score function or null if not found.
     */
    public static BiFunction<Object, Map<String, Object>, Double> getScoreFunction(String name) {
        return scoreFunctions.get(name);
    }
}