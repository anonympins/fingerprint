package com.anonympins.fingerprint.utils;

import java.util.HashMap;
import java.util.Map;
import java.util.function.BiFunction;

/**
 * Registre pour exposer de manière contrôlée les fonctions de la bibliothèque d'optimisation.
 * Permet de les appeler dynamiquement depuis la configuration des problèmes.
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
     * Récupère une fonction de score depuis le registre.
     *
     * @param name Le nom de la fonction de score.
     * @return La fonction de score ou null si non trouvée.
     */
    public static BiFunction<Object, Map<String, Object>, Double> getScoreFunction(String name) {
        return scoreFunctions.get(name);
    }
}