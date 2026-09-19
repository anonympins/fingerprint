package com.anonympins.fingerprint.utils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.function.Function;

/**
 * Fonctions pour générer dynamiquement les données d'un problème.
 */
public class ProblemInitializers {
    private static final Map<String, Function<Map<String, Object>, Object>> initializers = new HashMap<>();

    static {
        // Example: generate:randomPoints for TSP
        initializers.put("generate:randomPoints", params -> {
            int count = ((Number) params.getOrDefault("count", 0)).intValue();
            Map<String, Object> bounds = (Map<String, Object>) params.getOrDefault("bounds", new HashMap<>());
            double maxX = ((Number) bounds.getOrDefault("x", 1000.0)).doubleValue();
            double maxY = ((Number) bounds.getOrDefault("y", 1000.0)).doubleValue();
            
            List<Map<String, Double>> points = new ArrayList<>();
            Random rand = new Random();
            for (int i = 0; i < count; i++) {
                Map<String, Double> point = new HashMap<>();
                point.put("x", rand.nextDouble() * maxX);
                point.put("y", rand.nextDouble() * maxY);
                points.add(point);
            }
            return points;
        });

        // Example: generate:randomAssets for Portfolio Optimization
        initializers.put("generate:randomAssets", params -> {
            int count = ((Number) params.getOrDefault("count", 0)).intValue();
            List<Map<String, Object>> assets = new ArrayList<>();
            Random rand = new Random();
            for (int i = 0; i < count; i++) {
                Map<String, Object> asset = new HashMap<>();
                asset.put("expectedReturn", rand.nextDouble() * 0.2);
                asset.put("volatility", 0.1 + rand.nextDouble() * 0.3);
                assets.add(asset);
            }
            return assets;
        });
    }

    public static Function<Map<String, Object>, Object> getInitializer(String name) {
        return initializers.get(name);
    }
}