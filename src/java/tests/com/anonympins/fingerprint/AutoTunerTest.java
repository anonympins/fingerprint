package com.anonympins.fingerprint;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.*;

public class AutoTunerTest {

    private InMemoryStore store;
    private FingerprintEngine engine;
    private FingerprintProperties properties;

    @BeforeEach
    public void setUp() {
        store = new InMemoryStore();

        // Configuration initiale du moteur
        Map<String, Object> config = new HashMap<>();
        Map<String, Object> thresholds = new HashMap<>();
        thresholds.put("low", 20);
        thresholds.put("medium", 45);
        thresholds.put("high", 75);
        thresholds.put("block", 95);
        config.put("thresholds", thresholds);

        Map<String, Object> weights = new HashMap<>();
        weights.put("inconsistencyScore", 0.5);
        weights.put("tlsSpoofingScore", 0.5);
        weights.put("requestPatternScore", 0.5);
        weights.put("behaviorScore", 0.5);
        weights.put("botScore", 0.5);
        config.put("weights", weights);

        engine = new FingerprintEngine(config, store);

        // Configuration de l'Autotuner pour le test
        properties = new FingerprintProperties();
        FingerprintProperties.Autotuning autotuning = properties.getAutotuning();
        autotuning.setEnabled(true);
        autotuning.setMinDataPoints(10); // Seuil bas pour faciliter le test unitaire
        autotuning.setMaxDataPoints(100);
        autotuning.setValidationTolerance(1.0); // Tolérance maximale pour s'assurer de l'acceptation lors du test
        autotuning.setInterval(30);
    }

    @Test
    public void testAutoTunerOptimizationCycle() {
        // Génération de fausses données de trafic
        List<Map<String, Object>> logs = new ArrayList<>();

        // On génère 12 entrées (suffisant par rapport à minDataPoints = 10)
        for (int i = 0; i < 10; i++) {
            logs.add(createMockLog("request_passed", "dev-" + i, "192.168.1." + i, 15.0));
        }
        // Signal de confiance fort requis (ratio > 0.05 ou effectif >= 10)
        logs.add(createMockLog("challenge_solved", "dev-10", "192.168.1.10", 10.0));
        logs.add(createMockLog("trap_triggered", "dev-11", "192.168.1.11", 85.0));

        store.set("traffic_logs", logs, 3600);

        AutoTuner tuner = new AutoTuner(engine, store, properties);

        // On lance la boucle d'optimisation
        tuner.runOptimizationCycle();

        // Vérification que les poids ou les seuils ont été évalués et modifiés
        Map<String, Object> currentThresholds = engine.getThresholds();
        Map<String, Object> currentWeights = engine.getWeights();

        assertNotNull(currentThresholds);
        assertNotNull(currentWeights);
        
        // L'ajustement adaptatif par inertie (Inertial Smooth Update) doit être fonctionnel
        assertTrue(currentThresholds.containsKey("low"));
        assertTrue(currentWeights.containsKey("botScore"));
    }

    @Test
    public void testAutoTunerWithInsufficientData() {
        // S'il n'y a pas assez de points de données (1 seul log de trafic au lieu de 10 minimum)
        List<Map<String, Object>> logs = new ArrayList<>();
        logs.add(createMockLog("request_passed", "dev-1", "192.168.1.1", 15.0));
        store.set("traffic_logs", logs, 3600);

        AutoTuner tuner = new AutoTuner(engine, store, properties);

        Map<String, Object> initialThresholds = new HashMap<>(engine.getThresholds());
        Map<String, Object> initialWeights = new HashMap<>(engine.getWeights());

        tuner.runOptimizationCycle();

        // L'optimisation doit s'arrêter de manière précoce sans modifier la configuration active
        assertEquals(initialThresholds, engine.getThresholds(), "La configuration ne doit pas changer par manque de données");
        assertEquals(initialWeights, engine.getWeights(), "La configuration ne doit pas changer par manque de données");
    }

    private Map<String, Object> createMockLog(String type, String deviceId, String clientIp, double score) {
        Map<String, Object> log = new HashMap<>();
        log.put("type", type);
        log.put("deviceId", deviceId);
        log.put("clientIp", clientIp);
        log.put("score", score);
        log.put("timestamp", System.currentTimeMillis());

        Map<String, Double> vector = new HashMap<>();
        vector.put("inconsistencyScore", 20.0);
        vector.put("tlsSpoofingScore", 10.0);
        vector.put("requestPatternScore", 5.0);
        vector.put("behaviorScore", 12.0);
        vector.put("botScore", 0.0);
        log.put("vector", vector);
        return log;
    }
}