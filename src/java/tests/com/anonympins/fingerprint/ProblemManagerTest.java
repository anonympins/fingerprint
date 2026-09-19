package com.anonympins.fingerprint;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

public class ProblemManagerTest {
    private InMemoryStore store;
    private Path tempConfig;

    @BeforeEach
    public void setUp(@TempDir Path tempDir) throws IOException {
        store = new InMemoryStore();
        tempConfig = tempDir.resolve("problems.config.json");

        String jsonContent = "[" +
                "  {" +
                "    \"id\": \"tsp_10_cities\"," +
                "    \"workUnit\": {" +
                "      \"type\": \"simulated_annealing_iterations\"," +
                "      \"scoreFunction\": \"tsp.calculateEnergy\"," +
                "      \"baseIterations\": 15000," +
                "      \"scalingFactor\": 2.0" +
                "    }," +
                "    \"payload\": {}," +
                "    \"state\": {" +
                "      \"bestSolution\": null," +
                "      \"bestEnergy\": 1000.0" +
                "    }" +
                "  }," +
                "  {" +
                "    \"id\": \"portfolio_5_assets\"," +
                "    \"workUnit\": {" +
                "      \"type\": \"genetic_algorithm_generations\"," +
                "      \"baseGenerations\": 50," +
                "      \"scalingFactor\": 1.5" +
                "    }," +
                "    \"payload\": {}," +
                "    \"state\": {" +
                "      \"population\": []" +
                "    }" +
                "  }" +
                "]";
        Files.writeString(tempConfig, jsonContent);
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testLoadProblemsAndDispatch() {
        ProblemManager manager = ProblemManager.getInstance(tempConfig.toString(), store);
        assertNotNull(manager);

        // Dispatch d'une tâche d'optimisation classique
        Map<String, Object> work1 = manager.dispatchWork(0.5);
        assertNotNull(work1);
        assertEquals("tsp_10_cities", work1.get("problemId"));

        Map<String, Object> task1 = (Map<String, Object>) work1.get("task");
        assertEquals("simulated_annealing_iterations", task1.get("type"));
        assertEquals(21213, ((Number) task1.get("iterations")).intValue());
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testIntegrateModelTaskAndVerify() {
        ProblemManager manager = ProblemManager.getInstance(tempConfig.toString(), store);
        
        // Enregistrement de la tâche ML
        RequestClassifierTask mlTask = new RequestClassifierTask("request_classifier_nn", "/model.json", new HashMap<>());
        manager.registerModelTask(mlTask);

        // Préparation du contexte de tâche (poids initiaux)
        Map<String, Object> context = new HashMap<>();
        context.put("weights", Arrays.asList(0.1, -0.2, 0.8, 0.5));
        store.set("upo-task-ctx:request_classifier_nn", context, null);

        // Soumission de la solution client (Gradients légitimes)
        Map<String, Object> solutionData = new HashMap<>();
        solutionData.put("gradients", Arrays.asList(0.01, -0.02, 0.05, 0.1));

        manager.integrateSolution("request_classifier_nn", solutionData);

        // Vérification de la persistance de l'état mis à jour
        Map<String, Object> finalState = (Map<String, Object>) store.get("problem-state:request_classifier_nn");
        assertNotNull(finalState);
        assertTrue(finalState.containsKey("weights"));
    }
}