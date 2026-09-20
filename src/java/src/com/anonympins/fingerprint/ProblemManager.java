package com.anonympins.fingerprint;

import com.anonympins.fingerprint.utils.ChallengeUtils;
import com.anonympins.fingerprint.utils.ProblemInitializers;
import com.anonympins.fingerprint.utils.FunctionRegistry;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiFunction;

/**
 * Gère le cycle de vie des problèmes mathématiques d'optimisation et de ML (uPoW).
 */
public class ProblemManager {
    private static ProblemManager instance = null;
    private String configPath; // Made non-final to allow re-initialization if configPath changes
    private final IStore store;
    private final List<Map<String, Object>> problems = new ArrayList<>();
    private final Map<String, UpowModelTask> modelTasks = new ConcurrentHashMap<>();
    private int currentProblemIndex = 0;
    private boolean initialized = false;

    private ProblemManager(String configPath, IStore store) {
        // Ensure configPath is not null, even if empty string
        this.configPath = configPath != null ? configPath : "";

        this.store = store;
        this.loadProblems();
    }

    public static synchronized ProblemManager getInstance(String configPath, IStore store) {
        if (instance == null) {
            instance = new ProblemManager(configPath, store);
        } else if (!instance.configPath.equals(configPath) || instance.store != store) {
            // Re-initialize if configPath or store changes (e.g., in tests or dynamic config)
            instance = new ProblemManager(configPath, store);
            instance.initialized = false; // Force reload
        }
        return instance;
    }

    public static synchronized ProblemManager getInstance() {
        if (instance == null) {
            throw new IllegalStateException("ProblemManager must be initialized first.");
        }
        return instance;
    }

    /**
     * Enregistre une tâche de modèle uPoW spécifique.
     * Ces tâches sont généralement des implémentations concrètes de UpowModelTask
     * qui gèrent des modèles ML spécifiques (TF.js, ONNX).
     * @param task L'instance de la tâche de modèle.
     */
    public void registerModelTask(UpowModelTask task) {
        this.modelTasks.put(task.getProblemId(), task);
    }

    /**
     * Charge et parse les problèmes depuis le fichier de configuration JSON.
     * Il initialise également l'état des problèmes depuis le store ou les valeurs par défaut.
     */
    @SuppressWarnings("unchecked")
    private void loadProblems() {
        if (this.initialized) {
            return; // Already initialized
        }
        this.problems.clear(); // Clear existing problems before loading
        this.modelTasks.clear(); // Clear existing model tasks

        if (store == null) {
            System.err.println("[ProblemManager] Store is not configured. Cannot load problems.");
            return;
        }

        try {
            String jsonContent = new String(Files.readAllBytes(Paths.get(configPath)));
            List<Map<String, Object>> problemsFromFile = ChallengeUtils.simpleJsonParseList(jsonContent);

            for (Map<String, Object> problem : problemsFromFile) {
                String problemId = (String) problem.get("id");
                String storeKey = "problem-state:" + problemId;
                Map<String, Object> storedState = (Map<String, Object>) store.get(storeKey);

                if (storedState == null) {
                    storedState = (Map<String, Object>) problem.getOrDefault("state", new HashMap<>());
                    store.set(storeKey, storedState, null); // Persist initial state indefinitely
                }
                problem.put("state", storedState);

                // Resolve score functions for generic optimization problems
                Map<String, Object> workUnit = (Map<String, Object>) problem.get("workUnit");
                if (workUnit != null && workUnit.containsKey("scoreFunction")) {
                    String scoreFunctionName = (String) workUnit.get("scoreFunction");
                    BiFunction<Object, Map<String, Object>, Double> scoreFunction = FunctionRegistry.getScoreFunction(scoreFunctionName);
                    if (scoreFunction == null) {
                        System.err.println("[ProblemManager] Warning: scoreFunction '" + scoreFunctionName + "' not found in registry for problem '" + problemId + "'.");
                    }
                    // Store the resolved function (or its name) for later use
                    workUnit.put("resolvedScoreFunction", scoreFunction);
                }

                // Handle dynamic payload initialization (e.g., generate:randomPoints)
                Map<String, Object> payload = (Map<String, Object>) problem.get("payload");
                if (payload != null) {
                    for (Map.Entry<String, Object> entry : payload.entrySet()) {
                        Object value = entry.getValue();
                        if (value instanceof Map && ((Map<String, Object>) value).containsKey("$init")) {
                            Map<String, Object> initDirective = (Map<String, Object>) value;
                            String initializerName = (String) initDirective.get("$init");
                            Map<String, Object> params = (Map<String, Object>) initDirective.getOrDefault("params", new HashMap<>());
                            Object generatedData = ProblemInitializers.getInitializer(initializerName).apply(params);
                            entry.setValue(generatedData);
                        }
                    }
                }

                this.problems.add(problem);
            }
        } catch (IOException e) {
            System.err.println("[ProblemManager] Error loading problem config file: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("[ProblemManager] Error parsing or initializing problems: " + e.getMessage());
            e.printStackTrace();
        }
        this.initialized = true;
    }

    /**
     * Sélectionne et génère une tâche uPoW adaptée au score de suspicion.
     *
     * @param suspicionFactor Le facteur de suspicion pour ajuster la difficulté.
     * @return Un Map contenant l'ID du problème et la tâche à effectuer par le client, ou null si aucun problème n'est disponible.
     */
    public Map<String, Object> dispatchWork(double suspicionFactor) {
        if (problems.isEmpty() && modelTasks.isEmpty()) {
            return null;
        }

        // Simple round-robin dispatch for now
        if (currentProblemIndex >= problems.size()) {
            currentProblemIndex = 0;
        }
        if (problems.isEmpty()) {
            return null; // No problems loaded
        }

        Map<String, Object> problem = problems.get(currentProblemIndex);
        currentProblemIndex = (currentProblemIndex + 1) % problems.size();

        return createWorkTask(problem, suspicionFactor);
    }

    /**
     * Réceptionne, valide (via les validateurs de tâches) et applique les solutions soumises.
     */
    @SuppressWarnings("unchecked")
    public void integrateSolution(String problemId, Map<String, Object> solutionData) {
        if (modelTasks.containsKey(problemId)) {
            // This is an ML model task
            UpowModelTask task = modelTasks.get(problemId);
            
            // Contexte à récupérer depuis le store (poids d'origine pour vérifier le gradient)
            Map<String, Object> taskContext = (Map<String, Object>) store.get("upo-task-ctx:" + problemId);
            if (taskContext == null) {
                System.err.println("[ProblemManager] Task context not found for model: " + problemId);
                return;
            }
            
            if (task.verifySolution(taskContext, solutionData)) {
                task.integrateSolution(solutionData);
                // Persist the updated model state (e.g., weights)
                store.set("problem-state:" + problemId, task.getCurrentModelState(), null);
            } else {
                System.err.println("[ProblemManager] Solution rejetée pour le modèle : " + problemId + " (Triche/Empoisonnement suspecté)");
            }
        } else {
            // This is a generic optimization problem
            Map<String, Object> problem = problems.stream()
                    .filter(p -> problemId.equals(p.get("id")))
                    .findFirst()
                    .orElse(null);

            if (problem == null) {
                System.err.println("[ProblemManager] Problem not found: " + problemId);
                return;
            }

            Map<String, Object> workUnit = (Map<String, Object>) problem.get("workUnit");
            Map<String, Object> state = (Map<String, Object>) problem.get("state");
            Map<String, Object> payload = (Map<String, Object>) problem.get("payload");

            boolean stateChanged = false;

            switch ((String) workUnit.get("type")) {
                case "simulated_annealing_iterations":
                    if (solutionData.containsKey("solution") && solutionData.containsKey("energy")) {
                        BiFunction<Object, Map<String, Object>, Double> scoreFunction = (BiFunction<Object, Map<String, Object>, Double>) workUnit.get("resolvedScoreFunction");
                        if (scoreFunction == null) {
                            System.err.println("[ProblemManager] No score function defined for " + problemId + ". Cannot verify solution.");
                            return;
                        }
                        // 1. Never trust client's score. Recalculate.
                        Double recalculatedEnergy = scoreFunction.apply(solutionData.get("solution"), payload);
                        Double currentBest = ((Number) state.getOrDefault("bestEnergy", Double.POSITIVE_INFINITY)).doubleValue();

                        // 2. Compare recalculated score
                        if (recalculatedEnergy < currentBest) {
                            state.put("bestSolution", solutionData.get("solution"));
                            state.put("bestEnergy", recalculatedEnergy);
                            state.put("lastUpdate", new Date().toInstant().toString());
                            stateChanged = true;
                            System.out.println("[ProblemManager] New best solution for " + problemId + ": " + String.format("%.2f", recalculatedEnergy));
                        }
                    }
                    break;
                case "genetic_algorithm_generations":
                    if (solutionData.containsKey("population") && solutionData.get("population") instanceof List) {
                        List<Map<String, Object>> population = (List<Map<String, Object>>) solutionData.get("population");
                        BiFunction<Object, Map<String, Object>, Double> fitnessFunction = FunctionRegistry.getScoreFunction("portfolio.calculateMetrics");
                        if (fitnessFunction == null) {
                            System.err.println("[ProblemManager] Fitness function 'portfolio.calculateMetrics' not found for " + problemId + ". Cannot verify population.");
                            return;
                        }

                        // Sample-based verification
                        int sampleSize = Math.min(5, population.size());
                        Set<Integer> sampleIndices = new HashSet<>();
                        while (sampleIndices.size() < sampleSize) {
                            sampleIndices.add(new Random().nextInt(population.size()));
                        }

                        for (int index : sampleIndices) {
                            Map<String, Object> individual = population.get(index);
                            if (individual == null || !individual.containsKey("chromosome")) {
                                throw new IllegalArgumentException("Invalid individual structure or missing chromosome in population.");
                            }
                            Double recalculated = fitnessFunction.apply(individual.get("chromosome"), payload);
                            if (individual.containsKey("fitness") && !"-1".equals(String.valueOf(individual.get("fitness")))) {
                                if (Math.abs(((Number) individual.get("fitness")).doubleValue() - recalculated) > 1e-4) {
                                    System.err.println("[ProblemManager] Cheating detected for " + problemId + "! Declared fitness: " + individual.get("fitness") + ", recalculated: " + recalculated);
                                    return; // Reject entire population
                                }
                            }
                            individual.put("fitness", recalculated); // Force exact recalculated value
                        }
                        state.put("population", population);
                        state.put("lastUpdate", new Date().toInstant().toString());
                        stateChanged = true;
                        System.out.println("[ProblemManager] Population updated for " + problemId);
                    }
                    break;
                // Add other problem types as needed
            }

            if (stateChanged) {
                store.set("problem-state:" + problemId, state, null); // Persist updated state
            }
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> createWorkTask(Map<String, Object> problem, double suspicionFactor) {
        Map<String, Object> workUnit = (Map<String, Object>) problem.get("workUnit");
        Map<String, Object> state = (Map<String, Object>) problem.get("state");
        Map<String, Object> payload = (Map<String, Object>) problem.get("payload");

        Map<String, Object> task = new HashMap<>();
        task.put("type", workUnit.get("type"));

        double scalingFactor = ((Number) workUnit.getOrDefault("scalingFactor", 1.0)).doubleValue();

        switch ((String) workUnit.get("type")) {
            case "simulated_annealing_iterations":
                int baseIterations = ((Number) workUnit.getOrDefault("baseIterations", 15000)).intValue();
                task.put("iterations", (int) Math.floor(baseIterations * Math.pow(scalingFactor, suspicionFactor)));
                task.put("payload", payload);
                task.put("initialSolution", state.get("bestSolution"));
                break;
            case "genetic_algorithm_generations":
                int baseGenerations = ((Number) workUnit.getOrDefault("baseGenerations", 50)).intValue();
                task.put("generations", (int) Math.floor(baseGenerations * Math.pow(scalingFactor, suspicionFactor)));
                task.put("payload", payload);
                task.put("initialPopulation", state.get("population"));
                break;
            // Add other problem types for dispatching
        }
        Map<String, Object> result = new HashMap<>();
        result.put("problemId", problem.get("id"));
        result.put("task", task);
        return result;
    }

        /**
         * S'assure qu'un problème a une solution initiale. Si non, en génère une.
         */
        @SuppressWarnings("unchecked")
        private void ensureInitialSolution(Map<String, Object> problem) {
            Map<String, Object> state = (Map<String, Object>) problem.get("state");
            if (state == null) {
                state = new HashMap<>();
                problem.put("state", state);
            }
            if (state.get("bestSolution") != null) {
                return;
            }

            Map<String, Object> workUnit = (Map<String, Object>) problem.get("workUnit");
            if (workUnit == null) return;
            BiFunction<Object, Map<String, Object>, Double> scoreFunction = 
                (BiFunction<Object, Map<String, Object>, Double>) workUnit.get("resolvedScoreFunction");

            String initialSolutionSourceKey = (String) workUnit.get("initialSolutionSource");
            Map<String, Object> payload = (Map<String, Object>) problem.get("payload");
            if (payload == null) return;
            Object initialSolution = payload.get(initialSolutionSourceKey);

            if (scoreFunction != null && initialSolution instanceof List) {
                Double score = scoreFunction.apply(initialSolution, payload);
                state.put("bestSolution", initialSolution);
                state.put("bestEnergy", score);
                state.put("lastUpdate", new java.util.Date().toInstant().toString());
                store.set("problem-state:" + problem.get("id"), state, null);
            }
        }

        /**
         * Formate l'état d'un problème pour l'export externe.
         */
        @SuppressWarnings("unchecked")
        private Map<String, Object> formatSolution(Map<String, Object> problem) {
            Map<String, Object> state = (Map<String, Object>) problem.get("state");
            if (state == null) {
                return null;
            }

            Map<String, Object> workUnit = (Map<String, Object>) problem.get("workUnit");
            String type = workUnit != null ? (String) workUnit.get("type") : "";

            Map<String, Object> formatted = new HashMap<>();
            formatted.put("id", problem.get("id"));
            formatted.put("lastUpdate", state.get("lastUpdate"));

            if ("multi_objective_genetic_algorithm".equals(type)) {
                List<?> paretoFront = (List<?>) state.getOrDefault("paretoFront", new ArrayList<>());
                formatted.put("solution", paretoFront);
                formatted.put("score", paretoFront != null ? (double) paretoFront.size() : 0.0);
            } else {
                formatted.put("solution", state.get("bestSolution"));
                formatted.put("score", state.get("bestEnergy"));
            }
            return formatted;
        }

        /**
         * Récupère la meilleure solution actuellement connue pour un ou plusieurs problèmes.
         */
        @SuppressWarnings("unchecked")
        public Object getBestSolutions(String problemId) {
            for (Map<String, Object> p : this.problems) {
                if (problemId == null || problemId.equals(p.get("id"))) {
                    Map<String, Object> workUnit = (Map<String, Object>) p.get("workUnit");
                    String type = workUnit != null ? (String) workUnit.get("type") : "";
                    if (!"multi_objective_genetic_algorithm".equals(type)) {
                        ensureInitialSolution(p);
                    }
                    if (problemId != null) {
                        return formatSolution(p);
                    }
                }
            }

            if (problemId != null) {
                return null;
            }

            List<Map<String, Object>> results = new ArrayList<>();
            for (Map<String, Object> p : this.problems) {
                Map<String, Object> formatted = formatSolution(p);
                if (formatted != null && formatted.get("solution") != null) {
                    results.add(formatted);
                }
            }
            return results;
        }

        public Object getBestSolutions() {
            return getBestSolutions(null);
        }
}