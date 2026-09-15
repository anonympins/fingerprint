package com.anonympins.fingerprint;

import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class AutoTuner {
    private final FingerprintEngine engine;
    private final IStore store;
    private final Map<String, Object> config;
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    private final int minDataPoints;
    private final int maxDataPoints;
    private final double validationTolerance;
    private final long intervalMinutes;
    private static Map<String, Object> lastBestSolution = null;

    @SuppressWarnings("unchecked")
    public AutoTuner(FingerprintEngine engine, IStore store, FingerprintProperties properties) {
        this.engine = engine;
        this.store = store;
        this.config = properties.getAutotuning();

        this.minDataPoints = ((Number) config.getOrDefault("minDataPoints", 200)).intValue();
        this.maxDataPoints = ((Number) config.getOrDefault("maxDataPoints", 10000)).intValue();
        this.validationTolerance = ((Number) config.getOrDefault("validationTolerance", 0.15)).doubleValue();
        this.intervalMinutes = ((Number) config.getOrDefault("interval", 30)).longValue();
    }

    public void start() {
        scheduler.scheduleAtFixedRate(this::runOptimizationCycle, intervalMinutes, intervalMinutes, TimeUnit.MINUTES);
    }

    public void stop() {
        scheduler.shutdown();
    }

    @SuppressWarnings("unchecked")
    public synchronized void runOptimizationCycle() {
        List<Map<String, Object>> rawLogs = (List<Map<String, Object>>) store.get("traffic_logs");
        if (rawLogs == null || rawLogs.isEmpty()) {
            return;
        }

        // Pruning & Sanitize
        pruneLogs(rawLogs);
        List<Map<String, Object>> sanitizedData = sanitizeTrafficData(rawLogs);

        long highConfidenceLogs = sanitizedData.stream()
                .filter(log -> {
                    String type = (String) log.get("type");
                    return "challenge_solved".equals(type) || "trap_triggered".equals(type);
                }).count();

        double highConfidenceRatio = sanitizedData.isEmpty() ? 0.0 : (double) highConfidenceLogs / sanitizedData.size();
        double minConfidenceRatio = 0.05;
        int minHighConfidenceCount = 10;

        boolean hasEnoughSignal = highConfidenceRatio >= minConfidenceRatio || highConfidenceLogs >= minHighConfidenceCount;

        if (sanitizedData.size() < minDataPoints || !hasEnoughSignal) {
            return;
        }

        // Exécution de l'algorithme génétique multi-objectifs
        List<Individual> paretoFront = solveFullSecurityTuning(sanitizedData);
        if (paretoFront.isEmpty()) {
            return;
        }

        // Filtrage par les gardes-fous de sécurité (Sanity Guardrails)
        List<Individual> filteredFront = new ArrayList<>();
        for (Individual ind : paretoFront) {
            if (isValidSecurityConfig(ind.thresholds, ind.weights)) {
                filteredFront.add(ind);
            }
        }
        if (filteredFront.isEmpty()) {
            filteredFront = paretoFront;
        }

        // Sélection de la solution la plus équilibrée (distance minimale de l'origine)
        Individual bestSolution = filteredFront.get(0);
        double minDistance = Math.sqrt(Math.pow(bestSolution.objectives[0], 2) + Math.pow(bestSolution.objectives[1], 2));
        for (int i = 1; i < filteredFront.size(); i++) {
            Individual candidate = filteredFront.get(i);
            double dist = Math.sqrt(Math.pow(candidate.objectives[0], 2) + Math.pow(candidate.objectives[1], 2));
            if (dist < minDistance) {
                minDistance = dist;
                bestSolution = candidate;
            }
        }

        // Application adaptative avec inertie (Inertial Smooth Update)
        double trafficConfidence = Math.min(1.5, Math.max(0.3, highConfidenceRatio * 4.0));
        
        // Simulation d'une mise à jour temporaire pour la validation croisée
        Map<String, Object> tempThresholds = new HashMap<>(engine.getThresholds());
        Map<String, Object> tempWeights = new HashMap<>(engine.getWeights());

        applyInertialUpdate(tempThresholds, bestSolution.thresholds, "thresholds", trafficConfidence);
        applyInertialUpdate(tempWeights, bestSolution.weights, "weights", trafficConfidence);

        // Validation croisée (anti-poisoning)
        double[] currentObj = evaluateFitness(engine.getThresholds(), engine.getWeights(), sanitizedData);
        double[] proposedObj = evaluateFitness(tempThresholds, tempWeights, sanitizedData);

        if (proposedObj[0] > currentObj[0] + validationTolerance || proposedObj[1] > currentObj[1] + validationTolerance) {
            // Rejet car instabilité/poisoning détecté
            return;
        }

        // Application définitive à chaud
        applyInertialUpdate(engine.getThresholds(), bestSolution.thresholds, "thresholds", trafficConfidence);
        applyInertialUpdate(engine.getWeights(), bestSolution.weights, "weights", trafficConfidence);

        lastBestSolution = new HashMap<>();
        lastBestSolution.put("thresholds", engine.getThresholds());
        lastBestSolution.put("weights", engine.getWeights());
        lastBestSolution.put("objectives", bestSolution.objectives);
    }

    private void pruneLogs(List<Map<String, Object>> logs) {
        if (logs.size() > maxDataPoints) {
            logs.subList(0, logs.size() - maxDataPoints).clear();
        }
    }

    private List<Map<String, Object>> sanitizeTrafficData(List<Map<String, Object>> trafficData) {
        List<Map<String, Object>> suspiciousLogs = new ArrayList<>();
        List<Map<String, Object>> passedLogs = new ArrayList<>();
        Map<String, Integer> deviceCounts = new HashMap<>();
        Map<String, Integer> ipCounts = new HashMap<>();

        int totalCount = trafficData.size();
        int maxLogsPerDevice = Math.max(3, (int) Math.floor(totalCount * 0.02));
        int maxLogsPerIp = Math.max(3, (int) Math.floor(totalCount * 0.02));

        for (Map<String, Object> log : trafficData) {
            String devId = (String) log.getOrDefault("deviceId", "anonymous");
            String ip = (String) log.getOrDefault("clientIp", "unknown");
            String type = (String) log.getOrDefault("type", "");

            int currentDeviceCount = deviceCounts.getOrDefault(devId, 0);
            int currentIpCount = ipCounts.getOrDefault(ip, 0);

            if (currentDeviceCount < maxLogsPerDevice && currentIpCount < maxLogsPerIp) {
                deviceCounts.put(devId, currentDeviceCount + 1);
                ipCounts.put(ip, currentIpCount + 1);

                if ("request_passed".equals(type)) {
                    passedLogs.add(log);
                } else {
                    suspiciousLogs.add(log);
                }
            }
        }

        int maxPassedAllowed = Math.max(minDataPoints, suspiciousLogs.size() * 9);
        if (passedLogs.size() > maxPassedAllowed) {
            Collections.shuffle(passedLogs);
            passedLogs = passedLogs.subList(0, maxPassedAllowed);
        }

        List<Map<String, Object>> combined = new ArrayList<>(suspiciousLogs);
        combined.addAll(passedLogs);
        return combined;
    }

    private boolean isValidSecurityConfig(Map<String, Integer> thresholds, Map<String, Double> weights) {
        double activeWeightsSum = weights.getOrDefault("inconsistencyScore", 0.0) +
                weights.getOrDefault("tlsSpoofingScore", 0.0) +
                weights.getOrDefault("requestPatternScore", 0.0) +
                weights.getOrDefault("behaviorScore", 0.0) +
                weights.getOrDefault("botScore", 0.0);

        if (activeWeightsSum < 1.5) return false;

        int low = thresholds.getOrDefault("low", 0);
        int medium = thresholds.getOrDefault("medium", 0);
        int high = thresholds.getOrDefault("high", 0);
        int block = thresholds.getOrDefault("block", 0);

        return low >= 10 && low <= 35 &&
                medium >= low + 5 && medium <= 70 &&
                high >= medium + 5 && high <= 90 &&
                block >= high + 5 && block <= 99;
    }

    private void applyInertialUpdate(Map<String, Object> current, Map<String, ? extends Number> target, String type, double confidence) {
        double baseLearningRate = 0.15;
        double learningRate = Math.max(0.02, Math.min(0.40, baseLearningRate * confidence));

        for (String key : current.keySet()) {
            if (target.containsKey(key)) {
                double curVal = ((Number) current.get(key)).doubleValue();
                double tarVal = target.get(key).doubleValue();
                double updated = curVal + (tarVal - curVal) * learningRate;

                if ("weights".equals(type)) {
                    updated = Math.max(0.05, Math.min(1.8, updated));
                    current.put(key, updated);
                } else if ("thresholds".equals(type)) {
                    current.put(key, (int) Math.round(updated));
                }
            }
        }

        if ("thresholds".equals(type)) {
            int low = Math.max(10, Math.min(35, ((Number) current.get("low")).intValue()));
            int medium = Math.max(low + 8, Math.min(65, ((Number) current.get("medium")).intValue()));
            int high = Math.max(medium + 8, Math.min(85, ((Number) current.get("high")).intValue()));
            int block = Math.max(high + 8, Math.min(98, ((Number) current.get("block")).intValue()));

            current.put("low", low);
            current.put("medium", medium);
            current.put("high", high);
            current.put("block", block);
        }
    }

    // --- Résolveur d'algorithme génétique multi-objectifs de Pareto ---
    private List<Individual> solveFullSecurityTuning(List<Map<String, Object>> trafficData) {
        int populationSize = 50;
        int generations = 50;
        double mutationRate = 0.1;
        Random rand = new Random();

        List<Individual> population = new ArrayList<>();
        for (int i = 0; i < populationSize; i++) {
            population.add(randomIndividual(rand));
        }

        for (Individual ind : population) {
            ind.objectives = evaluateFitness(ind.thresholds, ind.weights, trafficData);
        }

        for (int gen = 0; gen < generations; gen++) {
            List<Individual> offspring = new ArrayList<>();
            for (int i = 0; i < populationSize; i++) {
                Individual parent1 = population.get(rand.nextInt(populationSize));
                Individual parent2 = population.get(rand.nextInt(populationSize));
                Individual child = crossover(parent1, parent2, rand);
                if (rand.nextDouble() < mutationRate) {
                    mutate(child, rand);
                }
                child.objectives = evaluateFitness(child.thresholds, child.weights, trafficData);
                offspring.add(child);
            }

            List<Individual> combined = new ArrayList<>(population);
            combined.addAll(offspring);
            List<List<Individual>> fronts = nonDominatedSort(combined);

            List<Individual> nextPop = new ArrayList<>();
            for (List<Individual> front : fronts) {
                if (nextPop.size() + front.size() <= populationSize) {
                    nextPop.addAll(front);
                } else {
                    calculateCrowdingDistance(front);
                    front.sort((a, b) -> Double.compare(b.crowdingDistance, a.crowdingDistance));
                    int remaining = populationSize - nextPop.size();
                    nextPop.addAll(front.subList(0, remaining));
                    break;
                }
            }
            population = nextPop;
        }

        return nonDominatedSort(population).get(0);
    }

    private Individual randomIndividual(Random rand) {
        Individual ind = new Individual();
        ind.thresholds.put("low", 10 + rand.nextInt(25));
        ind.thresholds.put("medium", ind.thresholds.get("low") + 10 + rand.nextInt(25));
        ind.thresholds.put("high", ind.thresholds.get("medium") + 10 + rand.nextInt(20));
        ind.thresholds.put("block", ind.thresholds.get("high") + 8 + rand.nextInt(10));

        for (String wKey : engine.getWeights().keySet()) {
            ind.weights.put(wKey, 0.1 + rand.nextDouble() * 1.3);
        }
        return ind;
    }

    private Individual crossover(Individual p1, Individual p2, Random rand) {
        Individual child = new Individual();
        for (String key : p1.thresholds.keySet()) {
            child.thresholds.put(key, (int) Math.round((p1.thresholds.get(key) + p2.thresholds.get(key)) / 2.0));
        }
        for (String key : p1.weights.keySet()) {
            child.weights.put(key, (p1.weights.get(key) + p2.weights.get(key)) / 2.0);
        }
        return child;
    }

    private void mutate(Individual ind, Random rand) {
        if (rand.nextBoolean()) {
            String[] tKeys = ind.thresholds.keySet().toArray(new String[0]);
            String k = tKeys[rand.nextInt(tKeys.length)];
            ind.thresholds.put(k, Math.max(10, ind.thresholds.get(k) + (rand.nextBoolean() ? 2 : -2)));
        } else {
            String[] wKeys = ind.weights.keySet().toArray(new String[0]);
            String k = wKeys[rand.nextInt(wKeys.length)];
            ind.weights.put(k, Math.max(0.05, Math.min(1.8, ind.weights.get(k) + (rand.nextDouble() - 0.5) * 0.2)));
        }
    }

    @SuppressWarnings("unchecked")
    private double[] evaluateFitness(Map<String, ?> thresholds, Map<String, ?> weights, List<Map<String, Object>> trafficData) {
        double falsePositives = 0;
        double falseNegatives = 0;
        double totalHumans = 0;
        double totalBots = 0;

        double lowThreshold = ((Number) thresholds.get("low")).doubleValue();

        for (Map<String, Object> log : trafficData) {
            String type = (String) log.get("type");
            Map<String, Double> vector = (Map<String, Double>) log.get("vector");

            double score = 0.0;
            for (String wKey : weights.keySet()) {
                score += vector.getOrDefault(wKey, 0.0) * ((Number) weights.get(wKey)).doubleValue();
            }

            boolean isLikelyBot = "request_blocked".equals(type) || "trap_triggered".equals(type);
            boolean isLikelyHuman = "request_passed".equals(type) || "challenge_solved".equals(type);

            if (isLikelyBot) {
                totalBots++;
                if (score < lowThreshold) {
                    falseNegatives++;
                }
            } else if (isLikelyHuman) {
                totalHumans++;
                if (score >= lowThreshold) {
                    falsePositives++;
                }
            }
        }

        double fpr = totalHumans > 0 ? falsePositives / totalHumans : 0.0;
        double fnr = totalBots > 0 ? falseNegatives / totalBots : 0.0;
        return new double[]{fpr, fnr};
    }

    private List<List<Individual>> nonDominatedSort(List<Individual> population) {
        List<List<Individual>> fronts = new ArrayList<>();
        fronts.add(new ArrayList<>());

        for (Individual p1 : population) {
            p1.dominationCount = 0;
            p1.dominatedSolutions.clear();

            for (Individual p2 : population) {
                if (p1 == p2) continue;
                if (paretoDominates(p1.objectives, p2.objectives)) {
                    p1.dominatedSolutions.add(p2);
                } else if (paretoDominates(p2.objectives, p1.objectives)) {
                    p1.dominationCount++;
                }
            }
            if (p1.dominationCount == 0) {
                p1.rank = 0;
                fronts.get(0).add(p1);
            }
        }

        int i = 0;
        while (fronts.get(i).size() > 0) {
            List<Individual> nextFront = new ArrayList<>();
            for (Individual p1 : fronts.get(i)) {
                for (Individual p2 : p1.dominatedSolutions) {
                    p2.dominationCount--;
                    if (p2.dominationCount == 0) {
                        p2.rank = i + 1;
                        nextFront.add(p2);
                    }
                }
            }
            i++;
            if (nextFront.isEmpty()) break;
            fronts.add(nextFront);
        }
        return fronts;
    }

    private boolean paretoDominates(double[] objA, double[] objB) {
        boolean better = false;
        for (int i = 0; i < objA.length; i++) {
            if (objA[i] > objB[i]) return false;
            if (objA[i] < objB[i]) better = true;
        }
        return better;
    }

    private void calculateCrowdingDistance(List<Individual> front) {
        if (front.isEmpty()) return;
        int l = front.size();
        front.forEach(p -> p.crowdingDistance = 0.0);

        for (int i = 0; i < 2; i++) {
            final int objIdx = i;
            front.sort(Comparator.comparingDouble(a -> a.objectives[objIdx]));
            front.get(0).crowdingDistance = Double.POSITIVE_INFINITY;
            front.get(l - 1).crowdingDistance = Double.POSITIVE_INFINITY;

            double min = front.get(0).objectives[objIdx];
            double max = front.get(l - 1).objectives[objIdx];
            if (max == min) continue;

            for (int j = 1; j < l - 1; j++) {
                front.get(j).crowdingDistance += (front.get(j + 1).objectives[objIdx] - front.get(j - 1).objectives[objIdx]) / (max - min);
            }
        }
    }

    private static class Individual {
        Map<String, Integer> thresholds = new HashMap<>();
        Map<String, Double> weights = new HashMap<>();
        double[] objectives = new double[2];
        int rank = 0;
        int dominationCount = 0;
        List<Individual> dominatedSolutions = new ArrayList<>();
        double crowdingDistance = 0.0;
    }
}