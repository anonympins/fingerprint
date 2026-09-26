package com.anonympins.fingerprint;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.SerializationFeature;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.*;

public class AutoTuner {
    private final FingerprintEngine engine;
    private final IStore store;
    private final FingerprintProperties.Autotuning config;
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    private final int minDataPoints;
    private final int maxDataPoints;
    private final double validationTolerance;
    private final double maxDensityPercentage;
    private final long intervalMinutes;
    private final String savePath;
    private static Map<String, Object> lastBestSolution = null;

    @SuppressWarnings("unchecked")
    public AutoTuner(FingerprintEngine engine, IStore store, FingerprintProperties properties) {
        this.engine = engine;
        this.store = store;
        this.config = properties.getAutotuning();

        this.minDataPoints = config.getMinDataPoints();
        this.maxDataPoints = config.getMaxDataPoints();
        this.validationTolerance = config.getValidationTolerance();
        this.maxDensityPercentage = config.getMaxDensityPercentage();
        this.intervalMinutes = config.getInterval();
        this.savePath = config.getSavePath();
    }

    public void start() {
        scheduler.scheduleAtFixedRate(this::runOptimizationCycle, intervalMinutes, intervalMinutes, TimeUnit.MINUTES);
    }

    public void stop() {
        scheduler.shutdown();
    }


    private double getVectorDistance(Map<String, Double> v1, Map<String, Double> v2) {
        if (v1 == null || v2 == null) return Double.POSITIVE_INFINITY;
        double sum = 0.0;
        Set<String> allKeys = new HashSet<>(v1.keySet());
        allKeys.addAll(v2.keySet());
        for (String key : allKeys) {
            double val1 = v1.getOrDefault(key, 0.0);
            double val2 = v2.getOrDefault(key, 0.0);
            sum += Math.pow(val1 - val2, 2);
        }
        return Math.sqrt(sum);
    }

    private String getHardwareCluster(Map<String, Object> log) {
        String fp = (String) log.getOrDefault("deviceHash", log.getOrDefault("fingerprint", log.getOrDefault("deviceFingerprint", "")));
        if (fp == null || fp.isEmpty()) {
            return (String) log.getOrDefault("deviceId", "anonymous-cluster");
        }
        String[] parts = fp.split("\\|");
        List<String> hwComponents = new ArrayList<>();
        for (String part : parts) {
            String[] pair = part.split(":", 2);
            if (pair.length == 2 && (pair[0].equals("gpu") || pair[0].equals("cvs") || pair[0].equals("hw"))) {
                hwComponents.add(part);
            }
        }
        if (!hwComponents.isEmpty()) {
            Collections.sort(hwComponents);
            return String.join("|", hwComponents);
        }
        return (String) log.getOrDefault("deviceId", "anonymous-cluster");
    }

    private String getIpSubnet(String ip) {
        if (ip == null || "unknown".equals(ip)) {
            return "unknown-subnet";
        }
        if (ip.contains(":")) {
            String[] parts = ip.split(":");
            if (parts.length >= 3) {
                return parts[0] + ":" + parts[1] + ":" + parts[2] + "::/48";
            }
            return "unknown-subnet";
        } else {
            String[] parts = ip.split("\\.");
            if (parts.length == 4) {
                return parts[0] + "." + parts[1] + "." + parts[2] + ".0/24";
            }
            return "unknown-subnet";
        }
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
        
        // Simulation d'une mise à jour temporaire pour la validation croisée (anti-poisoning)
        Map<String, Object> tempThresholds = new HashMap<>(engine.getThresholds());
        Map<String, Object> tempWeights = new HashMap<>(engine.getWeights());
        Map<String, Object> tempPatterns = new HashMap<>(engine.getPatterns());

        applyInertialUpdate(tempThresholds, bestSolution.thresholds, "thresholds", trafficConfidence);
        applyInertialUpdate(tempWeights, bestSolution.weights, "weights", trafficConfidence);
        applyInertialUpdate(tempPatterns, bestSolution.patterns, "patterns", trafficConfidence);

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
        applyInertialUpdate(engine.getPatterns(), bestSolution.patterns, "patterns", trafficConfidence);

        lastBestSolution = new HashMap<>();
        lastBestSolution.put("thresholds", engine.getThresholds());
        lastBestSolution.put("weights", engine.getWeights());
        lastBestSolution.put("patterns", engine.getPatterns());
        lastBestSolution.put("objectives", bestSolution.objectives);

        // Persist best configuration if savePath is configured
        if (savePath != null && !savePath.isEmpty()) {
            try {
                Map<String, Object> solutionToSave = new HashMap<>();
                solutionToSave.put("thresholds", bestSolution.thresholds);
                solutionToSave.put("weights", bestSolution.weights);
                solutionToSave.put("patterns", bestSolution.patterns);

                ObjectMapper mapper = new ObjectMapper();
                String json = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(solutionToSave);
                Files.writeString(Paths.get(savePath), json);
            } catch (IOException e) {
                System.err.println("[AutoTuner] Error saving optimized configuration: " + e.getMessage());
            }
        }
    }

    private void pruneLogs(List<Map<String, Object>> logs) {
        if (logs.size() > maxDataPoints) {
            logs.subList(0, logs.size() - maxDataPoints).clear();
        }
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> sanitizeTrafficData(List<Map<String, Object>> trafficData) {
        if (trafficData == null || trafficData.isEmpty()) {
            return new ArrayList<>();
        }

        List<Map<String, Object>> rawLogs = new ArrayList<>(trafficData);
        int totalCount = rawLogs.size();

        int maxLogsPerDevice = Math.max(3, (int) Math.floor(totalCount * 0.02));
        int maxLogsPerIp = Math.max(3, (int) Math.floor(totalCount * 0.02));
        int maxLogsPerSubnet = Math.max(5, (int) Math.floor(totalCount * 0.05));
        int maxLogsPerHardwareCluster = Math.max(3, (int) Math.floor(totalCount * 0.02));

        // --- REVOLUTION : Compression de Cohorte par Densité Vectorielle (Anti-Sybil / Anti-Poisoning) ---
        List<Map<String, Object>> clusteredLogs = new ArrayList<>();
        for (Map<String, Object> log : rawLogs) {
            Map<String, Object> matchedCluster = null;
            Map<String, Double> logVector = (Map<String, Double>) log.get("vector");
            String logType = (String) log.get("type");

            for (Map<String, Object> cluster : clusteredLogs) {
                Map<String, Double> clusterVector = (Map<String, Double>) cluster.get("vector");
                String clusterType = (String) cluster.get("type");

                if (Objects.equals(logType, clusterType) && getVectorDistance(logVector, clusterVector) < 5.0) {
                    matchedCluster = cluster;
                    break;
                }
            }

            if (matchedCluster != null) {
                int instancesCount = (int) matchedCluster.getOrDefault("instancesCount", 1) + 1;
                matchedCluster.put("instancesCount", instancesCount);
                matchedCluster.put("weight", 1.0 + Math.log(instancesCount)); // Compression logarithmique
            } else {
                Map<String, Object> logCopy = new HashMap<>(log);
                logCopy.put("instancesCount", 1);
                logCopy.put("weight", 1.0);
                clusteredLogs.add(logCopy);
            }
        }

        List<Map<String, Object>> suspiciousLogs = new ArrayList<>();
        List<Map<String, Object>> passedLogs = new ArrayList<>();
        Map<String, Integer> deviceCounts = new HashMap<>();
        Map<String, Integer> ipCounts = new HashMap<>();
        Map<String, Integer> subnetCounts = new HashMap<>();
        Map<String, Integer> hardwareClusterCounts = new HashMap<>();

        for (Map<String, Object> log : clusteredLogs) {
            String devId = (String) log.getOrDefault("deviceId", "anonymous");
            String ip = (String) log.getOrDefault("clientIp", "unknown");
            String subnet = getIpSubnet(ip);
            String hwCluster = getHardwareCluster(log);
            String type = (String) log.getOrDefault("type", "");

            int currentDeviceCount = deviceCounts.getOrDefault(devId, 0);
            int currentIpCount = ipCounts.getOrDefault(ip, 0);
            int currentSubnetCount = subnetCounts.getOrDefault(subnet, 0);
            int currentHwClusterCount = hardwareClusterCounts.getOrDefault(hwCluster, 0);

            if (currentDeviceCount < maxLogsPerDevice
                    && ("unknown".equals(ip) || currentIpCount < maxLogsPerIp)
                    && ("unknown-subnet".equals(subnet) || currentSubnetCount < maxLogsPerSubnet)
                    && currentHwClusterCount < maxLogsPerHardwareCluster) {

                deviceCounts.put(devId, currentDeviceCount + 1);
                if (!"unknown".equals(ip)) ipCounts.put(ip, currentIpCount + 1);
                if (!"unknown-subnet".equals(subnet)) subnetCounts.put(subnet, currentSubnetCount + 1);
                hardwareClusterCounts.put(hwCluster, currentHwClusterCount + 1);

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
                } else if ("patterns".equals(type)) {
                    if (key.equals("benfordThreshold")) {
                        updated = Math.max(0.05, Math.min(0.30, updated));
                    } else if (key.equals("decayFactor")) {
                        updated = Math.max(0.70, Math.min(0.98, updated));
                    } else if (key.equals("minSamples") || key.equals("historySize")) {
                        updated = Math.max(3, Math.min(30, (int) Math.round(updated)));
                    } else if (key.endsWith("Threshold")) {
                        updated = Math.max(50, Math.min(3000, (int) Math.round(updated)));
                    }
                    current.put(key, updated);
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

        for (Map.Entry<String, Object> entry : engine.getWeights().entrySet()) {
            double baseW = ((Number) entry.getValue()).doubleValue();
            ind.weights.put(entry.getKey(), baseW * (0.75 + rand.nextDouble() * 0.5)); // +/- 25%
        }
        for (Map.Entry<String, Object> entry : engine.getPatterns().entrySet()) {
            if (entry.getValue() instanceof Number) {
                ind.patterns.put(entry.getKey(), ((Number) entry.getValue()).doubleValue() * (0.75 + rand.nextDouble() * 0.5));
            }
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
        for (String key : p1.patterns.keySet()) {
            child.patterns.put(key, (((Number)p1.patterns.get(key)).doubleValue() + ((Number)p2.patterns.get(key)).doubleValue()) / 2.0);
        }
        return child;
    }

    private void mutate(Individual ind, Random rand) {
        double rVal = rand.nextDouble();
        String sectionToMutate = "patterns";
        if (rVal < 0.50) {
            sectionToMutate = "patterns";
        } else if (rVal < 0.75) {
            sectionToMutate = "thresholds";
        } else {
            sectionToMutate = "weights";
        }

        if ("weights".equals(sectionToMutate)) {
            String[] wKeys = ind.weights.keySet().toArray(new String[0]);
            if (wKeys.length > 0) {
                String k = wKeys[rand.nextInt(wKeys.length)];
                double mutatedWeight = ind.weights.get(k) + (rand.nextDouble() - 0.5) * 0.1;
                ind.weights.put(k, Math.max(0.05, Math.min(1.5, mutatedWeight)));
            }
        } else if ("thresholds".equals(sectionToMutate)) {
            String[] tKeys = ind.thresholds.keySet().toArray(new String[0]);
            if (tKeys.length > 0) {
                String k = tKeys[rand.nextInt(tKeys.length)];
                int mutatedThreshold = (int) Math.round(ind.thresholds.get(k) + (rand.nextDouble() - 0.5) * 5.0);
                ind.thresholds.put(k, Math.max(10, mutatedThreshold));
            }
        } else if ("patterns".equals(sectionToMutate)) {
            String[] pKeys = ind.patterns.keySet().stream().filter(k -> ind.patterns.get(k) instanceof Number).toArray(String[]::new);
            if (pKeys.length > 0) {
                String k = pKeys[rand.nextInt(pKeys.length)];
                double mutatedPattern = ((Number)ind.patterns.get(k)).doubleValue() * (0.9 + rand.nextDouble() * 0.2);
                ind.patterns.put(k, mutatedPattern);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private double[] evaluateFitness(Map<String, ?> thresholds, Map<String, ?> weights, List<Map<String, Object>> trafficData) {
        Map<String, List<String>> threatIndicators = new HashMap<>();
        threatIndicators.put("account_takeover", Arrays.asList("requestPatternScore", "behaviorScore", "timeInconsistencyScore", "clickVarianceScore"));
        threatIndicators.put("active_exploitation", Arrays.asList("honeypotScore", "headerAnomalyScore"));
        threatIndicators.put("mass_scraping", Arrays.asList("requestPatternScore", "renderingAnomalyScore", "clientHintsInconsistencyScore", "virtualizationScore"));
        threatIndicators.put("distributed_botnets", Arrays.asList("subnetScore", "botnetClusterScore", "ipReputationScore", "tlsSpoofingScore"));
        threatIndicators.put("basic_automation", Arrays.asList("botScore", "tlsSpoofingScore", "tcpAnomalyScore", "virtualizationScore"));

        Map<String, String> threatTargetThreshold = new HashMap<>();
        threatTargetThreshold.put("account_takeover", "block");
        threatTargetThreshold.put("active_exploitation", "block");
        threatTargetThreshold.put("mass_scraping", "low");
        threatTargetThreshold.put("distributed_botnets", "high");
        threatTargetThreshold.put("basic_automation", "medium");

        Map<String, Double> threatImportance = new HashMap<>();
        threatImportance.put("account_takeover", 10.0);
        threatImportance.put("active_exploitation", 8.0);
        threatImportance.put("mass_scraping", 3.0);
        threatImportance.put("distributed_botnets", 6.0);
        threatImportance.put("basic_automation", 5.0);

        Map<String, Double> threatUxRatio = new HashMap<>();
        threatUxRatio.put("account_takeover", 0.1);
        threatUxRatio.put("active_exploitation", 0.2);
        threatUxRatio.put("mass_scraping", 0.8);
        threatUxRatio.put("distributed_botnets", 0.5);
        threatUxRatio.put("basic_automation", 0.4);

        Map<String, double[]> threatStats = new HashMap<>();
        for (String key : threatIndicators.keySet()) {
            threatStats.put(key, new double[4]); // [fp, fn, totalHumans, totalBots]
        }

        double maxHumanScore = 0.0;
        double minBotScore = 100.0;

        for (Map<String, Object> log : trafficData) {
            String type = (String) log.get("type");
            Map<String, Double> vector = (Map<String, Double>) log.get("vector");

            double score = 0.0;
            for (String wKey : weights.keySet()) {
                score += vector.getOrDefault(wKey, 0.0) * ((Number) weights.get(wKey)).doubleValue();
            }

            boolean isLikelyBot = "request_blocked".equals(type) || "trap_triggered".equals(type) || "challenge_issued".equals(type);
            boolean isLikelyHuman = "request_passed".equals(type) || "challenge_solved".equals(type);

            if (isLikelyBot) {
                minBotScore = Math.min(minBotScore, score);
            } else if (isLikelyHuman) {
                maxHumanScore = Math.max(maxHumanScore, score);
            }

            for (String threatName : threatIndicators.keySet()) {
                double threatActivity = 0.0;
                for (String indKey : threatIndicators.get(threatName)) {
                    threatActivity += vector.getOrDefault(indKey, 0.0);
                }
                if (threatActivity <= 0.0) {
                    continue;
                }
                double effectiveConfidence = 1.0 * (threatActivity / 100.0);
                String targetKey = threatTargetThreshold.get(threatName);
                Object thresholdVal = thresholds.get(targetKey);
                double targetThreshold = (thresholdVal instanceof Number) ? ((Number) thresholdVal).doubleValue() : 20.0;

                double[] stats = threatStats.get(threatName);
                if (isLikelyBot) {
                    stats[3] += effectiveConfidence; // totalBots
                    if (score < targetThreshold) {
                        stats[1] += effectiveConfidence; // fn
                    }
                } else if (isLikelyHuman) {
                    stats[2] += effectiveConfidence; // totalHumans
                    if (score >= targetThreshold) {
                        stats[0] += effectiveConfidence; // fp
                    }
                }
            }
        }

        double weightedFpr = 0.0;
        double weightedFnr = 0.0;
        double totalImportance = 0.0;
        for (double val : threatImportance.values()) {
            totalImportance += val;
        }

        for (String threatName : threatIndicators.keySet()) {
            double[] stats = threatStats.get(threatName);
            double fpr = stats[2] > 0 ? stats[0] / stats[2] : 0.0;
            double fnr = stats[3] > 0 ? stats[1] / stats[3] : 0.0;

            double importanceWeight = threatImportance.get(threatName) / totalImportance;
            double uxRatio = threatUxRatio.get(threatName);
            double secRatio = 1.0 - uxRatio;

            weightedFpr += fpr * importanceWeight * uxRatio;
            weightedFnr += fnr * importanceWeight * secRatio;
        }

        double marginOverlap = Math.max(0.0, maxHumanScore - minBotScore);
        double marginPenalty = marginOverlap / 100.0;

        return new double[]{weightedFpr, weightedFnr + marginPenalty};
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
        Map<String, Double> patterns = new HashMap<>();
        double[] objectives = new double[2];
        int rank = 0;
        int dominationCount = 0;
        List<Individual> dominatedSolutions = new ArrayList<>();
        double crowdingDistance = 0.0;
    }
}