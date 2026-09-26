package com.anonympins.fingerprint.utils;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.net.InetAddress;
import java.security.NoSuchAlgorithmException;
import java.net.UnknownHostException;

import com.anonympins.fingerprint.FingerprintBuilder;
import com.anonympins.fingerprint.IStore;
import com.anonympins.fingerprint.RequestContext;

public class RequestUtils {

    @SuppressWarnings("unchecked")
    public static Map<String, Double> getBehavioralIndicators(RequestContext context, Map<String, Object> deviceData) {
        Map<String, Double> result = new HashMap<>();
        double historyScore = 0.0;
        double rotationScore = 0.0;

        if (deviceData != null) {
            long now = System.currentTimeMillis();
            String clientIp = context.clientIp;
            String currentFpHash = getCompositeDeviceHash(context);

            long rapidChangeThresholdMs = 2000L;
            int maxRapidChanges = 3;

            String lastFpHash = (String) deviceData.get("lastFpHash");
            int rapidChangeCount = ((Number) deviceData.getOrDefault("rapidChangeCount", 0)).intValue();
            long lastChangeTimestamp = ((Number) deviceData.getOrDefault("lastChangeTimestamp", 0L)).longValue();

            if (lastFpHash != null && !currentFpHash.equals(lastFpHash)) {
                String stable1 = extractStablePart(lastFpHash);
                String stable2 = extractStablePart(currentFpHash);

                long timeSinceLastChange = now - lastChangeTimestamp;

                if (!stable1.equals(stable2)) {
                    if (timeSinceLastChange < rapidChangeThresholdMs) {
                        rapidChangeCount++;
                    } else {
                        rapidChangeCount = Math.max(0, rapidChangeCount - 1);
                    }
                    lastChangeTimestamp = now;
                }
            } else if (lastFpHash == null) {
                lastChangeTimestamp = now;
            }

            deviceData.put("rapidChangeCount", rapidChangeCount);
            deviceData.put("lastChangeTimestamp", lastChangeTimestamp);
            deviceData.put("lastFpHash", currentFpHash);

            Set<String> ips = (Set<String>) deviceData.get("ips");
            if (ips == null) {
                ips = new HashSet<>();
                deviceData.put("ips", ips);
            }
            ips.add(clientIp);

            Map<String, Long> ipTimes = (Map<String, Long>) deviceData.get("ipTimes");
            if (ipTimes == null) {
                ipTimes = new HashMap<>();
                deviceData.put("ipTimes", ipTimes);
            }
            ipTimes.put(clientIp, now);

            long slidingWindow = 2L * 3600L * 1000L; // 2 heures
            long cutOff = now - slidingWindow;

            Iterator<Map.Entry<String, Long>> iterator = ipTimes.entrySet().iterator();
            while (iterator.hasNext()) {
                Map.Entry<String, Long> entry = iterator.next();
                if (entry.getValue() < cutOff) {
                    ips.remove(entry.getKey());
                    iterator.remove();
                }
            }

            historyScore = Math.min(100.0, (Math.max(0, ips.size() - 3) / 15.0) * 100.0);
            rotationScore = Math.min(100.0, (rapidChangeCount / (double) maxRapidChanges) * 100.0);
        }

        result.put("historyScore", historyScore);
        result.put("rotationScore", rotationScore);
        return result;
    }

    public static Map<String, Double> getHeaderAnomalies(RequestContext context) {
        Map<String, Double> result = new HashMap<>();
        double score = 0.0;
        String ua = context.getHeader("user-agent");
        String host = context.getHeader("host");
        if (ua == null || host == null) {
            score = 100.0;
        }
        result.put("headerAnomalyScore", score);
        return result;
    }

    public static Map<String, Double> getTlsSpoofingScore(RequestContext context) {
        Map<String, Double> result = new HashMap<>();
        double score = 0.0;
        if (context.tlsSessionId != null && context.tlsSessionId.length() < 10) {
            score = 50.0;
        }
        result.put("tlsSpoofingScore", score);
        return result;
    }

    public static Map<String, Double> getTimeInconsistencyScore(RequestContext context) {
        Map<String, Double> result = new HashMap<>();
        double score = 0.0;
        String clientTimeStr = context.getHeader("x-client-time");
        if (clientTimeStr != null) {
            try {
                long clientTime = Long.parseLong(clientTimeStr);
                long serverTime = System.currentTimeMillis();
                long diff = Math.abs(serverTime - clientTime);
                // Si l'écart dépasse 5 minutes, on calcule un score de suspicion proportionnel
                if (diff > 300000) {
                    score = Math.min(100.0, (diff - 300000) / 6000.0);
                }
            } catch (NumberFormatException e) {
                score = 50.0; // Format invalide suspect
            }
        }
        result.put("timeInconsistencyScore", score);
        return result;
    }

    public static Map<String, Double> getCrossLayerInconsistency(RequestContext context) {
        Map<String, Double> result = new HashMap<>();
        double score = 0.0;
        String userAgent = context.getHeader("user-agent");
        String secChUa = context.getHeader("sec-ch-ua");
        String clientFpString = context.getHeader("x-device-fingerprint");

        // 1. Incohérence entre les informations d'un User-Agent classique et les Client Hints
        if (userAgent != null && secChUa != null) {
            boolean isChromeInUA = userAgent.contains("Chrome");
            boolean isChromeInCH = secChUa.contains("Chrome") || secChUa.contains("Google Chrome");
            if (isChromeInUA != isChromeInCH) {
                score = Math.max(score, 80.0);
            }
        }

        if (clientFpString != null && !clientFpString.isEmpty()) {
            Map<String, String> clientFpMap = parseFingerprint(clientFpString);

            // 2. Incohérence de l'OS (client vs serveur)
            String clientOsHash = clientFpMap.get("os");
            if (clientOsHash != null && userAgent != null) {
                Map<String, String> serverOsParts = parseUserAgent(userAgent);
                if (serverOsParts.containsKey("os") && !clientOsHash.equals(FingerprintBuilder.cyrb53(serverOsParts.get("os"), 0))) {
                    score = Math.max(score, 50.0);
                }
            }

            // 3. Incohérence de l'écran (viewport vs résolution physique)
            String clientScreenHash = clientFpMap.get("scr");
            String viewportWidthHeader = context.getHeader("sec-ch-viewport-width");
            if (clientScreenHash != null && viewportWidthHeader != null) {
                try {
                    int viewportWidth = Integer.parseInt(viewportWidthHeader);
                    // Cette logique est simplifiée. Une implémentation complète nécessiterait une base de données de hash de résolutions.
                    // Pour l'exemple, on suppose qu'on peut extraire la largeur.
                    // Si le viewport est plus grand que l'écran physique, c'est une anomalie.
                    // (Simulation, car on ne peut pas dé-hasher `clientScreenHash` simplement)
                } catch (NumberFormatException e) {
                    // ignore
                }
            }

            // 4. Incohérence GPU vs JA3
            String clientGpuHash = clientFpMap.get("gpu");
            String ja3 = context.ja3;
            if (clientGpuHash != null && ja3 != null) {
                // Une implémentation complète nécessiterait une base de données de correspondances connues.
                // Exemple simplifié : si le JA3 est celui d'une librairie (Python, Go) mais qu'un GPU est rapporté, c'est suspect.
                if (isKnownLibraryJa3(ja3)) {
                    score = Math.max(score, 30.0);
                }
            }
        }

        // 5. Incohérence TCP vs User-Agent (si le score TCP est déjà calculé et élevé)
        if (context.preCalculatedVector != null) {
            double tcpAnomalyScore = context.preCalculatedVector.getOrDefault("tcpAnomalyScore", 0.0);
            if (tcpAnomalyScore > 70.0) {
                // L'OS de la pile réseau ne correspond pas à l'OS du User-Agent.
                // On augmente le score d'incohérence globale.
                score = 80.0;
            }
        }
        result.put("crossLayerInconsistencyScore", score);
        return result;
    }

    private static Map<String, String> parseFingerprint(String fpStr) {
        Map<String, String> map = new HashMap<>();
        if (fpStr == null || fpStr.isEmpty()) return map;
        for (String part : fpStr.split("\\|")) {
            String[] pair = part.split(":", 2);
            if (pair.length == 2 && !pair[0].isEmpty() && !pair[1].isEmpty()) {
                map.put(pair[0], pair[1]);
            }
        }
        return map;
    }

    private static Map<String, String> parseUserAgent(String ua) {
        Map<String, String> result = new HashMap<>();
        if (ua == null) {
            return result;
        }

        // Browser detection
        if (ua.contains("Chrome") && !ua.contains("Edg")) {
            result.put("browser", "Chrome");
        } else if (ua.contains("Firefox")) {
            result.put("browser", "Firefox");
        } else if (ua.contains("Safari") && !ua.contains("Chrome")) {
            result.put("browser", "Safari");
        } else if (ua.contains("Edg")) {
            result.put("browser", "Edge");
        }

        // OS detection
        if (ua.contains("Windows")) {
            result.put("os", "Windows");
        } else if (ua.contains("Macintosh") || ua.contains("Mac OS X")) {
            result.put("os", "macOS");
        } else if (ua.contains("Linux") && !ua.contains("Android")) {
            result.put("os", "Linux");
        } else if (ua.contains("Android")) {
            result.put("os", "Android");
        } else if (ua.contains("iPhone") || ua.contains("iPad")) {
            result.put("os", "iOS");
        }

        // Device type detection
        if (ua.contains("Mobile")) {
            result.put("device", "mobile");
        } else {
            result.put("device", "desktop");
        }

        return result;
    }

    private static boolean isKnownLibraryJa3(String ja3) {
        // Liste simplifiée de hashs JA3 connus pour des librairies non-navigateurs
        Set<String> libraryHashes = new HashSet<>(Arrays.asList(
            "47344a349b75c4e82333475553b5f358", // Python
            "b29587b8a143c42546133ad7704b3310"  // Go
        ));
        return libraryHashes.contains(ja3);
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Double> getRequestPatternScore(RequestContext context, Map<String, Object> deviceData, Map<String, Object> patternsConfig) {
        Map<String, Double> result = new HashMap<>();
        double score = 0.0;
        
        if (deviceData != null) {
            List<Map<String, Object>> history = (List<Map<String, Object>>) deviceData.get("requestHistory");
            if (history != null) {
                long now = System.currentTimeMillis();
                long lastRequest = (long) deviceData.getOrDefault("lastUpdate", now);
                long interval = now - lastRequest;
                
                // Détection de requêtes trop rapides
                if (interval < 100) {
                    score += 40.0;
                }
                
                Map<String, Object> currentReq = new HashMap<>();
                currentReq.put("timestamp", now);
                currentReq.put("path", context.getHeader("x-request-uri"));
                history.add(currentReq);
                if (history.size() > 10) {
                    history.remove(0);
                }
                
                // Détection d'un bot programmé (intervalles fixes / écart-type ultra-faible)
                if (history.size() >= 5) {
                    List<Long> intervals = new ArrayList<>();
                    for (int i = 1; i < history.size(); i++) {
                        long t1 = (long) history.get(i - 1).get("timestamp");
                        long t2 = (long) history.get(i).get("timestamp");
                        intervals.add(t2 - t1);
                    }
                    double mean = intervals.stream().mapToLong(Long::longValue).average().orElse(0.0);
                    double variance = intervals.stream()
                        .mapToDouble(val -> Math.pow(val - mean, 2))
                        .average()
                        .orElse(0.0);
                    double stdDev = Math.sqrt(variance);
                    if (stdDev < 50.0 && mean > 500.0) {
                        score += 50.0;
                    }
                }
            }
        }
        result.put("requestPatternScore", Math.min(100.0, score));
        return result;
    }

    public static Map<String, Double> getHoneypotScore(RequestContext context, Map<String, Object> honeypotConfig) {
        Map<String, Double> result = new HashMap<>();
        double score = 0.0;
        String requestPath = context.getHeader("x-request-uri");
        if (requestPath != null && honeypotConfig != null) {
            @SuppressWarnings("unchecked")
            List<String> paths = (List<String>) honeypotConfig.get("paths");
            if (paths != null) {
                for (String path : paths) {
                    if (requestPath.contains(path)) {
                        score = 100.0;
                        break;
                    }
                }
            }
        }
        result.put("honeypotScore", score);
        return result;
    }

    public static double benfordTest(List<? extends Number> numbers) {
        if (numbers == null || numbers.size() < 10) {
            return 0.0;
        }
        int[] counts = new int[10];
        int validCount = 0;
        for (Number num : numbers) {
            if (num == null) continue;
            double val = Math.abs(num.doubleValue());
            if (val == 0.0) continue;
            double log = Math.log10(val);
            double factor = Math.pow(10, Math.floor(log));
            int digit = (int) Math.floor(val / factor);
            if (digit >= 1 && digit <= 9) {
                counts[digit]++;
                validCount++;
            }
        }
        if (validCount < 10) {
            return 0.0;
        }
        double[] benfordDistribution = {0, 30.1, 17.6, 12.5, 9.7, 7.9, 6.7, 5.8, 5.1, 4.6};
        double totalDeviation = 0.0;
        for (int i = 1; i <= 9; i++) {
            double observedFrequency = ((double) counts[i] / validCount) * 100.0;
            double expectedFrequency = benfordDistribution[i];
            totalDeviation += Math.pow(observedFrequency - expectedFrequency, 2);
        }
        return Math.sqrt(totalDeviation) / 50.0;
    }

    private static Map<String, Object> analyzeMouseMovements(List<Map<String, Object>> history) {
        Map<String, Object> result = new HashMap<>();
        if (history == null || history.size() < 3) {
            result.put("avgSpeed", 0.0);
            result.put("avgAcceleration", 0.0);
            result.put("straightness", 1.0);
            result.put("pauses", 0);
            result.put("segments", new ArrayList<Double>());
            return result;
        }
        List<Map<String, Object>> segments = new ArrayList<>();
        double totalDistance = 0.0;
        int pauses = 0;
        for (int i = 1; i < history.size(); i++) {
            Map<String, Object> p1 = history.get(i - 1);
            Map<String, Object> p2 = history.get(i);
            double dx = ((Number) p2.get("x")).doubleValue() - ((Number) p1.get("x")).doubleValue();
            double dy = ((Number) p2.get("y")).doubleValue() - ((Number) p1.get("y")).doubleValue();
            double dt = ((Number) p2.get("t")).doubleValue() - ((Number) p1.get("t")).doubleValue();
            double distance = Math.sqrt(dx * dx + dy * dy);
            if (dt > 0) {
                double speed = distance / dt;
                Map<String, Object> segment = new HashMap<>();
                segment.put("distance", distance);
                segment.put("dt", dt);
                segment.put("speed", speed);
                segments.add(segment);
                totalDistance += distance;
            }
            if (dt > 100 && distance < 5) {
                pauses++;
            }
        }
        if (segments.size() < 2) {
            result.put("avgSpeed", 0.0);
            result.put("avgAcceleration", 0.0);
            result.put("straightness", 1.0);
            result.put("pauses", pauses);
            result.put("segments", new ArrayList<Double>());
            return result;
        }
        double totalTime = ((Number) history.get(history.size() - 1).get("t")).doubleValue() - ((Number) history.get(0).get("t")).doubleValue();
        double avgSpeed = 0.0;
        if (totalTime > 0) {
            double speedSum = 0.0;
            for (Map<String, Object> seg : segments) {
                speedSum += (Double) seg.get("speed");
            }
            avgSpeed = speedSum / segments.size();
        }
        double totalAbsAcceleration = 0.0;
        for (int i = 1; i < segments.size(); i++) {
            Map<String, Object> s1 = segments.get(i - 1);
            Map<String, Object> s2 = segments.get(i);
            double s2Dt = (Double) s2.get("dt");
            if (s2Dt > 0) {
                double acceleration = ((Double) s2.get("speed") - (Double) s1.get("speed")) / s2Dt;
                totalAbsAcceleration += Math.abs(acceleration);
            }
        }
        double avgAcceleration = totalAbsAcceleration / (segments.size() - 1);
        Map<String, Object> startPoint = history.get(0);
        Map<String, Object> endPoint = history.get(history.size() - 1);
        double straightDistance = Math.sqrt(Math.pow(((Number) endPoint.get("x")).doubleValue() - ((Number) startPoint.get("x")).doubleValue(), 2) +
                                            Math.pow(((Number) endPoint.get("y")).doubleValue() - ((Number) startPoint.get("y")).doubleValue(), 2));
        double straightness = totalDistance > 0 ? straightDistance / totalDistance : 1.0;
        List<Double> segmentDistances = new ArrayList<>();
        for (Map<String, Object> seg : segments) {
            segmentDistances.add((Double) seg.get("distance"));
        }
        result.put("avgSpeed", avgSpeed);
        result.put("avgAcceleration", avgAcceleration);
        result.put("straightness", straightness);
        result.put("pauses", pauses);
        result.put("segments", segmentDistances);
        return result;
    }

    private static Map<String, Object> analyzeTouchMovements(List<Map<String, Object>> history) {
        Map<String, Object> result = new HashMap<>();
        if (history == null || history.size() < 3) {
            result.put("avgSpeed", 0.0);
            result.put("avgAcceleration", 0.0);
            result.put("straightness", 1.0);
            result.put("pauses", 0);
            result.put("segments", new ArrayList<Double>());
            result.put("avgPressure", 0.0);
            result.put("avgRadius", 0.0);
            result.put("pressureVariance", 0.0);
            result.put("radiusVariance", 0.0);
            result.put("maxTouches", 1);
            return result;
        }
        List<Map<String, Object>> segments = new ArrayList<>();
        double totalDistance = 0.0;
        int pauses = 0;
        double totalPressure = 0.0;
        double totalRadius = 0.0;
        int maxTouches = 1;

        for (int i = 1; i < history.size(); i++) {
            Map<String, Object> p1 = history.get(i - 1);
            Map<String, Object> p2 = history.get(i);
            double dx = ((Number) p2.get("x")).doubleValue() - ((Number) p1.get("x")).doubleValue();
            double dy = ((Number) p2.get("y")).doubleValue() - ((Number) p1.get("y")).doubleValue();
            double dt = ((Number) p2.get("t")).doubleValue() - ((Number) p1.get("t")).doubleValue();
            double distance = Math.sqrt(dx * dx + dy * dy);

            totalPressure += p2.get("p") != null ? ((Number) p2.get("p")).doubleValue() : 0.0;
            totalRadius += p2.get("r") != null ? ((Number) p2.get("r")).doubleValue() : 0.0;
            if (p2.get("num") != null) {
                int num = ((Number) p2.get("num")).intValue();
                if (num > maxTouches) {
                    maxTouches = num;
                }
            }

            if (dt > 0) {
                double speed = distance / dt;
                Map<String, Object> segment = new HashMap<>();
                segment.put("distance", distance);
                segment.put("dt", dt);
                segment.put("speed", speed);
                segments.add(segment);
                totalDistance += distance;
            }
            if (dt > 100 && distance < 5) {
                pauses++;
            }
        }

        totalPressure += history.get(0).get("p") != null ? ((Number) history.get(0).get("p")).doubleValue() : 0.0;
        totalRadius += history.get(0).get("r") != null ? ((Number) history.get(0).get("r")).doubleValue() : 0.0;

        double avgPressure = totalPressure / history.size();
        double avgRadius = totalRadius / history.size();

        double sqDiffPressureSum = 0.0;
        double sqDiffRadiusSum = 0.0;
        for (Map<String, Object> pt : history) {
            double p = pt.get("p") != null ? ((Number) pt.get("p")).doubleValue() : 0.0;
            double r = pt.get("r") != null ? ((Number) pt.get("r")).doubleValue() : 0.0;
            sqDiffPressureSum += Math.pow(p - avgPressure, 2);
            sqDiffRadiusSum += Math.pow(r - avgRadius, 2);
        }
        double pressureVariance = sqDiffPressureSum / history.size();
        double radiusVariance = sqDiffRadiusSum / history.size();

        if (segments.size() < 2) {
            result.put("avgSpeed", 0.0);
            result.put("avgAcceleration", 0.0);
            result.put("straightness", 1.0);
            result.put("pauses", pauses);
            result.put("segments", new ArrayList<Double>());
            result.put("avgPressure", avgPressure);
            result.put("avgRadius", avgRadius);
            result.put("pressureVariance", pressureVariance);
            result.put("radiusVariance", radiusVariance);
            result.put("maxTouches", maxTouches);
            return result;
        }

        double totalTime = ((Number) history.get(history.size() - 1).get("t")).doubleValue() - ((Number) history.get(0).get("t")).doubleValue();
        double avgSpeed = 0.0;
        if (totalTime > 0) {
            double speedSum = 0.0;
            for (Map<String, Object> seg : segments) {
                speedSum += (Double) seg.get("speed");
            }
            avgSpeed = speedSum / segments.size();
        }

        double speedDtSum = 0.0;
        for (Map<String, Object> seg : segments) {
            double dt = (Double) seg.get("dt");
            if (dt > 0) {
                speedDtSum += ((Double) seg.get("speed") / dt);
            }
        }
        double avgAcceleration = speedDtSum / segments.size();

        Map<String, Object> startPoint = history.get(0);
        Map<String, Object> endPoint = history.get(history.size() - 1);
        double straightDistance = Math.sqrt(Math.pow(((Number) endPoint.get("x")).doubleValue() - ((Number) startPoint.get("x")).doubleValue(), 2) +
                                            Math.pow(((Number) endPoint.get("y")).doubleValue() - ((Number) startPoint.get("y")).doubleValue(), 2));
        double straightness = totalDistance > 0 ? straightDistance / totalDistance : 1.0;

        List<Double> segmentDistances = new ArrayList<>();
        for (Map<String, Object> seg : segments) {
            segmentDistances.add((Double) seg.get("distance"));
        }

        result.put("avgSpeed", avgSpeed);
        result.put("avgAcceleration", avgAcceleration);
        result.put("straightness", straightness);
        result.put("pauses", pauses);
        result.put("segments", segmentDistances);
        result.put("avgPressure", avgPressure);
        result.put("avgRadius", avgRadius);
        result.put("pressureVariance", pressureVariance);
        result.put("radiusVariance", radiusVariance);
        result.put("maxTouches", maxTouches);
        return result;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Double> getBehaviorScore(RequestContext context) {
        Map<String, Double> result = new HashMap<>();
        double score = 0.0;

        if (context.getHeader("x-automation-test") != null) {
            score += 90.0;
        }
        if (context.getHeader("accept") == null) {
            score += 30.0;
        }
        if (context.getHeader("accept-encoding") == null) {
            score += 20.0;
        }

        String behaviorHeader = context.getHeader("x-behavior-metrics");
        if (behaviorHeader != null && !behaviorHeader.trim().isEmpty()) {
            String trimmed = behaviorHeader.trim();
            try {
                double directScore = Double.parseDouble(trimmed);
                result.put("behaviorScore", Math.max(0.0, Math.min(100.0, directScore)));
                return result;
            } catch (NumberFormatException ignored) {
                // Pas un nombre brut, traitement du payload JSON
            }

            try {
                Map<String, Object> metrics = ChallengeUtils.simpleJsonParse(behaviorHeader);
                if (metrics != null && !metrics.isEmpty()) {
                    if (Boolean.TRUE.equals(metrics.get("honeypotInteraction"))) {
                        result.put("behaviorScore", 100.0);
                        return result;
                    }

                    if (Boolean.TRUE.equals(metrics.get("prototypeTampered"))) {
                        score += 80.0;
                    }

                    List<Map<String, Object>> mouseHistory = (List<Map<String, Object>>) metrics.get("mouseMovementsHistory");
                    List<Map<String, Object>> touchHistory = (List<Map<String, Object>>) metrics.get("touchMovementsHistory");

                    Map<String, Object> mouseAnalysis = analyzeMouseMovements(mouseHistory);
                    Map<String, Object> touchAnalysis = analyzeTouchMovements(touchHistory);

                    double mouseAvgSpeed = (Double) mouseAnalysis.get("avgSpeed");
                    double touchAvgSpeed = (Double) touchAnalysis.get("avgSpeed");
                    double keystrokeLatency = metrics.get("keystrokeLatency") != null ? ((Number) metrics.get("keystrokeLatency")).doubleValue() : 0.0;

                    if (metrics.containsKey("historyLength")) {
                        int historyLength = ((Number) metrics.get("historyLength")).intValue();
                        if (historyLength == 1) score += 15;
                        else if (historyLength >= 5) score -= 20;
                        else if (historyLength >= 2) score -= 10;
                    } else {
                        // Pénalité pour absence totale d'interaction. Un utilisateur légitime peut simplement lire la page.
                        // On applique donc une pénalité de base faible, qui est amplifiée uniquement si d'autres
                        // signaux passifs de bot (ex: rendu offscreen) sont présents.
                        if (mouseAvgSpeed == 0.0 && touchAvgSpeed == 0.0 && keystrokeLatency == 0.0) { 
                            double noInteractionPenalty = 5.0;
                            if (metrics.containsKey("rendering") && metrics.get("rendering") instanceof Map) {
                                @SuppressWarnings("unchecked")
                                Map<String, Object> rendering = (Map<String, Object>) metrics.get("rendering");
                                if (rendering != null && Boolean.TRUE.equals(rendering.get("offscreenAnom"))) noInteractionPenalty += 40.0;
                            }
                            score += noInteractionPenalty;                        }
                    }

                    if (mouseAvgSpeed > 0) {
                        if (mouseAvgSpeed > 3.0) score += 25;
                        if ((Double) mouseAnalysis.get("avgAcceleration") > 0.5) score += 20;
                        if ((Double) mouseAnalysis.get("straightness") > 0.95) score += 30;
                        if (((Integer) mouseAnalysis.get("pauses")) == 0 && ((List<?>) mouseAnalysis.get("segments")).size() > 20) score += 15;
                    }

                    if (keystrokeLatency > 0.0 && keystrokeLatency < 40.0) score += 25;
                    if (keystrokeLatency > 1000.0) score += 15;

                    // Digraphie/trigraphie (dwell & flight times)
                    List<Object> dwellTimesObj = (List<Object>) metrics.get("keystrokeDwellTimes");
                    List<Object> flightTimesObj = (List<Object>) metrics.get("keystrokeFlightTimes");

                    if (dwellTimesObj != null && dwellTimesObj.size() >= 5) {
                        List<Double> dwellTimes = new ArrayList<>();
                        for (Object o : dwellTimesObj) {
                            if (o instanceof Number) dwellTimes.add(((Number) o).doubleValue());
                        }
                        if (dwellTimes.size() >= 5) {
                            double meanDwell = dwellTimes.stream().mapToDouble(Double::doubleValue).average().orElse(0.0);
                            double varDwell = 0.0;
                            for (double d : dwellTimes) {
                                varDwell += Math.pow(d - meanDwell, 2);
                            }
                            varDwell /= dwellTimes.size();
                            double stdDevDwell = Math.sqrt(varDwell);

                            if (stdDevDwell < 2.0) {
                                score += 35.0;
                            }
                            if (meanDwell < 15.0) {
                                score += 25.0;
                            }
                        }
                    }

                    if (flightTimesObj != null && flightTimesObj.size() >= 5) {
                        List<Double> flightTimes = new ArrayList<>();
                        for (Object o : flightTimesObj) {
                            if (o instanceof Map) {
                                Map<String, Object> map = (Map<String, Object>) o;
                                if (map.containsKey("time")) {
                                    flightTimes.add(((Number) map.get("time")).doubleValue());
                                }
                            }
                        }
                        if (flightTimes.size() >= 5) {
                            double meanFlight = flightTimes.stream().mapToDouble(Double::doubleValue).average().orElse(0.0);
                            double varFlight = 0.0;
                            for (double f : flightTimes) {
                                varFlight += Math.pow(f - meanFlight, 2);
                            }
                            varFlight /= flightTimes.size();
                            double stdDevFlight = Math.sqrt(varFlight);

                            if (stdDevFlight < 3.0) {
                                score += 35.0;
                            }
                            if (meanFlight < 25.0) {
                                score += 25.0;
                            }
                            double benfordDev = benfordTest(flightTimes);
                            if (benfordDev > 0.18) {
                                score += 30.0;
                            }
                        }
                    }

                    // Benford test on mouse segments
                    List<Double> mouseSegments = (List<Double>) mouseAnalysis.get("segments");
                    if (mouseSegments != null && mouseSegments.size() > 10) {
                        double benfordDeviation = benfordTest(mouseSegments);
                        if (benfordDeviation > 0.18) {
                            score += 35.0;
                        }
                    }
                }
            } catch (Exception e) {
                score += 10.0; // Malformed header
            }
        }

        // Détection de ferme mobile : un appareil mobile parfaitement immobile est suspect, indépendamment des interactions tactiles.
        String ua = context.getHeader("user-agent");
        boolean isMobileDevice = ua != null && ua.contains("Mobile");
        if (behaviorHeader != null && behaviorHeader.startsWith("{") && isMobileDevice) {
            Map<String, Object> metrics = ChallengeUtils.simpleJsonParse(behaviorHeader);
            Object motionVariance = metrics != null ? metrics.get("motionVariance") : null;
            if (motionVariance instanceof Number && ((Number) motionVariance).doubleValue() == 0.0) score += 50.0; // Terminal fixé sur un châssis mécanique (rack ADB)
        }

        result.put("behaviorScore", Math.min(100.0, score));
        return result;
    }

    public static Map<String, Double> getBotScore(RequestContext context) {
        Map<String, Double> result = new HashMap<>();
        double score = 0.0;
        String ua = context.getHeader("user-agent");
        if (ua != null && (ua.contains("curl") || ua.contains("wget") || ua.contains("python-requests") || ua.contains("headless"))) {
            score = 100.0;
        }
        result.put("botScore", score);
        return result;
    }

    public static Map<String, Double> getClickVarianceScore(RequestContext context) {
        Map<String, Double> result = new HashMap<>();
        result.put("clickVarianceScore", 0.0);
        return result;
    }

    public static Map<String, Double> getClientHintsInconsistencyScore(RequestContext context) {
        Map<String, Double> result = new HashMap<>();
        double score = 0.0;
        String platform = context.getHeader("sec-ch-ua-platform");
        String ua = context.getHeader("user-agent");
        if (platform != null && ua != null) {
            if (platform.contains("Windows") && ua.contains("Macintosh")) {
                score = 100.0;
            }
        }
        result.put("clientHintsInconsistencyScore", score);
        return result;
    }

    public static int getIpCommonPrefixLength(String ip1, String ip2) {
        if (ip1 == null || ip2 == null || ip1.isEmpty() || ip2.isEmpty()) {
            return 0;
        }
        try {
            byte[] b1 = InetAddress.getByName(ip1).getAddress();
            byte[] b2 = InetAddress.getByName(ip2).getAddress();
            if (b1.length != b2.length) {
                return 0;
            }
            int bits = 0;
            for (int i = 0; i < b1.length; i++) {
                int xor = (b1[i] ^ b2[i]) & 0xFF;
                if (xor == 0) {
                    bits += 8;
                } else {
                    bits += Integer.numberOfLeadingZeros(xor) - 24;
                    break;
                }
            }
            return bits;
        } catch (UnknownHostException e) {
            return 0;
        }
    }

    @SuppressWarnings("unchecked")
    private static void decaySubnetData(Map<String, Object> subnetData, long now) {
        long lastActivity = ((Number) subnetData.getOrDefault("lastActivity", now)).longValue();
        long inactivitySec = now - lastActivity;
        long halfLives = inactivitySec / 1800L; // Demi-vie de 30 minutes

        if (halfLives > 0) {
            double decay = Math.pow(2, halfLives);
            int highScoreCount = ((Number) subnetData.getOrDefault("highScoreCount", 0)).intValue();
            subnetData.put("highScoreCount", Math.max(0, (int) Math.floor(highScoreCount / decay)));

            Map<String, Object> highScoreDevices = (Map<String, Object>) subnetData.get("highScoreDevices");
            if (highScoreDevices != null) {
                List<String> toRemove = new ArrayList<>();
                for (Map.Entry<String, Object> entry : highScoreDevices.entrySet()) {
                    int val = ((Number) entry.getValue()).intValue();
                    int decayedVal = (int) Math.floor(val / decay);
                    if (decayedVal <= 0) {
                        toRemove.add(entry.getKey());
                    } else {
                        entry.setValue(decayedVal);
                    }
                }
                for (String key : toRemove) {
                    highScoreDevices.remove(key);
                }
            }

            for (String field : Arrays.asList("deviceIds", "ips", "uas")) {
                List<Object> list = (List<Object>) subnetData.get(field);
                if (list != null) {
                    int newLen = Math.max(0, (int) Math.floor(list.size() / decay));
                    if (newLen < list.size()) {
                        subnetData.put(field, new ArrayList<>(list.subList(0, newLen)));
                    }
                }
            }

            List<Map<String, Object>> attackerIps = (List<Map<String, Object>>) subnetData.get("attackerIps");
            if (attackerIps != null) {
                attackerIps.removeIf(a -> {
                    long lastSeen = ((Number) a.getOrDefault("lastSeen", now)).longValue();
                    return (now - lastSeen) > 3600;
                });
            }

            subnetData.put("lastActivity", now - (inactivitySec % 1800L));
        }
    }

    @SuppressWarnings("unchecked")
    public static void updateSubnetMetrics(IStore store, RequestContext context, String deviceId, double finalScore) {
        String subnet = getIpSubnet(context.clientIp, 24, 48);
        if (subnet == null) return;

        String key = "subnet:" + subnet;
        Map<String, Object> subnetData = (Map<String, Object>) store.get(key);
        if (subnetData == null) {
            subnetData = new HashMap<>();
            subnetData.put("highScoreCount", 0);
            subnetData.put("deviceIds", new ArrayList<String>());
            subnetData.put("highScoreDevices", new HashMap<String, Integer>());
            subnetData.put("lastActivity", 0L);
            subnetData.put("ips", new ArrayList<String>());
            subnetData.put("uas", new ArrayList<String>());
            subnetData.put("attackerIps", new ArrayList<Map<String, Object>>());
        }

        if (!subnetData.containsKey("highScoreDevices")) {
            subnetData.put("highScoreDevices", new HashMap<String, Integer>());
        }
        if (!subnetData.containsKey("ips")) {
            subnetData.put("ips", new ArrayList<String>());
        }
        if (!subnetData.containsKey("uas")) {
            subnetData.put("uas", new ArrayList<String>());
        }
        if (!subnetData.containsKey("attackerIps")) {
            subnetData.put("attackerIps", new ArrayList<Map<String, Object>>());
        }

        long now = System.currentTimeMillis() / 1000L;
        decaySubnetData(subnetData, now);

        String currentDeviceHash = getCompositeDeviceHash(context);
        String stableFpId = FingerprintBuilder.cyrb53(extractStablePart(currentDeviceHash), 0);

        Map<String, Object> highScoreDevices = (Map<String, Object>) subnetData.get("highScoreDevices");
        int currentDeviceContributions = ((Number) highScoreDevices.getOrDefault(stableFpId, 0)).intValue();
        if (currentDeviceContributions < 1 && finalScore < 95) {
            highScoreDevices.put(stableFpId, currentDeviceContributions + 1);
            int highScoreCount = ((Number) subnetData.getOrDefault("highScoreCount", 0)).intValue();
            subnetData.put("highScoreCount", highScoreCount + 1);
        }

        List<String> deviceIds = (List<String>) subnetData.get("deviceIds");
        if (!deviceIds.contains(stableFpId)) {
            deviceIds.add(stableFpId);
        }

        List<String> ips = (List<String>) subnetData.get("ips");
        if (!ips.contains(context.clientIp)) {
            ips.add(context.clientIp);
        }

        String userAgent = context.getHeader("user-agent");
        List<String> uas = (List<String>) subnetData.get("uas");
        if (userAgent != null && !userAgent.isEmpty() && !uas.contains(userAgent)) {
            uas.add(userAgent);
        }

        if (finalScore >= 70.0) {
            List<Map<String, Object>> attackerIps = (List<Map<String, Object>>) subnetData.get("attackerIps");
            Map<String, Object> existing = null;
            for (Map<String, Object> a : attackerIps) {
                if (context.clientIp.equals(a.get("ip"))) {
                    existing = a;
                    break;
                }
            }
            if (existing != null) {
                existing.put("lastSeen", now);
                double prevScore = ((Number) existing.getOrDefault("score", 0.0)).doubleValue();
                existing.put("score", Math.max(prevScore, finalScore));
            } else {
                Map<String, Object> newAtt = new HashMap<>();
                newAtt.put("ip", context.clientIp);
                newAtt.put("lastSeen", now);
                newAtt.put("score", finalScore);
                attackerIps.add(newAtt);
                if (attackerIps.size() > 30) {
                    attackerIps.remove(0);
                }
            }
        }

        subnetData.put("lastActivity", now);

        if (deviceIds.size() > 100) {
            String oldDeviceId = deviceIds.remove(0);
            if (highScoreDevices.containsKey(oldDeviceId)) {
                int oldContributions = ((Number) highScoreDevices.remove(oldDeviceId)).intValue();
                int highScoreCount = ((Number) subnetData.getOrDefault("highScoreCount", 0)).intValue();
                subnetData.put("highScoreCount", Math.max(0, highScoreCount - oldContributions));
            }
        }
        if (ips.size() > 100) ips.remove(0);
        if (uas.size() > 50) uas.remove(0);

        store.set(key, subnetData, 86400);
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Double> getSubnetScore(IStore store, RequestContext context, String currentDeviceId) {
        return getSubnetScore(store, context, currentDeviceId, 45.0);
    }

    public static Map<String, Double> getSubnetScore(IStore store, RequestContext context, String currentDeviceId, double mediumThresold) {
        Map<String, Double> result = new HashMap<>();
        String subnet = getIpSubnet(context.clientIp, 24, 48);
        if (subnet == null) {
            result.put("subnetScore", 0.0);
            return result;
        }

        String key = "subnet:" + subnet;
        Map<String, Object> subnetData = (Map<String, Object>) store.get(key);
        if (subnetData == null) {
            result.put("subnetScore", 0.0);
            return result;
        }

        long now = System.currentTimeMillis() / 1000L;
        decaySubnetData(subnetData, now);

        int highScoreCount = ((Number) subnetData.getOrDefault("highScoreCount", 0)).intValue();
        List<?> deviceIds = (List<?>) subnetData.get("deviceIds");
        int deviceCount = deviceIds != null ? deviceIds.size() : 0;
        List<?> ips = (List<?>) subnetData.get("ips");
        int ipCount = ips != null ? ips.size() : 1;
        List<?> uas = (List<?>) subnetData.get("uas");
        int uaCount = uas != null ? uas.size() : 1;

        if (deviceCount == 0) {
            result.put("subnetScore", 0.0);
            return result;
        }

        // 1. Estimation Bayésienne de densité (évite les sur-réactions sur de faibles échantillons)
        double bayesianDensity = ((double) highScoreCount + 0.5) / ((double) deviceCount + 2.5);

        // 2. Dispersion IP / Terminal (CGNAT vs Proxy Pool distribué)
        double ipDispersion = Math.min(2.0, (double) ipCount / (double) deviceCount);
        double ipMultiplier = 0.6 + 0.4 * Math.tanh(ipDispersion);

        // 3. Volatilité des User-Agents (rotation de navigateurs sur matériel identique)
        double uaDispersion = Math.min(3.0, (double) Math.max(1, uaCount) / (double) deviceCount);
        double uaMultiplier = 0.7 + 0.3 * Math.tanh(uaDispersion - 1.0);

        // 4. Intensité continue de la menace (sans seuil abrupt ni dérivée nulle)
        double rawThreatIntensity = (double) highScoreCount * bayesianDensity * ipMultiplier * uaMultiplier;

        // 5. Composante 1 : Score ambiant plafonné en zone Medium (asymptote à 45.0)
        double ambientAsymptote = 48;
        double scaleFactor = 6;
        double ambientScore = ambientAsymptote * Math.tanh(rawThreatIntensity / scaleFactor);

        // 6. Composante 2 : Boost de proximité micro-réseau avec des attaquants récents (jusqu'à +55.0)
        double proximityBoost = 0.0;
        List<Map<String, Object>> attackerIps = (List<Map<String, Object>>) subnetData.get("attackerIps");
        String clientIp = context.clientIp;

        if (attackerIps != null && !attackerIps.isEmpty() && clientIp != null && !clientIp.isEmpty()) {
            int maxCommonPrefix = 0;
            boolean isV4 = !clientIp.contains(":");

            for (Map<String, Object> att : attackerIps) {
                String attIp = (String) att.get("ip");
                long lastSeen = ((Number) att.getOrDefault("lastSeen", now)).longValue();
                if (attIp != null && !attIp.isEmpty() && (now - lastSeen) <= 1800) {
                    int prefixLen = getIpCommonPrefixLength(clientIp, attIp);
                    if (prefixLen > maxCommonPrefix) {
                        maxCommonPrefix = prefixLen;
                    }
                }
            }

            if (isV4) {
                if (maxCommonPrefix >= 32) {
                    proximityBoost = 55.0;
                } else if (maxCommonPrefix >= 30) {
                    proximityBoost = 45.0;
                } else if (maxCommonPrefix >= 28) {
                    proximityBoost = 30.0;
                } else if (maxCommonPrefix >= 26) {
                    proximityBoost = 15.0;
                }
            } else {
                if (maxCommonPrefix >= 128) {
                    proximityBoost = 55.0;
                } else if (maxCommonPrefix >= 120) {
                    proximityBoost = 45.0;
                } else if (maxCommonPrefix >= 112) {
                    proximityBoost = 30.0;
                } else if (maxCommonPrefix >= 96) {
                    proximityBoost = 15.0;
                }
            }
        }

        double finalScore = Math.min(100.0, Math.round((ambientScore + proximityBoost) * 10.0) / 10.0);
        result.put("subnetScore", finalScore);
        return result;
    }

    public static String extractStablePart(String currentDeviceHash) {
        if (currentDeviceHash != null && currentDeviceHash.length() > 8) {
            return currentDeviceHash.substring(0, 8);
        }
        return currentDeviceHash != null ? currentDeviceHash : "";
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Double> getBotnetClusterScore(IStore store, RequestContext context, String stableFpHash) {
        Map<String, Double> result = new HashMap<>();
        if (stableFpHash == null || stableFpHash.isEmpty()) {
            result.put("botnetClusterScore", 0.0);
            return result;
        }

        String key = "botnet-cluster:" + stableFpHash;
        long now = System.currentTimeMillis() / 1000;
        long tenMinutesAgo = now - 600;

        List<Map<String, Object>> clusterData = (List<Map<String, Object>>) store.get(key);
        if (clusterData == null) {
            clusterData = new ArrayList<>();
        }

        List<Map<String, Object>> activeData = new ArrayList<>();
        Map<String, Object> existingEntry = null;

        for (Map<String, Object> entry : clusterData) {
            long timestamp = ((Number) entry.getOrDefault("timestamp", 0L)).longValue();
            if (timestamp > tenMinutesAgo) {
                activeData.add(entry);
                if (context.clientIp.equals(entry.get("ip"))) {
                    existingEntry = entry;
                }
            }
        }

        String userAgent = context.getHeader("user-agent");
        if (userAgent == null) userAgent = "";
        String subnet = getIpSubnet(context.clientIp, 24, 48);
        if (subnet == null) subnet = "unknown";

        if (existingEntry != null) {
            existingEntry.put("timestamp", now);
            existingEntry.put("ua", userAgent);
            existingEntry.put("subnet", subnet);
        } else {
            Map<String, Object> newEntry = new HashMap<>();
            newEntry.put("ip", context.clientIp);
            newEntry.put("timestamp", now);
            newEntry.put("ua", userAgent);
            newEntry.put("subnet", subnet);
            activeData.add(newEntry);
        }

        store.set(key, activeData, 600);

        int uniqueIpsCount = activeData.size();
        double botnetClusterScore = 0.0;
        if (uniqueIpsCount >= 2) {
            Set<String> uniqueSubnets = new HashSet<>();
            Set<String> uniqueUserAgents = new HashSet<>();

            for (Map<String, Object> entry : activeData) {
                String sub = (String) entry.get("subnet");
                String ua = (String) entry.get("ua");
                if (sub != null && !sub.isEmpty()) uniqueSubnets.add(sub);
                if (ua != null && !ua.isEmpty()) uniqueUserAgents.add(ua);
            }

            double subnetMultiplier = uniqueSubnets.size() > 1 ? 1.3 : 0.6;
            double uaRotationMultiplier = uniqueUserAgents.size() > 1 ? 1.5 : 1.0;

            double baseScore = 100.0 * (1.0 - Math.exp(-0.35 * (uniqueIpsCount - 1)));
            botnetClusterScore = Math.min(100.0, Math.round(baseScore * subnetMultiplier * uaRotationMultiplier * 10.0) / 10.0);
        }

        result.put("botnetClusterScore", botnetClusterScore);
        return result;
    }

    public static Map<String, Object> parseTcpSyn(byte[] binary) {
        if (binary == null || binary.length < 40) return null;
        int ttl = 64;
        int tcpOffset = 20;
        int version = (binary[0] & 0xFF) >> 4;

        if (version == 4) {
            ttl = binary[8] & 0xFF;
            int ihl = binary[0] & 0x0F;
            tcpOffset = ihl * 4;
        } else if (version == 6) {
            ttl = binary[7] & 0xFF;
            tcpOffset = 40;
        } else {
            tcpOffset = 0;
            ttl = 64;
        }

        if (binary.length < tcpOffset + 20) return null;

        int windowSize = ((binary[tcpOffset + 14] & 0xFF) << 8) | (binary[tcpOffset + 15] & 0xFF);
        int dataOffset = ((binary[tcpOffset + 12] & 0xFF) >> 4) * 4;
        int optionsEnd = tcpOffset + dataOffset;

        Integer mss = null;
        Integer ws = null;
        boolean sack = false;

        int i = tcpOffset + 20;
        while (i < optionsEnd && i < binary.length) {
            int optType = binary[i] & 0xFF;
            if (optType == 0) break;
            if (optType == 1) {
                i++;
                continue;
            }
            if (i + 1 >= binary.length) break;
            int optLen = binary[i + 1] & 0xFF;
            if (optLen < 2 || i + optLen > binary.length) break;

            if (optType == 2 && optLen == 4) {
                mss = ((binary[i + 2] & 0xFF) << 8) | (binary[i + 3] & 0xFF);
            } else if (optType == 3 && optLen == 3) {
                ws = binary[i + 2] & 0xFF;
            } else if (optType == 4 && optLen == 2) {
                sack = true;
            }
            i += optLen;
        }

        Map<String, Object> result = new HashMap<>();
        result.put("ttl", ttl);
        result.put("windowSize", windowSize);
        result.put("mss", mss);
        result.put("ws", ws);
        result.put("sack", sack);
        return result;
    }

    public static String classifyTcpOs(Map<String, Object> fingerprint) {
        if (fingerprint == null) return "unknown";
        int ttl = fingerprint.get("ttl") != null ? (Integer) fingerprint.get("ttl") : 64;
        int windowSize = fingerprint.get("windowSize") != null ? (Integer) fingerprint.get("windowSize") : 0;
        Integer ws = (Integer) fingerprint.get("ws");

        if (ttl > 64 && ttl <= 128) {
            return "Windows";
        }
        if (ttl > 32 && ttl <= 64) {
            if (windowSize == 29200 || windowSize == 14600 || windowSize == 5840) {
                return "Linux";
            }
            return "Linux";
        }
        if (ttl <= 64) {
            if (windowSize == 65535 && (ws != null && (ws == 6 || ws == 8 || ws == 5))) {
                return "macOS/iOS";
            }
        }
        if (ttl > 64) return "Windows";
        if (ttl > 0) return "Linux";
        return "unknown";
    }

    private static byte[] hexToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public static Map<String, Double> getTcpAnomalyScore(RequestContext context) {
        Map<String, Double> result = new HashMap<>();
        result.put("tcpAnomalyScore", 0.0);

        Map<String, Object> fp = null;
        String rawTcpBinary = context.getHeader("x-raw-tcp-binary");
        if (rawTcpBinary != null) {
            try {
                byte[] binary = hexToBytes(rawTcpBinary);
                fp = parseTcpSyn(binary);
            } catch (Exception e) {
                // ignore
            }
        }

        if (fp == null) {
            String tcpHeader = context.getHeader("x-tcp-fingerprint");
            if (tcpHeader == null) {
                tcpHeader = context.tcpFingerprint;
            }
            if (tcpHeader != null && !tcpHeader.isEmpty()) {
                String[] parts = tcpHeader.split(":");
                if (parts.length >= 2) {
                    try {
                        fp = new HashMap<>();
                        fp.put("ttl", Integer.parseInt(parts[0]));
                        fp.put("windowSize", Integer.parseInt(parts[1]));
                        fp.put("mss", parts.length > 2 && !parts[2].isEmpty() ? Integer.parseInt(parts[2]) : null);
                        fp.put("ws", parts.length > 3 && !parts[3].isEmpty() ? Integer.parseInt(parts[3]) : null);
                        fp.put("sack", parts.length > 4 && ("1".equals(parts[4]) || "true".equalsIgnoreCase(parts[4])));
                    } catch (Exception e) {
                        fp = null;
                    }
                }
            }
        }

        if (fp != null) {
            String tcpOs = classifyTcpOs(fp);
            String ua = context.getHeader("user-agent");
            if (ua == null) {
                ua = "";
            }
            Map<String, String> uaParts = parseUserAgent(ua);
            String uaOs = uaParts.get("os");

            if (uaOs != null && !"unknown".equals(tcpOs)) {
                String mappedOs = null;
                if (uaOs.startsWith("Windows")) mappedOs = "Windows";
                else if (uaOs.startsWith("Mac") || uaOs.startsWith("macOS")) mappedOs = "macOS";
                else if (uaOs.startsWith("iOS")) mappedOs = "iOS";
                else if (uaOs.startsWith("Linux")) mappedOs = "Linux";

                if (mappedOs != null) {
                    Map<String, Map<String, Object>> osExpectedTcp = new HashMap<>();
                    
                    Map<String, Object> winExpected = new HashMap<>();
                    winExpected.put("ttl", 128); winExpected.put("windowSize", 64240); winExpected.put("ws", 8); winExpected.put("mss", 1460); winExpected.put("sack", true);
                    osExpectedTcp.put("Windows", winExpected);

                    Map<String, Object> linuxExpected = new HashMap<>();
                    linuxExpected.put("ttl", 64); linuxExpected.put("windowSize", 29200); linuxExpected.put("ws", 7); linuxExpected.put("mss", 1460); linuxExpected.put("sack", true);
                    osExpectedTcp.put("Linux", linuxExpected);

                    Map<String, Object> macExpected = new HashMap<>();
                    macExpected.put("ttl", 64); macExpected.put("windowSize", 65535); macExpected.put("ws", 6); macExpected.put("mss", 1460); macExpected.put("sack", true);
                    osExpectedTcp.put("macOS", macExpected);

                    Map<String, Object> iosExpected = new HashMap<>();
                    iosExpected.put("ttl", 64); iosExpected.put("windowSize", 65535); iosExpected.put("ws", 6); iosExpected.put("mss", 1460); iosExpected.put("sack", true);
                    osExpectedTcp.put("iOS", iosExpected);

                    Map<String, Object> expected = osExpectedTcp.get(mappedOs);
                    
                    double ttlDiff = Math.abs(((Integer) fp.get("ttl")) - (Integer) expected.get("ttl")) / ((Integer) expected.get("ttl")).doubleValue();
                    double winDiff = Math.abs(((Integer) fp.get("windowSize")) - (Integer) expected.get("windowSize")) / ((Integer) expected.get("windowSize")).doubleValue();
                    
                    double wsDiff = 0.0;
                    if (expected.get("ws") != null && fp.get("ws") != null) {
                        wsDiff = Math.abs(((Integer) fp.get("ws")) - (Integer) expected.get("ws")) / ((Integer) expected.get("ws")).doubleValue();
                    }
                    
                    double mssDiff = 0.0;
                    if (expected.get("mss") != null && fp.get("mss") != null) {
                        mssDiff = Math.abs(((Integer) fp.get("mss")) - (Integer) expected.get("mss")) / ((Integer) expected.get("mss")).doubleValue();
                    }

                    boolean fpSack = fp.get("sack") == null || (Boolean) fp.get("sack");
                    boolean expSack = expected.get("sack") == null || (Boolean) expected.get("sack");
                    double sackDiff = fpSack == expSack ? 0.0 : 1.0;

                    double deviation = (
                        Math.min(1.0, ttlDiff) * 0.50 +
                        Math.min(1.0, winDiff) * 0.25 +
                        Math.min(1.0, wsDiff) * 0.15 +
                        Math.min(1.0, mssDiff) * 0.05 +
                        sackDiff * 0.05
                    );

                    double tcpAnomalyScore = 0.0;
                    if (!tcpOs.equals(mappedOs) && !"unknown".equals(tcpOs)) {
                        double baseAnomaly = "Windows".equals(mappedOs) ? 80.0 :
                                            (("macOS".equals(mappedOs) || "iOS".equals(mappedOs)) ? 85.0 : 75.0);
                        tcpAnomalyScore = baseAnomaly + (deviation - 0.4) * 10.0;
                    } else {
                        tcpAnomalyScore = deviation * 40.0;
                    }

                    result.put("tcpAnomalyScore", Math.max(0.0, Math.min(100.0, Math.round(tcpAnomalyScore * 10.0) / 10.0)));
                }
            }
        }
        return result;
    }

    public static Map<String, Double> getQuicAnomalyScore(RequestContext context) {
        Map<String, Double> result = new HashMap<>();
        result.put("quicAnomalyScore", 0.0);

        String quicFp = context.getHeader("x-quic-fp");
        if (quicFp == null) {
            quicFp = context.quicFingerprint;
        }
        if (quicFp != null && !quicFp.isEmpty()) {
            String[] parts = quicFp.split(";");
            if (parts.length >= 2) {
                Map<String, String> params = new HashMap<>();
                for (String p : parts[1].split(",")) {
                    String[] kv = p.split("=", 2);
                    if (kv.length == 2) {
                        params.put(kv[0], kv[1]);
                    }
                }
                String priorityOrder = parts.length > 2 ? parts[2] : "";
                String frameOrderRaw = parts.length > 3 ? parts[3] : (context.getHeader("x-quic-frame-order") != null ? context.getHeader("x-quic-frame-order") : "");
                List<String> frameOrder = new ArrayList<>();
                if (frameOrderRaw != null && !frameOrderRaw.isEmpty()) {
                    for (String f : frameOrderRaw.split(",")) {
                        String trimmed = f.trim().toLowerCase();
                        if (!trimmed.isEmpty()) frameOrder.add(trimmed);
                    }
                }

                String ua = context.getHeader("user-agent");
                if (ua == null) {
                    ua = "";
                }
                Map<String, String> uaParts = parseUserAgent(ua);
                String browser = uaParts.get("browser") != null ? uaParts.get("browser") : "";

                if (browser != null && !browser.isEmpty()) {
                    double anomaly = 0.0;
                    boolean isChromium = browser.startsWith("Chrome") || browser.startsWith("Edge");
                    boolean isFirefox = browser.startsWith("Firefox");
                    boolean isSafari = browser.startsWith("Safari");

                    int maxData = 0, maxStreams = 0, bidiLocal = 0, bidiRemote = 0;
                    try {
                        if (params.containsKey("1")) maxData = Integer.parseInt(params.get("1"));
                        else if (params.containsKey("0x01")) maxData = Integer.parseInt(params.get("0x01"));

                        if (params.containsKey("4")) maxStreams = Integer.parseInt(params.get("4"));
                        else if (params.containsKey("8")) maxStreams = Integer.parseInt(params.get("8"));
                        else if (params.containsKey("0x08")) maxStreams = Integer.parseInt(params.get("0x08"));

                        if (params.containsKey("5")) bidiLocal = Integer.parseInt(params.get("5"));
                        else if (params.containsKey("0x05")) bidiLocal = Integer.parseInt(params.get("0x05"));

                        if (params.containsKey("6")) bidiRemote = Integer.parseInt(params.get("6"));
                        else if (params.containsKey("0x06")) bidiRemote = Integer.parseInt(params.get("0x06"));
                    } catch (NumberFormatException ignored) {}

                    if (isChromium) {
                        if (maxData > 0 && maxData < 1048576) anomaly += 40.0;
                        if (maxStreams > 0 && maxStreams != 100) anomaly += 30.0;
                        if (priorityOrder != null && !priorityOrder.isEmpty() && !priorityOrder.contains("u=")) anomaly += 30.0;

                        if (bidiLocal > 0 && (bidiLocal < 524288 || bidiLocal == 262144)) anomaly += 40.0;
                        if (bidiRemote > 0 && (bidiRemote < 524288 || bidiRemote == 262144)) anomaly += 30.0;

                        if (frameOrder.size() >= 2) {
                            int sIdx = frameOrder.indexOf("s");
                            if (sIdx == -1) sIdx = frameOrder.indexOf("settings");
                            if (sIdx == -1) sIdx = frameOrder.indexOf("4");

                            int mIdx = frameOrder.indexOf("m");
                            if (mIdx == -1) mIdx = frameOrder.indexOf("max_streams");
                            if (mIdx == -1) mIdx = frameOrder.indexOf("18");

                            int pIdx = frameOrder.indexOf("p");
                            if (pIdx == -1) pIdx = frameOrder.indexOf("priority");
                            if (pIdx == -1) pIdx = frameOrder.indexOf("priority_update");
                            if (pIdx == -1) pIdx = frameOrder.indexOf("15");

                            if (sIdx != 0 && sIdx != -1) anomaly += 50.0;
                            if (mIdx != -1 && sIdx != -1 && mIdx < sIdx) anomaly += 60.0;
                            if (pIdx != -1 && sIdx != -1 && pIdx < sIdx) anomaly += 60.0;
                        }
                    } else if (isFirefox) {
                        if (maxData > 0 && maxData > 5000000) anomaly += 40.0;
                        if (maxStreams == 100) anomaly += 50.0;
                        if (bidiLocal == 6291456) anomaly += 50.0;
                        if (frameOrder.size() >= 2) {
                            int sIdx = frameOrder.indexOf("s");
                            if (sIdx == -1) sIdx = frameOrder.indexOf("settings");
                            if (sIdx == -1) sIdx = frameOrder.indexOf("4");
                            if (sIdx != 0 && sIdx != -1) anomaly += 50.0;
                        }
                    } else if (isSafari) {
                        if (maxStreams == 100 && maxData == 1572864 && priorityOrder != null && priorityOrder.contains("u=2,i")) {
                            anomaly += 60.0;
                        }
                        if (bidiLocal == 6291456) anomaly += 50.0;
                        if (frameOrder.size() >= 2) {
                            int sIdx = frameOrder.indexOf("s");
                            if (sIdx == -1) sIdx = frameOrder.indexOf("settings");
                            if (sIdx == -1) sIdx = frameOrder.indexOf("4");
                            int mIdx = frameOrder.indexOf("m");
                            if (mIdx == -1) mIdx = frameOrder.indexOf("max_streams");
                            if (mIdx != -1 && (mIdx == 0 || (sIdx != -1 && mIdx < sIdx))) {
                                anomaly += 50.0;
                            }
                        }
                    }
                    result.put("quicAnomalyScore", Math.max(0.0, Math.min(100.0, anomaly)));
                }
            }
        }
        return result;
    }

    public static Map<String, Double> getProtocolAnomalyScore(RequestContext context) {
        Map<String, Double> result = new HashMap<>();
        double http2Anomaly = 0.0;
        double quicAnomaly = 0.0;

        String ua = context.getHeader("user-agent");
        if (ua == null) {
            ua = "";
        }
        Map<String, String> uaParts = parseUserAgent(ua);
        String browser = uaParts.get("browser");

        if (browser != null && !browser.isEmpty()) {
            // HTTP/2 Anomaly Logic
            String h2Fp = context.getHeader("x-http2-fingerprint");
            if (h2Fp == null) {
                h2Fp = context.http2Fingerprint;
            }
            if (h2Fp != null && !h2Fp.isEmpty()) {
                String[] parts = h2Fp.split("\\|");
                if (parts.length >= 3) {
                    try {
                        int connWindow = Integer.parseInt(parts[1]);
                        String streamPriority = parts.length > 2 ? parts[2] : "";
                        String headerOrder = parts.length > 3 ? parts[3] : "";
                        boolean isChromium = browser.startsWith("Chrome") || browser.startsWith("Edge");
                        boolean isFirefox = browser.startsWith("Firefox");
                        boolean isSafari = browser.startsWith("Safari");

                        if (isChromium) {
                            if (headerOrder != null && !headerOrder.isEmpty() && !headerOrder.equals("m,a,s,p")) {
                                http2Anomaly += 60.0;
                            }
                            if (connWindow == 65535 || connWindow == 65536) {
                                http2Anomaly += 40.0;
                            }
                            if ("0".equals(streamPriority) || streamPriority.isEmpty()) {
                                http2Anomaly += 50.0;
                            }
                        } else if (isFirefox) {
                            if (headerOrder != null && !headerOrder.isEmpty() && !headerOrder.equals("m,s,p,a")) {
                                http2Anomaly += 60.0;
                            }
                        } else if (isSafari) {
                            if (headerOrder != null && !headerOrder.isEmpty() && !headerOrder.equals("m,s,p,a")) {
                                http2Anomaly += 60.0;
                            }
                        }

                        // Analyse fine des trames (PRIORITY, WINDOW_UPDATE, CONTINUATION)
                        if (parts.length >= 5) {
                            String frameCountsStr = parts[4];
                            Map<String, Integer> frameCounts = new HashMap<>();
                            for (String item : frameCountsStr.split(",")) {
                                String[] kv = item.split(":");
                                if (kv.length == 2) {
                                    try {
                                        frameCounts.put(kv[0], Integer.parseInt(kv[1]));
                                    } catch (NumberFormatException e) { /* ignore */ }
                                }
                            }

                            int priorityCount = frameCounts.getOrDefault("p", 0);
                            int windowUpdateCount = frameCounts.getOrDefault("w", 0);
                            int continuationCount = frameCounts.getOrDefault("c", 0);

                            if (isChromium) {
                                if (priorityCount == 0) http2Anomaly += 25.0; // Chrome envoie des trames PRIORITY
                                if (windowUpdateCount < 2) http2Anomaly += 20.0; // Chrome est agressif avec les WINDOW_UPDATE
                            } else if (isFirefox) {
                                if (priorityCount > 1) http2Anomaly += 20.0; // Firefox en envoie moins
                            }

                            long commaCount = headerOrder != null ? headerOrder.chars().filter(ch -> ch == ',').count() : 0;
                            if (continuationCount == 0 && commaCount > 3) {
                                http2Anomaly += 30.0; // Les bots n'envoient souvent pas de trames CONTINUATION
                            }
                        }
                    } catch (NumberFormatException e) {
                        // ignore
                    }
                }
            }

            // Délégation au module QUIC dédié pour éviter la duplication de code
            quicAnomaly = getQuicAnomalyScore(context).getOrDefault("quicAnomalyScore", 0.0);
        }

        double score = Math.max(
            0.0,
            Math.max(
                Math.min(100.0, http2Anomaly),
                Math.min(100.0, quicAnomaly)
            )
        );

        result.put("protocolAnomalyScore", score);
        result.put("http2AnomalyScore", http2Anomaly);
        result.put("quicAnomalyScore", quicAnomaly);
        return result;
    }

    public static Map<String, Double> getRenderingAnomalyScore(RequestContext context) {
        Map<String, Double> result = new HashMap<>();
        result.put("renderingAnomalyScore", 0.0);
        return result;
    }

    public static Map<String, Double> getThreatIntelScore(IStore store, String zkpY) {
        Map<String, Double> result = new HashMap<>();
        result.put("threatIntelScore", 0.0);
        if (zkpY != null && store.has("banned-zkp-y:" + zkpY)) {
            result.put("threatIntelScore", 100.0);
        }
        return result;
    }
    public static String getIpSubnet(String ip, int ipv4Prefix, int ipv6Prefix) {
        try {
            InetAddress addr = InetAddress.getByName(ip);
            byte[] bytes = addr.getAddress();
            if (bytes.length == 4) {
                if (ipv4Prefix < 0 || ipv4Prefix > 32) return null;
                byte[] mask = new byte[4];
                for (int i = 0; i < ipv4Prefix; i++) {
                    mask[i / 8] |= (byte) (1 << (7 - (i % 8)));
                }
                byte[] subnetBytes = new byte[4];
                for (int i = 0; i < 4; i++) {
                    subnetBytes[i] = (byte) (bytes[i] & mask[i]);
                }
                return InetAddress.getByAddress(subnetBytes).getHostAddress() + "/" + ipv4Prefix;
            } else if (bytes.length == 16) {
                if (ipv6Prefix < 0 || ipv6Prefix > 128) return null;
                byte[] mask = new byte[16];
                for (int i = 0; i < ipv6Prefix; i++) {
                    mask[i / 8] |= (byte) (1 << (7 - (i % 8)));
                }
                byte[] subnetBytes = new byte[16];
                for (int i = 0; i < 16; i++) {
                    subnetBytes[i] = (byte) (bytes[i] & mask[i]);
                }
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < 8; i++) {
                    int b1 = subnetBytes[i * 2] & 0xFF;
                    int b2 = subnetBytes[i * 2 + 1] & 0xFF;
                    int word = (b1 << 8) | b2;
                    sb.append(String.format("%04x", word));
                    if (i < 7) {
                        sb.append(":");
                    }
                }
                sb.append("/").append(ipv6Prefix);
                return sb.toString();
            }
        } catch (UnknownHostException e) {
            return null;
        }
        return null;
    }

    // Map IANA cipher suite names to their decimal IDs for JA3 calculation
    private static final Map<String, Integer> cipherSuiteMap = new HashMap<>();
    static {
        cipherSuiteMap.put("TLS_AES_128_GCM_SHA256", 4865);
        cipherSuiteMap.put("TLS_AES_256_GCM_SHA384", 4866);
        cipherSuiteMap.put("TLS_CHACHA20_POLY1305_SHA256", 4867);
        cipherSuiteMap.put("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 49195);
        cipherSuiteMap.put("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 49199);
        cipherSuiteMap.put("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 49196);
        cipherSuiteMap.put("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 49200);
        cipherSuiteMap.put("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", 52393);
        cipherSuiteMap.put("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 52392);
        cipherSuiteMap.put("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 49171);
        cipherSuiteMap.put("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", 49172);
        cipherSuiteMap.put("TLS_RSA_WITH_AES_128_GCM_SHA256", 156);
        cipherSuiteMap.put("TLS_RSA_WITH_AES_256_GCM_SHA384", 157);
        cipherSuiteMap.put("TLS_RSA_WITH_AES_128_CBC_SHA", 47);
        cipherSuiteMap.put("TLS_RSA_WITH_AES_256_CBC_SHA", 53);
        cipherSuiteMap.put("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", 49161);
        cipherSuiteMap.put("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", 49162);
        cipherSuiteMap.put("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", 158);
        cipherSuiteMap.put("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", 159);
        cipherSuiteMap.put("TLS_DHE_RSA_WITH_AES_128_CBC_SHA", 51);
        cipherSuiteMap.put("TLS_DHE_RSA_WITH_AES_256_CBC_SHA", 57);
        cipherSuiteMap.put("TLS_RSA_WITH_3DES_EDE_CBC_SHA", 10);
    }

    private static String md5Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            // Should not happen with MD5
            return null;
        }
    }

    /**
     * Extracts TLS fingerprints (JA3 and JA4) from request context.
     * Prioritizes headers from reverse proxies (x-ja4-hash) and falls back to JA3 calculation
     * from raw socket data if available.
     * @param context The request context.
     * @return An object containing JA3 and JA4 hashes.
     */
    public static Map<String, String> getTlsFingerprint(RequestContext context) {
        Map<String, String> tlsFingerprints = new HashMap<>();
        String ja3 = context.ja3;
        String ja4 = context.ja4;

        // 1. Prioritize JA4 hash from a trusted reverse proxy header.
        if (ja4 != null) {
            tlsFingerprints.put("ja4", ja4);
        }
        // 2. Prioritize JA3 hash from a trusted reverse proxy header.
        if (ja3 != null) {
            tlsFingerprints.put("ja3", ja3);
        }

        // 3. Fallback to calculating from raw ClientHello if available and if JA3 is not already set
        // This part would require a TLS ClientHello parser in Java, similar to the PHP/Python versions.
        // For simplicity, we assume raw ClientHello is passed as a header (X-JA3-Raw)
        // and contains comma-separated values as per JA3 spec.
        String ja3Raw = context.ja3Raw;
        if (ja3 == null && ja3Raw != null) {
            try {
                // JA3 string format: "TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats"
                // This is a simplified example. A full implementation would parse the raw TLS ClientHello bytes.
                // Assuming ja3Raw is already in the JA3 string format:
                tlsFingerprints.put("ja3", md5Hex(ja3Raw));
            } catch (Exception e) {
                // Could fail if ja3Raw is malformed.
            }
        }
        return tlsFingerprints;
    }

    public static String getCompositeDeviceHash(RequestContext context) {
        String clientFp = context.getHeader("x-device-fingerprint");
        if (clientFp == null) {
            clientFp = context.getHeader("x-hardware-fingerprint");
        }
        if (clientFp != null && !clientFp.isEmpty()) {
            return clientFp;
        }

        FingerprintBuilder srv = new FingerprintBuilder();
        
        // TLS Fingerprints
        Map<String, String> tlsFp = getTlsFingerprint(context);
        if (tlsFp.containsKey("ja3")) srv.add("ja3", tlsFp.get("ja3"));
        if (tlsFp.containsKey("ja4")) srv.add("ja4", tlsFp.get("ja4"));

        // Other headers
        String ua = context.getHeader("user-agent");
        if (ua != null) srv.add("ua", ua);

        return srv.toString();
    }

    public static double getIpReputationScore(IStore store, String clientIp) {
        return 0.0;
    }

    /**
     * Calcule le HMAC-SHA256 d'une chaîne de données avec une clé secrète.
     * @param data La chaîne de données à signer.
     * @param key La clé secrète.
     * @return La signature HMAC-SHA256 en format hexadécimal.
     */
    public static String hmacSha256(String data, String key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(secretKeySpec);
            byte[] hmacBytes = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hmacBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            System.err.println("Error calculating HMAC-SHA256: " + e.getMessage());
            return null;
        }
    }
}