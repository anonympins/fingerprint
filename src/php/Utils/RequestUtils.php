<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Utils;

use Anonympins\Fingerprint\FingerprintBuilder;
use Anonympins\Fingerprint\Optimization\Optimization;
use Anonympins\Fingerprint\RequestContext;

/**
 * Classe utilitaire pour l'analyse des requêtes et le calcul des scores de suspicion.
 */
class RequestUtils
{
    /**
     * Base de données de signatures JA3 connues.
     * @var array<string, string|string[]>
     */
    private const TLS_FINGERPRINT_DB = [
        // --- Chrome (Desktop) ---
        'e188a442b87f422c5a1e80b05399435b' => 'Chrome',
        'd8e35855049321c6042a4325c697858f' => 'Chrome',
        'a9f90958d44533748c139a5d1895b925' => 'Chrome',
        '3b5379916d2b3882253c42885956a350' => 'Chrome',
        // --- Chrome (Mobile) ---
        '59822058c95c33d2d06e52f410855c8c' => 'Chrome',
        // --- Firefox (Desktop) ---
        'b386946a5a586163c7c533636b45c355' => 'Firefox',
        '66236495a523c1785f8f3a105b248b11' => 'Firefox',
        'b73d470006575b5e35167a0b5a8540e2' => 'Firefox',
        '8443d7562933834333943465d52363cf' => 'Firefox',
        // --- Firefox (Mobile) ---
        '02720628957d38c6111a18433abe833f' => 'Firefox',
        // --- Safari & iOS (Shared TLS Stack) ---
        'b633f21d532d35967c8753c38536b4d3' => 'Safari',
        '4d7a28d5f55b359b69100a311013f03e' => ['Safari', 'Chrome', 'Firefox'],
        '8dd3d7532873575314df23c447543001' => ['Safari', 'Chrome', 'Firefox'],
        // --- Common Libraries & Bots ---
        '47344a349b75c4e82333475553b5f358' => 'Python',
        'b29587b8a143c42546133ad7704b3310' => 'Go',
        'd435b5223b2884c5a832b842637e245f' => 'Java',
        'c72366b9551263d990b7fa574225332c' => 'curl',
    ];

    /**
     * Crée un hash composite stable basé sur les caractéristiques de la requête.
     */
    public static function getCompositeDeviceHash(RequestContext $context): string
    {
        $srv = new FingerprintBuilder();

        $clientFp = $context->getHeader('x-device-fingerprint');
        if ($clientFp && str_contains($clientFp, 'cvs:')) {
            $srv->add("client_fp_hash", $clientFp);
        }

        $ua = $context->getHeader("user-agent");
        if ($ua) {
            $srv->add("ua", $ua);
        }

        if ($context->ja3) $srv->add("ja3", $context->ja3);
        if ($context->ja4) $srv->add("ja4", $context->ja4);
        if ($context->http2Fingerprint) $srv->add("h2", $context->http2Fingerprint);
        if ($context->tcpFingerprint) $srv->add("tcp", $context->tcpFingerprint);

        $headersToCapture = [
            "ch_ua" => "sec-ch-ua",
            "ch_platform" => "sec-ch-ua-platform",
            "ch_mobile" => "sec-ch-ua-mobile",
            "ch_model" => "sec-ch-ua-model",
            "ch_arch" => "sec-ch-ua-arch",
            "ch_bitness" => "sec-ch-ua-bitness",
            "upgrade_req" => "upgrade-insecure-requests",
            "accept_lang" => "accept-language",
            "accept_enc" => "accept-encoding",
            "accept" => "accept"
        ];

        foreach ($headersToCapture as $key => $headerName) {
            $headerValue = $context->getHeader($headerName);
            if ($headerValue) {
                $srv->add($key, $headerValue);
            }
        }

        if ($context->httpVersion) {
            $srv->add("http_ver", $context->httpVersion);
        }
        if (!empty($context->cookies)) {
            $cookieKeys = array_keys($context->cookies);
            sort($cookieKeys);
            $srv->add("cookie_keys", implode(',', $cookieKeys));
        }

        return (string)$srv;
    }

    /**
     * Calcule un score d'incohérence entre la signature TLS (JA3) et le User-Agent.
     * @return array{'tlsSpoofingScore': float}
     */
    public static function getTlsSpoofingScore(RequestContext $context): array
    {
        $ja3 = $context->ja3;
        $ua = $context->getHeader('user-agent') ?? '';

        if ($ja3 && (empty($ua) || strlen($ua) < 10 || stripos($ua, 'python') !== false || stripos($ua, 'curl') !== false)) {
            return ['tlsSpoofingScore' => 50.0];
        }

        if ($ja3 && !empty($ua) && isset(self::TLS_FINGERPRINT_DB[$ja3])) {
            $expectedBrowsers = self::TLS_FINGERPRINT_DB[$ja3];
            if (!is_array($expectedBrowsers)) {
                $expectedBrowsers = [$expectedBrowsers];
            }

            $claimedBrowserInfo = self::parseUserAgent($ua);
            $claimedBrowser = $claimedBrowserInfo['browser'] ?? null;

            if ($claimedBrowser) {
                $isMatch = false;
                foreach ($expectedBrowsers as $expected) {
                    if (str_starts_with($claimedBrowser, $expected)) {
                        $isMatch = true;
                        break;
                    }
                }
                if (!$isMatch) {
                    return ['tlsSpoofingScore' => 80.0];
                }
            }
        }

        return ['tlsSpoofingScore' => 0.0];
    }

    /**
     * Calcule un score basé sur les anomalies des en-têtes HTTP.
     * @return array{'headerAnomalyScore': float}
     */
    public static function getHeaderAnomalies(RequestContext $context): array
    {
        $anomalyScore = 0;
        $ua = $context->getHeader('user-agent');
        if (empty($ua) || strlen($ua) < 10) {
            $anomalyScore += 60;
        }
        if (!$context->getHeader('accept-language')) {
            $anomalyScore += 25;
        }
        if ($context->httpVersion === '1.0') {
            $anomalyScore += 15;
        }

        return ['headerAnomalyScore' => min(100.0, $anomalyScore)];
    }

    /**
     * Calcule un score basé sur la détection de marqueurs d'automatisation.
     * @return array{'botScore': float}
     */
    public static function getBotScore(RequestContext $context): array
    {
        $clientFpString = $context->getHeader('x-device-fingerprint');
        if (!$clientFpString) {
            return ['botScore' => 0.0];
        }

        // Une simple vérification par chaîne est suffisante et performante.
        if (str_contains($clientFpString, 'bot:true') || str_contains($clientFpString, 'cdp:true')) {
            return ['botScore' => 100.0];
        }

        return ['botScore' => 0.0];
    }

    /**
     * @private
     * Analyse une série de mouvements de souris pour en extraire des métriques comportementales.
     * @param array<int, array{x: int, y: int, t: float}>|null $history
     * @return array{avgSpeed: float, avgAcceleration: float, straightness: float, pauses: int, segments: array<float>}
     */
    private static function analyzeMouseMovements(?array $history): array
    {
        if (empty($history) || count($history) < 3) {
            return ['avgSpeed' => 0, 'avgAcceleration' => 0, 'straightness' => 1, 'pauses' => 0, 'segments' => []];
        }

        $segments = [];
        $totalDistance = 0.0;
        $pauses = 0;

        for ($i = 1; $i < count($history); $i++) {
            $p1 = $history[$i - 1];
            $p2 = $history[$i];
            $dx = $p2['x'] - $p1['x'];
            $dy = $p2['y'] - $p1['y'];
            $dt = $p2['t'] - $p1['t'];
            $distance = sqrt($dx * $dx + $dy * $dy);

            if ($dt > 0) {
                $speed = $distance / $dt;
                $segments[] = ['distance' => $distance, 'dt' => $dt, 'speed' => $speed];
                $totalDistance += $distance;
            }
            if ($dt > 100 && $distance < 5) {
                $pauses++;
            }
        }

        if (count($segments) < 2) {
            return ['avgSpeed' => 0, 'avgAcceleration' => 0, 'straightness' => 1, 'pauses' => $pauses, 'segments' => []];
        }

        $totalTime = $history[count($history) - 1]['t'] - $history[0]['t'];
        $avgSpeed = $totalTime > 0 ? array_sum(array_column($segments, 'speed')) / count($segments) : 0;

        $totalAbsAcceleration = 0.0;
        for ($i = 1; $i < count($segments); $i++) {
            $s1 = $segments[$i - 1];
            $s2 = $segments[$i];
            if ($s2['dt'] > 0) {
                $acceleration = ($s2['speed'] - $s1['speed']) / $s2['dt'];
                $totalAbsAcceleration += abs($acceleration);
            }
        }
        $avgAcceleration = $totalAbsAcceleration / (count($segments) - 1);

        $startPoint = $history[0];
        $endPoint = $history[count($history) - 1];
        $straightDistance = sqrt(pow($endPoint['x'] - $startPoint['x'], 2) + pow($endPoint['y'] - $startPoint['y'], 2));
        $straightness = $totalDistance > 0 ? $straightDistance / $totalDistance : 1;

        return ['avgSpeed' => $avgSpeed, 'avgAcceleration' => $avgAcceleration, 'straightness' => $straightness, 'pauses' => $pauses, 'segments' => array_column($segments, 'distance')];
    }


    /**
     * Calcule un score basé sur les métriques comportementales envoyées par le client.
     * @return array{'behaviorScore': float}
     */
    public static function getBehaviorScore(RequestContext $context): array
    {
        $behaviorHeader = $context->getHeader('x-behavior-metrics');
        if (!$behaviorHeader) {
            return ['behaviorScore' => 0.0];
        }

        $metrics = json_decode($behaviorHeader, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            return ['behaviorScore' => 10.0]; // En-tête malformé
        }

        if (!empty($metrics['honeypotInteraction'])) {
            return ['behaviorScore' => 100.0];
        }

        $score = 0.0;

        $mouseAnalysis = self::analyzeMouseMovements($metrics['mouseMovementsHistory'] ?? null);

        if (isset($metrics['historyLength'])) {
            if ($metrics['historyLength'] === 1) $score += 15;
            elseif ($metrics['historyLength'] >= 5) $score -= 20;
            elseif ($metrics['historyLength'] >= 2) $score -= 10;
        } else {
            // Pénalité pour absence totale d'interaction si l'historique n'est pas dispo
            if ($mouseAnalysis['avgSpeed'] == 0 && ($metrics['keystrokeLatency'] ?? 0) == 0) {
                $score += 40;
            }
        }

        if ($mouseAnalysis['avgSpeed'] > 0) {
            if ($mouseAnalysis['avgSpeed'] > 3) $score += 25;
            if ($mouseAnalysis['avgAcceleration'] > 0.5) $score += 20;
            if ($mouseAnalysis['straightness'] > 0.95) $score += 30;
            if ($mouseAnalysis['pauses'] === 0 && count($mouseAnalysis['segments']) > 20) $score += 15;
        }

        if (($metrics['keystrokeLatency'] ?? 0) > 0 && $metrics['keystrokeLatency'] < 40) $score += 25;
        if (($metrics['keystrokeLatency'] ?? 0) > 1000) $score += 15;

        // Analyse de Benford sur les segments de mouvement de la souris
        if (count($mouseAnalysis['segments']) > 10) {
            $benfordDeviation = Optimization::benfordTest($mouseAnalysis['segments']);
            if ($benfordDeviation > 0.18) {
                $score += 35;
            }
        }

        return ['behaviorScore' => min(100.0, $score)];
    }

    /**
     * Analyse basique d'un User-Agent.
     * @return array{browser?: string, os?: string, device?: string}
     */
    private static function parseUserAgent(string $ua): array
    {
        $result = [];

        if (str_contains($ua, 'Chrome') && !str_contains($ua, 'Edg')) {
            $result['browser'] = 'Chrome';
        } elseif (str_contains($ua, 'Firefox')) {
            $result['browser'] = 'Firefox';
        } elseif (str_contains($ua, 'Safari') && !str_contains($ua, 'Chrome')) {
            $result['browser'] = 'Safari';
        } elseif (str_contains($ua, 'Edg')) {
            $result['browser'] = 'Edge';
        }

        if (str_contains($ua, 'Windows NT 10.0')) $result['os'] = 'Windows';
        elseif (str_contains($ua, 'Mac OS X')) $result['os'] = 'macOS';
        elseif (str_contains($ua, 'Android')) $result['os'] = 'Android';
        elseif (str_contains($ua, 'iPhone') || str_contains($ua, 'iPad')) $result['os'] = 'iOS';
        elseif (str_contains($ua, 'Linux')) $result['os'] = 'Linux';

        if (str_contains($ua, 'Mobile')) $result['device'] = 'mobile';
        else $result['device'] = 'desktop';

        return $result;
    }

    /**
     * Calcule un score d'incohérence temporelle.
     * @return array{'timeInconsistencyScore': float}
     * @param RequestContext $context
     * @param array|null $metrics
     */
    public static function getTimeInconsistencyScore(RequestContext $context, ?array $metrics = null): array
    {
        if ($metrics === null) {
            $behaviorHeader = $context->getHeader('x-behavior-metrics');
            if (!$behaviorHeader) return ['timeInconsistencyScore' => 0.0];
            $metrics = json_decode($behaviorHeader, true);
        }

        if (!is_array($metrics) || empty($metrics['clientTimestamp'])) {
            return ['timeInconsistencyScore' => 0.0];
        }

        $timeDelta = $context->requestTimestamp - $metrics['clientTimestamp'];
        $replayThreshold = 5000; // 5 secondes

        $score = ($timeDelta > $replayThreshold) ? min(100.0, ($timeDelta / $replayThreshold - 1) * 50) : 0.0;
        return ['timeInconsistencyScore' => $score];
    }

    /**
     * Calcule un score d'incohérence entre les couches client et serveur.
     * @return array{'crossLayerInconsistencyScore': float}
     */
    public static function getCrossLayerInconsistency(RequestContext $context): array
    {
        $clientFpString = $context->getHeader('x-device-fingerprint');
        if (!$clientFpString) return ['crossLayerInconsistencyScore' => 0.0];

        $clientFpMap = [];
        foreach (explode('|', $clientFpString) as $part) {
            $pair = explode(':', $part, 2);
            if (count($pair) === 2) $clientFpMap[$pair[0]] = $pair[1];
        }

        $ua = $context->getHeader('user-agent') ?? '';
        $score = 0;

        $clientOsHash = $clientFpMap['os'] ?? null;
        if ($clientOsHash) {
            $serverOsParts = self::parseUserAgent($ua);
            if (!empty($serverOsParts['os']) && $clientOsHash !== FingerprintBuilder::cyrb53($serverOsParts['os'])) {
                $score += 50;
            }
        }

        return ['crossLayerInconsistencyScore' => min(100.0, $score)];
    }

    /**
     * Calcule les indicateurs comportementaux liés à l'historique de l'appareil.
     * @param array<string, mixed> $deviceData
     * @return array{'historyScore': float, 'rotationScore': float}
     */
    public static function getBehavioralIndicators(RequestContext $context, array &$deviceData): array
    {
        $now = time() * 1000;
        $clientIp = $context->clientIp;
        $currentFpHash = self::getCompositeDeviceHash($context);

        // Analyse de la fréquence de changement du fingerprint
        $rapidChangeThresholdMs = 2000; // 2 secondes
        $maxRapidChanges = 3;

        if (isset($deviceData['lastFpHash']) && $currentFpHash !== $deviceData['lastFpHash']) {
            $timeSinceLastChange = $now - ($deviceData['lastChangeTimestamp'] ?? 0);
            if ($timeSinceLastChange < $rapidChangeThresholdMs) {
                $deviceData['rapidChangeCount'] = ($deviceData['rapidChangeCount'] ?? 0) + 1;
            } else {
                $deviceData['rapidChangeCount'] = max(0, ($deviceData['rapidChangeCount'] ?? 0) - 1);
            }
            $deviceData['lastChangeTimestamp'] = $now;
        }
        $deviceData['lastFpHash'] = $currentFpHash;

        // Enregistrement de l'IP
        if (!in_array($clientIp, $deviceData['ips'])) {
            $deviceData['ips'][] = $clientIp;
        }

        // Score d'historique basé sur le nombre d'IPs utilisées (rotation de proxy)
        $maxIpsPerDevice = 15;
        $freeIpChanges = 3;
        $historyScore = min(100.0, (max(0, count($deviceData['ips']) - $freeIpChanges) / $maxIpsPerDevice) * 100);
        // Score de rotation basé sur les changements rapides de fingerprint
        $rotationScore = min(100.0, (($deviceData['rapidChangeCount'] ?? 0) / $maxRapidChanges) * 100);

        return ['historyScore' => $historyScore, 'rotationScore' => $rotationScore];
    }

    /**
     * Analyse les patterns de requêtes pour détecter les comportements de bot.
     * @param array<string, mixed> $deviceData
     * @param array<string, mixed> $patternConfig
     * @return array{'requestPatternScore': float}
     */
    public static function getRequestPatternScore(RequestContext $context, array &$deviceData, array $patternConfig): array
    {
        // Configuration avec valeurs par défaut robustes
        $historySize = $patternConfig['historySize'] ?? 20;
        $minSamples = $patternConfig['minSamples'] ?? 10;
        $regularityThreshold = $patternConfig['regularityThreshold'] ?? 150; // ms
        $benfordThreshold = $patternConfig['benfordThreshold'] ?? 0.15;
        $patternWeight = $patternConfig['patternWeight'] ?? 80;
        $decayFactor = $patternConfig['decayFactor'] ?? 0.95;
        $inactivityReset = $patternConfig['inactivityReset'] ?? 180000;

        $now = time() * 1000;
        $history = $deviceData['requestHistory'] ?? [];
        $deviceData['timingHistory'] = $deviceData['timingHistory'] ?? [];

        $lastRequest = end($history) ?: null;
        $timeSinceLast = $lastRequest ? $now - $lastRequest['timestamp'] : PHP_INT_MAX;

        // Mise à jour de l'historique
        $history[] = ['timestamp' => $now, 'path' => $context->path];
        if ($lastRequest) {
            $deviceData['timingHistory'][] = $timeSinceLast;
        }

        if (count($history) > $historySize) {
            array_shift($history);
        }
        if (count($deviceData['timingHistory']) > $historySize) {
            array_shift($deviceData['timingHistory']);
        }
        $deviceData['requestHistory'] = $history;

        $instantScore = 0;
        $timings = $deviceData['timingHistory'];

        // Analyse statistique si nous avons assez de données
        if (count($timings) >= $minSamples) {
            // FIX: Éviter la division par zéro si le tableau est vide, bien que count() >= minSamples devrait déjà le prévenir.
            if (count($timings) === 0) {
                return ['requestPatternScore' => min(100.0, $deviceData['lastPatternScore'] ?? 0)];
            }

            $mean = array_sum($timings) / count($timings); // @phpstan-ignore-line
            $variance = array_reduce($timings, fn($carry, $item) => $carry + pow($item - $mean, 2), 0) / count($timings); // @phpstan-ignore-line
            $stdDev = sqrt($variance);
            $benfordDeviation = Optimization::benfordTest($timings);

            // Détection de régularité (bots de type "cron")
            if ($stdDev < $regularityThreshold) {
                $instantScore = $patternWeight;
            }
            // Détection de distribution non-naturelle (bots "faussement aléatoires")
            elseif ($benfordDeviation > $benfordThreshold) {
                $instantScore = $patternWeight;
            }
        }

        // Logique de décroissance et de score final
        $newPatternScore = $deviceData['lastPatternScore'] ?? 0;

        if ($timeSinceLast > $inactivityReset) {
            $newPatternScore = 0; // Réinitialisation après inactivité
        } else {
            $newPatternScore *= $decayFactor;
        }
        $newPatternScore = max(0, $newPatternScore);

        $deviceData['lastPatternScore'] = $newPatternScore + $instantScore;

        return ['requestPatternScore' => min(100.0, $deviceData['lastPatternScore'])];
    }

    /**
     * Vérifie la soumission de champs honeypot.
     * @param array<string, mixed> $honeypotConfig
     * @return array{'honeypotScore': float}
     */
    public static function getHoneypotScore(RequestContext $context, array $honeypotConfig): array // @phpstan-ignore-line
    {
        $fields = $honeypotConfig['fields'] ?? [];
        $trapUrls = $honeypotConfig['trapUrls'] ?? [];
        $data = array_merge($context->query, is_array($context->body) ? $context->body : []);

        // 1. Vérifier les champs de formulaire pièges
        foreach ($fields as $field) {
            // Ignorer les paramètres de solution de challenge pour éviter les faux positifs.
            if (str_starts_with($field, 'pow_')) {
                continue;
            }
            if (!empty($data[$field])) {
                return ['honeypotScore' => 100.0];
            }
        }

        // 2. Vérifier l'accès aux URL pièges
        foreach ($trapUrls as $trap) {
            if (str_starts_with($context->path, $trap)) {
                return ['honeypotScore' => 100.0];
            }
        }

        // 3. (Optionnel) Détection d'injections
        if ($honeypotConfig['detectInjections'] ?? false) {
            $typesToDetect = is_array($honeypotConfig['detectInjections']) ? $honeypotConfig['detectInjections'] : [];
            foreach ($data as $value) {
                if (is_string($value) && MaliciousPatterns::isMalicious($value, $typesToDetect)) {
                    return ['honeypotScore' => 100.0];
                }
            }
        }

        return ['honeypotScore' => 0.0];
    }

    public static function getThreatIntelScore(RequestContext $context, array $threatIntelConfig): array
    {
        return ['threatIntelScore' => 0.0];
    }

    /**
     * Parse une chaîne de requête GraphQL pour extraire le type et le nom de l'opération.
     * @param array<string, mixed> $body Le corps de la requête.
     * @return array{type: string, name: string}|null
     */    
    public static function parseGraphQLQuery(array $body): ?array
    {
        $query = $body['query'] ?? null;
        if (!is_string($query)) {
            return null;
        }

        // Regex pour capturer le type d'opération et le nom optionnel.
        if (preg_match('/(?:^|\s)(query|mutation|subscription)\s*([_A-Za-z][_0-9A-Za-z]*)?/', $query, $matches)) {
            return [
                'type' => $matches[1],
                'name' => $matches[2] ?? 'Anonymous',
            ];
        }
        return null;
    }
    /**
     * @private
     * Analyzes click positions to detect unnaturally low variance.
     * @param array<int, array{x: int, y: int, targetId: string}>|null $history
     * @return float
     */
    private static function analyzeClickPositions(?array $history): float
    {
        if (empty($history) || count($history) < 3) {
            return 0.0;
        }

        $clicksByTarget = [];
        foreach ($history as $click) {
            if (empty($click['targetId'])) continue;
            if (!isset($clicksByTarget[$click['targetId']])) {
                $clicksByTarget[$click['targetId']] = [];
            }
            $clicksByTarget[$click['targetId']][] = $click;
        }

        $maxScore = 0.0;

        foreach ($clicksByTarget as $clicks) {
            if (count($clicks) < 3) continue;

            $n = count($clicks);
            $meanX = array_sum(array_column($clicks, 'x')) / $n;
            $meanY = array_sum(array_column($clicks, 'y')) / $n;

            $variance = array_reduce($clicks, function ($sum, $c) use ($meanX, $meanY) {
                    return $sum + pow($c['x'] - $meanX, 2) + pow($c['y'] - $meanY, 2);
                }, 0) / $n;

            if ($variance < 1.0) {
                $score = (1 - sqrt($variance) / 5) * 100;
                if ($score > $maxScore) {
                    $maxScore = $score;
                }
            }
        }

        return min(100.0, $maxScore);
    }

    /**
     * Calculates a score based on click variance metrics sent by the client.
     * @return array{'clickVarianceScore': float}
     */
    public static function getClickVarianceScore(RequestContext $context): array
    {
        $behaviorHeader = $context->getHeader('x-behavior-metrics');
        if (!$behaviorHeader) {
            return ['clickVarianceScore' => 0.0];
        }
        $metrics = json_decode($behaviorHeader, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            return ['clickVarianceScore' => 0.0];
        }
        $score = self::analyzeClickPositions($metrics['clicksHistory'] ?? null);
        return ['clickVarianceScore' => $score];
    }

    /**
     * Nettoie une URL de tous les paramètres de requête liés au PoW.
     * @param string $originalPath Le chemin original, potentiellement avec des query params.
     * @param array<string, mixed> $incomingQuery Le tableau de la query string de la requête entrante.
     * @return string Le chemin final nettoyé.
     */
    public static function cleanUrlFromPowParams(string $originalPath, array $incomingQuery): string
    {
        $urlParts = parse_url($originalPath);
        $path = $urlParts['path'] ?? '/';
        $finalQuery = $incomingQuery;

        $powParams = [
            'pow_type', 'pow_nonce', 'pow_solution', 'pow_solution_cpu',
            'pow_solution_mem', 'pow_fp', 'pow_solution_population',
            'pow_solution_work_result', 'pow_problem_id'
        ];

        foreach ($powParams as $param) {
            unset($finalQuery[$param]);
        }

        if (!empty($finalQuery)) {
            return $path . '?' . http_build_query($finalQuery);
        }
        return $path;
    }

    /**
     * Vérifie si un host et un path de requête correspondent à une entrée de liste blanche.
     */
    public static function hostPathMatches(string $requestHost, string $requestPath, string $entry): bool
    {
        $firstSlashIndex = strpos($entry, '/');
        if ($firstSlashIndex === false) return false;

        $hostPattern = substr($entry, 0, $firstSlashIndex);
        $pathPattern = substr($entry, $firstSlashIndex);

        if ($requestHost !== $hostPattern) return false;

        return self::pathMatches($requestPath, $pathPattern);
    }
}