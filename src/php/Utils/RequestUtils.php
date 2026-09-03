<?php

declare(strict_types=1);


namespace Anonympins\Fingerprint\Utils;

use Anonympins\Fingerprint\FingerprintBuilder;
use Anonympins\Fingerprint\Store\StoreManager;
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
     * Base de données de signatures JA4 connues.
     * @var array<string, string|string[]>
     */
    private const JA4_FINGERPRINT_DB = [
        // Format: {JA4 Hash} => {Client Name}
        // --- Chrome ---
        't13d1517h2_8daaf61527d5' => 'Chrome', // Chrome 117 on Win11
        't13d1516h2_8daaf61527d5' => 'Chrome', // Chrome 116 on Win10
        // --- Firefox ---
        't13d1517h2_2491a244c393' => 'Firefox', // Firefox 117 on Win11
        // --- Common Libraries & Bots ---
        't13d1500h1_4b56136b4d35' => 'Python', // Python requests
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
        if ($context->ja4s) $srv->add("ja4s", $context->ja4s);
        if ($context->ja4h) $srv->add("ja4h", $context->ja4h);
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
        $ua = $context->getHeader('user-agent') ?? '';
        $ja3 = $context->ja3;
        $ja4 = $context->ja4;

        // Si un fingerprint TLS est présent mais que le User-Agent est absent ou générique, c'est suspect.
        if (($ja3 || $ja4) && (empty($ua) || strlen($ua) < 10 || stripos($ua, 'python') !== false || stripos($ua, 'curl') !== false)) {
            return ['tlsSpoofingScore' => 50.0];
        }

        $claimedBrowserInfo = self::parseUserAgent($ua);
        $claimedBrowser = $claimedBrowserInfo['browser'] ?? null;

        if (empty($claimedBrowser) || empty($ua)) {
            return ['tlsSpoofingScore' => 0.0];
        }

        // Priorité à JA4 pour la détection de spoofing
        if ($ja4 && isset(self::JA4_FINGERPRINT_DB[$ja4])) {
            $expectedClients = self::JA4_FINGERPRINT_DB[$ja4];
            if (!is_array($expectedClients)) {
                $expectedClients = [$expectedClients];
            }

            $isMatch = false;
            foreach ($expectedClients as $expected) {
                if (stripos($claimedBrowser, $expected) !== false) {
                    $isMatch = true;
                    break;
                }
            }
            if (!$isMatch) {
                // Incohérence forte détectée avec JA4
                return ['tlsSpoofingScore' => 90.0];
            }
        }
        // Fallback sur JA3 si JA4 n'a pas matché
        elseif ($ja3 && isset(self::TLS_FINGERPRINT_DB[$ja3])) {
            $expectedClients = self::TLS_FINGERPRINT_DB[$ja3];
            if (!is_array($expectedClients)) {
                $expectedClients = [$expectedClients];
            }

            $isMatch = false;
            foreach ($expectedClients as $expected) {
                if (stripos($claimedBrowser, $expected) !== false) {
                    $isMatch = true;
                    break;
                }
            }
            if (!$isMatch) {
                // Incohérence détectée avec JA3
                return ['tlsSpoofingScore' => 80.0];
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
        $ua = $context->getHeader('user-agent') ?? '';
        if (empty($ua) || strlen($ua) < 10) {
            $anomalyScore += 60;
        }
        if (!$context->getHeader('accept-language')) {
            $anomalyScore += 25;
        }
        if ($context->httpVersion === '1.0') {
            $anomalyScore += 15;
        }

        // TE: trailers check for Firefox on Desktop
        $uaParts = self::parseUserAgent($ua);
        $isFirefoxDesktop = isset($uaParts['browser']) && str_starts_with($uaParts['browser'], 'Firefox') && ($uaParts['device'] ?? 'desktop') === 'desktop';
        $te = strtolower($context->getHeader('te') ?? '');

        if ($isFirefoxDesktop && $te !== 'trailers') {
            $anomalyScore += 30;
        } elseif (!$isFirefoxDesktop && ($uaParts['device'] ?? 'desktop') === 'desktop' && $te === 'trailers') {
            $anomalyScore += 30;
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
     * Calcule un score d'incohérence entre le User-Agent et les en-têtes Sec-CH-UA (Client Hints).
     * @return array{'clientHintsInconsistencyScore': float}
     */
    public static function getClientHintsInconsistencyScore(RequestContext $context): array
    {
        $ua = $context->getHeader('user-agent');
        $clientHints = $context->getHeader('sec-ch-ua');

        if (empty($ua) || empty($clientHints)) {
            return ['clientHintsInconsistencyScore' => 0.0];
        }

        // 1. Extraire la version du navigateur depuis le User-Agent
        $uaVersion = null;
        if (preg_match('/(Chrome|Firefox|Edg|Safari)\/([\d\.]+)/', $ua, $uaMatches)) {
            $uaBrowser = $uaMatches[1] === 'Edg' ? 'Edge' : $uaMatches[1];
            // Prendre uniquement la version majeure
            $uaVersion = explode('.', $uaMatches[2])[0] ?? null;
        }

        // 2. Extraire la version du navigateur depuis Sec-CH-UA
        $chVersion = null;
        $chBrowser = null;
        // Regex pour trouver une marque de navigateur connue et sa version
        if (preg_match('/"(?:Google Chrome|Chromium|Microsoft Edge)";v="(\d+)"/', $clientHints, $chMatches)) {
            $chVersion = $chMatches[1];
            // Déterminer le navigateur à partir de la marque trouvée
            if (str_contains($chMatches[0], 'Edge')) {
                $chBrowser = 'Edge';
            } else {
                $chBrowser = 'Chrome'; // Chrome ou Chromium
            }
        }

        if ($uaVersion === null || $chVersion === null || $uaBrowser === null || $chBrowser === null) {
            return ['clientHintsInconsistencyScore' => 0.0];
        }

        // 3. Comparer les versions
        // Tolérer une petite différence car les Client-Hints peuvent être plus précis ou mis à jour différemment
        $versionDifference = abs((int)$uaVersion - (int)$chVersion);

        // Si les navigateurs déclarés sont différents (ex: UA dit Firefox, CH dit Chrome)
        if ($uaBrowser !== $chBrowser && ($uaBrowser !== 'Chrome' || $chBrowser !== 'Edge')) { // Tolérer Chrome/Edge
             return ['clientHintsInconsistencyScore' => 90.0];
        }

        if ($versionDifference > 5) { // Un écart de plus de 5 versions majeures est très suspect
            return ['clientHintsInconsistencyScore' => 80.0];
        } elseif ($versionDifference > 1) { // Un petit écart est légèrement suspect
            return ['clientHintsInconsistencyScore' => 40.0];
        }

        return ['clientHintsInconsistencyScore' => 0.0];
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

        $lastFpHash = $deviceData['lastFpHash'] ?? null;

        if ($lastFpHash && $currentFpHash !== $lastFpHash) {
            // Comparaison plus intelligente : ne pénaliser que si les parties STABLES de l'empreinte changent.
            // Les parties stables sont celles qui ne devraient pas changer lors d'un simple changement de réseau.
            $stablePart1 = self::extractStablePart($lastFpHash);
            $stablePart2 = self::extractStablePart($currentFpHash);

            $timeSinceLastChange = $now - ($deviceData['lastChangeTimestamp'] ?? 0);

            // On incrémente le compteur de rotation rapide SEULEMENT si la partie stable a changé.
            if ($stablePart1 !== $stablePart2) {
                if ($timeSinceLastChange < $rapidChangeThresholdMs) {
                    $deviceData['rapidChangeCount'] = ($deviceData['rapidChangeCount'] ?? 0) + 1;
                } else {
                    // Si le changement est lent, on réduit le compteur pour pardonner les anciens changements rapides.
                    $deviceData['rapidChangeCount'] = max(0, ($deviceData['rapidChangeCount'] ?? 0) - 1);
                }
                $deviceData['lastChangeTimestamp'] = $now;
            }
            // Si seule la partie volatile a changé (ex: User-Agent, IP via en-têtes), on ne met pas à jour le `lastChangeTimestamp`.
            // Cela évite qu'un changement de réseau légitime soit suivi d'un autre changement (ex: mise en veille)
            // et soit compté comme une rotation rapide.

        } else if ($lastFpHash === null) {
            // Première visite, on initialise le timestamp.
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
     * Extrait la partie "stable" d'une chaîne d'empreinte.
     * La partie stable inclut les composants matériels (canvas, gpu) qui ne devraient pas changer.
     * @param string $fpString La chaîne d'empreinte complète.
     * @return string La sous-chaîne de l'empreinte contenant uniquement les parties stables.
     */
    private static function extractStablePart(string $fpString): string
    {
        $stableKeys = ['cvs', 'gpu', 'hw', 'client_fp_hash', 'os', 'scr'];
        $parts = explode('|', $fpString);
        $stableParts = [];
        foreach ($parts as $part) {
            $pair = explode(':', $part, 2);
            if (count($pair) === 2 && in_array($pair[0], $stableKeys, true)) {
                $stableParts[] = $part;
            }
        }
        sort($stableParts);
        return implode('|', $stableParts);
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

        // Détection d'énumération de chemins (crawling/scraping de ressources séquentielles)
        $enumerationScore = 0;
        if (count($history) >= 3) {
            $templates = array_map(function($h) {
                return preg_replace('/\d+/', '{num}', $h['path']);
            }, $history);

            $uniquePaths = array_unique(array_map(function($h) {
                return $h['path'];
            }, $history));

            $templateCounts = array_count_values($templates);
            $maxTemplateRepetition = !empty($templateCounts) ? max($templateCounts) : 0;

            if ($maxTemplateRepetition >= 3 && count($uniquePaths) === count($history)) {
                $enumerationScore = $patternWeight * 0.8;
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

        $deviceData['lastPatternScore'] = $newPatternScore + $instantScore + $enumerationScore;

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

    /**
     * Génère un masque de sous-réseau binaire pour une longueur de préfixe donnée.
     *
     * @param int $prefix La longueur du préfixe (ex: 24 pour IPv4, 48 pour IPv6).
     * @param int $totalBytes Le nombre total d'octets pour le masque (4 pour IPv4, 16 pour IPv6).
     * @return string|null Le masque binaire ou null si le préfixe est invalide.
     */
    private static function generateMask(int $prefix, int $totalBytes): ?string
    {
        if ($prefix < 0 || $prefix > $totalBytes * 8) {
            return null; // Préfixe invalide
        }
        $mask = str_repeat(chr(255), (int)floor($prefix / 8));
        if ($prefix % 8 !== 0) {
            $mask .= chr((255 << (8 - $prefix % 8)) & 255);
        }
        return str_pad($mask, $totalBytes, chr(0));
    }

    /**
     * Calcule le sous-réseau d'une adresse IP.
     * @param string $ip L'adresse IP.
     * @param int $ipv4Prefix Le préfixe pour les adresses IPv4 (défaut /24).
     * @param int $ipv6Prefix Le préfixe pour les adresses IPv6 (défaut /48).
     * @return string|null Le sous-réseau CIDR ou null si l'IP est invalide.
     */
    public static function getIpSubnet(string $ip, int $ipv4Prefix = 24, int $ipv6Prefix = 48): ?string
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $ipBinary = inet_pton($ip);
            if ($ipBinary === false) return null;

            $mask = self::generateMask($ipv4Prefix, 4);
            if ($mask === null) return null;

            $networkBinary = $ipBinary & $mask;
            return inet_ntop($networkBinary) . '/' . $ipv4Prefix;
        } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $ipBinary = inet_pton($ip);
            if ($ipBinary === false) return null;

            $mask = self::generateMask($ipv6Prefix, 16);
            if ($mask === null) return null;

            $networkBinary = $ipBinary & $mask;
            return inet_ntop($networkBinary) . '/' . $ipv6Prefix; // FIX: Use the provided ipv6Prefix
        }
        return null;
    }

    /**
     * Met à jour les métriques agrégées pour un sous-réseau IP.
     * @param RequestContext $context
     * @param string $deviceId
     * @param float $finalScore
     */
    public static function updateSubnetMetrics(RequestContext $context, string $deviceId, float $finalScore): void
    {
        $subnet = self::getIpSubnet($context->clientIp);
        if ($subnet === null) return;

        $store = StoreManager::getStore();
        $key = "subnet:{$subnet}";
        $subnetData = $store->get($key) ?? [
            'highScoreCount' => 0,
            'deviceIds' => [],
            'lastActivity' => 0
        ];

        $subnetData['highScoreCount']++;
        if (!in_array($deviceId, $subnetData['deviceIds'])) {
            $subnetData['deviceIds'][] = $deviceId;
        }
        $subnetData['lastActivity'] = time();

        // Limiter la taille du tableau des deviceIds pour éviter une consommation mémoire excessive.
        if (count($subnetData['deviceIds']) > 100) {
            array_shift($subnetData['deviceIds']);
        }

        // TTL de 24 heures pour les données de sous-réseau.
        $store->set($key, $subnetData, 86400);
    }

    /**
     * Calcule un score de suspicion basé sur l'activité historique du sous-réseau IP.
     * @param RequestContext $context
     * @param string $currentDeviceId
     * @return array{'subnetScore': float}
     */
    public static function getSubnetScore(RequestContext $context, string $currentDeviceId): array
    {
        $subnet = self::getIpSubnet($context->clientIp);
        if ($subnet === null) {
            return ['subnetScore' => 0.0];
        }

        $store = StoreManager::getStore();
        $key = "subnet:{$subnet}";
        $subnetData = $store->get($key);

        if ($subnetData === null) {
            return ['subnetScore' => 0.0];
        }

        $score = 0.0;

        // Pénalité basée sur le nombre de devices uniques vus depuis ce sous-réseau.
        $deviceCount = count($subnetData['deviceIds']);
        if ($deviceCount > 10) {
            $score += min(80.0, ($deviceCount - 10) * 5);
        }

        // Pénalité basée sur le nombre de scores élevés enregistrés.
        $score += min(40.0, $subnetData['highScoreCount'] * 2);

        return ['subnetScore' => min(100.0, $score)];
    }

    /**
     * Calcule le score de réputation d'une IP en appliquant la décroissance temporelle.
     */
    public static function getIpReputationScore(string $ip): float
    {
        $store = StoreManager::getStore();
        $key = "ip-reputation:{$ip}";
        $data = $store->get($key);
        if ($data === null) {
            return 0.0;
        }

        $now = time();
        $hoursPassed = ($now - $data['lastUpdate']) / 3600;
        $decay = (int)floor($hoursPassed * 2); // Décroissance de 2 points par heure

        return (float)max(0.0, $data['score'] - $decay);
    }

    /**
     * Met à jour le score de réputation locale d'une IP.
     */
    public static function updateIpReputationScore(string $ip, float $change): void
    {
        $store = StoreManager::getStore();
        $key = "ip-reputation:{$ip}";
        $current = self::getIpReputationScore($ip);
        $newScore = min(100.0, max(0.0, $current + $change));
        $store->set($key, ['score' => $newScore, 'lastUpdate' => time()], 86400 * 7); // TTL de 7 jours
    }


    /**
     * Assainit les données de trafic pour l'auto-tuner afin de prévenir les attaques par empoisonnement.
     * Limite la contribution de chaque deviceId à un pourcentage maximum (ex: 2%) du jeu de données total.
     *
     * @param array<int, array<string, mixed>> $trafficData
     * @return array<int, array<string, mixed>>
     */
    public static function sanitizeTrafficData(array $trafficData): array
    {
        if (empty($trafficData)) {
            return [];
        }

        $tempSanitized = [];
        $deviceCounts = [];
        $maxLogsPerDevice = max(3, (int)floor(count($trafficData) * 0.02));

        foreach ($trafficData as $log) {
            $deviceId = $log['deviceId'] ?? 'anonymous';
            if (!isset($deviceCounts[$deviceId])) {
                $deviceCounts[$deviceId] = 0;
            }
            if ($deviceCounts[$deviceId] < $maxLogsPerDevice) {
                $deviceCounts[$deviceId]++;
                $tempSanitized[] = $log;
            }
        }

        $passedLogs = [];
        $suspiciousLogs = [];
        foreach ($tempSanitized as $log) {
            if (($log['type'] ?? '') === 'request_passed') {
                $passedLogs[] = $log;
            } else {
                $suspiciousLogs[] = $log;
            }
        }

        $minDataPoints = 200; // Seuil par défaut
        $maxPassedAllowed = max($minDataPoints, count($suspiciousLogs) * 9);

        if (count($passedLogs) > $maxPassedAllowed) {
            shuffle($passedLogs);
            $passedLogs = array_slice($passedLogs, 0, $maxPassedAllowed);
        }

        return array_merge($suspiciousLogs, $passedLogs);
    }

    /**
     * Génère une signature HMAC-SHA256 pour sécuriser les données du challenge stockées.
     * @param string $secret Le secret global (POW_SECRET).
     * @param array<string, mixed> $payload Les données du challenge.
     * @param string $clientIp L'IP du client pour lier la signature.
     * @return string
     */
    public static function signChallengePayload(string $secret, array $payload, string $clientIp): string
    {
        $dataToSign = implode(':', [
            $payload['clientSecret'] ?? '',
            $payload['cpuTarget'] ?? '',
            $payload['fingerprint'] ?? '',
            $payload['memDifficulty'] ?? '',
            $payload['originalPath'] ?? '',
            $clientIp
        ]);

        return hash_hmac('sha256', $dataToSign, $secret);
    }

    /**
     * Vérifie la signature HMAC-SHA256 des données de challenge récupérées du store.
     * @param string $secret Le secret global (POW_SECRET).
     * @param array<string, mixed> $payload Les données du challenge contenant la signature.
     * @param string $clientIp L'IP du client.
     * @return bool True si la signature est valide, false sinon.
     */
    public static function verifyChallengePayload(string $secret, array $payload, string $clientIp): bool
    {
        if (empty($payload['signature'])) {
            return false;
        }

        $storedSignature = $payload['signature'];
        $payloadWithoutSig = $payload;
        unset($payloadWithoutSig['signature']);

        $expectedSignature = self::signChallengePayload($secret, $payloadWithoutSig, $clientIp);

        return hash_equals($expectedSignature, $storedSignature);
    }

    /**
     * Vérifie si un ticket de clearance (PoW) est valide, en supportant la tolérance au roaming.
     *
     * @param string $ip L'adresse IP de la requête courante.
     * @param string|null $ticket Le ticket de clearance extrait du cookie.
     * @param string $deviceId L'identifiant du cookie de l'appareil.
     * @param string $deviceHash L'empreinte matérielle calculée côté serveur.
     * @param string $secret La clé secrète (POW_SECRET).
     * @return bool True si le ticket est valide et correspond aux contraintes de sécurité.
     */
    public static function isTicketValid(string $ip, ?string $ticket, string $deviceId = '', string $deviceHash = '', string $secret = ''): bool
    {
        if (empty($ticket)) {
            return false;
        }

        if (str_contains($ticket, '|')) {
            $parts = explode('|', $ticket);
            if (count($parts) < 3) return false;
            [$expiry, $originalIp, $sig] = $parts;
        } elseif (str_contains($ticket, ':')) {
            // Fallback rétrocompatible pour les anciens tickets
            $parts = explode(':', $ticket);
            if (count($parts) < 2) return false;
            [$expiry, $sig] = $parts;
            $originalIp = $ip;
        } else {
            return false;
        }

        if (empty($expiry) || empty($sig) || (time() * 1000) > (int)$expiry) {
            return false;
        }

        if (str_contains($ticket, '|')) {
            $expectedSig = hash_hmac('sha256', "{$expiry}:{$originalIp}:{$deviceId}:{$deviceHash}", $secret);
        } else {
            $expectedSig = hash_hmac('sha256', "{$ip}:{$expiry}", $secret);
        }

        if (!hash_equals($expectedSig, $sig)) {
            return false;
        }

        if (!str_contains($ticket, '|')) {
            return $ip === $originalIp;
        }

        if ($ip === $originalIp) return true;
        $currentSubnet = self::getIpSubnet($ip);
        $originalSubnet = self::getIpSubnet($originalIp);
        if ($currentSubnet !== null && $originalSubnet !== null && $currentSubnet === $originalSubnet) {
            return true;
        }

        return !empty($deviceId) && !empty($deviceHash); // Match d'identité matérielle stricte (deviceId + deviceHash validés par HMAC)
    }
}