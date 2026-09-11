<?php

declare(strict_types=1);


namespace Anonympins\Fingerprint\Utils;

use Anonympins\Fingerprint\FingerprintBuilder;
use Anonympins\Fingerprint\Optimization\Optimization;
use Anonympins\Fingerprint\RequestContext;
use Anonympins\Fingerprint\Store\StoreManager;

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
            "ch_full_version_list" => "sec-ch-ua-full-version-list",
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
     * Analyse une série d'événements tactiles mobiles pour en extraire des indicateurs comportementaux.
     * @param array|null $history
     * @return array
     */
    private static function analyzeTouchMovements(?array $history): array
    {
        if (empty($history) || count($history) < 3) {
            return [
                'avgSpeed' => 0.0, 'avgAcceleration' => 0.0, 'straightness' => 1.0, 'pauses' => 0, 'segments' => [],
                'avgPressure' => 0.0, 'avgRadius' => 0.0, 'pressureVariance' => 0.0, 'radiusVariance' => 0.0, 'maxTouches' => 1
            ];
        }

        $segments = [];
        $totalDistance = 0.0;
        $pauses = 0;
        $totalPressure = 0.0;
        $totalRadius = 0.0;
        $maxTouches = 1;

        for ($i = 1; $i < count($history); $i++) {
            $p1 = $history[$i - 1];
            $p2 = $history[$i];
            $dx = $p2['x'] - $p1['x'];
            $dy = $p2['y'] - $p1['y'];
            $dt = $p2['t'] - $p1['t'];
            $distance = sqrt($dx * $dx + $dy * $dy);

            $totalPressure += (float)($p2['p'] ?? 0.0);
            $totalRadius += (float)($p2['r'] ?? 0.0);
            if (($p2['num'] ?? 1) > $maxTouches) {
                $maxTouches = (int)$p2['num'];
            }

            if ($dt > 0) {
                $speed = $distance / $dt;
                $segments[] = ['distance' => $distance, 'dt' => $dt, 'speed' => $speed];
                $totalDistance += $distance;
            }
            if ($dt > 100 && $distance < 5) {
                $pauses++;
            }
        }

        $totalPressure += (float)($history[0]['p'] ?? 0.0);
        $totalRadius += (float)($history[0]['r'] ?? 0.0);

        $avgPressure = $totalPressure / count($history);
        $avgRadius = $totalRadius / count($history);

        $sqDiffPressureSum = 0.0;
        $sqDiffRadiusSum = 0.0;
        foreach ($history as $pt) {
            $sqDiffPressureSum += pow((float)($pt['p'] ?? 0.0) - $avgPressure, 2);
            $sqDiffRadiusSum += pow((float)($pt['r'] ?? 0.0) - $avgRadius, 2);
        }
        $pressureVariance = $sqDiffPressureSum / count($history);
        $radiusVariance = $sqDiffRadiusSum / count($history);

        if (count($segments) < 2) {
            return [
                'avgSpeed' => 0.0, 'avgAcceleration' => 0.0, 'straightness' => 1.0, 'pauses' => $pauses, 'segments' => [],
                'avgPressure' => $avgPressure, 'avgRadius' => $avgRadius, 'pressureVariance' => $pressureVariance, 'radiusVariance' => $radiusVariance, 'maxTouches' => $maxTouches
            ];
        }

        $totalTime = $history[count($history) - 1]['t'] - $history[0]['t'];
        $avgSpeed = $totalTime > 0 ? array_sum(array_column($segments, 'speed')) / count($segments) : 0.0;

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
        $straightness = $totalDistance > 0 ? $straightDistance / $totalDistance : 1.0;

        return [
            'avgSpeed' => $avgSpeed,
            'avgAcceleration' => $avgAcceleration,
            'straightness' => $straightness,
            'pauses' => $pauses,
            'segments' => array_column($segments, 'distance'),
            'avgPressure' => $avgPressure,
            'avgRadius' => $avgRadius,
            'pressureVariance' => $pressureVariance,
            'radiusVariance' => $radiusVariance,
            'maxTouches' => $maxTouches
        ];
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
        $touch = self::analyzeTouchMovements($metrics['touchMovementsHistory'] ?? null);

        if (isset($metrics['historyLength'])) {
            if ($metrics['historyLength'] === 1) $score += 15;
            elseif ($metrics['historyLength'] >= 5) $score -= 20;
            elseif ($metrics['historyLength'] >= 2) $score -= 10;
        } else {
            // Pénalité pour absence totale d'interaction si l'historique n'est pas dispo
            if ($mouseAnalysis['avgSpeed'] == 0 && $touch['avgSpeed'] == 0 && ($metrics['keystrokeLatency'] ?? 0) == 0) {
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
        // Analyse comportementale des événements tactiles (Touch Move)
        $touchHistory = $metrics['touchMovementsHistory'] ?? null;
        if (!empty($touchHistory)) {
            if ($touch['avgSpeed'] > 0) {
                if ($touch['avgSpeed'] > 5) $score += 30;
                if ($touch['avgAcceleration'] > 0.8) $score += 20;
                if ($touch['straightness'] > 0.98) $score += 35;
                if ($touch['pauses'] === 0 && count($touch['segments']) > 25) $score += 15;

                // Détection de l'émulation (pression et rayon de contact constants)
                if ($touch['avgPressure'] > 0 && $touch['pressureVariance'] == 0) {
                    $score += 30;
                }
                if ($touch['avgRadius'] > 0 && $touch['radiusVariance'] == 0) {
                    $score += 30;
                }
            }
            if (count($touch['segments']) > 10) {
                $benfordDev = Optimization::benfordTest($touch['segments']);
                if ($benfordDev > 0.18) {
                    $score += 35;
                }
            }
        }

        return ['behaviorScore' => min(100.0, $score)];
    }

    /**
     * Calcule un score basé sur la régularité d'affichage (V-Sync) et l'utilisation suspecte d'OffscreenCanvas.
     * @return array{'renderingAnomalyScore': float}
     */
    public static function getRenderingAnomalyScore(RequestContext $context): array
    {
        $behaviorHeader = $context->getHeader('x-behavior-metrics');
        if (!$behaviorHeader) {
            return ['renderingAnomalyScore' => 0.0];
        }

        $metrics = json_decode($behaviorHeader, true);
        if (json_last_error() !== JSON_ERROR_NONE || !isset($metrics['rendering'])) {
            return ['renderingAnomalyScore' => 0.0];
        }

        $rendering = $metrics['rendering'];
        $score = 0.0;

        if (!empty($rendering['offscreenAnom'])) {
            $score += 100.0;
        }

        $fps = (float)($rendering['fps'] ?? 0.0);
        $jitter = (float)($rendering['jitter'] ?? 0.0);

        if ($fps > 250.0 || ($fps > 0.0 && $fps < 15.0)) {
            $score += 50.0;
        }
        if ($jitter > 6.0) {
            $score += min(80.0, ($jitter - 6.0) * 10.0);
        }

        return ['renderingAnomalyScore' => min(100.0, $score)];
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

          // 2. Incohérence de l'écran (si les Client Hints sont disponibles)
          $clientScreenHash = $clientFpMap['scr'] ?? null;
          $viewportWidth = $context->getHeader('sec-ch-viewport-width');
          if ($clientScreenHash && $viewportWidth) {
              $viewportWidthInt = (int)$viewportWidth;
              $matchedScreenWidth = null;
              $commonWidths = [320, 360, 375, 390, 412, 414, 768, 1024, 1280, 1366, 1440, 1536, 1600, 1920, 2560, 3840];
              $commonHeights = [480, 568, 640, 667, 736, 800, 812, 844, 896, 900, 1024, 1080, 1200, 1440, 1600, 2160];
              $commonDepths = [24, 30, 32];
              
              foreach ($commonWidths as $w) {
                  foreach ($commonHeights as $h) {
                      foreach ($commonDepths as $d) {
                          $candidate = "{$w}x{$h}_{$d}";
                          $candidateHash = (string)FingerprintBuilder::cyrb53($candidate);
                          if ($clientScreenHash === $candidateHash) {
                              $matchedScreenWidth = $w;
                              break 3;
                          }
                      }
                  }
              }
              
              if ($matchedScreenWidth !== null && $viewportWidthInt > $matchedScreenWidth) {
                  $score += 20;
              }
          }

          // 3. Incohérence du GPU/Canvas et JA3
          $clientGpuHash = $clientFpMap['gpu'] ?? null;
          $ja3 = $context->ja3;
          if ($clientGpuHash && $ja3) {
              $expectedClients = self::TLS_FINGERPRINT_DB[$ja3] ?? null;
              if ($expectedClients) {
                  if (!is_array($expectedClients)) {
                      $expectedClients = [$expectedClients];
                  }
                  $nonBrowserLibraries = ['Python', 'Go', 'Java', 'curl'];
                  $isLibrary = !empty(array_intersect($expectedClients, $nonBrowserLibraries));
                  if ($isLibrary) {
                      $score += 30;
                  }
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

        $fullVersionList = $context->getHeader('sec-ch-ua-full-version-list');
        if (!empty($fullVersionList)) {
            $chFullVersion = null;
            $chFullBrowser = null;
            if (preg_match_all('/"([^"]+)";v="([^"]+)"/', $fullVersionList, $matches, PREG_SET_ORDER)) {
                foreach ($matches as $match) {
                    $brand = $match[1];
                    $version = $match[2];
                    if ($brand === 'Google Chrome' || $brand === 'Chromium' || $brand === 'Microsoft Edge') {
                        $chFullVersion = $version;
                        $chFullBrowser = $brand === 'Microsoft Edge' ? 'Edge' : 'Chrome';
                        if ($brand === 'Google Chrome' || $brand === 'Microsoft Edge') {
                            break;
                        }
                    }
                }
            }
            if ($chFullVersion && $chFullBrowser) {
                if (preg_match('/(Chrome|Edg)\/([\d\.]+)/', $ua, $uaFullMatches)) {
                    $uaBrowserMapped = $uaFullMatches[1] === 'Edg' ? 'Edge' : 'Chrome';
                    $uaFullVersion = $uaFullMatches[2];
                    if ($uaBrowserMapped === $chFullBrowser && $uaFullVersion !== $chFullVersion) {
                        $parts1 = array_map('intval', explode('.', $uaFullVersion));
                        $parts2 = array_map('intval', explode('.', $chFullVersion));
                        $diffIndex = -1;
                        $maxLen = max(count($parts1), count($parts2));
                        for ($i = 0; $i < $maxLen; $i++) {
                            $p1 = $parts1[$i] ?? 0;
                            $p2 = $parts2[$i] ?? 0;
                            if ($p1 !== $p2) {
                                $diffIndex = $i;
                                break;
                            }
                        }
                        $baseScores = [95.0, 90.0, 85.0, 80.0];
                        $baseScore = $baseScores[$diffIndex] ?? 80.0;
                        $delta = abs(($parts1[$diffIndex] ?? 0) - ($parts2[$diffIndex] ?? 0));
                        $finalFullScore = min(100.0, $baseScore + min(5.0, $delta * 5.0));
                        return ['clientHintsInconsistencyScore' => $finalFullScore];
                    }
                }
            }
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

        $clientHintsInconsistencyScore = 0.0;
        if ($versionDifference > 0) {
            if ($versionDifference <= 2) {
                $clientHintsInconsistencyScore = $versionDifference * 20.0;
            } elseif ($versionDifference <= 7) {
                $clientHintsInconsistencyScore = 40.0 + ($versionDifference - 2) * 8.0;
            } else {
                $clientHintsInconsistencyScore = min(100.0, 80.0 + ($versionDifference - 7) * 3.33);
            }
            $clientHintsInconsistencyScore = round($clientHintsInconsistencyScore, 1);
        }

        return ['clientHintsInconsistencyScore' => $clientHintsInconsistencyScore];
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
    public static function extractStablePart(string $fpString): string
    {
        $stableKeys = ['ua', 'ja3', 'ja4', 'h2', 'tcp'];
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
        $regularityRatio = $patternConfig['regularityRatio'] ?? 0.4;
        $benfordRatio = $patternConfig['benfordRatio'] ?? 0.3;
        $enumerationRatio = $patternConfig['enumerationRatio'] ?? 0.3;

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

        $regularityScore = 0.0;
        $benfordScore = 0.0;
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

            if ($stdDev < $regularityThreshold) {
                $regularityScore = 1.0 - ($stdDev / $regularityThreshold);
            }
            if ($benfordDeviation > $benfordThreshold) {
                $benfordScore = min(1.0, ($benfordDeviation - $benfordThreshold) / (0.5 - $benfordThreshold));
            }
        }

        // Path enumeration progressif
        $enumerationScore = 0.0;
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
                $enumerationScore = min(1.0, ($maxTemplateRepetition - 2) / 5.0);
            }
        }

        $weightedScore = ($regularityScore * $regularityRatio) +
                         ($benfordScore * $benfordRatio) +
                         ($enumerationScore * $enumerationRatio);
        $instantScore = $weightedScore * $patternWeight;

        // Logique de décroissance et de score final
        $newPatternScore = $deviceData['lastPatternScore'] ?? 0;

        if ($timeSinceLast > $inactivityReset) {
            $newPatternScore = 0; // Réinitialisation après inactivité
        } else {
            $newPatternScore *= $decayFactor;
        }
        $newPatternScore = max(0, $newPatternScore);

        $deviceData['lastPatternScore'] = max((float)$instantScore, (float)$newPatternScore);

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
            'highScoreDevices' => [],
            'lastActivity' => 0
        ];

        if (!isset($subnetData['highScoreDevices'])) {
            $subnetData['highScoreDevices'] = [];
        }

        // Utilisation de la partie stable du fingerprint matériel plutôt que l'ID de cookie volatil
        $currentDeviceHash = self::getCompositeDeviceHash($context);
        $stableFpId = FingerprintBuilder::cyrb53(self::extractStablePart($currentDeviceHash));

        $currentDeviceContributions = $subnetData['highScoreDevices'][$stableFpId] ?? 0;
        if ($currentDeviceContributions < 5 && $finalScore < 95) {
            $subnetData['highScoreDevices'][$stableFpId] = $currentDeviceContributions + 1;
            $subnetData['highScoreCount']++;
        }

        if (!in_array($stableFpId, $subnetData['deviceIds'], true)) {
            $subnetData['deviceIds'][] = $stableFpId;
        }
        $subnetData['lastActivity'] = time();

        // Limiter la taille du tableau des deviceIds pour éviter une consommation mémoire excessive.
        if (count($subnetData['deviceIds']) > 100) {
            $oldDeviceId = array_shift($subnetData['deviceIds']);
            if (isset($subnetData['highScoreDevices'][$oldDeviceId])) {
                $oldContributions = $subnetData['highScoreDevices'][$oldDeviceId];
                $subnetData['highScoreCount'] = max(0, $subnetData['highScoreCount'] - $oldContributions);
                unset($subnetData['highScoreDevices'][$oldDeviceId]);
            }
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

        // Application d'une décroissance temporelle (demi-vie de 30 minutes soit 1800 secondes)
        $now = time();
        $inactivitySec = $now - ($subnetData['lastActivity'] ?? $now);
        $halfLives = (int)floor($inactivitySec / 1800);

        $highScoreCount = $subnetData['highScoreCount'] ?? 0;
        $deviceCount = isset($subnetData['deviceIds']) ? count($subnetData['deviceIds']) : 0;

        if ($halfLives > 0) {
            $highScoreCount = max(0, (int)floor($highScoreCount / pow(2, $halfLives)));
            $deviceCount = max(0, (int)floor($deviceCount / pow(2, $halfLives)));
        }

        $score = 0.0;

        // Pénalité basée sur le nombre de devices uniques vus depuis ce sous-réseau.
        if ($deviceCount > 10) {
            $score += min(80.0, ($deviceCount - 10) * 5);
        }

        // Pénalité basée sur le nombre de scores élevés enregistrés.
        $score += min(40.0, $highScoreCount * 2);

        return ['subnetScore' => min(100.0, $score)];
    }

    /**
     * Calcule le score d'anomalie de similarité réseau (Botnet Clustering).
     * @param RequestContext $context
     * @param string $stableFpHash
     * @return array{'botnetClusterScore': float}
     */
    public static function getBotnetClusterScore(RequestContext $context, string $stableFpHash): array
    {
        if (empty($stableFpHash)) {
            return ['botnetClusterScore' => 0.0];
        }

        $store = StoreManager::getStore();
        $key = "botnet-cluster:{$stableFpHash}";
        $now = time();
        $tenMinutesAgo = $now - 600;

        $clusterData = $store->get($key) ?? [];
        if (!is_array($clusterData)) {
            $clusterData = [];
        }

        $clusterData = array_filter($clusterData, function ($entry) use ($tenMinutesAgo) {
            return isset($entry['timestamp']) && $entry['timestamp'] > $tenMinutesAgo;
        });
        $clusterData = array_values($clusterData);

        $found = false;
        foreach ($clusterData as &$entry) {
            if (isset($entry['ip']) && $entry['ip'] === $context->clientIp) {
                $entry['timestamp'] = $now;
                $found = true;
                break;
            }
        }
        unset($entry);

        if (!$found) {
            $clusterData[] = ['ip' => $context->clientIp, 'timestamp' => $now];
        }

        $store->set($key, $clusterData, 600);
        $uniqueIpsCount = count($clusterData);
        $botnetClusterScore = 0.0;
        if ($uniqueIpsCount >= 2) {
            $botnetClusterScore = min(100.0, round(100.0 * (1.0 - exp(-0.35 * ($uniqueIpsCount - 1))), 1));
        }
        return ['botnetClusterScore' => $botnetClusterScore];
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
        $ipCounts = [];
        $subnetCounts = [];

        $totalCount = count($trafficData);
        $maxLogsPerDevice = max(3, (int)floor($totalCount * 0.02)); // Max 2% contribution per device
        $maxLogsPerIp = max(3, (int)floor($totalCount * 0.02));      // Max 2% par adresse IP individuelle
        $maxLogsPerSubnet = max(5, (int)floor($totalCount * 0.05));  // Max 5% par bloc réseau (anti-proxy-rotation)

        foreach ($trafficData as $log) {
            $devId = $log['deviceId'] ?? 'anonymous';
            $ip = $log['clientIp'] ?? $log['ip'] ?? 'unknown';
            $subnet = self::getIpSubnet($ip) ?? 'unknown-subnet';

            $currentDeviceCount = $deviceCounts[$devId] ?? 0;
            $currentIpCount = $ipCounts[$ip] ?? 0;
            $currentSubnetCount = $subnetCounts[$subnet] ?? 0;

            if (
                $currentDeviceCount < $maxLogsPerDevice &&
                ($ip === 'unknown' || $currentIpCount < $maxLogsPerIp) &&
                ($subnet === 'unknown-subnet' || $currentSubnetCount < $maxLogsPerSubnet)
            ) {
                $deviceCounts[$devId] = $currentDeviceCount + 1;
                if ($ip !== 'unknown') {
                    $ipCounts[$ip] = $currentIpCount + 1;
                }
                if ($subnet !== 'unknown-subnet') {
                    $subnetCounts[$subnet] = $currentSubnetCount + 1;
                }
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
     * Parse une trame TCP SYN brute (IPv4 ou IPv6).
     */
    public static function parseTcpSyn(?string $binary): ?array
    {
        if (!$binary || strlen($binary) < 40) return null;
        $ttl = 64;
        $tcpOffset = 20;
        $version = ord($binary[0]) >> 4;

        if ($version === 4) {
            $ttl = ord($binary[8]);
            $ihl = ord($binary[0]) & 0x0f;
            $tcpOffset = $ihl * 4;
        } elseif ($version === 6) {
            $ttl = ord($binary[7]); // Hop Limit
            $tcpOffset = 40;
        } else {
            $tcpOffset = 0;
            $ttl = 64;
        }

        if (strlen($binary) < $tcpOffset + 20) return null;

        $windowSize = (ord($binary[$tcpOffset + 14]) << 8) | ord($binary[$tcpOffset + 15]);
        $dataOffset = (ord($binary[$tcpOffset + 12]) >> 4) * 4;
        $optionsEnd = $tcpOffset + $dataOffset;

        $mss = null;
        $ws = null;
        $sack = false;

        $i = $tcpOffset + 20;
        while ($i < $optionsEnd && $i < strlen($binary)) {
            $optType = ord($binary[$i]);
            if ($optType === 0) break;
            if ($optType === 1) {
                $i++;
                continue;
            }
            if ($i + 1 >= strlen($binary)) break;
            $optLen = ord($binary[$i + 1]);
            if ($optLen < 2 || $i + $optLen > strlen($binary)) break;

            if ($optType === 2 && $optLen === 4) {
                $mss = (ord($binary[$i + 2]) << 8) | ord($binary[$i + 3]);
            } elseif ($optType === 3 && $optLen === 3) {
                $ws = ord($binary[$i + 2]);
            } elseif ($optType === 4 && $optLen === 2) {
                $sack = true;
            }
            $i += $optLen;
        }

        return ['ttl' => $ttl, 'windowSize' => $windowSize, 'mss' => $mss, 'ws' => $ws, 'sack' => $sack];
    }

    /**
     * Classifie l'OS à partir du fingerprint de la pile TCP/IP.
     */
    public static function classifyTcpOs(?array $fingerprint): string
    {
        if (!$fingerprint) return 'unknown';
        $ttl = $fingerprint['ttl'] ?? 64;
        $windowSize = $fingerprint['windowSize'] ?? 0;
        $ws = $fingerprint['ws'] ?? null;

        if ($ttl > 64 && $ttl <= 128) {
            return 'Windows';
        }
        if ($ttl > 32 && $ttl <= 64) {
            if ($windowSize === 29200 || $windowSize === 14600 || $windowSize === 5840) {
                return 'Linux';
            }
            return 'Linux';
        }
        if ($ttl <= 64) {
            if ($windowSize === 65535 && ($ws === 6 || $ws === 8 || $ws === 5)) {
                return 'macOS/iOS';
            }
        }
        if ($ttl > 64) return 'Windows';
        if ($ttl > 0) return 'Linux';
        return 'unknown';
    }

    /**
     * Détecte les anomalies de pile réseau par rapport au User-Agent.
     */
    public static function getTcpAnomalyScore(RequestContext $context): array
    {
        $fp = null;
        $rawTcpBinary = $context->getHeader('x-raw-tcp-binary') ?? $context->headers['x-raw-tcp-binary'] ?? null;
        if ($rawTcpBinary) {
            $binary = @hex2bin($rawTcpBinary) ?: $rawTcpBinary;
            $fp = self::parseTcpSyn($binary);
        }

        if (!$fp) {
            $tcpHeader = $context->getHeader('x-tcp-fingerprint') ?? $context->tcpFingerprint ?? null;
            if ($tcpHeader && is_string($tcpHeader)) {
                $parts = explode(':', $tcpHeader);
                if (count($parts) >= 2) {
                    $fp = [
                        'ttl' => (int)$parts[0],
                        'windowSize' => (int)$parts[1],
                        'mss' => isset($parts[2]) ? (int)$parts[2] : null,
                        'ws' => isset($parts[3]) ? (int)$parts[3] : null,
                        'sack' => isset($parts[4]) && ($parts[4] === '1' || $parts[4] === 'true')
                    ];
                }
            }
        }

        if (!$fp) {
            return ['tcpAnomalyScore' => 0.0];
        }

        $tcpOs = self::classifyTcpOs($fp);
        $ua = $context->getHeader('user-agent') ?? '';
        $uaParts = self::parseUserAgent($ua);
        $uaOs = $uaParts['os'] ?? null;

        if (!$uaOs || $tcpOs === 'unknown') {
            return ['tcpAnomalyScore' => 0.0];
        }

        $mappedOs = null;
        if (str_starts_with($uaOs, 'Windows')) {
            $mappedOs = 'Windows';
        } elseif (str_starts_with($uaOs, 'Mac') || str_starts_with($uaOs, 'macOS')) {
            $mappedOs = 'macOS';
        } elseif (str_starts_with($uaOs, 'iOS')) {
            $mappedOs = 'iOS';
        } elseif (str_starts_with($uaOs, 'Linux')) {
            $mappedOs = 'Linux';
        }

        if ($mappedOs === null) {
            return ['tcpAnomalyScore' => 0.0];
        }

        $osExpectedTcp = [
            'Windows' => ['ttl' => 128, 'windowSize' => 64240, 'ws' => 8, 'mss' => 1460, 'sack' => true],
            'Linux' => ['ttl' => 64, 'windowSize' => 29200, 'ws' => 7, 'mss' => 1460, 'sack' => true],
            'macOS' => ['ttl' => 64, 'windowSize' => 65535, 'ws' => 6, 'mss' => 1460, 'sack' => true],
            'iOS' => ['ttl' => 64, 'windowSize' => 65535, 'ws' => 6, 'mss' => 1460, 'sack' => true]
        ];

        $expected = $osExpectedTcp[$mappedOs];
        $ttlDiff = abs($fp['ttl'] - $expected['ttl']) / $expected['ttl'];
        $winDiff = abs($fp['windowSize'] - $expected['windowSize']) / $expected['windowSize'];
        $wsDiff = $expected['ws'] !== null && ($fp['ws'] ?? null) !== null ? abs($fp['ws'] - $expected['ws']) / $expected['ws'] : 0.0;
        $mssDiff = $expected['mss'] !== null && ($fp['mss'] ?? null) !== null ? abs($fp['mss'] - $expected['mss']) / $expected['mss'] : 0.0;
        $sackDiff = ($fp['sack'] ?? true) === ($expected['sack'] ?? true) ? 0.0 : 1.0;

        $deviation = (
            min(1.0, $ttlDiff) * 0.50 +
            min(1.0, $winDiff) * 0.25 +
            min(1.0, $wsDiff) * 0.15 +
            min(1.0, $mssDiff) * 0.05 +
            $sackDiff * 0.05
        );

        $tcpAnomalyScore = 0.0;
        if ($tcpOs !== $mappedOs && $tcpOs !== 'unknown') {
            $baseAnomaly = $mappedOs === 'Windows' ? 80.0 :
                (($mappedOs === 'macOS' || $mappedOs === 'iOS') ? 85.0 : 75.0);
            $tcpAnomalyScore = $baseAnomaly + ($deviation - 0.4) * 10.0;
        } else {
            $tcpAnomalyScore = $deviation * 40.0;
        }

        $tcpAnomalyScore = max(0.0, min(100.0, round($tcpAnomalyScore, 1)));
        return ['tcpAnomalyScore' => $tcpAnomalyScore];
    }

    /**
     * Détecte les anomalies de flux QUIC/HTTP3 par rapport au User-Agent.
     * @param RequestContext $context
     * @return array{'quicAnomalyScore': float}
     */
    public static function getQuicAnomalyScore(RequestContext $context): array
    {
        $quicFp = $context->getHeader('x-quic-fp') ?? $context->quicFingerprint ?? null;
        if (empty($quicFp) || !is_string($quicFp)) {
            return ['quicAnomalyScore' => 0.0];
        }

        $parts = explode(';', $quicFp);
        if (count($parts) < 2) {
            return ['quicAnomalyScore' => 0.0];
        }

        $params = [];
        foreach (explode(',', $parts[1]) as $p) {
            $kv = explode('=', $p, 2);
            if (count($kv) === 2) {
                $params[$kv[0]] = $kv[1];
            }
        }
        $priorityOrder = $parts[2] ?? '';

        $ua = $context->getHeader('user-agent') ?? '';
        $uaParts = self::parseUserAgent($ua);
        $browser = $uaParts['browser'] ?? null;

        if (empty($browser)) {
            return ['quicAnomalyScore' => 0.0];
        }

        $anomaly = 0.0;
        if (str_starts_with($browser, 'Chrome') || str_starts_with($browser, 'Edge')) {
            $maxData = isset($params['1']) ? (int)$params['1'] : 0;
            $maxStreams = isset($params['4']) ? (int)$params['4'] : 0;
            if ($maxData > 0 && $maxData < 1048576) $anomaly += 40.0;
            if ($maxStreams > 0 && $maxStreams !== 100) $anomaly += 30.0;
            if (!empty($priorityOrder) && !str_contains($priorityOrder, 'u=')) $anomaly += 30.0;
        } elseif (str_starts_with($browser, 'Firefox')) {
            $maxData = isset($params['1']) ? (int)$params['1'] : 0;
            if ($maxData > 0 && $maxData > 5000000) $anomaly += 40.0;
        }

        return ['quicAnomalyScore' => max(0.0, min(100.0, $anomaly))];
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

        if (str_contains($ticket, '.')) {
            $parts = explode('.', $ticket);
            if (count($parts) === 3) {
                $base64UrlDecode = function ($input) {
                    return base64_decode(strtr($input, '-_', '+/'));
                };
                $iv = $base64UrlDecode($parts[0]);
                $encrypted = $base64UrlDecode($parts[1]);
                $signature = $base64UrlDecode($parts[2]);
                if ($iv && $encrypted && $signature && strlen($iv) === 16) {
                    $key = hash('sha256', $secret ?: "fallback-dev-secret-32-chars-minimum", true);
                    $expectedSignature = hash_hmac('sha256', $iv . $encrypted, $key, true);
                    if (hash_equals($expectedSignature, $signature)) {
                        $decrypted = openssl_decrypt($encrypted, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
                        if ($decrypted !== false) {
                            $ticketData = json_decode($decrypted, true);
                            if ($ticketData) {
                                $expiry = $ticketData['expiry'] ?? null;
                                $originalIp = $ticketData['originalIp'] ?? null;
                                $storedDeviceId = $ticketData['deviceId'] ?? '';
                                $storedDeviceHash = $ticketData['deviceHash'] ?? '';
                                if (!$expiry || (time() * 1000) > (int)$expiry) {
                                    return false;
                                }
                                if ($ip === $originalIp) {
                                    return true;
                                }
                                $currentSubnet = self::getIpSubnet($ip);
                                $originalSubnet = self::getIpSubnet($originalIp);
                                if ($currentSubnet !== null && $originalSubnet !== null && $currentSubnet === $originalSubnet) {
                                    return true;
                                }
                                return !empty($deviceId) && $deviceId === $storedDeviceId && !empty($deviceHash) && $deviceHash === $storedDeviceHash;
                            }
                        }
                    }
                }
            }
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