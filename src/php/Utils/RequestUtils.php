<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Utils;

use Anonympins\Fingerprint\FingerprintBuilder;
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

        $score = 0;
        if (($metrics['mouseEntropy'] ?? 0) == 0 && ($metrics['keystrokeLatency'] ?? 0) == 0) {
            $score += 40;
        }

        if (isset($metrics['historyLength'])) {
            if ($metrics['historyLength'] === 1) $score += 15;
            elseif ($metrics['historyLength'] >= 5) $score -= 20;
            elseif ($metrics['historyLength'] >= 2) $score -= 10;
        }

        if (($metrics['mouseEntropy'] ?? 0) > 0 && $metrics['mouseEntropy'] < 0.1) $score += 20;
        if (($metrics['mouseEntropy'] ?? 0) > 500) $score += 30;

        if (($metrics['keystrokeLatency'] ?? 0) > 0 && $metrics['keystrokeLatency'] < 40) $score += 25;
        if (($metrics['keystrokeLatency'] ?? 0) > 1000) $score += 15;

        return ['behaviorScore' => max(0.0, min(100.0, $score))];
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
     */
    public static function getTimeInconsistencyScore(RequestContext $context): array
    {
        $behaviorHeader = $context->getHeader('x-behavior-metrics');
        if (!$behaviorHeader) return ['timeInconsistencyScore' => 0.0];

        $metrics = json_decode($behaviorHeader, true);
        if (json_last_error() !== JSON_ERROR_NONE || empty($metrics['clientTimestamp'])) {
            return ['timeInconsistencyScore' => 0.0];
        }

        $timeDelta = $context->requestTimestamp - $metrics['clientTimestamp'];
        $replayThreshold = 5000; // 5 secondes

        if ($timeDelta > $replayThreshold) {
            $score = min(100.0, ($timeDelta / $replayThreshold - 1) * 50);
            return ['timeInconsistencyScore' => $score];
        }

        return ['timeInconsistencyScore' => 0.0];
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

    // Les fonctions suivantes sont des placeholders pour les fonctionnalités qui dépendent d'un état
    // ou d'une logique plus complexe qui sera entièrement gérée par FingerprintEngine.
    // Elles sont ici pour la complétude de l'API de RequestUtils.

    public static function getBehavioralIndicators(RequestContext $context, array &$deviceData): array
    {
        // La logique de cette fonction (rotation d'IP, etc.) est complexe et dépend de l'état
        // stocké. Elle sera implémentée directement dans FingerprintEngine ou une classe dédiée à l'état.
        return ['historyScore' => 0.0, 'rotationScore' => 0.0];
    }

    public static function getRequestPatternScore(RequestContext $context, array &$deviceData, array $patternConfig): array
    {
        return ['requestPatternScore' => 0.0];
    }

    public static function getHoneypotScore(RequestContext $context, array $honeypotConfig): array
    {
        return ['honeypotScore' => 0.0];
    }

    public static function getThreatIntelScore(RequestContext $context, array $threatIntelConfig): array
    {
        return ['threatIntelScore' => 0.0];
    }
}