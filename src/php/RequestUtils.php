<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint;

use Anonympins\Fingerprint\FingerprintBuilder;

/**
 * Fournit des fonctions utilitaires pour extraire des informations et calculer
 * des scores de suspicion à partir d'un objet RequestContext.
 */
class RequestUtils
{
    /**
     * Base de données de fingerprints TLS (JA3) connus.
     * @var array<string, string|string[]>
     */
    private const TLS_FINGERPRINT_DB = [
        // --- Chrome (Desktop) ---
        'e188a442b87f422c5a1e80b05399435b' => 'Chrome',
        'd8e35855049321c6042a4325c697858f' => 'Chrome',
        'a9f90958d44533748c139a5d1895b925' => 'Chrome',
        '3b5379916d2b3882253c42885956a350' => 'Chrome',
        // --- Firefox (Desktop) ---
        'b386946a5a586163c7c533636b45c355' => 'Firefox',
        '66236495a523c1785f8f3a105b248b11' => 'Firefox',
        // --- Safari & iOS (Shared TLS Stack) ---
        'b633f21d532d35967c8753c38536b4d3' => 'Safari',
        '4d7a28d5f55b359b69100a311013f03e' => ['Safari', 'Chrome', 'Firefox'],
        // --- Common Libraries & Bots ---
        '47344a349b75c4e82333475553b5f358' => 'Python',
        'b29587b8a143c42546133ad7704b3310' => 'Go',
        'd435b5223b2884c5a832b842637e245f' => 'Java',
        'c72366b9551263d990b7fa574225332c' => 'curl',
    ];

    /**
     * Construit une empreinte composite côté serveur.
     */
    public static function getCompositeDeviceHash(RequestContext $context): string
    {
        $srv = new FingerprintBuilder();

        $clientFp = $context->getHeader('x-device-fingerprint');
        if ($clientFp && str_contains($clientFp, 'cvs:')) {
            $srv->add("client_fp_hash", $clientFp);
        }

        // 1. User Agent
        $ua = $context->getHeader("user-agent");
        if ($ua) {
            $srv->add("ua", $ua);
        }

        // 2. Signaux de bas niveau (fournis par le proxy)
        if ($context->ja3) $srv->add("ja3", $context->ja3);
        if ($context->ja4) $srv->add("ja4", $context->ja4);
        if ($context->http2Fingerprint) $srv->add("h2", $context->http2Fingerprint);
        if ($context->tcpFingerprint) $srv->add("tcp", $context->tcpFingerprint);

        // 3. Signaux de haut niveau (en-têtes)
        $headersToCapture = [
            "ch_ua" => "sec-ch-ua",
            "ch_platform" => "sec-ch-ua-platform",
            "ch_mobile" => "sec-ch-ua-mobile",
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

        // 4. Signaux de contexte
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
     * Calcule un score basé sur les anomalies des en-têtes HTTP.
     */
    public static function getHeaderAnomalies(RequestContext $context): array
    {
        $anomalyScore = 0;
        $ua = $context->getHeader("user-agent");

        if (!$ua || strlen($ua) < 10) {
            $anomalyScore += 60;
        }
        if (!$context->getHeader("accept-language")) {
            $anomalyScore += 25;
        }
        if ($context->httpVersion === "1.0") {
            $anomalyScore += 15;
        }

        return ['headerAnomalyScore' => min(100, $anomalyScore)];
    }

    /**
     * Calcule un score d'incohérence entre le fingerprint TLS (JA3) et le User-Agent.
     */
    public static function getTlsSpoofingScore(RequestContext $context): array
    {
        $ja3 = $context->ja3;
        $ua = $context->getHeader("user-agent") ?? '';

        if ($ja3 && (strlen($ua) < 10 || str_contains(strtolower($ua), 'python') || str_contains(strtolower($ua), 'curl'))) {
            return ['tlsSpoofingScore' => 50];
        }

        if ($ja3 && $ua) {
            $expectedBrowsers = self::TLS_FINGERPRINT_DB[$ja3] ?? null;

            if ($expectedBrowsers) {
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
                        return ['tlsSpoofingScore' => 80];
                    }
                }
            }
        }

        return ['tlsSpoofingScore' => 0];
    }

    /**
     * Analyse basique d'un User-Agent.
     * @return array{browser?: string, os?: string, device?: string}
     */
    public static function parseUserAgent(string $ua): array
    {
        $result = [];

        // Détection du navigateur
        if (preg_match('/Chrome\/(\d+)/', $ua) && !str_contains($ua, 'Edg')) {
            $result['browser'] = 'Chrome';
        } elseif (preg_match('/Firefox\/(\d+)/', $ua)) {
            $result['browser'] = 'Firefox';
        } elseif (preg_match('/Safari\/(\d+)/', $ua) && !str_contains($ua, 'Chrome')) {
            $result['browser'] = 'Safari';
        } elseif (preg_match('/Edg\/(\d+)/', $ua)) {
            $result['browser'] = 'Edge';
        }

        // Détection de l'OS
        if (str_contains($ua, 'Windows NT 10.0')) $result['os'] = 'Windows';
        elseif (str_contains($ua, 'Mac OS X')) $result['os'] = 'macOS';
        elseif (str_contains($ua, 'Linux') && !str_contains($ua, 'Android')) $result['os'] = 'Linux';
        elseif (str_contains($ua, 'Android')) $result['os'] = 'Android';
        elseif (str_contains($ua, 'iPhone') || str_contains($ua, 'iPad')) $result['os'] = 'iOS';

        // Détection du type d'appareil
        if (str_contains($ua, 'Mobile')) $result['device'] = 'mobile';
        elseif (str_contains($ua, 'Tablet')) $result['device'] = 'tablet';
        else $result['device'] = 'desktop';

        return $result;
    }

    /**
     * Vérifie si une IP est privée.
     */
    public static function isPrivateIp(string $ip): bool
    {
        return filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        ) === false;
    }

    /**
     * Calcule un score basé sur l'incohérence temporelle entre client et serveur.
     */
    public static function getTimeInconsistencyScore(RequestContext $context): array
    {
        $behaviorHeader = $context->getHeader('x-behavior-metrics');
        if (!$behaviorHeader) {
            return ['timeInconsistencyScore' => 0];
        }

        $metrics = json_decode($behaviorHeader, true);
        $clientTimestamp = $metrics['clientTimestamp'] ?? null;

        if ($clientTimestamp && $context->requestTimestamp) {
            $timeDelta = $context->requestTimestamp - $clientTimestamp;
            $replayThresholdMs = 5000; // 5 secondes

            if ($timeDelta > $replayThresholdMs) {
                $score = min(100, ($timeDelta / $replayThresholdMs - 1) * 50);
                return ['timeInconsistencyScore' => $score];
            }
        }

        return ['timeInconsistencyScore' => 0];
    }
}