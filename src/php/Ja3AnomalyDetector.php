<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint;

/**
 * TLS (JA3) fingerprint anomaly and spoofing detector in PHP.
 */
class Ja3AnomalyDetector
{
    // Decimal GREASE values (RFC 8701) used by Chromium and Safari TLS stacks
    private const GREASE_VALUES = [
        2570, 6682, 10794, 14906, 19018, 23130, 27242, 31354,
        35466, 39578, 43690, 47802, 51914, 55926, 60038, 64150
    ];

    // Known JA3 MD5 signatures for baseline cross-layer verification
    private const TLS_FINGERPRINT_DB = [
        'e188a442b87f422c5a1e80b05399435b' => ['Chrome'],
        'd8e35855049321c6042a4325c697858f' => ['Chrome'],
        'a9f90958d44533748c139a5d1895b925' => ['Chrome'],
        '3b5379916d2b3882253c42885956a350' => ['Chrome'],
        '59822058c95c33d2d06e52f410855c8c' => ['Chrome'],
        'b386946a5a586163c7c533636b45c355' => ['Firefox'],
        '66236495a523c1785f8f3a105b248b11' => ['Firefox'],
        'b73d470006575b5e35167a0b5a8540e2' => ['Firefox'],
        '8443d7562933834333943465d52363cf' => ['Firefox'],
        'b633f21d532d35967c8753c38536b4d3' => ['Safari'],
        '4d7a28d5f55b359b69100a311013f03e' => ['Safari', 'Chrome', 'Firefox'],
        '8dd3d7532873575314df23c447543001' => ['Safari', 'Chrome', 'Firefox'],
        // Automated scraper and library fingerprints
        '47344a349b75c4e82333475553b5f358' => ['Python'],
        'b29587b8a143c42546133ad7704b3310' => ['Go'],
        'd435b5223b2884c5a832b842637e245f' => ['Java'],
        'c72366b9551263d990b7fa574225332c' => ['curl'],
    ];

    /**
     * Parses a raw JA3 string.
     * Expected format: "TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurveFormats"
     */
    public static function parseJa3(string $ja3String): ?array
    {
        if (empty($ja3String)) {
            return null;
        }

        $parts = explode(',', $ja3String);
        if (count($parts) !== 5) {
            return null;
        }

        return [
            'tlsVersion' => (int)$parts[0],
            'ciphers'    => $parts[1] !== '' ? array_map('intval', explode('-', $parts[1])) : [],
            'extensions' => $parts[2] !== '' ? array_map('intval', explode('-', $parts[2])) : [],
            'curves'     => $parts[3] !== '' ? array_map('intval', explode('-', $parts[3])) : [],
            'points'     => $parts[4] !== '' ? array_map('intval', explode('-', $parts[4])) : []
        ];
    }

    /**
     * Checks if a collection contains any GREASE value.
     */
    public static function hasGrease(array $values): bool
    {
        foreach ($values as $val) {
            if (in_array($val, self::GREASE_VALUES, true)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Extracts browser family from User-Agent string.
     */
    public static function getBrowserFamily(string $userAgent): ?string
    {
        $ua = strtolower($userAgent);
        if (strpos($ua, 'edg') !== false) {
            return 'Edge';
        }
        if (strpos($ua, 'chrome') !== false) {
            return 'Chrome';
        }
        if (strpos($ua, 'firefox') !== false) {
            return 'Firefox';
        }
        if (strpos($ua, 'safari') !== false) {
            return 'Safari';
        }
        return null;
    }

    /**
     * Evaluates comprehensive JA3 spoofing and anomaly suspicion score.
     * 
     * @param string|null $ja3Hash MD5 hash of JA3 fingerprint (32 hex characters).
     * @param string|null $ja3Raw Raw unhashed JA3 string if available.
     * @param string $userAgent Request User-Agent header.
     * @param string $httpVersion HTTP protocol version string.
     * @param object|null $cacheInstance Cache store for multi-UA stagnation detection.
     * @return int Suspicion score between 0 and 100.
     */
    public static function getJa3AnomalyScore(
        ?string $ja3Hash,
        ?string $ja3Raw,
        string $userAgent,
        string $httpVersion,
        ?object $cacheInstance = null
    ): int {
        $score = 0;
        $claimedBrowser = self::getBrowserFamily($userAgent);
        $isHumanBrowser = in_array($claimedBrowser, ['Chrome', 'Firefox', 'Safari', 'Edge'], true);

        // --- ANALYSIS 1: MD5 JA3 HASH VERIFICATION ---
        if ($ja3Hash && strlen($ja3Hash) === 32) {
            if (isset(self::TLS_FINGERPRINT_DB[$ja3Hash])) {
                $expectedBrowsers = self::TLS_FINGERPRINT_DB[$ja3Hash];

                // Case A: TLS matches known automated library but UA claims standard browser
                $isLibrary = array_intersect($expectedBrowsers, ['Python', 'Go', 'Java', 'curl']);
                if (!empty($isLibrary) && $isHumanBrowser) {
                    $score = max($score, 90); // High confidence spoofing
                }
                
                // Case B: Direct discrepancy between claimed browser and expected TLS stack
                if ($claimedBrowser !== null) {
                    $matched = false;
                    foreach ($expectedBrowsers as $expected) {
                        if (stripos($claimedBrowser, $expected) === 0) {
                            $matched = true;
                            break;
                        }
                    }
                    if (!$matched) {
                        $score = max($score, 80); // Browser family mismatch
                    }
                }
            }

            // Case C: Stateful multi-UA stagnation detection
            if ($cacheInstance && $claimedBrowser !== null && method_exists($cacheInstance, 'get') && method_exists($cacheInstance, 'set')) {
                $cacheKey = "ja3-browsers:" . $ja3Hash;
                
                try {
                    $rawCached = $cacheInstance->get($cacheKey);
                    $seenBrowsers = $rawCached ? json_decode((string)$rawCached, true) : [];
                    if (!is_array($seenBrowsers)) {
                        $seenBrowsers = [];
                    }

                    if (!in_array($claimedBrowser, $seenBrowsers, true)) {
                        $seenBrowsers[] = $claimedBrowser;
                        // Cache for 24 hours (86400 seconds)
                        if (method_exists($cacheInstance, 'setex')) {
                            $cacheInstance->setex($cacheKey, 86400, json_encode($seenBrowsers));
                        } else {
                            $cacheInstance->set($cacheKey, json_encode($seenBrowsers), 86400);
                        }
                    }

                    // Multiple rotating browser UAs emitted from identical TLS stack
                    if (count($seenBrowsers) > 1) {
                        $score = max($score, 85);
                    }
                } catch (\Throwable $e) {
                    // Fault-tolerant fallback on cache error
                }
            }
        }

        // --- ANALYSIS 2: DEEP INSPECTION ON RAW JA3 STRING ---
        if ($ja3Raw) {
            $parsed = self::parseJa3($ja3Raw);
            if ($parsed) {
                // Check A: GREASE presence for Chrome / Edge
                if ($claimedBrowser === 'Chrome' || $claimedBrowser === 'Edge') {
                    $hasCiphersGrease = self::hasGrease($parsed['ciphers']);
                    $hasExtensionsGrease = self::hasGrease($parsed['extensions']);
                    
                    if (!$hasCiphersGrease && !$hasExtensionsGrease) {
                        // Modern Chromium missing GREASE indicates spoofing
                        $score = max($score, 75);
                    }
                }

                // Check B: HTTP/2 or HTTP/3 without ALPN extension (Extension 16)
                $isH2OrHigher = (
                    strpos($httpVersion, '2.0') !== false || 
                    strpos($httpVersion, 'HTTP/2') !== false || 
                    strpos($httpVersion, 'HTTP/3') !== false
                );
                $hasAlpnExtension = in_array(16, $parsed['extensions'], true);
                
                if ($isH2OrHigher && !$hasAlpnExtension) {
                    // HTTP/2 active at server level but missing from client ALPN extension
                    $score = max($score, 70);
                }

                // Check C: Deprecated TLS version negotiated by claimed modern browser
                if ($isHumanBrowser && $parsed['tlsVersion'] < 771) {
                    $score = max($score, 80);
                }
            }
        }

        return $score;
    }

    /**
     * Correlates low-level TCP RTT with application layer latency to detect residential proxy hops.
     * Evaluates continuous physical transit discrepancies rather than arbitrary step numbers.
     * 
     * @param RequestContext $context
     * @return float Suspicion score between 0.0 and 95.0
     */
    public static function getRttProxyScore(RequestContext $context): float
    {
        $tcpRttHeader = $context->headers['x-tcp-rtt'] ?? $context->headers['x-real-rtt'] ?? null;
        $tcpRtt = $tcpRttHeader !== null ? (int)$tcpRttHeader : null;

        $behaviorHeader = $context->headers['x-behavior-metrics'] ?? null;
        if ($behaviorHeader) {
            $metrics = json_decode($behaviorHeader, true);
            if (json_last_error() === JSON_ERROR_NONE && isset($metrics['clientTimestamp']) && is_numeric($metrics['clientTimestamp'])) {
                $clientTimestamp = (int)$metrics['clientTimestamp'];
                $appLatency = $context->requestTimestamp - $clientTimestamp;

                if ($tcpRtt !== null && $tcpRtt > 0 && $appLatency > 0) {
                    // Marge de tolérance défensive contre le jitter réseau et le scheduling JS / Garbage Collection
                    $jitterAllowance = 60.0;
                    $effectiveRtt = max((float)$tcpRtt, 5.0);
                    $tunnelDelta = $appLatency - ($tcpRtt + $jitterAllowance);
                    $divergenceRatio = $appLatency / $effectiveRtt;

                    // Condition de disjonction : liaison edge ultra-proche (< 40ms) + transit applicatif au moins 3x supérieur
                    if ($tcpRtt <= 40 && $divergenceRatio >= 3.0 && $tunnelDelta > 0) {
                        $scaling = 120.0;
                        $ratioWeight = min(1.0, ($divergenceRatio - 3.0) / 5.0);
                        $proxyScore = min(95.0, 40.0 + 55.0 * tanh($tunnelDelta / $scaling) * $ratioWeight);
                        return round($proxyScore, 1);
                    }
                }
            }
        }
        return 0.0;
    }
}

// --- EXEMPLE D'UTILISATION PRATIQUE ---
/*
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
$httpVersion = $_SERVER['SERVER_PROTOCOL'] ?? '';

// Récupération des en-têtes injectés par votre Reverse-Proxy (Nginx, HAProxy, etc.)
$ja3Hash = $_SERVER['HTTP_X_JA3_HASH'] ?? null;
$ja3Raw  = $_SERVER['HTTP_X_JA3_RAW'] ?? null; 

// Redis facultatif pour la détection stateful de rotation UA
$redis = new \Redis();
$redis->connect('127.0.0.1', 6379);

$suspicionScore = Ja3AnomalyDetector::getJa3AnomalyScore($ja3Hash, $ja3Raw, $userAgent, $httpVersion, $redis);
*/