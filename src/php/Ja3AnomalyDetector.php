<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint;

/**
 * Classe de détection d'anomalies et d'usurpation TLS (JA3) en PHP.
 */
class Ja3AnomalyDetector
{
    // Liste décimale des valeurs GREASE (RFC 8701) utilisées par les moteurs Chromium/Safari récents
    private const GREASE_VALUES = [
        2570, 6682, 10794, 14906, 19018, 23130, 27242, 31354,
        35466, 39578, 43690, 47802, 51914, 55926, 60038, 64150
    ];

    // Base de données locale de signatures JA3 MD5 connues pour la corroboration de base
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
        // Bibliothèques et scrapers automatisés connus
        '47344a349b75c4e82333475553b5f358' => ['Python'],
        'b29587b8a143c42546133ad7704b3310' => ['Go'],
        'd435b5223b2884c5a832b842637e245f' => ['Java'],
        'c72366b9551263d990b7fa574225332c' => ['curl'],
    ];

    /**
     * Analyse une chaîne JA3 brute non hachée.
     * Format attendu : "TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurveFormats"
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
     * Vérifie si un tableau contient au moins une valeur GREASE.
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
     * Parse sommairement le User-Agent pour en extraire la famille de navigateur.
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
     * Calcule le score global d'anomalie et d'usurpation JA3.
     * 
     * @param string|null $ja3Hash L'empreinte MD5 du JA3 (32 caractères)
     * @param string|null $ja3Raw L'empreinte brute non hachée (si disponible)
     * @param string $userAgent Le User-Agent de la requête
     * @param string $httpVersion La version HTTP de la requête (ex: "HTTP/2", "HTTP/1.1", ou "2.0")
     * @param object|null $cacheInstance Un driver de cache (ex: instance Redis) supportant get() et set() pour la détection de stagnation
     * @return int Un score de suspicion compris entre 0 et 100
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

        // --- ANALYSE 1 : CONTRÔLE SUR LE MD5 DU JA3 ---
        if ($ja3Hash && strlen($ja3Hash) === 32) {
            if (isset(self::TLS_FINGERPRINT_DB[$ja3Hash])) {
                $expectedBrowsers = self::TLS_FINGERPRINT_DB[$ja3Hash];

                // Cas A : L'empreinte correspond à un outil de scraping mais le UA prétend être humain
                $isLibrary = array_intersect($expectedBrowsers, ['Python', 'Go', 'Java', 'curl']);
                if (!empty($isLibrary) && $isHumanBrowser) {
                    $score = max($score, 90); // Suspicion maximale : usurpation évidente
                }
                
                // Cas B : Incohérence directe entre le UA prétendu et la stack TLS correspondante
                if ($claimedBrowser !== null) {
                    $matched = false;
                    foreach ($expectedBrowsers as $expected) {
                        if (stripos($claimedBrowser, $expected) === 0) {
                            $matched = true;
                            break;
                        }
                    }
                    if (!$matched) {
                        $score = max($score, 80); // Le navigateur déclaré ne correspond pas au client TLS utilisé
                    }
                }
            }

            // Cas C : Tracking de stagnation multi-UA (Stateful)
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
                        // Cache pendant 24 heures (86400 secondes)
                        if (method_exists($cacheInstance, 'setex')) {
                            $cacheInstance->setex($cacheKey, 86400, json_encode($seenBrowsers));
                        } else {
                            $cacheInstance->set($cacheKey, json_encode($seenBrowsers), 86400);
                        }
                    }

                    // Si une seule stack TLS génère des requêtes avec différents navigateurs, c'est un bot en rotation de UA
                    if (count($seenBrowsers) > 1) {
                        $score = max($score, 85);
                    }
                } catch (\Throwable $e) {
                    // Tolérance aux pannes du cache
                }
            }
        }

        // --- ANALYSE 2 : CONTRÔLE PROFOND SUR L'EMPREINTE BRUTE (RAW JA3) ---
        if ($ja3Raw) {
            $parsed = self::parseJa3($ja3Raw);
            if ($parsed) {
                // Contrôle A : Mécanisme GREASE pour Chrome / Edge (obligatoire)
                if ($claimedBrowser === 'Chrome' || $claimedBrowser === 'Edge') {
                    $hasCiphersGrease = self::hasGrease($parsed['ciphers']);
                    $hasExtensionsGrease = self::hasGrease($parsed['extensions']);
                    
                    if (!$hasCiphersGrease && !$hasExtensionsGrease) {
                        // Chrome ou Edge moderne sans GREASE = spoofing de bas niveau (ex: python-requests déguisé)
                        $score = max($score, 75);
                    }
                }

                // Contrôle B : HTTP/2 ou HTTP/3 sans négociation ALPN (Extension 16)
                $isH2OrHigher = (
                    strpos($httpVersion, '2.0') !== false || 
                    strpos($httpVersion, 'HTTP/2') !== false || 
                    strpos($httpVersion, 'HTTP/3') !== false
                );
                $hasAlpnExtension = in_array(16, $parsed['extensions'], true);
                
                if ($isH2OrHigher && !$hasAlpnExtension) {
                    // Négociation HTTP/2 active au niveau serveur mais absente au niveau des extensions TLS du client
                    $score = max($score, 70);
                }

                // Contrôle C : Version TLS obsolète négociée par un navigateur moderne (ex: TLS < 1.2, id < 771)
                if ($isHumanBrowser && $parsed['tlsVersion'] < 771) {
                    $score = max($score, 80);
                }
            }
        }

        return $score;
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