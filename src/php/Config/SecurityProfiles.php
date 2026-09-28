<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Config;

/**
 * Defines predefined security profiles for the Fingerprint library.
 * These profiles contain suspicion score weights and trigger thresholds.
 */
class SecurityProfiles
{
    /**
     * @var array<string, array<string, mixed>>
     */
    public const PROFILES = [
        /**
         * Balanced Profile (Default)
         * A general-purpose configuration suitable for most websites, offering a good mix of security and user experience.
         * It's sensitive enough to catch common bots without being overly aggressive towards legitimate users.
         */
        'balanced' => [
            'summary' => 'Balanced Profile (Default)',
            'description' => 'A general-purpose configuration suitable for most websites, offering a good mix of security and user experience. It\'s sensitive enough to catch common bots without being overly aggressive towards legitimate users.',
            'weights' => [
                'historyScore' => 0.3,
                'rotationScore' => 0.5,
                'headerAnomalyScore' => 0.1,
                'requestPatternScore' => 0.6,
                'inconsistencyScore' => 0.8,
                'behaviorScore' => 0.7,
                'honeypotScore' => 1.0,
                'crossLayerInconsistencyScore' => 0.4,
                'timeInconsistencyScore' => 0.9,
                'tlsSpoofingScore' => 0.8,
                'botScore' => 1.0,
                'cookieDroppingScore' => 0.4,
                'threatIntelScore' => 0.4,
                'clientHintsInconsistencyScore' => 0.7,
                'clickVarianceScore' => 0.6,
                'subnetScore' => 0.5,
                'ipReputationScore' => 0.5,
                'botnetClusterScore' => 0.6,
                'tcpAnomalyScore' => 0.8,
                'protocolAnomalyScore' => 0.8,
                'http2AnomalyScore' => 0.8,
                'quicAnomalyScore' => 0.8,
                'renderingAnomalyScore' => 0.8,
                'virtualizationScore' => 0.8,
                'mtuAnomalyScore' => 0.9,
            ],
            'thresholds' => ['low' => 20, 'medium' => 45, 'high' => 75, 'block' => 95],
            'patterns' => [
                'velocityThreshold' => 800,
                'burstThreshold' => 1500,
                'scrapeThreshold' => 1000,
                'historySize' => 10,
                'minSamples' => 5,
                'regularityThreshold' => 50,
                'benfordThreshold' => 0.15,
                'patternWeight' => 80,
                'decayFactor' => 0.9,
                'inactivityReset' => 5000,
            ],
            'cpu' => [
                'minDifficultyBits' => 8,
                'maxDifficultyBits' => 22,
            ],
        'filterWhitelist' => 85.0, // Moderate inspection strategy for allowlisted IPs/paths
        'wasm' => true,
        ],

        /**
         * Strict Profile
         * An aggressive configuration for sensitive applications (e.g., financial services, admin panels).
         * It uses lower suspicion thresholds and higher penalties for anomalies, prioritizing security over user convenience.
         * All new devices are challenged by default.
         */
        'strict' => [
            'summary' => 'Strict Profile',
            'description' => 'An aggressive configuration for sensitive applications (e.g., financial services, admin panels). It uses lower suspicion thresholds and higher penalties for anomalies, prioritizing security over user convenience. All new devices are challenged by default.',
            'weights' => [
                'historyScore' => 0.4,
                'rotationScore' => 0.6,
                'headerAnomalyScore' => 0.2,
                'requestPatternScore' => 0.8,
                'inconsistencyScore' => 1.0,
                'behaviorScore' => 0.8,
                'honeypotScore' => 1.0,
                'crossLayerInconsistencyScore' => 0.6,
                'timeInconsistencyScore' => 1.0,
                'tlsSpoofingScore' => 1.0,
                'botScore' => 1.0,
                'cookieDroppingScore' => 0.6,
                'threatIntelScore' => 0.7,
                'clientHintsInconsistencyScore' => 0.9,
                'clickVarianceScore' => 0.7,
                'subnetScore' => 0.7,
                'ipReputationScore' => 0.7,
                'botnetClusterScore' => 0.8,
                'tcpAnomalyScore' => 1.0,
                'protocolAnomalyScore' => 1.0,
                'http2AnomalyScore' => 1.0,
                'quicAnomalyScore' => 1.0,
                'renderingAnomalyScore' => 1.0,
                'virtualizationScore' => 1.0,
                'mtuAnomalyScore' => 0.9,
            ],
            'thresholds' => ['low' => 10, 'medium' => 35, 'high' => 65, 'block' => 90],
            'patterns' => [
                'velocityThreshold' => 1000,
                'burstThreshold' => 1800,
                'scrapeThreshold' => 1200,
                'historySize' => 15,
                'minSamples' => 4,
                'regularityThreshold' => 40,
                'benfordThreshold' => 0.12,
                'patternWeight' => 90,
                'decayFactor' => 0.85,
                'inactivityReset' => 4000,
            ],
            'cpu' => [
                'minDifficultyBits' => 10,
                'maxDifficultyBits' => 24,
            ],
            'challengeNewDevices' => true, // Challenge all new devices
        'wasm' => true,
        'filterWhitelist' => true, // Any definite attack behavior immediately bypasses the allowlist
        ],

        /**
         * API Profile
         * Optimized for protecting API endpoints. This profile is highly sensitive to request patterns (velocity, bursts)
         * and less reliant on browser-specific behavioral metrics. It's designed to quickly identify and throttle scrapers and automated clients.
         */
        'api' => [
            'summary' => 'API Profile',
            'description' => 'Optimized for protecting API endpoints. This profile is highly sensitive to request patterns (velocity, bursts) and less reliant on browser-specific behavioral metrics. It\'s designed to quickly identify and throttle scrapers and automated clients.',
            'weights' => [
                'historyScore' => 0.5,
                'rotationScore' => 0.5,
                'headerAnomalyScore' => 0.3,
                'requestPatternScore' => 1.0, // Very high weight for API patterns
                'inconsistencyScore' => 0.7,
                'behaviorScore' => 0.2, // Lower weight, as browser behavior is not applicable
                'honeypotScore' => 1.0,
                'crossLayerInconsistencyScore' => 0.5,
                'timeInconsistencyScore' => 0.8,
                'tlsSpoofingScore' => 0.7,
                'botScore' => 0.5,
                'cookieDroppingScore' => 0.5, // Important for API clients that need to maintain state
                'threatIntelScore' => 0.5, // APIs are often targeted by malicious IPs
                'clientHintsInconsistencyScore' => 0.6, // Relevant signal for APIs
                'clickVarianceScore' => 0.3, // Low weight as not applicable to APIs
                'subnetScore' => 0.8, // Highly important for APIs to detect botnets
                'ipReputationScore' => 0.6,
                'botnetClusterScore' => 0.7,
                'tcpAnomalyScore' => 0.8,
                'protocolAnomalyScore' => 0.8,
                'http2AnomalyScore' => 0.8,
                'quicAnomalyScore' => 0.8,
                'renderingAnomalyScore' => 0.2,
                'virtualizationScore' => 0.5,
                'mtuAnomalyScore' => 0.9,
            ],
            'thresholds' => ['low' => 25, 'medium' => 50, 'high' => 80, 'block' => 95],
            'patterns' => [
                'velocityThreshold' => 200, // APIs are expected to be fast
                'burstThreshold' => 500,
                'scrapeThreshold' => 400,
                'historySize' => 20,
                'minSamples' => 8,
                'regularityThreshold' => 20,
                'benfordThreshold' => 0.18,
                'patternWeight' => 85,
                'decayFactor' => 0.9,
                'inactivityReset' => 10000,
            ],
            'cpu' => [
                'minDifficultyBits' => 8,
                'maxDifficultyBits' => 20,
            ],
            // This would be a callable in PHP, but for now, we represent its intent.
            'isApiRequest' => 'req.path.startsWith("/api/") || req.headers.accept?.includes("application/json")',
        'filterWhitelist' => 75.0, // Low threshold to defend against stolen legitimate API keys/tokens
        'wasm' => true,
        ],

        /**
         * Blog Profile
         * Tuned for blogs and content-heavy websites. This profile focuses on detecting content scraping and comment spam
         * by placing a high weight on request patterns and honeypot traps, while being more lenient on behavioral metrics
         * typical of readers.
         */
        'blog' => [
            'summary' => 'Blog Profile',
            'description' => 'Tuned for blogs and content-heavy websites. This profile focuses on detecting content scraping and comment spam by placing a high weight on request patterns and honeypot traps, while being more lenient on behavioral metrics typical of readers.',
            'weights' => [
                'historyScore' => 0.2,
                'rotationScore' => 0.3,
                'headerAnomalyScore' => 0.1,
                'requestPatternScore' => 0.8, // High weight to detect content scraping
                'inconsistencyScore' => 0.7,
                'behaviorScore' => 0.5, // Less emphasis on complex interactions
                'honeypotScore' => 1.0, // Crucial for comment spam
                'crossLayerInconsistencyScore' => 0.4,
                'timeInconsistencyScore' => 0.8,
                'tlsSpoofingScore' => 0.6,
                'botScore' => 0.8,
                'cookieDroppingScore' => 0.3,
                'threatIntelScore' => 0.3,
                'clientHintsInconsistencyScore' => 0.5,
                'clickVarianceScore' => 0.5,
                'subnetScore' => 0.4,
                'ipReputationScore' => 0.3,
                'botnetClusterScore' => 0.5,
                'tcpAnomalyScore' => 0.5,
                'protocolAnomalyScore' => 0.5,
                'http2AnomalyScore' => 0.5,
                'quicAnomalyScore' => 0.5,
                'renderingAnomalyScore' => 0.5,
                'virtualizationScore' => 0.6,
                'mtuAnomalyScore' => 0.9,
            ],
            'thresholds' => ['low' => 25, 'medium' => 55, 'high' => 80, 'block' => 95],
            'patterns' => [
                'velocityThreshold' => 1000, // Readers can be fast
                'burstThreshold' => 2000,
                'scrapeThreshold' => 800, // Very sensitive to scraping patterns
                'historySize' => 12,
                'minSamples' => 5,
                'regularityThreshold' => 60,
                'benfordThreshold' => 0.16,
                'patternWeight' => 85,
                'decayFactor' => 0.92,
                'inactivityReset' => 10000,
            ],
            'cpu' => [
                'minDifficultyBits' => 8,
                'maxDifficultyBits' => 20,
            ],
        'filterWhitelist' => 90.0, // Highly lenient, only inspects if the score is near blocking
        'wasm' => true,
        ],

        /**
         * E-commerce Profile
         * A strict profile tailored for e-commerce sites. It's designed to combat inventory scalping,
         * price scraping, and account takeover attempts by using high weights for request patterns and fingerprint inconsistency.
         * It also challenges all new devices to increase the cost for bots.
         */
        'ecommerce' => [
            'summary' => 'E-commerce Profile',
            'description' => 'A strict profile tailored for e-commerce sites. It\'s designed to combat inventory scalping, price scraping, and account takeover attempts by using high weights for request patterns and fingerprint inconsistency. It also challenges all new devices to increase the cost for bots.',
            'weights' => [
                'historyScore' => 0.4,
                'rotationScore' => 0.6,
                'headerAnomalyScore' => 0.2,
                'requestPatternScore' => 0.9,
                'inconsistencyScore' => 1.0, // Crucial for preventing account takeover
                'behaviorScore' => 0.8, // Important for checkout/login forms
                'honeypotScore' => 1.0,
                'crossLayerInconsistencyScore' => 0.7,
                'timeInconsistencyScore' => 0.9,
                'tlsSpoofingScore' => 0.9,
                'botScore' => 1.0,
                'cookieDroppingScore' => 0.6, // Crucial for e-commerce bot detection
                'threatIntelScore' => 0.8, // Very important for e-commerce (scalping proxies)
                'clientHintsInconsistencyScore' => 0.9, // Very important for e-commerce
                'clickVarianceScore' => 0.8, // Very high weight for click variance
                'subnetScore' => 0.9, // Crucial against distributed scalping attacks
                'ipReputationScore' => 0.8,
                'botnetClusterScore' => 0.9,
                'tcpAnomalyScore' => 0.9,
                'protocolAnomalyScore' => 0.9,
                'http2AnomalyScore' => 0.9,
                'quicAnomalyScore' => 0.9,
                'renderingAnomalyScore' => 0.9,
                'virtualizationScore' => 0.9,
                'mtuAnomalyScore' => 0.9,
            ],
            'thresholds' => ['low' => 15, 'medium' => 40, 'high' => 70, 'block' => 90],
            'patterns' => [
                'velocityThreshold' => 500, // Bots are very fast
                'burstThreshold' => 1000, // Detects rapid retries on the same product/action
                'scrapeThreshold' => 600,
                'historySize' => 15,
                'minSamples' => 6,
                'regularityThreshold' => 30,
                'benfordThreshold' => 0.14,
                'patternWeight' => 95,
                'decayFactor' => 0.88,
                'inactivityReset' => 3000,
            ],
            'cpu' => [
                'minDifficultyBits' => 10,
                'maxDifficultyBits' => 24,
            ],
            'challengeNewDevices' => true, // New devices are suspicious in e-commerce
            // This would be a callable in PHP, but for now, we represent its intent.
            'isApiRequest' => 'req.path.startsWith("/api/cart") || req.path.startsWith("/api/stock") || req.path.startsWith("/api/checkout")',
        'wasm' => true,
        'filterWhitelist' => true, // Zero tolerance for scraping / distributed scalping
        ],
    ];

    /**
     * Creates a security configuration based on a named profile, with optional overrides.
     *
     * @param string $profileName The profile name to use ('balanced', 'strict', 'api', etc.).
     * @param array<string, mixed> $overrides An array to deep-merge with the profile, allowing customization.
     * @return array<string, mixed> The final security configuration object.
     */
    public static function createSecurityProfile(string $profileName = 'balanced', array $overrides = []): array
    {
        $baseProfile = self::PROFILES[$profileName] ?? self::PROFILES['balanced'];
        return self::deepMerge($baseProfile, $overrides);
    }

    /**
     * Deep-merges two arrays. Properties of the `$source` array overwrite those of `$target`.
     *
     * @param array<string, mixed> $target The target array.
     * @param array<string, mixed> $source The source array.
     * @return array<string, mixed> The merged array.
     */
    public static function deepMerge(array $target, array $source): array
    {
        $output = $target;

        foreach ($source as $key => $value) {
            if (is_array($value) && isset($output[$key]) && is_array($output[$key])) {
                $output[$key] = self::deepMerge($output[$key], $value);
            } else {
                $output[$key] = $value;
            }
        }

        return $output;
    }
}