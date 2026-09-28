<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint;

use Anonympins\Fingerprint\Challenge\ChallengeUtils;
use Anonympins\Fingerprint\Config\SecurityProfiles;
use Anonympins\Fingerprint\Store\StoreManager;
use Anonympins\Fingerprint\Utils\BlockList;
use Anonympins\Fingerprint\Utils\Logger;
use Anonympins\Fingerprint\Utils\MetricsManager;
use Anonympins\Fingerprint\Utils\RequestUtils;
use Anonympins\Fingerprint\Utils\Env;

/**
 * The main engine of the fingerprinting library.
 * Orchestrates identification, suspicion calculation, and challenge management.
 */
class FingerprintEngine
{
    private array $securityConfig;
    private bool $isProduction;
    private BlockList $allowlist;
    private bool $verbose;
    private ?Logger $logger = null;
    private bool $dryRun;

    private static ?array $googlebotEntries = null;
    private static ?array $yandexEntries = null;
    private static ?array $bingbotEntries = null;
    private static ?array $facebookEntries = null;

    private static array $dnsCircuitBreaker = [
        'state' => 'CLOSED',
        'failureCount' => 0,
        'lastStateChange' => 0,
        'threshold' => 5,
        'cooldown' => 30, // seconds
    ];

    /**
     * Records a successful DNS lookup, resetting the circuit breaker to CLOSED.
     *
     * @return void
     */
    private static function recordDnsSuccess(): void
    {
        self::$dnsCircuitBreaker['failureCount'] = 0;
        self::$dnsCircuitBreaker['state'] = 'CLOSED';
    }

    /**
     * Records a DNS lookup failure. If the failure count reaches the threshold,
     * the circuit breaker transitions to the OPEN state.
     *
     * @return void
     */
    private static function recordDnsFailure(): void
    {
        self::$dnsCircuitBreaker['failureCount']++;
        if (self::$dnsCircuitBreaker['failureCount'] >= self::$dnsCircuitBreaker['threshold']) {
            self::$dnsCircuitBreaker['state'] = 'OPEN';
            self::$dnsCircuitBreaker['lastStateChange'] = microtime(true);
        }
    }

    /**
     * Determines whether a DNS attempt is allowed based on the circuit breaker state.
     * In OPEN state, allows a retry only after the cooldown has elapsed (HALF-OPEN).
     *
     * @return bool True if a DNS attempt may be made, false otherwise.
     */
    private static function canAttemptDns(): bool
    {
        if (self::$dnsCircuitBreaker['state'] === 'CLOSED') {
            return true;
        }
        if (self::$dnsCircuitBreaker['state'] === 'OPEN') {
            if (microtime(true) - self::$dnsCircuitBreaker['lastStateChange'] >= self::$dnsCircuitBreaker['cooldown']) {
                self::$dnsCircuitBreaker['state'] = 'HALF-OPEN';
                return true;
            }
            return false;
        }
        return true; // HALF-OPEN
    }

    /**
     * Builds the reverse DNS query name for a given IP address
     * (in-addr.arpa for IPv4, ip6.arpa for IPv6).
     *
     * @param string $ip The IP address.
     * @return string|null The reverse DNS name, or null if the IP is invalid.
     */
    private static function getReverseDnsName(string $ip): ?string
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return implode('.', array_reverse(explode('.', $ip))) . '.in-addr.arpa';
        } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $hex = bin2hex((string)inet_pton($ip));
            return implode('.', array_reverse(str_split($hex))) . '.ip6.arpa';
        }
        return null;
    }

    /**
     * Resolves a DNS query using PHP's native `dns_get_record` function.
     * Supports PTR, A, and AAAA record types.
     *
     * @param string $query The DNS query name.
     * @param string $type The record type ('PTR', 'A', or 'AAAA').
     * @return array|null The list of resolved records, or null on failure.
     */
    private static function resolveDnsNative(string $query, string $type): ?array
    {
        $typeMap = [
            'PTR' => DNS_PTR,
            'A' => DNS_A,
            'AAAA' => DNS_AAAA
        ];
        $dnsType = $typeMap[$type] ?? null;
        if ($dnsType === null) {
            return null;
        }

        $records = @dns_get_record($query, $dnsType);
        if ($records === false) {
            return null;
        }

        $results = [];
        foreach ($records as $record) {
            if ($type === 'PTR' && isset($record['target'])) {
                $results[] = $record['target'];
            } elseif ($type === 'A' && isset($record['ip'])) {
                $results[] = $record['ip'];
            } elseif ($type === 'AAAA' && isset($record['ipv6'])) {
                $results[] = $record['ipv6'];
            }
        }
        return $results;
    }

    /**
     * Creates a new FingerprintEngine with the given security configuration.
     * Handles Ed25519 key binding/generation, autotuning config loading,
     * default whitelist application, config validation, and optional store reset.
     *
     * @param array $securityConfig The security configuration.
     */
    public function __construct(array $securityConfig)
    {
        $this->isProduction = Env::get('APP_ENV') === 'production';

        // Dynamically bind Ed25519 keys if passed via config
        if (isset($securityConfig['ed25519_private_key'])) {
            Env::set('ED25519_PRIVATE_KEY', $securityConfig['ed25519_private_key']);
        }
        if (isset($securityConfig['ed25519_public_key'])) {
            Env::set('ED25519_PUBLIC_KEY', $securityConfig['ed25519_public_key']);
        }

        // Automatic generation and persistence of the Ed25519 key pair
        $useAsymmetric = ($securityConfig['useAsymmetricTickets'] ?? false) === true || ($securityConfig['ed25519'] ?? '') === 'auto';
        $envPrivate = Env::get('ED25519_PRIVATE_KEY');
        if ($useAsymmetric && ($envPrivate === null || $envPrivate === '')) {
            if (function_exists('get_option') && function_exists('update_option')) {
                // In WordPress, persist cryptographic keys in the database options table
                $storedKeys = get_option('fingerprint_ed25519_keys');
                if (is_array($storedKeys) && isset($storedKeys['privateKey'], $storedKeys['publicKey'])) {
                    Env::set('ED25519_PRIVATE_KEY', $storedKeys['privateKey']);
                    Env::set('ED25519_PUBLIC_KEY', $storedKeys['publicKey']);
                } elseif (defined('OPENSSL_KEYTYPE_ED25519')) {
                    $pkey = openssl_pkey_new(["private_key_type" => OPENSSL_KEYTYPE_ED25519]);
                    $pemResult = ChallengeUtils::generateIssuerPemKeys();
                    $privateKeyPem = $pemResult['privateKey'];
                    $publicKeyPem = $pemResult['publicKey'];
                    Env::set('ED25519_PRIVATE_KEY', $privateKeyPem);
                    Env::set('ED25519_PUBLIC_KEY', $publicKeyPem);
                    update_option('fingerprint_ed25519_keys', [
                        'privateKey' => $privateKeyPem,
                        'publicKey'  => $publicKeyPem,
                    ], false);
                }
            } else {
                self::initStandaloneEd25519Keys();
            }
        }

        // Auto-load optimized config if autotuning savePath is specified
        if (isset($securityConfig['autotuning']['savePath'])) {
            $savePath = $securityConfig['autotuning']['savePath'];
            if (file_exists($savePath)) {
                try {
                    $savedConfig = json_decode(file_get_contents($savePath), true);
                    if (json_last_error() === JSON_ERROR_NONE && is_array($savedConfig)) {
                        $securityConfig = SecurityProfiles::deepMerge($securityConfig, $savedConfig);
                    }
                } catch (\Throwable $e) {
                    self::logError("[FingerprintEngine] Failed to auto-load optimized config from {$savePath}: " . $e->getMessage());
                }
            }
        }

        // If no allowlist is explicitly provided, apply the default list.
        if (!isset($securityConfig['whitelist'])) {
            $securityConfig['whitelist'] = self::default_whitelist();
        }

        $this->securityConfig = $securityConfig;
        $this->verbose = $securityConfig['verbose'] ?? false;
        $this->allowlist = $this->buildAllowlist();
        $this->logger = isset($securityConfig['logger']) && is_callable($securityConfig['logger']) ? new Logger($securityConfig['logger']) : null;
        $this->dryRun = $securityConfig['dryRun'] ?? false;
        $this->validateConfig($securityConfig);
        if ($this->securityConfig['reset'] ?? false) {
            $this->resetStore();
        }
    }

    /**
     * Initializes and persists Ed25519 keys for standalone PHP environments outside WordPress.
     * Loads from a persistent JSON file if it exists, otherwise generates a new key pair.
     *
     * @return void
     */
    private static function initStandaloneEd25519Keys(): void
    {
        $configDir = dirname(__DIR__, 1) . '/config';
        $persistentKeyPath = $configDir . '/ed25519_key.json';

        if (file_exists($persistentKeyPath)) {
            try {
                $keys = json_decode((string)file_get_contents($persistentKeyPath), true);
                if (isset($keys['privateKey'], $keys['publicKey'])) {
                    Env::set('ED25519_PRIVATE_KEY', $keys['privateKey']);
                    Env::set('ED25519_PUBLIC_KEY', $keys['publicKey']);
                }
            } catch (\Throwable $e) {
                self::logError('[Fingerprint] Failed to load persistent Ed25519 keys: ' . $e->getMessage());
            }
        } else {
            try {
                if (defined('OPENSSL_KEYTYPE_ED25519')) {
                    $pkey = openssl_pkey_new(["private_key_type" => OPENSSL_KEYTYPE_ED25519]);
                    if ($pkey && openssl_pkey_export($pkey, $privateKeyPem)) {
                        $details = openssl_pkey_get_details($pkey); // @phpstan-ignore-line
                        $publicKeyPem = $details['key'] ?? ''; // @phpstan-ignore-line
                        Env::set('ED25519_PRIVATE_KEY', $privateKeyPem);
                        Env::set('ED25519_PUBLIC_KEY', $publicKeyPem);
                        if (!is_dir($configDir)) {
                            if (function_exists('wp_mkdir_p')) {
                                wp_mkdir_p($configDir);
                            } else {
                                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- Non-WordPress standalone environment fallback
                                mkdir($configDir, 0777, true);
                            }
                        }
                        // phpcs:ignore PluginCheck.CodeAnalysis.WriteFile.PluginDirectoryWrite -- Non-WordPress standalone environment fallback
                        file_put_contents($persistentKeyPath, json_encode([
                            'privateKey' => $privateKeyPem,
                            'publicKey' => $publicKeyPem
                        ], JSON_PRETTY_PRINT));
                    }
                }
            } catch (\Throwable $e) {
                self::logError('[Fingerprint] Native Ed25519 key generation failed: ' . $e->getMessage());
            }
        }
    }

    /**
     * Hot-reloads a new security configuration (weights, thresholds, etc.)
     * without requiring a restart.
     *
     * @param array $newConfig The new configuration (partial or complete).
     */
    public function updateConfig(array $newConfig): void
    {
        $this->validateConfig($newConfig);
        $this->securityConfig = SecurityProfiles::deepMerge($this->securityConfig, $newConfig);
        $this->log('Configuration mise à jour à chaud (Hot-Reloaded)', $this->securityConfig);
    }

    /**
     * Resets the active persistence store.
     */
    public function resetStore(): void
    {
        $store = StoreManager::getStore();
        if (method_exists($store, 'clear')) {
            $store->clear();
        }
        $this->log('Store has been reset/cleared.');
    }

    /**
     * Validates a security configuration. Warns about missing or unknown keys
     * (e.g. weights, thresholds, typos).
     *
     * @param array $config The configuration to validate.
     * @return void
     */
    private function validateConfig(array $config): void
    {
        if (empty($config)) {
            $this->log('Warning: No securityConfig provided. Using default behaviors.', [], 'warn');
            return;
        }

        $knownKeys = [
            'weights', 'thresholds', 'cpu', 'ticketMaxAge', 'challengeTtl',
            'deviceIdCookieMaxAge', 'challengePagePath', 'verbose', 'patterns',
            'honeypot', 'threatIntel', 'whitelist', 'isStaticResource', 'isApiRequest', 'logger', 'probationaryTtl',
            'autotuning', 'enableUsefulWork', 'usefulWorkConfigPath', 'challengeNewDevices', 'graphql_operation_allowlist', 'dryRun',
            'similarityThreshold', 'summary', 'description',
            'ed25519_private_key', 'ed25519_public_key',
            'wasm', 'enableProofOfSpace', 'pospace', 'federatedPeers', 'federationSecret', 'reset',
            'filterWhitelist',
            'differentialPrivacy', 'dpEpsilon'
            ,'pat'
        ];

        if (empty($config['weights'])) {
            $this->log('Warning: `securityConfig.weights` is not defined. Suspicion scores will be 0.', [], 'warn');
        }
        if (empty($config['thresholds'])) {
            $this->log('Warning: `securityConfig.thresholds` is not defined. Challenges may not be issued correctly.', [], 'warn');
        }

        foreach (array_keys($config) as $key) {
            if (!in_array($key, $knownKeys, true)) {
                $this->log("Warning: Unknown key '{$key}' found in securityConfig. This might be a typo.", [], 'warn');
            }
        }
    }

    /**
     * Loads a bot whitelist from a JSON file in the config directory.
     * Falls back to the provided default entries if the file is missing or invalid.
     *
     * @param string $filename The whitelist JSON filename.
     * @param array $fallbackEntries The fallback entries if loading fails.
     * @return array The loaded or fallback whitelist entries.
     */
    private static function loadBotWhitelist(string $filename, array $fallbackEntries): array
    {
        $configDir = dirname(__DIR__, 2) . '/config';
        $filePath = $configDir . '/' . $filename;
        if (file_exists($filePath)) {
            try {
                $content = file_get_contents($filePath);
                if ($content !== false) {
                    $decoded = json_decode($content, true);
                    if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
                        return $decoded;
                    }
                }
            } catch (\Throwable $e) {
                self::logError("[Fingerprint] Error loading whitelist file {$filename}: " . $e->getMessage());
            }
        }
        return $fallbackEntries;
    }

    /**
     * Returns the Googlebot allowlist definition (type + entries).
     * The entries are lazily loaded and cached in a static property.
     *
     * @return array The Googlebot allowlist rule.
     */
    public static function googlebot_whitelist(): array
    {
        if (self::$googlebotEntries === null) {
            self::$googlebotEntries = self::loadBotWhitelist('googlebot.json', [
                "2001:4860:4801:10::/64",
                "2001:4860:4801:11::/64",
                "2001:4860:4801:12::/64",
                "66.249.79.64"
            ]);
        }
        return [
            'type' => 'allowlist',
            'entries' => self::$googlebotEntries
        ];
    }

    /**
     * Returns the Yandex allowlist definition (type + entries).
     * The entries are lazily loaded and cached in a static property.
     *
     * @return array The Yandex allowlist rule.
     */
    public static function yandex_whitelist(): array
    {
        if (self::$yandexEntries === null) {
            self::$yandexEntries = self::loadBotWhitelist('yandex.json', [
                "2a02:6b8::/29",
                "5.45.192.0/18",
                "213.180.192.0/19"
            ]);
        }
        return [
            'type' => 'allowlist',
            'entries' => self::$yandexEntries
        ];
    }

    /**
     * Returns the Bingbot allowlist definition (type + entries).
     * The entries are lazily loaded and cached in a static property.
     *
     * @return array The Bingbot allowlist rule.
     */
    public static function bingbot_whitelist(): array
    {
        if (self::$bingbotEntries === null) {
            self::$bingbotEntries = self::loadBotWhitelist('bingbot.json', [
                "157.55.39.0/24",
                "207.46.13.0/24",
                "40.77.178.0/23"
            ]);
        }
        return [
            'type' => 'allowlist',
            'entries' => self::$bingbotEntries
        ];
    }

    /**
     * Returns the Facebook allowlist definition (type + entries).
     * The entries are lazily loaded and cached in a static property.
     *
     * @return array The Facebook allowlist rule.
     */
    public static function facebook_whitelist(): array
    {
        if (self::$facebookEntries === null) {
            self::$facebookEntries = self::loadBotWhitelist('facebook.json', [
                "31.13.64.0/18", "66.220.144.0/20", "69.63.176.0/20", "157.240.0.0/16"
            ]);
        }
        return [
            'type' => 'allowlist',
            'entries' => self::$facebookEntries
        ];
    }

    /**
     * Returns the complete default whitelist, combining IP allowlists for major
     * bots (Googlebot, Bingbot, Yandex, Facebook) with hostname-suffix rules
     * for many known crawlers.
     *
     * @return array The default whitelist rules.
     */
    public static function default_whitelist(): array
    {
        return [
            self::googlebot_whitelist(),
            self::bingbot_whitelist(),
            self::yandex_whitelist(),
            self::facebook_whitelist(),
            ['userAgent' => 'Googlebot', 'hostnameSuffix' => '.googlebot.com'],
            ['userAgent' => 'Google-Extended', 'hostnameSuffix' => '.google.com'],
            ['userAgent' => 'AdsBot-Google', 'hostnameSuffix' => '.googlebot.com'],
            ['userAgent' => 'Mediapartners-Google', 'hostnameSuffix' => '.google.com'],
            ['userAgent' => 'Google-InspectionTool', 'hostnameSuffix' => '.google.com'],
            ['userAgent' => '(bingbot|adidxbot)', 'hostnameSuffix' => '.search.msn.com'],
            ['userAgent' => 'DuckDuckBot', 'hostnameSuffix' => '.duckduckgo.com'],
            ['userAgent' => 'YandexBot', 'hostnameSuffix' => '.yandex.com'],
            ['userAgent' => 'YandexImages', 'hostnameSuffix' => '.yandex.com'],
            ['userAgent' => 'Baiduspider', 'hostnameSuffix' => '.crawl.baidu.com'],
            ['userAgent' => 'Slurp', 'hostnameSuffix' => '.crawl.yahoo.net'],
            ['userAgent' => 'Sogou web spider', 'hostnameSuffix' => '.sogou.com'],
            ['userAgent' => 'Exabot', 'hostnameSuffix' => '.exabot.com'],
            ['userAgent' => 'ia_archiver', 'hostnameSuffix' => '.alexa.com'],
            ['userAgent' => 'SeznamBot', 'hostnameSuffix' => '.seznam.cz'],
            ['userAgent' => 'Mail.RU_Bot', 'hostnameSuffix' => '.mail.ru'],
            ['userAgent' => 'Yeti', 'hostnameSuffix' => '.naver.com'],
            ['userAgent' => 'AhrefsBot', 'hostnameSuffix' => '.ahrefs.com'],
            ['userAgent' => 'SemrushBot', 'hostnameSuffix' => '.semrush.com'],
            ['userAgent' => 'MJ12bot', 'hostnameSuffix' => '.mj12bot.com'],
            ['userAgent' => 'rogerbot', 'hostnameSuffix' => '.moz.com'],
            ['userAgent' => 'DotBot', 'hostnameSuffix' => '.moz.com'],
            ['userAgent' => 'Screaming Frog SEO Spider', 'hostnameSuffix' => '.screamingfrog.co.uk'],
        ];
    }

    /**
     * Emits a log message if verbose mode is enabled. Uses the configured
     * logger callback if available, otherwise falls back to error_log.
     *
     * @param string $message The message to log.
     * @param array $data Additional data to include.
     * @param string $level The log level (default 'info').
     * @return void
     */
    private function log(string $message, array $data = [], string $level = 'info'): void
    {
        if ($this->verbose) {
            // Uses the logger if configured, otherwise error_log
            if ($this->logger) {
                $this->logger->log($level, "[FingerprintEngine] " . $message, $data);
            } else {
                $logMessage = "[FingerprintEngine] {$message}";
                if (!empty($data)) $logMessage .= ' ' . json_encode($data);
                self::logError($logMessage);
            }
        }
    }

    /**
     * Computes the final suspicion score from a suspicion vector by applying
     * the configured weights. When an MTU anomaly (tunnel) is detected, several
     * weights are dynamically amplified to increase the score.
     *
     * @param array $suspicionVector The suspicion vector (metric name => score).
     * @return float The final score, capped at 100.0.
     */
    public function calculateFinalScore(array $suspicionVector): float
    {
        $baseWeights = $this->securityConfig['weights'] ?? [];

        $score = 0.0;
        // NEW: Weight amplification logic
        // If a tunnel is detected, increase the weight of other suspicious signals.
        $dynamicWeights = $baseWeights;
        if (($suspicionVector['mtuAnomalyScore'] ?? 0.0) > 50.0) {
            $this->log('Tunnel detected, amplifying suspicion weights.', ['mtuScore' => $suspicionVector['mtuAnomalyScore']]);

            // Increases the weight of low-level inconsistencies (hard to falsify)
            $dynamicWeights['tlsSpoofingScore'] = ($baseWeights['tlsSpoofingScore'] ?? 0.8) * 1.25;
            $dynamicWeights['crossLayerInconsistencyScore'] = ($baseWeights['crossLayerInconsistencyScore'] ?? 0.4) * 1.4;
            $dynamicWeights['clientHintsInconsistencyScore'] = ($baseWeights['clientHintsInconsistencyScore'] ?? 0.7) * 1.2;

            // Increases the weight of behavioral anomalies (a bot behind a VPN is more suspect)
            $dynamicWeights['behaviorScore'] = ($baseWeights['behaviorScore'] ?? 0.7) * 1.15;
            $dynamicWeights['requestPatternScore'] = ($baseWeights['requestPatternScore'] ?? 0.6) * 1.2;
        }

        foreach ($dynamicWeights as $key => $weight) {
            $metricScore = $suspicionVector[$key] ?? 0.0;
            if ($metricScore > 0) {
                $score += $metricScore * $weight;
            }
        }

        return min(100.0, $score);
    }

    /**
     * Builds the internal BlockList used for IP allowlist checks, from the
     * 'allowlist' rule found in the whitelist configuration.
     *
     * @return BlockList The populated allowlist.
     */
    private function buildAllowlist(): BlockList
    {
        $blockList = new BlockList();
        $whitelistRules = $this->securityConfig['whitelist'] ?? [];

        $allowlistRule = null;
        foreach ($whitelistRules as $rule) {
            if (($rule['type'] ?? '') === 'allowlist') {
                $allowlistRule = $rule;
                break;
            }
        }

        if (empty($allowlistRule['entries'])) {
            return $blockList;
        }

        foreach ($allowlistRule['entries'] as $entry) {
            $blockList->add($entry);
        }
        return $blockList;
    }

    /**
     * Checks whether the given client IP is in the IP allowlist.
     *
     * @param string $clientIp The client IP address.
     * @return bool True if the IP is allowlisted, false otherwise.
     */
    private function isIpInAllowlist(string $clientIp): bool
    {
        return $this->allowlist->check($clientIp);
    }

    /**
     * Checks whether the given request path is in the path allowlist.
     * Supports trailing-wildcard entries (e.g. "/admin/*").
     *
     * @param string $requestPath The request path.
     * @return bool True if the path is allowlisted, false otherwise.
     */
    private function isPathInAllowlist(string $requestPath): bool
    {
        $whitelistRules = $this->securityConfig['whitelist'] ?? [];
        $pathAllowlistRule = null;
        foreach ($whitelistRules as $rule) {
            if (($rule['type'] ?? '') === 'path_allowlist') {
                $pathAllowlistRule = $rule;
                break;
            }
        }

        if (empty($pathAllowlistRule['entries'])) {
            return false;
        }

        foreach ($pathAllowlistRule['entries'] as $entry) {
            if (str_ends_with($entry, '*')) {
                $base = substr($entry, 0, -1);
                if (str_starts_with($requestPath, $base)) {
                    return true;
                }
            } elseif ($requestPath === $entry) {
                return true;
            }
        }

        return false;
    }

    /**
     * Checks whether the (host, path) pair matches a host_path_allowlist entry.
     *
     * @param string|null $requestHost The request host.
     * @param string $requestPath The request path.
     * @return bool True if the host+path is allowlisted, false otherwise.
     */
    private function isHostPathInAllowlist(?string $requestHost, string $requestPath): bool
    {
        if (empty($requestHost)) {
            return false;
        }

        $whitelistRules = $this->securityConfig['whitelist'] ?? [];
        $hostPathRule = null;
        foreach ($whitelistRules as $rule) {
            if (($rule['type'] ?? '') === 'host_path_allowlist') {
                $hostPathRule = $rule;
                break;
            }
        }

        if (empty($hostPathRule['entries'])) {
            return false;
        }

        foreach ($hostPathRule['entries'] as $entry) {
            if (RequestUtils::hostPathMatches($requestHost, $requestPath, $entry)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if a request should be exempted due to an allowlist rule.
     * Evaluates IP, path, host+path, GraphQL operation, and verified bot rules.
     * Applies the `filterWhitelist` security option to optionally override
     * allowlisting for clearly malicious requests.
     *
     * @param RequestContext $context The request context.
     * @return bool True if the request should be allowed, false otherwise.
     */
    private function checkAllowlists(RequestContext $context): bool
    {
        $whitelisted = false;
        $type = '';

        if ($this->isIpInAllowlist($context->clientIp)) {
            $whitelisted = true;
            $type = 'allowlist';
        } elseif ($this->isPathInAllowlist($context->path)) {
            $whitelisted = true;
            $type = 'path_allowlist';
        } elseif ($this->isHostPathInAllowlist($context->getHeader('host'), $context->path)) {
            $whitelisted = true;
            $type = 'host_path_allowlist';
        } elseif ($context->graphqlOperation && $this->isGraphqlOperationInAllowlist($context->graphqlOperation['type'], $context->graphqlOperation['name'])) {
            $whitelisted = true;
            $type = 'graphql_operation_allowlist';
        } elseif ($this->verifyWhitelistedBot($context)) {
            $whitelisted = true;
            $type = 'bot';
        }

        if ($whitelisted) {
            $filterWhitelist = $this->securityConfig['filterWhitelist'] ?? false;
            $bypassWhitelist = false;
            if ($filterWhitelist === true || (is_numeric($filterWhitelist) && $type === 'bot')) {
                $bypassWhitelist = $this->hasCertainAttack($context);
            } elseif (is_numeric($filterWhitelist)) {
                if ($context->preCalculatedScore === null) {
                    $suspicionVector = [];
                    $context->preCalculatedVector = $this->getSuspicionVector($context, $suspicionVector);
                    $context->preCalculatedScore = $this->calculateFinalScore($context->preCalculatedVector);
                }
                if ($context->preCalculatedScore > $filterWhitelist) {
                    $bypassWhitelist = true;
                }
            }

            if ($bypassWhitelist) {
                $this->log('Whitelisted request exceeds filter threshold - bypassing whitelist bypass', ['clientIp' => $context->clientIp, 'path' => $context->path]);
                return false;
            }
            $this->log("IP/Path in allowlist ({$type}) - allowing request", ['clientIp' => $context->clientIp, 'path' => $context->path]);
            return true;
        }

        return false;
    }

    /**
     * Resolves the request identity (device ID, device data, and possibly a
     * new cookie to set). Attempts cookieless identity recovery via TLS session
     * ID, detects cookie dropping, and validates WebAuthn hardware anchors.
     *
     * @param RequestContext $context The request context.
     * @param array &$suspicionVector The suspicion vector (updated in place).
     * @return array{deviceId: string, deviceData: ?array, newCookie: ?array}
     */
    private function resolveRequestIdentity(RequestContext $context, array &$suspicionVector): array
    {
        if ($context->resolvedIdentity !== null) {
            return $context->resolvedIdentity;
        }
        $this->log('Resolving request identity', ['clientIp' => $context->clientIp, 'cookies' => $context->cookies]);
        $store = StoreManager::getStore();
        $existingDeviceId = $context->cookies['device_id'] ?? null; // @phpstan-ignore-line
        $currentDeviceHash = RequestUtils::getCompositeDeviceHash($context);
        $pendingCookieTtl = 120; // 2 minutes to detect removal

        $deviceId = $existingDeviceId;
        $deviceData = null;
        $newCookie = null;

        // Cookieless Identity Tracking: Attempt to restore device ID using TLS session resume ID
        $tlsSessionId = $context->tlsSessionId;
        if (!$deviceId && $tlsSessionId) {
            $resumedDeviceId = $store->get("tls-session:{$tlsSessionId}");
            if ($resumedDeviceId) {
                $deviceId = $resumedDeviceId;
                $this->log('Identity resumed via TLS Session ID', ['deviceId' => $deviceId, 'tlsSessionId' => $tlsSessionId]);
            }
        }

        if ($deviceId) {
            $deviceData = $store->get("device:{$deviceId}");
        }

        $ua = $context->getHeader('user-agent') ?? '';
        $pendingKey = "pending_cookie:" . md5($context->clientIp . '|' . $ua);

        if ($deviceData === null) {
            // New user or lost/invalid cookie
            $pendingDeviceId = $store->get($pendingKey);
            if ($pendingDeviceId && !$existingDeviceId) {
                // The penalty is now added directly to the suspicion vector.
                $this->log('Cookie dropping detected', ['clientIp' => $context->clientIp, 'pendingDeviceId' => $pendingDeviceId]);
                $suspicionVector['cookieDroppingScore'] = 100.0;
            }

            $deviceId = bin2hex(random_bytes(16)); // UUID-like

            $isHttps = !empty($context->isHttps);
            $secureOption = $isHttps;

            // Prepare the cookie to be sent
            $newCookie = [
                'name' => 'device_id',
                'value' => $deviceId,
                'options' => [
                    'httponly' => true,
                    'secure' => $secureOption,
                    'samesite' => 'Lax',
                    'path' => '/',
                ]
            ];
            if (isset($this->securityConfig['deviceIdCookieMaxAge'])) {
                $newCookie['options']['expires'] = time() + ($this->securityConfig['deviceIdCookieMaxAge'] / 1000);
            }

            $store->set($pendingKey, $deviceId, $pendingCookieTtl);

            $deviceData = [
                'initialDeviceHash' => $currentDeviceHash,
                'ips' => [$context->clientIp],
                'requestHistory' => [],
                'lastUpdate' => time() * 1000,
                'lastFpHash' => $currentDeviceHash,
                'lastChangeTimestamp' => 0,
                'rapidChangeCount' => 0,
                'highScoreCount' => 0,
                'lastHighScoreTimestamp' => 0,
            ];
        } else {
            // Ensure 'ips' is an array for the following operations.
            if (!isset($deviceData['ips']) || !is_array($deviceData['ips'])) { // @phpstan-ignore-line
                $deviceData['ips'] = [];
            }
            // The client returned a valid cookie: purge the pending entry immediately
            $store->delete($pendingKey);
        }

        // WebAuthn hardware anchor (Secure Enclave / TPM) validation
        $behaviorHeader = $context->getHeader('x-behavior-metrics');
        if (!empty($behaviorHeader) && is_string($behaviorHeader) && str_starts_with($behaviorHeader, '{')) {
            try {
                $parsedMetrics = json_decode($behaviorHeader, true);
                if (is_array($parsedMetrics) && !empty($parsedMetrics['webauthnAnchor']) && is_array($deviceData)) {
                    if ($this->verifyWebAuthnHardwareAnchor($parsedMetrics['webauthnAnchor'], $deviceData)) {
                        $deviceData['webauthnVerified'] = true;
                        $store->set("device:{$deviceId}", $deviceData);
                    }
                }
            } catch (\Throwable $e) {
            }
        }

        // Bind the current TLS session ID to the device ID
        if ($deviceId && $tlsSessionId) {
            $store->set("tls-session:{$tlsSessionId}", $deviceId, 3600); // 1h cache duration
        }

        $context->resolvedIdentity = [
            'deviceId' => $deviceId,
            'deviceData' => $deviceData,
            'newCookie' => $newCookie,
        ];
        return $context->resolvedIdentity;
    }

    /**
     * Computes the full suspicion vector for a request by aggregating dozens
     * of indicators (fingerprint consistency, TLS spoofing/JA4, behavioral
     * metrics, threat intel, subnet reputation, protocol/TCP anomalies, etc.).
     * Also updates and persists the device's state in the store.
     *
     * @param RequestContext $context The request context.
     * @param array &$suspicionVector The suspicion vector (updated in place).
     * @return array<string, float> The completed suspicion vector.
     */
    public function getSuspicionVector(RequestContext $context, array &$suspicionVector): array
    {
        $store = StoreManager::getStore();
        $identity = $this->resolveRequestIdentity($context, $suspicionVector);
        $deviceData = $identity['deviceData'];
        $deviceId = $identity['deviceId'];
        if ($deviceData && ($deviceData['condemned'] ?? false)) {
            $suspicionVector['honeypotScore'] = 100;
            return $suspicionVector;
        }

        // If a new cookie must be set, temporarily store it in the context
        // so that the calling code can handle it.
        if ($identity['newCookie']) {
            // This property is non-standard, prefix it to avoid conflicts.
            $context->newCookieForResponse = $identity['newCookie'];
        }

        // Periodic device data cleanup
        if ((time() * 1000) - ($deviceData['lastUpdate'] ?? 0) > 10 * 60 * 1000) { // 10 minutes
            $deviceData['ips'] = [];
            $deviceData['rapidChangeCount'] = 0;
            $deviceData['ipTimes'] = [];
        }
        $deviceData['lastUpdate'] = time() * 1000;

        // --- Computation of the various suspicion scores ---

        // Fingerprint inconsistency score (moved here to be with the others)
        $currentDeviceHash = RequestUtils::getCompositeDeviceHash($context);
        $consistencyScore = FingerprintBuilder::compare($deviceData['initialDeviceHash'] ?? '', $currentDeviceHash);
        $similarityThreshold = (float)($this->securityConfig['similarityThreshold'] ?? 0.72);
        $inconsistencyScore = RequestUtils::calculateAnalogInconsistencyScore($consistencyScore, $similarityThreshold);

        $behavioral = RequestUtils::getBehavioralIndicators($context, $deviceData);

        // Header anomaly score
        $headerAnomalies = RequestUtils::getHeaderAnomalies($context);

        // TLS spoofing score
        $tlsSpoofing = RequestUtils::getTlsSpoofingScore($context);
        $tlsSpoofingScore = (float)($tlsSpoofing['tlsSpoofingScore'] ?? 0.0);
        $virtualizationScore = RequestUtils::getVirtualizationAnomalyScore($context);

        // Advanced JA4 TLS Inconsistency checks
        $ja4 = $context->getHeader('x-ja4-hash');
        if ($ja4) {
            $spoofedJa4s = [
                't13d1516h2_8daaf6152771_390237aa04be', // Classic Chrome (curl-impersonate / tls-client)
                't13d1413h2_bc66258908f0_bc2531da1615', // Static Firefox (curl-impersonate-ff / curl_cffi)
                't13d1515h2_8daaf6152771_a729e2f67de4', // Static Safari (curl-impersonate-safari / tls-client)
                't13d1516h2_8daaf6152771_4be0df930c2c', // Chrome alternative (tls-client Go)
                't12d1516h2_8daaf6152771_390237aa04be', // Spoofed Chrome downgraded to TLS 1.2
                't13d1516h2_e822d36d892d_93ec3f0b2f5b'  // Custom OpenSSL scraping bot
            ];
            if (in_array($ja4, $spoofedJa4s, true)) {
                $tlsSpoofingScore = max($tlsSpoofingScore, 100.0);
            }

            $parsedJa4 = $this->parseJa4($ja4);
            if ($parsedJa4) {
                $ua = $context->getHeader('user-agent') ?? '';
                $uaParts = $this->parseUserAgent($ua);

                // Check 1: ALPN / HTTP Version inconsistency
                $httpVersion = $context->httpVersion ?? '1.1';
                if ($parsedJa4['alpn'] === 'h2' && ($httpVersion === '1.1' || $httpVersion === '1.0')) {
                    $hasProxy = $context->getHeader('via') || $context->getHeader('forwarded') || $context->getHeader('x-forwarded-proto') || $context->getHeader('x-forwarded-for');
                    if (!$hasProxy) {
                        $tlsSpoofingScore = max($tlsSpoofingScore, 40.0);
                    }
                }

                // Check 2: OS/Platform vs TLS Capabilities inconsistency
                if ($parsedJa4['version'] === '12' && ($uaParts['os'] === 'iOS' || $uaParts['os'] === 'macOS') && ($uaParts['browser'] && str_starts_with($uaParts['browser'], 'Safari'))) {
                    $tlsSpoofingScore = max($tlsSpoofingScore, 60.0);
                }

                // Check 3: User-Agent vs JA4 Signature inconsistency
                if ($uaParts['browser'] && str_starts_with($uaParts['browser'], 'Chrome') && $parsedJa4['alpn'] === '00') {
                    $tlsSpoofingScore = max($tlsSpoofingScore, 50.0);
                }
                if ($uaParts['browser'] && str_starts_with($uaParts['browser'], 'Firefox') && $parsedJa4['extensionsCount'] > 15) {
                    $tlsSpoofingScore = max($tlsSpoofingScore, 50.0);
                }

                // Check 4: Stagnation (Lack of Entropy / Genericity)
                if (is_string($uaParts['browser'])) {
                    $ja4Key = "ja4-browsers:{$ja4}";
                    $seenBrowsers = $store->get($ja4Key) ?: [];
                    if (!is_array($seenBrowsers)) {
                        $seenBrowsers = [];
                    }
                    $browserFamily = explode('/', (string)$uaParts['browser'])[0] ?? null;
                    if ($browserFamily && !in_array($browserFamily, $seenBrowsers, true)) {
                        $seenBrowsers[] = $browserFamily;
                        $store->set($ja4Key, $seenBrowsers, 86400);
                    }
                    if (count($seenBrowsers) > 1) {
                        $tlsSpoofingScore = max($tlsSpoofingScore, 80.0);
                    }
                }
            }
        }

        // Time inconsistency score (replay attack)
        $timeInconsistency = RequestUtils::getTimeInconsistencyScore($context);

        // Cross-layer inconsistency score (client vs server)
        $crossLayerInconsistency = RequestUtils::getCrossLayerInconsistency($context);

        // Request pattern score (scraping, velocity)
        $requestPattern = RequestUtils::getRequestPatternScore($context, $deviceData, $this->securityConfig['patterns'] ?? []);

        // Honeypot score
        $honeypot = RequestUtils::getHoneypotScore($context, $this->securityConfig['honeypot'] ?? []);

        // Client behavioral metrics score (mouse, keyboard)
        $behavior = RequestUtils::getBehaviorScore($context);

        // Explicit bot detection score (automation markers)
        $bot = RequestUtils::getBotScore($context);

        // Click variance score
        $clickVariance = RequestUtils::getClickVarianceScore($context);

        // Threat Intelligence score
        $threatIntel = RequestUtils::getThreatIntelScore($context, $this->securityConfig['threatIntel'] ?? []);

        // Client-Hints inconsistency score
        $clientHintsInconsistency = RequestUtils::getClientHintsInconsistencyScore($context);

        // Global fingerprint similarity score (Botnet Clustering)
        $stableFp = RequestUtils::extractStablePart($currentDeviceHash);
        $stableFpHash = FingerprintBuilder::cyrb53($stableFp);
        $botnetCluster = RequestUtils::getBotnetClusterScore($context, $stableFpHash);

        // NEW: IP subnet reputation score
        $subnetScore = RequestUtils::getSubnetScore($context, $deviceId, $this->securityConfig);

        // TCP/IP stack anomaly score
        $tcpAnomaly = RequestUtils::getTcpAnomalyScore($context);

        // Protocol anomaly score (HTTP/2 and QUIC)
        $protocolAnomaly = RequestUtils::getProtocolAnomalyScore($context);

        // Display rendering anomaly score (V-Sync)
        $renderingAnomaly = RequestUtils::getRenderingAnomalyScore($context);

        // Assembly of the final suspicion vector
        $suspicionVector = array_merge($suspicionVector, [
            'inconsistencyScore' => $inconsistencyScore,
            'historyScore' => $behavioral['historyScore'],
            'rotationScore' => $behavioral['rotationScore'],
            'headerAnomalyScore' => $headerAnomalies['headerAnomalyScore'],
            'tlsSpoofingScore' => $tlsSpoofingScore,
            'timeInconsistencyScore' => $timeInconsistency['timeInconsistencyScore'],
            'crossLayerInconsistencyScore' => $crossLayerInconsistency['crossLayerInconsistencyScore'],
            'requestPatternScore' => $requestPattern['requestPatternScore'], // This score is now computed
            'honeypotScore' => $honeypot['honeypotScore'],
            'behaviorScore' => $behavior['behaviorScore'],
            'botScore' => $bot['botScore'],
            'clickVarianceScore' => $clickVariance['clickVarianceScore'],
            'threatIntelScore' => $threatIntel['threatIntelScore'],
            'clientHintsInconsistencyScore' => $clientHintsInconsistency['clientHintsInconsistencyScore'],
            'subnetScore' => $subnetScore['subnetScore'],
            'botnetClusterScore' => $botnetCluster['botnetClusterScore'],
            'tcpAnomalyScore' => $tcpAnomaly['tcpAnomalyScore'],
            'protocolAnomalyScore' => $protocolAnomaly['protocolAnomalyScore'],
            'renderingAnomalyScore' => $renderingAnomaly['renderingAnomalyScore'],
            'virtualizationScore' => $virtualizationScore
        ]);

        // Save the updated device state in the store
        $store->set("device:{$deviceId}", $deviceData);

        return $suspicionVector;
    }

    /**
     * Parse a basic User-Agent string.
     *
     * @param string $ua The User-Agent string.
     * @return array An array with 'browser' and 'os' keys.
     */
    private function parseUserAgent(string $ua): array
    {
        $result = ['browser' => null, 'os' => null];

        if (str_contains($ua, 'Chrome') && !str_contains($ua, 'Edg')) {
            $result['browser'] = 'Chrome';
            if (preg_match('/Chrome\/(\d+)/', $ua, $matches)) {
                $result['browser'] .= '/' . $matches[1];
            }
        } elseif (str_contains($ua, 'Firefox')) {
            $result['browser'] = 'Firefox';
            if (preg_match('/Firefox\/(\d+)/', $ua, $matches)) {
                $result['browser'] .= '/' . $matches[1];
            }
        } elseif (str_contains($ua, 'Safari') && !str_contains($ua, 'Chrome')) {
            $result['browser'] = 'Safari';
            if (preg_match('/Version\/(\d+)/', $ua, $matches)) {
                $result['browser'] .= '/' . $matches[1];
            }
        } elseif (str_contains($ua, 'Edg')) {
            $result['browser'] = 'Edge';
            if (preg_match('/Edg\/(\d+)/', $ua, $matches)) {
                $result['browser'] .= '/' . $matches[1];
            }
        }

        if (str_contains($ua, 'Windows NT 10.0')) $result['os'] = 'Windows 10';
        elseif (str_contains($ua, 'Windows NT 6.1')) $result['os'] = 'Windows 7';
        elseif (str_contains($ua, 'Mac OS X')) $result['os'] = 'macOS';
        elseif (str_contains($ua, 'Linux') && !str_contains($ua, 'Android')) $result['os'] = 'Linux';
        elseif (str_contains($ua, 'Android')) $result['os'] = 'Android';
        elseif (str_contains($ua, 'iPhone') || str_contains($ua, 'iPad')) $result['os'] = 'iOS';

        return $result;
    }

    /**
     * Parse JA4 string into protocol, version, ALPN etc.
     *
     * @param string|null $ja4 The JA4 string.
     * @return array|null The parsed components, or null if invalid.
     */
    private function parseJa4(?string $ja4): ?array
    {
        if (empty($ja4)) return null;
        $parts = explode('_', $ja4);
        $ja4a = $parts[0];
        if (strlen($ja4a) < 10) return null;
        return [
            'protocol' => $ja4a[0],
            'version' => substr($ja4a, 1, 2),
            'sni' => $ja4a[3],
            'ciphersCount' => (int)substr($ja4a, 4, 2),
            'extensionsCount' => (int)substr($ja4a, 6, 2),
            'alpn' => substr($ja4a, 8, 2),
            'ja4b' => $parts[1] ?? null,
            'ja4c' => $parts[2] ?? null
        ];
    }


    /**
     * Decodes a polymorphic fingerprint by restoring the original keys from
     * a mapping of randomized keys.
     *
     * @param string $fpString The encoded fingerprint string.
     * @param array $mapping The mapping containing a `keys` (orig => rand) entry.
     * @return string The decoded fingerprint with original keys.
     */
    private function decodePolymorphicFingerprint(string $fpString, array $mapping): string
    {
        if (empty($mapping['keys'])) {
            return $fpString;
        }
        $reverseKeys = array_flip($mapping['keys']);
        $parts = explode('|', $fpString);
        $mappedParts = [];
        foreach ($parts as $part) {
            $pair = explode(':', $part, 2);
            if (count($pair) === 2) {
                $origKey = $reverseKeys[$pair[0]] ?? $pair[0];
                $mappedParts[] = "{$origKey}:{$pair[1]}";
            } else {
                $mappedParts[] = $part;
            }
        }
        return implode('|', $mappedParts);
    }

    /**
     * Translates polymorphic (randomized) header names back to their canonical
     * names (x-device-fingerprint, x-behavior-metrics) and decodes the
     * fingerprint values using the active mapping.
     *
     * @param RequestContext $context The request context (mutated in place).
     * @return void
     */
    private function translatePolymorphicHeaders(RequestContext $context): void
    {
        $store = StoreManager::getStore();
        $activeMappings = $store->get('active-polymorphic-mappings') ?: [];
        if (!is_array($activeMappings)) {
            return;
        }

        foreach ($activeMappings as $mapping) {
            $devFpHeader = strtolower($mapping['headers']['x-device-fingerprint'] ?? '');
            $behaviorHeader = strtolower($mapping['headers']['x-behavior-metrics'] ?? '');

            if (!empty($devFpHeader) && isset($context->headers[$devFpHeader])) {
                $context->headers['x-device-fingerprint'] = $context->headers[$devFpHeader];
                if (!empty($behaviorHeader) && isset($context->headers[$behaviorHeader])) {
                    $context->headers['x-behavior-metrics'] = $context->headers[$behaviorHeader];
                }

                $clientFp = $context->headers['x-device-fingerprint'];
                if ($clientFp && is_string($clientFp)) {
                    $context->headers['x-device-fingerprint'] = $this->decodePolymorphicFingerprint($clientFp, $mapping);
                }
                break;
            }
        }
    }

    /**
     * Evaluates whether the request exhibits clear attack characteristics or
     * has triggered a honeypot (i.e. a certain attack).
     *
     * @param RequestContext $context The request context.
     * @return bool True if a certain attack is detected, false otherwise.
     */
    private function hasCertainAttack(RequestContext $context): bool
    {
        $honeypotConfig = $this->securityConfig['honeypot'] ?? [];
        $honeypot = RequestUtils::getHoneypotScore($context, $honeypotConfig);
        if (($honeypot['honeypotScore'] ?? 0.0) >= 100.0) {
            return true;
        }
        $bot = RequestUtils::getBotScore($context);
        if (($bot['botScore'] ?? 0.0) >= 100.0) {
            return true;
        }
        return false;
    }

    /**
     * Processes an incoming request and returns a decision (action to take).
     * This is the main entry point of the engine: it resolves identity,
     * checks allowlists/tickets, computes the suspicion score, verifies PoW
     * submissions, selects and issues challenges, and applies block/allow logic.
     *
     * @param RequestContext $context The request context.
     * @return array{action: string, score: float, vector: array, status?: int, body?: mixed, cookie?: array, path?: string, newCookieForResponse?: array}
     */
    public function processRequest(RequestContext $context): array
    {
        $store = StoreManager::getStore();
        $this->translatePolymorphicHeaders($context);

        // Initialize the suspicion vector to avoid type errors.
        $suspicionVector = [];

        $coopOp = $context->query['coop_op'] ?? null;
        if ($coopOp) {
            $result = ChallengeUtils::handleCooperativeRequest($context->query, $context->clientIp, $this->securityConfig);
            return [
                'action' => 'challenge',
                'status' => 200,
                'body' => $result
            ];
        }

        $this->log('Processing request', ['clientIp' => $context->clientIp, 'path' => $context->path]);

        // Parse GraphQL query if applicable
        if ($context->path === '/graphql' && !empty($context->body)) {
            $gqlInfo = RequestUtils::parseGraphQLQuery(is_array($context->body) ? $context->body : []);
            if ($gqlInfo) {
                $context->graphqlOperation = $gqlInfo;
            }
        }

        // 0. Resolve device identity and validate WebAuthn hardware attestation
        $identity = $this->resolveRequestIdentity($context, $suspicionVector);
        $deviceId = $identity['deviceId'];
        $deviceData = $identity['deviceData'];

        // Anti-Farm Rule: A condemned device or one conducting a certain attack gets no bypass
        if (($deviceData['condemned'] ?? false) || $this->hasCertainAttack($context)) {
            if (is_array($deviceData)) {
                $deviceData['condemned'] = true;
                $deviceData['webauthnVerified'] = false;
                $store->set("device:{$deviceId}", $deviceData);
            }
            $this->log('Condemned device or attack detected - revoking hardware trust and blocking', ['deviceId' => $deviceId]);
            $decision = ['action' => 'block', 'status' => 403, 'body' => 'Forbidden', 'score' => 100.0, 'vector' => ['honeypotScore' => 100.0]];
            if ($this->dryRun) {
                $this->log("[Dry Run] Intended action: {$decision['action']}", ['score' => $decision['score']]);
                $decision['intendedAction'] = $decision['action'];
                $decision['action'] = 'next';
                unset($decision['status'], $decision['body']);
            }
            return $decision;
        }

        // Instant bypass if the device has cryptographically proven its hardware identity (Secure Enclave / TPM)
        if ($deviceData && !empty($deviceData['webauthnVerified'])) {
            $this->log('Hardware-anchored device verified (WebAuthn) - full bypass granted', ['deviceId' => $deviceId]);
            $greenlistTtl = 365 * 86400 * 1000; // 1 year (permanent)
            $greenlistTicket = ChallengeUtils::generateStatelessTicket([
                'expiry' => (int)floor(microtime(true) * 1000) + $greenlistTtl,
                'originalIp' => $context->clientIp,
                'deviceId' => $deviceId,
                'deviceHash' => 'webauthn:greenlist:' . ($deviceData['webauthnCredentialId'] ?? $deviceId),
                'greenlist' => true
            ]);

            $isHttps = !empty($context->isHttps);
            $decision = [
                'action' => 'next',
                'score' => 0.0,
                'vector' => ['webauthn_verified' => 100.0],
                'cookie' => [
                    'name' => 'pow_clearance',
                    'value' => $greenlistTicket,
                    'options' => [
                        'httponly' => true,
                        'secure' => $isHttps,
                        'samesite' => 'Strict',
                        'expires' => time() + ($greenlistTtl / 1000),
                        'path' => '/',
                    ]
                ]
            ];
            if (isset($context->newCookieForResponse)) {
                $decision['newCookieForResponse'] = $context->newCookieForResponse;
            }
            return $decision;
        }

        // --- PRIVATE ACCESS TOKENS (PAT / RFC 9505 & Privacy Pass) ZERO-FRICTION BYPASS ---
        $rawPatTokens = RequestUtils::extractPrivateAccessTokens($context);
        if (!empty($rawPatTokens)) {
            $patConfig = $this->securityConfig['pat'] ?? [];
            foreach ($rawPatTokens as $rawToken) {
                $parsedToken = RequestUtils::parsePrivateAccessToken($rawToken);
                if ($parsedToken !== null) {
                    $nonceKey = "pat-nonce:{$parsedToken['nonce']}";
                    if (!$store->has($nonceKey)) {
                        $isValid = RequestUtils::verifyPatSignature($parsedToken, $patConfig);
                        if ($isValid) {
                            $nonceTtl = $patConfig['nonceTtl'] ?? 86400;
                            $store->set($nonceKey, true, $nonceTtl);
                            $this->log('Private Access Token (PAT) cryptographically verified - granting zero-friction bypass', [
                                'tokenType' => $parsedToken['tokenType'],
                                'tokenKeyId' => $parsedToken['tokenKeyId']
                            ]);
                            $decision = [
                                'action' => 'next',
                                'score' => 0.0,
                                'vector' => ['pat_verified' => 100.0, 'privacy_pass' => 100.0]
                            ];
                            return $decision;
                        }
                    }
                }
            }
        }

        // 1. Check allowlists
        if ($this->checkAllowlists($context)) {
            MetricsManager::incrementCounter('requests_total', ['status' => 'whitelisted']);
            return ['action' => 'next', 'score' => 0.0, 'vector' => ['whitelisted' => 100.0]];
        }

        // Initialize the suspicion vector
        $thresholds = $this->securityConfig['thresholds'];

        // 2. Handle challenge solution submission (HIGH PRIORITY)
        $powNonce = $context->query['pow_nonce'] ?? null;
        $isChallengeSubmission = $powNonce && (
                isset($context->query['pow_solution']) ||
                isset($context->query['pow_solution_cpu']) ||
                isset($context->query['pow_solution_space']) ||
                (isset($context->query['pow_type']) && $context->query['pow_type'] === 'useful_work_task')
            );
        if ($isChallengeSubmission) {
            $this->log('Challenge solution submitted', ['pow_type' => $context->query['pow_type'] ?? 'unknown', 'nonce' => $powNonce]);
            $store = StoreManager::getStore();
            $challengeContext = $store->get("secret:{$powNonce}");
            $powType = $context->query['pow_type'] ?? null;

            if ($challengeContext) {
                $isValid = false;
                $ticket = null;

                // Fingerprint consistency check
                $solverFingerprint = $context->query['pow_fp'] ?? RequestUtils::getCompositeDeviceHash($context);
                $originalFingerprint = $challengeContext['fingerprint'] ?? '';
                $similarity = FingerprintBuilder::compare($originalFingerprint, $solverFingerprint);
                $similarityThreshold = $this->securityConfig['similarityThreshold'] ?? 0.95;

                if ($similarity < $similarityThreshold) {
                    $this->log('Fingerprint mismatch - challenge solved on a different machine!', [
                        'similarity' => round($similarity, 4),
                        'threshold' => $similarityThreshold
                    ], 'warn');
                    $isValid = false;
                } else {
                    // The fingerprint is consistent, the solution can be verified
                    if ($powType === 'cpu_target' || $powType === 'cpu_mem') {
                        $cpuSolution = $context->query['pow_solution_cpu'] ?? $context->query['pow_solution'] ?? null;
                        if ($cpuSolution !== null && $cpuSolution !== '') {
                            $identity = $this->resolveRequestIdentity($context, $suspicionVector);
                            $deviceId = (string)($identity['deviceId'] ?? '');
                            $currentDeviceHash = (string)($identity['currentDeviceHash'] ?? RequestUtils::getCompositeDeviceHash($context));

                            $ticket = ChallengeUtils::verifyCpuTargetPoWAndGenerateTicket(
                                $context->clientIp,
                                3600000,
                                $powNonce,
                                (string)$cpuSolution,
                                $challengeContext,
                                $deviceId,
                                $currentDeviceHash
                            );
                            $isValid = $ticket !== null;

                            if ($powType === 'cpu_mem') {
                                if (!empty($challengeContext['isHttp'])) {
                                    $isMemValid = true;
                                } else {
                                    $memSolution = $context->query['pow_solution_mem'] ?? null;
                                    $isMemValid = ($memSolution !== null && $memSolution !== '')
                                        ? ChallengeUtils::verifyMemoryPoW(
                                            $powNonce,
                                            (string)$memSolution,
                                            $challengeContext['memDifficulty'] ?? 0,
                                            $challengeContext['clientSecret'] ?? ''
                                        )
                                        : false;
                                }
                                $isValid = $isValid && $isMemValid;
                            }
                        }
                    } elseif ($powType === 'pospace') {
                        $powSolutionSpace = $context->query['pow_solution_space'] ?? null;
                        if ($powSolutionSpace && isset($challengeContext['queries'])) {
                            $isSpaceValid = ChallengeUtils::verifySpacePoW(
                                $powNonce,
                                $powSolutionSpace,
                                $challengeContext['queries'],
                                $powNonce . ":" . $challengeContext['clientSecret'],
                                $challengeContext['clientSecret']
                            );
                            $isValid = $isSpaceValid;
                            if ($isValid) {
                                $ticketTtl = $this->securityConfig['ticketMaxAge'] ?? 3600000;
                                $expiry = (int)floor(microtime(true) * 1000) + $ticketTtl;
                                $ticket = ChallengeUtils::generateStatelessTicket([
                                    'expiry' => $expiry,
                                    'originalIp' => $context->clientIp,
                                    'deviceId' => '',
                                    'deviceHash' => ''
                                ]);
                            }
                        }
                    } elseif ($powType === 'useful_work_task') {
                        $problemId = $context->query['pow_problem_id'] ?? null;
                        $workResultJson = $context->query['pow_solution_work_result'] ?? null;
                        if ($problemId && $workResultJson) {
                            $workResult = json_decode($workResultJson, true);
                            $this->log('Verifying useful work solution.', [
                                'problemId' => $problemId,
                                'receivedData' => $workResult,
                                'jsonLastError' => json_last_error_msg()
                            ]);
                            if (json_last_error() === JSON_ERROR_NONE) {
                                // @phpstan-ignore-next-line - The instance is managed by the singleton
                                $defaultPath = dirname(__DIR__, 2) . '/config/problems.config.json';
                                $configPath = $this->securityConfig['usefulWorkConfigPath'] ?? (file_exists($defaultPath) ? $defaultPath : null);
                                $problemManager = \Anonympins\Fingerprint\ProblemManager::getInstance($configPath, $store);
                                // FIX: The solution is directly $workResult, not a sub-property.
                                $problemManager->integrateSolution($problemId, $workResult);

                                // If the solved problem is security auto-tuning and auto-tuning is enabled,
                                // we directly apply the best computed solution to the live engine.
                                if ($problemId === 'security_auto_tuning' && ($this->securityConfig['autotuning']['enabled'] ?? false)) {
                                    $paretoFront = $workResult['paretoFront'] ?? null;
                                    if (is_array($paretoFront) && !empty($paretoFront)) {
                                        $bestSolution = $paretoFront[0];
                                        $minDistance = sqrt(pow((float)$bestSolution['objectives'][0], 2) + pow((float)$bestSolution['objectives'][1], 2));
                                        for ($i = 1; $i < count($paretoFront); $i++) {
                                            $distance = sqrt(pow((float)$paretoFront[$i]['objectives'][0], 2) + pow((float)$paretoFront[$i]['objectives'][1], 2));
                                            if ($distance < $minDistance) {
                                                $minDistance = $distance;
                                                $bestSolution = $paretoFront[$i];
                                            }
                                        }
                                        if (isset($bestSolution['solution'])) {
                                            $this->updateConfig($bestSolution['solution']);
                                            $this->log('Useful Work auto-tuning applied successfully to live config.');
                                        }
                                    }
                                }

                                $isValid = true;
                                // FIX: Generate a real ticket for uPoW, like for a normal PoW.
                                $ticketTtl = $this->securityConfig['ticketMaxAge'] ?? 3600000; // 1 hour by default
                                $expiry = (int)floor(microtime(true) * 1000) + $ticketTtl;
                                $signature = hash_hmac('sha256', "{$context->clientIp}:{$expiry}", ChallengeUtils::getPowSecret());
                                $ticket = "{$expiry}:{$signature}";
                            }
                        }
                    }
                }

                if ($isValid) {
                    $store->delete("secret:{$powNonce}");
                    $ticketTtl = $this->securityConfig['ticketMaxAge'] ?? 3600000;
                    MetricsManager::incrementCounter('challenges_solved_total');
                    $this->log('Challenge solution valid - issuing ticket', ['ticketMaxAge' => $ticketTtl]);

                    $isHttps = !empty($context->isHttps);
                    $secureOption = $isHttps;

                    return [
                        'action' => 'redirect',
                        'path' => RequestUtils::cleanUrlFromPowParams($challengeContext['originalPath'] ?? '/', $context->query),
                        'score' => 0.0,
                        'vector' => ['challenge_solved' => 100],
                        'cookie' => [
                            'name' => 'pow_clearance',
                            'value' => $ticket,
                            'options' => [
                                'httponly' => true,
                                'secure' => $secureOption,
                                'samesite' => 'Strict',
                                'expires' => time() + ($ticketTtl / 1000),
                                'path' => '/',
                            ]
                        ]
                    ];
                }
            }
            // If the solution is invalid or the nonce is expired, we strongly penalize it for the following steps.
            MetricsManager::incrementCounter('challenges_failed_total');
            $this->log('Challenge solution invalid or context expired', ['nonce' => $powNonce], 'warn');
            $suspicionVector['honeypotScore'] = 100.0;
        }

        // 3. Check an existing ticket
        $hasValidTicket = false;
        $powCookie = $context->cookies['pow_clearance'] ?? null;
        $zkpProof = $context->getHeader('x-zkp-proof') ?? $context->query['pow_zkp'] ?? '';
        $deviceId = $context->cookies['device_id'] ?? '';
        $currentDeviceHash = RequestUtils::getCompositeDeviceHash($context);
        $allowRoaming = $this->securityConfig['allowCrossNetworkRoaming'] ?? false;
        if (ChallengeUtils::isTicketValid($context->clientIp, $powCookie, $deviceId, $currentDeviceHash, $allowRoaming, $zkpProof)) {
            $hasValidTicket = true;
            MetricsManager::incrementCounter('tickets_valid_total');
            // We do not return immediately to allow re-challenging.
            // $this->log('Valid clearance ticket found');
            // return ['action' => 'next', 'score' => 0.0, 'vector' => ['ticket_valid' => 100]];
        }

        // 4. Compute the suspicion vector and score
        // Resolve identity and check "condemned" status
        $store = StoreManager::getStore();
        $identity = $this->resolveRequestIdentity($context, $suspicionVector);
        $deviceId = $identity['deviceId'];
        $deviceData = $identity['deviceData'];
        if ($deviceData && ($deviceData['condemned'] ?? false)) {
            $this->log('Device condemned - blocking request', ['deviceId' => $deviceId], 'warn');
            $decision = ['action' => 'block', 'status' => 403, 'body' => 'Forbidden', 'score' => 100, 'vector' => ['honeypotScore' => 100]];
            if ($this->dryRun) {
                $this->log("[Dry Run] Intended action: {$decision['action']}", ['score' => $decision['score']]);
                $decision['intendedAction'] = $decision['action'];
                $decision['action'] = 'next';
                unset($decision['status'], $decision['body']);
            }
            return $decision;
        }

        $suspicionVector = $context->preCalculatedVector ?? $this->getSuspicionVector($context, $suspicionVector);
        $finalScore = $context->preCalculatedScore ?? $this->calculateFinalScore($suspicionVector);
        $this->log('Suspicion vector and final score calculated', [
            'finalScore' => round($finalScore, 2),
            'vector' => $suspicionVector
        ]);

        // Update subnet metrics after computing the final score
        if ($finalScore >= ($thresholds['medium'] ?? 45)) {
            RequestUtils::updateSubnetMetrics($context, $deviceId, $finalScore);
            MetricsManager::observeValue('suspicion_score', $finalScore, ['action' => 'high_score_subnet_update']);
        }

        // Logic to challenge new devices (moved here to have the final score)
        $isNewDevice = $identity['newCookie'] !== null;
        if ($isNewDevice && ($this->securityConfig['challengeNewDevices'] ?? false) && $finalScore < $thresholds['low']) {
            $this->log('New device - enforcing minimum challenge score', [
                'originalScore' => round($finalScore, 2),
                'enforcedScore' => (float)$thresholds['low']
            ]);
            $finalScore = (float)$thresholds['low'];
        }

        // Check trap URLs (after score computation)
        $lastNonce = $deviceData['lastChallengeNonce'] ?? null;
        if ($lastNonce && ChallengeUtils::verifyTrapUrl($context->path, $context->query['sig'] ?? '', $lastNonce)) {
            if ($this->logger) {
                $this->logger->log('info', 'trap_triggered', ['deviceId' => $deviceId, 'score' => 100, 'path' => $context->path, 'vector' => ['honeypotScore' => 100]]);
            }
            $this->log('Honeypot trap URL triggered - condemning device', ['path' => $context->path, 'deviceId' => $deviceId]);
            $deviceData['condemned'] = true; // @phpstan-ignore-line
            $store->set("device:{$deviceId}", $deviceData);
            $decision = ['action' => 'block', 'status' => 403, 'body' => 'Forbidden', 'score' => 100, 'vector' => ['honeypotScore' => 100]];
            if ($this->dryRun) {
                $this->log("[Dry Run] Intended action: {$decision['action']}", ['score' => $decision['score']]);
                $decision['intendedAction'] = $decision['action'];
                $decision['action'] = 'next';
                unset($decision['status'], $decision['body']);
            }
            return $decision;
        }

        // 5. Decide based on the score - Check blocking first.
        $blockThreshold = $thresholds['block'] ?? 95;
        $isBlocked = $finalScore >= $blockThreshold;
        if ($isBlocked) {
            if ($this->logger) {
                MetricsManager::incrementCounter('requests_total', ['status' => 'blocked']);
                $this->logger->log('info', 'request_blocked', ['deviceId' => $deviceId, 'score' => $finalScore, 'vector' => $suspicionVector]);
            }

            // Federated Threat Intelligence & ZKP Synchronization
            $zkpProof = $context->getHeader('x-zkp-proof') ?? $context->query['pow_zkp'] ?? '';
            $parts = explode(':', $zkpProof);
            if (count($parts) === 3) {
                $zkpY = $parts[0];
                $zkpT = $parts[1];
                $zkpS = $parts[2];
                // 1. Cryptographically validate the proof before banning/broadcasting
                if (ChallengeUtils::verifyZkpProof($zkpY, $zkpT, $zkpS)) {
                    // 2. De-duplicate: only broadcast if the key is not already banned
                    $peersKey = "fed-peers:{$zkpY}";
                    $reportedPeers = $store->get($peersKey) ?: [];
                    if (!is_array($reportedPeers)) {
                        $reportedPeers = [];
                    }
                    if (!in_array('local', $reportedPeers, true)) {
                        $reportedPeers[] = 'local';
                        $store->set($peersKey, $reportedPeers, 86400 * 30);
                    }

                    $threshold = $this->securityConfig['federationConsensusThreshold'] ?? 3;
                    if (count($reportedPeers) >= $threshold) {
                        $store->set("banned-zkp-y:{$zkpY}", true, 86400 * 30);
                    }
                    $this->broadcastBannedZkp($zkpY);
                }
            }

            $decision = ['action' => 'block', 'status' => 403, 'body' => 'Forbidden', 'score' => $finalScore, 'vector' => $suspicionVector];
            if ($this->dryRun) {
                $this->log("[Dry Run] Intended action: {$decision['action']}", ['score' => $decision['score']]);
                $decision['intendedAction'] = $decision['action'];
                $decision['action'] = 'next';
                unset($decision['status'], $decision['body']);
                MetricsManager::incrementCounter('requests_total', ['status' => 'dry_run_block']);
            }
            $response = $decision;
        } else {
            // Re-challenge logic
            // If a nonce is present but it is not a valid solution submission, it is a probe.
            if ($powNonce && !$isChallengeSubmission) {
                $this->log('Honeypot probe detected - blocking request', ['path' => $context->path, 'pow_nonce' => $powNonce]);
                $suspicionVector['honeypotScore'] = 100.0;
                $finalScore = $this->calculateFinalScore($suspicionVector); // Recalculate score
                $decision = ['action' => 'block', 'status' => 403, 'body' => 'Forbidden', 'score' => $finalScore, 'vector' => $suspicionVector];
                // Apply dry run logic here as well
                if ($this->dryRun) {
                    MetricsManager::incrementCounter('requests_total', ['status' => 'dry_run_block']);
                    $this->log("[Dry Run] Intended action: {$decision['action']}", ['score' => $decision['score']]);
                    $decision['intendedAction'] = $decision['action'];
                    $decision['action'] = 'next';
                    unset($decision['status'], $decision['body']);
                }
                return $decision;
            }

            $mediumThreshold = $thresholds['medium'] ?? 45;
            $maxIndicatorsCount = 0;
            foreach ($suspicionVector as $val) {
                if (is_numeric($val) && (float)$val >= 100.0) {
                    $maxIndicatorsCount++;
                }
            }
            $mustReChallenge = (($suspicionVector['honeypotScore'] ?? 0.0) >= $mediumThreshold) || ($maxIndicatorsCount >= 1);

            $lowThreshold = $thresholds['low'] ?? 20;
            if (($finalScore >= $lowThreshold && !$hasValidTicket) || $mustReChallenge) {
                if ($mustReChallenge) {
                    $this->log('High suspicion score detected - overriding valid ticket to re-issue challenge', ['finalScore' => $finalScore, 'deviceId' => $deviceId]);
                }

                // --- ADDED: Rate limiter (Token Bucket) ---
                $rateLimitPassed = ChallengeUtils::checkChallengeRateLimit($context->clientIp);
                if (!$rateLimitPassed) {
                    $this->log('Challenge rate limit exceeded - blocking with 429', ['clientIp' => $context->clientIp]);
                    $decision = [
                        'action' => 'block',
                        'status' => 429,
                        'body' => 'Too Many Requests',
                        'score' => $finalScore,
                        'vector' => $suspicionVector
                    ];
                    if ($this->dryRun) {
                        $this->log("[Dry Run] Intended action: {$decision['action']}", ['score' => $decision['score']]);
                        $decision['intendedAction'] = $decision['action'];
                        $decision['action'] = 'next';
                        unset($decision['status'], $decision['body']);
                    }
                    return $decision;
                }

                $decision = ['action' => 'challenge', 'score' => $finalScore, 'vector' => $suspicionVector, 'status' => 403];

                if ($this->dryRun) {
                    MetricsManager::incrementCounter('requests_total', ['status' => 'dry_run_challenge']);
                    $this->log("[Dry Run] Intended action: {$decision['action']}", ['score' => $decision['score']]);
                    $decision['intendedAction'] = $decision['action'];
                    $decision['action'] = 'next';
                    unset($decision['status']);
                    return $decision;
                }

                MetricsManager::incrementCounter('requests_total', ['status' => 'challenged']);
                $this->log('Suspicious request - selecting challenge type', ['finalScore' => $finalScore]);

                $nonce = bin2hex(random_bytes(16));
                $clientSecret = bin2hex(random_bytes(16));
                $highThreshold = $thresholds['high'] ?? 75;

                $suspicionFactor = ($finalScore - $lowThreshold) / (($thresholds['high'] ?? 75) - $lowThreshold);
                $suspicionFactor = max(0, min(1.5, $suspicionFactor));

                // --- NEW uPoW LOGIC ---
                $shouldUseUsefulWork = ($this->securityConfig['enableUsefulWork'] ?? false) && (
                        ($this->securityConfig['forceUsefulWork'] ?? false) || (random_int(0, 255) / 255) > 0.5
                    );

                // Determine if it is an API request before choosing the challenge type
                $isApiRequest = false;
                if (isset($this->securityConfig['isApiRequest']) && is_callable($this->securityConfig['isApiRequest'])) {
                    $isApiRequest = ($this->securityConfig['isApiRequest'])($context);
                }

                if ($shouldUseUsefulWork) {
                    $this->log('Issuing a useful work challenge', ['finalScore' => $finalScore]);
                    $defaultPath = dirname(__DIR__, 1) . '/config/problems.config.json';
                    $configPath = $this->securityConfig['usefulWorkConfigPath'] ?? (file_exists($defaultPath) ? $defaultPath : null);
                    $problemManager = ProblemManager::getInstance($configPath, $store);
                    $work = $problemManager->dispatchWork($finalScore);

                    if ($work !== null) {
                        $store->set("secret:{$nonce}", ['clientSecret' => $clientSecret, 'originalPath' => $context->path], 300);
                        $challengePayload = [
                            'challenge' => [
                                'type' => 'useful_work_task',
                                'nonce' => $nonce,
                                'clientSecret' => $clientSecret,
                                'usefulWorkTask' => [
                                    'problemId' => $work['problemId'],
                                    'task' => $work['task']
                                ]
                            ]
                        ];
                        if ($isApiRequest) {
                            $decision['body'] = $challengePayload;
                            return $decision;
                        } else {
                            $html = '<html><body><script>';
                            $html .= 'window.location.href = "' . $context->path . '?pow_type=useful_work_task&pow_nonce=' . $nonce . '&pow_problem_id=' . $work['problemId'] . '&pow_solution_work_result=" + encodeURIComponent(JSON.stringify({"solution": [], "energy": 0}));';
                            $html .= '</script></body></html>';
                            $decision['body'] = $html;
                            return $decision;
                        }
                    } else {
                        // This case handles when uPoW is enabled but dispatching a task fails (e.g., config not found).
                        // We log it and fall through to the standard PoW challenge.
                        $this->log('Useful work dispatch failed, falling back to standard PoW.', [], 'warn');
                        $shouldUseUsefulWork = false; // Explicitly disable for this request
                    }
                }

                // --- END OF uPoW LOGIC (the rest is the fallback) ---

                if ($this->securityConfig['enableProofOfSpace'] ?? false) {
                    $spaceChallenge = ChallengeUtils::generateSpaceChallenge($context->clientIp, $nonce, $suspicionFactor, $context->path, $this->securityConfig);
                    $store->set("secret:{$nonce}", [
                        'clientSecret' => $clientSecret,
                        'suspicionScore' => $finalScore,
                        'queries' => $spaceChallenge['queries'],
                        'sizeMb' => $spaceChallenge['sizeMb'],
                        'fingerprint' => RequestUtils::getCompositeDeviceHash($context),
                        'originalPath' => $context->path,
                    ], $this->securityConfig['challengeTtl'] ?? 300);

                    if ($deviceData) {
                        $deviceData['lastChallengeNonce'] = $nonce;
                        $store->set("device:{$deviceId}", $deviceData); // @phpstan-ignore-line
                    }

                    if ($isApiRequest) {
                        $decision['body'] = [
                            'challenge' => [
                                'type' => 'pospace',
                                'nonce' => $nonce,
                                'clientSecret' => $clientSecret,
                                'queries' => $spaceChallenge['queries'],
                                'sizeMb' => $spaceChallenge['sizeMb'],
                            ]
                        ];
                    } else {
                        $page = ChallengeUtils::generateSpaceChallengePage($spaceChallenge, $clientSecret, $this->securityConfig);
                        $decision['body'] = $page;
                    }
                    return $decision;
                }

                $cpuChallengeDetails = [
                    'type' => 'cpu_target',
                    'nonce' => $nonce,
                    'target' => ChallengeUtils::calculateCpuTarget($suspicionFactor, $this->securityConfig),
                    'path' => $context->path,
                ];

                // Perfect linear alignment of the CPU/Memory effort ratio
                $memActivationFactor = $suspicionFactor;
                $memDifficulty = (int)round($memActivationFactor * 48); // 0 to 48MB

                $originalFingerprint = RequestUtils::getCompositeDeviceHash($context);
                $tlsSessionId = $context->tlsSessionId ?? '';
                $baseBlock = ChallengeUtils::createCpuChallengeBaseBlock($nonce, $clientSecret, $originalFingerprint, $context->clientIp, $tlsSessionId);

                $isHttps = !empty($context->isHttps);
                $challengeContext = [
                    'clientSecret' => $clientSecret,
                    'cpuTarget' => $cpuChallengeDetails['target'],
                    'suspicionScore' => $finalScore,
                    'fingerprint' => $originalFingerprint,
                    'memDifficulty' => $memDifficulty,
                    'baseBlock' => $baseBlock,
                    'originalPath' => $context->path,
                    'isHttp' => !$isHttps,
                ];

                $store->set("secret:{$nonce}", $challengeContext, $this->securityConfig['challengeTtl'] ?? 300);

                // Associate the nonce with the device for trap URL verification
                if ($deviceData) {
                    $deviceData['lastChallengeNonce'] = $nonce;
                    $store->set("device:{$deviceId}", $deviceData); // @phpstan-ignore-line
                }

                $trapUrls = [ChallengeUtils::generateTrapUrl($nonce), ChallengeUtils::generateTrapUrl($nonce)];
                $this->log('Challenge issued', ['nonce' => $nonce, 'ttl' => $this->securityConfig['challengeTtl'] ?? 300]);

                if ($this->logger) {
                    $this->logger->log('info', 'challenge_issued', ['deviceId' => $deviceId, 'score' => $finalScore, 'vector' => $suspicionVector]);
                }

                // For API requests, return a JSON challenge
                if ($isApiRequest) {
                    $challengePayload = [
                        'challenge' => [
                            'type' => 'cpu_mem',
                            'nonce' => $nonce,
                            'clientSecret' => $clientSecret,
                            'cpuTarget' => $cpuChallengeDetails['target'],
                            'memDifficulty' => $memDifficulty,
                            'baseBlock' => array_values(unpack('C*', $baseBlock)), // Send as a byte array
                        ]
                    ];
                    $decision['body'] = $challengePayload;
                } else {
                    // For browsers, return an HTML page
                    $pageBody = ChallengeUtils::generateCombinedPoWChallengePage(
                        $cpuChallengeDetails, $memDifficulty, $clientSecret,
                        $this->securityConfig, $trapUrls, $originalFingerprint,
                        $context->clientIp, $tlsSessionId, $baseBlock, $isHttps
                    );
                    $decision['body'] = $pageBody;
                }
                $response = $decision;
            } elseif ($hasValidTicket) {
                // If we get here with a valid ticket and a low score, allow the request
                MetricsManager::incrementCounter('requests_total', ['status' => 'passed']);
                $this->log('Valid clearance ticket found and score is low - allowing request');
                $response = ['action' => 'next', 'score' => 0.0, 'vector' => ['ticket_valid' => 100], 'intendedAction' => 'next'];
            } else {
                // 6. If the score is low and there is no ticket, allow the request
                MetricsManager::incrementCounter('requests_total', ['status' => 'passed']);
                $this->log('Request passed - no challenge required', ['finalScore' => $finalScore]);
                if ($this->logger) {
                    MetricsManager::observeValue('suspicion_score', $finalScore, ['action' => 'passed']);
                    $this->logger->log('info', 'request_passed', ['deviceId' => $deviceId, 'score' => $finalScore, 'vector' => $suspicionVector]);
                }
                $response = ['action' => 'next', 'score' => $finalScore, 'vector' => $suspicionVector, 'intendedAction' => 'next'];
            }
        }

        // If a new identification cookie has been generated, add it to the response.
        if (isset($context->newCookieForResponse)) {
            $response['newCookieForResponse'] = $context->newCookieForResponse;
        }

        return $response;
    }

    /**
     * Checks whether the GraphQL operation matches a whitelist entry.
     * Supports exact matches, wildcard '*' for operation name, and
     * trailing-wildcard prefixes on operation names.
     *
     * @param string|null $operationType The GraphQL operation type (query/mutation).
     * @param string|null $operationName The GraphQL operation name.
     * @return bool True if the operation is allowlisted, false otherwise.
     */
    private function isGraphqlOperationInAllowlist(?string $operationType, ?string $operationName): bool
    {
        if (empty($operationType) || empty($operationName)) {
            return false;
        }

        $whitelistRules = $this->securityConfig['whitelist'] ?? [];
        $graphqlRule = null;
        foreach ($whitelistRules as $rule) {
            if (($rule['type'] ?? '') === 'graphql_operation_allowlist') {
                $graphqlRule = $rule;
                break;
            }
        }

        if (empty($graphqlRule['entries'])) {
            return false;
        }

        foreach ($graphqlRule['entries'] as $entry) {
            [$entryType, $entryName] = explode(':', $entry, 2);
            if ($entryType !== $operationType) continue;

            if ($entryName === $operationName || $entryName === '*') return true;

            if (str_ends_with($entryName, '*') && str_starts_with($operationName, substr($entryName, 0, -1))) return true;
        }

        return false;
    }


    /**
     * Broadcasts a banned ZKP public key to all federated peers, with optional
     * differential privacy (Laplacian timestamp noise and decoy keys).
     *
     * @param string $zkpY The ZKP public key to broadcast.
     * @return void
     */
    private function broadcastBannedZkp(string $zkpY): void
    {
        $peers = $this->securityConfig['federatedPeers'] ?? [];
        if (empty($peers)) return;

        $dpConfig = $this->securityConfig['differentialPrivacy'] ?? [];
        $dpEnabled = ($dpConfig['enabled'] ?? true) !== false;
        $epsilon = isset($dpConfig['epsilon']) && is_numeric($dpConfig['epsilon'])
            ? (float)$dpConfig['epsilon']
            : (float)($this->securityConfig['dpEpsilon'] ?? 1.0);

        $sendThreatReport = function (string $targetZkpY, int $ts) use ($peers) {
            $msg = "{$ts}:{$targetZkpY}";
            $signature = '';
            $isAsymmetric = false;

            $privateKey = Env::get('ED25519_PRIVATE_KEY');
            if ($privateKey) {
                try {
                    $cleanKey = str_replace('\n', "\n", $privateKey);
                    $pkeyObj = openssl_pkey_get_private($cleanKey);
                    if ($pkeyObj && openssl_sign($msg, $sigBytes, $pkeyObj, null)) {
                        $signature = bin2hex($sigBytes);
                        $isAsymmetric = true;
                    }
                } catch (\Throwable $e) {
                    self::logError('[Fingerprint] Asymmetric broadcast signing failed: ' . $e->getMessage());
                }
            }

            if (!$isAsymmetric) {
                $secret = $this->securityConfig['federationSecret'] ?? ChallengeUtils::getPowSecret();
                $signature = hash_hmac('sha256', $msg, $secret);
            }

            foreach ($peers as $peerUrl) {
                $this->asyncPost($peerUrl . '?coop_op=share_threat_intel', [
                    'zkpY' => $targetZkpY,
                    'signature' => $isAsymmetric ? '' : $signature,
                    'signature_ed25519' => $isAsymmetric ? $signature : '',
                    'timestamp' => $ts
                ]);
            }
        };

        $now = (int)(microtime(true) * 1000);
        $reportTimestamp = $now;

        if ($dpEnabled) {
            // 1. Differential Privacy: Laplacian noise on the timestamp
            $deltaT = 5000;
            $b = $deltaT / max(0.1, $epsilon);
            $u = (random_int(1, 999999) / 1000000.0) - 0.5;
            $safeU = abs($u) < 1e-7 ? ($u >= 0 ? 1e-7 : -1e-7) : $u;
            $laplaceNoise = -$b * ($safeU <=> 0) * log(1.0 - 2.0 * abs($safeU));
            $clampedNoise = (int)max(-60000, min(60000, round($laplaceNoise)));
            $reportTimestamp = $now + $clampedNoise;
        }

        $sendThreatReport($zkpY, $reportTimestamp);

        if ($dpEnabled) {
            // 2. Differential Privacy: Decoy ZKP key injection
            $decoyProb = isset($dpConfig['dummyRate']) && is_numeric($dpConfig['dummyRate'])
                ? (float)$dpConfig['dummyRate']
                : (1.0 / (1.0 + exp($epsilon)));

            $randFloat = random_int(0, 999999) / 1000000.0;
            if ($randFloat < $decoyProb) {
                $decoyBytes = random_bytes(32);
                $decoyZkpY = ltrim(bin2hex($decoyBytes), '0') ?: '1';

                $uDecoy = (random_int(1, 999999) / 1000000.0) - 0.5;
                $safeUDecoy = abs($uDecoy) < 1e-7 ? ($uDecoy >= 0 ? 1e-7 : -1e-7) : $uDecoy;
                $b = 5000 / max(0.1, $epsilon);
                $decoyNoise = (int)max(-60000, min(60000, round(-$b * ($safeUDecoy <=> 0) * log(1.0 - 2.0 * abs($safeUDecoy)))));
                $decoyTimestamp = $now + $decoyNoise;

                $sendThreatReport($decoyZkpY, $decoyTimestamp);
            }
        }
    }

    /**
     * Sends an asynchronous HTTP POST request to a given URL with the given
     * parameters (JSON-encoded). Uses non-blocking stream sockets with a short
     * connection timeout, so the caller is not delayed.
     *
     * @param string $url The target URL.
     * @param array $params The parameters to JSON-encode and POST.
     * @return void
     */
    protected function asyncPost(string $url, array $params): void
    {
        // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- wp_parse_url used if available
        $parts = function_exists('wp_parse_url') ? wp_parse_url($url) : parse_url($url);
        if ($parts === false) return;

        $host = $parts['host'];
        $port = $parts['port'] ?? ($parts['scheme'] === 'https' ? 443 : 80);
        $path = ($parts['path'] ?? '/') . (isset($parts['query']) ? '?' . $parts['query'] : '');
        $scheme = $parts['scheme'] === 'https' ? 'ssl://' : '';

        $postData = json_encode($params);

        $fp = @stream_socket_client(
            "{$scheme}{$host}:{$port}",
            $errno,
            $errstr,
            0.5,
            STREAM_CLIENT_CONNECT | STREAM_CLIENT_ASYNC_CONNECT
        );

        if ($fp) {
            stream_set_blocking($fp, false);
            $out = "POST {$path} HTTP/1.1\r\n";
            $out .= "Host: {$host}\r\n";
            $out .= "Content-Type: application/json\r\n";
            $out .= "Content-Length: " . strlen($postData) . "\r\n";
            $out .= "X-Federation-Signature: " . ($params['signature'] ?? '') . "\r\n";
            $out .= "X-Federation-Signature-Ed25519: " . ($params['signature_ed25519'] ?? '') . "\r\n";
            $out .= "X-Federation-Timestamp: " . ($params['timestamp'] ?? '') . "\r\n";
            $out .= "Connection: Close\r\n\r\n";
            $out .= $postData;

            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- Socket stream write
            @fwrite($fp, $out);
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Socket stream close
            @fclose($fp);
        }
    }

    /**
     * Checks whether a request comes from a legitimate, whitelisted bot (e.g. Googlebot)
     * using reverse DNS lookup followed by forward DNS lookup (with a circuit breaker
     * on DNS failures). Results are cached for 24 hours on success and 5 minutes on
     * failure.
     *
     * @param RequestContext $context The request context.
     * @return bool True if the request is from a verified whitelisted bot, false otherwise.
     */
    private function verifyWhitelistedBot(RequestContext $context): bool
    {
        $whitelistRules = $this->securityConfig['whitelist'] ?? [];
        $botRules = array_filter($whitelistRules, fn($rule) => isset($rule['hostnameSuffix']));
        if (empty($botRules)) {
            return false;
        }

        $userAgent = $context->getHeader('user-agent') ?? '';
        $matchedRule = null;
        foreach ($botRules as $rule) {
            if (isset($rule['userAgent']) && preg_match('/' . $rule['userAgent'] . '/', $userAgent)) {
                $matchedRule = $rule;
                break;
            }
        }
        if ($matchedRule === null) {
            return false;
        }

        $store = StoreManager::getStore();
        $cacheKey = "ip-whitelist:{$context->clientIp}";
        $cachedStatus = $store->get($cacheKey);

        if ($cachedStatus === 'verified') return true;
        if ($cachedStatus === 'failed') return false;

        if (!self::canAttemptDns()) {
            return false;
        }

        try {
            // 1. Reverse DNS lookup with strict 500ms timeout using our custom UDP DNS Client
            $revName = self::getReverseDnsName($context->clientIp);
            if (!$revName) {
                $store->set($cacheKey, 'failed', 300); // 5 min negative caching
                return false;
            }
            $hostnames = self::resolveDnsNative($revName, 'PTR');
            if ($hostnames === null || empty($hostnames)) {
                self::recordDnsFailure();
                $store->set($cacheKey, 'failed', 300); // 5 min negative caching
                return false;
            }

            $validHostname = null;
            foreach ($hostnames as $hostname) {
                if (str_ends_with($hostname, $matchedRule['hostnameSuffix'])) {
                    $validHostname = $hostname;
                    break;
                }
            }

            if ($validHostname === null) {
                $store->set($cacheKey, 'failed', 300); // 5 min negative caching
                return false;
            }

            // 2. Forward DNS lookup with strict 500ms timeout
            $ips = [];
            $resolvedA = self::resolveDnsNative($validHostname, 'A');
            if ($resolvedA === null) {
                self::recordDnsFailure();
                $store->set($cacheKey, 'failed', 300); // 5 min negative caching
                return false;
            }
            $ips = array_merge($ips, $resolvedA);

            $resolvedAaaa = self::resolveDnsNative($validHostname, 'AAAA');
            if ($resolvedAaaa === null) {
                self::recordDnsFailure();
                $store->set($cacheKey, 'failed', 300); // 5 min negative caching
                return false;
            }
            $ips = array_merge($ips, $resolvedAaaa);

            if (in_array($context->clientIp, $ips, true)) {
                self::recordDnsSuccess();
                $store->set($cacheKey, 'verified', 86400);
                return true;
            }
        } catch (\Exception $e) {
            self::recordDnsFailure();
            $store->set($cacheKey, 'failed', 300); // 5 min negative caching
            return false;
        }

        $store->set($cacheKey, 'failed', 300); // 5 min negative caching
        return false;
    }

    /**
     * @internal For testing purposes only.
     *
     * Returns the list of registered problems from the ProblemManager singleton.
     *
     * @return array The list of problems.
     */
    public function getProblems(): array
    {
        $problemManager = ProblemManager::getInstance();
        return $problemManager->getProblems();
    }

    /**
     * Decodes a CBOR-encoded string (used for WebAuthn attestation objects).
     * Supports major types 0-5 (unsigned int, negative int, byte string,
     * text string, array, map).
     *
     * @param string $str The CBOR-encoded input.
     * @param int &$offset The current byte offset (updated in place).
     * @return mixed The decoded value.
     * @throws \Exception On malformed CBOR or unsupported integer sizes.
     */
    private static function decodeCBOR(string $str, int &$offset = 0)
    {
        if ($offset >= strlen($str)) throw new \Exception("End of CBOR");
        $initial = ord($str[$offset++]);
        $major = $initial >> 5;
        $val = $initial & 0x1f;

        $readInt = function (int $val, string $str, int &$offset) {
            if ($val < 24) return $val;
            if ($val === 24) return ord($str[$offset++]);
            if ($val === 25) {
                $b1 = ord($str[$offset++]); $b2 = ord($str[$offset++]);
                return ($b1 << 8) | $b2;
            }
            if ($val === 26) {
                $b1 = ord($str[$offset++]); $b2 = ord($str[$offset++]);
                $b3 = ord($str[$offset++]); $b4 = ord($str[$offset++]);
                return ($b1 << 24) | ($b2 << 16) | ($b3 << 8) | $b4;
            }
            throw new \Exception("Unsupported integer size: " . (int)$val);
        };

        if ($major === 0) {
            return $readInt($val, $str, $offset);
        } elseif ($major === 1) {
            return -1 - $readInt($val, $str, $offset);
        } elseif ($major === 2 || $major === 3) {
            $len = $readInt($val, $str, $offset);
            $bytes = substr($str, $offset, $len);
            $offset += $len;
            return $bytes;
        } elseif ($major === 4) {
            $len = $readInt($val, $str, $offset);
            $arr = [];
            for ($i = 0; $i < $len; $i++) {
                $arr[] = self::decodeCBOR($str, $offset);
            }
            return $arr;
        } elseif ($major === 5) {
            $len = $readInt($val, $str, $offset);
            $map = [];
            for ($i = 0; $i < $len; $i++) {
                $k = self::decodeCBOR($str, $offset);
                $v = self::decodeCBOR($str, $offset);
                $map[$k] = $v;
            }
            return $map;
        }
        return null;
    }

    /**
     * Returns the list of trusted hardware attestation root certificates
     * (e.g. Yubico, FIDO Alliance) used to validate WebAuthn attestation chains.
     *
     * @return array The list of PEM-encoded trusted root certificates.
     */
    private static function getTrustedHardwareRoots(): array
    {
        return [
            "-----BEGIN CERTIFICATE-----\n" .
            "MIIDHzCCAfegAwIBAgIJANCvWjvF+2O6MA0GCSqGSIb3DQEBCwUAMC0xKzApBgNV\n" .
            "BAMTIll1YmljbyBBdHRlc3RhdGlvbiBSb290IENBMB4XDTE0MDgwNDAwMDAwMFox\n" .
            "TSUxSDBGBgNVBAMMT1l1YmljbyBBdHRlc3RhdGlvbiBSb290IENBMSowKAYDVQQK\n" .
            "EyFZdWJpY28gQUIxDzANBgNVBAcTBVN0b2NraG9sbTELMAkGA1UEBhMCU0UwggEi\n" .
            "MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC6XW0d87g+N6kGgSgC/H9UfA2p\n" .
            "-----END CERTIFICATE-----",
            "-----BEGIN CERTIFICATE-----\n" .
            "MIIB1DCCAXWgAwIBAgIEUI70WjAKBggqhkjOPQQDAjArMSkwJwYDVQQDEyBGSURP\n" .
            "IEFsbGlhbmNlIFJvb3QgQ0EgKFRlc3QpMB4XDTE0MDgxODA4MzA0NVoXDTM5MDgx\n" .
            "ODA4MzA0NVowKzEpMCcGA1UEAxMgRklETyBBbGxpYW5jZSBSb290IENBIChUZXN0\n" .
            "KTB2MBAGByqGSM49AgEGBSuBBAAiA2IABFv81Jm9M7AehfOIdpCH567gP0yqS40m\n" +
            "aN0j1a8n152G7n/nUf7J0j9F4pL9J2w1X8hN1N8f9Y3G9w8L29/m7/zX3O3n2e7/\n" .
            "g==\n" .
            "-----END CERTIFICATE-----"
        ];
    }

    /**
     * Verifies a WebAuthn hardware anchor, handling both registration
     * (attestation chain validation against trusted roots) and assertion
     * (signature verification against the stored public key).
     *
     * @param array $anchor The WebAuthn anchor data (type, clientDataJSON, etc.).
     * @param array &$deviceData The device data (updated in place on registration).
     * @return bool True if the anchor is valid, false otherwise.
     */
    private function verifyWebAuthnHardwareAnchor(array $anchor, array &$deviceData): bool
    {
        if (empty($anchor['type'])) return false;

        try {
            $clientDataHash = hash('sha256', base64_decode($anchor['clientDataJSON']), true);

            if ($anchor['type'] === 'registration') {
                if (empty($anchor['publicKey']) || empty($anchor['credentialId']) || empty($anchor['attestationObject'])) {
                    return false;
                }

                $attestationBytes = base64_decode($anchor['attestationObject']);
                $offset = 0;
                $decoded = self::decodeCBOR($attestationBytes, $offset);

                if (!$decoded || empty($decoded['fmt']) || empty($decoded['attStmt'])) {
                    return false;
                }

                $fmt = $decoded['fmt'];
                $attStmt = $decoded['attStmt'];

                if ($fmt !== 'none') {
                    if (empty($attStmt['x5c']) || !is_array($attStmt['x5c'])) {
                        return false;
                    }

                    $pems = [];
                    foreach ($attStmt['x5c'] as $der) {
                        $pems[] = "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END CERTIFICATE-----";
                    }

                    for ($i = 0; $i < count($pems) - 1; $i++) {
                        if (openssl_x509_verify($pems[$i], $pems[$i + 1]) !== 1) {
                            return false;
                        }
                    }

                    $rootPem = $pems[count($pems) - 1];
                    $trusted = false;
                    $trustedRoots = self::getTrustedHardwareRoots();
                    foreach ($trustedRoots as $trustedRootPem) {
                        if (openssl_x509_verify($rootPem, $trustedRootPem) === 1 || md5($rootPem) === md5($trustedRootPem)) {
                            $trusted = true;
                            break;
                        }
                    }
                    if (!$trusted) {
                        return false;
                    }
                }

                $deviceData['webauthnPublicKey'] = $anchor['publicKey'];
                $deviceData['webauthnCredentialId'] = $anchor['credentialId'];
                return true;
            } elseif ($anchor['type'] === 'assertion') {
                $storedPublicKeyPem = $deviceData['webauthnPublicKey'] ?? null;
                if (!$storedPublicKeyPem || ($deviceData['webauthnCredentialId'] ?? '') !== $anchor['credentialId']) {
                    return false;
                }

                $verifyBuffer = base64_decode($anchor['authenticatorData']) . $clientDataHash;
                $publicKey = openssl_pkey_get_public("-----BEGIN PUBLIC KEY-----\n" . chunk_split($storedPublicKeyPem, 64, "\n") . "-----END PUBLIC KEY-----");
                if (!$publicKey) return false;

                return openssl_verify($verifyBuffer, base64_decode($anchor['signature']), $publicKey, OPENSSL_ALGO_SHA256) === 1;
            }
        } catch (\Throwable $e) {
            self::logError('[WebAuthn-Server] PHP verification failed: ' . $e->getMessage());
        }
        return false;
    }

    /**
     * Logs an error message using the PHP error log.
     *
     * @param string $message The message to log.
     * @return void
     */
    private static function logError(string $message): void
    {
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Engine diagnostic error log
        error_log($message);
    }
}