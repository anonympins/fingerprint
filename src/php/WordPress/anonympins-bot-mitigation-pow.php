<?php
/**
 * Plugin Name: Anonympins Bot Mitigation with Proof-of-Work
 * Plugin URI: https://github.com/anonympins/fingerprint
 * Description: High-performance client-side anti-bot protection and Proof-of-Work challenge verification for WordPress.
 * Version: 0.8.3
 * Author: anonympins
 * Requires at least: 5.9
 * Requires PHP: 8.0
 * License: MIT
 * Text Domain: anonympins-bot-mitigation-pow
 * Domain Path: /languages
 */

declare(strict_types=1);

use Anonympins\Fingerprint\DirectFingerprint;
use Anonympins\Fingerprint\Store\StoreManager;
use Anonympins\Fingerprint\Config\SecurityProfiles;
use Anonympins\Fingerprint\Utils\MetricsManager;
use Anonympins\Fingerprint\WordPress\WpDbStore;

if (!defined('ABSPATH')) {
    exit;
}

if (!defined('ANONYMPINS_BOT_MITIGATION_VERSION')) {
    define('ANONYMPINS_BOT_MITIGATION_VERSION', '0.8.3');
}

if (!defined('ANONYMPINS_BOT_MITIGATION_FILE')) {
    define('ANONYMPINS_BOT_MITIGATION_FILE', __FILE__);
}

if (!defined('ANONYMPINS_BOT_MITIGATION_DIR')) {
    define('ANONYMPINS_BOT_MITIGATION_DIR', plugin_dir_path(ANONYMPINS_BOT_MITIGATION_FILE));
}

if (!defined('ANONYMPINS_BOT_MITIGATION_URL')) {
    define('ANONYMPINS_BOT_MITIGATION_URL', plugin_dir_url(ANONYMPINS_BOT_MITIGATION_FILE));
}

// =============================================================================
// HONEYPOT TRAPS FOR THIRD-PARTY ENVIRONMENTS (NON-WORDPRESS)
// =============================================================================
$fingerprint_foreign_env_trap_urls = [
    '/phpmyadmin', '/pma', '/adminer', '/mysql', '/dbadmin', '/phpinfo',
    '/.env', '/artisan', '/telescope', '/_profiler', '/config/database.php', '/vendor/',
    '/actuator', '/actuator/health', '/actuator/gateway', '/api-docs', '/swagger-ui',
    '/.flask', '/django_admin', '/__pycache__',
    '/.npmrc', '/package.json', '/package-lock.json',
    '/elmah.axd', '/trace.axd', '/cgi-bin/',
    '/.git', '/.svn', '/.aws', '/.kube', '/docker-compose', '/serverless'
];

$fingerprint_foreign_env_honeypot_fields = [
    '_token',
    'csrfmiddlewaretoken',
    'authenticity_token',
    'form_build_id',
    'form_id',
    'j_username',
    'j_password',
    '__VIEWSTATE',
    '__EVENTVALIDATION',
];

// =============================================================================
// DEFAULT SECURITY PROFILES CONFIGURATION BY CONTEXT
// =============================================================================
$fingerprint_security_profiles = [
    'api' => [
        'profile'   => 'api',
        'overrides' => [
            'verbose'             => false,
            'challengeNewDevices' => false,
            'honeypot'            => [
                'fields'           => $fingerprint_foreign_env_honeypot_fields,
                'trapUrls'         => $fingerprint_foreign_env_trap_urls,
                'detectInjections' => true,
            ],
        ],
    ],
    'admin' => [
        'profile'   => 'strict',
        'overrides' => [
            'verbose'             => true,
            'challengeNewDevices' => true,
            'honeypot'            => [
                'fields'           => $fingerprint_foreign_env_honeypot_fields,
                'trapUrls'         => $fingerprint_foreign_env_trap_urls,
                'detectInjections' => true,
            ],
        ],
    ],
    'frontend' => [
        'profile'   => 'blog',
        'overrides' => [
            'verbose'             => false,
            'challengeNewDevices' => false,
            'honeypot'            => [
                'fields'           => $fingerprint_foreign_env_honeypot_fields,
                'trapUrls'         => $fingerprint_foreign_env_trap_urls,
                'detectInjections' => true,
            ],
        ],
    ],
];

/**
 * Retrieves configurations merged with settings persisted in WordPress.
 */
function fingerprint_get_effective_profiles(array $defaultProfiles): array {
    $saved = get_option('anonympins_security_options', get_option('fingerprint_security_options', []));
    if (!is_array($saved) || empty($saved)) {
        return $defaultProfiles;
    }
    return [
        'frontend' => SecurityProfiles::deepMerge($defaultProfiles['frontend'], $saved['frontend'] ?? []),
        'admin'    => SecurityProfiles::deepMerge($defaultProfiles['admin'], $saved['admin'] ?? []),
        'api'      => SecurityProfiles::deepMerge($defaultProfiles['api'], $saved['api'] ?? []),
    ];
}

/**
 * Retrieves the configured settings for Sandbox / Simulation mode.
 */
function fingerprint_get_sandbox_config(): array {
    $saved = get_option('anonympins_security_options', get_option('fingerprint_security_options', []));
    $sandbox = is_array($saved) && isset($saved['sandbox']) && is_array($saved['sandbox']) ? $saved['sandbox'] : [];

    return [
        'enabled'      => !empty($sandbox['enabled']),
        'audit_only'   => !empty($sandbox['audit_only']),
        'log_requests' => !empty($sandbox['log_requests']),
        'add_headers'  => !isset($sandbox['add_headers']) || !empty($sandbox['add_headers']),
        'ip_filter'    => isset($sandbox['ip_filter']) ? trim((string)$sandbox['ip_filter']) : '',
    ];
}

/**
 * Retrieves the configured direct endpoint path for Prometheus metrics scraping.
 */
function fingerprint_get_metrics_endpoint(): string {
    $saved = get_option('anonympins_security_options', get_option('fingerprint_security_options', []));
    if (!isset($saved['metrics_endpoint'])) {
        return '/metrics';
    }
    $path = trim((string)$saved['metrics_endpoint']);
    if ($path === '') {
        return '';
    }
    return str_starts_with($path, '/') ? $path : '/' . $path;
}

/**
 * Returns the built-in default HTML challenge template (derived from fingerprint.js).
 */
function fingerprint_get_default_challenge_template(): string {
    return "<!DOCTYPE html>\n" .
        "<html>\n" .
        "<head>\n" .
        "\t<meta charset=\"utf-8\">\n" .
        "\t<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n" .
        "\t<title>{{TITLE}}</title>\n" .
        "\t<style>\n" .
        "\t\t{{CUSTOM_CSS}}\n" .
        "\t\tbody { font-family: sans-serif; text-align: center; padding-top: 50px; background: #fff; color: #222; }\n" .
        "\t\t#loader { margin: 20px; font-size: 15px; color: #2271b1; }\n" .
        "\t</style>\n" .
        "</head>\n" .
        "<body>\n" .
        "\t<h1>{{TITLE}}</h1>\n" .
        "\t<p>{{MESSAGE}}</p>\n" .
        "\t<div id=\"loader\">⚙️ Initializing combined verification...</div>\n" .
        "\t{{SOLVER_SCRIPT}}\n" .
        "</body>\n" .
        "</html>";
}

// 1. PSR-4 autoloader for the Fingerprint engine.
$fingerprint_composer_paths = [
    __DIR__ . '/vendor/autoload.php',
    (defined('ABSPATH') ? ABSPATH . 'vendor/autoload.php' : ''),
];
foreach ($fingerprint_composer_paths as $fingerprint_composer_path) {
    if (!empty($fingerprint_composer_path) && file_exists($fingerprint_composer_path)) {
        require_once $fingerprint_composer_path;
        break;
    }
}

spl_autoload_register(function (string $class): void {
    $prefix = 'Anonympins\\Fingerprint\\';
    $len = strlen($prefix);
    if (strncmp($prefix, $class, $len) !== 0) {
        return;
    }

    $relativeClass = substr($class, $len);

    if (str_starts_with($relativeClass, 'WordPress\\')) {
        $localClass = substr($relativeClass, strlen('WordPress\\'));
        $localFile = __DIR__ . '/' . str_replace('\\', '/', $localClass) . '.php';
        if (file_exists($localFile)) {
            require_once $localFile;
            return;
        }
    }

    $candidateDirs = [
        __DIR__ . '/src/',
        __DIR__ . '/includes/',
        __DIR__ . '/',
        dirname(__DIR__) . '/',
    ];

    $fileRelative = str_replace('\\', '/', $relativeClass) . '.php';
    foreach ($candidateDirs as $dir) {
        $fullPath = $dir . $fileRelative;
        if (file_exists($fullPath)) {
            require_once $fullPath;
            return;
        }
    }
});

if (file_exists(__DIR__ . '/WpDbStore.php')) {
    require_once __DIR__ . '/WpDbStore.php';
}

// 2. Plugin activation: Create the SQL cache table.
register_activation_hook(__FILE__, function () {
    $store = new WpDbStore();
    $store->ensureTable();

    if (!wp_next_scheduled('fingerprint_prune_expired_entries')) {
        wp_schedule_event(time(), 'hourly', 'fingerprint_prune_expired_entries');
    }
});

// 3. Deactivation: Clean up the WP-Cron.
register_deactivation_hook(__FILE__, function () {
    wp_clear_scheduled_hook('fingerprint_prune_expired_entries');
});

// 4. WP-Cron background task: Purge expired keys from the database.
add_action('fingerprint_prune_expired_entries', function () {
    $store = new WpDbStore();
    $store->pruneExpired();
});

// 5. Admin Notices
add_action('admin_notices', function () {
    if (!is_ssl()) {
        echo '<div class="notice notice-warning is-dismissible">';
        echo '<p><strong>' . esc_html__('[Anonympins bot mitigation security warning]', 'anonympins-bot-mitigation-pow') . '</strong> : ' .
            esc_html__('Your website is currently running on unencrypted HTTP. In this mode, modern web browsers disable the native Web Cryptography API (crypto.subtle) for security reasons, forcing a JavaScript fallback simulation that is slower and vulnerable to Man-in-the-Middle (MitM) attacks. We strongly recommend deploying a TLS/SSL certificate and enforcing HTTPS to ensure the cryptographic integrity of Proof-of-Work computations and identity protection.', 'anonympins-bot-mitigation-pow') .
            '</p>';
        echo '</div>';
    }
});

add_action('admin_notices', function () {
    $sandbox = fingerprint_get_sandbox_config();
    if ($sandbox['enabled'] && current_user_can('manage_options')) {
        $modeDesc = !empty($sandbox['audit_only'])
            ? esc_html__('Audit-Only dry-run is active: visitors will not be blocked or challenged.', 'anonympins-bot-mitigation-pow')
            : esc_html__('Enforced test mode: suspicion analysis and PoW challenges are actively triggered.', 'anonympins-bot-mitigation-pow');

        echo '<div class="notice notice-warning is-dismissible">';
        echo '<p><strong>' . esc_html__('[Anonympins bot mitigation sandbox active]', 'anonympins-bot-mitigation-pow') . '</strong> : ' .
            esc_html__('Sandbox mode is currently ENABLED.', 'anonympins-bot-mitigation-pow') . ' ' . esc_html($modeDesc) .
            ' <a href="' . esc_url(admin_url('options-general.php?page=anonympins-bot-mitigation#tab-sandbox')) . '">' . esc_html__('Configure sandbox', 'anonympins-bot-mitigation-pow') . '</a></p>';
        echo '</div>';
    }
});

/**
 * Records a challenge event in the store's circular buffer.
 */
function fingerprint_record_challenge_event(array $event): void {
    $store = new WpDbStore();
    $history = $store->get('fingerprint_challenges_log');
    if (!is_array($history)) {
        $history = [];
    }
    array_unshift($history, $event);
    if (count($history) > 50) {
        $history = array_slice($history, 0, 50);
    }
    $store->set('fingerprint_challenges_log', $history, 3600);
    $store->set('fingerprint_latest_challenge', $event, 3600);
}

$GLOBALS['fingerprint_current_evaluation'] = null;

// 6. Security interception at the earliest point in the WordPress lifecycle.
add_action('plugins_loaded', function () use ($fingerprint_security_profiles) {
    if ((defined('WP_CLI') && WP_CLI) || (defined('DOING_CRON') && DOING_CRON)) {
        return;
    }

    // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
    $rawUri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/';
    $requestUri = !empty($rawUri) ? $rawUri : '/';
    $isRestApi = defined('REST_REQUEST') && REST_REQUEST;

    if (preg_match('/\.(ico|png|jpg|jpeg|gif|webp|svg|css|js|woff|woff2|ttf)$/i', (string)wp_parse_url($requestUri, PHP_URL_PATH))) {
        return;
    }
    // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
    $isAdmin = is_admin() || (isset($_SERVER['PHP_SELF']) && str_contains(sanitize_text_field(wp_unslash($_SERVER['PHP_SELF'])), 'wp-login.php')) || str_contains($requestUri, 'wp-login.php');

    if (str_contains($requestUri, 'page=anonympins-bot-mitigation') || str_contains($requestUri, 'page=fingerprint-settings') || str_contains($requestUri, '/wp-json/fingerprint/v1/')) {
        return;
    }

    $store = new WpDbStore();
    $store->ensureTable();
    StoreManager::configureStore($store);

    $effectiveProfiles = fingerprint_get_effective_profiles($fingerprint_security_profiles);
    $configs = apply_filters('fingerprint_security_profiles', $effectiveProfiles);

    if ($isRestApi || str_starts_with($requestUri, '/wp-json/')) {
        $contextConfig = $configs['api'] ?? $fingerprint_security_profiles['api'];
    } elseif ($isAdmin) {
        $contextConfig = $configs['admin'] ?? $fingerprint_security_profiles['admin'];
    } else {
        $contextConfig = $configs['frontend'] ?? $fingerprint_security_profiles['frontend'];
    }

    $savedOptions = get_option('anonympins_security_options', get_option('fingerprint_security_options', []));
    $contextConfig['overrides']['challengeTemplate'] = (is_array($savedOptions) && isset($savedOptions['challenge_template']))
        ? (string)$savedOptions['challenge_template']
        : fingerprint_get_default_challenge_template();

    $sandboxConfig = fingerprint_get_sandbox_config();
    $isSandboxActive = false;

    // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
    $clientIp = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '';

    if ($sandboxConfig['enabled']) {
        if (!empty($sandboxConfig['ip_filter'])) {
            $targetIps = array_filter(array_map('trim', explode(',', $sandboxConfig['ip_filter'])));
            if (in_array($clientIp, $targetIps, true)) {
                $isSandboxActive = true;
            }
        } else {
            $isSandboxActive = true;
        }
    }

    if ($isSandboxActive) {
        $contextConfig['overrides']['sandboxMode'] = true;
        if (!empty($sandboxConfig['audit_only'])) {
            $contextConfig['overrides']['dryRun'] = true;
        }
        if ($sandboxConfig['log_requests']) {
            $contextConfig['overrides']['verbose'] = true;
        }
    }

    $contextConfig['overrides']['onDecision'] = function (array $decision, \Anonympins\Fingerprint\RequestContext $context) use ($isSandboxActive, $sandboxConfig, $requestUri, $clientIp, $contextConfig) {
        $score = (float)($decision['score'] ?? 0.0);
        $thresholdLow = (float)($contextConfig['overrides']['thresholds']['low'] ?? 20.0);
        $thresholdBlock = (float)($contextConfig['overrides']['thresholds']['block'] ?? 95.0);

        $action = $decision['intendedAction'] ?? ($decision['action'] ?? 'next');
        $actionTaken = 'allow';
        if ($action === 'block' || $score >= $thresholdBlock) {
            $actionTaken = 'block';
        } elseif ($action === 'challenge' || ($decision['action'] ?? '') === 'challenge' || $score >= $thresholdLow) {
            $actionTaken = 'challenge';
        } elseif ($action === 'redirect') {
            $actionTaken = 'challenge_solved';
        } elseif (!empty($decision['intendedAction']) && $decision['intendedAction'] !== 'next') {
            $actionTaken = (string)$decision['intendedAction'];
        }

        if ($isSandboxActive && !empty($sandboxConfig['audit_only'])) {
            if ($actionTaken !== 'allow') {
                $actionTaken = 'audit_sim (' . $actionTaken . ')';
            }
        }

        $isChallengedOrSuspect = ($actionTaken === 'challenge' || $actionTaken === 'block' || $actionTaken === 'challenge_solved' || str_starts_with($actionTaken, 'audit_sim'));

        $payload = [
            'id'              => uniqid('ch_', true),
            'timestamp'       => time(),
            'uri'             => $requestUri,
            'ip'              => !empty($clientIp) ? $clientIp : ($context->clientIp ?? 'unknown'),
            'suspicionScore'  => round($score, 1),
            'action'          => $actionTaken,
            'suspicionVector' => $decision['vector'] ?? [],
            'sandbox'         => $isSandboxActive,
        ];
        $GLOBALS['fingerprint_current_evaluation'] = $payload;

        if ($isSandboxActive && $sandboxConfig['add_headers'] && !headers_sent()) {
            header('X-Fingerprint-Sandbox: active');
            header('X-Fingerprint-Mode: ' . (!empty($sandboxConfig['audit_only']) ? 'audit-only' : 'enforce'));
            header('X-Fingerprint-Score: ' . (string)round($score, 1));
        }

        if ($sandboxConfig['log_requests']) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
            error_log(sprintf('[Fingerprint Challenge Log] Target: %s | IP: %s | Action: %s | Score: %s', $requestUri, $payload['ip'], $actionTaken, $payload['suspicionScore']));
        }

        if ($isChallengedOrSuspect) {
            fingerprint_record_challenge_event($payload);
        }
    };

    $securityConfig = SecurityProfiles::createSecurityProfile($contextConfig['profile'], $contextConfig['overrides'] ?? []);
    $guard = new DirectFingerprint($securityConfig);

    // Handle direct metrics endpoint if requested
    $metricsPath = fingerprint_get_metrics_endpoint();
    $path = (string)wp_parse_url($requestUri, PHP_URL_PATH);
    if ($metricsPath !== '' && ($path === $metricsPath || str_ends_with($path, $metricsPath))) {
        $context = $guard->buildRequestContext();
        $isAuth = current_user_can('manage_options') || apply_filters('fingerprint_metrics_authorization', false, $context);
        if (!$isAuth) {
            status_header(403);
            echo "Access to metrics denied.";
            exit;
        }
        $guard->handleMetricsRequest($context);
        return;
    }
    $guard->protect();
}, 0);

// =============================================================================
// CLIENT TELEMETRY LOADING & INITIALIZATION
// =============================================================================
add_action('wp_enqueue_scripts', 'fingerprint_enqueue_client_telemetry');
add_action('login_enqueue_scripts', 'fingerprint_enqueue_client_telemetry');

function fingerprint_enqueue_client_telemetry(): void {
    global $fingerprint_foreign_env_honeypot_fields, $fingerprint_foreign_env_trap_urls;

    $scriptUrl = ANONYMPINS_BOT_MITIGATION_URL . 'assets/fingerprint.client.js';
    $scriptPath = ANONYMPINS_BOT_MITIGATION_DIR . 'assets/fingerprint.client.js';

    if (!file_exists($scriptPath)) {
        return;
    }

    $version = filemtime($scriptPath) ?: ANONYMPINS_BOT_MITIGATION_VERSION;
    wp_enqueue_script('fingerprint-client-telemetry', $scriptUrl, [], (string)$version, false);

    $clientConfig = [
        'mouse'        => true,
        'keystrokes'   => true,
        'clicks'       => true,
        'touches'      => true,
        'motion'       => true,
        'rendering'    => true,
        'phantomTraps' => true,
        'honeypots'    => array_values($fingerprint_foreign_env_honeypot_fields),
        'trapUrls'     => array_values($fingerprint_foreign_env_trap_urls),
        'fetch'        => [
            'handleChallenges' => true,
        ],
    ];

    $inlineInit = 'if (window.ClientLibrary && typeof window.ClientLibrary.initializeClient === "function") {'
        . ' window.ClientLibrary.initializeClient(' . wp_json_encode($clientConfig) . ');'
        . '};';

    wp_add_inline_script('fingerprint-client-telemetry', $inlineInit);
}

// =============================================================================
// SUSPICION VECTOR INJECTION (VIA WP_ENQUEUE_SCRIPT & WP_ADD_INLINE_SCRIPT)
// =============================================================================
add_action('wp_enqueue_scripts', 'fingerprint_inject_client_suspicion_event', 20);
add_action('admin_enqueue_scripts', 'fingerprint_inject_client_suspicion_event', 20);
add_action('login_enqueue_scripts', 'fingerprint_inject_client_suspicion_event', 20);

function fingerprint_inject_client_suspicion_event(): void {
    $eval = $GLOBALS['fingerprint_current_evaluation'] ?? null;
    $sandbox = fingerprint_get_sandbox_config();
    if (!$eval || (!current_user_can('manage_options') && empty($sandbox['enabled']))) {
        return;
    }

    $jsonPayload = wp_json_encode($eval);
    $script = 'window.__FINGERPRINT_VECTOR__ = ' . $jsonPayload . '; try { document.dispatchEvent(new CustomEvent("fingerprint:suspicion", { detail: window.__FINGERPRINT_VECTOR__ })); } catch(e) {}';

    wp_register_script('anonympins-suspicion-event', false, [], ANONYMPINS_BOT_MITIGATION_VERSION, true);
    wp_enqueue_script('anonympins-suspicion-event');
    wp_add_inline_script('anonympins-suspicion-event', $script);
}

// =============================================================================
// SPECIAL SANDBOX ROUTES: REST & SERVER-SENT EVENTS (SSE)
// =============================================================================
add_action('rest_api_init', function () {
    // 1. Prometheus Metrics (registered under plugin namespace and legacy namespace)
    register_rest_route('anonympins/v1', '/metrics', [
        'methods'             => 'GET',
        'callback'            => 'fingerprint_rest_prometheus_metrics',
        'permission_callback' => function () {
            return current_user_can('manage_options') || apply_filters('fingerprint_metrics_access', false);
        },
    ]);

    register_rest_route('fingerprint/v1', '/sandbox/telemetry', [
        'methods'             => 'GET',
        'callback'            => 'fingerprint_rest_sandbox_telemetry',
        'permission_callback' => function () {
            return current_user_can('manage_options');
        },
    ]);

    // 2. Sandbox Inspection Routes (Strictly restricted to manage_options)
    register_rest_route('fingerprint/v1', '/sandbox/sse', [
        'methods'             => 'GET',
        'callback'            => 'fingerprint_rest_sandbox_sse',
        'permission_callback' => function () {
            return current_user_can('manage_options');
        },
    ]);

    register_rest_route('fingerprint/v1', '/metrics', [
        'methods'             => 'GET',
        'callback'            => 'fingerprint_rest_prometheus_metrics',
        'permission_callback' => function () {
            return current_user_can('manage_options') || apply_filters('fingerprint_metrics_access', false);
        },
    ]);

    register_rest_route('fingerprint/v1', '/sandbox/clear-challenges', [
        'methods'             => 'POST',
        'callback'            => 'fingerprint_rest_sandbox_clear_challenges',
        'permission_callback' => function () {
            return current_user_can('manage_options');
        },
    ]);
});

function fingerprint_rest_sandbox_telemetry(\WP_REST_Request $request): \WP_REST_Response {
    $store = new WpDbStore();
    $history = $store->get('fingerprint_challenges_log');
    if (!is_array($history)) {
        $history = [];
    }
    $latest = !empty($history) ? $history[0] : null;

    return new \WP_REST_Response([
        'latest'  => $latest ?: null,
        'history' => $history,
        'total'   => count($history),
    ], 200);
}

function fingerprint_rest_sandbox_clear_challenges(): \WP_REST_Response {
    $store = new WpDbStore();
    $store->delete('fingerprint_challenges_log');
    $store->delete('fingerprint_latest_challenge');
    return new \WP_REST_Response(['cleared' => true], 200);
}

function fingerprint_rest_prometheus_metrics(\WP_REST_Request $request): \WP_REST_Response {
    $effectiveProfiles = fingerprint_get_effective_profiles($GLOBALS['fingerprint_security_profiles'] ?? []);
    $securityConfig = SecurityProfiles::createSecurityProfile($effectiveProfiles['frontend']['profile'] ?? 'blog', $effectiveProfiles['frontend']['overrides'] ?? []);
    $metricsOutput = MetricsManager::getPrometheusMetrics($securityConfig);

    $response = new \WP_REST_Response($metricsOutput, 200);
    $response->header('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
    return $response;
}

function fingerprint_rest_sandbox_sse(): void {
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('Unauthorized access.', 'anonympins-bot-mitigation-pow'), '', ['response' => 403]);
    }

    if (function_exists('apache_setenv')) {
        apache_setenv('no-gzip', '1');
    }
    // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.ob_end_clean_ob_end_clean
    if (ob_get_level() > 0) {
        ob_end_clean();
    }

    header('Content-Type: text/event-stream; charset=utf-8');
    header('Cache-Control: no-cache, no-transform');
    header('Connection: keep-alive');
    header('X-Accel-Buffering: no');

    $store = new WpDbStore();
    $lastSeenId = '';

    // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
    if (!empty($_SERVER['HTTP_LAST_EVENT_ID'])) {
        $lastSeenId = sanitize_text_field(wp_unslash($_SERVER['HTTP_LAST_EVENT_ID']));
    }

    $endTime = time() + 25;
    while (time() < $endTime) {
        $history = $store->get('fingerprint_challenges_log');
        if (is_array($history) && !empty($history)) {
            $newEvents = [];
            foreach ($history as $ev) {
                if (!empty($ev['id']) && (string)$ev['id'] === $lastSeenId) {
                    break;
                }
                $newEvents[] = $ev;
            }
            if (!empty($newEvents)) {
                $newEvents = array_reverse($newEvents);
                foreach ($newEvents as $ev) {
                    $lastSeenId = (string)$ev['id'];
                    echo "id: " . esc_attr($lastSeenId) . "\n";
                    echo "event: challenge\n";
                    echo 'data: ' . wp_json_encode($ev) . "\n\n";
                }
                if (flush() && ob_get_level() > 0) {
                    ob_flush();
                }
            }
        } else {
            echo ": ping\n\n";
            if (flush() && ob_get_level() > 0) {
                ob_flush();
            }
        }
        usleep(400000); // 400ms
    }
    exit;
}

// =============================================================================
// ADMINISTRATION INTERFACE, SETTINGS & METRICS INSPECTION
// =============================================================================
add_action('admin_menu', function () {
    add_options_page(
        __('Anonympins bot mitigation', 'anonympins-bot-mitigation-pow'),
        __('Anonympins bot mitigation', 'anonympins-bot-mitigation-pow'),
        'manage_options',
        'anonympins-bot-mitigation',
        'fingerprint_render_admin_page'
    );
});

/**
 * Registers the admin page JS script via admin_enqueue_scripts (required by WP).
 */
add_action('admin_enqueue_scripts', function (string $hook) {
    if (strpos($hook, 'anonympins-bot-mitigation') === false) {
        return;
    }

    // Enqueue native WordPress CodeMirror editor for HTML template editing
    $editorSettings = wp_enqueue_code_editor(['type' => 'text/html']);

    wp_register_script('anonympins-admin-settings', false, [], ANONYMPINS_BOT_MITIGATION_VERSION, true);
    wp_enqueue_script('anonympins-admin-settings');

    $adminScript = '
    function fingerprintSwitchTab(evt, tabId) {
        evt.preventDefault();
        document.querySelectorAll(".fingerprint-tab-content").forEach(function(t) { t.style.display = "none"; });
        document.querySelectorAll(".nav-tab-wrapper a").forEach(function(n) { n.classList.remove("nav-tab-active"); });
        var target = document.getElementById(tabId);
        if (target) { target.style.display = "block"; }
        evt.currentTarget.classList.add("nav-tab-active");

        if (tabId === "tab-template" && window.fingerprintCodeMirrorInstance) {
            window.fingerprintCodeMirrorInstance.codemirror.refresh();
        }
        if (window.location.hash !== "#" + tabId && history.pushState) {
            history.pushState(null, null, "#" + tabId);
        }
    }

    document.addEventListener("DOMContentLoaded", function() {
        const hash = window.location.hash;
        if (hash) {
            const targetId = hash.replace("#", "");
            const targetContent = document.getElementById(targetId);
            const targetLink = document.querySelector(".nav-tab-wrapper a[href=\'" + hash + "\']");
            if (targetContent && targetLink) {
                document.querySelectorAll(".fingerprint-tab-content").forEach(function(t) { t.style.display = "none"; });
                document.querySelectorAll(".nav-tab-wrapper a").forEach(function(n) { n.classList.remove("nav-tab-active"); });
                targetContent.style.display = "block";
                targetLink.classList.add("nav-tab-active");
                if (targetId === "tab-template" && window.fingerprintCodeMirrorInstance) {
                    setTimeout(function() { window.fingerprintCodeMirrorInstance.codemirror.refresh(); }, 50);
                }
            }
        }

        if (window.wp && wp.codeEditor && document.getElementById("challenge_template")) {
            var editorConfig = ' . wp_json_encode($editorSettings) . ';
            if (editorConfig) {
                window.fingerprintCodeMirrorInstance = wp.codeEditor.initialize(document.getElementById("challenge_template"), editorConfig);
            }
        }
    });

    let sseSource = null;
    let challengesHistory = [];
    let selectedChallengeId = null;
    const wpRestNonce = ' . wp_json_encode(wp_create_nonce('wp_rest')) . ';

    function fingerprintToggleSSE() {
        const statusEl = document.getElementById("sse-connection-status");
        const btnText = document.getElementById("sse-btn-text");
        if (sseSource) {
            sseSource.close();
            sseSource = null;
            statusEl.textContent = ' . wp_json_encode(__('SSE disconnected', 'anonympins-bot-mitigation-pow')) . ';
            statusEl.style.color = "#646970";
            btnText.textContent = ' . wp_json_encode(__('Start real-time SSE stream', 'anonympins-bot-mitigation-pow')) . ';
            return;
        }

        statusEl.textContent = ' . wp_json_encode(__('Connecting to SSE stream...', 'anonympins-bot-mitigation-pow')) . ';
        statusEl.style.color = "#2271b1";
        sseSource = new EventSource(' . wp_json_encode(rest_url('fingerprint/v1/sandbox/sse')) . ' + "?_wpnonce=" + wpRestNonce);

        sseSource.onopen = function() {
            statusEl.textContent = ' . wp_json_encode(__('SSE live connected', 'anonympins-bot-mitigation-pow')) . ';
            statusEl.style.color = "#007017";
            btnText.textContent = ' . wp_json_encode(__('Stop stream', 'anonympins-bot-mitigation-pow')) . ';
        };

        sseSource.addEventListener("challenge", function(e) {
            try {
                const newChallenge = JSON.parse(e.data);
                if (!challengesHistory.some(function(c) { return c.id === newChallenge.id; })) {
                    challengesHistory.unshift(newChallenge);
                    if (challengesHistory.length > 50) { challengesHistory.pop(); }
                    selectedChallengeId = newChallenge.id;
                    renderChallengesUI();
                }
            } catch(err) {}
        });

        sseSource.onerror = function() {
            statusEl.textContent = ' . wp_json_encode(__('SSE reconnecting...', 'anonympins-bot-mitigation-pow')) . ';
            statusEl.style.color = "#d63638";
        };
    }

    function fingerprintFetchTelemetry() {
        fetch(' . wp_json_encode(rest_url('fingerprint/v1/sandbox/telemetry')) . ', {
            headers: { "X-WP-Nonce": wpRestNonce }
        })
            .then(function(res) { return res.json(); })
            .then(function(data) {
                if (data && Array.isArray(data.history)) {
                    challengesHistory = data.history;
                    renderChallengesUI();
                }
            })
            .catch(function(err) { console.error(err); });
    }

    function fingerprintClearFeed() {
        if (!confirm(' . wp_json_encode(__('Clear the live challenged visitors feed?', 'anonympins-bot-mitigation-pow')) . ')) {
            return;
        }
        fetch(' . wp_json_encode(rest_url('fingerprint/v1/sandbox/clear-challenges')) . ', {
            method: "POST",
            headers: { "X-WP-Nonce": wpRestNonce }
        })
            .then(function() {
                challengesHistory = [];
                selectedChallengeId = null;
                renderChallengesUI();
            })
            .catch(function(err) { console.error(err); });
    }

    function renderChallengesUI() {
        const tableBody = document.getElementById("live-challenges-tbody");
        const countEl = document.getElementById("live-challenges-count");
        countEl.textContent = challengesHistory.length;

        if (!challengesHistory.length) {
            tableBody.innerHTML = "<tr><td colspan=\"6\" style=\"text-align:center;color:#646970;padding:16px;\"><em>" + ' . wp_json_encode(__('No challenged visitors recorded yet.', 'anonympins-bot-mitigation-pow')) . ' + "</em></td></tr>";
            renderDetailView(null);
            return;
        }

        let rowsHtml = "";
        challengesHistory.forEach(function(item, index) {
            const isSelected = item.id === selectedChallengeId || (!selectedChallengeId && index === 0);
            if (isSelected && !selectedChallengeId) { selectedChallengeId = item.id; }

            const date = item.timestamp ? new Date(item.timestamp * 1000).toLocaleTimeString() : "--:--:--";
            const score = item.suspicionScore !== undefined ? Math.round(item.suspicionScore) : 0;
            const scoreColor = score >= 75 ? "#d63638" : (score >= 40 ? "#dba617" : "#2271b1");
            const actionBadge = (item.action || "challenge").toUpperCase();
            const actionBg = actionBadge.indexOf("BLOCK") !== -1 ? "#d63638" : (actionBadge.indexOf("AUDIT") !== -1 ? "#72aee6" : "#dba617");

            rowsHtml += "<tr style=\"cursor:pointer;background:" + (isSelected ? "#f0f6fc" : "transparent") + ";\" onclick=\"fingerprintSelectChallenge(\'" + item.id + "\')\">" +
                "<td><b>" + date + "</b></td>" +
                "<td><code>" + escapeHtml(item.ip || "unknown") + "</code></td>" +
                "<td style=\"max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;\" title=\"" + escapeHtml(item.uri || "/") + "\"><code>" + escapeHtml(item.uri || "/") + "</code></td>" +
                "<td><span style=\"font-weight:bold;color:" + scoreColor + ";\">" + score + "</span></td>" +
                "<td><span style=\"display:inline-block;padding:2px 6px;border-radius:3px;font-size:11px;font-weight:bold;color:#fff;background:" + actionBg + ";\">" + escapeHtml(actionBadge) + "</span></td>" +
                "<td><button type=\"button\" class=\"button button-small button-secondary\">" + (isSelected ? "&#9654; View" : "Inspect") + "</button></td>" +
            "</tr>";
        });

        tableBody.innerHTML = rowsHtml;
        const selectedItem = challengesHistory.find(function(c) { return c.id === selectedChallengeId; }) || challengesHistory[0];
        renderDetailView(selectedItem);
    }

    function renderDetailView(item) {
        const detailScore = document.getElementById("live-score-val");
        const detailSub = document.getElementById("live-score-sub");
        const breakdownEl = document.getElementById("live-vector-breakdown");

        if (!item) {
            detailScore.textContent = "--";
            detailScore.style.color = "#2271b1";
            detailSub.textContent = ' . wp_json_encode(__('Select an entry from the list to inspect its vector.', 'anonympins-bot-mitigation-pow')) . ';
            breakdownEl.innerHTML = "<em>" + ' . wp_json_encode(__('No entry selected.', 'anonympins-bot-mitigation-pow')) . ' + "</em>";
            return;
        }

        const score = item.suspicionScore !== undefined ? Math.round(item.suspicionScore) : 0;
        detailScore.textContent = score;
        detailScore.style.color = score >= 75 ? "#d63638" : (score >= 40 ? "#dba617" : "#2271b1");
        detailSub.innerHTML = "<b>IP:</b> " + escapeHtml(item.ip || "unknown") + "<br><b>Target:</b> " + escapeHtml(item.uri || "/") + "<br><b>Action:</b> " + escapeHtml(item.action || "challenge");

        const vector = item.suspicionVector || {};
        const keys = Object.keys(vector);
        if (keys.length === 0) {
            breakdownEl.innerHTML = "<em>" + ' . wp_json_encode(__('No indicators recorded for this entry.', 'anonympins-bot-mitigation-pow')) . ' + "</em>";
            return;
        }
        let html = "<table style=\"width:100%;border-collapse:collapse;font-size:12px;\">";
        keys.forEach(function(k) {
            html += "<tr style=\"border-bottom:1px solid #f0f0f1;\"><td style=\"padding:3px 6px;\"><b>" + escapeHtml(k) + "</b></td><td style=\"padding:3px 6px;text-align:right;\"><code>" + escapeHtml(JSON.stringify(vector[k])) + "</code></td></tr>";
        });
        html += "</table>";
        breakdownEl.innerHTML = html;
    }

    function fingerprintSelectChallenge(id) {
        selectedChallengeId = id;
        renderChallengesUI();
    }

    function escapeHtml(str) {
        return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
    }

    document.addEventListener("DOMContentLoaded", function() {
        fingerprintFetchTelemetry();
    });';

    wp_add_inline_script('anonympins-admin-settings', $adminScript);
});

function fingerprint_render_admin_page(): void {
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('You do not have sufficient permissions to access this page.', 'anonympins-bot-mitigation-pow'));
    }

    global $fingerprint_security_profiles, $wpdb;

    if (isset($_POST['fingerprint_save_settings']) && check_admin_referer('fingerprint_settings_nonce', 'fingerprint_nonce')) {
        $saved = get_option('anonympins_security_options', get_option('fingerprint_security_options', []));
        if (!is_array($saved)) {
            $saved = [];
        }

        $saved['frontend']['profile'] = isset($_POST['frontend_profile']) ? sanitize_text_field(wp_unslash($_POST['frontend_profile'])) : 'blog';
        $saved['admin']['profile']    = isset($_POST['admin_profile']) ? sanitize_text_field(wp_unslash($_POST['admin_profile'])) : 'strict';
        $saved['api']['profile']      = isset($_POST['api_profile']) ? sanitize_text_field(wp_unslash($_POST['api_profile'])) : 'api';

        $saved['frontend']['overrides']['thresholds'] = [
            'low'    => max(1, isset($_POST['frontend_threshold_low']) ? (int)sanitize_text_field(wp_unslash($_POST['frontend_threshold_low'])) : 20),
            'medium' => max(5, isset($_POST['frontend_threshold_medium']) ? (int)sanitize_text_field(wp_unslash($_POST['frontend_threshold_medium'])) : 45),
            'high'   => max(10, isset($_POST['frontend_threshold_high']) ? (int)sanitize_text_field(wp_unslash($_POST['frontend_threshold_high'])) : 75),
            'block'  => max(20, isset($_POST['frontend_threshold_block']) ? (int)sanitize_text_field(wp_unslash($_POST['frontend_threshold_block'])) : 95),
        ];

        $saved['frontend']['overrides']['challengeNewDevices'] = !empty($_POST['frontend_challenge_new']);
        $saved['frontend']['overrides']['verbose']             = !empty($_POST['frontend_verbose']);
        $saved['frontend']['overrides']['honeypot']['detectInjections'] = !empty($_POST['detect_injections']);

        foreach ($_POST as $postKey => $postVal) {
            if (str_starts_with((string)$postKey, 'weight_')) {
                $wKey = sanitize_key(substr((string)$postKey, 7));
                $val = (float)sanitize_text_field(wp_unslash($postVal));
                $saved['frontend']['overrides']['weights'][$wKey] = max(0.0, min(2.0, $val));
            }
        }

        update_option('anonympins_security_options', $saved);
        echo '<div class="notice notice-success is-dismissible"><p><strong>' . esc_html__('Settings updated successfully.', 'anonympins-bot-mitigation-pow') . '</strong></p></div>';
    }

    if (isset($_POST['fingerprint_save_sandbox']) && check_admin_referer('fingerprint_sandbox_nonce', 'fingerprint_nonce_sandbox')) {
        $saved = get_option('anonympins_security_options', get_option('fingerprint_security_options', []));
        if (!is_array($saved)) {
            $saved = [];
        }

        $saved['sandbox'] = [
            'enabled'      => !empty($_POST['sandbox_enabled']),
            'audit_only'   => !empty($_POST['sandbox_audit_only']),
            'log_requests' => !empty($_POST['sandbox_log_requests']),
            'add_headers'  => !empty($_POST['sandbox_add_headers']),
            'ip_filter'    => isset($_POST['sandbox_ip_filter']) ? sanitize_text_field(wp_unslash($_POST['sandbox_ip_filter'])) : '',
        ];

        update_option('anonympins_security_options', $saved);
        echo '<div class="notice notice-success is-dismissible"><p><strong>' . esc_html__('Sandbox settings updated successfully.', 'anonympins-bot-mitigation-pow') . '</strong></p></div>';
    }

    if (isset($_POST['fingerprint_save_prometheus']) && check_admin_referer('fingerprint_prometheus_nonce', 'fingerprint_nonce_prometheus')) {
        $saved = get_option('anonympins_security_options', get_option('fingerprint_security_options', []));
        if (!is_array($saved)) {
            $saved = [];
        }

        $rawEndpoint = isset($_POST['metrics_endpoint']) ? sanitize_text_field(wp_unslash($_POST['metrics_endpoint'])) : '/metrics';
        $rawEndpoint = trim($rawEndpoint);
        if ($rawEndpoint !== '' && !str_starts_with($rawEndpoint, '/')) {
            $rawEndpoint = '/' . $rawEndpoint;
        }
        $saved['metrics_endpoint'] = $rawEndpoint;
        update_option('anonympins_security_options', $saved);
        echo '<div class="notice notice-success is-dismissible"><p><strong>' . esc_html__('Prometheus settings updated successfully.', 'anonympins-bot-mitigation-pow') . '</strong></p></div>';
    }

    if ((isset($_POST['fingerprint_save_template']) || isset($_POST['fingerprint_reset_template'])) && check_admin_referer('fingerprint_template_nonce', 'fingerprint_nonce_template')) {
        $saved = get_option('anonympins_security_options', get_option('fingerprint_security_options', []));
        if (!is_array($saved)) {
            $saved = [];
        }
        if (isset($_POST['fingerprint_reset_template'])) {
            unset($saved['challenge_template']);
            echo '<div class="notice notice-info is-dismissible"><p><strong>' . esc_html__('Template reset to default successfully.', 'anonympins-bot-mitigation-pow') . '</strong></p></div>';
        } else {
            // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Administrator code template editor with script/style placeholders.
            $rawTemplate = isset($_POST['challenge_template']) ? wp_unslash($_POST['challenge_template']) : '';
            if (!current_user_can('unfiltered_html')) {
                $saved['challenge_template'] = wp_kses_post($rawTemplate);
            } else {
                $saved['challenge_template'] = (string)$rawTemplate;
            }
            echo '<div class="notice notice-success is-dismissible"><p><strong>' . esc_html__('Challenge template updated successfully.', 'anonympins-bot-mitigation-pow') . '</strong></p></div>';
        }
        update_option('anonympins_security_options', $saved);
    }

    if (isset($_POST['fingerprint_clear_store']) && check_admin_referer('fingerprint_clear_nonce', 'fingerprint_nonce_clear')) {
        $store = new WpDbStore();
        $store->clear();
        echo '<div class="notice notice-info is-dismissible"><p>' . esc_html__('SQL cache table ($wpdb) cleared successfully.', 'anonympins-bot-mitigation-pow') . '</p></div>';
    }

    $sandboxConfig = fingerprint_get_sandbox_config();
    $effective = fingerprint_get_effective_profiles($fingerprint_security_profiles);
    $frontendConfig = SecurityProfiles::createSecurityProfile($effective['frontend']['profile'], $effective['frontend']['overrides'] ?? []);
    $savedOptions = get_option('anonympins_security_options', get_option('fingerprint_security_options', []));
    $currentTemplate = (is_array($savedOptions) && !empty($savedOptions['challenge_template']))
        ? (string)$savedOptions['challenge_template']
        : fingerprint_get_default_challenge_template();

    $store = new WpDbStore();
    $totalRows = $store->getTotalCount();
    $expiredRows = $store->getExpiredCount();
    $tableName = esc_sql($wpdb->prefix . 'fingerprint_store');
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
    $now = time();
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter

    $prometheusRaw = MetricsManager::getPrometheusMetrics($frontendConfig);
    ?>
    <div class="wrap">
        <h1><span class="dashicons dashicons-shield-alt" style="font-size:32px;vertical-align:middle;margin-right:8px;"></span> Anonympins bot mitigation with proof-of-work</h1>
        <p class="description"><?php esc_html_e('Client-side behavioral and cryptographic anti-bot protection without third-party CAPTCHA for WordPress.', 'anonympins-bot-mitigation-pow'); ?></p>

        <div style="background:#fff;border-left:4px solid #2271b1;padding:12px 18px;margin:18px 0;box-shadow:0 1px 1px rgba(0,0,0,.04);">
            <p style="margin:4px 0;">
                <strong><?php esc_html_e('Official documentation reference:', 'anonympins-bot-mitigation-pow'); ?></strong>
                <a href="https://github.com/anonympins/fingerprint/blob/main/doc/full_options.md" target="_blank" rel="noopener noreferrer" class="button button-secondary" style="margin-left:8px;">
                    <span class="dashicons dashicons-external" style="vertical-align:middle;"></span> <?php esc_html_e('View full configuration options on GitHub', 'anonympins-bot-mitigation-pow'); ?>
                </a>
                <a href="https://github.com/anonympins/fingerprint" target="_blank" rel="noopener noreferrer" class="button button-secondary" style="margin-left:4px;">
                    <span class="dashicons dashicons-admin-plugins" style="vertical-align:middle;"></span> <?php esc_html_e('GitHub repository', 'anonympins-bot-mitigation-pow'); ?>
                </a>
            </p>
        </div>

        <!-- STATISTICS & STATUS DASHBOARD -->
        <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(240px, 1fr));gap:16px;margin-bottom:24px;">
            <div style="background:#fff;padding:16px;border-radius:4px;border:1px solid #ccd0d4;">
                <h3 style="margin-top:0;"><?php esc_html_e('HTTPS status', 'anonympins-bot-mitigation-pow'); ?></h3>
                <?php if (is_ssl()): ?>
                    <p style="color:#007017;font-weight:bold;font-size:16px;">
                        <span class="dashicons dashicons-yes-alt"></span> <?php esc_html_e('Active (WebCrypto Subtle available)', 'anonympins-bot-mitigation-pow'); ?>
                    </p>
                <?php else: ?>
                    <p style="color:#d63638;font-weight:bold;font-size:16px;">
                        <span class="dashicons dashicons-warning"></span> <?php esc_html_e('Insecure (Unencrypted HTTP)', 'anonympins-bot-mitigation-pow'); ?>
                    </p>
                <?php endif; ?>
            </div>
            <div style="background:#fff;padding:16px;border-radius:4px;border:1px solid #ccd0d4;">
                <h3 style="margin-top:0;"><?php esc_html_e('SQL cache ($wpdb)', 'anonympins-bot-mitigation-pow'); ?></h3>
                <p style="font-size:22px;margin:0;font-weight:600;"><?php echo esc_html((string)$totalRows); ?> <span style="font-size:14px;color:#646970;font-weight:normal;"><?php esc_html_e('keys in database', 'anonympins-bot-mitigation-pow'); ?></span></p>
                <small style="color:#8c8f94;"><?php
                    /* translators: %d: number of expired keys awaiting cron purge */
                    echo esc_html(sprintf(__(' %d expired keys awaiting cron purge', 'anonympins-bot-mitigation-pow'), $expiredRows));
                ?></small>
            </div>
            <div style="background:#fff;padding:16px;border-radius:4px;border:1px solid #ccd0d4;">
                <h3 style="margin-top:0;"><?php esc_html_e('Active profiles', 'anonympins-bot-mitigation-pow'); ?></h3>
                <p style="margin:0;">
                    <?php esc_html_e('Frontend:', 'anonympins-bot-mitigation-pow'); ?> <strong><?php echo esc_html($effective['frontend']['profile']); ?></strong><br>
                    <?php esc_html_e('Admin:', 'anonympins-bot-mitigation-pow'); ?> <strong><?php echo esc_html($effective['admin']['profile']); ?></strong><br>
                    <?php esc_html_e('REST API:', 'anonympins-bot-mitigation-pow'); ?> <strong><?php echo esc_html($effective['api']['profile']); ?></strong>
                </p>
            </div>
            <div style="background:#fff;padding:16px;border-radius:4px;border:1px solid #ccd0d4;">
                <h3 style="margin-top:0;"><?php esc_html_e('Sandbox mode', 'anonympins-bot-mitigation-pow'); ?></h3>
                <?php if ($sandboxConfig['enabled']): ?>
                    <p style="color:#dba617;font-weight:bold;font-size:16px;margin:0;">
                        <span class="dashicons dashicons-warning"></span> <?php esc_html_e('Active (Simulation)', 'anonympins-bot-mitigation-pow'); ?>
                    </p>
                    <small style="color:#646970;"><?php echo !empty($sandboxConfig['audit_only']) ? esc_html__('Audit-Only: non-blocking observation.', 'anonympins-bot-mitigation-pow') : esc_html__('Testing: challenges & mitigations active.', 'anonympins-bot-mitigation-pow'); ?></small>
                <?php else: ?>
                    <p style="color:#007017;font-weight:bold;font-size:16px;margin:0;">
                        <span class="dashicons dashicons-yes-alt"></span> <?php esc_html_e('Production (Enforced)', 'anonympins-bot-mitigation-pow'); ?>
                    </p>
                    <small style="color:#646970;"><?php esc_html_e('Bot protection active across all visitors.', 'anonympins-bot-mitigation-pow'); ?></small>
                <?php endif; ?>
            </div>
        </div>

        <!-- NAVIGATION TABS -->
        <h2 class="nav-tab-wrapper">
            <a href="#tab-settings" class="nav-tab nav-tab-active" onclick="fingerprintSwitchTab(event, 'tab-settings')"><?php esc_html_e('Settings & profiles', 'anonympins-bot-mitigation-pow'); ?></a>
            <a href="#tab-template" class="nav-tab" onclick="fingerprintSwitchTab(event, 'tab-template')"><?php esc_html_e('Challenge HTML template', 'anonympins-bot-mitigation-pow'); ?></a>
            <a href="#tab-sandbox" class="nav-tab" onclick="fingerprintSwitchTab(event, 'tab-sandbox')"><?php esc_html_e('Sandbox / test mode', 'anonympins-bot-mitigation-pow'); ?></a>
            <a href="#tab-metrics" class="nav-tab" onclick="fingerprintSwitchTab(event, 'tab-metrics')"><?php esc_html_e('Metrics & weights view', 'anonympins-bot-mitigation-pow'); ?></a>
            <a href="#tab-prometheus" class="nav-tab" onclick="fingerprintSwitchTab(event, 'tab-prometheus')"><?php esc_html_e('Prometheus stream', 'anonympins-bot-mitigation-pow'); ?></a>
        </h2>

        <div id="tab-settings" class="fingerprint-tab-content" style="background:#fff;padding:20px;border:1px solid #ccd0d4;border-top:none;">
            <form method="post" action="">
                <?php wp_nonce_field('fingerprint_settings_nonce', 'fingerprint_nonce'); ?>
                <h3><?php esc_html_e('1. Target security profiles', 'anonympins-bot-mitigation-pow'); ?></h3>
                <table class="form-table">
                    <tr>
                        <th scope="row"><label for="frontend_profile"><?php esc_html_e('Visitors & frontend', 'anonympins-bot-mitigation-pow'); ?></label></th>
                        <td>
                            <select name="frontend_profile" id="frontend_profile">
                                <option value="blog" <?php selected($effective['frontend']['profile'], 'blog'); ?>><?php esc_html_e('Blog (Optimal for content, smooth UX)', 'anonympins-bot-mitigation-pow'); ?></option>
                                <option value="balanced" <?php selected($effective['frontend']['profile'], 'balanced'); ?>><?php esc_html_e('Balanced (General purpose)', 'anonympins-bot-mitigation-pow'); ?></option>
                                <option value="strict" <?php selected($effective['frontend']['profile'], 'strict'); ?>><?php esc_html_e('Strict (Maximum protection)', 'anonympins-bot-mitigation-pow'); ?></option>
                                <option value="ecommerce" <?php selected($effective['frontend']['profile'], 'ecommerce'); ?>><?php esc_html_e('E-commerce (anti-scraping / scalping)', 'anonympins-bot-mitigation-pow'); ?></option>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="admin_profile"><?php esc_html_e('Administration area (wp-login / wp-admin)', 'anonympins-bot-mitigation-pow'); ?></label></th>
                        <td>
                            <select name="admin_profile" id="admin_profile">
                                <option value="strict" <?php selected($effective['admin']['profile'], 'strict'); ?>><?php esc_html_e('Strict (Recommended to secure logins)', 'anonympins-bot-mitigation-pow'); ?></option>
                                <option value="balanced" <?php selected($effective['admin']['profile'], 'balanced'); ?>><?php esc_html_e('Balanced', 'anonympins-bot-mitigation-pow'); ?></option>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="api_profile"><?php esc_html_e('REST API (/wp-json/)', 'anonympins-bot-mitigation-pow'); ?></label></th>
                        <td>
                            <select name="api_profile" id="api_profile">
                                <option value="api" <?php selected($effective['api']['profile'], 'api'); ?>><?php esc_html_e('API (JSON challenges & machine PoW)', 'anonympins-bot-mitigation-pow'); ?></option>
                                <option value="strict" <?php selected($effective['api']['profile'], 'strict'); ?>><?php esc_html_e('Strict', 'anonympins-bot-mitigation-pow'); ?></option>
                            </select>
                        </td>
                    </tr>
                </table>
                <hr>
                <h3><?php esc_html_e('2. Action thresholds (frontend)', 'anonympins-bot-mitigation-pow'); ?></h3>
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e('Suspicion score thresholds (0 - 100)', 'anonympins-bot-mitigation-pow'); ?></th>
                        <td>
                            <label><?php esc_html_e('Low (initial challenge):', 'anonympins-bot-mitigation-pow'); ?>
                                <input type="number" name="frontend_threshold_low" value="<?php echo esc_attr((string)($frontendConfig['thresholds']['low'] ?? 20)); ?>" min="1" max="50" style="width:80px;">
                            </label><br><br>
                            <label><?php esc_html_e('Medium (hardened challenge):', 'anonympins-bot-mitigation-pow'); ?>
                                <input type="number" name="frontend_threshold_medium" value="<?php echo esc_attr((string)($frontendConfig['thresholds']['medium'] ?? 45)); ?>" min="10" max="75" style="width:80px;">
                            </label><br><br>
                            <label><?php esc_html_e('High (heavy proof-of-work):', 'anonympins-bot-mitigation-pow'); ?>
                                <input type="number" name="frontend_threshold_high" value="<?php echo esc_attr((string)($frontendConfig['thresholds']['high'] ?? 75)); ?>" min="30" max="95" style="width:80px;">
                            </label><br><br>
                            <label><?php esc_html_e('Block (immediate 403 forbidden):', 'anonympins-bot-mitigation-pow'); ?>
                                <input type="number" name="frontend_threshold_block" value="<?php echo esc_attr((string)($frontendConfig['thresholds']['block'] ?? 95)); ?>" min="50" max="100" style="width:80px;">
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Advanced behaviors', 'anonympins-bot-mitigation-pow'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="frontend_challenge_new" value="1" <?php checked(!empty($frontendConfig['challengeNewDevices'])); ?>>
                                <?php esc_html_e('Automatically challenge unknown new devices (without device_id cookie)', 'anonympins-bot-mitigation-pow'); ?>
                            </label><br>
                            <label>
                                <input type="checkbox" name="detect_injections" value="1" <?php checked(!empty($frontendConfig['honeypot']['detectInjections'])); ?>>
                                <?php esc_html_e('Enable recursive WAF inspection (SQL, NoSQL, Log4j, Traversal in GET/POST)', 'anonympins-bot-mitigation-pow'); ?>
                            </label><br>
                            <label>
                                <input type="checkbox" name="frontend_verbose" value="1" <?php checked(!empty($frontendConfig['verbose'])); ?>>
                                <?php esc_html_e('Verbose mode in PHP logs (Debugging)', 'anonympins-bot-mitigation-pow'); ?>
                            </label>
                        </td>
                    </tr>
                </table>
                <?php submit_button(esc_html__('Save changes', 'anonympins-bot-mitigation-pow'), 'primary', 'fingerprint_save_settings'); ?>
            </form>
            <hr>
            <form method="post" action="" style="margin-top:16px;">
                <?php wp_nonce_field('fingerprint_clear_nonce', 'fingerprint_nonce_clear'); ?>
                <p>
                    <strong><?php esc_html_e('Store maintenance:', 'anonympins-bot-mitigation-pow'); ?></strong>
                    <button type="submit" name="fingerprint_clear_store" class="button button-secondary" onclick="return confirm('<?php echo esc_js(__('Purge all stored sessions and nonces?', 'anonympins-bot-mitigation-pow')); ?>');">
                        <?php esc_html_e('Clear SQL cache table ($wpdb)', 'anonympins-bot-mitigation-pow'); ?>
                    </button>
                </p>
            </form>
        </div>

        <div id="tab-template" class="fingerprint-tab-content" style="display:none;background:#fff;padding:20px;border:1px solid #ccd0d4;border-top:none;">
            <h3><?php esc_html_e('Challenge HTML template editor', 'anonympins-bot-mitigation-pow'); ?></h3>
            <p class="description">
                <?php esc_html_e('Customize the HTML markup presented to challenged visitors. Leave empty or reset to use the built-in responsive default template.', 'anonympins-bot-mitigation-pow'); ?>
            </p>

            <div style="background:#f0f6fc;border-left:4px solid #2271b1;padding:12px 16px;margin:16px 0;">
                <h4 style="margin:0 0 8px 0;"><?php esc_html_e('Available template placeholders', 'anonympins-bot-mitigation-pow'); ?></h4>
                <table class="widefat striped" style="background:#fff;font-size:12px;">
                    <thead>
                        <tr>
                            <th style="width:200px;"><?php esc_html_e('Placeholder', 'anonympins-bot-mitigation-pow'); ?></th>
                            <th><?php esc_html_e('Description & content injected', 'anonympins-bot-mitigation-pow'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><code>{{TITLE}}</code></td>
                            <td><?php esc_html_e('Challenge page title (e.g., "Security verification")', 'anonympins-bot-mitigation-pow'); ?></td>
                        </tr>
                        <tr>
                            <td><code>{{MESSAGE}}</code></td>
                            <td><?php esc_html_e('Human-readable instruction or explanation message', 'anonympins-bot-mitigation-pow'); ?></td>
                        </tr>
                        <tr>
                            <td><code>{{NONCE}}</code></td>
                            <td><?php esc_html_e('Unique cryptographic challenge nonce generated by the server', 'anonympins-bot-mitigation-pow'); ?></td>
                        </tr>
                        <tr>
                            <td><code>{{DIFFICULTY}}</code></td>
                            <td><?php esc_html_e('Target computational difficulty complexity number', 'anonympins-bot-mitigation-pow'); ?></td>
                        </tr>
                        <tr>
                            <td><code>{{ALGORITHM}}</code></td>
                            <td><?php esc_html_e('Selected hashing algorithm (e.g., "SHA-256")', 'anonympins-bot-mitigation-pow'); ?></td>
                        </tr>
                        <tr>
                            <td><code>{{FORM_ACTION}}</code></td>
                            <td><?php esc_html_e('Target POST URI destination where the PoW result must be submitted', 'anonympins-bot-mitigation-pow'); ?></td>
                        </tr>
                        <tr>
                            <td><code>{{SOLVER_SCRIPT}}</code></td>
                            <td><?php esc_html_e('Mandatory: inlined WebAssembly/WebWorker solver script block required for verification', 'anonympins-bot-mitigation-pow'); ?></td>
                        </tr>
                        <tr>
                            <td><code>{{CUSTOM_CSS}}</code></td>
                            <td><?php esc_html_e('Optional: default reset styling and challenge animations', 'anonympins-bot-mitigation-pow'); ?></td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <form method="post" action="">
                <?php wp_nonce_field('fingerprint_template_nonce', 'fingerprint_nonce_template'); ?>
                <p>
                    <textarea name="challenge_template" id="challenge_template" rows="18" style="width:100%;font-family:monospace;"><?php echo esc_textarea($currentTemplate); ?></textarea>
                </p>
                <p style="display:flex;gap:10px;">
                    <?php submit_button(esc_html__('Save template', 'anonympins-bot-mitigation-pow'), 'primary', 'fingerprint_save_template', false); ?>
                    <?php submit_button(esc_html__('Reset to default template', 'anonympins-bot-mitigation-pow'), 'secondary', 'fingerprint_reset_template', false, ['onclick' => "return confirm('" . esc_js(__('Reset challenge template to default?', 'anonympins-bot-mitigation-pow')) . "');"]); ?>
                </p>
            </form>
        </div>

        <div id="tab-sandbox" class="fingerprint-tab-content" style="display:none;background:#fff;padding:20px;border:1px solid #ccd0d4;border-top:none;">
            <h3><?php esc_html_e('Sandbox mode & dry-run configuration', 'anonympins-bot-mitigation-pow'); ?></h3>
            <form method="post" action="">
                <?php wp_nonce_field('fingerprint_sandbox_nonce', 'fingerprint_nonce_sandbox'); ?>
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e('Sandbox activation', 'anonympins-bot-mitigation-pow'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="sandbox_enabled" value="1" <?php checked($sandboxConfig['enabled']); ?>>
                                <strong><?php esc_html_e('Enable sandbox mode', 'anonympins-bot-mitigation-pow'); ?></strong>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Behavior & enforcement', 'anonympins-bot-mitigation-pow'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="sandbox_audit_only" value="1" <?php checked($sandboxConfig['audit_only']); ?>>
                                <strong><?php esc_html_e('Audit only / dry-run (never block or challenge visitors)', 'anonympins-bot-mitigation-pow'); ?></strong>
                            </label><br><br>
                            <label>
                                <input type="checkbox" name="sandbox_add_headers" value="1" <?php checked($sandboxConfig['add_headers']); ?>>
                                <?php esc_html_e('Add diagnostic HTTP headers (X-Fingerprint-Sandbox: active)', 'anonympins-bot-mitigation-pow'); ?>
                            </label><br><br>
                            <label>
                                <input type="checkbox" name="sandbox_log_requests" value="1" <?php checked($sandboxConfig['log_requests']); ?>>
                                <?php esc_html_e('Log evaluated scores and suspicious attempts to PHP error_log', 'anonympins-bot-mitigation-pow'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="sandbox_ip_filter"><?php esc_html_e('Test IP whitelist filter', 'anonympins-bot-mitigation-pow'); ?></label></th>
                        <td>
                            <?php
                            // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
                            $currentAdminIp = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '';
                            ?>
                            <input type="text" name="sandbox_ip_filter" id="sandbox_ip_filter" value="<?php echo esc_attr($sandboxConfig['ip_filter']); ?>" class="regular-text" placeholder="e.g. 192.168.1.100, 203.0.113.42">
                            <?php if (!empty($currentAdminIp)): ?>
                                <button type="button" class="button button-secondary button-small" onclick="document.getElementById('sandbox_ip_filter').value = '<?php echo esc_js($currentAdminIp); ?>';">
                                    <?php esc_html_e('Use my IP', 'anonympins-bot-mitigation-pow'); ?> (<?php echo esc_html($currentAdminIp); ?>)
                                </button>
                            <?php endif; ?>
                        </td>
                    </tr>
                </table>
                <?php submit_button(esc_html__('Save sandbox settings', 'anonympins-bot-mitigation-pow'), 'primary', 'fingerprint_save_sandbox'); ?>
            </form>
            <hr>
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                <h3 style="margin:0;"><span class="dashicons dashicons-shield" style="vertical-align:text-bottom;"></span> <?php esc_html_e('Live challenged visitors & suspicion monitor', 'anonympins-bot-mitigation-pow'); ?></h3>
                <div>
                    <span style="font-weight:600;color:#646970;"><?php esc_html_e('Recent challenges:', 'anonympins-bot-mitigation-pow'); ?></span>
                    <span id="live-challenges-count" style="display:inline-block;padding:2px 8px;background:#2271b1;color:#fff;border-radius:10px;font-weight:bold;font-size:12px;">0</span>
                </div>
            </div>
            <div style="background:#f6f7f7;padding:16px;border:1px solid #c3c4c7;border-radius:4px;margin-bottom:15px;">
                <div style="display:flex;gap:12px;align-items:center;margin-bottom:12px;flex-wrap:wrap;">
                    <button type="button" class="button button-primary" id="btn-toggle-sse" onclick="fingerprintToggleSSE();">
                        <span class="dashicons dashicons-controls-play" style="vertical-align:middle;"></span> <span id="sse-btn-text"><?php esc_html_e('Start real-time SSE stream', 'anonympins-bot-mitigation-pow'); ?></span>
                    </button>
                    <button type="button" class="button button-secondary" onclick="fingerprintFetchTelemetry();">
                        <span class="dashicons dashicons-update" style="vertical-align:middle;"></span> <?php esc_html_e('Poll now (REST)', 'anonympins-bot-mitigation-pow'); ?>
                    </button>
                    <button type="button" class="button button-secondary" onclick="fingerprintClearFeed();">
                        <span class="dashicons dashicons-trash" style="vertical-align:middle;"></span> <?php esc_html_e('Clear feed', 'anonympins-bot-mitigation-pow'); ?>
                    </button>
                    <span id="sse-connection-status" style="font-weight:bold;color:#646970;"></span>
                </div>
                <div style="display:grid;grid-template-columns: 1.4fr 1fr;gap:16px;">
                    <div style="background:#fff;padding:12px;border:1px solid #dcdcde;border-radius:4px;overflow-x:auto;">
                        <h4 style="margin:0 0 8px 0;"><?php esc_html_e('Challenged visitors stream', 'anonympins-bot-mitigation-pow'); ?></h4>
                        <table class="wp-list-table widefat fixed striped" style="font-size:12px;">
                            <thead>
                                <tr>
                                    <th style="width:75px;"><?php esc_html_e('Time', 'anonympins-bot-mitigation-pow'); ?></th>
                                    <th style="width:110px;"><?php esc_html_e('IP', 'anonympins-bot-mitigation-pow'); ?></th>
                                    <th><?php esc_html_e('URI', 'anonympins-bot-mitigation-pow'); ?></th>
                                    <th style="width:50px;"><?php esc_html_e('Score', 'anonympins-bot-mitigation-pow'); ?></th>
                                    <th style="width:90px;"><?php esc_html_e('Action', 'anonympins-bot-mitigation-pow'); ?></th>
                                    <th style="width:70px;"></th>
                                </tr>
                            </thead>
                            <tbody id="live-challenges-tbody">
                                <tr><td colspan="6" style="text-align:center;color:#646970;padding:16px;"><em><?php esc_html_e('Awaiting incoming challenges...', 'anonympins-bot-mitigation-pow'); ?></em></td></tr>
                            </tbody>
                        </table>
                    </div>
                    <div style="background:#fff;padding:14px;border:1px solid #dcdcde;border-radius:4px;">
                        <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px;">
                            <h4 style="margin:0;"><?php esc_html_e('Inspection & suspicion vector', 'anonympins-bot-mitigation-pow'); ?></h4>
                            <div id="live-score-val" style="font-size:28px;font-weight:bold;color:#2271b1;line-height:1;">--</div>
                        </div>
                        <div id="live-score-sub" style="font-size:12px;color:#646970;background:#f6f7f7;padding:8px;border-radius:3px;margin-bottom:10px;">
                            <?php esc_html_e('Select an entry from the list to inspect its vector.', 'anonympins-bot-mitigation-pow'); ?>
                        </div>
                        <div id="live-vector-breakdown" style="font-family:monospace;font-size:12px;max-height:220px;overflow-y:auto;color:#2c3338;">
                            <em><?php esc_html_e('No entry selected.', 'anonympins-bot-mitigation-pow'); ?></em>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div id="tab-metrics" class="fingerprint-tab-content" style="display:none;background:#fff;padding:20px;border:1px solid #ccd0d4;border-top:none;">
            <h3><?php esc_html_e('Behavioral & transport indicator weights', 'anonympins-bot-mitigation-pow'); ?></h3>
            <form method="post" action="">
                <?php wp_nonce_field('fingerprint_settings_nonce', 'fingerprint_nonce'); ?>
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th style="width:280px;"><?php esc_html_e('Indicator / metric', 'anonympins-bot-mitigation-pow'); ?></th>
                            <th style="width:120px;"><?php esc_html_e('Current weight', 'anonympins-bot-mitigation-pow'); ?></th>
                            <th><?php esc_html_e('Description & detection role', 'anonympins-bot-mitigation-pow'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($frontendConfig['weights'] as $indicator => $weight): ?>
                        <tr>
                            <td><code><?php echo esc_html($indicator); ?></code></td>
                            <td><input type="number" step="0.05" min="0" max="2.0" name="weight_<?php echo esc_attr($indicator); ?>" value="<?php echo esc_attr((string)$weight); ?>" style="width:75px;"></td>
                            <td><?php esc_html_e('Behavioral suspicion indicator.', 'anonympins-bot-mitigation-pow'); ?></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
                <p style="margin-top:16px;">
                    <?php submit_button(esc_html__('Update metric weights', 'anonympins-bot-mitigation-pow'), 'primary', 'fingerprint_save_settings', false); ?>
                </p>
            </form>
        </div>

        <div id="tab-prometheus" class="fingerprint-tab-content" style="display:none;background:#fff;padding:20px;border:1px solid #ccd0d4;border-top:none;">
            <h3><?php esc_html_e('Real-time prometheus metrics', 'anonympins-bot-mitigation-pow'); ?></h3>
            <form method="post" action="" style="margin-bottom:20px;">
                <?php wp_nonce_field('fingerprint_prometheus_nonce', 'fingerprint_nonce_prometheus'); ?>
                <table class="form-table">
                    <tr>
                        <th scope="row"><label for="metrics_endpoint"><?php esc_html_e('Metrics endpoint path', 'anonympins-bot-mitigation-pow'); ?></label></th>
                        <td>
                            <input type="text" name="metrics_endpoint" id="metrics_endpoint" value="<?php echo esc_attr(fingerprint_get_metrics_endpoint()); ?>" class="regular-text" placeholder="/metrics">
                            <p class="description">
                                <?php esc_html_e('Custom path for direct Prometheus scraping (default: /metrics). Leave empty to disable direct path scraping.', 'anonympins-bot-mitigation-pow'); ?>
                            </p>
                            <?php if (fingerprint_get_metrics_endpoint() !== ''): ?>
                                <p class="description">
                                    <strong><?php esc_html_e('Scrape URL:', 'anonympins-bot-mitigation-pow'); ?></strong> <code><?php echo esc_html(home_url(fingerprint_get_metrics_endpoint())); ?></code>
                                </p>
                            <?php endif; ?>
                        </td>
                    </tr>
                </table>
                <?php submit_button(esc_html__('Save prometheus settings', 'anonympins-bot-mitigation-pow'), 'primary', 'fingerprint_save_prometheus'); ?>
            </form>
            <textarea readonly style="width:100%;height:380px;font-family:monospace;background:#f6f7f7;padding:12px;"><?php echo esc_textarea($prometheusRaw); ?></textarea>
        </div>
    </div>
    <?php
}