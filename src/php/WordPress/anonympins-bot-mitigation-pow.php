<?php
/**
 * Plugin Name: Anonympins Bot Mitigation with Proof-of-Work
 * Plugin URI: https://github.com/anonympins/fingerprint
 * Description: High-performance client-side anti-bot protection and Proof-of-Work challenge verification for WordPress.
 * Version: 0.7.5
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

// =============================================================================
// PIÈGES HONEYPOT POUR ENVIRONNEMENTS TIERS (NON-WORDPRESS)
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
// CONFIGURATION PAR DÉFAUT DES PROFILS DE SÉCURITÉ PAR CONTEXTE
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
 * Récupère les configurations fusionnées avec les réglages persistés dans WordPress.
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
 * Récupère les paramètres configurés pour le mode Sandbox / Simulation.
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

// 1. Autoloader PSR-4 pour le moteur Fingerprint
if (!class_exists(DirectFingerprint::class)) {
    $fingerprint_composer_paths = [
        __DIR__ . '/vendor/autoload.php',
        dirname(__DIR__, 2) . '/vendor/autoload.php',
        dirname(__DIR__, 3) . '/vendor/autoload.php',
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
}

// 1.b Chargement des traductions i18n du plugin
add_action('init', function (): void {
    load_plugin_textdomain(
        'anonympins-bot-mitigation-pow',
        false,
        dirname(plugin_basename(__FILE__)) . '/languages'
    );
});

// 2. Activation du plugin : Création de la table de cache SQL
register_activation_hook(__FILE__, function () {
    $store = new WpDbStore();
    $store->ensureTable();

    if (!wp_next_scheduled('fingerprint_prune_expired_entries')) {
        wp_schedule_event(time(), 'hourly', 'fingerprint_prune_expired_entries');
    }
});

// 3. Désactivation : Nettoyage du WP-Cron
register_deactivation_hook(__FILE__, function () {
    wp_clear_scheduled_hook('fingerprint_prune_expired_entries');
});

// 4. Tâche de fond WP-Cron : Purge des clés expirées dans la BDD
add_action('fingerprint_prune_expired_entries', function () {
    $store = new WpDbStore();
    $store->pruneExpired();
});

// 5. Avertissements Admin
add_action('admin_notices', function () {
    if (!is_ssl()) {
        echo '<div class="notice notice-warning is-dismissible">';
        echo '<p><strong>' . esc_html__('[Anonympins Bot Mitigation Security Warning]', 'anonympins-bot-mitigation-pow') . '</strong> : ' .
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
        echo '<p><strong>' . esc_html__('[Anonympins Bot Mitigation Sandbox Active]', 'anonympins-bot-mitigation-pow') . '</strong> : ' .
            esc_html__('Sandbox Mode is currently ENABLED.', 'anonympins-bot-mitigation-pow') . ' ' . $modeDesc .
            ' <a href="' . esc_url(admin_url('options-general.php?page=anonympins-bot-mitigation#tab-sandbox')) . '">' . esc_html__('Configure Sandbox', 'anonympins-bot-mitigation-pow') . '</a></p>';
        echo '</div>';
    }
});

/**
 * Enregistre un événement de challenge dans le tampon tournant du store.
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

// 6. Interception de sécurité au plus tôt du cycle de vie WordPress
add_action('plugins_loaded', function () use ($fingerprint_security_profiles) {
    if ((defined('WP_CLI') && WP_CLI) || (defined('DOING_CRON') && DOING_CRON)) {
        return;
    }

    // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
    $rawUri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/';
    $requestUri = !empty($rawUri) ? $rawUri : '/';
    $isRestApi = defined('REST_REQUEST') && REST_REQUEST;

    if (preg_match('/\.(ico|png|jpg|jpeg|gif|webp|svg|css|js|woff|woff2|ttf)$/i', (string)parse_url($requestUri, PHP_URL_PATH))) {
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
    $guard->protect();
}, 0);

// =============================================================================
// CHARGEMENT & INITIALISATION DE LA TÉLÉMÉTRIE CLIENT
// =============================================================================
add_action('wp_enqueue_scripts', 'fingerprint_enqueue_client_telemetry');
add_action('login_enqueue_scripts', 'fingerprint_enqueue_client_telemetry');

function fingerprint_enqueue_client_telemetry(): void {
    global $fingerprint_foreign_env_honeypot_fields, $fingerprint_foreign_env_trap_urls;

    $scriptUrl = plugin_dir_url(__FILE__) . 'assets/fingerprint.client.js';
    $scriptPath = plugin_dir_path(__FILE__) . 'assets/fingerprint.client.js';

    if (!file_exists($scriptPath)) {
        return;
    }

    $version = filemtime($scriptPath) ?: '0.7.5';
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
// INJECTION DU VECTEUR DE SUSPICION (VIA WP_ENQUEUE_SCRIPT & WP_ADD_INLINE_SCRIPT)
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

    wp_register_script('anonympins-suspicion-event', false, [], false, true);
    wp_enqueue_script('anonympins-suspicion-event');
    wp_add_inline_script('anonympins-suspicion-event', $script);
}

// =============================================================================
// ROUTES SPÉCIALES SANDBOX : REST & SERVER-SENT EVENTS (SSE)
// =============================================================================
add_action('rest_api_init', function () {
    register_rest_route('fingerprint/v1', '/sandbox/telemetry', [
        'methods'             => 'GET',
        'callback'            => 'fingerprint_rest_sandbox_telemetry',
        'permission_callback' => function () {
            return current_user_can('manage_options') || !empty(fingerprint_get_sandbox_config()['enabled']);
        },
    ]);

    register_rest_route('fingerprint/v1', '/sandbox/sse', [
        'methods'             => 'GET',
        'callback'            => 'fingerprint_rest_sandbox_sse',
        'permission_callback' => function () {
            return current_user_can('manage_options') || !empty(fingerprint_get_sandbox_config()['enabled']);
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

function fingerprint_rest_sandbox_sse(): void {
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
// INTERFACE D'ADMINISTRATION, RÉGLAGES & INSPECTION DES MÉTRIQUES
// =============================================================================
add_action('admin_menu', function () {
    add_options_page(
        __('Anonympins Bot Mitigation', 'anonympins-bot-mitigation-pow'),
        __('Anonympins Bot Mitigation', 'anonympins-bot-mitigation-pow'),
        'manage_options',
        'anonympins-bot-mitigation',
        'fingerprint_render_admin_page'
    );
});

/**
 * Enregistre le script JS de la page d'administration via admin_enqueue_scripts (requis par WP)
 */
add_action('admin_enqueue_scripts', function (string $hook) {
    if (strpos($hook, 'anonympins-bot-mitigation') === false) {
        return;
    }

    wp_register_script('anonympins-admin-settings', false, [], false, true);
    wp_enqueue_script('anonympins-admin-settings');

    $adminScript = '
    function fingerprintSwitchTab(evt, tabId) {
        evt.preventDefault();
        document.querySelectorAll(".fingerprint-tab-content").forEach(function(t) { t.style.display = "none"; });
        document.querySelectorAll(".nav-tab-wrapper a").forEach(function(n) { n.classList.remove("nav-tab-active"); });
        document.getElementById(tabId).style.display = "block";
        evt.currentTarget.classList.add("nav-tab-active");
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
            statusEl.textContent = ' . wp_json_encode(__('SSE Disconnected', 'anonympins-bot-mitigation-pow')) . ';
            statusEl.style.color = "#646970";
            btnText.textContent = ' . wp_json_encode(__('Start Real-Time SSE Stream', 'anonympins-bot-mitigation-pow')) . ';
            return;
        }

        statusEl.textContent = ' . wp_json_encode(__('Connecting to SSE stream...', 'anonympins-bot-mitigation-pow')) . ';
        statusEl.style.color = "#2271b1";
        sseSource = new EventSource(' . wp_json_encode(rest_url('fingerprint/v1/sandbox/sse')) . ' + "?_wpnonce=" + wpRestNonce);

        sseSource.onopen = function() {
            statusEl.textContent = ' . wp_json_encode(__('SSE Live Connected', 'anonympins-bot-mitigation-pow')) . ';
            statusEl.style.color = "#007017";
            btnText.textContent = ' . wp_json_encode(__('Stop Stream', 'anonympins-bot-mitigation-pow')) . ';
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
            statusEl.textContent = ' . wp_json_encode(__('SSE Reconnecting...', 'anonympins-bot-mitigation-pow')) . ';
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

    if (isset($_POST['fingerprint_clear_store']) && check_admin_referer('fingerprint_clear_nonce', 'fingerprint_nonce_clear')) {
        $store = new WpDbStore();
        $store->clear();
        echo '<div class="notice notice-info is-dismissible"><p>' . esc_html__('SQL cache table ($wpdb) cleared successfully.', 'anonympins-bot-mitigation-pow') . '</p></div>';
    }

    $sandboxConfig = fingerprint_get_sandbox_config();
    $effective = fingerprint_get_effective_profiles($fingerprint_security_profiles);
    $frontendConfig = SecurityProfiles::createSecurityProfile($effective['frontend']['profile'], $effective['frontend']['overrides'] ?? []);

    $tableName = esc_sql($wpdb->prefix . 'fingerprint_store');
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
    $totalRows = (int)$wpdb->get_var("SELECT COUNT(*) FROM `{$tableName}`");
    $now = time();
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
    $expiredRows = (int)$wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM `{$tableName}` WHERE expires_at IS NOT NULL AND expires_at < %d", $now));

    $prometheusRaw = MetricsManager::getPrometheusMetrics($frontendConfig);
    ?>
    <div class="wrap">
        <h1><span class="dashicons dashicons-shield-alt" style="font-size:32px;vertical-align:middle;margin-right:8px;"></span> Anonympins Bot Mitigation with Proof-of-Work</h1>
        <p class="description"><?php esc_html_e('Client-side behavioral and cryptographic anti-bot protection without third-party CAPTCHA for WordPress.', 'anonympins-bot-mitigation-pow'); ?></p>

        <div style="background:#fff;border-left:4px solid #2271b1;padding:12px 18px;margin:18px 0;box-shadow:0 1px 1px rgba(0,0,0,.04);">
            <p style="margin:4px 0;">
                <strong><?php esc_html_e('Official documentation reference:', 'anonympins-bot-mitigation-pow'); ?></strong>
                <a href="https://github.com/anonympins/fingerprint/blob/main/doc/full_options.md" target="_blank" rel="noopener noreferrer" class="button button-secondary" style="margin-left:8px;">
                    <span class="dashicons dashicons-external" style="vertical-align:middle;"></span> <?php esc_html_e('View Full Configuration Options on GitHub', 'anonympins-bot-mitigation-pow'); ?>
                </a>
                <a href="https://github.com/anonympins/fingerprint" target="_blank" rel="noopener noreferrer" class="button button-secondary" style="margin-left:4px;">
                    <span class="dashicons dashicons-admin-plugins" style="vertical-align:middle;"></span> <?php esc_html_e('GitHub Repository', 'anonympins-bot-mitigation-pow'); ?>
                </a>
            </p>
        </div>

        <!-- TABLEAU DE BORD STATISTIQUES & ÉTAT -->
        <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(240px, 1fr));gap:16px;margin-bottom:24px;">
            <div style="background:#fff;padding:16px;border-radius:4px;border:1px solid #ccd0d4;">
                <h3 style="margin-top:0;"><?php esc_html_e('HTTPS Status', 'anonympins-bot-mitigation-pow'); ?></h3>
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
                <h3 style="margin-top:0;"><?php esc_html_e('SQL Cache ($wpdb)', 'anonympins-bot-mitigation-pow'); ?></h3>
                <p style="font-size:22px;margin:0;font-weight:600;"><?php echo esc_html((string)$totalRows); ?> <span style="font-size:14px;color:#646970;font-weight:normal;"><?php esc_html_e('keys in database', 'anonympins-bot-mitigation-pow'); ?></span></p>
                <small style="color:#8c8f94;"><?php
                    /* translators: %d: number of expired keys awaiting cron purge */
                    echo esc_html(sprintf(__(' %d expired keys awaiting cron purge', 'anonympins-bot-mitigation-pow'), $expiredRows));
                ?></small>
            </div>
            <div style="background:#fff;padding:16px;border-radius:4px;border:1px solid #ccd0d4;">
                <h3 style="margin-top:0;"><?php esc_html_e('Active Profiles', 'anonympins-bot-mitigation-pow'); ?></h3>
                <p style="margin:0;">
                    <?php esc_html_e('Frontend:', 'anonympins-bot-mitigation-pow'); ?> <strong><?php echo esc_html($effective['frontend']['profile']); ?></strong><br>
                    <?php esc_html_e('Admin:', 'anonympins-bot-mitigation-pow'); ?> <strong><?php echo esc_html($effective['admin']['profile']); ?></strong><br>
                    <?php esc_html_e('REST API:', 'anonympins-bot-mitigation-pow'); ?> <strong><?php echo esc_html($effective['api']['profile']); ?></strong>
                </p>
            </div>
            <div style="background:#fff;padding:16px;border-radius:4px;border:1px solid #ccd0d4;">
                <h3 style="margin-top:0;"><?php esc_html_e('Sandbox Mode', 'anonympins-bot-mitigation-pow'); ?></h3>
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

        <!-- ONGLETS DE NAVIGATION -->
        <h2 class="nav-tab-wrapper">
            <a href="#tab-settings" class="nav-tab nav-tab-active" onclick="fingerprintSwitchTab(event, 'tab-settings')"><?php esc_html_e('Settings & Profiles', 'anonympins-bot-mitigation-pow'); ?></a>
            <a href="#tab-sandbox" class="nav-tab" onclick="fingerprintSwitchTab(event, 'tab-sandbox')"><?php esc_html_e('Sandbox / Test Mode', 'anonympins-bot-mitigation-pow'); ?></a>
            <a href="#tab-metrics" class="nav-tab" onclick="fingerprintSwitchTab(event, 'tab-metrics')"><?php esc_html_e('Metrics & Weights View', 'anonympins-bot-mitigation-pow'); ?></a>
            <a href="#tab-prometheus" class="nav-tab" onclick="fingerprintSwitchTab(event, 'tab-prometheus')"><?php esc_html_e('Prometheus Stream', 'anonympins-bot-mitigation-pow'); ?></a>
        </h2>

        <div id="tab-settings" class="fingerprint-tab-content" style="background:#fff;padding:20px;border:1px solid #ccd0d4;border-top:none;">
            <form method="post" action="">
                <?php wp_nonce_field('fingerprint_settings_nonce', 'fingerprint_nonce'); ?>
                <h3><?php esc_html_e('1. Target Security Profiles', 'anonympins-bot-mitigation-pow'); ?></h3>
                <table class="form-table">
                    <tr>
                        <th scope="row"><label for="frontend_profile"><?php esc_html_e('Visitors & Frontend', 'anonympins-bot-mitigation-pow'); ?></label></th>
                        <td>
                            <select name="frontend_profile" id="frontend_profile">
                                <option value="blog" <?php selected($effective['frontend']['profile'], 'blog'); ?>><?php esc_html_e('Blog (Optimal for content, smooth UX)', 'anonympins-bot-mitigation-pow'); ?></option>
                                <option value="balanced" <?php selected($effective['frontend']['profile'], 'balanced'); ?>><?php esc_html_e('Balanced (General purpose)', 'anonympins-bot-mitigation-pow'); ?></option>
                                <option value="strict" <?php selected($effective['frontend']['profile'], 'strict'); ?>><?php esc_html_e('Strict (Maximum protection)', 'anonympins-bot-mitigation-pow'); ?></option>
                                <option value="ecommerce" <?php selected($effective['frontend']['profile'], 'ecommerce'); ?>><?php esc_html_e('E-commerce (Anti-scraping / scalping)', 'anonympins-bot-mitigation-pow'); ?></option>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="admin_profile"><?php esc_html_e('Administration Area (wp-login / wp-admin)', 'anonympins-bot-mitigation-pow'); ?></label></th>
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
                <h3><?php esc_html_e('2. Action Thresholds (Frontend)', 'anonympins-bot-mitigation-pow'); ?></h3>
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e('Suspicion Score Thresholds (0 - 100)', 'anonympins-bot-mitigation-pow'); ?></th>
                        <td>
                            <label><?php esc_html_e('Low (Initial challenge):', 'anonympins-bot-mitigation-pow'); ?>
                                <input type="number" name="frontend_threshold_low" value="<?php echo esc_attr((string)($frontendConfig['thresholds']['low'] ?? 20)); ?>" min="1" max="50" style="width:80px;">
                            </label><br><br>
                            <label><?php esc_html_e('Medium (Hardened challenge):', 'anonympins-bot-mitigation-pow'); ?>
                                <input type="number" name="frontend_threshold_medium" value="<?php echo esc_attr((string)($frontendConfig['thresholds']['medium'] ?? 45)); ?>" min="10" max="75" style="width:80px;">
                            </label><br><br>
                            <label><?php esc_html_e('High (Heavy Proof-of-Work):', 'anonympins-bot-mitigation-pow'); ?>
                                <input type="number" name="frontend_threshold_high" value="<?php echo esc_attr((string)($frontendConfig['thresholds']['high'] ?? 75)); ?>" min="30" max="95" style="width:80px;">
                            </label><br><br>
                            <label><?php esc_html_e('Block (Immediate 403 Forbidden):', 'anonympins-bot-mitigation-pow'); ?>
                                <input type="number" name="frontend_threshold_block" value="<?php echo esc_attr((string)($frontendConfig['thresholds']['block'] ?? 95)); ?>" min="50" max="100" style="width:80px;">
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Advanced Behaviors', 'anonympins-bot-mitigation-pow'); ?></th>
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
                <?php submit_button(esc_html__('Save Changes', 'anonympins-bot-mitigation-pow'), 'primary', 'fingerprint_save_settings'); ?>
            </form>
            <hr>
            <form method="post" action="" style="margin-top:16px;">
                <?php wp_nonce_field('fingerprint_clear_nonce', 'fingerprint_nonce_clear'); ?>
                <p>
                    <strong><?php esc_html_e('Store Maintenance:', 'anonympins-bot-mitigation-pow'); ?></strong>
                    <button type="submit" name="fingerprint_clear_store" class="button button-secondary" onclick="return confirm('<?php echo esc_js(__('Purge all stored sessions and nonces?', 'anonympins-bot-mitigation-pow')); ?>');">
                        <?php esc_html_e('Clear SQL cache table ($wpdb)', 'anonympins-bot-mitigation-pow'); ?>
                    </button>
                </p>
            </form>
        </div>

        <div id="tab-sandbox" class="fingerprint-tab-content" style="display:none;background:#fff;padding:20px;border:1px solid #ccd0d4;border-top:none;">
            <h3><?php esc_html_e('Sandbox Mode & Dry-Run Configuration', 'anonympins-bot-mitigation-pow'); ?></h3>
            <form method="post" action="">
                <?php wp_nonce_field('fingerprint_sandbox_nonce', 'fingerprint_nonce_sandbox'); ?>
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e('Sandbox Activation', 'anonympins-bot-mitigation-pow'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="sandbox_enabled" value="1" <?php checked($sandboxConfig['enabled']); ?>>
                                <strong><?php esc_html_e('Enable Sandbox Mode', 'anonympins-bot-mitigation-pow'); ?></strong>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Behavior & Enforcement', 'anonympins-bot-mitigation-pow'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="sandbox_audit_only" value="1" <?php checked($sandboxConfig['audit_only']); ?>>
                                <strong><?php esc_html_e('Audit Only / Dry-Run (Never block or challenge visitors)', 'anonympins-bot-mitigation-pow'); ?></strong>
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
                        <th scope="row"><label for="sandbox_ip_filter"><?php esc_html_e('Test IP Whitelist Filter', 'anonympins-bot-mitigation-pow'); ?></label></th>
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
                <?php submit_button(esc_html__('Save Sandbox Settings', 'anonympins-bot-mitigation-pow'), 'primary', 'fingerprint_save_sandbox'); ?>
            </form>
            <hr>
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                <h3 style="margin:0;"><span class="dashicons dashicons-shield" style="vertical-align:text-bottom;"></span> <?php esc_html_e('Live Challenged Visitors & Suspicion Monitor', 'anonympins-bot-mitigation-pow'); ?></h3>
                <div>
                    <span style="font-weight:600;color:#646970;"><?php esc_html_e('Recent Challenges:', 'anonympins-bot-mitigation-pow'); ?></span>
                    <span id="live-challenges-count" style="display:inline-block;padding:2px 8px;background:#2271b1;color:#fff;border-radius:10px;font-weight:bold;font-size:12px;">0</span>
                </div>
            </div>
            <div style="background:#f6f7f7;padding:16px;border:1px solid #c3c4c7;border-radius:4px;margin-bottom:15px;">
                <div style="display:flex;gap:12px;align-items:center;margin-bottom:12px;flex-wrap:wrap;">
                    <button type="button" class="button button-primary" id="btn-toggle-sse" onclick="fingerprintToggleSSE();">
                        <span class="dashicons dashicons-controls-play" style="vertical-align:middle;"></span> <span id="sse-btn-text"><?php esc_html_e('Start Real-Time SSE Stream', 'anonympins-bot-mitigation-pow'); ?></span>
                    </button>
                    <button type="button" class="button button-secondary" onclick="fingerprintFetchTelemetry();">
                        <span class="dashicons dashicons-update" style="vertical-align:middle;"></span> <?php esc_html_e('Poll Now (REST)', 'anonympins-bot-mitigation-pow'); ?>
                    </button>
                    <button type="button" class="button button-secondary" onclick="fingerprintClearFeed();">
                        <span class="dashicons dashicons-trash" style="vertical-align:middle;"></span> <?php esc_html_e('Clear Feed', 'anonympins-bot-mitigation-pow'); ?>
                    </button>
                    <span id="sse-connection-status" style="font-weight:bold;color:#646970;"></span>
                </div>
                <div style="display:grid;grid-template-columns: 1.4fr 1fr;gap:16px;">
                    <div style="background:#fff;padding:12px;border:1px solid #dcdcde;border-radius:4px;overflow-x:auto;">
                        <h4 style="margin:0 0 8px 0;"><?php esc_html_e('Challenged Visitors Stream', 'anonympins-bot-mitigation-pow'); ?></h4>
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
                            <h4 style="margin:0;"><?php esc_html_e('Inspection & Suspicion Vector', 'anonympins-bot-mitigation-pow'); ?></h4>
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
            <h3><?php esc_html_e('Behavioral & Transport Indicator Weights', 'anonympins-bot-mitigation-pow'); ?></h3>
            <form method="post" action="">
                <?php wp_nonce_field('fingerprint_settings_nonce', 'fingerprint_nonce'); ?>
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th style="width:280px;"><?php esc_html_e('Indicator / Metric', 'anonympins-bot-mitigation-pow'); ?></th>
                            <th style="width:120px;"><?php esc_html_e('Current Weight', 'anonympins-bot-mitigation-pow'); ?></th>
                            <th><?php esc_html_e('Description & Detection Role', 'anonympins-bot-mitigation-pow'); ?></th>
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
                    <?php submit_button(esc_html__('Update Metric Weights', 'anonympins-bot-mitigation-pow'), 'primary', 'fingerprint_save_settings', false); ?>
                </p>
            </form>
        </div>

        <div id="tab-prometheus" class="fingerprint-tab-content" style="display:none;background:#fff;padding:20px;border:1px solid #ccd0d4;border-top:none;">
            <h3><?php esc_html_e('Real-Time Prometheus Metrics', 'anonympins-bot-mitigation-pow'); ?></h3>
            <textarea readonly style="width:100%;height:380px;font-family:monospace;background:#f6f7f7;padding:12px;"><?php echo esc_textarea($prometheusRaw); ?></textarea>
        </div>
    </div>
    <?php
}