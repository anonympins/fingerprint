<?php
/**
 * Plugin Name: Fingerprint Anti-Bot & Proof-of-Work
 * Plugin URI: https://github.com/anonympins/fingerprint
 * Description: High-performance client-side anti-bot protection and Proof-of-Work challenge verification for WordPress.
 * Version: 0.7.5
 * Author: anonympins
 * Requires at least: 5.9
 * Requires PHP: 8.0
 * License: MIT
 * Text Domain: fingerprint-anti-bot
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
// Détecte et bloque instantanément les scans de vulnérabilités ciblant
// Laravel, Symfony, Spring Boot, Django, ASP.NET, phpMyAdmin, Git, Cloud, etc.
// =============================================================================
$fingerprint_foreign_env_trap_urls = [
    // Outils d'administration BDD & scripts de debug
    '/phpmyadmin', '/pma', '/adminer', '/mysql', '/dbadmin', '/phpinfo',
    // Frameworks PHP (Laravel, Symfony) & fichiers d'environnement
    '/.env', '/artisan', '/telescope', '/_profiler', '/config/database.php', '/vendor/',
    // Java / Spring Boot / Actuator
    '/actuator', '/actuator/health', '/actuator/gateway', '/api-docs', '/swagger-ui',
    // Python / Django / Flask
    '/.flask', '/django_admin', '/__pycache__',
    // Node.js & configuration paquets
    '/.npmrc', '/package.json', '/package-lock.json',
    // ASP.NET / IIS / CGI
    '/elmah.axd', '/trace.axd', '/cgi-bin/',
    // DevOps, VCS & Déploiements cloud
    '/.git', '/.svn', '/.aws', '/.kube', '/docker-compose', '/serverless'
];

$fingerprint_foreign_env_honeypot_fields = [
    // Tokens CSRF et formulaires spécifiques à d'autres frameworks
    '_token',                // Laravel
    'csrfmiddlewaretoken',   // Django
    'authenticity_token',    // Ruby on Rails
    'form_build_id',         // Drupal
    'form_id',               // Drupal
    'j_username',            // Java / Spring Security
    'j_password',            // Java / Spring Security
    '__VIEWSTATE',           // ASP.NET WebForms
    '__EVENTVALIDATION',     // ASP.NET WebForms
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
    $saved = get_option('fingerprint_security_options', []);
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
    $saved = get_option('fingerprint_security_options', []);
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

        // Classes spécifiques WordPress (ex: WpDbStore)
        if (str_starts_with($relativeClass, 'WordPress\\')) {
            $localClass = substr($relativeClass, strlen('WordPress\\'));
            $localFile = __DIR__ . '/' . str_replace('\\', '/', $localClass) . '.php';
            if (file_exists($localFile)) {
                require_once $localFile;
                return;
            }
        }

        // Chemins candidats pour le moteur PHP (packagé ou environnement dev)
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

// 5. Avertissement Admin si le site n'utilise pas HTTPS (Environnement Non Sécurisé)
add_action('admin_notices', function () {
    if (!is_ssl()) {
        echo '<div class="notice notice-warning is-dismissible">';
        echo '<p><strong>' . esc_html__('[Fingerprint Anti-Bot Security Warning]', 'fingerprint-anti-bot') . '</strong> : ' .
            esc_html__('Your website is currently running on unencrypted HTTP. In this mode, modern web browsers disable the native Web Cryptography API (crypto.subtle) for security reasons, forcing a JavaScript fallback simulation that is slower and vulnerable to Man-in-the-Middle (MitM) attacks. We strongly recommend deploying a TLS/SSL certificate and enforcing HTTPS to ensure the cryptographic integrity of Proof-of-Work computations and identity protection.', 'fingerprint-anti-bot') .
            '</p>';
        echo '</div>';
    }
});

// Avertissement Admin si le Mode Sandbox est activé
add_action('admin_notices', function () {
    $sandbox = fingerprint_get_sandbox_config();
    if ($sandbox['enabled'] && current_user_can('manage_options')) {
        $modeDesc = !empty($sandbox['audit_only'])
            ? esc_html__('Audit-Only dry-run is active: visitors will not be blocked or challenged.', 'fingerprint-anti-bot')
            : esc_html__('Enforced test mode: suspicion analysis and PoW challenges are actively triggered.', 'fingerprint-anti-bot');

        echo '<div class="notice notice-warning is-dismissible">';
        echo '<p><strong>' . esc_html__('[Fingerprint Anti-Bot Sandbox Active]', 'fingerprint-anti-bot') . '</strong> : ' .
            esc_html__('Sandbox Mode is currently ENABLED.', 'fingerprint-anti-bot') . ' ' . $modeDesc .
            ' <a href="' . esc_url(admin_url('options-general.php?page=fingerprint-settings#tab-sandbox')) . '">' . esc_html__('Configure Sandbox', 'fingerprint-anti-bot') . '</a></p>';
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

// Variable globale pour stocker l'évaluation de la requête courante (utilisée par JS et REST)
$GLOBALS['fingerprint_current_evaluation'] = null;

// 6. Interception de sécurité au plus tôt du cycle de vie WordPress
add_action('plugins_loaded', function () use ($fingerprint_security_profiles) {
    // Ignore WP-CLI et les exécutions internes de cron
    if ((defined('WP_CLI') && WP_CLI) || (defined('DOING_CRON') && DOING_CRON)) {
        return;
    }

    // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitized with sanitize_text_field
    $rawUri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '/';
    $requestUri = !empty($rawUri) ? $rawUri : '/';
    $isRestApi = defined('REST_REQUEST') && REST_REQUEST;

    // Ignore les requêtes de favicons et d'assets statiques pour ne pas polluer l'inspection
    if (preg_match('/\.(ico|png|jpg|jpeg|gif|webp|svg|css|js|woff|woff2|ttf)$/i', (string)parse_url($requestUri, PHP_URL_PATH))) {
        return;
    }
    // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
    $isAdmin = is_admin() || (isset($_SERVER['PHP_SELF']) && str_contains(sanitize_text_field(wp_unslash($_SERVER['PHP_SELF'])), 'wp-login.php')) || str_contains($requestUri, 'wp-login.php');

    // Whitelist inconditionnelle de la page des réglages du plugin et des endpoints REST de diagnostic
    if (str_contains($requestUri, 'page=fingerprint-settings') || str_contains($requestUri, '/wp-json/fingerprint/v1/')) {
        return;
    }

    // Initialiser le Store persistant basé sur $wpdb
    $store = new WpDbStore();
    $store->ensureTable();
    StoreManager::configureStore($store);

    // Fusion avec les options enregistrées via l'admin WP
    $effectiveProfiles = fingerprint_get_effective_profiles($fingerprint_security_profiles);

    // Possibilité de filtrer la configuration via functions.php ou un thème
    $configs = apply_filters('fingerprint_security_profiles', $effectiveProfiles);

    // Sélection adaptative du profil selon la cible de la requête
    if ($isRestApi || str_starts_with($requestUri, '/wp-json/')) {
        $contextConfig = $configs['api'] ?? $fingerprint_security_profiles['api'];
    } elseif ($isAdmin) {
        $contextConfig = $configs['admin'] ?? $fingerprint_security_profiles['admin'];
    } else {
        $contextConfig = $configs['frontend'] ?? $fingerprint_security_profiles['frontend'];
    }

    // Évaluation du Mode Sandbox
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

    // Configuration du callback onDecision pour capturer les événements en temps réel (challenges, blocks, audits)
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

        // Diagnostic HTTP headers if active
        if ($isSandboxActive && $sandboxConfig['add_headers'] && !headers_sent()) {
            header('X-Fingerprint-Sandbox: active');
            header('X-Fingerprint-Mode: ' . (!empty($sandboxConfig['audit_only']) ? 'audit-only' : 'enforce'));
            header('X-Fingerprint-Score: ' . (string)round($score, 1));
        }

        if ($sandboxConfig['log_requests']) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
            error_log(sprintf('[Fingerprint Challenge Log] Target: %s | IP: %s | Action: %s | Score: %s', $requestUri, $payload['ip'], $actionTaken, $payload['suspicionScore']));
        }

        // Journalise tout challenge, blocage ou action suspecte dans la file partagée
        if ($isChallengedOrSuspect) {
            fingerprint_record_challenge_event($payload);
        }
    };

    $securityConfig = SecurityProfiles::createSecurityProfile($contextConfig['profile'], $contextConfig['overrides'] ?? []);
    $guard = new DirectFingerprint($securityConfig);

    // Inspecte la requête : bloque ou envoie le challenge si nécessaire et stoppe le script
    $guard->protect();
}, 0);

// =============================================================================
// CHARGEMENT & INITIALISATION DE LA TÉLÉMÉTRIE CLIENT (BIOMÉTRIE & HONEYPOTS)
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

    // Options d'initialisation transmises au client
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
// INJECTION DU VECTEUR DE SUSPICION CÔTÉ CLIENT (ÉVÉNEMENT JS)
// =============================================================================
add_action('wp_head', 'fingerprint_inject_client_suspicion_event');
add_action('admin_head', 'fingerprint_inject_client_suspicion_event');
function fingerprint_inject_client_suspicion_event(): void {
    $eval = $GLOBALS['fingerprint_current_evaluation'] ?? null;
    if (!$eval || (!current_user_can('manage_options') && empty(fingerprint_get_sandbox_config()['enabled']))) {
        return;
    }
    $jsonPayload = wp_json_encode($eval);
    ?>
    <script>
    (function() {
        window.__FINGERPRINT_VECTOR__ = <?php echo $jsonPayload; ?>;
        try {
            const evt = new CustomEvent('fingerprint:suspicion', { detail: window.__FINGERPRINT_VECTOR__ });
            document.dispatchEvent(evt);
        } catch(e) {}
    })();
    </script>
    <?php
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

/**
 * Retourne la liste des derniers visiteurs challengés sur le site.
 */
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

/**
 * Réinitialise le journal des visiteurs challengés.
 */
function fingerprint_rest_sandbox_clear_challenges(): \WP_REST_Response {
    $store = new WpDbStore();
    $store->delete('fingerprint_challenges_log');
    $store->delete('fingerprint_latest_challenge');
    return new \WP_REST_Response(['cleared' => true], 200);
}

/**
 * Stream Server-Sent Events (SSE) émettant en direct chaque visiteur challengé sur le site.
 */
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
        __('Fingerprint Anti-Bot', 'fingerprint-anti-bot'),
        __('Fingerprint Anti-Bot', 'fingerprint-anti-bot'),
        'manage_options',
        'fingerprint-settings',
        'fingerprint_render_admin_page'
    );
});

/**
 * Rendu de la page de réglages et du visualiseur de métriques.
 */
function fingerprint_render_admin_page(): void {
    if (!current_user_can('manage_options')) {
        wp_die(esc_html__('You do not have sufficient permissions to access this page.', 'fingerprint-anti-bot'));
    }

    global $fingerprint_security_profiles, $wpdb;

    // Sauvegarde des réglages
    if (isset($_POST['fingerprint_save_settings']) && check_admin_referer('fingerprint_settings_nonce', 'fingerprint_nonce')) {
        $saved = get_option('fingerprint_security_options', []);
        if (!is_array($saved)) {
            $saved = [];
        }

        // Profils sélectionnés
        $saved['frontend']['profile'] = isset($_POST['frontend_profile']) ? sanitize_text_field(wp_unslash($_POST['frontend_profile'])) : 'blog';
        $saved['admin']['profile']    = isset($_POST['admin_profile']) ? sanitize_text_field(wp_unslash($_POST['admin_profile'])) : 'strict';
        $saved['api']['profile']      = isset($_POST['api_profile']) ? sanitize_text_field(wp_unslash($_POST['api_profile'])) : 'api';

        // Seuils Frontend
        $saved['frontend']['overrides']['thresholds'] = [
            'low'    => max(1, isset($_POST['frontend_threshold_low']) ? (int)sanitize_text_field(wp_unslash($_POST['frontend_threshold_low'])) : 20),
            'medium' => max(5, isset($_POST['frontend_threshold_medium']) ? (int)sanitize_text_field(wp_unslash($_POST['frontend_threshold_medium'])) : 45),
            'high'   => max(10, isset($_POST['frontend_threshold_high']) ? (int)sanitize_text_field(wp_unslash($_POST['frontend_threshold_high'])) : 75),
            'block'  => max(20, isset($_POST['frontend_threshold_block']) ? (int)sanitize_text_field(wp_unslash($_POST['frontend_threshold_block'])) : 95),
        ];

        // Options booléennes
        $saved['frontend']['overrides']['challengeNewDevices'] = !empty($_POST['frontend_challenge_new']);
        $saved['frontend']['overrides']['verbose']             = !empty($_POST['frontend_verbose']);
        $saved['frontend']['overrides']['honeypot']['detectInjections'] = !empty($_POST['detect_injections']);

        // Surcharges de l'ensemble des poids de métriques
        foreach ($_POST as $postKey => $postVal) {
            if (str_starts_with((string)$postKey, 'weight_')) {
                $wKey = sanitize_key(substr((string)$postKey, 7));
                $val = (float)sanitize_text_field(wp_unslash($postVal));
                $saved['frontend']['overrides']['weights'][$wKey] = max(0.0, min(2.0, $val));
            }
        }

        update_option('fingerprint_security_options', $saved);
        echo '<div class="notice notice-success is-dismissible"><p><strong>' . esc_html__('Fingerprint settings updated successfully.', 'fingerprint-anti-bot') . '</strong></p></div>';
    }

    // Sauvegarde des réglages Sandbox
    if (isset($_POST['fingerprint_save_sandbox']) && check_admin_referer('fingerprint_sandbox_nonce', 'fingerprint_nonce_sandbox')) {
        $saved = get_option('fingerprint_security_options', []);
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

        update_option('fingerprint_security_options', $saved);
        echo '<div class="notice notice-success is-dismissible"><p><strong>' . esc_html__('Sandbox settings updated successfully.', 'fingerprint-anti-bot') . '</strong></p></div>';
    }

    // Action pour vider le cache SQL manuellement
    if (isset($_POST['fingerprint_clear_store']) && check_admin_referer('fingerprint_clear_nonce', 'fingerprint_nonce_clear')) {
        $store = new WpDbStore();
        $store->clear();
        echo '<div class="notice notice-info is-dismissible"><p>' . esc_html__('SQL cache table ($wpdb) cleared successfully.', 'fingerprint-anti-bot') . '</p></div>';
    }

    // Récupération des profils effectifs
    $sandboxConfig = fingerprint_get_sandbox_config();
    $effective = fingerprint_get_effective_profiles($fingerprint_security_profiles);
    $frontendConfig = SecurityProfiles::createSecurityProfile($effective['frontend']['profile'], $effective['frontend']['overrides'] ?? []);

    // Statistiques de la table de cache SQL
    $tableName = esc_sql($wpdb->prefix . 'fingerprint_store');
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Administrative stats on custom high-velocity table.
    $totalRows = (int)$wpdb->get_var("SELECT COUNT(*) FROM `{$tableName}`");
    $now = time();
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Administrative stats on custom high-velocity table.
    $expiredRows = (int)$wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM `{$tableName}` WHERE expires_at IS NOT NULL AND expires_at < %d", $now));

    // Métriques Prometheus au format texte
    $prometheusRaw = MetricsManager::getPrometheusMetrics($frontendConfig);
    ?>
    <div class="wrap">
        <h1><span class="dashicons dashicons-shield-alt" style="font-size:32px;vertical-align:middle;margin-right:8px;"></span> Fingerprint Anti-Bot & Proof-of-Work</h1>
        <p class="description"><?php esc_html_e('Client-side behavioral and cryptographic anti-bot protection without third-party CAPTCHA for WordPress.', 'fingerprint-anti-bot'); ?></p>

        <div style="background:#fff;border-left:4px solid #2271b1;padding:12px 18px;margin:18px 0;box-shadow:0 1px 1px rgba(0,0,0,.04);">
            <p style="margin:4px 0;">
                <strong><?php esc_html_e('Official documentation reference:', 'fingerprint-anti-bot'); ?></strong>
                <a href="https://github.com/anonympins/fingerprint/blob/main/doc/full_options.md" target="_blank" rel="noopener noreferrer" class="button button-secondary" style="margin-left:8px;">
                    <span class="dashicons dashicons-external" style="vertical-align:middle;"></span> <?php esc_html_e('View Full Configuration Options on GitHub', 'fingerprint-anti-bot'); ?>
                </a>
                <a href="https://github.com/anonympins/fingerprint" target="_blank" rel="noopener noreferrer" class="button button-secondary" style="margin-left:4px;">
                    <span class="dashicons dashicons-admin-plugins" style="vertical-align:middle;"></span> <?php esc_html_e('GitHub Repository', 'fingerprint-anti-bot'); ?>
                </a>
            </p>
        </div>

        <!-- TABLEAU DE BORD STATISTIQUES & ÉTAT -->
        <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(240px, 1fr));gap:16px;margin-bottom:24px;">
            <div style="background:#fff;padding:16px;border-radius:4px;border:1px solid #ccd0d4;">
                <h3 style="margin-top:0;"><?php esc_html_e('HTTPS Status', 'fingerprint-anti-bot'); ?></h3>
                <?php if (is_ssl()): ?>
                    <p style="color:#007017;font-weight:bold;font-size:16px;">
                        <span class="dashicons dashicons-yes-alt"></span> <?php esc_html_e('Active (WebCrypto Subtle available)', 'fingerprint-anti-bot'); ?>
                    </p>
                <?php else: ?>
                    <p style="color:#d63638;font-weight:bold;font-size:16px;">
                        <span class="dashicons dashicons-warning"></span> <?php esc_html_e('Insecure (Unencrypted HTTP)', 'fingerprint-anti-bot'); ?>
                    </p>
                <?php endif; ?>
            </div>
            <div style="background:#fff;padding:16px;border-radius:4px;border:1px solid #ccd0d4;">
                <h3 style="margin-top:0;"><?php esc_html_e('SQL Cache ($wpdb)', 'fingerprint-anti-bot'); ?></h3>
                <p style="font-size:22px;margin:0;font-weight:600;"><?php echo esc_html((string)$totalRows); ?> <span style="font-size:14px;color:#646970;font-weight:normal;"><?php esc_html_e('keys in database', 'fingerprint-anti-bot'); ?></span></p>
                <small style="color:#8c8f94;"><?php
                    /* translators: %d: number of expired keys awaiting cron purge */
                    echo esc_html(sprintf(__(' %d expired keys awaiting cron purge', 'fingerprint-anti-bot'), $expiredRows));
                ?></small>
            </div>
            <div style="background:#fff;padding:16px;border-radius:4px;border:1px solid #ccd0d4;">
                <h3 style="margin-top:0;"><?php esc_html_e('Active Profiles', 'fingerprint-anti-bot'); ?></h3>
                <p style="margin:0;">
                    <?php esc_html_e('Frontend:', 'fingerprint-anti-bot'); ?> <strong><?php echo esc_html($effective['frontend']['profile']); ?></strong><br>
                    <?php esc_html_e('Admin:', 'fingerprint-anti-bot'); ?> <strong><?php echo esc_html($effective['admin']['profile']); ?></strong><br>
                    <?php esc_html_e('REST API:', 'fingerprint-anti-bot'); ?> <strong><?php echo esc_html($effective['api']['profile']); ?></strong>
                </p>
            </div>
            <div style="background:#fff;padding:16px;border-radius:4px;border:1px solid #ccd0d4;">
                <h3 style="margin-top:0;"><?php esc_html_e('Sandbox Mode', 'fingerprint-anti-bot'); ?></h3>
                <?php if ($sandboxConfig['enabled']): ?>
                    <p style="color:#dba617;font-weight:bold;font-size:16px;margin:0;">
                        <span class="dashicons dashicons-warning"></span> <?php esc_html_e('Active (Simulation)', 'fingerprint-anti-bot'); ?>
                    </p>
                    <small style="color:#646970;"><?php echo !empty($sandboxConfig['audit_only']) ? esc_html__('Audit-Only: non-blocking observation.', 'fingerprint-anti-bot') : esc_html__('Testing: challenges & mitigations active.', 'fingerprint-anti-bot'); ?></small>
                <?php else: ?>
                    <p style="color:#007017;font-weight:bold;font-size:16px;margin:0;">
                        <span class="dashicons dashicons-yes-alt"></span> <?php esc_html_e('Production (Enforced)', 'fingerprint-anti-bot'); ?>
                    </p>
                    <small style="color:#646970;"><?php esc_html_e('Bot protection active across all visitors.', 'fingerprint-anti-bot'); ?></small>
                <?php endif; ?>
            </div>
        </div>

        <!-- ONGLETS DE NAVIGATION -->
        <h2 class="nav-tab-wrapper">
            <a href="#tab-settings" class="nav-tab nav-tab-active" onclick="fingerprintSwitchTab(event, 'tab-settings')"><?php esc_html_e('Settings & Profiles', 'fingerprint-anti-bot'); ?></a>
            <a href="#tab-sandbox" class="nav-tab" onclick="fingerprintSwitchTab(event, 'tab-sandbox')"><?php esc_html_e('Sandbox / Test Mode', 'fingerprint-anti-bot'); ?></a>
            <a href="#tab-metrics" class="nav-tab" onclick="fingerprintSwitchTab(event, 'tab-metrics')"><?php esc_html_e('Metrics & Weights View', 'fingerprint-anti-bot'); ?></a>
            <a href="#tab-prometheus" class="nav-tab" onclick="fingerprintSwitchTab(event, 'tab-prometheus')"><?php esc_html_e('Prometheus Stream', 'fingerprint-anti-bot'); ?></a>
        </h2>

        <!-- TAB 1 : RÉGLAGES -->
        <div id="tab-settings" class="fingerprint-tab-content" style="background:#fff;padding:20px;border:1px solid #ccd0d4;border-top:none;">
            <form method="post" action="">
                <?php wp_nonce_field('fingerprint_settings_nonce', 'fingerprint_nonce'); ?>

                <h3><?php esc_html_e('1. Target Security Profiles', 'fingerprint-anti-bot'); ?></h3>
                <table class="form-table">
                    <tr>
                        <th scope="row"><label for="frontend_profile"><?php esc_html_e('Visitors & Frontend', 'fingerprint-anti-bot'); ?></label></th>
                        <td>
                            <select name="frontend_profile" id="frontend_profile">
                                <option value="blog" <?php selected($effective['frontend']['profile'], 'blog'); ?>><?php esc_html_e('Blog (Optimal for content, smooth UX)', 'fingerprint-anti-bot'); ?></option>
                                <option value="balanced" <?php selected($effective['frontend']['profile'], 'balanced'); ?>><?php esc_html_e('Balanced (General purpose)', 'fingerprint-anti-bot'); ?></option>
                                <option value="strict" <?php selected($effective['frontend']['profile'], 'strict'); ?>><?php esc_html_e('Strict (Maximum protection)', 'fingerprint-anti-bot'); ?></option>
                                <option value="ecommerce" <?php selected($effective['frontend']['profile'], 'ecommerce'); ?>><?php esc_html_e('E-commerce (Anti-scraping / scalping)', 'fingerprint-anti-bot'); ?></option>
                            </select>
                            <p class="description"><?php esc_html_e('Profile applied to all public pages of the WordPress site.', 'fingerprint-anti-bot'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="admin_profile"><?php esc_html_e('Administration Area (wp-login / wp-admin)', 'fingerprint-anti-bot'); ?></label></th>
                        <td>
                            <select name="admin_profile" id="admin_profile">
                                <option value="strict" <?php selected($effective['admin']['profile'], 'strict'); ?>><?php esc_html_e('Strict (Recommended to secure logins)', 'fingerprint-anti-bot'); ?></option>
                                <option value="balanced" <?php selected($effective['admin']['profile'], 'balanced'); ?>><?php esc_html_e('Balanced', 'fingerprint-anti-bot'); ?></option>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="api_profile"><?php esc_html_e('REST API (/wp-json/)', 'fingerprint-anti-bot'); ?></label></th>
                        <td>
                            <select name="api_profile" id="api_profile">
                                <option value="api" <?php selected($effective['api']['profile'], 'api'); ?>><?php esc_html_e('API (JSON challenges & machine PoW)', 'fingerprint-anti-bot'); ?></option>
                                <option value="strict" <?php selected($effective['api']['profile'], 'strict'); ?>><?php esc_html_e('Strict', 'fingerprint-anti-bot'); ?></option>
                            </select>
                        </td>
                    </tr>
                </table>

                <hr>

                <h3><?php esc_html_e('2. Action Thresholds (Frontend)', 'fingerprint-anti-bot'); ?></h3>
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e('Suspicion Score Thresholds (0 - 100)', 'fingerprint-anti-bot'); ?></th>
                        <td>
                            <label><?php esc_html_e('Low (Initial challenge):', 'fingerprint-anti-bot'); ?>
                                <input type="number" name="frontend_threshold_low" value="<?php echo esc_attr((string)($frontendConfig['thresholds']['low'] ?? 20)); ?>" min="1" max="50" style="width:80px;">
                            </label><br><br>
                            <label><?php esc_html_e('Medium (Hardened challenge):', 'fingerprint-anti-bot'); ?>
                                <input type="number" name="frontend_threshold_medium" value="<?php echo esc_attr((string)($frontendConfig['thresholds']['medium'] ?? 45)); ?>" min="10" max="75" style="width:80px;">
                            </label><br><br>
                            <label><?php esc_html_e('High (Heavy Proof-of-Work):', 'fingerprint-anti-bot'); ?>
                                <input type="number" name="frontend_threshold_high" value="<?php echo esc_attr((string)($frontendConfig['thresholds']['high'] ?? 75)); ?>" min="30" max="95" style="width:80px;">
                            </label><br><br>
                            <label><?php esc_html_e('Block (Immediate 403 Forbidden):', 'fingerprint-anti-bot'); ?>
                                <input type="number" name="frontend_threshold_block" value="<?php echo esc_attr((string)($frontendConfig['thresholds']['block'] ?? 95)); ?>" min="50" max="100" style="width:80px;">
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Advanced Behaviors', 'fingerprint-anti-bot'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="frontend_challenge_new" value="1" <?php checked(!empty($frontendConfig['challengeNewDevices'])); ?>>
                                <?php esc_html_e('Automatically challenge unknown new devices (without device_id cookie)', 'fingerprint-anti-bot'); ?>
                            </label><br>
                            <label>
                                <input type="checkbox" name="detect_injections" value="1" <?php checked(!empty($frontendConfig['honeypot']['detectInjections'])); ?>>
                                <?php esc_html_e('Enable recursive WAF inspection (SQL, NoSQL, Log4j, Traversal in GET/POST)', 'fingerprint-anti-bot'); ?>
                            </label><br>
                            <label>
                                <input type="checkbox" name="frontend_verbose" value="1" <?php checked(!empty($frontendConfig['verbose'])); ?>>
                                <?php esc_html_e('Verbose mode in PHP logs (Debugging)', 'fingerprint-anti-bot'); ?>
                            </label>
                        </td>
                    </tr>
                </table>

                <?php submit_button(esc_html__('Save Changes', 'fingerprint-anti-bot'), 'primary', 'fingerprint_save_settings'); ?>
            </form>

            <hr>
            <form method="post" action="" style="margin-top:16px;">
                <?php wp_nonce_field('fingerprint_clear_nonce', 'fingerprint_nonce_clear'); ?>
                <p>
                    <strong><?php esc_html_e('Store Maintenance:', 'fingerprint-anti-bot'); ?></strong>
                    <button type="submit" name="fingerprint_clear_store" class="button button-secondary" onclick="return confirm('<?php echo esc_js(__('Purge all stored sessions and nonces?', 'fingerprint-anti-bot')); ?>');">
                        <?php esc_html_e('Clear SQL cache table ($wpdb)', 'fingerprint-anti-bot'); ?>
                    </button>
                </p>
            </form>
        </div>

        <!-- TAB SANDBOX : BAC À SABLE / SIMULATION -->
        <div id="tab-sandbox" class="fingerprint-tab-content" style="display:none;background:#fff;padding:20px;border:1px solid #ccd0d4;border-top:none;">
            <h3><?php esc_html_e('Sandbox Mode & Dry-Run Configuration', 'fingerprint-anti-bot'); ?></h3>
            <p class="description"><?php esc_html_e('Sandbox mode enables telemetry observation, diagnostic headers, and targeted IP testing. You can test actual challenges or opt into passive observation with Audit-Only mode.', 'fingerprint-anti-bot'); ?></p>

            <form method="post" action="">
                <?php wp_nonce_field('fingerprint_sandbox_nonce', 'fingerprint_nonce_sandbox'); ?>
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e('Sandbox Activation', 'fingerprint-anti-bot'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="sandbox_enabled" value="1" <?php checked($sandboxConfig['enabled']); ?>>
                                <strong><?php esc_html_e('Enable Sandbox Mode', 'fingerprint-anti-bot'); ?></strong>
                            </label>
                            <p class="description"><?php esc_html_e('Enables the sandbox testing environment with diagnostic headers and real-time telemetry streaming.', 'fingerprint-anti-bot'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Behavior & Enforcement', 'fingerprint-anti-bot'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="sandbox_audit_only" value="1" <?php checked($sandboxConfig['audit_only']); ?>>
                                <strong><?php esc_html_e('Audit Only / Dry-Run (Never block or challenge visitors)', 'fingerprint-anti-bot'); ?></strong>
                            </label>
                            <p class="description"><?php esc_html_e('Optional: Check this to bypass PoW challenges and blocking (pure observation). When unchecked, challenges and mitigations are actively enforced so you can test them live.', 'fingerprint-anti-bot'); ?></p>
                            <label>
                                <input type="checkbox" name="sandbox_add_headers" value="1" <?php checked($sandboxConfig['add_headers']); ?>>
                                <?php esc_html_e('Add diagnostic HTTP headers (X-Fingerprint-Sandbox: active)', 'fingerprint-anti-bot'); ?>
                            </label><br><br>
                            <label>
                                <input type="checkbox" name="sandbox_log_requests" value="1" <?php checked($sandboxConfig['log_requests']); ?>>
                                <?php esc_html_e('Log evaluated scores and suspicious attempts to PHP error_log', 'fingerprint-anti-bot'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="sandbox_ip_filter"><?php esc_html_e('Test IP Whitelist Filter', 'fingerprint-anti-bot'); ?></label></th>
                        <td>
                            <?php
                            // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
                            $currentAdminIp = isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '';
                            ?>
                            <input type="text" name="sandbox_ip_filter" id="sandbox_ip_filter" value="<?php echo esc_attr($sandboxConfig['ip_filter']); ?>" class="regular-text" placeholder="e.g. 192.168.1.100, 203.0.113.42">
                            <?php if (!empty($currentAdminIp)): ?>
                                <button type="button" class="button button-secondary button-small" onclick="document.getElementById('sandbox_ip_filter').value = '<?php echo esc_js($currentAdminIp); ?>';">
                                    <?php esc_html_e('Use my IP', 'fingerprint-anti-bot'); ?> (<?php echo esc_html($currentAdminIp); ?>)
                                </button>
                            <?php endif; ?>
                            <p class="description"><?php esc_html_e('Optional comma-separated list of IP addresses. If filled, Sandbox simulation applies ONLY to these IPs, while all other visitors remain under normal production protection.', 'fingerprint-anti-bot'); ?></p>
                        </td>
                    </tr>
                </table>

                <?php submit_button(esc_html__('Save Sandbox Settings', 'fingerprint-anti-bot'), 'primary', 'fingerprint_save_sandbox'); ?>
            </form>

            <hr>
            <!-- MONITEUR DES VISITEURS CHALLENGÉS EN DIRECT (SSE & REST) -->
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                <h3 style="margin:0;"><span class="dashicons dashicons-shield" style="vertical-align:text-bottom;"></span> <?php esc_html_e('Live Challenged Visitors & Suspicion Monitor', 'fingerprint-anti-bot'); ?></h3>
                <div>
                    <span style="font-weight:600;color:#646970;"><?php esc_html_e('Recent Challenges:', 'fingerprint-anti-bot'); ?></span>
                    <span id="live-challenges-count" style="display:inline-block;padding:2px 8px;background:#2271b1;color:#fff;border-radius:10px;font-weight:bold;font-size:12px;">0</span>
                </div>
            </div>
            <p class="description"><?php esc_html_e('Real-time feed of all visitors across the site who triggered a Proof-of-Work challenge, bot heuristic, or security mitigation.', 'fingerprint-anti-bot'); ?></p>

            <div style="background:#f6f7f7;padding:16px;border:1px solid #c3c4c7;border-radius:4px;margin-bottom:15px;">
                <div style="display:flex;gap:12px;align-items:center;margin-bottom:12px;flex-wrap:wrap;">
                    <button type="button" class="button button-primary" id="btn-toggle-sse" onclick="fingerprintToggleSSE();">
                        <span class="dashicons dashicons-controls-play" style="vertical-align:middle;"></span> <span id="sse-btn-text"><?php esc_html_e('Start Real-Time SSE Stream', 'fingerprint-anti-bot'); ?></span>
                    </button>
                    <button type="button" class="button button-secondary" onclick="fingerprintFetchTelemetry();">
                        <span class="dashicons dashicons-update" style="vertical-align:middle;"></span> <?php esc_html_e('Poll Now (REST)', 'fingerprint-anti-bot'); ?>
                    </button>
                    <button type="button" class="button button-secondary" onclick="fingerprintClearFeed();">
                        <span class="dashicons dashicons-trash" style="vertical-align:middle;"></span> <?php esc_html_e('Clear Feed', 'fingerprint-anti-bot'); ?>
                    </button>
                    <span id="sse-connection-status" style="font-weight:bold;color:#646970;"></span>
                </div>

                <div style="display:grid;grid-template-columns: 1.4fr 1fr;gap:16px;">
                    <!-- TABLEAU DES CHALLENGES EN DIRECT -->
                    <div style="background:#fff;padding:12px;border:1px solid #dcdcde;border-radius:4px;overflow-x:auto;">
                        <h4 style="margin:0 0 8px 0;"><?php esc_html_e('Challenged Visitors Stream (All Users)', 'fingerprint-anti-bot'); ?></h4>
                        <table class="wp-list-table widefat fixed striped" style="font-size:12px;">
                            <thead>
                                <tr>
                                    <th style="width:75px;"><?php esc_html_e('Time', 'fingerprint-anti-bot'); ?></th>
                                    <th style="width:110px;"><?php esc_html_e('IP', 'fingerprint-anti-bot'); ?></th>
                                    <th><?php esc_html_e('URI', 'fingerprint-anti-bot'); ?></th>
                                    <th style="width:50px;"><?php esc_html_e('Score', 'fingerprint-anti-bot'); ?></th>
                                    <th style="width:90px;"><?php esc_html_e('Action', 'fingerprint-anti-bot'); ?></th>
                                    <th style="width:70px;"></th>
                                </tr>
                            </thead>
                            <tbody id="live-challenges-tbody">
                                <tr><td colspan="6" style="text-align:center;color:#646970;padding:16px;"><em><?php esc_html_e('Awaiting incoming challenges...', 'fingerprint-anti-bot'); ?></em></td></tr>
                            </tbody>
                        </table>
                    </div>

                    <!-- DÉTAILS DU VECTEUR DE SUSPICION DU VISITEUR SÉLECTIONNÉ -->
                    <div style="background:#fff;padding:14px;border:1px solid #dcdcde;border-radius:4px;">
                        <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px;">
                            <h4 style="margin:0;"><?php esc_html_e('Inspection & Suspicion Vector', 'fingerprint-anti-bot'); ?></h4>
                            <div id="live-score-val" style="font-size:28px;font-weight:bold;color:#2271b1;line-height:1;">--</div>
                        </div>
                        <div id="live-score-sub" style="font-size:12px;color:#646970;background:#f6f7f7;padding:8px;border-radius:3px;margin-bottom:10px;">
                            <?php esc_html_e('Select an entry from the list to inspect its vector.', 'fingerprint-anti-bot'); ?>
                        </div>
                        <div id="live-vector-breakdown" style="font-family:monospace;font-size:12px;max-height:220px;overflow-y:auto;color:#2c3338;">
                            <em><?php esc_html_e('No entry selected.', 'fingerprint-anti-bot'); ?></em>
                        </div>
                    </div>
                </div>

                <div style="margin-top:12px;">
                    <details style="border:1px solid #c3c4c7;border-radius:4px;padding:10px 14px;background:#fff;">
                        <summary style="cursor:pointer;color:#2271b1;font-weight:600;font-size:14px;">
                            <span class="dashicons dashicons-book" style="vertical-align:text-bottom;"></span>
                            <?php esc_html_e('Documentation: API Endpoints & Live Suspicion Vector Stream', 'fingerprint-anti-bot'); ?>
                        </summary>
                        <div style="margin-top:12px;font-size:13px;line-height:1.6;color:#2c3338;">
                            <p><?php esc_html_e('During testing and sandbox analysis, you can inspect incoming requests, timestamps, evaluated scores, and behavioral indicator vectors using either HTTP REST, Server-Sent Events (SSE), or in-browser JavaScript events.', 'fingerprint-anti-bot'); ?></p>

                            <h4 style="margin:12px 0 6px 0;"><?php esc_html_e('1. Server-Sent Events (SSE) Stream — Continuous Real-Time Logs', 'fingerprint-anti-bot'); ?></h4>
                            <p><?php esc_html_e('Endpoint:', 'fingerprint-anti-bot'); ?> <code>GET <?php echo esc_url(rest_url('fingerprint/v1/sandbox/sse')); ?></code><br>
                            <small style="color:#646970;"><?php esc_html_e('Emits a timestamped "suspicion" event each time a request is evaluated for the current IP.', 'fingerprint-anti-bot'); ?></small></p>
                            <pre style="background:#f6f7f7;padding:10px;border:1px solid #dcdcde;border-radius:4px;font-size:12px;overflow-x:auto;">
<span style="color:#007017;">// JavaScript SSE subscriber example:</span>
const sse = new EventSource('<?php echo esc_url(rest_url('fingerprint/v1/sandbox/sse')); ?>');
sse.addEventListener('suspicion', (e) => {
    const entry = JSON.parse(e.data);
    console.log(`[${new Date(entry.timestamp * 1000).toISOString()}] IP: ${entry.ip} | Score: ${entry.suspicionScore}`, entry.suspicionVector);
});
sse.onerror = () => sse.close();
</pre>

                            <h4 style="margin:14px 0 6px 0;"><?php esc_html_e('2. REST Polling Endpoint — Last Evaluated Request', 'fingerprint-anti-bot'); ?></h4>
                            <p><?php esc_html_e('Endpoint:', 'fingerprint-anti-bot'); ?> <code>GET <?php echo esc_url(rest_url('fingerprint/v1/sandbox/telemetry')); ?></code></p>
                            <pre style="background:#f6f7f7;padding:10px;border:1px solid #dcdcde;border-radius:4px;font-size:12px;overflow-x:auto;">
<span style="color:#007017;"># CLI / Terminal cURL:</span>
curl -s -X GET "<?php echo esc_url(rest_url('fingerprint/v1/sandbox/telemetry')); ?>"

<span style="color:#007017;">// JSON Response Payload Structure:</span>
{
  "timestamp": 1740000000,
  "uri": "/checkout",
  "ip": "203.0.113.42",
  "suspicionScore": 38.5,
  "suspicionVector": {
    "headerAnomalyScore": 12.0,
    "tlsSpoofingScore": 0.0,
    "behaviorScore": 26.5
  },
  "sandbox": true
}
</pre>

                            <h4 style="margin:14px 0 6px 0;"><?php esc_html_e('3. Client-Side JavaScript DOM Event & Global Object', 'fingerprint-anti-bot'); ?></h4>
                            <p><?php esc_html_e('When Sandbox Mode is active (or when logged-in as an administrator), the evaluation data is injected directly into each rendered page.', 'fingerprint-anti-bot'); ?></p>
                            <pre style="background:#f6f7f7;padding:10px;border:1px solid #dcdcde;border-radius:4px;font-size:12px;overflow-x:auto;">
<span style="color:#007017;">// Option A: Listen for the CustomEvent fired on the document:</span>
document.addEventListener('fingerprint:suspicion', function(event) {
    console.log('Timestamp:', event.detail.timestamp);
    console.log('Active IP:', event.detail.ip);
    console.log('Target URI:', event.detail.uri);
    console.log('Score:', event.detail.suspicionScore);
    console.log('Vector breakdown:', event.detail.suspicionVector);
});

<span style="color:#007017;">// Option B: Read directly from the global window object:</span>
if (window.__FINGERPRINT_VECTOR__) {
    console.log('Current Request Vector:', window.__FINGERPRINT_VECTOR__.suspicionVector);
}
</pre>

                            <p style="margin-top:10px;font-size:12px;color:#646970;">
                                <strong><?php esc_html_e('Authorization note:', 'fingerprint-anti-bot'); ?></strong>
                                <?php esc_html_e('These diagnostic routes require administrator permissions (manage_options) OR an active Sandbox Mode. They are automatically rate-limited and protected against external abuse.', 'fingerprint-anti-bot'); ?>
                            </p>
                        </div>
                    </details>
                </div>
            </div>
        </div>

        <!-- TAB 2 : VUE DÉTAILLÉE DES MÉTRIQUES -->
        <div id="tab-metrics" class="fingerprint-tab-content" style="display:none;background:#fff;padding:20px;border:1px solid #ccd0d4;border-top:none;">
            <h3><?php esc_html_e('Behavioral & Transport Indicator Weights (Active Frontend Profile)', 'fingerprint-anti-bot'); ?></h3>
            <p class="description"><?php echo wp_kses_post(__('The final score of each request is computed using the weighted sum: <code>Score = &Sigma; (Metric &times; Weight)</code>.', 'fingerprint-anti-bot')); ?></p>

            <form method="post" action="">
                <?php wp_nonce_field('fingerprint_settings_nonce', 'fingerprint_nonce'); ?>
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th style="width:280px;"><?php esc_html_e('Indicator / Metric', 'fingerprint-anti-bot'); ?></th>
                            <th style="width:120px;"><?php esc_html_e('Current Weight', 'fingerprint-anti-bot'); ?></th>
                            <th><?php esc_html_e('Description & Detection Role', 'fingerprint-anti-bot'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php
                        $metricDescriptions = [
                            'honeypotScore'              => __('Triggering of invisible trap links, multi-framework honeypots, and injection probes.', 'fingerprint-anti-bot'),
                            'headerAnomalyScore'         => __('Missing, malformed, or out-of-order HTTP headers inconsistent with legitimate browsers.', 'fingerprint-anti-bot'),
                            'tlsSpoofingScore'           => __('Discrepancy between User-Agent and TLS cryptographic fingerprints (JA3/JA4, extensions, GREASE).', 'fingerprint-anti-bot'),
                            'behaviorScore'              => __('Dynamic biometrics: mouse movements, keystroke dynamics, and mobile touch anomalies.', 'fingerprint-anti-bot'),
                            'requestPatternScore'        => __('Velocity, robotic bursts, request standard deviation, and Benford\'s law statistical analysis.', 'fingerprint-anti-bot'),
                            'inconsistencyScore'         => __('Alteration or drift in the hardware fingerprint between visits with the same cookie.', 'fingerprint-anti-bot'),
                            'subnetScore'                => __('Aggregated IP reputation of the network subnet (/24 or /48) and nearby attacker density.', 'fingerprint-anti-bot'),
                            'ipReputationScore'          => __('Local historical reputation score of the client IP address with temporal decay over time.', 'fingerprint-anti-bot'),
                            'renderingAnomalyScore'      => __('Display rendering anomalies, V-Sync/FPS cadence, and OffscreenCanvas hooking.', 'fingerprint-anti-bot'),
                            'protocolAnomalyScore'       => __('Divergence in HTTP/2 and QUIC / HTTP/3 flow control frame settings.', 'fingerprint-anti-bot'),
                            'quicAnomalyScore'           => __('Anomalies in QUIC transport parameters (flow control windows, max streams, and control frame ordering).', 'fingerprint-anti-bot'),
                            'tcpAnomalyScore'            => __('Passive TCP/IP stack fingerprinting (SYN packet TTL, window size, MSS, options) vs declared operating system.', 'fingerprint-anti-bot'),
                            'historyScore'               => __('Suspicious rotation of multiple IP addresses associated with a single hardware identity.', 'fingerprint-anti-bot'),
                            'rotationScore'              => __('Rapid and abnormal modifications to the application stack.', 'fingerprint-anti-bot'),
                            'botScore'                   => __('Detection of native automation attributes (navigator.webdriver, Chrome CDP).', 'fingerprint-anti-bot'),
                            'cookieDroppingScore'        => __('Detection of cookie deletion, dropping, or refusal between consecutive requests to bypass device identification.', 'fingerprint-anti-bot'),
                            'threatIntelScore'           => __('Correlation with known proxy IPs, Tor exit nodes, and federated threat intelligence blacklist.', 'fingerprint-anti-bot'),
                            'clientHintsInconsistencyScore' => __('Discrepancies between standard User-Agent and Sec-CH-UA Client Hints headers (browser family, version drift).', 'fingerprint-anti-bot'),
                            'clickVarianceScore'         => __('Statistical analysis of click coordinate variance; flags unnaturally low pixel variance typical of click bots.', 'fingerprint-anti-bot'),
                            'botnetClusterScore'         => __('Clustering of volatile client requests sharing identical hardware signatures across distinct IP addresses.', 'fingerprint-anti-bot'),
                            'timeInconsistencyScore'     => __('Time delta between client timestamp and server reception to detect replay and automated delay attacks.', 'fingerprint-anti-bot'),
                            'virtualizationScore'        => __('Detection of headless browsers, virtual GPU renderers (SwiftShader, llvmpipe) and emulated display resolutions.', 'fingerprint-anti-bot'),
                            'crossLayerInconsistencyScore' => __('Strict contradiction between layers (e.g. declared OS in User-Agent vs network TCP/IP stack OS).', 'fingerprint-anti-bot'),
                        ];

                        foreach ($frontendConfig['weights'] as $indicator => $weight):
                            $desc = $metricDescriptions[$indicator] ?? __('Behavioral suspicion indicator.', 'fingerprint-anti-bot');
                        ?>
                        <tr>
                            <td><code><?php echo esc_html($indicator); ?></code></td>
                            <td>
                                <input type="number" step="0.05" min="0" max="2.0" name="weight_<?php echo esc_attr($indicator); ?>" value="<?php echo esc_attr((string)$weight); ?>" style="width:75px;">
                            </td>
                            <td><?php echo esc_html($desc); ?></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
                <p style="margin-top:16px;">
                    <?php submit_button(esc_html__('Update Metric Weights', 'fingerprint-anti-bot'), 'primary', 'fingerprint_save_settings', false); ?>
                </p>
            </form>
        </div>

        <!-- TAB 3 : FLUX PROMETHEUS -->
        <div id="tab-prometheus" class="fingerprint-tab-content" style="display:none;background:#fff;padding:20px;border:1px solid #ccd0d4;border-top:none;">
            <h3><?php esc_html_e('Real-Time Prometheus Metrics', 'fingerprint-anti-bot'); ?></h3>
            <p class="description"><?php esc_html_e('Raw text format exported for scraping by Prometheus, Grafana Agent, or Datadog.', 'fingerprint-anti-bot'); ?></p>
            <textarea readonly style="width:100%;height:380px;font-family:monospace;background:#f6f7f7;padding:12px;"><?php echo esc_textarea($prometheusRaw); ?></textarea>
        </div>
    </div>

    <script>
    function fingerprintSwitchTab(evt, tabId) {
        evt.preventDefault();
        const tabs = document.querySelectorAll('.fingerprint-tab-content');
        tabs.forEach(t => t.style.display = 'none');
        const navs = document.querySelectorAll('.nav-tab-wrapper a');
        navs.forEach(n => n.classList.remove('nav-tab-active'));
        document.getElementById(tabId).style.display = 'block';
        evt.currentTarget.classList.add('nav-tab-active');
        if (window.location.hash !== '#' + tabId && history.pushState) {
            history.pushState(null, null, '#' + tabId);
        }
    }

    document.addEventListener('DOMContentLoaded', function() {
        const hash = window.location.hash;
        if (hash) {
            const targetId = hash.replace('#', '');
            const targetContent = document.getElementById(targetId);
            const targetLink = document.querySelector('.nav-tab-wrapper a[href="' + hash + '"]');
            if (targetContent && targetLink) {
                document.querySelectorAll('.fingerprint-tab-content').forEach(function(t) {
                    t.style.display = 'none';
                });
                document.querySelectorAll('.nav-tab-wrapper a').forEach(function(n) {
                    n.classList.remove('nav-tab-active');
                });
                targetContent.style.display = 'block';
                targetLink.classList.add('nav-tab-active');
            }
        }
    });

    // Client SSE & Polling pour le Moniteur de Suspicion Vector
    let sseSource = null;
    let challengesHistory = [];
    let selectedChallengeId = null;
    const wpRestNonce = '<?php echo esc_js(wp_create_nonce('wp_rest')); ?>';

    function fingerprintToggleSSE() {
        const statusEl = document.getElementById('sse-connection-status');
        const btnText = document.getElementById('sse-btn-text');
        if (sseSource) {
            sseSource.close();
            sseSource = null;
            statusEl.textContent = '<?php echo esc_js(__('SSE Disconnected', 'fingerprint-anti-bot')); ?>';
            statusEl.style.color = '#646970';
            btnText.textContent = '<?php echo esc_js(__('Start Real-Time SSE Stream', 'fingerprint-anti-bot')); ?>';
            return;
        }

        statusEl.textContent = '<?php echo esc_js(__('Connecting to SSE stream...', 'fingerprint-anti-bot')); ?>';
        statusEl.style.color = '#2271b1';
        sseSource = new EventSource('<?php echo esc_url(rest_url('fingerprint/v1/sandbox/sse')); ?>?_wpnonce=' + wpRestNonce);

        sseSource.onopen = function() {
            statusEl.textContent = '<?php echo esc_js(__('SSE Live Connected', 'fingerprint-anti-bot')); ?>';
            statusEl.style.color = '#007017';
            btnText.textContent = '<?php echo esc_js(__('Stop Stream', 'fingerprint-anti-bot')); ?>';
        };

        sseSource.addEventListener('challenge', function(e) {
            try {
                const newChallenge = JSON.parse(e.data);
                if (!challengesHistory.some(c => c.id === newChallenge.id)) {
                    challengesHistory.unshift(newChallenge);
                    if (challengesHistory.length > 50) {
                        challengesHistory.pop();
                    }
                    selectedChallengeId = newChallenge.id;
                    renderChallengesUI();
                }
            } catch(err) {}
        });

        sseSource.onerror = function() {
            statusEl.textContent = '<?php echo esc_js(__('SSE Reconnecting...', 'fingerprint-anti-bot')); ?>';
            statusEl.style.color = '#d63638';
        };
    }

    function fingerprintFetchTelemetry() {
        fetch('<?php echo esc_url(rest_url('fingerprint/v1/sandbox/telemetry')); ?>', {
            headers: { 'X-WP-Nonce': wpRestNonce }
        })
            .then(res => res.json())
            .then(data => {
                if (data && Array.isArray(data.history)) {
                    challengesHistory = data.history;
                    renderChallengesUI();
                }
            })
            .catch(err => console.error(err));
    }

    function fingerprintClearFeed() {
        if (!confirm('<?php echo esc_js(__('Clear the live challenged visitors feed?', 'fingerprint-anti-bot')); ?>')) {
            return;
        }
        fetch('<?php echo esc_url(rest_url('fingerprint/v1/sandbox/clear-challenges')); ?>', {
            method: 'POST',
            headers: { 'X-WP-Nonce': wpRestNonce }
        })
            .then(() => {
                challengesHistory = [];
                selectedChallengeId = null;
                renderChallengesUI();
            })
            .catch(err => console.error(err));
    }

    function renderChallengesUI() {
        const tableBody = document.getElementById('live-challenges-tbody');
        const countEl = document.getElementById('live-challenges-count');
        countEl.textContent = challengesHistory.length;

        if (!challengesHistory.length) {
            tableBody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:#646970;padding:16px;"><em><?php echo esc_js(__('No challenged visitors recorded yet. When a visitor triggers a challenge or bot threshold, it will appear here in real time.', 'fingerprint-anti-bot')); ?></em></td></tr>';
            renderDetailView(null);
            return;
        }

        let rowsHtml = '';
        challengesHistory.forEach((item, index) => {
            const isSelected = item.id === selectedChallengeId || (!selectedChallengeId && index === 0);
            if (isSelected && !selectedChallengeId) {
                selectedChallengeId = item.id;
            }

            const date = item.timestamp ? new Date(item.timestamp * 1000).toLocaleTimeString() : '--:--:--';
            const score = item.suspicionScore !== undefined ? Math.round(item.suspicionScore) : 0;
            const scoreColor = score >= 75 ? '#d63638' : (score >= 40 ? '#dba617' : '#2271b1');
            const actionBadge = (item.action || 'challenge').toUpperCase();
            const actionBg = actionBadge.includes('BLOCK') ? '#d63638' : (actionBadge.includes('AUDIT') ? '#72aee6' : '#dba617');

            rowsHtml += `<tr style="cursor:pointer;background:${isSelected ? '#f0f6fc' : 'transparent'};" onclick="fingerprintSelectChallenge('${item.id}')">
                <td><b>${date}</b></td>
                <td><code>${escapeHtml(item.ip || 'unknown')}</code></td>
                <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escapeHtml(item.uri || '/')}"><code>${escapeHtml(item.uri || '/')}</code></td>
                <td><span style="font-weight:bold;color:${scoreColor};">${score}</span></td>
                <td><span style="display:inline-block;padding:2px 6px;border-radius:3px;font-size:11px;font-weight:bold;color:#fff;background:${actionBg};">${escapeHtml(actionBadge)}</span></td>
                <td><button type="button" class="button button-small button-secondary">${isSelected ? '&#9654; View' : 'Inspect'}</button></td>
            </tr>`;
        });

        tableBody.innerHTML = rowsHtml;
        const selectedItem = challengesHistory.find(c => c.id === selectedChallengeId) || challengesHistory[0];
        renderDetailView(selectedItem);
    }

    function renderDetailView(item) {
        const detailScore = document.getElementById('live-score-val');
        const detailSub = document.getElementById('live-score-sub');
        const breakdownEl = document.getElementById('live-vector-breakdown');

        if (!item) {
            detailScore.textContent = '--';
            detailScore.style.color = '#2271b1';
            detailSub.textContent = '<?php echo esc_js(__('Select an entry from the list to inspect its vector.', 'fingerprint-anti-bot')); ?>';
            breakdownEl.innerHTML = '<em><?php echo esc_js(__('No entry selected.', 'fingerprint-anti-bot')); ?></em>';
            return;
        }

        const score = item.suspicionScore !== undefined ? Math.round(item.suspicionScore) : 0;
        detailScore.textContent = score;
        detailScore.style.color = score >= 75 ? '#d63638' : (score >= 40 ? '#dba617' : '#2271b1');
        detailSub.innerHTML = `<b>IP:</b> ${escapeHtml(item.ip || 'unknown')}<br><b>Target:</b> ${escapeHtml(item.uri || '/')}<br><b>Action:</b> ${escapeHtml(item.action || 'challenge')}`;

        const vector = item.suspicionVector || {};
        const keys = Object.keys(vector);
        if (keys.length === 0) {
            breakdownEl.innerHTML = '<em><?php echo esc_js(__('No indicators recorded for this entry.', 'fingerprint-anti-bot')); ?></em>';
            return;
        }
        let html = '<table style="width:100%;border-collapse:collapse;font-size:12px;">';
        keys.forEach(k => {
            html += `<tr style="border-bottom:1px solid #f0f0f1;"><td style="padding:3px 6px;"><b>${escapeHtml(k)}</b></td><td style="padding:3px 6px;text-align:right;"><code>${escapeHtml(JSON.stringify(vector[k]))}</code></td></tr>`;
        });
        html += '</table>';
        breakdownEl.innerHTML = html;
    }

    function fingerprintSelectChallenge(id) {
        selectedChallengeId = id;
        renderChallengesUI();
    }

    function escapeHtml(str) {
        return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    // Chargement automatique des derniers challenges à l'ouverture
    document.addEventListener('DOMContentLoaded', function() {
        fingerprintFetchTelemetry();
    });
    </script>
    <?php
}