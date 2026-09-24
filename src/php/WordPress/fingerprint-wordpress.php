<?php
/**
 * Plugin Name: Fingerprint Anti-Bot & Proof-of-Work
 * Plugin URI: https://github.com/anonympins/fingerprint
 * Description: High-performance client-side anti-bot protection and Proof-of-Work challenge verification for WordPress.
 * Version: 0.7.1
 * Author: Anonympins
 * License: MIT
 * Text Domain: fingerprint-wordpress
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
$foreignEnvTrapUrls = [
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

$foreignEnvHoneypotFields = [
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
$fingerprintSecurityProfiles = [
    'api' => [
        'profile'   => 'api',
        'overrides' => [
            'verbose'             => false,
            'challengeNewDevices' => false,
            'honeypot'            => [
                'fields'           => $foreignEnvHoneypotFields,
                'trapUrls'         => $foreignEnvTrapUrls,
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
                'fields'           => $foreignEnvHoneypotFields,
                'trapUrls'         => $foreignEnvTrapUrls,
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
                'fields'           => $foreignEnvHoneypotFields,
                'trapUrls'         => $foreignEnvTrapUrls,
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

// Chargement du domaine de traduction i18n (FR / EN / DE)
add_action('init', function (): void {
    load_plugin_textdomain('fingerprint-wordpress', false, dirname(plugin_basename(__FILE__)) . '/languages');
});

// 1. Autoloader PSR-4 pour le moteur Fingerprint
if (!class_exists(DirectFingerprint::class)) {
    $composerPaths = [
        __DIR__ . '/vendor/autoload.php',
        dirname(__DIR__, 2) . '/vendor/autoload.php',
        dirname(__DIR__, 3) . '/vendor/autoload.php',
        (defined('ABSPATH') ? ABSPATH . 'vendor/autoload.php' : ''),
    ];
    foreach ($composerPaths as $cPath) {
        if (!empty($cPath) && file_exists($cPath)) {
            require_once $cPath;
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
        echo '<p><strong>' . esc_html__('[Fingerprint Anti-Bot Security Warning]', 'fingerprint-wordpress') . '</strong> : ' .
            esc_html__('Your website is currently running on unencrypted HTTP. In this mode, modern web browsers disable the native Web Cryptography API (crypto.subtle) for security reasons, forcing a JavaScript fallback simulation that is slower and vulnerable to Man-in-the-Middle (MitM) attacks. We strongly recommend deploying a TLS/SSL certificate and enforcing HTTPS to ensure the cryptographic integrity of Proof-of-Work computations and identity protection.', 'fingerprint-wordpress') .
            '</p>';
        echo '</div>';
    }
});

// 6. Interception de sécurité au plus tôt du cycle de vie WordPress
add_action('plugins_loaded', function () use ($fingerprintSecurityProfiles) {
    // Ignore WP-CLI et les exécutions internes de cron
    if ((defined('WP_CLI') && WP_CLI) || (defined('DOING_CRON') && DOING_CRON)) {
        return;
    }

    // Initialiser le Store persistant basé sur $wpdb
    $store = new WpDbStore();
    StoreManager::configureStore($store);

    $requestUri = $_SERVER['REQUEST_URI'] ?? '/';
    $isRestApi = defined('REST_REQUEST') && REST_REQUEST;
    $isAdmin = is_admin() || str_contains($requestUri, 'wp-login.php');

    // Fusion avec les options enregistrées via l'admin WP
    $effectiveProfiles = fingerprint_get_effective_profiles($fingerprintSecurityProfiles);

    // Possibilité de filtrer la configuration via functions.php ou un thème
    $configs = apply_filters('fingerprint_security_profiles', $effectiveProfiles);

    // Sélection adaptative du profil selon la cible de la requête
    if ($isRestApi || str_starts_with($requestUri, '/wp-json/')) {
        $contextConfig = $configs['api'] ?? $fingerprintSecurityProfiles['api'];
    } elseif ($isAdmin) {
        $contextConfig = $configs['admin'] ?? $fingerprintSecurityProfiles['admin'];
    } else {
        $contextConfig = $configs['frontend'] ?? $fingerprintSecurityProfiles['frontend'];
    }

    $securityConfig = SecurityProfiles::createSecurityProfile($contextConfig['profile'], $contextConfig['overrides'] ?? []);
    $guard = new DirectFingerprint($securityConfig);

    // Inspecte la requête : bloque ou envoie le challenge si nécessaire et stoppe le script
    $guard->protect();
}, 0);

// =============================================================================
// INTERFACE D'ADMINISTRATION, RÉGLAGES & INSPECTION DES MÉTRIQUES
// =============================================================================

add_action('admin_menu', function () {
    add_options_page(
        __('Fingerprint Anti-Bot', 'fingerprint-wordpress'),
        'Fingerprint Anti-Bot',
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
        wp_die(esc_html__('You do not have sufficient permissions to access this page.', 'fingerprint-wordpress'));
    }

    global $fingerprintSecurityProfiles, $wpdb;

    // Sauvegarde des réglages
    if (isset($_POST['fingerprint_save_settings']) && check_admin_referer('fingerprint_settings_nonce', 'fingerprint_nonce')) {
        $saved = get_option('fingerprint_security_options', []);
        if (!is_array($saved)) {
            $saved = [];
        }

        // Profils sélectionnés
        $saved['frontend']['profile'] = sanitize_text_field($_POST['frontend_profile'] ?? 'blog');
        $saved['admin']['profile']    = sanitize_text_field($_POST['admin_profile'] ?? 'strict');
        $saved['api']['profile']      = sanitize_text_field($_POST['api_profile'] ?? 'api');

        // Seuils Frontend
        $saved['frontend']['overrides']['thresholds'] = [
            'low'    => max(1, (int)($_POST['frontend_threshold_low'] ?? 20)),
            'medium' => max(5, (int)($_POST['frontend_threshold_medium'] ?? 45)),
            'high'   => max(10, (int)($_POST['frontend_threshold_high'] ?? 75)),
            'block'  => max(20, (int)($_POST['frontend_threshold_block'] ?? 95)),
        ];

        // Options booléennes
        $saved['frontend']['overrides']['challengeNewDevices'] = !empty($_POST['frontend_challenge_new']);
        $saved['frontend']['overrides']['verbose']             = !empty($_POST['frontend_verbose']);
        $saved['frontend']['overrides']['honeypot']['detectInjections'] = !empty($_POST['detect_injections']);

        // Surcharges de poids clés
        $weightsKeys = [
            'honeypotScore', 'tlsSpoofingScore', 'behaviorScore', 'requestPatternScore',
            'inconsistencyScore', 'subnetScore', 'renderingAnomalyScore', 'protocolAnomalyScore'
        ];
        foreach ($weightsKeys as $wKey) {
            if (isset($_POST["weight_{$wKey}"])) {
                $val = (float)$_POST["weight_{$wKey}"];
                $saved['frontend']['overrides']['weights'][$wKey] = max(0.0, min(2.0, $val));
            }
        }

        update_option('fingerprint_security_options', $saved);
        echo '<div class="notice notice-success is-dismissible"><p><strong>' . esc_html__('Fingerprint settings updated successfully.', 'fingerprint-wordpress') . '</strong></p></div>';
    }

    // Action pour vider le cache SQL manuellement
    if (isset($_POST['fingerprint_clear_store']) && check_admin_referer('fingerprint_clear_nonce', 'fingerprint_nonce_clear')) {
        $store = new WpDbStore();
        $store->clear();
        echo '<div class="notice notice-info is-dismissible"><p>' . esc_html__('SQL cache table ($wpdb) cleared successfully.', 'fingerprint-wordpress') . '</p></div>';
    }

    // Récupération des profils effectifs
    $effective = fingerprint_get_effective_profiles($fingerprintSecurityProfiles);
    $frontendConfig = SecurityProfiles::createSecurityProfile($effective['frontend']['profile'], $effective['frontend']['overrides'] ?? []);

    // Statistiques de la table de cache SQL
    $tableName = $wpdb->prefix . 'fingerprint_store';
    $totalRows = (int)$wpdb->get_var("SELECT COUNT(*) FROM {$tableName}");
    $now = time();
    $expiredRows = (int)$wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$tableName} WHERE expires_at IS NOT NULL AND expires_at < %d", $now));

    // Métriques Prometheus au format texte
    $prometheusRaw = MetricsManager::getPrometheusMetrics($frontendConfig);
    ?>
    <div class="wrap">
        <h1><span class="dashicons dashicons-shield-alt" style="font-size:32px;vertical-align:middle;margin-right:8px;"></span> Fingerprint Anti-Bot & Proof-of-Work</h1>
        <p class="description"><?php esc_html_e('Client-side behavioral and cryptographic anti-bot protection without third-party CAPTCHA for WordPress.', 'fingerprint-wordpress'); ?></p>

        <div style="background:#fff;border-left:4px solid #2271b1;padding:12px 18px;margin:18px 0;box-shadow:0 1px 1px rgba(0,0,0,.04);">
            <p style="margin:4px 0;">
                <strong><?php esc_html_e('Official documentation reference:', 'fingerprint-wordpress'); ?></strong>
                <a href="https://github.com/anonympins/fingerprint/blob/main/doc/full_options.md" target="_blank" rel="noopener noreferrer" class="button button-secondary" style="margin-left:8px;">
                    <span class="dashicons dashicons-external" style="vertical-align:middle;"></span> <?php esc_html_e('View Full Configuration Options on GitHub', 'fingerprint-wordpress'); ?>
                </a>
                <a href="https://github.com/anonympins/fingerprint" target="_blank" rel="noopener noreferrer" class="button button-secondary" style="margin-left:4px;">
                    <span class="dashicons dashicons-admin-plugins" style="vertical-align:middle;"></span> <?php esc_html_e('GitHub Repository', 'fingerprint-wordpress'); ?>
                </a>
            </p>
        </div>

        <!-- TABLEAU DE BORD STATISTIQUES & ÉTAT -->
        <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(240px, 1fr));gap:16px;margin-bottom:24px;">
            <div style="background:#fff;padding:16px;border-radius:4px;border:1px solid #ccd0d4;">
                <h3 style="margin-top:0;"><?php esc_html_e('HTTPS Status', 'fingerprint-wordpress'); ?></h3>
                <?php if (is_ssl()): ?>
                    <p style="color:#007017;font-weight:bold;font-size:16px;">
                        <span class="dashicons dashicons-yes-alt"></span> <?php esc_html_e('Active (WebCrypto Subtle available)', 'fingerprint-wordpress'); ?>
                    </p>
                <?php else: ?>
                    <p style="color:#d63638;font-weight:bold;font-size:16px;">
                        <span class="dashicons dashicons-warning"></span> <?php esc_html_e('Insecure (Unencrypted HTTP)', 'fingerprint-wordpress'); ?>
                    </p>
                <?php endif; ?>
            </div>
            <div style="background:#fff;padding:16px;border-radius:4px;border:1px solid #ccd0d4;">
                <h3 style="margin-top:0;"><?php esc_html_e('SQL Cache ($wpdb)', 'fingerprint-wordpress'); ?></h3>
                <p style="font-size:22px;margin:0;font-weight:600;"><?php echo esc_html((string)$totalRows); ?> <span style="font-size:14px;color:#646970;font-weight:normal;"><?php esc_html_e('keys in database', 'fingerprint-wordpress'); ?></span></p>
                <small style="color:#8c8f94;"><?php echo sprintf(esc_html__('%d expired keys awaiting cron purge', 'fingerprint-wordpress'), $expiredRows); ?></small>
            </div>
            <div style="background:#fff;padding:16px;border-radius:4px;border:1px solid #ccd0d4;">
                <h3 style="margin-top:0;"><?php esc_html_e('Active Profiles', 'fingerprint-wordpress'); ?></h3>
                <p style="margin:0;">
                    <?php esc_html_e('Frontend:', 'fingerprint-wordpress'); ?> <strong><?php echo esc_html($effective['frontend']['profile']); ?></strong><br>
                    <?php esc_html_e('Admin:', 'fingerprint-wordpress'); ?> <strong><?php echo esc_html($effective['admin']['profile']); ?></strong><br>
                    <?php esc_html_e('REST API:', 'fingerprint-wordpress'); ?> <strong><?php echo esc_html($effective['api']['profile']); ?></strong>
                </p>
            </div>
        </div>

        <!-- ONGLETS DE NAVIGATION -->
        <h2 class="nav-tab-wrapper">
            <a href="#tab-settings" class="nav-tab nav-tab-active" onclick="fingerprintSwitchTab(event, 'tab-settings')"><?php esc_html_e('Settings & Profiles', 'fingerprint-wordpress'); ?></a>
            <a href="#tab-metrics" class="nav-tab" onclick="fingerprintSwitchTab(event, 'tab-metrics')"><?php esc_html_e('Metrics & Weights View', 'fingerprint-wordpress'); ?></a>
            <a href="#tab-prometheus" class="nav-tab" onclick="fingerprintSwitchTab(event, 'tab-prometheus')"><?php esc_html_e('Prometheus Stream', 'fingerprint-wordpress'); ?></a>
        </h2>

        <!-- TAB 1 : RÉGLAGES -->
        <div id="tab-settings" class="fingerprint-tab-content" style="background:#fff;padding:20px;border:1px solid #ccd0d4;border-top:none;">
            <form method="post" action="">
                <?php wp_nonce_field('fingerprint_settings_nonce', 'fingerprint_nonce'); ?>

                <h3><?php esc_html_e('1. Target Security Profiles', 'fingerprint-wordpress'); ?></h3>
                <table class="form-table">
                    <tr>
                        <th scope="row"><label for="frontend_profile"><?php esc_html_e('Visitors & Frontend', 'fingerprint-wordpress'); ?></label></th>
                        <td>
                            <select name="frontend_profile" id="frontend_profile">
                                <option value="blog" <?php selected($effective['frontend']['profile'], 'blog'); ?>><?php esc_html_e('Blog (Optimal for content, smooth UX)', 'fingerprint-wordpress'); ?></option>
                                <option value="balanced" <?php selected($effective['frontend']['profile'], 'balanced'); ?>><?php esc_html_e('Balanced (General purpose)', 'fingerprint-wordpress'); ?></option>
                                <option value="strict" <?php selected($effective['frontend']['profile'], 'strict'); ?>><?php esc_html_e('Strict (Maximum protection)', 'fingerprint-wordpress'); ?></option>
                                <option value="ecommerce" <?php selected($effective['frontend']['profile'], 'ecommerce'); ?>><?php esc_html_e('E-commerce (Anti-scraping / scalping)', 'fingerprint-wordpress'); ?></option>
                            </select>
                            <p class="description"><?php esc_html_e('Profile applied to all public pages of the WordPress site.', 'fingerprint-wordpress'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="admin_profile"><?php esc_html_e('Administration Area (wp-login / wp-admin)', 'fingerprint-wordpress'); ?></label></th>
                        <td>
                            <select name="admin_profile" id="admin_profile">
                                <option value="strict" <?php selected($effective['admin']['profile'], 'strict'); ?>><?php esc_html_e('Strict (Recommended to secure logins)', 'fingerprint-wordpress'); ?></option>
                                <option value="balanced" <?php selected($effective['admin']['profile'], 'balanced'); ?>><?php esc_html_e('Balanced', 'fingerprint-wordpress'); ?></option>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="api_profile"><?php esc_html_e('REST API (/wp-json/)', 'fingerprint-wordpress'); ?></label></th>
                        <td>
                            <select name="api_profile" id="api_profile">
                                <option value="api" <?php selected($effective['api']['profile'], 'api'); ?>><?php esc_html_e('API (JSON challenges & machine PoW)', 'fingerprint-wordpress'); ?></option>
                                <option value="strict" <?php selected($effective['api']['profile'], 'strict'); ?>><?php esc_html_e('Strict', 'fingerprint-wordpress'); ?></option>
                            </select>
                        </td>
                    </tr>
                </table>

                <hr>

                <h3><?php esc_html_e('2. Action Thresholds (Frontend)', 'fingerprint-wordpress'); ?></h3>
                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e('Suspicion Score Thresholds (0 - 100)', 'fingerprint-wordpress'); ?></th>
                        <td>
                            <label><?php esc_html_e('Low (Initial challenge):', 'fingerprint-wordpress'); ?>
                                <input type="number" name="frontend_threshold_low" value="<?php echo esc_attr((string)($frontendConfig['thresholds']['low'] ?? 20)); ?>" min="1" max="50" style="width:80px;">
                            </label><br><br>
                            <label><?php esc_html_e('Medium (Hardened challenge):', 'fingerprint-wordpress'); ?>
                                <input type="number" name="frontend_threshold_medium" value="<?php echo esc_attr((string)($frontendConfig['thresholds']['medium'] ?? 45)); ?>" min="10" max="75" style="width:80px;">
                            </label><br><br>
                            <label><?php esc_html_e('High (Heavy Proof-of-Work):', 'fingerprint-wordpress'); ?>
                                <input type="number" name="frontend_threshold_high" value="<?php echo esc_attr((string)($frontendConfig['thresholds']['high'] ?? 75)); ?>" min="30" max="95" style="width:80px;">
                            </label><br><br>
                            <label><?php esc_html_e('Block (Immediate 403 Forbidden):', 'fingerprint-wordpress'); ?>
                                <input type="number" name="frontend_threshold_block" value="<?php echo esc_attr((string)($frontendConfig['thresholds']['block'] ?? 95)); ?>" min="50" max="100" style="width:80px;">
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Advanced Behaviors', 'fingerprint-wordpress'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="frontend_challenge_new" value="1" <?php checked(!empty($frontendConfig['challengeNewDevices'])); ?>>
                                <?php esc_html_e('Automatically challenge unknown new devices (without device_id cookie)', 'fingerprint-wordpress'); ?>
                            </label><br>
                            <label>
                                <input type="checkbox" name="detect_injections" value="1" <?php checked(!empty($frontendConfig['honeypot']['detectInjections'])); ?>>
                                <?php esc_html_e('Enable recursive WAF inspection (SQL, NoSQL, Log4j, Traversal in GET/POST)', 'fingerprint-wordpress'); ?>
                            </label><br>
                            <label>
                                <input type="checkbox" name="frontend_verbose" value="1" <?php checked(!empty($frontendConfig['verbose'])); ?>>
                                <?php esc_html_e('Verbose mode in PHP logs (Debugging)', 'fingerprint-wordpress'); ?>
                            </label>
                        </td>
                    </tr>
                </table>

                <?php submit_button(esc_html__('Save Changes', 'fingerprint-wordpress'), 'primary', 'fingerprint_save_settings'); ?>
            </form>

            <hr>
            <form method="post" action="" style="margin-top:16px;">
                <?php wp_nonce_field('fingerprint_clear_nonce', 'fingerprint_nonce_clear'); ?>
                <p>
                    <strong><?php esc_html_e('Store Maintenance:', 'fingerprint-wordpress'); ?></strong>
                    <button type="submit" name="fingerprint_clear_store" class="button button-secondary" onclick="return confirm('<?php echo esc_js(__('Purge all stored sessions and nonces?', 'fingerprint-wordpress')); ?>');">
                        <?php esc_html_e('Clear SQL cache table ($wpdb)', 'fingerprint-wordpress'); ?>
                    </button>
                </p>
            </form>
        </div>

        <!-- TAB 2 : VUE DÉTAILLÉE DES MÉTRIQUES -->
        <div id="tab-metrics" class="fingerprint-tab-content" style="display:none;background:#fff;padding:20px;border:1px solid #ccd0d4;border-top:none;">
            <h3><?php esc_html_e('Behavioral & Transport Indicator Weights (Active Frontend Profile)', 'fingerprint-wordpress'); ?></h3>
            <p class="description"><?php echo wp_kses_post(__('The final score of each request is computed using the weighted sum: <code>Score = &Sigma; (Metric &times; Weight)</code>.', 'fingerprint-wordpress')); ?></p>

            <form method="post" action="">
                <?php wp_nonce_field('fingerprint_settings_nonce', 'fingerprint_nonce'); ?>
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th style="width:280px;"><?php esc_html_e('Indicator / Metric', 'fingerprint-wordpress'); ?></th>
                            <th style="width:120px;"><?php esc_html_e('Current Weight', 'fingerprint-wordpress'); ?></th>
                            <th><?php esc_html_e('Description & Detection Role', 'fingerprint-wordpress'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php
                        $metricDescriptions = [
                            'honeypotScore'              => __('Triggering of invisible trap links, multi-framework honeypots, and injection probes.', 'fingerprint-wordpress'),
                            'tlsSpoofingScore'           => __('Discrepancy between User-Agent and TLS cryptographic fingerprints (JA3/JA4, extensions, GREASE).', 'fingerprint-wordpress'),
                            'behaviorScore'              => __('Dynamic biometrics: mouse movements, keystroke dynamics, and mobile touch anomalies.', 'fingerprint-wordpress'),
                            'requestPatternScore'        => __('Velocity, robotic bursts, request standard deviation, and Benford\'s law statistical analysis.', 'fingerprint-wordpress'),
                            'inconsistencyScore'         => __('Alteration or drift in the hardware fingerprint between visits with the same cookie.', 'fingerprint-wordpress'),
                            'subnetScore'                => __('Aggregated IP reputation of the network subnet (/24 or /48) and nearby attacker density.', 'fingerprint-wordpress'),
                            'renderingAnomalyScore'      => __('Display rendering anomalies, V-Sync/FPS cadence, and OffscreenCanvas hooking.', 'fingerprint-wordpress'),
                            'protocolAnomalyScore'       => __('Divergence in HTTP/2 and QUIC / HTTP/3 flow control frame settings.', 'fingerprint-wordpress'),
                            'historyScore'               => __('Suspicious rotation of multiple IP addresses associated with a single hardware identity.', 'fingerprint-wordpress'),
                            'rotationScore'              => __('Rapid and abnormal modifications to the application stack.', 'fingerprint-wordpress'),
                            'botScore'                   => __('Detection of native automation attributes (navigator.webdriver, Chrome CDP).', 'fingerprint-wordpress'),
                            'crossLayerInconsistencyScore' => __('Strict contradiction between layers (e.g. declared OS in User-Agent vs network TCP/IP stack OS).', 'fingerprint-wordpress')
                        ];

                        foreach ($frontendConfig['weights'] as $indicator => $weight):
                            $desc = $metricDescriptions[$indicator] ?? __('Behavioral suspicion indicator.', 'fingerprint-wordpress');
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
                    <?php submit_button(esc_html__('Update Metric Weights', 'fingerprint-wordpress'), 'primary', 'fingerprint_save_settings', false); ?>
                </p>
            </form>
        </div>

        <!-- TAB 3 : FLUX PROMETHEUS -->
        <div id="tab-prometheus" class="fingerprint-tab-content" style="display:none;background:#fff;padding:20px;border:1px solid #ccd0d4;border-top:none;">
            <h3><?php esc_html_e('Real-Time Prometheus Metrics', 'fingerprint-wordpress'); ?></h3>
            <p class="description"><?php esc_html_e('Raw text format exported for scraping by Prometheus, Grafana Agent, or Datadog.', 'fingerprint-wordpress'); ?></p>
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
    }
    </script>
    <?php
}