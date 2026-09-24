<?php
/**
 * Plugin Name: Fingerprint Anti-Bot & Proof-of-Work
 * Plugin URI: https://github.com/anonympins/fingerprint
 * Description: Protection bot haute performance pour WordPress avec Proof-of-Work client et détection d'anomalies.
 * Version: 0.7.1
 * Author: Anonympins
 * License: MIT
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
        echo '<p><strong>[Fingerprint Anti-Bot Security Warning]</strong> : Votre site fonctionne actuellement sous le protocole non chiffré <code>HTTP</code>. ';
        echo 'Dans ce mode, l\'API native <em>Web Cryptography</em> (<code>crypto.subtle</code>) des navigateurs est désactivée par mesure de sécurité par les navigateurs modernes, ';
        echo 'forçant l\'exécution d\'un simulacre/fallback purement JavaScript plus lent et vulnérable aux attaques par interception (MitM). ';
        echo 'Il est fortement recommandé de déployer un certificat TLS/SSL et de forcer <code>HTTPS</code> pour garantir l\'intégrité des calculs PoW et la protection des cookies d\'identité.</p>';
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
        'Fingerprint Anti-Bot',
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
        wp_die(__('Vous n\'avez pas les permissions suffisantes pour accéder à cette page.'));
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
        echo '<div class="notice notice-success is-dismissible"><p><strong>Paramètres Fingerprint mis à jour avec succès.</strong></p></div>';
    }

    // Action pour vider le cache SQL manuellement
    if (isset($_POST['fingerprint_clear_store']) && check_admin_referer('fingerprint_clear_nonce', 'fingerprint_nonce_clear')) {
        $store = new WpDbStore();
        $store->clear();
        echo '<div class="notice notice-info is-dismissible"><p>Table de cache SQL ($wpdb) purgée avec succès.</p></div>';
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
        <p class="description">Protection comportementale et cryptographique sans CAPTCHA tiers pour WordPress.</p>

        <div style="background:#fff;border-left:4px solid #2271b1;padding:12px 18px;margin:18px 0;box-shadow:0 1px 1px rgba(0,0,0,.04);">
            <p style="margin:4px 0;">
                <strong>Documentation complète de référence :</strong>
                <a href="https://github.com/anonympins/fingerprint/blob/main/doc/full_options.md" target="_blank" rel="noopener noreferrer" class="button button-secondary" style="margin-left:8px;">
                    <span class="dashicons dashicons-external" style="vertical-align:middle;"></span> Voir Full Configuration Options sur GitHub
                </a>
                <a href="https://github.com/anonympins/fingerprint" target="_blank" rel="noopener noreferrer" class="button button-secondary" style="margin-left:4px;">
                    <span class="dashicons dashicons-admin-plugins" style="vertical-align:middle;"></span> Dépôt GitHub
                </a>
            </p>
        </div>

        <!-- TABLEAU DE BORD STATISTIQUES & ÉTAT -->
        <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(240px, 1fr));gap:16px;margin-bottom:24px;">
            <div style="background:#fff;padding:16px;border-radius:4px;border:1px solid #ccd0d4;">
                <h3 style="margin-top:0;">État HTTPS</h3>
                <?php if (is_ssl()): ?>
                    <p style="color:#007017;font-weight:bold;font-size:16px;">
                        <span class="dashicons dashicons-yes-alt"></span> Actif (WebCrypto Subtle disponible)
                    </p>
                <?php else: ?>
                    <p style="color:#d63638;font-weight:bold;font-size:16px;">
                        <span class="dashicons dashicons-warning"></span> Insecure (HTTP non chiffré)
                    </p>
                <?php endif; ?>
            </div>
            <div style="background:#fff;padding:16px;border-radius:4px;border:1px solid #ccd0d4;">
                <h3 style="margin-top:0;">Cache SQL ($wpdb)</h3>
                <p style="font-size:22px;margin:0;font-weight:600;"><?php echo esc_html((string)$totalRows); ?> <span style="font-size:14px;color:#646970;font-weight:normal;">clés en base</span></p>
                <small style="color:#8c8f94;"><?php echo esc_html((string)$expiredRows); ?> clés expirées en attente de purge cron</small>
            </div>
            <div style="background:#fff;padding:16px;border-radius:4px;border:1px solid #ccd0d4;">
                <h3 style="margin-top:0;">Profils Actifs</h3>
                <p style="margin:0;">
                    Frontend : <strong><?php echo esc_html($effective['frontend']['profile']); ?></strong><br>
                    Admin : <strong><?php echo esc_html($effective['admin']['profile']); ?></strong><br>
                    API REST : <strong><?php echo esc_html($effective['api']['profile']); ?></strong>
                </p>
            </div>
        </div>

        <!-- ONGLETS DE NAVIGATION -->
        <h2 class="nav-tab-wrapper">
            <a href="#tab-settings" class="nav-tab nav-tab-active" onclick="fingerprintSwitchTab(event, 'tab-settings')">Réglages & Profils</a>
            <a href="#tab-metrics" class="nav-tab" onclick="fingerprintSwitchTab(event, 'tab-metrics')">Vue des Métriques & Poids</a>
            <a href="#tab-prometheus" class="nav-tab" onclick="fingerprintSwitchTab(event, 'tab-prometheus')">Flux Prometheus</a>
        </h2>

        <!-- TAB 1 : RÉGLAGES -->
        <div id="tab-settings" class="fingerprint-tab-content" style="background:#fff;padding:20px;border:1px solid #ccd0d4;border-top:none;">
            <form method="post" action="">
                <?php wp_nonce_field('fingerprint_settings_nonce', 'fingerprint_nonce'); ?>

                <h3>1. Profils de sécurité par cible</h3>
                <table class="form-table">
                    <tr>
                        <th scope="row"><label for="frontend_profile">Visiteurs & Frontend</label></th>
                        <td>
                            <select name="frontend_profile" id="frontend_profile">
                                <option value="blog" <?php selected($effective['frontend']['profile'], 'blog'); ?>>Blog (Optimal pour contenus, UX fluide)</option>
                                <option value="balanced" <?php selected($effective['frontend']['profile'], 'balanced'); ?>>Balanced (Équilibré)</option>
                                <option value="strict" <?php selected($effective['frontend']['profile'], 'strict'); ?>>Strict (Protection maximale)</option>
                                <option value="ecommerce" <?php selected($effective['frontend']['profile'], 'ecommerce'); ?>>E-commerce (Anti-scraping / scalping)</option>
                            </select>
                            <p class="description">Profil appliqué à toutes les pages publiques du site WordPress.</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="admin_profile">Zone d'administration (wp-login / wp-admin)</label></th>
                        <td>
                            <select name="admin_profile" id="admin_profile">
                                <option value="strict" <?php selected($effective['admin']['profile'], 'strict'); ?>>Strict (Recommandé pour sécuriser les logins)</option>
                                <option value="balanced" <?php selected($effective['admin']['profile'], 'balanced'); ?>>Balanced</option>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="api_profile">API REST (/wp-json/)</label></th>
                        <td>
                            <select name="api_profile" id="api_profile">
                                <option value="api" <?php selected($effective['api']['profile'], 'api'); ?>>API (Challenges JSON & PoW machine)</option>
                                <option value="strict" <?php selected($effective['api']['profile'], 'strict'); ?>>Strict</option>
                            </select>
                        </td>
                    </tr>
                </table>

                <hr>

                <h3>2. Seuils d'action (Thresholds Frontend)</h3>
                <table class="form-table">
                    <tr>
                        <th scope="row">Seuils de score (0 - 100)</th>
                        <td>
                            <label>Low (Challenge initial) :
                                <input type="number" name="frontend_threshold_low" value="<?php echo esc_attr((string)($frontendConfig['thresholds']['low'] ?? 20)); ?>" min="1" max="50" style="width:80px;">
                            </label><br><br>
                            <label>Medium (Challenge renforcé) :
                                <input type="number" name="frontend_threshold_medium" value="<?php echo esc_attr((string)($frontendConfig['thresholds']['medium'] ?? 45)); ?>" min="10" max="75" style="width:80px;">
                            </label><br><br>
                            <label>High (Preuve de travail lourde) :
                                <input type="number" name="frontend_threshold_high" value="<?php echo esc_attr((string)($frontendConfig['thresholds']['high'] ?? 75)); ?>" min="30" max="95" style="width:80px;">
                            </label><br><br>
                            <label>Block (Blocage immédiat 403) :
                                <input type="number" name="frontend_threshold_block" value="<?php echo esc_attr((string)($frontendConfig['thresholds']['block'] ?? 95)); ?>" min="50" max="100" style="width:80px;">
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Comportements avancés</th>
                        <td>
                            <label>
                                <input type="checkbox" name="frontend_challenge_new" value="1" <?php checked(!empty($frontendConfig['challengeNewDevices'])); ?>>
                                Challenger automatiquement les nouveaux navigateurs inconnus (sans cookie device_id)
                            </label><br>
                            <label>
                                <input type="checkbox" name="detect_injections" value="1" <?php checked(!empty($frontendConfig['honeypot']['detectInjections'])); ?>>
                                Activer l'analyse récursive WAF (Injections SQL, NoSQL, Log4j, Traversal dans GET/POST)
                            </label><br>
                            <label>
                                <input type="checkbox" name="frontend_verbose" value="1" <?php checked(!empty($frontendConfig['verbose'])); ?>>
                                Mode verbeux dans les logs PHP (Débogage)
                            </label>
                        </td>
                    </tr>
                </table>

                <?php submit_button('Enregistrer les modifications', 'primary', 'fingerprint_save_settings'); ?>
            </form>

            <hr>
            <form method="post" action="" style="margin-top:16px;">
                <?php wp_nonce_field('fingerprint_clear_nonce', 'fingerprint_nonce_clear'); ?>
                <p>
                    <strong>Maintenance du Store :</strong>
                    <button type="submit" name="fingerprint_clear_store" class="button button-secondary" onclick="return confirm('Purger toutes les sessions et nonces enregistrés ?');">
                        Vider la table de cache SQL ($wpdb)
                    </button>
                </p>
            </form>
        </div>

        <!-- TAB 2 : VUE DÉTAILLÉE DES MÉTRIQUES -->
        <div id="tab-metrics" class="fingerprint-tab-content" style="display:none;background:#fff;padding:20px;border:1px solid #ccd0d4;border-top:none;">
            <h3>Poids des indicateurs comportementaux & transport (Profil Frontend Actif)</h3>
            <p class="description">Le score final de chaque requête est calculé par la somme pondérée : <code>Score = &Sigma; (Métrique &times; Poids)</code>.</p>

            <form method="post" action="">
                <?php wp_nonce_field('fingerprint_settings_nonce', 'fingerprint_nonce'); ?>
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th style="width:280px;">Indicateur / Métrique</th>
                            <th style="width:120px;">Poids Actuel</th>
                            <th>Description & Rôle Détecté</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php
                        $metricDescriptions = [
                            'honeypotScore'              => 'Déclenchement de liens pièges invisibles, honeypots multi-frameworks et sondes d\'injection.',
                            'tlsSpoofingScore'           => 'Discordance entre User-Agent et empreintes cryptographiques TLS (JA3/JA4, extensions, GREASE).',
                            'behaviorScore'              => 'Biométrie dynamique : mouvements souris, cadence frappe clavier, anomalies de touch mobile.',
                            'requestPatternScore'        => 'Vélocité, rafales robotiques, écart-type des requêtes et analyse statistique de Benford.',
                            'inconsistencyScore'         => 'Altération ou dérive du fingerprint matériel entre deux visites du même cookie.',
                            'subnetScore'                => 'Réputation IP agrégée du sous-réseau (/24 ou /48) et densité d\'attaquants proches.',
                            'renderingAnomalyScore'      => 'Anomalies de rendu graphique, cadence V-Sync/FPS et hook d\'OffscreenCanvas.',
                            'protocolAnomalyScore'       => 'Divergence des réglages de trames de contrôle de flux HTTP/2 et QUIC / HTTP/3.',
                            'historyScore'               => 'Rotation suspecte d\'adresses IP distinctes sur une même identité matérielle.',
                            'rotationScore'              => 'Changements rapides et anormaux de la pile applicative.',
                            'botScore'                   => 'Détection d\'attributs natifs d\'automatisation (navigator.webdriver, CDP Chrome).',
                            'crossLayerInconsistencyScore' => 'Contradiction stricte entre couches (ex: OS déclaré dans UA vs OS réseau TCP/IP).'
                        ];

                        foreach ($frontendConfig['weights'] as $indicator => $weight):
                            $desc = $metricDescriptions[$indicator] ?? 'Indicateur de suspicion comportemental.';
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
                    <?php submit_button('Mettre à jour les poids des métriques', 'primary', 'fingerprint_save_settings', false); ?>
                </p>
            </form>
        </div>

        <!-- TAB 3 : FLUX PROMETHEUS -->
        <div id="tab-prometheus" class="fingerprint-tab-content" style="display:none;background:#fff;padding:20px;border:1px solid #ccd0d4;border-top:none;">
            <h3>Métriques Prometheus Temps Réel</h3>
            <p class="description">Format brut exporté pour scraping par Prometheus, Grafana Agent ou Datadog.</p>
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