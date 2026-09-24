<?php
/**
 * Plugin Name: Fingerprint Anti-Bot & Proof-of-Work
 * Plugin URI: https://github.com/anonympins/fingerprint
 * Description: Protection bot haute performance pour WordPress avec Proof-of-Work client et détection d'anomalies.
 * Version: 1.0.0
 * Author: Anonympins
 * License: MIT
 */

declare(strict_types=1);

use Anonympins\Fingerprint\DirectFingerprint;
use Anonympins\Fingerprint\Store\StoreManager;
use Anonympins\Fingerprint\Config\SecurityProfiles;
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
// CONFIGURATION RAPIDE DES PROFILS DE SÉCURITÉ PAR CONTEXTE
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

// 5. Interception de sécurité au plus tôt du cycle de vie WordPress
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

    // Possibilité de filtrer la configuration via functions.php ou un thème
    $configs = apply_filters('fingerprint_security_profiles', $fingerprintSecurityProfiles);

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