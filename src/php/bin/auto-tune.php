<?php

declare(strict_types=1);

/**
 * CLI Script d'auto-tuning périodique des configurations de sécurité.
 * Ce script lit la configuration courante, récupère les logs, les assainit,
 * exécute l'optimiseur génétique, et écrase le fichier JSON d'origine.
 */

$autoloaderPaths = [
    __DIR__ . '/../../vendor/autoload.php',
    __DIR__ . '/../vendor/autoload.php',
    __DIR__ . '/../../../autoload.php',
];

$autoloaded = false;
foreach ($autoloaderPaths as $path) {
    if (file_exists($path)) {
        require_once $path;
        $autoloaded = true;
        break;
    }
}

if (!$autoloaded) {
    fwrite(STDERR, "Erreur : Impossible de charger l'autoloader. Exécutez 'composer install'.\n");
    exit(1);
}

use Anonympins\Fingerprint\Optimization\Optimization;
use Anonympins\Fingerprint\Store\StoreManager;
use Anonympins\Fingerprint\Utils\RequestUtils;

// 1. Récupération des arguments CLI
$configPath = $argv[1] ?? null;
if (!$configPath) {
    echo "Usage: php auto-tune.php [chemin_vers_security-config.json]\n";
    exit(1);
}

if (!file_exists($configPath)) {
    fwrite(STDERR, "Erreur : Fichier de configuration introuvable : {$configPath}\n");
    exit(1);
}

$config = json_decode(file_get_contents($configPath), true);
if (json_last_error() !== JSON_ERROR_NONE) {
    fwrite(STDERR, "Erreur : Fichier de configuration JSON invalide.\n");
    exit(1);
}

// 2. Connexion au store pour récupérer les logs accumulés
$store = StoreManager::getStore();
if (!$store) {
    fwrite(STDERR, "Erreur : Aucun store de persistance actif.\n");
    exit(1);
}

$rawTrafficLogs = $store->get('traffic_logs') ?? [];
if (empty($rawTrafficLogs)) {
    echo "[AutoTuning] Aucun log de trafic disponible pour l'optimisation.\n";
    exit(0);
}

// 3. Nettoyage des données pour prévenir l'empoisonnement (Sybil attacks)
$sanitizedLogs = RequestUtils::sanitizeTrafficData($rawTrafficLogs);

$minDataPoints = $config['autotuning']['minDataPoints'] ?? 200;
if (count($sanitizedLogs) < $minDataPoints) {
    echo "[AutoTuning] Reporté : Pas assez de données assainies (" . count($sanitizedLogs) . "/{$minDataPoints}).\n";
    exit(0);
}

echo "[AutoTuning] Lancement de l'optimisation sur " . count($sanitizedLogs) . " données de trafic...\n";

// 4. Résolution du Front de Pareto
$paretoFront = Optimization::solveFullSecurityTuning(['trafficData' => $sanitizedLogs]);
if (empty($paretoFront)) {
    fwrite(STDERR, "[AutoTuning] L'optimisation n'a retourné aucun résultat.\n");
    exit(1);
}

// 5. Sélection de la solution la plus équilibrée
$bestSolution = $paretoFront[0];
$minDistance = sqrt(pow($bestSolution['objectives'][0], 2) + pow($bestSolution['objectives'][1], 2));
foreach ($paretoFront as $candidate) {
    $distance = sqrt(pow($candidate['objectives'][0], 2) + pow($candidate['objectives'][1], 2));
    if ($distance < $minDistance) {
        $minDistance = $distance;
        $bestSolution = $candidate;
    }
}

$newConfig = $bestSolution['solution'];
$maxChangeVelocity = 0.15; // Inertie de 15% maximum par cycle

$applyInertialUpdate = function (array &$current, array $target) use ($maxChangeVelocity) {
    $sumCurrent = array_sum($current);
    if ($sumCurrent === 0) return;
    $sumTarget = 0;
    foreach ($current as $k => $v) {
        if (isset($target[$k])) $sumTarget += $target[$k];
    }
    $ratio = ($sumTarget - $sumCurrent) / $sumCurrent;
    $factor = 1 + max(-$maxChangeVelocity, min($maxChangeVelocity, $ratio));
    foreach ($current as $k => &$v) {
        if (isset($target[$k])) $v *= $factor;
    }
};

$applyInertialUpdate($config['thresholds'], $newConfig['thresholds']);
$applyInertialUpdate($config['weights'], $newConfig['weights']);
$applyInertialUpdate($config['patterns'], $newConfig['patterns']);

// 6. Écrasement propre du fichier de configuration original
file_put_contents($configPath, json_encode($config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
echo "[AutoTuning] Succès : Fichier {$configPath} mis à jour avec les paramètres optimisés.\n";