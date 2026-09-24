<?php

declare(strict_types=1);

/**
 * Periodic security configuration auto-tuning CLI script.
 * Reads current configuration, prunes and sanitizes traffic logs,
 * executes the genetic optimizer, and writes back the optimized profile.
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
    fwrite(STDERR, "Error: Unable to load autoloader. Run 'composer install'.\n");
    exit(1);
}

use Anonympins\Fingerprint\Optimization\Optimization;
use Anonympins\Fingerprint\Store\StoreManager;
use Anonympins\Fingerprint\Utils\RequestUtils;

// 1. Récupération des arguments CLI
$configPath = $argv[1] ?? null;
if (!$configPath) {
    echo "Usage: php auto-tune.php [path_to_security-config.json]\n";
    exit(1);
}

if (!file_exists($configPath)) {
    fwrite(STDERR, "Error: Configuration file not found: {$configPath}\n");
    exit(1);
}

$config = json_decode(file_get_contents($configPath), true);
if (json_last_error() !== JSON_ERROR_NONE) {
    fwrite(STDERR, "Error: Invalid JSON configuration file.\n");
    exit(1);
}

// 2. Connect to datastore to retrieve accumulated traffic logs
$store = StoreManager::getStore();
if (!$store) {
    fwrite(STDERR, "Error: No active persistent datastore available.\n");
    exit(1);
}

$rawTrafficLogs = $store->get('traffic_logs') ?? [];
if (empty($rawTrafficLogs)) {
    echo "[AutoTuning] No traffic logs available for optimization.\n";
    exit(0);
}

// 3. Sanitize data to prevent poisoning / Sybil attacks
$sanitizedLogs = RequestUtils::sanitizeTrafficData($rawTrafficLogs);

$minDataPoints = $config['autotuning']['minDataPoints'] ?? 200;
if (count($sanitizedLogs) < $minDataPoints) {
    echo "[AutoTuning] Postponed: Insufficient sanitized logs (" . count($sanitizedLogs) . "/{$minDataPoints}).\n";
    exit(0);
}

echo "[AutoTuning] Starting optimization pass on " . count($sanitizedLogs) . " traffic data points...\n";

// 4. Compute Pareto front
$paretoFront = Optimization::solveFullSecurityTuning(['trafficData' => $sanitizedLogs]);
if (empty($paretoFront)) {
    fwrite(STDERR, "[AutoTuning] Optimization returned no solutions.\n");
    exit(1);
}

// 5. Select the most balanced solution (closest to origin)
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
$maxChangeVelocity = 0.15; // Max 15% inertial step per cycle

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

// 6. Write back optimized parameters to configuration file
file_put_contents($configPath, json_encode($config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
echo "[AutoTuning] Success: File {$configPath} updated with optimized parameters.\n";