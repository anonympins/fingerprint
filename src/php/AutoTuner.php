<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint;

use Anonympins\Fingerprint\Optimization\OptimizationOperators;
use Anonympins\Fingerprint\Utils\RequestUtils;

/**
 * Gère le processus d'auto-ajustement en arrière-plan pour les seuils et poids de sécurité.
 * Conçu pour être exécuté périodiquement (par exemple, via une tâche cron).
 */
class AutoTuner
{
    /**
     * @var array<string, mixed> La configuration de sécurité en direct qui sera mutée.
     */
    private array $securityConfig;

    /**
     * @var array<int, array<string, mixed>> Les données de trafic collectées.
     */
    private array $trafficData;

    private int $minDataPoints;
    private int $maxDataPoints;
    private ?int $maxAgeMs;
    private bool $clearAfterTuning;
    /** @var ?callable */
    private $onCleanup;
    private ?string $savePath;

    /**
     * @var ?array<string, mixed> La dernière meilleure solution trouvée par l'optimiseur.
     */
    private static ?array $lastBestSolution = null;

    /**
     * @param array<string, mixed> &$securityConfig La configuration de sécurité (passée par référence).
     * @param array<int, array<string, mixed>> &$trafficData Les données de trafic (passées par référence).
     * @param array<string, int> $options Options pour l'auto-ajustement.
     */
    public function __construct(array &$securityConfig, array &$trafficData, array $options = [])
    {
        $this->securityConfig = &$securityConfig;
        $this->trafficData = &$trafficData;
        $this->minDataPoints = $options['minDataPoints'] ?? 200;
        $this->maxDataPoints = $options['maxDataPoints'] ?? 10000;
        $this->maxAgeMs = $options['maxAgeMs'] ?? null;
        $this->clearAfterTuning = $options['clearAfterTuning'] ?? false;
        $this->onCleanup = $options['onCleanup'] ?? null;
        $this->savePath = $options['savePath'] ?? null;
    }

    /**
     * Prunes old or excess traffic logs to prevent memory leaks.
     */
    private function pruneTrafficData(): void
    {
        $now = (int)(microtime(true) * 1000);
        $removed = [];

        // 1. Expire par temps (maxAgeMs)
        if ($this->maxAgeMs !== null && $this->maxAgeMs > 0) {
            $threshold = $now - $this->maxAgeMs;
            foreach ($this->trafficData as $key => $log) {
                $logTs = $log['timestamp'] ?? $log['requestTimestamp'] ?? $now;
                if ($logTs < $threshold) {
                    $removed[] = $log;
                    unset($this->trafficData[$key]);
                }
            }
            $this->trafficData = array_values($this->trafficData);
        }

        // 2. Politique de taille maximale (maxDataPoints)
        if ($this->maxDataPoints > 0 && count($this->trafficData) > $this->maxDataPoints) {
            $overflowCount = count($this->trafficData) - $this->maxDataPoints;
            $spliced = array_splice($this->trafficData, 0, $overflowCount);
            $removed = array_merge($removed, $spliced);
        }

        // 3. Invocation du callback onCleanup
        if ($this->onCleanup !== null && is_callable($this->onCleanup) && !empty($removed)) {
            try {
                call_user_func($this->onCleanup, $removed);
            } catch (\Throwable $e) {
                error_log("[AutoTuning] Error in onCleanup callback: " . $e->getMessage());
            }
        }
    }

    /**
     * Exécute un cycle d'optimisation des seuils.
     */
    public function runOptimizationCycle(): void
    {
        $this->pruneTrafficData();

        $sanitizedData = RequestUtils::sanitizeTrafficData($this->trafficData);

        $highConfidenceLogs = count(array_filter(
            $sanitizedData,
            fn ($log) => in_array($log['type'] ?? '', ['challenge_solved', 'trap_triggered'])
        ));
        $highConfidenceRatio = count($sanitizedData) > 0 ? $highConfidenceLogs / count($sanitizedData) : 0;
        $minConfidenceRatio = 0.05; // Exiger au moins 5% de signaux forts.
        $minHighConfidenceCount = 10; // Absolu de secours pour éviter le gel lors de floods

        $hasEnoughSignal = $highConfidenceRatio >= $minConfidenceRatio || $highConfidenceLogs >= $minHighConfidenceCount;

        if (count($sanitizedData) < $this->minDataPoints || !$hasEnoughSignal) {
            if (count($sanitizedData) < $this->minDataPoints) {
                echo sprintf("[AutoTuning] Reporté : %d/%d points de données.\n", count($sanitizedData), $this->minDataPoints);
            } else {
                echo sprintf("[AutoTuning] Reporté : Signaux de confiance insuffisants (Ratio: %.2f%% < %.2f%% et absolu: %d < %d).\n", $highConfidenceRatio * 100, $minConfidenceRatio * 100, $highConfidenceLogs, $minHighConfidenceCount);
            }
            return;
        }

        if (count($this->trafficData) > $this->maxDataPoints) {
            echo sprintf("[AutoTuning] Le journal de trafic a atteint %d entrées (max: %d). Troncation des données les plus anciennes.\n", count($this->trafficData), $this->maxDataPoints);
            $this->trafficData = array_slice($this->trafficData, count($this->trafficData) - $this->maxDataPoints);
        }

        echo sprintf("[AutoTuning] Démarrage du cycle d'optimisation complet avec %d points de données assainis.\n", count($sanitizedData));

        $paretoFront = OptimizationOperators::solveFullSecurityTuning(['trafficData' => $sanitizedData, 'currentConfig' => $this->securityConfig], []);

        if (empty($paretoFront)) {
            echo "[AutoTuning] L'optimisation n'a retourné aucune solution.\n";
            return;
        }

        // Règles de gardiennage (Sanity Guardrails) pour filtrer le front de Pareto
        $isValidSecurityConfig = function (array $config): bool {
            if (!isset($config['weights']) || !isset($config['thresholds'])) return false;
            $w = $config['weights'];
            $t = $config['thresholds'];
            $activeWeightsSum = ($w['inconsistencyScore'] ?? 0) + ($w['tlsSpoofingScore'] ?? 0) + ($w['requestPatternScore'] ?? 0) + ($w['behaviorScore'] ?? 0) + ($w['botScore'] ?? 0);
            if ($activeWeightsSum < 1.5) return false;
            if ($t['low'] < 10 || $t['low'] > 35) return false;
            if ($t['medium'] < $t['low'] + 5 || $t['medium'] > 70) return false;
            if ($t['high'] < $t['medium'] + 5 || $t['high'] > 90) return false;
            if ($t['block'] < $t['high'] + 5 || $t['block'] > 99) return false;
            return true;
        };

        $filteredFront = array_filter($paretoFront, fn ($p) => $isValidSecurityConfig($p['solution']));
        if (empty($filteredFront)) {
            echo "[AutoTuning] Attention : Toutes les solutions ont été rejetées par les règles de gardiennage. Rétablissement du front brut.\n";
            $filteredFront = $paretoFront;
        } else {
            $filteredFront = array_values($filteredFront);
        }

        // Stratégie de sélection : choisir la solution la plus équilibrée (la plus proche de l'origine).
        $bestSolution = $filteredFront[0];
        $minDistance = sqrt(pow($bestSolution['objectives'][0], 2) + pow($bestSolution['objectives'][1], 2));

        for ($i = 1; $i < count($filteredFront); $i++) {
            $distance = sqrt(pow($filteredFront[$i]['objectives'][0], 2) + pow($filteredFront[$i]['objectives'][1], 2));
            if ($distance < $minDistance) {
                $minDistance = $distance;
                $bestSolution = $filteredFront[$i];
            }
        }

        // Logique d'inertie pour l'application de la configuration.
        $newConfig = $bestSolution['solution'];
        $trafficConfidence = min(1.5, max(0.3, $highConfidenceRatio * 4));

        $applyInertialUpdate = function (&$currentConfig, $targetConfig, string $type, float $confidenceFactor = 1.0) {
            if (empty($currentConfig) || empty($targetConfig)) return;

            $baseLearningRate = 0.15;
            $learningRate = max(0.02, min(0.40, $baseLearningRate * $confidenceFactor));

            foreach ($currentConfig as $key => &$value) {
                if (isset($targetConfig[$key]) && is_numeric($value)) {
                    $currentVal = (float)$value;
                    $targetVal = (float)$targetConfig[$key];

                    $updatedVal = $currentVal + ($targetVal - $currentVal) * $learningRate;

                    if ($type === 'weights') {
                        $updatedVal = max(0.05, min(1.8, $updatedVal));
                    } elseif ($type === 'patterns') {
                        if ($key === 'benfordThreshold') $updatedVal = max(0.05, min(0.30, $updatedVal));
                        elseif ($key === 'decayFactor') $updatedVal = max(0.70, min(0.98, $updatedVal));
                        elseif ($key === 'minSamples') $updatedVal = max(3, min(15, (int)round($updatedVal)));
                        elseif ($key === 'historySize') $updatedVal = max(5, min(30, (int)round($updatedVal)));
                        elseif (str_ends_with($key, 'Threshold')) $updatedVal = max(50, min(3000, (int)round($updatedVal)));
                    }

                    $value = $updatedVal;
                }
            }

            if ($type === 'thresholds') {
                $low = max(10, min(35, $currentConfig['low']));
                $medium = max($low + 8, min(65, $currentConfig['medium']));
                $high = max($medium + 8, min(85, $currentConfig['high']));
                $block = max($high + 8, min(98, $currentConfig['block']));

                $currentConfig['low'] = (int)round($low);
                $currentConfig['medium'] = (int)round($medium);
                $currentConfig['high'] = (int)round($high);
                $currentConfig['block'] = (int)round($block);
            }
        };

        $applyInertialUpdate($this->securityConfig['thresholds'], $newConfig['thresholds'], 'thresholds', $trafficConfidence);
        $applyInertialUpdate($this->securityConfig['weights'], $newConfig['weights'], 'weights', $trafficConfidence);
        $applyInertialUpdate($this->securityConfig['patterns'], $newConfig['patterns'], 'patterns', $trafficConfidence);

        self::$lastBestSolution = $bestSolution;

        echo "[AutoTuning] Nouvelle configuration de sécurité optimisée appliquée.\n";
        echo "[AutoTuning] Objectifs atteints : " . json_encode([
            'falsePositiveRate' => round($bestSolution['objectives'][0], 4),
            'falseNegativeRate' => round($bestSolution['objectives'][1], 4)
        ]) . "\n";
        echo "[AutoTuning] Nouveaux seuils : " . json_encode($this->securityConfig['thresholds']) . "\n";
        echo "[AutoTuning] Nouveaux poids : " . json_encode($this->securityConfig['weights']) . "\n";
        echo "[AutoTuning] Nouveaux patterns : " . json_encode($this->securityConfig['patterns']) . "\n";

        // NOUVEAU: Sauvegarder la meilleure configuration si un chemin est fourni.
        if ($this->savePath !== null) {
            try {
                file_put_contents($this->savePath, json_encode($bestSolution['solution'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
                echo "[AutoTuning] Meilleure configuration sauvegardée dans : {$this->savePath}\n";
            } catch (\Throwable $e) {
                error_log("[AutoTuning] Erreur lors de la sauvegarde de la configuration optimisée : " . $e->getMessage());
            }
        }

        if ($this->clearAfterTuning) {
            $cleared = array_splice($this->trafficData, 0);
            if ($this->onCleanup !== null && is_callable($this->onCleanup) && !empty($cleared)) {
                try {
                    call_user_func($this->onCleanup, $cleared);
                } catch (\Throwable $e) {
                    error_log("[AutoTuning] Error in onCleanup callback after clearing: " . $e->getMessage());
                }
            }
            echo sprintf("[AutoTuning] Explicitly cleared %d processed traffic data points.\n", count($cleared));
        }
    }

    /**
     * Retourne la dernière meilleure solution trouvée par l'auto-tuner.
     * @return array<string, mixed>|null
     */
    public static function getBestTuningSolution(): ?array
    {
        return self::$lastBestSolution;
    }

    /**
     * Réinitialise la meilleure solution statique. Utile pour les tests.
     * @internal
     */
    public static function resetBestTuningSolution(): void
    {
        self::$lastBestSolution = null;
    }
}