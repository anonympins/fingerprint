<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint;

use Anonympins\Fingerprint\Optimization\OptimizationOperators;

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
    }

    /**
     * Exécute un cycle d'optimisation des seuils.
     */
    public function runOptimizationCycle(): void
    {
        $highConfidenceLogs = count(array_filter(
            $this->trafficData,
            fn ($log) => in_array($log['type'], ['challenge_solved', 'trap_triggered'])
        ));
        $highConfidenceRatio = count($this->trafficData) > 0 ? $highConfidenceLogs / count($this->trafficData) : 0;
        $minConfidenceRatio = 0.05; // Exiger au moins 5% de signaux forts.

        if (count($this->trafficData) < $this->minDataPoints || $highConfidenceRatio < $minConfidenceRatio) {
            if (count($this->trafficData) < $this->minDataPoints) {
                echo sprintf("[AutoTuning] Reporté : %d/%d points de données.\n", count($this->trafficData), $this->minDataPoints);
            } else {
                echo sprintf("[AutoTuning] Reporté : Ratio de confiance insuffisant (%.2f%% < %.2f%%).\n", $highConfidenceRatio * 100, $minConfidenceRatio * 100);
            }
            return;
        }

        if (count($this->trafficData) > $this->maxDataPoints) {
            echo sprintf("[AutoTuning] Le journal de trafic a atteint %d entrées (max: %d). Troncation des données les plus anciennes.\n", count($this->trafficData), $this->maxDataPoints);
            $this->trafficData = array_slice($this->trafficData, count($this->trafficData) - $this->maxDataPoints);
        }

        echo sprintf("[AutoTuning] Démarrage du cycle d'optimisation avec %d points de données.\n", count($this->trafficData));

        $paretoFront = OptimizationOperators::solveFullSecurityTuning(['trafficData' => $this->trafficData]);

        if (empty($paretoFront)) {
            echo "[AutoTuning] L'optimisation n'a retourné aucune solution.\n";
            return;
        }

        // Stratégie de sélection : choisir la solution la plus équilibrée (la plus proche de l'origine).
        $bestSolution = $paretoFront[0];
        $minDistance = sqrt(pow($bestSolution['objectives'][0], 2) + pow($bestSolution['objectives'][1], 2));

        for ($i = 1; $i < count($paretoFront); $i++) {
            $distance = sqrt(pow($paretoFront[$i]['objectives'][0], 2) + pow($paretoFront[$i]['objectives'][1], 2));
            if ($distance < $minDistance) {
                $minDistance = $distance;
                $bestSolution = $paretoFront[$i];
            }
        }

        // Logique d'inertie pour l'application de la configuration.
        $newConfig = $bestSolution['solution'];
        $maxChangeVelocity = 0.15; // 15% de changement maximum par cycle.

        $applyInertialUpdate = function (&$currentConfig, $targetConfig) use ($maxChangeVelocity) {
            if (empty($currentConfig) || empty($targetConfig)) return;

            $totalCurrentWeight = 0;
            $totalTargetWeight = 0;

            foreach ($currentConfig as $key => $value) {
                if (isset($targetConfig[$key])) {
                    $totalCurrentWeight += $value;
                    $totalTargetWeight += $targetConfig[$key];
                }
            }

            if ($totalCurrentWeight === 0) return;

            $globalChangeRatio = ($totalTargetWeight - $totalCurrentWeight) / $totalCurrentWeight;
            $adjustmentFactor = max(-$maxChangeVelocity, min($maxChangeVelocity, $globalChangeRatio));

            foreach ($currentConfig as $key => &$value) {
                if (isset($targetConfig[$key])) {
                    $value *= (1 + $adjustmentFactor);
                }
            }
        };

        $applyInertialUpdate($this->securityConfig['thresholds'], $newConfig['thresholds']);
        $applyInertialUpdate($this->securityConfig['weights'], $newConfig['weights']);
        $applyInertialUpdate($this->securityConfig['patterns'], $newConfig['patterns']);

        self::$lastBestSolution = $bestSolution;

        echo "[AutoTuning] Nouvelle configuration de sécurité optimisée appliquée.\n";
        echo "[AutoTuning] Objectifs atteints : " . json_encode([
            'falsePositiveRate' => round($bestSolution['objectives'][0], 4),
            'falseNegativeRate' => round($bestSolution['objectives'][1], 4)
        ]) . "\n";
        echo "[AutoTuning] Nouveaux seuils : " . json_encode($this->securityConfig['thresholds']) . "\n";
        echo "[AutoTuning] Nouveaux poids : " . json_encode($this->securityConfig['weights']) . "\n";
        echo "[AutoTuning] Nouveaux patterns : " . json_encode($this->securityConfig['patterns']) . "\n";
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