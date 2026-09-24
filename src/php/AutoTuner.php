<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint;

use Anonympins\Fingerprint\Optimization\OptimizationOperators;
use Anonympins\Fingerprint\Utils\RequestUtils;

/**
 * Manages the background auto-tuning process for security thresholds and weights.
 * Designed to be executed periodically (e.g. via a cron job).
 */
class AutoTuner
{
    /**
     * @var array<string, mixed> Live security configuration that will be mutated.
     */
    private array $securityConfig;

    /**
     * @var array<int, array<string, mixed>> Collected traffic data log.
     */
    private array $trafficData;

    private int $minDataPoints;
    private int $maxDataPoints;
    private ?int $maxAgeMs;
    private bool $clearAfterTuning;
    /** @var ?callable */
    private $onCleanup;
    private ?string $savePath;
    private float $validationTolerance;

    /**
     * @var ?array<string, mixed> Last best solution found by the optimizer.
     */
    private static ?array $lastBestSolution = null;

    /**
     * @param array<string, mixed> &$securityConfig Security configuration passed by reference.
     * @param array<int, array<string, mixed>> &$trafficData Traffic logs passed by reference.
     * @param array<string, int> $options Auto-tuning options.
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
        $this->validationTolerance = $options['validationTolerance'] ?? 0.15;

        if (isset($this->securityConfig['logger']) && is_callable($this->securityConfig['logger']) && !isset($this->securityConfig['logger_wrapped'])) {
            $originalLogger = $this->securityConfig['logger'];
            $maxPercentage = $this->securityConfig['autotuning']['maxDensityPercentage'] ?? 0.02;

            $this->securityConfig['logger'] = function (array $log) use ($originalLogger, $maxPercentage) {
                $ip = $log['clientIp'] ?? $log['ip'] ?? null;
                $subnet = $ip ? RequestUtils::getIpSubnet($ip, 24, 48) : null;
                $fp = $log['deviceHash'] ?? $log['fingerprint'] ?? $log['deviceFingerprint'] ?? null;
                $stableFp = $fp ? RequestUtils::extractStablePart($fp) : null;

                if (count($this->trafficData) > 0) {
                    $total = count($this->trafficData);
                    $ipMatchCount = 0;
                    $fpMatchCount = 0;
                    $matchedKey = null;

                    foreach ($this->trafficData as $key => $existingLog) {
                        $logIp = $existingLog['clientIp'] ?? $existingLog['ip'] ?? null;
                        $logSubnet = $logIp ? RequestUtils::getIpSubnet($logIp, 24, 48) : null;
                        $logFp = $existingLog['deviceHash'] ?? $existingLog['fingerprint'] ?? $existingLog['deviceFingerprint'] ?? null;
                        $logStableFp = $logFp ? RequestUtils::extractStablePart($logFp) : null;

                        $isIpMatch = $subnet && $logSubnet === $subnet;
                        $isFpMatch = $stableFp && $logStableFp === $stableFp;
                        if ($isIpMatch) $ipMatchCount++;
                        if ($isFpMatch) $fpMatchCount++;
                        if ($isIpMatch || $isFpMatch) $matchedKey = $key;
                    }
                    if (($subnet && ($ipMatchCount / $total) > $maxPercentage) || ($stableFp && ($fpMatchCount / $total) > $maxPercentage)) {
                        if ($matchedKey !== null) {
                            $this->trafficData[$matchedKey]['instancesCount'] = ($this->trafficData[$matchedKey]['instancesCount'] ?? 1) + 1;
                            $this->trafficData[$matchedKey]['weight'] = ($this->trafficData[$matchedKey]['weight'] ?? 1.0) + 1.0;
                        }
                        return;
                    }
                }
                $originalLogger($log);
            };
            $this->securityConfig['logger_wrapped'] = true;
        }
    }

    /**
     * Prunes old or excess traffic logs to prevent memory leaks.
     */
    private function pruneTrafficData(): void
    {
        $now = (int)(microtime(true) * 1000);
        $removed = [];

        // 1. Time-based expiration (maxAgeMs)
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

        // 2. Maximum dataset size enforcement (maxDataPoints)
        if ($this->maxDataPoints > 0 && count($this->trafficData) > $this->maxDataPoints) {
            $overflowCount = count($this->trafficData) - $this->maxDataPoints;
            $spliced = array_splice($this->trafficData, 0, $overflowCount);
            $removed = array_merge($removed, $spliced);
        }

        // 3. Execute cleanup callback
        if ($this->onCleanup !== null && is_callable($this->onCleanup) && !empty($removed)) {
            try {
                call_user_func($this->onCleanup, $removed);
            } catch (\Throwable $e) {
                error_log("[AutoTuning] Error in onCleanup callback: " . $e->getMessage());
            }
        }
    }

    /**
     * Executes a threshold optimization cycle.
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
        $minConfidenceRatio = 0.05; // Require at least 5% high-confidence signals
        $minHighConfidenceCount = 10; // Fallback absolute count to avoid starvation during floods

        $hasEnoughSignal = $highConfidenceRatio >= $minConfidenceRatio || $highConfidenceLogs >= $minHighConfidenceCount;

        if (count($sanitizedData) < $this->minDataPoints || !$hasEnoughSignal) {
            if (count($sanitizedData) < $this->minDataPoints) {
                echo sprintf("[AutoTuning] Postponed: %d/%d data points collected.\n", count($sanitizedData), $this->minDataPoints);
            } else {
                echo sprintf("[AutoTuning] Postponed: Insufficient confidence signals (Ratio: %.2f%% < %.2f%% and count: %d < %d).\n", $highConfidenceRatio * 100, $minConfidenceRatio * 100, $highConfidenceLogs, $minHighConfidenceCount);
            }
            return;
        }

        if (count($this->trafficData) > $this->maxDataPoints) {
            echo sprintf("[AutoTuning] Traffic log reached %d entries (max: %d). Truncating oldest logs.\n", count($this->trafficData), $this->maxDataPoints);
            $this->trafficData = array_slice($this->trafficData, count($this->trafficData) - $this->maxDataPoints);
        }

        echo sprintf("[AutoTuning] Starting complete optimization cycle with %d sanitized data points.\n", count($sanitizedData));

        $paretoFront = OptimizationOperators::solveFullSecurityTuning(['trafficData' => $sanitizedData, 'currentConfig' => $this->securityConfig], []);

        if (empty($paretoFront)) {
            echo "[AutoTuning] Optimization returned no solutions.\n";
            return;
        }

        // Sanity guardrails to filter candidate Pareto solutions
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
            echo "[AutoTuning] Warning: All Pareto solutions violated sanity guardrails. Restoring raw front.\n";
            $filteredFront = $paretoFront;
        } else {
            $filteredFront = array_values($filteredFront);
        }

        // Selection strategy: pick the most balanced solution (closest to origin in objective space)
        $bestSolution = $filteredFront[0];
        $minDistance = sqrt(pow($bestSolution['objectives'][0], 2) + pow($bestSolution['objectives'][1], 2));

        for ($i = 1; $i < count($filteredFront); $i++) {
            $distance = sqrt(pow($filteredFront[$i]['objectives'][0], 2) + pow($filteredFront[$i]['objectives'][1], 2));
            if ($distance < $minDistance) {
                $minDistance = $distance;
                $bestSolution = $filteredFront[$i];
            }
        }

        // Inertial update logic to prevent drastic parameter jumps
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

        // --- POST-COMPUTATION VALIDATION (Rollback guard & tolerance threshold) ---
        $tempConfig = [
            'thresholds' => $this->securityConfig['thresholds'],
            'weights' => $this->securityConfig['weights'],
            'patterns' => $this->securityConfig['patterns'],
        ];

        $applyInertialUpdate($tempConfig['thresholds'], $newConfig['thresholds'], 'thresholds', $trafficConfidence);
        $applyInertialUpdate($tempConfig['weights'], $newConfig['weights'], 'weights', $trafficConfidence);
        $applyInertialUpdate($tempConfig['patterns'], $newConfig['patterns'], 'patterns', $trafficConfidence);

        $evaluator = OptimizationOperators::createFullSecurityConfigEvaluator(['trafficData' => $sanitizedData]);
        $currentObjectives = $evaluator($this->securityConfig);
        $proposedObjectives = $evaluator($tempConfig);

        $currentFPR = $currentObjectives[0];
        $currentFNR = $currentObjectives[1];
        $proposedFPR = $proposedObjectives[0];
        $proposedFNR = $proposedObjectives[1];

        $validationTolerance = $this->securityConfig['autotuning']['validationTolerance'] ?? $this->validationTolerance;

        if ($proposedFPR > $currentFPR + $validationTolerance || $proposedFNR > $currentFNR + $validationTolerance) {
            error_log(sprintf(
                "[AutoTuning] [SECURITY ALERT] Proposed configuration rejected due to instability/poisoning risk! Proposed FPR: %.4f (Current: %.4f), Proposed FNR: %.4f (Current: %.4f)",
                $proposedFPR, $currentFPR, $proposedFNR, $currentFNR
            ));
            if (isset($this->securityConfig['logger']) && is_callable($this->securityConfig['logger'])) {
                call_user_func($this->securityConfig['logger'], [
                    'type' => 'autotuning_instability_alert',
                    'proposedFPR' => $proposedFPR,
                    'currentFPR' => $currentFPR,
                    'proposedFNR' => $proposedFNR,
                    'currentFNR' => $currentFNR,
                    'timestamp' => (int)(microtime(true) * 1000)
                ]);
            }
            return; // Rollback
        }

        $applyInertialUpdate($this->securityConfig['thresholds'], $newConfig['thresholds'], 'thresholds', $trafficConfidence);
        $applyInertialUpdate($this->securityConfig['weights'], $newConfig['weights'], 'weights', $trafficConfidence);
        $applyInertialUpdate($this->securityConfig['patterns'], $newConfig['patterns'], 'patterns', $trafficConfidence);

        self::$lastBestSolution = $bestSolution;

        echo "[AutoTuning] New optimized security configuration applied.\n";
        echo "[AutoTuning] Objectives achieved: " . json_encode([
            'falsePositiveRate' => round($bestSolution['objectives'][0], 4),
            'falseNegativeRate' => round($bestSolution['objectives'][1], 4)
        ]) . "\n";
        echo "[AutoTuning] New thresholds: " . json_encode($this->securityConfig['thresholds']) . "\n";
        echo "[AutoTuning] New weights: " . json_encode($this->securityConfig['weights']) . "\n";
        echo "[AutoTuning] New patterns: " . json_encode($this->securityConfig['patterns']) . "\n";

        // Persist best configuration if savePath is configured
        if ($this->savePath !== null) {
            try {
                file_put_contents($this->savePath, json_encode($bestSolution['solution'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
                echo "[AutoTuning] Best configuration saved to: {$this->savePath}\n";
            } catch (\Throwable $e) {
                error_log("[AutoTuning] Error saving optimized configuration: " . $e->getMessage());
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
     * Returns the latest best solution found by the auto-tuner.
     * @return array<string, mixed>|null
     */
    public static function getBestTuningSolution(): ?array
    {
        return self::$lastBestSolution;
    }

    /**
     * Resets the static best solution. Intended for testing.
     * @internal
     */
    public static function resetBestTuningSolution(): void
    {
        self::$lastBestSolution = null;
    }
}