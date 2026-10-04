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
                // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- AutoTuning system log
                $this->logError("[AutoTuning] Error in onCleanup callback: " . $e->getMessage());
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
                $this->logMessage(sprintf("[AutoTuning] Postponed: %d/%d data points collected.\n", count($sanitizedData), $this->minDataPoints));
            } else {
                $this->logMessage(sprintf("[AutoTuning] Postponed: Insufficient confidence signals (Ratio: %.2f%% < %.2f%% and count: %d < %d).\n", $highConfidenceRatio * 100, $minConfidenceRatio * 100, $highConfidenceLogs, $minHighConfidenceCount));
            }
            return;
        }

        if (count($this->trafficData) > $this->maxDataPoints) {
            $this->logMessage(sprintf("[AutoTuning] Traffic log reached %d entries (max: %d). Truncating oldest logs.\n", count($this->trafficData), $this->maxDataPoints));
            $this->trafficData = array_slice($this->trafficData, count($this->trafficData) - $this->maxDataPoints);
        }

        $this->logMessage(sprintf("[AutoTuning] Starting complete optimization cycle with %d sanitized data points.\n", count($sanitizedData)));

        $paretoFront = OptimizationOperators::solveFullSecurityTuning(['trafficData' => $sanitizedData, 'currentConfig' => $this->securityConfig], []);

        if (empty($paretoFront)) {
            $this->logMessage("[AutoTuning] Optimization returned no solutions.\n");
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
            if (isset($config['pow']) && is_array($config['pow'])) {
                $pow = $config['pow'];
                $ttl = $pow['challengeTtl'] ?? 300;
                $minB = $pow['minDifficultyBits'] ?? 8;
                $maxB = $pow['maxDifficultyBits'] ?? 22;
                if ($ttl < 60 || $ttl > 900 || $minB < 4 || $minB > 16 || $maxB < $minB || $maxB > 28) return false;
            }
            return true;
        };

        $filteredFront = array_filter($paretoFront, fn ($p) => $isValidSecurityConfig($p['solution']));
        if (empty($filteredFront)) {
            $this->logMessage("[AutoTuning] Warning: All Pareto solutions violated sanity guardrails. Restoring raw front.\n");
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
                        continue; // Poids strictement invariants sur trafic hétérogène
                    } elseif ($type === 'patterns') {
                        if ($key === 'benfordThreshold') $updatedVal = max(0.05, min(0.30, $updatedVal));
                        elseif ($key === 'decayFactor') $updatedVal = max(0.70, min(0.98, $updatedVal));
                        elseif ($key === 'minSamples') $updatedVal = max(3, min(15, (int)round($updatedVal)));
                        elseif ($key === 'historySize') $updatedVal = max(5, min(30, (int)round($updatedVal)));
                        elseif (str_ends_with($key, 'Threshold')) $updatedVal = max(50, min(3000, (int)round($updatedVal)));
                    } elseif ($type === 'pow') {
                        if ($key === 'challengeTtl') $updatedVal = max(60, min(900, (int)round($updatedVal)));
                        elseif ($key === 'minDifficultyBits') $updatedVal = max(4, min(16, (int)round($updatedVal)));
                        elseif ($key === 'maxDifficultyBits') $updatedVal = max(16, min(28, (int)round($updatedVal)));
                    }

                    $value = $updatedVal;
                }
            }
            unset($value);

            if ($type === 'thresholds') {
                $low = max(10, min(35, $currentConfig['low']));
                $medium = max($low + 8, min(65, $currentConfig['medium']));
                $high = max($medium + 8, min(85, $currentConfig['high']));
                $block = max($high + 8, min(98, $currentConfig['block']));

                $currentConfig['low'] = (int)round($low);
                $currentConfig['medium'] = (int)round($medium);
                $currentConfig['high'] = (int)round($high);
                $currentConfig['block'] = (int)round($block);
            } elseif ($type === 'pow') {
                if (($currentConfig['minDifficultyBits'] ?? 8) > ($currentConfig['maxDifficultyBits'] ?? 22)) {
                    $currentConfig['minDifficultyBits'] = max(4, ($currentConfig['maxDifficultyBits'] ?? 22) - 2);
                }
            }
        };

        // --- POST-COMPUTATION VALIDATION (Rollback guard & tolerance threshold) ---
        $tempPow = [
            'challengeTtl' => $this->securityConfig['challengeTtl'] ?? 300,
            'minDifficultyBits' => $this->securityConfig['cpu']['minDifficultyBits'] ?? 8,
            'maxDifficultyBits' => $this->securityConfig['cpu']['maxDifficultyBits'] ?? 22,
        ];
        $tempConfig = [
            'thresholds' => $this->securityConfig['thresholds'],
            'weights' => $this->securityConfig['weights'],
            'patterns' => $this->securityConfig['patterns'],
            'pow' => $tempPow,
        ];

        $applyInertialUpdate($tempConfig['thresholds'], $newConfig['thresholds'], 'thresholds', $trafficConfidence);
        $applyInertialUpdate($tempConfig['patterns'], $newConfig['patterns'], 'patterns', $trafficConfidence);
        $applyInertialUpdate($tempConfig['pow'], $newConfig['pow'] ?? [], 'pow', $trafficConfidence);

        $evaluator = OptimizationOperators::createFullSecurityConfigEvaluator(['trafficData' => $sanitizedData]);
        $currentObjectives = $evaluator($this->securityConfig);
        $proposedObjectives = $evaluator($tempConfig);

        $currentFPR = $currentObjectives[0];
        $currentFNR = $currentObjectives[1];
        $proposedFPR = $proposedObjectives[0];
        $proposedFNR = $proposedObjectives[1];

        $validationTolerance = $this->securityConfig['autotuning']['validationTolerance'] ?? $this->validationTolerance;

        if ($proposedFPR > $currentFPR + $validationTolerance || $proposedFNR > $currentFNR + $validationTolerance) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- AutoTuning system alert
            $this->logError(sprintf(
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
        $applyInertialUpdate($this->securityConfig['patterns'], $newConfig['patterns'], 'patterns', $trafficConfidence);
        $applyInertialUpdate($tempPow, $newConfig['pow'] ?? [], 'pow', $trafficConfidence);

        $this->securityConfig['challengeTtl'] = (int)$tempPow['challengeTtl'];
        if (!isset($this->securityConfig['cpu']) || !is_array($this->securityConfig['cpu'])) {
            $this->securityConfig['cpu'] = [];
        }
        $this->securityConfig['cpu']['minDifficultyBits'] = (int)$tempPow['minDifficultyBits'];
        $this->securityConfig['cpu']['maxDifficultyBits'] = (int)$tempPow['maxDifficultyBits'];

        self::$lastBestSolution = $bestSolution;

        $this->logMessage("[AutoTuning] New optimized security configuration applied.\n");
        $this->logMessage("[AutoTuning] Objectives achieved: " . json_encode([
            'falsePositiveRate' => round($bestSolution['objectives'][0], 4),
            'falseNegativeRate' => round($bestSolution['objectives'][1], 4)
        ]) . "\n");
        $this->logMessage("[AutoTuning] New thresholds: " . json_encode($this->securityConfig['thresholds']) . "\n");
        $this->logMessage("[AutoTuning] PoW parameters: " . json_encode($tempPow) . "\n");
        $this->logMessage("[AutoTuning] New patterns: " . json_encode($this->securityConfig['patterns']) . "\n");

        // Persist best configuration if savePath is configured
        if ($this->savePath !== null) {
            $this->saveConfigurationToFile($bestSolution['solution']);
        }

        if ($this->clearAfterTuning) {
            $cleared = array_splice($this->trafficData, 0);
            if ($this->onCleanup !== null && is_callable($this->onCleanup) && !empty($cleared)) {
                try {
                    call_user_func($this->onCleanup, $cleared);
                } catch (\Throwable $e) {
                    // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- AutoTuning system log
                    $this->logError("[AutoTuning] Error in onCleanup callback after clearing: " . $e->getMessage());
                }
            }
            $this->logMessage(sprintf("[AutoTuning] Explicitly cleared %d processed traffic data points.\n", count($cleared)));
        }
    }

    private function logMessage(string $message): void
    {
        if (PHP_SAPI === 'cli') {
            // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CLI message output
            echo $message;
        }
    }

    private function logError(string $message): void
    {
        // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- AutoTuning system log
        error_log($message);
    }

    /**
     * Validates and resolves the configuration save path.
     * Restricts file writes to the WordPress uploads directory (or system temp directory in standalone mode)
     * and strictly requires a .json file extension to prevent arbitrary file overwrite or code execution.
     */
    private function validateAndResolveSavePath(?string $path): ?string
    {
        if ($path === null || trim($path) === '') {
            return null;
        }

        $cleanPath = trim($path);

        // 1. Prevent null-byte injection
        if (str_contains($cleanPath, "\0")) {
            $this->logError('[AutoTuning] Security alert: null byte detected in savePath.');
            return null;
        }

        // 2. Strictly require .json extension
        if (strtolower(pathinfo($cleanPath, PATHINFO_EXTENSION)) !== 'json') {
            $this->logError('[AutoTuning] Security warning: savePath must have a .json extension.');
            return null;
        }

        // 3. Resolve path according to environment
        if (function_exists('wp_upload_dir')) {
            $uploadInfo = wp_upload_dir();
            $uploadBase = !empty($uploadInfo['basedir']) ? $uploadInfo['basedir'] : null;

            if ($uploadBase === null) {
                $this->logError('[AutoTuning] Unable to determine WordPress uploads directory.');
                return null;
            }

            $normalizedUploadBase = str_replace('\\', '/', $uploadBase);
            $normalizedPath = str_replace('\\', '/', $cleanPath);

            // If a relative path or bare filename is provided, place it inside uploads
            if (!str_starts_with($normalizedPath, '/') && !preg_match('#^[a-zA-Z]:/#', $normalizedPath)) {
                $targetFile = rtrim($normalizedUploadBase, '/') . '/' . ltrim($normalizedPath, '/');
            } else {
                $targetFile = $normalizedPath;
            }

            // Ensure parent directory exists
            $targetDir = dirname($targetFile);
            if (!is_dir($targetDir)) {
                if (function_exists('wp_mkdir_p')) {
                    wp_mkdir_p($targetDir);
                } else {
                    // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- Upload directory creation
                    @mkdir($targetDir, 0755, true);
                }
            }

            $realTargetDir = realpath($targetDir);
            $realUploadBase = realpath($uploadBase);

            if ($realTargetDir === false || $realUploadBase === false) {
                $this->logError('[AutoTuning] Failed to resolve canonical path for savePath.');
                return null;
            }

            $normRealTarget = str_replace('\\', '/', $realTargetDir);
            $normRealUpload = str_replace('\\', '/', $realUploadBase);

            // Verify canonical path is strictly contained within uploads directory
            if ($normRealTarget !== $normRealUpload && !str_starts_with($normRealTarget, $normRealUpload . '/')) {
                $this->logError('[AutoTuning] Security alert: savePath must be located within the WordPress uploads directory.');
                return null;
            }

            return $realTargetDir . DIRECTORY_SEPARATOR . basename($targetFile);
        }

        // Standalone PHP / CLI fallback: prevent path traversal and ensure directory is valid
        if (str_contains($cleanPath, '..')) {
            $this->logError('[AutoTuning] Security alert: path traversal detected in savePath.');
            return null;
        }

        $targetDir = dirname($cleanPath);
        if (!is_dir($targetDir)) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- Standalone directory creation
            @mkdir($targetDir, 0755, true);
        }

        $realTargetDir = realpath($targetDir);
        if ($realTargetDir === false) {
            $this->logError('[AutoTuning] Failed to resolve directory for savePath.');
            return null;
        }

        return $realTargetDir . DIRECTORY_SEPARATOR . basename($cleanPath);
    }

    /**
     * Persists the best configuration to disk if savePath is valid.
     *
     * @param array<string, mixed> $solution
     */
    private function saveConfigurationToFile(array $solution): void
    {
        $safePath = $this->validateAndResolveSavePath($this->savePath);
        if ($safePath === null) {
            return;
        }

        $jsonContent = json_encode($solution, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if ($jsonContent === false) {
            $this->logError('[AutoTuning] Failed to encode configuration JSON.');
            return;
        }

        try {
            global $wp_filesystem;
            if (empty($wp_filesystem) && defined('ABSPATH')) {
                require_once ABSPATH . 'wp-admin/includes/file.php';
                WP_Filesystem();
            }

            if (!empty($wp_filesystem) && is_object($wp_filesystem) && method_exists($wp_filesystem, 'put_contents')) {
                $written = (bool)$wp_filesystem->put_contents($safePath, $jsonContent, 0644);
            } else {
                // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Safe validated JSON save path
                $written = file_put_contents($safePath, $jsonContent, LOCK_EX) !== false;
            }

            if ($written) {
                $this->logMessage("[AutoTuning] Best configuration saved to: {$safePath}\n");
            } else {
                $this->logError("[AutoTuning] Error writing configuration to: {$safePath}");
            }
        } catch (\Throwable $e) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- AutoTuning system log
            $this->logError("[AutoTuning] Error saving optimized configuration: " . $e->getMessage());
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