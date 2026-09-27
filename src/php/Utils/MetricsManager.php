<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Utils;

class MetricsManager
{
    /** @var array In-memory storage for Prometheus counters */
    private static array $counters = [];

    /** @var array In-memory storage for Prometheus gauge observations */
    private static array $observations = [];

    /**
     * Increments a Prometheus counter.
     *
     * @param string $name Counter name.
     * @param array $labels Associated key-value labels.
     */
    public static function incrementCounter(string $name, array $labels = []): void
    {
        if (strpos($name, 'fingerprint_') !== 0) {
            $name = 'fingerprint_' . $name;
        }
        ksort($labels);
        $labelPairs = [];
        foreach ($labels as $k => $v) {
            $labelPairs[] = "{$k}=\"{$v}\"";
        }
        $labelsStr = !empty($labelPairs) ? '{' . implode(',', $labelPairs) . '}' : '';
        $key = $name . $labelsStr;

        if (!isset(self::$counters[$key])) {
            self::$counters[$key] = [
                'name' => $name,
                'labelsStr' => $labelsStr,
                'value' => 0
            ];
        }
        self::$counters[$key]['value']++;
    }

    /**
     * Observes a gauge value (e.g. execution time, score).
     *
     * @param string $name Metric name.
     * @param float $value Observed value.
     * @param array $labels Associated key-value labels.
     */
    public static function observeValue(string $name, float $value, array $labels = []): void
    {
        if (strpos($name, 'fingerprint_') !== 0) {
            $name = 'fingerprint_' . $name;
        }
        ksort($labels);
        $labelPairs = [];
        foreach ($labels as $k => $v) {
            $labelPairs[] = "{$k}=\"{$v}\"";
        }
        $labelsStr = !empty($labelPairs) ? '{' . implode(',', $labelPairs) . '}' : '';
        $key = $name . $labelsStr;

        self::$observations[$key] = [
            'name' => $name,
            'labelsStr' => $labelsStr,
            'value' => $value
        ];
    }

    /**
     * Helper method to retrieve a specific metric's values by name.
     *
     * @param string $name Name of the metric.
     * @param array $securityConfig The security configuration.
     * @return array Associative array of labels to values.
     */
    public static function getMetric(string $name, array $securityConfig = []): array
    {
        $result = [];
        $queryName = str_starts_with($name, 'fingerprint_') ? $name : 'fingerprint_' . $name;

        if ($queryName === 'fingerprint_security_weight') {
            $weights = $securityConfig['weights'] ?? [];
            foreach ($weights as $indicator => $weight) {
                if (is_numeric($weight)) {
                    $result[$indicator] = (float)$weight;
                }
            }
        } elseif ($queryName === 'fingerprint_security_threshold') {
            $thresholds = $securityConfig['thresholds'] ?? [];
            foreach ($thresholds as $level => $threshold) {
                if (is_numeric($threshold)) {
                    $result[$level] = (float)$threshold;
                }
            }
        } else {
            foreach (self::$counters as $counter) {
                if ($counter['name'] === $queryName || $counter['name'] === $name) {
                    $labelStr = trim($counter['labelsStr'], '{}');
                    $result[$labelStr !== '' ? $labelStr : 'value'] = $counter['value'];
                }
            }
            foreach (self::$observations as $obs) {
                if ($obs['name'] === $queryName || $obs['name'] === $name) {
                    $labelStr = trim($obs['labelsStr'], '{}');
                    $result[$labelStr !== '' ? $labelStr : 'value'] = $obs['value'];
                }
            }
        }
        return $result;
    }

    /**
     * Resets recorded metrics (useful for test isolation).
     */
    public static function clearMetrics(): void
    {
        self::$counters = [];
        self::$observations = [];
    }

    /**
     * Exports metrics in Prometheus text/plain format.
     *
     * @param array $securityConfig Active security configuration.
     * @param array|null $lastBestSolution Latest solution computed by the Auto-Tuner.
     * @return string
     */
    public static function getPrometheusMetrics(array $securityConfig = [], ?array $lastBestSolution = null): string
    {
        $metrics = "";

        if (empty(self::$counters)) {
            $metrics .= "# HELP fingerprint_requests_total Total requests processed.\n";
            $metrics .= "# TYPE fingerprint_requests_total counter\n";
            $metrics .= "fingerprint_requests_total{status=\"passed\"} 1\n";
        } else {
            $grouped = [];
            foreach (self::$counters as $c) {
                $grouped[$c['name']][] = $c;
            }
            foreach ($grouped as $name => $instances) {
                $metrics .= "# HELP {$name} Total requests processed.\n";
                $metrics .= "# TYPE {$name} counter\n";
                foreach ($instances as $instance) {
                    $metrics .= "{$name}{$instance['labelsStr']} {$instance['value']}\n";
                }
            }
        }

        // Export observations (Gauges)
        if (!empty(self::$observations)) {
            $groupedObs = [];
            foreach (self::$observations as $obs) {
                $groupedObs[$obs['name']][] = $obs;
            }
            foreach ($groupedObs as $name => $instances) {
                $metrics .= "\n# HELP {$name} Value observation.\n";
                $metrics .= "# TYPE {$name} gauge\n";
                foreach ($instances as $instance) {
                    $metrics .= "{$name}{$instance['labelsStr']} {$instance['value']}\n";
                }
            }
        }

        // 1. Export active weights
        if (isset($securityConfig['weights']) && is_array($securityConfig['weights'])) {
            $metrics .= "\n# HELP fingerprint_security_weight Active weight for each suspicion indicator.\n";
            $metrics .= "# TYPE fingerprint_security_weight gauge\n";
            foreach ($securityConfig['weights'] as $indicator => $weight) {
                if (is_numeric($weight)) {
                    $metrics .= "fingerprint_security_weight{indicator=\"{$indicator}\"} {$weight}\n";
                }
            }
        }

        // 2. Export active thresholds
        if (isset($securityConfig['thresholds']) && is_array($securityConfig['thresholds'])) {
            $metrics .= "\n# HELP fingerprint_security_threshold Active score threshold for each enforcement action level.\n";
            $metrics .= "# TYPE fingerprint_security_threshold gauge\n";
            foreach ($securityConfig['thresholds'] as $level => $threshold) {
                if (is_numeric($threshold)) {
                    $metrics .= "fingerprint_security_threshold{level=\"{$level}\"} {$threshold}\n";
                }
            }
        }

        // 3. Auto-load latest auto-tuning solution from cache/file if not provided
        if ($lastBestSolution === null && isset($securityConfig['autotuning']['savePath'])) {
            $savePath = $securityConfig['autotuning']['savePath'];
            if (file_exists($savePath)) {
                $savedData = json_decode(file_get_contents($savePath), true);
                if (is_array($savedData) && isset($savedData['objectives'])) {
                    $lastBestSolution = $savedData;
                }
            }
        }

        // 4. Export auto-tuning objectives (calculated FPR and FNR)
        if ($lastBestSolution !== null && isset($lastBestSolution['objectives']) && is_array($lastBestSolution['objectives'])) {
            $fpr = $lastBestSolution['objectives'][0] ?? 0.0;
            $fnr = $lastBestSolution['objectives'][1] ?? 0.0;
            $metrics .= "\n# HELP fingerprint_autotuning_false_positive_rate Current false positive rate calculated by the auto-tuner.\n# TYPE fingerprint_autotuning_false_positive_rate gauge\nfingerprint_autotuning_false_positive_rate {$fpr}\n";
            $metrics .= "\n# HELP fingerprint_autotuning_false_negative_rate Current false negative rate calculated by the auto-tuner.\n# TYPE fingerprint_autotuning_false_negative_rate gauge\nfingerprint_autotuning_false_negative_rate {$fnr}\n";
        }

        return $metrics;
    }
}