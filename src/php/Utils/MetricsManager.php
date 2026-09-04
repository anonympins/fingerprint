<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Utils;

use Anonympins\Fingerprint\Store\StoreManager;

/**
 * Manages and exposes application metrics in Prometheus format.
 */
class MetricsManager
{
    private const METRICS_PREFIX = 'fingerprint_';
    private const METRICS_TTL = 86400 * 30; // 30 days TTL for metrics

    /**
     * Increments a counter metric.
     * @param string $name The base name of the metric (e.g., 'requests_total').
     * @param array<string, string> $labels Associative array of labels (e.g., ['status' => 'passed']).
     */
    public static function incrementCounter(string $name, array $labels = []): void
    {
        $store = StoreManager::getStore();
        $key = self::buildMetricKey($name, $labels, 'counter');
        $currentValue = (int)$store->get($key) ?? 0;
        $store->set($key, $currentValue + 1, self::METRICS_TTL);
    }

    /**
     * Observes a value for a gauge metric.
     * @param string $name The base name of the metric (e.g., 'device_count').
     * @param float $value The value to set the gauge to.
     * @param array<string, string> $labels Associative array of labels.
     */
    public static function setGauge(string $name, float $value, array $labels = []): void
    {
        $store = StoreManager::getStore();
        $key = self::buildMetricKey($name, $labels, 'gauge');
        $store->set($key, $value, self::METRICS_TTL);
    }

    /**
     * Adds an observation to a summary/histogram metric (for sum and count).
     * @param string $name The base name of the metric (e.g., 'suspicion_score').
     * @param float $value The observed value.
     * @param array<string, string> $labels Associative array of labels.
     */
    public static function observeValue(string $name, float $value, array $labels = []): void
    {
        $store = StoreManager::getStore();
        $sumKey = self::buildMetricKey($name, $labels, 'sum');
        $countKey = self::buildMetricKey($name, $labels, 'count');

        $currentSum = (float)$store->get($sumKey) ?? 0.0;
        $currentCount = (int)$store->get($countKey) ?? 0;

        $store->set($sumKey, $currentSum + $value, self::METRICS_TTL);
        $store->set($countKey, $currentCount + 1, self::METRICS_TTL);
    }

    /**
     * Retrieves all metrics and formats them for Prometheus.
     * @return string
     */
    public static function getPrometheusMetrics(): string
    {
        $store = StoreManager::getStore();
        $metrics = [];

        // List of known metric keys to retrieve.
        $knownMetricKeys = [
            self::buildMetricKey('requests_total', ['status' => 'passed'], 'counter'),
            self::buildMetricKey('requests_total', ['status' => 'blocked'], 'counter'),
            self::buildMetricKey('requests_total', ['status' => 'challenged'], 'counter'),
            self::buildMetricKey('requests_total', ['status' => 'whitelisted'], 'counter'),
            self::buildMetricKey('requests_total', ['status' => 'dry_run_block'], 'counter'),
            self::buildMetricKey('requests_total', ['status' => 'dry_run_challenge'], 'counter'),
            self::buildMetricKey('challenges_solved_total', [], 'counter'),
            self::buildMetricKey('challenges_failed_total', [], 'counter'),
            self::buildMetricKey('suspicion_score', [], 'sum'),
            self::buildMetricKey('suspicion_score', [], 'count'),
            self::buildMetricKey('autotuner_runs_total', [], 'counter'),
            self::buildMetricKey('autotuner_optimized_config_count', [], 'gauge'),
        ];

        foreach ($knownMetricKeys as $key) {
            $value = $store->get($key);
            if ($value !== null) {
                $metrics[$key] = $value;
            }
        }

        $output = [];
        foreach ($metrics as $key => $value) {
            [$metricName, $labelsString, $typeSuffix] = self::parseMetricKey($key);
            $baseName = str_replace(['_counter', '_gauge', '_sum', '_count'], '', $metricName);

            if (!isset($output[$baseName])) {
                $output[$baseName] = [
                    'help' => "# HELP " . self::METRICS_PREFIX . $baseName . " " . ucfirst(str_replace('_', ' ', $baseName)) . " metric.",
                    'type' => "# TYPE " . self::METRICS_PREFIX . $baseName . " " . self::getPrometheusType($typeSuffix),
                    'values' => []
                ];
            }
            $output[$baseName]['values'][] = self::METRICS_PREFIX . $metricName . ($labelsString ? '{' . $labelsString . '}' : '') . " " . $value;
        }

        $formattedMetrics = [];
        foreach ($output as $metricData) {
            $formattedMetrics[] = $metricData['help'];
            $formattedMetrics[] = $metricData['type'];
            $formattedMetrics = array_merge($formattedMetrics, $metricData['values']);
        }

        return implode("\n", $formattedMetrics) . "\n";
    }

    /**
     * Builds a unique key for storing a metric in the store.
     * Format: fingerprint_metricName{label1="value1",label2="value2"}_type
     * @param string $name
     * @param array<string, string> $labels
     * @param string $typeSuffix 'counter', 'gauge', 'sum', 'count'
     * @return string
     */
    private static function buildMetricKey(string $name, array $labels, string $typeSuffix): string
    {
        $labelParts = [];
        ksort($labels); // Ensure consistent order for key generation
        foreach ($labels as $key => $value) {
            $labelParts[] = "{$key}=\"{$value}\"";
        }
        $labelsString = implode(',', $labelParts);
        return self::METRICS_PREFIX . $name . ($labelsString ? '{' . $labelsString . '}' : '') . '_' . $typeSuffix;
    }

    /**
     * Parses a metric key back into its components.
     * @param string $key
     * @return array{string, string, string} [metricName, labelsString, typeSuffix]
     */
    private static function parseMetricKey(string $key): array
    {
        $key = str_replace(self::METRICS_PREFIX, '', $key);
        preg_match('/^([a-zA-Z0-9_]+)(?:\{(.*)\})?_([a-z]+)$/', $key, $matches);
        return [$matches[1], $matches[2] ?? '', $matches[3]];
    }

    /**
     * Maps our internal type suffix to Prometheus type.
     * @param string $typeSuffix
     * @return string
     */
    private static function getPrometheusType(string $typeSuffix): string
    {
        switch ($typeSuffix) {
            case 'counter':
                return 'counter';
            case 'gauge':
                return 'gauge';
            case 'sum':
            case 'count':
                return 'summary'; // Prometheus summary has _sum and _count
            default:
                return 'untyped';
        }
    }
}