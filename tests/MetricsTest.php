<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Tests;

use PHPUnit\Framework\TestCase;
use Anonympins\Fingerprint\DirectFingerprint;
use Anonympins\Fingerprint\Utils\MetricsManager;

class MetricsTest extends TestCase
{
    protected function setUp(): void
    {
        DirectFingerprint::setLastBestSolution(null);
    }

    public function testGetPrometheusMetricsOutputsWeightsAndThresholds(): void
    {
        $config = [
            'weights' => [
                'historyScore' => 0.35,
                'rotationScore' => 0.65,
            ],
            'thresholds' => [
                'low' => 22,
                'block' => 92,
            ]
        ];

        $output = MetricsManager::getPrometheusMetrics($config);

        $this->assertStringContainsString('fingerprint_requests_total{status="passed"} 1', $output);
        $this->assertStringContainsString('fingerprint_security_weight{indicator="historyScore"} 0.35', $output);
        $this->assertStringContainsString('fingerprint_security_weight{indicator="rotationScore"} 0.65', $output);
        $this->assertStringContainsString('fingerprint_security_threshold{level="low"} 22', $output);
        $this->assertStringContainsString('fingerprint_security_threshold{level="block"} 92', $output);
    }

    public function testGetPrometheusMetricsOutputsAutoTuningObjectives(): void
    {
        $config = [
            'weights' => [],
            'thresholds' => []
        ];

        $solution = [
            'objectives' => [0.0123, 0.0456]
        ];

        $output = MetricsManager::getPrometheusMetrics($config, $solution);

        $this->assertStringContainsString('fingerprint_autotuning_false_positive_rate 0.0123', $output);
        $this->assertStringContainsString('fingerprint_autotuning_false_negative_rate 0.0456', $output);
    }
}