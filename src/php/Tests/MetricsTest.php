<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Tests;

use Anonympins\Fingerprint\RequestContext;
use Anonympins\Fingerprint\DirectFingerprint;
use Anonympins\Fingerprint\Utils\MetricsManager;
use Anonympins\Fingerprint\Store\InMemoryStore;
use Anonympins\Fingerprint\Store\StoreManager;
use PHPUnit\Framework\TestCase;

class MetricsTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        StoreManager::configureStore(new InMemoryStore());
    }

    public function testIncrementCounterAndGetPrometheusMetrics(): void
    {
        MetricsManager::incrementCounter('requests_total', ['status' => 'passed']);
        $metrics = MetricsManager::getPrometheusMetrics();

        $this->assertStringContainsString('fingerprint_requests_total', $metrics);
        $this->assertStringContainsString('status="passed"', $metrics);
    }

    public function testGetPrometheusMetricsViaDirectFingerprint(): void
    {
        $config = [
            'metricsAuthorizationCallback' => function (RequestContext $context) {
                return true;
            }
        ];

        $direct = new DirectFingerprint($config);
        MetricsManager::incrementCounter('requests_total', ['status' => 'passed']);
        $metrics = $direct->getPrometheusMetrics();

        $this->assertNotNull($metrics);
        $this->assertStringContainsString('fingerprint_requests_total', $metrics);
    }

    public function testGetMetricSecurityWeights(): void
    {
        $config = [
            'weights' => [
                'historyScore' => 0.3,
                'rotationScore' => 0.5,
                'invalidWeight' => 'not-a-number'
            ]
        ];

        $weights = MetricsManager::getMetric('security_weight', $config);
        $this->assertArrayHasKey('historyScore', $weights);
        $this->assertEquals(0.3, $weights['historyScore']);
        $this->assertArrayHasKey('rotationScore', $weights);
        $this->assertEquals(0.5, $weights['rotationScore']);
        $this->assertArrayNotHasKey('invalidWeight', $weights);
    }

    public function testGetMetricSecurityThresholds(): void
    {
        $config = [
            'thresholds' => [
                'low' => 20,
                'medium' => 45,
                'high' => 75,
                'block' => 95
            ]
        ];

        $thresholds = MetricsManager::getMetric('security_threshold', $config);
        $this->assertEquals(20.0, $thresholds['low']);
        $this->assertEquals(45.0, $thresholds['medium']);
        $this->assertEquals(75.0, $thresholds['high']);
        $this->assertEquals(95.0, $thresholds['block']);
    }

    public function testGetMetricDynamicCountersAndObservations(): void
    {
        MetricsManager::clearMetrics();
        MetricsManager::incrementCounter('requests_total', ['status' => 'passed']);
        MetricsManager::incrementCounter('requests_total', ['status' => 'passed']);
        MetricsManager::incrementCounter('requests_total', ['status' => 'blocked']);

        $counters = MetricsManager::getMetric('requests_total');
        $this->assertEquals(2, $counters['status="passed"']);
        $this->assertEquals(1, $counters['status="blocked"']);

        MetricsManager::observeValue('suspicion_score', 85.5, ['action' => 'blocked']);
        $observations = MetricsManager::getMetric('suspicion_score');
        $this->assertEquals(85.5, $observations['action="blocked"']);
    }
}