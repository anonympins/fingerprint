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
}