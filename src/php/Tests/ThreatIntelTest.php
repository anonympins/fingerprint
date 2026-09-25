<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Tests;

use Anonympins\Fingerprint\Ja3AnomalyDetector;
use Anonympins\Fingerprint\RequestContext;
use Anonympins\Fingerprint\Store\InMemoryStore;
use Anonympins\Fingerprint\Store\StoreManager;
use Anonympins\Fingerprint\Utils\RequestUtils;
use PHPUnit\Framework\TestCase;

class ThreatIntelTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        StoreManager::configureStore(new InMemoryStore());
    }

    public function testRttProxyScoreReturnsZeroForCoherentTurnaround(): void
    {
        $reqTime = 1700000000000;
        $context = new RequestContext(
            '127.0.0.1', '/',
            [
                'x-tcp-rtt' => '15',
                'x-behavior-metrics' => json_encode(['clientTimestamp' => $reqTime - 30])
            ],
            [], null, [], '1.1', $reqTime
        );

        $score = Ja3AnomalyDetector::getRttProxyScore($context);
        $this->assertEquals(0.0, $score);
    }

    public function testRttProxyScoreIgnoresSlowConnectionWithoutTcpRtt(): void
    {
        $reqTime = 1700000000000;
        $context = new RequestContext(
            '127.0.0.1', '/',
            ['x-behavior-metrics' => json_encode(['clientTimestamp' => $reqTime - 450])],
            [], null, [], '1.1', $reqTime
        );

        $score = Ja3AnomalyDetector::getRttProxyScore($context);
        $this->assertEquals(0.0, $score, 'A slow connection without TCP RTT context should not trigger a false positive.');
    }

    public function testRttProxyScoreContinuouslyPenalizesResidentialTunneling(): void
    {
        $reqTime = 1700000000000;
        $context = new RequestContext(
            '127.0.0.1', '/',
            ['x-tcp-rtt' => '10', 'x-behavior-metrics' => json_encode(['clientTimestamp' => $reqTime - 300])],
            [], null, [], '1.1', $reqTime
        );

        $score = Ja3AnomalyDetector::getRttProxyScore($context);
        $this->assertGreaterThan(75.0, $score);
        $this->assertLessThanOrEqual(95.0, $score);
    }
}