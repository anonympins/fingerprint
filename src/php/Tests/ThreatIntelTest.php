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

    public function testDifferentialPrivacyDecoyInjectionAndTimestampNoise(): void
    {
        $config = [
            'federatedPeers' => ['https://peer1.example.com'],
            'federationSecret' => 'test-secret-key-32-chars-long!!',
            'differentialPrivacy' => [
                'enabled' => true,
                'epsilon' => 1.0,
                'dummyRate' => 1.0 // Forcer l'injection d'un leurre pour le test
            ]
        ];

        $postedCalls = [];
        $engineSub = new class($config, $postedCalls) extends \Anonympins\Fingerprint\FingerprintEngine {
            public array $calls = [];
            public function __construct(array $cfg, array &$callsRef) {
                $this->calls = &$callsRef;
                parent::__construct($cfg);
            }
            protected function asyncPost(string $url, array $params): void {
                $this->calls[] = ['url' => $url, 'params' => $params];
            }
        };

        $refSub = new \ReflectionClass($engineSub);
        $broadcastMethod = $refSub->getMethod('broadcastBannedZkp');
        $broadcastMethod->setAccessible(true);

        $realZkpY = 'realzkpykey12345';
        $broadcastMethod->invoke($engineSub, $realZkpY);

        $this->assertCount(2, $postedCalls, 'Doit diffuser à la fois la clé réelle et la clé leurre');
    }
}