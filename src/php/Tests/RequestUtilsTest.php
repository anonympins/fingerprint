<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Tests;

use PHPUnit\Framework\TestCase;
use Anonympins\Fingerprint\RequestContext;
use Anonympins\Fingerprint\Utils\RequestUtils;

class RequestUtilsTest extends TestCase
{
    private function createRequestContext(array $overrides = []): RequestContext
    {
        $defaults = [
            'clientIp' => '127.0.0.1',
            'path' => '/',
            'headers' => ['user-agent' => 'Test UA'],
            'query' => [],
            'body' => null,
            'cookies' => [],
            'httpVersion' => '1.1',
        ];
        $params = array_merge($defaults, $overrides);
        return new RequestContext(
            $params['clientIp'], $params['path'], $params['headers'],
            $params['query'], $params['body'], $params['cookies'], $params['httpVersion']
        );
    }

    public function testGetClickVarianceScoreReturnsZeroForNoHistory(): void
    {
        $context = $this->createRequestContext([
            'headers' => ['x-behavior-metrics' => json_encode([])]
        ]);
        $result = RequestUtils::getClickVarianceScore($context);
        $this->assertEquals(0.0, $result['clickVarianceScore']);
    }

    public function testGetClickVarianceScoreReturnsZeroForInsufficientClicks(): void
    {
        $metrics = [
            'clicksHistory' => [
                ['x' => 10, 'y' => 10, 'targetId' => 'hash1'],
                ['x' => 11, 'y' => 11, 'targetId' => 'hash1'],
                ['x' => 100, 'y' => 100, 'targetId' => 'hash2']
            ]
        ];
        $context = $this->createRequestContext(['headers' => ['x-behavior-metrics' => json_encode($metrics)]]);
        $result = RequestUtils::getClickVarianceScore($context);
        $this->assertEquals(0.0, $result['clickVarianceScore']);
    }

    public function testGetClickVarianceScoreReturnsHighScoreForLowVariance(): void
    {
        $metrics = [
            'clicksHistory' => [
                ['x' => 100, 'y' => 100, 'targetId' => 'hash1'],
                ['x' => 100.1, 'y' => 100.2, 'targetId' => 'hash1'],
                ['x' => 99.9, 'y' => 99.8, 'targetId' => 'hash1']
            ]
        ];
        $context = $this->createRequestContext(['headers' => ['x-behavior-metrics' => json_encode($metrics)]]);
        $result = RequestUtils::getClickVarianceScore($context);
        $this->assertGreaterThan(90, $result['clickVarianceScore']);
    }

    public function testGetClickVarianceScoreReturnsLowScoreForHighVariance(): void
    {
        $metrics = [
            'clicksHistory' => [
                ['x' => 105, 'y' => 110, 'targetId' => 'hash1'],
                ['x' => 98, 'y' => 102, 'targetId' => 'hash1'],
                ['x' => 112, 'y' => 95, 'targetId' => 'hash1']
            ]
        ];
        $context = $this->createRequestContext(['headers' => ['x-behavior-metrics' => json_encode($metrics)]]);
        $result = RequestUtils::getClickVarianceScore($context);
        $this->assertEquals(0.0, $result['clickVarianceScore']);
    }

    public function testSanitizeTrafficDataFiltersSybilAttacks(): void
    {
        $trafficData = [];
        // Ajout de 100 logs provenant d'un attaquant (Sybil)
        for ($i = 0; $i < 100; $i++) {
            $trafficData[] = ['deviceId' => 'attacker_device', 'type' => 'trap_triggered'];
        }
        // Ajout de 10 logs d'utilisateurs légitimes distincts
        for ($i = 0; $i < 10; $i++) {
            $trafficData[] = ['deviceId' => "legit_device_{$i}", 'type' => 'challenge_solved'];
        }

        $sanitized = RequestUtils::sanitizeTrafficData($trafficData);

        $attackerLogs = array_filter($sanitized, fn($log) => $log['deviceId'] === 'attacker_device');

        // Total de 110 logs. 2% de 110 est 2.2 -> max(3, 2) = 3 logs maximum autorisés pour l'attaquant.
        $this->assertLessThanOrEqual(3, count($attackerLogs));
    }
}