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
}