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
            'clientIp' => '192.168.1.10',
            'path' => '/',
            'headers' => [
                'user-agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36',
                'accept-language' => 'en-US,en;q=0.9',
            ],
            'query' => [],
            'body' => null,
            'cookies' => [],
            'httpVersion' => '1.1',
        ];

        $params = array_merge($defaults, $overrides);

        return new RequestContext(
            $params['clientIp'],
            $params['path'],
            $params['headers'],
            $params['query'],
            $params['body'],
            $params['cookies'],
            $params['httpVersion']
        );
    }

    public function testGetTlsSpoofingScoreReturnsZeroForConsistentUaAndJa3(): void
    {
        // JA3 for Chrome, User-Agent for Chrome
        $context = $this->createRequestContext(['headers' => ['user-agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36']]);
        $context->ja3 = 'e188a442b87f422c5a1e80b05399435b'; // Known Chrome JA3

        $result = RequestUtils::getTlsSpoofingScore($context);
        $this->assertEquals(0, $result['tlsSpoofingScore']);
    }

    public function testGetTlsSpoofingScoreReturnsHighForInconsistentUaAndJa3(): void
    {
        // JA3 for Chrome, User-Agent for Firefox
        $context = $this->createRequestContext(['headers' => ['user-agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0']]);
        $context->ja3 = 'e188a442b87f422c5a1e80b05399435b'; // Known Chrome JA3

        $result = RequestUtils::getTlsSpoofingScore($context);
        $this->assertEquals(80.0, $result['tlsSpoofingScore']);
    }

    public function testGetTlsSpoofingScoreReturnsPenaltyForMissingUaWithJa3(): void
    {
        $context = $this->createRequestContext(['headers' => []]);
        $context->ja3 = 'e188a442b87f422c5a1e80b05399435b';

        $result = RequestUtils::getTlsSpoofingScore($context);
        $this->assertEquals(50.0, $result['tlsSpoofingScore']);
    }

    public function testGetBehaviorScoreReturnsZeroForMissingHeader(): void
    {
        $context = $this->createRequestContext();
        $result = RequestUtils::getBehaviorScore($context);
        $this->assertEquals(0, $result['behaviorScore']);
    }

    public function testGetBehaviorScoreReturnsMaxForHoneypotInteraction(): void
    {
        $metrics = ['honeypotInteraction' => true];
        $context = $this->createRequestContext(['headers' => ['x-behavior-metrics' => json_encode($metrics)]]);
        $result = RequestUtils::getBehaviorScore($context);
        $this->assertEquals(100, $result['behaviorScore']);
    }

    public function testGetBehaviorScorePenalizesNoInteraction(): void
    {
        // historyLength is absent, so the no-interaction penalty should apply.
        $metrics = ['honeypotInteraction' => false, 'mouseEntropy' => 0, 'keystrokeLatency' => 0];
        $context = $this->createRequestContext(['headers' => ['x-behavior-metrics' => json_encode($metrics)]]);
        $result = RequestUtils::getBehaviorScore($context);
        $this->assertEquals(40, $result['behaviorScore']);
    }

    public function testGetBehaviorScoreHandlesHistoryLength(): void
    {
        // New session
        $metrics1 = ['historyLength' => 1, 'mouseEntropy' => 0, 'keystrokeLatency' => 0];
        $context1 = $this->createRequestContext(['headers' => ['x-behavior-metrics' => json_encode($metrics1)]]);
        $this->assertEquals(15, RequestUtils::getBehaviorScore($context1)['behaviorScore']);

        // Established session (bonus)
        $metrics2 = ['historyLength' => 10];
        $context2 = $this->createRequestContext(['headers' => ['x-behavior-metrics' => json_encode($metrics2)]]);
        $this->assertEquals(-20, RequestUtils::getBehaviorScore($context2)['behaviorScore']);
    }

    public function testGetTimeInconsistencyScore(): void
    {
        $requestTimestamp = (int)(microtime(true) * 1000);

        // No delay
        $metrics1 = ['clientTimestamp' => $requestTimestamp - 100];
        $context1 = $this->createRequestContext();
        $context1->requestTimestamp = $requestTimestamp;
        $this->assertEquals(0, RequestUtils::getTimeInconsistencyScore($context1, $metrics1)['timeInconsistencyScore']);

        // Replay attack
        $metrics2 = ['clientTimestamp' => $requestTimestamp - 6000]; // 6s delay
        $context2 = $this->createRequestContext();
        $context2->requestTimestamp = $requestTimestamp;
        // (6000 / 5000 - 1) * 50 = 10
        $this->assertEqualsWithDelta(10, RequestUtils::getTimeInconsistencyScore($context2, $metrics2)['timeInconsistencyScore'], 0.2);
    }

    public function testGetHoneypotScoreDetectsInjections(): void
    {
        $honeypotConfig = ['detectInjections' => true];

        // SQLi
        $context1 = $this->createRequestContext(['query' => ['id' => "1' OR '1'='1"]]);
        $this->assertEquals(100, RequestUtils::getHoneypotScore($context1, $honeypotConfig)['honeypotScore']);

        // Path Traversal
        $context2 = $this->createRequestContext(['body' => ['file' => '../../etc/passwd']]);
        $this->assertEquals(100, RequestUtils::getHoneypotScore($context2, $honeypotConfig)['honeypotScore']);

        // No injection
        $context3 = $this->createRequestContext(['body' => ['comment' => 'A normal comment.']]);
        $this->assertEquals(0, RequestUtils::getHoneypotScore($context3, $honeypotConfig)['honeypotScore']);
    }

    public function testGetRequestPatternScoreDetectsRegularity(): void
    {
        $patternConfig = ['minSamples' => 5, 'regularityThreshold' => 50, 'patternWeight' => 80];
        $deviceData = [
            'timingHistory' => [100, 100, 100, 100, 100], // stdDev = 0
            'requestHistory' => []
        ];
        $context = $this->createRequestContext();

        $result = RequestUtils::getRequestPatternScore($context, $deviceData, $patternConfig);
        $this->assertEquals(80, $result['requestPatternScore']);
    }
}