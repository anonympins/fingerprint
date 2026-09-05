<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Tests;

use Anonympins\Fingerprint\FingerprintBuilder;
use Anonympins\Fingerprint\RequestContext;
use Anonympins\Fingerprint\Utils\RequestUtils;
use PHPUnit\Framework\TestCase;

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

    public function testChallengePayloadSigningAndVerification(): void
    {
        $secret = 'test-fallback-dev-secret-32-chars-minimum';
        $clientIp = '203.0.113.42';
        $payload = [
            'clientSecret' => 'some_client_secret',
            'cpuTarget' => '00000000ffffffff',
            'fingerprint' => 'os:hash|gpu:hash2',
            'memDifficulty' => '16',
            'originalPath' => '/submit',
        ];

        // 1. Cas nominal : Signature et vérification réussies
        $signature = RequestUtils::signChallengePayload($secret, $payload, $clientIp);
        $this->assertNotEmpty($signature);

        $payloadWithSig = $payload;
        $payloadWithSig['signature'] = $signature;

        $isValid = RequestUtils::verifyChallengePayload($secret, $payloadWithSig, $clientIp);
        $this->assertTrue($isValid, "La signature valide doit être acceptée.");

        // 2. Détection de modification (tampering) sur cpuTarget
        $tamperedPayload = $payloadWithSig;
        $tamperedPayload['cpuTarget'] = 'ffffffffffffffff'; // Tentative de baisse de la difficulté
        
        $isTamperedValid = RequestUtils::verifyChallengePayload($secret, $tamperedPayload, $clientIp);
        $this->assertFalse($isTamperedValid, "Un payload modifié doit être rejeté.");

        // 3. Détection de modification sur le fingerprint
        $tamperedFpPayload = $payloadWithSig;
        $tamperedFpPayload['fingerprint'] = 'os:another_hash|gpu:hash2';
        
        $isTamperedFpValid = RequestUtils::verifyChallengePayload($secret, $tamperedFpPayload, $clientIp);
        $this->assertFalse($isTamperedFpValid, "Un fingerprint modifié doit être rejeté.");

        // 4. Détection d'usurpation d'adresse IP (IP mismatch)
        $isIpMismatchValid = RequestUtils::verifyChallengePayload($secret, $payloadWithSig, '198.51.100.1');
        $this->assertFalse($isIpMismatchValid, "Le payload ne doit pas être valide pour une autre adresse IP.");

        // 5. Absence de signature
        $isMissingSigValid = RequestUtils::verifyChallengePayload($secret, $payload, $clientIp);
        $this->assertFalse($isMissingSigValid, "Un payload sans signature doit être rejeté.");
    }

    public function testGetBehaviorScoreReturnsProperScores(): void
    {
        $contextEmpty = $this->createRequestContext();
        $scoreEmpty = RequestUtils::getBehaviorScore($contextEmpty);
        $this->assertEquals(0.0, $scoreEmpty['behaviorScore']);

        $metricsHoneypot = ['honeypotInteraction' => true];
        $contextHoneypot = $this->createRequestContext([
            'headers' => ['x-behavior-metrics' => json_encode($metricsHoneypot)]
        ]);
        $scoreHoneypot = RequestUtils::getBehaviorScore($contextHoneypot);
        $this->assertEquals(100.0, $scoreHoneypot['behaviorScore']);

        $metricsNoActivity = ['honeypotInteraction' => false, 'mouseMovementsHistory' => [], 'keystrokeLatency' => 0];
        $contextNoActivity = $this->createRequestContext([
            'headers' => ['x-behavior-metrics' => json_encode($metricsNoActivity)]
        ]);
        $scoreNoActivity = RequestUtils::getBehaviorScore($contextNoActivity);
        $this->assertEquals(40.0, $scoreNoActivity['behaviorScore']);
    }

    public function testGetTimeInconsistencyScore(): void
    {
        $requestTimestamp = time() * 1000;

        $metricsNormal = ['clientTimestamp' => $requestTimestamp - 100];
        $contextNormal = $this->createRequestContext([
            'headers' => ['x-behavior-metrics' => json_encode($metricsNormal)]
        ]);
        $contextNormal->requestTimestamp = $requestTimestamp;
        $scoreNormal = RequestUtils::getTimeInconsistencyScore($contextNormal);
        $this->assertEquals(0.0, $scoreNormal['timeInconsistencyScore']);

        $metricsReplay = ['clientTimestamp' => $requestTimestamp - 10000];
        $contextReplay = $this->createRequestContext([
            'headers' => ['x-behavior-metrics' => json_encode($metricsReplay)]
        ]);
        $contextReplay->requestTimestamp = $requestTimestamp;
        $scoreReplay = RequestUtils::getTimeInconsistencyScore($contextReplay);
        $this->assertGreaterThan(0.0, $scoreReplay['timeInconsistencyScore']);
    }

    public function testGetCrossLayerInconsistencyOSMismatch(): void
    {
        $windowsHash = FingerprintBuilder::cyrb53("Windows");
        $context = $this->createRequestContext([
            'headers' => [
                'x-device-fingerprint' => "os:{$windowsHash}",
                'user-agent' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15'
            ]
        ]);

        $score = RequestUtils::getCrossLayerInconsistency($context);
        $this->assertEquals(50.0, $score['crossLayerInconsistencyScore']);
    }

    public function testGetBotScoreDetections(): void
    {
        $contextBot = $this->createRequestContext([
            'headers' => ['x-device-fingerprint' => 'ua:123|bot:true']
        ]);
        $scoreBot = RequestUtils::getBotScore($contextBot);
        $this->assertEquals(100.0, $scoreBot['botScore']);

        $contextCdp = $this->createRequestContext([
            'headers' => ['x-device-fingerprint' => 'ua:123|cdp:true']
        ]);
        $scoreCdp = RequestUtils::getBotScore($contextCdp);
        $this->assertEquals(100.0, $scoreCdp['botScore']);

        $contextClean = $this->createRequestContext([
            'headers' => ['x-device-fingerprint' => 'ua:123|os:456']
        ]);
        $scoreClean = RequestUtils::getBotScore($contextClean);
        $this->assertEquals(0.0, $scoreClean['botScore']);
    }

    public function testGetHeaderAnomaliesFirefoxTE(): void
    {
        $contextFirefoxNoTe = $this->createRequestContext([
            'headers' => [
                'user-agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
                'accept-language' => 'en-US,en;q=0.9',
            ]
        ]);
        $scoreFirefoxNoTe = RequestUtils::getHeaderAnomalies($contextFirefoxNoTe);
        $this->assertEquals(30.0, $scoreFirefoxNoTe['headerAnomalyScore']);
    }

    public function testGetBehavioralIndicatorsRotationAndHistory(): void
    {
        $deviceData = [
            'ips' => ['127.0.0.1'],
            'lastFpHash' => 'cvs:original-canvas|gpu:original-gpu',
            'lastChangeTimestamp' => (time() * 1000) - 500,
            'rapidChangeCount' => 1
        ];

        $context = $this->createRequestContext([
            'headers' => ['x-device-fingerprint' => 'cvs:new-canvas|gpu:new-gpu']
        ]);

        $indicators = RequestUtils::getBehavioralIndicators($context, $deviceData);
        $this->assertEquals(2, $deviceData['rapidChangeCount']);
        $this->assertGreaterThan(0, $indicators['rotationScore']);
    }
}