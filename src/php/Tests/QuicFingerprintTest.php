<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Tests;

use Anonympins\Fingerprint\RequestContext;
use Anonympins\Fingerprint\Utils\RequestUtils;
use PHPUnit\Framework\TestCase;

class QuicFingerprintTest extends TestCase
{
    public function testGetQuicAnomalyScoreReturnsZeroIfNoFp(): void
    {
        $context = $this->createMock(RequestContext::class);
        $context->method('getHeader')->willReturn(null);
        $res = RequestUtils::getQuicAnomalyScore($context);
        $this->assertEquals(0.0, $res['quicAnomalyScore']);
    }

    public function testGetQuicAnomalyScoreDetectsSpoofedChrome(): void
    {
        $context = $this->createMock(RequestContext::class);
        $context->method('getHeader')->willReturnCallback(function($name) {
            if ($name === 'user-agent') {
                return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
            }
            if ($name === 'x-quic-fp') {
                return '1;1=65536,4=50;i=0';
            }
            return null;
        });

        $res = RequestUtils::getQuicAnomalyScore($context);
        $this->assertEquals(100.0, $res['quicAnomalyScore']);
    }

    public function testGetQuicAnomalyScoreAllowsLegitChrome(): void
    {
        $context = $this->createMock(RequestContext::class);
        $context->method('getHeader')->willReturnCallback(function($name) {
            if ($name === 'user-agent') {
                return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
            }
            if ($name === 'x-quic-fp') {
                return '1;1=1572864,4=100;u=2,i';
            }
            return null;
        });

        $res = RequestUtils::getQuicAnomalyScore($context);
        $this->assertEquals(0.0, $res['quicAnomalyScore']);
    }
}