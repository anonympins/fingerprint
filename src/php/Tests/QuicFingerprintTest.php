<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Tests;

use Anonympins\Fingerprint\RequestContext;
use Anonympins\Fingerprint\Utils\RequestUtils;
use PHPUnit\Framework\TestCase;

class QuicFingerprintTest extends TestCase
{
    public function testGetProtocolAnomalyScoreReturnsZeroIfNoFp(): void
    {
        $context = $this->createMock(RequestContext::class);
        $context->method('getHeader')->willReturn(null);
        $res = RequestUtils::getProtocolAnomalyScore($context);
        $this->assertEquals(0.0, $res['protocolAnomalyScore']);
    }

    public function testGetProtocolAnomalyScoreDetectsSpoofedChrome(): void
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

        $res = RequestUtils::getProtocolAnomalyScore($context);
        $this->assertEquals(100.0, $res['protocolAnomalyScore']);
    }

    public function testGetProtocolAnomalyScoreAllowsLegitChrome(): void
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

        $res = RequestUtils::getProtocolAnomalyScore($context);
        $this->assertEquals(0.0, $res['protocolAnomalyScore']);
    }

    public function testRfc9218PriorityWithoutIncrementalFlag(): void
    {
        $context = $this->createMock(RequestContext::class);
        $context->method('getHeader')->willReturnCallback(function($name) {
            if ($name === 'user-agent') return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
            if ($name === 'x-quic-fp') return '1;1=1572864,4=100;u=2'; // Manque le drapeau 'i'
            return null;
        });
        $res = RequestUtils::getProtocolAnomalyScore($context);
        $this->assertEquals(40.0, $res['quicAnomalyScore']);
    }

    public function testCompressionRatioPenalty(): void
    {
        $context = $this->createMock(RequestContext::class);
        $context->method('getHeader')->willReturnCallback(function($name) {
            if ($name === 'user-agent') return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
            if ($name === 'x-compression-info') return 'req_count:5,hpack_ratio:0.2';
            return null;
        });
        $res = RequestUtils::getProtocolAnomalyScore($context);
        $this->assertEquals(40.0, $res['http2AnomalyScore']);
    }

    public function testRfc9218UrgencyOutOfRange(): void
    {
        $context = $this->createMock(RequestContext::class);
        $context->method('getHeader')->willReturnCallback(function($name) {
            if ($name === 'user-agent') return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
            if ($name === 'x-quic-fp') return '1;1=1572864,4=100;u=9,i';
            return null;
        });
        $res = RequestUtils::getProtocolAnomalyScore($context);
        $this->assertGreaterThanOrEqual(50.0, $res['quicAnomalyScore']);
    }

    public function testHttp2DefaultGoScraperDependencyTree(): void
    {
        $context = $this->createMock(RequestContext::class);
        $context->method('getHeader')->willReturnCallback(function($name) {
            if ($name === 'user-agent') return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
            if ($name === 'x-http2-fingerprint') return 's:1:65536,2:0,3:1000,4:6291456,6:262144|15663105|1:0:0:16|m,a,s,p|p:3,w:4,c:1';
            return null;
        });
        $context->httpVersion = '2.0';
        $res = RequestUtils::getProtocolAnomalyScore($context);
        $this->assertGreaterThanOrEqual(55.0, $res['http2AnomalyScore']);
    }

    public function testScraperWithZeroDynamicTableEntries(): void
    {
        $context = $this->createMock(RequestContext::class);
        $context->method('getHeader')->willReturnCallback(function($name) {
            if ($name === 'user-agent') return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
            if ($name === 'x-compression-info') return 'req_count:5,dynamic_table_entries:0';
            return null;
        });
        $context->httpVersion = '2.0';
        $res = RequestUtils::getProtocolAnomalyScore($context);
        $this->assertGreaterThanOrEqual(45.0, $res['http2AnomalyScore']);
    }
}