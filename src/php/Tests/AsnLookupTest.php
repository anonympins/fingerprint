<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Tests;

use Anonympins\Fingerprint\AsnLookupEngine;
use Anonympins\Fingerprint\NetworkProfile;
use Anonympins\Fingerprint\Utils\RequestUtils;
use PHPUnit\Framework\TestCase;

class AsnLookupTest extends TestCase
{
    private AsnLookupEngine $engine;

    protected function setUp(): void
    {
        parent::setUp();
        $this->engine = AsnLookupEngine::getInstance();
    }

    public function testDatacenterResolutionAndPriorScore(): void
    {
        $hetzner = $this->engine->lookup('95.216.12.34');
        $this->assertSame('HOSTING', $hetzner->getType());
        $this->assertSame(55.0, $hetzner->getBaseScore());
        $this->assertSame(0.85, $hetzner->getInflectionPoint());
        $this->assertFalse($hetzner->isToleranceRotation());

        $aws = $this->engine->lookup('54.210.1.20');
        $this->assertSame('HOSTING', $aws->getType());
        $this->assertSame(55.0, $aws->getBaseScore());
    }

    public function testMobileCgnatResolution(): void
    {
        $cgnat = $this->engine->lookup('100.70.1.25');
        $this->assertSame('CELLULAR', $cgnat->getType());
        $this->assertSame(10.0, $cgnat->getBaseScore());
        $this->assertSame(0.60, $cgnat->getInflectionPoint());
        $this->assertTrue($cgnat->isToleranceRotation());
    }

    public function testStarlinkSatelliteResolution(): void
    {
        $starlink = $this->engine->lookup('98.97.10.5');
        $this->assertSame('SATELLITE', $starlink->getType());
        $this->assertSame(15.0, $starlink->getBaseScore());
        $this->assertSame(150.0, $starlink->getJitterTolerance());
    }

    public function testAnalogInconsistencyModulation(): void
    {
        $consistency = 0.80; // Incohérence légère de rendu
        $scoreDatacenter = RequestUtils::calculateAnalogInconsistencyScore($consistency, NetworkProfile::hosting());
        $scoreMobile = RequestUtils::calculateAnalogInconsistencyScore($consistency, NetworkProfile::cellular());

        $this->assertGreaterThan(55.0, $scoreDatacenter, 'Sur Datacenter (0.80 < 0.85), la suspicion décolle au-dessus de 55.0');
        $this->assertLessThan(10.0, $scoreMobile, 'Sur Mobile (0.80 > 0.60), la variation est entièrement absorbée (< 10.0)');
    }
}