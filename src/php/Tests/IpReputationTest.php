<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Tests;

use PHPUnit\Framework\TestCase;
use Anonympins\Fingerprint\Utils\RequestUtils;
use Anonympins\Fingerprint\Store\StoreManager;
use Anonympins\Fingerprint\Store\IStore;

class IpReputationTest extends TestCase
{
    private $store;

    protected function setUp(): void
    {
        parent::setUp();

        // Un mock anonyme simple et en mémoire du Store pour isoler les tests
        $this->store = new class implements IStore {
            private array $data = [];
            public function get(string $key) { return $this->data[$key] ?? null; }
            public function set(string $key, $value, ?int $ttl = null): void { $this->data[$key] = $value; }
            public function has(string $key): bool { return isset($this->data[$key]); }
            public function delete(string $key): void { unset($this->data[$key]); }
        };

        StoreManager::setStore($this->store);
    }

    public function testGetScoreReturnsZeroForUnknownIp(): void
    {
        $score = RequestUtils::getIpReputationScore('8.8.8.8');
        $this->assertEquals(0.0, $score);
    }

    public function testUpdateScoreChangesValueCorrectly(): void
    {
        $ip = '8.8.4.4';
        RequestUtils::updateIpReputationScore($ip, 45.0);
        $this->assertEquals(45.0, RequestUtils::getIpReputationScore($ip));

        RequestUtils::updateIpReputationScore($ip, -15.0);
        $this->assertEquals(30.0, RequestUtils::getIpReputationScore($ip));
    }

    public function testBoundsAreClampedBetween0And100(): void
    {
        $ip = '1.1.1.1';
        RequestUtils::updateIpReputationScore($ip, 120.0);
        $this->assertEquals(100.0, RequestUtils::getIpReputationScore($ip));

        RequestUtils::updateIpReputationScore($ip, -150.0);
        $this->assertEquals(0.0, RequestUtils::getIpReputationScore($ip));
    }

    public function testTimeDecayCalculatesLossOfTwoPointsPerHour(): void
    {
        $ip = '2.2.2.2';
        $now = time();

        // Simulation d'un score de 80 vieux de 4 heures (4 * 2 = 8 points de perte)
        $this->store->set("ip-reputation:{$ip}", [
            'score' => 80.0,
            'lastUpdate' => $now - 14400
        ]);

        $score = RequestUtils::getIpReputationScore($ip);
        $this->assertEquals(72.0, $score);
    }
}