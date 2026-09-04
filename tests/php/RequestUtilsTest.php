<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Tests;

use Anonympins\Fingerprint\RequestContext;
use Anonympins\Fingerprint\Store\StoreManager;
use Anonympins\Fingerprint\Store\InMemoryStore;
use Anonympins\Fingerprint\Utils\RequestUtils;
use PHPUnit\Framework\TestCase;

class RequestUtilsTest extends TestCase
{
    private InMemoryStore $store;

    protected function setUp(): void
    {
        parent::setUp();
        $this->store = new InMemoryStore();
        // Configure le StoreManager pour utiliser notre InMemoryStore mocké
        StoreManager::configureStore($this->store);
    }

    protected function tearDown(): void
    {
        // Nettoie le store après chaque test
        $this->store->clear();
        parent::tearDown();
    }

    public function testUpdateSubnetMetricsIncrementsHighScoreCountWhenScoreIsBelow95AndContributionsAreBelow5(): void
    {
        $clientIp = '192.168.1.10';
        $deviceId = 'device-123';
        $finalScore = 80.0; // Below 95

        $context = $this->createMock(RequestContext::class);
        $context->clientIp = $clientIp;

        // Initialiser le subnetData dans le store
        $subnetKey = 'subnet:192.168.1.0/24';
        $initialSubnetData = [
            'highScoreCount' => 0,
            'deviceIds' => [],
            'highScoreDevices' => [],
            'lastActivity' => 0
        ];
        $this->store->set($subnetKey, $initialSubnetData);

        RequestUtils::updateSubnetMetrics($context, $deviceId, $finalScore);

        $updatedSubnetData = $this->store->get($subnetKey);
        $this->assertNotNull($updatedSubnetData);
        $this->assertEquals(1, $updatedSubnetData['highScoreCount']);
        $this->assertEquals(1, $updatedSubnetData['highScoreDevices'][$deviceId]);
    }

    public function testUpdateSubnetMetricsDoesNotIncrementHighScoreCountWhenScoreIs95OrAbove(): void
    {
        $clientIp = '192.168.1.10';
        $deviceId = 'device-123';
        $finalScore = 95.0; // Equal to 95

        $context = $this->createMock(RequestContext::class);
        $context->clientIp = $clientIp;

        $subnetKey = 'subnet:192.168.1.0/24';
        $initialSubnetData = [
            'highScoreCount' => 0,
            'deviceIds' => [],
            'highScoreDevices' => [],
            'lastActivity' => 0
        ];
        $this->store->set($subnetKey, $initialSubnetData);

        RequestUtils::updateSubnetMetrics($context, $deviceId, $finalScore);

        $updatedSubnetData = $this->store->get($subnetKey);
        $this->assertNotNull($updatedSubnetData);
        $this->assertEquals(0, $updatedSubnetData['highScoreCount']);
        $this->assertArrayNotHasKey($deviceId, $updatedSubnetData['highScoreDevices']);

        $finalScore = 100.0; // Above 95
        RequestUtils::updateSubnetMetrics($context, $deviceId, $finalScore);
        $updatedSubnetData = $this->store->get($subnetKey);
        $this->assertEquals(0, $updatedSubnetData['highScoreCount']);
    }

    public function testUpdateSubnetMetricsDoesNotIncrementHighScoreCountWhenContributionsAre5OrAbove(): void
    {
        $clientIp = '192.168.1.10';
        $deviceId = 'device-123';
        $finalScore = 80.0; // Below 95

        $context = $this->createMock(RequestContext::class);
        $context->clientIp = $clientIp;

        $subnetKey = 'subnet:192.168.1.0/24';
        $initialSubnetData = [
            'highScoreCount' => 10,
            'deviceIds' => [$deviceId],
            'highScoreDevices' => [$deviceId => 5], // Contributions already 5
            'lastActivity' => 0
        ];
        $this->store->set($subnetKey, $initialSubnetData);

        RequestUtils::updateSubnetMetrics($context, $deviceId, $finalScore);

        $updatedSubnetData = $this->store->get($subnetKey);
        $this->assertNotNull($updatedSubnetData);
        // highScoreCount ne devrait pas changer car les contributions sont déjà à 5
        $this->assertEquals(10, $updatedSubnetData['highScoreCount']);
        // highScoreDevices pour ce deviceId ne devrait pas changer non plus
        $this->assertEquals(5, $updatedSubnetData['highScoreDevices'][$deviceId]);
    }
}
```