<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Tests;

use Anonympins\Fingerprint\FingerprintEngine;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

class DnsCircuitBreakerTest extends TestCase
{
    private ReflectionClass $reflection;

    protected function setUp(): void
    {
        parent::setUp();
        $this->reflection = new ReflectionClass(FingerprintEngine::class);

        // Réinitialise l'état statique du disjoncteur avant chaque test
        $this->setCircuitBreakerState([
            'state' => 'CLOSED',
            'failureCount' => 0,
            'lastStateChange' => 0,
            'threshold' => 5,
            'cooldown' => 1, // 1 seconde de cooldown pour accélérer le test
        ]);
    }

    private function getCircuitBreakerState(): array
    {
        $property = $this->reflection->getProperty('dnsCircuitBreaker');
        if (PHP_VERSION_ID < 80100) {
            $property->setAccessible(true);
        }
        return $property->getValue();
    }

    private function setCircuitBreakerState(array $state): void
    {
        $property = $this->reflection->getProperty('dnsCircuitBreaker');
        if (PHP_VERSION_ID < 80100) {
            $property->setAccessible(true);
        }
        $property->setValue(null, $state);
    }

    private function invokeMethod(string $methodName, array $args = [])
    {
        $method = $this->reflection->getMethod($methodName);
        if (PHP_VERSION_ID < 80100) { // PHP 8.1.0
            $method->setAccessible(true);
        }
        return $method->invokeArgs(null, $args);
    }

    public function testInitialStateIsClosed(): void
    {
        $this->assertTrue($this->invokeMethod('canAttemptDns'));
        $state = $this->getCircuitBreakerState();
        $this->assertSame('CLOSED', $state['state']);
    }

    public function testFailureThresholdTripsBreaker(): void
    {
        for ($i = 0; $i < 4; $i++) {
            $this->invokeMethod('recordDnsFailure');
            $this->assertTrue($this->invokeMethod('canAttemptDns'));
            $state = $this->getCircuitBreakerState();
            $this->assertSame('CLOSED', $state['state']);
        }

        $this->invokeMethod('recordDnsFailure');
        $this->assertFalse($this->invokeMethod('canAttemptDns'));
        $state = $this->getCircuitBreakerState();
        $this->assertSame('OPEN', $state['state']);
    }

    public function testCooldownTransitionsToHalfOpen(): void
    {
        for ($i = 0; $i < 5; $i++) {
            $this->invokeMethod('recordDnsFailure');
        }
        $this->assertFalse($this->invokeMethod('canAttemptDns'));

        usleep(1100000); // 1.1s

        $this->assertTrue($this->invokeMethod('canAttemptDns'));
        $state = $this->getCircuitBreakerState();
        $this->assertSame('HALF-OPEN', $state['state']);
    }

    public function testSuccessOnHalfOpenResetsBreaker(): void
    {
        for ($i = 0; $i < 5; $i++) {
            $this->invokeMethod('recordDnsFailure');
        }
        usleep(1100000);
        $this->assertTrue($this->invokeMethod('canAttemptDns'));

        $this->invokeMethod('recordDnsSuccess');
        $state = $this->getCircuitBreakerState();
        $this->assertSame('CLOSED', $state['state']);
        $this->assertSame(0, $state['failureCount']);
    }
}