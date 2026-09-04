<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Tests;

use Anonympins\Fingerprint\Challenge\ChallengeUtils;
use Anonympins\Fingerprint\Utils\BigInt;
use PHPUnit\Framework\TestCase;

class ChallengeUtilsTest extends TestCase
{
    protected function setUp(): void
    {
        // Définir une clé secrète pour les tests
        $_ENV['POW_SECRET'] = 'test-secret-key-that-is-long-enough-for-hmac';
    }

    public function testIsTicketValid(): void
    {
        $ip = '127.0.0.1';
        $expiry = (int)floor(microtime(true) * 1000) + 3600000; // 1 heure
        $signature = hash_hmac('sha256', "{$ip}:{$expiry}", $_ENV['POW_SECRET']);
        $validTicket = "{$expiry}:{$signature}";

        $this->assertTrue(ChallengeUtils::isTicketValid($ip, $validTicket));
        $this->assertFalse(ChallengeUtils::isTicketValid('192.168.1.1', $validTicket), "Le ticket ne doit pas être valide pour une autre IP.");

        $expiredExpiry = (int)floor(microtime(true) * 1000) - 1000;
        $expiredSignature = hash_hmac('sha256', "{$ip}:{$expiredExpiry}", $_ENV['POW_SECRET']);
        $expiredTicket = "{$expiredExpiry}:{$expiredSignature}";
        $this->assertFalse(ChallengeUtils::isTicketValid($ip, $expiredTicket), "Un ticket expiré doit être invalide.");

        $this->assertFalse(ChallengeUtils::isTicketValid($ip, 'invalid-ticket-format'), "Un format de ticket invalide doit être rejeté.");
    }

    public function testCpuTargetCalculation(): void
    {
        $config = ['cpu' => ['minDifficultyBits' => 8, 'maxDifficultyBits' => 24]];

        // Low suspicion -> minimum difficulty
        $targetLow = ChallengeUtils::calculateCpuTarget(0.0, $config);
        $expectedTargetLow = (new BigInt(1))->shiftLeft(256 - 8);
        $this->assertEquals(0, BigInt::fromHex($targetLow)->compareTo($expectedTargetLow), "Target for 0.0 suspicion should correspond to 8 bits of difficulty.");

        // High suspicion -> maximum difficulty
        $targetHigh = ChallengeUtils::calculateCpuTarget(1.0, $config);
        $expectedTargetHigh = (new BigInt(1))->shiftLeft(256 - 24);
        $this->assertEquals(0, BigInt::fromHex($targetHigh)->compareTo($expectedTargetHigh), "Target for 1.0 suspicion should correspond to 24 bits of difficulty.");

        // Medium suspicion -> intermediate difficulty
        $targetMid = ChallengeUtils::calculateCpuTarget(0.5, $config);
        $expectedBits = 8 + 0.5 * (24 - 8); // 16 bits
        $expectedTargetMid = (new BigInt(1))->shiftLeft(256 - (int)$expectedBits);
        $this->assertEquals(0, BigInt::fromHex($targetMid)->compareTo($expectedTargetMid), "Target for 0.5 suspicion should correspond to 16 bits of difficulty.");
    }

    public function testVerifyCpuTargetPoW(): void
    {
        $ip = '127.0.0.1';
        $nonce = 'test-nonce';
        $fingerprint = 'ua:test-fp';
        $clientSecret = 'test-secret';
        $baseBlock = ChallengeUtils::createCpuChallengeBaseBlock($nonce, $clientSecret, $fingerprint);

        // Cible facile pour un test rapide (ex: 4 zéros hexadécimaux -> 16 bits)
        $targetHex = '0000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
        $challengeContext = ['cpuTarget' => $targetHex, 'baseBlock' => $baseBlock];

        // Trouver une solution valide
        $solution = 0;
        while (true) {
            $hash = hash('sha256', $baseBlock . $solution);
            if (strcmp($hash, $targetHex) < 0) break;
            $solution++;
        }

        $ticket = ChallengeUtils::verifyCpuTargetPoWAndGenerateTicket($ip, 3600, $nonce, (string)$solution, $challengeContext);
        $this->assertNotNull($ticket, "Un ticket valide aurait dû être généré.");
        $this->assertTrue(ChallengeUtils::isTicketValid($ip, $ticket));
    }
}