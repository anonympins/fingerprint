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

    public function testZkpProofValidation(): void
    {
        $fp = 'cvs:12345|gpu:67890';
        $p = BigInt::fromHex('fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f');
        $g = new BigInt(2);

        $x = BigInt::fromHex(hash('sha256', $fp))->mod($p);
        $y = $g->modPow($x, $p);
        $v = new BigInt(987654321);
        $t = $g->modPow($v, $p);

        $cStr = (string)$g . (string)$y . (string)$t;
        $c = BigInt::fromHex(hash('sha256', $cStr))->mod($p);
        $s = $v->add($c->mul($x))->mod($p->sub(new BigInt(1)));

        $zkpProof = $y->toHex() . ':' . $t->toHex() . ':' . $s->toHex();
        $this->assertTrue(ChallengeUtils::verifyZkpProof($y->toHex(), $t->toHex(), $s->toHex()));

        $ticket = ChallengeUtils::generateStatelessTicket([
            'expiry' => (time() + 3600) * 1000,
            'originalIp' => '127.0.0.1',
            'deviceId' => 'dev-zkp',
            'deviceHash' => 'zkp:' . $y->toHex()
        ]);

        $this->assertTrue(ChallengeUtils::isTicketValid('127.0.0.1', $ticket, 'dev-zkp', '', false, '', $zkpProof));
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

    public function testEd25519TicketValidation(): void
    {
        if (!extension_loaded('openssl')) {
            $this->markTestSkipped('openssl extension is not loaded.');
        }

        if (!defined('OPENSSL_KEYTYPE_ED25519')) {
            $this->markTestSkipped('Ed25519 is not supported or constant OPENSSL_KEYTYPE_ED25519 is undefined in this PHP/OpenSSL environment.');
        }

        $pkey = @openssl_pkey_new(["private_key_type" => constant('OPENSSL_KEYTYPE_ED25519')]);
        if (!$pkey) {
            $this->markTestSkipped('Ed25519 is not supported in this PHP/OpenSSL environment.');
        }

        openssl_pkey_export($pkey, $privateKeyPem);
        $details = openssl_pkey_get_details($pkey);
        $publicKeyPem = $details['key'];

        // Test if openssl_sign supports null algorithm for Ed25519 (PHP 8.0.0 bug)
        $testSig = '';
        $testPriv = @openssl_pkey_get_private($privateKeyPem);
        try {
            if (!$testPriv || !@openssl_sign('test', $testSig, $testPriv, null)) {
                $this->markTestSkipped('Ed25519 signing is not fully supported or buggy in this PHP/OpenSSL environment.');
            }
        } catch (\TypeError $e) {
            $this->markTestSkipped('Ed25519 signing is not supported due to PHP 8.0.0 openssl_sign() null algorithm bug.');
        }

        $_ENV['ED25519_PRIVATE_KEY'] = $privateKeyPem;
        $_ENV['ED25519_PUBLIC_KEY'] = $publicKeyPem;

        $ip = '127.0.0.1';
        $expiry = (int)floor(microtime(true) * 1000) + 3600000;
        $payload = [
            'expiry' => $expiry,
            'originalIp' => $ip,
            'deviceId' => 'device-123',
            'deviceHash' => 'hash-abc'
        ];

        $ticket = ChallengeUtils::generateStatelessTicket($payload);
        $this->assertStringStartsWith('ed25519.', $ticket);

        $this->assertTrue(ChallengeUtils::isTicketValid($ip, $ticket, 'device-123', 'hash-abc'));
        $this->assertFalse(ChallengeUtils::isTicketValid('192.168.1.1', $ticket, 'device-123', 'hash-abc'));

        unset($_ENV['ED25519_PRIVATE_KEY'], $_ENV['ED25519_PUBLIC_KEY']);
    }
}