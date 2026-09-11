<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Tests;

use Anonympins\Fingerprint\Challenge\ChallengeUtils;
use Anonympins\Fingerprint\Utils\BigInt;
use PHPUnit\Framework\TestCase;

class ChallengeUtilsTest extends TestCase
{
    public function testGpuPowDeterministicHashing(): void
    {
        $seed = 'test-seed-determinism';
        $f1 = ChallengeUtils::hashSeedToFloat($seed);
        $f2 = ChallengeUtils::hashSeedToFloat($seed);
        $f3 = ChallengeUtils::hashSeedToFloat('different-seed');

        $this->assertEquals($f1, $f2, 'Seed hashing must be deterministic.');
        $this->assertGreaterThanOrEqual(0, $f1);
        $this->assertLessThan(1, $f1);
        $this->assertNotEquals($f1, $f3);
    }

    public function testGpuPowVerificationRejectsTamperedSolution(): void
    {
        $seed = 'php-verification-seed';
        $iterations = 100;

        // Generate correct solutions mimicking the GPU solver trajectory
        $numericSeed = ChallengeUtils::hashSeedToFloat($seed);
        $r = 3.9999;
        $solutions = [];
        $fround = function (float $value): float {
            return unpack('f', pack('f', $value))[1];
        };

        for ($idx = 0; $idx < 64; $idx++) {
            $x = $fround($numericSeed + $idx * 0.015);
            $rFloat = $fround($r);
            for ($i = 0; $i < $iterations; $i++) {
                $x = $fround($rFloat * $x * $fround(1.0 - $x));
            }
            $solutions[] = number_format($x, 6, '.', '');
        }
        $validSolution = implode(',', $solutions);

        $this->assertTrue(ChallengeUtils::verifyGpuPow($seed, $iterations, $validSolution));

        // Tamper with value on verified sample index 12
        $tampered = $solutions;
        $tampered[12] = (string)((float)$tampered[12] + 0.0002); // Out of tolerance
        $this->assertFalse(ChallengeUtils::verifyGpuPow($seed, $iterations, implode(',', $tampered)));
    }

    public function testGpuPowVerification(): void
    {
        $seed = 'php-gpu-test-seed';
        $iterations = 50;
        
        $hash = 0;
        for ($i = 0; $i < strlen($seed); $i++) {
            $hash = (($hash << 5) - $hash + ord($seed[$i])) & 0xffffffff;
            if ($hash & 0x80000000) {
                $hash = $hash - 0x100000000;
            }
        }
        $numericSeed = abs($hash % 1000000) / 1000000;
        $r = 3.9999;
        $solutions = [];
        $fround = function (float $value): float {
            return unpack('f', pack('f', $value))[1];
        };
        for ($idx = 0; $idx < 64; $idx++) {
            $x = $fround($numericSeed + $idx * 0.015);
            $rFloat = $fround($r);
            for ($i = 0; $i < $iterations; $i++) {
                $x = $fround($rFloat * $x * $fround(1.0 - $x));
            }
            $solutions[] = number_format($x, 6, '.', '');
        }
        $solutionString = implode(',', $solutions);
        $this->assertTrue(ChallengeUtils::verifyGpuPow($seed, $iterations, $solutionString));
        $tamperedSolutions = $solutions;
        $tamperedSolutions[0] = (string)((float)$tamperedSolutions[0] + 0.1);
        $this->assertFalse(ChallengeUtils::verifyGpuPow($seed, $iterations, implode(',', $tamperedSolutions)));
    }

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

    public function testCooperativePoSpaceWorkflow(): void
    {
        $clientIp = '127.0.0.1';
        $nodeIdA = 'node-a';
        $seedA = 'seed-a';
        
        // 1. Enregistrement du nœud A (pair)
        ChallengeUtils::registerCooperativeNode($clientIp, $nodeIdA, $seedA);
        
        // 2. Recherche de pair pour le nœud B (dans le même sous-réseau)
        $peer = ChallengeUtils::findPeerInSubnet($clientIp, 'node-b');
        $this->assertNotNull($peer);
        $this->assertEquals($nodeIdA, $peer['nodeId']);
        $this->assertEquals($seedA, $peer['seed']);
        
        // 3. Demande de bloc du nœud B vers le nœud A
        $paramsReq = [
            'coop_op' => 'request_peer_block',
            'node_id' => 'node-b',
            'peer_id' => 'node-a',
            'block_idx' => '42',
            'req_id' => 'req-123'
        ];
        $resReq = ChallengeUtils::handleCooperativeRequest($paramsReq);
        $this->assertEquals('queued', $resReq['status']);
        
        // 4. Récupération de la demande par le nœud A
        $paramsPoll = [
            'coop_op' => 'poll_requests',
            'node_id' => 'node-a'
        ];
        $resPoll = ChallengeUtils::handleCooperativeRequest($paramsPoll);
        $this->assertCount(1, $resPoll['requests']);
        $this->assertEquals('req-123', $resPoll['requests'][0]['req_id']);
        $this->assertEquals(42, $resPoll['requests'][0]['block_idx']);
        
        // 5. Réponse avec la donnée de bloc par le nœud A
        $paramsResp = [
            'coop_op' => 'respond_block',
            'node_id' => 'node-a',
            'requester_id' => 'node-b',
            'req_id' => 'req-123',
            'block_data' => 'dummy-block-data-xyz'
        ];
        $resResp = ChallengeUtils::handleCooperativeRequest($paramsResp);
        $this->assertEquals('delivered', $resResp['status']);
    }
}