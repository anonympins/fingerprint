<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Tests;

use Anonympins\Fingerprint\Challenge\ChallengeUtils;
use Anonympins\Fingerprint\Store\InMemoryStore;
use Anonympins\Fingerprint\Store\StoreManager;
use Anonympins\Fingerprint\Utils\BigInt;
 use Anonympins\Fingerprint\Utils\Env;
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
            $x = $fround(fmod($numericSeed + $idx * 0.015, 1.0));
            $x = $fround(fmod($numericSeed + $idx * 0.015, 1.0));
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
        $sampleIndices = ChallengeUtils::deriveSampleIndices('127.0.0.1', 'gpu-pow-salt');
        $tamperedIndex = $sampleIndices[0];
        $tampered[$tamperedIndex] = (string)((float)$tampered[$tamperedIndex] + 0.0002); // Out of tolerance
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
            $x = $fround(fmod($numericSeed + $idx * 0.015, 1.0));
            $rFloat = $fround($r);
            for ($i = 0; $i < $iterations; $i++) {
                $x = $fround($rFloat * $x * $fround(1.0 - $x));
            }
            $solutions[] = number_format($x, 6, '.', '');
        }
        $solutionString = implode(',', $solutions);
        $this->assertTrue(ChallengeUtils::verifyGpuPow($seed, $iterations, $solutionString));
        $sampleIndices = ChallengeUtils::deriveSampleIndices('127.0.0.1', 'gpu-pow-salt');
        $tamperedIndex = $sampleIndices[0];
        $tamperedSolutions = $solutions;
        $tamperedSolutions[$tamperedIndex] = (string)((float)$tamperedSolutions[$tamperedIndex] + 0.1);
        $this->assertFalse(ChallengeUtils::verifyGpuPow($seed, $iterations, implode(',', $tamperedSolutions)));
    }

    protected function setUp(): void
    {
        // Définir une clé secrète pour les tests
        $store = new InMemoryStore();
        StoreManager::configureStore($store);
        Env::set('POW_SECRET', 'test-secret-key-that-is-long-enough-for-hmac');
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

        Env::set('ED25519_PRIVATE_KEY', $privateKeyPem);
        Env::set('ED25519_PUBLIC_KEY', $publicKeyPem);

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

        Env::clear('ED25519_PRIVATE_KEY');
        Env::clear('ED25519_PUBLIC_KEY');
    }

    public function testCooperativePoSpaceWorkflow(): void
    {
        $clientIp = '127.0.0.1';
        $nodeIdA = 'node-a';
        $seedA = 'seed-a';
        
        // Configurer les secrets dans le store pour passer la validation de signature
        $store = StoreManager::getStore();
        $store->set("secret:node-a", ['clientSecret' => 'secret-a'], 300);
        $store->set("secret:node-b", ['clientSecret' => 'secret-b'], 300);

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
            'req_id' => 'req-123',
            'coop_sig' => hash('sha256', 'secret-b:request_peer_block:node-b:node-a:42:req-123')
        ];
        $resReq = ChallengeUtils::handleCooperativeRequest($paramsReq);
        $this->assertEquals('queued', $resReq['status']);
        
        // 4. Récupération de la demande par le nœud A
        $paramsPoll = [
            'coop_op' => 'poll_requests',
            'node_id' => 'node-a',
            'coop_sig' => hash('sha256', 'secret-a:poll_requests:node-a')
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
            'block_data' => 'dummy-block-data-xyz',
            'coop_sig' => hash('sha256', 'secret-a:respond_block:node-a:node-b:req-123:dummy-block-data-xyz')
        ];
        $resResp = ChallengeUtils::handleCooperativeRequest($paramsResp);
        $this->assertEquals('delivered', $resResp['status']);
    }

    public function testCooperativeRequestHandlingWithSignatures(): void
    {
        $store = StoreManager::getStore();

        // 1. Setup: Define test data
        $nodeIdA = 'node-alpha';
        $nodeIdB = 'node-beta';
        $clientSecretA = 'secret-alpha-for-node-a';
        $clientSecretB = 'secret-beta-for-node-b';
        $seedA = 'seed-for-alpha';
        $seedB = 'seed-for-beta';
        $blockIdx = 42;
        $reqId = 'req-12345';
        $blockData = '0102030405060708090a0b0c0d0e0f'; // Hex string representing block data

        // Mock $_SERVER['REMOTE_ADDR'] for register operation
        $_SERVER['REMOTE_ADDR'] = '192.168.1.100';

        // Store challenge contexts for both nodes (crucial for signature verification)
        $store->set("secret:{$nodeIdA}", ['clientSecret' => $clientSecretA], 300);
        $store->set("secret:{$nodeIdB}", ['clientSecret' => $clientSecretB], 300);

        // Helper to generate valid signatures (mimics client-side logic)
        $generateCoopSig = function (string $op, string $nodeId, string $clientSecret, ...$extraParams) {
            $msg = "{$clientSecret}:{$op}:{$nodeId}";
            foreach ($extraParams as $param) {
                $msg .= ":{$param}";
            }
            return hash('sha256', $msg);
        };

        // --- Test 1: Successful Registration (Node A) ---
        $sigA_register = $generateCoopSig('register', $nodeIdA, $clientSecretA, $seedA);
        $paramsRegisterA = [
            'coop_op' => 'register',
            'node_id' => $nodeIdA,
            'seed' => $seedA,
            'coop_sig' => $sigA_register
        ];
        $resRegisterA = ChallengeUtils::handleCooperativeRequest($paramsRegisterA);
        $this->assertEquals(['status' => 'registered'], $resRegisterA, 'Node A should register successfully.');

        // --- Test 2: Successful Registration (Node B) ---
        $sigB_register = $generateCoopSig('register', $nodeIdB, $clientSecretB, $seedB);
        $paramsRegisterB = [
            'coop_op' => 'register',
            'node_id' => $nodeIdB,
            'seed' => $seedB,
            'coop_sig' => $sigB_register
        ];
        $resRegisterB = ChallengeUtils::handleCooperativeRequest($paramsRegisterB);
        $this->assertEquals(['status' => 'registered'], $resRegisterB, 'Node B should register successfully.');

        // --- Test 3: Failed Registration (Invalid Signature) ---
        $paramsInvalidSig = $paramsRegisterA;
        $paramsInvalidSig['coop_sig'] = 'invalid-signature';
        $resInvalidSig = ChallengeUtils::handleCooperativeRequest($paramsInvalidSig);
        $this->assertEquals(['error' => 'Invalid cooperative signature'], $resInvalidSig, 'Registration with invalid signature should fail.');

        // --- Test 4: Successful Block Request (Node A requests from Node B) ---
        $sigA_requestBlock = $generateCoopSig('request_peer_block', $nodeIdA, $clientSecretA, $nodeIdB, (string)$blockIdx, $reqId);
        $paramsRequestBlock = [
            'coop_op' => 'request_peer_block',
            'node_id' => $nodeIdA,
            'peer_id' => $nodeIdB,
            'block_idx' => (string)$blockIdx,
            'req_id' => $reqId,
            'coop_sig' => $sigA_requestBlock
        ];
        $resRequestBlock = ChallengeUtils::handleCooperativeRequest($paramsRequestBlock);
        $this->assertEquals(['status' => 'queued'], $resRequestBlock, 'Block request should be queued.');

        // --- Test 5: Failed Block Request (Invalid Signature) ---
        $paramsInvalidSig = $paramsRequestBlock;
        $paramsInvalidSig['coop_sig'] = 'invalid-signature';
        $resInvalidSig = ChallengeUtils::handleCooperativeRequest($paramsInvalidSig);
        $this->assertEquals(['error' => 'Invalid cooperative signature'], $resInvalidSig, 'Block request with invalid signature should fail.');

        // --- Test 6: Successful Poll Requests (Node B polls for requests) ---
        $sigB_pollRequests = $generateCoopSig('poll_requests', $nodeIdB, $clientSecretB);
        $paramsPollRequests = [
            'coop_op' => 'poll_requests',
            'node_id' => $nodeIdB,
            'coop_sig' => $sigB_pollRequests
        ];
        $resPollRequests = ChallengeUtils::handleCooperativeRequest($paramsPollRequests);
        $this->assertCount(1, $resPollRequests['requests'], 'Node B should receive 1 request.');
        $this->assertEquals($reqId, $resPollRequests['requests'][0]['req_id']);
        $this->assertEquals($nodeIdA, $resPollRequests['requests'][0]['requester_id']);
        $this->assertEquals($blockIdx, $resPollRequests['requests'][0]['block_idx']);

        // --- Test 7: Failed Poll Requests (Invalid Signature) ---
        $paramsInvalidSig = $paramsPollRequests;
        $paramsInvalidSig['coop_sig'] = 'invalid-signature';
        $resInvalidSig = ChallengeUtils::handleCooperativeRequest($paramsInvalidSig);
        $this->assertEquals(['error' => 'Invalid cooperative signature'], $resInvalidSig, 'Poll requests with invalid signature should fail.');

        // --- Test 8: Successful Respond Block (Node B responds to Node A) ---
        $sigB_respondBlock = $generateCoopSig('respond_block', $nodeIdB, $clientSecretB, $nodeIdA, $reqId, $blockData);
        $paramsRespondBlock = [
            'coop_op' => 'respond_block',
            'node_id' => $nodeIdB,
            'requester_id' => $nodeIdA,
            'req_id' => $reqId,
            'block_data' => $blockData,
            'coop_sig' => $sigB_respondBlock
        ];
        $resRespondBlock = ChallengeUtils::handleCooperativeRequest($paramsRespondBlock);
        $this->assertEquals(['status' => 'delivered'], $resRespondBlock, 'Block response should be delivered.');

        // --- Test 9: Failed Respond Block (Invalid Signature) ---
        $paramsInvalidSig = $paramsRespondBlock;
        $paramsInvalidSig['coop_sig'] = 'invalid-signature';
        $resInvalidSig = ChallengeUtils::handleCooperativeRequest($paramsInvalidSig);
        $this->assertEquals(['error' => 'Invalid cooperative signature'], $resInvalidSig, 'Respond block with invalid signature should fail.');

        // --- Test 10: Successful Poll Response (Node A polls for response) ---
        $sigA_pollResponse = $generateCoopSig('poll_response', $nodeIdA, $clientSecretA, $reqId);
        $paramsPollResponse = [
            'coop_op' => 'poll_response',
            'node_id' => $nodeIdA,
            'req_id' => $reqId,
            'coop_sig' => $sigA_pollResponse
        ];
        $resPollResponse = ChallengeUtils::handleCooperativeRequest($paramsPollResponse);
        $this->assertEquals(['status' => 'ready', 'block_data' => $blockData], $resPollResponse, 'Node A should receive the block data.');

        // --- Test 11: Failed Poll Response (Invalid Signature) ---
        $paramsInvalidSig = $paramsPollResponse;
        $paramsInvalidSig['coop_sig'] = 'invalid-signature';
        $resInvalidSig = ChallengeUtils::handleCooperativeRequest($paramsInvalidSig);
        $this->assertEquals(['error' => 'Invalid cooperative signature'], $resInvalidSig, 'Poll response with invalid signature should fail.');

        // --- Test 12: Invalid/Expired node_id ---
        $paramsExpiredNode = ['coop_op' => 'register', 'node_id' => 'non-existent-node', 'coop_sig' => 'any-sig'];
        $resExpiredNode = ChallengeUtils::handleCooperativeRequest($paramsExpiredNode);
        $this->assertEquals(['error' => 'Invalid or expired node_id'], $resExpiredNode, 'Request with non-existent node_id should fail.');

        // --- Test 13: Missing node_id ---
        $paramsMissingNodeId = ['coop_op' => 'register', 'coop_sig' => 'any-sig'];
        $resMissingNodeId = ChallengeUtils::handleCooperativeRequest($paramsMissingNodeId);
        $this->assertEquals(['error' => 'Missing node_id'], $resMissingNodeId, 'Request without node_id should fail.');

        // --- Test 14: Invalid cooperative operation ---
        $paramsInvalidOp = ['coop_op' => 'unknown_op', 'node_id' => $nodeIdA, 'coop_sig' => 'any-sig'];
        $resInvalidOp = ChallengeUtils::handleCooperativeRequest($paramsInvalidOp);
        $this->assertEquals(['error' => 'Invalid cooperative operation'], $resInvalidOp, 'Request with unknown operation should fail.');
    }
}