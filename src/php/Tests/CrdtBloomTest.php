<?php

declare(strict_types=1);

namespace Anonympins\Fingerprint\Tests;

use Anonympins\Fingerprint\Challenge\ChallengeUtils;
use Anonympins\Fingerprint\Crdt\BloomFilterSync;
use Anonympins\Fingerprint\Crdt\LwwElementSet;
use Anonympins\Fingerprint\Store\InMemoryStore;
use Anonympins\Fingerprint\Store\StoreManager;
use PHPUnit\Framework\TestCase;

class CrdtBloomTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        StoreManager::configureStore(new InMemoryStore());
        ChallengeUtils::getThreatIntelCrdt()->clear();
        ChallengeUtils::getWhitelistCrdt()->clear();
    }

    public function testLwwElementSetAddRemoveResolution(): void
    {
        $crdt = new LwwElementSet();
        $now = 1000;

        $crdt->add("malicious-zkp-1", 1000, 60000);
        $this->assertTrue($crdt->contains("malicious-zkp-1", $now));

        $crdt->remove("malicious-zkp-1", 1005);
        $this->assertFalse($crdt->contains("malicious-zkp-1", $now));

        $crdt->add("malicious-zkp-1", 1002, 60000);
        $this->assertFalse($crdt->contains("malicious-zkp-1", $now), "Le tombstone postérieur (1005) doit l'emporter");

        $crdt->add("malicious-zkp-1", 1010, 60000);
        $this->assertTrue($crdt->contains("malicious-zkp-1", $now), "L'ajout postérieur (1010) doit réactiver l'élément");
    }

    public function testBloomFilterSyncCompressionAndDeltaReconciliation(): void
    {
        $peerA = new LwwElementSet();
        $peerB = new LwwElementSet();

        for ($i = 0; $i < 50; $i++) {
            $peerA->add("item-" . $i, 1000, 3600000);
        }
        $peerB->mergeDelta($peerA->exportDelta());
        $peerB->add("item-new-1", 1000, 3600000);
        $peerB->add("item-new-2", 1000, 3600000);
        $peerB->add("item-new-3", 1000, 3600000);

        $filterA = BloomFilterSync::create(100, 0.01);
        foreach ($peerA->getActiveElements(1000) as $key) {
            $filterA->put($key);
        }
        $compressed = $filterA->exportCompressedBase64();

        $remoteFilter = BloomFilterSync::fromCompressedBase64($compressed, $filterA->getBitSize(), $filterA->getNumHashFunctions());
        $missing = $remoteFilter->computeMissingDelta($peerB, 1000);

        $this->assertCount(3, $missing, "Seuls les 3 éléments différentiels doivent être détectés");
    }

    public function testHandleCooperativeRequestThreatIntelSyncAndMerge(): void
    {
        $now = (int)(microtime(true) * 1000);
        ChallengeUtils::getThreatIntelCrdt()->add("zkp-local-threat-99", $now, 86400000);

        // 1. Export du filtre de Bloom local
        $step1 = ChallengeUtils::handleCooperativeRequest(['coop_op' => 'sync_threat_intel']);
        $this->assertEquals('bloom_filter_ready', $step1['status']);
        $this->assertNotEmpty($step1['bloom_filter']);
        $this->assertGreaterThan(0, $step1['bit_size']);
        $this->assertGreaterThan(0, $step1['hash_count']);

        // 2. Calcul du delta à partir d'un filtre distant vide
        $emptyFilter = BloomFilterSync::create(50, 0.01);
        $step2 = ChallengeUtils::handleCooperativeRequest([
            'coop_op' => 'sync_threat_intel',
            'bloom_filter' => $emptyFilter->exportCompressedBase64(),
            'bit_size' => (string)$emptyFilter->getBitSize(),
            'hash_count' => (string)$emptyFilter->getNumHashFunctions(),
        ]);

        $this->assertEquals('delta_ready', $step2['status']);
        $this->assertGreaterThanOrEqual(1, $step2['delta_count']);
        $found = false;
        foreach ($step2['delta'] as $item) {
            if (($item['key'] ?? '') === 'zkp-local-threat-99') {
                $found = true;
                break;
            }
        }
        $this->assertTrue($found);

        // 3. Fusion d'un delta reçu
        $mergePayload = [
            ['key' => 'zkp-incoming-threat-88', 'addTs' => $now, 'remTs' => 0, 'ttlMs' => 86400000]
        ];
        $step3 = ChallengeUtils::handleCooperativeRequest([
            'coop_op' => 'merge_threat_intel',
            'delta' => json_encode($mergePayload)
        ]);

        $this->assertEquals('merged', $step3['status']);
        $this->assertTrue(ChallengeUtils::getThreatIntelCrdt()->contains('zkp-incoming-threat-88', $now));
    }

    public function testHandleCooperativeRequestWhitelistSyncAndMerge(): void
    {
        $now = (int)(microtime(true) * 1000);
        $step1 = ChallengeUtils::handleCooperativeRequest(['coop_op' => 'sync_whitelist']);
        $this->assertEquals('bloom_filter_ready', $step1['status']);
        $this->assertNotEmpty($step1['bloom_filter']);

        $whitelistDelta = [
            ['key' => 'ip:203.0.113.10', 'addTs' => $now, 'remTs' => 0, 'ttlMs' => 7200000],
            ['key' => 'subnet:192.0.2.0/24', 'addTs' => $now, 'remTs' => 0, 'ttlMs' => 7200000]
        ];
        $step2 = ChallengeUtils::handleCooperativeRequest([
            'coop_op' => 'merge_whitelist',
            'delta' => $whitelistDelta
        ]);
        $this->assertEquals('merged', $step2['status']);
        $this->assertTrue(ChallengeUtils::getWhitelistCrdt()->contains('ip:203.0.113.10', $now));
        $this->assertTrue(ChallengeUtils::getWhitelistCrdt()->contains('subnet:192.0.2.0/24', $now));
    }
}