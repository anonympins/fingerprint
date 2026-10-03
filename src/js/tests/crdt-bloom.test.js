import { describe, it, beforeEach } from "vitest";
import assert from "node:assert/strict";
import { LwwElementSet, BloomFilterSync } from "../crdt.js";
import { handleCooperativeRequest, threatIntelCrdt, whitelistCrdt, FingerprintEngine } from "../fingerprint.js";

describe("CRDT et filtres de Bloom synchronisés", () => {
    beforeEach(() => {
        threatIntelCrdt.elements.clear();
        whitelistCrdt.elements.clear();
    });

    it("LwwElementSet gère correctement la résolution LWW (Last-Write-Wins)", () => {
        const crdt = new LwwElementSet();
        const now = 1000;

        // Ajout initial
        crdt.add("zkp-target-1", 1000, 60000);
        assert.equal(crdt.contains("zkp-target-1", now), true);

        // Révocation postérieure
        crdt.remove("zkp-target-1", 1005);
        assert.equal(crdt.contains("zkp-target-1", now), false);

        // Ajout antérieur désynchronisé ignoré par le tombstone
        crdt.add("zkp-target-1", 1002, 60000);
        assert.equal(crdt.contains("zkp-target-1", now), false);

        // Réactivation postérieure
        crdt.add("zkp-target-1", 1010, 60000);
        assert.equal(crdt.contains("zkp-target-1", now), true);
    });

    it("BloomFilterSync compresse, décompresse et identifie les deltas manquants", () => {
        const peerA = new LwwElementSet();
        const peerB = new LwwElementSet();

        for (let i = 0; i < 40; i++) {
            peerA.add(`zkp-device-${i}`, 1000, 3600000);
        }

        peerB.mergeDelta(peerA.exportDelta());
        peerB.add("zkp-device-delta-1", 1000, 3600000);
        peerB.add("zkp-device-delta-2", 1000, 3600000);

        const filterA = BloomFilterSync.create(100, 0.01);
        for (const item of peerA.getActiveElements(1000)) {
            filterA.put(item);
        }
        const compressedB64 = filterA.exportCompressedBase64();

        // Décompression côté Peer B et calcul du delta manquant
        const remoteFilter = BloomFilterSync.fromCompressedBase64(compressedB64, filterA.bitSize, filterA.numHashFunctions);
        const missing = remoteFilter.computeMissingDelta(peerB, 1000);

        assert.equal(missing.length, 2);
        const missingKeys = missing.map(m => m.key).sort();
        assert.deepEqual(missingKeys, ["zkp-device-delta-1", "zkp-device-delta-2"]);
    });

    it("handleCooperativeRequest exécute l'anti-entropie sync_threat_intel et merge_threat_intel", async () => {
        const now = Date.now();
        threatIntelCrdt.add("zkp-local-threat-99", now, 86400000);

        // 1. Export du filtre de Bloom local
        const step1 = await handleCooperativeRequest({ coop_op: "sync_threat_intel" });
        assert.equal(step1.status, "bloom_filter_ready");
        assert.ok(step1.bloom_filter);
        assert.ok(step1.bit_size > 0);
        assert.ok(step1.hash_count > 0);

        // 2. Calcul du delta à partir d'un filtre distant vide
        const emptyFilter = BloomFilterSync.create(50, 0.01);
        const step2 = await handleCooperativeRequest({
            coop_op: "sync_threat_intel",
            bloom_filter: emptyFilter.exportCompressedBase64(),
            bit_size: String(emptyFilter.bitSize),
            hash_count: String(emptyFilter.numHashFunctions)
        });

        assert.equal(step2.status, "delta_ready");
        assert.ok(step2.delta_count >= 1);
        assert.ok(step2.delta.some(d => d.key === "zkp-local-threat-99"));

        // 3. Fusion d'un delta reçu
        const mergePayload = [
            { key: "zkp-incoming-threat-88", addTs: now, remTs: 0, ttlMs: 86400000 }
        ];
        const step3 = await handleCooperativeRequest({
            coop_op: "merge_threat_intel",
            delta: JSON.stringify(mergePayload)
        });

        assert.equal(step3.status, "merged");
        assert.equal(threatIntelCrdt.contains("zkp-incoming-threat-88", now), true);
    });

    it("handleCooperativeRequest exécute l'anti-entropie sync_whitelist et merge_whitelist", async () => {
        const now = Date.now();

        const step1 = await handleCooperativeRequest({ coop_op: "sync_whitelist" });
        assert.equal(step1.status, "bloom_filter_ready");
        assert.ok(step1.bloom_filter);

        const whitelistDelta = [
            { key: "ip:203.0.113.10", addTs: now, remTs: 0, ttlMs: 7200000 },
            { key: "subnet:192.0.2.0/24", addTs: now, remTs: 0, ttlMs: 7200000 }
        ];
        const step2 = await handleCooperativeRequest({
            coop_op: "merge_whitelist",
            delta: whitelistDelta
        });

        assert.equal(step2.status, "merged");
        assert.equal(whitelistCrdt.contains("ip:203.0.113.10", now), true);
        assert.equal(whitelistCrdt.contains("subnet:192.0.2.0/24", now), true);
    });

    it("FingerprintEngine autorise immédiatement une entrée en liste blanche CRDT", async () => {
        const now = Date.now();
        whitelistCrdt.add("ip:198.51.100.77", now, 3600000);

        const engine = new FingerprintEngine({});
        const decision = await engine.processRequest({
            clientIp: "198.51.100.77",
            path: "/index.html",
            headers: {}
        });

        assert.equal(decision.action, "next");
        assert.equal(decision.score, 0);
        assert.equal(decision.vector.whitelisted, 100);
    });
});