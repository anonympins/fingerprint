package com.anonympins.fingerprint;

import com.anonympins.fingerprint.crdt.BloomFilterSync;
import com.anonympins.fingerprint.crdt.LwwElementSet;
import com.anonympins.fingerprint.utils.ChallengeUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CrdtBloomTest {

    @BeforeEach
    public void setUp() {
        ChallengeUtils.setStore(new InMemoryStore());
        ChallengeUtils.getThreatIntelCrdt().clear();
        ChallengeUtils.getWhitelistCrdt().clear();
    }

    @Test
    public void testLwwElementSetAddRemoveResolution() {
        LwwElementSet crdt = new LwwElementSet();
        long now = 1000L;

        // Ajout avec timestamp 1000
        crdt.add("malicious-zkp-1", 1000L, 60000L);
        assertTrue(crdt.contains("malicious-zkp-1", now));

        // Révocation conflictuelle postérieure (timestamp 1005)
        crdt.remove("malicious-zkp-1", 1005L);
        assertFalse(crdt.contains("malicious-zkp-1", now));

        // Tentative d'ajout désynchronisé antérieur (timestamp 1002 < 1005) : le tombstone l'emporte
        crdt.add("malicious-zkp-1", 1002L, 60000L);
        assertFalse(crdt.contains("malicious-zkp-1", now));

        // Ajout postérieur valide (timestamp 1010 > 1005)
        crdt.add("malicious-zkp-1", 1010L, 60000L);
        assertTrue(crdt.contains("malicious-zkp-1", now));
    }

    @Test
    public void testBloomFilterSyncCompressAndDeltaExtraction() {
        LwwElementSet peerA = new LwwElementSet();
        LwwElementSet peerB = new LwwElementSet();

        for (int i = 0; i < 50; i++) {
            peerA.add("item-" + i, 1000L, 3600000L);
        }
        // Peer B a les 50 items + 3 items supplémentaires
        peerB.mergeDelta(peerA.exportDelta());
        peerB.add("item-new-1", 1000L, 3600000L);
        peerB.add("item-new-2", 1000L, 3600000L);
        peerB.add("item-new-3", 1000L, 3600000L);

        // Peer A envoie son filtre de Bloom compressé
        BloomFilterSync filterA = BloomFilterSync.createFromSet(peerA, 1000L);
        String compressed = filterA.exportCompressedBase64();

        // Peer B décompresse et identifie les deltas manquants
        BloomFilterSync remoteFilter = BloomFilterSync.fromCompressedBase64(compressed, filterA.getBitSize(), filterA.getNumHashFunctions());
        List<Map<String, Object>> missing = remoteFilter.computeMissingDelta(peerB, 1000L);

        assertEquals(3, missing.size(), "Seuls les 3 éléments nouveaux doivent être identifiés dans le delta");
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testThreatIntelCooperativeAntiEntropyFlow() {
        LwwElementSet threatSet = ChallengeUtils.getThreatIntelCrdt();
        long now = System.currentTimeMillis();

        // Enregistrement d'un item local
        threatSet.add("zkp-initial-threat", now, 86400000L);

        // 1. Étape 1 : Le pair distant demande notre filtre de Bloom local
        Map<String, String> step1Params = new HashMap<>();
        step1Params.put("coop_op", "sync_threat_intel");
        Map<String, Object> step1Res = ChallengeUtils.handleCooperativeRequest(step1Params, "127.0.0.1", Collections.emptyMap());

        assertEquals("bloom_filter_ready", step1Res.get("status"));
        String bloomFilterB64 = (String) step1Res.get("bloom_filter");
        assertNotNull(bloomFilterB64);
        int bitSize = ((Number) step1Res.get("bit_size")).intValue();
        int hashCount = ((Number) step1Res.get("hash_count")).intValue();

        // 2. Étape 2 : Simulation du pair émettant une requête avec son propre filtre distant
        // Création d'un filtre externe ne contenant pas un item nouveau
        BloomFilterSync remoteFilter = new BloomFilterSync(100, 0.01);
        remoteFilter.put("zkp-other-unrelated-key");

        Map<String, String> step2Params = new HashMap<>();
        step2Params.put("coop_op", "sync_threat_intel");
        step2Params.put("bloom_filter", remoteFilter.exportCompressedBase64());
        step2Params.put("bit_size", String.valueOf(remoteFilter.getBitSize()));
        step2Params.put("hash_count", String.valueOf(remoteFilter.getNumHashFunctions()));

        Map<String, Object> step2Res = ChallengeUtils.handleCooperativeRequest(step2Params, "127.0.0.1", Collections.emptyMap());
        assertEquals("delta_ready", step2Res.get("status"));
        List<Map<String, Object>> missingDelta = (List<Map<String, Object>>) step2Res.get("delta");
        assertNotNull(missingDelta);
        assertTrue(missingDelta.stream().anyMatch(e -> "zkp-initial-threat".equals(e.get("key"))));

        // 3. Étape 3 : Réception et fusion d'un delta entrant (merge_threat_intel)
        String incomingDeltaJson = "[{\"key\":\"zkp-peer-threat-42\",\"addTs\":" + now + ",\"remTs\":0,\"ttlMs\":86400000}]";
        Map<String, String> step3Params = new HashMap<>();
        step3Params.put("coop_op", "merge_threat_intel");
        step3Params.put("delta", incomingDeltaJson);

        Map<String, Object> step3Res = ChallengeUtils.handleCooperativeRequest(step3Params, "127.0.0.1", Collections.emptyMap());
        assertEquals("merged", step3Res.get("status"));
        assertTrue(threatSet.contains("zkp-peer-threat-42", now));
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testWhitelistCooperativeSyncAndMerge() {
        LwwElementSet whitelistSet = ChallengeUtils.getWhitelistCrdt();
        long now = System.currentTimeMillis();

        // Demande initiale du filtre de Bloom
        Map<String, String> syncParams = new HashMap<>();
        syncParams.put("coop_op", "sync_whitelist");
        Map<String, Object> syncRes = ChallengeUtils.handleCooperativeRequest(syncParams, "127.0.0.1", Collections.emptyMap());
        assertEquals("bloom_filter_ready", syncRes.get("status"));

        // Fusion d'un sous-réseau en liste blanche via merge_whitelist
        String deltaJson = "[{\"key\":\"subnet:198.51.100.0/24\",\"addTs\":" + now + ",\"remTs\":0,\"ttlMs\":3600000}]";
        Map<String, String> mergeParams = new HashMap<>();
        mergeParams.put("coop_op", "merge_whitelist");
        mergeParams.put("delta", deltaJson);

        Map<String, Object> mergeRes = ChallengeUtils.handleCooperativeRequest(mergeParams, "127.0.0.1", Collections.emptyMap());
        assertEquals("merged", mergeRes.get("status"));
        assertTrue(whitelistSet.contains("subnet:198.51.100.0/24", now));
    }

    @Test
    public void testFingerprintEngineAllowsWhitelistedCrdtEntry() {
        long now = System.currentTimeMillis();
        ChallengeUtils.getWhitelistCrdt().add("ip:198.51.100.77", now, 3600000L);

        InMemoryStore store = new InMemoryStore();
        FingerprintEngine engine = new FingerprintEngine(new HashMap<>(), store);

        RequestContext context = new RequestContext("198.51.100.77", "/index.html", new HashMap<>(), null, null, null, "1.1");
        Map<String, Object> decision = engine.processRequest(context);

        assertEquals("allow", decision.get("action"));
        assertEquals(0.0, ((Number) decision.get("score")).doubleValue());
    }
}