import json
import time
import pytest

from crdt import LwwElementSet, BloomFilterSync
from challenge_utils import ChallengeUtils, threat_intel_crdt, whitelist_crdt
from storage import InMemoryStore


def test_lww_element_set_lww_resolution():
    crdt = LwwElementSet()
    now = 1000

    # Ajout initial
    crdt.add("zkp-target-1", 1000, 60000)
    assert crdt.contains("zkp-target-1", now) is True

    # Révocation postérieure
    crdt.remove("zkp-target-1", 1005)
    assert crdt.contains("zkp-target-1", now) is False

    # Ajout antérieur désynchronisé ignoré par le tombstone
    crdt.add("zkp-target-1", 1002, 60000)
    assert crdt.contains("zkp-target-1", now) is False

    # Réactivation postérieure
    crdt.add("zkp-target-1", 1010, 60000)
    assert crdt.contains("zkp-target-1", now) is True


def test_bloom_filter_sync_compression_and_missing_delta():
    peer_a = LwwElementSet()
    peer_b = LwwElementSet()

    for i in range(40):
        peer_a.add(f"zkp-device-{i}", 1000, 3600000)

    peer_b.merge_delta(peer_a.export_delta())
    peer_b.add("zkp-device-delta-1", 1000, 3600000)
    peer_b.add("zkp-device-delta-2", 1000, 3600000)

    filter_a = BloomFilterSync.create(100, 0.01)
    for item in peer_a.get_active_elements(1000):
        filter_a.put(item)

    compressed_b64 = filter_a.export_compressed_base64()
    remote_filter = BloomFilterSync.from_compressed_base64(
        compressed_b64, filter_a.bit_size, filter_a.num_hash_functions
    )
    missing = remote_filter.compute_missing_delta(peer_b, 1000)

    assert len(missing) == 2
    missing_keys = sorted(m["key"] for m in missing)
    assert missing_keys == ["zkp-device-delta-1", "zkp-device-delta-2"]


@pytest.mark.asyncio
async def test_handle_cooperative_request_threat_intel_sync_and_merge():
    store = InMemoryStore()
    now = int(time.time() * 1000)
    threat_intel_crdt.clear()
    threat_intel_crdt.add("zkp-local-threat-99", now, 86400000)

    # 1. Export du filtre de Bloom local
    step1 = await ChallengeUtils.handle_cooperative_request(store, {"coop_op": "sync_threat_intel"})
    assert step1["status"] == "bloom_filter_ready"
    assert step1["bloom_filter"]
    assert step1["bit_size"] > 0
    assert step1["hash_count"] > 0

    # 2. Calcul du delta à partir d'un filtre distant vide
    empty_filter = BloomFilterSync.create(50, 0.01)
    step2 = await ChallengeUtils.handle_cooperative_request(store, {
        "coop_op": "sync_threat_intel",
        "bloom_filter": empty_filter.export_compressed_base64(),
        "bit_size": str(empty_filter.bit_size),
        "hash_count": str(empty_filter.num_hash_functions)
    })
    assert step2["status"] == "delta_ready"
    assert step2["delta_count"] >= 1
    assert any(d.get("key") == "zkp-local-threat-99" for d in step2["delta"])

    # 3. Fusion d'un delta reçu
    merge_payload = [
        {"key": "zkp-incoming-threat-88", "addTs": now, "remTs": 0, "ttlMs": 86400000}
    ]
    step3 = await ChallengeUtils.handle_cooperative_request(store, {
        "coop_op": "merge_threat_intel",
        "delta": json.dumps(merge_payload)
    })
    assert step3["status"] == "merged"
    assert threat_intel_crdt.contains("zkp-incoming-threat-88", now) is True


@pytest.mark.asyncio
async def test_handle_cooperative_request_whitelist_sync_and_merge():
    store = InMemoryStore()
    now = int(time.time() * 1000)
    whitelist_crdt.clear()

    step1 = await ChallengeUtils.handle_cooperative_request(store, {"coop_op": "sync_whitelist"})
    assert step1["status"] == "bloom_filter_ready"
    assert step1["bloom_filter"]

    whitelist_delta = [
        {"key": "ip:203.0.113.10", "addTs": now, "remTs": 0, "ttlMs": 7200000},
        {"key": "subnet:192.0.2.0/24", "addTs": now, "remTs": 0, "ttlMs": 7200000}
    ]
    step2 = await ChallengeUtils.handle_cooperative_request(store, {
        "coop_op": "merge_whitelist",
        "delta": whitelist_delta
    })
    assert step2["status"] == "merged"
    assert whitelist_crdt.contains("ip:203.0.113.10", now) is True
    assert whitelist_crdt.contains("subnet:192.0.2.0/24", now) is True