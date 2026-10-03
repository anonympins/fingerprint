import base64
import hashlib
import math
import struct
import time
import zlib
from typing import Any, Dict, List, Optional, Set


class LwwElementSet:
    """
    LWW-Element-Set CRDT pour la Threat Intelligence et les Whitelists fédérées.
    Garantit une convergence sans conflit pour les ajouts et révocations distribuées.
    """
    def __init__(self):
        self._elements: Dict[str, Dict[str, Any]] = {}

    def add(self, key: str, timestamp: int, ttl_ms: int = 0) -> None:
        rec = self._elements.get(key)
        if rec is None:
            self._elements[key] = {
                "key": key,
                "addTs": timestamp,
                "remTs": 0,
                "ttlMs": ttl_ms,
            }
        else:
            if timestamp > rec["addTs"]:
                rec["addTs"] = timestamp
                rec["ttlMs"] = ttl_ms

    def remove(self, key: str, timestamp: int) -> None:
        rec = self._elements.get(key)
        if rec is None:
            self._elements[key] = {
                "key": key,
                "addTs": 0,
                "remTs": timestamp,
                "ttlMs": 0,
            }
        else:
            if timestamp > rec["remTs"]:
                rec["remTs"] = timestamp

    def contains(self, key: str, now: Optional[int] = None) -> bool:
        now = now if now is not None else int(time.time() * 1000)
        rec = self._elements.get(key)
        if not rec:
            return False
        if rec["addTs"] <= rec["remTs"]:
            return False
        return rec["ttlMs"] <= 0 or (now < rec["addTs"] + rec["ttlMs"])

    def get_active_elements(self, now: Optional[int] = None) -> List[str]:
        now = now if now is not None else int(time.time() * 1000)
        return [k for k, rec in self._elements.items() if self.contains(k, now)]

    def export_delta(self) -> List[Dict[str, Any]]:
        return list(self._elements.values())

    def merge_delta(self, delta: List[Dict[str, Any]]) -> None:
        if not delta:
            return
        for item in delta:
            key = item.get("key")
            if not key:
                continue
            add_ts = int(item.get("addTs", 0))
            rem_ts = int(item.get("remTs", 0))
            ttl_ms = int(item.get("ttlMs", 0))
            rec = self._elements.get(key)
            if rec is None:
                self._elements[key] = {
                    "key": key,
                    "addTs": add_ts,
                    "remTs": rem_ts,
                    "ttlMs": ttl_ms,
                }
            else:
                if add_ts > rec["addTs"]:
                    rec["addTs"] = add_ts
                    rec["ttlMs"] = ttl_ms
                if rem_ts > rec["remTs"]:
                    rec["remTs"] = rem_ts

    def prune_expired(self, now: Optional[int] = None, max_tombstone_age_ms: int = 86400000 * 7) -> None:
        now = now if now is not None else int(time.time() * 1000)
        to_del = []
        for k, rec in self._elements.items():
            expired = rec["ttlMs"] > 0 and (now >= rec["addTs"] + rec["ttlMs"])
            old_tombstone = rec["remTs"] > 0 and (now - rec["remTs"] > max_tombstone_age_ms)
            if expired or old_tombstone:
                to_del.append(k)
        for k in to_del:
            del self._elements[k]

    def __len__(self) -> int:
        return len(self._elements)

    def clear(self) -> None:
        self._elements.clear()


class BloomFilterSync:
    """
    Filtre de Bloom à double hachage compatible avec le moteur Java.
    Compression Zlib pour une réduction de bande passante inter-nœuds > 90%.
    """
    def __init__(self, bit_size: int, num_hash_functions: int, raw_bytes: Optional[bytes] = None):
        self.bit_size = bit_size
        self.num_hash_functions = num_hash_functions
        byte_len = (bit_size + 7) // 8
        self.bits = bytearray(raw_bytes if raw_bytes else b"\x00" * byte_len)

    @classmethod
    def create(cls, expected_elements: int = 1000, fp_rate: float = 0.01) -> "BloomFilterSync":
        expected_elements = max(10, expected_elements)
        bit_size = max(64, int(math.ceil(-expected_elements * math.log(fp_rate) / (math.log(2) ** 2))))
        num_hashes = max(1, int(round((bit_size / expected_elements) * math.log(2))))
        return cls(bit_size, num_hashes)

    def _hashes(self, item: str) -> List[int]:
        digest = hashlib.sha256(item.encode("utf-8")).digest()
        h1 = struct.unpack(">q", digest[0:8])[0]
        h2 = struct.unpack(">q", digest[8:16])[0]
        indices = []
        for i in range(self.num_hash_functions):
            combined = h1 + i * h2
            indices.append(combined % self.bit_size)
        return indices

    def put(self, item: str) -> None:
        for bit_idx in self._hashes(item):
            self.bits[bit_idx // 8] |= (1 << (bit_idx % 8))

    def might_contain(self, item: str) -> bool:
        for bit_idx in self._hashes(item):
            if not (self.bits[bit_idx // 8] & (1 << (bit_idx % 8))):
                return False
        return True

    def export_compressed_base64(self) -> str:
        compressed = zlib.compress(bytes(self.bits), level=9)
        return base64.urlsafe_b64encode(compressed).decode("utf-8").rstrip("=")

    @classmethod
    def from_compressed_base64(cls, b64_str: str, bit_size: int, num_hash_functions: int) -> "BloomFilterSync":
        padded = b64_str + "=" * ((4 - len(b64_str) % 4) % 4)
        raw_compressed = base64.urlsafe_b64decode(padded)
        decompressed = zlib.decompress(raw_compressed)
        return cls(bit_size, num_hash_functions, decompressed)

    def compute_missing_delta(self, local_set: LwwElementSet, now: Optional[int] = None) -> List[Dict[str, Any]]:
        now = now if now is not None else int(time.time() * 1000)
        delta = local_set.export_delta()
        return [item for item in delta if not self.might_contain(item["key"])]