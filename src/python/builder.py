from typing import Any, Dict, Optional


def imul(a: int, b: int) -> int:
    """Emulates JavaScript Math.imul (signed 32-bit integer multiplication)."""
    res = (a * b) & 0xffffffff
    return res - 0x100000000 if res >= 0x80000000 else res


def cyrb53(string: str, seed: int = 0) -> int:
    """Deterministic cyrb53 hash ported from JS."""
    h1 = (0xdeadbeef ^ seed) & 0xffffffff
    h2 = (0x41c6ce57 ^ seed) & 0xffffffff
    
    for char in string:
        ch = ord(char)
        h1 = imul(h1 ^ ch, 2654435761)
        h2 = imul(h2 ^ ch, 1597334677)
        
    h1 = imul(h1 ^ (h1 >> 16), 2246822507) ^ imul(h2 ^ (h2 >> 13), 3266489909)
    h2 = imul(h2 ^ (h2 >> 16), 2246822507) ^ imul(h1 ^ (h1 >> 13), 3266489909)
    
    unsigned_h1 = h1 & 0xffffffff
    return 4294967296 * (2097151 & h2) + unsigned_h1


class FingerprintBuilder:
    """Generates a composite device fingerprint hash."""
    def __init__(self):
        self.components: Dict[str, int] = {}

    def add(self, group: str, value: Optional[str]) -> "FingerprintBuilder":
        if value:
            self.components[group] = cyrb53(value)
        return self

    def __str__(self) -> str:
        sorted_components = sorted(self.components.items())
        return "|".join(f"{k}:{v}" for k, v in sorted_components)

    @staticmethod
    def compare(fp1: str, fp2: str) -> float:
        if not fp1 or not fp2:
            return 0.0
        
        def parse(fp_str: str) -> Dict[str, str]:
            return dict(part.split(":", 1) for part in fp_str.split("|") if ":" in part)

        map1, map2 = parse(fp1), parse(fp2)
        volatile_keys = {
            "ch_ua", "ch_platform", "ch_mobile", "cookie_keys", "network", "http_ver"
        }
        weights = {
            "cvs": 5.0, "gpu": 4.0, "ja3": 3.5, "ua": 2.0, "hw": 1.5, "scr": 1.0, "os": 0.8
        }

        weighted_matches = 0.0
        total_weight = 0.0
        for key in set(map1.keys()) | set(map2.keys()):
            if key in volatile_keys:
                continue
            weight = weights.get(key, 0.5)
            total_weight += weight
            if map1.get(key) == map2.get(key):
                weighted_matches += weight

        return weighted_matches / total_weight if total_weight > 0 else 0.0


def extract_stable_part(fp_str: str) -> str:
    """Extracts immutable components (ua, ja3, ja4, h2, tcp) from a composite fingerprint string."""
    stable_keys = {"ua", "ja3", "ja4", "h2", "tcp"}
    parts = fp_str.split("|")
    stable_parts = [part for part in parts if part.split(":", 1)[0] in stable_keys]
    return "|".join(sorted(stable_parts))


def get_composite_device_hash(context: Any) -> str:
    """Generates a composite device fingerprint hash from request headers."""
    builder = FingerprintBuilder()
    headers = getattr(context, "headers", None)
    if headers and hasattr(headers, "get"):
        ua = headers.get("user-agent", "")
        builder.add("ua", ua)
        ja3 = headers.get("x-ja3-hash")
        if ja3:
            builder.add("ja3", ja3)
        accept_lang = headers.get("accept-language")
        if accept_lang:
            builder.add("accept_lang", accept_lang)
    elif hasattr(context, "get_header"):
        builder.add("ua", context.get_header("user-agent") or "")
        builder.add("ja3", context.get_header("x-ja3-hash"))
        builder.add("accept_lang", context.get_header("accept-language"))
    return str(builder)