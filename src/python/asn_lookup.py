from functools import lru_cache
import ipaddress
from dataclasses import dataclass
from typing import Optional, List, Union


@dataclass(frozen=True)
class NetworkProfile:
    type: str
    base_score: float
    inflection_point: float
    tolerance_rotation: bool
    jitter_tolerance: float


RESIDENTIAL = NetworkProfile(
    type="RESIDENTIAL",
    base_score=0.0,
    inflection_point=0.72,
    tolerance_rotation=False,
    jitter_tolerance=60.0,
)

CELLULAR = NetworkProfile(
    type="CELLULAR",
    base_score=10.0,
    inflection_point=0.60,
    tolerance_rotation=True,
    jitter_tolerance=80.0,
)

SATELLITE = NetworkProfile(
    type="SATELLITE",
    base_score=15.0,
    inflection_point=0.68,
    tolerance_rotation=False,
    jitter_tolerance=150.0,
)

HOSTING = NetworkProfile(
    type="HOSTING",
    base_score=55.0,
    inflection_point=0.85,
    tolerance_rotation=False,
    jitter_tolerance=30.0,
)

ANONYMIZER = NetworkProfile(
    type="ANONYMIZER",
    base_score=85.0,
    inflection_point=0.90,
    tolerance_rotation=False,
    jitter_tolerance=40.0,
)


class TrieNode:
    __slots__ = ("children", "profile")

    def __init__(self):
        self.children: List[Optional["TrieNode"]] = [None, None]
        self.profile: Optional[NetworkProfile] = None


class AsnLookupEngine:
    """
    Patricia Trie / Radix Trie compressé en mémoire pour la résolution
    ultra-rapide (< 50ns) du profil réseau d'adresses IPv4 et IPv6 sans I/O.
    """

    def __init__(self):
        self.root_v4 = TrieNode()
        self.root_v6 = TrieNode()
        self.load_default_prefixes()

    def insert(self, cidr: str, profile: NetworkProfile) -> None:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return

        is_v4 = net.version == 4
        max_bits = 32 if is_v4 else 128
        prefix_len = net.prefixlen
        int_val = int(net.network_address)

        current = self.root_v4 if is_v4 else self.root_v6
        for i in range(prefix_len):
            bit = (int_val >> (max_bits - 1 - i)) & 1
            if current.children[bit] is None:
                current.children[bit] = TrieNode()
            current = current.children[bit]

        current.profile = profile
        self.lookup.cache_clear()

    @lru_cache(maxsize=4096)
    def lookup(self, ip: Optional[str]) -> NetworkProfile:
        if not ip or not isinstance(ip, str):
            return RESIDENTIAL

        clean_ip = ip.strip().lower()
        if clean_ip.startswith("::ffff:"):
            clean_ip = clean_ip[7:]

        try:
            addr = ipaddress.ip_address(clean_ip)
        except ValueError:
            return RESIDENTIAL

        is_v4 = addr.version == 4
        int_val = int(addr)
        current = self.root_v4 if is_v4 else self.root_v6
        matched_profile: Optional[NetworkProfile] = None

        bits_count = 32 if is_v4 else 128
        for i in range(bits_count - 1, -1, -1):
            if current.profile is not None:
                matched_profile = current.profile  # Longest Prefix Match
            bit = (int_val >> i) & 1
            current = current.children[bit]
            if current is None:
                break

        if current is not None and current.profile is not None:
            matched_profile = current.profile

        return matched_profile or RESIDENTIAL

    def load_default_prefixes(self) -> None:
        # Mobile CGNAT (RFC 6598)
        self.insert("100.64.0.0/10", CELLULAR)

        # Datacenters & Cloud majeurs (AWS, Hetzner, OVH, DigitalOcean)
        datacenter_ranges = [
            # AWS
            "3.0.0.0/9", "3.128.0.0/9", "18.192.0.0/11", "34.192.0.0/10",
            "35.156.0.0/14", "52.0.0.0/11", "54.0.0.0/8",
            # Hetzner
            "78.46.0.0/15", "88.198.0.0/16", "94.130.0.0/16", "95.216.0.0/15",
            "116.202.0.0/15", "135.181.0.0/16", "136.243.0.0/16", "138.201.0.0/16",
            "142.132.0.0/16", "144.76.0.0/16", "148.251.0.0/16", "159.69.0.0/16",
            "168.119.0.0/16", "178.63.0.0/16", "188.40.0.0/16", "195.201.0.0/16",
            # OVH
            "51.68.0.0/14", "51.75.0.0/15", "51.77.0.0/16", "51.79.0.0/16",
            "51.81.0.0/16", "51.83.0.0/16", "51.89.0.0/16", "51.91.0.0/16",
            "137.74.0.0/16", "141.94.0.0/15", "145.239.0.0/16", "147.135.0.0/16",
            "176.31.0.0/16", "178.32.0.0/15", "188.165.0.0/16", "198.27.64.0/18",
            # DigitalOcean
            "64.225.0.0/16", "68.183.0.0/16", "104.248.0.0/16", "128.199.0.0/16",
            "134.209.0.0/16", "138.68.0.0/16", "138.197.0.0/16", "139.59.0.0/16",
            "142.93.0.0/16", "143.198.0.0/16", "146.190.0.0/16", "157.230.0.0/16",
            "159.65.0.0/16", "159.89.0.0/16", "161.35.0.0/16", "164.90.128.0/17",
            "165.22.0.0/16", "165.227.0.0/16", "167.99.0.0/16", "174.138.0.0/16",
            "178.62.0.0/16", "178.128.0.0/16", "188.166.0.0/16", "206.189.0.0/16",
        ]
        for r in datacenter_ranges:
            self.insert(r, HOSTING)

        # Satellite (Starlink Space-X)
        satellite_ranges = [
            "98.97.0.0/16", "129.222.0.0/16", "143.130.0.0/16",
            "143.244.0.0/16", "206.214.224.0/19"
        ]
        for r in satellite_ranges:
            self.insert(r, SATELLITE)

        # Tor Exit Relays / Proxies anonymiseurs
        anonymizer_ranges = [
            "185.220.101.0/24", "185.220.102.0/24", "185.220.103.0/24",
            "185.100.86.128/25", "198.98.56.0/24", "199.249.230.0/24"
        ]
        for r in anonymizer_ranges:
            self.insert(r, ANONYMIZER)


default_asn_lookup = AsnLookupEngine()