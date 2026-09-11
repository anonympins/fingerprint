import hmac
import hashlib
import time
import uuid
import math
import ctypes
import re
import random
import copy
import json
import os
import asyncio
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
from typing import Dict, Any, List, Optional, Callable, Set
from dataclasses import dataclass, field

# --- UTILS ---

def imul(a: int, b: int) -> int:
    """
    Emulates JavaScript Math.imul (signed 32-bit integer multiplication).
    This is crucial for consistent hash calculation between JS and Python.
    """
    return ctypes.c_int32((a * b) & 0xffffffff).value

def parse_tcp_syn(binary: bytes) -> Optional[Dict[str, Any]]:
    """Parses raw TCP SYN binary packets to extract TTL, window size, MSS, WS, and SACK."""
    if not binary or len(binary) < 40:
        return None
    ttl = 64
    tcp_offset = 20
    version = binary[0] >> 4

    if version == 4:
        ttl = binary[8]
        ihl = binary[0] & 0x0f
        tcp_offset = ihl * 4
    elif version == 6:
        ttl = binary[7]  # Hop Limit
        tcp_offset = 40
    else:
        tcp_offset = 0
        ttl = 64

    if len(binary) < tcp_offset + 20:
        return None

    import struct
    window_size = struct.unpack("!H", binary[tcp_offset + 14 : tcp_offset + 16])[0]
    data_offset = (binary[tcp_offset + 12] >> 4) * 4
    options_end = tcp_offset + data_offset

    mss = None
    ws = None
    sack = False

    i = tcp_offset + 20
    while i < options_end and i < len(binary):
        opt_type = binary[i]
        if opt_type == 0:
            break
        if opt_type == 1:
            i += 1
            continue
        if i + 1 >= len(binary):
            break
        opt_len = binary[i + 1]
        if opt_len < 2 or i + opt_len > len(binary):
            break

        if opt_type == 2 and opt_len == 4:
            mss = struct.unpack("!H", binary[i + 2 : i + 4])[0]
        elif opt_type == 3 and opt_len == 3:
            ws = binary[i + 2]
        elif opt_type == 4 and opt_len == 2:
            sack = True
        i += opt_len

    return {"ttl": ttl, "windowSize": window_size, "mss": mss, "ws": ws, "sack": sack}

def classify_tcp_os(fingerprint: Optional[Dict[str, Any]]) -> str:
    """Classifies OS based on passive TCP fingerprinted values."""
    if not fingerprint:
        return "unknown"
    ttl = fingerprint.get("ttl", 64)
    window_size = fingerprint.get("windowSize", 0)
    ws = fingerprint.get("ws")

    if 64 < ttl <= 128:
        return "Windows"
    if 32 < ttl <= 64:
        if window_size in (29200, 14600, 5840):
            return "Linux"
        return "Linux"
    if ttl <= 64:
        if window_size == 65535 and ws in (6, 8, 5):
            return "macOS/iOS"
    if ttl > 64:
        return "Windows"
    if ttl > 0:
        return "Linux"
    return "unknown"
# --- UTILS: Cyrb53 Hash Emulation ---

# Note: This cyrb53 implementation is a direct port from the JavaScript version
# to ensure cross-language consistency in fingerprint hashing.
# It relies on the `imul` function for 32-bit integer multiplication emulation.

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

def get_ip_subnet(ip: str, ipv4_prefix: int = 24, ipv6_prefix: int = 48) -> Optional[str]:
    """Calculates the subnet of an IP address (IPv4 or IPv6)."""
    import socket
    import struct
    try:
        # Check IPv4
        socket.inet_pton(socket.AF_INET, ip)
        ip_ints = [int(x) for x in ip.split('.')]
        mask = (0xffffffff << (32 - ipv4_prefix)) & 0xffffffff
        ip_val = (ip_ints[0] << 24) | (ip_ints[1] << 16) | (ip_ints[2] << 8) | ip_ints[3]
        net_val = ip_val & mask
        net_ints = [
            (net_val >> 24) & 0xff,
            (net_val >> 16) & 0xff,
            (net_val >> 8) & 0xff,
            net_val & 0xff
        ]
        return f"{'.'.join(map(str, net_ints))}/{ipv4_prefix}"
    except socket.error:
        try:
            # Check IPv6
            ip_bin = socket.inet_pton(socket.AF_INET6, ip)
            words = struct.unpack("!8H", ip_bin)
            keep_words = ipv6_prefix // 16
            net_words = list(words[:keep_words]) + [0] * (8 - keep_words)
            net_str = ":".join(f"{w:x}" for w in net_words)
            return f"{net_str}/{ipv6_prefix}"
        except socket.error:
            return None

async def generate_space_challenge(store, client_ip: str, nonce: str, suspicion_factor: float, original_url: str, security_config: dict) -> dict:
    pospace_config = security_config.get("pospace", {}) or {}
    size_mb = pospace_config.get("sizeMb", 100)
    num_queries = pospace_config.get("numQueries", 10)
    queries = []
    max_blocks = size_mb * 1024
    while len(queries) < num_queries:
        idx = random.randint(0, max_blocks - 1)
        if idx not in queries:
            queries.append(idx)
    challenge = {
        "type": "pospace",
        "nonce": nonce,
        "sizeMb": size_mb,
        "queries": queries,
        "path": original_url
    }

    peer = await ChallengeUtils.find_peer_in_subnet(store, client_ip, nonce)
    if peer:
        challenge["peerId"] = peer["nodeId"]
        challenge["peerBlockIdx"] = random.randint(0, max_blocks - 1)

        await store.set(f"coop-assoc:{nonce}", {
            "peerNodeId": peer["nodeId"],
            "peerSeed": peer["seed"],
            "peerBlockIdx": challenge["peerBlockIdx"]
        }, 120)

    return challenge

def generate_space_challenge_page(challenge_details: dict, client_secret: str, security_config: dict) -> str:
    nonce = challenge_details["nonce"]
    size_mb = challenge_details["sizeMb"]
    queries = challenge_details["queries"]
    path = challenge_details["path"]
    
    solver_code = ""
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        solver_path = os.path.join(current_dir, "..", "js", "pow.solver.inline.js")
        if os.path.exists(solver_path):
            with open(solver_path, "r", encoding="utf-8") as f:
                solver_code = f.read()
    except Exception:
        pass

    queries_json = json.dumps(queries)
    challenge_script = f"""
    async function solve() {{
      const nonce = "{nonce}";
      const path = "{path}";
      const clientSecret = "{client_secret}";
      const queries = {queries_json};
      const sizeMb = {size_mb};
      
      document.getElementById('loader').innerText = '⚙&#xFE0F; Checking persistent local storage...';
      await new Promise(r => setTimeout(r, 10));
      
      try {{
          await window.initializeSpace(nonce + ":" + clientSecret, size_mb);
          document.getElementById('loader').innerText = '⚙&#xFE0F; Generating Proof of Space...';
          const hash = await window.solveSpaceChallenge(nonce + ":" + clientSecret, queries, nonce, clientSecret);
          
          window.location.href = path + "?pow_type=pospace&pow_nonce=" + nonce + "&pow_solution_space=" + hash;
      }} catch(e) {{
          document.getElementById('loader').innerText = "Error initializing local storage: " + e.message;
      }}
    }}
    solve();
    """
    
    return f"""<html><head><title>Security Check</title></head>
  <body style="font-family:sans-serif; text-align:center; padding-top:50px;">
    <h1>Security Check (Level 2)</h1>
    <p>We are verifying your storage allocation. This may take a few seconds on first load.</p>
    <div id="loader" style="margin:20px;">⚙&#xFE0F; Initializing storage space...</div>
    <script>{solver_code}</script>
    <script>{challenge_script}</script>
  </body></html>"""

def sanitize_traffic_data(traffic_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Sanitizes traffic data to protect the auto-tuner from poisoning attacks."""
    if not traffic_data:
        return []
    
    temp_sanitized = []
    device_counts = {}
    ip_counts = {}
    subnet_counts = {}

    total_count = len(traffic_data)
    max_logs_per_device = max(3, total_count // 50) # 2%
    max_logs_per_ip = max(3, total_count // 50)      # 2%
    max_logs_per_subnet = max(5, total_count // 20)  # 5%

    for log in traffic_data:
        dev_id = log.get("deviceId") or "anonymous"
        ip = log.get("clientIp") or log.get("ip") or "unknown"
        subnet = get_ip_subnet(ip) or "unknown-subnet"

        current_device_count = device_counts.get(dev_id, 0)
        current_ip_count = ip_counts.get(ip, 0)
        current_subnet_count = subnet_counts.get(subnet, 0)

        if (
            current_device_count < max_logs_per_device and
            (ip == "unknown" or current_ip_count < max_logs_per_ip) and
            (subnet == "unknown-subnet" or current_subnet_count < max_logs_per_subnet)
        ):
            device_counts[dev_id] = current_device_count + 1
            if ip != "unknown":
                ip_counts[ip] = current_ip_count + 1
            if subnet != "unknown-subnet":
                subnet_counts[subnet] = current_subnet_count + 1
            temp_sanitized.append(log)

    passed_logs = [log for log in temp_sanitized if log.get("type") == "request_passed"]
    suspicious_logs = [log for log in temp_sanitized if log.get("type") != "request_passed"]

    min_data_points = 200
    max_passed_allowed = max(min_data_points, len(suspicious_logs) * 9)

    if len(passed_logs) > max_passed_allowed:
        random.shuffle(passed_logs)
        passed_logs = passed_logs[:max_passed_allowed]

    return suspicious_logs + passed_logs

# --- DATASTRUCTURES: Request Context & Storage ---
@dataclass
class RequestContext:
    """
    Represents the context of an incoming HTTP request, providing a unified interface
    to access information needed for fingerprint analysis.
    """
    client_ip: str
    path: str
    headers: Dict[str, str]
    query_params: Dict[str, Any]
    cookies: Dict[str, str]
    body: Optional[Any] = None
    http_version: str = "1.1"
    request_timestamp: int = field(default_factory=lambda: int(time.time() * 1000))
    new_cookies: List[Dict[str, Any]] = field(default_factory=list)
    tls_session_id: Optional[str] = None
    quic_fingerprint: Optional[str] = None

    def __post_init__(self):
        # Normalize headers to lowercase for consistent lookup
        self.headers = {k.lower(): v for k, v in self.headers.items()}
        if not self.tls_session_id:
            self.tls_session_id = self.headers.get("x-tls-session-id") or self.headers.get("x-ssl-session-id")
        if not self.quic_fingerprint:
            self.quic_fingerprint = self.headers.get("x-quic-fp")

class InMemoryStore:
    """
    A simple in-memory key-value store implementation with TTL support.
    This store is suitable for development and testing, but not recommended for production
    environments as data is lost upon application restart.
    """
    def __init__(self):
        self._store: Dict[str, Any] = {}
        self._expires: Dict[str, float] = {}

    async def get(self, key: str) -> Optional[Any]:
        """Retrieves a value associated with a key, checking for expiration."""
        if key in self._expires and self._expires[key] < time.time():
            await self.delete(key)
            return None
        return self._store.get(key)
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Stores a value associated with a key, with an optional time-to-live (TTL) in seconds."""
        self._store[key] = value
        if ttl:
            self._expires[key] = time.time() + ttl
        elif key in self._expires:
            del self._expires[key]

    async def has(self, key: str) -> bool:
        """Checks if a key exists and is not expired in the store."""
        if key in self._expires and self._expires[key] < time.time():
            await self.delete(key)
            return False
        return key in self._store
    async def delete(self, key: str) -> None:
        """Deletes a key from the store."""
        self._store.pop(key, None)
        self._expires.pop(key, None)


# --- CORE: FingerprintBuilder ---
class FingerprintBuilder:
    """Generates a composite device fingerprint hash."""
    def __init__(self):
        """Initializes the FingerprintBuilder."""
        self.components: Dict[str, int] = {}

    def add(self, group: str, value: Optional[str]) -> "FingerprintBuilder":
        """
        Adds a component to the composite fingerprint.
        The value is hashed using cyrb53 for anonymization and size reduction.

        Args:
            group (str): The name of the component group (e.g., 'hw', 'screen', 'geo').
            value (Optional[str]): The raw value to be hashed.

        Returns:
            FingerprintBuilder: The builder instance for chaining.
        """
        if value:
            self.components[group] = cyrb53(value)
        return self

    def __str__(self) -> str:
        """Generates the final fingerprint string by sorting components deterministically."""
        sorted_components = sorted(self.components.items())
        return "|".join(f"{k}:{v}" for k, v in sorted_components)

    @staticmethod
    def compare(fp1: str, fp2: str) -> float:
        """
        Compares two fingerprints and returns a similarity score (0 to 1).
        Weights are applied to give more importance to stable invariants (Canvas, GPU, JA3).

        Args:
            fp1 (str): The first fingerprint string.
            fp2 (str): The second fingerprint string.

        Returns:
            float: A similarity score between 0.0 (completely different) and 1.0 (identical).
        """
        if not fp1 or not fp2:
            return 0.0
        
        def parse(fp_str: str) -> Dict[str, str]:
            """Helper to parse a fingerprint string into a dictionary of components."""
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
        all_keys = set(map1.keys()) | set(map2.keys())

        for key in all_keys:
            if key in volatile_keys:
                continue
            weight = weights.get(key, 0.5)
            total_weight += weight
            if map1.get(key) == map2.get(key):
                weighted_matches += weight

        return weighted_matches / total_weight if total_weight > 0 else 0.0


# --- CORE: Challenge Utilities ---
class ChallengeUtils:
    @staticmethod
    def fround(val: float) -> float:
        import struct
        try:
            return struct.unpack('f', struct.pack('f', val))[0]
        except OverflowError:
            return float('-inf') if val < 0 else float('inf')

    @staticmethod
    def hash_seed_to_float(seed: str) -> float:
        import ctypes
        h = 0
        for char in seed:
            h = (h << 5) - h + ord(char)
            h = ctypes.c_int32(h).value
        return abs(h % 1000000) / 1000000

    @staticmethod
    def verify_gpu_pow(seed: str, iterations: int, solution: str, sample_indices: list = [0, 12, 35, 57]) -> bool:
        if not solution:
            return False
        values = solution.split(",")
        if len(values) != 64:
            return False
        try:
            numeric_seed = ChallengeUtils.hash_seed_to_float(seed)
            r = 3.9999
            for idx in sample_indices:
                if idx < 0 or idx >= 64:
                    return False
                x = ChallengeUtils.fround(numeric_seed + idx * 0.015)
                r_float = ChallengeUtils.fround(r)
                for _ in range(iterations):
                    x = ChallengeUtils.fround(r_float * x * ChallengeUtils.fround(1.0 - x))
                client_val = float(values[idx])
                if abs(client_val - x) > 1e-4:
                    return False
            return True
        except Exception:
            return False

    @staticmethod
    def _base64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

    @staticmethod
    def _base64url_decode(string: str) -> bytes:
        rem = len(string) % 4
        if rem > 0:
            string += '=' * (4 - rem)
        return base64.urlsafe_b64decode(string.encode('utf-8'))

    @staticmethod
    def generate_block(seed: str, block_index: int, block_size: int = 1024) -> bytes:
        block = bytearray(block_size)
        h = cyrb53(f"{seed}:{block_index}")
        h_int = h % 4294967296
        if h_int >= 2147483648:
            h_int -= 4294967296
        for i in range(block_size):
            h_int = imul(h_int ^ i, 1597334677)
            block[i] = h_int & 0xff
        return bytes(block)

    @staticmethod
    async def verify_space_pow(store, nonce: str, solution: str, queries: list, seed: str, client_secret: str) -> bool:
        combined = bytearray()
        for idx in queries:
            combined.extend(ChallengeUtils.generate_block(seed, int(idx)))

        assoc = await store.get(f"coop-assoc:{nonce}")
        if assoc:
            peer_seed = assoc.get("peerSeed")
            peer_block_idx = assoc.get("peerBlockIdx")
            if peer_seed is not None and peer_block_idx is not None:
                combined.extend(ChallengeUtils.generate_block(peer_seed, int(peer_block_idx)))
            await store.delete(f"coop-assoc:{nonce}")

        final_block = bytes(combined) + f"{nonce}:{client_secret}".encode("utf-8")
        h = hashlib.sha256(final_block).hexdigest()
        return hmac.compare_digest(h, solution)

    @staticmethod
    async def register_cooperative_node(store, client_ip: str, node_id: str, seed: str) -> None:
        subnet = get_ip_subnet(client_ip)
        if not subnet:
            return

        key = f"coop-pospace:subnet:{subnet}"
        nodes = await store.get(key) or {}
        now = int(time.time())

        cleaned_nodes = {}
        for id_, node in nodes.items():
            if now - node.get("timestamp", 0) < 120:
                cleaned_nodes[id_] = node

        cleaned_nodes[node_id] = {
            "nodeId": node_id,
            "seed": seed,
            "timestamp": now
        }

        await store.set(key, cleaned_nodes, 120)

    @staticmethod
    async def find_peer_in_subnet(store, client_ip: str, exclude_node_id: str) -> Optional[Dict[str, Any]]:
        subnet = get_ip_subnet(client_ip)
        if not subnet:
            return None

        key = f"coop-pospace:subnet:{subnet}"
        nodes = await store.get(key) or {}
        now = int(time.time())

        active_peers = []
        for id_, node in nodes.items():
            if id_ != exclude_node_id and now - node.get("timestamp", 0) < 120:
                active_peers.append(node)

        if not active_peers:
            return None

        return random.choice(active_peers)

    @staticmethod
    async def handle_cooperative_request(store, params: Dict[str, Any], client_ip: str = '127.0.0.1') -> Optional[Dict[str, Any]]:
        op = params.get("coop_op")
        if not op:
            return None

        node_id = params.get("node_id") or ""
        if not node_id:
            return {"error": "Missing node_id"}

        if op == "register":
            seed = params.get("seed") or ""
            await ChallengeUtils.register_cooperative_node(store, client_ip, node_id, seed)
            return {"status": "registered"}

        elif op == "request_peer_block":
            peer_id = params.get("peer_id") or ""
            block_idx = int(params.get("block_idx") or "0")
            req_id = params.get("req_id") or ""
            if not peer_id or not req_id:
                return {"error": "Invalid parameters"}

            queue_key = f"coop-mailbox:queue:{peer_id}"
            requests = await store.get(queue_key) or []
            requests.append({
                "req_id": req_id,
                "requester_id": node_id,
                "block_idx": block_idx
            })
            await store.set(queue_key, requests, 30)
            return {"status": "queued"}

        elif op == "poll_requests":
            poll_queue_key = f"coop-mailbox:queue:{node_id}"
            polled_requests = await store.get(poll_queue_key) or []
            await store.delete(poll_queue_key)
            return {"requests": polled_requests}

        elif op == "respond_block":
            requester_id = params.get("requester_id") or ""
            respond_req_id = params.get("req_id") or ""
            block_data = params.get("block_data") or ""
            if not requester_id or not respond_req_id:
                return {"error": "Invalid parameters"}

            response_key = f"coop-mailbox:res:{requester_id}:{respond_req_id}"
            await store.set(response_key, {"block_data": block_data}, 30)
            return {"status": "delivered"}

        elif op == "poll_response":
            poll_response_req_id = params.get("req_id") or ""
            poll_response_key = f"coop-mailbox:res:{node_id}:{poll_response_req_id}"
            data = await store.get(poll_response_key)
            if data:
                await store.delete(poll_response_key)
                return {"status": "ready", "block_data": data.get("block_data")}
            return {"status": "pending"}

        return None

    @staticmethod
    def verify_zkp_proof(y_str: str, t_str: str, s_str: str) -> bool:
        try:
            y = int(y_str, 16)
            t = int(t_str, 16)
            s = int(s_str, 16)
            ZKP_P = 115792089237316195423570985008687907853269984665640564039457584007908834671663
            ZKP_G = 2
            c_str = f"{ZKP_G}{y}{t}"
            c = int(hashlib.sha256(c_str.encode("utf-8")).hexdigest(), 16) % ZKP_P
            left = pow(ZKP_G, s, ZKP_P)
            right = (t * pow(y, c, ZKP_P)) % ZKP_P
            return left == right
        except Exception:
            return False

    @staticmethod
    def generate_stateless_ticket(payload: Dict[str, Any], secret: str) -> str:
        ed25519_key_pem = os.environ.get("ED25519_PRIVATE_KEY")
        if ed25519_key_pem:
            try:
                from cryptography.hazmat.primitives.serialization import load_pem_private_key
                private_key = load_pem_private_key(ed25519_key_pem.encode('utf-8'), password=None, backend=default_backend())
                serialized = json.dumps(payload).encode('utf-8')
                signature = private_key.sign(serialized)
                return f"ed25519.{ChallengeUtils._base64url_encode(serialized)}.{ChallengeUtils._base64url_encode(signature)}"
            except Exception as e:
                print(f"[ChallengeUtils] Ed25519 signing failed, falling back to symmetric: {e}")

        key = hashlib.sha256(secret.encode('utf-8')).digest()
        iv = os.urandom(16)
        plaintext = json.dumps(payload).encode('utf-8')
        
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encrypter = cipher.encryptor()
        encrypted = encrypter.update(padded_data) + encrypter.finalize()
        
        signature = hmac.new(key, iv + encrypted, hashlib.sha256).digest()
        
        return f"{ChallengeUtils._base64url_encode(iv)}.{ChallengeUtils._base64url_encode(encrypted)}.{ChallengeUtils._base64url_encode(signature)}"

    @staticmethod
    def parse_stateless_ticket(ticket: str, secret: str) -> Optional[Dict[str, Any]]:
        if not ticket or "." not in ticket:
            return None
        if ticket.startswith("ed25519."):
            parts = ticket.split(".")
            if len(parts) != 3:
                return None
            try:
                payload_bytes = ChallengeUtils._base64url_decode(parts[1])
                signature = ChallengeUtils._base64url_decode(parts[2])
                
                ed25519_pub_pem = os.environ.get("ED25519_PUBLIC_KEY")
                if not ed25519_pub_pem:
                    print("[ChallengeUtils] ED25519_PUBLIC_KEY is not defined in environment.")
                    return None
                    
                from cryptography.hazmat.primitives.serialization import load_pem_public_key
                public_key = load_pem_public_key(ed25519_pub_pem.encode('utf-8'), backend=default_backend())
                public_key.verify(signature, payload_bytes)
                return json.loads(payload_bytes.decode('utf-8'))
            except Exception as e:
                print(f"[ChallengeUtils] Ed25519 verification failed: {e}")
                return None

        parts = ticket.split(".")
        if len(parts) != 3:
            return None
        
        try:
            iv = ChallengeUtils._base64url_decode(parts[0])
            encrypted = ChallengeUtils._base64url_decode(parts[1])
            signature = ChallengeUtils._base64url_decode(parts[2])
            
            if len(iv) != 16:
                return None
                
            key = hashlib.sha256(secret.encode('utf-8')).digest()
            expected_signature = hmac.new(key, iv + encrypted, hashlib.sha256).digest()
            if not hmac.compare_digest(expected_signature, signature):
                return None
                
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decrypter = cipher.decryptor()
            decrypted_padded = decrypter.update(encrypted) + decrypter.finalize()
            
            unpadder = padding.PKCS7(128).unpadder()
            decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
            
            return json.loads(decrypted.decode('utf-8'))
        except Exception:
            return None

    @staticmethod
    async def is_ticket_valid(
        ip: str,
        ticket: Optional[str],
        device_id: str = '',
        device_hash: str = '',
        secret: str = '',
        allow_cross_network_roaming: bool = False,
        store: Optional[Any] = None,
        zkp_proof: str = ''
    ) -> bool:
        if not ip or not ticket:
            return False
            
        ticket_data = ChallengeUtils.parse_stateless_ticket(ticket, secret)
        if ticket_data is not None:
            expiry = ticket_data.get("expiry")
            original_ip = ticket_data.get("originalIp")
            stored_device_id = ticket_data.get("deviceId", "")
            stored_device_hash = ticket_data.get("deviceHash", "")
            
            if not expiry or int(time.time() * 1000) > int(expiry):
                return False
            if stored_device_hash and stored_device_hash.startswith("zkp:"):
                expected_y = stored_device_hash.split(":")[1]
                if zkp_proof:
                    y, t, s = zkp_proof.split(":")
                    if y == expected_y and ChallengeUtils.verify_zkp_proof(y, t, s):
                        return True
                return False
            if ip == original_ip:
                return True
            current_subnet = get_ip_subnet(ip)
            original_subnet = get_ip_subnet(original_ip) if original_ip else None
            if current_subnet is not None and original_subnet is not None and current_subnet == original_subnet:
                return True
            if not allow_cross_network_roaming:
                return False
            return bool(device_id and device_id == stored_device_id and device_hash and device_hash == stored_device_hash)
            
        if store is not None:
            db_data = await store.get(f"ticket:{ticket}")
            if db_data is not None:
                original_ip = db_data.get("ip") or db_data.get("originalIp")
                stored_device_id = db_data.get("device_id") or db_data.get("deviceId", "")
                stored_device_hash = db_data.get("deviceHash", "")
                expiry = db_data.get("expiry")
                
                if expiry and int(time.time() * 1000) > int(expiry):
                    await store.delete(f"ticket:{ticket}")
                    return False
                if stored_device_hash and stored_device_hash.startswith("zkp:"):
                    expected_y = stored_device_hash.split(":")[1]
                    if zkp_proof:
                        y, t, s = zkp_proof.split(":")
                        if y == expected_y and ChallengeUtils.verify_zkp_proof(y, t, s):
                            return True
                    return False
                    
                if ip == original_ip:
                    return True
                current_subnet = get_ip_subnet(ip)
                original_subnet = get_ip_subnet(original_ip) if original_ip else None
                if current_subnet is not None and original_subnet is not None and current_subnet == original_subnet:
                    return True
                if not allow_cross_network_roaming:
                    return False
                return bool(device_id and device_id == stored_device_id and device_hash and device_hash == stored_device_hash)

        if ":" in ticket:
            try:
                parts = ticket.split(":")
                if len(parts) < 2:
                    return False
                expiry, sig = parts[0], parts[1]
                if not expiry or not sig or int(time.time() * 1000) > int(expiry):
                    return False
                
                expected_sig = hmac.new(secret.encode('utf-8'), f"{ip}:{expiry}".encode('utf-8'), hashlib.sha256).hexdigest()
                return hmac.compare_digest(expected_sig, sig)
            except Exception:
                return False
                
        return False

    @staticmethod
    def calculate_cpu_target(suspicion_factor: float, security_config: Optional[Dict[str, Any]] = None) -> str:
        """
        Calculates the CPU Proof-of-Work target based on the suspicion factor.
        A higher suspicion factor results in a harder challenge (lower target value).

        Args:
            suspicion_factor (float): A value from 0.0 to 1.0 (or higher for extreme cases).
            security_config (Optional[Dict[str, Any]]): The security configuration containing CPU difficulty settings.

        Returns:
            str: The hexadecimal representation of the target value.
        """
        cpu_config = (security_config or {}).get("cpu", {})
        min_bits = cpu_config.get("minDifficultyBits", 8)
        max_bits = cpu_config.get("maxDifficultyBits", 16)
        total_bits = min_bits + suspicion_factor * (max_bits - min_bits)
        if total_bits <= 0:
            return "f" * 64
        shift = 256 - int(math.floor(total_bits))
        return hex(1 << shift)[2:].zfill(64)
    @staticmethod
    def verify_cpu_pow(base_block: bytes, target_hex: str, solution: str) -> bool:
        """
        Verifies a CPU Proof-of-Work solution.

        Args:
            base_block (bytes): The base block used for hashing (nonce, secret, fingerprint).
            target_hex (str): The hexadecimal target value.
            solution (str): The client's submitted solution (an integer).

        Returns:
            bool: True if the solution is valid, False otherwise.
        """
        try:
            final_block = base_block + str(solution).encode("utf-8")
            h = hashlib.sha256(final_block).hexdigest()
            return int(h, 16) < int(target_hex, 16)
        except Exception:
            return False
    @staticmethod
    def verify_memory_pow(nonce: str, solution: str, difficulty: int, client_secret: str) -> bool:
        """
        Verifies a Memory Proof-of-Work solution.
        This function emulates the client-side memory challenge to validate the solution.

        Args:
            nonce (str): The challenge nonce.
            solution (str): The client's submitted solution (an integer).
            difficulty (int): The memory difficulty in MB.
            client_secret (str): The client-specific secret.

        Returns:
            bool: True if the solution is valid, False otherwise.
        """
        if difficulty <= 0:
            return True
        try:
            size = difficulty * 1024 * 1024
            iterations = size // 16
            buffer_len = size // 4
            buffer = [0] * buffer_len
            seed = f":{nonce}:{client_secret}"
            h = sum(seed.encode("utf-8"))
            for i in range(buffer_len):
                h = imul(h ^ i, 1597334677)
                buffer[i] = h & 0xffffffff
            final_hash = 0
            addr = (buffer[0] % buffer_len) if buffer_len > 0 else 0
            for _ in range(iterations):
                addr = buffer[addr] % buffer_len
                final_hash ^= addr
            return final_hash == int(solution)
        except Exception:
            return False

    @staticmethod
    async def check_challenge_rate_limit(store, client_ip: str) -> bool:
        """
        Vérifie le limiteur de débit Token Bucket pour les demandes de challenge d'un sous-réseau.
        """
        subnet = get_ip_subnet(client_ip)
        if not subnet:
            return False

        key = f"rate-limit:{subnet}"
        rate_limit_data = await store.get(key)
        if not rate_limit_data:
            rate_limit_data = {
                "tokens": 5.0,
                "lastRefill": time.time()
            }

        capacity = 5.0
        refill_rate = 0.1  # 1 token toutes les 10 secondes
        now = time.time()

        elapsed = now - rate_limit_data["lastRefill"]
        tokens = min(capacity, rate_limit_data["tokens"] + elapsed * refill_rate)

        if tokens < 1.0:
            await store.set(key, {"tokens": tokens, "lastRefill": now}, 60)
            return False

        await store.set(key, {"tokens": tokens - 1.0, "lastRefill": now}, 60)
        return True


# --- CORE: Request Analysis Utilities ---
class RequestUtils:
    _botnet_clusters: Dict[str, List[Dict[str, Any]]] = {}

    @staticmethod
    def parse_user_agent(ua: str) -> Dict[str, Optional[str]]:
        """
        Parses a User-Agent string to extract basic browser, OS, and device information.

        Args:
            ua (str): The User-Agent string.

        Returns:
            Dict[str, Optional[str]]: A dictionary containing 'browser', 'os', and 'device'.
        """
        result = {"browser": None, "os": None, "device": "desktop"}
        ua_lower = ua.lower()
        if "chrome" in ua_lower and "edg" not in ua_lower:
            result["browser"] = "Chrome"
            match = re.search(r"Chrome/(\d+)", ua)
            if match:
                result["browser"] += "/" + match.group(1)
        elif "firefox" in ua_lower:
            result["browser"] = "Firefox"
            match = re.search(r"Firefox/(\d+)", ua)
            if match:
                result["browser"] += "/" + match.group(1)
        elif "safari" in ua_lower and "chrome" not in ua_lower:
            result["browser"] = "Safari"
            match = re.search(r"Version/(\d+)", ua)
            if match:
                result["browser"] += "/" + match.group(1)
        elif "edg" in ua_lower:
            result["browser"] = "Edge"
            match = re.search(r"Edg/(\d+)", ua)
            if match:
                result["browser"] += "/" + match.group(1)

        if "windows nt 10.0" in ua_lower:
            result["os"] = "Windows 10"
        elif "windows nt 6.1" in ua_lower:
            result["os"] = "Windows 7"
        elif "iphone" in ua_lower or "ipad" in ua_lower:
            result["os"] = "iOS"
            result["device"] = "mobile"
        elif "android" in ua_lower:
            result["os"] = "Android"
            result["device"] = "mobile"
        elif "mac os x" in ua_lower:
            result["os"] = "macOS"
        elif "linux" in ua_lower:
            result["os"] = "Linux"

        if "mobile" in ua_lower:
            result["device"] = "mobile"
        elif "tablet" in ua_lower:
            result["device"] = "tablet"

        return result

    @staticmethod
    def clean_url_from_pow_params(original_path: str, incoming_query: Dict[str, Any]) -> str:
        from urllib.parse import urlparse, urlencode
        parsed = urlparse(original_path)
        path = parsed.path or "/"
        
        final_query = {k: v for k, v in incoming_query.items()}
        pow_params = [
            "pow_type", "pow_nonce", "pow_solution", "pow_solution_cpu",
            "pow_solution_mem", "pow_fp", "pow_solution_population",
            "pow_solution_work_result", "pow_problem_id", "pow_solution_space"
        ]
        for param in pow_params:
            final_query.pop(param, None)
            
        if final_query:
            return f"{path}?{urlencode(final_query, doseq=True)}"
        return path

    @staticmethod
    def get_header_anomalies(context: RequestContext) -> float:
        """
        Calculates a suspicion score based on HTTP header anomalies.
        Detects missing or inconsistent headers often found in automated requests.

        Args:
            context (RequestContext): The request context.

        Returns:
            float: A score from 0.0 to 100.0, where higher indicates more anomalies.
        """
        anomaly_score = 0.0
        ua = context.headers.get("user-agent", "")
        if not ua or len(ua) < 10:
            anomaly_score += 60.0
        if "accept-language" not in context.headers:
            anomaly_score += 25.0
        if context.http_version == "1.0":
            anomaly_score += 15.0

        ua_parts = RequestUtils.parse_user_agent(ua)
        is_firefox_desktop = (ua_parts.get("browser") or "").startswith("Firefox") and ua_parts.get("device") == "desktop"
        te_header = context.headers.get("te", "").lower()

        if is_firefox_desktop and te_header != "trailers":
            anomaly_score += 30.0
        elif not is_firefox_desktop and ua_parts.get("device") == "desktop" and te_header == "trailers":
            anomaly_score += 30.0

        return min(100.0, anomaly_score)

    @staticmethod
    def get_client_hints_inconsistency(context: RequestContext) -> float:
        """
        Calculates a suspicion score based on inconsistencies between the User-Agent
        and Client Hints headers (Sec-CH-UA, etc.).

        Args:
            context (RequestContext): The request context.

        Returns:
            float: A score from 0.0 to 100.0, where higher indicates more inconsistency.
        """
        ua = context.headers.get("user-agent", "")
        client_hints = context.headers.get("sec-ch-ua", "")
        if not ua or not client_hints:
            return 0.0

        full_version_list = context.headers.get("sec-ch-ua-full-version-list", "")
        if full_version_list:
            ch_full_version = None
            ch_full_browser = None
            matches = re.findall(r'"([^"]+)";v="([^"]+)"', full_version_list)
            for brand, version in matches:
                if brand in ("Google Chrome", "Chromium", "Microsoft Edge"):
                    ch_full_version = version
                    ch_full_browser = "Edge" if brand == "Microsoft Edge" else "Chrome"
                    if brand in ("Google Chrome", "Microsoft Edge"):
                        break
            if ch_full_version and ch_full_browser:
                ua_full_match = re.search(r"(Chrome|Edg)/([\d.]+)", ua)
                if ua_full_match:
                    ua_browser_mapped = "Edge" if ua_full_match.group(1) == "Edg" else "Chrome"
                    ua_full_version = ua_full_match.group(2)
                    if ua_browser_mapped == ch_full_browser and ua_full_version != ch_full_version:
                            parts1 = [int(x) for x in ua_full_version.split(".")]
                            parts2 = [int(x) for x in ch_full_version.split(".")]
                            diff_index = -1
                            for i in range(max(len(parts1), len(parts2))):
                                p1 = parts1[i] if i < len(parts1) else 0
                                p2 = parts2[i] if i < len(parts2) else 0
                                if p1 != p2:
                                    diff_index = i
                                    break
                            base_scores = [95.0, 90.0, 85.0, 80.0]
                            base_score = base_scores[diff_index] if diff_index < len(base_scores) else 80.0
                            delta = abs((parts1[diff_index] if diff_index < len(parts1) else 0) - (parts2[diff_index] if diff_index < len(parts2) else 0))
                            final_full_score = min(100.0, base_score + min(5.0, delta * 5.0))
                            return final_full_score

        ua_browser = None
        ua_version = None
        ua_match = re.search(r"(Chrome|Firefox|Edg|Safari)/([\d.]+)", ua)
        if ua_match:
            ua_browser = "Edge" if ua_match.group(1) == "Edg" else ua_match.group(1)
            ua_version = ua_match.group(2).split(".")[0]

        ch_browser = None
        ch_version = None
        ch_match = re.search(r'"(Google Chrome|Chromium|Microsoft Edge)";v="(\d+)"', client_hints)
        if ch_match:
            ch_version = ch_match.group(2)
            ch_browser = "Edge" if ch_match.group(1) == "Microsoft Edge" else "Chrome"

        if not ua_version or not ch_version or not ua_browser or not ch_browser:
            return 0.0

        if ua_browser != ch_browser and not (ua_browser == "Chrome" and ch_browser == "Edge"):
            return 90.0

        try:
            version_diff = abs(int(ua_version) - int(ch_version))
            client_hints_inconsistency_score = 0.0
            if version_diff > 0:
                if version_diff <= 2:
                    client_hints_inconsistency_score = version_diff * 20.0
                elif version_diff <= 7:
                    client_hints_inconsistency_score = 40.0 + (version_diff - 2) * 8.0
                else:
                    client_hints_inconsistency_score = min(100.0, 80.0 + (version_diff - 7) * 3.33)
                return round(client_hints_inconsistency_score, 1)
        except ValueError:
            pass

        return 0.0

    @staticmethod
    def get_time_inconsistency_score(context: RequestContext) -> float:
        header = context.headers.get("x-behavior-metrics")
        if not header:
            return 0.0
        try:
            metrics = json.loads(header)
        except Exception:
            return 0.0
        client_ts = metrics.get("clientTimestamp")
        if not client_ts or not context.request_timestamp:
            return 0.0
        time_delta = context.request_timestamp - client_ts
        replay_threshold = 5000
        if time_delta > replay_threshold:
            return min(100.0, (time_delta / replay_threshold - 1.0) * 50.0)
        return 0.0

    @staticmethod
    def get_quic_anomaly_score(context: RequestContext) -> Dict[str, float]:
        quic_fp = context.headers.get("x-quic-fp") or getattr(context, "quic_fingerprint", None)
        if not quic_fp or not isinstance(quic_fp, str):
            return {"quicAnomalyScore": 0.0}

        parts = quic_fp.split(";")
        if len(parts) < 2:
            return {"quicAnomalyScore": 0.0}

        params = {}
        for p in parts[1].split(","):
            kv = p.split("=", 1)
            if len(kv) == 2:
                params[kv[0]] = kv[1]
        priority_order = parts[2] if len(parts) > 2 else ""

        ua = context.headers.get("user-agent", "")
        ua_parts = RequestUtils.parse_user_agent(ua)
        browser = ua_parts.get("browser")

        if not browser:
            return {"quicAnomalyScore": 0.0}

        anomaly = 0.0
        if browser.startswith("Chrome") or browser.startswith("Edge"):
            try:
                max_data = int(params.get("1", "0"))
                max_streams = int(params.get("4", "0"))
                if max_data > 0 and max_data < 1048576:
                    anomaly += 40.0
                if max_streams > 0 and max_streams != 100:
                    anomaly += 30.0
                if priority_order and "u=" not in priority_order:
                    anomaly += 30.0
            except ValueError:
                pass
        elif browser.startswith("Firefox"):
            try:
                max_data = int(params.get("1", "0"))
                if max_data > 0 and max_data > 5000000:
                    anomaly += 40.0
            except ValueError:
                pass

        return {"quicAnomalyScore": max(0.0, min(100.0, anomaly))}

    @staticmethod
    def get_rendering_anomaly_score(context: RequestContext) -> Dict[str, float]:
        header = context.headers.get("x-behavior-metrics")
        if not header:
            return {"renderingAnomalyScore": 0.0}
        try:
            metrics = json.loads(header)
        except Exception:
            return {"renderingAnomalyScore": 0.0}

        rendering = metrics.get("rendering")
        if not rendering:
            return {"renderingAnomalyScore": 0.0}

        score = 0.0
        if rendering.get("offscreenAnom"):
            score += 100.0

        try:
            fps = float(rendering.get("fps", 0.0))
            jitter = float(rendering.get("jitter", 0.0))
        except (ValueError, TypeError):
            fps = 0.0
            jitter = 0.0

        if fps > 250.0 or (0.0 < fps < 15.0):
            score += 50.0
        if jitter > 6.0:
            score += min(80.0, (jitter - 6.0) * 10.0)

        return {"renderingAnomalyScore": min(100.0, score)}

    @staticmethod
    def get_click_variance_score(context: RequestContext) -> float:
        header = context.headers.get("x-behavior-metrics")
        if not header:
            return 0.0
        try:
            metrics = json.loads(header)
        except Exception:
            return 0.0
        history = metrics.get("clicksHistory")
        if not history or len(history) < 3:
            return 0.0
        clicks_by_target = {}
        for click in history:
            tid = click.get("targetId")
            if tid:
                clicks_by_target.setdefault(tid, []).append(click)
        max_score = 0.0
        for clicks in clicks_by_target.values():
            if len(clicks) < 3:
                continue
            n = len(clicks)
            mean_x = sum(c["x"] for c in clicks) / n
            mean_y = sum(c["y"] for c in clicks) / n
            variance = sum((c["x"] - mean_x)**2 + (c["y"] - mean_y)**2 for c in clicks) / n
            if variance < 1.0:
                score = (1.0 - math.sqrt(variance) / 5.0) * 100.0
                if score > max_score:
                    max_score = score
        return min(100.0, max_score)

    @staticmethod
    def get_cross_layer_inconsistency(context: RequestContext) -> float:
        client_fp = context.headers.get("x-device-fingerprint")
        if not client_fp:
            return 0.0
        try:
            fp_map = dict(part.split(":", 1) for part in client_fp.split("|") if ":" in part)
        except Exception:
            return 10.0
        ua = context.headers.get("user-agent", "")
        score = 0.0
        client_os_hash = fp_map.get("os")
        if client_os_hash:
            srv_os = RequestUtils.parse_user_agent(ua).get("os")
            if srv_os and client_os_hash != str(cyrb53(srv_os)):
                score += 50.0

            # 2. Incohérence de l'écran (si les Client Hints sont disponibles)
        client_screen_hash = fp_map.get("scr")
        viewport_width = context.headers.get("sec-ch-viewport-width")
        if client_screen_hash and viewport_width:
            try:
                viewport_width_int = int(viewport_width)
                matched_screen_width = None
                common_widths = [320, 360, 375, 390, 412, 414, 768, 1024, 1280, 1366, 1440, 1536, 1600, 1920, 2560, 3840]
                common_heights = [480, 568, 640, 667, 736, 800, 812, 844, 896, 900, 1024, 1080, 1200, 1440, 1600, 2160]
                common_depths = [24, 30, 32]

                for w in common_widths:
                    for h in common_heights:
                        for d in common_depths:
                            candidate = f"{w}x{h}_{d}"
                            if client_screen_hash == str(cyrb53(candidate)):
                                matched_screen_width = w
                                break
                        if matched_screen_width is not None:
                            break
                    if matched_screen_width is not None:
                        break

                if matched_screen_width is not None and viewport_width_int > matched_screen_width:
                    score += 20.0
            except Exception:
                pass

        # 3. Incohérence du GPU/Canvas et JA3
        client_gpu_hash = fp_map.get("gpu")
        ja3 = context.headers.get("x-ja3-hash")
        if client_gpu_hash and ja3:
            tls_fingerprint_db = {
                "e188a442b87f422c5a1e80b05399435b": ["Chrome"],
                "d8e35855049321c6042a4325c697858f": ["Chrome"],
                "a9f90958d44533748c139a5d1895b925": ["Chrome"],
                "3b5379916d2b3882253c42885956a350": ["Chrome"],
                "59822058c95c33d2d06e52f410855c8c": ["Chrome"],
                "b386946a5a586163c7c533636b45c355": ["Firefox"],
                "66236495a523c1785f8f3a105b248b11": ["Firefox"],
                "b73d470006575b5e35167a0b5a8540e2": ["Firefox"],
                "8443d7562933834333943465d52363cf": ["Firefox"],
                "b633f21d532d35967c8753c38536b4d3": ["Safari"],
                "4d7a28d5f55b359b69100a311013f03e": ["Safari", "Chrome", "Firefox"],
                "8dd3d7532873575314df23c447543001": ["Safari", "Chrome", "Firefox"],
                "47344a349b75c4e82333475553b5f358": ["Python"],
                "b29587b8a143c42546133ad7704b3310": ["Go"],
                "d435b5223b2884c5a832b842637e245f": ["Java"],
                "c72366b9551263d990b7fa574225332c": ["curl"]
            }
            expected_clients = tls_fingerprint_db.get(ja3)
            if expected_clients:
                if not isinstance(expected_clients, list):
                    expected_clients = [expected_clients]
                non_browser_libraries = ["Python", "Go", "Java", "curl"]
                is_library = any(lib in non_browser_libraries for lib in expected_clients)
                if is_library:
                    score += 30.0
        return min(100.0, score)

    @staticmethod
    def get_threat_intel_score(context: RequestContext, threat_intel_config: Optional[Dict[str, Any]] = None) -> float:
        if not threat_intel_config:
            return 0.0
        known_ips = threat_intel_config.get("knownIps", [])
        if context.client_ip in known_ips:
            return 100.0
        return 0.0

    @staticmethod
    def analyze_mouse_movements(history: Optional[List[Dict[str, Any]]]) -> Dict[str, Any]:
        if not history or len(history) < 3:
            return {"avgSpeed": 0.0, "avgAcceleration": 0.0, "straightness": 1.0, "pauses": 0, "segments": []}
        segments, total_distance, pauses = [], 0.0, 0
        for i in range(1, len(history)):
            p1, p2 = history[i-1], history[i]
            dx, dy, dt = p2["x"] - p1["x"], p2["y"] - p1["y"], p2["t"] - p1["t"]
            distance = math.sqrt(dx*dx + dy*dy)
            if dt > 0:
                segments.append({"distance": distance, "dt": dt, "speed": distance / dt})
                total_distance += distance
            if dt > 100 and distance < 5:
                pauses += 1
        if len(segments) < 2:
            return {"avgSpeed": 0.0, "avgAcceleration": 0.0, "straightness": 1.0, "pauses": pauses, "segments": []}
        total_time = history[-1]["t"] - history[0]["t"]
        avg_speed = sum(s["speed"] for s in segments) / len(segments) if total_time > 0 else 0.0
        total_abs_acc = sum(abs((segments[i]["speed"] - segments[i-1]["speed"]) / segments[i]["dt"]) for i in range(1, len(segments)) if segments[i]["dt"] > 0)
        avg_acceleration = total_abs_acc / (len(segments) - 1)
        straight_dist = math.sqrt((history[-1]["x"] - history[0]["x"])**2 + (history[-1]["y"] - history[0]["y"])**2)
        return {"avgSpeed": avg_speed, "avgAcceleration": avg_acceleration, "straightness": straight_dist / total_distance if total_distance > 0 else 1.0, "pauses": pauses, "segments": [s["distance"] for s in segments]}

    @staticmethod
    def analyze_touch_movements(history: Optional[List[Dict[str, Any]]]) -> Dict[str, Any]:
        if not history or len(history) < 3:
            return {
                "avgSpeed": 0.0, "avgAcceleration": 0.0, "straightness": 1.0, "pauses": 0, "segments": [],
                "avgPressure": 0.0, "avgRadius": 0.0, "pressureVariance": 0.0, "radiusVariance": 0.0, "maxTouches": 1
            }
        segments, total_distance, pauses = [], 0.0, 0
        total_pressure, total_radius, max_touches = 0.0, 0.0, 1
        for i in range(1, len(history)):
            p1, p2 = history[i-1], history[i]
            dx, dy, dt = p2["x"] - p1["x"], p2["y"] - p1["y"], p2["t"] - p1["t"]
            distance = math.sqrt(dx*dx + dy*dy)
            total_pressure += p2.get("p", 0.0)
            total_radius += p2.get("r", 0.0)
            if p2.get("num", 1) > max_touches:
                max_touches = p2.get("num", 1)
            if dt > 0:
                segments.append({"distance": distance, "dt": dt, "speed": distance / dt})
                total_distance += distance
            if dt > 100 and distance < 5:
                pauses += 1

        total_pressure += history[0].get("p", 0.0)
        total_radius += history[0].get("r", 0.0)

        avg_pressure = total_pressure / len(history)
        avg_radius = total_radius / len(history)

        pressure_variance = sum((pt.get("p", 0.0) - avg_pressure) ** 2 for pt in history) / len(history)
        radius_variance = sum((pt.get("r", 0.0) - avg_radius) ** 2 for pt in history) / len(history)

        if len(segments) < 2:
            return {
                "avgSpeed": 0.0, "avgAcceleration": 0.0, "straightness": 1.0, "pauses": pauses, "segments": [],
                "avgPressure": avg_pressure, "avgRadius": avg_radius, "pressureVariance": pressure_variance, "radiusVariance": radius_variance, "maxTouches": max_touches
            }
        total_time = history[-1]["t"] - history[0]["t"]
        avg_speed = sum(s["speed"] for s in segments) / len(segments) if total_time > 0 else 0.0
        total_abs_acc = sum(abs((segments[i]["speed"] - segments[i-1]["speed"]) / segments[i]["dt"]) for i in range(1, len(segments)) if segments[i]["dt"] > 0)
        avg_acceleration = total_abs_acc / (len(segments) - 1)
        straight_dist = math.sqrt((history[-1]["x"] - history[0]["x"])**2 + (history[-1]["y"] - history[0]["y"])**2)
        return {
            "avgSpeed": avg_speed, "avgAcceleration": avg_acceleration,
            "straightness": straight_dist / total_distance if total_distance > 0 else 1.0, "pauses": pauses,
            "segments": [s["distance"] for s in segments], "avgPressure": avg_pressure, "avgRadius": avg_radius,
            "pressureVariance": pressure_variance, "radiusVariance": radius_variance, "maxTouches": max_touches
        }

    @staticmethod
    def get_behavior_score(context: RequestContext) -> float:
        header = context.headers.get("x-behavior-metrics")
        if not header:
            return 0.0
        try:
            metrics = json.loads(header)
        except Exception:
            return 10.0
        if metrics.get("honeypotInteraction"):
            return 100.0
        score = 0.0
        mouse_analysis = RequestUtils.analyze_mouse_movements(metrics.get("mouseMovementsHistory"))
        touch_analysis = RequestUtils.analyze_touch_movements(metrics.get("touchMovementsHistory"))
        if "historyLength" in metrics:
            hl = metrics["historyLength"]
            if hl == 1: score += 15.0
            elif hl >= 5: score -= 20.0
            elif hl >= 2: score -= 10.0
        else:
            if mouse_analysis["avgSpeed"] == 0.0 and touch_analysis["avgSpeed"] == 0.0 and metrics.get("keystrokeLatency", 0.0) == 0.0:
                score += 40.0
        if mouse_analysis["avgSpeed"] > 0.0:
            if mouse_analysis["avgSpeed"] > 3.0: score += 25.0
            if mouse_analysis["avgAcceleration"] > 0.5: score += 20.0
            if mouse_analysis["straightness"] > 0.95: score += 30.0
            if mouse_analysis["pauses"] == 0 and len(mouse_analysis["segments"]) > 20: score += 15.0

        if touch_analysis["avgSpeed"] > 0.0:
            if touch_analysis["avgSpeed"] > 5.0: score += 30.0
            if touch_analysis["avgAcceleration"] > 0.8: score += 20.0
            if touch_analysis["straightness"] > 0.98: score += 35.0
            if touch_analysis["pauses"] == 0 and len(touch_analysis["segments"]) > 25: score += 15.0
            if touch_analysis["avgPressure"] > 0.0 and touch_analysis["pressureVariance"] == 0.0: score += 30.0
            if touch_analysis["avgRadius"] > 0.0 and touch_analysis["radiusVariance"] == 0.0: score += 30.0
        if len(touch_analysis["segments"]) > 10:
            benford_deviation = Optimization.benford_test(touch_analysis["segments"])
            if benford_deviation > 0.18: score += 35.0

        ks_latency = metrics.get("keystrokeLatency", 0.0)
        if 0.0 < ks_latency < 40.0: score += 25.0
        if ks_latency > 1000.0: score += 15.0
        if len(mouse_analysis["segments"]) > 10:
            benford_deviation = Optimization.benford_test(mouse_analysis["segments"])
            if benford_deviation > 0.18: score += 35.0
        return min(100.0, score)

    @staticmethod
    def get_request_pattern_score(context: RequestContext, device_data: Dict[str, Any], pattern_config: Dict[str, Any]) -> Dict[str, float]:
        history_size = pattern_config.get("historySize", 20)
        min_samples = pattern_config.get("minSamples", 10)
        regularity_threshold = pattern_config.get("regularityThreshold", 150)
        benford_threshold = pattern_config.get("benfordThreshold", 0.15)
        pattern_weight = pattern_config.get("patternWeight", 80)
        decay_factor = pattern_config.get("decayFactor", 0.95)
        inactivity_reset = pattern_config.get("inactivityReset", 180000)
        regularity_ratio = pattern_config.get("regularityRatio", 0.4)
        benford_ratio = pattern_config.get("benfordRatio", 0.3)
        enumeration_ratio = pattern_config.get("enumerationRatio", 0.3)
        now = int(time.time() * 1000)
        history = device_data.get("requestHistory", [])
        device_data["timingHistory"] = device_data.get("timingHistory", [])
        last_request = history[-1] if history else None
        time_since_last = now - last_request["timestamp"] if last_request else float("inf")
        history.append({"timestamp": now, "path": context.path})
        if last_request:
            device_data["timingHistory"].append(time_since_last)
        if len(history) > history_size: history.pop(0)
        if len(device_data["timingHistory"]) > history_size: device_data["timingHistory"].pop(0)
        device_data["requestHistory"] = history
        regularity_score = 0.0
        benford_score = 0.0
        timings = device_data["timingHistory"]
        if len(timings) >= min_samples:
            mean = sum(timings) / len(timings)
            variance = sum((t - mean) ** 2 for t in timings) / len(timings)
            std_dev = math.sqrt(variance)
            benford_deviation = Optimization.benford_test(timings)
            if std_dev < regularity_threshold:
                regularity_score = 1.0 - (std_dev / regularity_threshold)
            if benford_deviation > benford_threshold:
                benford_score = min(1.0, (benford_deviation - benford_threshold) / (0.5 - benford_threshold))

        # Path enumeration progressif
        enumeration_score = 0.0
        if len(history) >= 3:
            templates = [re.sub(r"\d+", "{num}", h["path"]) for h in history]
            unique_paths = set(h["path"] for h in history)
            from collections import Counter
            template_counts = Counter(templates)
            max_template_repetition = max(template_counts.values()) if template_counts else 0
            if max_template_repetition >= 3 and len(unique_paths) == len(history):
                enumeration_score = min(1.0, (max_template_repetition - 2) / 5.0)

        weighted_score = (regularity_score * regularity_ratio) + \
                         (benford_score * benford_ratio) + \
                         (enumeration_score * enumeration_ratio)
        instant_score = weighted_score * pattern_weight

        new_pattern_score = device_data.get("lastPatternScore", 0.0)
        if time_since_last > inactivity_reset: new_pattern_score = 0.0
        else: new_pattern_score *= decay_factor
        device_data["lastPatternScore"] = max(0.0, max(instant_score, new_pattern_score))
        return {"requestPatternScore": min(100.0, device_data["lastPatternScore"])}

    @staticmethod
    async def get_ip_reputation_score(store, ip: str) -> float:
        key = f"ip-reputation:{ip}"
        data = await store.get(key)
        if not data: return 0.0
        now = time.time()
        hours_passed = (now - data.get("lastUpdate", now)) / 3600.0
        decay = int(math.floor(hours_passed * 2))
        return max(0.0, float(data.get("score", 0.0) - decay))

    @staticmethod
    async def update_ip_reputation_score(store, ip: str, change: float) -> None:
        key = f"ip-reputation:{ip}"
        current = await RequestUtils.get_ip_reputation_score(store, ip)
        new_score = min(100.0, max(0.0, current + change))
        await store.set(key, {"score": new_score, "lastUpdate": time.time()}, 86400 * 7)

    @staticmethod
    async def update_subnet_metrics(store, client_ip: str, device_id: str, final_score: float) -> None:
        subnet = get_ip_subnet(client_ip)
        if not subnet: return
        key = f"subnet:{subnet}"
        subnet_data = await store.get(key) or {"highScoreCount": 0, "deviceIds": [], "highScoreDevices": {}, "lastActivity": 0}
        subnet_data.setdefault("highScoreDevices", {})
        current_contributions = subnet_data["highScoreDevices"].get(device_id, 0)
        if current_contributions < 5 and final_score < 95:
            subnet_data["highScoreDevices"][device_id] = current_contributions + 1
            subnet_data["highScoreCount"] += 1
        if device_id not in subnet_data["deviceIds"]:
            subnet_data["deviceIds"].append(device_id)
        subnet_data["lastActivity"] = int(time.time())
        if len(subnet_data["deviceIds"]) > 100:
            old_device_id = subnet_data["deviceIds"].pop(0)
            if old_device_id in subnet_data["highScoreDevices"]:
                old_contrib = subnet_data["highScoreDevices"].pop(old_device_id)
                subnet_data["highScoreCount"] = max(0, subnet_data["highScoreCount"] - old_contrib)
        await store.set(key, subnet_data, 86400)

    @staticmethod
    async def get_subnet_score(store, client_ip: str, current_device_id: str) -> Dict[str, float]:
        subnet = get_ip_subnet(client_ip)
        if not subnet: return {"subnetScore": 0.0}
        key = f"subnet:{subnet}"
        subnet_data = await store.get(key)
        if not subnet_data: return {"subnetScore": 0.0}
        now = int(time.time())
        inactivity_sec = now - subnet_data.get("lastActivity", now)
        half_lives = int(math.floor(inactivity_sec / 1800))
        high_score_count = subnet_data.get("highScoreCount", 0)
        device_count = len(subnet_data.get("deviceIds", []))
        if half_lives > 0:
            high_score_count = max(0, int(math.floor(high_score_count / (2 ** half_lives))))
            device_count = max(0, int(math.floor(device_count / (2 ** half_lives))))
        score = 0.0
        if device_count > 10:
            score += min(80.0, (device_count - 10) * 5)
        score += min(40.0, high_score_count * 2)
        return {"subnetScore": min(100.0, score)}

    @staticmethod
    def get_tcp_anomaly_score(context: RequestContext) -> Dict[str, float]:
        fp = None
        raw_tcp_binary = context.headers.get("x-raw-tcp-binary")
        if raw_tcp_binary:
            if isinstance(raw_tcp_binary, str):
                try:
                    binary = bytes.fromhex(raw_tcp_binary)
                except ValueError:
                    binary = raw_tcp_binary.encode("utf-8")
            else:
                binary = raw_tcp_binary
            fp = parse_tcp_syn(binary)

        if not fp:
            tcp_header = context.headers.get("x-tcp-fingerprint") or getattr(context, "tcp_fingerprint", None)
            if tcp_header and isinstance(tcp_header, str):
                parts = tcp_header.split(":")
                if len(parts) >= 2:
                    try:
                        fp = {
                            "ttl": int(parts[0]),
                            "windowSize": int(parts[1]),
                            "mss": int(parts[2]) if len(parts) > 2 and parts[2] else None,
                            "ws": int(parts[3]) if len(parts) > 3 and parts[3] else None,
                            "sack": len(parts) > 4 and parts[4] in ("1", "true")
                        }
                    except ValueError:
                        pass
        if not fp:
            return {"tcpAnomalyScore": 0.0}
        tcp_os = classify_tcp_os(fp)
        ua = context.headers.get("user-agent", "")
        ua_parts = RequestUtils.parse_user_agent(ua)
        ua_os = ua_parts.get("os")
        if not ua_os or tcp_os == "unknown":
            return {"tcpAnomalyScore": 0.0}

        mapped_os = None
        if ua_os.startswith("Windows"):
            mapped_os = "Windows"
        elif ua_os.startswith("Mac") or ua_os.startswith("macOS"):
            mapped_os = "macOS"
        elif ua_os.startswith("iOS"):
            mapped_os = "iOS"
        elif ua_os.startswith("Linux"):
            mapped_os = "Linux"

        if mapped_os is None:
            return {"tcpAnomalyScore": 0.0}

        os_expected_tcp = {
            "Windows": {"ttl": 128, "windowSize": 64240, "ws": 8, "mss": 1460, "sack": True},
            "Linux": {"ttl": 64, "windowSize": 29200, "ws": 7, "mss": 1460, "sack": True},
            "macOS": {"ttl": 64, "windowSize": 65535, "ws": 6, "mss": 1460, "sack": True},
            "iOS": {"ttl": 64, "windowSize": 65535, "ws": 6, "mss": 1460, "sack": True}
        }

        expected = os_expected_tcp[mapped_os]
        ttl_diff = abs(fp["ttl"] - expected["ttl"]) / expected["ttl"]
        win_diff = abs(fp["windowSize"] - expected["windowSize"]) / expected["windowSize"]
        ws_diff = abs(fp["ws"] - expected["ws"]) / expected["ws"] if expected["ws"] is not None and fp.get("ws") is not None else 0.0
        mss_diff = abs(fp["mss"] - expected["mss"]) / expected["mss"] if expected["mss"] is not None and fp.get("mss") is not None else 0.0
        sack_diff = 0.0 if (fp.get("sack") if fp.get("sack") is not None else True) == expected["sack"] else 1.0

        deviation = (
                min(1.0, ttl_diff) * 0.50 +
                min(1.0, win_diff) * 0.25 +
                min(1.0, ws_diff) * 0.15 +
                min(1.0, mss_diff) * 0.05 +
                sack_diff * 0.05
        )

        tcp_anomaly_score = 0.0
        if tcp_os != mapped_os and tcp_os != "unknown":
            base_anomaly = 80.0 if mapped_os == "Windows" else (85.0 if mapped_os in ("macOS", "iOS") else 75.0)
            tcp_anomaly_score = base_anomaly + (deviation - 0.4) * 10.0
        else:
            tcp_anomaly_score = deviation * 40.0

        tcp_anomaly_score = max(0.0, min(100.0, round(tcp_anomaly_score, 1)))
        return {"tcpAnomalyScore": tcp_anomaly_score}

    @staticmethod
    def get_honeypot_score(context: RequestContext, honeypot_config: Optional[Dict[str, Any]] = None) -> float:
        if not honeypot_config: return 0.0
        fields = honeypot_config.get("fields", [])
        trap_urls = honeypot_config.get("trapUrls", [])
        detect_injections = honeypot_config.get("detectInjections", True)
        for trap in trap_urls:
            if context.path.startswith(trap): return 100.0
        data = {}
        if isinstance(context.query_params, dict): data.update(context.query_params)
        if isinstance(context.body, dict): data.update(context.body)
        for field_name in fields:
            if field_name.startswith("pow_") or field_name in ("pow_nonce", "pow_solution_cpu", "pow_solution_mem"): continue
            if field_name in data and data[field_name]: return 100.0
        if detect_injections:
            types_to_detect = detect_injections if isinstance(detect_injections, list) else None
            for k, v in data.items():
                if isinstance(v, str) and MaliciousPatterns.is_malicious(v, types_to_detect): return 100.0
                elif isinstance(v, dict) and MaliciousPatterns.is_malicious(json.dumps(v), types_to_detect): return 100.0
        return 0.0

    @staticmethod
    def get_bot_score(context: RequestContext) -> float:
        """
        Calculates a suspicion score based on explicit bot detection markers
        present in the client-side fingerprint.

        Args:
            context (RequestContext): The request context.

        Returns:
            float: A score of 100.0 if bot markers are found, 0.0 otherwise.
        """
        client_fp = context.headers.get("x-device-fingerprint", "")
        if not client_fp:
            return 0.0
        if "bot:true" in client_fp or "cdp:true" in client_fp:
            return 100.0
        return 0.0

    @staticmethod
    def get_honeypot_score(context: RequestContext, honeypot_config: Optional[Dict[str, Any]] = None) -> float:
        """
        Calculates a suspicion score based on honeypot interactions.
        Triggers a high score if hidden form fields are filled or trap URLs are accessed.

        Args:
            context (RequestContext): The request context.
            honeypot_config (Optional[Dict[str, Any]]): Configuration for honeypots.

        Returns:
            float: A score of 100.0 if a honeypot is triggered, 0.0 otherwise.
        """
        if not honeypot_config:
            return 0.0
        
        fields = honeypot_config.get("fields", [])
        trap_urls = honeypot_config.get("trapUrls", [])
        
        for trap in trap_urls:
            if context.path.startswith(trap):
                return 100.0
                
        data = {}
        if isinstance(context.query_params, dict):
            data.update(context.query_params)
        if isinstance(context.body, dict):
            data.update(context.body)
            
        for field_name in fields:
            if field_name.startswith("pow_") or field_name in ("pow_nonce", "pow_solution_cpu", "pow_solution_mem"):
                continue
            if field_name in data and data[field_name]:
                return 100.0
                
        return 0.0

    @staticmethod
    def get_botnet_cluster_score(context: RequestContext, stable_fp_hash: str) -> Dict[str, float]:
        if not stable_fp_hash:
            return {"botnetClusterScore": 0.0}

        now = int(time.time())
        ten_minutes_ago = now - 600

        cluster_data = RequestUtils._botnet_clusters.get(stable_fp_hash, [])
        if not isinstance(cluster_data, list):
            cluster_data = []

        # Filter out entries older than 10 minutes
        cluster_data = [entry for entry in cluster_data if entry.get("timestamp", 0) > ten_minutes_ago]

        # Check if the client IP already exists in the cluster
        found = False
        for entry in cluster_data:
            if entry.get("ip") == context.client_ip:
                entry["timestamp"] = now
                found = True
                break

        if not found:
            cluster_data.append({"ip": context.client_ip, "timestamp": now})

        # Save back to class-level cache
        RequestUtils._botnet_clusters[stable_fp_hash] = cluster_data

        unique_ips_count = len(cluster_data)
        botnet_cluster_score = 0.0
        if unique_ips_count >= 2:
            raw_score = 100.0 * (1.0 - math.exp(-0.35 * (unique_ips_count - 1)))
            botnet_cluster_score = min(100.0, round(raw_score, 1))

        return {"botnetClusterScore": botnet_cluster_score}

class RedisStore:
    """
    Production-grade Redis adapter for FingerprintEngine.
    Handles serialization, deserialization, and Set-to-list conversions.
    """
    def __init__(self, redis_client):
        self._client = redis_client

    def _serialize(self, value: Any) -> str:
        def convert(obj):
            if isinstance(obj, set):
                return list(obj)
            return obj
        return json.dumps(value, default=convert)

    def _deserialize(self, value: str) -> Any:
        obj = json.loads(value)
        if isinstance(obj, dict) and "ips" in obj and isinstance(obj["ips"], list):
            obj["ips"] = set(obj["ips"])
        return obj

    async def get(self, key: str) -> Optional[Any]:
        val = await self._client.get(key)
        if not val:
            return None
        return self._deserialize(val.decode("utf-8") if isinstance(val, bytes) else val)

    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        val_str = self._serialize(value)
        if ttl:
            await self._client.setex(key, ttl, val_str)
        else:
            await self._client.set(key, val_str)

    async def has(self, key: str) -> bool:
        return await self._client.exists(key) > 0

    async def delete(self, key: str) -> None:
        await self._client.delete(key)

class MongoDbStore:
    """
    Production-grade MongoDB adapter using motor or pymongo async.
    Includes dynamic active expiration and Set-to-list conversions.
    """
    def __init__(self, collection):
        self._collection = collection

    def _serialize(self, value: Any) -> str:
        def convert(obj):
            if isinstance(obj, set):
                return list(obj)
            return obj
        return json.dumps(value, default=convert)

    def _deserialize(self, value: str) -> Any:
        obj = json.loads(value)
        if isinstance(obj, dict) and "ips" in obj and isinstance(obj["ips"], list):
            obj["ips"] = set(obj["ips"])
        return obj

    async def get(self, key: str) -> Optional[Any]:
        doc = await self._collection.find_one({"_id": key})
        if not doc:
            return None
        if "expiresAt" in doc:
            expires_at = doc["expiresAt"]
            if expires_at.tzinfo is None:
                now = datetime.datetime.utcnow()
            else:
                now = datetime.datetime.now(datetime.timezone.utc)
            if expires_at < now:
                await self.delete(key)
                return None
        return self._deserialize(doc["value"])

    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        doc = {
            "_id": key,
            "value": self._serialize(value)
        }
        if ttl:
            doc["expiresAt"] = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=ttl)
        await self._collection.replace_one({"_id": key}, doc, upsert=True)

    async def has(self, key: str) -> bool:
        doc = await self._collection.find_one({"_id": key}, {"expiresAt": 1})
        if not doc:
            return False
        if "expiresAt" in doc:
            expires_at = doc["expiresAt"]
            if expires_at.tzinfo is None:
                now = datetime.datetime.utcnow()
            else:
                now = datetime.datetime.now(datetime.timezone.utc)
            if expires_at < now:
                await self.delete(key)
                return False
        return True

    async def delete(self, key: str) -> None:
        await self._collection.delete_one({"_id": key})

    async def init(self) -> None:
        import pymongo
        await self._collection.create_index([("expiresAt", pymongo.ASCENDING)], expireAfterSeconds=0)

class MaliciousPatterns:
    """Provides utilities for recursive WAF detection on inputs."""
    INJECTION_PATTERNS = {
        "sql": re.compile(r"(\$ne|' *OR *'1'='1|['\";]\s*--|; ?(DROP|TRUNCATE|DELETE)|UNION SELECT|(?:SLEEP|BENCHMARK)\s*\(|WAITFOR DELAY)", re.IGNORECASE),
        "log4shell": re.compile(r"\$\{jndi:(ldap|rmi|dns):", re.IGNORECASE),
        "ssti": re.compile(r"\{\{.*\}\}|\{%.*%\}"),
        "xxe": re.compile(r"<!ENTITY\s+.*SYSTEM", re.IGNORECASE),
        "traversal": re.compile(r"(\.\.\/|\.\.)"),
        "rce": re.compile(r"`.*`|(?:^|[\n;&|]\s*)(?:ping|ls|whoami|cat|rm|ncat|nc|bash|sh|powershell|cmd)\b", re.IGNORECASE),
        "ssrf": re.compile(r"(?:https?://)?(?:127\.\d+\.\d+\.\d+|169\.254\.169\.254|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|localhost|0\.0\.0\.0|\[[0:]+1\])\b", re.IGNORECASE),
        "crlf": re.compile(r"[\r\n]|%0[ad]", re.IGNORECASE),
        "xss": re.compile(r"(<script|javascript:|on\w+\s*=|alert\s*\(|confirm\s*\(|prompt\s*\(|<img\s+src[^>]+onerror|<iframe)", re.IGNORECASE),
        "openRedirect": re.compile(r"^(https?:)?//(?![^\/]*?(localhost|127\.0\.0\.1))[^\s\/]+", re.IGNORECASE),
        "lfi": re.compile(r"(?:etc/passwd|win\.ini|boot\.ini|php://filter|data://|zip://)", re.IGNORECASE),
        "shellshock": re.compile(r"\(\)\s*\{\s*:\s*;\s*\}\s*", re.IGNORECASE),
        "nosql": re.compile(r"\$(?:eq|ne|gt|gte|lt|lte|in|nin|and|or|nor|not|expr|jsonSchema|mod|regex|text|where|elemMatch)", re.IGNORECASE)
    }

    @staticmethod
    def is_malicious(string: str, types_to_detect: Optional[List[str]] = None) -> bool:
        if not types_to_detect:
            types_to_detect = [k for k in MaliciousPatterns.INJECTION_PATTERNS.keys() if k != "openRedirect"]
        for t in types_to_detect:
            pattern = MaliciousPatterns.INJECTION_PATTERNS.get(t)
            if pattern and pattern.search(string):
                return True
        return False

class MetricsManager:
    """Prometheus-compatible real-time metrics manager."""
    _counters: Dict[str, Dict[str, Any]] = {}
    _observations: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def increment_counter(cls, name: str, labels: Optional[Dict[str, str]] = None) -> None:
        if not name.startswith("fingerprint_"):
            name = "fingerprint_" + name
        labels = labels or {}
        sorted_labels = sorted(labels.items())
        if labels:
            pairs = [f'{k}="{v}"' for k, v in sorted_labels]
            labels_str = f"{{{','.join(pairs)}}}"
        else:
            labels_str = ""
        if labels:
            pairs = [f'{k}="{v}"' for k, v in sorted_labels]
            labels_str = f"{{{','.join(pairs)}}}"
        else:
            labels_str = ""
        key = f"{name}{labels_str}"
        if key not in cls._counters:
            cls._counters[key] = {"name": name, "labelsStr": labels_str, "value": 0}
        cls._counters[key]["value"] += 1

    @classmethod
    def observe_value(cls, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        if not name.startswith("fingerprint_"):
            name = "fingerprint_" + name
        labels = labels or {}
        sorted_labels = sorted(labels.items())
        if labels:
            pairs = [f'{k}="{v}"' for k, v in sorted_labels]
            labels_str = f"{{{','.join(pairs)}}}"
        else:
            labels_str = ""
        key = f"{name}{labels_str}"
        cls._observations[key] = {"name": name, "labelsStr": labels_str, "value": value}

    @classmethod
    def clear_metrics(cls) -> None:
        cls._counters = {}
        cls._observations = {}

    @classmethod
    def get_prometheus_metrics(cls, security_config: Optional[Dict[str, Any]] = None, last_best_solution: Optional[Dict[str, Any]] = None) -> str:
        metrics = []
        if not cls._counters:
            metrics.append("# HELP fingerprint_requests_total Total requests processed.")
            metrics.append("# TYPE fingerprint_requests_total counter")
            metrics.append('fingerprint_requests_total{status="passed"} 1')
        else:
            grouped = {}
            for k, c in cls._counters.items():
                grouped.setdefault(c["name"], []).append(c)
            for name, instances in grouped.items():
                metrics.append(f"# HELP {name} Total requests processed.")
                metrics.append(f"# TYPE {name} counter")
                for inst in instances:
                    metrics.append(f"{name}{inst['labelsStr']} {inst['value']}")

        if cls._observations:
            grouped_obs = {}
            for k, obs in cls._observations.items():
                grouped_obs.setdefault(obs["name"], []).append(obs)
            for name, instances in grouped_obs.items():
                metrics.append(f"\n# HELP {name} Value observation.")
                metrics.append(f"# TYPE {name} gauge")
                for inst in instances:
                    metrics.append(f"{name}{inst['labelsStr']} {inst['value']}")

        config = security_config or {}
        if "weights" in config and isinstance(config["weights"], dict):
            metrics.append("\n# HELP fingerprint_security_weight Active weight for each suspicion indicator.")
            metrics.append("# TYPE fingerprint_security_weight gauge")
            for indicator, weight in config["weights"].items():
                if isinstance(weight, (int, float)):
                    metrics.append(f'fingerprint_security_weight{{indicator="{indicator}"}} {weight}')

        if "thresholds" in config and isinstance(config["thresholds"], dict):
            metrics.append("\n# HELP fingerprint_security_threshold Active score threshold for each enforcement action level.")
            metrics.append("# TYPE fingerprint_security_threshold gauge")
            for level, val in config["thresholds"].items():
                if isinstance(val, (int, float)):
                    metrics.append(f'fingerprint_security_threshold{{level="{level}"}} {val}')

        if last_best_solution and "objectives" in last_best_solution:
            fpr = last_best_solution["objectives"][0]
            fnr = last_best_solution["objectives"][1]
            metrics.append("\n# HELP fingerprint_autotuning_false_positive_rate Current false positive rate calculated by the auto-tuner.")
            metrics.append("# TYPE fingerprint_autotuning_false_positive_rate gauge")
            metrics.append(f"fingerprint_autotuning_false_positive_rate {fpr}")
            metrics.append("\n# HELP fingerprint_autotuning_false_negative_rate Current false negative rate calculated by the auto-tuner.")
            metrics.append("# TYPE fingerprint_autotuning_false_negative_rate gauge")
            metrics.append(f"fingerprint_autotuning_false_negative_rate {fnr}")

        return "\n".join(metrics) + "\n"
class TLSClientHelloParser:
    """Binary TLS Client Hello decoder to natively extract JA3 strings."""
    GREASE_VALUES = {
        2570, 6682, 10794, 14906, 19018, 23130, 27242, 31354,
        35466, 39578, 43690, 47802, 51914, 55926, 60038, 64150
    }

    @staticmethod
    def parse(binary: bytes) -> Optional[Dict[str, str]]:
        length = len(binary)
        if length < 43:
            return None
        if binary[0] != 0x16 or binary[5] != 0x01:
            return None

        import struct
        offset = 43
        if length < offset + 1:
            return None

        session_len = binary[offset]
        offset += 1 + session_len
        if length < offset + 2:
            return None

        ciphers_len = struct.unpack("!H", binary[offset:offset+2])[0]
        offset += 2
        if length < offset + ciphers_len + 1:
            return None

        ciphers = [struct.unpack("!H", binary[offset+i:offset+i+2])[0] for i in range(0, ciphers_len, 2)]
        offset += ciphers_len

        compression_len = binary[offset]
        offset += 1 + compression_len
        if length < offset + 2:
            return None

        extensions_len = struct.unpack("!H", binary[offset:offset+2])[0]
        offset += 2

        extensions, curves, points = [], [], []
        ext_limit = offset + extensions_len
        while offset < ext_limit and offset + 4 <= length:
            ext_type = struct.unpack("!H", binary[offset:offset+2])[0]
            ext_len = struct.unpack("!H", binary[offset+2:offset+4])[0]
            offset += 4
            if offset + ext_len > length:
                break
            extensions.append(ext_type)
            if ext_type == 10 and ext_len >= 2:
                curves_len = struct.unpack("!H", binary[offset:offset+2])[0]
                curves.extend(struct.unpack(f"!{curves_len//2}H", binary[offset+2:offset+2+curves_len]))
            elif ext_type == 11 and ext_len >= 1:
                points_len = binary[offset]
                points.extend(binary[offset+1:offset+1+points_len])
            offset += ext_len

        filter_grease = lambda arr: [v for v in arr if v not in TLSClientHelloParser.GREASE_VALUES]
        ssl_version = struct.unpack("!H", binary[9:11])[0]
        ja3_string = f"{ssl_version},{'-'.join(map(str, filter_grease(ciphers)))},{'-'.join(map(str, filter_grease(extensions)))},{'-'.join(map(str, filter_grease(curves)))},{'-'.join(map(str, filter_grease(points)))}"
        return {"ja3_string": ja3_string, "ja3_hash": hashlib.md5(ja3_string.encode("utf-8")).hexdigest()}


class FingerprintClient:
    """HTML templating and script tag injection utilities."""
    def __init__(self, client_script_path: str, client_config: Optional[Dict[str, Any]] = None):
        self.client_script_path = client_script_path
        default_config = {
            "mouse": True, "keystrokes": True, "clicks": True, "honeypots": [],
            "fetch": {"handleChallenges": True, "probationaryTtl": 30000},
            "wasm": True, "wasmPath": "/fp.js"
        }
        self.client_config = copy.deepcopy(default_config)
        if client_config:
            self.client_config.update(client_config)
        self.nonce = uuid.uuid4().hex[:16]

    def generate_honeypot_field(self, field_name: str) -> str:
        if field_name not in self.client_config["honeypots"]:
            self.client_config["honeypots"].append(field_name)
        styles = "position:absolute; left:-9999px; top:-9999px; transform:scale(0); opacity:0; pointer-events:none;"
        from html import escape
        f_name = escape(field_name)
        return f'<div style="{styles}" aria-hidden="true"><label for="{f_name}">&gt;</label><input type="text" id="{f_name}" name="{f_name}" tabindex="-1" autocomplete="off"></div>'

    def get_script_tag(self) -> str:
        config_json = json.dumps(self.client_config)
        from html import escape
        nonce_attr = f' nonce="{self.nonce}"' if self.nonce else ""
        init_script = f"""
         document.addEventListener('DOMContentLoaded', function() {{
             const config = {config_json};
             if (window.ClientLibrary) {{
                 if (config.wasmPath) {{
                     const wasmScript = document.createElement('script');
                     wasmScript.src = config.wasmPath;
                     wasmScript.async = true;
                     wasmScript.nonce = '{self.nonce}';
                     document.head.appendChild(wasmScript);
                 }}
                 window.ClientLibrary.initializeClient(config);
             }} else {{
                 console.error('Fingerprint client library not loaded.');
             }}
         }});"""
        return f'<script src="{escape(self.client_script_path)}"{nonce_attr}></script><script{nonce_attr}>{init_script}</script>'

# --- CORE: FingerprintEngine ---
class FingerprintEngine:
    def __init__(self, config: Dict[str, Any], store: InMemoryStore):
        """
        Initializes the FingerprintEngine with a security configuration and a data store.

        Args:
            config (Dict[str, Any]): The security configuration dictionary.
            store (InMemoryStore): An instance of a data store (e.g., InMemoryStore, RedisStore).
        """
        self.config = config
        self.store = store
        self.thresholds = config.get("thresholds", {"low": 20, "high": 75, "block": 95})
        self.weights = config.get("weights", {})
        self.dry_run = config.get("dryRun", False)

        # Bouclier thermique local (Fast-Path Cache) pour amortir les attaques de masse
        # Format: {"ip_or_subnet": (expiration_timestamp, action_to_take)}
        self._fast_path_cache: Dict[str, tuple] = {}
        self._last_prune_time: float = time.time()
        self._prune_interval: float = 10.0 # secondes

        if config.get("enableUsefulWork"):
            try:
                default_path = os.path.join(os.getcwd(), "problems.config.json")
                config_path = config.get("usefulWorkConfigPath") or (default_path if os.path.exists(default_path) else None)
                if config_path:
                    pm = ProblemManager.get_instance(config_path, self.store)
                    if not pm.initialized:
                        try:
                            loop = asyncio.get_running_loop()
                            loop.create_task(pm.load_problems())
                        except RuntimeError:
                            try:
                                loop = asyncio.get_event_loop()
                                if loop.is_running():
                                    loop.create_task(pm.load_problems())
                                else:
                                    loop.run_until_complete(pm.load_problems())
                            except Exception:
                                pass
            except Exception as e:
                print(f"[FingerprintEngine] Background initialization of ProblemManager failed: {e}")

    def _get_weight(self, key: str, default: float) -> float:
        if not self.weights:
            return default
        return self.weights.get(key, 0.0)

    def _extract_stable_part(self, fp_str: str) -> str:
        stable_keys = {"ua", "ja3", "ja4", "h2", "tcp"}
        parts = fp_str.split("|")
        stable_parts = [part for part in parts if part.split(":", 1)[0] in stable_keys]
        return "|".join(sorted(stable_parts))

    async def translate_polymorphic_headers(self, context: RequestContext) -> None:
        if getattr(context, "headers_translated", False):
            return
        context.headers_translated = True
        active_mappings = await self.store.get("active-polymorphic-mappings") or []
        if not isinstance(active_mappings, list):
            return

        for mapping in active_mappings:
            headers_map = mapping.get("headers", {})
            dev_fp_header = (headers_map.get("x-device-fingerprint") or "").lower()
            behavior_header = (headers_map.get("x-behavior-metrics") or "").lower()

            if dev_fp_header and dev_fp_header in context.headers:
                context.headers["x-device-fingerprint"] = context.headers[dev_fp_header]
                if behavior_header and behavior_header in context.headers:
                    context.headers["x-behavior-metrics"] = context.headers[behavior_header]

                client_fp = context.headers.get("x-device-fingerprint")
                if client_fp and isinstance(client_fp, str):
                    context.headers["x-device-fingerprint"] = self.decode_polymorphic_fingerprint(client_fp, mapping)
                break

    def decode_polymorphic_fingerprint(self, fp_string: str, mapping: Dict[str, Any]) -> str:
        keys_map = mapping.get("keys", {})
        if not keys_map:
            return fp_string
        reverse_keys = {v: k for k, v in keys_map.items()}
        parts = fp_string.split("|")
        mapped_parts = []
        for part in parts:
            pair = part.split(":", 1)
            if len(pair) == 2:
                orig_key = reverse_keys.get(pair[0], pair[0])
                mapped_parts.append(f"{orig_key}:{pair[1]}")
            else:
                mapped_parts.append(part)
        return "|".join(mapped_parts)

    def get_composite_device_hash(self, context: RequestContext) -> str:
        """
        Generates a composite device fingerprint hash from the request context.
        This hash is used for consistency checks and identity anchoring.

        Args:
            context (RequestContext): The request context.

        Returns:
            str: The composite fingerprint string.
        """
        builder = FingerprintBuilder()
        
        # Grab standard HTTP elements
        ua = context.headers.get("user-agent", "")
        builder.add("ua", ua)
        
        # Handle potential proxy TLS headers
        ja3 = context.headers.get("x-ja3-hash")
        if ja3:
            builder.add("ja3", ja3)
            
        # Include accept headers
        accept_lang = context.headers.get("accept-language")
        if accept_lang:
            builder.add("accept_lang", accept_lang)
            
        return str(builder)

    async def resolve_identity(self, context: RequestContext) -> Dict[str, Any]:
        """
        Resolves the identity of the client based on existing cookies or creates a new one.
        Also handles the creation of new cookies for the response.

        Args:
            context (RequestContext): The request context.

        Returns:
            Dict[str, Any]: A dictionary containing 'device_id', 'device_data', and 'new_cookie' (if any).
        """
        existing_device_id = context.cookies.get("device_id")
        current_hash = self.get_composite_device_hash(context)
        new_cookie = None
        cookie_dropping_score = 0.0

        device_id = existing_device_id
        if not device_id and context.tls_session_id:
            device_id = await self.store.get(f"tls-session:{context.tls_session_id}")

        if device_id:
            device_data = await self.store.get(f"device:{device_id}")
        else:
            device_data = None

        if not device_data:
            pending_device_id = await self.store.get(f"pending_cookie:{context.client_ip}")
            if pending_device_id and not existing_device_id:
                cookie_dropping_score = 100.0
            device_id = str(uuid.uuid4())
            new_cookie = {
                "name": "device_id",
                "value": device_id,
                "options": {
                    "httponly": True,
                    "samesite": "Strict",
                    "path": "/",
                }
            }
            context.cookies["device_id"] = device_id
            device_data = {
                "initialDeviceHash": current_hash,
                "ips": {context.client_ip},
                "lastUpdate": int(time.time() * 1000)
            }
            await self.store.set(f"device:{device_id}", device_data)
            await self.store.set(f"pending_cookie:{context.client_ip}", device_id, 120)
        else:
            if "ips" not in device_data:
                device_data["ips"] = set()
            elif isinstance(device_data["ips"], list):
                device_data["ips"] = set(device_data["ips"])
            device_data["ips"].add(context.client_ip)

        if device_id and context.tls_session_id:
            await self.store.set(f"tls-session:{context.tls_session_id}", device_id, 3600)

        return {"device_id": device_id, "device_data": device_data, "new_cookie": new_cookie, "cookie_dropping_score": cookie_dropping_score}

    async def get_behavioral_indicators(self, context: RequestContext, device_data: Dict[str, Any]) -> Dict[str, float]:
        now = int(time.time() * 1000)
        client_ip = context.client_ip
        current_fp = self.get_composite_device_hash(context)
        last_fp = device_data.get("lastFpHash")
        if last_fp and current_fp != last_fp:
            stable1 = self._extract_stable_part(last_fp)
            stable2 = self._extract_stable_part(current_fp)
            time_since_last_change = now - device_data.get("lastChangeTimestamp", 0)
            if stable1 != stable2:
                if time_since_last_change < 2000:
                    device_data["rapidChangeCount"] = device_data.get("rapidChangeCount", 0) + 1
                else:
                    device_data["rapidChangeCount"] = max(0, device_data.get("rapidChangeCount", 0) - 1)
                device_data["lastChangeTimestamp"] = now
        elif not last_fp:
            device_data["lastChangeTimestamp"] = now
        device_data["lastFpHash"] = current_fp
        if "ips" not in device_data:
            device_data["ips"] = set()
        elif isinstance(device_data["ips"], list):
            device_data["ips"] = set(device_data["ips"])
        device_data["ips"].add(client_ip)
        max_ips, free_ips = 15, 3
        history_score = min(100.0, (max(0, len(device_data["ips"]) - free_ips) / max_ips) * 100.0)
        rotation_score = min(100.0, (device_data.get("rapidChangeCount", 0) / 3.0) * 100.0)
        return {"historyScore": history_score, "rotationScore": rotation_score}

    async def get_suspicion_vector(self, context: RequestContext, suspicion_vector: Optional[Dict[str, float]] = None) -> Dict[str, float]:
        await self.translate_polymorphic_headers(context)
        if suspicion_vector is None:
            suspicion_vector = {}

        identity = await self.resolve_identity(context)
        device_data = identity["device_data"]
        device_id = identity["device_id"]
        cookie_dropping_score = identity.get("cookie_dropping_score", 0.0)

        if device_data and device_data.get("condemned"):
            suspicion_vector["honeypotScore"] = 100.0
            return suspicion_vector
    # Inconsistency score
        current_hash = self.get_composite_device_hash(context)
        similarity = FingerprintBuilder.compare(device_data.get("initialDeviceHash"), current_hash)
        inconsistency_score = max(0.0, (1.0 - similarity) * 200.0)
        if similarity < self.config.get("similarityThreshold", 0.7):
            inconsistency_score = 100.0

        behavioral_indicators = await self.get_behavioral_indicators(context, device_data)
        history_score = behavioral_indicators["historyScore"]
        rotation_score = behavioral_indicators["rotationScore"]

    # 1. Anomalies d'en-têtes
        header_anomaly = RequestUtils.get_header_anomalies(context)

        client_hints_score = RequestUtils.get_client_hints_inconsistency(context)

        tls_spoofing_score = 0.0
        ua = context.headers.get("user-agent", "")
        ja3 = context.headers.get("x-ja3-hash")
        ja4 = context.headers.get("x-ja4-hash")

        tls_fingerprint_db = {
            "e188a442b87f422c5a1e80b05399435b": ["Chrome"],
            "d8e35855049321c6042a4325c697858f": ["Chrome"],
            "a9f90958d44533748c139a5d1895b925": ["Chrome"],
            "3b5379916d2b3882253c42885956a350": ["Chrome"],
            "59822058c95c33d2d06e52f410855c8c": ["Chrome"],
            "b386946a5a586163c7c533636b45c355": ["Firefox"],
            "66236495a523c1785f8f3a105b248b11": ["Firefox"],
            "b73d470006575b5e35167a0b5a8540e2": ["Firefox"],
            "8443d7562933834333943465d52363cf": ["Firefox"],
            "b633f21d532d35967c8753c38536b4d3": ["Safari"],
            "4d7a28d5f55b359b69100a311013f03e": ["Safari", "Chrome", "Firefox"],
            "8dd3d7532873575314df23c447543001": ["Safari", "Chrome", "Firefox"]
        }

        if (ja3 or ja4) and (not ua or len(ua) < 10 or "python" in ua.lower() or "curl" in ua.lower()):
            tls_spoofing_score = 50.0
        else:
            claimed_browser = RequestUtils.parse_user_agent(ua).get("browser")
            if claimed_browser:
                if ja4 == "t13d1517h2_8daaf61527d5" and "Chrome" not in claimed_browser:
                    tls_spoofing_score = 90.0
                elif ja3 in tls_fingerprint_db:
                    expected_browsers = tls_fingerprint_db[ja3]
                    if not any(exp in claimed_browser for exp in expected_browsers):
                        tls_spoofing_score = 80.0

        # Calculate weighted average
        bot_score = RequestUtils.get_bot_score(context)
        honeypot_score = RequestUtils.get_honeypot_score(context, self.config.get("honeypot"))
        behavior_score = RequestUtils.get_behavior_score(context)
        time_inconsistency_score = RequestUtils.get_time_inconsistency_score(context)
        cross_layer_inconsistency_score = RequestUtils.get_cross_layer_inconsistency(context)
        click_variance_score = RequestUtils.get_click_variance_score(context)
        request_pattern_score = RequestUtils.get_request_pattern_score(context, device_data, self.config.get("patterns", {}))["requestPatternScore"]
        threat_intel_score = RequestUtils.get_threat_intel_score(context, self.config.get("threatIntel"))
        ip_reputation_score = await RequestUtils.get_ip_reputation_score(self.store, context.client_ip)
        subnet_score = (await RequestUtils.get_subnet_score(self.store, context.client_ip, device_id))["subnetScore"]

        tcp_anomaly = RequestUtils.get_tcp_anomaly_score(context)
        tcp_anomaly_score = tcp_anomaly.get("tcpAnomalyScore", 0.0)

        quic_anomaly = RequestUtils.get_quic_anomaly_score(context)
        quic_anomaly_score = quic_anomaly.get("quicAnomalyScore", 0.0)

        rendering_anomaly = RequestUtils.get_rendering_anomaly_score(context)
        rendering_anomaly_score = rendering_anomaly.get("renderingAnomalyScore", 0.0)


        await self.store.set(f"device:{device_id}", device_data)

        suspicion_vector.update({
            "inconsistencyScore": inconsistency_score,
            "historyScore": history_score,
            "rotationScore": rotation_score,
            "headerAnomalyScore": header_anomaly,
            "clientHintsInconsistencyScore": client_hints_score,
            "tlsSpoofingScore": tls_spoofing_score,
            "botScore": bot_score,
            "honeypotScore": honeypot_score,
            "behaviorScore": behavior_score,
            "timeInconsistencyScore": time_inconsistency_score,
            "crossLayerInconsistencyScore": cross_layer_inconsistency_score,
            "clickVarianceScore": click_variance_score,
            "requestPatternScore": request_pattern_score,
            "threatIntelScore": threat_intel_score,
            "ipReputationScore": ip_reputation_score,
            "cookieDroppingScore": cookie_dropping_score,
            "subnetScore": subnet_score,
            "quicAnomalyScore": quic_anomaly_score,
            "tcpAnomalyScore": tcp_anomaly_score,
            "renderingAnomalyScore": rendering_anomaly_score,
        })
        return suspicion_vector

    def calculate_final_score(self, suspicion_vector: Dict[str, float]) -> float:
        weights = self.config.get("weights", {})
        if not weights:
            return 0.0
        score = 0.0
        for key, weight in weights.items():
            score += suspicion_vector.get(key, 0.0) * weight
        return min(100.0, score)

    async def get_suspicion_score(self, context: RequestContext) -> float:
        await self.translate_polymorphic_headers(context)
        vector = await self.get_suspicion_vector(context)
        return self.calculate_final_score(vector)

    async def process_request(self, context: RequestContext) -> Dict[str, Any]:
        """
        Processes an incoming request, applies fingerprinting logic, calculates
        a suspicion score, and determines the appropriate action (block, challenge, redirect, next).

        Args:
            context (RequestContext): The request context.

        Returns:
            Dict[str, Any]: A dictionary describing the action to be taken and any associated data.
        """
        await self.translate_polymorphic_headers(context)
        identity = await self.resolve_identity(context)
        decision = await self._process_request_internal(context, identity)
        if identity.get("new_cookie"):
            decision["newCookieForResponse"] = identity["new_cookie"]
        return decision

    async def _process_request_internal(self, context: RequestContext, identity: Dict[str, Any]) -> Dict[str, Any]:
        """
        Internal request processing logic.
        """
        current_time = time.time()

        # 1. Nettoyage périodique du bouclier thermique local
        if current_time - self._last_prune_time > self._prune_interval:
            self._fast_path_cache = {
                k: v for k, v in self._fast_path_cache.items() if v[0] > current_time
            }
            self._last_prune_time = current_time

        # 2. Vérification du Bouclier Thermique (Short-Circuit Fast-Path)
        # Si l'IP ou le sous-réseau est actuellement dans le cache local, on applique l'action immédiatement
        client_ip = context.client_ip
        subnet = get_ip_subnet(client_ip) or "unknown-subnet"
        
        for key in (client_ip, subnet):
            if key in self._fast_path_cache:
                expiry, fast_action = self._fast_path_cache[key]
                if expiry > current_time:
                    if fast_action == "block":
                        MetricsManager.increment_counter("requests_total", {"status": "blocked"})
                        if self.dry_run:
                            return {"action": "next", "intendedAction": "block"}
                        return {"action": "block", "status": 403, "body": "Forbidden"}
                    elif fast_action == "challenge":
                        MetricsManager.increment_counter("requests_total", {"status": "challenged"})
                        # On retourne une structure simplifiée sans régénérer de nonce coûteux
                        if self.dry_run:
                            return {"action": "next", "intendedAction": "challenge"}
                        return {
                            "action": "challenge",
                            "status": 403,
                            "body": "<html><body>Suspicious activity detected. Please refresh.</body></html>"
                        }

        device_id = identity["device_id"]
        device_data = identity["device_data"]

        # Early block for condemned devices
        if device_data and device_data.get("condemned"):
            MetricsManager.increment_counter("requests_total", {"status": "blocked"})
            if self.dry_run:
                return {"action": "next", "intendedAction": "block"}
            return {"action": "block", "status": 403, "body": "Forbidden"}

        # Honeypot trap URL instant check & condemnation
        honeypot_config = self.config.get("honeypot", {})
        for trap in honeypot_config.get("trapUrls", []):
            if context.path.startswith(trap):
                device_data["condemned"] = True
                self._fast_path_cache[client_ip] = (current_time + 60.0, "block")
                await self.store.set(f"device:{device_id}", device_data)
                MetricsManager.increment_counter("requests_total", {"status": "blocked"})
                if self.dry_run:
                    return {"action": "next", "intendedAction": "block"}
                return {"action": "block", "status": 403, "body": "Forbidden"}

        # Check for challenge submission
        pow_nonce = context.query_params.get("pow_nonce")
        pow_sol_cpu = context.query_params.get("pow_solution_cpu") or context.query_params.get("pow_solution")
        pow_sol_mem = context.query_params.get("pow_solution_mem")
        pow_fp = context.query_params.get("pow_fp") or self.get_composite_device_hash(context)
        pow_type = context.query_params.get("pow_type")
        pow_solution_space = context.query_params.get("pow_solution_space")
        pow_solution_work_result = context.query_params.get("pow_solution_work_result")
        pow_problem_id = context.query_params.get("pow_problem_id")

        if pow_nonce and pow_type == "useful_work_task" and pow_solution_work_result and pow_problem_id:
            challenge_context = await self.store.get(f"secret:{pow_nonce}")
            if challenge_context:
                try:
                    work_result = json.loads(pow_solution_work_result)
                    default_path = os.path.join(os.getcwd(), "problems.config.json")
                    config_path = self.config.get("usefulWorkConfigPath") or (default_path if os.path.exists(default_path) else None)
                    pm = ProblemManager.get_instance(config_path, self.store)
                    if not pm.initialized:
                        await pm.load_problems()
                    await pm.integrate_solution(pow_problem_id, work_result)

                    await self.store.delete(f"secret:{pow_nonce}")
                    ticket = str(uuid.uuid4())
                    await self.store.set(f"ticket:{ticket}", {"ip": context.client_ip, "device_id": device_id}, 3600)
                    MetricsManager.increment_counter("challenges_solved_total")
                    return {
                        "action": "redirect",
                        "path": context.path,
                        "cookie": {
                            "name": "pow_clearance",
                            "value": ticket,
                            "options": {"httponly": True, "max_age": 3600, "path": "/"}
                        }
                    }
                except Exception as e:
                    print(f"[FingerprintEngine] Error processing useful work solution: {e}")
                    MetricsManager.increment_counter("challenges_failed_total")

        if pow_nonce and pow_type == "pospace" and pow_solution_space:
            challenge_context = await self.store.get(f"secret:{pow_nonce}")
            if challenge_context:
                is_valid = await ChallengeUtils.verify_space_pow(
                    self.store,
                    pow_nonce,
                    pow_solution_space,
                    challenge_context.get("queries", []),
                    pow_nonce + ":" + challenge_context.get("client_secret", ""),
                    challenge_context.get("client_secret", "")
                )
                if is_valid:
                    await self.store.delete(f"secret:{pow_nonce}")
                    ticket = str(uuid.uuid4())
                    await self.store.set(f"ticket:{ticket}", {"ip": context.client_ip, "device_id": device_id}, 3600)
                    MetricsManager.increment_counter("challenges_solved_total")
                    
                    clean_path = RequestUtils.clean_url_from_pow_params(context.path, context.query_params)
                    return {
                        "action": "redirect",
                        "path": clean_path,
                        "cookie": {
                            "name": "pow_clearance",
                            "value": ticket,
                            "options": {"httponly": True, "max_age": 3600, "path": "/"}
                        }
                    }
                else:
                    MetricsManager.increment_counter("challenges_failed_total")

        if pow_nonce and pow_sol_cpu:
            challenge_context = await self.store.get(f"secret:{pow_nonce}")
            if challenge_context:
                import asyncio
                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    loop = asyncio.get_event_loop()

                base_block = f"{pow_nonce}:{challenge_context.get('client_secret', '')}:{challenge_context.get('fingerprint', '')}:".encode("utf-8")
                cpu_valid = await loop.run_in_executor(
                    None, ChallengeUtils.verify_cpu_pow, base_block, challenge_context.get("cpu_target", ""), pow_sol_cpu
                )
                mem_difficulty = challenge_context.get("mem_difficulty", 0)
                mem_valid = True
                if mem_difficulty > 0 and pow_sol_mem:
                    mem_valid = await loop.run_in_executor(
                        None, ChallengeUtils.verify_memory_pow, pow_nonce, pow_sol_mem, mem_difficulty, challenge_context.get("client_secret", "")
                    )

                if cpu_valid and mem_valid:
                    await self.store.delete(f"secret:{pow_nonce}")
                    ticket = str(uuid.uuid4())
                    await self.store.set(f"ticket:{ticket}", {"ip": context.client_ip, "device_id": device_id}, 3600)
                    MetricsManager.increment_counter("challenges_solved_total")
                    return {
                        "action": "redirect",
                        "path": context.path,
                        "cookie": {
                            "name": "pow_clearance",
                            "value": ticket,
                            "options": {"httponly": True, "max_age": 3600, "path": "/"}
                        }
                    }
                else:
                    MetricsManager.increment_counter("challenges_failed_total")

        # Check existing ticket
        pow_cookie = context.cookies.get("pow_clearance")
        has_valid_ticket = False
        if pow_cookie:
            pow_secret = self.config.get("powSecret") or os.environ.get("POW_SECRET") or "fallback-dev-secret-32-chars-minimum"
            allow_roaming = self.config.get("allowCrossNetworkRoaming", False)
            current_hash = self.get_composite_device_hash(context)
            has_valid_ticket = await ChallengeUtils.is_ticket_valid(
                ip=context.client_ip,
                ticket=pow_cookie,
                device_id=device_id,
                device_hash=current_hash,
                secret=pow_secret,
                allow_cross_network_roaming=allow_roaming,
                store=self.store
            )
            if has_valid_ticket:
                MetricsManager.increment_counter("tickets_valid_total")

        suspicion_vector = await self.get_suspicion_vector(context)
        score = self.calculate_final_score(suspicion_vector)

        low_threshold = self.thresholds.get("low", 20)
        high_threshold = self.thresholds.get("high", 75)
        block_threshold = self.thresholds.get("block", 95)

        if score > low_threshold and score < block_threshold:
            # Utilise l'identifiant matériel stable pour éviter les faux positifs lors du cookie dropping
            current_hash = self.get_composite_device_hash(context)
            stable_fp_id = str(cyrb53(self._extract_stable_part(current_hash)))
            await RequestUtils.update_subnet_metrics(self.store, client_ip, stable_fp_id, score)
            MetricsManager.observe_value("suspicion_score", score, {"action": "high_score_subnet_update"})


        if score >= block_threshold:
            # Protection contre le flood : On enregistre le blocage localement pour 10 secondes
            # Évite d'interroger la DB ou de recalculer le fingerprint pour les requêtes suivantes du flood
            self._fast_path_cache[client_ip] = (current_time + 10.0, "block")
            if subnet != "unknown-subnet":
                self._fast_path_cache[subnet] = (current_time + 5.0, "block")
            MetricsManager.increment_counter("requests_total", {"status": "blocked"})
            if self.dry_run:
                return {"action": "next", "intendedAction": "block", "score": score, "vector": suspicion_vector}
            return {"action": "block", "status": 403, "body": "Forbidden"}

        high_threshold = self.thresholds.get("high", 75)
        must_rechallenge = score >= high_threshold and has_valid_ticket
        low_threshold = self.thresholds.get("low", 20)

        if (score >= low_threshold and not has_valid_ticket) or must_rechallenge:
            # --- AJOUT: Limiteur de débit (Token Bucket) ---
            rate_limit_passed = await ChallengeUtils.check_challenge_rate_limit(self.store, client_ip)
            if not rate_limit_passed:
                decision = {
                    "action": "block",
                    "status": 429,
                    "body": "Too Many Requests",
                    "score": score,
                    "vector": suspicion_vector
                }
                if self.dry_run:
                    decision["intendedAction"] = decision["action"]
                    decision["action"] = "next"
                    decision.pop("status", None)
                    decision.pop("body", None)
                return decision

            nonce = str(uuid.uuid4()).replace("-", "")[:16]
            client_secret = str(uuid.uuid4()).replace("-", "")[:16]
            suspicion_factor = (score - low_threshold) / (high_threshold - low_threshold) if high_threshold > low_threshold else 0.5
            suspicion_factor = max(0.0, min(1.0, suspicion_factor))

            should_use_useful_work = self.config.get("enableUsefulWork", False) and (
                    self.config.get("forceUsefulWork", False) or random.random() > 0.5
            )

            if should_use_useful_work:
                try:
                    default_path = os.path.join(os.getcwd(), "problems.config.json")
                    config_path = self.config.get("usefulWorkConfigPath") or (default_path if os.path.exists(default_path) else None)
                    pm = ProblemManager.get_instance(config_path, self.store)
                    if not pm.initialized:
                        await pm.load_problems()
                    work = await pm.dispatch_work(suspicion_factor)
                    if work:
                        await self.store.set(f"secret:{nonce}", {
                            "client_secret": client_secret,
                            "cpu_target": ChallengeUtils.calculate_cpu_target(suspicion_factor, self.config),
                            "mem_difficulty": int(round(max(0.0, suspicion_factor - 0.25) * 48)),
                            "fingerprint": self.get_composite_device_hash(context),
                            "original_path": context.path
                        }, 300)

                        challenge_payload = {
                            "challenge": {
                                "type": "useful_work_task",
                                "nonce": nonce,
                                "clientSecret": client_secret,
                                "usefulWorkTask": {
                                    "problemId": work["problemId"],
                                    "task": work["task"]
                                }
                            }
                        }

                        is_api = self.config.get("isApiRequest")
                        MetricsManager.increment_counter("requests_total", {"status": "challenged"})
                        if is_api and callable(is_api) and is_api(context):
                            if self.dry_run:
                                return {"action": "next", "intendedAction": "challenge", "score": score, "vector": suspicion_vector}
                            return {
                                "action": "challenge",
                                "status": 403,
                                "body": challenge_payload
                            }
                        else:
                            html = f"""<html><body>
                             <script>
                                 window.location.href = "{context.path}?pow_type=useful_work_task&pow_nonce={nonce}&pow_problem_id={work['problemId']}&pow_solution_work_result=" + encodeURIComponent(JSON.stringify({{ "solution": [], "energy": 0 }}));
                             </script>
                             </body></html>"""
                            return {
                                "action": "challenge",
                                "status": 403,
                                "body": html
                            }
                except Exception as e:
                    print(f"[FingerprintEngine] Failed to dispatch useful work, falling back to PoW: {e}")

            if self.config.get("enableProofOfSpace"):
                space_challenge = await generate_space_challenge(self.store, client_ip, nonce, suspicion_factor, context.path, self.config)
                await self.store.set(f"secret:{nonce}", {
                    "client_secret": client_secret,
                    "suspicionScore": score,
                    "queries": space_challenge["queries"],
                    "sizeMb": space_challenge["sizeMb"],
                    "fingerprint": self.get_composite_device_hash(context),
                    "original_path": context.path,
                }, self.config.get("challengeTtl", 300))
                
                is_api = self.config.get("isApiRequest")
                decision = {
                    "action": "challenge",
                    "score": score,
                    "vector": suspicion_vector,
                    "status": 403
                }
                if is_api and callable(is_api) and is_api(context):
                    decision["body"] = {
                        "challenge": {
                            "type": "pospace",
                            "nonce": nonce,
                            "clientSecret": client_secret,
                            "queries": space_challenge["queries"],
                            "sizeMb": space_challenge["sizeMb"],
                        }
                    }
                else:
                    page = generate_space_challenge_page(space_challenge, client_secret, self.config)
                    decision["body"] = page
                return decision

            cpu_target = ChallengeUtils.calculate_cpu_target(suspicion_factor, self.config)
            mem_difficulty = int(round(max(0.0, suspicion_factor - 0.25) * 48))

            self._fast_path_cache[client_ip] = (current_time + 5.0, "challenge")

            original_fingerprint = self.get_composite_device_hash(context)
            challenge_context = {
                "client_secret": client_secret,
                "cpu_target": cpu_target,
                "mem_difficulty": mem_difficulty,
                "fingerprint": original_fingerprint,
                "original_path": context.path
            }
            await self.store.set(f"secret:{nonce}", challenge_context, 300)

            html = f"""<html><body>
            <script>
                window.location.href = "{context.path}?pow_type=cpu_mem&pow_nonce={nonce}&pow_solution_cpu=0&pow_solution_mem=0";
            </script>
            </body></html>"""

            if self.dry_run:
                return {"action": "next", "intendedAction": "challenge", "score": score, "vector": suspicion_vector}
            MetricsManager.increment_counter("requests_total", {"status": "challenged"})
            return {
                "action": "challenge",
                "status": 403,
                "body": html
            }

        MetricsManager.increment_counter("requests_total", {"status": "passed"})
        MetricsManager.observe_value("suspicion_score", score, {"action": "passed"})
        return {"action": "next"}

    # --- CORE: ProblemManager for uPoW ---
class ProblemManager:
    _instance = None

    @classmethod
    def get_instance(cls, config_path: Optional[str] = None, store: Optional[Any] = None) -> "ProblemManager":
        if cls._instance is None:
            if config_path is None:
                default_path = os.path.join(os.getcwd(), "problems.config.json")
                config_path = default_path if os.path.exists(default_path) else None
            if config_path is None or store is None:
                raise RuntimeError("ProblemManager must be initialized with config_path and store.")
            cls._instance = cls(config_path, store)
        return cls._instance

    def __init__(self, config_path: str, store: Any):
        self.config_path = config_path
        self.store = store
        self.problems: List[Dict[str, Any]] = []
        self.current_problem_index = 0
        self.initialized = False

    async def load_problems(self):
        if not os.path.exists(self.config_path):
            print(f"[ProblemManager] Problem config file not found: {self.config_path}")
            return
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                problems_from_file = json.load(f)
        except Exception as e:
            print(f"[ProblemManager] Failed to read/parse problem config file: {e}")
            return

        for problem in problems_from_file:
            store_key = f"problem-state:{problem['id']}"
            stored_state = await self.store.get(store_key)

            if stored_state is None:
                stored_state = problem.get("state", {})
                await self.store.set(store_key, stored_state)
            problem["state"] = stored_state

            # Resolve dynamic initializers
            payload = problem.get("payload", {})
            if isinstance(payload, dict):
                for key, value in payload.items():
                    if isinstance(value, dict) and "$init" in value:
                        init_type = value["$init"]
                        params = value.get("params", {})
                        if init_type == "generate:randomPoints":
                            count = params.get("count", 0)
                            bounds = params.get("bounds", {"x": 1000, "y": 1000})
                            points = []
                            for _ in range(count):
                                points.append({
                                    "x": random.random() * bounds.get("x", 1000),
                                    "y": random.random() * bounds.get("y", 1000)
                                })
                            payload[key] = points
                        elif init_type == "generate:randomAssets":
                            count = params.get("count", 0)
                            assets = []
                            for i in range(count):
                                assets.append({
                                    "name": f"Asset {i + 1}",
                                    "expectedReturn": random.random() * 0.2,
                                    "volatility": 0.1 + random.random() * 0.3
                                })
                            payload[key] = assets
            self.problems.append(problem)
        self.initialized = True

    async def dispatch_work(self, suspicion_factor: float) -> Optional[Dict[str, Any]]:
        if not self.problems:
            return None
        problem = self.problems[self.current_problem_index]
        self.current_problem_index = (self.current_problem_index + 1) % len(self.problems)

        work_unit = problem.get("workUnit", {})
        task_type = work_unit.get("type")
        task = {"type": task_type}
        scaling_factor = work_unit.get("scalingFactor")

        if task_type == "simulated_annealing_iterations":
            base_iterations = work_unit.get("baseIterations", 15000)
            if scaling_factor:
                task["iterations"] = int(math.floor(base_iterations * math.pow(scaling_factor, suspicion_factor)))
            else:
                task["iterations"] = int(math.floor(base_iterations * (0.5 + suspicion_factor)))
            task["payload"] = problem.get("payload", {})
            task["initialSolution"] = problem.get("state", {}).get("bestSolution")
        elif task_type == "genetic_algorithm_generations":
            base_generations = max(50, work_unit.get("baseGenerations", 0))
            if scaling_factor:
                task["generations"] = int(math.floor(base_generations * math.pow(scaling_factor, suspicion_factor)))
            else:
                task["generations"] = int(math.floor(base_generations * (0.5 + suspicion_factor)))
            task["payload"] = problem.get("payload", {})
            task["initialPopulation"] = problem.get("state", {}).get("population")
        elif task_type == "multi_objective_genetic_algorithm":
            base_generations_multi = max(30, work_unit.get("baseGenerations", 0))
            if scaling_factor:
                task["generations"] = int(math.floor(base_generations_multi * math.pow(scaling_factor, suspicion_factor)))
            else:
                task["generations"] = int(math.floor(base_generations_multi * (0.5 + suspicion_factor)))
            task["payload"] = problem.get("payload", {})
            task["initialFront"] = problem.get("state", {}).get("paretoFront")
            task["solverName"] = work_unit.get("solverName")
        else:
            print(f"[ProblemManager] Unknown useful work type: {task_type}")
            return None

        return {"problemId": problem["id"], "task": task}

    async def integrate_solution(self, problem_id: str, solution_data: Dict[str, Any]) -> None:
        problem = None
        for p in self.problems:
            if p["id"] == problem_id:
                problem = p
                break
        if not problem:
            return

        state_changed = False
        store_key = f"problem-state:{problem['id']}"
        work_unit_type = problem.get("workUnit", {}).get("type")

        if work_unit_type == "simulated_annealing_iterations":
            if "solution" in solution_data and "energy" in solution_data:
                score_function_name = problem.get("workUnit", {}).get("scoreFunction")
                recalculated_energy = float("inf")
                if score_function_name == "facility.calculateEnergy":
                    recalculated_energy = OptimizationOperators.evaluate_facility_location(
                        solution_data["solution"], problem.get("payload", {})
                    )
                else:
                    recalculated_energy = float(solution_data["energy"])

                current_best = float(problem.get("state", {}).get("bestEnergy", float("inf")))
                if recalculated_energy < current_best:
                    problem["state"]["bestSolution"] = solution_data["solution"]
                    problem["state"]["bestEnergy"] = recalculated_energy
                    problem["state"]["lastUpdate"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    state_changed = True
                    print(f"[ProblemManager] New best solution for {problem_id}: {recalculated_energy}")
        elif work_unit_type == "genetic_algorithm_generations":
            if "population" in solution_data and isinstance(solution_data["population"], list):
                problem["state"]["population"] = solution_data["population"]
                problem["state"]["lastUpdate"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                state_changed = True
        elif work_unit_type == "multi_objective_genetic_algorithm":
            if "paretoFront" in solution_data and isinstance(solution_data["paretoFront"], list):
                state_changed = await self._integrate_pareto_front(problem, solution_data["paretoFront"])

        if state_changed:
            await self.store.set(store_key, problem["state"])

    async def _integrate_pareto_front(self, problem: Dict[str, Any], new_front: List[Dict[str, Any]]) -> bool:
        current_front = problem.get("state", {}).get("paretoFront", [])
        if new_front and json.dumps(new_front, sort_keys=True) != json.dumps(current_front, sort_keys=True):
            problem["state"]["paretoFront"] = new_front
            problem["state"]["lastUpdate"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            print(f"[ProblemManager] New Pareto front for {problem['id']} with {len(new_front)} solutions.")
            return True
        return False

# --- CORE: Optimization & AutoTuning ---
class Optimization:
    @staticmethod
    def genetic_algorithm_multi_objective(
        create_individual: Callable[[], Any],
        fitness_function: Callable[[Any], List[float]],
        crossover: Callable[[Any, Any], Any],
        mutate: Callable[[Any], Any],
        options: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        options = options or {}
        generations = options.get("generations", 50)
        population_size = options.get("populationSize", 50)
        mutation_rate = options.get("mutationRate", 0.1)

        population = []
        for _ in range(population_size):
            ind = create_individual()
            population.append({
                "individual": ind,
                "objectives": fitness_function(ind)
            })

        for _ in range(generations):
            offspring = []
            for _ in range(population_size):
                p1 = random.choice(population)
                p2 = random.choice(population)
                child_ind = crossover(p1["individual"], p2["individual"])
                if random.random() < mutation_rate:
                    child_ind = mutate(child_ind)
                offspring.append({
                    "individual": child_ind,
                    "objectives": fitness_function(child_ind)
                })

            combined = population + offspring
            fronts = Optimization.non_dominated_sort(combined)

            new_pop = []
            for front in fronts:
                if len(new_pop) + len(front) <= population_size:
                    new_pop.extend(front)
                else:
                    Optimization.calculate_crowding_distance(front)
                    front.sort(key=lambda x: x.get("crowdingDistance", 0.0), reverse=True)
                    remaining = population_size - len(new_pop)
                    new_pop.extend(front[:remaining])
                    break
            population = new_pop

        final_fronts = Optimization.non_dominated_sort(population)
        best_front = final_fronts[0] if final_fronts else []

        unique_solutions = []
        seen = set()
        for p in best_front:
            key = json.dumps(p["objectives"])
            if key not in seen:
                seen.add(key)
                unique_solutions.append({
                    "solution": p["individual"],
                    "objectives": p["objectives"]
                })
        return unique_solutions

    @staticmethod
    def non_dominated_sort(population: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
        fronts = [[]]
        n = len(population)
        for i in range(n):
            p1 = population[i]
            p1["dominationCount"] = 0
            p1["dominatedSolutions"] = []
            for j in range(n):
                if i == j:
                    continue
                p2 = population[j]
                if Optimization.pareto_dominates(p1["objectives"], p2["objectives"]):
                    p1["dominatedSolutions"].append(j)
                elif Optimization.pareto_dominates(p2["objectives"], p1["objectives"]):
                    p1["dominationCount"] += 1
            if p1["dominationCount"] == 0:
                p1["rank"] = 0
                fronts[0].append(p1)

        i = 0
        while len(fronts[i]) > 0:
            next_front = []
            for p1 in fronts[i]:
                for p2_idx in p1["dominatedSolutions"]:
                    p2 = population[p2_idx]
                    p2["dominationCount"] -= 1
                    if p2["dominationCount"] == 0:
                        p2["rank"] = i + 1
                        next_front.append(p2)
            i += 1
            if next_front:
                fronts.append(next_front)
            else:
                break
        return [f for f in fronts if f]

    @staticmethod
    def pareto_dominates(obj_a: List[float], obj_b: List[float]) -> bool:
        better = False
        for a, b in zip(obj_a, obj_b):
            if a > b:
                return False
            if a < b:
                better = True
        return better

    @staticmethod
    def calculate_crowding_distance(front: List[Dict[str, Any]]) -> None:
        if not front:
            return
        n = len(front)
        num_obj = len(front[0]["objectives"])
        for p in front:
            p["crowdingDistance"] = 0.0

        for i in range(num_obj):
            front.sort(key=lambda x: x["objectives"][i])
            front[0]["crowdingDistance"] = float("inf")
            front[-1]["crowdingDistance"] = float("inf")
            min_val = front[0]["objectives"][i]
            max_val = front[-1]["objectives"][i]
            if max_val == min_val:
                continue
            for j in range(1, n - 1):
                front[j]["crowdingDistance"] += (front[j+1]["objectives"][i] - front[j-1]["objectives"][i]) / (max_val - min_val)

    @staticmethod
    def benford_test(numbers: List[float]) -> float:
        if len(numbers) < 10:
            return 0.0
        leading_digits = []
        for n in numbers:
            s = str(n).lstrip("0.")
            if s:
                leading_digits.append(s[0])
        leading_digits = [d for d in leading_digits if "1" <= d <= "9"]
        if len(leading_digits) < 10:
            return 0.0
        counts = {str(i): 0 for i in range(1, 10)}
        for d in leading_digits:
            counts[d] += 1
        benford = {1: 30.1, 2: 17.6, 3: 12.5, 4: 9.7, 5: 7.9, 6: 6.7, 7: 5.8, 8: 5.1, 9: 4.6}
        deviation = 0.0
        for i in range(1, 10):
            obs = (counts[str(i)] / len(leading_digits)) * 100.0
            exp = benford[i]
            deviation += (obs - exp) ** 2
        return math.sqrt(deviation) / 50.0

class OptimizationOperators:
    @staticmethod
    def create_full_security_config_evaluator(traffic_data: List[Dict[str, Any]]) -> Callable[[Dict[str, Any]], List[float]]:
        def evaluator(config: Dict[str, Any]) -> List[float]:
            false_positives = 0.0
            false_negatives = 0.0
            total_humans = 0.0
            total_bots = 0.0

            def calculate_score(log: Dict[str, Any]) -> float:
                score = 0.0
                for k, w in config.get("weights", {}).items():
                    score += log.get("vector", {}).get(k, 0) * w
                return score

            confidence_weights = {
                "request_passed": 0.7,
                "challenge_issued": 1.0,
                "request_blocked": 1.0,
                "challenge_solved": 1.5,
                "trap_triggered": 2.0,
            }

            for log in traffic_data:
                confidence = confidence_weights.get(log.get("type", ""), 1.0)
                is_likely_bot = log.get("type") in ("challenge_issued", "request_blocked", "trap_triggered")
                is_likely_human = log.get("type") in ("request_passed", "challenge_solved")

                if is_likely_bot:
                    total_bots += confidence
                    score = calculate_score(log)
                    if score < config.get("thresholds", {}).get("low", 20):
                        false_negatives += confidence
                elif is_likely_human:
                    total_humans += confidence
                    score = calculate_score(log)
                    if score >= config.get("thresholds", {}).get("low", 20):
                        false_positives += confidence

            fpr = false_positives / total_humans if total_humans > 0 else 0.0
            fnr = false_negatives / total_bots if total_bots > 0 else 0.0
            return [fpr, fnr]
        return evaluator

    @staticmethod
    def solve_full_security_tuning(traffic_data: List[Dict[str, Any]], options: Optional[Dict[str, Any]] = None, current_config: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        fitness_fn = OptimizationOperators.create_full_security_config_evaluator(traffic_data)

        def create_individual() -> Dict[str, Any]:
            if current_config:
                ind = {
                    "thresholds": {},
                    "weights": {},
                    "patterns": {}
                }
                for section in ("thresholds", "weights", "patterns"):
                    if section in current_config:
                        for k, v in current_config[section].items():
                            if isinstance(v, (int, float)) and k != "honeypotScore":
                                ind[section][k] = v * (1.0 + random.uniform(-0.25, 0.25))
                            else:
                                ind[section][k] = v
                if "low" in ind["thresholds"] and "medium" in ind["thresholds"] and "high" in ind["thresholds"]:
                    ind["thresholds"]["low"] = max(10.0, min(35.0, ind["thresholds"]["low"]))
                    ind["thresholds"]["medium"] = max(ind["thresholds"]["low"] + 5.0, min(70.0, ind["thresholds"]["medium"]))
                    ind["thresholds"]["high"] = max(ind["thresholds"]["medium"] + 5.0, min(90.0, ind["thresholds"]["high"]))
                return ind

            return {
                "thresholds": {
                    "low": 15 + random.random() * 20,
                    "medium": 40 + random.random() * 25,
                    "high": 70 + random.random() * 20,
                },
                "weights": {
                    "historyScore": random.random(),
                    "rotationScore": random.random(),
                    "headerAnomalyScore": random.random(),
                    "requestPatternScore": 0.5 + random.random(),
                    "inconsistencyScore": random.random(),
                    "honeypotScore": 1.0,
                    "behaviorScore": random.random(),
                    "crossLayerInconsistencyScore": random.random(),
                    "timeInconsistencyScore": random.random(),
                    "tlsSpoofingScore": random.random(),
                    "botScore": random.random(),
                    "cookieDroppingScore": random.random(),
                    "threatIntelScore": random.random(),
                },
                "patterns": {
                    "velocityThreshold": 100 + random.random() * 400,
                    "burstThreshold": 300 + random.random() * 700,
                    "scrapeThreshold": 500 + random.random() * 1000,
                    "regularityThreshold": 50 + random.random() * 200,
                    "decayFactor": 0.85 + random.random() * 0.14,
                    "inactivityReset": 15000 + random.random() * 45000,
                }
            }

        def crossover(c1: Dict[str, Any], c2: Dict[str, Any]) -> Dict[str, Any]:
            child = copy.deepcopy(c1)
            for section in ("thresholds", "weights", "patterns"):
                for k in child[section]:
                    if k != "honeypotScore":
                        child[section][k] = (c1[section][k] + c2[section][k]) / 2.0
            return child

        def mutate(c: Dict[str, Any]) -> Dict[str, Any]:
            new_config = copy.deepcopy(c)
            sections = [
                {"name": "patterns", "weight": 0.5},
                {"name": "weights", "weight": 0.35},
                {"name": "thresholds", "weight": 0.15}
            ]
            rand = random.random()
            cumulative = 0.0
            section_to_mutate = "patterns"
            for section in sections:
                cumulative += section["weight"]
                if rand < cumulative:
                    section_to_mutate = section["name"]
                    break
            keys = list(new_config[section_to_mutate].keys())
            key_to_mutate = random.choice(keys)
            if key_to_mutate == "honeypotScore":
                return new_config
            
            mutation_amount = (random.random() - 0.5) * 0.4
            new_config[section_to_mutate][key_to_mutate] *= (1.0 + mutation_amount)

            if section_to_mutate == "weights":
                new_config[section_to_mutate][key_to_mutate] = max(0.0, min(1.5, new_config[section_to_mutate][key_to_mutate]))

            # Drift constraint relative to current_config
            if current_config and section_to_mutate in current_config and key_to_mutate in current_config[section_to_mutate]:
                orig_val = current_config[section_to_mutate][key_to_mutate]
                if isinstance(orig_val, (int, float)):
                    min_val = orig_val * 0.70
                    max_val = orig_val * 1.30
                    new_config[section_to_mutate][key_to_mutate] = max(min_val, min(max_val, new_config[section_to_mutate][key_to_mutate]))
            
            return new_config

        return Optimization.genetic_algorithm_multi_objective(
            create_individual, fitness_fn, crossover, mutate, options
        )


    @staticmethod
    def evaluate_facility_location(facilities: List[Dict[str, float]], payload: Dict[str, Any]) -> float:
        """
        Evaluates the connection cost + fixed cost for a given set of facilities.
        Used by the server to safely verify uPoW results.
        """
        customers = payload.get("customers", [])
        fixed_cost = payload.get("options", {}).get("fixedCostPerFacility", 0.0)
        total_connection_cost = 0.0

        for customer in customers:
            min_dist_sq = float("inf")
            for facility in facilities:
                dx = customer["x"] - facility["x"]
                dy = customer["y"] - facility["y"]
                d_sq = dx * dx + dy * dy
                if d_sq < min_dist_sq:
                    min_dist_sq = d_sq
            total_connection_cost += math.sqrt(min_dist_sq)

        return total_connection_cost + len(facilities) * fixed_cost

    @staticmethod
    def solve_facility_location(
            customers: List[Dict[str, float]],
            num_facilities: int,
            bounds: Dict[str, float],
            options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Complete Simulated Annealing solver for the Facility Location Problem.
        Matches client-side JS implementation.
        """
        options = options or {}
        fixed_cost = options.get("fixedCostPerFacility", 0.0)
        initial_temp = options.get("initialTemperature", 100000.0)
        cooling_rate = options.get("coolingRate", 0.999)
        max_iterations = options.get("maxIterations", 5000) # Seuil raisonnable de rapidité

        def evaluator(facilities: List[Dict[str, float]]) -> float:
            total_connection_cost = 0.0
            for customer in customers:
                min_dist_sq = float("inf")
                for facility in facilities:
                    dx = customer["x"] - facility["x"]
                    dy = customer["y"] - facility["y"]
                    d_sq = dx * dx + dy * dy
                    if d_sq < min_dist_sq:
                        min_dist_sq = d_sq
                total_connection_cost += math.sqrt(min_dist_sq)
            return total_connection_cost + len(facilities) * fixed_cost

        def neighbor(facilities: List[Dict[str, float]]) -> List[Dict[str, float]]:
            new_facilities = copy.deepcopy(facilities)
            i = random.randint(0, num_facilities - 1)
            move_x = (random.random() - 0.5) * (bounds["maxX"] - bounds["minX"]) * 0.1
            move_y = (random.random() - 0.5) * (bounds["maxY"] - bounds["minY"]) * 0.1
            new_facilities[i]["x"] = max(bounds["minX"], min(bounds["maxX"], new_facilities[i]["x"] + move_x))
            new_facilities[i]["y"] = max(bounds["minY"], min(bounds["maxY"], new_facilities[i]["y"] + move_y))
            return new_facilities

        current_solution = [
            {
                "x": bounds["minX"] + random.random() * (bounds["maxX"] - bounds["minX"]),
                "y": bounds["minY"] + random.random() * (bounds["maxY"] - bounds["minY"])
            }
            for _ in range(num_facilities)
        ]

        current_energy = evaluator(current_solution)
        best_solution = current_solution
        best_energy = current_energy
        temperature = initial_temp

        for _ in range(max_iterations):
            new_sol = neighbor(current_solution)
            new_energy = evaluator(new_sol)

            try:
                acceptance = math.exp((current_energy - new_energy) / temperature)
            except OverflowError:
                acceptance = 0.0 if new_energy > current_energy else 1.0

            if new_energy < current_energy or random.random() < acceptance:
                current_solution = new_sol
                current_energy = new_energy

            if current_energy < best_energy:
                best_solution = current_solution
                best_energy = current_energy

            temperature *= cooling_rate

        return {"solution": best_solution, "energy": best_energy}

class AutoTuner:
    _last_best_solution: Optional[Dict[str, Any]] = None

    def __init__(self, security_config: Dict[str, Any], traffic_data: List[Dict[str, Any]], options: Optional[Dict[str, Any]] = None):
        """
        Initializes the AutoTuner with security configuration, traffic data, and pruning options.

        Args:
            security_config (Dict[str, Any]): The live security configuration dictionary to be optimized.
            traffic_data (List[Dict[str, Any]]): The list of collected traffic data logs.
            options (Optional[Dict[str, Any]]): Configuration options including:
                - minDataPoints (int, default 200): Minimum required data points to start tuning.
                - maxDataPoints (int, default 10000): Maximum data points retained in memory.
                - maxAgeMs (Optional[int], default None): Maximum age of logs in milliseconds.
                - clearAfterTuning (bool, default False): If True, clear traffic data after tuning.
                - onCleanup (Optional[Callable], default None): Callback function for processed/pruned logs.
        """
        self.security_config = security_config
        self.traffic_data = traffic_data
        options = options or {}
        self.min_data_points = options.get("minDataPoints", 200)
        self.max_data_points = options.get("maxDataPoints", 10000)
        self.clear_after_tuning = options.get("clearAfterTuning", False)
        self.options = options

    def prune_traffic_data(self) -> None:
        now = int(time.time() * 1000)
        removed = []

        # 1. Expire par temps
        max_age_ms = self.options.get("maxAgeMs")
        if max_age_ms and max_age_ms > 0:
            threshold = now - max_age_ms
            retained = []
            for log in self.traffic_data:
                log_ts = log.get("timestamp") or log.get("requestTimestamp") or now
                if log_ts < threshold:
                    removed.append(log)
                else:
                    retained.append(log)
            self.traffic_data[:] = retained

        # 2. Politique de taille maximale (conserver les plus récents)
        if self.max_data_points > 0 and len(self.traffic_data) > self.max_data_points:
            overflow_count = len(self.traffic_data) - self.max_data_points
            removed.extend(self.traffic_data[:overflow_count])
            self.traffic_data[:] = self.traffic_data[overflow_count:]

        # 3. Invocation du callback
        on_cleanup = self.options.get("onCleanup")
        if on_cleanup and callable(on_cleanup) and removed:
            try:
                on_cleanup(removed)
            except Exception as e:
                print(f"[AutoTuning] Error in onCleanup callback: {e}")

    def run_optimization_cycle(self) -> None:
        self.prune_traffic_data()

        sanitized_data = sanitize_traffic_data(self.traffic_data)

        high_confidence_logs = len([
            log for log in sanitized_data 
            if log.get("type") in ("challenge_solved", "trap_triggered")
        ])
        high_confidence_ratio = high_confidence_logs / len(sanitized_data) if sanitized_data else 0.0
        min_confidence_ratio = 0.05
        min_high_confidence_count = 10

        has_enough_signal = high_confidence_ratio >= min_confidence_ratio or high_confidence_logs >= min_high_confidence_count

        if len(sanitized_data) < self.min_data_points or not has_enough_signal:
            if len(sanitized_data) < self.min_data_points:
                print(f"[AutoTuning] Reporté : {len(sanitized_data)}/{self.min_data_points} points de données.")
            else:
                print(f"[AutoTuning] Reporté : Signaux de confiance insuffisants (Ratio: {high_confidence_ratio*100:.2f}% < {min_confidence_ratio*100:.2f}% et absolu: {high_confidence_logs} < {min_high_confidence_count}).")
            return

        if len(self.traffic_data) > self.max_data_points:
            print(f"[AutoTuning] Le journal de trafic a atteint {len(self.traffic_data)} entrées (max: {self.max_data_points}). Troncation.")
            self.traffic_data[:] = self.traffic_data[len(self.traffic_data) - self.max_data_points:]

        print(f"[AutoTuning] Démarrage du cycle d'optimisation complet avec {len(sanitized_data)} points de données assainis.")

        pareto_front = OptimizationOperators.solve_full_security_tuning(sanitized_data, options=None, current_config=self.security_config)

        if not pareto_front:
            print("[AutoTuning] L'optimisation n'a retourné aucune solution.")
            return

        def is_valid_security_config(config: Dict[str, Any]) -> bool:
            if not config or "weights" not in config or "thresholds" not in config:
                return False
            w = config["weights"]
            t = config["thresholds"]
            active_weights_sum = (
                w.get("inconsistencyScore", 0.0) +
                w.get("tlsSpoofingScore", 0.0) +
                w.get("requestPatternScore", 0.0) +
                w.get("behaviorScore", 0.0) +
                w.get("botScore", 0.0)
            )
            if active_weights_sum < 1.5:
                return False
            if t.get("low", 0.0) < 10 or t.get("low", 0.0) > 35:
                return False
            if t.get("medium", 0.0) < t.get("low", 0.0) + 5 or t.get("medium", 0.0) > 70:
                return False
            if t.get("high", 0.0) < t.get("medium", 0.0) + 5 or t.get("high", 0.0) > 90:
                return False
            if t.get("block", 0.0) < t.get("high", 0.0) + 5 or t.get("block", 0.0) > 99:
                return False
            return True

        filtered_front = [p for p in pareto_front if is_valid_security_config(p["solution"])]
        if not filtered_front:
            print("[AutoTuning] Toutes les solutions du front de Pareto ont été rejetées par les règles de gardiennage. Fallback.")
            filtered_front = pareto_front

        # Selecting most balanced solution
        best_solution = filtered_front[0]
        min_distance = math.sqrt(best_solution["objectives"][0]**2 + best_solution["objectives"][1]**2)

        for candidate in filtered_front[1:]:
            dist = math.sqrt(candidate["objectives"][0]**2 + candidate["objectives"][1]**2)
            if dist < min_distance:
                min_distance = dist
                best_solution = candidate

        new_config = best_solution["solution"]
        traffic_confidence = min(1.5, max(0.3, high_confidence_ratio * 4.0))

        def apply_inertial_update(current_config: Dict[str, Any], target_config: Dict[str, Any], type_str: str, confidence_factor: float = 1.0):
            if not current_config or not target_config:
                return
            base_learning_rate = 0.15
            learning_rate = max(0.02, min(0.40, base_learning_rate * confidence_factor))

            for key in current_config:
                if key in target_config and isinstance(current_config[key], (int, float)):
                    current_val = float(current_config[key])
                    target_val = float(target_config[key])

                    updated_val = current_val + (target_val - current_val) * learning_rate

                    if type_str == "weights":
                        updated_val = max(0.05, min(1.8, updated_val))
                    elif type_str == "patterns":
                        if key == "benfordThreshold":
                            updated_val = max(0.05, min(0.30, updated_val))
                        elif key == "decayFactor":
                            updated_val = max(0.70, min(0.98, updated_val))
                        elif key == "minSamples":
                            updated_val = max(3, min(15, int(round(updated_val))))
                        elif key == "historySize":
                            updated_val = max(5, min(30, int(round(updated_val))))
                        elif key.endswith("Threshold"):
                            updated_val = max(50, min(3000, int(round(updated_val))))

                    current_config[key] = updated_val

            if type_str == "thresholds":
                low = max(10, min(35, current_config["low"]))
                medium = max(low + 8, min(65, current_config["medium"]))
                high = max(medium + 8, min(85, current_config["high"]))
                block = max(high + 8, min(98, current_config["block"]))

                current_config["low"] = int(round(low))
                current_config["medium"] = int(round(medium))
                current_config["high"] = int(round(high))
                current_config["block"] = int(round(block))

        apply_inertial_update(self.security_config["thresholds"], new_config["thresholds"], "thresholds", traffic_confidence)
        apply_inertial_update(self.security_config["weights"], new_config["weights"], "weights", traffic_confidence)
        apply_inertial_update(self.security_config["patterns"], new_config["patterns"], "patterns", traffic_confidence)

        AutoTuner._last_best_solution = best_solution

        print("[AutoTuning] Nouvelle configuration de sécurité optimisée appliquée.")
        print(f"[AutoTuning] Objectifs atteints : {json.dumps({'falsePositiveRate': round(best_solution['objectives'][0], 4), 'falseNegativeRate': round(best_solution['objectives'][1], 4)})}")
        print(f"[AutoTuning] Nouveaux seuils : {json.dumps(self.security_config['thresholds'])}")
        print(f"[AutoTuning] Nouveaux poids : {json.dumps(self.security_config['weights'])}")
        print(f"[AutoTuning] Nouveaux patterns : {json.dumps(self.security_config['patterns'])}")

        if self.clear_after_tuning:
            cleared = list(self.traffic_data)
            self.traffic_data.clear()
            on_cleanup = self.options.get("onCleanup")
            if on_cleanup and callable(on_cleanup) and cleared:
                try:
                    on_cleanup(cleared)
                except Exception as e:
                    print(f"[AutoTuning] Error in onCleanup callback after clearing: {e}")
            print(f"[AutoTuning] Explicitly cleared {len(cleared)} processed traffic data points.")

    @staticmethod
    def get_best_tuning_solution() -> Optional[Dict[str, Any]]:
        return AutoTuner._last_best_solution

    @staticmethod
    def reset_best_tuning_solution() -> None:
        AutoTuner._last_best_solution = None


# --- UNIVERSAL MIDDLEWARES: ASGI & WSGI ---

class ASGIFingerprintMiddleware:
    """
    Universal ASGI 3.0 middleware. Works with FastAPI, Starlette, Quart, Sanic, etc.
    It intercepts incoming ASGI requests, applies fingerprinting and security checks,
    and modifies the response or passes control to the next middleware/application.

    Args:
        app: The ASGI application to wrap.
        security_config (Dict[str, Any]): The security configuration for the fingerprint engine.
        store (Optional[Any]): An optional data store instance (defaults to InMemoryStore).

    Requires no framework-specific dependencies.
    """
    def __init__(self, app, security_config: Dict[str, Any], store: Optional[Any] = None):
        self.app = app
        self.store = store or InMemoryStore()
        self.engine = FingerprintEngine(security_config, self.store)

    async def __call__(self, scope, receive, send):
        """
        The ASGI callable method.

        Args:
            scope (Dict[str, Any]): The ASGI scope dictionary.
            receive (Callable): The ASGI receive channel.
            send (Callable): The ASGI send channel.
        """
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        # Extract headers (lowercased for consistency)
        headers = {}
        for k, v in scope.get("headers", []):
            headers[k.decode("latin1").lower()] = v.decode("latin1")

        # Resolve IP with X-Forwarded-For fallback
        client_ip = "127.0.0.1"
        if scope.get("client"):
            client_ip = scope["client"][0]
        xff = headers.get("x-forwarded-for")
        if xff:
            client_ip = xff.split(",")[0].strip()

        # Parse query params
        from urllib.parse import parse_qs
        query_string = scope.get("query_string", b"").decode("latin1")
        query_params = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(query_string).items()}

        # Parse cookies
        from http.cookies import SimpleCookie
        cookie_header = headers.get("cookie", "")
        cookies = {}
        if cookie_header:
            try:
                c = SimpleCookie()
                c.load(cookie_header)
                cookies = {k: v.value for k, v in c.items()}
            except Exception:
                pass

        context = RequestContext(
            client_ip=client_ip,
            path=scope.get("path", "/"),
            headers=headers,
            query_params=query_params,
            cookies=cookies,
            http_version=scope.get("http_version", "1.1")
        )

        decision = await self.engine.process_request(context)

        if decision["action"] == "block":
            await self._send_response(send, decision.get("status", 403), [
                (b"content-type", b"text/plain")
            ], decision.get("body", "Forbidden").encode("utf-8"))
            return

        if decision["action"] == "challenge":
            await self._send_response(send, decision.get("status", 403), [
                (b"content-type", b"text/html; charset=utf-8")
            ], decision.get("body", "").encode("utf-8"))
            return

        if decision["action"] == "redirect":
            res_headers = [(b"location", decision["path"].encode("utf-8"))]
            if "cookie" in decision:
                c = decision["cookie"]
                cookie_val = f"{c['name']}={c['value']}; Path={c['options'].get('path', '/')}"
                if c["options"].get("httponly"):
                    cookie_val += "; HttpOnly"
                if c["options"].get("secure"):
                    cookie_val += "; Secure"
                if "max_age" in c["options"]:
                    cookie_val += f"; Max-Age={c['options']['max_age']}"
                res_headers.append((b"set-cookie", cookie_val.encode("utf-8")))

            await self._send_response(send, 302, res_headers, b"")
            return

        # Inject new tracking cookies if resolved
        new_cookie = decision.get("newCookieForResponse")

        if new_cookie:
            async def custom_send(event):
                if event["type"] == "http.response.start":
                    c = new_cookie
                    cookie_val = f"{c['name']}={c['value']}; Path={c['options'].get('path', '/')}"
                    if c["options"].get("httponly"):
                        cookie_val += "; HttpOnly"
                    if c["options"].get("secure"):
                        cookie_val += "; Secure"
                    if "max_age" in c["options"]:
                        cookie_val += f"; Max-Age={c['options']['max_age']}"
                    event["headers"].append((b"set-cookie", cookie_val.encode("utf-8")))
                await send(event)
            await self.app(scope, receive, custom_send)
        else:
            await self.app(scope, receive, send)

    async def _send_response(self, send, status: int, headers: List[tuple], body: bytes):
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": headers
        })
        await send({
            "type": "http.response.body",
            "body": body,
            "more_body": False
        })


class WSGIFingerprintMiddleware:
    """
    Universal WSGI 1.0 middleware. Works with Flask, Django, Bottle, etc.
    It intercepts incoming WSGI requests, applies fingerprinting and security checks,
    and modifies the response or passes control to the next middleware/application.
    This middleware handles the necessary asynchronous bridging internally for WSGI applications.

    Args:
        app: The WSGI application to wrap.
        security_config (Dict[str, Any]): The security configuration for the fingerprint engine.
        store (Optional[Any]): An optional data store instance (defaults to InMemoryStore).
    Handles the async bridge safely under the hood.
    """
    def __init__(self, app, security_config: Dict[str, Any], store: Optional[Any] = None):
        self.app = app
        self.store = store or InMemoryStore()
        self.engine = FingerprintEngine(security_config, self.store)

    def __call__(self, environ, start_response):
        """
        The WSGI callable method.

        Args:
            environ (Dict[str, Any]): The WSGI environment dictionary.
            start_response (Callable): The WSGI start_response callable.

        Returns:
            Iterable[bytes]: An iterable of response body bytes.
        """
        # Extract remote IP
        client_ip = environ.get("HTTP_X_FORWARDED_FOR")
        if client_ip:
            client_ip = client_ip.split(",")[0].strip()
        else:
            client_ip = environ.get("REMOTE_ADDR", "127.0.0.1")

        # Extract headers
        headers = {}
        for k, v in environ.items():
            if k.startswith("HTTP_"):
                headers[k[5:].replace("_", "-").lower()] = v
            elif k in ("CONTENT_TYPE", "CONTENT_LENGTH"):
                headers[k.replace("_", "-").lower()] = v

        # Extract query params
        from urllib.parse import parse_qs
        query_string = environ.get("QUERY_STRING", "")
        query_params = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(query_string).items()}

        # Parse cookies
        from http.cookies import SimpleCookie
        cookie_header = headers.get("cookie", "")
        cookies = {}
        if cookie_header:
            try:
                c = SimpleCookie()
                c.load(cookie_header)
                cookies = {k: v.value for k, v in c.items()}
            except Exception:
                pass

        context = RequestContext(
            client_ip=client_ip,
            path=environ.get("PATH_INFO", "/"),
            headers=headers,
            query_params=query_params,
            cookies=cookies,
            http_version=environ.get("SERVER_PROTOCOL", "HTTP/1.1")
        )

        # Safe event loop bridge
        import asyncio
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        decision = loop.run_until_complete(self.engine.process_request(context))

        if decision["action"] == "block":
            start_response(f"{decision.get('status', 403)} Forbidden", [("Content-Type", "text/plain")])
            return [decision.get("body", "Forbidden").encode("utf-8")]

        if decision["action"] == "challenge":
            start_response(f"{decision.get('status', 403)} Forbidden", [("Content-Type", "text/html; charset=utf-8")])
            return [decision.get("body", "").encode("utf-8")]

        if decision["action"] == "redirect":
            res_headers = [("Location", decision["path"])]
            if "cookie" in decision:
                c = decision["cookie"]
                cookie_val = f"{c['name']}={c['value']}; Path={c['options'].get('path', '/')}"
                if c["options"].get("httponly"):
                    cookie_val += "; HttpOnly"
                if c["options"].get("secure"):
                    cookie_val += "; Secure"
                if "max_age" in c["options"]:
                    cookie_val += f"; Max-Age={c['options']['max_age']}"
                res_headers.append(("Set-Cookie", cookie_val))
            start_response("302 Found", res_headers)
            return [b""]

        # Inject new tracking cookies on legacy synchronous start_response
        new_cookie = decision.get("newCookieForResponse")

        if new_cookie:
            def custom_start_response(status, response_headers, exc_info=None):
                c = new_cookie
                cookie_val = f"{c['name']}={c['value']}; Path={c['options'].get('path', '/')}"
                if c["options"].get("httponly"):
                    cookie_val += "; HttpOnly"
                if c["options"].get("secure"):
                    cookie_val += "; Secure"
                if "max_age" in c["options"]:
                    cookie_val += f"; Max-Age={c['options']['max_age']}"
                response_headers.append(("Set-Cookie", cookie_val))
                return start_response(status, response_headers, exc_info)
            return self.app(environ, custom_start_response)

        return self.app(environ, start_response)


# --- ASGI: FastAPI Middleware Implementation ---
try:
    from fastapi import Request, Response
    from starlette.middleware.base import BaseHTTPMiddleware
    
    class FastAPIFingerprintMiddleware(BaseHTTPMiddleware):
        """
        FastAPI-specific middleware for integrating the fingerprint engine.
        It extends Starlette's BaseHTTPMiddleware for seamless integration.

        Args:
            app: The FastAPI application instance.
            security_config (Dict[str, Any]): The security configuration for the fingerprint engine.
            store (Optional[InMemoryStore]): An optional data store instance (defaults to InMemoryStore).
        """
        def __init__(self, app, security_config: Dict[str, Any], store: Optional[InMemoryStore] = None):
            super().__init__(app)
            self.store = store or InMemoryStore()
            self.engine = FingerprintEngine(security_config, self.store)

        async def dispatch(self, request: Request, call_next: Callable) -> Response:
            """
            Dispatches the incoming request through the fingerprint engine.

            Args:
                request (Request): The incoming FastAPI request.
                call_next (Callable): The next callable in the middleware stack.

            Returns:
                Response: The FastAPI response, potentially modified by the fingerprint engine.
            """
            # Map ASGI request to internal RequestContext
            headers_dict = {k.decode("utf-8"): v.decode("utf-8") for k, v in request.headers.raw}
            cookies_dict = dict(request.cookies)
            query_dict = dict(request.query_params)
            
            context = RequestContext(
                client_ip=request.client.host if request.client else "unknown",
                path=request.url.path,
                headers=headers_dict,
                query_params=query_dict,
                cookies=cookies_dict
            )
            
            decision = await self.engine.process_request(context)
            
            if decision["action"] == "block":
                return Response(content=decision.get("body", "Forbidden"), status_code=decision.get("status", 403))
                
            if decision["action"] == "challenge":
                return Response(content=decision.get("body", ""), status_code=decision.get("status", 403), media_type="text/html")
                
            if decision["action"] == "redirect":
                from fastapi.responses import RedirectResponse
                response = RedirectResponse(url=decision["path"], status_code=302)
                if "cookie" in decision:
                    c = decision["cookie"]
                    response.set_cookie(c["name"], c["value"], **c["options"])
                return response
            
            # Proceed with request
            response: Response = await call_next(request)
            
            # Inject tracking cookie if generated
            identity_resolution = await self.engine.resolve_identity(context)
            if identity_resolution["new_cookie"]:
                cookie = identity_resolution["new_cookie"]
                response.set_cookie(cookie["name"], cookie["value"], **cookie["options"])
                
            return response

except ImportError:
    pass

get_tcp_anomaly_score = RequestUtils.get_tcp_anomaly_score

if __name__ == "__main__":
    import asyncio
    import json

    async def run_demo():
        print("=" * 60)
        print("  FINGERPRINT ENGINE - PYTHON DEMO RUN")
        print("=" * 60)

        # 1. Configuration de sécurité type "balanced"
        config = {
            "thresholds": {"low": 20, "high": 75, "block": 95},
            "weights": {
                "inconsistencyScore": 0.8,
                "headerAnomalyScore": 0.1,
                "clientHintsInconsistencyScore": 0.7,
                "tlsSpoofingScore": 0.8,
                "botScore": 1.0,
                "honeypotScore": 1.0,
                "quicAnomalyScore": 0.8,
                "renderingAnomalyScore": 0.8,
            },
            "honeypot": {
                "fields": ["email_confirm"],
                "trapUrls": ["/wp-admin", "/.env"]
            },
            "similarityThreshold": 0.7
        }

        store = InMemoryStore()
        engine = FingerprintEngine(config, store)

        # Scénario A : Requête légitime (Nouvel appareil)
        context_legit = RequestContext(
            client_ip="192.168.1.50",
            path="/",
            headers={
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "accept-language": "fr-FR,fr;q=0.9,en;q=0.8"
            },
            query_params={},
            cookies={}
        )

        print("\n[Action] Simulation d'une requête légitime (humain)...")
        decision_legit = await engine.process_request(context_legit)
        print(f"-> Décision : {decision_legit['action']}")
        print(f"-> Cookie généré : {json.dumps(decision_legit.get('newCookieForResponse'))}")

        # Scénario B : Requête hostile (Bot accédant à une URL piège)
        context_bot = RequestContext(
            client_ip="203.0.113.88",
            path="/.env",
            headers={"user-agent": "curl/7.68.0"},
            query_params={},
            cookies={}
        )

        print("\n[Action] Simulation d'une attaque de bot (accès à /.env)...")
        decision_bot = await engine.process_request(context_bot)
        print(f"-> Décision : {decision_bot['action']} (Status: {decision_bot.get('status')})")
        print(f"-> Réponse retournée : {decision_bot.get('body')}")
        print("=" * 60)

    asyncio.run(run_demo())