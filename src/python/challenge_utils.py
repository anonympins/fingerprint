import hmac
import hashlib
import time
import math
import re
import random
import json
import os
import base64
import struct
import ctypes
from typing import Dict, Any, List, Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

from utils import get_ip_subnet, is_loopback_ip
from builder import cyrb53, imul


class ChallengeUtils:
    @staticmethod
    def fround(val: float) -> float:
        try:
            return struct.unpack('f', struct.pack('f', val))[0]
        except OverflowError:
            return float('-inf') if val < 0 else float('inf')

    @staticmethod
    def hash_seed_to_float(seed: str) -> float:
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
    def verify_ed25519_signature(message: str, signature_hex: str, config: Optional[Dict[str, Any]] = None) -> bool:
        if not message or not signature_hex:
            return False
        cfg = config or {}
        pub_pem = cfg.get("ed25519_public_key") or os.environ.get("ED25519_PUBLIC_KEY")
        if not pub_pem:
            return False
        try:
            from cryptography.hazmat.primitives.serialization import load_pem_public_key
            from cryptography.hazmat.backends import default_backend

            public_key = load_pem_public_key(pub_pem.encode("utf-8"), backend=default_backend())
            sig_bytes = bytes.fromhex(signature_hex)
            public_key.verify(sig_bytes, message.encode("utf-8"))
            return True
        except Exception:
            return False

    @staticmethod
    async def handle_cooperative_request(store, params: Dict[str, Any], client_ip: str = '127.0.0.1', headers: Optional[Dict[str, str]] = None, config: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        op = params.get("coop_op")
        if not op:
            return None

        cfg = config or {}
        peers = cfg.get("federatedPeers") or []
        if peers and op in ("share_threat_intel", "share_whitelist"):
            import urllib.parse
            allowed_hosts = []
            for url in peers:
                try:
                    parsed = urllib.parse.urlparse(url)
                    allowed_hosts.append(parsed.hostname or url)
                except Exception:
                    allowed_hosts.append(url)
            if client_ip not in allowed_hosts:
                return {"error": "Unauthorized federation sender IP"}

        if op == "share_threat_intel":
            zkp_y = params.get("zkpY") or ""
            hdrs = headers or {}
            sig_ed25519 = params.get("signature_ed25519") or hdrs.get("x-federation-signature-ed25519") or ""
            signature = params.get("signature") or hdrs.get("x-federation-signature") or ""
            timestamp_str = params.get("timestamp") or hdrs.get("x-federation-timestamp") or "0"
            try:
                timestamp = int(timestamp_str)
            except ValueError:
                timestamp = 0

            if not zkp_y or (not signature and not sig_ed25519) or not timestamp:
                return {"error": "Missing threat intel parameters"}

            # Anti-replay (5 minutes safety window)
            now_ms = int(time.time() * 1000)
            if abs(now_ms - timestamp) > 300000:
                return {"error": "Message expired or clock skew too high"}

            secret = params.get("federationSecret") or os.environ.get("POW_SECRET") or "fallback-dev-secret-32-chars-minimum"
            msg = f"{timestamp}:{zkp_y}"
            verified = False
            if sig_ed25519:
                verified = ChallengeUtils.verify_ed25519_signature(msg, sig_ed25519, cfg)
            elif signature:
                expected_sig = hmac.new(secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()
                verified = hmac.compare_digest(expected_sig, signature)

            if not verified:
                return {"error": "Invalid federation signature"}

            # Ban the ZKP public key for 30 days
            await store.set(f"banned-zkp-y:{zkp_y}", True, 86400 * 30)
            return {"status": "synchronized"}

        if op == "share_whitelist":
            entry = params.get("entry")
            entry_type = params.get("entry_type", "ip")
            hdrs = headers or {}
            sig_ed25519 = params.get("signature_ed25519") or hdrs.get("x-federation-signature-ed25519") or ""
            timestamp_str = params.get("timestamp") or hdrs.get("x-federation-timestamp") or ""
            ttl_str = params.get("ttl", "86400")

            if not entry or not entry.strip() or not sig_ed25519 or not timestamp_str:
                return {"error": "Missing required parameters for share_whitelist"}

            clean_entry = entry.strip()
            if clean_entry in ("*", "0.0.0.0/0", "::/0"):
                return {"error": "Permissive wildcard entries are prohibited"}

            try:
                timestamp = int(timestamp_str)
            except ValueError:
                return {"error": "Invalid timestamp format"}

            now_ms = int(time.time() * 1000)
            if abs(now_ms - timestamp) > 300000:
                return {"error": "Timestamp expired or clock skew too high"}

            msg = f"{timestamp}:whitelist:{entry_type}:{clean_entry}"
            if not ChallengeUtils.verify_ed25519_signature(msg, sig_ed25519, cfg):
                return {"error": "Invalid Ed25519 signature for whitelist synchronization"}

            try:
                ttl = min(604800, max(60, int(ttl_str)))
            except ValueError:
                ttl = 86400

            await store.set(f"federated-whitelist:{entry_type}:{clean_entry}", True, ttl)
            return {"status": "whitelist_synchronized"}

        node_id = params.get("node_id") or ""
        if not node_id:
            return {"error": "Missing node_id"}

        if op == "register":
            seed = params.get("seed") or ""
            await ChallengeUtils.register_cooperative_node(store, client_ip, node_id, seed)
            return {"status": "registered"}

        elif op == "find_peer":
            peer = await ChallengeUtils.find_peer_in_subnet(store, client_ip, node_id)
            if not peer:
                return {"status": "no_peers"}
            return {
                "status": "peer_found",
                "peer_id": peer.get("nodeId"),
                "seed": peer.get("seed", "")
            }

        elif op == "webrtc_signal":
            target_peer_id = params.get("target_peer_id") or ""
            signal_type = params.get("signal_type") or ""
            signal_data = params.get("signal_data") or ""
            if not target_peer_id or not signal_type or not signal_data:
                return {"error": "Invalid parameters"}

            signal_queue_key = f"coop-webrtc:signals:{target_peer_id}"
            signals = await store.get(signal_queue_key) or []
            signals.append({
                "from_peer_id": node_id,
                "signal_type": signal_type,
                "signal_data": signal_data,
                "timestamp": int(time.time() * 1000)
            })
            await store.set(signal_queue_key, signals, 30)
            return {"status": "signal_queued"}

        elif op == "poll_signals":
            poll_signal_key = f"coop-webrtc:signals:{node_id}"
            signals = await store.get(poll_signal_key) or []
            if signals:
                await store.delete(poll_signal_key)
            return {"status": "ok", "signals": signals}

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
        cpu_config = (security_config or {}).get("cpu", {})
        min_bits = cpu_config.get("minDifficultyBits", 8)
        max_bits = cpu_config.get("maxDifficultyBits", 22)
        total_bits = min_bits + suspicion_factor * (max_bits - min_bits)
        if total_bits <= 0:
            return "f" * 64
        shift = 256 - int(math.floor(total_bits))
        return hex(1 << shift)[2:].zfill(64)

    @staticmethod
    def verify_cpu_pow(base_block: bytes, target_hex: str, solution: str) -> bool:
        try:
            final_block = base_block + str(solution).encode("utf-8")
            h = hashlib.sha256(final_block).hexdigest()
            return int(h, 16) < int(target_hex, 16)
        except Exception:
            return False

    @staticmethod
    def get_challenged_indices(seed: str, solution: int, num_blocks: int, k: int = 4) -> list:
        indices = []
        h = cyrb53(f"{seed}:{solution}") % 4294967296
        if h >= 2147483648:
            h -= 4294967296
        for i in range(k):
            h = imul(h ^ i, 1597334677)
            indices.append(abs(h) % num_blocks)
        return indices

    @staticmethod
    def verify_merkle_proof(leaf_hash: str, index: int, proof: list, root: str) -> bool:
        current_hash = leaf_hash
        idx = index
        for sibling in proof:
            combined = current_hash + sibling if idx % 2 == 0 else sibling + current_hash
            current_hash = hashlib.sha256(bytes.fromhex(combined)).hexdigest()
            idx //= 2
        return current_hash == root

    @staticmethod
    def verify_memory_pow_legacy(nonce: str, solution: int, difficulty: int, client_secret: str) -> bool:
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
        return final_hash == solution

    @staticmethod
    def verify_memory_pow(nonce: str, solution: str, difficulty: int, client_secret: str) -> bool:
        if difficulty == 0:
            return True
        try:
            data = json.loads(solution) if isinstance(solution, str) else solution
        except Exception:
            data = None

        if not isinstance(data, dict):
            if difficulty <= 4 and re.match(r'^\d+$', str(solution)):
                return ChallengeUtils.verify_memory_pow_legacy(nonce, int(solution), difficulty, client_secret)
            return False

        if "solution" not in data or "merkleRoot" not in data or "proofs" not in data:
            if difficulty <= 4 and re.match(r'^\d+$', str(solution)):
                return ChallengeUtils.verify_memory_pow_legacy(nonce, int(solution), difficulty, client_secret)
            return False

        sol = data["solution"]
        merkle_root = data["merkleRoot"]
        proofs = data["proofs"]

        num_blocks = difficulty * 256
        seed = f":{nonce}:{client_secret}"

        challenged_indices = ChallengeUtils.get_challenged_indices(seed, int(sol), num_blocks, 4)

        for b in challenged_indices:
            if str(b) not in proofs and b not in proofs:
                return False
            proof = proofs.get(str(b)) or proofs.get(b)

            block_bytes = bytearray()
            h = cyrb53(f"{seed}:{b}") % 4294967296
            if h >= 2147483648:
                h -= 4294967296
            for i in range(1024):
                h = imul(h ^ i, 1597334677)
                block_bytes.extend(struct.pack("<I", h & 0xffffffff))

            expected_leaf = hashlib.sha256(block_bytes).hexdigest()

            if not ChallengeUtils.verify_merkle_proof(expected_leaf, b, proof, merkle_root):
                return False

        block_cache = {}
        def get_block_element(block_idx: int, element_idx: int) -> int:
            if block_idx not in block_cache:
                block = [0] * 1024
                h_val = cyrb53(f"{seed}:{block_idx}") % 4294967296
                if h_val >= 2147483648:
                    h_val -= 4294967296
                for i in range(1024):
                    h_val = imul(h_val ^ i, 1597334677)
                    block[i] = h_val & 0xffffffff
                block_cache[block_idx] = block
            return block_cache[block_idx][element_idx]

        total_elements = num_blocks * 1024
        addr = (get_block_element(0, 0) % total_elements) if total_elements > 0 else 0
        expected_solution = 0
        iterations = 1024
        for _ in range(iterations):
            block_idx = addr // 1024
            element_idx = addr % 1024
            addr = get_block_element(block_idx, element_idx) % total_elements
            expected_solution ^= addr

        return expected_solution == int(sol)

    @staticmethod
    async def check_challenge_rate_limit(
        store,
        client_ip: str,
        domain: str = "default",
        rate_limit_config: Optional[Dict[str, Any]] = None
    ) -> bool:
        rate_limit_config = rate_limit_config or {}
        if rate_limit_config.get("enabled") is False:
            return True

        if not client_ip or is_loopback_ip(client_ip):
            return True

        subnet = get_ip_subnet(client_ip) or client_ip
        if not subnet:
            return False

        host = (domain or "default").lower().split(":")[0]
        key = f"rate-limit:{host}:{subnet}"

        capacity = float(rate_limit_config.get("capacity", 30.0))
        refill_rate = float(rate_limit_config.get("refillRate", 1.0))
        now = time.time()
        ttl = max(60, int(math.ceil(capacity / max(0.1, refill_rate))))

        if hasattr(store, "rate_limit_token_bucket"):
            return await store.rate_limit_token_bucket(
                key=key,
                capacity=capacity,
                refill_rate=refill_rate,
                now=now,
                cost=1.0,
                ttl=ttl
            )

        rate_limit_data = await store.get(key)
        if not rate_limit_data:
            rate_limit_data = {"tokens": capacity, "lastRefill": now}

        elapsed = max(0.0, now - rate_limit_data.get("lastRefill", now))
        tokens = min(capacity, float(rate_limit_data.get("tokens", capacity)) + elapsed * refill_rate)

        if tokens < 1.0:
            await store.set(key, {"tokens": tokens, "lastRefill": now}, ttl)
            return False

        await store.set(key, {"tokens": tokens - 1.0, "lastRefill": now}, ttl)
        return True


def verify_zkp_proof(y_str, t_str, s_str):
    return ChallengeUtils.verify_zkp_proof(y_str, t_str, s_str)

def get_pow_secret():
    return os.environ.get('POW_SECRET', 'fallback-dev-secret-32-chars-minimum')

async def handle_cooperative_request(store, params, client_ip='127.0.0.1', headers=None, config=None):
    return await ChallengeUtils.handle_cooperative_request(store, params, client_ip, headers, config)

__all__ = ["ChallengeUtils", "verify_zkp_proof", "get_pow_secret", "handle_cooperative_request"]