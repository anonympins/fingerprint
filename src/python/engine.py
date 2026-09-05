import hmac
import hashlib
import time
import uuid
import math
import ctypes
import re
from typing import Dict, Any, List, Optional, Callable, Set
from dataclasses import dataclass, field

# --- UTILS ---

def imul(a: int, b: int) -> int:
    """
    Emulates JavaScript Math.imul (signed 32-bit integer multiplication).
    This is crucial for consistent hash calculation between JS and Python.
    """
    return ctypes.c_int32((a * b) & 0xffffffff).value


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


# --- CORE: Request Analysis Utilities ---
class RequestUtils:
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
            if version_diff > 5:
                return 80.0
            elif version_diff > 1:
                return 40.0
        except ValueError:
            pass

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
        
        if existing_device_id:
            device_data = await self.store.get(f"device:{existing_device_id}")
        else:
            device_data = None

        if not device_data:
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
            device_data = {
                "initialDeviceHash": current_hash,
                "ips": {context.client_ip},
                "lastUpdate": int(time.time() * 1000)
            }
            await self.store.set(f"device:{device_id}", device_data)
        else:
            device_id = existing_device_id
            device_data["ips"].add(context.client_ip)
            
        return {"device_id": device_id, "device_data": device_data, "new_cookie": new_cookie}

    async def get_suspicion_score(self, context: RequestContext) -> float:
        """
        Calculates the overall suspicion score for a request by combining various
        suspicion vectors with their configured weights.

        Args:
            context (RequestContext): The request context.

        Returns:
            float: The final suspicion score (0.0 to 100.0).
        """
        identity = await self.resolve_identity(context)
        device_data = identity["device_data"]
        
        # Inconsistency score
        current_hash = self.get_composite_device_hash(context)
        similarity = FingerprintBuilder.compare(device_data.get("initialDeviceHash"), current_hash)
        inconsistency_score = max(0.0, (1.0 - similarity) * 200.0)
        if similarity < self.config.get("similarityThreshold", 0.7):
            inconsistency_score = 100.0

        # 1. Anomalies d'en-têtes
        header_anomaly = RequestUtils.get_header_anomalies(context)

        # 2. Incohérence des Client Hints
        client_hints_score = RequestUtils.get_client_hints_inconsistency(context)

        # 3. Spoofing TLS (JA3/JA4 vs User-Agent)
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
        score = (
            inconsistency_score * self.weights.get("inconsistencyScore", 0.3) +
            header_anomaly * self.weights.get("headerAnomalyScore", 0.2) +
            client_hints_score * self.weights.get("clientHintsInconsistencyScore", 0.2) +
            tls_spoofing_score * self.weights.get("tlsSpoofingScore", 0.3) +
            bot_score * self.weights.get("botScore", 0.1) +
            honeypot_score * self.weights.get("honeypotScore", 1.0)
        )
        return min(100.0, score)

    async def process_request(self, context: RequestContext) -> Dict[str, Any]:
        """
        Processes an incoming request, applies fingerprinting logic, calculates
        a suspicion score, and determines the appropriate action (block, challenge, redirect, next).

        Args:
            context (RequestContext): The request context.

        Returns:
            Dict[str, Any]: A dictionary describing the action to be taken and any associated data.
        """
        identity = await self.resolve_identity(context)
        device_id = identity["device_id"]
        device_data = identity["device_data"]

        # Early block for condemned devices
        if device_data and device_data.get("condemned"):
            return {"action": "block", "status": 403, "body": "Forbidden"}

        # Honeypot trap URL instant check & condemnation
        honeypot_config = self.config.get("honeypot", {})
        for trap in honeypot_config.get("trapUrls", []):
            if context.path.startswith(trap):
                device_data["condemned"] = True
                await self.store.set(f"device:{device_id}", device_data)
                return {"action": "block", "status": 403, "body": "Forbidden"}

        # Check for challenge submission
        pow_nonce = context.query_params.get("pow_nonce")
        pow_sol_cpu = context.query_params.get("pow_solution_cpu") or context.query_params.get("pow_solution")
        pow_sol_mem = context.query_params.get("pow_solution_mem")
        pow_fp = context.query_params.get("pow_fp") or self.get_composite_device_hash(context)

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
                    return {
                        "action": "redirect",
                        "path": context.path,
                        "cookie": {
                            "name": "pow_clearance",
                            "value": ticket,
                            "options": {"httponly": True, "max_age": 3600, "path": "/"}
                        }
                    }

        # Check existing ticket
        pow_cookie = context.cookies.get("pow_clearance")
        has_valid_ticket = False
        if pow_cookie:
            ticket_data = await self.store.get(f"ticket:{pow_cookie}")
            if ticket_data and ticket_data.get("ip") == context.client_ip:
                has_valid_ticket = True

        score = await self.get_suspicion_score(context)

        if score >= self.thresholds.get("block", 95):
            return {"action": "block", "status": 403, "body": "Forbidden"}

        if score >= self.thresholds.get("low", 20) and not has_valid_ticket:
            # Issue a new challenge
            nonce = str(uuid.uuid4()).replace("-", "")[:16]
            client_secret = str(uuid.uuid4()).replace("-", "")[:16]
            suspicion_factor = (score - self.thresholds["low"]) / (self.thresholds["high"] - self.thresholds["low"]) if "high" in self.thresholds else 0.5
            suspicion_factor = max(0.0, min(1.0, suspicion_factor))
            
            cpu_target = ChallengeUtils.calculate_cpu_target(suspicion_factor, self.config)
            mem_difficulty = int(round(max(0.0, suspicion_factor - 0.25) * 48))

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

            return {
                "action": "challenge",
                "status": 403,
                "body": html
            }

        return {"action": "next"}


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
        identity_resolution = await self.engine.resolve_identity(context)
        new_cookie = identity_resolution["new_cookie"]

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
        identity_resolution = loop.run_until_complete(self.engine.resolve_identity(context))
        new_cookie = identity_resolution["new_cookie"]

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