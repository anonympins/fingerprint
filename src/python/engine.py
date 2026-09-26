import hmac
import hashlib
import time
import uuid
import math
import ctypes
import re
import random
import logging
import copy
import json
import os
import asyncio
import base64
import ipaddress
from problem_manager import ProblemManager
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
from typing import Dict, Any, List, Optional, Callable, Set
from dataclasses import dataclass, field

# --- UTILS ---

class BlockList:
     def __init__(self):
         self.entries = []
 
     def add(self, entry: str):
         try:
             if "/" in entry:
                 self.entries.append(ipaddress.ip_network(entry, strict=False))
             else:
                 self.entries.append(ipaddress.ip_address(entry))
         except ValueError:
             pass
 
     def check(self, ip: str) -> bool:
         try:
             ip_obj = ipaddress.ip_address(ip)
             for entry in self.entries:
                 if isinstance(entry, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                     if ip_obj in entry:
                         return True
                 else:
                     if ip_obj == entry:
                         return True
         except ValueError:
             pass
         return False

dns_circuit_breaker = {
    "state": "CLOSED",
    "failureCount": 0,
    "lastStateChange": 0.0,
    "threshold": 5,
    "cooldown": 30.0, # seconds
}

def record_dns_success():
    dns_circuit_breaker["failureCount"] = 0
    dns_circuit_breaker["state"] = "CLOSED"

def record_dns_failure():
    dns_circuit_breaker["failureCount"] += 1
    if dns_circuit_breaker["failureCount"] >= dns_circuit_breaker["threshold"]:
        dns_circuit_breaker["state"] = "OPEN"
        dns_circuit_breaker["lastStateChange"] = time.time()

def can_attempt_dns() -> bool:
    if dns_circuit_breaker["state"] == "CLOSED":
        return True
    if dns_circuit_breaker["state"] == "OPEN":
        if time.time() - dns_circuit_breaker["lastStateChange"] > dns_circuit_breaker["cooldown"]:
            dns_circuit_breaker["state"] = "HALF-OPEN"
            return True
        return False
    return True # HALF-OPEN

_googlebot_entries = None
_bingbot_entries = None
_yandex_entries = None

def load_bot_whitelist(filename: str, fallback_entries: list) -> list:
 config_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../config"))
 file_path = os.path.join(config_dir, filename)
 if os.path.exists(file_path):
     try:
         with open(file_path, "r", encoding="utf-8") as f:
             return json.load(f)
     except Exception as e:
         print(f"[Fingerprint] Error loading whitelist file {filename}: {e}")
 return fallback_entries

def googlebot_whitelist() -> dict:
 global _googlebot_entries
 if _googlebot_entries is None:
     _googlebot_entries = load_bot_whitelist("googlebot.json", [
         "2001:4860:4801:10::/64",
         "2001:4860:4801:11::/64",
         "2001:4860:4801:12::/64",
         "66.249.79.64"
     ])
 return {
     "type": "allowlist",
     "entries": _googlebot_entries
 }

def bingbot_whitelist() -> dict:
 global _bingbot_entries
 if _bingbot_entries is None:
     _bingbot_entries = load_bot_whitelist("bingbot.json", [
         "157.55.39.0/24",
         "207.46.13.0/24",
         "40.77.178.0/23"
     ])
 return {
     "type": "allowlist",
     "entries": _bingbot_entries
 }

def yandex_whitelist() -> dict:
 global _yandex_entries
 if _yandex_entries is None:
     _yandex_entries = load_bot_whitelist("yandex.json", [
         "2a02:6b8::/29",
         "5.45.192.0/18",
         "213.180.192.0/19"
     ])
 return {
     "type": "allowlist",
     "entries": _yandex_entries
 }

def default_whitelist() -> list:
 return [
     googlebot_whitelist(),
     bingbot_whitelist(),
     yandex_whitelist(),
     {"userAgent": "Googlebot", "hostnameSuffix": ".googlebot.com"},
     {"userAgent": "Google-Extended", "hostnameSuffix": ".google.com"},
     {"userAgent": "AdsBot-Google", "hostnameSuffix": ".googlebot.com"},
     {"userAgent": "Mediapartners-Google", "hostnameSuffix": ".google.com"},
     {"userAgent": "Google-InspectionTool", "hostnameSuffix": ".google.com"},
     {"userAgent": "(bingbot|adidxbot)", "hostnameSuffix": ".search.msn.com"},
     {"userAgent": "DuckDuckBot", "hostnameSuffix": ".duckduckgo.com"},
     {"userAgent": "YandexBot", "hostnameSuffix": ".yandex.com"},
     {"userAgent": "YandexImages", "hostnameSuffix": ".yandex.com"},
     {"userAgent": "Baiduspider", "hostnameSuffix": ".crawl.baidu.com"},
     {"userAgent": "Slurp", "hostnameSuffix": ".crawl.yahoo.net"},
     {"userAgent": "Sogou web spider", "hostnameSuffix": ".sogou.com"},
     {"userAgent": "Exabot", "hostnameSuffix": ".exabot.com"},
     {"userAgent": "ia_archiver", "hostnameSuffix": ".alexa.com"},
     {"userAgent": "SeznamBot", "hostnameSuffix": ".seznam.cz"},
     {"userAgent": "Mail.RU_Bot", "hostnameSuffix": ".mail.ru"},
     {"userAgent": "Yeti", "hostnameSuffix": ".naver.com"},
 ]

DEFAULT_WEIGHTS = {
    "historyScore": 0.3,
    "rotationScore": 0.5,
    "headerAnomalyScore": 0.2,
    "requestPatternScore": 0.6,
    "inconsistencyScore": 0.8,
    "behaviorScore": 0.7,
    "honeypotScore": 1.0,
    "botScore": 1.0,
    "cookieDroppingScore": 0.9,
    "crossLayerInconsistencyScore": 0.4,
    "timeInconsistencyScore": 0.9,
    "tlsSpoofingScore": 0.8,
    "clientHintsInconsistencyScore": 0.7,
    "clickVarianceScore": 0.6,
    "subnetScore": 0.4,
    "ipReputationScore": 0.5,
    "botnetClusterScore": 0.7,
    "tcpAnomalyScore": 0.8,
    "protocolAnomalyScore": 0.8,
    "quicAnomalyScore": 0.8,
    "renderingAnomalyScore": 0.8,
    "threatIntelScore": 1.0,
    "virtualizationScore": 0.8
}

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
                socket.inet_pton(socket.AF_INET6, ip)
                normalized = ip.strip().lower()
                if "::" in normalized:
                    parts = normalized.split("::", 1)
                    left = parts[0].split(":") if parts[0] else []
                    right = parts[1].split(":") if parts[1] else []
                    missing = 8 - (len(left) + len(right))
                    middle = ["0000"] * missing
                    groups = left + middle + right
                else:
                    groups = normalized.split(":")
                    if len(groups) != 8:
                        return None
                for i in range(8):
                    try:
                        val = int(groups[i], 16)
                    except ValueError:
                        val = 0
                    groups[i] = f"{val:04x}"
                for i in range(8):
                    start_bit = i * 16
                    if ipv6_prefix >= (i + 1) * 16:
                        continue
                    elif ipv6_prefix <= start_bit:
                        groups[i] = "0000"
                    else:
                        bits_to_keep = ipv6_prefix - start_bit
                        val = int(groups[i], 16)
                        mask = (0xffff << (16 - bits_to_keep)) & 0xffff
                        groups[i] = f"{val & mask:04x}"
                return f"{':'.join(groups)}/{ipv6_prefix}"
        except socket.error:
            return None

def get_ip_common_prefix_length(ip1: str, ip2: str) -> int:
    """Calculates the common prefix length in bits between two IP addresses (IPv4 or IPv6)."""
    import socket
    if not ip1 or not ip2:
        return 0
    try:
        socket.inet_pton(socket.AF_INET, ip1)
        socket.inet_pton(socket.AF_INET, ip2)
        b1 = [int(x) for x in ip1.split('.')]
        b2 = [int(x) for x in ip2.split('.')]
        int1 = (b1[0] << 24) | (b1[1] << 16) | (b1[2] << 8) | b1[3]
        int2 = (b2[0] << 24) | (b2[1] << 16) | (b2[2] << 8) | b2[3]
        xor = (int1 ^ int2) & 0xffffffff
        if xor == 0:
            return 32
        return 32 - xor.bit_length()
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ip1)
            socket.inet_pton(socket.AF_INET6, ip2)
            addr1 = ipaddress.IPv6Address(ip1)
            addr2 = ipaddress.IPv6Address(ip2)
            int1 = int(addr1)
            int2 = int(addr2)
            xor = int1 ^ int2
            if xor == 0:
                return 128
            return 128 - xor.bit_length()
        except Exception:
            return 0

def is_loopback_ip(ip: str) -> bool:
    """Checks if an IP address is a loopback/local address."""
    if not ip or ip in ("127.0.0.1", "::1", "localhost"):
        return True
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False

GREASE_VALUES = {
    2570, 6682, 10794, 14906, 19018, 23130, 27242, 31354,
    35466, 39578, 43690, 47802, 51914, 55926, 60038, 64150
}

def has_grease(values: list) -> bool:
    if not isinstance(values, list):
        return False
    return any(v in GREASE_VALUES for v in values)

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

    def safe_json_dumps(val) -> str:
        return json.dumps(val).replace("<", "\\u003c").replace(">", "\\u003e")

    safe_path = safe_json_dumps(path)
    safe_nonce = safe_json_dumps(nonce)
    safe_client_secret = safe_json_dumps(client_secret)

    peer_id = challenge_details.get("peerId", "")
    peer_block_idx = challenge_details.get("peerBlockIdx", -1)
    coop_timeout = security_config.get("pospace", {}).get("coopTimeout", 15)

    challenge_script = f"""
    async function solve() {{
      const nonce = {safe_nonce};
      const path = {safe_path};
      const clientSecret = {safe_client_secret};
      const queries = {queries_json};
      const sizeMb = {size_mb};
      const nodeId = nonce;
      const peerId = "{peer_id}";
      const peerBlockIdx = {peer_block_idx};
      const coopTimeout = {coop_timeout};

      async function signCoop(op, nid, extra = "") {{
        const msg = clientSecret + ":" + op + ":" + nid + (extra ? ":" + extra : "");
        const encoder = new TextEncoder();
        const data = encoder.encode(msg);
        const hashBuffer = await crypto.subtle.digest("SHA-256", data);
        return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
      }}

      async function sendWebRtcSignal(targetId, type, data) {{
        const sig = await signCoop("webrtc_signal", nodeId, targetId + ":" + type + ":" + data);
        await fetch(window.location.pathname + "?coop_op=webrtc_signal&node_id=" + nodeId + "&target_peer_id=" + targetId + "&signal_type=" + type + "&signal_data=" + encodeURIComponent(data) + "&coop_sig=" + sig);
      }}
      
      document.getElementById('loader').innerText = '⚙&#xFE0F; Checking persistent local storage...';
      await new Promise(r => setTimeout(r, 10));
      
      try {{
          await window.initializeSpace(nonce + ":" + clientSecret, size_mb);

          if (peerId && peerBlockIdx !== -1) {{
              const sig = await signCoop("register", nodeId, nonce + ":" + clientSecret);
              await fetch(window.location.pathname + "?coop_op=register&node_id=" + nodeId + "&seed=" + encodeURIComponent(nonce + ":" + clientSecret) + "&coop_sig=" + sig);
          }}

          const peerConnections = {{}};

          setInterval(async () => {{
              try {{
                  const sigWebrtc = await signCoop("poll_signals", nodeId);
                  const resWebrtc = await fetch(window.location.pathname + "?coop_op=poll_signals&node_id=" + nodeId + "&coop_sig=" + sigWebrtc);
                  const dataWebrtc = await resWebrtc.json();
                  if (dataWebrtc.signals && dataWebrtc.signals.length > 0) {{
                      for (const sig of dataWebrtc.signals) {{
                          const fromId = sig.from_peer_id;
                          if (sig.signal_type === 'offer') {{
                              const pc = new RTCPeerConnection({{ iceServers: [] }});
                              peerConnections[fromId] = pc;
                              pc.onicecandidate = (e) => {{
                                  if (e.candidate) sendWebRtcSignal(fromId, 'candidate', JSON.stringify(e.candidate));
                              }};
                              pc.ondatachannel = (e) => {{
                                  const dc = e.channel;
                                  dc.onmessage = async (evt) => {{
                                      try {{
                                          const req = JSON.parse(evt.data);
                                          if (req.type === 'get_block') {{
                                              document.getElementById('loader').innerText = '📤 Transfert direct P2P (WebRTC) du bloc vers le pair...';
                                              const blockData = await window.readSpaceBlock(req.block_idx);
                                              dc.send(JSON.stringify({{ type: 'block_data', block_data: blockData }}));
                                          }}
                                      }} catch (err) {{}}
                                  }};
                              }};
                              await pc.setRemoteDescription(new RTCSessionDescription(JSON.parse(sig.signal_data)));
                              const answer = await pc.createAnswer();
                              await pc.setLocalDescription(answer);
                              await sendWebRtcSignal(fromId, 'answer', JSON.stringify(answer));
                          }} else if (sig.signal_type === 'answer' && peerConnections[fromId]) {{
                              await peerConnections[fromId].setRemoteDescription(new RTCSessionDescription(JSON.parse(sig.signal_data)));
                          }} else if (sig.signal_type === 'candidate' && peerConnections[fromId]) {{
                              await peerConnections[fromId].addIceCandidate(new RTCIceCandidate(JSON.parse(sig.signal_data)));
                          }}
                      }}
                  }}
              }} catch (e) {{}}
          }}, 800);

          let peerBlock = "";
          if (peerId && peerBlockIdx !== -1) {{
              document.getElementById('loader').innerText = '📥 Connexion WebRTC P2P directe au pair (' + peerId + ')...';

              const webrtcTransferPromise = new Promise(async (resolve) => {{
                  if (!window.RTCPeerConnection) return resolve(null);
                  try {{
                      const pc = new RTCPeerConnection({{ iceServers: [] }});
                      peerConnections[peerId] = pc;
                      const dc = pc.createDataChannel("pospace-transfer");
                      pc.onicecandidate = (e) => {{
                          if (e.candidate) sendWebRtcSignal(peerId, 'candidate', JSON.stringify(e.candidate));
                      }};
                      dc.onopen = () => {{
                          dc.send(JSON.stringify({{ type: 'get_block', block_idx: peerBlockIdx }}));
                      }};
                      dc.onmessage = (e) => {{
                          try {{
                              const msg = JSON.parse(e.data);
                              if (msg.type === 'block_data' && msg.block_data) {{
                                  resolve(msg.block_data);
                              }}
                          }} catch (err) {{}}
                      }};
                      const offer = await pc.createOffer();
                      await pc.setLocalDescription(offer);
                      await sendWebRtcSignal(peerId, 'offer', JSON.stringify(offer));
                  }} catch (err) {{
                      resolve(null);
                  }}
              }});

              const webrtcTimeoutPromise = new Promise((resolve) => setTimeout(() => resolve(null), 5000));
              peerBlock = await Promise.race([webrtcTransferPromise, webrtcTimeoutPromise]);

              if (peerBlock) {{
                  document.getElementById('loader').innerText = '⚡ Bloc reçu en direct via WebRTC P2P sans transit serveur !';
              }} else {{
                  document.getElementById('loader').innerText = '⚠️ WebRTC indisponible. Téléchargement via relais HTTP...';
                  const reqId = Math.random().toString(36).substring(2);
                  const reqSig = await signCoop("request_peer_block", nodeId, peerId + ":" + peerBlockIdx + ":" + reqId);
                  await fetch(window.location.pathname + "?coop_op=request_peer_block&node_id=" + nodeId + "&peer_id=" + peerId + "&block_idx=" + peerBlockIdx + "&req_id=" + reqId + "&coop_sig=" + reqSig);
              }}
          }}

          document.getElementById('loader').innerText = '⚙&#xFE0F; Generating Proof of Space...';
          const hash = await window.solveSpaceChallenge(nonce + ":" + clientSecret, queries, nonce, clientSecret, peerBlock);
          
          window.location.href = path + "?pow_type=pospace&pow_nonce=" + nonce + "&pow_solution_space=" + hash + (peerBlock ? "&pow_coop=1" : "");
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
    
    raw_logs = list(traffic_data)
    suspicious_logs = []
    passed_logs = []
    device_counts = {}
    ip_counts = {}
    subnet_counts = {}
    hw_cluster_counts = {}
    hw_cluster_cache = {}

    total_count = len(traffic_data)
    max_logs_per_device = max(3, total_count // 50) # 2%
    max_logs_per_ip = max(3, total_count // 50)      # 2%
    max_logs_per_subnet = max(5, total_count // 20)  # 5%
    max_logs_per_hw_cluster = max(3, total_count // 50) # 2%

    def get_vector_distance(v1: Dict[str, float], v2: Dict[str, float]) -> float:
        if not v1 or not v2:
            return float('inf')
        all_keys = set(v1.keys()).union(v2.keys())
        sum_sq = 0.0
        for key in all_keys:
            sum_sq += (v1.get(key, 0.0) - v2.get(key, 0.0)) ** 2
        return math.sqrt(sum_sq)

    # Cohort compression (Anti-Sybil / Anti-Poisoning)
    clustered_logs = []
    for log in raw_logs:
        matched_cluster = None
        log_vector = log.get("vector") or {}
        log_type = log.get("type") or ""
        for cluster in clustered_logs:
            if log_type == cluster.get("type", "") and get_vector_distance(log_vector, cluster.get("vector", {})) < 5.0:
                matched_cluster = cluster
                break
        if matched_cluster is not None:
            matched_cluster["instancesCount"] = matched_cluster.get("instancesCount", 1) + 1
            matched_cluster["weight"] = 1.0 + math.log(matched_cluster["instancesCount"])
        else:
            log_copy = dict(log)
            log_copy["instancesCount"] = 1
            log_copy["weight"] = 1.0
            clustered_logs.append(log_copy)

    def get_hardware_cluster(log_entry: Dict[str, Any]) -> str:
        fp = log_entry.get("deviceHash") or log_entry.get("fingerprint") or log_entry.get("deviceFingerprint") or ""
        if fp and isinstance(fp, str):
            if fp in hw_cluster_cache:
                return hw_cluster_cache[fp]
            parts = fp.split("|")
            hw_components = []
            for part in parts:
                pair = part.split(":", 1)
                if len(pair) == 2 and pair[0] in ("gpu", "cvs", "hw"):
                    hw_components.append(part)
            if hw_components:
                result = "|".join(sorted(hw_components))
            else:
                result = log_entry.get("deviceId") or "anonymous-cluster"
            hw_cluster_cache[fp] = result
            return result
        return log_entry.get("deviceId") or "anonymous-cluster"

    for log in clustered_logs:
        dev_id = log.get("deviceId") or "anonymous"
        ip = log.get("clientIp") or log.get("ip") or "unknown"
        subnet = get_ip_subnet(ip) or "unknown-subnet"
        hw_cluster = get_hardware_cluster(log)

        current_device_count = device_counts.get(dev_id, 0)
        current_ip_count = ip_counts.get(ip, 0)
        current_subnet_count = subnet_counts.get(subnet, 0)
        current_hw_cluster_count = hw_cluster_counts.get(hw_cluster, 0)

        if (
            current_device_count < max_logs_per_device and
            (ip == "unknown" or current_ip_count < max_logs_per_ip) and
            (subnet == "unknown-subnet" or current_subnet_count < max_logs_per_subnet) and
            current_hw_cluster_count < max_logs_per_hw_cluster
        ):
            device_counts[dev_id] = current_device_count + 1
            if ip != "unknown":
                ip_counts[ip] = current_ip_count + 1
            if subnet != "unknown-subnet":
                subnet_counts[subnet] = current_subnet_count + 1
            hw_cluster_counts[hw_cluster] = current_hw_cluster_count + 1
            if log.get("type") == "request_passed":
                passed_logs.append(log)
            else:
                suspicious_logs.append(log)

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
    http2_fingerprint: Optional[str] = None

    def __post_init__(self):
        # Normalize headers to lowercase for consistent lookup
        self.headers = {k.lower(): v for k, v in self.headers.items()}
        if not self.tls_session_id:
            self.tls_session_id = self.headers.get("x-tls-session-id") or self.headers.get("x-ssl-session-id")
        if not self.quic_fingerprint:
            self.quic_fingerprint = self.headers.get("x-quic-fp")
        if not self.http2_fingerprint:
            self.http2_fingerprint = self.headers.get("x-http2-fingerprint")

    def get_header(self, name: str) -> Optional[str]:
        return self.headers.get(name.lower())

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
    async def handle_cooperative_request(store, params: Dict[str, Any], client_ip: str = '127.0.0.1', headers: Optional[Dict[str, str]] = None) -> Optional[Dict[str, Any]]:
        op = params.get("coop_op")
        if not op:
            return None

        if op == "share_threat_intel":
            zkp_y = params.get("zkpY") or ""
            hdrs = headers or {}
            signature = params.get("signature") or hdrs.get("x-federation-signature") or ""
            timestamp_str = params.get("timestamp") or hdrs.get("x-federation-timestamp") or "0"
            try:
                timestamp = int(timestamp_str)
            except ValueError:
                timestamp = 0

            if not zkp_y or not signature or not timestamp:
                return {"error": "Missing threat intel parameters"}

            # Anti-replay (5 minutes safety window)
            now_ms = int(time.time() * 1000)
            if abs(now_ms - timestamp) > 300000:
                return {"error": "Message expired or clock skew too high"}

            secret = params.get("federationSecret") or os.environ.get("POW_SECRET") or "fallback-dev-secret-32-chars-minimum"
            msg = f"{timestamp}:{zkp_y}"
            expected_sig = hmac.new(secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()

            if not hmac.compare_digest(expected_sig, signature):
                return {"error": "Invalid federation signature"}

            # Ban the ZKP public key for 30 days
            await store.set(f"banned-zkp-y:{zkp_y}", True, 86400 * 30)
            return {"status": "synchronized"}

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
        max_bits = cpu_config.get("maxDifficultyBits", 22)
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

        import struct
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
        """
        Vérifie le limiteur de débit Token Bucket pour les demandes de challenge d'un sous-réseau par domaine.
        """
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

        rate_limit_data = await store.get(key)
        if not rate_limit_data:
            rate_limit_data = {"tokens": capacity, "lastRefill": now}

        elapsed = max(0.0, now - rate_limit_data.get("lastRefill", now))
        tokens = min(capacity, float(rate_limit_data.get("tokens", capacity)) + elapsed * refill_rate)
        ttl = max(60, int(math.ceil(capacity / max(0.1, refill_rate))))

        if tokens < 1.0:
            await store.set(key, {"tokens": tokens, "lastRefill": now}, ttl)
            return False

        await store.set(key, {"tokens": tokens - 1.0, "lastRefill": now}, ttl)
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
    def calculate_analog_inconsistency_score(
        consistency_score: float,
        inflection_point: float = 0.72,
        steepness: float = 12.0
    ) -> float:
        """
        Calcule un score d'incohérence analogique et lisse (sigmoïde continue),
        plafonnant à une asymptote stricte de 99.9.
        """
        s = max(0.0, min(1.0, float(consistency_score)))
        if s >= 0.98:
            return 0.0

        asymptote = 99.9
        raw = 1.0 / (1.0 + math.exp(steepness * (s - inflection_point)))
        min_val = 1.0 / (1.0 + math.exp(steepness * (1.0 - inflection_point)))
        max_val = 1.0 / (1.0 + math.exp(steepness * (0.0 - inflection_point)))
        normalized = ((raw - min_val) / (max_val - min_val)) * asymptote
        return min(asymptote, round(normalized, 1))

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
    def get_protocol_anomaly_score(context: RequestContext) -> Dict[str, float]:
        http2_anomaly = 0.0
        ua = context.headers.get("user-agent", "")
        ua_parts = RequestUtils.parse_user_agent(ua)
        browser = ua_parts.get("browser") or ""

        h2_fp = context.headers.get("x-http2-fingerprint") or getattr(context, "http2_fingerprint", None)
        if browser and h2_fp and isinstance(h2_fp, str):
            parts = h2_fp.split("|")
            if len(parts) >= 4:
                try:
                    conn_window = int(parts[1])
                except ValueError:
                    conn_window = 0
                header_order = parts[3].strip().lower()
                is_chromium = browser.startswith("Chrome") or browser.startswith("Edge")
                is_firefox = browser.startswith("Firefox")
                is_safari = browser.startswith("Safari")

                if is_chromium:
                    if header_order and header_order != "m,a,s,p":
                        http2_anomaly += 60.0
                    if conn_window in (65535, 65536):
                        http2_anomaly += 40.0
                elif is_firefox:
                    if header_order and header_order != "m,s,p,a":
                        http2_anomaly += 60.0
                elif is_safari:
                    if header_order and header_order != "m,s,p,a":
                        http2_anomaly += 60.0

        quic_res = RequestUtils.get_quic_anomaly_score(context)
        quic_anomaly = quic_res.get("quicAnomalyScore", 0.0)
        proto_score = max(0.0, min(100.0, http2_anomaly), min(100.0, quic_anomaly))
        return {
            "protocolAnomalyScore": proto_score,
            "http2AnomalyScore": min(100.0, http2_anomaly),
            "quicAnomalyScore": quic_anomaly
        }

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
        frame_order_raw = parts[3] if len(parts) > 3 else (context.headers.get("x-quic-frame-order") or "")
        frame_order = [s.strip().lower() for s in frame_order_raw.split(",") if s.strip()]

        ua = context.headers.get("user-agent", "")
        ua_parts = RequestUtils.parse_user_agent(ua)
        browser = ua_parts.get("browser") or ""

        if not browser:
            return {"quicAnomalyScore": 0.0}

        is_chromium = browser.startswith("Chrome") or browser.startswith("Edge")
        is_firefox = browser.startswith("Firefox")
        is_safari = browser.startswith("Safari")

        try:
            max_data = int(params.get("1") or params.get("0x01") or "0")
            max_streams = int(params.get("4") or params.get("8") or params.get("0x08") or "0")
            bidi_local = int(params.get("5") or params.get("0x05") or "0")
            bidi_remote = int(params.get("6") or params.get("0x06") or "0")
        except ValueError:
            max_data, max_streams, bidi_local, bidi_remote = 0, 0, 0, 0

        anomaly = 0.0
        if is_chromium:
            if max_data > 0 and max_data < 1048576:
                anomaly += 40.0
            if max_streams > 0 and max_streams != 100:
                anomaly += 30.0
            if priority_order and "u=" not in priority_order:
                anomaly += 30.0

            # Contrôle de flux bidi (Chromium alloue 6MB = 6291456 ou au minimum 512 Ko)
            # curl-impersonate / quiche alloue 256 Ko (262144) ou 128 Ko (131072)
            if bidi_local > 0 and (bidi_local < 524288 or bidi_local == 262144):
                anomaly += 40.0
            if bidi_remote > 0 and (bidi_remote < 524288 or bidi_remote == 262144):
                anomaly += 30.0

            # Ordre des trames de contrôle QUIC (SETTINGS, MAX_STREAMS, PRIORITY)
            if len(frame_order) >= 2:
                s_idx = next((i for i, f in enumerate(frame_order) if f in ("s", "settings", "4")), -1)
                m_idx = next((i for i, f in enumerate(frame_order) if f in ("m", "max_streams", "18")), -1)
                p_idx = next((i for i, f in enumerate(frame_order) if f in ("p", "priority", "priority_update", "15")), -1)

                if s_idx != 0 and s_idx != -1:
                    anomaly += 50.0  # SETTINGS doit impérativement être la 1ère trame
                if m_idx != -1 and s_idx != -1 and m_idx < s_idx:
                    anomaly += 60.0  # MAX_STREAMS envoyé avant SETTINGS (curl/quiche)
                if p_idx != -1 and s_idx != -1 and p_idx < s_idx:
                    anomaly += 60.0
        elif is_firefox:
            if max_data > 0 and max_data > 5000000:
                anomaly += 40.0
            if max_streams == 100:
                anomaly += 50.0
            if bidi_local == 6291456:
                anomaly += 50.0
            if len(frame_order) >= 2:
                s_idx = next((i for i, f in enumerate(frame_order) if f in ("s", "settings", "4")), -1)
                if s_idx != 0 and s_idx != -1:
                    anomaly += 50.0
        elif is_safari:
            if max_streams == 100 and max_data == 1572864 and "u=2,i" in priority_order:
                anomaly += 60.0  # Usurpation profil Cronet
            if bidi_local == 6291456:
                anomaly += 50.0
            if len(frame_order) >= 2:
                s_idx = next((i for i, f in enumerate(frame_order) if f in ("s", "settings", "4")), -1)
                m_idx = next((i for i, f in enumerate(frame_order) if f in ("m", "max_streams")), -1)
                if m_idx != -1 and (m_idx == 0 or (s_idx != -1 and m_idx < s_idx)):
                    anomaly += 50.0

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
        if metrics.get("prototypeTampered"):
            score += 80.0
        touch_history = metrics.get("touchMovementsHistory") or []
        mouse_analysis = RequestUtils.analyze_mouse_movements(metrics.get("mouseMovementsHistory"))
        touch_analysis = RequestUtils.analyze_touch_movements(touch_history)
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

        # NOUVEAU: Analyse de digraphie/trigraphie (dwell & flight times)
        dwell_times = metrics.get("keystrokeDwellTimes") or []
        flight_times = metrics.get("keystrokeFlightTimes") or []

        if len(dwell_times) >= 5:
            mean_dwell = sum(dwell_times) / len(dwell_times)
            var_dwell = sum((t - mean_dwell) ** 2 for t in dwell_times) / len(dwell_times)
            std_dev_dwell = math.sqrt(var_dwell)

            if std_dev_dwell < 2.0:
                score += 35.0
            if mean_dwell < 15.0:
                score += 25.0

        if len(flight_times) >= 5:
            times = [f.get("time") for f in flight_times if f.get("time") is not None]
            if len(times) >= 5:
                mean_flight = sum(times) / len(times)
                var_flight = sum((t - mean_flight) ** 2 for t in times) / len(times)
                std_dev_flight = math.sqrt(var_flight)

                if std_dev_flight < 3.0:
                    score += 35.0
                if mean_flight < 25.0:
                    score += 25.0
                benford_dev = Optimization.benford_test(times)
                if benford_dev > 0.18:
                    score += 30.0

        if len(mouse_analysis["segments"]) > 10:
            benford_deviation = Optimization.benford_test(mouse_analysis["segments"])
            if benford_deviation > 0.18: score += 35.0

        # Détection de ferme mobile : Touch actif sur mobile sans aucune vibration physique (châssis/rack ADB)
        ua = context.headers.get("user-agent", "")
        is_mobile_device = "Mobile" in ua
        motion_variance = metrics.get("motionVariance")
        if is_mobile_device and len(touch_history) >= 5 and isinstance(motion_variance, (int, float)):
            if motion_variance == 0:
                score += 50.0
        return min(100.0, score)

    @staticmethod
    def get_virtualization_anomaly_score(context: RequestContext) -> float:
        """
        Détecte si le navigateur s'exécute dans un environnement virtuel ou headless
        (commun pour les bots hébergés directement sur des serveurs proxy résidentiels).
        """
        client_fp = context.headers.get("x-device-fingerprint")
        if not client_fp:
            return 0.0
            
        try:
            fp_map = dict(part.split(":", 1) for part in client_fp.split("|") if ":" in part)
        except Exception:
            return 0.0
            
        score = 0.0
        client_gpu_hash = fp_map.get("gpu")
        
        if client_gpu_hash:
            # Liste de renderers virtuels ou logiciels couramment utilisés en environnement automatisé / VPS
            virtual_gpus = [
                "Google SwiftShader",
                "SwiftShader",
                "Mesa llvmpipe",
                "llvmpipe",
                "Mesa Gallium",
                "Microsoft Basic Render Driver",
                "HeadlessChrome",
                "Intel(R) HD Graphics" # Souvent usurpé ou émulé par défaut
            ]
            # Génération dynamique des hashes cyrb53 correspondants pour comparaison sans faille
            virtual_gpu_hashes = {str(cyrb53(gpu)) for gpu in virtual_gpus}
            
            if client_gpu_hash in virtual_gpu_hashes:
                # Le client utilise un moteur de rendu graphique virtuel ou logiciel !
                score += 75.0

        # Détection de résolutions d'écran caractéristiques d'instances headless Docker/VNC (ex: 800x600 ou 1024x768 par défaut)
        client_screen_hash = fp_map.get("scr")
        if client_screen_hash:
            headless_resolutions = {"800x600_24", "1024x768_24"}
            headless_hashes = {str(cyrb53(res)) for res in headless_resolutions}
            if client_screen_hash in headless_hashes:
                score += 25.0
                
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
    def _decay_subnet_data(subnet_data: dict, now: int) -> bool:
        inactivity_sec = now - subnet_data.get("lastActivity", now)
        half_lives = int(math.floor(inactivity_sec / 1800))
        if half_lives > 0:
            decay = 2 ** half_lives
            subnet_data["highScoreCount"] = max(0, int(math.floor(subnet_data.get("highScoreCount", 0) / decay)))

            if "highScoreDevices" in subnet_data:
                to_remove = []
                for fp_id, val in subnet_data["highScoreDevices"].items():
                    decayed_val = int(math.floor(val / decay))
                    if decayed_val <= 0:
                        to_remove.append(fp_id)
                    else:
                        subnet_data["highScoreDevices"][fp_id] = decayed_val
                for fp_id in to_remove:
                    del subnet_data["highScoreDevices"][fp_id]

            if "deviceIds" in subnet_data:
                new_len = max(0, int(math.floor(len(subnet_data["deviceIds"]) / decay)))
                subnet_data["deviceIds"] = subnet_data["deviceIds"][:new_len]

            if "ips" in subnet_data:
                new_len = max(0, int(math.floor(len(subnet_data["ips"]) / decay)))
                subnet_data["ips"] = subnet_data["ips"][:new_len]

            if "uas" in subnet_data:
                new_len = max(0, int(math.floor(len(subnet_data["uas"]) / decay)))
                subnet_data["uas"] = subnet_data["uas"][:new_len]

            if "attackerIps" in subnet_data and isinstance(subnet_data["attackerIps"], list):
                max_attacker_age_sec = 3600
                subnet_data["attackerIps"] = [a for a in subnet_data["attackerIps"] if (now - a.get("lastSeen", now)) < max_attacker_age_sec]

            subnet_data["lastActivity"] = now - (inactivity_sec % 1800)
            return True
        return False

    @staticmethod
    async def update_subnet_metrics(store, context: RequestContext, device_id: str, final_score: float) -> None:
        if isinstance(context, str):
            client_ip = context
            user_agent = ""
        else:
            client_ip = getattr(context, "client_ip", "")
            headers = getattr(context, "headers", None)
            user_agent = headers.get("user-agent", "") if (headers and hasattr(headers, "get")) else ""

        subnet = get_ip_subnet(client_ip)
        if not subnet: return
        key = f"subnet:{subnet}"
        subnet_data = await store.get(key) or {
            "highScoreCount": 0,
            "deviceIds": [],
            "highScoreDevices": {},
            "lastActivity": 0,
            "ips": [],
            "uas": [],
            "attackerIps": []
        }
        subnet_data.setdefault("highScoreDevices", {})
        subnet_data.setdefault("ips", [])
        subnet_data.setdefault("uas", [])
        subnet_data.setdefault("attackerIps", [])
        now = int(time.time())
        RequestUtils._decay_subnet_data(subnet_data, now)

        current_contributions = subnet_data["highScoreDevices"].get(device_id, 0)

        # OPTIMISATION : Cap strict à 1 pénalité maximum par appareil unique stable
        # pour éviter qu'une seule machine mal configurée ne sature le sous-réseau.
        if current_contributions < 1 and final_score < 95:
            subnet_data["highScoreDevices"][device_id] = current_contributions + 1
            subnet_data["highScoreCount"] += 1

        if device_id not in subnet_data["deviceIds"]:
            subnet_data["deviceIds"].append(device_id)

        if client_ip not in subnet_data["ips"]:
            subnet_data["ips"].append(client_ip)

        if user_agent and user_agent not in subnet_data["uas"]:
            subnet_data["uas"].append(user_agent)

        is_confirmed_cluster_attack = (len(subnet_data["deviceIds"]) > 1 and final_score >= 70) or final_score >= 95
        if is_confirmed_cluster_attack:
            existing_attacker = next((a for a in subnet_data["attackerIps"] if a.get("ip") == client_ip), None)
            if existing_attacker:
                existing_attacker["lastSeen"] = now
                existing_attacker["score"] = max(existing_attacker.get("score", 0.0), final_score)
            else:
                subnet_data["attackerIps"].append({"ip": client_ip, "lastSeen": now, "score": final_score})
                if len(subnet_data["attackerIps"]) > 30:
                    subnet_data["attackerIps"].pop(0)

        subnet_data["lastActivity"] = now
        if len(subnet_data["deviceIds"]) > 100:
            old_device_id = subnet_data["deviceIds"].pop(0)
            if old_device_id in subnet_data["highScoreDevices"]:
                old_contrib = subnet_data["highScoreDevices"].pop(old_device_id)
                subnet_data["highScoreCount"] = max(0, subnet_data["highScoreCount"] - old_contrib)
        if len(subnet_data["ips"]) > 100:
            subnet_data["ips"].pop(0)
        if len(subnet_data["uas"]) > 50:
            subnet_data["uas"].pop(0)
        await store.set(key, subnet_data, 86400)

    @staticmethod
    async def get_subnet_score(store, client_ip_or_context: str, current_device_id: str, security_config: Optional[Dict[str, Any]] = None) -> Dict[str, float]:
        if isinstance(client_ip_or_context, str):
            client_ip = client_ip_or_context
        else:
            client_ip = getattr(client_ip_or_context, "client_ip", "")

        subnet = get_ip_subnet(client_ip)
        if not subnet: return {"subnetScore": 0.0}
        key = f"subnet:{subnet}"
        subnet_data = await store.get(key)
        if not subnet_data: return {"subnetScore": 0.0}
        now = int(time.time())
        if RequestUtils._decay_subnet_data(subnet_data, now):
            await store.set(key, subnet_data, 86400)
            
        high_score_count = subnet_data.get("highScoreCount", 0)
        device_ids = subnet_data.get("deviceIds", [])
        device_count = len(device_ids)
        ips = subnet_data.get("ips", [])
        ip_count = len(ips) if ips else 1
        uas = subnet_data.get("uas", [])
        ua_count = len(uas) if uas else 1

        if device_count <= 1 and high_score_count <= 1:
            return {"subnetScore": 0.0}

        # 1. Estimation Bayésienne de densité (évite les sur-réactions sur de faibles échantillons)
        bayesian_density = (high_score_count + 0.5) / (device_count + 2.5)

        # 2. Dispersion IP / Terminal (CGNAT vs Proxy Pool distribué)
        ip_dispersion = min(2.0, ip_count / device_count)
        ip_multiplier = 0.6 + 0.4 * math.tanh(ip_dispersion)

        # 3. Volatilité des User-Agents (rotation de navigateurs sur matériel identique)
        ua_dispersion = min(3.0, max(1, ua_count) / device_count)
        ua_multiplier = 0.7 + 0.3 * math.tanh(ua_dispersion - 1.0)

        # 4. Intensité continue de la menace (sans seuil abrupt ni dérivée nulle)
        raw_threat_intensity = high_score_count * bayesian_density * ip_multiplier * ua_multiplier

        # 5. Composante 1 : Score ambiant plafonné au seuil Medium (par défaut 45.0)
        medium_threshold = 45.0
        if security_config and "thresholds" in security_config and "medium" in security_config["thresholds"]:
            try:
                medium_threshold = float(security_config["thresholds"]["medium"])
            except (ValueError, TypeError):
                medium_threshold = 45.0
        ambient_asymptote = medium_threshold
        max_proximity_boost = max(0.0, 100.0 - ambient_asymptote)
        scale_factor = 10.0
        ambient_score = ambient_asymptote * math.tanh(raw_threat_intensity / scale_factor)

        # 6. Composante 2 : Boost de proximité micro-réseau avec des attaquants récents
        proximity_boost = 0.0
        attacker_ips = subnet_data.get("attackerIps", [])
        if attacker_ips and client_ip:
            max_common_prefix = 0
            is_client_v4 = "." in client_ip
            is_client_v6 = ":" in client_ip

            for att in attacker_ips:
                att_ip = att.get("ip")
                if att_ip and (now - att.get("lastSeen", now)) <= 1800:
                    prefix_len = get_ip_common_prefix_length(client_ip, att_ip)
                    if prefix_len > max_common_prefix:
                        max_common_prefix = prefix_len

            if is_client_v4:
                if max_common_prefix >= 32:
                    proximity_boost = max_proximity_boost
                elif max_common_prefix >= 30:
                    proximity_boost = max_proximity_boost * (45.0 / 55.0)
                elif max_common_prefix >= 28:
                    proximity_boost = max_proximity_boost * (30.0 / 55.0)
                elif max_common_prefix >= 26:
                    proximity_boost = max_proximity_boost * (15.0 / 55.0)
            elif is_client_v6:
                if max_common_prefix >= 128:
                    proximity_boost = max_proximity_boost
                elif max_common_prefix >= 120:
                    proximity_boost = max_proximity_boost * (45.0 / 55.0)
                elif max_common_prefix >= 112:
                    proximity_boost = max_proximity_boost * (30.0 / 55.0)
                elif max_common_prefix >= 96:
                    proximity_boost = max_proximity_boost * (15.0 / 55.0)

        final_score = min(100.0, round((ambient_score + proximity_boost) * 10.0) / 10.0)
        return {"subnetScore": final_score}

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
        user_agent = context.headers.get("user-agent", "")
        subnet = get_ip_subnet(context.client_ip) or "unknown"

        cluster_data = RequestUtils._botnet_clusters.get(stable_fp_hash, [])
        if not isinstance(cluster_data, list):
            cluster_data = []

        cluster_data = [entry for entry in cluster_data if entry.get("timestamp", 0) > ten_minutes_ago]

        found = False
        for entry in cluster_data:
            if entry.get("ip") == context.client_ip:
                entry["timestamp"] = now
                entry["ua"] = user_agent
                entry["subnet"] = subnet
                found = True
                break

        if not found:
            cluster_data.append({
                "ip": context.client_ip,
                "timestamp": now,
                "ua": user_agent,
                "subnet": subnet
            })

        RequestUtils._botnet_clusters[stable_fp_hash] = cluster_data

        unique_ips_count = len(cluster_data)
        botnet_cluster_score = 0.0
        if unique_ips_count >= 2:
            unique_subnets = len(set(e.get("subnet") for e in cluster_data))
            unique_user_agents = len(set(e.get("ua") for e in cluster_data if e.get("ua")))
            subnet_multiplier = 1.3 if unique_subnets > 1 else 0.6
            ua_rotation_multiplier = 1.5 if unique_user_agents > 1 else 1.0
            base_score = 100.0 * (1.0 - math.exp(-0.35 * (unique_ips_count - 1)))
            botnet_cluster_score = min(100.0, round(base_score * subnet_multiplier * ua_rotation_multiplier * 10.0) / 10.0)

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
    def read_var_int(data: bytes, offset: int) -> tuple:
        if offset >= len(data):
            return None, offset
        first = data[offset]
        prefix = first >> 6
        first_val = first & 0x3f
        if prefix == 0:
            return first_val, offset + 1
        elif prefix == 1:
            if offset + 2 > len(data):
                return None, offset
            val = (first_val << 8) | data[offset + 1]
            return val, offset + 2
        elif prefix == 2:
            if offset + 4 > len(data):
                return None, offset
            val = (first_val << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3]
            return val, offset + 4
        else:
            if offset + 8 > len(data):
                return None, offset
            val = first_val
            for i in range(1, 8):
                val = (val << 8) | data[offset + i]
            return val, offset + 8

    @staticmethod
    def parse_quic_transport_parameters(data: bytes) -> Dict[int, Any]:
        params = {}
        offset = 0
        length = len(data)
        while offset < length:
            param_id, offset = TLSClientHelloParser.read_var_int(data, offset)
            if param_id is None:
                break
            param_len, offset = TLSClientHelloParser.read_var_int(data, offset)
            if param_len is None or offset + param_len > length:
                break
            param_val_bytes = data[offset:offset + param_len]
            offset += param_len
            if param_len > 0 and param_id in (1, 3, 4, 5, 6, 7, 8, 9, 11, 14):
                val, _ = TLSClientHelloParser.read_var_int(param_val_bytes, 0)
                params[param_id] = val if val is not None else param_val_bytes.hex()
            else:
                params[param_id] = param_val_bytes.hex()
        return params

    @staticmethod
    def parse_quic_control_frames(stream_data: bytes) -> Dict[str, Any]:
        frames = []
        frame_order = []
        settings = {}
        offset = 0
        length = len(stream_data)
        if length == 0:
            return {"frames": [], "frame_order": "", "settings": {}}

        if stream_data[0] == 0x00:
            offset = 1

        while offset < length:
            frame_type, offset = TLSClientHelloParser.read_var_int(stream_data, offset)
            if frame_type is None:
                break
            frame_len, offset = TLSClientHelloParser.read_var_int(stream_data, offset)
            if frame_len is None or offset + frame_len > length:
                break
            payload = stream_data[offset:offset + frame_len]
            offset += frame_len

            abbr = "s" if frame_type == 0x04 else (
                "m" if frame_type in (0x12, 0x02) else (
                    "p" if frame_type in (0x0f, 0xaf, 0xf0700) else (
                        "d" if frame_type in (0x10, 0x0d) else (
                            "g" if frame_type == 0x07 else "u"
                        )
                    )
                )
            )
            frames.append({"type": frame_type, "length": frame_len})
            frame_order.append(abbr)

            if frame_type == 0x04:
                s_offset = 0
                s_len = len(payload)
                while s_offset < s_len:
                    s_id, s_offset = TLSClientHelloParser.read_var_int(payload, s_offset)
                    if s_id is None:
                        break
                    s_val, s_offset = TLSClientHelloParser.read_var_int(payload, s_offset)
                    if s_val is None:
                        break
                    settings[s_id] = s_val

        return {
            "frames": frames,
            "frame_order": ",".join(frame_order),
            "settings": settings
        }

    @staticmethod
    def format_quic_fingerprint(params: Dict[int, Any], priority: str = "", frame_order: str = "") -> str:
        param_parts = [f"{k}={v}" for k, v in params.items()]
        fp = "1;" + ",".join(param_parts)
        if priority or frame_order:
            fp += f";{priority}"
        if frame_order:
            fp += f";{frame_order}"
        return fp
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
        sig_algs, supported_versions = [], []
        has_sni = False
        alpn_protocol = ""
        quic_params = None
        ext_limit = offset + extensions_len
        while offset < ext_limit and offset + 4 <= length:
            ext_type = struct.unpack("!H", binary[offset:offset+2])[0]
            ext_len = struct.unpack("!H", binary[offset+2:offset+4])[0]
            offset += 4
            if offset + ext_len > length:
                break
            extensions.append(ext_type)
            if ext_type == 0:
                has_sni = True
            elif ext_type == 10 and ext_len >= 2:
                curves_len = struct.unpack("!H", binary[offset:offset+2])[0]
                curves.extend(struct.unpack(f"!{curves_len//2}H", binary[offset+2:offset+2+curves_len]))
            elif ext_type == 11 and ext_len >= 1:
                points_len = binary[offset]
                points.extend(binary[offset+1:offset+1+points_len])
            elif ext_type == 13 and ext_len >= 2:
                if offset + 2 <= length:
                    sig_algs_len = struct.unpack("!H", binary[offset:offset+2])[0]
                    for j in range(2, sig_algs_len + 2, 2):
                        if offset + j + 2 <= length and j + 2 <= ext_len:
                            sig_algs.append(struct.unpack("!H", binary[offset+j:offset+j+2])[0])
            elif ext_type == 16 and ext_len >= 3:
                if offset + 2 <= length:
                    alpn_list_len = struct.unpack("!H", binary[offset:offset+2])[0]
                    if ext_len >= 2 + alpn_list_len and offset + 2 + alpn_list_len <= length:
                        alpn_str_len = binary[offset + 2]
                        if alpn_list_len >= 1 + alpn_str_len:
                            alpn_protocol = binary[offset + 3:offset + 3 + alpn_str_len].decode("latin1", errors="ignore")
            elif ext_type == 43 and ext_len >= 1:
                if offset + 1 <= length:
                    versions_len = binary[offset]
                    for j in range(1, versions_len + 1, 2):
                        if offset + j + 2 <= length and j + 2 <= ext_len:
                            supported_versions.append(struct.unpack("!H", binary[offset+j:offset+j+2])[0])
            elif ext_type == 57 or ext_type == 0xffa5:
                if ext_len > 0 and offset + ext_len <= length:
                    quic_data = binary[offset:offset + ext_len]
                    quic_params = TLSClientHelloParser.parse_quic_transport_parameters(quic_data)
            offset += ext_len

        filter_grease = lambda arr: [v for v in arr if v not in TLSClientHelloParser.GREASE_VALUES]
        clean_ciphers = filter_grease(ciphers)
        clean_extensions = filter_grease(extensions)
        clean_curves = filter_grease(curves)
        clean_points = filter_grease(points)
        clean_sig_algs = filter_grease(sig_algs)
        clean_supported_versions = filter_grease(supported_versions)

        ssl_version = struct.unpack("!H", binary[9:11])[0]
        ja3_string = f"{ssl_version},{'-'.join(map(str, clean_ciphers))},{'-'.join(map(str, clean_extensions))},{'-'.join(map(str, clean_curves))},{'-'.join(map(str, clean_points))}"
        
        # Calcul natif de JA4
        highest_version = ssl_version
        if clean_supported_versions:
            highest_version = max(clean_supported_versions)
        
        ja4_version = "12"
        if highest_version == 0x0304:
            ja4_version = "13"
        elif highest_version == 0x0303:
            ja4_version = "12"
        elif highest_version == 0x0302:
            ja4_version = "11"
        elif highest_version == 0x0301:
            ja4_version = "10"
            
        sni_status = "d" if has_sni else "i"
        num_ciphers = min(99, len(clean_ciphers))
        num_extensions = min(99, len(clean_extensions))
        
        ja4_alpn = "00"
        if alpn_protocol:
            len_alpn = len(alpn_protocol)
            if len_alpn == 1:
                ja4_alpn = alpn_protocol + alpn_protocol
            else:
                ja4_alpn = alpn_protocol[0] + alpn_protocol[-1]
                
        ja4_a = f"t{ja4_version}{sni_status}{num_ciphers:02d}{num_extensions:02d}{ja4_alpn}"
        
        sorted_ciphers = sorted(clean_ciphers)
        ciphers_hex = [f"{c:04x}" for c in sorted_ciphers]
        ciphers_str = ",".join(ciphers_hex)
        ja4_b = hashlib.sha256(ciphers_str.encode("utf-8")).hexdigest()[:12]
        
        sorted_extensions = sorted(clean_extensions)
        extensions_hex = [f"{e:04x}" for e in sorted_extensions]
        extensions_str = ",".join(extensions_hex)
        
        sorted_sig_algs = sorted(clean_sig_algs)
        sig_algs_hex = [f"{s:04x}" for s in sorted_sig_algs]
        sig_algs_str = ",".join(sig_algs_hex)
        
        ja4_c_input = f"{extensions_str}_{sig_algs_str}"
        ja4_c = hashlib.sha256(ja4_c_input.encode("utf-8")).hexdigest()[:12]
        
        ja4_hash = f"{ja4_a}_{ja4_b}_{ja4_c}"

        result = {
            "ja3_string": ja3_string,
            "ja3_hash": hashlib.md5(ja3_string.encode("utf-8")).hexdigest(),
            "ja4_raw": ja4_hash
        }
        if quic_params is not None:
            result["quic_params"] = quic_params
            result["quic_fp"] = TLSClientHelloParser.format_quic_fingerprint(quic_params)
        return result


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
            style_options = [
                "position:absolute; left:-9999px; top:-9999px; transform:scale(0); opacity:0; pointer-events:none;",
                "position:fixed; left:-8888px; top:-8888px; width:0; height:0; overflow:hidden; opacity:0; pointer-events:none;",
                "display:none; visibility:hidden; pointer-events:none;"
            ]
            styles = random.choice(style_options)
            container_tags = ["div", "span", "p", "section"]
            tag = random.choice(container_tags)
            from html import escape
            f_name = escape(field_name)
            nesting_type = random.randint(0, 1)
            if nesting_type == 1:
                return f'<{tag} style="{styles}" aria-hidden="true"><label for="{f_name}">{f_name}<input type="text" id="{f_name}" name="{f_name}" tabindex="-1" autocomplete="off"></label></{tag}>'
            return f'<{tag} style="{styles}" aria-hidden="true"><label for="{f_name}">{f_name}</label><input type="text" id="{f_name}" name="{f_name}" tabindex="-1" autocomplete="off"></{tag}>'

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
        self.initialize_ed25519_keys(config)

        self.config = config
        if not self.config.get("whitelist"):
            self.config["whitelist"] = default_whitelist()

        self.store = store
        self.thresholds = config.get("thresholds", {"low": 20, "medium": 45, "high": 75, "block": 95})
        self.weights = copy.deepcopy(DEFAULT_WEIGHTS)
        if "weights" in config and isinstance(config["weights"], dict):
            self.weights.update(config["weights"])
        self.dry_run = config.get("dryRun", False)
        self._allowlist = self._build_allowlist()

        # Bouclier thermique local (Fast-Path Cache) pour amortir les attaques de masse
        # Format: {"ip_or_subnet": (expiration_timestamp, action_to_take)}
        self._fast_path_cache: Dict[str, tuple] = {}
        self._last_prune_time: float = time.time()
        self._prune_interval: float = 10.0 # secondes
        self.problem_manager = None

        if config.get("enableUsefulWork"):
            try:
                default_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../config/problems.config.json"))
                config_path = config.get("usefulWorkConfigPath") or (default_path if os.path.exists(default_path) else None)
                if config_path:
                    self.problem_manager = ProblemManager.get_instance(config_path, self.store)
            except Exception as e:
                print(f"[FingerprintEngine] Background initialization of ProblemManager failed: {e}")

    def initialize_ed25519_keys(self, config: Dict[str, Any]) -> None:
        # Bind Ed25519 keys if passed via config
        if config.get("ed25519_private_key"):
            os.environ["ED25519_PRIVATE_KEY"] = config["ed25519_private_key"]
        if config.get("ed25519_public_key"):
            os.environ["ED25519_PUBLIC_KEY"] = config["ed25519_public_key"]

        # Auto-generate Ed25519 key pair on load if indicated and keys are not set
        if (config.get("useAsymmetricTickets") or config.get("ed25519") == "auto") and not os.environ.get("ED25519_PRIVATE_KEY"):
            try:
                from cryptography.hazmat.primitives.asymmetric import ed25519
                from cryptography.hazmat.primitives import serialization

                private_key = ed25519.Ed25519PrivateKey.generate()
                private_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode("utf-8")

                public_key = private_key.public_key()
                public_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode("utf-8")

                os.environ["ED25519_PRIVATE_KEY"] = private_pem
                os.environ["ED25519_PUBLIC_KEY"] = public_pem
            except Exception as e:
                print(f"[Fingerprint] Native Ed25519 key generation failed: {e}")

    def _build_allowlist(self) -> BlockList:
         block_list = BlockList()
         whitelist_rules = self.config.get("whitelist", [])
         for rule in whitelist_rules:
            if rule.get("type") == "allowlist" and rule.get("entries"):
                for entry in rule["entries"]:
                    block_list.add(entry)
         return block_list
 
    def _is_ip_in_allowlist(self, client_ip: str) -> bool:
         return self._allowlist.check(client_ip)
 
    def _is_path_in_allowlist(self, request_path: str) -> bool:
         whitelist_rules = self.config.get("whitelist", [])
         path_rule = next((r for r in whitelist_rules if r.get("type") == "path_allowlist"), None)
         if not path_rule or not path_rule.get("entries"):
             return False
 
         for entry in path_rule["entries"]:
             if entry.endswith("*"):
                 base = entry[:-1]
                 if request_path.startswith(base):
                     return True
             elif request_path == entry:
                 return True
         return False
 
    def _is_host_path_in_allowlist(self, request_host: Optional[str], request_path: str) -> bool:
         if not request_host:
             return False
         whitelist_rules = self.config.get("whitelist", [])
         host_path_rule = next((r for r in whitelist_rules if r.get("type") == "host_path_allowlist"), None)
         if not host_path_rule or not host_path_rule.get("entries"):
             return False
 
         for entry in host_path_rule["entries"]:
             if "/" not in entry:
                 continue
             first_slash = entry.index("/")
             host_pattern = entry[:first_slash]
             path_pattern = entry[first_slash:]
 
             if request_host != host_pattern:
                 continue
 
             if path_pattern.endswith("*"):
                 base = path_pattern[:-1]
                 if request_path.startswith(base):
                     return True
             elif request_path == path_pattern:
                 return True
         return False
 
    def _is_graphql_operation_in_allowlist(self, operation_type: Optional[str], operation_name: Optional[str]) -> bool:
         if not operation_type or not operation_name:
             return False
         whitelist_rules = self.config.get("whitelist", [])
         graphql_rule = next((r for r in whitelist_rules if r.get("type") == "graphql_operation_allowlist"), None)
         if not graphql_rule or not graphql_rule.get("entries"):
             return False
 
         for entry in graphql_rule["entries"]:
             if ":" not in entry:
                 continue
             entry_type, entry_name = entry.split(":", 1)
             if entry_type != operation_type:
                 continue
             if entry_name == operation_name or entry_name == "*":
                 return True
             if entry_name.endswith("*") and operation_name.startswith(entry_name[:-1]):
                 return True
         return False
 
    async def _verify_whitelisted_bot(self, context: RequestContext) -> bool:
         whitelist_rules = self.config.get("whitelist", [])
         bot_rules = [rule for rule in whitelist_rules if "hostnameSuffix" in rule]
         if not bot_rules:
             return False
 
         user_agent = context.headers.get("user-agent", "")
         matched_rule = None
         for rule in bot_rules:
             if "userAgent" in rule:
                 try:
                     if re.search(rule["userAgent"], user_agent):
                         matched_rule = rule
                         break
                 except Exception:
                     pass
 
         if matched_rule is None:
             return False
 
         cache_key = f"ip-whitelist:{context.client_ip}"
         cached_status = await self.store.get(cache_key)
 
         if cached_status == "verified":
             return True
         if cached_status == "failed":
             return False
 
         if not can_attempt_dns():
             return False

         import socket
         try:
             # 1. Reverse DNS lookup with strict 500ms timeout
             loop = asyncio.get_running_loop()
             try:
                 hostname, _, _ = await asyncio.wait_for(
                     loop.run_in_executor(None, socket.gethostbyaddr, context.client_ip),
                     timeout=0.5
                 )
             except (asyncio.TimeoutError, Exception):
                 record_dns_failure()
                 await self.store.set(cache_key, "failed", 300) # Temporary negative caching (5 minutes)
                 return False

             if not hostname or hostname == context.client_ip:
                 await self.store.set(cache_key, "failed", 300) # Temporary negative caching (5 minutes)
                 return False
 
             if not hostname.endswith(matched_rule["hostnameSuffix"]):
                 await self.store.set(cache_key, "failed", 300) # Temporary negative caching (5 minutes)
                 return False
 
             # 2. Forward DNS lookup with strict 500ms timeout
             try:
                 addr_infos = await asyncio.wait_for(
                     loop.run_in_executor(None, socket.getaddrinfo, hostname, None),
                     timeout=0.5
                 )
             except (asyncio.TimeoutError, Exception):
                 record_dns_failure()
                 await self.store.set(cache_key, "failed", 300) # Temporary negative caching (5 minutes)
                 return False

             ips = {info[4][0] for info in addr_infos}
 
             if context.client_ip in ips:
                 record_dns_success()
                 await self.store.set(cache_key, "verified", 86400)
                 return True
         except Exception:
             record_dns_failure()
             await self.store.set(cache_key, "failed", 300) # Temporary negative caching (5 minutes)
             return False
 
         await self.store.set(cache_key, "failed", 300) # Temporary negative caching (5 minutes)
         return False
 
    async def _check_allowlists(self, context: RequestContext) -> bool:
         if self._is_ip_in_allowlist(context.client_ip):
             return True
         if self._is_path_in_allowlist(context.path):
             return True
         if self._is_host_path_in_allowlist(context.headers.get("host"), context.path):
             return True
         
         graphql_op = getattr(context, "graphql_operation", None)
         if graphql_op and self._is_graphql_operation_in_allowlist(graphql_op.get("type"), graphql_op.get("name")):
             return True
 
         if await self._verify_whitelisted_bot(context):
             return True
 
         return False

    def _has_certain_attack(self, context: RequestContext) -> bool:
        """
        Évalue si la requête présente des caractéristiques d'attaque flagrantes
        (comme le déclenchement d'un honeypot ou un score de bot atteignant le maximum).

        Args:
            context (RequestContext): Le contexte de la requête.

        Returns:
            bool: True si une attaque flagrante est détectée, False sinon.
        """
        honeypot_config = self.config.get("honeypot", {})
        
        honeypot_score = RequestUtils.get_honeypot_score(context, honeypot_config)
        if honeypot_score >= 100.0:
            return True
            
        bot_score = RequestUtils.get_bot_score(context)
        if bot_score >= 100.0:
            return True
            
        return False

    def update_config(self, new_config: Dict[str, Any]) -> None:
        """
        Applique à chaud une nouvelle configuration de sécurité (poids, seuils, etc.)
        sans nécessiter de redémarrage.
        """
        def deep_merge(target: dict, source: dict) -> dict:
            out = copy.deepcopy(target)
            for k, v in source.items():
                if isinstance(v, dict) and k in out and isinstance(out[k], dict):
                    out[k] = deep_merge(out[k], v)
                else:
                    out[k] = copy.deepcopy(v)
            return out

        self.config = deep_merge(self.config, new_config)
        self.thresholds = self.config.get("thresholds", self.thresholds)
        self.weights = self.config.get("weights", self.weights)
        self.dry_run = self.config.get("dryRun", self.dry_run)

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
            is_https = (
                 context.headers.get("x-forwarded-proto") == "https" or 
                 context.headers.get("x-forwarded-ssl") == "on" or 
                 context.headers.get("x-url-scheme") == "https"
            )
            secure_option = is_https or (self.config.get("env") == "production")
            new_cookie = {
                "name": "device_id",
                "value": device_id,
                "options": {
                    "httponly": True,
                    "samesite": "Strict",
                    "path": "/",
                     "secure": secure_option,
                     **({"partitioned": True} if secure_option else {})
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

        # Active sliding window pruning (2 hours)
        if "ipTimes" not in device_data:
            device_data["ipTimes"] = {}
        device_data["ipTimes"][client_ip] = now

        sliding_window = 2 * 3600 * 1000  # 2 hours in milliseconds
        cutoff = now - sliding_window
        expired_ips = [ip for ip, last_seen in device_data["ipTimes"].items() if last_seen < cutoff]
        for ip in expired_ips:
            device_data["ips"].discard(ip)
            device_data["ipTimes"].pop(ip, None)

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

        # Inconsistency score analogique lisse
        current_hash = self.get_composite_device_hash(context)
        similarity = FingerprintBuilder.compare(device_data.get("initialDeviceHash") or "", current_hash)
        similarity_threshold = float(self.config.get("similarityThreshold", 0.72))
        inconsistency_score = RequestUtils.calculate_analog_inconsistency_score(similarity, similarity_threshold)

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
        ja3_raw = context.headers.get("x-ja3-raw")
        http_version = getattr(context, "http_version", "") or ""

        spoofed_ja4s = {
            "t13d1516h2_8daaf6152771_4be0df930c2c",
            "t12d1516h2_8daaf6152771_390237aa04be",
            "t13d1516h2_e822d36d892d_93ec3f0b2f5b"
        }
        if ja4 and ja4 in spoofed_ja4s:
            tls_spoofing_score = max(tls_spoofing_score, 100.0)

        claimed_browser_info = RequestUtils.parse_user_agent(ua).get("browser")
        claimed_browser = claimed_browser_info.split("/")[0] if claimed_browser_info else None
        is_human_browser = claimed_browser in ("Chrome", "Firefox", "Safari", "Edge")

        if ja3_raw and isinstance(ja3_raw, str):
            raw_parts = ja3_raw.split(",")
            if len(raw_parts) >= 3:
                try:
                    raw_version = int(raw_parts[0])
                    raw_ciphers = [int(x) for x in raw_parts[1].split("-") if x]
                    raw_extensions = [int(x) for x in raw_parts[2].split("-") if x]
                except ValueError:
                    raw_version, raw_ciphers, raw_extensions = 0, [], []

                if claimed_browser in ("Chrome", "Edge"):
                    if not has_grease(raw_ciphers) and not has_grease(raw_extensions):
                        tls_spoofing_score = max(tls_spoofing_score, 75.0)

                is_h2_or_higher = ("2.0" in http_version) or ("HTTP/2" in http_version) or ("HTTP/3" in http_version)
                if is_h2_or_higher and 16 not in raw_extensions:
                    tls_spoofing_score = max(tls_spoofing_score, 70.0)

                if is_human_browser and raw_version < 771:
                    tls_spoofing_score = max(tls_spoofing_score, 80.0)

        if ja4 and isinstance(ja4, str):
            parts = ja4.split("_")
            ja4a = parts[0]
            if len(ja4a) >= 10:
                ja4_version = ja4a[1:3]
                alpn = ja4a[8:10]
                try:
                    ext_count = int(ja4a[6:8])
                except ValueError:
                    ext_count = 0
                ua_parts = RequestUtils.parse_user_agent(ua)

                if alpn == "h2" and (http_version in ("1.1", "1.0", "HTTP/1.1", "HTTP/1.0")):
                    has_proxy = any(context.headers.get(h) for h in ("via", "forwarded", "x-forwarded-proto", "x-forwarded-for"))
                    if not has_proxy:
                        tls_spoofing_score = max(tls_spoofing_score, 40.0)

                if ja4_version == "12" and ua_parts.get("os") in ("iOS", "macOS") and (ua_parts.get("browser") or "").startswith("Safari"):
                    tls_spoofing_score = max(tls_spoofing_score, 60.0)

                if (ua_parts.get("browser") or "").startswith("Chrome") and alpn == "00":
                    tls_spoofing_score = max(tls_spoofing_score, 50.0)
                if (ua_parts.get("browser") or "").startswith("Firefox") and ext_count > 15:
                    tls_spoofing_score = max(tls_spoofing_score, 50.0)

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
            tls_spoofing_score = max(tls_spoofing_score, 50.0)
        else:
            if claimed_browser:
                if ja4 == "t13d1517h2_8daaf61527d5" and "Chrome" not in claimed_browser:
                    tls_spoofing_score = max(tls_spoofing_score, 90.0)
                elif ja3 in tls_fingerprint_db:
                    expected_browsers = tls_fingerprint_db[ja3]
                    is_library = any(lib in ("Python", "Go", "Java", "curl") for lib in expected_browsers)
                    if is_library and is_human_browser:
                        tls_spoofing_score = max(tls_spoofing_score, 90.0)
                    elif not any(exp in claimed_browser for exp in expected_browsers):
                        tls_spoofing_score = max(tls_spoofing_score, 80.0)

        if claimed_browser:
            if ja4:
                ja4_key = f"ja4-browsers:{ja4}"
                seen_browsers = await self.store.get(ja4_key) or []
                if not isinstance(seen_browsers, list):
                    seen_browsers = []
                if claimed_browser not in seen_browsers:
                    seen_browsers.append(claimed_browser)
                    await self.store.set(ja4_key, seen_browsers, 86400)
                if len(seen_browsers) > 1:
                    tls_spoofing_score = max(tls_spoofing_score, 80.0)
            if ja3:
                ja3_key = f"ja3-browsers:{ja3}"
                seen_browsers = await self.store.get(ja3_key) or []
                if not isinstance(seen_browsers, list):
                    seen_browsers = []
                if claimed_browser not in seen_browsers:
                    seen_browsers.append(claimed_browser)
                    await self.store.set(ja3_key, seen_browsers, 86400)
                if len(seen_browsers) > 1:
                    tls_spoofing_score = max(tls_spoofing_score, 85.0)

        # Calculate weighted average
        bot_score = RequestUtils.get_bot_score(context)
        honeypot_score = RequestUtils.get_honeypot_score(context, self.config.get("honeypot"))
        behavior_score = RequestUtils.get_behavior_score(context)
        time_inconsistency_score = RequestUtils.get_time_inconsistency_score(context)
        cross_layer_inconsistency_score = RequestUtils.get_cross_layer_inconsistency(context)
        click_variance_score = RequestUtils.get_click_variance_score(context)
        request_pattern_score = RequestUtils.get_request_pattern_score(context, device_data, self.config.get("patterns", {}))["requestPatternScore"]
        
        stable_hash_for_cluster = str(cyrb53(self._extract_stable_part(current_hash)))
        botnet_cluster_score = RequestUtils.get_botnet_cluster_score(context, stable_hash_for_cluster)["botnetClusterScore"]

        # Extraction et validation de la clé publique ZKP du client
        zkp_proof = context.headers.get("x-zkp-proof") or context.query_params.get("pow_zkp") or ""
        zkp_y = zkp_proof.split(":")[0] if zkp_proof and ":" in zkp_proof else None
        threat_intel_score = await self.calculate_threat_intel_score(context, zkp_y)

        ip_reputation_score = await RequestUtils.get_ip_reputation_score(self.store, context.client_ip)
        subnet_score = (await RequestUtils.get_subnet_score(self.store, context.client_ip, device_id, self.config))["subnetScore"]

        tcp_anomaly = RequestUtils.get_tcp_anomaly_score(context)
        tcp_anomaly_score = tcp_anomaly.get("tcpAnomalyScore", 0.0)

        protocol_anomaly_data = RequestUtils.get_protocol_anomaly_score(context)
        protocol_anomaly_score = protocol_anomaly_data.get("protocolAnomalyScore", 0.0)
        http2_anomaly_score = protocol_anomaly_data.get("http2AnomalyScore", 0.0)
        quic_anomaly_score = protocol_anomaly_data.get("quicAnomalyScore", 0.0)

        virtualization_score = RequestUtils.get_virtualization_anomaly_score(context)

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
            "botnetClusterScore": botnet_cluster_score,
            "protocolAnomalyScore": protocol_anomaly_score,
            "http2AnomalyScore": http2_anomaly_score,
            "quicAnomalyScore": quic_anomaly_score,
            "tcpAnomalyScore": tcp_anomaly_score,
            "renderingAnomalyScore": rendering_anomaly_score,
            "virtualizationScore": virtualization_score,
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

    async def broadcast_banned_zkp(self, zkp_y: str) -> None:
        peers = self.config.get("federatedPeers") or []
        secret = self.config.get("federationSecret") or os.environ.get("POW_SECRET") or "fallback-dev-secret-32-chars-minimum"
        if not peers:
            return

        timestamp = int(time.time() * 1000)
        msg = f"{timestamp}:{zkp_y}"
        signature = hmac.new(secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()

        import urllib.parse
        import asyncio
        import json

        # Semaphore to cap maximum concurrent sockets and scale gracefully
        semaphore = asyncio.Semaphore(10)

        async def send_one(peer_url):
            try:
                async with semaphore:
                    try:
                        parsed = urllib.parse.urlparse(peer_url)
                        host = parsed.hostname
                        port = parsed.port or (443 if parsed.scheme == "https" else 80)
                        path = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")
                        connector = "?" if "?" not in path else "&"
                        path = f"{path}{connector}coop_op=share_threat_intel"

                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(host, port, ssl=(parsed.scheme == "https")),
                            timeout=0.5
                        )

                        post_data = json.dumps({"zkpY": zkp_y})
                        request = (
                            f"POST {path} HTTP/1.1\r\n"
                            f"Host: {host}\r\n"
                            f"Content-Type: application/json\r\n"
                            f"Content-Length: {len(post_data)}\r\n"
                            f"X-Federation-Signature: {signature}\r\n"
                            f"X-Federation-Timestamp: {timestamp}\r\n"
                            f"Connection: close\r\n\r\n"
                            f"{post_data}"
                        )
                        writer.write(request.encode("utf-8"))
                        await writer.drain()
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass
            except Exception:
                pass

        await asyncio.gather(*(send_one(peer) for peer in peers), return_exceptions=True)

    def get_rtt_proxy_score(self, context: RequestContext) -> float:
        """
        Feature 7 : Corrélation RTT & Latence de Proxy Résidentiel
        Compare le RTT de transport TCP réel avec l'horodatage applicatif client
        pour lever les masques des proxys résidentiels rotatifs.
        """
        tcp_rtt_header = context.get_header("x-tcp-rtt") or context.get_header("x-real-rtt")
        tcp_rtt = None
        if tcp_rtt_header:
            try:
                tcp_rtt = int(tcp_rtt_header)
            except ValueError:
                pass

        behavior_header = context.get_header("x-behavior-metrics")
        if behavior_header:
            try:
                metrics = json.loads(behavior_header)
                client_timestamp = metrics.get("clientTimestamp")
                if client_timestamp is not None:
                    app_latency = context.request_timestamp - int(client_timestamp)
                    if tcp_rtt is not None and tcp_rtt > 0:
                        jitter_allowance = 60.0
                        effective_rtt = max(float(tcp_rtt), 5.0)
                        tunnel_delta = app_latency - (tcp_rtt + jitter_allowance)
                        divergence_ratio = app_latency / effective_rtt
                        if tcp_rtt <= 40 and divergence_ratio >= 3.0 and tunnel_delta > 0:
                            scaling = 120.0
                            ratio_weight = min(1.0, (divergence_ratio - 3.0) / 5.0)
                            proxy_score = min(95.0, 40.0 + 55.0 * math.tanh(tunnel_delta / scaling) * ratio_weight)
                            return round(proxy_score * 10.0) / 10.0
                    else:
                        if app_latency > 350:
                            return 40.0
            except Exception:
                # Fail-safe silencieux
                pass
        return 0.0

    async def calculate_threat_intel_score(self, context: RequestContext, zkp_y: Optional[str]) -> float:
        # Récupération du score de base de Threat Intelligence (ZKP réputation)
        is_banned = await self.store.has(f"banned-zkp-y:{zkp_y}") if zkp_y else False
        base_score = 100.0 if is_banned else 0.0
        rtt_score = self.get_rtt_proxy_score(context)
        return max(base_score, rtt_score)
    
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

        if await self._check_allowlists(context):
             MetricsManager.increment_counter("requests_total", {"status": "passed"})
             return {"action": "next", "score": 0.0, "vector": {"whitelisted": 100.0}}

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

        # Instant check & condemnation for certain attacks (Honeypot or Bot)
        if self._has_certain_attack(context):
            if device_data:
                device_data["condemned"] = True
                await self.store.set(f"device:{device_id}", device_data)
            self._fast_path_cache[client_ip] = (current_time + 60.0, "block")
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
                    if self.problem_manager is not None:
                        await self.problem_manager.integrate_solution(pow_problem_id, work_result)

                        # Si le problème résolu est l'auto-tuning de sécurité et que l'auto-tuning est activé,
                        # on applique directement la meilleure solution calculée au moteur en direct.
                        if pow_problem_id == "security_auto_tuning" and self.config.get("autotuning", {}).get("enabled", False):
                            pareto_front = work_result.get("paretoFront")
                            if isinstance(pareto_front, list) and len(pareto_front) > 0:
                                best_solution = pareto_front[0]
                                min_distance = math.sqrt(
                                    float(best_solution['objectives'][0])**2 +
                                    float(best_solution['objectives'][1])**2
                                )

                                for item in pareto_front[1:]:
                                    distance = math.sqrt(
                                        float(item['objectives'][0])**2 +
                                        float(item['objectives'][1])**2
                                    )
                                    if distance < min_distance:
                                        min_distance = distance
                                        best_solution = item

                                if "solution" in best_solution:
                                    self.update_config(best_solution["solution"])
                                    print("[FingerprintEngine] Useful Work auto-tuning applied successfully to live config.")

                    default_path = os.path.join(os.getcwd(), "problems.config.json")
                    config_path = self.config.get("usefulWorkConfigPath") or (default_path if os.path.exists(default_path) else None)
                    pm = ProblemManager.get_instance(config_path, self.store)
                    if not pm.initialized:
                        await pm.load_problems()
                    await pm.integrate_solution(pow_problem_id, work_result)

                    # Si le problème résolu est l'auto-tuning de sécurité et que l'auto-tuning est activé,
                    # on applique directement la meilleure solution calculée au moteur en direct.
                    if pow_problem_id == "security_auto_tuning" and self.config.get("autotuning", {}).get("enabled", False):
                        pareto_front = work_result.get("paretoFront")
                        if isinstance(pareto_front, list) and pareto_front:
                            best_solution = pareto_front[0]
                            min_distance = math.sqrt(float(best_solution['objectives'][0])**2 + float(best_solution['objectives'][1])**2)
                            for item in pareto_front[1:]:
                                distance = math.sqrt(float(item['objectives'][0])**2 + float(item['objectives'][1])**2)
                                if distance < min_distance:
                                    min_distance = distance
                                    best_solution = item
                            if "solution" in best_solution:
                                self.update_config(best_solution["solution"])
                                print("[FingerprintEngine] Useful Work auto-tuning applied successfully to live config.")

                    await self.store.delete(f"secret:{pow_nonce}")
                    ticket = str(uuid.uuid4())
                    await self.store.set(f"ticket:{ticket}", {"ip": context.client_ip, "device_id": device_id}, 3600)
                    MetricsManager.increment_counter("challenges_solved_total")
                    is_https = (
                        context.headers.get("x-forwarded-proto") == "https" or 
                        context.headers.get("x-forwarded-ssl") == "on" or 
                        context.headers.get("x-url-scheme") == "https"
                    )
                    secure_option = is_https or (self.config.get("env") == "production")
                    return {
                        "action": "redirect",
                        "path": context.path,
                        "cookie": {
                            "name": "pow_clearance",
                            "value": ticket,
                            "options": {
                                "httponly": True, 
                                "secure": secure_option,
                                "max_age": 3600, 
                                "path": "/",
                                **({"partitioned": True} if secure_option else {})
                            }
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
                    is_https = (
                        context.headers.get("x-forwarded-proto") == "https" or 
                        context.headers.get("x-forwarded-ssl") == "on" or 
                        context.headers.get("x-url-scheme") == "https"
                    )
                    secure_option = is_https or (self.config.get("env") == "production")
                    return {
                        "action": "redirect",
                        "path": clean_path,
                        "cookie": {
                            "name": "pow_clearance",
                            "value": ticket,
                            "options": {
                                "httponly": True, 
                                "secure": secure_option,
                                "max_age": 3600, 
                                "path": "/",
                                **({"partitioned": True} if secure_option else {})
                            }
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
                    is_https = (
                        context.headers.get("x-forwarded-proto") == "https" or 
                        context.headers.get("x-forwarded-ssl") == "on" or 
                        context.headers.get("x-url-scheme") == "https"
                    )
                    secure_option = is_https or (self.config.get("env") == "production")
                    return {
                        "action": "redirect",
                        "path": context.path,
                        "cookie": {
                            "name": "pow_clearance",
                            "value": ticket,
                            "options": {
                                "httponly": True, 
                                "secure": secure_option,
                                "max_age": 3600, 
                                "path": "/",
                                **({"partitioned": True} if secure_option else {})
                            }
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
        medium_threshold = self.thresholds.get("medium", 45)
        high_threshold = self.thresholds.get("high", 75)
        block_threshold = self.thresholds.get("block", 95)

        if score >= medium_threshold and score < block_threshold:
            # Utilise l'identifiant matériel stable pour éviter les faux positifs lors du cookie dropping
            current_hash = self.get_composite_device_hash(context)
            stable_fp_id = str(cyrb53(self._extract_stable_part(current_hash)))
            await RequestUtils.update_subnet_metrics(self.store, context, stable_fp_id, score)
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
        medium_threshold = self.thresholds.get("medium", 45)
        max_indicators_count = sum(1 for val in suspicion_vector.values() if isinstance(val, (int, float)) and val >= 100.0)
        must_rechallenge = (suspicion_vector.get("honeypotScore", 0.0) >= medium_threshold) or (max_indicators_count >= 1)

        low_threshold = self.thresholds.get("low", 20)

        if (score >= low_threshold and not has_valid_ticket) or must_rechallenge:
            # --- Limiteur de débit par domaine et sous-réseau (Token Bucket) ---
            domain = context.headers.get("host", "default")
            rate_limit_config = self.config.get("challengeRateLimit", {})
            rate_limit_passed = await ChallengeUtils.check_challenge_rate_limit(self.store, client_ip, domain, rate_limit_config)
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
            # Ratio d'effort linéaire synchrone CPU / Mémoire
            mem_difficulty = int(round(suspicion_factor * 48))

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

    calculate_analog_inconsistency_score = staticmethod(RequestUtils.calculate_analog_inconsistency_score)

calculate_analog_inconsistency_score = RequestUtils.calculate_analog_inconsistency_score

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
        leading_digits = []
        for n in numbers:
            s = str(n).lstrip("0.")
            if s:
                leading_digits.append(s[0])
        leading_digits = [d for d in leading_digits if "1" <= d <= "9"]
        if len(leading_digits) < 10:
            return 0.0
        counts = {str(i): 0 for i in range(1, 10)}
        valid_count = 0

        for n in numbers:
            try:
                val = abs(float(n))
            except (ValueError, TypeError):
                continue
            if val == 0.0:
                continue
            log = math.log10(val)
            factor = 10 ** math.floor(log)
            digit = math.floor(val / factor)
            if 1 <= digit <= 9:
                counts[str(digit)] += 1
                valid_count += 1

        if valid_count < 10:
            return 0.0
        benford = {1: 30.1, 2: 17.6, 3: 12.5, 4: 9.7, 5: 7.9, 6: 6.7, 7: 5.8, 8: 5.1, 9: 4.6}
        deviation = 0.0
        for i in range(1, 10):
            obs = (counts[str(i)] / valid_count) * 100.0
            exp = benford[i]
            deviation += (obs - exp) ** 2
        return math.sqrt(deviation) / 50.0

class OptimizationOperators:
    @staticmethod
    def create_tournament_selection(options: Optional[Dict[str, Any]] = None) -> Callable[[List[Dict[str, Any]]], Dict[str, Any]]:
        """
        Crée une fonction de sélection par tournoi pour un algorithme génétique.
        """
        options = options or {}
        tournament_size = options.get("size", 5)

        def tournament_selection(population: List[Dict[str, Any]]) -> Dict[str, Any]:
            best = None
            pop_len = len(population)

            for _ in range(tournament_size):
                individual = population[random.randint(0, pop_len - 1)]
                individual_fitness = individual.get("fitness")
                if individual_fitness is None:
                    individual_fitness = sum(individual.get("objectives", [])) if "objectives" in individual else float("inf")
                
                if best is None:
                    best = individual
                else:
                    best_fitness = best.get("fitness")
                    if best_fitness is None:
                        best_fitness = sum(best.get("objectives", [])) if "objectives" in best else float("inf")
                    if individual_fitness < best_fitness:
                        best = individual

            return best if best is not None else population[random.randint(0, pop_len - 1)]

        return tournament_selection

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
                    "clientHintsInconsistencyScore": random.random(),
                    "clickVarianceScore": random.random(),
                    "subnetScore": random.random(),
                    "ipReputationScore": random.random(),
                    "botnetClusterScore": random.random(),
                    "tcpAnomalyScore": random.random(),
                    "protocolAnomalyScore": random.random(),
                    "quicAnomalyScore": random.random(),
                    "renderingAnomalyScore": random.random(),
                    "virtualizationScore": random.random(),
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

class Individual:
    def __init__(self, thresholds: Dict[str, float] = None, weights: Dict[str, float] = None, patterns: Dict[str, float] = None):
        self.thresholds = thresholds or {}
        self.weights = weights or {}
        self.objectives = [0.0, 0.0]
        self.patterns = patterns or {}
        self.rank = 0
        self.domination_count = 0
        self.dominated_solutions = []
        self.crowding_distance = 0.0

class AutoTuner:
    _last_best_solution: Optional[Dict[str, Any]] = None

    def __init__(self, security_config: Dict[str, Any], store, options: Dict[str, Any] = None):
        self.security_config = security_config
        self.store = store
        self.traffic_data = store
        options = options or {}
        self.min_data_points = options.get("min_data_points") or options.get("minDataPoints") or 200
        self.max_data_points = options.get("max_data_points") or options.get("maxDataPoints") or 10000
        self.max_age_ms = options.get("max_age_ms") or options.get("maxAgeMs")
        self.validation_tolerance = options.get("validation_tolerance") or options.get("validationTolerance") or 0.15
        self.interval_minutes = options.get("interval", 30)
        self.save_path = options.get("save_path")
        self.clear_after_tuning = options.get("clear_after_tuning", False)
        self.on_cleanup = options.get("on_cleanup")
        self.last_best_solution = None

    def run_optimization_cycle(self) -> Any:
        if isinstance(self.store, list):
            return self._run_optimization_cycle_sync()
        else:
            return self._run_optimization_cycle_async()

    def _run_optimization_cycle_sync(self) -> None:
        raw_logs = self.store
        if not raw_logs:
            return

        self._prune_logs(raw_logs)
        sanitized_data = self.sanitize_traffic_data(raw_logs)

        high_confidence_logs = sum(
            log.get("instancesCount", 1) for log in sanitized_data 
            if log.get("type") in ("challenge_solved", "trap_triggered")
        )
        total_sanitized_instances = sum(log.get("instancesCount", 1) for log in sanitized_data)
        high_confidence_ratio = (
            high_confidence_logs / total_sanitized_instances if total_sanitized_instances else 0.0
        )
        min_confidence_ratio = 0.05
        min_high_confidence_count = 10

        has_enough_signal = (
            high_confidence_ratio >= min_confidence_ratio 
            or high_confidence_logs >= min_high_confidence_count
        )

        if total_sanitized_instances < self.min_data_points or not has_enough_signal:
            return

        # Execute genetic algorithm
        pareto_front = self.solve_full_security_tuning(sanitized_data)
        if not pareto_front:
            return

        # Security guardrails check
        filtered_front = [
            ind for ind in pareto_front 
            if self.is_valid_security_config(ind.thresholds, ind.weights)
        ]
        
        if not filtered_front:
            filtered_front = pareto_front

        # Select the most balanced solution (closest to origin)
        best_solution = filtered_front[0]
        min_distance = math.sqrt(best_solution.objectives[0]**2 + best_solution.objectives[1]**2)
        for ind in filtered_front[1:]:
            dist = math.sqrt(ind.objectives[0]**2 + ind.objectives[1]**2)
            if dist < min_distance:
                min_distance = dist
                best_solution = ind

        traffic_confidence = min(1.5, max(0.3, high_confidence_ratio * 4.0))

        # Cross validation
        temp_thresholds = dict(self.security_config.get("thresholds", {}))
        temp_weights = dict(self.security_config.get("weights", {}))
        temp_patterns = dict(self.security_config.get("patterns", {}))

        self.apply_inertial_update(temp_thresholds, best_solution.thresholds, "thresholds", traffic_confidence)
        self.apply_inertial_update(temp_weights, best_solution.weights, "weights", traffic_confidence)
        self.apply_inertial_update(temp_patterns, best_solution.patterns, "patterns", traffic_confidence)

        current_obj = self.evaluate_fitness(
            self.security_config.get("thresholds", {}), 
            self.security_config.get("weights", {}),
            sanitized_data
        )
        proposed_obj = self.evaluate_fitness(temp_thresholds, temp_weights, sanitized_data)

        if (proposed_obj[0] > current_obj[0] + self.validation_tolerance or 
            proposed_obj[1] > current_obj[1] + self.validation_tolerance):
            # Reject due to poisoning/instability
            return

        # Apply permanently
        self.apply_inertial_update(self.security_config["thresholds"], best_solution.thresholds, "thresholds", traffic_confidence)
        self.apply_inertial_update(self.security_config["weights"], best_solution.weights, "weights", traffic_confidence)
        self.security_config.setdefault("patterns", {})
        self.apply_inertial_update(self.security_config["patterns"], best_solution.patterns, "patterns", traffic_confidence)

        self.last_best_solution = {
            "thresholds": self.security_config["thresholds"],
            "weights": self.security_config["weights"],
            "patterns": self.security_config["patterns"],
            "objectives": best_solution.objectives
        }
        AutoTuner._last_best_solution = self.last_best_solution

        if self.save_path:
            try:
                with open(self.save_path, 'w') as f:
                    json.dump(self.last_best_solution, f, indent=2)
            except Exception as e:
                logging.error(f"[AutoTuning] Failed to save optimized config: {e}")

        if self.clear_after_tuning:
            self.store.clear()
            if self.on_cleanup and callable(self.on_cleanup):
                try:
                    self.on_cleanup(raw_logs)
                except Exception as e:
                    logging.error(f"[AutoTuning] Error in on_cleanup callback after clearing: {e}")

    async def _run_optimization_cycle_async(self) -> None:
        raw_logs = await self.store.get("traffic_logs") or []
        if not raw_logs:
            return

        self._prune_logs(raw_logs)
        await self.store.set("traffic_logs", raw_logs)
        sanitized_data = self.sanitize_traffic_data(raw_logs)

        high_confidence_logs = sum(
            log.get("instancesCount", 1) for log in sanitized_data 
            if log.get("type") in ("challenge_solved", "trap_triggered")
        )
        total_sanitized_instances = sum(log.get("instancesCount", 1) for log in sanitized_data)
        high_confidence_ratio = (
            high_confidence_logs / total_sanitized_instances if total_sanitized_instances else 0.0
        )
        min_confidence_ratio = 0.05
        min_high_confidence_count = 10

        has_enough_signal = (
            high_confidence_ratio >= min_confidence_ratio 
            or high_confidence_logs >= min_high_confidence_count
        )

        if total_sanitized_instances < self.min_data_points or not has_enough_signal:
            return

        # Execute genetic algorithm
        pareto_front = self.solve_full_security_tuning(sanitized_data)
        if not pareto_front:
            return

        # Security guardrails check
        filtered_front = [
            ind for ind in pareto_front 
            if self.is_valid_security_config(ind.thresholds, ind.weights)
        ]
        
        if not filtered_front:
            filtered_front = pareto_front

        # Select the most balanced solution (closest to origin)
        best_solution = filtered_front[0]
        min_distance = math.sqrt(best_solution.objectives[0]**2 + best_solution.objectives[1]**2)
        for ind in filtered_front[1:]:
            dist = math.sqrt(ind.objectives[0]**2 + ind.objectives[1]**2)
            if dist < min_distance:
                min_distance = dist
                best_solution = ind

        traffic_confidence = min(1.5, max(0.3, high_confidence_ratio * 4.0))

        # Cross validation
        temp_thresholds = dict(self.security_config.get("thresholds", {}))
        temp_weights = dict(self.security_config.get("weights", {}))
        temp_patterns = dict(self.security_config.get("patterns", {}))

        self.apply_inertial_update(temp_thresholds, best_solution.thresholds, "thresholds", traffic_confidence)
        self.apply_inertial_update(temp_weights, best_solution.weights, "weights", traffic_confidence)
        self.apply_inertial_update(temp_patterns, best_solution.patterns, "patterns", traffic_confidence)

        current_obj = self.evaluate_fitness(
            self.security_config.get("thresholds", {}), 
            self.security_config.get("weights", {}),
            sanitized_data
        )
        proposed_obj = self.evaluate_fitness(temp_thresholds, temp_weights, sanitized_data)

        if (proposed_obj[0] > current_obj[0] + self.validation_tolerance or 
            proposed_obj[1] > current_obj[1] + self.validation_tolerance):
            # Reject due to poisoning/instability
            return

        # Apply permanently
        self.apply_inertial_update(self.security_config["thresholds"], best_solution.thresholds, "thresholds", traffic_confidence)
        self.apply_inertial_update(self.security_config["weights"], best_solution.weights, "weights", traffic_confidence)
        self.security_config.setdefault("patterns", {})
        self.apply_inertial_update(self.security_config["patterns"], best_solution.patterns, "patterns", traffic_confidence)

        self.last_best_solution = {
            "thresholds": self.security_config["thresholds"],
            "weights": self.security_config["weights"],
            "patterns": self.security_config["patterns"],
            "objectives": best_solution.objectives
        }
        AutoTuner._last_best_solution = self.last_best_solution

        if self.save_path:
            try:
                with open(self.save_path, 'w') as f:
                    json.dump(self.last_best_solution, f, indent=2)
            except Exception as e:
                logging.error(f"[AutoTuning] Failed to save optimized config: {e}")

        if self.clear_after_tuning:
            await self.store.delete("traffic_logs")
            if self.on_cleanup and callable(self.on_cleanup):
                try:
                    self.on_cleanup(raw_logs)
                except Exception as e:
                    logging.error(f"[AutoTuning] Error in on_cleanup callback after clearing: {e}")

    def _prune_logs(self, logs: List[Dict[str, Any]]) -> None:
        now = int(time.time() * 1000)
        removed = []
        if hasattr(self, "max_age_ms") and self.max_age_ms and self.max_age_ms > 0:
            threshold = now - self.max_age_ms
            i = 0
            while i < len(logs):
                log = logs[i]
                log_ts = log.get("timestamp") or log.get("requestTimestamp") or now
                if log_ts < threshold:
                    removed.append(logs.pop(i))
                else:
                    i += 1
        if self.max_data_points and len(logs) > self.max_data_points:
            overflow_count = len(logs) - self.max_data_points
            removed.extend(logs[:overflow_count])
            del logs[:overflow_count]
        if self.on_cleanup and callable(self.on_cleanup) and removed:
            try:
                self.on_cleanup(removed)
            except Exception as e:
                logging.error(f"[AutoTuning] Error in on_cleanup callback: {e}")

    def get_ip_subnet(self, ip: str, ipv4_prefix: int = 24, ipv6_prefix: int = 48) -> str:
        if not ip or ip == "unknown":
            return "unknown-subnet"
        if ":" in ip:
            parts = ip.split(":")
            return ":".join(parts[:3]) + f"/{ipv6_prefix}"
        else:
            parts = ip.split(".")
            if len(parts) == 4:
                return ".".join(parts[:3]) + f"/{ipv4_prefix}"
        return "unknown-subnet"

    def get_vector_distance(self, v1: Dict[str, float], v2: Dict[str, float]) -> float:
        if not v1 or not v2:
            return float('inf')
        all_keys = set(v1.keys()).union(v2.keys())
        sum_sq = 0.0
        for key in all_keys:
            sum_sq += (v1.get(key, 0.0) - v2.get(key, 0.0)) ** 2
        return math.sqrt(sum_sq)

    def get_hardware_cluster(self, log: Dict[str, Any]) -> str:
        fp = log.get("deviceHash") or log.get("fingerprint") or log.get("deviceFingerprint") or ""
        if not fp or not isinstance(fp, str):
            return log.get("deviceId") or "anonymous-cluster"
        parts = fp.split("|")
        hw_components = []
        for part in parts:
            pair = part.split(":", 1)
            if len(pair) == 2 and pair[0] in ("gpu", "cvs", "hw"):
                hw_components.append(part)
        if hw_components:
            hw_components.sort()
            return "|".join(hw_components)
        return log.get("deviceId") or "anonymous-cluster"

    def sanitize_traffic_data(self, traffic_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not traffic_data:
            return []

        raw_logs = list(traffic_data)
        total_count = len(raw_logs)

        max_logs_per_device = max(3, int(math.floor(total_count * 0.02)))
        max_logs_per_ip = max(3, int(math.floor(total_count * 0.02)))
        max_logs_per_subnet = max(5, int(math.floor(total_count * 0.05)))
        max_logs_per_hw_cluster = max(3, int(math.floor(total_count * 0.02)))

        # Cohort compression
        clustered_logs = []
        for log in raw_logs:
            matched_cluster = None
            log_vector = log.get("vector", {})
            log_type = log.get("type", "")

            for cluster in clustered_logs:
                cluster_vector = cluster.get("vector", {})
                cluster_type = cluster.get("type", "")

                if log_type == cluster_type and self.get_vector_distance(log_vector, cluster_vector) < 5.0:
                    matched_cluster = cluster
                    break

            if matched_cluster is not None:
                matched_cluster["instancesCount"] = matched_cluster.get("instancesCount", 1) + 1
                matched_cluster["weight"] = 1.0 + math.log(matched_cluster["instancesCount"])
            else:
                log_copy = dict(log)
                log_copy["instancesCount"] = 1
                log_copy["weight"] = 1.0
                clustered_logs.append(log_copy)

        suspicious_logs = []
        passed_logs = []
        device_counts = {}
        ip_counts = {}
        subnet_counts = {}
        hw_cluster_counts = {}

        for log in clustered_logs:
            dev_id = log.get("deviceId", "anonymous")
            ip = log.get("clientIp", "unknown")
            subnet = self.get_ip_subnet(ip)
            hw_cluster = self.get_hardware_cluster(log)
            type_ = log.get("type", "")

            cur_dev_count = device_counts.get(dev_id, 0)
            cur_ip_count = ip_counts.get(ip, 0)
            cur_subnet_count = subnet_counts.get(subnet, 0)
            cur_hw_count = hw_cluster_counts.get(hw_cluster, 0)

            if (cur_dev_count < max_logs_per_device
                    and (ip == "unknown" or cur_ip_count < max_logs_per_ip)
                    and (subnet == "unknown-subnet" or cur_subnet_count < max_logs_per_subnet)
                    and cur_hw_count < max_logs_per_hw_cluster):

                device_counts[dev_id] = cur_dev_count + 1
                if ip != "unknown":
                    ip_counts[ip] = cur_ip_count + 1
                if subnet != "unknown-subnet":
                    subnet_counts[subnet] = cur_subnet_count + 1
                hw_cluster_counts[hw_cluster] = cur_hw_count + 1

                if type_ == "request_passed":
                    passed_logs.append(log)
                else:
                    suspicious_logs.append(log)

        max_passed_allowed = max(self.min_data_points, len(suspicious_logs) * 9)
        if len(passed_logs) > max_passed_allowed:
            random.shuffle(passed_logs)
            passed_logs = passed_logs[:max_passed_allowed]

        return suspicious_logs + passed_logs

    def is_valid_security_config(self, thresholds: Dict[str, float], weights: Dict[str, float]) -> bool:
        active_weights_sum = (
            weights.get("inconsistencyScore", 0.0) +
            weights.get("tlsSpoofingScore", 0.0) +
            weights.get("requestPatternScore", 0.0) +
            weights.get("behaviorScore", 0.0) +
            weights.get("botScore", 0.0)
        )
        if active_weights_sum < 1.5:
            return False

        low = thresholds.get("low", 0.0)
        medium = thresholds.get("medium", 0.0)
        high = thresholds.get("high", 0.0)
        block = thresholds.get("block", 0.0)

        return (low >= 10 and low <= 35 and
                medium >= low + 5 and medium <= 70 and
                high >= medium + 5 and high <= 90 and
                block >= high + 5 and block <= 99)

    def apply_inertial_update(self, current: Dict[str, Any], target: Dict[str, float], type_: str, confidence: float) -> None:
        base_learning_rate = 0.15
        learning_rate = max(0.02, min(0.40, base_learning_rate * confidence))

        for key in current.keys():
            if key in target:
                cur_val = float(current[key])
                tar_val = float(target[key])
                updated = cur_val + (tar_val - cur_val) * learning_rate

                if type_ == "weights":
                    updated = max(0.05, min(1.8, updated))
                    current[key] = updated
                elif type_ == "thresholds":
                    current[key] = int(round(updated))
                elif type_ == "patterns":
                    if key == 'benfordThreshold':
                        updated = max(0.05, min(0.30, updated))
                    elif key == 'decayFactor':
                        updated = max(0.70, min(0.98, updated))
                    elif key == 'minSamples':
                        updated = max(3, min(15, int(round(updated))))
                    elif key == 'historySize':
                        updated = max(5, min(30, int(round(updated))))
                    elif key.endswith('Threshold'):
                        updated = max(50, min(3000, int(round(updated))))
                    current[key] = updated
        if type_ == "thresholds":
            low = max(10, min(35, int(current.get("low", 20))))
            medium = max(low + 8, min(65, int(current.get("medium", 45))))
            high = max(medium + 8, min(85, int(current.get("high", 75))))
            block = max(high + 8, min(98, int(current.get("block", 95))))

            current["low"] = low
            current["medium"] = medium
            current["high"] = high
            current["block"] = block

    def evaluate_fitness(self, thresholds: Dict[str, Any], weights: Dict[str, Any], traffic_data: List[Dict[str, Any]]) -> List[float]:
        threat_profiles = {
            "account_takeover": {
                "importance": 10.0,
                "ux_vs_security_ratio": 0.1,
                "indicators": ["requestPatternScore", "behaviorScore", "timeInconsistencyScore", "clickVarianceScore"]
            },
            "active_exploitation": {
                "importance": 8.0,
                "ux_vs_security_ratio": 0.2,
                "indicators": ["honeypotScore", "headerAnomalyScore"]
            },
            "mass_scraping": {
                "importance": 3.0,
                "ux_vs_security_ratio": 0.8,
                "indicators": ["requestPatternScore", "renderingAnomalyScore", "clientHintsInconsistencyScore", "virtualizationScore"]
            },
            "distributed_botnets": {
                "importance": 6.0,
                "ux_vs_security_ratio": 0.5,
                "indicators": ["subnetScore", "botnetClusterScore", "ipReputationScore", "tlsSpoofingScore"]
            },
            "basic_automation": {
                "importance": 5.0,
                "ux_vs_security_ratio": 0.4,
                "indicators": ["botScore", "tlsSpoofingScore", "tcpAnomalyScore", "virtualizationScore"]
            }
        }

        threat_stats = {
            name: {"fp": 0.0, "fn": 0.0, "totalHumans": 0.0, "totalBots": 0.0}
            for name in threat_profiles
        }

        max_human_score = 0.0
        min_bot_score = 100.0
        low_threshold = float(thresholds.get("low", 20.0))

        for log in traffic_data:
            log_type = log.get("type")
            vector = log.get("vector", {})

            score = 0.0
            for w_key in weights.keys():
                score += float(vector.get(w_key, 0.0)) * float(weights[w_key])

            is_likely_bot = log_type in ("request_blocked", "trap_triggered")
            is_likely_human = log_type in ("request_passed", "challenge_solved")

            if is_likely_bot:
                min_bot_score = min(min_bot_score, score)
            elif is_likely_human:
                max_human_score = max(max_human_score, score)

            for name, profile in threat_profiles.items():
                threat_score = sum(float(vector.get(ind, 0.0)) * float(weights.get(ind, 0.0)) for ind in profile["indicators"])
                stats = threat_stats[name]
                if is_likely_bot:
                    stats["totalBots"] += 1.0
                    if threat_score < low_threshold:
                        stats["fn"] += 1.0
                elif is_likely_human:
                    stats["totalHumans"] += 1.0
                    if threat_score >= low_threshold:
                        stats["fp"] += 1.0

        weighted_fpr = 0.0
        weighted_fnr = 0.0
        total_importance = sum(p["importance"] for p in threat_profiles.values())

        for name, profile in threat_profiles.items():
            stats = threat_stats[name]
            fpr = stats["fp"] / stats["totalHumans"] if stats["totalHumans"] > 0.0 else 0.0
            fnr = stats["fn"] / stats["totalBots"] if stats["totalBots"] > 0.0 else 0.0

            importance_weight = profile["importance"] / total_importance
            ux_ratio = profile["ux_vs_security_ratio"]
            sec_ratio = 1.0 - ux_ratio

            weighted_fpr += fpr * importance_weight * ux_ratio
            weighted_fnr += fnr * importance_weight * sec_ratio

        margin_overlap = max(0.0, max_human_score - min_bot_score)
        margin_penalty = margin_overlap / 100.0

        return [weighted_fpr, weighted_fnr + margin_penalty]

    def solve_full_security_tuning(self, traffic_data: List[Dict[str, Any]]) -> List[Individual]:
        population_size = 50
        generations = 50
        mutation_rate = 0.1

        population = []
        for _ in range(population_size):
            population.append(self.random_individual())

        for ind in population:
            ind.objectives = self.evaluate_fitness(ind.thresholds, ind.weights, traffic_data)

        for _ in range(generations):
            offspring = []
            for _ in range(population_size):
                p1 = random.choice(population)
                p2 = random.choice(population)
                child = self.crossover(p1, p2)
                if random.random() < mutation_rate:
                    self.mutate(child)
                child.objectives = self.evaluate_fitness(child.thresholds, child.weights, traffic_data)
                offspring.append(child)

            combined = population + offspring
            fronts = self.non_dominated_sort(combined)

            next_pop = []
            for front in fronts:
                if len(next_pop) + len(front) <= population_size:
                    next_pop.extend(front)
                else:
                    self.calculate_crowding_distance(front)
                    front.sort(key=lambda x: x.crowding_distance, reverse=True)
                    remaining = population_size - len(next_pop)
                    next_pop.extend(front[:remaining])
                    break
            population = next_pop

        return self.non_dominated_sort(population)[0]

    def random_individual(self) -> Individual:
        ind = Individual()
        low = random.randint(10, 35)
        medium = low + 10 + random.randint(0, 25)
        high = medium + 10 + random.randint(0, 20)
        block = high + 8 + random.randint(0, 10)

        ind.thresholds = {"low": low, "medium": medium, "high": high, "block": block}
        weights_config = self.security_config.get("weights", {})
        for w_key, w_val in weights_config.items():
            ind.weights[w_key] = float(w_val)
        patterns_config = self.security_config.get("patterns", {})
        for p_key, p_val in patterns_config.items():
            if isinstance(p_val, (int, float)):
                ind.patterns[p_key] = p_val * (0.5 + random.random())
            else:
                ind.patterns[p_key] = p_val
        return ind

    def crossover(self, p1: Individual, p2: Individual) -> Individual:
        child = Individual()
        for key in p1.thresholds.keys():
            child.thresholds[key] = int(round((p1.thresholds[key] + p2.thresholds[key]) / 2.0))
        child.weights = copy.deepcopy(p1.weights)
        for key in p1.patterns.keys():
            if isinstance(p1.patterns[key], (int, float)) and isinstance(p2.patterns[key], (int, float)):
                child.patterns[key] = (p1.patterns[key] + p2.patterns[key]) / 2.0
            else:
                child.patterns[key] = p1.patterns[key]
        return child

    def mutate(self, ind: Individual) -> None:
        mutation_target = random.choice(["thresholds", "patterns"])
        if mutation_target == "thresholds":
            k = random.choice(list(ind.thresholds.keys()))
            ind.thresholds[k] = max(10, ind.thresholds[k] + random.choice([2, -2]))
        elif mutation_target == "patterns" and ind.patterns:
            numeric_keys = [k for k, v in ind.patterns.items() if isinstance(v, (int, float))]
            if numeric_keys:
                k = random.choice(numeric_keys)
                ind.patterns[k] = max(0.05, ind.patterns[k] + (random.random() - 0.5) * 0.2 * ind.patterns[k])

    def non_dominated_sort(self, population: List[Individual]) -> List[List[Individual]]:
        fronts = [[]]
        for p1 in population:
            p1.domination_count = 0
            p1.dominated_solutions = []
            for p2 in population:
                if p1 is p2:
                    continue
                if self.pareto_dominates(p1.objectives, p2.objectives):
                    p1.dominated_solutions.append(p2)
                elif self.pareto_dominates(p2.objectives, p1.objectives):
                    p1.domination_count += 1
            if p1.domination_count == 0:
                p1.rank = 0
                fronts[0].append(p1)

        i = 0
        while len(fronts[i]) > 0:
            next_front = []
            for p1 in fronts[i]:
                for p2 in p1.dominated_solutions:
                    p2.domination_count -= 1
                    if p2.domination_count == 0:
                        p2.rank = i + 1
                        next_front.append(p2)
            i += 1
            if not next_front:
                break
            fronts.append(next_front)
        return fronts

    def pareto_dominates(self, objA: List[float], objB: List[float]) -> bool:
        better = False
        for i in range(len(objA)):
            if objA[i] > objB[i]:
                return False
            if objA[i] < objB[i]:
                better = True
        return better

    def calculate_crowding_distance(self, front: List[Individual]) -> None:
        if not front:
            return
        l = len(front)
        for p in front:
            p.crowding_distance = 0.0

        for i in range(2):
            obj_idx = i
            front.sort(key=lambda x: x.objectives[obj_idx])
            front[0].crowding_distance = float('inf')
            front[-1].crowding_distance = float('inf')

            min_val = front[0].objectives[obj_idx]
            max_val = front[-1].objectives[obj_idx]
            if max_val == min_val:
                continue

            for j in range(1, l - 1):
                front[j].crowding_distance += (front[j + 1].objectives[obj_idx] - front[j - 1].objectives[obj_idx]) / (max_val - min_val)

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
                if c["options"].get("partitioned"):
                    cookie_val += "; Partitioned"
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
                    if c["options"].get("partitioned"):
                        cookie_val += "; Partitioned"
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
                if c["options"].get("partitioned"):
                    cookie_val += "; Partitioned"
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
                if c["options"].get("partitioned"):
                    cookie_val += "; Partitioned"
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
                "historyScore": 0.3,
                "rotationScore": 0.5,
                "inconsistencyScore": 0.8,
                "headerAnomalyScore": 0.2,
                "requestPatternScore": 0.6,
                "behaviorScore": 0.7,
                "clientHintsInconsistencyScore": 0.7,
                "clickVarianceScore": 0.6,
                "crossLayerInconsistencyScore": 0.4,
                "timeInconsistencyScore": 0.9,
                "tlsSpoofingScore": 0.8,
                "botScore": 1.0,
                "cookieDroppingScore": 0.9,
                "subnetScore": 0.4,
                "ipReputationScore": 0.5,
                "botnetClusterScore": 0.7,
                "tcpAnomalyScore": 0.8,
                "protocolAnomalyScore": 0.8,
                "threatIntelScore": 1.0,
                "honeypotScore": 1.0,
                "quicAnomalyScore": 0.8,
                "renderingAnomalyScore": 0.8,
                "virtualizationScore": 0.8,
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