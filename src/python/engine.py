import hmac
import hashlib
import time
import uuid
import math
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
from typing import Dict, Any, List, Optional, Callable, Set, Union

from utils import get_ip_subnet, is_loopback_ip, get_ip_common_prefix_length
from challenge_utils import ChallengeUtils
from request_utils import (
    RequestContext,
    RequestUtils,
    parse_tcp_syn,
    classify_tcp_os,
    calculate_analog_inconsistency_score,
    get_tcp_anomaly_score,
    parse_user_agent,
)
from builder import (
    FingerprintBuilder,
    cyrb53,
    imul,
    extract_stable_part,
    get_composite_device_hash,
)
from storage import InMemoryStore, RedisStore, MongoDbStore
from waf import MaliciousPatterns
from metrics import MetricsManager
from tls_parser import TLSClientHelloParser
from optimization import (
    sanitize_traffic_data,
    Individual,
    Optimization,
    OptimizationOperators,
    AutoTuner,
)
from client import FingerprintClient
from security_profiles import SecurityProfiles
from key_manager import initialize_ed25519_keys as setup_ed25519_keys

__all__ = [
    # Types et contextes principaux
    "RequestContext",
    "FingerprintEngine",
    "BlockList",
    "ChallengeUtils",
    "RequestUtils",
    "calculate_analog_inconsistency_score",
    "get_tcp_anomaly_score",
    # Circuit breaker DNS & whitelists
    "dns_circuit_breaker",
    "record_dns_success",
    "record_dns_failure",
    "can_attempt_dns",
    "default_whitelist",
    "DEFAULT_WEIGHTS",
    "parse_tcp_syn",
    "classify_tcp_os",
    "generate_space_challenge",
    "generate_space_challenge_page",
    # Re-exports de compatibilité avec les modules délégués
    "get_ip_subnet",
    "imul",
    "cyrb53",
    "extract_stable_part",
    "get_composite_device_hash",
    "FingerprintBuilder",
    "InMemoryStore",
    "RedisStore",
    "MongoDbStore",
    "MaliciousPatterns",
    "MetricsManager",
    "TLSClientHelloParser",
    "FingerprintClient",
    "Individual",
    "Optimization",
    "OptimizationOperators",
    "AutoTuner",
    "sanitize_traffic_data",
    "ASGIFingerprintMiddleware",
    "WSGIFingerprintMiddleware",
    "FastAPIFingerprintMiddleware",
    "ProblemManager",
    "SecurityProfiles",
]

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
_facebook_entries = None

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

def facebook_whitelist() -> dict:
 global _facebook_entries
 if _facebook_entries is None:
     _facebook_entries = load_bot_whitelist("facebook.json", [
         "31.13.64.0/18", "66.220.144.0/20", "69.63.176.0/20", "157.240.0.0/16"
     ])
 return {
     "type": "allowlist",
     "entries": _facebook_entries
 }

def default_whitelist() -> list:
 return [
     googlebot_whitelist(),
     bingbot_whitelist(),
     yandex_whitelist(),
     facebook_whitelist(),
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
    "virtualizationScore": 0.8,
    "mtuAnomalyScore": 0.9
}

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
                                              document.getElementById('loader').innerText = '📤 Direct P2P (WebRTC) block transfer to peer...';
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
              document.getElementById('loader').innerText = '📥 Direct WebRTC P2P connection to peer (' + peerId + ')...';

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
                  document.getElementById('loader').innerText = '⚡ Block received live via WebRTC P2P without server relay!';
              }} else {{
                  document.getElementById('loader').innerText = '⚠️ WebRTC unavailable. Downloading via HTTP relay...';
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

# --- CORE: FingerprintEngine ---
class FingerprintEngine:
    def __init__(self, config: Union[str, Dict[str, Any]], store: Optional[Any] = None):
        """
        Initializes the FingerprintEngine with a security configuration and a data store.

        Args:
            config (Union[str, Dict[str, Any]]): The security configuration dictionary or a profile name.
            store (Optional[Any]): An instance of a data store (e.g., InMemoryStore, RedisStore, MongoDbStore).
        """
        if isinstance(config, str):
            config = SecurityProfiles.create_security_profile(config)
        elif isinstance(config, dict) and "profile" in config:
            profile_name = config.get("profile", "balanced")
            config = SecurityProfiles.create_security_profile(profile_name, config)
        else:
            config = dict(config)

        self.initialize_ed25519_keys(config)
        self.store = store if store is not None else InMemoryStore()
        self.config = config
        if not self.config.get("whitelist"):
            self.config["whitelist"] = default_whitelist()
        self.thresholds = config.get("thresholds", {"low": 20, "medium": 45, "high": 75, "block": 95})
        self.weights = copy.deepcopy(DEFAULT_WEIGHTS)
        if "weights" in config and isinstance(config["weights"], dict):
            self.weights.update(config["weights"])
        self.dry_run = config.get("dryRun", False)
        self._allowlist = self._build_allowlist()

        # Fast-Path local cache to mitigate heavy flood attacks
        # Format: {"ip_or_subnet": (expiration_timestamp, action_to_take)}
        self._fast_path_cache: Dict[str, tuple] = {}
        self._last_prune_time: float = time.time()
        self._prune_interval: float = 10.0  # seconds
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

        if (config.get("useAsymmetricTickets") or config.get("ed25519") == "auto") and not os.environ.get("ED25519_PRIVATE_KEY"):
            try:
                config_dir = config.get("configDir", "config")
                setup_ed25519_keys(config_dir=config_dir, verbose=False)
            except Exception:
                pass
            if not os.environ.get("ED25519_PRIVATE_KEY"):
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

    def get_client(self, client_script_path: Optional[str] = None, client_config: Optional[Dict[str, Any]] = None) -> FingerprintClient:
        """Returns an instance of FingerprintClient configured for this engine."""
        script_path = client_script_path or self.config.get("clientScriptPath", "/static/fp.js")
        cfg = client_config or self.config.get("clientConfig", {})
        return FingerprintClient(script_path, cfg)

    def get_metrics(self) -> str:
        """Returns Prometheus-formatted metrics string for current engine state."""
        last_best = AutoTuner.get_best_tuning_solution() if hasattr(AutoTuner, "get_best_tuning_solution") else None
        return MetricsManager.get_prometheus_metrics(self.config, last_best)

    def create_autotuner(self, options: Optional[Dict[str, Any]] = None) -> AutoTuner:
        """Creates an AutoTuner instance bound to this engine configuration and store."""
        return AutoTuner(self.config, self.store, options)

    def run_autotuning_cycle(self, options: Optional[Dict[str, Any]] = None) -> Any:
        """Runs an optimization cycle and immediately updates engine thresholds and weights."""
        tuner = self.create_autotuner(options)
        res = tuner.run_optimization_cycle()
        best = AutoTuner.get_best_tuning_solution()
        if best:
            if "thresholds" in best and isinstance(best["thresholds"], dict):
                self.thresholds.update(best["thresholds"])
            if "weights" in best and isinstance(best["weights"], dict):
                self.weights.update(best["weights"])
        return res

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
         whitelisted = False
         whitelist_type = ""
         if self._is_ip_in_allowlist(context.client_ip):
             whitelisted = True
             whitelist_type = "allowlist"
         elif self._is_path_in_allowlist(context.path):
             whitelisted = True
             whitelist_type = "path_allowlist"
         elif self._is_host_path_in_allowlist(context.headers.get("host"), context.path):
             whitelisted = True
             whitelist_type = "host_path_allowlist"
         else:
             graphql_op = getattr(context, "graphql_operation", None)
             if graphql_op and self._is_graphql_operation_in_allowlist(graphql_op.get("type"), graphql_op.get("name")):
                 whitelisted = True
                 whitelist_type = "graphql_operation_allowlist"
             elif await self._verify_whitelisted_bot(context):
                 whitelisted = True
                 whitelist_type = "bot"

         if whitelisted:
             filter_whitelist = self.config.get("filterWhitelist", False)
             bypass_whitelist = False
             if filter_whitelist is True or (isinstance(filter_whitelist, (int, float)) and whitelist_type == "bot"):
                 bypass_whitelist = self._has_certain_attack(context)
             elif isinstance(filter_whitelist, (int, float)):
                 score = await self.get_suspicion_score(context)
                 if score > filter_whitelist:
                     bypass_whitelist = True

             if bypass_whitelist:
                 return False
             return True
 
         return False

    def _has_certain_attack(self, context: RequestContext) -> bool:
        """
        Evaluates if the request shows clear attack characteristics
        (such as triggering a honeypot or reaching maximum bot score).

        Args:
            context (RequestContext): The request context.

        Returns:
            bool: True if a clear attack is detected, False otherwise.
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
        Hot-reloads a new security configuration (weights, thresholds, etc.)
        without restarting the engine.
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
        return extract_stable_part(fp_str)

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
        return get_composite_device_hash(context)

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
            secure_option = context.is_https or (self.config.get("env") == "production")
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

        # Smooth analog inconsistency score
        current_hash = self.get_composite_device_hash(context)
        similarity = FingerprintBuilder.compare(device_data.get("initialDeviceHash") or "", current_hash)
        similarity_threshold = float(self.config.get("similarityThreshold", 0.72))
        inconsistency_score = RequestUtils.calculate_analog_inconsistency_score(similarity, similarity_threshold)

        behavioral_indicators = await self.get_behavioral_indicators(context, device_data)
        history_score = behavioral_indicators["historyScore"]
        rotation_score = behavioral_indicators["rotationScore"]

        # 1. Header anomalies
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

        # Validation TLS 1.3 Encrypted Client Hello (ECH) & Discrépance SNI
        outer_sni = context.headers.get("x-ech-outer-sni")
        host = context.headers.get("host", "").split(":")[0].strip()
        has_ech = context.headers.get("x-ech-present") == "true" or context.headers.get("x-has-ech") == "true"
        ech_expected = context.headers.get("x-ech-expected") == "true" or bool(outer_sni)

        if outer_sni and host and outer_sni.lower() != host.lower() and not has_ech:
            tls_spoofing_score = max(tls_spoofing_score, 60.0)

        browser_ver = 0
        ua_parsed = RequestUtils.parse_user_agent(ua)
        if "version" in ua_parsed:
            browser_ver = ua_parsed["version"]

        is_modern_ech_browser = (
            (claimed_browser in ("Chrome", "Edge") and browser_ver >= 119) or
            (claimed_browser == "Firefox" and browser_ver >= 118)
        )
        if context.is_https and is_modern_ech_browser and ech_expected and not has_ech:
            tls_spoofing_score = max(tls_spoofing_score, 55.0)

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

        # Client ZKP public key extraction and validation
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

        mtu_anomaly_score = RequestUtils.get_mtu_anomaly_score(context)


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
            "mtuAnomalyScore": mtu_anomaly_score,
        })
        return suspicion_vector

    def calculate_final_score(self, suspicion_vector: Dict[str, float]) -> float:
        weights = self.config.get("weights", {})
        if not weights:
            return 0.0

        effective_weights = dict(weights)

        # Dynamic amplification based on MTU anomaly
        if suspicion_vector.get("mtuAnomalyScore", 0.0) > 50.0:
            amplification_factor = 1.25
            keys_to_amplify = [
                "tlsSpoofingScore", "crossLayerInconsistencyScore", 
                "clientHintsInconsistencyScore", "behaviorScore",
                "inconsistencyScore", "rotationScore"
            ]
            for key in keys_to_amplify:
                if key in effective_weights:
                    effective_weights[key] *= amplification_factor

        score = 0.0
        for key, weight in effective_weights.items():
            score += suspicion_vector.get(key, 0.0) * weight
        return min(100.0, score)

    async def broadcast_banned_zkp(self, zkp_y: str) -> None:
        peers = self.config.get("federatedPeers") or []
        secret = self.config.get("federationSecret") or os.environ.get("POW_SECRET") or "fallback-dev-secret-32-chars-minimum"
        if not peers:
            return

        import urllib.parse
        import asyncio
        import json

        # Semaphore to cap maximum concurrent sockets and scale gracefully
        semaphore = asyncio.Semaphore(10)

        async def send_report(target_zkp_y: str, ts: int):
            msg = f"{ts}:{target_zkp_y}"
            sig_hmac = hmac.new(secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()
            sig_ed25519 = ""
            ed25519_key_pem = os.environ.get("ED25519_PRIVATE_KEY")
            if ed25519_key_pem:
                try:
                    from cryptography.hazmat.primitives.serialization import load_pem_private_key
                    priv_key = load_pem_private_key(ed25519_key_pem.encode("utf-8"), password=None, backend=default_backend())
                    sig_ed25519 = priv_key.sign(msg.encode("utf-8")).hex()
                except Exception:
                    pass

            is_asymmetric = bool(sig_ed25519)
            signature = sig_ed25519 if is_asymmetric else sig_hmac

            async def send_one(peer_url):
                try:
                    async with semaphore:
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

                        post_data = json.dumps({"zkpY": target_zkp_y})
                        request = (
                            f"POST {path} HTTP/1.1\r\n"
                            f"Host: {host}\r\n"
                            f"Content-Type: application/json\r\n"
                            f"Content-Length: {len(post_data)}\r\n"
                            f"X-Federation-Signature: {'' if is_asymmetric else signature}\r\n"
                            f"X-Federation-Signature-Ed25519: {signature if is_asymmetric else ''}\r\n"
                            f"X-Federation-Timestamp: {ts}\r\n"
                            f"Connection: close\r\n\r\n"
                            f"{post_data}"
                        )
                        writer.write(request.encode("utf-8"))
                        await writer.drain()
                        writer.close()
                        await writer.wait_closed()
                except Exception:
                    pass

            await asyncio.gather(*(send_one(peer) for peer in peers), return_exceptions=True)

        dp_config = self.config.get("differentialPrivacy") or {}
        dp_enabled = dp_config.get("enabled", True) is not False
        epsilon = float(dp_config.get("epsilon") or self.config.get("dpEpsilon") or 1.0)

        now_ms = int(time.time() * 1000)
        report_ts = now_ms
        if dp_enabled:
            delta_t = 5000.0  # 5s sensitivity
            b = delta_t / max(0.1, epsilon)
            u = random.random() - 0.5
            safe_u = (1e-7 if u >= 0 else -1e-7) if abs(u) < 1e-7 else u
            sign_u = 1.0 if safe_u > 0 else (-1.0 if safe_u < 0 else 0.0)
            laplace_noise = -b * sign_u * math.log(1.0 - 2.0 * abs(safe_u))
            clamped_noise = int(max(-60000, min(60000, round(laplace_noise))))
            report_ts = now_ms + clamped_noise

        await send_report(zkp_y, report_ts)

        if dp_enabled:
            dummy_rate = dp_config.get("dummyRate")
            decoy_prob = float(dummy_rate) if dummy_rate is not None else (1.0 / (1.0 + math.exp(epsilon)))
            if random.random() < decoy_prob:
                zkp_p = 115792089237316195423570985008687907853269984665640564039457584007908834671663
                decoy_int = (int.from_bytes(os.urandom(32), byteorder="big") % (zkp_p - 2)) + 1
                decoy_zkp_y = hex(decoy_int)[2:]

                u_decoy = random.random() - 0.5
                safe_u_decoy = (1e-7 if u_decoy >= 0 else -1e-7) if abs(u_decoy) < 1e-7 else u_decoy
                sign_u_decoy = 1.0 if safe_u_decoy > 0 else (-1.0 if safe_u_decoy < 0 else 0.0)
                b = 5000.0 / max(0.1, epsilon)
                decoy_noise = int(max(-60000, min(60000, round(-b * sign_u_decoy * math.log(1.0 - 2.0 * abs(safe_u_decoy))))))
                decoy_ts = now_ms + decoy_noise

                await send_report(decoy_zkp_y, decoy_ts)

        await asyncio.gather(*(send_one(peer) for peer in peers), return_exceptions=True)

    def get_rtt_proxy_score(self, context: RequestContext) -> float:
        """
        Feature 7: RTT & Residential Proxy Latency Correlation.
        Compares real TCP transport RTT with client application timestamp
        to unmask rotating residential proxies.
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
                if not isinstance(metrics, dict):
                    return 0.0
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
                # Silent fail-safe
                pass
        return 0.0

    async def calculate_threat_intel_score(self, context: RequestContext, zkp_y: Optional[str]) -> float:
        # Base Threat Intelligence score retrieval (ZKP reputation)
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

        # 1. Periodic cleanup of the fast-path cache
        if current_time - self._last_prune_time > self._prune_interval:
            self._fast_path_cache = {
                k: v for k, v in self._fast_path_cache.items() if v[0] > current_time
            }
            self._last_prune_time = current_time

        # 2. Fast-Path short-circuit check
        # Immediately enforce action if client IP or subnet is cached
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
                        # Return lightweight challenge without regenerating expensive nonces
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
                    pm = self.problem_manager
                    if pm is None:
                        default_path = os.path.join(os.getcwd(), "problems.config.json")
                        config_path = self.config.get("usefulWorkConfigPath") or (default_path if os.path.exists(default_path) else None)
                        pm = ProblemManager.get_instance(config_path, self.store)
                        if not pm.initialized:
                            await pm.load_problems()
                    if pm is not None:
                        await pm.integrate_solution(pow_problem_id, work_result)

                    # If the solved problem is security auto-tuning and auto-tuning is enabled,
                    # directly apply the best computed solution to the live engine.
                    if pow_problem_id == "security_auto_tuning" and self.config.get("autotuning", {}).get("enabled", False):
                        pareto_front = work_result.get("paretoFront")
                        if isinstance(pareto_front, list) and pareto_front:
                            best_solution = pareto_front[0]
                            min_distance = math.sqrt(
                                float(best_solution['objectives'][0])**2 + float(best_solution['objectives'][1])**2
                            )
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
                    secure_option = context.is_https or (self.config.get("env") == "production")
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
                    secure_option = context.is_https or (self.config.get("env") == "production")
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
                    secure_option = context.is_https or (self.config.get("env") == "production")
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
            # Use stable hardware ID to prevent false positives during cookie dropping
            current_hash = self.get_composite_device_hash(context)
            stable_fp_id = str(cyrb53(self._extract_stable_part(current_hash)))
            await RequestUtils.update_subnet_metrics(self.store, context, stable_fp_id, score)
            MetricsManager.observe_value("suspicion_score", score, {"action": "high_score_subnet_update"})


        if score >= block_threshold:
            # Flood mitigation: cache block action locally for 10s
            # Avoids DB queries and fingerprint recalculation for subsequent flood requests
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
            # --- Domain and subnet Token Bucket rate limiter ---
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
            # Linear CPU / Memory synchronous work effort ratio
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

get_tcp_anomaly_score = RequestUtils.get_tcp_anomaly_score

# Imports différés après la définition de FingerprintEngine pour casser l'import circulaire
try:
    from middleware import (
        ASGIFingerprintMiddleware,
        WSGIFingerprintMiddleware,
        FastAPIFingerprintMiddleware,
    )
except ImportError:
    from middleware import (
        ASGIFingerprintMiddleware,
        WSGIFingerprintMiddleware,
    )
    FastAPIFingerprintMiddleware = None

if __name__ == "__main__":
    import asyncio
    import json

    async def run_demo():
        print("=" * 60)
        print("  FINGERPRINT ENGINE - PYTHON DEMO RUN")
        print("=" * 60)

        # 1. Sample "balanced" security configuration
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

        # Scenario A: Legitimate request (New device)
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

        print("\n[Action] Simulating legitimate request (human)...")
        decision_legit = await engine.process_request(context_legit)
        print(f"-> Decision: {decision_legit['action']}")
        print(f"-> Generated Cookie: {json.dumps(decision_legit.get('newCookieForResponse'))}")

        # Scenario B: Hostile request (Bot accessing a honeypot URL)
        context_bot = RequestContext(
            client_ip="203.0.113.88",
            path="/.env",
            headers={"user-agent": "curl/7.68.0"},
            query_params={},
            cookies={}
        )

        print("\n[Action] Simulating bot attack (accessing /.env)...")
        decision_bot = await engine.process_request(context_bot)
        print(f"-> Decision: {decision_bot['action']} (Status: {decision_bot.get('status')})")
        print(f"-> Returned response: {decision_bot.get('body')}")
        print("=" * 60)

    asyncio.run(run_demo())