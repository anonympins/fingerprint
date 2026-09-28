import collections
import json
import math
import re
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urlencode

from builder import cyrb53
from optimization import Optimization
from tls_parser import TLSClientHelloParser
from utils import get_ip_subnet, get_ip_common_prefix_length
from waf import MaliciousPatterns


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


@dataclass
class RequestContext:
    """
    Represents the context of an incoming HTTP request, providing a unified interface
    to access information needed for fingerprint analysis.
    """
    client_ip: str = "127.0.0.1"
    path: str = "/"
    headers: Dict[str, str] = field(default_factory=dict)
    query_params: Dict[str, Any] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    body: Optional[Any] = None
    http_version: str = "1.1"
    scheme: str = "http"
    request_timestamp: int = field(default_factory=lambda: int(time.time() * 1000))
    new_cookies: List[Dict[str, Any]] = field(default_factory=list)
    tls_session_id: Optional[str] = None
    quic_fingerprint: Optional[str] = None
    http2_fingerprint: Optional[str] = None
    is_https: bool = False
    raw_tls_client_hello: Optional[bytes] = None
    raw_tcp_binary: Optional[bytes] = None

    def __post_init__(self):
        self.headers = {k.lower(): v for k, v in self.headers.items()}
        if not self.tls_session_id:
            self.tls_session_id = self.headers.get("x-tls-session-id") or self.headers.get("x-ssl-session-id")
        if not self.quic_fingerprint:
            self.quic_fingerprint = self.headers.get("x-quic-fp")
        if not self.http2_fingerprint:
            self.http2_fingerprint = self.headers.get("x-http2-fingerprint")
        self.is_https = (
            self.scheme == "https" or
            self.headers.get("x-forwarded-proto") == "https" or
            self.headers.get("x-forwarded-ssl") == "on" or
            self.headers.get("x-url-scheme") == "https"
        )

        raw_tls = self.headers.get("x-raw-tls-client-hello") or self.raw_tls_client_hello
        if raw_tls:
            try:
                raw_bytes = bytes.fromhex(raw_tls) if isinstance(raw_tls, str) else raw_tls
                tls_data = TLSClientHelloParser.parse(raw_bytes)
                if tls_data:
                    if "ja3_hash" in tls_data and "x-ja3-hash" not in self.headers:
                        self.headers["x-ja3-hash"] = tls_data["ja3_hash"]
                    if "ja4_raw" in tls_data and "x-ja4-hash" not in self.headers:
                        self.headers["x-ja4-hash"] = tls_data["ja4_raw"]
                    if "quic_fp" in tls_data and not self.quic_fingerprint:
                        self.quic_fingerprint = tls_data["quic_fp"]
            except Exception:
                pass

        if self.raw_tcp_binary and "x-raw-tcp-binary" not in self.headers:
            self.headers["x-raw-tcp-binary"] = self.raw_tcp_binary.hex() if isinstance(self.raw_tcp_binary, bytes) else str(self.raw_tcp_binary)

    def get_header(self, name: str) -> Optional[str]:
        return self.headers.get(name.lower())


class RequestUtils:
    _botnet_clusters: Dict[str, List[Dict[str, Any]]] = {}

    @staticmethod
    def parse_user_agent(ua: str) -> Dict[str, Optional[str]]:
        result = {"browser": None, "os": None, "device": "desktop"}
        ua_lower = ua.lower()
        if "chrome" in ua_lower and "edg" not in ua_lower:
            result["browser"] = "Chrome"
            match = re.search(r"Chrome/(\d+)", ua)
            if match:
                result["browser"] += "/" + match.group(1)
                result["version"] = int(match.group(1))
        elif "firefox" in ua_lower:
            result["browser"] = "Firefox"
            match = re.search(r"Firefox/(\d+)", ua)
            if match:
                result["browser"] += "/" + match.group(1)
                result["version"] = int(match.group(1))
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
        protocol_anomaly = 0.0
        ua = context.headers.get("user-agent", "")
        ua_parts = RequestUtils.parse_user_agent(ua)
        browser = ua_parts.get("browser") or ""
        http_version = getattr(context, "http_version", "") or ""
        is_h2_or_h3 = "2" in http_version or "3" in http_version

        if is_h2_or_h3:
            forbidden_headers = ["connection", "keep-alive", "proxy-connection", "transfer-encoding"]
            for h in forbidden_headers:
                if h in context.headers:
                    protocol_anomaly += 70.0
                    break

        behavior_header = context.headers.get("x-behavior-metrics")
        if behavior_header:
            try:
                metrics = json.loads(behavior_header)
                if isinstance(metrics, dict) and "network" in metrics:
                    client_proto = metrics["network"].get("nextHopProtocol")
                    if client_proto:
                        server_proto = "h2" if "2" in http_version else ("h3" if "3" in http_version else "http/1.1")
                        if "h2" in client_proto: client_proto_norm = "h2"
                        elif "h3" in client_proto: client_proto_norm = "h3"
                        elif "1.1" in client_proto: client_proto_norm = "http/1.1"
                        else: client_proto_norm = client_proto
                        
                        if server_proto != client_proto_norm:
                            if client_proto_norm == "h3" and server_proto == "http/1.1":
                                protocol_anomaly += 85.0
                            elif client_proto_norm == "h2" and server_proto == "http/1.1":
                                protocol_anomaly += 65.0
                            else:
                                protocol_anomaly += 50.0
            except (json.JSONDecodeError, ValueError, TypeError):
                pass

        h2_fp = context.headers.get("x-http2-fingerprint") or getattr(context, "http2_fingerprint", None)
        if browser and h2_fp and isinstance(h2_fp, str):
            parts = h2_fp.split("|")
            if len(parts) >= 3:
                try:
                    conn_window = int(parts[1])
                except ValueError:
                    conn_window = 0
                stream_priority = parts[2] if len(parts) > 2 else ''
                header_order = parts[3].strip().lower() if len(parts) > 3 else ''
                is_chromium = browser.startswith("Chrome") or browser.startswith("Edge")
                is_firefox = browser.startswith("Firefox")
                is_safari = browser.startswith("Safari")

                if is_chromium:
                    if header_order and header_order != "m,a,s,p":
                        http2_anomaly += 60.0
                    if conn_window in (65535, 65536):
                        http2_anomaly += 40.0
                    if stream_priority == '0' or stream_priority == '':
                        http2_anomaly += 50.0
                elif is_firefox:
                    if header_order and header_order != "m,s,p,a":
                        http2_anomaly += 60.0
                elif is_safari:
                    if header_order and header_order != "m,s,p,a":
                        http2_anomaly += 60.0

                if len(parts) >= 5:
                    frame_counts_str = parts[4]
                    frame_counts = {}
                    for item in frame_counts_str.split(','):
                        kv = item.split(':')
                        if len(kv) == 2:
                            try:
                                frame_counts[kv[0]] = int(kv[1])
                            except ValueError:
                                pass

                    priority_count = frame_counts.get('p', 0)
                    window_update_count = frame_counts.get('w', 0)
                    continuation_count = frame_counts.get('c', 0)

                    if is_chromium:
                        if priority_count == 0:
                            http2_anomaly += 25.0
                        if window_update_count < 2:
                            http2_anomaly += 20.0
                        priority_deps = stream_priority.count(',')
                        if "," in stream_priority and priority_deps < 2 and priority_count > 0:
                            http2_anomaly += 35.0
                    elif is_firefox:
                        if priority_count > 1:
                            http2_anomaly += 20.0

                    if continuation_count == 0 and header_order.count(',') > 3:
                        http2_anomaly += 30.0

        is_modern_browser = browser.startswith("Chrome") or browser.startswith("Firefox") or browser.startswith("Edge") or browser.startswith("Safari")
        has_proxy_header = any(h in context.headers for h in ["via", "forwarded", "x-forwarded-for"])

        if is_modern_browser and context.is_https and "1.1" in http_version and not has_proxy_header:
            protocol_anomaly += 45.0

        if "3" in http_version:
            non_browser_uas = ["python", "go-http-client", "curl", "java", "okhttp"]
            ua_lower = ua.lower()
            if any(lib in ua_lower for lib in non_browser_uas):
                protocol_anomaly += 90.0

        quic_res = RequestUtils.get_quic_anomaly_score(context)
        quic_anomaly = quic_res.get("quicAnomalyScore", 0.0)

        # HPACK / QPACK Compression Ratio Analysis
        compression_info = context.headers.get("x-compression-info")
        if compression_info:
            info = {}
            for p in compression_info.split(","):
                kv = p.split(":", 1)
                if len(kv) == 2:
                    try: info[kv[0].strip()] = float(kv[1].strip())
                    except ValueError: pass
            req_count = info.get("req_count", 0.0)
            hpack_ratio = info.get("hpack_ratio")
            qpack_ratio = info.get("qpack_ratio")
            claimed_family = browser.split("/")[0] if browser else ""
            is_human = claimed_family in ("Chrome", "Firefox", "Safari", "Edge")
            if req_count > 3 and is_human:
                if hpack_ratio is not None and hpack_ratio < 0.4:
                    http2_anomaly += (1.0 - hpack_ratio) * 50.0
                if qpack_ratio is not None and qpack_ratio < 0.4:
                    quic_anomaly += (1.0 - qpack_ratio) * 50.0

        proto_score = max(min(100.0, protocol_anomaly), min(100.0, http2_anomaly), min(100.0, quic_anomaly))
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
            if priority_order:
                if "u=" in priority_order and "i" not in priority_order:
                    anomaly += 40.0
                elif "u=" not in priority_order:
                    anomaly += 30.0
                if priority_order in ("p", "i"):
                    anomaly += 50.0

            if bidi_local > 0 and (bidi_local < 524288 or bidi_local == 262144):
                anomaly += 40.0
            if bidi_remote > 0 and (bidi_remote < 524288 or bidi_remote == 262144):
                anomaly += 30.0

            if len(frame_order) >= 2:
                s_idx = next((i for i, f in enumerate(frame_order) if f in ("s", "settings", "4")), -1)
                m_idx = next((i for i, f in enumerate(frame_order) if f in ("m", "max_streams", "18")), -1)
                p_idx = next((i for i, f in enumerate(frame_order) if f in ("p", "priority", "priority_update", "15")), -1)

                if s_idx != 0 and s_idx != -1:
                    anomaly += 50.0
                if m_idx != -1 and s_idx != -1 and m_idx < s_idx:
                    anomaly += 60.0
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
                anomaly += 60.0
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

        if isinstance(header, (int, float)):
            return max(0.0, min(100.0, float(header)))

        if isinstance(header, str):
            try:
                num = float(header.strip())
                return max(0.0, min(100.0, num))
            except ValueError:
                pass

        try:
            metrics = json.loads(header)
        except Exception:
            return 10.0

        if isinstance(metrics, (int, float)):
            return max(0.0, min(100.0, float(metrics)))

        if not isinstance(metrics, dict):
            return 0.0

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
                no_interaction_penalty = 5.0
                if metrics.get("rendering", {}).get("offscreenAnom"): no_interaction_penalty += 40.0
                score += no_interaction_penalty
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

        ua = context.headers.get("user-agent", "")
        is_mobile_device = "Mobile" in ua
        motion_variance = metrics.get("motionVariance")
        if is_mobile_device and isinstance(motion_variance, (int, float)) and motion_variance == 0.0:
            score += 50.0
        return min(100.0, score)

    @staticmethod
    def get_virtualization_anomaly_score(context: RequestContext) -> float:
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
            virtual_gpus = [
                "Google SwiftShader", "SwiftShader", "Mesa llvmpipe",
                "llvmpipe", "Mesa Gallium", "Microsoft Basic Render Driver",
                "HeadlessChrome", "Intel(R) HD Graphics"
            ]
            virtual_gpu_hashes = {str(cyrb53(gpu)) for gpu in virtual_gpus}
            if client_gpu_hash in virtual_gpu_hashes:
                score += 75.0

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

        enumeration_score = 0.0
        if len(history) >= 3:
            templates = [re.sub(r"\d+", "{num}", h["path"]) for h in history]
            unique_paths = set(h["path"] for h in history)
            template_counts = collections.Counter(templates)
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

        bayesian_density = (high_score_count + 0.5) / (device_count + 2.5)
        ip_dispersion = min(2.0, ip_count / device_count)
        ip_multiplier = 0.6 + 0.4 * math.tanh(ip_dispersion)
        ua_dispersion = min(3.0, max(1, ua_count) / device_count)
        ua_multiplier = 0.7 + 0.3 * math.tanh(ua_dispersion - 1.0)

        raw_threat_intensity = high_score_count * bayesian_density * ip_multiplier * ua_multiplier

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
            if MaliciousPatterns.is_malicious(context.path, types_to_detect):
                return 100.0
            for k, v in data.items():
                if isinstance(v, str) and MaliciousPatterns.is_malicious(v, types_to_detect): return 100.0
                elif isinstance(v, dict) and MaliciousPatterns.is_malicious(json.dumps(v), types_to_detect): return 100.0
        return 0.0

    @staticmethod
    def get_bot_score(context: RequestContext) -> float:
        client_fp = context.headers.get("x-device-fingerprint", "")
        if not client_fp:
            return 0.0
        if "bot:true" in client_fp or "cdp:true" in client_fp:
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

    @staticmethod
    def get_mtu_anomaly_score(context: RequestContext) -> float:
        score = 0.0
        mss = None
        mtu = None
        df_bit = True

        if context.headers.get("x-tcp-mtu-info"):
            try:
                parts = context.headers["x-tcp-mtu-info"].split(',')
                info = {p.split(':')[0].strip(): p.split(':')[1].strip() for p in parts if ':' in p}
                if 'mss' in info: mss = int(info['mss'])
                if 'mtu' in info: mtu = int(info['mtu'])
                if 'df' in info: df_bit = info['df'] in ('1', 'true')
            except (ValueError, IndexError):
                pass
        
        if mss is None:
            mss_headers = ["x-tcp-mss", "x-mss", "x-forwarded-mss"]
            for h in mss_headers:
                if context.headers.get(h):
                    try:
                        mss = int(context.headers[h])
                        break
                    except ValueError:
                        pass

        if mss is None or mtu is None:
            behavior_header = context.headers.get("x-behavior-metrics")
            if behavior_header:
                try:
                    metrics = json.loads(behavior_header)
                    if isinstance(metrics, dict) and "network" in metrics:
                        if mss is None and metrics["network"].get("netMss"):
                            mss = int(metrics["network"]["netMss"])
                        if mtu is None and metrics["network"].get("netMtu"):
                            mtu = int(metrics["network"]["netMtu"])
                except (json.JSONDecodeError, ValueError, TypeError):
                    pass

        if mtu is None and mss is not None:
            is_ipv6 = ":" in context.client_ip
            header_size = 60 if is_ipv6 else 40
            mtu = mss + header_size

        if mtu is None:
            return 0.0

        if mtu <= 1420:
            score += 65.0
        elif mtu <= 1450:
            score += 55.0
        elif mtu < 1492:
            score += 30.0

        ua_os = RequestUtils.parse_user_agent(context.headers.get("user-agent", "")).get("os")
        if ua_os:
            if "Windows" in ua_os:
                if mtu < 1492 and mtu > 0:
                    if mtu < 1472:
                        score += 25.0
                if not df_bit:
                    score += 40.0
            
            if "Linux" in ua_os and mtu > 1500:
                score += 35.0

        return min(100.0, score)


parse_user_agent = RequestUtils.parse_user_agent
get_protocol_anomaly_score = RequestUtils.get_protocol_anomaly_score
calculate_analog_inconsistency_score = RequestUtils.calculate_analog_inconsistency_score
get_tcp_anomaly_score = RequestUtils.get_tcp_anomaly_score

__all__ = [
    "RequestContext",
    "RequestUtils",
    "parse_tcp_syn",
    "classify_tcp_os",
    "parse_user_agent",
    "get_protocol_anomaly_score",
    "calculate_analog_inconsistency_score",
    "get_tcp_anomaly_score",
]