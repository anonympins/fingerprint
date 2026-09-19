import re

class RequestContext:
    def __init__(self, headers, http_version, http2_fingerprint=None, quic_fingerprint=None):
        self.headers = {k.lower(): v for k, v in headers.items()} if headers else {}
        self.http_version = http_version or "1.1"
        self.http2_fingerprint = http2_fingerprint or self.headers.get('x-http2-fingerprint')
        self.quic_fingerprint = quic_fingerprint or self.headers.get('x-quic-fp')

    def get_header(self, name):
        return self.headers.get(name.lower())

def parse_user_agent(ua):
    result = {"browser": None, "os": None, "device": "desktop"}
    if not ua:
        return result
    
    # Browser detection
    if "Chrome" in ua and "Edg" not in ua:
        result["browser"] = "Chrome"
        match = re.search(r"Chrome/(\d+)", ua)
        if match:
            result["browser"] += f"/{match.group(1)}"
    elif "Firefox" in ua:
        result["browser"] = "Firefox"
        match = re.search(r"Firefox/(\d+)", ua)
        if match:
            result["browser"] += f"/{match.group(1)}"
    elif "Safari" in ua and "Chrome" not in ua:
        result["browser"] = "Safari"
        match = re.search(r"Version/(\d+)", ua)
        if match:
            result["browser"] += f"/{match.group(1)}"
    elif "Edg" in ua:
        result["browser"] = "Edge"
        match = re.search(r"Edg/(\d+)", ua)
        if match:
            result["browser"] += f"/{match.group(1)}"

    # OS detection
    if "Windows NT 10.0" in ua:
        result["os"] = "Windows"
    elif "Mac OS X" in ua:
        result["os"] = "macOS"
    elif "Android" in ua:
        result["os"] = "Android"
    elif "iPhone" in ua or "iPad" in ua:
        result["os"] = "iOS"
    elif "Linux" in ua:
        result["os"] = "Linux"

    if "Mobile" in ua:
        result["device"] = "mobile"
    elif "Tablet" in ua:
        result["device"] = "tablet"

    return result

def get_protocol_anomaly_score(context):
    http2_anomaly = 0.0
    quic_anomaly = 0.0

    ua = context.get_header("user-agent") or ""
    ua_parts = parse_user_agent(ua)
    browser = ua_parts["browser"]

    # HTTP/2 Anomaly logic
    h2_fp = context.http2_fingerprint or context.get_header("x-http2-fingerprint")
    if h2_fp and browser:
        parts = h2_fp.split("|")
        if len(parts) >= 4:
            try:
                conn_window = int(parts[1])
            except ValueError:
                conn_window = 0
            header_order = parts[3]
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

    # QUIC Anomaly logic
    quic_fp = context.quic_fingerprint or context.get_header("x-quic-fp")
    if quic_fp and browser:
        parts = quic_fp.split(";")
        if len(parts) >= 2:
            params = {}
            for p in parts[1].split(","):
                kv = p.split("=", 1)
                if len(kv) == 2:
                    params[kv[0]] = kv[1]
            priority_order = parts[2] if len(parts) > 2 else ""

            if browser.startswith("Chrome") or browser.startswith("Edge"):
                try:
                    max_data = int(params.get("1", "0"))
                    max_streams = int(params.get("4", "0"))
                except ValueError:
                    max_data, max_streams = 0, 0

                if max_data > 0 and max_data < 1048576:
                    quic_anomaly += 40.0
                if max_streams > 0 and max_streams != 100:
                    quic_anomaly += 30.0
                if priority_order and "u=" not in priority_order:
                    quic_anomaly += 30.0
            elif browser.startswith("Firefox"):
                try:
                    max_data = int(params.get("1", "0"))
                except ValueError:
                    max_data = 0
                if max_data > 0 and max_data > 5000000:
                    quic_anomaly += 40.0

    return {
        "protocolAnomalyScore": max(
            0.0,
            min(100.0, http2_anomaly),
            min(100.0, quic_anomaly)
        )
    }