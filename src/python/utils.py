import math
import time
import ipaddress
from typing import Optional, Dict, Any, List

from fingerprint import get_composite_device_hash, cyrb53, extract_stable_part

def get_ip_subnet(ip: str, ipv4_prefix: int = 24, ipv6_prefix: int = 48) -> Optional[str]:
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            network = ipaddress.ip_network(f"{ip}/{ipv4_prefix}", strict=False)
            return str(network)
        elif addr.version == 6:
            network = ipaddress.ip_network(f"{ip}/{ipv6_prefix}", strict=False)
            # Retourne le format complet normalisé identique à JS, PHP, Java
            return f"{network.network_address.exploded}/{ipv6_prefix}"
    except Exception:
        return None

async def update_subnet_metrics(store: Any, context: Any, device_id: str, final_score: float) -> None:
    subnet = get_ip_subnet(context.client_ip)
    if not subnet:
        return

    key = f"subnet:{subnet}"
    subnet_data = await store.get(key)
    if not isinstance(subnet_data, dict):
        subnet_data = {
            "highScoreCount": 0,
            "deviceIds": [],
            "highScoreDevices": {},
            "lastActivity": 0,
            "ips": [],
            "uas": []
        }

    if "highScoreDevices" not in subnet_data:
        subnet_data["highScoreDevices"] = {}
    if "ips" not in subnet_data:
        subnet_data["ips"] = []
    if "uas" not in subnet_data:
        subnet_data["uas"] = []

    current_device_hash = get_composite_device_hash(context)
    stable_fp_id = str(cyrb53(extract_stable_part(current_device_hash)))

    current_device_contributions = subnet_data["highScoreDevices"].get(stable_fp_id, 0)
    if current_device_contributions < 1:
        subnet_data["highScoreDevices"][stable_fp_id] = current_device_contributions + 1
        subnet_data["highScoreCount"] += 1

    if stable_fp_id not in subnet_data["deviceIds"]:
        subnet_data["deviceIds"].append(stable_fp_id)

    if context.client_ip not in subnet_data["ips"]:
        subnet_data["ips"].append(context.client_ip)

    user_agent = context.get_header("user-agent") or ""
    if user_agent and user_agent not in subnet_data["uas"]:
        subnet_data["uas"].append(user_agent)

    subnet_data["lastActivity"] = int(time.time() * 1000)

    if len(subnet_data["deviceIds"]) > 100:
        old_device_id = subnet_data["deviceIds"].pop(0)
        if old_device_id in subnet_data["highScoreDevices"]:
            old_contributions = subnet_data["highScoreDevices"][old_device_id]
            subnet_data["highScoreCount"] = max(0, subnet_data["highScoreCount"] - old_contributions)
            del subnet_data["highScoreDevices"][old_device_id]

    if len(subnet_data["ips"]) > 100:
        subnet_data["ips"].pop(0)
    if len(subnet_data["uas"]) > 50:
        subnet_data["uas"].pop(0)

    await store.set(key, subnet_data, 86400)

async def get_subnet_score(store: Any, context: Any, device_id: str) -> Dict[str, float]:
    subnet = get_ip_subnet(context.client_ip)
    if not subnet:
        return {"subnetScore": 0.0}

    subnet_data = await store.get(f"subnet:{subnet}")
    if not subnet_data:
        return {"subnetScore": 0.0}

    now = int(time.time() * 1000)
    last_activity = subnet_data.get("lastActivity", now)
    inactivity_sec = (now - last_activity) / 1000
    half_lives = int(inactivity_sec // 1800)

    high_score_count = subnet_data.get("highScoreCount", 0)
    device_count = len(subnet_data.get("deviceIds", []))
    ip_count = len(subnet_data.get("ips", [])) or 1

    if half_lives > 0:
        decay = 2 ** half_lives
        high_score_count = max(0, int(high_score_count // decay))
        device_count = max(0, int(device_count // decay))
        ip_count = max(1, int(ip_count // decay))

    if device_count == 0:
        return {"subnetScore": 0.0}

    suspicion_density = high_score_count / device_count
    ip_device_ratio = ip_count / device_count

    base_score = 100.0 * (1.0 - math.exp(-0.15 * high_score_count))

    density_multiplier = 0.4 + (1.6 * suspicion_density)
    distribution_multiplier = 0.5 + (1.0 * ip_device_ratio)
    dampening = 1.0
    if high_score_count < 3:
        dampening = high_score_count / 3.0
    final_score = min(100.0, round(base_score * density_multiplier * distribution_multiplier * dampening * 10.0) / 10.0)
    return {"subnetScore": final_score}

async def get_botnet_cluster_score(store: Any, context: Any, stable_fp_hash: str) -> Dict[str, float]:
    if not stable_fp_hash:
        return {"botnetClusterScore": 0.0}

    key = f"botnet-cluster:{stable_fp_hash}"
    now = int(time.time())
    ten_minutes_ago = now - 600

    cluster_data = await store.get(key)
    if not isinstance(cluster_data, list):
        cluster_data = []

    active_data = [entry for entry in cluster_data if entry.get("timestamp", 0) > ten_minutes_ago]

    user_agent = context.get_header("user-agent") or ""
    subnet = get_ip_subnet(context.client_ip) or "unknown"

    existing_entry = next((entry for entry in active_data if entry.get("ip") == context.client_ip), None)
    if existing_entry:
        existing_entry["timestamp"] = now
        existing_entry["ua"] = user_agent
        existing_entry["subnet"] = subnet
    else:
        active_data.append({
            "ip": context.client_ip,
            "timestamp": now,
            "ua": user_agent,
            "subnet": subnet
        })

    await store.set(key, active_data, 600)

    unique_ips_count = len(active_data)
    botnet_cluster_score = 0.0
    if unique_ips_count >= 2:
        unique_subnets = len(set(entry.get("subnet") for entry in active_data if entry.get("subnet")))
        unique_user_agents = len(set(entry.get("ua") for entry in active_data if entry.get("ua")))

        subnet_multiplier = 1.3 if unique_subnets > 1 else 0.6
        ua_rotation_multiplier = 1.5 if unique_user_agents > 1 else 1.0

        base_score = 100.0 * (1.0 - math.exp(-0.35 * (unique_ips_count - 1)))
        botnet_cluster_score = min(100.0, round(base_score * subnet_multiplier * ua_rotation_multiplier * 10.0) / 10.0)

    return {"botnetClusterScore": botnet_cluster_score}