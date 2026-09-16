import math
import time

async def get_botnet_cluster_score(store, context, stable_fp_hash, get_ip_subnet_fn):
    if not stable_fp_hash:
        return {"botnetClusterScore": 0.0}

    key = f"botnet-cluster:{stable_fp_hash}"
    now = int(time.time())
    ten_minutes_ago = now - 600

    cluster_data = await store.get(key)
    if not isinstance(cluster_data, list):
        cluster_data = []

    # Filtre les anciens enregistrements de plus de 10 minutes
    cluster_data = [entry for entry in cluster_data if entry.get("timestamp", 0) > ten_minutes_ago]

    user_agent = context.get_header("user-agent") or ""
    subnet = get_ip_subnet_fn(context.client_ip) or "unknown"

    existing_entry = next((entry for entry in cluster_data if entry.get("ip") == context.client_ip), None)

    if existing_entry:
        existing_entry["timestamp"] = now
        existing_entry["ua"] = user_agent
        existing_entry["subnet"] = subnet
    else:
        cluster_data.append({
            "ip": context.client_ip,
            "timestamp": now,
            "ua": user_agent,
            "subnet": subnet
        })

    await store.set(key, cluster_data, 600)

    unique_ips_count = len(cluster_data)
    botnet_cluster_score = 0.0

    if unique_ips_count >= 2:
        unique_subnets = len(set(entry.get("subnet") for entry in cluster_data if entry.get("subnet")))
        unique_user_agents = len(set(entry.get("ua") for entry in cluster_data if entry.get("ua")))

        subnet_multiplier = 1.3 if unique_subnets > 1 else 0.6
        ua_rotation_multiplier = 1.5 if unique_user_agents > 1 else 1.0

        base_score = 100.0 * (1.0 - math.exp(-0.35 * (unique_ips_count - 1)))
        botnet_cluster_score = min(100.0, round(base_score * subnet_multiplier * ua_rotation_multiplier * 10.0) / 10.0)

    return {"botnetClusterScore": botnet_cluster_score}