# attack detection rules

def check_flood(stats):
    alerts = []
    if stats["tcp_count"] > 0:
        syn_ratio = stats["syn_count"] / stats["tcp_count"]
        if syn_ratio > 0.85 and stats["packet_count"] > 50:
            alerts.append(("SYN_FLOOD", f"{syn_ratio:.0%} SYN"))
    if stats.get("packets_per_sec", 0) > 1000:
        alerts.append(("HIGH_TRAFFIC", f"{stats['packets_per_sec']:.0f} pps"))
    return alerts

def check_port_scan(stats):
    alerts = []
    if stats["unique_dst_port_count"] > 15 and stats["packet_count"] > 20:
        alerts.append(("PORT_SCAN", f"{stats['unique_dst_port_count']} ports"))
    return alerts

def check_ssh_bruteforce(window):
    ssh = 0
    for p in window:
        if p.get("dst_port") == 22:
            ssh += 1
    if ssh > 20:
        return [("SSH_BRUTEFORCE", f"{ssh} attempts")]
    return []
