# attack signatures and detection logic
# mitre att&ck mappings for each detection

import time
from collections import defaultdict

MITRE = {
    "SYN_FLOOD": "T1498 - Network Denial of Service",
    "SSH_BRUTEFORCE": "T1110 - Brute Force",
    "PORT_SCAN": "T1046 - Network Service Scanning",
    "DNS_AMPLIFICATION": "T1498.002 - Reflection Amplification",
    "C2_BEACONING": "T1071.001 - Application Layer Protocol",
    "DNS_EXFILTRATION": "T1048 - Exfiltration Over Alternative Protocol",
    "ML_ANOMALY": "T1072 - Unclassified Anomaly",
}

def check_flood(stats):
    """ detects volumetric attacks:
    - syn flood: high syn ratio + high packet count
    - general flood: high pps
    """
    alerts = []

    if stats["packet_count"] < 10:
        return alerts

    pps = stats.get("packets_per_sec", 0)
    bps = stats.get("bytes_per_sec", 0)

    # syn flood detection
    if stats["tcp_count"] > 0:
        syn_ratio = stats["syn_count"] / stats["tcp_count"]
        if syn_ratio > 0.85 and stats["packet_count"] > 50:
            severity = "HIGH" if stats["packet_count"] > 500 else "MEDIUM"
            alerts.append({
                "type": "SYN_FLOOD",
                "severity": severity,
                "desc": f"{syn_ratio:.0%} SYN packets ({stats['packet_count']} total)",
                "mitre": MITRE["SYN_FLOOD"],
                "confidence": min(syn_ratio * 100, 99),
            })

    # high traffic volume
    if pps > 1000:
        alerts.append({
            "type": "VOLUMETRIC_ANOMALY",
            "severity": "HIGH",
            "desc": f"{pps:.0f} pkts/sec",
            "mitre": MITRE["SYN_FLOOD"],
            "confidence": min(pps / 20, 99),
        })

    if bps > 500000:
        alerts.append({
            "type": "HIGH_BANDWIDTH",
            "severity": "MEDIUM",
            "desc": f"{bps / 1000000:.2f} MB/s",
            "mitre": "T1498.001 - Direct Network Flood",
            "confidence": min(bps / 10000, 99),
        })

    return alerts

def check_port_scan(stats):
    """ detects horizontal port scans - T1046 """
    alerts = []

    if stats["unique_dst_port_count"] > 15 and stats["packet_count"] > 20:
        severity = "HIGH" if stats["unique_dst_port_count"] > 50 else "MEDIUM"
        alerts.append({
            "type": "PORT_SCAN",
            "severity": severity,
            "desc": f"{stats['unique_dst_port_count']} unique ports in window",
            "mitre": MITRE["PORT_SCAN"],
            "confidence": min(stats["unique_dst_port_count"] * 2, 95),
        })

    return alerts

def check_ssh_bruteforce(window, all_windows):
    """ detects ssh brute-force by tracking connection attempts to port 22
    brute force sends SYN -> SYN-ACK -> RST repeatedly
    """
    alerts = []

    # count unique src/dst pairs to port 22
    ssh_attempts = 0
    for p in window:
        if p.get("dst_port") == 22 or p.get("dport") == 22:
            ssh_attempts += 1

    if ssh_attempts > 20:
        alerts.append({
            "type": "SSH_BRUTEFORCE",
            "severity": "HIGH",
            "desc": f"{ssh_attempts} SSH attempts in window",
            "mitre": MITRE["SSH_BRUTEFORCE"],
            "confidence": min(ssh_attempts, 98),
        })
    elif ssh_attempts > 5:
        alerts.append({
            "type": "SSH_BRUTEFORCE",
            "severity": "LOW",
            "desc": f"{ssh_attempts} SSH attempts in window",
            "mitre": MITRE["SSH_BRUTEFORCE"],
            "confidence": min(ssh_attempts, 70),
        })

    return alerts

def check_dns_amplification(window):
    """ detects dns amplification: large dns responses to a single ip """
    alerts = []
    ip_dns_bytes = defaultdict(int)
    dns_counts = defaultdict(int)

    for p in window:
        proto = p.get("protocol", "")
        if proto == "UDP" and (p.get("dst_port") == 53 or p.get("dport") == 53):
            dst = p.get("dst_ip", "")
            src = p.get("src_ip", "")
            ip_dns_bytes[dst] += p.get("length", 0)
            ip_dns_bytes[src] += 0
            dns_counts[dst] += 1

    for ip, total_bytes in ip_dns_bytes.items():
        if total_bytes > 10000 and dns_counts.get(ip, 0) > 5:
            alerts.append({
                "type": "DNS_AMPLIFICATION",
                "severity": "HIGH" if total_bytes > 50000 else "MEDIUM",
                "desc": f"{ip} received {total_bytes} bytes of DNS ({dns_counts.get(ip, 0)} packets)",
                "mitre": MITRE["DNS_AMPLIFICATION"],
                "confidence": min(total_bytes / 500, 99),
            })

    return alerts

def check_c2_beaconing(window, all_windows, history):
    """ detects c2 beaconing: periodic small packets to external ip """
    alerts = []
    ip_pairs = defaultdict(list)

    for p in window:
        src = p.get("src_ip", "")
        dst = p.get("dst_ip", "")
        ts = p.get("timestamp", 0)
        length = p.get("length", 0)

        if length < 200 and dst.startswith(("45.", "104.", "185.", "5.")):
            pair = (src, dst)
            ip_pairs[pair].append(ts)

    for (src, dst), timestamps in ip_pairs.items():
        if len(timestamps) > 3:
            # check for regular intervals
            intervals = []
            for i in range(1, len(timestamps)):
                intervals.append(timestamps[i] - timestamps[i-1])

            if intervals and len(intervals) > 1:
                avg_interval = sum(intervals) / len(intervals)
                std = (sum((x - avg_interval)**2 for x in intervals) / len(intervals))**0.5

                # low std = regular intervals = beaconing
                if std < 2.0 and avg_interval > 0.5:
                    alerts.append({
                        "type": "C2_BEACONING",
                        "severity": "HIGH",
                        "desc": f"{src} -> {dst}: {len(timestamps)} beacons, interval={avg_interval:.1f}s, jitter={std:.2f}s",
                        "mitre": MITRE["C2_BEACONING"],
                        "confidence": max(0, 95 - std * 10),
                    })

    return alerts

def check_dns_exfiltration(window):
    """ detects dns tunneling: many unique subdomain queries """
    alerts = []
    dns_queries = defaultdict(list)

    for p in window:
        if p.get("dst_port") == 53 or p.get("dport") == 53:
            src = p.get("src_ip", "")
            dns_queries[src].append(p)

    for src, queries in dns_queries.items():
        if len(queries) > 10:
            total_len = sum(q.get("length", 0) for q in queries)
            avg_len = total_len / len(queries)

            # dns queries are usually small. large avg + many queries = suspicious
            if avg_len > 80:
                alerts.append({
                    "type": "DNS_EXFILTRATION",
                    "severity": "MEDIUM",
                    "desc": f"{src}: {len(queries)} large DNS queries (avg {avg_len:.0f}B)",
                    "mitre": MITRE["DNS_EXFILTRATION"],
                    "confidence": min(len(queries), 90),
                })

    return alerts
