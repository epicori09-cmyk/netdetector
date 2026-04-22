# reads packet features ...
# run after producer.py
import json
import time
import os
import sys
from collections import defaultdict
QUEUE_FILE = "data/packet_queue.jsonl"

def read_packets():  
    packets = []
    f = open(QUEUE_FILE, 'r')
    for line in f:
        line = line.strip()
        if line:
            packets.append(json.loads(line))
    f.close()
    return packets

def window_packets(packets, window_sec=5):
    if not packets:
        return []  
    windows = []
    start_time = packets[0]["timestamp"]
    current_window = []
    for p in packets:
        if p["timestamp"] - start_time <= window_sec:
            current_window.append(p)
        else:
            windows.append(current_window)
            start_time = p["timestamp"]
            current_window = [p]
    if current_window:
        windows.append(current_window)
    return windows

def analyze_window(window):
    stats = {
        "start_time": window[0]["timestamp"],
        "end_time": window[-1]["timestamp"],
        "packet_count": len(window),
        "byte_count": 0,
        "unique_dst_ports": set(),
        "syn_count": 0,
        "tcp_count": 0,
        "udp_count": 0,
        "src_ips": defaultdict(int),
        "dst_ips": defaultdict(int),
    }
    for p in window:
        stats["byte_count"] += p["length"]
        stats["unique_dst_ports"].add(p["dst_port"])
        if p["protocol"] == "TCP":
            stats["tcp_count"] += 1
            # check SYN flag (0x02)
            if p["flags"] & 0x02:
                stats["syn_count"] += 1
        elif p["protocol"] == "UDP":
            stats["udp_count"] += 1
        if p["src_ip"]:
            stats["src_ips"][p["src_ip"]] += 1  
        if p["dst_ip"]:
            stats["dst_ips"][p["dst_ip"]] += 1
    # convert set to count
    stats["unique_dst_port_count"] = len(stats["unique_dst_ports"])
    del stats["unique_dst_ports"]
    # convert defaultdicts to regular dicts
    stats["src_ips"] = dict(stats["src_ips"])
    stats["dst_ips"] = dict(stats["dst_ips"])  
    duration = stats["end_time"] - stats["start_time"]
    if duration > 0:
        stats["packets_per_sec"] = stats["packet_count"] / duration
        stats["bytes_per_sec"] = stats["byte_count"] / duration
    else:
        stats["packets_per_sec"] = 0
        stats["bytes_per_sec"] = 0
    return stats

def detect_anomalies(stats):
    alerts = []
    # syn flood
    if stats["tcp_count"] > 0:
        syn_ratio = stats["syn_count"] / stats["tcp_count"]
        if syn_ratio > 0.8 and stats["packet_count"] > 10:
            alerts.append(f"SYN flood? {syn_ratio:.0%} SYN, {stats['packet_count']} packets")
    # port scan
    if stats["unique_dst_port_count"] > 10:
        alerts.append(f"Port scan? {stats['unique_dst_port_count']} unique ports")
    # high traffic
    if stats["packets_per_sec"] > 100:
        alerts.append(f"High traffic: {stats['packets_per_sec']:.0f} pps")
    return alerts
if __name__ == '__main__':
    if not os.path.exists(QUEUE_FILE):
        print(f"queue file not found: {QUEUE_FILE}")
        print("run producer.py first")  
        sys.exit(1)
    packets = read_packets()
    print(f"read {len(packets)} packets from queue")
    windows = window_packets(packets)
    print(f"grouped into {len(windows)} windows")
    for i, w in enumerate(windows):
        stats = analyze_window(w)
        alerts = detect_anomalies(stats)
        print(f"\nwindow {i+1}: {stats['packet_count']} pkts, {stats['bytes_per_sec']:.0f} B/s")
        if alerts:
            print("  ALERTS:")
            for a in alerts:
                print(f"    [!] {a}")  
        else:
            print("  normal")