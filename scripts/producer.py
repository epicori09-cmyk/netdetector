# reads packets and ...
# run this first, then run consumer.py
from scapy.all import *
import json  
import time
import os
QUEUE_FILE = "data/packet_queue.jsonl"

def extract_features(pkt):
    feats = {
        "timestamp": float(getattr(pkt, 'time', time.time())),
        "src_ip": None,  
        "dst_ip": None,
        "src_port": 0,
        "dst_port": 0,
        "protocol": "other",
        "length": len(pkt),
        "flags": 0,
    }
    if IP in pkt:
        feats["src_ip"] = pkt[IP].src
        feats["dst_ip"] = pkt[IP].dst
    if TCP in pkt:
        feats["protocol"] = "TCP"
        feats["src_port"] = pkt[TCP].sport
        feats["dst_port"] = pkt[TCP].dport
        feats["flags"] = int(pkt[TCP].flags)
    elif UDP in pkt:
        feats["protocol"] = "UDP"
        feats["src_port"] = pkt[UDP].sport
        feats["dst_port"] = pkt[UDP].dport
    return feats

def process_pcap(filepath):
    print(f"reading pcap: {filepath}")
    packets = rdpcap(filepath)
    f = open(QUEUE_FILE, 'w')
    count = 0
    for pkt in packets:
        feats = extract_features(pkt)
        f.write(json.dumps(feats) + '\n')
        count += 1
    f.close()
    print(f"wrote {count} packets to {QUEUE_FILE}")
    return count

def capture_live(count=50):
    print(f"capturing {count} live packets...")
    print("  (may need admin)")
    try:
        packets = sniff(count=count, timeout=10)  
        f = open(QUEUE_FILE, 'w')
        for pkt in packets:
            feats = extract_features(pkt)
            f.write(json.dumps(feats) + '\n')
        f.close()
        print(f"captured {len(packets)} packets")
        return len(packets)
    except Exception as e:
        print(f"capture failed: {e}")
        return 0
if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == '--live':
        capture_live()
    else:
        pcap = sys.argv[1] if len(sys.argv) > 1 else "data/sample_traffic.pcap"
        if os.path.exists(pcap):
            process_pcap(pcap)
        else:
            print(f"file not found: {pcap}")
            print("generate one with: python scripts/read_pcap.py")