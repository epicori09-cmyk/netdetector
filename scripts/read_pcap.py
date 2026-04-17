# playing with scapy ...
# copied some of this from stackoverflow
from scapy.all import *
import time
import os

def generate_sample_traffic():
    print("got here")  # debug
    # make some fake packets for testing
    print("generating sample traffic...")
    packets = []
    # normal web traffic
    for i in range(20):
        pkt = IP(src="192.168.1.10", dst="10.0.0.1")/TCP(sport=12345+i, dport=443)/Raw(load=b"GET / HTTP/1.1")
        packets.append(pkt)
    # some DNS lookups
    for i in range(5):
        pkt = IP(src="192.168.1.10", dst="8.8.8.8")/UDP(sport=54321+i, dport=53)/DNS(qd=DNSQR(qname="google.com"))
        packets.append(pkt)
    # ssh connection 
    for i in range(10):
        pkt = IP(src="10.0.0.5", dst="192.168.1.1")/TCP(sport=22, dport=50000+i)
        packets.append(pkt)
    # suspicious - port scan from unknown ip
    for port in range(20, 40):
        pkt = IP(src="10.0.0.99", dst="192.168.1.1")/TCP(sport=31337, dport=port, flags="S")
        packets.append(pkt)
    wrpcap("data/sample_traffic.pcap", packets)
    print(f"saved {len(packets)} packets to data/sample_traffic.pcap")
    return "data/sample_traffic.pcap"


def analyze_pcap(filepath):
    print(f"\nreading: {filepath}")
    packets = rdpcap(filepath)
    print(f"total packets: {len(packets)}")
    # count by protocol
    tcp = 0
    udp = 0
    other = 0
    for pkt in packets:
        if TCP in pkt:
            tcp += 1
        elif UDP in pkt:
            udp += 1
        else:
            other += 1
    print(f"TCP: {tcp}, UDP: {udp}, other: {other}")
    # show first few packets
    print("\nfirst 5 packets:")
    for i, pkt in enumerate(packets[:5]):
        print(f"  {i+1}. {pkt.summary()}")
    # show source IPs
    src_ips = {}
    for pkt in packets:
        if IP in pkt:
            src = pkt[IP].src
            if src not in src_ips:
                print("checking")  # debug
                src_ips[src] = 0
            src_ips[src] += 1
    print("\npackets per src IP:")
    for ip, c in sorted(src_ips.items(), key=lambda x: -x[1]):
        print(f"  {ip}: {c}")
    # check for port scan
    print("\nchecking for port scan...")
    scan_attempts = {}
    for pkt in packets:
        if TCP in pkt and pkt[TCP].flags == 0x02:  # SYN flag
            src = pkt[IP].src
            dst_port = pkt[TCP].dport
            if src not in scan_attempts:
                scan_attempts[src] = []
            scan_attempts[src].append(dst_port)
    for ip, ports in scan_attempts.items():
        if len(ports) > 5:
            print(f"  [!] possible port scan from {ip}: {len(ports)} ports")
            print(f"      ports: {sorted(ports)[:10]}...")
if __name__ == '__main__':
    pcap = generate_sample_traffic()
    analyze_pcap(pcap)