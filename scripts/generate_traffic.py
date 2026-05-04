# generates realistic network traffic with attack scenarios
# each scenario creates a separate pcap so you can test detection per attack

from scapy.all import *
import time
import os
import random

OUT_DIR = "data/scenarios"
os.makedirs(OUT_DIR, exist_ok=True)

def normal_browsing(count=100):
    """ simulate normal web browsing traffic """
    packets = []
    clients = ["192.168.1." + str(i) for i in range(10, 50)]
    servers = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]

    for i in range(count):
        src = random.choice(clients)
        dst = random.choice(servers)
        sport = random.randint(40000, 60000)
        dport = random.choice([80, 443, 8080])

        # web request + response
        pkt = IP(src=src, dst=dst)/TCP(sport=sport, dport=dport, flags="S")
        packets.append(pkt)

        # occasionally add some DNS
        if random.random() < 0.15:
            dns_pkt = IP(src=src, dst="8.8.8.8")/UDP(sport=sport, dport=53)/DNS(
                id=random.randint(1, 65535),
                qd=DNSQR(qname=random.choice(["google.com", "wikipedia.org", "github.com", "ynet.co.il"]))
            )
            packets.append(dns_pkt)

        # small delay between requests
        if i % 10 == 0:
            time.sleep(0.01)

    wrpcap(os.path.join(OUT_DIR, "01_normal.pcap"), packets)
    print(f"normal: {len(packets)} packets -> {OUT_DIR}/01_normal.pcap")
    return os.path.join(OUT_DIR, "01_normal.pcap")

def syn_flood(target_ip="10.0.0.1", target_port=443, count=500):
    """ SYN flood attack - T1498 Network Denial of Service """
    packets = []
    spoofed_base = random.randint(1, 250)

    for i in range(count):
        src = f"192.168.{random.randint(1, 10)}.{random.randint(1, 254)}"
        sport = random.randint(1024, 65535)
        pkt = IP(src=src, dst=target_ip)/TCP(sport=sport, dport=target_port, flags="S")
        packets.append(pkt)

    wrpcap(os.path.join(OUT_DIR, "02_syn_flood.pcap"), packets)
    print(f"syn flood: {len(packets)} packets -> {OUT_DIR}/02_syn_flood.pcap")
    return os.path.join(OUT_DIR, "02_syn_flood.pcap")

def ssh_bruteforce(target_ip="10.0.0.1", count=100):
    """ SSH brute-force - T1110 Brute Force """
    packets = []
    attacker = "5.5.5.5"

    for i in range(count):
        sport = 50000 + i
        # SYN to SSH port
        pkt = IP(src=attacker, dst=target_ip)/TCP(sport=sport, dport=22, flags="S")
        packets.append(pkt)
        # SYN-ACK back
        pkt2 = IP(src=target_ip, dst=attacker)/TCP(sport=22, dport=sport, flags="SA")
        packets.append(pkt2)
        # RST (close connection after failed auth attempt)
        pkt3 = IP(src=attacker, dst=target_ip)/TCP(sport=sport, dport=22, flags="R")
        packets.append(pkt3)

    wrpcap(os.path.join(OUT_DIR, "03_ssh_bruteforce.pcap"), packets)
    print(f"ssh brute-force: {len(packets)} packets -> {OUT_DIR}/03_ssh_bruteforce.pcap")
    return os.path.join(OUT_DIR, "03_ssh_bruteforce.pcap")

def dns_amplification(target_ip="192.168.1.10", count=200):
    """ DNS amplification attack - T1498.002 Reflection Amplification """
    packets = []
    dns_servers = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "208.67.222.222"]

    for i in range(count):
        src = random.choice(dns_servers)
        qport = random.randint(30000, 60000)

        # Large response from DNS server to target (amplified)
        # normal dns response is ~100B, amplified is much larger
        pkt = IP(src=src, dst=target_ip)/UDP(sport=53, dport=qport)/DNS(
            id=i, qr=1, qd=DNSQR(qname="example.com"),
            an=DNSRR(rrname="example.com", ttl=86400, rdata=target_ip)
        )
        # pad to make it look amplified
        pkt = pkt / Raw(load=b"A" * random.randint(400, 1500))
        packets.append(pkt)

    wrpcap(os.path.join(OUT_DIR, "04_dns_amplification.pcap"), packets)
    print(f"dns amplification: {len(packets)} packets -> {OUT_DIR}/04_dns_amplification.pcap")
    return os.path.join(OUT_DIR, "04_dns_amplification.pcap")

def c2_beaconing(count=30, interval_sec=5):
    """ C2 beaconing simulation - T1071.001 Application Layer Protocol """
    packets = []
    victim = "192.168.1.100"
    c2_server = "45.33.32.156"

    for i in range(count):
        # beacon at regular intervals
        pkt = IP(src=victim, dst=c2_server)/TCP(sport=random.randint(40000, 50000), dport=8080, flags="PA")/Raw(
            load=bytes(random.randint(20, 100))
        )
        packets.append(pkt)

        # response from C2
        rpkt = IP(src=c2_server, dst=victim)/TCP(sport=8080, dport=random.randint(40000, 50000), flags="PA")/Raw(
            load=bytes(random.randint(10, 50))
        )
        packets.append(rpkt)

    wrpcap(os.path.join(OUT_DIR, "05_c2_beaconing.pcap"), packets)
    print(f"c2 beaconing: {len(packets)} packets -> {OUT_DIR}/05_c2_beaconing.pcap")
    return os.path.join(OUT_DIR, "05_c2_beaconing.pcap")

def dns_exfiltration(count=100):
    """ DNS tunneling / data exfiltration - T1048 Exfiltration Over Alternative Protocol """
    packets = []
    victim = "192.168.1.100"
    dns_server = "8.8.8.8"

    for i in range(count):
        subdomain = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=random.randint(15, 30)))
        query = f"{subdomain}.exfil.attacker.com"

        pkt = IP(src=victim, dst=dns_server)/UDP(sport=random.randint(30000, 60000), dport=53)/DNS(
            id=i, qd=DNSQR(qname=query, qtype="TXT")
        )
        packets.append(pkt)

    wrpcap(os.path.join(OUT_DIR, "06_dns_exfiltration.pcap"), packets)
    print(f"dns exfiltration: {len(packets)} packets -> {OUT_DIR}/06_dns_exfiltration.pcap")
    return os.path.join(OUT_DIR, "06_dns_exfiltration.pcap")

def generate_all():
    """ generate all scenarios into one combined pcap """
    print("generating traffic scenarios...\n")

    files = []
    files.append(normal_browsing(200))
    files.append(syn_flood(count=1000))
    files.append(ssh_bruteforce(count=200))
    files.append(dns_amplification(count=300))
    files.append(c2_beaconing(count=60))
    files.append(dns_exfiltration(count=150))

    # merge all into one big pcap with realistic timestamps
    all_packets = []
    base_time = time.time()
    for f in files:
        packets = rdpcap(f)
        for i, pkt in enumerate(packets):
            # spread each scenario over a few seconds, with gaps between attacks
            gap = len(files) * 5  # 5 seconds per scenario
            pkt.time = base_time + (len(all_packets) + i) * 0.01  # 10ms between packets
        all_packets.extend(packets)
        base_time += 6  # 6 second gap between scenarios

    combined = "data/combined_traffic.pcap"
    wrpcap(combined, all_packets)
    print(f"\ncombined: {len(all_packets)} packets -> {combined}")
    return combined

if __name__ == '__main__':
    generate_all()
