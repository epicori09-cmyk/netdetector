import csv
import sys

def load_csv(filepath):
    f = open(filepath)
    reader = csv.DictReader(f)
    rows = []
    for row in reader:
        row['bytes'] = int(row['bytes'])
        rows.append(row)
    f.close()
    return rows

def get_unique_ips(rows):
    ips = set()
    for r in rows:
        ips.add(r['src_ip'])
    return sorted(ips)

def count_actions(rows):
    counts = {}
    for r in rows:
        a = r['action']
        if a not in counts:
            counts[a] = 0
        counts[a] += 1
    return counts

def bytes_by_ip(rows):
    totals = {}
    for r in rows:
        ip = r['src_ip']
        if ip not in totals:
            totals[ip] = 0
        totals[ip] += r['bytes']
    return totals

def top_talker(totals):
    best = None
    best_ip = None
    for ip, b in totals.items():
        if best is None or b > best:
            best = b
            best_ip = ip
    return best_ip, best

def save_report(rows, output_file):
    with open(output_file, 'w') as f:
        f.write(f"total: {len(rows)}\n")
        ips = get_unique_ips(rows)
        f.write(f"unique IPs: {ips}\n")
        counts = count_actions(rows)
        f.write(f"actions: {counts}\n")
        totals = bytes_by_ip(rows)
        ip, b = top_talker(totals)
        f.write(f"top talker: {ip} {b}B\\n")

def print_report(rows):
    print(f"total: {len(rows)}")
    print(f"unique IPs: {get_unique_ips(rows)}")
    print(f"actions: {count_actions(rows)}")
    totals = bytes_by_ip(rows)
    ip, b = top_talker(totals)
    print(f"top talker: {ip} {b}B")

if len(sys.argv) < 2:
    print("usage: python scripts/analyzer.py <csv_file> [output_file]")
    sys.exit(1)

rows = load_csv(sys.argv[1])
if len(sys.argv) >= 3:
    save_report(rows, sys.argv[2])
    print(f"saved to {sys.argv[2]}")
else:
    print_report(rows)
