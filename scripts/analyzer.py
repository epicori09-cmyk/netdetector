import csv

f = open('data/sample_log.csv')
reader = csv.DictReader(f)
rows = []
for row in reader:
    row['bytes'] = int(row['bytes'])
    rows.append(row)
f.close()

ips = set()
for r in rows:
    ips.add(r['src_ip'])
print(f"unique IPs: {sorted(ips)}")

counts = {}
for r in rows:
    a = r['action']
    if a not in counts:
        counts[a] = 0
    counts[a] += 1
print(f"actions: {counts}")

total = sum(r['bytes'] for r in rows)
print(f"total bytes: {total}")
