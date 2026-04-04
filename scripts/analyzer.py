import csv

f = open('data/sample_log.csv')
reader = csv.DictReader(f)

rows = []
for row in reader:
    row['bytes'] = int(row['bytes'])
    rows.append(row)

f.close()

print(f"total rows: {len(rows)}")
