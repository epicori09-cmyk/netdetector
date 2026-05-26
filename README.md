# NetDetect — Network Anomaly Detection

Scans PCAP files for network attacks using rule-based detection and Isolation Forest. Maps findings to MITRE ATT&CK. Includes a FastAPI dashboard and Telegram alerts.

## Architecture

```
pcap file  →  feature extraction  →  time windows  →  detection rules  →  alerts + report
                                      (producer)       (detectors.py)
```

Scans packets → extracts features (IP, port, protocol, flags, size) → groups into 5-second windows → runs detection on each window → generates report with MITRE mapping.

## Attack Coverage

| Attack | MITRE ID | Detection Method |
|--------|----------|-----------------|
| SYN Flood | T1498 | SYN/total ratio > 85% + volume > 50 pkts |
| SSH Brute Force | T1110 | Connection attempts to port 22 (>20 per window) |
| Port Scan | T1046 | Unique destination ports > 15 per window |
| DNS Amplification | T1498.002 | Large DNS responses to single IP (>10KB) |
| C2 Beaconing | T1071.001 | Regular interval detection (low jitter between packets to external IP) |
| DNS Exfiltration | T1048 | High volume of large DNS queries |
| Volumetric Anomaly | T1498 | >1000 pkts/sec |

## Detection Examples

### SYN Flood Detection
Checks SYN flag ratio against total TCP packets in each window. A real SYN flood hits 100% SYN because there are no ACK handshake completions. Threshold is 85% + at least 50 packets to avoid false positives from normal connections.

### SSH Brute Force
Tracks port 22 connection attempts within a window. Each SSH auth attempt produces: SYN → SYN-ACK → RST. Multiple rapid sequences from the same source IP indicate brute-force activity.

### C2 Beaconing
Measures inter-packet timing consistency. C2 beacons typically communicate at fixed intervals with low jitter. The tool computes the standard deviation of intervals — values under 2 seconds with consistent packet sizes suggest beaconing.

## Results (Sample Analysis)

8 windows analyzed across 2395 packets:
- Windows 1-3: SYN flood detected (100% SYN ratio, up to 501 pkts/window)
- Windows 4-5: SSH brute-force + port scan (334 SSH attempts, 168 unique ports)
- Windows 6-7: Port scan (299 unique ports)
- Window 8: DNS exfiltration + amplification (150 large DNS queries)

5 MITRE techniques mapped across 11 alerts total.

## Setup

```bash
uv venv
uv pip install -r requirements.txt

# generate sample attack traffic
.venv\Scripts\python scripts/generate_traffic.py

# extract features
.venv\Scripts\python scripts/producer.py data/combined_traffic.pcap

# run detection
.venv\Scripts\python scripts/run_detection.py

# dashboard
.venv\Scripts\python -m uvicorn web.app:app --host 0.0.0.0 --port 8000
```

## Telegram Alerts

Set in `scripts/config.py`:
```python
TELEGRAM_BOT_TOKEN = "your_token"
TELEGRAM_CHAT_ID = "your_chat_id"
```

## Limitations

- PCAP-based only (no live capture on Windows without Npcap)
- Detection thresholds are static — needs tuning for different network profiles
- ML model (Isolation Forest) trained on limited sample data
- Time-based windowing misses slow scans spread over minutes

## Project Structure

```
scripts/
  generate_traffic.py   generates realistic attack PCAPs
  producer.py           reads PCAP, extracts features
  consumer.py           groups packets into time windows
  detector.py           ML model wrapper
  attacks.py            attack signatures + MITRE mapping
  run_detection.py      full detection pipeline
  train.py              train Isolation Forest
  alert.py              Telegram integration
  config.py             thresholds + tokens
web/
  app.py                FastAPI dashboard
  templates/index.html  dashboard HTML with Chart.js
```

## Tech

Python, Scapy, scikit-learn, FastAPI, Chart.js, Docker
