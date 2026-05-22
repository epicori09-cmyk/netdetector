# dashboard with attack analysis and mitre mapping

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'scripts'))

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
import json

from scripts.consumer import read_packets, window_packets, analyze_window

ROOT = os.path.dirname(os.path.dirname(__file__))
app = FastAPI(title="NetDetect")
templates = Jinja2Templates(directory=os.path.join(ROOT, "web", "templates"))

def load_json(path):
    p = os.path.join(ROOT, path)
    if os.path.exists(p):
        with open(p) as f:
            return json.load(f)
    return None

@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    queue_file = os.path.join(ROOT, "data/packet_queue.jsonl")
    alerts_file = os.path.join(ROOT, "data/alerts.json")

    packets = []
    windows = []
    alerts = load_json("data/alerts.json") or []

    if os.path.exists(queue_file):
        packets = read_packets()
        windows = window_packets(packets)

    window_stats = []
    for i, w in enumerate(windows):
        s = analyze_window(w)
        s["window_num"] = i + 1
        window_stats.append(s)

    total_packets = len(packets)
    tcp = sum(w["tcp_count"] for w in window_stats)
    udp = sum(w["udp_count"] for w in window_stats)

    # top src IPs
    src_ips = {}
    for w in window_stats:
        for ip, c in w["src_ips"].items():
            src_ips[ip] = src_ips.get(ip, 0) + c
    top_ips = sorted(src_ips.items(), key=lambda x: -x[1])[:5]

    # timeline data for chart
    timeline = [{"window": s["window_num"], "packets": s["packet_count"]} for s in window_stats]

    # count by mitre technique
    mitre_counts = {}
    for a in alerts:
        m = a.get("mitre", "Unknown")
        mitre_counts[m] = mitre_counts.get(m, 0) + 1

    # severity counts
    sev_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in alerts:
        sev_counts[a.get("severity", "LOW")] = sev_counts.get(a.get("severity", "LOW"), 0) + 1

    return templates.TemplateResponse("index.html", {
        "request": request,
        "total_packets": total_packets,
        "total_windows": len(windows),
        "tcp": tcp,
        "udp": udp,
        "top_ips": top_ips,
        "alerts": alerts,
        "alert_count": len(alerts),
        "timeline": json.dumps(timeline),
        "mitre_counts": json.dumps(mitre_counts),
        "high_count": sev_counts["HIGH"],
        "med_count": sev_counts["MEDIUM"],
        "low_count": sev_counts["LOW"],
    })

@app.get("/api/stats")
async def api_stats():
    queue_file = os.path.join(ROOT, "data/packet_queue.jsonl")
    if not os.path.exists(queue_file):
        return {"error": "no data"}
    packets = read_packets()
    windows = window_packets(packets)
    stats = []
    for w in windows:
        stats.append(analyze_window(w))
    return {"windows": stats, "total_packets": len(packets)}

@app.get("/api/alerts")
async def api_alerts():
    alerts = load_json("data/alerts.json")
    return {"alerts": alerts or []}

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
