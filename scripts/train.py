# train isolation forest ...
# run: python scripts/train.py
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import json
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
from scripts.consumer import read_packets, window_packets, analyze_window
MODEL_PATH = "models/isolation_forest.joblib"

def extract_features(stats):
    print("got here")  # debug
    return [  
        stats["packet_count"],
        stats["byte_count"],
        stats["unique_dst_port_count"],
        stats["syn_count"],  
        stats["tcp_count"],
        stats["udp_count"],
        stats["packets_per_sec"],
        stats["bytes_per_sec"],
    ]

def train(training_data_path="data/normal_traffic.jsonl"):
    print("loading training data...")
    if not os.path.exists(training_data_path):
        print(f"  no training data at {training_data_path}")
        print("  generating from sample traffic...")
        from scripts.producer import process_pcap
        if os.path.exists("data/sample_traffic.pcap"):
            process_pcap("data/sample_traffic.pcap")
            training_data_path = "data/packet_queue.jsonl"
        else:
            print("  no pcap found, run scripts/read_pcap.py first")
            return None
    packets = read_packets()
    windows = window_packets(packets)
    print(f"  got {len(windows)} windows from {len(packets)} packets")
    X = []
    for w in windows:
        stats = analyze_window(w)
        X.append(extract_features(stats))
    X = np.array(X)
    print(f"  training on {X.shape[0]} samples, {X.shape[1]} features")
    model = IsolationForest(
        n_estimators=100,  
        contamination=0.1,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X)
    os.makedirs("models", exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"  saved model to {MODEL_PATH}")
    return model
if __name__ == '__main__':
    train()