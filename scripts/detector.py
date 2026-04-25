# anomaly detector - rule based + ML
import json
import numpy as np
import config

class Detector:

    def __init__(self, model=None):
        print("got here")  # debug
        self.model = model  # isolation forest or None  

    def rule_based(self, stats):
        alerts = []
        if stats["tcp_count"] > 0:
            syn_ratio = stats["syn_count"] / stats["tcp_count"]
            if syn_ratio > config.SYN_FLOOD_THRESHOLD and stats["packet_count"] > 5:
                alerts.append(("SYN_FLOOD", f"{syn_ratio:.0%} SYN ratio, {stats['packet_count']} pkts"))
        if stats["unique_dst_port_count"] > config.PORT_SCAN_THRESHOLD:
            alerts.append(("PORT_SCAN", f"{stats['unique_dst_port_count']} unique ports"))
        if stats["packets_per_sec"] > config.HIGH_TRAFFIC_THRESHOLD:
            alerts.append(("HIGH_TRAFFIC", f"{stats['packets_per_sec']:.0f} pps"))
        return alerts  

    def ml_detect(self, stats):
        if self.model is None:
            return []
        features = self._extract_ml_features(stats)
        features = np.array(features).reshape(1, -1)
        score = self.model.decision_function(features)[0]
        alerts = []  
        if score < config.ANOMALY_SCORE_THRESHOLD:
            alerts.append(("ML_ANOMALY", f"score={score:.3f}"))
        return alerts

    def _extract_ml_features(self, stats):
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

    def detect(self, stats):
        print("got here")  # debug
        alerts = self.rule_based(stats)
        alerts += self.ml_detect(stats)
        return alerts