"""
Behavioral Analysis Engine
Tracks per-source-IP statistics over a sliding time window.
Detects: port scans, DoS floods, brute force, network scans, data exfiltration.
"""

import time
import threading
from collections import defaultdict
from typing import Dict, Optional, Tuple

import yaml


class BehavioralEngine:

    DEFAULT_CONFIG = {
        "window_seconds": 60,
        "thresholds": {
            "port_scan":         {"unique_dst_ports": 50},
            "dos_flood":         {"packets_in_window": 5000, "window_seconds": 10},
            "brute_force":       {"failed_connections": 20,  "window_seconds": 30},
            "network_scan":      {"unique_dst_ips": 30},
            "data_exfiltration": {"outbound_bytes_mb": 100},
        }
    }

    def __init__(self, config_path: str = "config/behavioral_config.yaml"):
        self._lock  = threading.Lock()
        self._state: Dict[str, dict] = defaultdict(self._new_state)
        self.config = self._load_config(config_path)

    def _load_config(self, path: str) -> dict:
        try:
            with open(path) as f:
                return yaml.safe_load(f)
        except Exception:
            return self.DEFAULT_CONFIG

    @staticmethod
    def _new_state() -> dict:
        return {
            "packet_count":       0,
            "byte_count":         0,
            "byte_count_outbound":0,
            "unique_dst_ports":   set(),
            "unique_dst_ips":     set(),
            "connection_count":   0,
            "failed_connections": 0,
            "first_seen":         time.time(),
            "last_seen":          time.time(),
            "timestamps":         [],
        }

    def update(self, src_ip: str, dst_ip: str, dst_port: int,
               pkt_len: int, tcp_flags: int) -> None:
        with self._lock:
            s = self._state[src_ip]
            now = time.time()
            s["packet_count"]        += 1
            s["byte_count"]          += pkt_len
            s["byte_count_outbound"] += pkt_len
            s["unique_dst_ports"].add(dst_port)
            s["unique_dst_ips"].add(dst_ip)
            s["last_seen"] = now
            s["timestamps"].append(now)
            if tcp_flags & 0x02:   # SYN
                s["connection_count"] += 1
            if tcp_flags & 0x04:   # RST
                s["failed_connections"] += 1
            # Trim old timestamps
            window = self.config.get("window_seconds", 60)
            s["timestamps"] = [t for t in s["timestamps"] if now - t < window]

    def get_state(self, src_ip: str) -> dict:
        with self._lock:
            s = self._state[src_ip]
            return {
                "packet_count":        s["packet_count"],
                "packets_per_second":  len(s["timestamps"]),
                "unique_dst_ports":    len(s["unique_dst_ports"]),
                "unique_dst_ips":      len(s["unique_dst_ips"]),
                "connection_count":    s["connection_count"],
                "failed_connections":  s["failed_connections"],
                "byte_count_mb":       s["byte_count_outbound"] / (1024*1024),
            }

    def evaluate(self, src_ip: str) -> Optional[Tuple[str, str]]:
        """Returns (attack_type, severity) or None if nothing suspicious."""
        s = self.get_state(src_ip)
        t = self.config.get("thresholds", self.DEFAULT_CONFIG["thresholds"])

        if s["unique_dst_ports"] > t["port_scan"]["unique_dst_ports"]:
            return "PORT_SCAN", "HIGH"
        if s["packets_per_second"] > t["dos_flood"]["packets_in_window"]:
            return "DOS", "CRITICAL"
        if s["failed_connections"] > t["brute_force"]["failed_connections"]:
            return "BRUTEFORCE", "HIGH"
        if s["unique_dst_ips"] > t["network_scan"]["unique_dst_ips"]:
            return "NETWORK_SCAN", "MEDIUM"
        if s["byte_count_mb"] > t["data_exfiltration"]["outbound_bytes_mb"]:
            return "DATA_EXFIL", "HIGH"
        return None
