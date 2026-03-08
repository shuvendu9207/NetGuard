"""
Rule Engine
Evaluates blocking rules from rules.yaml.
Supports hot-reload without restarting.
"""

import yaml
import threading
from typing import List, Optional


class RuleEngine:

    def __init__(self, rules_path: str = "config/rules.yaml"):
        self._path  = rules_path
        self._lock  = threading.Lock()
        self._rules = {}
        self.reload()

    def reload(self):
        try:
            with open(self._path) as f:
                data = yaml.safe_load(f) or {}
            with self._lock:
                self._rules = data
            print(f"[RuleEngine] Rules loaded from {self._path}")
        except Exception as e:
            print(f"[RuleEngine] Failed to load rules: {e}")

    def is_blocked(self, src_ip: str = "",
                   dst_port: int = 0,
                   protocol: str = "",
                   sni: str = "",
                   app_type: str = "") -> Optional[str]:
        """
        Returns the reason string if blocked, else None.
        """
        with self._lock:
            r = self._rules

        if src_ip in (r.get("block_ips") or []):
            return f"IP_BLOCK:{src_ip}"

        if dst_port in (r.get("block_ports") or []):
            return f"PORT_BLOCK:{dst_port}"

        proto_upper = protocol.upper()
        if proto_upper in (r.get("block_protocols") or []):
            return f"PROTO_BLOCK:{protocol}"

        for domain in (r.get("block_domains") or []):
            if domain.lower() in sni.lower():
                return f"DOMAIN_BLOCK:{domain}"

        if app_type in (r.get("block_apps") or []):
            return f"APP_BLOCK:{app_type}"

        return None
