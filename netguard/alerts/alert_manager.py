"""
Alert Manager
Generates, formats, and routes alerts to console, log file, JSON stream,
and optional webhook.
"""

import json
import queue
import threading
import time
import uuid
from dataclasses import dataclass, asdict
from typing import Optional

SEVERITY_COLORS = {
    "INFO":     "[94m",   # Blue
    "LOW":      "[93m",   # Yellow
    "MEDIUM":   "[38;5;208m",  # Orange
    "HIGH":     "[91m",   # Red
    "CRITICAL": "[91;5m", # Red + blink
    "RESET":    "[0m",
}


@dataclass
class Alert:
    timestamp: str
    alert_id:  str
    severity:  str
    attack_type: str
    src_ip:    str
    dst_ip:    str
    dst_port:  Optional[int]
    protocol:  str
    confidence: float
    detection_method: str
    sni:       Optional[str]
    action_taken: str
    extra:     dict


class AlertManager:

    def __init__(self, log_path: str  = "alerts/alerts.log",
                       json_path: str = "alerts/alerts.json",
                       webhook_url: str = ""):
        self.log_path    = log_path
        self.json_path   = json_path
        self.webhook_url = webhook_url
        self._queue      = queue.Queue()
        self._thread     = threading.Thread(target=self._run, daemon=True,
                                            name="AlertThread")
        self._thread.start()

    def fire(self, severity: str, attack_type: str, src_ip: str,
             dst_ip: str = "", dst_port: int = None, protocol: str = "TCP",
             confidence: float = 0.0, detection_method: str = "",
             sni: str = None, action: str = "BLOCKED", extra: dict = None):
        alert = Alert(
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            alert_id=f"ALT-{uuid.uuid4().hex[:5].upper()}",
            severity=severity,
            attack_type=attack_type,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            confidence=confidence,
            detection_method=detection_method,
            sni=sni,
            action_taken=action,
            extra=extra or {},
        )
        self._queue.put(alert)

    def _run(self):
        while True:
            alert = self._queue.get()
            self._print(alert)
            self._write_log(alert)
            self._write_json(alert)

    def _print(self, a: Alert):
        color = SEVERITY_COLORS.get(a.severity, "")
        reset = SEVERITY_COLORS["RESET"]
        print(f"{color}[{a.timestamp}] ⚠  {a.severity:<8} {a.attack_type:<15} "
              f"src={a.src_ip}  conf={a.confidence:.2f}  → {a.action_taken}{reset}")

    def _write_log(self, a: Alert):
        try:
            line = (f"{a.timestamp} | {a.severity:<8} | {a.attack_type:<14} | "
                    f"{a.src_ip:<15} | conf={a.confidence:.2f} | {a.action_taken}")
            with open(self.log_path, "a") as f:
                f.write(line)
                f.write("\n")
        except Exception:
            pass

    def _write_json(self, a: Alert):
        try:
            with open(self.json_path, "a") as f:
                f.write(json.dumps(asdict(a)) + "\n")
        except Exception:
            pass
