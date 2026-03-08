"""
Flow Tracker
Maps a five-tuple to a flow state.
Each flow accumulates SNI, app type, packet count, and block status.
"""

import threading
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

FiveTuple = Tuple[str, str, int, int, int]  # src_ip, dst_ip, src_port, dst_port, proto


@dataclass
class Flow:
    src_ip:    str = ""
    dst_ip:    str = ""
    src_port:  int = 0
    dst_port:  int = 0
    protocol:  int = 0
    sni:       str = ""
    app_type:  str = "UNKNOWN"
    pkt_count: int = 0
    byte_count:int = 0
    blocked:   bool = False
    block_reason: str = ""
    label:     str = "NORMAL"


class FlowTracker:

    def __init__(self):
        self._lock  = threading.Lock()
        self._flows: Dict[FiveTuple, Flow] = {}

    def get_or_create(self, key: FiveTuple) -> Flow:
        with self._lock:
            if key not in self._flows:
                self._flows[key] = Flow(
                    src_ip=key[0], dst_ip=key[1],
                    src_port=key[2], dst_port=key[3], protocol=key[4]
                )
            return self._flows[key]

    def update(self, key: FiveTuple, **kwargs):
        with self._lock:
            flow = self._flows.get(key)
            if flow:
                for k, v in kwargs.items():
                    setattr(flow, k, v)

    def all_flows(self) -> Dict[FiveTuple, Flow]:
        with self._lock:
            return dict(self._flows)

    def count(self) -> int:
        return len(self._flows)
