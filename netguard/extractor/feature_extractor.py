"""
Feature Extractor Module
Converts a ParsedPacket + behavioral state into a numeric feature vector
suitable for the ML model.
"""

import struct
from typing import List, Dict, Any
from parser.packet_parser import ParsedPacket


FEATURE_NAMES = [
    "src_ip_numeric", "dst_ip_numeric",
    "src_port", "dst_port",
    "protocol",
    "packet_length", "payload_size",
    "tcp_flags", "ttl", "ip_version",
    "is_fragment", "window_size", "urgent_pointer",
    "sni_length", "is_tls", "is_http",
    "hour_of_day",
    "packets_per_second", "unique_ports_accessed", "connection_count",
]


def ip_to_int(ip: str) -> int:
    """Convert dotted-decimal IP string to 32-bit integer."""
    try:
        parts = [int(x) for x in ip.split(".")]
        return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
    except Exception:
        return 0


class FeatureExtractor:

    @staticmethod
    def extract(pkt: ParsedPacket,
                sni: str = "",
                is_http: bool = False,
                behavioral: Dict[str, Any] = None) -> List[float]:
        """
        Returns a list of floats in the order defined by FEATURE_NAMES.
        behavioral: dict from behavioral_engine for this src IP.
        """
        beh = behavioral or {}

        import datetime
        hour = datetime.datetime.fromtimestamp(pkt.timestamp).hour if pkt.timestamp else 0

        features = [
            ip_to_int(pkt.src_ip),
            ip_to_int(pkt.dst_ip),
            pkt.src_port / 65535.0,
            pkt.dst_port / 65535.0,
            pkt.protocol,
            pkt.ip_length,
            pkt.payload_size,
            pkt.tcp_flags,
            pkt.ttl,
            pkt.ip_version,
            int(pkt.is_fragment),
            pkt.window_size,
            pkt.urgent_ptr,
            len(sni),
            int(pkt.dst_port == 443),
            int(is_http),
            hour,
            beh.get("packets_per_second", 0),
            beh.get("unique_dst_ports", 0),
            beh.get("connection_count", 0),
        ]
        return features
