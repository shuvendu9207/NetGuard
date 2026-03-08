"""
Packet Parser
Parses raw bytes into a structured ParsedPacket.
Handles: Ethernet → IPv4 → TCP / UDP / ICMP
"""

import struct
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ParsedPacket:
    # Ethernet
    src_mac:    str  = ""
    dst_mac:    str  = ""
    ether_type: int  = 0

    # IP
    ip_version:  int  = 4
    src_ip:      str  = ""
    dst_ip:      str  = ""
    protocol:    int  = 0     # 6=TCP 17=UDP 1=ICMP
    ttl:         int  = 0
    ip_length:   int  = 0
    is_fragment: bool = False

    # TCP
    has_tcp:     bool = False
    src_port:    int  = 0
    dst_port:    int  = 0
    seq_num:     int  = 0
    ack_num:     int  = 0
    tcp_flags:   int  = 0    # FIN=1 SYN=2 RST=4 PSH=8 ACK=16 URG=32
    window_size: int  = 0
    urgent_ptr:  int  = 0

    # UDP
    has_udp: bool = False

    # ICMP
    has_icmp:  bool = False
    icmp_type: int  = 0
    icmp_code: int  = 0

    # Payload
    payload:      bytes = field(default_factory=bytes)
    payload_size: int   = 0

    # Metadata
    timestamp:  float = 0.0
    raw_length: int   = 0


def _mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _ip(raw: bytes) -> str:
    return ".".join(str(b) for b in raw)


class PacketParser:

    @staticmethod
    def parse(data: bytes, timestamp: float = 0.0) -> Optional[ParsedPacket]:
        pkt = ParsedPacket(timestamp=timestamp, raw_length=len(data))

        try:
            # ── Ethernet header (14 bytes) ────────────────────────────────
            if len(data) < 14:
                return None
            pkt.dst_mac    = _mac(data[0:6])
            pkt.src_mac    = _mac(data[6:12])
            pkt.ether_type = struct.unpack("!H", data[12:14])[0]

            # Only handle IPv4 (0x0800)
            if pkt.ether_type != 0x0800:
                return pkt

            # ── IPv4 header (min 20 bytes) ────────────────────────────────
            if len(data) < 34:
                return pkt
            ip_start  = 14
            ihl       = (data[ip_start] & 0x0F) * 4
            pkt.ip_version  = (data[ip_start] >> 4)
            pkt.ip_length   = struct.unpack("!H", data[ip_start+2:ip_start+4])[0]
            flags_frag      = struct.unpack("!H", data[ip_start+6:ip_start+8])[0]
            pkt.is_fragment = bool(flags_frag & 0x1FFF)
            pkt.ttl         = data[ip_start+8]
            pkt.protocol    = data[ip_start+9]
            pkt.src_ip      = _ip(data[ip_start+12:ip_start+16])
            pkt.dst_ip      = _ip(data[ip_start+16:ip_start+20])

            transport_start = ip_start + ihl

            # ── TCP (protocol 6) ──────────────────────────────────────────
            if pkt.protocol == 6:
                if len(data) < transport_start + 20:
                    return pkt
                pkt.has_tcp    = True
                pkt.src_port   = struct.unpack("!H", data[transport_start:transport_start+2])[0]
                pkt.dst_port   = struct.unpack("!H", data[transport_start+2:transport_start+4])[0]
                pkt.seq_num    = struct.unpack("!I", data[transport_start+4:transport_start+8])[0]
                pkt.ack_num    = struct.unpack("!I", data[transport_start+8:transport_start+12])[0]
                tcp_hlen       = ((data[transport_start+12] >> 4) * 4)
                pkt.tcp_flags  = data[transport_start+13]
                pkt.window_size= struct.unpack("!H", data[transport_start+14:transport_start+16])[0]
                pkt.urgent_ptr = struct.unpack("!H", data[transport_start+18:transport_start+20])[0]
                payload_start  = transport_start + tcp_hlen
                pkt.payload    = data[payload_start:]
                pkt.payload_size = len(pkt.payload)

            # ── UDP (protocol 17) ─────────────────────────────────────────
            elif pkt.protocol == 17:
                if len(data) < transport_start + 8:
                    return pkt
                pkt.has_udp  = True
                pkt.src_port = struct.unpack("!H", data[transport_start:transport_start+2])[0]
                pkt.dst_port = struct.unpack("!H", data[transport_start+2:transport_start+4])[0]
                pkt.payload  = data[transport_start+8:]
                pkt.payload_size = len(pkt.payload)

            # ── ICMP (protocol 1) ─────────────────────────────────────────
            elif pkt.protocol == 1:
                if len(data) < transport_start + 4:
                    return pkt
                pkt.has_icmp   = True
                pkt.icmp_type  = data[transport_start]
                pkt.icmp_code  = data[transport_start+1]

        except Exception:
            pass

        return pkt
