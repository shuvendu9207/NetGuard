"""
Capture Module
Reads packets from a PCAP file or live interface and pushes
RawPacket objects onto a thread-safe queue.
"""

import queue
import struct
import threading
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class RawPacket:
    data:      bytes
    timestamp: float
    orig_len:  int


class CaptureThread(threading.Thread):

    def __init__(self, packet_queue: queue.Queue,
                 pcap_file: Optional[str] = None,
                 interface: Optional[str] = None):
        super().__init__(daemon=True, name="CaptureThread")
        self.packet_queue = packet_queue
        self.pcap_file    = pcap_file
        self.interface    = interface
        self._stop_event  = threading.Event()
        self.total_read   = 0

    def stop(self):
        self._stop_event.set()

    def run(self):
        if self.pcap_file:
            self._read_pcap()
        elif self.interface:
            self._live_capture()
        else:
            raise ValueError("Provide either pcap_file or interface.")

    # ── PCAP reader (no external libs needed) ────────────────────────────────
    def _read_pcap(self):
        try:
            with open(self.pcap_file, "rb") as f:
                # Global header (24 bytes)
                magic = struct.unpack("<I", f.read(4))[0]
                if magic == 0xa1b2c3d4:
                    endian = "<"
                elif magic == 0xd4c3b2a1:
                    endian = ">"
                else:
                    print(f"[Capture] Not a valid PCAP file: {self.pcap_file}")
                    return

                f.read(20)  # skip rest of global header

                while not self._stop_event.is_set():
                    hdr = f.read(16)
                    if len(hdr) < 16:
                        break  # EOF
                    ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                        endian + "IIII", hdr
                    )
                    data = f.read(incl_len)
                    if len(data) < incl_len:
                        break
                    timestamp = ts_sec + ts_usec / 1_000_000
                    pkt = RawPacket(data=data, timestamp=timestamp,
                                    orig_len=orig_len)
                    self.packet_queue.put(pkt)
                    self.total_read += 1

        except FileNotFoundError:
            print(f"[Capture] File not found: {self.pcap_file}")
        except Exception as e:
            print(f"[Capture] Error reading PCAP: {e}")

    # ── Live capture via scapy ────────────────────────────────────────────────
    def _live_capture(self):
        try:
            from scapy.all import sniff, raw
            def handle(pkt):
                if self._stop_event.is_set():
                    return
                raw_pkt = RawPacket(
                    data=bytes(pkt),
                    timestamp=float(pkt.time),
                    orig_len=len(pkt)
                )
                self.packet_queue.put(raw_pkt)
                self.total_read += 1

            print(f"[Capture] Live capture on {self.interface} ...")
            sniff(iface=self.interface, prn=handle,
                  stop_filter=lambda _: self._stop_event.is_set())
        except Exception as e:
            print(f"[Capture] Live capture error: {e}")
