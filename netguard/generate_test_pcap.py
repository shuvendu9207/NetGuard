#!/usr/bin/env python3
"""
Generate a test PCAP with a variety of traffic types.
Requires scapy: pip install scapy
"""
from scapy.all import *
import random

packets = []

# Normal HTTPS
for i in range(20):
    pkt = (Ether() /
           IP(src="192.168.1.100", dst="142.250.185.78") /
           TCP(sport=random.randint(49152,65535), dport=443, flags="S"))
    packets.append(pkt)

# Port scan simulation
for port in range(1, 60):
    pkt = (Ether() /
           IP(src="192.168.1.77", dst="10.0.0.1") /
           TCP(sport=54321, dport=port, flags="S"))
    packets.append(pkt)

# HTTP traffic
for i in range(10):
    payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    pkt = (Ether() /
           IP(src="192.168.1.101", dst="93.184.216.34") /
           TCP(sport=random.randint(49152,65535), dport=80) /
           Raw(load=payload))
    packets.append(pkt)

wrpcap("test_dpi.pcap", packets)
print(f"[+] Generated test_dpi.pcap with {len(packets)} packets.")
