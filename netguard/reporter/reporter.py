"""
Reporter Module
Generates a live terminal summary and an HTML report after a session.
"""

import os
import time
from collections import defaultdict
from typing import Dict


class Reporter:

    def __init__(self, output_dir: str = "reports/"):
        self.output_dir    = output_dir
        self.start_time    = time.time()
        self.total_packets = 0
        self.total_bytes   = 0
        self.forwarded     = 0
        self.dropped       = 0
        self.alerts        = 0
        self.app_counts: Dict[str, int]    = defaultdict(int)
        self.label_counts: Dict[str, int]  = defaultdict(int)
        self.top_talkers: Dict[str, int]   = defaultdict(int)

    def record(self, src_ip: str, pkt_len: int, app_type: str,
               label: str, blocked: bool):
        self.total_packets += 1
        self.total_bytes   += pkt_len
        self.app_counts[app_type]  += 1
        self.label_counts[label]   += 1
        self.top_talkers[src_ip]   += 1
        if blocked:
            self.dropped += 1
        else:
            self.forwarded += 1

    def print_summary(self):
        elapsed = int(time.time() - self.start_time)
        total   = self.total_packets or 1
        sep     = "=" * 60
        print()
        print(sep)
        print(f"{'NetGuard Session Report':^60}")
        print(sep)
        print(f"  Elapsed:         {elapsed}s")
        print(f"  Total Packets:   {self.total_packets:,}")
        print(f"  Total Bytes:     {self.total_bytes/1024:.1f} KB")
        print(f"  Forwarded:       {self.forwarded:,}")
        print(f"  Dropped:         {self.dropped:,}")
        print(f"  Alerts:          {self.alerts:,}")
        print("-" * 60)
        print("  APPLICATION BREAKDOWN")
        for app, count in sorted(self.app_counts.items(),
                                  key=lambda x: -x[1])[:10]:
            pct = count / total * 100
            bar = "#" * int(pct / 3)
            print(f"  {app:<20} {count:>6}  {pct:5.1f}%  {bar}")
        print("-" * 60)
        print("  ML DETECTIONS")
        for label, count in sorted(self.label_counts.items(),
                                    key=lambda x: -x[1]):
            print(f"  {label:<20} {count:>6}  ({count/total*100:.1f}%)")
        print(sep)

    def save_html(self):
        os.makedirs(self.output_dir, exist_ok=True)
        filename = os.path.join(
            self.output_dir,
            f"report_{time.strftime('%Y%m%d_%H%M%S')}.html"
        )
        # TODO: render full HTML report with Jinja2 template
        with open(filename, "w") as f:
            f.write(f"<html><body><h1>NetGuard Report</h1>"
                    f"<p>Packets: {self.total_packets}</p></body></html>")
        print(f"[Reporter] HTML report saved: {filename}")
        return filename
