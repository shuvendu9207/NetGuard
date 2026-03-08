"""
Dataset Exporter
Buffers packet feature vectors and flushes them to a CSV file.
Thread-safe, batched writes for performance.
"""

import csv
import queue
import threading
import os
from typing import List
from extractor.feature_extractor import FEATURE_NAMES

CSV_COLUMNS = FEATURE_NAMES + ["label", "src_ip", "dst_ip", "timestamp"]


class DatasetExporter:

    def __init__(self, output_path: str = "data/captures.csv",
                 buffer_size: int = 500):
        self.output_path = output_path
        self.buffer_size = buffer_size
        self._queue      = queue.Queue()
        self._thread     = threading.Thread(target=self._run, daemon=True,
                                            name="DatasetExportThread")
        self._write_header()
        self._thread.start()

    def _write_header(self):
        if not os.path.exists(self.output_path):
            os.makedirs(os.path.dirname(self.output_path), exist_ok=True)
            with open(self.output_path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(CSV_COLUMNS)

    def add(self, features: List[float], label: str,
            src_ip: str = "", dst_ip: str = "", timestamp: float = 0.0):
        row = features + [label, src_ip, dst_ip, timestamp]
        self._queue.put(row)

    def _run(self):
        buffer = []
        while True:
            row = self._queue.get()
            buffer.append(row)
            if len(buffer) >= self.buffer_size:
                self._flush(buffer)
                buffer = []

    def _flush(self, rows: list):
        try:
            with open(self.output_path, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerows(rows)
        except Exception as e:
            print(f"[DatasetExporter] Write error: {e}")
