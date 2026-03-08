"""
Worker Thread Pool
Spawns N worker threads that each drain a shared packet queue.
"""

import queue
import threading
from typing import Callable, List


class WorkerPool:

    def __init__(self, num_workers: int, task_fn: Callable):
        self.num_workers = num_workers
        self.task_fn     = task_fn
        self.queue       = queue.Queue(maxsize=10000)
        self._threads: List[threading.Thread] = []

    def start(self):
        for i in range(self.num_workers):
            t = threading.Thread(target=self._worker, daemon=True,
                                 name=f"Worker-{i}")
            t.start()
            self._threads.append(t)

    def submit(self, item):
        self.queue.put(item)

    def _worker(self):
        while True:
            item = self.queue.get()
            try:
                self.task_fn(item)
            except Exception as e:
                print(f"[Worker] Error: {e}")
            finally:
                self.queue.task_done()

    def wait(self):
        self.queue.join()
