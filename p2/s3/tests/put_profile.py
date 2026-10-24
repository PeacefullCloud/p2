"""Test-only native commit measurements, never installed in deployment."""
import threading
from time import perf_counter

from p2.s3 import volume_writer

_lock = threading.Lock()
_metrics = {}


def install():
    original = volume_writer._write_and_commit_batch

    def measured(batch, resolve):
        for job in batch:
            if job.timings is None:
                job.timings = {}
                job.submitted_at = perf_counter()
        original(batch, resolve)
        with _lock:
            _metrics["batches"] = _metrics.get("batches", 0) + 1
            _metrics["objects"] = _metrics.get("objects", 0) + len(batch)
            for job in batch:
                for name in ("data_write", "data_sync", "metadata_lock", "metadata_commit"):
                    _metrics[name] = _metrics.get(name, 0) + job.timings.get(name, 0)

    volume_writer._write_and_commit_batch = measured


def snapshot(reset=False):
    with _lock:
        result = dict(_metrics)
        if reset:
            _metrics.clear()
    return result
