"""Lightweight, non-invasive resource profiler (build spec section 38; Task 15).

Measures peak RSS (MiB), wall-clock time, CPU count, and output disk usage with negligible overhead (<1%).
"""

from __future__ import annotations

import os
import resource
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def get_peak_rss_mib() -> float:
    """Return process lifetime peak RSS (high-water mark) in MiB via getrusage.

    On Linux, ru_maxrss is reported in KiB (1024 bytes).
    On Darwin (macOS), ru_maxrss is reported in bytes.
    """
    rusage = resource.getrusage(resource.RUSAGE_SELF)
    raw_rss = float(rusage.ru_maxrss)
    if sys.platform == "darwin":
        return raw_rss / (1024.0 * 1024.0)
    # Linux and other POSIX report in KiB
    return raw_rss / 1024.0


# Backward compatibility alias
get_rss_mib = get_peak_rss_mib


def get_current_rss_mib() -> float:
    """Return instantaneous resident set size (current RSS) in MiB.

    On Linux, reads from /proc/self/statm for true instantaneous memory usage.
    Falls back to get_peak_rss_mib() on systems without /proc.
    """
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/self/statm", "r", encoding="utf-8") as f:
                parts = f.read().split()
                if len(parts) >= 2:
                    resident_pages = int(parts[1])
                    return float(resident_pages * resource.getpagesize()) / (1024.0 * 1024.0)
        except OSError:
            pass
    return get_peak_rss_mib()


@dataclass
class ResourceProfile:
    """Structured resource consumption metrics.

    Note on memory semantics:
    - start_rss_mib: instantaneous process RSS at profiler entry.
    - end_rss_mib: instantaneous process RSS at profiler exit.
    - peak_rss_mib: kernel-recorded process lifetime high-water mark (ru_maxrss).
    """

    peak_rss_mib: float = 0.0
    start_rss_mib: float = 0.0
    end_rss_mib: float = 0.0
    duration_s: float = 0.0
    cpu_count: int = 1
    disk_bytes: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "peak_rss_mib": round(self.peak_rss_mib, 2),
            "start_rss_mib": round(self.start_rss_mib, 2),
            "end_rss_mib": round(self.end_rss_mib, 2),
            "rss_delta_mib": round(max(0.0, self.end_rss_mib - self.start_rss_mib), 2),
            "duration_s": round(self.duration_s, 4),
            "cpu_count": self.cpu_count,
            "disk_bytes": self.disk_bytes,
            "disk_mib": round(self.disk_bytes / (1024.0 * 1024.0), 3),
        }


class ResourceProfiler:
    """Context manager for profiling execution resources with precise semantics."""

    def __init__(self, target_dir: str | Path | None = None) -> None:
        self.target_dir = Path(target_dir) if target_dir else None
        self.profile = ResourceProfile()
        self._start_time: float = 0.0

    def __enter__(self) -> ResourceProfiler:
        self._start_time = time.perf_counter()
        self.profile.start_rss_mib = get_current_rss_mib()
        self.profile.cpu_count = os.cpu_count() or 1
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.profile.duration_s = time.perf_counter() - self._start_time
        self.profile.end_rss_mib = get_current_rss_mib()
        self.profile.peak_rss_mib = get_peak_rss_mib()
        if self.target_dir and self.target_dir.is_dir():
            total_disk = 0
            for p in self.target_dir.rglob("*"):
                if p.is_file():
                    try:
                        total_disk += p.stat().st_size
                    except OSError:
                        pass
            self.profile.disk_bytes = total_disk

    def to_dict(self) -> dict[str, Any]:
        return self.profile.to_dict()
