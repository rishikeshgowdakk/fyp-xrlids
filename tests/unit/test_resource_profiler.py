"""Unit tests for ResourceProfiler (Task 15)."""

from __future__ import annotations

import sys
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from xrlids.utils.profiler import ResourceProfiler, get_rss_mib


def test_get_rss_mib_conversion_linux():
    """Verify that on Linux ru_maxrss (reported in KiB) is converted to MiB by dividing by 1024."""
    mock_rusage = MagicMock()
    mock_rusage.ru_maxrss = 1048576  # 1,048,576 KiB = 1024 MiB
    with patch("sys.platform", "linux"), patch("resource.getrusage", return_value=mock_rusage):
        mib = get_rss_mib()
        assert mib == pytest.approx(1024.0)


def test_get_rss_mib_conversion_darwin():
    """Verify that on macOS ru_maxrss (reported in bytes) is converted to MiB by dividing by 1024^2."""
    mock_rusage = MagicMock()
    mock_rusage.ru_maxrss = 1073741824  # 1 GiB in bytes = 1024 MiB
    with patch("sys.platform", "darwin"), patch("resource.getrusage", return_value=mock_rusage):
        mib = get_rss_mib()
        assert mib == pytest.approx(1024.0)


def test_profiler_context_manager(tmp_path: Path):
    """Verify context manager captures start/end states, duration, and disk usage."""
    test_file = tmp_path / "test_artifact.bin"
    
    with ResourceProfiler(target_dir=tmp_path) as prof:
        time.sleep(0.05)
        test_file.write_bytes(b"0" * 4096)

    data = prof.to_dict()
    assert data["duration_s"] >= 0.04
    assert data["start_rss_mib"] > 0
    assert data["end_rss_mib"] > 0
    assert data["peak_rss_mib"] >= data["start_rss_mib"]
    assert data["disk_bytes"] >= 4096
    assert data["cpu_count"] >= 1


def test_get_current_vs_peak_rss():
    """Verify that get_current_rss_mib returns positive value and peak >= current."""
    from xrlids.utils.profiler import get_current_rss_mib, get_peak_rss_mib

    curr = get_current_rss_mib()
    peak = get_peak_rss_mib()

    assert curr > 0.0
    assert peak > 0.0
    # Process peak (ru_maxrss) should always be greater than or equal to current instantaneous RSS
    assert peak >= curr
