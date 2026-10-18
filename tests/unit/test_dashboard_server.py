from __future__ import annotations

import json
import threading
import time
import urllib.request
from pathlib import Path
import sys

import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from dashboard.server import (
    DASHBOARD_DIR,
    FIGURES_DIR,
    REPO_ROOT as SERVER_REPO_ROOT,
    LiveSession,
    create_server,
    get_dashboard_data,
)
from xrlids.demo.pcap import build_raw_packet, write_pcap
from xrlids.demo.replay import ReplayEngine
from xrlids.live.capture import PacketCaptureService


class _AlwaysAttackModel:
    """Mock detector returning a fixed attack probability (test double)."""

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        return np.array([[0.1, 0.9]] * len(X))


def _write_attack_pcap(path: Path) -> None:
    """Write a single attack-like flow (burst + RST) to a PCAP file."""
    packets = []
    t = 100.0
    for _ in range(5):
        packets.append((t, build_raw_packet("10.0.0.99", "192.168.1.1", 6000, 80, 6, payload_len=50)))
        t += 0.001
    packets.append((t, build_raw_packet("192.168.1.1", "10.0.0.99", 80, 6000, 6, {"rst": True})))
    write_pcap(path, packets)


def test_dashboard_files_exist():
    assert DASHBOARD_DIR.exists()
    assert (DASHBOARD_DIR / "index.html").is_file()
    assert (DASHBOARD_DIR / "app.js").is_file()
    assert (DASHBOARD_DIR / "server.py").is_file()
    assert (DASHBOARD_DIR / "README.md").is_file()


def test_get_dashboard_data_structure():
    data = get_dashboard_data()
    assert isinstance(data, dict)
    assert "status" in data
    assert data["status"] == "ready"
    assert "replay" in data
    assert "shap" in data
    assert "figures" in data
    assert isinstance(data["figures"], list)


def test_live_session_sample_stream_lifecycle(tmp_path: Path):
    """Verify a sample-stream session captures packets, completes flows, and emits observations/alerts."""
    pcap = tmp_path / "live_session_test.pcap"
    _write_attack_pcap(pcap)

    engine = ReplayEngine(model=_AlwaysAttackModel(), threshold=0.50)
    session = LiveSession(engine=engine)

    result = session.start(mode="sample", pcap=str(pcap), pace_speed=1000.0, loop=False)
    assert not result.get("error")
    assert result["status"] == "running"
    assert result["mode"] == "sample"

    deadline = time.time() + 10.0
    snapshot = session.snapshot()
    while snapshot["status"] == "running" and time.time() < deadline:
        time.sleep(0.05)
        snapshot = session.snapshot()

    assert snapshot["status"] == "stopped"
    assert snapshot["counters"]["packets"] == 6
    assert snapshot["counters"]["flows"] >= 1
    # The mock model returns 0.9 for every flow -> every flow is an alert at threshold 0.50.
    assert snapshot["counters"]["alerts"] == snapshot["counters"]["flows"]
    assert any(
        "10.0.0.99" in flow["src_endpoint"] or "10.0.0.99" in flow["dst_endpoint"]
        for flow in snapshot["recent_flows"]
    )
    assert snapshot["recent_flows"][-1]["prediction_label"] == "ATTACK"
    assert snapshot["recent_alerts"][-1]["alert_level"] == "HIGH"

    # Session is reusable after it stops.
    second = session.start(mode="sample", pcap=str(pcap), pace_speed=1000.0, loop=False)
    assert not second.get("error")
    session.stop()


def test_live_session_live_mode_requires_root_when_unprivileged():
    """Live interface capture is refused with a clear message when raw sockets are unavailable."""
    if PacketCaptureService.check_permissions():
        return  # Privileged context (e.g. CI as root): permission gate cannot be exercised here.
    engine = ReplayEngine(model=_AlwaysAttackModel(), threshold=0.50)
    session = LiveSession(engine=engine)
    result = session.start(mode="live", interface="lo")
    assert result.get("error")
    assert "root" in result["error"].lower()
    assert session.snapshot()["status"] == "stopped"


def test_live_session_rejects_unknown_mode():
    engine = ReplayEngine(model=_AlwaysAttackModel(), threshold=0.50)
    session = LiveSession(engine=engine)
    result = session.start(mode="telepathy")
    assert result.get("error")


def test_dashboard_http_live_endpoints():
    """Smoke-test the HTTP surface for the live monitor endpoints."""
    server = create_server(port=0)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/live", timeout=5) as resp:
            assert resp.status == 200
            snapshot = json.loads(resp.read().decode("utf-8"))
        assert "status" in snapshot
        assert "counters" in snapshot
        assert "thresholds" in snapshot

        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/live/interfaces", timeout=5) as resp:
            assert resp.status == 200
            info = json.loads(resp.read().decode("utf-8"))
        assert isinstance(info["interfaces"], list)
        assert "raw_socket" in info["permissions"]

        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as resp:
            assert resp.status == 200
            html = resp.read().decode("utf-8")
        assert "Live Monitor" in html
        assert "Replay &amp; Evidence" in html
    finally:
        server.shutdown()
        server.server_close()
