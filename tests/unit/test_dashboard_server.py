from __future__ import annotations

import json
import threading
import time
import urllib.error
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
    # Offline model comparison is part of the evidence view (3-seed RF/LSTM/fusion).
    assert "model_comparison" in data
    comparison = data["model_comparison"]
    assert comparison is not None
    assert comparison["seeds"] == [42, 123, 456]
    assert "ci_source" in comparison
    for model_name in ("random_forest", "lstm", "fusion"):
        assert model_name in comparison["models"]
        for metric in ("accuracy", "f1", "roc_auc"):
            entry = comparison["models"][model_name][metric]
            assert "mean" in entry
            assert "std" in entry
            assert "ci" in entry
            assert entry["ci"]["lower"] <= entry["ci"]["upper"]


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
    # Device discovery is live-only; sample traffic is synthetic and must not
    # populate the real-network device table.
    assert snapshot["devices"] == []
    assert snapshot["network"] is None
    assert snapshot["device_discovery"]["available"] is False

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


def test_live_session_attack_injection(tmp_path: Path):
    """Injected scenario packets flow through the same pipeline, complete, and alert."""
    pcap = tmp_path / "inject_session.pcap"
    _write_attack_pcap(pcap)

    engine = ReplayEngine(model=_AlwaysAttackModel(), threshold=0.50)
    session = LiveSession(engine=engine)
    result = session.start(mode="sample", pcap=str(pcap), pace_speed=50.0, loop=True)
    assert not result.get("error")

    try:
        # speed=50 compresses the 3.27 s scenario pacing to ~65 ms (test aid only).
        started = session.inject_scenario("slow_http_dos_lite", speed=50.0)
        assert not started.get("error")
        assert started["status"] == "injecting"
        assert started["injection"]["packets_total"] == 2

        deadline = time.time() + 10.0
        status = session.snapshot()["injection"]
        while status["active"] and time.time() < deadline:
            time.sleep(0.05)
            status = session.snapshot()["injection"]
        assert status["active"] is False
        assert status["packets_sent"] == 2
        assert status["finished_at"]

        snapshot = session.snapshot()
        injected_flows = [f for f in snapshot["recent_flows"] if "203.0.113.67" in f["src_endpoint"]]
        assert injected_flows, "the injected scenario flow must appear in the live flow table"
        # The mock model scores every flow 0.9 -> the injected flow produced a HIGH alert.
        assert any(
            "203.0.113.67" in a["src_endpoint"] and a["alert_level"] == "HIGH"
            for a in snapshot["recent_alerts"]
        )
    finally:
        session.stop()


def test_live_session_injection_guards(tmp_path: Path):
    """Injection is refused without a running session, for unknown ids, and while one is active."""
    pcap = tmp_path / "inject_guard.pcap"
    _write_attack_pcap(pcap)

    engine = ReplayEngine(model=_AlwaysAttackModel(), threshold=0.50)
    session = LiveSession(engine=engine)
    assert session.inject_scenario("slow_http_dos").get("error"), (
        "must refuse injection without a running session"
    )

    result = session.start(mode="sample", pcap=str(pcap), pace_speed=50.0, loop=True)
    assert not result.get("error")
    try:
        unknown = session.inject_scenario("does_not_exist")
        assert unknown.get("error")
        assert "Unknown scenario" in unknown["error"]

        started = session.inject_scenario("slow_http_dos", speed=1.0)  # ~3.25 s of real pacing
        assert not started.get("error")
        concurrent = session.inject_scenario("slow_http_dos_lite", speed=1.0)
        assert concurrent.get("error"), "a second injection must be rejected while one is active"

        time.sleep(0.1)
        status = session.snapshot()["injection"]
        assert status["active"] is True
        assert status["packets_sent"] == 1  # first packet emitted immediately; next is ~3.25 s away
    finally:
        session.stop()


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
        assert "devices" in snapshot
        assert isinstance(snapshot["devices"], list)
        assert "network" in snapshot
        assert "device_counters" in snapshot
        assert "device_discovery" in snapshot

        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/live/devices", timeout=5) as resp:
            assert resp.status == 200
            device_data = json.loads(resp.read().decode("utf-8"))
        assert device_data["scope"] == "passive-observed"
        assert isinstance(device_data["devices"], list)
        assert "counters" in device_data

        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/live/interfaces", timeout=5) as resp:
            assert resp.status == 200
            info = json.loads(resp.read().decode("utf-8"))
        assert isinstance(info["interfaces"], list)
        assert "raw_socket" in info["permissions"]

        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/live/scenarios", timeout=5) as resp:
            assert resp.status == 200
            scenario_data = json.loads(resp.read().decode("utf-8"))
        assert len(scenario_data["scenarios"]) >= 1
        assert all("expected_band" in spec for spec in scenario_data["scenarios"])

        # Injection without a running session is rejected with a clear error.
        inject_req = urllib.request.Request(
            f"http://127.0.0.1:{port}/api/live/inject-attack",
            data=json.dumps({"scenario": "slow_http_dos"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(inject_req, timeout=5)
            raised = False
        except urllib.error.HTTPError as exc:
            raised = exc.code == 400
        assert raised, "inject-attack must return HTTP 400 when no session is running"

        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as resp:
            assert resp.status == 200
            html = resp.read().decode("utf-8")
        assert "Live Monitor" in html
        assert "Replay &amp; Evidence" in html
    finally:
        server.shutdown()
        server.server_close()
