"""Unit tests for genuine per-flow TreeSHAP explainability in XRL-IDARS.

Validates:
1. Exact TreeSHAP calculation via explain_flow_prediction().
2. Honest error handling when features are missing or incomplete (no silent zero-filling).
3. Preservation of complete feature dictionaries across LiveLabMonitor and LiveSession streams.
4. Server POST /api/csv/explain endpoint handling valid features, flow_id lookup, and error states.
5. Removal of fabricated numerical SHAP values and ground-truth branching from frontend files.
"""

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
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from dashboard.server import LIVE_SESSION, LiveSession, create_server
from xrlids.demo.flow import FlowBuilder
from xrlids.demo.live_lab import FlowObservation, LiveLabMonitor
from xrlids.demo.pcap import PacketInfo, build_raw_packet, write_pcap
from xrlids.demo.replay import ReplayEngine
from xrlids.evaluation.csv_evaluator import explain_flow_prediction
from xrlids.features.definitions import R10_FEATURES, R4_FEATURES


class _MockModel:
    """Mock detector predicting consistent attack score."""

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        return np.array([[0.2, 0.8]] * len(X))


def _sample_r10_features() -> dict[str, float]:
    return {
        "flow_duration_ms": 1500.0,
        "flow_packets_per_s": 45.2,
        "flow_bytes_per_s": 8200.5,
        "packet_length_mean": 240.0,
        "packet_length_std": 110.5,
        "syn_count": 2.0,
        "ack_count": 3.0,
        "rst_count": 0.0,
        "fin_count": 1.0,
        "syn_ack_ratio": 0.67,
    }


def _write_test_pcap(path: Path) -> None:
    packets = []
    t = 100.0
    for _ in range(4):
        packets.append((t, build_raw_packet("10.0.0.1", "10.0.0.2", 5000, 80, 6, payload_len=60)))
        t += 0.01
    packets.append((t, build_raw_packet("10.0.0.2", "10.0.0.1", 80, 5000, 6, {"fin": True})))
    write_pcap(path, packets)


# ---------------------------------------------------------------------------
# 1. explain_flow_prediction() unit tests
# ---------------------------------------------------------------------------

def test_explain_flow_prediction_valid_cicids2017():
    features = _sample_r10_features()
    result = explain_flow_prediction(features, benchmark="cicids2017")

    assert "features" in result
    assert "attributions" in result
    assert "base_value" in result
    assert "Random Forest" in result["explainer_model"]
    assert len(result["features"]) == 10
    assert len(result["attributions"]) == 10

    # Ensure ranking is strictly by absolute SHAP attribution descending
    abs_shaps = [abs(f["shap_attribution"]) for f in result["features"]]
    assert abs_shaps == sorted(abs_shaps, reverse=True)

    # Check direction mapping
    for f in result["features"]:
        assert f["direction"] in ("INCREASES_THREAT", "DECREASES_THREAT")
        if f["shap_attribution"] > 0:
            assert f["direction"] == "INCREASES_THREAT"
        elif f["shap_attribution"] < 0:
            assert f["direction"] == "DECREASES_THREAT"
        assert isinstance(f["value"], (int, float))

    # Check scientific notices
    notices = result["scientific_notices"]
    assert any("Random Forest" in n for n in notices)
    assert any("LSTM" in n or "DQN" in n for n in notices)


def test_explain_flow_prediction_r4_unswnb15():
    r4_feats = {f: 100.0 for f in R4_FEATURES}
    result = explain_flow_prediction(r4_feats, benchmark="unswnb15")
    assert len(result["features"]) == 4
    assert {f["feature"] for f in result["features"]} == set(R4_FEATURES)


def test_explain_flow_prediction_missing_features_rejected():
    """Verify missing features are NOT silently filled with zeros."""
    incomplete = {"flow_duration_ms": 100.0}
    with pytest.raises(ValueError, match="missing required features"):
        explain_flow_prediction(incomplete, benchmark="cicids2017")

    with pytest.raises(ValueError, match="missing required features"):
        explain_flow_prediction({}, benchmark="cicids2017")

    with pytest.raises(ValueError, match="must be a dictionary"):
        explain_flow_prediction(None, benchmark="cicids2017")  # type: ignore


def test_explain_flow_prediction_invalid_benchmark():
    features = _sample_r10_features()
    with pytest.raises(ValueError, match="Unsupported benchmark"):
        explain_flow_prediction(features, benchmark="imaginary_ids_2099")


# ---------------------------------------------------------------------------
# 2. Feature preservation in FlowObservation and LiveLabMonitor
# ---------------------------------------------------------------------------

def test_livelab_monitor_preserves_features(tmp_path: Path):
    pcap = tmp_path / "monitor_test.pcap"
    _write_test_pcap(pcap)

    engine = ReplayEngine(model=_MockModel(), threshold=0.50)
    flows_recorded: list[FlowObservation] = []

    monitor = LiveLabMonitor(
        engine=engine,
        alert_threshold=0.50,
        on_flow_callback=lambda flow_obs: flows_recorded.append(flow_obs),
    )

    from xrlids.demo.pcap import PcapReader
    reader = PcapReader(pcap)
    monitor.process_packet_stream(reader.read_packets())

    assert len(flows_recorded) >= 1
    flow0 = flows_recorded[0]
    assert flow0.features is not None
    assert set(flow0.features.keys()) == set(R10_FEATURES)
    for feat_name, val in flow0.features.items():
        assert isinstance(val, (int, float))
        assert not np.isnan(val)


def test_live_session_sample_stream_preserves_features(tmp_path: Path):
    pcap = tmp_path / "live_session_features.pcap"
    _write_test_pcap(pcap)

    engine = ReplayEngine(model=_MockModel(), threshold=0.50)
    session = LiveSession(engine=engine)
    session.start(mode="sample", pcap=str(pcap), pace_speed=1000.0, loop=False)

    deadline = time.time() + 5.0
    snapshot = session.snapshot()
    while snapshot["status"] == "running" and time.time() < deadline:
        time.sleep(0.05)
        snapshot = session.snapshot()
    session.stop()

    assert snapshot["status"] == "stopped"
    assert len(snapshot["recent_flows"]) >= 1
    last_flow = snapshot["recent_flows"][-1]
    assert "features" in last_flow
    assert last_flow["features"] is not None
    assert set(last_flow["features"].keys()) == set(R10_FEATURES)


def test_live_session_dataset_stream_preserves_features():
    engine = ReplayEngine(model=_MockModel(), threshold=0.50)
    session = LiveSession(engine=engine)
    session.start(mode="dataset", dataset_category="benign", pace_speed=50.0, loop=False)

    deadline = time.time() + 5.0
    snapshot = session.snapshot()
    while len(snapshot["recent_flows"]) < 2 and time.time() < deadline:
        time.sleep(0.05)
        snapshot = session.snapshot()
    session.stop()

    assert len(snapshot["recent_flows"]) >= 1
    flow = snapshot["recent_flows"][0]
    assert "features" in flow
    assert flow["features"] is not None
    assert set(flow["features"].keys()) == set(R10_FEATURES)


# ---------------------------------------------------------------------------
# 3. Server /api/csv/explain API endpoint tests
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def explain_test_server():
    server = create_server(port=0)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


def test_api_csv_explain_with_direct_features(explain_test_server: str):
    url = f"{explain_test_server}/api/csv/explain"
    payload = json.dumps({
        "features": _sample_r10_features(),
        "benchmark": "cicids2017",
    }).encode("utf-8")

    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert "features" in data
        assert len(data["features"]) == 10
        assert "Random Forest" in data["explainer_model"]


def test_api_csv_explain_with_flow_id_lookup(explain_test_server: str):
    # Register a flow in LIVE_SESSION
    test_features = _sample_r10_features()
    with LIVE_SESSION._lock:
        LIVE_SESSION.flows.append({
            "flow_id": 88888,
            "src_endpoint": "10.0.0.1:1234",
            "dst_endpoint": "10.0.0.2:80",
            "protocol": "TCP",
            "packet_count": 5,
            "duration_ms": 1500.0,
            "attack_score": 0.85,
            "prediction_class": 1,
            "prediction_label": "ATTACK",
            "is_alert": True,
            "ground_truth": "TEST",
            "features": test_features,
        })

    url = f"{explain_test_server}/api/csv/explain"
    payload = json.dumps({
        "flow_id": 88888,
        "benchmark": "cicids2017",
    }).encode("utf-8")

    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status == 200
        data = json.loads(resp.read().decode("utf-8"))
        assert len(data["features"]) == 10


def test_api_csv_explain_rejects_missing_features(explain_test_server: str):
    url = f"{explain_test_server}/api/csv/explain"

    # 1. Empty body
    req = urllib.request.Request(url, data=json.dumps({}).encode("utf-8"), headers={"Content-Type": "application/json"})
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req, timeout=5)
    assert exc_info.value.code == 400

    # 2. Incomplete features
    req2 = urllib.request.Request(
        url,
        data=json.dumps({"features": {"flow_duration_ms": 10.0}}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info2:
        urllib.request.urlopen(req2, timeout=5)
    assert exc_info2.value.code == 400


# ---------------------------------------------------------------------------
# 4. Frontend integrity tests: no fabricated SHAP or GT branching
# ---------------------------------------------------------------------------

def test_frontend_has_no_fabricated_shap_values():
    demo_js = (REPO_ROOT / "dashboard" / "demo.js").read_text(encoding="utf-8")
    demo_html = (REPO_ROOT / "dashboard" / "demo.html").read_text(encoding="utf-8")

    # Fabricated numbers that were previously hardcoded in demo.js and demo.html
    fabricated_numbers = ["+0.089", "+0.077", "+0.047", "+0.091", "+0.065", "+0.038", "+0.082", "+0.071", "+0.041", "-0.061", "-0.054", "-0.034"]
    for num in fabricated_numbers:
        assert num not in demo_js, f"Fabricated SHAP value {num} found in demo.js"
        assert num not in demo_html, f"Fabricated SHAP value {num} found in demo.html"

    # Verify no ground_truth branching in demo.js
    assert "gt.includes" not in demo_js
    assert "ground_truth" not in demo_js

    # Verify honest fallback notice
    assert "TreeSHAP explanation unavailable for this flow." in demo_js

    # Verify call to /api/csv/explain in demo.js
    assert "/api/csv/explain" in demo_js
