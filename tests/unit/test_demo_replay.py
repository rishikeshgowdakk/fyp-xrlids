"""Unit tests for ReplayEngine, report generation, and LiveLabMonitor."""

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from xrlids.demo.flow import Flow
from xrlids.demo.live_lab import AlertEvent, LiveLabMonitor
from xrlids.demo.pcap import build_raw_packet, write_pcap
from xrlids.demo.replay import (
    FlowPredictionEvent,
    NoDetectorLoadedError,
    ReplayEngine,
    ReplaySummary,
    save_demo_artifacts,
)
from xrlids.features.definitions import R10_FEATURES


def test_engine_without_detector_refuses_to_score():
    """An engine with no detector must raise, never emit a substitute score.

    A heuristic score written into replay artifacts is indistinguishable from
    real model output, so the failure has to be loud.
    """
    engine = ReplayEngine(model=None)
    with pytest.raises(NoDetectorLoadedError):
        engine.predict_features({f: 0.0 for f in R10_FEATURES})


class DummyMockModel:
    """Mock detector predicting attack when flow duration < 50ms or packet rate > 50."""

    def __init__(self):
        self.feature_names = [
            "flow_duration_ms",
            "flow_packets_per_s",
            "flow_bytes_per_s",
            "packet_length_mean",
            "packet_length_std",
            "syn_count",
            "ack_count",
            "rst_count",
            "fin_count",
            "syn_ack_ratio",
        ]

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        probs = []
        for _, row in X.iterrows():
            if row["flow_packets_per_s"] > 50.0 or row["flow_duration_ms"] < 50.0:
                probs.append(0.95)
            else:
                probs.append(0.05)
        return np.array(probs)


def test_replay_engine_end_to_end(tmp_path: Path):
    """Verify PCAP replay, flow accumulation, inference, and summary reporting."""
    pcap_file = tmp_path / "replay_test.pcap"

    # Create 2 flows:
    # Flow 1: 5 packets over 1.0s (rate = 5 pkts/s -> benign)
    # Flow 2: 10 packets over 0.05s (rate = 200 pkts/s -> attack)
    packets = []
    t = 100.0
    for _ in range(5):
        pkt = build_raw_packet("192.168.1.1", "10.0.0.1", 1001, 80, 6, payload_len=100)
        packets.append((t, pkt))
        t += 0.2
    # FIN to terminate Flow 1
    packets.append((t, build_raw_packet("10.0.0.1", "192.168.1.1", 80, 1001, 6, {"fin": True}, payload_len=0)))

    t = 110.0
    for _ in range(10):
        pkt = build_raw_packet("10.0.0.99", "192.168.1.1", 5555, 80, 6, payload_len=64)
        packets.append((t, pkt))
        t += 0.005
    # RST to terminate Flow 2
    packets.append((t, build_raw_packet("192.168.1.1", "10.0.0.99", 80, 5555, 6, {"rst": True}, payload_len=0)))

    write_pcap(pcap_file, packets)

    model = DummyMockModel()
    engine = ReplayEngine(model=model, threshold=0.50)

    def resolver(flow: Flow) -> int:
        return 1 if "10.0.0.99" in (flow.source_first_ip, flow.dest_first_ip) else 0

    events: list[FlowPredictionEvent] = []
    summary = engine.replay_pcap(
        pcap_file=pcap_file,
        ground_truth_resolver=resolver,
        on_flow_callback=lambda ev: events.append(ev),
    )

    assert summary.total_packets == len(packets)
    assert summary.total_flows == 2
    assert summary.evaluated_flows == 2
    assert summary.confusion_matrix["tp"] == 1
    assert summary.confusion_matrix["tn"] == 1
    assert summary.confusion_matrix["fp"] == 0
    assert summary.confusion_matrix["fn"] == 0
    assert summary.metrics["accuracy"] == 1.0
    assert summary.metrics["f1"] == 1.0

    # Test artifact serialization
    out_dir = tmp_path / "results_demo"
    json_path, md_path = save_demo_artifacts(summary, output_dir=out_dir)
    assert json_path.exists()
    assert md_path.exists()

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
        assert data["evaluated_flows"] == 2
        assert "accuracy" in data["metrics"]


def test_live_lab_monitor_observational_alerting(tmp_path: Path):
    """Verify that LiveLabMonitor detects attacks and emits structured alerts without network mutations."""
    pcap_file = tmp_path / "live_test.pcap"
    packets = []
    t = 200.0
    for _ in range(10):
        pkt = build_raw_packet("10.0.0.99", "192.168.1.1", 6000, 80, 6, payload_len=50)
        packets.append((t, pkt))
        t += 0.001
    packets.append((t, build_raw_packet("192.168.1.1", "10.0.0.99", 80, 6000, 6, {"rst": True})))
    write_pcap(pcap_file, packets)

    from xrlids.demo.pcap import PcapReader

    model = DummyMockModel()
    engine = ReplayEngine(model=model, threshold=0.50)

    alerts: list[AlertEvent] = []
    monitor = LiveLabMonitor(
        engine=engine,
        alert_threshold=0.50,
        on_alert_callback=lambda a: alerts.append(a),
    )

    reader = PcapReader(pcap_file)
    emitted = monitor.process_packet_stream(reader.read_packets())

    assert len(emitted) == 1
    assert emitted[0].alert_level == "HIGH"
    assert "10.0.0.99" in emitted[0].src_endpoint or "10.0.0.99" in emitted[0].dst_endpoint
    assert len(alerts) == 1

    # Check raw socket capability check executes cleanly
    cap = LiveLabMonitor.check_raw_socket_capability()
    assert isinstance(cap, bool)


def test_live_lab_monitor_emits_flow_observations(tmp_path: Path):
    """Verify every completed flow is observed via on_flow_callback; alerts remain the attack subset."""
    pcap_file = tmp_path / "observation_test.pcap"

    packets = []
    t = 300.0
    # Benign flow: 5 packets over 1.0 s (5 pkt/s, 1000 ms), closed with FIN
    for _ in range(5):
        packets.append((t, build_raw_packet("192.168.1.1", "10.0.0.1", 1001, 80, 6, payload_len=100)))
        t += 0.2
    packets.append((t + 0.1, build_raw_packet("10.0.0.1", "192.168.1.1", 80, 1001, 6, {"fin": True, "ack": True})))
    # Attack flow: 10 packets over 0.05 s (200 pkt/s), closed with RST
    t += 10.0
    for _ in range(10):
        packets.append((t, build_raw_packet("10.0.0.99", "192.168.1.1", 6000, 80, 6, payload_len=50)))
        t += 0.005
    packets.append((t + 0.1, build_raw_packet("192.168.1.1", "10.0.0.99", 80, 6000, 6, {"rst": True})))
    write_pcap(pcap_file, packets)

    from xrlids.demo.pcap import PcapReader

    engine = ReplayEngine(model=DummyMockModel(), threshold=0.50)
    observations = []
    alerts = []
    monitor = LiveLabMonitor(
        engine=engine,
        alert_threshold=0.50,
        on_alert_callback=lambda a: alerts.append(a),
        on_flow_callback=lambda o: observations.append(o),
    )
    monitor.process_packet_stream(PcapReader(pcap_file).read_packets())

    assert len(observations) == 2
    labels_by_src = {o.src_endpoint: o.prediction_label for o in observations}
    assert labels_by_src["10.0.0.99:6000"] == "ATTACK"
    assert labels_by_src["192.168.1.1:1001"] == "BENIGN"
    assert observations[0].is_alert is False
    assert observations[1].is_alert is True
    assert len(alerts) == 1
    assert len(monitor.observations) == 2
