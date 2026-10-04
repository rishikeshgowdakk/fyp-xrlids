"""Unit tests for Phase 3E 1000-packet burst generation, latency mechanics, and safety invariants."""

import json
from pathlib import Path
import numpy as np
import pytest

from xrlids.live.burst import BurstConfig, audit_burst, generate_1000_packet_burst
from xrlids.live.capture import CaptureConfig, PacketCaptureService
from xrlids.live.flow_builder import LiveFlowBuilder
from xrlids.live.runner import LatencyTracker, LiveMode, LivePipelineRunner
from xrlids.response.baselines import SingleThresholdPolicy
from xrlids.response.safety import DeterministicSafetyGate


def test_1000_packet_burst_generation_exact_count_and_reproducibility():
    """Verify burst generator yields exactly 1000 packets with deterministic reproducibility."""
    cfg1 = BurstConfig(total_packets=1000, seed=42)
    pkts1 = generate_1000_packet_burst(cfg1)

    assert len(pkts1) == 1000

    # Test deterministic reproducibility with identical seed
    cfg2 = BurstConfig(total_packets=1000, seed=42)
    pkts2 = generate_1000_packet_burst(cfg2)

    assert len(pkts2) == 1000
    for p1, p2 in zip(pkts1, pkts2):
        assert p1.src_ip == p2.src_ip
        assert p1.dst_ip == p2.dst_ip
        assert p1.src_port == p2.src_port
        assert p1.dst_port == p2.dst_port
        assert p1.packet_length == p2.packet_length
        assert p1.timestamp == p2.timestamp

    # Test different seed produces different sequence
    cfg3 = BurstConfig(total_packets=1000, seed=12345)
    pkts3 = generate_1000_packet_burst(cfg3)
    assert any(p1.src_ip != p3.src_ip or p1.src_port != p3.src_port for p1, p3 in zip(pkts1, pkts3))


def test_burst_composition_and_accounting():
    """Verify exact 800 benign + 200 attack packet composition and monotonic timestamps."""
    pkts = generate_1000_packet_burst()
    audit = audit_burst(pkts)

    assert audit.total_packets == 1000
    assert audit.benign_packets == 800
    assert audit.attack_packets == 200
    assert audit.is_valid_1000_burst is True
    assert audit.min_packet_length >= 54
    assert audit.max_packet_length <= 1500
    assert audit.total_duration_s > 0.0

    # Verify timestamps are strictly non-decreasing
    for i in range(1, len(pkts)):
        assert pkts[i].timestamp >= pkts[i - 1].timestamp


def test_latency_tracker_percentile_calculation_mechanics():
    """Verify LatencyTracker computes P50, P95, P99, min, max, mean accurately."""
    tracker = LatencyTracker()

    # Empty tracker returns zeros without error
    empty_dist = tracker._calc_dist([])
    assert empty_dist["count"] == 0
    assert empty_dist["p50_us"] == 0.0

    # 100 synthetic samples in seconds (1.0 to 100.0 microseconds)
    samples_s = [i * 1e-6 for i in range(1, 101)]
    dist = tracker._calc_dist(samples_s)

    assert dist["count"] == 100
    assert dist["min_us"] == 1.0
    assert dist["max_us"] == 100.0
    assert dist["mean_us"] == 50.5
    assert dist["p50_us"] == 50.5
    assert dist["p95_us"] == 95.05
    assert dist["p99_us"] == 99.01


def test_dry_run_zero_mutation_and_failure_accounting():
    """Verify live pipeline operates under DRY_RUN with zero network mutation and full audit logging."""
    pkts = generate_1000_packet_burst()[:50]  # Subset of 50 packets for fast unit test
    capture = PacketCaptureService(synthetic_stream=pkts)
    policy = SingleThresholdPolicy(threshold=0.50)
    safety_gate = DeterministicSafetyGate()

    runner = LivePipelineRunner(
        capture_service=capture,
        policy=policy,
        safety_gate=safety_gate,
        mode=LiveMode.DRY_RUN,
    )

    report = runner.run()

    assert report["zero_network_mutation_guaranteed"] is True
    assert report["mode"] == "DRY_RUN"
    assert report["auditor_summary"]["inference_failures"] == 0
    assert report["capture_stats"]["packets_captured"] == 50
    assert len(runner.auditor.audit_cards) > 0

    # Verify audit cards have all required fields
    card = runner.auditor.audit_cards[0]
    assert card.proposed_action in ("ALLOW", "ALERT", "RATE_LIMIT", "ISOLATE")
    assert card.enforced_action in ("ALLOW", "ALERT", "RATE_LIMIT", "ISOLATE")
    assert isinstance(card.r10_features, dict)
    assert len(card.r10_features) == 10


def test_dry_run_enforcement_mode_inviolability():
    """Verify attempting to run LivePipelineRunner in CONTROLLED_ENFORCEMENT raises RuntimeError."""
    capture = PacketCaptureService(synthetic_stream=[])
    with pytest.raises(RuntimeError, match="Controlled enforcement mode is locked"):
        LivePipelineRunner(capture_service=capture, mode=LiveMode.CONTROLLED_ENFORCEMENT)


def test_committed_burst_experiment_artifacts_exist():
    """Verify all machine-readable artifacts and sidecars exist for EXP-P3-BURST-1000-001."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    exp_dir = repo_root / "results" / "phase3" / "EXP-P3-BURST-1000-001"

    required_files = [
        "experiment_config.json",
        "environment.json",
        "latency_metrics.json",
        "throughput_metrics.json",
        "action_distribution.json",
        "safety_metrics.json",
        "run_summary.json",
        "README.md",
    ]

    for fname in required_files:
        fpath = exp_dir / fname
        assert fpath.exists(), f"Missing required artifact: {fpath}"
        assert fpath.stat().st_size > 0, f"Empty artifact: {fpath}"

    # Verify run_summary content
    summary_path = exp_dir / "run_summary.json"
    data = json.loads(summary_path.read_text(encoding="utf-8"))
    summary = data["run_summary"]

    assert summary["experiment_id"] == "EXP-P3-BURST-1000-001"
    assert summary["all_packets_consumed"] is True
    assert summary["packet_accounting"]["processed_packets"] == 1000
    assert summary["safety_metrics"]["zero_network_mutation_guaranteed"] is True
    assert summary["safety_metrics"]["firewall_rules_mutated"] == 0
