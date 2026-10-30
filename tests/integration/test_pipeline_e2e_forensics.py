"""End-to-End Forensic Integration Test (Phase 14 & Priority 6).

Verifies the complete 11-stage autonomous intrusion detection and response pipeline:
1. PCAP Replay (ScapyCaptureService)
2. Canonical Bidirectional 5-Tuple Aggregation (CanonicalFlowBuilder)
3. Schema Validation & R10 Contract (FeatureSchemaValidator)
4. Primary ML Perception (ModelManager RF / XGBoost)
5. Multiclass Attack Family Attribution (MulticlassAttackClassifier)
6. RFC 793/1122 Deterministic Invariants (RuleEngine)
7. Hybrid Arbitration & Discrepancy Resolution (HybridDecisionEngine)
8. Multi-Flow Activity Tracking & Escalation (SourceActivityTracker)
9. Local Additive Feature Attributions (TreeSHAPExplainer)
10. Reinforcement Learning Mitigation Policy (DQNResponseService)
11. Deterministic Safety Gate, Transaction Verification & Event Dispatch (ResponseExecutor & EventManager)
"""

from __future__ import annotations

from pathlib import Path
import pytest

from xrlids.capture.scapy_service import ScapyCaptureService
from xrlids.events.manager import EventManager
from xrlids.flow.canonical_builder import CanonicalFlowBuilder
from xrlids.pipeline.active_pipeline import ActiveInferencePipeline
from xrlids.response.executor import ActionLifecycleState
from xrlids.response.safety import Action


def test_full_pcap_pipeline_e2e_forensic():
    """Verify full packet ingestion to autonomous response execution."""
    repo_root = Path(__file__).resolve().parents[2]
    pcap_path = repo_root / "data" / "demo" / "sample_traffic.pcap"
    assert pcap_path.is_file(), f"Sample PCAP missing at {pcap_path}"

    event_manager = EventManager(max_buffer_size=100)
    pipeline = ActiveInferencePipeline(event_manager=event_manager)

    capture_service = ScapyCaptureService()
    flow_builder = CanonicalFlowBuilder(idle_timeout_s=120.0)

    completed_flows = []
    pipeline_results = []

    # Stream packets from PCAP through canonical flow assembler
    for pkt in capture_service.replay_pcap(pcap_path, max_packets=200):
        flows = flow_builder.process_packet(pkt)
        for f in flows:
            completed_flows.append(f)
            res = pipeline.process_flow(f)
            pipeline_results.append(res)

    # Flush any remaining active flows at conclusion of capture
    flushed = flow_builder.flush_all()
    for f in flushed:
        completed_flows.append(f)
        res = pipeline.process_flow(f)
        pipeline_results.append(res)

    # 1. Flow Construction Verification
    assert len(completed_flows) > 0, "No flows assembled from PCAP"
    assert len(pipeline_results) == len(completed_flows)

    # 2. Pipeline Results and Event Verification
    events = event_manager.get_all_events()
    assert len(events) == len(pipeline_results)

    for res in pipeline_results:
        # Schema Contract R10
        assert len(res.features) == 10
        assert "flow_duration_ms" in res.features
        assert "packet_length_mean" in res.features

        # Perception & Inference
        assert 0.0 <= res.inference.attack_score <= 1.0
        assert res.inference.prediction_label in ("BENIGN", "ATTACK")

        # Multiclass Attribution
        assert res.inference.attack_family is not None
        assert 0.0 <= res.inference.attack_family_confidence <= 1.0

        # Deterministic Rules
        assert isinstance(res.rule_matches, list)

        # Source Tracking
        assert res.source_decision.source_ip == res.source_ip

        # Response & Safety
        assert res.enforced_action in (Action.ALLOW, Action.ALERT, Action.RATE_LIMIT, Action.ISOLATE)
        assert res.execution_report is not None
        assert res.execution_report.final_lifecycle_state in (
            ActionLifecycleState.VERIFIED,
            ActionLifecycleState.REJECTED,
            ActionLifecycleState.ROLLED_BACK,
        )
        assert res.execution_report.is_advisory  # Advisory invariant maintained

        # Telemetry
        assert res.total_pipeline_time_ms > 0.0
