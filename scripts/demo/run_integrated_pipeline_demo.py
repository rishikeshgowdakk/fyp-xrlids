"""Real End-to-End Integrated Demonstration for XRL-IDARS Operational Pipeline.

Verifies that captured or replayed traffic travels through the complete
operational pipeline:
  Scapy -> Canonical FlowEngine -> R10 Feature Extraction -> StandardScaler
        -> Random Forest -> Security Event -> TreeSHAP Explanation
        -> Dueling DQN -> Deterministic Safety Gate -> Advisory Response Actuator
        -> Streamlit Event Queue

Asserts that the resulting RF prediction, TreeSHAP explanation, DQN recommendation,
safety decision, and advisory response record are all associated with the SAME
security event and visible in the Streamlit audit store.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import time

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from xrlids.capture.scapy_service import ScapyCaptureConfig, ScapyCaptureService, scapy_packet_to_packet_info
from xrlids.demo.scapy_simulator import ScapyAttackSimulator
from xrlids.events.manager import EventManager
from xrlids.flow.canonical_builder import CanonicalFlow, CanonicalFlowBuilder
from xrlids.pipeline.active_pipeline import ActiveInferencePipeline, PipelineResult


def run_integrated_demonstration() -> bool:
    print("=" * 76)
    print("  XRL-IDARS — Complete Real End-to-End Operational Pipeline Demonstration")
    print("=" * 76)

    # 1. Initialize Event Manager and Active Pipeline
    print("\n[Stage 1] Initializing Operational Subsystems...")
    event_manager = EventManager()
    pipeline = ActiveInferencePipeline(
        event_manager=event_manager,
        explain_all=True,  # Force TreeSHAP calculation on all evaluated flows
    )
    print(f"  ✓ Model Loaded:       {pipeline.model_manager.model_name}")
    print(f"  ✓ Explainer Engine:   TreeSHAP (Lundberg & Lee)")
    print(f"  ✓ Response Engine:    Dueling DQN (4-Action Policy)")
    print(f"  ✓ Safety Guard:       Deterministic Safety Gate (Advisory Dry-Run)")
    print(f"  ✓ Streamlit Audit:    EventManager active (0 initial events)")

    # 2. Ingest authentic wire packets from PCAP replay
    pcap_path = REPO_ROOT / "data" / "demo" / "sample_traffic.pcap"
    print(f"\n[Stage 2] Replaying Authentic Wire Packets from: {pcap_path.name}")
    if not pcap_path.exists():
        print(f"  ✗ Error: PCAP file {pcap_path} not found.")
        return False

    cfg = ScapyCaptureConfig(pcap_path=pcap_path, queue_size=1000)
    capture_service = ScapyCaptureService(cfg)
    flow_builder = CanonicalFlowBuilder(idle_timeout_s=120.0)

    capture_service.start()
    pcap_packets = []
    t_start = time.time()
    while capture_service.is_running or not capture_service._queue.empty():
        pkt = capture_service.get_packet(timeout=0.1)
        if pkt is not None:
            pcap_packets.append(pkt)
        if time.time() - t_start > 5.0 or len(pcap_packets) >= 50:
            break
    capture_service.stop()
    print(f"  ✓ Replayed {len(pcap_packets)} authentic packets via ScapyCaptureService.")

    completed_flows: list[CanonicalFlow] = []
    for pkt in pcap_packets:
        completed_flows.extend(flow_builder.process_packet(pkt))
    completed_flows.extend(flow_builder.flush_all())
    print(f"  ✓ Canonical FlowEngine assembled {len(completed_flows)} completed flow(s).")

    # 3. Ingest calibrated Scapy wire packets (TCP SYN burst)
    print(f"\n[Stage 3] Generating Wire-Format Scapy Packets (Scenario C: TCP SYN Burst)...")
    sim = ScapyAttackSimulator()
    raw_packets = sim.build_packets_for_scenario("scenario_c_syn_burst")
    scapy_packets = [scapy_packet_to_packet_info(p) for p in raw_packets]
    print(f"  ✓ Synthesized {len(scapy_packets)} raw wire packets with asymmetric TCP flags.")
    
    syn_flow_builder = CanonicalFlowBuilder(idle_timeout_s=120.0)
    for pkt in scapy_packets:
        completed_flows.extend(syn_flow_builder.process_packet(pkt))
    completed_flows.extend(syn_flow_builder.flush_all())
    print(f"  ✓ Total completed flows ready for end-to-end evaluation: {len(completed_flows)}")

    # 4. Stream each flow through the complete operational pipeline
    print(f"\n[Stage 4] Executing Operational Pipeline across {len(completed_flows)} Flow(s)...")
    results: list[PipelineResult] = []

    for i, flow in enumerate(completed_flows, start=1):
        res = pipeline.process_flow(flow, explain=True)
        results.append(res)
        print(f"  - Flow #{i} [{res.flow_id}]: {res.source_ip}:{res.source_port} -> {res.dest_ip}:{res.dest_port} | Verdict: {res.hybrid.verdict} | Enforced: {res.enforced_action.name}")

    # 5. Rigorous Integration Assertions on Security Event Association
    print("\n[Stage 5] Verifying Unified Security Event Association & Streamlit Visibility...")
    all_events = event_manager.get_all_events()
    assert len(all_events) == len(completed_flows), f"Expected {len(completed_flows)} events, got {len(all_events)}"

    verified_count = 0
    for res in results:
        ev = res.security_event
        # Match against event stored in event_manager
        stored_ev = next((e for e in all_events if e.event_id == ev.event_id), None)
        assert stored_ev is not None, f"Event {ev.event_id} missing from Streamlit EventManager store"

        # Verification 1: Identity & Metadata
        assert ev.flow_id == res.flow_id
        assert ev.source_ip == res.source_ip
        assert ev.dest_ip == res.dest_ip

        # Verification 2: Random Forest Prediction
        assert "attack_score" in ev.detection
        assert 0.0 <= ev.detection["attack_score"] <= 1.0
        assert "Random Forest" in ev.detection["model_name"]

        # Verification 3: TreeSHAP Explanation Association
        assert ev.explanation is not None, f"Missing TreeSHAP explanation in event {ev.event_id}"
        assert "attributions" in ev.explanation
        assert len(ev.explanation["attributions"]) == 10, "Expected 10 R10 Shapley feature attributions"
        assert "base_value" in ev.explanation

        # Verification 4: Dueling DQN Action Recommendation
        assert "proposed_action" in ev.response
        assert ev.response["proposed_action"] in ("ALLOW", "ALERT", "RATE_LIMIT", "ISOLATE")
        assert "q_values" in ev.response
        assert len(ev.response["q_values"]) == 4

        # Verification 5: Deterministic Safety Gate Decision
        assert "enforced_action" in ev.response
        assert "safety_override" in ev.response
        assert ev.response["enforced_action"] in ("ALLOW", "ALERT", "RATE_LIMIT", "ISOLATE")

        # Verification 6: Advisory Dry-Run Execution Record
        assert "execution_report" in ev.response
        exec_rep = ev.response["execution_report"]
        assert exec_rep["is_advisory"] is True, "Expected dry-run advisory execution (0 kernel mutations)"
        assert "execution_id" in exec_rep
        assert "final_lifecycle_state" in exec_rep

        verified_count += 1

    print(f"  ✓ {verified_count} of {len(results)} events verified with 100% component association integrity:")
    print("    [1] Random Forest Detection Score")
    print("    [2] Lundberg TreeSHAP Local Attributions (10 Features)")
    print("    [3] Dueling DQN Q-Value Action Recommendation")
    print("    [4] Deterministic Safety Gate Decision & Overrides")
    print("    [5] Advisory Dry-Run Response Execution Record")
    print("    All 5 components are linked to the identical SecurityEvent ID and stored in EventManager.")

    # 6. Detailed Inspection of an Attack Event
    attack_event = next((r.security_event for r in results if r.hybrid.is_attack), results[0].security_event)
    print("\n" + "=" * 76)
    print(f"  Sample Integrated Security Event Payload (Event ID: {attack_event.event_id})")
    print("=" * 76)
    print(f"Flow ID:          {attack_event.flow_id}")
    print(f"Timestamp:        {attack_event.timestamp}")
    print(f"Endpoints:        {attack_event.source_ip}:{attack_event.source_port} -> {attack_event.dest_ip}:{attack_event.dest_port} (Proto: {attack_event.protocol})")
    print(f"RF Score:         {attack_event.detection['attack_score']:.4f} ({attack_event.detection['model_name']})")
    print(f"Rule Violations:  {[r['rule_id'] for r in attack_event.rule_matches]}")
    print(f"Hybrid Verdict:   {attack_event.hybrid_verdict} (Severity: {attack_event.severity})")
    print(f"TreeSHAP Base:    {attack_event.explanation['base_value']:.4f}")
    print("Top Attributions:")
    for attr in attack_event.explanation['attributions'][:3]:
        print(f"  • {attr['feature']:<20}: {attr['shap_attribution']:+.4f} ({attr['direction']})")
    print(f"DQN Proposed:     {attack_event.response['proposed_action']}")
    print(f"DQN Q-Values:     {attack_event.response['q_values']}")
    print(f"Safety Enforced:  {attack_event.response['enforced_action']} (Override: {attack_event.response['safety_override']})")
    print(f"Advisory Record:  Dry-Run Mode (0 kernel mutations, lifecycle: {attack_event.response['execution_report']['final_lifecycle_state']}, is_advisory: {attack_event.response['execution_report']['is_advisory']})")
    print("=" * 76)

    # 7. Verify Streamlit Statistics
    stats = event_manager.get_stats()
    print(f"\nStreamlit Telemetry KPIs:")
    print(f"  Total Events Evaluated:     {stats['total_events']}")
    print(f"  Threat Intrusions Flagged:  {stats['threat_events']}")
    print(f"  Rule Violations Triggered:  {stats['rule_matches_count']}")
    print(f"  Source Escalations:         {stats['escalated_events_count']}")

    print("\n>>> INTEGRATION VERIFICATION SUCCESSFUL: Pipeline is genuine, end-to-end, and integrated! <<<\n")
    return True


if __name__ == "__main__":
    success = run_integrated_demonstration()
    sys.exit(0 if success else 1)
