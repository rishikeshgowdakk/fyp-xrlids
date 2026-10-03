#!/usr/bin/env python3
"""Run reproducible PCAP replay demonstration and empirical validation (Task 5).

Demonstrates the live inference foundation:
1. Replays network packets from a PCAP file.
2. Aggregates packets into bidirectional flows under the D-006 hybrid policy.
3. Computes the frozen 10 R10 features with verified parity.
4. Executes model inference using trained CIC-IDS2017 Random Forest.
5. Evaluates against known ground truth.
6. Outputs formatted live event logs and produces results/demo/ artifacts.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Ensure repo root is on sys.path
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from xrlids.demo.extractor import flows_to_dataframe, verify_feature_parity
from xrlids.demo.flow import Flow
from xrlids.demo.pcap import build_raw_packet, write_pcap
from xrlids.demo.replay import FlowPredictionEvent, ReplayEngine, save_demo_artifacts


def generate_synthetic_demo_pcap(filepath: str | Path) -> None:
    """Generate a reproducible multi-flow PCAP containing benign and attack traffic."""
    pcap_path = Path(filepath)
    pcap_path.parent.mkdir(parents=True, exist_ok=True)

    packets: list[tuple[float, bytes]] = []
    base_ts = 1700000000.0

    # --- 1. Benign Flow 1: Web browsing (TCP HTTP session) ---
    t = base_ts
    p = build_raw_packet("192.168.1.50", "142.250.190.46", 45000, 80, 6, {"syn": True}, payload_len=0)
    packets.append((t, p))
    t += 0.02
    p = build_raw_packet("142.250.190.46", "192.168.1.50", 80, 45000, 6, {"syn": True, "ack": True}, payload_len=0)
    packets.append((t, p))
    t += 0.01
    p = build_raw_packet("192.168.1.50", "142.250.190.46", 45000, 80, 6, {"ack": True}, payload_len=0)
    packets.append((t, p))
    t += 0.05
    p = build_raw_packet("192.168.1.50", "142.250.190.46", 45000, 80, 6, {"ack": True}, payload_len=450)
    packets.append((t, p))
    for _ in range(3):
        t += 0.03
        p = build_raw_packet("142.250.190.46", "192.168.1.50", 80, 45000, 6, {"ack": True}, payload_len=1200)
        packets.append((t, p))
    t += 0.05
    p = build_raw_packet("142.250.190.46", "192.168.1.50", 80, 45000, 6, {"fin": True, "ack": True}, payload_len=0)
    packets.append((t, p))

    # --- 2. Benign Flow 2: DNS Query & Response (UDP) ---
    t = base_ts + 1.0
    p = build_raw_packet("192.168.1.50", "8.8.8.8", 51234, 53, 17, payload_len=68)
    packets.append((t, p))
    t += 0.025
    p = build_raw_packet("8.8.8.8", "192.168.1.50", 53, 51234, 17, payload_len=142)
    packets.append((t, p))

    # --- 3. Benign Flow 3: Secure API Call (TLS session) ---
    t = base_ts + 2.0
    p = build_raw_packet("192.168.1.50", "104.16.132.229", 49152, 443, 6, {"syn": True}, payload_len=0)
    packets.append((t, p))
    t += 0.015
    p = build_raw_packet("104.16.132.229", "192.168.1.50", 443, 49152, 6, {"syn": True, "ack": True}, payload_len=0)
    packets.append((t, p))
    t += 0.01
    p = build_raw_packet("192.168.1.50", "104.16.132.229", 49152, 443, 6, {"ack": True}, payload_len=0)
    packets.append((t, p))
    t += 0.02
    p = build_raw_packet("192.168.1.50", "104.16.132.229", 49152, 443, 6, {"ack": True}, payload_len=300)
    packets.append((t, p))
    t += 0.02
    p = build_raw_packet("104.16.132.229", "192.168.1.50", 443, 49152, 6, {"ack": True}, payload_len=800)
    packets.append((t, p))
    t += 0.05
    p = build_raw_packet("192.168.1.50", "104.16.132.229", 49152, 443, 6, {"fin": True, "ack": True}, payload_len=0)
    packets.append((t, p))

    # --- 4. Attack Flow 1: DoS Hulk Burst (High-rate, large packet variation) ---
    t = base_ts + 3.0
    hulk_lengths = [54, 1460, 5840, 1460, 5840, 1460, 1460]
    for idx, l in enumerate(hulk_lengths):
        p = build_raw_packet("10.0.0.99", "192.168.1.10", 45123, 80, 6, payload_len=l)
        packets.append((t, p))
        t += 0.0003
    p = build_raw_packet("192.168.1.10", "10.0.0.99", 80, 45123, 6, {"rst": True}, payload_len=0)
    packets.append((t, p))

    # --- 5. Attack Flow 2: DDoS Inundation Flow ---
    t = base_ts + 4.0
    ddos_lengths = [26, 1460, 5840, 1460, 5840, 1460, 1460, 1460]
    for l in ddos_lengths:
        p = build_raw_packet("10.0.0.99", "192.168.1.10", 45124, 80, 6, payload_len=l)
        packets.append((t, p))
        t += 0.129
    p = build_raw_packet("192.168.1.10", "10.0.0.99", 80, 45124, 6, {"rst": True}, payload_len=0)
    packets.append((t, p))

    # --- 6. Attack Flow 3: DoS GoldenEye Session ---
    t = base_ts + 6.0
    goldeneye_lengths = [64, 1460, 5840, 1460, 5840, 1460, 1460, 1460]
    for l in goldeneye_lengths:
        p = build_raw_packet("10.0.0.99", "192.168.1.10", 45125, 80, 6, payload_len=l)
        packets.append((t, p))
        t += 0.05
    p = build_raw_packet("192.168.1.10", "10.0.0.99", 80, 45125, 6, {"rst": True}, payload_len=0)
    packets.append((t, p))

    write_pcap(pcap_path, packets)
    print(f"Generated synthetic demonstration PCAP with {len(packets)} packets at {pcap_path}")


def demo_ground_truth_resolver(flow: Flow) -> int | None:
    """Resolve ground truth class: 1 for attack host (10.0.0.99), 0 for benign hosts."""
    if flow.source_first_ip == "10.0.0.99" or flow.dest_first_ip == "10.0.0.99":
        return 1
    return 0


def format_flow_event_console(ev: FlowPredictionEvent) -> None:
    """Print nicely formatted streaming flow event line showing dual-threshold predictions."""
    v_res_col = "\033[92m" if ev.verdict_research == "CORRECT" else ("\033[91m" if ev.verdict_research == "INCORRECT" else "\033[93m")
    v_ops_col = "\033[92m" if ev.verdict_operational == "CORRECT" else ("\033[91m" if ev.verdict_operational == "INCORRECT" else "\033[93m")
    reset = "\033[0m"

    p_res_col = "\033[91m" if ev.pred_research_label == "ATTACK" else "\033[92m"
    p_ops_col = "\033[91m" if ev.pred_operational_label == "ATTACK" else "\033[92m"

    print(
        f"Flow #{ev.flow_id:<2} | {ev.protocol_name:<4} | "
        f"{ev.src_endpoint:<21} -> {ev.dst_endpoint:<21} | "
        f"Pkts: {ev.packet_count:<2} | Dur: {ev.duration_ms:>6.1f}ms | "
        f"Score: {ev.attack_score:.4f} | Truth: {ev.ground_truth_label:<6} | "
        f"Res (0.50): {p_res_col}{ev.pred_research_label:<6}{reset} ({v_res_col}{ev.verdict_research}{reset}) | "
        f"Ops (0.40): {p_ops_col}{ev.pred_operational_label:<6}{reset} ({v_ops_col}{ev.verdict_operational}{reset})"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="XRL-IDARS PCAP Replay Demonstration (Task 5)")
    parser.add_argument("--pcap", type=str, default="data/demo/sample_traffic.pcap", help="Input PCAP file path")
    parser.add_argument("--model-dir", type=str, default="results/experiments/EXP-P1-CIC2017-R10-001", help="Model directory")
    parser.add_argument("--output-dir", type=str, default="results/demo", help="Output artifact directory")
    parser.add_argument("--research-threshold", type=float, default=0.50, help="Research baseline decision threshold (frozen under D-003)")
    parser.add_argument("--operational-threshold", type=float, default=0.40, help="Proposed Phase 2 operational candidate threshold (not selected; D-003 remains open)")
    parser.add_argument("--generate-sample", action="store_true", help="Force regenerate synthetic sample PCAP")

    args = parser.parse_args()

    pcap_path = Path(args.pcap)
    if args.generate_sample or not pcap_path.exists():
        generate_synthetic_demo_pcap(pcap_path)

    print("=" * 80)
    print("XRL-IDARS — Reproducible Live Inference & Replay Demonstration")
    print("=" * 80)
    print(f"Target PCAP:            {pcap_path}")
    print(f"Model Directory:        {args.model_dir}")
    print(f"Research Threshold:     {args.research_threshold} (Frozen Baseline for Academic Comparison)")
    print(f"Operational Candidate:  {args.operational_threshold} (Proposed Phase 2 Operational Parameter)")
    print(f"Output Directory:       {args.output_dir}")
    print("-" * 80)
    print("Streaming flow classification in progress...")
    print("-" * 80)

    try:
        engine = ReplayEngine(
            model_path=args.model_dir if Path(args.model_dir).exists() else None,
            research_threshold=args.research_threshold,
            operational_candidate_threshold=args.operational_threshold,
        )
    except Exception as exc:
        print(f"Warning: Could not load model from {args.model_dir} ({exc}). Using heuristic fallback.")
        engine = ReplayEngine(
            model=None,
            research_threshold=args.research_threshold,
            operational_candidate_threshold=args.operational_threshold,
        )

    summary = engine.replay_pcap(
        pcap_file=pcap_path,
        ground_truth_resolver=demo_ground_truth_resolver,
        on_flow_callback=format_flow_event_console,
    )

    json_path, md_path = save_demo_artifacts(summary, output_dir=args.output_dir)

    cm_r = summary.confusion_matrix_research
    m_r = summary.metrics_research
    cm_o = summary.confusion_matrix_operational
    m_o = summary.metrics_operational

    print("-" * 80)
    print("DEMONSTRATION EXECUTION COMPLETE")
    print("-" * 80)
    print(f"Packets Processed: {summary.total_packets}")
    print(f"Completed Flows:   {summary.total_flows}")
    print(f"Evaluated Flows:   {summary.evaluated_flows}")
    print("\n--- Research Baseline Threshold (tau = 0.50) ---")
    print(f"Confusion Matrix:  TP={cm_r['tp']}, FP={cm_r['fp']}, TN={cm_r['tn']}, FN={cm_r['fn']}")
    print(f"Accuracy:          {m_r['accuracy'] * 100:.2f}% | Precision: {m_r['precision'] * 100:.2f}% | Recall: {m_r['recall'] * 100:.2f}% | F1: {m_r['f1']:.4f}")
    print(f"False Alarm (FPR): {m_r['fpr'] * 100:.2f}% | Miss Rate (FNR): {m_r['fnr'] * 100:.2f}%")
    print("\n--- Proposed Phase 2 Operational Candidate (tau_ops = 0.40; Sample Demo PCAP Only) ---")
    print(f"Confusion Matrix:  TP={cm_o['tp']}, FP={cm_o['fp']}, TN={cm_o['tn']}, FN={cm_o['fn']}")
    print(f"Accuracy:          {m_o['accuracy'] * 100:.2f}% | Precision: {m_o['precision'] * 100:.2f}% | Recall: {m_o['recall'] * 100:.2f}% | F1: {m_o['f1']:.4f}")
    print(f"False Alarm (FPR): {m_o['fpr'] * 100:.2f}% | Miss Rate (FNR): {m_o['fnr'] * 100:.2f}%")
    print("-" * 80)
    print(f"Artifacts Saved:   {json_path}")
    print(f"                   {md_path}")
    print("=" * 80)

    return 0


if __name__ == "__main__":
    sys.exit(main())
