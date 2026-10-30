#!/usr/bin/env python3
"""CLI runner for XRL-IDARS Scapy Isolated Lab Attack Simulator.

Demonstrates real Scapy packet generation, bidirectional flow reconstruction,
canonical feature extraction, Random Forest / Unified inference, deterministic
rules, TreeSHAP explainability, and DQN response policy under the safety gate.

Usage:
    python scripts/demo/run_scapy_simulation.py --scenario scenario_a_benign
    python scripts/demo/run_scapy_simulation.py --scenario scenario_b_port_scan
    python scripts/demo/run_scapy_simulation.py --scenario scenario_c_syn_burst
    python scripts/demo/run_scapy_simulation.py --scenario scenario_d_icmp_burst
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from xrlids.capture.scapy_service import scapy_packet_to_packet_info
from xrlids.demo.flow import FlowBuilder
from xrlids.demo.scapy_simulator import (
    ATTACKER_IP,
    SCENARIO_SPECS,
    VICTIM_IP,
    ScapyAttackSimulator,
    validate_target_safety,
)
from xrlids.evaluation.csv_evaluator import explain_flow_prediction
from xrlids.models.inference_service import DEFAULT_INFERENCE_SERVICE
from xrlids.response.dqn.network import DuelingQNetwork
from xrlids.response.safety import DeterministicSafetyGate
from xrlids.response.state import StateBuilder
from xrlids.response.types import Action, ActionSpaceMode
from xrlids.rules.engine import RuleEngine


def main() -> int:
    parser = argparse.ArgumentParser(
        description="XRL-IDARS Scapy Attack Simulator & Pipeline Verification CLI"
    )
    parser.add_argument(
        "--scenario",
        choices=list(SCENARIO_SPECS.keys()),
        default="scenario_c_syn_burst",
        help="Simulation scenario to execute (default: scenario_c_syn_burst)",
    )
    parser.add_argument(
        "--target-ip",
        default=VICTIM_IP,
        help=f"Target IP address within isolated lab subnet (default: {VICTIM_IP})",
    )
    parser.add_argument(
        "--packets",
        type=int,
        default=None,
        help="Override packet count for scenario",
    )
    parser.add_argument(
        "--speed",
        type=float,
        default=10.0,
        help="Pacing speed multiplier (1.0 = real-time, 10.0 = fast; default: 10.0)",
    )
    parser.add_argument(
        "--pcap-out",
        type=str,
        default=None,
        help="Optional path to write generated Scapy packets as PCAP",
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        default=True,
        help="Compute and display TreeSHAP local feature attributions",
    )
    args = parser.parse_args()

    # 1. Enforce strict safety boundary
    try:
        validate_target_safety(args.target_ip)
    except ValueError as exc:
        print(f"\n[ERROR] Safety invariant violated: {exc}")
        return 1

    spec = SCENARIO_SPECS[args.scenario]
    print("\n" + "=" * 70)
    print(f"  XRL-IDARS — Scapy Attack Simulator & Pipeline Evaluation")
    print("=" * 70)
    print(f"Scenario:     {spec.name}")
    print(f"Category:     {spec.category} (Family: {spec.attack_family})")
    print(f"Target:       {args.target_ip} (Ports: {spec.target_ports or 'All'})")
    print(f"Description:  {spec.description}")
    print("=" * 70)

    # 2. Build Scapy Packets
    simulator = ScapyAttackSimulator(attacker_ip=ATTACKER_IP, victim_ip=args.target_ip)
    t0_gen = time.perf_counter()
    scapy_packets = simulator.build_packets_for_scenario(
        scenario_id=args.scenario,
        packet_count=args.packets,
    )
    t_gen_ms = (time.perf_counter() - t0_gen) * 1000.0

    print(f"\n[1] Scapy Packet Generation:")
    print(f"    Generated {len(scapy_packets)} genuine Scapy packets in {t_gen_ms:.2f} ms.")

    if args.pcap_out:
        pcap_path = simulator.export_scenario_pcap(args.scenario, args.pcap_out)
        print(f"    Exported PCAP to: {pcap_path}")

    # 3. Stream through Bidirectional FlowBuilder
    flow_builder = FlowBuilder(idle_timeout_s=2.0)
    flows = []
    t0_cap = time.perf_counter()
    for pkt in scapy_packets:
        pinfo = scapy_packet_to_packet_info(pkt)
        if pinfo is not None:
            completed = flow_builder.process_packet(pinfo)
            flows.extend(completed)
    flows.extend(flow_builder.flush_all())
    t_cap_ms = (time.perf_counter() - t0_cap) * 1000.0

    print(f"\n[2] Flow Reconstruction:")
    print(f"    Reconstructed {len(flows)} bidirectional flow(s) in {t_cap_ms:.2f} ms.")

    # 4. Pipeline Execution: Rules, RF/LSTM Inference, TreeSHAP, DQN & Safety Gate
    rule_engine = RuleEngine()
    safety_gate = DeterministicSafetyGate(action_mode=ActionSpaceMode.FOUR_ACTION)
    state_builder = StateBuilder()

    # Load DQN
    import torch
    dqn_path = REPO_ROOT / "models" / "dqn" / "dqn_4action_best.pt"
    dqn = DuelingQNetwork(input_dim=6, action_dim=4)
    if dqn_path.exists():
        ckpt = torch.load(dqn_path, map_location="cpu", weights_only=False)
        st = ckpt.get("online_net_state_dict", ckpt.get("model_state_dict", ckpt))
        dqn.load_state_dict(st)
        dqn.eval()

    print("\n[3] Pipeline Inferences & Security Evaluation:")
    threat_count = 0

    for idx, fl in enumerate(flows, 1):
        features = fl.to_features()
        session_key = f"{fl.source_first_ip}->{fl.dest_first_ip}"

        # Inference
        t0_inf = time.perf_counter()
        inf_res = DEFAULT_INFERENCE_SERVICE.infer(
            features=features,
            session_key=session_key,
            benchmark="cicids2017",
        )
        t_inf_ms = (time.perf_counter() - t0_inf) * 1000.0

        # Deterministic rules
        rule_matches = rule_engine.evaluate_flow(fl)
        is_attack = (inf_res.prediction == 1) or (len(rule_matches) > 0)
        if is_attack:
            threat_count += 1

        # DQN & Safety Gate
        bytes_per_s = features.get("flow_bytes_per_s", 0.0)
        state_vec = state_builder.build_state(attack_score=inf_res.attack_score, flow_bytes_per_s=bytes_per_s)
        with torch.no_grad():
            q_vals = dqn(torch.from_numpy(state_vec).float().unsqueeze(0))
            proposed_act = Action(int(torch.argmax(q_vals, dim=-1).item()))

        enforced_act, overridden, reason = safety_gate.enforce_safety(
            step=idx,
            flow_id=f"flow_{idx}",
            host_id=fl.source_first_ip,
            proposed_action=proposed_act,
        )

        proto = "TCP" if fl.key.protocol == 6 else ("UDP" if fl.key.protocol == 17 else f"PROTO_{fl.key.protocol}")
        print(f"\n  Flow #{idx}: [{proto}] {fl.source_first_ip}:{fl.source_first_port} -> {fl.dest_first_ip}:{fl.dest_first_port}")
        print(f"    Packets: {fl.packet_count} | Duration: {fl.duration_ms:.1f} ms | Bytes: {fl.total_bytes}")
        print(f"    Result: {'[ATTACK]' if is_attack else '[BENIGN]'} | Score: {inf_res.attack_score:.4f} (RF: {inf_res.rf_score:.4f})")
        print(f"    Source: {inf_res.inference_source} (Infer Time: {t_inf_ms:.2f} ms)")
        if rule_matches:
            print(f"    Rule Triggers: {', '.join(r.rule_id for r in rule_matches)}")
        print(f"    DQN Recommendation: {proposed_act.name} -> Enforced: {enforced_act.name} (Overridden: {overridden})")

        # TreeSHAP Explanation for first flow or threat
        if args.explain and (idx == 1 or is_attack):
            try:
                shap_res = explain_flow_prediction(features, benchmark="cicids2017")
                print(f"    TreeSHAP Base Value: {shap_res.get('base_value', 0.5):.3f}")
                print(f"    TreeSHAP Top Features:")
                for tf in shap_res.get("features", [])[:3]:
                    print(f"      - {tf['feature']:<22}: attr = {tf['shap_attribution']:+.4f} (value: {tf['value']})")
            except Exception as e:
                print(f"    TreeSHAP: Explanation unavailable ({e})")

    print("\n" + "=" * 70)
    print(f"Summary: {len(scapy_packets)} pkts captured | {len(flows)} flows processed | {threat_count} threat(s) detected")
    print(f"Safety Mode: ADVISORY ONLY (Zero network mutations)")
    print("=" * 70 + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
