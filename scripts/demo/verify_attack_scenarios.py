#!/usr/bin/env python3
"""Verify the Attack Simulator calibration against the frozen detector.

Replays every scenario from ``xrlids.demo.attack_sim`` through the exact live
pipeline components (FlowBuilder with the D-006 policy -> frozen R10 feature
extraction -> frozen CIC-IDS2017 Random Forest from
``results/experiments/EXP-P1-CIC2017-R10-001``) and checks that:

1. the number of completed flows matches the scenario's expectation,
2. single-flow scenarios complete with the scripted packet count,
3. the recorded ``expected_score`` matches the frozen model's output (tolerance),
4. the ``expected_band`` is consistent with the score (HIGH >= 0.85,
   ALERT >= 0.50, NONE < 0.50).

Run:  .venv/bin/python scripts/demo/verify_attack_scenarios.py
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from xrlids.demo.attack_sim import SCENARIOS, build_scenario_packets  # noqa: E402
from xrlids.demo.flow import FlowBuilder  # noqa: E402
from xrlids.demo.replay import ReplayEngine  # noqa: E402

MODEL_DIR = REPO_ROOT / "results" / "experiments" / "EXP-P1-CIC2017-R10-001"
SCORE_TOLERANCE = 0.05


def verify_scenario(engine: ReplayEngine, spec) -> tuple[list[str], list[float], list[int]]:
    """Return (failures, flow scores, flow packet counts) for one scenario."""
    failures: list[str] = []
    packets = build_scenario_packets(spec)

    builder = FlowBuilder(idle_timeout_s=engine.idle_timeout_s)
    flows = []
    for pkt in packets:
        flows.extend(builder.process_packet(pkt))
    flows.extend(builder.flush_all())

    if len(flows) != spec.expected_flows:
        failures.append(f"expected {spec.expected_flows} flows, got {len(flows)}")

    scores = [engine._predict_flow(flow)[1] for flow in flows]
    packet_counts = [flow.packet_count for flow in flows]

    if spec.expected_flows == 1 and flows:
        if flows[0].packet_count != spec.packet_count:
            failures.append(f"expected {spec.packet_count} packets in the flow, got {flows[0].packet_count}")

    best = max(scores) if scores else 0.0
    if abs(best - spec.expected_score) > SCORE_TOLERANCE:
        failures.append(f"expected score {spec.expected_score:.4f}, frozen model produced {best:.4f}")

    if spec.expected_band == "HIGH" and best < 0.85:
        failures.append(f"band HIGH requires score >= 0.85, got {best:.4f}")
    elif spec.expected_band == "ALERT" and not (0.50 <= best < 0.85):
        failures.append(f"band ALERT requires 0.50 <= score < 0.85, got {best:.4f}")
    elif spec.expected_band == "NONE" and best >= 0.50:
        failures.append(f"band NONE requires score < 0.50, got {best:.4f}")

    return failures, scores, packet_counts


def main() -> int:
    if not MODEL_DIR.exists():
        print(f"Frozen model directory not found: {MODEL_DIR}")
        print("This verification requires the trained CIC-IDS2017 R10 artefacts.")
        return 2

    engine = ReplayEngine(model_path=MODEL_DIR)
    print(f"Frozen detector: {MODEL_DIR.relative_to(REPO_ROOT)}")
    print()
    print(f"{'scenario':<22} {'flows':>5} {'pkts':>6} {'max score':>10} {'expected':>9} {'band':>6}  status")
    print("-" * 78)

    all_failures: list[str] = []
    for spec in SCENARIOS.values():
        failures, scores, packet_counts = verify_scenario(engine, spec)
        best = max(scores) if scores else 0.0
        pkts = packet_counts[0] if len(set(packet_counts)) == 1 and packet_counts else -1
        status = "OK" if not failures else "FAIL"
        print(
            f"{spec.id:<22} {len(scores):>5} {pkts:>6} {best:>10.4f} {spec.expected_score:>9.4f} "
            f"{spec.expected_band:>6}  {status}"
        )
        all_failures.extend(f"{spec.id}: {failure}" for failure in failures)

    print()
    if all_failures:
        print("FAILURES:")
        for failure in all_failures:
            print(f"  - {failure}")
        return 1

    print(
        f"All {len(SCENARIOS)} scenarios verified against the frozen detector "
        f"(tolerance {SCORE_TOLERANCE})."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
