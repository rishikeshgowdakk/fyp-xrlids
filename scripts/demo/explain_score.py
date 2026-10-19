#!/usr/bin/env python3
"""Explain and verify a dashboard threat score end-to-end.

This tool is the anti-"it's fake" check. It takes a calibrated simulator
scenario, runs its packets through the same ``FlowBuilder`` used by the live
dashboard, computes the frozen R10 features, loads the frozen Random Forest,
and prints the model's own ``predict_proba`` output. It also scores a normal
TCP request as a control, and sweeps the inter-packet gap to show that the
score changes with the flow's time shape (i.e. it is not a stored constant).

Usage (from the repository root):

    .venv/bin/python scripts/demo/explain_score.py
    .venv/bin/python scripts/demo/explain_score.py --scenario slowloris_session
    .venv/bin/python scripts/demo/explain_score.py --json

The script is read-only: it does not capture, transmit, or mutate network
traffic, and it does not write any files.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from xrlids.demo.attack_sim import build_scenario_packets, get_scenario  # noqa: E402
from xrlids.demo.flow import Flow, FlowBuilder  # noqa: E402
from xrlids.demo.pcap import PacketInfo  # noqa: E402
from xrlids.demo.replay import ReplayEngine  # noqa: E402

DEFAULT_MODEL_DIR = REPO_ROOT / "results" / "experiments" / "EXP-P1-CIC2017-R10-001"
BASE_TS = 1_700_000_000.0
VICTIM_IP = "192.168.1.10"
BENIGN_IP = "192.168.1.50"


def _positive_proba(proba: Any) -> float:
    """Normalise predict_proba output (1-D positive class or 2-D two-class)."""
    if getattr(proba, "ndim", 0) == 2:
        return float(proba[0, 1])
    return float(proba[0])


def _score_flow(engine: ReplayEngine, flow: Flow) -> tuple[dict[str, float], float]:
    raw = flow.to_features()
    frame = pd.DataFrame([raw])
    preprocessed = engine.preprocessor.transform(frame)
    return raw, _positive_proba(engine.model.predict_proba(preprocessed))


def _flows_from_packets(packets: list[PacketInfo]) -> list[Flow]:
    builder = FlowBuilder(idle_timeout_s=120.0)
    completed: list[Flow] = []
    for packet in packets:
        completed.extend(builder.process_packet(packet))
    completed.extend(builder.flush_all())
    return completed


def _packet(
    offset_s: float,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    length: int,
    **flags: bool,
) -> PacketInfo:
    return PacketInfo(
        timestamp=BASE_TS + offset_s,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=6,
        packet_length=length,
        is_tcp=True,
        **flags,
    )


def _benign_http_flow() -> list[PacketInfo]:
    """A normal six-packet TCP request/response, closed by the client with RST."""
    return [
        _packet(0.00, BENIGN_IP, 52000, VICTIM_IP, 80, 74, syn=True),
        _packet(0.03, VICTIM_IP, 80, BENIGN_IP, 52000, 74, syn=True, ack=True),
        _packet(0.06, BENIGN_IP, 52000, VICTIM_IP, 80, 66, ack=True),
        _packet(0.08, BENIGN_IP, 52000, VICTIM_IP, 80, 500, ack=True),
        _packet(0.10, VICTIM_IP, 80, BENIGN_IP, 52000, 66, ack=True),
        _packet(0.12, BENIGN_IP, 52000, VICTIM_IP, 80, 66, ack=True, rst=True),
    ]


def _slow_pair(gap_s: float, attacker_ip: str = "203.0.113.66") -> list[PacketInfo]:
    """The two-packet slow-HTTP shape, parameterised only by its inter-packet gap."""
    return [
        _packet(0.0, attacker_ip, 41001, VICTIM_IP, 80, 356, syn=True),
        _packet(gap_s, attacker_ip, 41001, VICTIM_IP, 80, 356, ack=True, rst=True),
    ]


def _flow_record(
    engine: ReplayEngine, flow: Flow, expected_score: float | None = None
) -> dict[str, Any]:
    features, score = _score_flow(engine, flow)
    return {
        "endpoint": (
            f"{flow.source_first_ip}:{flow.source_first_port} -> "
            f"{flow.dest_first_ip}:{flow.dest_first_port}"
        ),
        "packets": flow.packet_count,
        "duration_ms": round(flow.duration_ms, 3),
        "features": {name: round(value, 6) for name, value in features.items()},
        "score": round(score, 6),
        "label": "ATTACK" if score >= 0.50 else "BENIGN",
        "alert_band": (
            "HIGH" if score >= 0.85 else "MEDIUM" if score >= 0.65 else "LOW" if score >= 0.50 else "NONE"
        ),
        "expected_score": expected_score,
        "matches_expected": (
            expected_score is not None and abs(score - expected_score) <= 0.05
        ),
    }


def explain(model_dir: Path, scenario_id: str) -> dict[str, Any]:
    if not model_dir.exists():
        raise FileNotFoundError(f"Frozen model directory not found: {model_dir}")

    engine = ReplayEngine(model_path=model_dir)
    model_file = model_dir / "random_forest.joblib"
    spec = get_scenario(scenario_id)
    if spec is None:
        available = ", ".join(sorted(s.id for s in _all_scenarios()))
        raise ValueError(f"Unknown scenario {scenario_id!r}. Available: {available}")

    scenario_flows = _flows_from_packets(build_scenario_packets(spec))
    benign_flows = _flows_from_packets(_benign_http_flow())

    gap_sweep = []
    for gap in (0.05, 0.50, 1.00, 2.00, 3.25):
        flows = _flows_from_packets(_slow_pair(gap))
        _, score = _score_flow(engine, flows[0])
        gap_sweep.append(
            {
                "gap_s": gap,
                "duration_ms": round(flows[0].duration_ms, 3),
                "score": round(score, 6),
            }
        )

    return {
        "model": {
            "path": str(model_file),
            "sha256": hashlib.sha256(model_file.read_bytes()).hexdigest(),
            "class": type(engine.model).__name__,
            "preprocessor": type(engine.preprocessor).__name__,
            "feature_contract": list(engine.model.feature_names)
            if hasattr(engine.model, "feature_names")
            else None,
        },
        "scenario": {
            "id": spec.id,
            "name": spec.name,
            "description": spec.description,
            "attacker_ip": spec.attacker_ip,
            "victim_ip": VICTIM_IP,
            "expected_score": spec.expected_score,
            "expected_band": spec.expected_band,
            "flows": [_flow_record(engine, flow, spec.expected_score) for flow in scenario_flows],
        },
        "benign_control": {
            "description": "Normal TCP HTTP request/response (six packets, closed by client RST)",
            "flows": [_flow_record(engine, flow) for flow in benign_flows],
        },
        "timing_sweep": gap_sweep,
        "note": (
            "The simulator supplies packets only. FlowBuilder computes the R10 features and the "
            "frozen Random Forest computes the score; no score is stored in the scenario definition."
        ),
    }


def _all_scenarios():
    from xrlids.demo.attack_sim import SCENARIOS

    return SCENARIOS.values()


def _print_human(result: dict[str, Any]) -> None:
    model = result["model"]
    print("Frozen detector")
    print(f"  path:   {model['path']}")
    print(f"  sha256: {model['sha256']}")
    print(f"  class:  {model['class']} + {model['preprocessor']}")
    if model.get("feature_contract"):
        print(f"  R10:    {', '.join(model['feature_contract'])}")

    print("\nBenign control")
    for flow in result["benign_control"]["flows"]:
        print(f"  {flow['endpoint']} | {flow['packets']} pkts | {flow['duration_ms']:.1f} ms")
        print(f"  score = {flow['score']:.6f} -> {flow['label']} ({flow['alert_band']})")

    scenario = result["scenario"]
    print(f"\nSimulator scenario: {scenario['id']} — {scenario['name']}")
    print(f"  expected: {scenario['expected_band']} ≈ {scenario['expected_score']:.4f}")
    for flow in scenario["flows"]:
        print(f"  {flow['endpoint']} | {flow['packets']} pkts | {flow['duration_ms']:.1f} ms")
        print("  features the model received:")
        for name, value in flow["features"].items():
            print(f"    {name:>22} = {value:.6f}")
        print(f"  score = {flow['score']:.6f} -> {flow['label']} ({flow['alert_band']})")
        print(f"  matches calibrated expectation (tolerance 0.05): {flow['matches_expected']}")

    print("\nSame two packets, only the inter-packet gap changes")
    for row in result["timing_sweep"]:
        print(f"  gap={row['gap_s']:>4.2f}s  duration_ms={row['duration_ms']:>8.1f}  "
              f"score={row['score']:.6f}")
    print("\nThe score changes with the flow's time shape — it is computed by the model, not stored.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scenario", default="slow_http_dos", help="Scenario id (default: slow_http_dos)")
    parser.add_argument("--model-dir", default=str(DEFAULT_MODEL_DIR), help="Frozen model directory")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON instead of text")
    args = parser.parse_args(argv)

    try:
        result = explain(Path(args.model_dir), args.scenario)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        _print_human(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
