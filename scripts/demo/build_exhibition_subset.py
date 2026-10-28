#!/usr/bin/env python
"""Rebuild the 200-flow exhibition demos from the canonical held-out test splits.

The source benchmark CSV files contain flow features and labels, but CIC-IDS2017,
CSE-CIC-IDS2018 and UNSW-NB15 distributable feature tables do not contain packet-level
IP addresses. This builder therefore emits RFC 5737 documentation addresses for display
and records that provenance explicitly; it never claims those endpoints came from the
capture.

Usage:
    .venv/bin/python scripts/demo/build_exhibition_subset.py --dataset all
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import yaml  # noqa: E402

from xrlids.datasets.population import PopulationConfig, load_dataset_population  # noqa: E402
from xrlids.features.registry import load_feature_registry  # noqa: E402
from xrlids.labels.contract import load_label_contract  # noqa: E402
from xrlids.splitting.splitter import SplitConfig, build_splits  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = REPO_ROOT / "data" / "demo"

DATASETS: dict[str, dict[str, str]] = {
    "cicids2017": {
        "config": "configs/experiments/p1_cicids2017_r10.yaml",
        "prefix": "cicids2017",
        "source_file": "Wednesday-workingHours.pcap_ISCX.csv",
        "benchmark_name": "CIC-IDS2017",
    },
    "cse2018": {
        "config": "configs/experiments/p1_cse_cic_ids2018_r10_multifile.yaml",
        "prefix": "cse2018",
        "source_file": "Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv",
        "benchmark_name": "CSE-CIC-IDS2018",
    },
    "unswnb15": {
        "config": "configs/experiments/p1_unsw_nb15_r10_multifile.yaml",
        "prefix": "unswnb15",
        "source_file": "UNSW_NB15_testing-set.csv",
        "benchmark_name": "UNSW-NB15",
    },
}


def _display_endpoints(flow_id: int) -> tuple[str, str]:
    """Return deterministic documentation-only endpoints (RFC 5737 TEST-NET-1/2)."""
    src = f"192.0.2.{10 + (flow_id % 200)}:{40000 + flow_id}"
    dst = f"198.51.100.{10 + (flow_id % 200)}:443"
    return src, dst


def build_one(key: str, *, seed: int, benign_n: int, attack_n: int) -> dict:
    meta = DATASETS[key]
    cfg = yaml.safe_load((REPO_ROOT / meta["config"]).read_text(encoding="utf-8"))
    registry = load_feature_registry()
    contract = load_label_contract()

    requested = registry.rung_features(cfg["features"]["rung"])
    pop_cfg = PopulationConfig(
        dataset=cfg["dataset"]["key"],
        files=cfg["dataset"].get("files", "all_verified"),
        exclude_files=cfg["dataset"].get("exclude_files", []),
        file_order=cfg["dataset"].get("file_order", "manifest"),
        require_verified_checksums=bool(cfg["dataset"].get("require_verified_checksums", True)),
        require_schema_validated=bool(cfg["dataset"].get("require_schema_validated", True)),
        duplicate_policy=cfg["split"].get("duplicate_policy", "deduplicate_features"),
        duplicate_conflict_policy=cfg["split"].get("duplicate_conflict_policy", "reject_conflicts"),
        seed=seed,
    )
    population = load_dataset_population(
        pop_cfg, requested, contract=contract, registry=registry
    )
    feature_names = list(population.features.columns)
    split = build_splits(
        population.features,
        population.labels,
        feature_names,
        SplitConfig(
            train=float(cfg["split"].get("train", 0.6)),
            validation=float(cfg["split"].get("validation", 0.2)),
            test=float(cfg["split"].get("test", 0.2)),
            seed=seed,
            stratify=bool(cfg["split"].get("stratify", True)),
            duplicate_policy=cfg["split"].get("duplicate_policy", "deduplicate_features"),
        ),
        dataset=cfg["dataset"]["key"],
        provenance=population.provenance,
        run_leakage_audit=False,
    )

    test = split.splits["test"]
    labels = split.label_splits["test"]
    provenance = split.provenance_splits["test"]
    source_mask = provenance["source_file"].astype(str).to_numpy() == meta["source_file"]
    source_positions = np.flatnonzero(source_mask)
    if len(source_positions) == 0:
        raise SystemExit(f"{key}: no test rows from {meta['source_file']}")

    benign_positions = source_positions[labels.to_numpy()[source_positions] == 0]
    attack_positions = source_positions[labels.to_numpy()[source_positions] == 1]
    if len(benign_positions) < benign_n or len(attack_positions) < attack_n:
        raise SystemExit(
            f"{key}: not enough held-out rows in {meta['source_file']} "
            f"(benign={len(benign_positions)}, attack={len(attack_positions)})"
        )

    rng = np.random.default_rng(seed)
    chosen = np.concatenate([
        rng.choice(benign_positions, size=benign_n, replace=False),
        rng.choice(attack_positions, size=attack_n, replace=False),
    ])
    chosen = chosen[np.argsort(provenance["original_order"].to_numpy()[chosen], kind="stable")]

    flows: list[dict] = []
    for flow_id, pos in enumerate(chosen):
        row = test.iloc[int(pos)]
        features = {name: float(row[name]) for name in feature_names}
        is_attack = bool(labels.iloc[int(pos)] == 1)
        canonical = str(provenance["canonical_label"].iloc[int(pos)])
        family = str(provenance["label_family"].iloc[int(pos)])
        src, dst = _display_endpoints(flow_id)
        timestamp = provenance["timestamp"].iloc[int(pos)]
        flow = {
            "flow_id": flow_id,
            "features": features,
            "label": canonical,
            "is_attack": is_attack,
            "ground_truth": family,
            "category": family.lower().replace(" ", "_"),
            "src_endpoint": src,
            "dst_endpoint": dst,
            "protocol": "N/A",
            "duration_ms": round(float(row["flow_duration_ms"]), 6),
            "source_file": meta["source_file"],
        }
        if pd.notna(timestamp):
            flow["timestamp"] = pd.Timestamp(timestamp).strftime("%d/%m/%Y %H:%M:%S")
        flows.append(flow)

    payload = {
        "dataset": key,
        "benchmark_name": meta["benchmark_name"],
        "split": "held_out_test_exhibition_subset",
        "total_flows": len(flows),
        "benign_flows": benign_n,
        "attack_flows": attack_n,
        "attack_prevalence_pct": round(100.0 * attack_n / len(flows), 2),
        "feature_contract": f"R{len(feature_names)}",
        "provenance": (
            f"Deterministic {len(flows)}-flow subset drawn from the canonical held-out test "
            f"partition (seed={seed}), restricted to source file {meta['source_file']}."
        ),
        "metadata_provenance": {
            "endpoints": (
                "Synthetic RFC 5737 documentation addresses for display only. The distributable "
                "flow tables do not contain source/destination IP addresses."
            ),
            "protocol": "Not retained by the feature loader; shown as N/A.",
            "packet_count": "Not derivable from the R10/R4 feature contract; omitted.",
        },
        "flows": flows,
    }
    return payload


def _csv_text(payload: dict) -> str:
    feature_names = list(payload["flows"][0]["features"].keys())
    cols = [
        "flow_id", "src_endpoint", "dst_endpoint", "protocol", "source_file",
        *feature_names, "label",
    ]
    lines = [",".join(cols)]
    for flow in payload["flows"]:
        row = {
            "flow_id": flow["flow_id"],
            "src_endpoint": flow["src_endpoint"],
            "dst_endpoint": flow["dst_endpoint"],
            "protocol": flow["protocol"],
            "source_file": flow["source_file"],
            **flow["features"],
            "label": flow["label"],
        }
        lines.append(",".join(str(row[c]) for c in cols))
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", default="all", choices=["all", *DATASETS])
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--benign", type=int, default=166)
    parser.add_argument("--attack", type=int, default=34)
    parser.add_argument("--out-dir", default=str(OUT_DIR))
    args = parser.parse_args()

    keys = list(DATASETS) if args.dataset == "all" else [args.dataset]
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for key in keys:
        payload = build_one(key, seed=args.seed, benign_n=args.benign, attack_n=args.attack)
        prefix = DATASETS[key]["prefix"]
        json_path = out_dir / f"{prefix}_exhibition_200.json"
        csv_path = out_dir / f"{prefix}_exhibition_200.csv"
        json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        csv_path.write_text(_csv_text(payload), encoding="utf-8")
        print(f"{key}: wrote {json_path} and {csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
