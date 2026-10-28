#!/usr/bin/env python
"""Rebuild the live dataset-stream samples from the canonical CIC-IDS2017 test split.

The stream is a presentation aid, not a benchmark. It uses real CIC-IDS2017 feature
rows from the held-out test partition; display endpoints are deterministic RFC 5737
documentation addresses because the distributable flow table contains no IP addresses.

Usage:
    .venv/bin/python scripts/demo/build_dataset_stream_samples.py
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
OUT_PATH = REPO_ROOT / "data" / "demo" / "dataset_samples.json"


def _endpoints(flow_id: int) -> tuple[str, str]:
    return (
        f"192.0.2.{10 + (flow_id % 200)}:{40000 + flow_id}",
        f"198.51.100.{10 + (flow_id % 200)}:443",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", default=str(OUT_PATH))
    args = parser.parse_args()

    cfg = yaml.safe_load(
        (REPO_ROOT / "configs/experiments/p1_cicids2017_r10.yaml").read_text(encoding="utf-8")
    )
    registry = load_feature_registry()
    contract = load_label_contract()
    feature_names = registry.rung_features(cfg["features"]["rung"])
    population = load_dataset_population(
        PopulationConfig(
            dataset="cicids2017",
            files="all_verified",
            duplicate_policy="deduplicate_features",
            duplicate_conflict_policy="reject_conflicts",
            seed=args.seed,
        ),
        feature_names,
        contract=contract,
        registry=registry,
    )
    split = build_splits(
        population.features,
        population.labels,
        list(population.features.columns),
        SplitConfig(seed=args.seed, stratify=True, duplicate_policy="deduplicate_features"),
        dataset="cicids2017",
        provenance=population.provenance,
        run_leakage_audit=False,
    )

    test = split.splits["test"]
    labels = split.label_splits["test"].to_numpy()
    provenance = split.provenance_splits["test"]
    family = provenance["label_family"].astype(str).str.upper().to_numpy()
    positions = np.arange(len(test))
    benign_positions = positions[labels == 0]
    attack_positions = {
        "ddos": positions[(labels == 1) & np.array(["DDOS" in x for x in family])],
        "portscan": positions[(labels == 1) & np.array(["PORTSCAN" in x for x in family])],
        "dos": positions[(labels == 1) & np.array(["DOS HULK" in x for x in family])],
    }
    for name, pos in attack_positions.items():
        if len(pos) < 30:
            raise SystemExit(f"Not enough held-out {name} rows: {len(pos)}")
    if len(benign_positions) < 125:
        raise SystemExit(f"Not enough held-out benign rows: {len(benign_positions)}")

    rng = np.random.default_rng(args.seed)
    benign_draw = rng.choice(benign_positions, size=125, replace=False)
    benign_sets = {
        "ddos": benign_draw[:15],
        "portscan": benign_draw[15:30],
        "dos": benign_draw[30:45],
        "benign": benign_draw[45:85],
    }
    benign_index = 0
    output: dict[str, list[dict]] = {}
    for category in ("ddos", "portscan", "dos"):
        chosen = np.concatenate([
            rng.choice(attack_positions[category], size=30, replace=False),
            benign_sets[category],
        ])
        output[category] = _rows_for(chosen, category, test, labels, provenance, benign_index)
        benign_index += len(benign_sets[category])
    output["benign"] = _rows_for(
        benign_sets["benign"], "benign", test, labels, provenance, benign_index
    )

    Path(args.out).write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


def _rows_for(
    positions: np.ndarray,
    category: str,
    test: pd.DataFrame,
    labels: np.ndarray,
    provenance: pd.DataFrame,
    offset: int,
) -> list[dict]:
    rows: list[dict] = []
    for i, pos in enumerate(positions):
        row = test.iloc[int(pos)]
        flow_id = offset + i
        src, dst = _endpoints(flow_id)
        duration_ms = float(row["flow_duration_ms"])
        packets = max(1, int(round(float(row["flow_packets_per_s"]) * duration_ms / 1000.0)))
        rows.append({
            "category": category,
            "is_attack": bool(labels[int(pos)] == 1),
            "ground_truth": str(provenance["label_family"].iloc[int(pos)]),
            "src_endpoint": src,
            "dst_endpoint": dst,
            "protocol": "N/A",
            "packet_count": packets,
            "duration_ms": round(duration_ms, 3),
            "features": {name: float(row[name]) for name in test.columns},
            "source_file": str(provenance["source_file"].iloc[int(pos)]),
            "metadata_provenance": "endpoints are synthetic RFC 5737 display addresses; features are real held-out rows",
        })
    return rows


if __name__ == "__main__":
    raise SystemExit(main())
