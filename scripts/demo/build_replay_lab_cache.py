#!/usr/bin/env python3
"""Build canonical, indexed replay cache pool for the XRL-IDARS Replay Lab.

Extracts genuine flow records directly from raw CSV files in data/raw/cicids2017/
and data/raw/cse_cic_ids2018/, preserving:
1. Exact source file name.
2. Exact 0-indexed row number in that source file.
3. Original raw label text.
4. Mapped binary ground truth (0 for BENIGN, 1 for ATTACK).
5. Ground-truth attack family name according to configs/labels/label_mapping.yaml.
6. Canonical 10 R10 features extracted via xrlids.features.compute.build_feature_matrix.

Saves compactly to data/demo/replay_lab_cache.joblib for instant, zero-latency
sampling of up to 10,000 records per run without reloading gigabytes of raw CSVs.
"""

from __future__ import annotations

import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from xrlids.features.compute import build_feature_matrix
from xrlids.features.registry import load_feature_registry
from xrlids.labels.contract import load_label_contract

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("build_replay_lab_cache")

OUT_PATH = REPO_ROOT / "data" / "demo" / "replay_lab_cache.joblib"


def sample_records_from_csv(
    csv_path: Path,
    dataset: str,
    target_families: list[str] | None = None,
    max_per_family: int = 10000,
    chunksize: int = 100000,
) -> list[dict[str, Any]]:
    """Sample genuine records from raw CSV, extracting features and metadata."""
    contract = load_label_contract()
    registry = load_feature_registry()
    fname = csv_path.name
    spec = contract._dataset_spec(dataset)
    benign_labels = [contract.normalize(b) for b in spec.get("benign_labels", ["BENIGN"])]
    family_map = {contract.normalize(k): v for k, v in (spec.get("family_map", {})).items()}

    # Determine label column
    head = pd.read_csv(csv_path, nrows=2)
    lcol = None
    for cand in spec.get("label_column_candidates", ["Label", " Label"]):
        for col in head.columns:
            if col.strip().lower() == cand.strip().lower():
                lcol = col
                break
        if lcol:
            break
    if not lcol:
        logger.warning(f"Could not find label column in {fname}")
        return []

    collected_by_family: dict[str, list[dict[str, Any]]] = {}
    current_row_idx = 0

    logger.info(f"Scanning {fname} (chunksize={chunksize})...")
    for chunk in pd.read_csv(csv_path, chunksize=chunksize, low_memory=False):
        chunk_len = len(chunk)
        raw_labels = chunk[lcol].astype(str).tolist()

        # Classify rows into families
        row_indices_by_fam: dict[str, list[int]] = {}
        for i, raw_lbl in enumerate(raw_labels):
            norm_lbl = contract.normalize(raw_lbl)
            if norm_lbl in benign_labels:
                fam = "Benign"
            elif norm_lbl in family_map:
                fam = family_map[norm_lbl]
            else:
                continue

            if target_families and fam not in target_families:
                continue

            current_count = len(collected_by_family.get(fam, [])) + len(row_indices_by_fam.get(fam, []))
            if current_count < max_per_family:
                row_indices_by_fam.setdefault(fam, []).append(i)

        # If any rows needed from this chunk, extract R10 features
        all_chunk_indices = []
        for fam, idx_list in row_indices_by_fam.items():
            all_chunk_indices.extend(idx_list)

        if all_chunk_indices:
            all_chunk_indices.sort()
            sub_chunk = chunk.iloc[all_chunk_indices].copy()
            global_indices = [current_row_idx + i for i in all_chunk_indices]

            try:
                feat_matrix = build_feature_matrix(sub_chunk, dataset, "R10", registry, strict=False, validate=False)
                feat_df = feat_matrix.frame

                for local_pos, global_idx in enumerate(global_indices):
                    raw_lbl = str(sub_chunk[lcol].iloc[local_pos])
                    norm_lbl = contract.normalize(raw_lbl)
                    is_benign = norm_lbl in benign_labels
                    fam = "Benign" if is_benign else family_map.get(norm_lbl, "Other")
                    feat_dict = feat_df.iloc[local_pos].to_dict()

                    # Filter out NaN/inf in key features
                    if any(np.isnan(v) or np.isinf(v) for v in feat_dict.values()):
                        continue

                    rec = {
                        "dataset": dataset,
                        "source_file": fname,
                        "source_row_index": global_idx,
                        "original_label": raw_lbl,
                        "ground_truth_family": fam,
                        "is_attack": not is_benign,
                        "binary_label": 0 if is_benign else 1,
                        "features": feat_dict,
                    }
                    collected_by_family.setdefault(fam, []).append(rec)
            except Exception as err:
                logger.error(f"Error computing features for chunk in {fname}: {err}")

        current_row_idx += chunk_len

        # Check if all targeted families are saturated
        if target_families and all(len(collected_by_family.get(f, [])) >= max_per_family for f in target_families):
            break

    total_records = []
    for fam, records in collected_by_family.items():
        logger.info(f"  {fname} -> {fam}: {len(records)} records")
        total_records.extend(records)

    return total_records


def build_all() -> None:
    t0 = time.time()
    all_records = []

    # 1. CIC-IDS2017 files
    cic_dir = REPO_ROOT / "data" / "raw" / "cicids2017"
    cic_tasks = [
        ("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", ["DDoS"], 12000),
        ("Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", ["PortScan"], 12000),
        ("Friday-WorkingHours-Morning.pcap_ISCX.csv", ["Bot"], 5000),
        ("Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv", ["Infiltration"], 5000),
        ("Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv", ["Web"], 5000),
        ("Tuesday-WorkingHours.pcap_ISCX.csv", ["BruteForce"], 12000),
        ("Wednesday-workingHours.pcap_ISCX.csv", ["DoS", "Heartbleed"], 12000),
        ("Monday-WorkingHours.pcap_ISCX.csv", ["Benign"], 12000),
    ]

    for fname, fams, limit in cic_tasks:
        fpath = cic_dir / fname
        if fpath.exists():
            records = sample_records_from_csv(fpath, "cicids2017", fams, limit)
            all_records.extend(records)

    # 2. CSE-CIC-IDS2018 files
    cse_dir = REPO_ROOT / "data" / "raw" / "cse_cic_ids2018"
    cse_tasks = [
        ("Friday-02-03-2018_TrafficForML_CICFlowMeter.csv", ["Bot"], 12000),
        ("Friday-16-02-2018_TrafficForML_CICFlowMeter.csv", ["DoS"], 12000),
        ("Friday-23-02-2018_TrafficForML_CICFlowMeter.csv", ["Web"], 5000),
        ("Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv", ["DDoS"], 12000),
        ("Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv", ["Infiltration"], 12000),
        ("Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv", ["Benign"], 12000),
        ("Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv", ["Web"], 5000),
        ("Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv", ["BruteForce"], 12000),
        ("Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv", ["DDoS"], 12000),
    ]

    for fname, fams, limit in cse_tasks:
        fpath = cse_dir / fname
        if fpath.exists():
            records = sample_records_from_csv(fpath, "cse_cic_ids2018", fams, limit)
            all_records.extend(records)

    logger.info(f"Total sampled pool records: {len(all_records)} across both datasets.")
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(all_records, OUT_PATH, compress=3)
    elapsed = time.time() - t0
    logger.info(f"Saved replay lab cache to {OUT_PATH} ({OUT_PATH.stat().st_size / (1024*1024):.1f} MB) in {elapsed:.1f}s.")


if __name__ == "__main__":
    build_all()
