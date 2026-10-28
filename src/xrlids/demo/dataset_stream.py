"""Curated benchmark dataset streaming for demonstration and validation.

Streams curated CIC-IDS2017 feature vectors (DDoS, DoS Hulk, PortScan, and Benign
enterprise traffic) with ground-truth verification for live demonstrations. The
distributable feature table has no IP addresses; display endpoints in the sample
file are synthetic placeholders and are not capture metadata.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_SAMPLES_FILE = REPO_ROOT / "data" / "demo" / "dataset_samples.json"

CATEGORIES: dict[str, str] = {
    "mixed": "Curated Benchmark Mix (DDoS, DoS Hulk, PortScan, Benign)",
    "ddos": "Friday Afternoon — DDoS Attacks + Benign",
    "dos": "Wednesday — DoS Hulk / Slowloris + Benign",
    "portscan": "Friday Afternoon — PortScan Reconnaissance + Benign",
    "benign": "Monday — Normal Enterprise Benign Traffic Only",
}


def load_dataset_samples(
    category: str = "mixed",
    filepath: Path | str | None = None,
) -> list[dict[str, Any]]:
    """Load curated benchmark dataset flows for a given category.

    Args:
        category: One of 'mixed', 'ddos', 'dos', 'portscan', 'benign'.
        filepath: Optional path to the dataset_samples.json file.

    Returns:
        A list of flow dictionaries with ground truth, endpoints, protocol,
        packet count, duration, and R10 features.
    """
    path = Path(filepath) if filepath else DEFAULT_SAMPLES_FILE
    if not path.exists():
        raise FileNotFoundError(
            f"Dataset stream sample file not found: {path}. "
            "Restore the committed data/demo/dataset_samples.json; no synthetic fallback is used."
        )

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    cat = category.lower().strip()
    if cat == "mixed":
        return _build_mixed_stream(data)

    if cat in data:
        return list(data[cat])

    # Default fallback to mixed
    return _build_mixed_stream(data)


def _build_mixed_stream(data: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """Interleave benign and diverse attack flows for a dynamic presentation."""
    benign_pool = list(data.get("benign", []))
    ddos_pool = [x for x in data.get("ddos", []) if x.get("is_attack")]
    dos_pool = [x for x in data.get("dos", []) if x.get("is_attack")]
    scan_pool = [x for x in data.get("portscan", []) if x.get("is_attack")]

    mixed: list[dict[str, Any]] = []
    b_idx = d_idx = h_idx = s_idx = 0

    max_rounds = max(len(benign_pool), len(ddos_pool) + len(dos_pool) + len(scan_pool))

    for _ in range(max_rounds):
        # 1-2 Benign flows
        for _ in range(2):
            if benign_pool:
                mixed.append(benign_pool[b_idx % len(benign_pool)])
                b_idx += 1

        # DDoS flow
        if ddos_pool:
            mixed.append(ddos_pool[d_idx % len(ddos_pool)])
            d_idx += 1

        # 1 Benign flow
        if benign_pool:
            mixed.append(benign_pool[b_idx % len(benign_pool)])
            b_idx += 1

        # DoS Hulk flow
        if dos_pool:
            mixed.append(dos_pool[h_idx % len(dos_pool)])
            h_idx += 1

        # PortScan flow
        if scan_pool:
            mixed.append(scan_pool[s_idx % len(scan_pool)])
            s_idx += 1

    return mixed if mixed else data.get("ddos", [])
