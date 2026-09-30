"""Synthetic fixtures for TESTS and SMOKE RUNS ONLY.

These frames are NOT dataset rows and must never be reported as experimental results.
They exist so the pipeline can be exercised end-to-end without the real datasets, which
is explicitly permitted for fixtures (build spec section 34) but explicitly forbidden as
evidence (scientific RULES 1 and 2).

The generator emits CICFlowMeter-style column names so it exercises the real column maps,
and embeds a modest learnable signal so a smoke run can confirm the plumbing (not accuracy).
"""

from __future__ import annotations

import numpy as np
import pandas as pd

CIC_COLUMNS = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Packet Length Mean",
    "Packet Length Std",
    "SYN Flag Count",
    "ACK Flag Count",
    "RST Flag Count",
    "FIN Flag Count",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Active Mean",
    "Idle Mean",
    "Subflow Fwd Bytes",
    "Subflow Bwd Bytes",
]


def synthetic_cic_frame(n_rows: int = 1200, seed: int = 0, attack_fraction: float = 0.35) -> pd.DataFrame:
    """Return a deterministic CIC-shaped synthetic frame with a ``Label`` column.

    Signal design (kept simple and explicit):
      * BENIGN flows: longer duration, balanced directions, ACK-heavy, modest rates.
      * ATTACK flows: short duration, SYN-heavy with few ACKs, small uniform packets.
    """
    rng = np.random.default_rng(seed)
    n_attack = int(round(n_rows * attack_fraction))
    n_benign = n_rows - n_attack
    labels = np.array(["BENIGN"] * n_benign + ["DoS Hulk"] * n_attack)
    rng.shuffle(labels)

    is_attack = labels != "BENIGN"

    duration_us = np.where(
        is_attack,
        rng.integers(500, 60_000, size=n_rows),
        rng.integers(200_000, 5_000_000, size=n_rows),
    ).astype(float)
    duration_s = np.clip(duration_us / 1e6, 1e-6, None)

    fwd_packets = np.where(is_attack, rng.integers(5, 60, n_rows), rng.integers(2, 30, n_rows))
    bwd_packets = np.where(is_attack, rng.integers(0, 3, n_rows), rng.integers(2, 30, n_rows))
    total_packets = fwd_packets + bwd_packets

    pkt_len_mean = np.where(is_attack, rng.normal(60, 3, n_rows), rng.normal(600, 120, n_rows)).clip(20, None)
    pkt_len_std = np.where(is_attack, rng.normal(2, 0.5, n_rows), rng.normal(200, 40, n_rows)).clip(0, None)

    fwd_bytes = fwd_packets * pkt_len_mean
    bwd_bytes = bwd_packets * pkt_len_mean

    syn = np.where(is_attack, rng.integers(5, 40, n_rows), rng.integers(0, 3, n_rows))
    ack = np.where(is_attack, rng.integers(0, 2, n_rows), rng.integers(1, 25, n_rows))
    rst = np.where(is_attack, rng.integers(0, 3, n_rows), np.zeros(n_rows, dtype=int))
    fin = np.where(is_attack, rng.integers(0, 2, n_rows), rng.integers(0, 4, n_rows))

    iat_mean_s = duration_s / np.clip(total_packets, 1, None)
    iat_std_s = np.where(is_attack, rng.normal(0.0005, 0.0001, n_rows), rng.normal(0.05, 0.02, n_rows)).clip(0, None)

    frame = pd.DataFrame(
        {
            "Flow Duration": duration_us,
            "Total Fwd Packets": fwd_packets,
            "Total Backward Packets": bwd_packets,
            "Total Length of Fwd Packets": fwd_bytes,
            "Total Length of Bwd Packets": bwd_bytes,
            "Packet Length Mean": pkt_len_mean,
            "Packet Length Std": pkt_len_std,
            "SYN Flag Count": syn,
            "ACK Flag Count": ack,
            "RST Flag Count": rst,
            "FIN Flag Count": fin,
            "Flow IAT Mean": iat_mean_s * 1e6,
            "Flow IAT Std": iat_std_s * 1e6,
            "Fwd Packet Length Mean": pkt_len_mean,
            "Bwd Packet Length Mean": pkt_len_mean * 0.9,
            "Active Mean": rng.integers(0, 5000, n_rows),
            "Idle Mean": rng.integers(0, 5000, n_rows),
            "Subflow Fwd Bytes": fwd_bytes * 0.6,
            "Subflow Bwd Bytes": bwd_bytes * 0.6,
            "Label": labels,
        }
    )
    return frame
