# FEATURE COMPATIBILITY

Status: **implementation complete, dataset confirmation pending (audit required).**

The full generated matrix lives at
[`../../reports/generated/feature_compatibility.md`](../../reports/generated/feature_compatibility.md).
It is generated from `configs/features/features.yaml` by
`scripts/phase1/generate_reports.py`, so it cannot drift from the registry.

## Availability legend

| Value | Meaning |
| --- | --- |
| YES | semantic field declared in the dataset's column map and reproducible live |
| NO | not declared / not available; dependent features are reported unavailable |
| CONDITIONAL | declared but requires re-derivation or an unverified column name |

## Matrix (static, from the column maps)

| Dataset | R10 | R15 | R20 |
| --- | --- | --- | --- |
| CICIDS2017 | 10/10 | 15/15 | 20/20 |
| CSE-CIC-IDS2018 | 10/10 | 15/15 | 20/20 |
| UNSW-NB15 | **4/10** | **5/15** | **6/20** |

## Live (Scapy) compatibility

`live_available` is recorded per feature in the registry. The R20-only features
(`active_mean_ms`, `idle_mean_ms`, `subflow_fwd_bytes`, `subflow_bwd_bytes`) are
**not live-reproducible**: they depend on flow-segmentation and subflow semantics that a
packet-level builder does not naturally produce. That is precisely why R20 is marked
`live_compatible: false`.

## The UNSW-NB15 blocker (important finding)

UNSW-NB15 has a fundamentally different feature-derivation pipeline (Argus/Bro-style). It
provides duration, packet counts, byte counts and means, but **no TCP flag counts, no
inter-arrival statistics, no active/idle segmentation and no subflow fields**.

Consequences:

1. `syn_count`, `ack_count`, `rst_count`, `fin_count`, `syn_ack_ratio` and
   `packet_length_std` cannot be computed for UNSW-NB15 under the current contract.
2. Therefore the **R10 contract as defined cannot be evaluated on UNSW-NB15**, and the
   planned 3×3×3 feature sweep is only 2/3 evaluable at R10.
3. The pipeline does not paper over this: `run_single_dataset` returns
   `BLOCKED_FEATURE_INCOMPATIBLE` for UNSW-NB15 at R10 rather than substituting columns or
   dropping the features silently.

This is a **research decision**, not something the implementation may resolve alone:

| Option | Consequence |
| --- | --- |
| A. UNSW-NB15 uses a dataset-specific reduced contract | Cross-dataset comparison at R10 is no longer apples-to-apples |
| B. Define a portable sub-contract (features available everywhere) | R10 would shrink to ~4 features, weakening in-domain results |
| C. Exclude UNSW-NB15 from R10 experiments and evaluate it only at a bespoke rung | Weakens RQ5 (domain shift) evidence |
| D. Re-derive missing UNSW features from raw packets | UNSW-NB15 releases flow records, not packets; likely infeasible |

**Recorded for decision. No option has been chosen.** See `docs/04_QUESTIONS/OPEN_QUESTIONS.md`.

## Verification status

The column maps are marked `unverified_pending_audit`. The static matrix above is a claim
about the contract, **not** about the files. The audit
(`scripts/phase1/01_dataset_audit.py`) must confirm the raw column names actually exist
before any result is reported; a wrong column name currently fails loudly.
