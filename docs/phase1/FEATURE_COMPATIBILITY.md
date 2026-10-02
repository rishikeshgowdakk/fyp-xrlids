# FEATURE COMPATIBILITY

Status: **FROZEN under Decision D-002 (Audit Complete).**

The full generated matrix lives at
[`../../reports/generated/feature_compatibility.md`](../../reports/generated/feature_compatibility.md).
It is generated from `configs/features/features.yaml` by
`scripts/phase1/generate_reports.py`, so it cannot drift from the registry.
Detailed audit evidence lives at [`FEATURE_CONTRACT_AUDIT.md`](FEATURE_CONTRACT_AUDIT.md).

## Availability legend

| Value | Meaning |
| --- | --- |
| YES | semantic field declared in the dataset's column map and reproducible live |
| NO | not declared / not available; dependent features are reported unavailable |
| CONDITIONAL | declared but requires re-derivation or an unverified column name |

## Matrix (audited and verified on real files)

| Dataset | R10 | R15 | R20 | Status |
| --- | --- | --- | --- | --- |
| CICIDS2017 | **10/10** | 15/15 | 20/20 | ✅ Full Support (Frozen Contract) |
| CSE-CIC-IDS2018 | **10/10** | 15/15 | 20/20 | ✅ Full Support (Frozen Contract) |
| UNSW-NB15 | **4/10** | **5/15** | **6/20** | ⚠️ Blocked on 6 missing features (Auxiliary Fallback Only) |

## Live (Scapy) compatibility

`live_available` is recorded per feature in the registry. The R20-only features
(`active_mean_ms`, `idle_mean_ms`, `subflow_fwd_bytes`, `subflow_bwd_bytes`) are
**not live-reproducible**: they depend on flow-segmentation and subflow semantics that a
packet-level builder does not naturally produce. That is precisely why R20 is marked
`live_compatible: false`. All 10 features of the R10 contract are `live_compatible: true`.

## The UNSW-NB15 blocker (formally resolved under D-002)

UNSW-NB15 has a fundamentally different feature-derivation pipeline (Argus/Bro-style). It
provides duration, packet counts, byte counts and means, but **no TCP flag counts, no
inter-arrival statistics, no active/idle segmentation and no subflow fields**.

Consequences:

1. `syn_count`, `ack_count`, `rst_count`, `fin_count`, `syn_ack_ratio` and
   `packet_length_std` cannot be computed for UNSW-NB15 from published flow records.
2. Under Decision D-002, **these 6 features are NEVER fabricated**.
3. R10 is frozen as the primary cross-dataset contract for CIC-IDS2017 and CSE-CIC-IDS2018.
4. UNSW-NB15 cross-dataset experiments are restricted to the 4-feature contract as an
   explicit auxiliary fallback. See [`FEATURE_CONTRACT_AUDIT.md`](FEATURE_CONTRACT_AUDIT.md).

## Verification status

The column maps are marked `verified_audited`. All canonical column names and scalings
have been empirically verified against physical CSV files in `data/raw/`.
