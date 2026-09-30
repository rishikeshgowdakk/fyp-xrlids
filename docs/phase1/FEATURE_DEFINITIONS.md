# FEATURE DEFINITIONS

Status: **implemented** in `src/xrlids/features/definitions.py` — the single source of truth
for feature mathematics.

The full table (formula, unit, live availability, directionality, decision-gate answers) is
generated at [`../../reports/generated/feature_compatibility.md`](../../reports/generated/feature_compatibility.md).

## Architecture

Features are computed from **semantic fields** (dataset-independent quantities such as
`duration_seconds`, `syn_flags`), not from raw dataset columns. Raw columns are mapped to
semantic fields in `configs/features/features.yaml`. This separation is what makes
cross-dataset claims honest: if a dataset cannot supply a semantic field, the dependent
feature is *reported unavailable* rather than approximated.

```text
raw dataset columns --(column_maps)--> semantic fields --(formulas)--> canonical features
```

## Canonical features (20) and rungs

| Rung | Features | Live-compatible |
| --- | --- | --- |
| R10 | flow_duration_ms, flow_packets_per_s, flow_bytes_per_s, packet_length_mean, packet_length_std, syn_count, ack_count, rst_count, fin_count, syn_ack_ratio | yes |
| R15 | R10 + flow_iat_mean_ms, flow_iat_std_ms, down_up_ratio, fwd_packet_length_mean, bwd_packet_length_mean | yes |
| R20 | R15 + flow_bytes_per_packet, active_mean_ms, idle_mean_ms, subflow_fwd_bytes, subflow_bwd_bytes | no |

R10 is the project's stated 10-feature live-reproducible baseline. R15 and R20 are
**candidates**: membership must still be justified by the decision gate and the feature
sweep before the contract is frozen (D-002).

## Selected formulas

```text
flow_duration_ms     = duration_seconds * 1000
flow_packets_per_s   = total_packets / duration_seconds
flow_bytes_per_s     = total_bytes   / duration_seconds
packet_length_mean   = pkt_len_mean
packet_length_std    = pkt_len_std
syn_count            = syn_flags
ack_count            = ack_flags
rst_count            = rst_flags
fin_count            = fin_flags
syn_ack_ratio        = syn_flags / max(ack_flags, 1)
flow_iat_mean_ms     = flow_iat_mean_s * 1000
flow_iat_std_ms      = flow_iat_std_s  * 1000
down_up_ratio        = total_bwd_packets / max(total_fwd_packets, 1)
flow_bytes_per_packet = total_bytes / max(total_packets, 1)
```

where `total_packets = total_fwd_packets + total_bwd_packets` and
`total_bytes = fwd_bytes + bwd_bytes`.

## Edge-case policy

| Case | Policy |
| --- | --- |
| `duration <= 0`, packets > 0 | rate is **NaN** (genuinely undefined), never `Infinity` |
| `duration <= 0`, packets = 0 | rate is `0.0` (nothing happened) |
| ratio denominator = 0 | denominator floored at 1 (`syn_ack_ratio`, `down_up_ratio`, `flow_bytes_per_packet`) |
| missing semantic field | feature reported **unavailable**; pipeline raises or blocks |

NaN is never silently replaced at feature-computation time; the row-level policy and its
count live in `DATA_CLEANING_POLICY.md`.

## Excluded columns

Identifiers and labels are **never** model inputs: flow id, timestamps, source/destination
IP and port, `attack_cat`, `label`. They may be used for grouping, leakage analysis and
provenance only. The exclusion patterns are enforced by
`FeatureRegistry.is_excluded_column` and unit-tested.

## Rationale and limitations

Each feature carries `rationale` and `limitations` in code and is emitted into the generated
report. Examples of honest limitations already recorded:

- `syn_ack_ratio` saturates for large SYN counts because the denominator is floored.
- `flow_bytes_per_packet` is closely related to `packet_length_mean`; may be redundant.
- `active_mean_ms` / `idle_mean_ms` depend on flow segmentation that live capture may not
  reproduce, which is why R20 is not live-compatible.
