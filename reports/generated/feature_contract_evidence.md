# Feature-contract evidence (D-002 decision support)

Decision status: **OPEN - evidence provided, decision reserved to the project owner**
Contract status: `candidate_not_frozen`

## Availability matrix

| dataset | rung | supported | unsupported |
| --- | --- | --- | --- |
| cicids2017 | R10 | 10/10 | - |
| cicids2017 | R15 | 15/15 | - |
| cicids2017 | R20 | 20/20 | - |
| cse_cic_ids2018 | R10 | 10/10 | - |
| cse_cic_ids2018 | R15 | 15/15 | - |
| cse_cic_ids2018 | R20 | 20/20 | - |
| unsw_nb15 | R10 | 4/10 | packet_length_std, syn_count, ack_count, rst_count, fin_count, syn_ack_ratio |
| unsw_nb15 | R15 | 5/15 | packet_length_std, syn_count, ack_count, rst_count, fin_count, syn_ack_ratio, flow_iat_mean_ms, flow_iat_std_ms, fwd_packet_length_mean, bwd_packet_length_mean |
| unsw_nb15 | R20 | 6/20 | packet_length_std, syn_count, ack_count, rst_count, fin_count, syn_ack_ratio, flow_iat_mean_ms, flow_iat_std_ms, fwd_packet_length_mean, bwd_packet_length_mean, active_mean_ms, idle_mean_ms, subflow_fwd_bytes, subflow_bwd_bytes |

## Live-computability

| feature | blocked because |
| --- | --- |
| `active_mean_ms` | requires flow segmentation that live capture (Phase 3) may not reproduce |
| `idle_mean_ms` | same segmentation dependency as active_mean_ms |
| `subflow_fwd_bytes` | tool-specific definition; not live-reproducible, not available in UNSW-NB15 |
| `subflow_bwd_bytes` | tool-specific definition; not live-reproducible, not available in UNSW-NB15 |

## Empirical schema validation (real files)

### cicids2017
- `DATA_NOT_AVAILABLE` - no files registered or present

### cse_cic_ids2018
- status: `validated`
- files checked: 1
- identical schemas across files: True
- all declared columns present: True

### unsw_nb15
- `DATA_NOT_AVAILABLE` - no files registered or present


## Evidence still missing for the decision

- **distribution_behaviour**: requires real data audit (per-feature min/max/median, missingness, outliers)
- **missingness**: requires real data audit
- **quality_anomalies**: requires real data audit (constant columns, invalid values)
- **validation_performance**: requires the feature sweep (blocked on D-004 acquisition)
- **cross_dataset_performance**: requires the transfer experiments (blocked on D-005)
- **computational_cost**: requires latency measurement with trained models

## Options for the project owner

- A. keep the candidate rungs as-is (R10 live-baseline intact; UNSW evaluated only at bespoke rungs)
- B. redefine rungs to a smallest-common cross-dataset contract (~4 features; weak in-domain)
- C. dual contracts: primary live-compatible + secondary per-dataset research contract
- D. per-dataset rungs with explicit non-comparability caveats in cross-dataset work

> No recommendation is made and no option is selected here. Resolving D-002 is a
> project-owner decision; this artifact exists to make that decision evidence-based.