# Feature Compatibility and Contract Report (generated)

Registry status: `frozen` (frozen by `D-002`).
Column-map status: `verified_audited`.

## In-Domain Rungs (Supported vs Unsupported)

| Dataset | Rung | Supported | Unsupported Features |
| --- | --- | --- | --- |
| `cicids2017` | `R10` | 10/10 | None (Fully Supported) |
| `cicids2017` | `R15` | 15/15 | None (Fully Supported) |
| `cicids2017` | `R20` | 20/20 | None (Fully Supported) |
| `cse_cic_ids2018` | `R10` | 10/10 | None (Fully Supported) |
| `cse_cic_ids2018` | `R15` | 15/15 | None (Fully Supported) |
| `cse_cic_ids2018` | `R20` | 20/20 | None (Fully Supported) |
| `unsw_nb15` | `R10` | 4/10 | packet_length_std, syn_count, ack_count, rst_count, fin_count, syn_ack_ratio |
| `unsw_nb15` | `R15` | 5/15 | packet_length_std, syn_count, ack_count, rst_count, fin_count, syn_ack_ratio, flow_iat_mean_ms, flow_iat_std_ms, fwd_packet_length_mean, bwd_packet_length_mean |
| `unsw_nb15` | `R20` | 6/20 | packet_length_std, syn_count, ack_count, rst_count, fin_count, syn_ack_ratio, flow_iat_mean_ms, flow_iat_std_ms, fwd_packet_length_mean, bwd_packet_length_mean, active_mean_ms, idle_mean_ms, subflow_fwd_bytes, subflow_bwd_bytes |

## Cross-Dataset Common Transfer Contract

> [!NOTE]
> When transferring between structurally different datasets (e.g. CSE-CIC-IDS2018 to UNSW-NB15),
> the model must only receive features supported by **BOTH** datasets. Unsupported features must
> never be fabricated or assigned arbitrary proxy values.

- **Common Transfer Features (Intersection = 4)**:
  1. `flow_duration_ms`
  2. `flow_packets_per_s`
  3. `flow_bytes_per_s`
  4. `packet_length_mean`
- **Unsupported UNSW-NB15 Features in R10 (6 features marked `UNSUPPORTED`)**:
  `packet_length_std`, `syn_count`, `ack_count`, `rst_count`, `fin_count`, `syn_ack_ratio`.

## Feature Definitions

| Feature | Formula | Unit | Live Available | Directionality |
| --- | --- | --- | --- | --- |
| `flow_duration_ms` | duration_seconds * 1000 | ms | Yes | longer flows are more likely benign bulk transfer |
| `flow_packets_per_s` | total_packets / duration_seconds | packets/s | Yes | high rate indicates flooding-like behaviour |
| `flow_bytes_per_s` | total_bytes / duration_seconds | bytes/s | Yes | high throughput is more consistent with bulk transfer than with attack |
| `packet_length_mean` | mean(packet_length) | bytes | Yes | attack tools often emit uniform small packets |
| `packet_length_std` | std(packet_length) | bytes | Yes | low variance suggests scripted traffic |
| `syn_count` | count(TCP SYN) | packets | Yes | syn-heavy, ack-light traffic suggests scanning or SYN flood |
| `ack_count` | count(TCP ACK) | packets | Yes | low ack relative to syn indicates half-open connections |
| `rst_count` | count(TCP RST) | packets | Yes | many resets suggest scanning or connection refusal |
| `fin_count` | count(TCP FIN) | packets | Yes | graceful termination indicator; near-absence on flood flows |
| `syn_ack_ratio` | syn_count / max(ack_count, 1) | ratio | Yes | high ratio indicates unanswered connection attempts |
| `flow_iat_mean_ms` | mean(inter_arrival_time) * 1000 | ms | Yes | very regular short IATs suggest automated traffic |
| `flow_iat_std_ms` | std(inter_arrival_time) * 1000 | ms | Yes | low dispersion suggests machine-generated pacing |
| `down_up_ratio` | total_bwd_packets / max(total_fwd_packets, 1) | ratio | Yes | near-zero indicates one-way (spoofed/flooded) traffic |
| `fwd_packet_length_mean` | mean(packet_length[forward]) | bytes | Yes | informational |
| `bwd_packet_length_mean` | mean(packet_length[backward]) | bytes | Yes | informational |
| `flow_bytes_per_packet` | total_bytes / max(total_packets, 1) | bytes/packet | Yes | small values indicate many tiny packets |
| `active_mean_ms` | mean(active_period) * 1000 | ms | No | informational |
| `idle_mean_ms` | mean(idle_period) * 1000 | ms | No | informational |
| `subflow_fwd_bytes` | subflow_fwd_bytes | bytes | No | informational |
| `subflow_bwd_bytes` | subflow_bwd_bytes | bytes | No | informational |