# Feature contract / dataset compatibility (generated)

Registry status: `candidate_not_frozen` (frozen by `D-002`).
Column-map status: `unverified_pending_audit`.

A feature is *supported* for a dataset when every semantic field it requires is
declared in that dataset's column map. This is a **static** judgement about the
contract; the audit must still confirm the raw column names exist in the files.

| dataset | rung | supported | unsupported features |
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

## Feature definitions

| feature | formula | unit | live | directionality |
| --- | --- | --- | --- | --- |
| `flow_duration_ms` | duration_seconds * 1000 | ms | yes | longer flows are more likely benign bulk transfer |
| `flow_packets_per_s` | total_packets / duration_seconds | packets/s | yes | high rate indicates flooding-like behaviour |
| `flow_bytes_per_s` | total_bytes / duration_seconds | bytes/s | yes | high throughput is more consistent with bulk transfer than with attack |
| `packet_length_mean` | mean(packet_length) | bytes | yes | attack tools often emit uniform small packets |
| `packet_length_std` | std(packet_length) | bytes | yes | low variance suggests scripted traffic |
| `syn_count` | count(TCP SYN) | packets | yes | syn-heavy, ack-light traffic suggests scanning or SYN flood |
| `ack_count` | count(TCP ACK) | packets | yes | low ack relative to syn indicates half-open connections |
| `rst_count` | count(TCP RST) | packets | yes | many resets suggest scanning or connection refusal |
| `fin_count` | count(TCP FIN) | packets | yes | graceful termination indicator; near-absence on flood flows |
| `syn_ack_ratio` | syn_count / max(ack_count, 1) | ratio | yes | high ratio indicates unanswered connection attempts |
| `flow_iat_mean_ms` | mean(inter_arrival_time) * 1000 | ms | yes | very regular short IATs suggest automated traffic |
| `flow_iat_std_ms` | std(inter_arrival_time) * 1000 | ms | yes | low dispersion suggests machine-generated pacing |
| `down_up_ratio` | total_bwd_packets / max(total_fwd_packets, 1) | ratio | yes | near-zero indicates one-way (spoofed/flooded) traffic |
| `fwd_packet_length_mean` | mean(packet_length[forward]) | bytes | yes | informational |
| `bwd_packet_length_mean` | mean(packet_length[backward]) | bytes | yes | informational |
| `flow_bytes_per_packet` | total_bytes / max(total_packets, 1) | bytes/packet | yes | small values indicate many tiny packets |
| `active_mean_ms` | mean(active_period) * 1000 | ms | no | informational |
| `idle_mean_ms` | mean(idle_period) * 1000 | ms | no | informational |
| `subflow_fwd_bytes` | subflow_fwd_bytes | bytes | no | informational |
| `subflow_bwd_bytes` | subflow_bwd_bytes | bytes | no | informational |

## Decision-gate answers

| feature | Q1 | Q2 | Q3 | Q4 | Q5 | Q6 | Q7 | Q8 | Q9 | Q10 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `flow_duration_ms` | yes | yes | no | no | no | yes | unverified | unverified | no | yes |
| `flow_packets_per_s` | yes | yes | no | no | no | yes | unverified | unverified | no | yes |
| `flow_bytes_per_s` | yes | yes | no | no | no | yes | unverified | unverified | no | yes |
| `packet_length_mean` | yes | partial | no | no | no | yes | unverified | unverified | no | yes |
| `packet_length_std` | yes | no | no | no | no | yes | unverified | unverified | no | partial |
| `syn_count` | yes | no | no | no | no | yes | unverified | unverified | no | partial |
| `ack_count` | yes | no | no | no | no | yes | unverified | unverified | no | partial |
| `rst_count` | yes | no | no | no | no | yes | unverified | unverified | no | partial |
| `fin_count` | yes | no | no | no | no | yes | unverified | unverified | no | partial |
| `syn_ack_ratio` | yes | no | no | no | no | yes | unverified | unverified | no | yes |
| `flow_iat_mean_ms` | yes | no | no | no | no | yes | unverified | unverified | no | yes |
| `flow_iat_std_ms` | yes | no | no | no | no | yes | unverified | unverified | no | partial |
| `down_up_ratio` | yes | partial | no | no | no | yes | unverified | unverified | no | yes |
| `fwd_packet_length_mean` | yes | no | no | no | no | yes | unverified | unverified | no | partial |
| `bwd_packet_length_mean` | yes | no | no | no | no | yes | unverified | unverified | no | partial |
| `flow_bytes_per_packet` | yes | yes | no | no | no | yes | unverified | unverified | no | yes |
| `active_mean_ms` | partial | no | no | no | no | yes | unverified | unverified | yes | partial |
| `idle_mean_ms` | partial | no | no | no | no | yes | unverified | unverified | yes | partial |
| `subflow_fwd_bytes` | no | no | no | no | no | yes | unverified | unverified | no | partial |
| `subflow_bwd_bytes` | no | no | no | no | no | yes | unverified | unverified | no | partial |
