# SHAP Explainability Report (generated)

Status: `EMPIRICALLY OBSERVED` (TreeSHAP computed on Random Forest ensemble, CIC-IDS2017 Multi-File Benchmark (`EXP-P1-CIC2017-R10-001`)).

> [!IMPORTANT]
> **Scientific Disclaimer**:
> 1. SHAP values quantify additive associative attributions relative to the background expectation.
> 2. SHAP does **NOT** prove physical or causal mechanisms in underlying network packets.
> 3. Test set data was strictly evaluated post-hoc and was **never** used to tune or select features.

## Global Feature Importance Ranking (Mean Absolute SHAP)

| Rank | Feature Name | Mean Absolute SHAP Value | Relative Contribution |
| --- | --- | --- | --- |
| 1 | `packet_length_std` | 0.094327 | 28.1% |
| 2 | `packet_length_mean` | 0.087260 | 26.0% |
| 3 | `flow_packets_per_s` | 0.047941 | 14.3% |
| 4 | `flow_bytes_per_s` | 0.036564 | 10.9% |
| 5 | `flow_duration_ms` | 0.031858 | 9.5% |
| 6 | `ack_count` | 0.020760 | 6.2% |
| 7 | `fin_count` | 0.011039 | 3.3% |
| 8 | `syn_count` | 0.003289 | 1.0% |
| 9 | `syn_ack_ratio` | 0.002803 | 0.8% |
| 10 | `rst_count` | 0.000000 | 0.0% |

## Key Attribution Insights

1. **`packet_length_std`** ranks first (Mean |SHAP| = 0.0943), indicating this feature provides the strongest mathematical contrast separating attack flows from benign traffic in tree splits.
2. **`packet_length_mean`** ranks second (Mean |SHAP| = 0.0873), serving as the primary secondary behavioral discriminator.
3. **`flow_packets_per_s`** ranks third (Mean |SHAP| = 0.0479), capturing additional flow dynamics.
