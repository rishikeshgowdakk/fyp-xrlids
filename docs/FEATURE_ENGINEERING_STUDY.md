# Feature Engineering Study & Multi-Rung Evaluation
**Project:** Explainable Reinforcement Learning-Based Intrusion Detection and Autonomous Response System (XRL-IDARS)  
**Artifact ID:** `STUDY-FEATURES-R10-R30-001`  
**Classification:** Research and Architectural Evaluation  
**Status:** COMPLETE / VERIFIED  

---

## 1. Feature Hierarchy & Mathematical Definitions

XRL-IDARS structures network flow features into hierarchical rungs to balance detection accuracy, computational overhead, and cross-dataset compatibility:

```
[R4: Flow Core] -> [R10: Primary Contract] -> [R15: Pacing & Direction] -> [R20: Activity Windows] -> [R30: Extended TCP]
```

### 1.1 Rung Definitions

#### Rung $R_4$ (Degraded Cross-Dataset Core)
Supported universally across CICIDS2017, CSE-CIC-IDS2018, UNSW-NB15, and Live Scapy:
1. `flow_duration_ms`: Total session duration in milliseconds ($\Delta t = (t_{\text{last}} - t_{\text{start}}) \times 1000$).
2. `flow_packets_per_s`: Packet transmission rate ($N_{\text{packets}} / \max(\Delta t_{\text{sec}}, 10^{-6})$).
3. `flow_bytes_per_s`: Byte transmission throughput ($B_{\text{total}} / \max(\Delta t_{\text{sec}}, 10^{-6})$).
4. `packet_length_mean`: Arithmetic mean of bidirectional packet sizes ($\frac{1}{N} \sum_{i=1}^N L_i$).

#### Rung $R_{10}$ (Canonical Production Contract — Decision D-002)
Adds Layer 4 TCP flag state counts and dispersion metrics:
5. `packet_length_std`: Standard deviation of packet sizes ($\sqrt{\frac{1}{N} \sum_{i=1}^N (L_i - \bar{L})^2}$).
6. `syn_count`: Total TCP SYN flag occurrences.
7. `ack_count`: Total TCP ACK flag occurrences.
8. `rst_count`: Total TCP RST flag occurrences.
9. `fin_count`: Total TCP FIN flag occurrences.
10. `syn_ack_ratio`: Asymmetry ratio ($N_{\text{SYN}} / \max(N_{\text{ACK}}, 1.0)$).

#### Rung $R_{15}$ (Directional & Inter-Arrival Timing Extension)
Adds temporal pacing and directional asymmetry:
11. `flow_iat_mean_ms`: Mean inter-arrival time between consecutive packets in milliseconds.
12. `flow_iat_std_ms`: Standard deviation of packet inter-arrival times.
13. `down_up_ratio`: Backward-to-forward packet count ratio ($N_{\text{bwd}} / \max(N_{\text{fwd}}, 1)$).
14. `fwd_packet_length_mean`: Mean size of packets transmitted in forward direction.
15. `bwd_packet_length_mean`: Mean size of packets transmitted in backward direction.

#### Rung $R_{20}$ (Subflow & Activity Structure)
Adds subflow segmentation and idle/active bursts:
16. `flow_bytes_per_packet`: Mean bytes per individual packet ($B_{\text{total}} / \max(N_{\text{packets}}, 1)$).
17. `active_mean_ms`: Mean duration of active transmission periods.
18. `idle_mean_ms`: Mean duration of idle periods before session resumption.
19. `subflow_fwd_bytes`: Total bytes in the primary forward subflow.
20. `subflow_bwd_bytes`: Total bytes in the primary backward subflow.

#### Rung $R_{30}$ (Extended Layer 4 Protocol Metrics)
Adds fine-grained header metrics and push/urgent flags:
21. `fwd_iat_mean_ms`: Forward direction inter-arrival mean.
22. `bwd_iat_mean_ms`: Backward direction inter-arrival mean.
23. `fwd_packets_per_s`: Forward packet rate.
24. `bwd_packets_per_s`: Backward packet rate.
25. `packet_length_min`: Minimum observed packet length.
26. `packet_length_max`: Maximum observed packet length.
27. `fwd_header_length`: Total forward IP/TCP header bytes.
28. `bwd_header_length`: Total backward IP/TCP header bytes.
29. `psh_count`: TCP PUSH flag count.
30. `urg_count`: TCP URGENT flag count.

---

## 2. Empirical Benchmark Evaluation Across Rungs

We evaluated Random Forest (100 estimators) and XGBoost (100 estimators, max_depth=6) across the rungs on CICIDS2017 holdout test sets:

| Feature Rung | Feature Count | RF Test F1 | RF Latency (ms) | XGB Test F1 | XGB Latency (ms) | Live Scapy Compatible? | UNSW-NB15 Compatible? |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **$R_4$** | 4 | 0.9124 | 22.4 ms | 0.9240 | 0.18 ms | Yes | **Yes (Native)** |
| **$R_{10}$ (Champion)** | **10** | **0.9745** | **47.2 ms** | **0.9749** | **0.24 ms** | **Yes** | No (Missing Flags/Std) |
| **$R_{15}$** | 15 | 0.9782 | 68.5 ms | 0.9791 | 0.31 ms | Yes | No |
| **$R_{20}$** | 20 | 0.9805 | 89.1 ms | 0.9812 | 0.39 ms | No (Subflow limits) | No |
| **$R_{30}$** | 30 | 0.9821 | 134.7 ms | 0.9830 | 0.52 ms | No (High memory) | No |

### Key Findings
1. **Diminishing Returns Beyond $R_{10}$:** Moving from $R_4$ to $R_{10}$ yields a massive **+6.2% F1 gain** (from 0.9124 to 0.9745) because TCP flag ratios instantly expose SYN floods, port scans, and reset attacks.
2. **Marginal Improvement Beyond $R_{10}$:** Expanding from $R_{10}$ to $R_{30}$ gains only **+0.76% F1** (0.9745 to 0.9821) while tripling computational memory overhead and breaking live Scapy real-time streaming compatibility.
3. **Architectural Justification for Decision D-002:** $R_{10}$ represents the optimal Pareto frontier between detection efficacy, TreeSHAP explainability speed, and real-time live packet streaming.
