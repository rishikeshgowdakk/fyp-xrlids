# Cross-Dataset Feature Availability Matrix
**Project:** Explainable Reinforcement Learning-Based Intrusion Detection and Autonomous Response System (XRL-IDARS)  
**Artifact ID:** `MATRIX-FEATURE-AVAILABILITY-001`  
**Classification:** Scientific Contract and Data Lineage Reference  
**Status:** FROZEN & VERIFIED  

---

## 1. Overview & Non-Fabrication Mandate

In accordance with project engineering principles, **no missing feature may ever be synthetically fabricated or silently zero-imputed** to force model transfer. If a dataset lacks the raw packet signals required to compute a semantic field, that feature is reported as **UNAVAILABLE**.

---

## 2. Comprehensive Feature Availability Table

The following matrix documents the exact status of candidate features across all three benchmark datasets and the live Scapy sniffer:

| Semantic Feature | CIC-IDS2017 | CSE-CIC-IDS2018 | UNSW-NB15 | Live Scapy Sniffer | Contract Rung | Rationale / Derivation |
|:---|:---:|:---:|:---:|:---:|:---:|:---|
| `flow_duration_ms` | Available | Available | Available | Available | $R_4, R_{10}, R_{15}, R_{20}, R_{30}$ | Microseconds $\times 10^{-3}$ in CIC/CSE; `dur` $\times 10^3$ in UNSW |
| `flow_packets_per_s` | Available | Available | Available | Available | $R_4, R_{10}, R_{15}, R_{20}, R_{30}$ | `Total Packets / Duration (sec)` |
| `flow_bytes_per_s` | Available | Available | Available | Available | $R_4, R_{10}, R_{15}, R_{20}, R_{30}$ | `Total Bytes / Duration (sec)` |
| `packet_length_mean` | Available | Available | Available | Available | $R_4, R_{10}, R_{15}, R_{20}, R_{30}$ | `Packet Length Mean` or `(sbytes+dbytes)/(spkts+dpkts)` |
| `packet_length_std` | Available | Available | **UNAVAILABLE** | Available | $R_{10}, R_{15}, R_{20}, R_{30}$ | Requires individual packet length variance (absent in UNSW flow summary) |
| `syn_count` | Available | Available | **UNAVAILABLE** | Available | $R_{10}, R_{15}, R_{20}, R_{30}$ | TCP SYN flag counts (absent in UNSW NetFlow export) |
| `ack_count` | Available | Available | **UNAVAILABLE** | Available | $R_{10}, R_{15}, R_{20}, R_{30}$ | TCP ACK flag counts (absent in UNSW NetFlow export) |
| `rst_count` | Available | Available | **UNAVAILABLE** | Available | $R_{10}, R_{15}, R_{20}, R_{30}$ | TCP RST flag counts (absent in UNSW NetFlow export) |
| `fin_count` | Available | Available | **UNAVAILABLE** | Available | $R_{10}, R_{15}, R_{20}, R_{30}$ | TCP FIN flag counts (absent in UNSW NetFlow export) |
| `syn_ack_ratio` | Available | Available | **UNAVAILABLE** | Available | $R_{10}, R_{15}, R_{20}, R_{30}$ | `syn_count / max(ack_count, 1)` |
| `flow_iat_mean_ms` | Available | Available | **UNAVAILABLE** | Available | $R_{15}, R_{20}, R_{30}$ | Mean packet inter-arrival time |
| `flow_iat_std_ms` | Available | Available | **UNAVAILABLE** | Available | $R_{15}, R_{20}, R_{30}$ | Dispersion of packet inter-arrival times |
| `down_up_ratio` | Available | Available | Available | Available | $R_{15}, R_{20}, R_{30}$ | `bwd_packets / max(fwd_packets, 1)` |
| `fwd_packet_length_mean` | Available | Available | Available | Available | $R_{15}, R_{20}, R_{30}$ | Forward direction packet size mean |
| `bwd_packet_length_mean` | Available | Available | Available | Available | $R_{15}, R_{20}, R_{30}$ | Backward direction packet size mean |
| `flow_bytes_per_packet` | Available | Available | Available | Available | $R_{20}, R_{30}$ | `total_bytes / max(total_packets, 1)` |
| `active_mean_ms` | Available | Available | **UNAVAILABLE** | Limited | $R_{20}, R_{30}$ | Requires tool-specific flow segmentation |
| `idle_mean_ms` | Available | Available | **UNAVAILABLE** | Limited | $R_{20}, R_{30}$ | Requires tool-specific flow segmentation |
| `subflow_fwd_bytes` | Available | Available | **UNAVAILABLE** | **UNAVAILABLE** | $R_{20}, R_{30}$ | Tool-specific opening subflow volume |
| `subflow_bwd_bytes` | Available | Available | **UNAVAILABLE** | **UNAVAILABLE** | $R_{20}, R_{30}$ | Tool-specific opening subflow volume |

---

## 3. UNSW-NB15 Segregation Rationale

As demonstrated above, **6 of the 10 canonical $R_{10}$ features cannot be derived from published UNSW-NB15 flow records without raw PCAP re-extraction**.
Therefore:
- **Decision D-002** locks the primary cross-dataset enterprise contract to **$R_{10}$** between **CIC-IDS2017** and **CSE-CIC-IDS2018**.
- **UNSW-NB15** is maintained strictly as an **auxiliary benchmark under contract $R_4$**, preventing model cross-contamination and scientifically invalid feature imputations.
