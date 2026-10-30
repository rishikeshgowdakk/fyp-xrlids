# XRL-IDARS — Feature Engineering & Parity Contracts

**Document ID:** `DOC-ML-FEATURES-001`  
**Version:** 1.0.0  
**Status:** COMPLETE & AUTHORITATIVE  
**Date:** October 30, 2026  

---

## 1. The Canonical R10 Feature Contract

The primary feature set for XRL-IDARS consists of **10 deterministic features** derived from bidirectional network flows:

| # | Feature Name | Description | Mathematical Formulation | Unit | Value Range |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `flow_duration_ms` | Flow lifespan from first to last packet | $(t_{\text{latest}} - t_{\text{first}}) \times 1000.0$ | Milliseconds | $[0.0, \infty)$ |
| 2 | `flow_packets_per_s`| Flow packet throughput rate | $N_{\text{total}} / \max(d_s, 0.001)$ | Packets/sec | $[0.0, \infty)$ |
| 3 | `flow_bytes_per_s` | Flow byte throughput rate | $B_{\text{total}} / \max(d_s, 0.001)$ | Bytes/sec | $[0.0, \infty)$ |
| 4 | `packet_length_mean`| Average packet length | $\frac{1}{N} \sum_{i=1}^N l_i$ | Bytes | $[0.0, 65535.0]$ |
| 5 | `packet_length_std` | Population standard deviation ($\text{ddof}=0$)| $\sqrt{\frac{1}{N} \sum_{i=1}^N (l_i - \mu)^2}$ | Bytes | $[0.0, 65535.0]$ |
| 6 | `syn_count` | Binary SYN flag indicator | $\min(\text{syn\_packets}, 1.0)$ | Binary | $\{0.0, 1.0\}$ |
| 7 | `ack_count` | Binary ACK flag indicator | $\min(\text{ack\_packets}, 1.0)$ | Binary | $\{0.0, 1.0\}$ |
| 8 | `rst_count` | Binary RST flag indicator | $\min(\text{rst\_packets}, 1.0)$ | Binary | $\{0.0, 1.0\}$ |
| 9 | `fin_count` | Binary FIN flag indicator | $\min(\text{fin\_packets}, 1.0)$ | Binary | $\{0.0, 1.0\}$ |
| 10 | `syn_ack_ratio` | Ratio of SYN to ACK packets with smoothing | $\frac{N_{\text{syn}} + 1.0}{N_{\text{ack}} + 1.0}$ | Ratio | $(0.0, \infty)$ |

---

## 2. Sensor-Degraded R4 Feature Contract (UNSW-NB15)

For low-resource edge sensors and datasets lacking detailed TCP flag statistics (such as UNSW-NB15), XRL-IDARS provides the **R4 feature contract**:
1. `flow_duration_ms`
2. `flow_packets_per_s`
3. `flow_bytes_per_s`
4. `packet_length_mean`

---

## 3. Critical Offline vs. Live Feature Parity Corrections

### 1. TCP Flag Binary Mapping vs. Packet Counting
- **The Defect**: In CICFlowMeter CSV datasets, columns such as `SYN Flag Cnt` and `ACK Flag Cnt` represent **binary indicators** ($\in \{0, 1\}$). However, live Scapy packet counters accumulate every packet with a flag set ($> 100$).
- **Impact**: Feeding a count of $100$ into a scaler with $\mu = 0.08, \sigma = 0.82$ produced an out-of-distribution anomaly of **$+121\sigma$**, corrupting tree splits.
- **The Fix**: Enforced exact binary indicator mapping:
  $$\text{flag\_indicator} = \min(\text{flag\_packet\_count}, 1.0)$$
- **Verification**: Verified by automated parity tests in [`tests/unit/test_r10_flowseq_parity.py`](file:///home/rishikesh/Desktop/fyp-xrlids/tests/unit/test_r10_flowseq_parity.py).

### 2. Population vs. Sample Standard Deviation
- **The Defect**: Using sample standard deviation ($\text{ddof}=1$) causes divide-by-zero on single-packet flows ($N=1$) and produces discrepancies against CICFlowMeter CSVs.
- **The Fix**: Enforced population standard deviation ($\text{ddof}=0$), returning $0.0$ for single-packet flows.
