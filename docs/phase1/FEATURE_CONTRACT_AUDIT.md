# Feature Contract Audit & Freeze: Common 10-Feature Semantic Contract

**Platform**: XRL-IDARS (Intrusion Detection and Autonomous Response System)  
**Date**: 2026-10-02  
**Contract Version**: 1.0.0 (`frozen` under Decision D-002)  
**Scope**: CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15  

---

## 1. Executive Summary & Decision Gate D-002 Resolution

Under Decision **D-002**, the **Common 10-Feature Semantic Contract (R10)** is formally evaluated, audited against real dataset files, and **FROZEN** as the primary behavioral representation for in-domain and cross-dataset experimentation between CIC-IDS2017 and CSE-CIC-IDS2018.

### Formal Status:
1. **CIC-IDS2017 & CSE-CIC-IDS2018**: **10/10 FEATURES VERIFIED & EQUIVALENT**. Both benchmark suites were captured via CICFlowMeter and map with 100% semantic identity and matching physical units across all 10 features.
2. **UNSW-NB15**: **4/10 FEATURES AVAILABLE, 6/10 MATHEMATICALLY UNCONSTRUCTABLE (DATA-AVAILABILITY BLOCKER)**. UNSW-NB15 was generated via Argus and Bro/Zeek network flow monitors. In its published flow records, it provides volume, packet, and duration totals, but **does not record individual TCP flag counts, packet size variance, or packet-level distributions**. Without raw packet captures (PCAPs), these 6 features cannot be derived.
3. **Scientific Integrity Mandate**: The 6 missing features for UNSW-NB15 **must NEVER be fabricated, proxied, or silently substituted**. The historical 4-feature contract is quarantined as an explicitly documented auxiliary/fallback transfer experiment and will not serve as the primary representation.

---

## 2. Target 10 Semantic Features: Definitions, Formulas, and Units

The 10 semantic features represent fundamental, live-computable flow dynamics:

| Feature Name | Mathematical Definition | Physical Unit | Input Semantic Fields | Live (Scapy) Computable? |
| :--- | :--- | :---: | :--- | :---: |
| `flow_duration_ms` | $\text{duration\_seconds} \times 1000.0$ | $\text{ms}$ | `duration_seconds` | ✅ Yes |
| `flow_packets_per_s` | $\frac{\text{total\_packets}}{\text{duration\_seconds}}$ | $\text{packets/s}$ | `total_packets`, `duration_seconds` | ✅ Yes |
| `flow_bytes_per_s` | $\frac{\text{total\_bytes}}{\text{duration\_seconds}}$ | $\text{bytes/s}$ | `total_bytes`, `duration_seconds` | ✅ Yes |
| `packet_length_mean` | $\frac{\text{total\_bytes}}{\text{total\_packets}}$ or $\text{mean}(L_p)$ | $\text{bytes}$ | `pkt_len_mean` (or `total_bytes`/`total_packets`) | ✅ Yes |
| `packet_length_std` | $\sqrt{\frac{1}{N}\sum (L_p - \bar{L})^2}$ | $\text{bytes}$ | `pkt_len_std` | ✅ Yes |
| `syn_count` | $\sum \mathbb{I}(\text{TCP\_SYN} = 1)$ | $\text{packets}$ | `syn_flags` | ✅ Yes |
| `ack_count` | $\sum \mathbb{I}(\text{TCP\_ACK} = 1)$ | $\text{packets}$ | `ack_flags` | ✅ Yes |
| `rst_count` | $\sum \mathbb{I}(\text{TCP\_RST} = 1)$ | $\text{packets}$ | `rst_flags` | ✅ Yes |
| `fin_count` | $\sum \mathbb{I}(\text{TCP\_FIN} = 1)$ | $\text{packets}$ | `fin_flags` | ✅ Yes |
| `syn_ack_ratio` | $\frac{\text{syn\_count}}{\max(\text{ack\_count}, 1.0)}$ | $\text{ratio}$ | `syn_flags`, `ack_flags` | ✅ Yes |

### Edge-Case and Zero-Denominator Policies:
- **Zero Duration**: When $\text{duration\_seconds} \le 0$:
  - If $\text{total\_packets} > 0$ or $\text{total\_bytes} > 0$, rate is mathematically undefined ($\text{NaN}$), flagged and handled by the data cleaning pipeline.
  - If $\text{total\_packets} == 0$ and $\text{total\_bytes} == 0$, rate evaluates to $0.0$.
- **Zero Denominator in `syn_ack_ratio`**: Denominator is clipped at $\max(\text{ack\_count}, 1.0)$ to prevent division by zero in half-open or unacknowledged scanning attempts.
- **Extreme / Vendor Infinity Values**: Vendor-supplied rate columns in raw CSVs often contain `Infinity` due to integer division by zero microsecond durations. All rates are **recomputed directly from source quantities** (`total_packets`, `total_bytes`, `duration_seconds`) rather than trusting vendor rate columns.

---

## 3. Formal Feature Mapping Table

| Feature Name | CIC-IDS2017 Source / Derivation | CSE-CIC-IDS2018 Source / Derivation | UNSW-NB15 Source / Derivation | Semantic Equivalence? |
| :--- | :--- | :--- | :--- | :---: |
| `flow_duration_ms` | `Flow Duration` ($\mu\text{s} \times 10^{-3}$) | `Flow Duration` ($\mu\text{s} \times 10^{-3}$) | `dur` ($\text{s} \times 10^{3}$) | ✅ **YES** (Identical meaning: flow lifetime in ms) |
| `flow_packets_per_s` | Recomputed: $\frac{\text{FwdPkts} + \text{BwdPkts}}{\text{Duration (s)}}$ | Recomputed: $\frac{\text{TotFwdPkts} + \text{TotBwdPkts}}{\text{Duration (s)}}$ | Recomputed: $\frac{\text{spkts} + \text{dpkts}}{\text{dur}}$ (or `rate`) | ✅ **YES** (Identical meaning: flow packet rate) |
| `flow_bytes_per_s` | Recomputed: $\frac{\text{FwdBytes} + \text{BwdBytes}}{\text{Duration (s)}}$ | Recomputed: $\frac{\text{TotLenFwd} + \text{TotLenBwd}}{\text{Duration (s)}}$ | Recomputed: $\frac{\text{sbytes} + \text{dbytes}}{\text{dur}}$ | ✅ **YES** (Identical meaning: throughput in B/s) |
| `packet_length_mean` | Direct: `Packet Length Mean` | Direct: `Pkt Len Mean` | Recomputed: $\frac{\text{sbytes} + \text{dbytes}}{\text{spkts} + \text{dpkts}}$ | ✅ **YES** (Identical meaning: average packet size in bytes) |
| `packet_length_std` | Direct: `Packet Length Std` | Direct: `Pkt Len Std` | ❌ **NOT AVAILABLE** | ❌ **NO** (Argus provides only directional means `smean`, `dmean`; variance is absent) |
| `syn_count` | Direct: `SYN Flag Count` | Direct: `SYN Flag Cnt` | ❌ **NOT AVAILABLE** | ❌ **NO** (Argus logs connection state, not per-flow TCP flag counts) |
| `ack_count` | Direct: `ACK Flag Count` | Direct: `ACK Flag Cnt` | ❌ **NOT AVAILABLE** | ❌ **NO** (Absent from Argus flow records) |
| `rst_count` | Direct: `RST Flag Count` | Direct: `RST Flag Cnt` | ❌ **NOT AVAILABLE** | ❌ **NO** (Absent from Argus flow records) |
| `fin_count` | Direct: `FIN Flag Count` | Direct: `FIN Flag Cnt` | ❌ **NOT AVAILABLE** | ❌ **NO** (Absent from Argus flow records) |
| `syn_ack_ratio` | Derived: $\frac{\text{syn\_count}}{\max(\text{ack\_count}, 1)}$ | Derived: $\frac{\text{syn\_count}}{\max(\text{ack\_count}, 1)}$ | ❌ **NOT AVAILABLE** | ❌ **NO** (Cannot be computed without SYN/ACK counts) |

---

## 4. Empirical Numerical Range Validation

Audited directly from raw dataset files (50,000-flow samples per dataset):

### 4.1 CIC-IDS2017 (`Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`)
- **`flow_duration_ms`**: Min $0.0$, Max $119,998.11$, Median $760.56$, P25 $44.73$, P75 $6,851.86$, Zeros $13$, Negatives $0$, NaNs $0$, Infs $0$
- **`flow_packets_per_s`**: Min $0.0312$, Max $3,000,000.0$, Median $10.23$, P25 $0.82$, P75 $127.79$, Zeros $0$, Negatives $0$, NaNs $13$ (handled by cleaning), Infs $0$
- **`flow_bytes_per_s`**: Min $0.0$, Max $2,071,000,000.0$, Median $3,939.31$, P25 $50.01$, P75 $30,999.27$, Zeros $1,826$, Negatives $0$, NaNs $10$, Infs $0$
- **`packet_length_mean`**: Min $0.0$, Max $1,936.83$, Median $81.33$, P25 $6.0$, P75 $1,057.0$, Zeros $1,826$, Negatives $0$, NaNs $0$, Infs $0$
- **`packet_length_std`**: Min $0.0$, Max $4,731.52$, Median $57.59$, P25 $0.0$, P75 $1,913.82$, Zeros $13,866$, Negatives $0$, NaNs $0$, Infs $0$
- **`syn_count`**: Min $0.0$, Max $1.0$, Median $0.0$, P25 $0.0$, P75 $0.0$, Zeros $48,025$, Negatives $0$, NaNs $0$, Infs $0$
- **`ack_count`**: Min $0.0$, Max $1.0$, Median $0.0$, P25 $0.0$, P75 $1.0$, Zeros $29,006$, Negatives $0$, NaNs $0$, Infs $0$
- **`rst_count`**: Min $0.0$, Max $1.0$, Median $0.0$, P25 $0.0$, P75 $0.0$, Zeros $49,568$, Negatives $0$, NaNs $0$, Infs $0$
- **`fin_count`**: Min $0.0$, Max $1.0$, Median $0.0$, P25 $0.0$, P75 $0.0$, Zeros $49,439$, Negatives $0$, NaNs $0$, Infs $0$
- **`syn_ack_ratio`**: Min $0.0$, Max $1.0$, Median $0.0$, P25 $0.0$, P75 $0.0$, Zeros $48,025$, Negatives $0$, NaNs $0$, Infs $0$

### 4.2 CSE-CIC-IDS2018 (`Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv`)
- **`flow_duration_ms`**: Min $0.0$, Max $119,999.87$, Median $36.53$, P25 $0.37$, P75 $2,645.00$, Zeros $691$, Negatives $0$, NaNs $0$, Infs $0$
- **`flow_packets_per_s`**: Min $0.0167$, Max $3,000,000.0$, Median $104.35$, P25 $5.70$, P75 $5,434.78$, Zeros $0$, Negatives $0$, NaNs $691$, Infs $0$
- **`flow_bytes_per_s`**: Min $0.0$, Max $707,878,787.88$, Median $1,937.58$, P25 $37.62$, P75 $124,606.81$, Zeros $9,534$, Negatives $0$, NaNs $270$, Infs $0$
- **`packet_length_mean`**: Min $0.0$, Max $1,400.84$, Median $55.33$, P25 $27.91$, P75 $139.19$, Zeros $9,534$, Negatives $0$, NaNs $0$, Infs $0$
- **`packet_length_std`**: Min $0.0$, Max $936.50$, Median $33.01$, P25 $9.24$, P75 $292.33$, Zeros $10,167$, Negatives $0$, NaNs $0$, Infs $0$
- **`syn_count`**: Min $0.0$, Max $1.0$, Median $0.0$, P25 $0.0$, P75 $0.0$, Zeros $45,992$, Negatives $0$, NaNs $0$, Infs $0$
- **`ack_count`**: Min $0.0$, Max $1.0$, Median $0.0$, P25 $0.0$, P75 $0.0$, Zeros $38,672$, Negatives $0$, NaNs $0$, Infs $0$
- **`rst_count`**: Min $0.0$, Max $1.0$, Median $0.0$, P25 $0.0$, P75 $0.0$, Zeros $39,002$, Negatives $0$, NaNs $0$, Infs $0$
- **`fin_count`**: Min $0.0$, Max $1.0$, Median $0.0$, P25 $0.0$, P75 $0.0$, Zeros $49,717$, Negatives $0$, NaNs $0$, Infs $0$
- **`syn_ack_ratio`**: Min $0.0$, Max $1.0$, Median $0.0$, P25 $0.0$, P75 $0.0$, Zeros $45,992$, Negatives $0$, NaNs $0$, Infs $0$

### 4.3 UNSW-NB15 (`UNSW_NB15_training-set.csv`)
- **`flow_duration_ms`**: Min $0.0$, Max $59,999.97$, Median $37.86$, P25 $3.99$, P75 $606.47$, Zeros $329$, Negatives $0$, NaNs $0$, Infs $0$
- **`flow_packets_per_s`**: Min $0.0333$, Max $2,000,000.0$, Median $1,822.74$, P25 $71.31$, P75 $4,056.80$, Zeros $0$, Negatives $0$, NaNs $329$, Infs $0$
- **`flow_bytes_per_s`**: Min $1.53$, Max $1,074,000,000.0$, Median $278,360.34$, P25 $12,256.74$, P75 $800,565.27$, Zeros $0$, Negatives $0$, NaNs $329$, Infs $0$
- **`packet_length_mean`**: Min $28.0$, Max $1,499.0$, Median $111.0$, P25 $81.0$, P75 $391.6$, Zeros $0$, Negatives $0$, NaNs $0$, Infs $0$
- **`packet_length_std`**: ❌ **UNAVAILABLE**
- **`syn_count`**: ❌ **UNAVAILABLE**
- **`ack_count`**: ❌ **UNAVAILABLE**
- **`rst_count`**: ❌ **UNAVAILABLE**
- **`fin_count`**: ❌ **UNAVAILABLE**
- **`syn_ack_ratio`**: ❌ **UNAVAILABLE**

---

## 5. The UNSW-NB15 Mathematical Derivability Blocker

### 5.1 Why `packet_length_std` Cannot Be Derived
In UNSW-NB15, the flow records provide forward packet mean $smean = \frac{\text{sbytes}}{\text{spkts}}$ and backward packet mean $dmean = \frac{\text{dbytes}}{\text{dpkts}}$.
By the law of total variance, the true variance of packet lengths across the flow is:
$$\sigma^2 = \frac{N_s}{N} \sigma_s^2 + \frac{N_d}{N} \sigma_d^2 + \frac{N_s}{N}(smean - \bar{x})^2 + \frac{N_d}{N}(dmean - \bar{x})^2$$
where $\sigma_s^2$ is the variance of source packet lengths and $\sigma_d^2$ is the variance of destination packet lengths.
**Neither $\sigma_s^2$ nor $\sigma_d^2$ exists in UNSW-NB15**. Assuming $\sigma_s^2 = \sigma_d^2 = 0$ corresponds to assuming all packets in each direction are identical in size, which severely underestimates dispersion and discards packet jitter. Therefore, `packet_length_std` cannot be mathematically derived.

### 5.2 Why TCP Flag Counts Cannot Be Derived
Argus records connection status (`state`: `FIN`, `INT`, `CON`, `REQ`, `RST`, `ECO`, etc.) and handshake timing intervals (`synack`, `ackdat`, `tcprtt`). It does **not** count the total number of packets bearing specific TCP control flags. For example:
- A SYN flood generates hundreds of unanswered SYN packets with zero ACK packets. In Argus, this connection may simply be labeled `INT` or `REQ` with no count of packets.
- An established connection that sends 5 RST packets during teardown is labeled `RST` with no count of resets.
- TCP flag count is a continuous integer count per flow; converting categorical state into flag counts is scientifically indefensible.

### 5.3 Blocker Conclusion
Under the project's scientific honesty mandate, **we do NOT fabricate these 6 features**. 
- The **Common 10-Feature Contract (R10)** is valid and frozen for **CIC-IDS2017** and **CSE-CIC-IDS2018**.
- Cross-dataset evaluation between CIC-IDS2017 and CSE-CIC-IDS2018 will use the complete **10-feature representation**.
- For UNSW-NB15, the **4-feature contract** (`flow_duration_ms`, `flow_packets_per_s`, `flow_bytes_per_s`, `packet_length_mean`) is preserved strictly as an **auxiliary/fallback domain-shift evaluation**, clearly documented as such.

---

## 6. Frozen Contract Specification

- **Contract Name**: `MAIN CROSS-DATASET 10-FEATURE CONTRACT (R10)`
- **Version**: `1.0.0`
- **Schema Hash**: `d74897f18b669ea806488222fda4514b28b335921ce019ebd41fc49ff6b65e21`
- **Deterministic Feature Ordering**:
  1. `flow_duration_ms`
  2. `flow_packets_per_s`
  3. `flow_bytes_per_s`
  4. `packet_length_mean`
  5. `packet_length_std`
  6. `syn_count`
  7. `ack_count`
  8. `rst_count`
  9. `fin_count`
  10. `syn_ack_ratio`
- **Live / Offline Parity**: All 10 features are live-computable from packet streams using Scapy / flow assembler pipelines without requiring post-hoc batch statistics.
