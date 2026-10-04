# Controlled vs. Unseen Traffic: Methodological Taxonomy

**Document Identifier**: `DOC-P3-TRAFFIC-TAXONOMY-001`  
**Purpose**: Strict methodological boundary separating data tiers in Phase 3 evaluation  
**Status**: `ACTIVE METHODOLOGICAL CONTRACT`  

---

## 1. Rationale & Epistemological Boundaries

A critical vulnerability in network intrusion detection research is the careless conflation of different traffic sources. Claiming "high detection accuracy" on live campus or enterprise traffic without independent ground-truth verification is scientifically invalid. Similarly, evaluating models on replayed PCAP files cannot be equated with verifying real-time packet-processing throughput under physical interface buffer constraints.

To prevent invalid scientific claims, this document formalizes the **eight distinct traffic tiers** recognized in XRL-IDARS. Under no circumstances may empirical results or performance metrics from one category be combined with or substituted for another.

---

## 2. Taxonomy of Traffic Tiers

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        XRL-IDARS TRAFFIC TIERS                         │
├────────────────────────────────────────────────────────────────────────┤
│ 1. In-Domain Training Population (D_train)                             │
│ 2. In-Domain Validation Population (D_val)                             │
│ 3. Held-Out In-Domain Test Population (D_test / D_pol_test)            │
│ 4. Cross-Dataset Transfer Population (CSE-CIC-IDS2018 / UNSW-NB15)    │
│ 5. Synthetic Unit Traffic (Programmatic Packet Vectors)                │
│ 6. Deterministic PCAP Replay (Time-Stamped Recorded Traffic)           │
│ 7. Controlled Lab Packet Burst ("1000 Packets from One Click")         │
│ 8. Genuinely Live Physical Traffic (Raw Interface Ingestion)           │
└────────────────────────────────────────────────────────────────────────┘
```

### Tier 1: In-Domain Training Population ($D_{\text{train}}$)
- **Source**: Designated 60% training partition of CIC-IDS2017 (Policy A feature-deduplicated split).
- **Role**: Parameter optimization for Phase 1 Random Forest and LSTM detectors.
- **Allowed Metrics**: Training loss, convergence curve, training fit.
- **Forbidden**: Any reporting of generalization or operational efficacy.

### Tier 2: In-Domain Validation Population ($D_{\text{val}}$)
- **Source**: Designated 20% validation partition of CIC-IDS2017. Partitioned into $D_{\text{pol\_train}}$ (60%) and $D_{\text{pol\_val}}$ (40%) during Phase 2.
- **Role**: Hyperparameter tuning, threshold sweep, and RL response policy training.
- **Allowed Metrics**: Validation AUC, ECE calibration loss, policy reward optimization.

### Tier 3: Held-Out In-Domain Test Population ($D_{\text{test}}$ / $D_{\text{pol\_test}}$)
- **Source**: Designated 20% held-out partition of CIC-IDS2017 (355,865 tabular flows). Strictly quarantined until final freeze.
- **Role**: Single authoritative evaluation of detector accuracy (Phase 1) and response policy operational cost (Phase 2).
- **Allowed Metrics**: Precision, Recall, Macro F1, Cumulative Cost, ACI, FQR.

### Tier 4: Cross-Dataset Transfer Population
- **Source**: Full multi-file populations of CSE-CIC-IDS2018 (8.31M rows) and UNSW-NB15 (122K rows).
- **Role**: Empirical measurement of domain shift degradation (RQ5) and out-of-domain safety bounds (RQ7.2).
- **Allowed Metrics**: Transfer degradation ($\Delta \text{F1}$), False Quarantine Rate under domain shift.
- **Forbidden**: Assuming in-domain performance transfers without domain adaptation.

### Tier 5: Synthetic Unit Traffic
- **Source**: Programmatically generated `PacketInfo` sequences with deterministic flags, timestamps, and payload sizes.
- **Role**: Unit testing of flow builder, state accumulator, corner-case handling (zero duration, flag combinations), and feature parity verification ($\text{atol} \le 10^{-4}$).
- **Forbidden**: Quoting accuracy, latency, or throughput figures as representative of operational networks.

### Tier 6: Deterministic PCAP Replay
- **Source**: Packet capture files (`.pcap`) recorded from controlled lab or benchmark environments replayed through `PcapReader`.
- **Role**: Timing-controlled end-to-end pipeline verification (Phase 2A baseline demonstration, reproducible regression tests).
- **Distinction**: Packet inter-arrival times are derived from packet header timestamps ($t_{\text{hdr}}$), not real wall-clock arrival.

### Tier 7: Controlled Lab Packet Burst
- **Source**: Controlled local packet generation (e.g., local loopback or isolated veth interface) injecting a pre-registered attack burst ("1000 packets from one click").
- **Role**: End-to-end validation of real interface capture, socket buffer draining, flow completion under D-006, detector inference, safety gate intervention, and dry-run audit card generation.
- **Distinction**: Ground truth is known *by experimental construction*, enabling controlled true positive / false positive accounting.

### Tier 8: Genuinely Live Physical Traffic
- **Source**: Real network interface (e.g., Ethernet or Wi-Fi interface) carrying unmanaged ambient network traffic.
- **Role**: Real-world stress testing of socket ingress, parser robustness against malformed frames, and background false-positive monitoring.
- **Strict Ground-Truth Invariant (§64)**:
  > **Live predictions CANNOT be reported as "accuracy", "precision", or "recall" without independently verified ground-truth flow labeling.**
  > On live traffic, the system may report strictly:
  > - Packets and bytes ingested
  > - Flows assembled and completed
  > - Inference latency (P50, P95, P99)
  > - End-to-end throughput (flows/s, pkts/s)
  > - Action distribution (fraction of ALLOW, ALERT, RATE_LIMIT, ISOLATE)
  > - Safety gate override frequency
  > - System error and drop counters

---

## 3. Methodological Compliance Rules

1. **No Conflation**: An evaluation report must state the exact traffic tier in its header.
2. **Ground-Truth Honesty**: Any claim of detection accuracy on Tier 8 (live traffic) without third-party forensic packet labeling is an immediate scientific violation.
3. **Reproducibility Guarantee**: All Phase 3 assertions of feature parity or response behavior must be reproducible using Tier 5 (synthetic) and Tier 6 (PCAP replay) test artifacts committed to the repository.
