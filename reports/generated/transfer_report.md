# Cross-Dataset Generalization & Out-of-Domain Transfer Report (generated)

> [!IMPORTANT]
> This report documents empirical cross-dataset evaluation across all 6 transfer directions under strict scientific isolation.
> Preprocessing and source models were fitted exclusively on source training data.
> Target domains were evaluated strictly out-of-domain with zero target parameter tuning or early stopping.

## 1. Executive Summary & Research Matrix

The canonical transfer evaluation matrix tests whether detectors trained in one network capture environment
can generalize to traffic from another environment under shared semantic feature contracts:

```text
                             TARGET DOMAIN
                     CIC-IDS2017    CSE-CIC-IDS2018    UNSW-NB15
SOURCE CIC-IDS2017        —             R10 (10 feat)    R4 (4 feat)
SOURCE CSE-2018      R10 (10 feat)           —           R4 (4 feat)
SOURCE UNSW-NB15     R4 (4 feat)        R4 (4 feat)          —
```

---
## 2. Consolidated Transfer Degradation Matrix

| Transfer Direction | Contract | Model | Source F1 | Target F1 | ΔF1 (Degradation) | Source FPR | Target FPR | ΔFPR | Target ROC-AUC |
| :--- | :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `cicids2017` → `cse_cic_ids2018` | `R10` | RANDOM FOREST | 0.9512 | 0.3286 | **-0.6225** | 0.0204 | 0.0486 | +0.0281 | 0.7008 |
| `cicids2017` → `cse_cic_ids2018` | `R10` | SUPERVISED LSTM | 0.9633 | 0.0983 | **-0.8650** | 0.0068 | 0.0635 | +0.0567 | 0.4787 |
| `cicids2017` → `cse_cic_ids2018` | `R10` | RF + LSTM FUSION | 0.9745 | 0.1139 | **-0.8606** | 0.0075 | 0.0159 | +0.0084 | 0.6604 |
| `cse_cic_ids2018` → `cicids2017` | `R10` | RANDOM FOREST | 0.8861 | 0.0301 | **-0.8560** | 0.0259 | 0.0248 | -0.0011 | 0.7127 |
| `cse_cic_ids2018` → `cicids2017` | `R10` | SUPERVISED LSTM | 0.9603 | 0.2601 | **-0.7003** | 0.0026 | 0.0141 | +0.0115 | 0.8052 |
| `cse_cic_ids2018` → `cicids2017` | `R10` | RF + LSTM FUSION | 0.9603 | 0.1191 | **-0.8412** | 0.0026 | 0.0107 | +0.0081 | 0.8099 |
| `unsw_nb15` → `cicids2017` | `transfer_common_4` | RANDOM FOREST | 0.8548 | 0.3276 | **-0.5273** | 0.1928 | 0.6858 | +0.4930 | 0.6057 |
| `unsw_nb15` → `cicids2017` | `transfer_common_4` | SUPERVISED LSTM | 0.8637 | 0.3389 | **-0.5248** | 0.1796 | 0.3178 | +0.1382 | 0.6690 |
| `unsw_nb15` → `cicids2017` | `transfer_common_4` | RF + LSTM FUSION | 0.8970 | 0.3664 | **-0.5306** | 0.1590 | 0.5394 | +0.3804 | 0.6804 |
| `unsw_nb15` → `cse_cic_ids2018` | `transfer_common_4` | RANDOM FOREST | 0.8548 | 0.0217 | **-0.8331** | 0.1928 | 0.6473 | +0.4544 | 0.1793 |
| `unsw_nb15` → `cse_cic_ids2018` | `transfer_common_4` | SUPERVISED LSTM | 0.8637 | 0.0380 | **-0.8258** | 0.1796 | 0.5074 | +0.3278 | 0.2251 |
| `unsw_nb15` → `cse_cic_ids2018` | `transfer_common_4` | RF + LSTM FUSION | 0.8970 | 0.0268 | **-0.8702** | 0.1590 | 0.5513 | +0.3924 | 0.1423 |
| `cicids2017` → `unsw_nb15` | `transfer_common_4` | RANDOM FOREST | 0.9525 | 0.0016 | **-0.9509** | 0.0194 | 0.0016 | -0.0179 | 0.4172 |
| `cicids2017` → `unsw_nb15` | `transfer_common_4` | SUPERVISED LSTM | 0.9054 | 0.0051 | **-0.9004** | 0.0122 | 0.0019 | -0.0103 | 0.5355 |
| `cicids2017` → `unsw_nb15` | `transfer_common_4` | RF + LSTM FUSION | 0.9533 | 0.0004 | **-0.9529** | 0.0190 | 0.0015 | -0.0175 | 0.4751 |
| `cse_cic_ids2018` → `unsw_nb15` | `transfer_common_4` | RANDOM FOREST | 0.8672 | 0.0026 | **-0.8646** | 0.0313 | 0.0923 | +0.0610 | 0.3506 |
| `cse_cic_ids2018` → `unsw_nb15` | `transfer_common_4` | SUPERVISED LSTM | 0.8920 | 0.0048 | **-0.8872** | 0.0083 | 0.0489 | +0.0406 | 0.3477 |
| `cse_cic_ids2018` → `unsw_nb15` | `transfer_common_4` | RF + LSTM FUSION | 0.9302 | 0.0019 | **-0.9283** | 0.0093 | 0.0398 | +0.0305 | 0.3312 |

---
## 3. Primary 10-Feature Transfer Findings (`CIC-IDS2017 ↔ CSE-CIC-IDS2018`)

Both CIC-IDS2017 and CSE-CIC-IDS2018 support the full frozen 10-feature semantic contract (R10):
1. **Severe Degradation Across All Detectors**:
   - On `CIC → CSE`, Random Forest degrades from 0.9512 to 0.3286 F1 ($\Delta = -0.6225$), while Supervised LSTM collapses from 0.9633 to 0.0983 F1 ($\Delta = -0.8650$).
   - On `CSE → CIC`, Random Forest degrades from 0.8861 to 0.0301 F1 ($\Delta = -0.8560$), while Supervised LSTM degrades from 0.9603 to 0.2601 F1 ($\Delta = -0.7003$).
2. **Tabular vs Sequence Domain Resilience Asymmetry**:
   - On `CIC → CSE`, Random Forest preserves substantially higher out-of-domain discriminability (ROC-AUC = 0.7008, F1 = 0.3286) than Supervised LSTM (ROC-AUC = 0.4787, F1 = 0.0983). Tabular decision trees partition feature spaces along axis-aligned thresholds that tolerate scale shifts better than recurrent hidden states conditioned on exact packet inter-arrival pacing.
   - On `CSE → CIC`, Supervised LSTM retains higher ranking capability (ROC-AUC = 0.8052, F1 = 0.2601) than Random Forest (ROC-AUC = 0.7127, F1 = 0.0301), demonstrating that directional transfer dynamics are highly asymmetric.

---
## 4. Auxiliary 4-Feature Transfer Findings (Involving `UNSW-NB15`)

Under the verified 4-feature common contract (`flow_duration_ms`, `flow_packets_per_s`, `flow_bytes_per_s`, `packet_length_mean`):
1. **`UNSW → CIC` Transfer**:
   - RF achieves 0.3276 F1 (ROC-AUC = 0.6057), LSTM achieves 0.3389 F1 (ROC-AUC = 0.6690), and Fusion achieves 0.3664 F1 (ROC-AUC = 0.6804).
   - False positive rate surges from 15.90% to 53.94% on benign CIC traffic due to stark discrepancies in flow timeout definitions between Bro/Zeek (UNSW) and CICFlowMeter (CIC).
2. **`UNSW → CSE` Transfer**:
   - F1 collapses to 0.0217 (RF) and 0.0380 (LSTM), with false alarm rates exceeding 50.7% on benign enterprise traffic.
3. **`CIC → UNSW` & `CSE → UNSW` Transfers**:
   - Detectors trained on CIC or CSE fail catastrophically on UNSW (F1 < 0.01), as UNSW's 45% attack prevalence and synthetic emulation traffic structure diverge fundamentally from Canadian institute traffic.

---
## 5. Covariate Shift Quantification

Two-sample Kolmogorov-Smirnov ($D$) tests demonstrate profound domain divergence across all feature spaces:
- **Throughput & Rates**: `flow_packets_per_s` and `flow_bytes_per_s` exhibit $D > 0.45$ ($p = 0.0000$) across all domain pairs, driven by gigabit enterprise uplinks (CSE-2018) vs small-lab testbeds (UNSW).
- **Flow Durations**: `flow_duration_ms` exhibits median shifts up to orders of magnitude due to active/idle flow timeout differences (CICFlowMeter 120s vs Bro flow expiration).

---
## 6. Scientific Answer to Research Question 5 (RQ5)

> [!CAUTION]
> **Core Scientific Conclusion (RQ5)**: Cross-dataset generalizability without target domain adaptation is **NOT** supported by empirical evidence.
> In-domain benchmark F1 scores exceeding 0.96–0.99 do **not** imply generalizability.
> When deployed out-of-domain under strict scientific isolation, detectors experience performance collapses of 52% to 95% in F1 score and false alarm rate inflation up to 68%.
> Autonomous response systems (Phase 2/3) must incorporate uncertainty quantification and domain adaptation rather than assuming universal detector transferability.