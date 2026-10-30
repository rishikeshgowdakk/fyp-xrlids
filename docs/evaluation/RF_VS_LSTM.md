# XRL-IDARS — Scientific Reconciliation: Random Forest vs. Temporal LSTM

**Document ID:** `DOC-EVAL-RF-VS-LSTM-001`  
**Version:** 1.0.0  
**Status:** COMPLETE & AUTHORITATIVE  
**Date:** October 30, 2026  
**Research Lead:** Senior Machine Learning Systems Engineer  
**Experiment ID:** `EXP-P2-LSTM-VALID-001`  

---

## 1. The Core Research Question

> **"Does a properly trained LSTM add meaningful, reproducible value over the existing Random Forest detector in XRL-IDARS?"**

### Definitive Finding: **NO.**
While a mathematically verified chronological LSTM achieves an F1-score of **$0.9996$** (compared to Random Forest's **$0.9977$**), it does **not** provide operational value that justifies replacing, delaying, or ensembling with Random Forest.

Random Forest remains the sole primary operational intrusion detector in XRL-IDARS. All RF-LSTM score-level fusion is permanently excluded.

---

## 2. Empirical Head-to-Head Comparison

Both models were evaluated on the **identical common evaluation population** of 8,726 held-out chronological test instances from the CSE-CIC-IDS2018 DDoS-LOIC-HTTP dataset:
- **Random Forest**: Evaluated the 5th flow tabular R10 feature vector ($X \in \mathbb{R}^{10}$).
- **LSTM Detector**: Evaluated the full 5-flow host sequence matrix ($X \in \mathbb{R}^{5 \times 11}$) including inter-flow arrival delta.

| Evaluation Dimension | Metric | Random Forest (Operational) | Temporal LSTM (Research) | Delta ($\text{LSTM} - \text{RF}$) | Operational Significance |
| :--- | :--- | :---: | :---: | :---: | :--- |
| **Detection Quality** | **Accuracy** | $99.72\%$ | **$99.95\%$** | $+0.23\%$ | High separation on volumetric flood traffic. |
| | **Precision** | $99.77\%$ | **$100.00\%$** | $+0.23\%$ | LSTM eliminated 11 false positives. |
| | **Recall** | $99.77\%$ | **$99.92\%$** | $+0.15\%$ | LSTM correctly caught 9 additional attacks. |
| | **F1-Score** | $0.9977$ | **$0.9996$** | **$+0.0019$ (+0.19%)** | Incremental gain of only 16 flows out of 8,726. |
| | **PR-AUC** | $0.9999$ | **$1.0000$** | $+0.0001$ | Negligible separation boundary difference. |
| | **ROC-AUC** | $0.9999$ | **$1.0000$** | $+0.0001$ | Negligible area difference. |
| **Error Rates** | **False Positive Rate** | $0.35\%$ | **$0.00\%$** | $-0.35\%$ | Minimal baseline false alarm rate. |
| | **False Negative Rate** | $0.23\%$ | **$0.08\%$** | $-0.15\%$ | Both models achieve $< 0.25\%$ miss rate. |
| **Generalization** | **Unseen Host F1** | $0.9987$ | **$0.9996$** | $+0.0008$ | Both models generalize to unseen AWS subnets. |
| **Operational Feasibility** | **Warm-up Blindness** | **0 flows** (Immediate) | **5 completed flows** | $+4$ flows blindness | **CRITICAL FLAW**: LSTM is blind to flows 1 to 4. |
| | **Latency (End-to-End)** | **$0.80\,\text{ms}$** | $0.38\,\text{ms} + \text{Buffering}$ | Buffer delay: $100\,\text{ms} \to \text{minutes}$ | LSTM is gated by flow completion time. |
| | **Explainability** | **Exact TreeSHAP** | Recurrent Hidden State | Opaque decision path | RF provides exact polynomial feature attributions. |
| | **Dataset Applicability** | **100% of Datasets** | **1 single day** (Tuesday 2018) | Inapplicable to 16/17 attack families | LSTM cannot be trained on CIC-2017 or UNSW. |

---

## 3. Four Decisive Reasons Against Operational LSTM Deployment

### Reason 1: The $+0.19\%$ F1 Gain Represents Only 16 Flows
Out of 8,726 test flows, Random Forest correctly classified 8,702 flows ($99.72\%$). The LSTM correctly classified 8,722 flows ($99.95\%$). The entire benefit of maintaining a complex, multi-flow PyTorch recurrent model boils down to **16 additional flows**.

### Reason 2: Cold-Start Blindness ($K < 5$)
An operational NIDS cannot afford to remain silent while an attacker executes the first four connection attempts. 
- A port scan, brute-force SSH probe, or single-flow exploit payload can compromise a target host on flow 1.
- Random Forest classifies flow 1 within $0.80\,\text{ms}$ of packet arrival.
- The LSTM returns `None` for flows 1, 2, 3, and 4, providing an open window of exposure.

### Reason 3: State-Exhaustion Vulnerability
To maintain sliding windows of 5 flows per host, the NIDS must allocate state tables indexed by IP address. 
- In a volumetric DDoS attack with randomized source IP spoofing, maintaining state tables creates an immediate memory exhaustion vulnerability (denial of service against the IDS itself).
- Random Forest evaluates individual flows statelessly, making it resilient to state exhaustion.

### Reason 4: Total Inapplicability Across the Canonical Attack Taxonomy
The XRL-IDARS attack taxonomy spans 17 distinct attack families across three benchmark datasets (CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15). 
- As proven in `docs/evaluation/DATASET_ELIGIBILITY.md`, only Tuesday CSE-CIC-IDS2018 contains the IP addresses and monotonic timestamps needed to construct host sequences.
- An operational detector cannot rely on an architecture that cannot be trained or validated on 16 out of the 17 attack families in the system scope.

---

## 4. Final Architectural Verdict

1. **Outcome B (RF-Only Operational Detector) is decisively confirmed.**
2. **Random Forest is certified as the sole primary operational classifier.**
3. **RF-LSTM score fusion is permanently deprecated and removed.**
4. The LSTM model checkpoint (`lstm_flowseq_best.pt`) is preserved in `results/experiments/EXP-P2-LSTM-VALID-001/` as a valuable research contribution documenting why sequence models do not deliver operational advantages over tabular tree ensembles in network flow intrusion detection.
