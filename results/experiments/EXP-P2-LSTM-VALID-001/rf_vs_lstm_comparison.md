# Empirical Head-to-Head Comparison: Random Forest vs. Valid Chronological LSTM

**Experiment ID:** EXP-P2-LSTM-VALID-001  
**Project:** XRL-IDARS (Final Year Engineering Project)  
**Evaluator:** Senior ML Systems Engineer & Network Security Researcher  
**Date:** 2026-10-30  
**Dataset:** CSE-CIC-IDS2018 (Tuesday 20-02-2018, LOIC-HTTP Flood)  
**Evaluation Scope:** Strictly Common Evaluation Population (8,726 held-out chronological test sequences)  

---

## 1. Experimental Integrity & Evaluation Setup

To eliminate historical methodological flaws (such as pseudo-sequences built from randomly permuted rows), both models were trained and evaluated on **authentic, host-isolated, chronological data**:
- **Sequence Construction**: $K=5$ flows grouped strictly by source host (`host_id`), ordered monotonically by flow start timestamp (`ts`).
- **Session Boundary Reset**: Gaps $> 300.0\,\text{s}$ flushed the host sequence buffer.
- **Common Evaluation Population**: Exactly 8,726 test sequences.
  - The **Random Forest** evaluated the current 5th flow's tabular R10 feature vector ($X \in \mathbb{R}^{10}$).
  - The **Temporal LSTM** evaluated the complete causal 5-flow sequence matrix ($X \in \mathbb{R}^{5 \times 11}$) including the inter-flow arrival delta ($\Delta t$).
- **Strict Leakage Prevention**: `StandardScaler` fitted strictly on Train split flows. Attacker hosts 27, 28, and 29 (`18.218.11.51`, `18.219.32.43`, `18.218.115.60`) were **strictly isolated to the held-out test split** to test true unseen attacker generalization.

---

## 2. Multi-Dimensional Performance Comparison Matrix

| Evaluation Dimension | Metric | Random Forest (Primary Operational) | Temporal LSTM (Sequence Model) | Delta ($\text{LSTM} - \text{RF}$) | Scientific Interpretation |
| :--- | :--- | :---: | :---: | :---: | :--- |
| **Classification Quality** | **Accuracy** | $99.72\%$ | **$99.95\%$** | $+0.23\%$ | Both models achieve near-perfect classification on volumetric DDoS flows. |
| | **Precision** | $99.77\%$ | **$100.00\%$** | $+0.23\%$ | LSTM eliminated false alarms on the test sequences. |
| | **Recall** | $99.77\%$ | **$99.92\%$** | $+0.15\%$ | High detection sensitivity on both models. |
| | **F1-Score** | $0.9977$ | **$0.9996$** | **$+0.0019$ (+0.19%)** | Incremental gain of $0.19\%$ (16 additional flows out of 8,726). |
| | **Macro-F1** | $0.9971$ | **$0.9995$** | $+0.0024$ | Balanced performance across both benign and attack classes. |
| **Threshold Independence** | **PR-AUC** | $0.9999$ | **$1.0000$** | $+0.0001$ | Both models exhibit near-ideal separation boundaries. |
| | **ROC-AUC** | $0.9999$ | **$1.0000$** | $+0.0001$ | Negligible difference in area under ROC curve. |
| **Error Rates** | **False Positive Rate (FPR)** | $0.35\%$ | **$0.00\%$** | $-0.35\%$ | LSTM achieves zero false alarms on the evaluated test set. |
| | **False Negative Rate (FNR)**| $0.23\%$ | **$0.08\%$** | $-0.15\%$ | Both models miss fewer than 0.25% of attack instances. |
| **Generalization** | **Unseen Attacker Host F1** | $0.9987$ | **$0.9996$** | $+0.0008$ | Both models generalize exceptionally to unseen AWS attacker subnets. |
| **Operational Feasibility** | **Single-Sample Latency** | **$0.80\,\text{ms}$** | $0.38\,\text{ms}$ (model pass) | $-0.42\,\text{ms}$ (model only) | **Caveat**: LSTM model pass is fast, but sequence buffer management adds memory & locking overhead. |
| | **Warm-up Dependency** | **ZERO flows** (Immediate on flow 1) | **5 completed flows** | $+4$ flows blindness | **CRITICAL FLAW**: LSTM cannot detect single-flow or low-volume attacks (bursts $< 5$). |
| | **Explainability** | **Exact TreeSHAP** | Causal Hidden State (Opaque) | Opaque decision boundary | RF provides exact feature attributions; LSTM requires gradient approximations. |
| | **Cross-Dataset Viability** | **100% of Datasets** (CIC-2017, CSE-2018, UNSW) | **1 single day** (Tuesday 2018) | Inapplicable to 16/17 attack families | LSTM cannot be trained on CIC-IDS2017 or UNSW-NB15 due to missing IPs/timestamps. |

---

## 3. Flagship Research Question Answer

> **"Does a properly trained LSTM add meaningful, reproducible value over the existing RF detector in XRL-IDARS?"**

### **Definitive Scientific Answer: NO.**

While a properly trained LSTM achieves a mathematically valid F1-score of **$0.9996$** (compared to Random Forest's **$0.9977$**), it does **not** provide meaningful operational value that justifies replacing, delaying, or ensembling with Random Forest.

### Key Justifications:
1. **Marginal Incremental Gain ($+0.19\%$ F1)**:
   Random Forest already achieves $99.77\%$ F1 and $99.99\%$ PR-AUC on tabular flow features alone. The $0.19\%$ F1 increase from the LSTM accounts for only 16 additional flows correctly identified out of 8,726.
2. **Warm-Up Blindness ($K < 5$)**:
   The LSTM requires 5 completed flows from the same source host before it can produce a prediction. For stealthy scans, micro-bursts, or initial exploit attempts ($1 \to 4$ flows), the LSTM produces `None`. Random Forest provides instant detection on the very first packet flow.
3. **Stateful Resource & Attack Surface Overhead**:
   Maintaining active per-host sequence buffers exposes the NIDS to state-exhaustion memory exhaustion under volumetric spoofing attacks.
4. **Severe Dataset Ineligibility Across the Literature**:
   Only 1 day of 1 benchmark dataset (Tuesday 20-02-2018) contains the network identifiers and timestamps required for sequence modeling. The LSTM cannot be validated on the remaining 16 attack families in the project's canonical attack taxonomy.

---

## 4. Final Architectural Recommendation: Outcome B (RF-Only Operational Detector)

- **Random Forest is certified as the sole primary operational detector.**
- **RF-LSTM score fusion remains permanently removed.**
- The LSTM model checkpoint (`lstm_flowseq_best.pt`) and evaluation artifacts are preserved in `results/experiments/EXP-P2-LSTM-VALID-001/` for academic traceability and thesis defense.
- The operational pipeline continues to run proudly, safely, and deterministically on Random Forest alone.
