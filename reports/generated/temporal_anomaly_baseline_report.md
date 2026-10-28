# Temporal Generalization: Anomaly Detection Baseline Report

**Experiment ID**: `EXP-TEMPORAL-ANOMALY-BASELINE-001`  
**Dataset**: `CSE-CIC-IDS2018` (Strict Chronological Future Holdout)  
**Evaluated Model**: `IsolationForestDetector` (Unsupervised, Fit on Benign Baseline Only)  
**Reference Model**: `RandomForestDetector` (`EXP-P1-CSE2018-TEMPORAL-R10-001`, Supervised)  
**Generated**: `2026-10-28T17:44:09Z`  

---

## 1. Executive Summary & Research Question

This benchmark directly addresses **Milestone 1**: resolving the temporal detection collapse on CSE-CIC-IDS2018 where the supervised Random Forest fell from $F_1 = 0.8861$ down to $F_1 = 0.0113$ on chronological holdout days.

**Methodological Invariant**:
The `IsolationForestDetector` was trained **exclusively on benign flows** ($y = 0$) from the early capture period (`2018-02-14` to `2018-02-20`). It received zero exposure to attack labels or signatures during fitting. It was then evaluated on unseen future attack families from the later period (`2018-02-22` to `2018-03-02`).

---

## 2. Overall Performance Comparison (Threshold $\tau = 0.50$)

| Metric | Supervised Random Forest (EXP-P1) | Unsupervised Anomaly Baseline (Isolation Forest) | Empirical Delta |
| :--- | :---: | :---: | :---: |
| **Accuracy** | 0.9633 | 0.9641 | +0.0008 |
| **Precision** | 0.0332 | 0.3884 | +0.3552 |
| **Recall** | 0.0068 | 0.2685 | **+0.2617** |
| **F1 Score** | **0.0113** | **0.3175** | **+0.3062** |
| **False Positive Rate (FPR)** | 0.0063 | 0.0136 | +0.0073 |
| **ROC-AUC** | 0.3905 | 0.7742 | +0.3837 |

---

## 3. Per-Attack-Family Detection Breakdown

| Attack Family | Support | Supervised RF Detection Rate | Anomaly Baseline Detection Rate | Anomaly Miss Rate | Status |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **BOT (Ares Botnet)** | 186 | 0.09% | **65.05%** | 34.95% | **Significant Gain** |
| **INFILTERATION** | 426 | 0.94% | **8.69%** | 91.31% | **Moderate Gain** |
| **WEB_ATTACKS** | 10 | 0.00% | **90.00%** | 10.00% | **Detected** |
| **BENIGN (Background)** | 19,383 | 99.37% (Specificity) | **98.64%** | 1.36% (FPR) | Trade-off observed |

---

## 4. Scientific Findings & Honest Limitations

1. **Unseen Attack Generalization**: The unsupervised anomaly detector successfully flags structural deviations in unseen attack families (such as Ares botnet beaconing), which completely eluded the supervised Random Forest.
2. **False Positive Trade-off**: Anomaly detection inherently incurs a higher baseline False Positive Rate than supervised tree ensembles on complex background enterprise traffic.
3. **Architectural Recommendation**: The anomaly baseline should NOT completely replace supervised models. Instead, an asymmetric ensemble architecture is recommended:
   - **Supervised Random Forest / LSTM**: Low-FPR filtering of known, high-confidence volumetric attack signatures.
   - **Unsupervised Anomaly Detector**: Low-threshold escalation / alerting on zero-day deviations for human-in-the-loop triage.
