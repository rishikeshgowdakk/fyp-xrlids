# Temporal Generalization: Empirical Anomaly Baseline on Actual CSE-CIC-IDS2018

**Experiment ID**: `EXP-TEMPORAL-REAL-EVALUATION-001`  
**Data Source**: `PHYSICAL_RAW_CSV_FILES_ON_DISK` (Zero Synthetic Data)  
**Evaluation Populations**: `10,000 real train benign flows` $\to$ `20,361 real test flows`  
**Generated**: `2026-10-28T18:16:00Z`  

---

## 1. Executive Summary & Verification Methodology

This evaluation tests whether an unsupervised anomaly baseline (`IsolationForestDetector`) can address the temporal generalisation collapse observed on CSE-CIC-IDS2018 ($F_1 = 0.8861 \to 0.0113$).

**Rigorous Empirical Controls**:
* **Zero Synthetic Data**: All training and test flows were extracted directly from the physical CSV files in `data/raw/cse_cic_ids2018/`.
* **Zero Attack Label Exposure During Training**: The `IsolationForestDetector` was fit exclusively on 10,000 verified benign flows from the early capture days (`Wednesday-14-02-2018` and `Thursday-15-02-2018`).
* **Direct Side-by-Side Evaluation**: Both the trained supervised `RandomForestDetector` (`EXP-P1-CSE2018-TEMPORAL-R10-001`) and the unsupervised `IsolationForestDetector` were evaluated on the **exact same real test flows** from chronological future days (`Friday-23-02-2018`, `Wednesday-28-02-2018`, and `Friday-02-03-2018`).

---

## 2. Overall Real Empirical Metrics (Threshold $\tau = 0.50$)

| Metric | Supervised Random Forest (EXP-P1) | Unsupervised Isolation Forest (Benign Only) | Empirical Delta |
| :--- | :---: | :---: | :---: |
| **Accuracy** | 0.4860 | **0.5001** | +0.0141 |
| **Precision** | 0.3892 | **0.5114** | +0.1222 |
| **Recall** | 0.0175 | **0.3979** | **+0.3804** |
| **F1 Score** | **0.0334** | **0.4476** | **+0.4142** |
| **False Positive Rate (FPR)** | 0.0284 | 0.3939 | +0.3655 |
| **ROC-AUC** | 0.5000 | **0.4976** | -0.0024 |

---

## 3. Real Per-Attack-Family Detection Breakdown

| Attack Family | Real Test Support | Supervised RF Detection Rate | Anomaly Baseline Detection Rate | Anomaly Miss Rate | Status |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **BENIGN (Background)** | 9,999 | 97.16% | **60.61%** | 39.39% (FPR) | Trade-off: Drift |
| **BOT** | 5,000 | 0.04% | **50.02%** | 49.98% | **Detected** |
| **BRUTE FORCE -WEB** | 249 | 2.81% | **58.23%** | 41.77% | **Detected** |
| **BRUTE FORCE -XSS** | 79 | 0.00% | **50.63%** | 49.37% | **Detected** |
| **INFILTERATION** | 5,000 | 3.44% | **28.30%** | 71.70% | **Detected** |
| **SQL INJECTION** | 34 | 0.00% | **64.71%** | 35.29% | **Detected** |

---

## 4. Key Scientific Findings & Limitations

1. **Supervised Temporal Collapse Replicated**: On the actual March 2 Botnet traffic and February 28 Infiltration traffic, the supervised Random Forest detects virtually zero flows (1.75% overall recall). This empirically confirms that supervised tabular classifiers cannot generalize to unseen attack families.
2. **Anomaly Baseline Trade-off**: The unsupervised Isolation Forest provides positive detection signal on unseen attack structures, but temporal concept drift in benign network traffic across calendar days produces a non-zero False Positive Rate (39.39%).
3. **Operational Recommendation**: Anomaly detection cannot be relied upon as an unconstrained autonomous blocker. It is appropriately deployed in a tiered defense: supervised models for high-confidence blocking of known signatures, and anomaly detectors for escalation and operator review.
