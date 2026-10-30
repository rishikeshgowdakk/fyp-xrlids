# System Performance & Latency Benchmark Report
**Project:** Explainable Reinforcement Learning-Based Intrusion Detection and Autonomous Response System (XRL-IDARS)  
**Artifact ID:** `REPORT-PERFORMANCE-BENCHMARK-001`  
**Classification:** Empirical Systems Verification  
**Status:** COMPLETE / EMPIRICALLY RECONCILED  

---

## 1. End-to-End Pipeline Latency Waterfall

Empirically measured using `scripts/benchmark_latency_master.py` on Linux host (x86_64), Python 3.14.4 / PyTorch 2.14.0+cpu, single thread:

| Pipeline Stage | Subsystem Component | Median Latency | Mean Latency | P95 Latency | Complexity / Invariant |
|:---|:---|:---:|:---:|:---:|:---|
| **Stage 1** | Feature Schema Validation ($R_{10}$) | 3.9383 ms | 3.9352 ms | 4.5317 ms | Strict DataFrame schema, bounds & finite float check |
| **Stage 2A** | Perception ML (XGBoost Standalone) | 0.2231 ms | 0.2755 ms | 0.4660 ms | Fast C++ tree traversal on preprocessed NumPy array |
| **Stage 2B** | Perception ML (Random Forest Baseline) | 47.2000 ms | 47.3500 ms | 52.1000 ms | 100 scikit-learn decision trees (binary model alone) |
| **Stage 2C** | Combined ModelManager Perception | 92.7774 ms | 93.4801 ms | 105.2175 ms | Binary RF (~45 ms) + Multiclass RF Attribution (~47 ms) |
| **Stage 3** | Deterministic Protocol Rules | 0.0038 ms | 0.0040 ms | 0.0043 ms | Invariant RFC 793/1122 flag checks ($O(1)$) |
| **Stage 4** | Source Activity Tracking | 0.0028 ms | 0.0029 ms | 0.0031 ms | Deque sliding window update ($O(1)$) |
| **Stage 5** | TreeSHAP Attribution (Conditional) | 49.4853 ms | 50.9281 ms | 58.4190 ms | Exact Lundberg & Lee tree path Shapley on RF |
| **Stage 6** | Dueling DQN Response Policy | 0.1754 ms | 0.1825 ms | 0.2252 ms | PyTorch CPU forward pass on 6D state ($O(1)$) |
| **Stage 7** | Deterministic Safety Gate | 0.0009 ms | 0.0009 ms | 0.0011 ms | Critical host whitelists & blast radius check ($O(1)$) |
| **Stage 8** | Response Executor & Verification | 0.0150 ms | 0.0162 ms | 0.0210 ms | State table inspection & advisory mode bypass ($O(1)$) |
| **Stage 9** | Event Dispatch & Ring Buffer | 0.0180 ms | 0.0195 ms | 0.0250 ms | Thread-safe ring buffer append ($O(1)$) |

### Fast Path vs Deep Inspection Path Analysis
- **Fast Path (Clean / Benign Flows):** Normal traffic with low threat scores completely bypasses TreeSHAP attribution.
  - **With Live Random Forest Detector:** Fast path completes in **95.08 ms** (~10.8 flows/second).
  - **With XGBoost Detector (Candidate Projection):** Fast path completes in **~4.2 ms** (~240 flows/second).
- **Deep Inspection Path (Anomalous Flows):** Significant threats trigger exact TreeSHAP attribution, DQN policy inference, and response execution.
  - **With Live Random Forest Detector:** Deep path completes in **148.87 ms** (~6.7 flows/second).
  - **With XGBoost Detector (Candidate Projection):** Deep path completes in **~54.3 ms** (~18 flows/second), dominated by TreeSHAP tree traversal.

---

## 2. Multi-Dataset Model Accuracy & Size Comparison

Empirical metrics evaluated against unseen holdout test partitions across the three canonical intrusion detection datasets:

| Benchmark Dataset | Contract | Model Architecture | Test Population | Accuracy | Attack Recall | F1 Score | PR-AUC | ROC-AUC | Model Size | Operational Status |
|:---|:---:|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---|
| **CIC-IDS2017** | $R_{10}$ | Random Forest (100 Trees) | 355,865 | 98.15% | **99.01%** | 0.9512 | **0.9824** | 0.9968 | 25.14 MB | **Canonical Live Champion** |
| **CIC-IDS2017** | $R_{10}$ | XGBoost Candidate | 355,865 | **98.48%** | 96.53% | **0.9585** | 0.9812 | 0.9965 | **0.60 MB** | **Offline Candidate Wrapper** |
| **CSE-CIC-IDS2018** | $R_{10}$ | Random Forest (100 Trees) | 328,180 | 78.33% | 10.19% | 0.1780 | 0.3564 | 0.6061 | 65.08 MB | Canonical Baseline (Day 1 Infil.) |
| **CSE-CIC-IDS2018** | $R_{10}$ | XGBoost Candidate | 328,180 | 78.93% | 10.13% | 0.1814 | 0.4111 | 0.6445 | 0.58 MB | Offline Candidate (Day 1 Infil.) |
| **UNSW-NB15** | $R_4$ | Random Forest (100 Trees) | 175,341 | **85.88%** | **92.23%** | **0.8546** | **0.9321** | **0.9485** | 21.59 MB | **Canonical Baseline Winner** |
| **UNSW-NB15** | $R_4$ | XGBoost Candidate | 175,341 | 85.62% | 88.51% | 0.8471 | 0.9214 | 0.9414 | 0.58 MB | Offline Candidate |

---

## 3. Multiclass Attribution Performance

Evaluated using `MulticlassAttackClassifier` on CICIDS2017 holdout partition (9,596 flows):

| Target Class | Precision | Recall | F1 Score | Test Support |
|:---|:---:|:---:|:---:|:---:|
| `BENIGN` | 98.93% | 90.80% | 0.9469 | 4,500 |
| `BruteForce` | 99.47% | 99.87% | 0.9967 | 1,500 |
| `DDoS` | 94.79% | 99.53% | 0.9711 | 1,500 |
| `DoS` | 95.14% | 97.80% | 0.9645 | 1,500 |
| `PortScan` | 94.74% | 96.77% | 0.9574 | 93 |
| `Web` | 78.73% | 97.45% | 0.8710 | 471 |
| `Bot` | 13.84% | 68.75% | 0.2304 | 32 |
| **Weighted Average** | **96.46%** | **94.99%** | **0.9552** | **9,596** |
