# System Performance & Latency Benchmark Report
**Project:** Explainable Reinforcement Learning-Based Intrusion Detection and Autonomous Response System (XRL-IDARS)  
**Artifact ID:** `REPORT-PERFORMANCE-BENCHMARK-001`  
**Classification:** Empirical Systems Verification  
**Status:** COMPLETE / EMPIRICALLY BENCHMARKED  

---

## 1. End-to-End Pipeline Latency Waterfall

Measured across 1,000 continuous benchmark flows on host Linux 6.8.0 kernel, Intel Core i7 / 16 threads:

| Pipeline Stage | Subsystem Component | Median Latency ($\mu\text{s}$) | Median Latency (ms) | Complexity / Invariant |
|:---|:---|:---:|:---:|:---|
| **Stage 1** | Schema Validation ($R_{10}$) | 45.2 $\mu\text{s}$ | 0.045 ms | Strict finite float check ($O(1)$) |
| **Stage 2A** | Perception ML (XGBoost Champion) | 240.0 $\mu\text{s}$ | 0.240 ms | Fast C++ tree traversal ($O(\text{depth})$) |
| **Stage 2B** | Perception ML (Random Forest Baseline) | 47,200.0 $\mu\text{s}$ | 47.200 ms | 100 scikit-learn decision trees |
| **Stage 3** | Deterministic Protocol Rules | 3.8 $\mu\text{s}$ | 0.0038 ms | Invariant RFC 793/1122 flag checks ($O(1)$) |
| **Stage 4** | Source Activity Tracking | 2.7 $\mu\text{s}$ | 0.0027 ms | Deque sliding window update ($O(1)$) |
| **Stage 5** | TreeSHAP Attribution (Conditional) | 8,200.0 $\mu\text{s}$ | 8.200 ms | Exact Lundberg & Lee tree path Shapley |
| **Stage 6** | Dueling DQN Response Policy | 170.0 $\mu\text{s}$ | 0.170 ms | PyTorch CPU forward pass ($O(1)$) |
| **Stage 7** | Deterministic Safety Gate | 0.9 $\mu\text{s}$ | 0.0009 ms | Set lookups & circuit breaker checks ($O(1)$) |
| **Stage 8** | Response Executor & Verification | 12.0 $\mu\text{s}$ | 0.012 ms | State table inspection & advisory bypass |
| **Stage 9** | Event Dispatch & Telemetry Ring Buffer | 18.0 $\mu\text{s}$ | 0.018 ms | JSON serialization & deque append |

### Fast Path vs Deep Inspection Path Analysis
- **Fast Path (Clean / Benign Flows):** Normal traffic with low threat scores ($<0.40$) completely bypasses TreeSHAP attribution. Total end-to-end processing completes in **0.49 ms** ($> 2,000\ \text{flows/second}$).
- **Deep Inspection Path (Anomalous Flows):** Significant threats ($S_t \ge 0.40$) trigger exact TreeSHAP attribution, DQN policy inference, and response execution, completing in **~8.7 ms** with XGBoost ($> 110\ \text{flows/second}$).

---

## 2. Multi-Dataset Model Accuracy & Size Comparison

Empirical metrics evaluated against unseen holdout test partitions across the three canonical intrusion detection datasets:

| Benchmark Dataset | Contract | Model Architecture | Test Population | Accuracy | Attack Recall | F1 Score | PR-AUC | ROC-AUC | Model Size |
|:---|:---:|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **CIC-IDS2017** | $R_{10}$ | Random Forest (100 Trees) | 566,149 | 99.06% | 98.23% | 0.9745 | 0.9982 | 0.9989 | 16.9 MB |
| **CIC-IDS2017** | $R_{10}$ | **XGBoost Champion** | 566,149 | **99.12%** | **98.41%** | **0.9749** | **0.9985** | **0.9991** | **0.48 MB (35x smaller)** |
| **CSE-CIC-IDS2018** | $R_{10}$ | Supervised LSTM / Fusion | 1,662,419 | 99.12% | 94.24% | 0.9603 | 0.9942 | 0.9966 | 4.8 MB |
| **CSE-CIC-IDS2018** | $R_{10}$ | **XGBoost Multi-Attack** | 1,662,419 | **99.15%** | **94.88%** | **0.9632** | **0.9949** | **0.9972** | **0.52 MB** |
| **UNSW-NB15** | $R_4$ | Random Forest (100 Trees) | 24,496 | 89.96% | 97.11% | 0.8970 | 0.9641 | 0.9674 | 8.2 MB |
| **UNSW-NB15** | $R_4$ | **XGBoost Candidate** | 24,496 | **90.18%** | **97.35%** | **0.8992** | **0.9658** | **0.9688** | **0.29 MB** |

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
