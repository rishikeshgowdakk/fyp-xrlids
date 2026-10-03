# XRL-IDARS — Demonstration & Live Replay Verification Report

## 1. Executive Summary
- **Run Timestamp (UTC):** `2026-10-03T13:46:58.233401+00:00`
- **Source Traffic (PCAP):** `data/demo/sample_traffic.pcap`
- **Model Identifier:** `results/experiments/EXP-P1-CIC2017-R10-001`
- **Research Reporting Baseline Threshold:** `0.5` (Frozen for literature comparability)
- **Proposed Phase 2 Operational Candidate Threshold:** `0.4` (Proposed policy parameter)
- **Total Ingested Packets:** `42`
- **Completed Network Flows:** `6`
- **Evaluated Labeled Flows:** `6`

## 2. Classification Performance Comparison

### 2.1 Research Baseline Threshold ($\\tau_{\\text{research}} = 0.50$)
| | Predicted Benign | Predicted Attack | Total |
|---|---|---|---|
| **Actual Benign** | 3 (TN) | 0 (FP) | 3 |
| **Actual Attack** | 1 (FN) | 2 (TP) | 3 |
| **Total** | 4 | 2 | 6 |

- **Accuracy:** `0.8333` (83.33%)
- **Precision:** `1.0000` (100.00%)
- **Recall (TPR):** `0.6667` (66.67%)
- **F1-Score:** `0.8000`
- **False Positive Rate (FPR):** `0.0000` (0.00%)
- **False Negative Rate (FNR):** `0.3333` (33.33%)

### 2.2 Proposed Phase 2 Operational Candidate ($\\tau_{\\text{ops}} = 0.40$)
> *Note: $\\tau_{\\text{ops}}=0.40$ is a proposed operational policy parameter for Phase 2 autonomous response, not an empirically selected optimum.*

| | Predicted Benign | Predicted Attack | Total |
|---|---|---|---|
| **Actual Benign** | 3 (TN) | 0 (FP) | 3 |
| **Actual Attack** | 0 (FN) | 3 (TP) | 3 |
| **Total** | 3 | 3 | 6 |

- **Accuracy:** `1.0000` (100.00%)
- **Precision:** `1.0000` (100.00%)
- **Recall (TPR):** `1.0000` (100.00%)
- **F1-Score:** `1.0000`
- **False Positive Rate (FPR):** `0.0000` (0.00%)
- **False Negative Rate (FNR):** `0.0000` (0.00%)

## 3. Flow-Level Inspection & Threshold Sensitivity

| Flow ID | Protocol | Source Endpoint | Destination Endpoint | Packets | Dur (ms) | Score | Truth | Pred ($\tau=0.50$) | Pred ($\tau_{\text{ops}}=0.40$) |
|---|---|---|---|---|---|---|---|---|---|
| 1 | TCP | 192.168.1.50:45000 | 142.250.190.46:80 | 8 | 220.0 | `0.1438` | BENIGN | **BENIGN** (`CORRECT`) | **BENIGN** (`CORRECT`) |
| 2 | TCP | 192.168.1.50:49152 | 104.16.132.229:443 | 6 | 115.0 | `0.1230` | BENIGN | **BENIGN** (`CORRECT`) | **BENIGN** (`CORRECT`) |
| 3 | TCP | 10.0.0.99:45123 | 192.168.1.10:80 | 8 | 2.1 | `0.5080` | ATTACK | **ATTACK** (`CORRECT`) | **ATTACK** (`CORRECT`) |
| 4 | TCP | 10.0.0.99:45124 | 192.168.1.10:80 | 9 | 1032.0 | `0.5399` | ATTACK | **ATTACK** (`CORRECT`) | **ATTACK** (`CORRECT`) |
| 5 | TCP | 10.0.0.99:45125 | 192.168.1.10:80 | 9 | 400.0 | `0.4692` | ATTACK | **BENIGN** (`INCORRECT`) | **ATTACK** (`CORRECT`) |
| 6 | UDP | 192.168.1.50:51234 | 8.8.8.8:53 | 2 | 25.0 | `0.0001` | BENIGN | **BENIGN** (`CORRECT`) | **BENIGN** (`CORRECT`) |

### 3.1 Threshold Sensitivity Analysis on Sample Flow #5
- **Flow #5 Score**: `0.4692` (model posterior estimate / tree ensemble vote fraction).
- **Research Baseline ($\\tau = 0.50$)**: `0.4692 < 0.50` -> Predicted as **BENIGN** (`INCORRECT` / False Negative relative to attack ground truth).
- **Proposed Operational Candidate ($\\tau_{\\text{ops}} = 0.40$)**: `0.4692 >= 0.40` -> Predicted as **ATTACK** (`CORRECT` / True Positive).
- **Operational Insight**: This demonstrates the asymmetric trade-off under decision gate D-003. Shifting threshold below 0.50 captures borderline attack patterns that evade fixed neutral boundaries.

## 4. Verification & Operational Contracts
- **R10 Semantic Feature Parity:** Streaming flow accumulator produces exact 10 R10 features matching canonical definitions within `atol <= 1e-4`.
- **D-003 Threshold Governance:** Research baseline frozen at 0.50; operational threshold selection remains open pending deployment-specific cost matrix.
- **D-006 Flow Completion Policy:** Flow aggregation enforced at 120.0s idle timeout or TCP FIN/RST packet.
- **Safety Guarantee:** Pure observational execution; zero firewall modifications or network mutations.
