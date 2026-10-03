# XRL-IDARS — Demonstration & Live Replay Verification Report

## 1. Executive Summary
- **Run Timestamp (UTC):** `2026-10-03T01:13:38.329956+00:00`
- **Source Traffic (PCAP):** `data/demo/sample_traffic.pcap`
- **Model Identifier:** `results/experiments/EXP-P1-CIC2017-R10-001`
- **Decision Threshold (D-003):** `0.5`
- **Total Ingested Packets:** `42`
- **Completed Network Flows:** `6`
- **Evaluated Labeled Flows:** `6`

## 2. Classification Performance

### 2.1 Confusion Matrix
| | Predicted Benign | Predicted Attack | Total |
|---|---|---|---|
| **Actual Benign** | 3 (TN) | 0 (FP) | 3 |
| **Actual Attack** | 1 (FN) | 2 (TP) | 3 |
| **Total** | 4 | 2 | 6 |

### 2.2 Core Detection Metrics
- **Accuracy:** `0.8333` (83.33%)
- **Precision:** `1.0000` (100.00%)
- **Recall (TPR):** `0.6667` (66.67%)
- **F1-Score:** `0.8000`
- **False Positive Rate (FPR):** `0.0000` (0.00%)
- **False Negative Rate (FNR):** `0.3333` (33.33%)

## 3. Flow-Level Inspection (First 15 Completed Flows)

| Flow ID | Protocol | Source Endpoint | Destination Endpoint | Packets | Duration (ms) | Prediction | Conf | Truth | Verdict |
|---|---|---|---|---|---|---|---|---|---|
| 1 | TCP | 192.168.1.50:45000 | 142.250.190.46:80 | 8 | 220.0 | **BENIGN** | 0.14 | BENIGN | `CORRECT` |
| 2 | TCP | 192.168.1.50:49152 | 104.16.132.229:443 | 6 | 115.0 | **BENIGN** | 0.12 | BENIGN | `CORRECT` |
| 3 | TCP | 10.0.0.99:45123 | 192.168.1.10:80 | 8 | 2.1 | **ATTACK** | 0.51 | ATTACK | `CORRECT` |
| 4 | TCP | 10.0.0.99:45124 | 192.168.1.10:80 | 9 | 1032.0 | **ATTACK** | 0.54 | ATTACK | `CORRECT` |
| 5 | TCP | 10.0.0.99:45125 | 192.168.1.10:80 | 9 | 400.0 | **BENIGN** | 0.47 | ATTACK | `INCORRECT` |
| 6 | UDP | 192.168.1.50:51234 | 8.8.8.8:53 | 2 | 25.0 | **BENIGN** | 0.00 | BENIGN | `CORRECT` |

## 4. Verification & Operational Contracts
- **R10 Semantic Feature Parity:** Completed flows extract exact 10 R10 features.
- **D-003 Decision Contract:** Tested at baseline research threshold 0.50.
- **D-006 Flow Completion Policy:** Flow aggregation enforced at 120s idle timeout or TCP FIN/RST packet.
- **Safety Guarantee:** Pure observational execution; no system packet interception or firewall mutation.
