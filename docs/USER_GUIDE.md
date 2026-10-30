# XRL-IDARS — Operator & User Guide

**Document ID:** `DOC-USER-GUIDE-001`  
**Version:** 1.0.0  
**Status:** COMPLETE & AUTHORITATIVE  
**Date:** October 30, 2026  

---

## 1. Overview & Launching the Dashboard

XRL-IDARS provides an integrated, browser-based graphical console for monitoring live network flows, inspecting explainable AI detections, and auditing autonomous defense actions.

### Starting the Server:
```bash
.venv/bin/python scripts/demo/run_dashboard.py 8000
```
Open any modern web browser at: **`http://localhost:8000`**

![Full Dashboard Live View](file:///home/rishikesh/Desktop/fyp-xrlids/docs/images/01_full_dashboard_live.png)

---

## 2. Dashboard Navigation & Primary Views

### 1. Live Telemetry & System Header
The top navigation bar displays real-time operational status:
- **Pipeline State**: `RUNNING`, `PAUSED`, or `STOPPED`.
- **Packet Throughput**: Packets per second (pps) and flows per second (fps).
- **Operational Detector**: `Random Forest (R10 Contract)`.
- **Response Safety Mode**: `ADVISORY / DRY_RUN` (ensuring zero uncommanded firewall mutations).

### 2. Live Flow Table
Displays each completed network flow in chronological order:
- **Timestamp**: Microsecond flow completion time.
- **5-Tuple Endpoints**: Source IP/Port $\to$ Destination IP/Port and Transport Protocol.
- **Volume**: Packet count, total bytes, and duration.
- **ML Score**: Calibrated attack probability $P(\text{attack}) \in [0.0, 1.0]$.
- **Classification**: `BENIGN` (Green pill) or `ATTACK` (Red pill).
- **Explain Button**: Clicking the "Explain" button opens the local TreeSHAP attribution waterfall.

### 3. TreeSHAP Attribution Modal
When an alert is clicked, the dashboard renders an interactive Lundberg waterfall chart:
- **Base Value ($\phi_0$)**: Expected dataset attack probability ($0.500$).
- **Positive Drivers (Red Bars)**: Features pushing the flow toward an attack classification (e.g., elevated `syn_count`, high `flow_packets_per_s`).
- **Negative Drivers (Blue Bars)**: Features pulling the flow toward benign behavior (e.g., normal `packet_length_std`, high `flow_duration_ms`).

![Analysis and Evidence View](file:///home/rishikesh/Desktop/fyp-xrlids/docs/images/03_analysis_and_evidence.png)

### 4. Score Provenance Modal
For research traceability, operators can inspect the multi-model score provenance modal:
- Shows the primary operational **Random Forest** score.
- Displays the experimental **Temporal LSTM** sequence score ($T=5$).
- Documents why the system selects Random Forest as the definitive operational classification.

![Score Provenance Modal](file:///home/rishikesh/Desktop/fyp-xrlids/docs/images/02_score_provenance_modal.png)

### 5. Autonomous Response Policy & Safety Gate Log
When an alert is confirmed, the response console details:
- **DQN Proposed Action**: Proactive recommendation (`RATE_LIMIT`, `QUARANTINE_IP`, `DEEP_INSPECTION`, or `NO_ACTION`).
- **Safety Gate Verdict**: `APPROVED` or `OVERRIDDEN`.
- **Override Reason**: Detailed rule triggering the override (e.g., `CRITICAL_HOST_ALLOWLIST`, `COOLDOWN_ACTIVE: 18 steps remaining`, `BLAST_RADIUS_LIMIT_EXCEEDED`).
- **Enforced Advisory Action**: Logged dry-run mitigation action.

### 6. Cross-Benchmark & Evaluation Workbench
Operators can evaluate external flow records against frozen models across all three benchmark suites (CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15).

![Cross Benchmark Comparison](file:///home/rishikesh/Desktop/fyp-xrlids/docs/images/04_cross_benchmark_comparison.png)
