# XRL-IDARS — Known Issues, Technical Debt & Historical Resolutions

**Document ID:** `DOC-FINAL-KNOWN-ISSUES-001`  
**Version:** 1.0.0  
**Status:** COMPLETE & AUTHORITATIVE  
**Date:** October 30, 2026  

---

## 1. Resolved Historical Issues

### Issue 1: Historical LSTM Pseudo-Sequence Data Leakage
- **Defect**: Pre-existing LSTM checkpoints were trained on non-consecutive, randomly permuted CSV rows sliced into blocks of 5 without grouping by host IP or ordering by timestamp.
- **Resolution**: Forensic audit in `docs/LSTM_TRAINING_LIVE_PARITY_AUDIT.md` and resolution in experiment `EXP-P2-LSTM-VALID-001` using host-grouped, chronological extraction with 120-second purge gaps and unseen host holdout.

### Issue 2: Live TCP Flag Cumulative Counting Mismatch
- **Defect**: Live Scapy flow builders counted cumulative flag packets ($> 100$), whereas offline CICFlowMeter CSV columns were binary indicators ($\in \{0, 1\}$), causing $+121\sigma$ scaler distortion.
- **Resolution**: Enforced binary indicator mapping ($\min(\text{packet\_count}, 1.0)$) with unit test validation in `tests/unit/test_r10_flowseq_parity.py`.

---

## 2. Documented Operational Boundaries

### Boundary 1: Sequence Modeling Eligibility Across Benchmark Datasets
- **Status**: Documented Boundary.
- **Detail**: 19 out of 20 benchmark CSV files across CIC-IDS2017, CSE-CIC-IDS2018, and UNSW-NB15 lack IP addresses or monotonic timestamps. Sequence modeling is physically limited to Tuesday CSE-CIC-IDS2018.

### Boundary 2: Python / Scapy Packet Ingestion Line-Rate Ceiling
- **Status**: Documented Architectural Scope.
- **Detail**: Scapy Python capture sustains $\approx 2,000 \to 5,000\,\text{pps}$ on modern CPUs. The system is designed as an algorithmic research platform, not a hardware line-rate appliance.

### Boundary 3: Advisory Dry-Run Mitigation
- **Status**: Permanent Architectural Guardrail.
- **Detail**: To prevent destructive firewall mutations on host development machines, all DQN mitigation recommendations execute as logged advisory events.
