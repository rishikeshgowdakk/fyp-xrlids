# XRL-IDARS — Exact Reproduction Instructions

**Document ID:** `DOC-RES-REPRODUCIBILITY-001`  
**Version:** 1.0.0  
**Status:** COMPLETE & AUTHORITATIVE  
**Date:** October 30, 2026  

---

## 1. Reproduction of All Empirical Results

All experimental results and benchmarks reported in XRL-IDARS can be reproduced from a clean terminal using the commands below:

### Step 1: Run Full Automated Test Suite (605 Tests)
```bash
.venv/bin/pytest tests/ -v
```
*Expected Result*: 605 passed in $< 60\,\text{seconds}$.

### Step 2: Reproduce the LSTM vs. Random Forest Experiment
```bash
.venv/bin/python scripts/experiments/run_valid_lstm_experiment.py
```
*Output Artifacts*: Updated metrics in `results/experiments/EXP-P2-LSTM-VALID-001/`.

### Step 3: Run Empirical Latency Benchmark
```bash
.venv/bin/python scripts/benchmark_latency.py
```
*Expected Output*: Prints median, P95, and P99 latency percentiles for feature extraction, RF inference, TreeSHAP attribution, and end-to-end pipeline execution.

### Step 4: Verify Calibrated Scapy Attack Scenarios
```bash
.venv/bin/python scripts/demo/verify_attack_scenarios.py
```
*Expected Output*: Confirms all 7 attack scenarios match calibrated scores within 0.05 tolerance.

### Step 5: Verify Anti-Mock Dynamic Score Computation
```bash
.venv/bin/python scripts/demo/explain_score.py --scenario slow_http_dos
```
*Expected Output*: Demonstrates that flow score varies continuously with inter-packet arrival gaps.
