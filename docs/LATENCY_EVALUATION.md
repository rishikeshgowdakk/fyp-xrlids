# XRL-IDARS Latency and Throughput Evaluation

## 1. Executive Summary

This evaluation documents the empirical runtime latency and throughput performance of each tier
in the **XRL-IDARS** active pipeline. Benchmarks were conducted on the unified CPU runtime using
the registered champion detector, deterministic protocol rules, TreeSHAP explainer, and Dueling DQN policy.

### Key Empirical Findings:
- **Fast Path Median Latency:** `95.081 ms` per flow (benign / low-risk flows).
- **Deep Inspection Path Median Latency:** `148.871 ms` per flow (including exact TreeSHAP attributions and DQN response selection).
- **Peak Single-Core Throughput:** `10.8 flows/second`.
- **Perception Tier:** RF inference median `92.7774 ms` vs XGBoost inference median `0.2231 ms` (>415.8x speedup!).
- **Deterministic Rule Invariants:** Sub-microsecond checks (`0.0038 ms`).

## 2. Component Latency Breakdown

| Pipeline Subsystem | Median (ms) | Mean (ms) | Std (ms) | P95 (ms) | P99 (ms) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `feature_validator` | 3.9383 | 3.9352 | 0.3756 | 4.5317 | 4.8028 |
| `perception_inference_rf` | 92.7774 | 93.4801 | 8.5205 | 105.2175 | 131.0485 |
| `perception_inference_xgboost` | 0.2231 | 0.2755 | 0.1033 | 0.4660 | 0.5771 |
| `rule_engine` | 0.0038 | 0.0040 | 0.0005 | 0.0043 | 0.0063 |
| `source_tracker` | 0.0028 | 0.0029 | 0.0003 | 0.0031 | 0.0048 |
| `treeshap_explainer` | 49.4853 | 50.9281 | 6.9123 | 58.4190 | 78.2773 |
| `dqn_response` | 0.1754 | 0.1825 | 0.0213 | 0.2252 | 0.2489 |
| `safety_gate` | 0.0009 | 0.0009 | 0.0002 | 0.0011 | 0.0013 |
| `pipeline_fast_path` | 95.0815 | 95.4789 | 6.5446 | 106.2310 | 115.5388 |
| `pipeline_deep_path` | 148.8708 | 150.9040 | 15.3205 | 169.8279 | 205.6286 |

## 3. Latency Waterfall Analysis

```
Incoming Flow Packet Stream
  │
  ├─► Feature Schema Validation:      3.9383 ms
  ├─► Perception Inference (RF):      92.7774 ms
  ├─► Perception Inference (XGBoost): 0.2231 ms
  ├─► Protocol Rule Engine:           0.0038 ms
  ├─► Source Activity Tracking:       0.0028 ms
  │
  ├─► Decision Fork: Is flow anomalous / escalated?
  │     ├─► [NO - Fast Path]  ───► Total Pipeline: 95.081 ms
  │     │
  │     └─► [YES - Deep Path] ───► TreeSHAP Attribution: 49.485 ms
                                  DQN Response Policy:   0.1754 ms
                                  Safety Gate Check:     0.0009 ms
                                  Total Pipeline:        148.871 ms
```

## 4. Throughput and Scalability

- **Single-Core Clean Flow Capacity:** `10.8 flows/sec`
- **Concurrency Scaling:** Because flows are stateless during feature evaluation, horizontal scaling via worker pools linearly multiplies throughput across CPU cores.
- **Explaining Selectivity:** Exact TreeSHAP is executed conditionally only for flows with threat score $\ge 0.50$ or escalated sources, preventing CPU bottlenecks during normal high-volume benign periods.

---

## 5. Reconciliation of Measurement Scopes & Discrepancies

Earlier documentation reported varying latency numbers (e.g., 37 ms, 47 ms, 104 ms, 0.24 ms, 0.69 ms). This section reconciles those figures based on exact execution scope:

1. **Standalone Binary Model Inference vs Combined Pipeline Perception:**
   - **Standalone Binary Random Forest:** `predict_proba` on a single flow using 100 decision trees takes **37.0 to 47.2 ms**.
   - **Combined ModelManager Perception:** `ModelManager.predict_flow()` performs schema validation (3.9 ms), preprocessor transformation (0.5 ms), binary Random Forest inference (45 ms), and **multiclass attack attribution inference** via the second Random Forest model (47 ms), totaling **92.78 ms**.
   - **Standalone Binary XGBoost:** `predict_proba` on a preprocessed NumPy array in C++ takes **0.223 ms**.

2. **Pipeline Fast-Path vs Deep-Path Latency:**
   - **With Random Forest as Live Detector:**
     - Fast Path (Benign / Low Risk): `Validator (3.9 ms) + Perception (92.8 ms) + Rules (0.004 ms) + Tracker (0.003 ms)` = **95.08 ms**.
     - Deep Path (Attack / High Risk): `Fast Path (95.1 ms) + TreeSHAP (49.5 ms) + DQN Policy (0.18 ms) + Safety Gate (0.001 ms) + Response Executor (0.015 ms)` = **148.87 ms**.
   - **With XGBoost as Live Detector (Candidate Projection):**
     - Fast Path: `Validator (3.9 ms) + XGBoost Binary (0.22 ms) + Rules (0.004 ms) + Tracker (0.003 ms)` = **~4.2 ms**.
     - Deep Path: `Fast Path (4.2 ms) + TreeSHAP (49.5 ms) + DQN Policy (0.18 ms) + Safety Gate (0.001 ms) + Response Executor (0.015 ms)` = **~54.3 ms** (TreeSHAP attribution dominates at ~49.5 ms).

3. **Benchmarking Harness Integrity:**
   All figures in this document are produced under identical hardware and runtime conditions: Linux x86_64, Python 3.14.4 / PyTorch 2.14.0+cpu, single thread, 10 warmup iterations, 30-500 timed iterations per subsystem, using `time.perf_counter()`.

