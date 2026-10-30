> **Measurement integrity addendum (2026-10-30):** This document's historical latency figures are not yet reconciled with `docs/RF_VS_XGBOOST.md`. That comparison reports XGBoost medians of 0.6909/0.2995/0.2925 ms and RF medians around 37 ms, while this report lists XGBoost 0.2428 ms and RF 47.2357 ms; prose elsewhere also cites 0.12–0.15 ms. Until the same hardware, model/preprocessor artifacts, batch size, warm-up, repetitions, thread count, and timing harness are recorded and rerun for both models, **do not quote a definitive XGBoost speedup (including 194x) as verified**. Treat the values below as historical measurements whose comparability is unverified. The current canonical live registry uses RF, not XGBoost.

---

# XRL-IDARS Latency and Throughput Evaluation

## 1. Executive Summary

This evaluation documents the empirical runtime latency and throughput performance of each tier
in the **XRL-IDARS** active pipeline. Benchmarks were conducted on the unified CPU runtime using
the registered champion detector, deterministic protocol rules, TreeSHAP explainer, and Dueling DQN policy.

### Key Empirical Findings:
- **Fast Path Median Latency:** `48.989 ms` per flow (benign / low-risk flows).
- **Deep Inspection Path Median Latency:** `104.597 ms` per flow (including exact TreeSHAP attributions and DQN response selection).
- **Peak Single-Core Throughput:** `19.8 flows/second`.
- **Perception Tier:** RF inference median `47.2357 ms` vs XGBoost inference median `0.2428 ms` (>194.6x speedup!).
- **Deterministic Rule Invariants:** Sub-microsecond checks (`0.0038 ms`).

## 2. Component Latency Breakdown

| Pipeline Subsystem | Median (ms) | Mean (ms) | Std (ms) | P95 (ms) | P99 (ms) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `feature_validator` | 3.9286 | 3.9733 | 0.3098 | 4.4801 | 4.6107 |
| `perception_inference_rf` | 47.2357 | 47.6673 | 2.0507 | 52.5503 | 52.8490 |
| `perception_inference_xgboost` | 0.2428 | 0.5742 | 4.6899 | 0.4996 | 0.5540 |
| `rule_engine` | 0.0038 | 0.0039 | 0.0006 | 0.0040 | 0.0070 |
| `source_tracker` | 0.0027 | 0.0028 | 0.0005 | 0.0032 | 0.0051 |
| `treeshap_explainer` | 51.0672 | 50.8998 | 0.8917 | 51.9666 | 52.4345 |
| `dqn_response` | 0.1748 | 0.1796 | 0.0148 | 0.2037 | 0.2372 |
| `safety_gate` | 0.0009 | 0.0011 | 0.0008 | 0.0017 | 0.0042 |
| `pipeline_fast_path` | 48.9885 | 51.6318 | 8.0628 | 72.3946 | 82.9409 |
| `pipeline_deep_path` | 104.5972 | 107.1692 | 8.5532 | 120.2516 | 140.2314 |

## 3. Latency Waterfall Analysis

```
Incoming Flow Packet Stream
  │
  ├─► Feature Schema Validation:      3.9286 ms
  ├─► Perception Inference (RF):      47.2357 ms
  ├─► Perception Inference (XGBoost): 0.2428 ms
  ├─► Protocol Rule Engine:           0.0038 ms
  ├─► Source Activity Tracking:       0.0027 ms
  │
  ├─► Decision Fork: Is flow anomalous / escalated?
  │     ├─► [NO - Fast Path]  ───► Total Pipeline: 48.989 ms
  │     │
  │     └─► [YES - Deep Path] ───► TreeSHAP Attribution: 51.067 ms
                                  DQN Response Policy:   0.1748 ms
                                  Safety Gate Check:     0.0009 ms
                                  Total Pipeline:        104.597 ms
```

## 4. Throughput and Scalability

- **Single-Core Clean Flow Capacity:** `19.8 flows/sec`
- **Concurrency Scaling:** Because flows are stateless during feature evaluation, horizontal scaling via worker pools linearly multiplies throughput across CPU cores.
- **Explaining Selectivity:** Exact TreeSHAP is executed conditionally only for flows with threat score $\ge 0.50$ or escalated sources, preventing CPU bottlenecks during normal high-volume benign periods.
