# XRL-IDARS — Latency & Throughput Benchmark Report

**Document ID:** `DOC-EVAL-LATENCY-001`  
**Version:** 1.0.0  
**Status:** COMPLETE & EMPIRICALLY BENCHMARKED  
**Date:** October 30, 2026  
**Benchmarking Script:** `scripts/benchmark_latency.py`  
**Runtime:** Python 3.14.4 on Linux 7.0.0-42-generic x86_64, 14.58 GB RAM  

---

## 1. Executive Summary

This report documents the empirical latency and execution timing of the XRL-IDARS pipeline components. Measurements were collected using high-resolution monotonic clocks (`time.perf_counter_ns`) across 100 benchmark trials (25 trials for compute-intensive TreeSHAP explanations) on an isolated CPU runtime.

### Key Latency Highlights:
1. **Flow Feature Extraction**: **$0.041\,\text{ms}$ median** ($41\,\mu\text{s}$) to extract the canonical 10-feature vector from bidirectional packet accumulators.
2. **Operational RF Prediction**: **$24.43\,\text{ms}$ median** for a 100-tree forest traversal; **$31.91\,\text{ms}$ median** when including schema validation, StandardScaler normalization, and multiclass mapping.
3. **TreeSHAP Attribution**: **$27.39\,\text{ms}$ median** to compute exact game-theoretic Shapley feature attributions for all 10 features.
4. **End-to-End Alert & Explainability**: **$67.08\,\text{ms}$ median** from raw packet arrival through flow construction, RF inference, alert packaging, and TreeSHAP waterfall generation.

---

## 2. Empirical Component Latency Distribution

All values in milliseconds ($\text{ms}$).

| Pipeline Component | Scope | Samples | Median | Mean | P95 | P99 | Min / Max |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Feature Extraction** | `Flow.to_features()` on 10 accumulated packets | 100 | **0.041** | 0.042 | 0.049 | 0.057 | 0.011 / 0.087 |
| **Pure RF Inference** | 100-tree forest traversal on raw float32 array | 100 | **24.428** | 25.812 | 35.795 | 36.653 | 23.033 / 37.025 |
| **RF Inference + Preproc**| Validation, StandardScaler, class mapping | 100 | **31.914** | 38.642 | 66.351 | 77.023 | 27.262 / 80.723 |
| **TreeSHAP Explanation** | Exact TreeExplainer attribution on 10 features | 25 | **27.385** | 27.388 | 27.582 | 27.601 | 27.218 / 27.605 |
| **Packet $\to$ Prediction**| Ingestion $\to$ Flow $\to$ Features $\to$ RF | 100 | **29.161** | 35.801 | 78.097 | 83.786 | 25.466 / 84.505 |
| **Packet $\to$ Explanation** | Ingestion $\to$ Flow $\to$ Features $\to$ RF $\to$ SHAP | 25 | **67.078** | 76.541 | 89.908 | 119.815 | 54.636 / 129.136 |

---

## 3. Operational Timing Comparison: Random Forest vs. LSTM

A common misconception in recurrent neural network literature is to report only the GPU or CPU matrix-multiplication time of the model's forward pass while ignoring the time required to accumulate physical network packets.

### Algorithmic vs. Operational Latency:
- **PyTorch LSTM Forward Pass**: The forward pass of `lstm_flowseq_best.pt` on a pre-formed $(1, 5, 11)$ tensor takes **$0.38\,\text{ms}$**.
- **Real Operational Latency of LSTM**:
  $$\text{Operational Latency}_{\text{LSTM}} = \sum_{i=1}^{5} \text{FlowDuration}_i + \sum_{i=1}^{4} \Delta t_i + \text{BufferOverhead} + t_{\text{forward}}$$
  Because the LSTM requires **5 completed network flows** from the same host, the real-world operational delay is bounded by the network traffic rate:
  - Under active flood conditions ($100\,\text{flows/s}$): Buffer accumulation delay is $\approx 50\,\text{ms}$.
  - Under stealthy reconnaissance ($1\,\text{flow every 10 s}$): Buffer accumulation delay is **$40\,\text{seconds}$**.
  - For single-flow exploit attempts ($K=1$): Operational delay is **infinite** (LSTM never predicts).
- **Real Operational Latency of Random Forest**:
  $$\text{Operational Latency}_{\text{RF}} = \text{FlowDuration}_1 + t_{\text{features}} + t_{\text{RF}} \approx \text{Immediate on Flow 1}$$
  Random Forest classifies every flow independently as soon as it terminates or reaches the active timeout.

---

## 4. Methodological Disclaimer & Line-Rate Limitations

> [!NOTE]
> **Single-Flow Microbenchmarks vs. Line-Rate Throughput:**
> The benchmarks reported in this document measure per-flow algorithmic computational latency on isolated Python processes. They exclude:
> 1. Linux kernel socket buffer queueing and packet drops under heavy network saturation.
> 2. Scapy Python-space packet decoding overhead (which tops out at $\approx 2,000 \to 5,000\,\text{packets/sec}$ on standard CPUs).
> 3. Inter-process IPC and WebSocket serialization overhead.
> 
> Therefore, these results certify **sub-100 millisecond response advisory capability** on individual network flows, but should not be cited as sustained 10 Gbps hardware line-rate throughput.
