# XRL-IDARS — Machine Learning Model Overview

**Document ID:** `DOC-ML-OVERVIEW-001`  
**Version:** 1.0.0  
**Status:** COMPLETE & AUTHORITATIVE  
**Date:** October 30, 2026  

---

## 1. Executive Summary

XRL-IDARS decouples its machine learning models into distinct operational, experimental, and policy domains:
- **Operational Intrusion Detection**: Tabular **Random Forest** classifying individual network flows within $< 1.0\,\text{ms}$.
- **Experimental Sequence Modeling**: Recurrent **PyTorch LSTM** evaluating 5-flow host sequences ($T=5$) strictly as a comparative research study.
- **Autonomous Response Policy**: **Dueling Deep Q-Network (DQN)** mapping 6D security telemetry to cost-penalized mitigation recommendations.

---

## 2. Model Roles and Deployment Matrix

| Subsystem | Model Family | Framework | Input Dimension | Deployment Status | Operational Path |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Intrusion Detection** | Random Forest | Scikit-Learn 1.6+ | $X \in \mathbb{R}^{10}$ (R10) | **OPERATIONAL BASELINE** | Yes (Live & PCAP) |
| **Sequence Detection** | 2-Layer LSTM | PyTorch 2.6+ | $X \in \mathbb{R}^{5 \times 11}$ | **EXPERIMENTAL RESEARCH** | No (Offline Audit Only) |
| **Response Advisory** | Dueling DQN | PyTorch 2.6+ | $s \in \mathbb{R}^6$ | **OPERATIONAL ADVISORY** | Yes (Advisory Dry-Run) |
| **Local Explainability**| TreeSHAP | SHAP 0.46+ | $X \in \mathbb{R}^{10}$ | **OPERATIONAL EXPLAINER** | Yes (On Alert Trigger) |

---

## 3. Operational Integrity Principles

1. **Random Forest Operates Independently**: The operational detector does not depend on sequence buffers, packet arrival delays, or recurrent hidden states.
2. **Zero Score-Level Fusion**: The operational critical path never blends or weights Random Forest and LSTM probabilities.
3. **Calibrated Probabilities**: Prediction decisions are based on posterior probabilities evaluated against a research threshold ($\tau = 0.50$).
