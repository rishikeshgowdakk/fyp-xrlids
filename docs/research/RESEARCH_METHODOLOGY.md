# XRL-IDARS — Research Methodology & Scientific Design

**Document ID:** `DOC-RES-METHODOLOGY-001`  
**Version:** 1.0.0  
**Status:** COMPLETE & AUTHORITATIVE  
**Date:** October 30, 2026  

---

## 1. Research Problem & Core Questions

Modern Network Intrusion Detection Systems (NIDS) face three fundamental challenges:
1. **The Tabular vs. Temporal Debate**: Does complex temporal sequence modeling (LSTMs, GRUs) provide measurable operational advantages over fast tabular tree ensembles in network flow detection?
2. **The "Black Box" Barrier**: Can machine learning intrusion decisions be explained to human security operators in real time using game-theoretic feature attributions?
3. **The Autonomous Response Dilemma**: Can reinforcement learning agents recommend proactive mitigation actions without causing collateral damage or self-inflicted Denial of Service?

---

## 2. Methodology & Scientific Design

### 1. Separation of Concerns
Rather than forcing a monolithic neural network to handle detection, explainability, and mitigation, XRL-IDARS establishes a modular pipeline:
- **Detection**: Tabular Random Forest ($X \in \mathbb{R}^{10}$) for deterministic, sub-millisecond classification.
- **Explainability**: TreeSHAP ($O(TLD^2)$ complexity) for exact Shapley feature attributions.
- **Response**: Dueling DQN over continuous causal state ($s \in \mathbb{R}^6$) governed by a deterministic safety gate.

### 2. Empirical Verification of Sequence Modeling
To answer the temporal research question without methodological shortcuts, the project conducted experiment `EXP-P2-LSTM-VALID-001`, evaluating both Random Forest and a chronological PyTorch LSTM on a common held-out test population of 8,726 instances.
