# XRL-IDARS — Dueling DQN Response Agent Overview

**Document ID:** `DOC-RESP-DQN-OVERVIEW-001`  
**Version:** 1.0.0  
**Status:** COMPLETE & AUTHORITATIVE  
**Date:** October 30, 2026  

---

## 1. Executive Summary

The Dueling Deep Q-Network (DQN) response policy agent operates downstream from the intrusion detection system. Its role is to recommend context-aware, cost-optimal mitigation actions to balance network protection against operational disruption.

### Reinforcement Learning Formulation:
- **Environment**: Simulated network environment with Markov Decision Process (MDP) dynamics.
- **State Space**: Continuous 6-dimensional causal telemetry vector ($s_t \in \mathbb{R}^6$).
- **Action Space**: Discrete 4-action mitigation set ($\mathcal{A} = \{0: \text{NO\_ACTION}, 1: \text{RATE\_LIMIT}, 2: \text{QUARANTINE}, 3: \text{DEEP\_INSPECTION}\}$).
- **Reward Function**: Cost-penalized utility balancing attack containment against false-positive collateral damage.

---

## 2. 6D State Vector Definition

$$s_t = \begin{bmatrix}
s_0: P(\text{attack}) \in [0.0, 1.0] \\
s_1: \text{anomaly\_severity} \in [0.0, 1.0] \\
s_2: \text{packet\_burst\_rate} \in [0.0, 1.0] \\
s_3: \text{unique\_dst\_ports} \in [0.0, 1.0] \\
s_4: \text{is\_currently\_mitigated} \in \{0.0, 1.0\} \\
s_5: \text{defense\_mode\_level} \in [0.0, 1.0]
\end{bmatrix}$$

---

## 3. Network Architecture & Checkpoints

- **Model Class**: `DuelingQNetwork` (`src/xrlids/response/dqn/network.py`)
- **Shared Representation**: Linear(6, 64) $\to$ LayerNorm $\to$ LeakyReLU(0.01)
- **Value Head**: Linear(64, 32) $\to$ LeakyReLU $\to$ Linear(32, 1)
- **Advantage Head**: Linear(64, 32) $\to$ LeakyReLU $\to$ Linear(32, 4)
- **Primary Checkpoint**: `models/dqn/dqn_4action_best.pt`
- **Secondary Checkpoint**: `models/dqn/dqn_3action_best.pt`
