# XRL-IDARS — End-to-End Data Flow Specification

**Document ID:** `DOC-ARCH-DATAFLOW-001`  
**Version:** 1.0.0  
**Status:** COMPLETE & AUTHORITATIVE  
**Date:** October 30, 2026  
**Architect:** Senior ML Systems Engineer  

---

## 1. Executive Summary

This document specifies the exact data schemas, mathematical transformations, and boundary contracts governing information flow through the XRL-IDARS pipeline. Data flows unidirectionally from packet capture to dashboard presentation with zero cyclic dependencies.

---

## 2. End-to-End Data Flow Diagram

```mermaid
flowchart LR
    PKT["Raw Packet (Scapy / AF_PACKET)"] -->|PacketInfo| FLOW["Flow Accumulator (FlowKey + Stats)"]
    FLOW -->|Flow Object| FEAT["R10 Feature Vector (10 Floats)"]
    FEAT -->|Validated Dict| PREP["StandardScaler (numpy float32)"]
    PREP -->|Scaled Array (1, 10)| DETECT["Random Forest Model (Scikit-Learn)"]
    DETECT -->|Score P in [0, 1]| ALERT["AlertEvent Structure"]
    ALERT -->|Features + Model| SHAP["TreeSHAP Explainer (shap_values)"]
    ALERT -->|Score + Flow Rates| STATE["StateBuilder (s_t in R^6)"]
    STATE -->|State Vector| DQN["Dueling DQN Policy Net"]
    DQN -->|Action Enum (0..3)| GATE["Deterministic Safety Gate"]
    GATE -->|Enforced Action| TELEM["Telemetry Bus (JSON / WebSocket)"]
    SHAP -->|Attributions| TELEM
    TELEM --> UI["Web Dashboard (app.js)"]
```

---

## 3. Data Transformation Stages & Schemas

### Stage 1: Packet to Bidirectional Flow
- **Input**: Raw Ethernet/IP frames from network interface or PCAP reader.
- **Transformation**: Endpoint sorting to create a canonical 5-tuple:
  $$\text{endpoint\_a} = \min((\text{ip}_1, \text{port}_1), (\text{ip}_2, \text{port}_2)), \quad \text{endpoint\_b} = \max((\text{ip}_1, \text{port}_1), (\text{ip}_2, \text{port}_2))$$
- **Accumulator State**:
  - Forward packets, backward packets, forward bytes, backward bytes.
  - Directional TCP flag counters (`SYN`, `ACK`, `RST`, `FIN`).
  - Packet length history ($L = [l_1, l_2, \dots, l_n]$).
  - First packet timestamp ($t_{\text{start}}$) and latest packet timestamp ($t_{\text{latest}}$).

### Stage 2: Flow to Canonical R10 Feature Vector
- **Input**: Completed `Flow` instance.
- **Contract Schema**: Mapping of 10 float values:
  1. `flow_duration_ms`: $(t_{\text{latest}} - t_{\text{start}}) \times 1000.0$
  2. `flow_packets_per_s`: $N_{\text{total}} / \max(\text{duration\_s}, 0.001)$
  3. `flow_bytes_per_s`: $B_{\text{total}} / \max(\text{duration\_s}, 0.001)$
  4. `packet_length_mean`: $\frac{1}{N} \sum_{i=1}^N l_i$
  5. `packet_length_std`: $\sqrt{\frac{1}{N} \sum_{i=1}^N (l_i - \mu)^2}$ (Population standard deviation, $\text{ddof}=0$)
  6. `syn_count`: $\min(\text{syn\_packets}, 1.0)$ (Binary indicator)
  7. `ack_count`: $\min(\text{ack\_packets}, 1.0)$ (Binary indicator)
  8. `rst_count`: $\min(\text{rst\_packets}, 1.0)$ (Binary indicator)
  9. `fin_count`: $\min(\text{fin\_packets}, 1.0)$ (Binary indicator)
  10. `syn_ack_ratio`: $\frac{N_{\text{syn}} + 1.0}{N_{\text{ack}} + 1.0}$
- **Validation**: Strict rejection of missing keys, non-numeric strings, `NaN`, and `Inf`.

### Stage 3: Normalization via Frozen Preprocessor
- **Input**: Dictionary of 10 raw feature values.
- **Transformation**: Transformed using frozen `StandardScaler` fitted strictly on training data:
  $$x_i^{\text{scaled}} = \frac{x_i - \mu_i^{\text{train}}}{\sigma_i^{\text{train}}}$$
- **Output**: 1D NumPy array of shape `(10,)`, `dtype=float32`.

### Stage 4: Random Forest Inference & Classification
- **Input**: Scaled array of shape `(1, 10)`.
- **Transformation**: 100 independent decision tree traversals calculating vote fraction for class 1 (Attack):
  $$P(\text{Attack} \mid x) = \frac{1}{100} \sum_{t=1}^{100} I_t(x = 1)$$
- **Output**: `attack_score` $\in [0.0, 1.0]$, `prediction` $\in \{0, 1\}$.

### Stage 5: TreeSHAP Attribution Calculation
- **Input**: Raw/scaled feature vector and loaded tree ensemble.
- **Transformation**: Polynomial-time Lundberg TreeSHAP algorithm computing exact additive Shapley values:
  $$f(x) = \phi_0 + \sum_{i=1}^{10} \phi_i(x)$$
- **Output**: Dictionary mapping each feature to its signed attribution value ($\phi_i$), base value ($\phi_0$), and waterfall ordering.

### Stage 6: 6D Causal State Construction
- **Input**: `attack_score` ($P$), `flow_bytes_per_s`, host mitigation history, and cooldown state.
- **Transformation**: Normalization and bounded clipping into $\mathbb{R}^6$:
  $$s_t = \begin{bmatrix}
  P(\text{attack}) \\
  \min(\text{anomaly\_score}, 1.0) \\
  \min(\text{packet\_burst\_rate} / 1000.0, 1.0) \\
  \min(\text{unique\_dst\_ports} / 100.0, 1.0) \\
  \text{is\_currently\_mitigated} \in \{0.0, 1.0\} \\
  \text{defense\_mode\_level} \in [0.0, 1.0]
  \end{bmatrix}$$
- **Output**: 1D NumPy float32 array of shape `(6,)`.

### Stage 7: DQN Action Proposal & Safety Verification
- **Input**: 6D state tensor $(1, 6)$.
- **Transformation**: Forward pass through Dueling DQN generating action Q-values:
  $$Q(s, a) = V(s) + \left( A(s, a) - \frac{1}{|\mathcal{A}|} \sum_{a'} A(s, a') \right)$$
  $$a^* = \arg\max_{a} Q(s, a)$$
- **Safety Gate Filtering**: Validates $a^*$ against:
  1. Critical Host Allowlist (infrastructure IPs cannot be isolated).
  2. Cooldown timer ($T_{\text{cooldown}} = 30$ steps between disruptive actions on the same host).
  3. Blast-radius breaker (maximum $5\%$ of active hosts concurrently quarantined).
- **Output**: `enforced_action` $\in \{0: \text{NO\_ACTION}, 1: \text{RATE\_LIMIT}, 2: \text{QUARANTINE}, 3: \text{DEEP\_INSPECTION}\}$.
