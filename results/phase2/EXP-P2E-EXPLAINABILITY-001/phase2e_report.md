# Phase 2E: Explainability Engine and Safety Invariant Audit Report

**Experiment ID**: `EXP-P2E-EXPLAINABILITY-001`  
**Research Question**: `RQ7.3` (Dual-Layer Explainability Architecture)  
**Parent Detector**: `EXP-P1-CIC2017-R10-001`  
**Parent Policy Model**: `EXP-P2B-DQN-001`  
**Generated**: `2026-10-03T22:21:07.066824+00:00`  
**Git Commit**: `7ab8cf3a075ab852162194302bdc594c695ded05`  

---

## 1. Executive Summary & Audit Mandate

Phase 2E implements and evaluates the **Dual-Layer Explainability Framework** specified in
`docs/phase2/AUTONOMOUS_RESPONSE_SPEC.md` (`SPEC-P2-AUTONOMOUS-RESPONSE-001` Section 13 & 14).

**Core Objectives & Governance Mandates**:
1. **Layer 1: Perception Explainability**: Every autonomous action decomposes the underlying detector risk score
   into local feature attributions using TreeSHAP on the frozen Phase 1 Random Forest model.
2. **Layer 2: Response Policy Explainability**: The reinforcement learning decision is decomposed into candidate
   Q-values, the decision margin ($Q(s, a^*) - \max_{a \ne a^*} Q(s, a)$), and human-interpretable driving state factors.
3. **Deterministic Safety Compliance**: 100% of candidate interventions are audited against the 4 non-bypassable safety invariants.
4. **RQ7.3 Pre-Registered Target**: 100% of non-ALLOW actions must be accompanied by a valid Action Decision Audit Card.

---

## 2. Quantitative Audit Metrics & Pre-Registered Criteria

| Evaluation Metric | Target / Specification | Observed Value | Status |
|:---|:---:|:---:|:---:|
| Evaluated Flow Population ($D_{\text{pol\_val}}$) | Full validation stream | 142,346 flows | VALIDATED |
| Autonomous Interventions (Non-ALLOW) | Observed actions | 28,167 actions | RECORDED |
| Audit Records Generated | 100% of non-ALLOW | 28,167 cards | GENERATED |
| Audit Coverage Percentage | $\ge 99.99\%$ (100%) | **100.00%** | PASS (RQ7.3 Met) |
| Mean Decision Margin (Q-Value Advantage) | $> 0.0$ | **+1.98** | VALIDATED |
| Safety Overrides Logged | Monitored | 12,573 overrides | AUDITED |

---

## 3. Layer 1 Perception Explainability: Global Feature Attribution Rankings

Aggregated TreeSHAP feature importance across all audited non-ALLOW interventions:

| Rank | Feature Name | Mean Absolute SHAP | Top-1 Attribution Frequency | Description |
|:---:|:---|---:|---:|:---|
| 1 | `packet_length_std` | 0.2159 | 98.7% | Standard deviation of packet byte lengths |
| 2 | `flow_packets_per_s` | 0.1228 | 0.1% | Packet rate per second across session |
| 3 | `flow_duration_ms` | 0.0731 | 1.1% | Total duration of bi-directional flow session |
| 4 | `flow_bytes_per_s` | 0.0545 | 0.0% | Byte transfer rate per second across session |
| 5 | `packet_length_mean` | 0.0044 | 0.1% | Mean byte length of observed IP packets |
| 6 | `ack_count` | 0.0027 | 0.0% | Count of TCP ACK packets observed in window |
| 7 | `syn_count` | 0.0000 | 0.0% | Count of TCP SYN packets observed in window |
| 8 | `rst_count` | 0.0000 | 0.0% | Count of TCP RST packets indicating abrupt teardown |
| 9 | `fin_count` | 0.0000 | 0.0% | Count of TCP FIN packets indicating orderly termination |
| 10 | `syn_ack_ratio` | 0.0000 | 0.0% | Ratio of SYN to ACK packets measuring handshake symmetry |

---

## 4. Deterministic Safety Gate Invariant Audit

- **Total Gate Invariant Evaluations**: 142,346
- **Total Safety Overrides Enforced**: 12,573 (8.83%)
- **Active Isolated Hosts at Termination**: 10
- **Active Rate-Limited Hosts at Termination**: 10
- **Total Distinct Hosts Tracked**: 250

### Override Reason Breakdown:
- `CRITICAL_INFRASTRUCTURE_EXEMPTION`: 147 interventions
- `BLAST_RADIUS_CIRCUIT_BREAKER`: 12,426 interventions

---

## 5. Sample Action Decision Audit Cards

The following sample audit cards illustrate the dual-layer attribution format for real interventions:

### Action Decision Audit Card: `0`

- **Timestamp**: `2026-10-03T22:20:57.000645+00:00`
- **Target Host**: `host_0`
- **Proposed Action**: `ISOLATE`
- **Enforced Action**: `ALERT`

#### Layer 1: Perception Explainability (TreeSHAP)
- **Detector Risk Score ($S_t$)**: `0.9934`
- **Top Contributing Features**:
  - `packet_length_std`: SHAP `+0.2107` (Value: 1425.15)
  - `flow_packets_per_s`: SHAP `-0.1378` (Value: 0.16)
  - `flow_bytes_per_s`: SHAP `-0.1143` (Value: 138.44)

#### Layer 2: Response Policy Explainability
- **Action Q-Values**:
  - `ALERT: -19.72`, `ALLOW: -108.84`, `ISOLATE: -12.36`, `RATE_LIMIT: -22.56`
- **Decision Margin**: `+7.36`
- **Driving State Factors**:
  - Instantaneous attack risk is severe (S_t=0.993 >= 0.75)
  - Recent alert density is elevated (N_alert=100.0% of past 20 flows >= 0.50)
  - Destination endpoint is designated critical infrastructure (isolation strictly prohibited by safety gate)
  - Threat score elevated but risk does not warrant disruptive traffic containment

#### Deterministic Safety Invariants
- **Invariants Checked**: `CRITICAL_INFRASTRUCTURE_EXEMPTION`, `MANDATORY_ACTION_COOLDOWN`, `BLAST_RADIUS_CIRCUIT_BREAKER`
- **Action Overruled**: `YES`
- **Override Reason**: `CRITICAL_INFRASTRUCTURE_EXEMPTION`


---

### Action Decision Audit Card: `2`

- **Timestamp**: `2026-10-03T22:20:57.001983+00:00`
- **Target Host**: `host_2`
- **Proposed Action**: `ISOLATE`
- **Enforced Action**: `ISOLATE`

#### Layer 1: Perception Explainability (TreeSHAP)
- **Detector Risk Score ($S_t$)**: `0.9970`
- **Top Contributing Features**:
  - `packet_length_std`: SHAP `+0.2107` (Value: 1746.21)
  - `flow_packets_per_s`: SHAP `-0.1379` (Value: 0.17)
  - `flow_bytes_per_s`: SHAP `-0.1143` (Value: 138.87)

#### Layer 2: Response Policy Explainability
- **Action Q-Values**:
  - `ALERT: -15.21`, `ALLOW: -82.14`, `ISOLATE: -10.86`, `RATE_LIMIT: -32.79`
- **Decision Margin**: `+4.34`
- **Driving State Factors**:
  - Instantaneous attack risk is severe (S_t=0.997 >= 0.75)
  - Threat velocity accelerating rapidly (rate-of-change delta=+0.50 over 5-flow window)
  - Recent alert density is elevated (N_alert=66.7% of past 20 flows >= 0.50)
  - Endpoint active cooldown in effect (30 steps remaining)
  - Destination endpoint is standard network inventory (isolation permissible if justified)
  - High cumulative threat density and persistent attack pattern justify complete endpoint containment

#### Deterministic Safety Invariants
- **Invariants Checked**: `CRITICAL_INFRASTRUCTURE_EXEMPTION`, `MANDATORY_ACTION_COOLDOWN`, `BLAST_RADIUS_CIRCUIT_BREAKER`
- **Action Overruled**: `NO`


---

### Action Decision Audit Card: `6`

- **Timestamp**: `2026-10-03T22:20:57.002605+00:00`
- **Target Host**: `host_6`
- **Proposed Action**: `ISOLATE`
- **Enforced Action**: `ALERT`

#### Layer 1: Perception Explainability (TreeSHAP)
- **Detector Risk Score ($S_t$)**: `0.9840`
- **Top Contributing Features**:
  - `packet_length_std`: SHAP `+0.2322` (Value: 1645.24)
  - `flow_duration_ms`: SHAP `-0.1596` (Value: 1185.70)
  - `flow_packets_per_s`: SHAP `-0.1413` (Value: 7.59)

#### Layer 2: Response Policy Explainability
- **Action Q-Values**:
  - `ALERT: -18.99`, `ALLOW: -106.50`, `ISOLATE: -14.92`, `RATE_LIMIT: -23.40`
- **Decision Margin**: `+4.07`
- **Driving State Factors**:
  - Instantaneous attack risk is severe (S_t=0.984 >= 0.75)
  - Threat velocity accelerating rapidly (rate-of-change delta=+0.78 over 5-flow window)
  - Moderate sustained threat background present (N_alert=42.9%)
  - Destination endpoint is standard network inventory (isolation permissible if justified)
  - Threat score elevated but risk does not warrant disruptive traffic containment

#### Deterministic Safety Invariants
- **Invariants Checked**: `CRITICAL_INFRASTRUCTURE_EXEMPTION`, `MANDATORY_ACTION_COOLDOWN`, `BLAST_RADIUS_CIRCUIT_BREAKER`
- **Action Overruled**: `YES`
- **Override Reason**: `BLAST_RADIUS_CIRCUIT_BREAKER`


---

### Action Decision Audit Card: `18`

- **Timestamp**: `2026-10-03T22:20:57.003026+00:00`
- **Target Host**: `host_18`
- **Proposed Action**: `ISOLATE`
- **Enforced Action**: `ALERT`

#### Layer 1: Perception Explainability (TreeSHAP)
- **Detector Risk Score ($S_t$)**: `0.9951`
- **Top Contributing Features**:
  - `packet_length_std`: SHAP `+0.2102` (Value: 2705.04)
  - `flow_packets_per_s`: SHAP `-0.1388` (Value: 0.15)
  - `flow_bytes_per_s`: SHAP `-0.1153` (Value: 135.41)

#### Layer 2: Response Policy Explainability
- **Action Q-Values**:
  - `ALERT: -18.56`, `ALLOW: -105.95`, `ISOLATE: -17.72`, `RATE_LIMIT: -23.17`
- **Decision Margin**: `+0.85`
- **Driving State Factors**:
  - Instantaneous attack risk is severe (S_t=0.995 >= 0.75)
  - Threat velocity accelerating rapidly (rate-of-change delta=+0.99 over 5-flow window)
  - Moderate sustained threat background present (N_alert=21.1%)
  - Destination endpoint is standard network inventory (isolation permissible if justified)
  - Threat score elevated but risk does not warrant disruptive traffic containment

#### Deterministic Safety Invariants
- **Invariants Checked**: `CRITICAL_INFRASTRUCTURE_EXEMPTION`, `MANDATORY_ACTION_COOLDOWN`, `BLAST_RADIUS_CIRCUIT_BREAKER`
- **Action Overruled**: `YES`
- **Override Reason**: `BLAST_RADIUS_CIRCUIT_BREAKER`


---

### Action Decision Audit Card: `21`

- **Timestamp**: `2026-10-03T22:20:57.003449+00:00`
- **Target Host**: `host_21`
- **Proposed Action**: `ISOLATE`
- **Enforced Action**: `ALERT`

#### Layer 1: Perception Explainability (TreeSHAP)
- **Detector Risk Score ($S_t$)**: `0.9724`
- **Top Contributing Features**:
  - `packet_length_std`: SHAP `+0.2322` (Value: 188.20)
  - `flow_duration_ms`: SHAP `-0.1595` (Value: 12828.21)
  - `flow_packets_per_s`: SHAP `-0.1411` (Value: 4.21)

#### Layer 2: Response Policy Explainability
- **Action Q-Values**:
  - `ALERT: -18.77`, `ALLOW: -106.76`, `ISOLATE: -18.37`, `RATE_LIMIT: -23.56`
- **Decision Margin**: `+0.40`
- **Driving State Factors**:
  - Instantaneous attack risk is severe (S_t=0.972 >= 0.75)
  - Threat velocity accelerating rapidly (rate-of-change delta=+0.77 over 5-flow window)
  - Destination endpoint is standard network inventory (isolation permissible if justified)
  - Threat score elevated but risk does not warrant disruptive traffic containment

#### Deterministic Safety Invariants
- **Invariants Checked**: `CRITICAL_INFRASTRUCTURE_EXEMPTION`, `MANDATORY_ACTION_COOLDOWN`, `BLAST_RADIUS_CIRCUIT_BREAKER`
- **Action Overruled**: `YES`
- **Override Reason**: `BLAST_RADIUS_CIRCUIT_BREAKER`


---

### Action Decision Audit Card: `24`

- **Timestamp**: `2026-10-03T22:20:57.003832+00:00`
- **Target Host**: `host_24`
- **Proposed Action**: `ISOLATE`
- **Enforced Action**: `ALERT`

#### Layer 1: Perception Explainability (TreeSHAP)
- **Detector Risk Score ($S_t$)**: `0.9964`
- **Top Contributing Features**:
  - `packet_length_std`: SHAP `+0.2100` (Value: 1579.01)
  - `flow_packets_per_s`: SHAP `-0.1363` (Value: 0.13)
  - `flow_bytes_per_s`: SHAP `-0.1153` (Value: 102.97)

#### Layer 2: Response Policy Explainability
- **Action Q-Values**:
  - `ALERT: -18.74`, `ALLOW: -106.78`, `ISOLATE: -18.29`, `RATE_LIMIT: -23.54`
- **Decision Margin**: `+0.45`
- **Driving State Factors**:
  - Instantaneous attack risk is severe (S_t=0.996 >= 0.75)
  - Threat velocity accelerating rapidly (rate-of-change delta=+0.80 over 5-flow window)
  - Destination endpoint is standard network inventory (isolation permissible if justified)
  - Threat score elevated but risk does not warrant disruptive traffic containment

#### Deterministic Safety Invariants
- **Invariants Checked**: `CRITICAL_INFRASTRUCTURE_EXEMPTION`, `MANDATORY_ACTION_COOLDOWN`, `BLAST_RADIUS_CIRCUIT_BREAKER`
- **Action Overruled**: `YES`
- **Override Reason**: `BLAST_RADIUS_CIRCUIT_BREAKER`


---

### Action Decision Audit Card: `25`

- **Timestamp**: `2026-10-03T22:20:57.004219+00:00`
- **Target Host**: `host_25`
- **Proposed Action**: `RATE_LIMIT`
- **Enforced Action**: `RATE_LIMIT`

#### Layer 1: Perception Explainability (TreeSHAP)
- **Detector Risk Score ($S_t$)**: `0.9798`
- **Top Contributing Features**:
  - `packet_length_std`: SHAP `+0.2322` (Value: 1753.72)
  - `flow_duration_ms`: SHAP `-0.1596` (Value: 1358.60)
  - `flow_packets_per_s`: SHAP `-0.1413` (Value: 8.10)

#### Layer 2: Response Policy Explainability
- **Action Q-Values**:
  - `ALERT: -18.87`, `ALLOW: -105.67`, `ISOLATE: -14.54`, `RATE_LIMIT: -23.93`
- **Decision Margin**: `+4.33`
- **Driving State Factors**:
  - Instantaneous attack risk is severe (S_t=0.980 >= 0.75)
  - Threat velocity accelerating rapidly (rate-of-change delta=+0.58 over 5-flow window)
  - Moderate sustained threat background present (N_alert=23.8%)
  - Previous action state: ALERT (monitoring active)
  - Endpoint active cooldown in effect (30 steps remaining)
  - Destination endpoint is standard network inventory (isolation permissible if justified)
  - Suspicious velocity or critical infrastructure status indicates rate-limiting to preserve availability

#### Deterministic Safety Invariants
- **Invariants Checked**: `CRITICAL_INFRASTRUCTURE_EXEMPTION`, `MANDATORY_ACTION_COOLDOWN`, `BLAST_RADIUS_CIRCUIT_BREAKER`
- **Action Overruled**: `NO`


---

### Action Decision Audit Card: `28`

- **Timestamp**: `2026-10-03T22:20:57.004585+00:00`
- **Target Host**: `host_28`
- **Proposed Action**: `ISOLATE`
- **Enforced Action**: `ALERT`

#### Layer 1: Perception Explainability (TreeSHAP)
- **Detector Risk Score ($S_t$)**: `0.9853`
- **Top Contributing Features**:
  - `packet_length_std`: SHAP `+0.2328` (Value: 3337.88)
  - `flow_duration_ms`: SHAP `-0.1596` (Value: 81.66)
  - `flow_packets_per_s`: SHAP `-0.1409` (Value: 97.97)

#### Layer 2: Response Policy Explainability
- **Action Q-Values**:
  - `ALERT: -18.82`, `ALLOW: -106.16`, `ISOLATE: -18.57`, `RATE_LIMIT: -22.94`
- **Decision Margin**: `+0.26`
- **Driving State Factors**:
  - Instantaneous attack risk is severe (S_t=0.985 >= 0.75)
  - Threat velocity accelerating rapidly (rate-of-change delta=+0.59 over 5-flow window)
  - Moderate sustained threat background present (N_alert=23.8%)
  - Elevated flow byte volume detected (v_t=0.65, heavy transfer)
  - Destination endpoint is standard network inventory (isolation permissible if justified)
  - Threat score elevated but risk does not warrant disruptive traffic containment

#### Deterministic Safety Invariants
- **Invariants Checked**: `CRITICAL_INFRASTRUCTURE_EXEMPTION`, `MANDATORY_ACTION_COOLDOWN`, `BLAST_RADIUS_CIRCUIT_BREAKER`
- **Action Overruled**: `YES`
- **Override Reason**: `BLAST_RADIUS_CIRCUIT_BREAKER`


---

### Action Decision Audit Card: `56`

- **Timestamp**: `2026-10-03T22:20:57.004988+00:00`
- **Target Host**: `host_56`
- **Proposed Action**: `ISOLATE`
- **Enforced Action**: `ISOLATE`

#### Layer 1: Perception Explainability (TreeSHAP)
- **Detector Risk Score ($S_t$)**: `0.9927`
- **Top Contributing Features**:
  - `packet_length_std`: SHAP `+0.2103` (Value: 1620.61)
  - `flow_packets_per_s`: SHAP `-0.1389` (Value: 0.14)
  - `flow_bytes_per_s`: SHAP `-0.1152` (Value: 121.56)

#### Layer 2: Response Policy Explainability
- **Action Q-Values**:
  - `ALERT: -17.31`, `ALLOW: -91.09`, `ISOLATE: -16.82`, `RATE_LIMIT: -33.61`
- **Decision Margin**: `+0.50`
- **Driving State Factors**:
  - Instantaneous attack risk is severe (S_t=0.993 >= 0.75)
  - Threat velocity accelerating rapidly (rate-of-change delta=+0.99 over 5-flow window)
  - Endpoint active cooldown in effect (30 steps remaining)
  - Destination endpoint is standard network inventory (isolation permissible if justified)
  - High cumulative threat density and persistent attack pattern justify complete endpoint containment

#### Deterministic Safety Invariants
- **Invariants Checked**: `CRITICAL_INFRASTRUCTURE_EXEMPTION`, `MANDATORY_ACTION_COOLDOWN`, `BLAST_RADIUS_CIRCUIT_BREAKER`
- **Action Overruled**: `NO`


---

### Action Decision Audit Card: `63`

- **Timestamp**: `2026-10-03T22:20:57.005655+00:00`
- **Target Host**: `host_63`
- **Proposed Action**: `ISOLATE`
- **Enforced Action**: `ISOLATE`

#### Layer 1: Perception Explainability (TreeSHAP)
- **Detector Risk Score ($S_t$)**: `0.9910`
- **Top Contributing Features**:
  - `packet_length_std`: SHAP `+0.2108` (Value: 1461.83)
  - `flow_packets_per_s`: SHAP `-0.1385` (Value: 0.13)
  - `flow_bytes_per_s`: SHAP `-0.1153` (Value: 118.91)

#### Layer 2: Response Policy Explainability
- **Action Q-Values**:
  - `ALERT: -17.62`, `ALLOW: -91.97`, `ISOLATE: -16.24`, `RATE_LIMIT: -33.69`
- **Decision Margin**: `+1.38`
- **Driving State Factors**:
  - Instantaneous attack risk is severe (S_t=0.991 >= 0.75)
  - Threat velocity accelerating rapidly (rate-of-change delta=+0.96 over 5-flow window)
  - Endpoint active cooldown in effect (30 steps remaining)
  - Destination endpoint is standard network inventory (isolation permissible if justified)
  - High cumulative threat density and persistent attack pattern justify complete endpoint containment

#### Deterministic Safety Invariants
- **Invariants Checked**: `CRITICAL_INFRASTRUCTURE_EXEMPTION`, `MANDATORY_ACTION_COOLDOWN`, `BLAST_RADIUS_CIRCUIT_BREAKER`
- **Action Overruled**: `NO`


---

## 6. Scientific Conclusions

1. **Pre-Registered RQ7.3 Verification**: The dual-layer explainability architecture achieved **100.0% audit coverage** across all non-ALLOW interventions.
2. **Dual-Layer Transparency**: TreeSHAP reliably isolates the network flow features driving high detector threat scores (Layer 1), while Q-value decomposition and driving state factors clarify why the policy selected specific containment actions (Layer 2).
3. **Safety Invariance**: The Deterministic Safety Gate operates downstream of the policy as a hard, non-bypassable barrier, ensuring zero unauthorized isolations of critical infrastructure.