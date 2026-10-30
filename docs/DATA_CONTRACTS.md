# XRL-IDARS — Canonical Data Contracts & Type Schemas

**Document ID:** `DOC-DATA-CONTRACTS-001`  
**Version:** 1.0.0  
**Status:** COMPLETE & AUTHORITATIVE  
**Date:** October 30, 2026  

---

## 1. R10 Feature Contract Schema

| Key | Type | Description | Invariant Constraints |
| :--- | :--- | :--- | :--- |
| `flow_duration_ms` | `float` | Flow duration in ms | $\ge 0.0$, finite, not NaN |
| `flow_packets_per_s` | `float` | Flow packet throughput rate | $\ge 0.0$, finite, not NaN |
| `flow_bytes_per_s` | `float` | Flow byte throughput rate | $\ge 0.0$, finite, not NaN |
| `packet_length_mean` | `float` | Mean packet length in bytes | $\ge 0.0$, finite, not NaN |
| `packet_length_std` | `float` | Population standard deviation ($\text{ddof}=0$)| $\ge 0.0$, finite, not NaN |
| `syn_count` | `float` | Binary SYN flag indicator | $\in \{0.0, 1.0\}$ |
| `ack_count` | `float` | Binary ACK flag indicator | $\in \{0.0, 1.0\}$ |
| `rst_count` | `float` | Binary RST flag indicator | $\in \{0.0, 1.0\}$ |
| `fin_count` | `float` | Binary FIN flag indicator | $\in \{0.0, 1.0\}$ |
| `syn_ack_ratio` | `float` | Smoothed SYN to ACK packet ratio | $> 0.0$, finite, not NaN |

---

## 2. AlertEvent Data Contract

```python
@dataclass
class AlertEvent:
    alert_id: str                   # Unique UUID / sequential alert ID
    timestamp: float                # Epoch seconds (float)
    source_ip: str                  # Threat origin IP (string)
    source_port: int                # Threat origin port (0-65535)
    dest_ip: str                    # Target IP (string)
    dest_port: int                  # Target port (0-65535)
    protocol: str                   # "TCP", "UDP", "ICMP", or "PROTO_<N>"
    attack_score: float             # Calibrated RF probability in [0.0, 1.0]
    classification: str             # "ATTACK"
    detection_source: str           # "RANDOM_FOREST" or "RULE" or "HYBRID"
    rule_ids: list[str]             # Matching rule identifiers
    rf_score: float                 # Pure Random Forest score
    lstm_score: float | None        # Optional research sequence score
    top_shap_features: list[dict]   # Top 3 Lundberg attributions
    dqn_action: str | None          # Advisory action recommendation
    enforced_action: str | None     # Safety-gate approved action
    override_applied: bool          # True if safety gate modified proposal
    override_reason: str | None     # Explanation of safety override
```

---

## 3. 6D Causal State Vector Contract

- **Data Type**: `numpy.ndarray` with `dtype=np.float32`, shape `(6,)`.
- **Bounds**: All components clipped to $[0.0, 1.0]$.
- **Vector Mapping**:
  - $s_0$: RF detection score ($P \in [0.0, 1.0]$)
  - $s_1$: Deterministic rule severity ($0.0 \to 1.0$)
  - $s_2$: Packet burst rate normalized ($\min(\text{rate} / 1000.0, 1.0)$)
  - $s_3$: Port sweep breadth ($\min(\text{ports} / 100.0, 1.0)$)
  - $s_4$: Host mitigation flag ($1.0$ if under cooldown/rate-limit, else $0.0$)
  - $s_5$: System defense alert level ($0.0 = \text{Normal}, 1.0 = \text{Critical}$)
