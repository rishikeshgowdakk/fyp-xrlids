# XRL-IDARS — Deterministic Rule Engine & Hybrid Decision Engine Specification

**Modules:**
- `src/xrlids/rules/engine.py` (`RuleEngine`, `RuleMatch`)
- `src/xrlids/rules/hybrid.py` (`HybridDecisionEngine`, `HybridDecision`)

---

## 1. Role of Deterministic Rules in XRL-IDARS

Machine learning models (Random Forest, XGBoost) are statistical pattern recognizers. While they excel at detecting complex multi-variate statistical anomalies, they lack deterministic knowledge of network protocol invariants and RFC specifications.

The **Deterministic Rule Engine** operates in parallel with the primary ML detector. It provides fast ($<0.01$ ms), RFC-grounded detection for unambiguous network attacks, ensuring immediate detection and explainable evidence.

---

## 2. Rule Catalog & Specifications

The Rule Engine evaluates 5 deterministic protocol and traffic rules:

| Rule ID | Rule Name | Evaluated Condition | Severity | Intended Attack Type |
|---|---|---|---|---|
| `RULE-TCP-INVALID-FLAGS` | Invalid TCP Control Flags | `has_syn_fin \|\| has_syn_rst \|\| has_xmas_flags \|\| has_null_flags` | **HIGH** | Stealth Port Scanning (Xmas / Null / SYN-FIN) |
| `RULE-SYN-FLOOD` | Disproportionate SYN vs ACK | `syn_count \ge 10.0` and `syn_ack_ratio \ge 5.0` | **CRITICAL** | TCP SYN Flood DoS / DDoS |
| `RULE-PORT-SCAN` | Rapid Ephemeral Port Probing | Short duration ($\le 100$ ms), small packets ($\le 80$ B), and SYN without ACK | **HIGH** | Reconnaissance / Port Sweep |
| `RULE-HIGH-RATE-BURST` | Extreme Packet/Byte Rate Burst | `flow_packets_per_s > 50,000` or `flow_bytes_per_s > 50,000,000` | **HIGH** | Volumetric DoS / UDP Flood |
| `RULE-IP-SPOOF-RESERVED` | Reserved or Martian IP Address | Source IP in `0.0.0.0/8`, `127.0.0.0/8`, `224.0.0.0/4`, `240.0.0.0/4` | **HIGH** | IP Spoofing / Martian Packets |

---

## 3. Hybrid Arbitration Matrix (`HybridDecisionEngine`)

When both the ML Champion Detector and the Rule Engine evaluate a completed flow, the `HybridDecisionEngine` deterministically reconciles their outputs into a final verdict:

| Rule Match Present? | ML Probability ($P \ge 0.50$)? | Final Decision Label | Priority / Rationale | Severity Floor |
|---|---|---|---|---|
| **YES** | **YES** | **`HYBRID`** | Both engines agree on intrusion. Maximum confidence. | At least `HIGH` (or rule severity) |
| **YES** | **NO** | **`RULE`** | Deterministic protocol violation overrides statistical false-negative. | Rule severity (`HIGH` or `CRITICAL`) |
| **NO** | **YES** | **`RF`** (or `ML`) | Statistical anomaly detected without explicit protocol violation. | `LOW` ($P < 0.85$) or `MEDIUM` ($P \ge 0.85$) |
| **NO** | **NO** | **`BENIGN`** | Both engines agree traffic is benign. | `NONE` |

### Discrepancy Auditing

Any disagreement between the statistical ML model and deterministic rules is explicitly preserved in the flow record as `RULE` or `RF` (not silently collapsed). This gives security analysts full visibility into edge cases and adversarial evasion attempts.
