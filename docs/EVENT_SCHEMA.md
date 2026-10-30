# XRL-IDARS — Canonical Security Event Schema Specification

**Module:** `src/xrlids/events/schema.py` (`SecurityEvent`), `src/xrlids/events/manager.py` (`EventManager`)

---

## 1. Schema Overview

The XRL-IDARS architecture unifies perception (ML detection), deterministic protocol analysis (rules), local feature attribution (TreeSHAP), host behavioural tracking (Source-IP Tracker), and policy decision-making (DQN + Safety Gate) through a canonical, JSON-serializable `SecurityEvent`.

Every network flow evaluated by the active inference pipeline produces an immutable `SecurityEvent` published to the event bus and appended to the persistent JSONL audit trail (`results/audits/security_events.jsonl`).

---

## 2. Field Definitions

| Category | Field Name | Data Type | Description |
|---|---|---|---|
| **Identity & Timing** | `event_id` | String | Globally unique identifier (e.g., `evt-a1b2c3d4e5f6`). |
| | `timestamp` | String | ISO 8601 UTC timestamp of event generation. |
| | `flow_id` | String | Unique flow session identifier. |
| **Network Endpoints** | `source_ip` | String | Source IPv4 address of initiating flow. |
| | `dest_ip` | String | Destination IPv4 address. |
| | `source_port` | Integer | Source port number ($0 - 65535$). |
| | `dest_port` | Integer | Destination port number ($0 - 65535$). |
| | `protocol` | Integer | IANA protocol number ($6 = \text{TCP}, 17 = \text{UDP}$). |
| **Features** | `features` | Object | Full validated $R_{10}$ statistical feature dictionary. |
| **ML Perception** | `detection.model_name` | String | Name of active champion detector (e.g. Random Forest / XGBoost). |
| | `detection.attack_score` | Float | Continuous posterior threat probability $P(\text{ATTACK}) \in [0.0, 1.0]$. |
| | `detection.prediction_label`| String | `BENIGN` or `ATTACK` (at decision threshold $\tau = 0.50$). |
| **Rules & Behaviour** | `rule_matches` | Array | List of matched deterministic rule records (`rule_id`, `description`, `severity`). |
| | `hybrid_verdict` | String | Arbitration outcome: `BENIGN`, `RF`, `RULE`, `HYBRID`. |
| | `severity` | String | Severity rating: `NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`. |
| | `source_escalated` | Boolean | True if source IP crossed 5-flow / 60s sliding threshold. |
| **Explainability** | `explanation.top_features` | Array | Top features sorted by absolute Shapley magnitude with directionality. |
| | `explanation.base_value` | Float | Expected model output baseline $\mathbb{E}[f(x)]$. |
| **Response & Safety** | `response.proposed_action`| String | Action recommended by Dueling DQN policy (`ALLOW`, `ALERT`, `RATE_LIMIT`, `ISOLATE`). |
| | `response.enforced_action`| String | Action verified and enforced by Deterministic Safety Gate. |
| | `response.safety_override` | Boolean | True if Deterministic Safety Gate modified the proposal. |
| | `response.q_values` | Object | Full action-value distribution from DQN policy. |
| | `response.justification` | String | Human-readable explanation of response decision. |
