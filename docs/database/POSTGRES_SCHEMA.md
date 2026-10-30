# XRL-IDARS — PostgreSQL Database Schema & Index Specification

## 1. DDL: Table `security_events`

The `security_events` table preserves complete multi-tier perception, explainability, source tracking, and autonomous response metadata produced by XRL-IDARS.

```sql
CREATE TABLE IF NOT EXISTS security_events (
    event_id VARCHAR(64) PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    flow_id VARCHAR(128) NOT NULL,
    source_mode VARCHAR(32) NOT NULL,
    source_ip VARCHAR(64) NOT NULL,
    dest_ip VARCHAR(64) NOT NULL,
    source_port INTEGER NOT NULL,
    dest_port INTEGER NOT NULL,
    protocol INTEGER NOT NULL,
    hybrid_verdict VARCHAR(32) NOT NULL,
    hybrid_risk_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    severity VARCHAR(32) NOT NULL,
    source_escalated BOOLEAN NOT NULL DEFAULT FALSE,
    features JSONB NOT NULL DEFAULT '{}'::jsonb,
    detection JSONB NOT NULL DEFAULT '{}'::jsonb,
    rule_matches JSONB NOT NULL DEFAULT '[]'::jsonb,
    source_status JSONB NOT NULL DEFAULT '{}'::jsonb,
    explanation JSONB,
    response JSONB NOT NULL DEFAULT '{}'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

---

## 2. Column Dictionary & Type Mapping

| Column | PostgreSQL Type | Python Data Type | Description |
| :--- | :--- | :--- | :--- |
| `event_id` | `VARCHAR(64)` | `str` | Unique primary key (e.g. `evt-1a2b3c4d5e6f`) |
| `timestamp` | `TIMESTAMPTZ` | `str` (ISO8601) | Timestamp of event creation with UTC timezone |
| `flow_id` | `VARCHAR(128)` | `str` | Canonical bidirectional flow identifier |
| `source_mode` | `VARCHAR(32)` | `str` | Ingestion mode: `LIVE`, `PCAP`, or `SAMPLE` |
| `source_ip` | `VARCHAR(64)` | `str` | IPv4/IPv6 source address |
| `dest_ip` | `VARCHAR(64)` | `str` | IPv4/IPv6 destination address |
| `source_port` | `INTEGER` | `int` | Transport layer source port number |
| `dest_port` | `INTEGER` | `int` | Transport layer destination port number |
| `protocol` | `INTEGER` | `int` | IANA protocol number (TCP=6, UDP=17) |
| `hybrid_verdict`| `VARCHAR(32)` | `str` | Arbitration verdict: `BENIGN`, `RF`, `RULE`, `HYBRID` |
| `hybrid_risk_score` | `DOUBLE PRECISION` | `float` | Continuous calibrated risk score in range `[0.0, 1.0]` |
| `severity` | `VARCHAR(32)` | `str` | Categorical severity: `NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `source_escalated` | `BOOLEAN` | `bool` | True if source IP activity tracker flagged escalation |
| `features` | `JSONB` | `dict[str, float]` | R10 real-time extracted flow statistical features |
| `detection` | `JSONB` | `dict[str, Any]` | Random Forest output, attack family distribution, thresholds |
| `rule_matches` | `JSONB` | `list[dict]` | Deterministic protocol violation records |
| `source_status`| `JSONB` | `dict[str, Any]` | Sliding window flow rates, burst indicators, threat counts |
| `explanation` | `JSONB` | `dict[str, Any]` | TreeSHAP local attributions, top features, base value |
| `response` | `JSONB` | `dict[str, Any]` | Dueling DQN 6D state, Q-values, Safety Gate enforced action |
| `metadata` | `JSONB` | `dict[str, Any]` | Sensor identification, capture interface, pipeline version |
| `created_at` | `TIMESTAMPTZ` | `datetime` | Database row insertion timestamp |

---

## 3. Performance Indexes

Six B-tree indexes optimize high-frequency dashboard queries and analytical filtering:

```sql
-- 1. Primary time-series sort for dashboard real-time feeds
CREATE INDEX IF NOT EXISTS idx_security_events_timestamp 
    ON security_events (timestamp DESC);

-- 2. Fast source IP lookup and threat tracking
CREATE INDEX IF NOT EXISTS idx_security_events_source_ip 
    ON security_events (source_ip);

-- 3. Severity filtering for alert dashboards
CREATE INDEX IF NOT EXISTS idx_security_events_severity 
    ON security_events (severity);

-- 4. Hybrid arbitration verdict filtering
CREATE INDEX IF NOT EXISTS idx_security_events_hybrid_verdict 
    ON security_events (hybrid_verdict);

-- 5. Ingestion source isolation (LIVE vs PCAP vs SAMPLE)
CREATE INDEX IF NOT EXISTS idx_security_events_source_mode 
    ON security_events (source_mode);

-- 6. Composite index for host-specific timeline queries
CREATE INDEX IF NOT EXISTS idx_security_events_source_time 
    ON security_events (source_ip, timestamp DESC);
```

---

## 4. JSONB Structure Specifications

### `features` (R10 Real-Time Flow Statistics)
```json
{
  "flow_duration_ms": 125.4,
  "flow_packets_per_s": 420.5,
  "flow_bytes_per_s": 154200.0,
  "packet_length_mean": 366.7,
  "packet_length_std": 210.1,
  "syn_count": 28.0,
  "ack_count": 0.0,
  "rst_count": 0.0,
  "fin_count": 0.0,
  "syn_ack_ratio": 28.0
}
```

### `detection` (Random Forest Inference)
```json
{
  "model_name": "Random Forest (Sole Operational Detector)",
  "attack_score": 0.942,
  "prediction_label": "ATTACK",
  "attack_family": "DoS/DDoS",
  "attack_family_confidence": 0.96,
  "family_probabilities": {
    "BENIGN": 0.04,
    "DoS/DDoS": 0.96,
    "PortScan": 0.00,
    "BruteForce": 0.00,
    "Botnet": 0.00,
    "WebAttack": 0.00
  }
}
```

### `explanation` (TreeSHAP Local Attributions)
```json
{
  "base_value": 0.50,
  "top_attributions": {
    "syn_count": 0.385,
    "flow_packets_per_s": 0.124,
    "syn_ack_ratio": 0.082
  },
  "explanation_algorithm": "TreeSHAP"
}
```

### `response` (Dueling DQN & Deterministic Safety Gate)
```json
{
  "proposed_action": "ISOLATE",
  "enforced_action": "ALERT",
  "safety_override": true,
  "override_reason": "CRITICAL_INFRASTRUCTURE_EXEMPTION",
  "q_values": {
    "ALLOW": -12.4,
    "ALERT": -1.8,
    "RATE_LIMIT": -4.2,
    "ISOLATE": -0.9
  },
  "state_vector": [0.942, 0.25, 0.60, 0.333, 0.0, 0.75]
}
```
