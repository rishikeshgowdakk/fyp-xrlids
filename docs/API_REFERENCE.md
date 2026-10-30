# XRL-IDARS — HTTP REST & WebSocket API Reference

**Document ID:** `DOC-API-REFERENCE-001`  
**Version:** 1.0.0  
**Status:** COMPLETE & AUTHORITATIVE  
**Date:** October 30, 2026  
**Server Host:** `dashboard/server.py` (Default: `http://localhost:8000`)  

---

## 1. Primary Information Endpoints (GET)

### 1. `GET /api/overview`
Returns high-level system telemetry, active detector information, throughput, and error counts.

#### Response (200 OK):
```json
{
  "status": "running",
  "operational_mode": "ADVISORY / DRY_RUN",
  "primary_detector": "Random Forest (R10 Contract)",
  "uptime_seconds": 142.5,
  "packets_total": 45120,
  "flows_total": 2340,
  "alerts_total": 12,
  "pps": 316.6,
  "fps": 16.4
}
```

### 2. `GET /api/flows?limit=50`
Returns the latest completed bidirectional flow observations from the in-memory ring buffer.

#### Response (200 OK):
```json
{
  "flows": [
    {
      "flow_id": "flow_1042",
      "timestamp": "2026-10-30T14:22:15.102Z",
      "src_ip": "192.168.1.100",
      "src_port": 54320,
      "dst_ip": "192.168.1.10",
      "dst_port": 80,
      "protocol": "TCP",
      "packets": 12,
      "bytes": 1420,
      "duration_ms": 45.2,
      "score": 0.021,
      "prediction": "BENIGN",
      "source": "RANDOM_FOREST"
    }
  ]
}
```

### 3. `GET /api/explainability?flow_id=flow_1042`
Returns the exact TreeSHAP Lundberg attribution values for a specific flow.

#### Response (200 OK):
```json
{
  "flow_id": "flow_1042",
  "base_value": 0.500,
  "prediction_score": 0.991,
  "features": {
    "flow_duration_ms": 3250.0,
    "flow_packets_per_s": 0.615,
    "flow_bytes_per_s": 219.07,
    "packet_length_mean": 356.0,
    "packet_length_std": 0.0,
    "syn_count": 1.0,
    "ack_count": 1.0,
    "rst_count": 1.0,
    "fin_count": 0.0,
    "syn_ack_ratio": 1.0
  },
  "attributions": {
    "flow_duration_ms": 0.354,
    "flow_packets_per_s": 0.182,
    "syn_ack_ratio": 0.121,
    "packet_length_std": -0.052
  }
}
```

---

## 2. Live Control Endpoints (POST)

### 1. `POST /api/live/start`
Starts packet capture or stream replay in the background.

#### Request Body (JSON):
```json
{
  "mode": "live",
  "interface": "eth0",
  "benchmark": "cicids2017"
}
```

### 2. `POST /api/live/stop`
Gracefully halts capture and flushes active flow tables.

### 3. `POST /api/live/inject-attack`
Injects a calibrated Scapy scenario into the active monitor.

#### Request Body (JSON):
```json
{
  "scenario": "scenario_c_syn_burst",
  "target_ip": "10.200.1.3"
}
```
