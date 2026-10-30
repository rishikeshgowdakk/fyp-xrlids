# XRL-IDARS — Final Integration Verification Report

## 1. Runtime Environment Specifications

- **Operating System**: Linux x86_64 (`Ubuntu 24.04 / Linux 6.8`)
- **Python Runtime**: Python 3.14.4 (CPython, 64-bit virtual environment `.venv`)
- **Core ML Frameworks**:
  - PyTorch: `2.14.0+cpu`
  - Scikit-Learn: `1.9.1`
  - SHAP: `0.52.0`
  - NumPy: `2.2.3`
  - Pandas: `2.2.3`
- **Database Subsystem**:
  - PostgreSQL Engine: PostgreSQL 18.6 daemon (port 5433 / `xrlids` test database) & Docker Compose (`postgres:16-alpine` on port 5432)
  - Driver: `psycopg` 3.3.6 & `psycopg-binary` 3.3.6 (Native C-extension JSONB adaptation)
- **Frontend Framework**: Streamlit `1.66.1`
- **Networking & Capture**: Scapy `2.6.1`
- **Browser Automation & Evidence**: Playwright `1.58.0` / Google Chrome Headless `1440x960` (port 9222)
- **Git State**:
  - Branch: `fix/final-engineering-correctness`
  - Remote: `https://github.com/rishikeshgowdakk/fyp-xrlids.git`

---

## 2. Summary of Executed Commands

```bash
# 1. Environment and database verification
POSTGRES_PORT=5433 .venv/bin/pytest tests/unit/test_events_postgres.py tests/integration/test_postgres_storage_integration.py -v

# 2. Comprehensive regression test suite
.venv/bin/pytest -q

# 3. 10,000-Record Authoritative Benchmark Execution
.venv/bin/python scripts/demo/run_10k_benchmark.py

# 4. Streamlit Server Launch
POSTGRES_HOST=localhost POSTGRES_PORT=5433 POSTGRES_DB=xrlids POSTGRES_USER=xrlids_user XRLIDS_STORAGE_MODE=auto \
.venv/bin/streamlit run dashboard/streamlit_app.py --server.port 8501 --server.headless true

# 5. Supplementary REST API Server Launch
.venv/bin/python dashboard/server.py 8000

# 6. Automated Browser Evidence Collection & Screenshot Generation
.venv/bin/python scripts/demo/capture_final_evidence.py
```

---

## 3. Test Suite & Verification Results

### Backend Unit & Integration Tests
- **Full Test Suite Result**: **704 passed, 0 failed** across all test suites (100% pass rate in 85.34s).
- **PostgreSQL Persistence Tests**:
  - `tests/unit/test_events_postgres.py`: **7 passed, 0 failed**
  - `tests/integration/test_postgres_storage_integration.py`: **6 passed, 0 failed**
- **StateBuilder Contract**:
  - `tests/unit/test_response_state.py`: **7 passed, 0 failed**

### Frontend UI Verification
- Verified Streamlit multi-page application with exactly 3 primary navigation sections:
  1. `Overview` (`http://localhost:8501/`)
  2. `Live Demo` (`http://localhost:8501/Live_Demo`)
  3. `Benchmarks` (`http://localhost:8501/Benchmarks`)
- Supplementary REST API server running on port 8000: HTTP 200 on `/api/overview`, `/api/live/*`, `/api/demo/*`.

---

## 4. Genuine Traffic & Attack Demonstration Evidence

All demonstration traffic processed through the single canonical operational pipeline:
`Scapy / Sim / PCAP → Canonical FlowEngine → R10 Feature Extraction → StandardScaler → Random Forest → TreeSHAP → Dueling DQN → Deterministic Safety Gate → Advisory Actuator → EventManager → PostgreSQL`.

1. **Scenario A: Benign Ping (Safe Local Traffic)**:
   - Packets: Real ICMP Echo Request / Reply and normal TCP handshake.
   - Target: `10.200.1.3` (Isolated Lab Subnet).
   - Random Forest Score: `0.0142` ($P \le 0.15$).
   - Rule Matches: `None` (0 protocol violations).
   - Hybrid Verdict: `BENIGN` (Severity: `NONE`, Risk Score: `0.0142`).
   - Dueling DQN Recommendation: `ALLOW`.
   - Safety Gate: Approved.
   - Actuator: Zero mutations.

2. **Scenario C: Volumetric TCP SYN Burst**:
   - Packets: 60 asymmetric TCP SYN packets without ACKs to port 80.
   - Flow Features: `syn_count = 60.0`, `syn_ack_ratio = 60.0`, `flow_packets_per_s = 6000.0`.
   - Random Forest Score: `0.8850` (Prediction: `ATTACK`, Attack Family: `DoS/DDoS`, 94% confidence).
   - Rule Matches: `RULE-SYN-FLOOD` (Severity: `HIGH`).
   - Hybrid Verdict: `HYBRID` (Severity: `HIGH`, Risk Score: `0.8850`).
   - TreeSHAP Local Attributions: Top positive feature drivers: `syn_count` (+0.385), `flow_packets_per_s` (+0.124), `syn_ack_ratio` (+0.082).
   - Dueling DQN State Vector: $[0.8850, 0.2000, 0.5000, 0.3333, 0.0000, 0.6000]$.
   - Q-Values: `ALLOW: -104.8`, `ALERT: -19.0`, `RATE_LIMIT: -23.1`, `ISOLATE: -11.3` (Advantage: $\Delta Q = 7.78$).
   - Safety Gate Check: Verified critical host exemption (not critical), verified 30s cooldown, verified $<5\%$ blast-radius limit.
   - Authorized Action: `ISOLATE`.
   - Actuator Audit: Advisory dry-run mode (0 kernel mutations, verified safe).
   - Persistence: Persisted to PostgreSQL table `security_events` with complete JSONB attributes.

3. **Scenario D: Controlled ICMP Flood**:
   - Packets: 40 ICMP Echo packets at 40 pps targeting loopback/lab.
   - Detection: `RULE-ICMP-FLOOD` matched; hybrid verdict `RULE` / `ATTACK`.
   - DQN Action: `RATE_LIMIT` recommended and authorized.

4. **Scenario B: Port Scan Simulation**:
   - Packets: Controlled probes across ports 21, 22, 80, 443, 8080.
   - Detection: `RULE-PORT-SCAN` matched; hybrid verdict `RULE` / `ATTACK`.

5. **PCAP Replay (`data/demo/sample_traffic.pcap`)**:
   - Replayed authentic wire frames.
   - Assembled into canonical bidirectional flows and processed with continuous event correlation.

---

## 5. PostgreSQL Persistence Verification

- **Schema**: `security_events` table initialized with 6 B-tree indexes.
- **Round-Trip Integrity**: Tested and verified across all 6 structured JSONB columns (`features`, `detection`, `rule_matches`, `source_status`, `explanation`, `response`).
- **Restart Persistence Proof**: A fresh `EventManager` process instance with an empty in-memory buffer successfully queried PostgreSQL and retrieved historical events intact.
- **Outage Resilience**: Bounded async worker absorbed connection failures to unreachable port `5499` with exponential backoff; EventManager cleanly transitioned to `memory` mode with JSONL append logging without blocking or crashing the operational packet pipeline.

---

## 6. Authoritative 10,000-Record Benchmark Results

Evaluated across 10,000 genuine records from CIC-IDS2017:

| Model | Evaluated Population | Accuracy | Precision | Recall | F1-Score | ROC-AUC | Inference Latency | Line-Rate Wire Viability |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Random Forest (Operational Champion)** | 10,000 | **85.42%** | **0.9718** | **0.7296** | **0.8334** | **0.9834** | **0.78 ms** | **YES (< 1.0 ms)** |
| **PyTorch LSTM FlowSeq (5 Flows)** | 9,969 | 77.77% | 0.9859 | 0.5624 | 0.7163 | 0.9671 | 12.45 ms | NO (Buffer overflow risk) |
| **Convex RF–LSTM Fusion ($\alpha=0.70$)** | 9,969 | 82.79% | 0.9976 | 0.6565 | 0.7919 | 0.9814 | 13.25 ms | NO (Recurrent latency) |

### Confusion Matrices (10k Record Run):
- **Random Forest**: `TN = 4894`, `FP = 106`, `FN = 1352`, `TP = 3648` (FPR: 2.12%, FNR: 27.04%).
- **PyTorch LSTM**: `TN = 4956`, `FP = 40`, `FN = 2176`, `TP = 2797` (FPR: 0.80%, FNR: 43.76%).
- **RF–LSTM Fusion**: `TN = 4988`, `FP = 8`, `FN = 1708`, `TP = 3265` (FPR: 0.16%, FNR: 34.35%).

*Note:* On targeted flood/DDoS attack windows (`EXP-P2-LSTM-VALID-001`), the LSTM sequence model achieves $99.96\%$ F1. Across the diverse 10,000 mixed-family evaluation, Random Forest demonstrates superior generalization and statutory resilience against cold-start sequence delay.

---

## 7. Verified Screenshots Index (`docs/screenshots/`)

All 12 screenshots were captured from the authentic running application via headless Chrome automation:

| File Name | Description & Visible Artifacts | Status |
| :--- | :--- | :---: |
| [`01-overview-architecture.png`](docs/screenshots/01-overview-architecture.png) | Animated architecture flowchart, decoupled pipeline stages, async PostgreSQL persistence branch | **VERIFIED** |
| [`02-live-demo-benign.png`](docs/screenshots/02-live-demo-benign.png) | Benign ping simulation, ICMP flow extraction, RF score $\le 0.15$, clean rule engine | **VERIFIED** |
| [`03-live-demo-attack.png`](docs/screenshots/03-live-demo-attack.png) | Controlled TCP SYN burst, real-time threat score 0.885, high SYN/ACK ratio | **VERIFIED** |
| [`04-random-forest-detection.png`](docs/screenshots/04-random-forest-detection.png) | RF score gauge, 0.50 threshold, attack family probabilities, deterministic rule matches | **VERIFIED** |
| [`05-rules-and-explainability.png`](docs/screenshots/05-rules-and-explainability.png) | TreeSHAP local Shapley feature attributions, base value, positive/negative drivers | **VERIFIED** |
| [`06-dqn-response.png`](docs/screenshots/06-dqn-response.png) | 6D causal state vector $\mathbf{s}_t$, action Q-values, proposed response action | **VERIFIED** |
| [`07-response-audit.png`](docs/screenshots/07-response-audit.png) | Deterministic safety gate check, critical host protection, advisory dry-run verification | **VERIFIED** |
| [`08-pcap-replay.png`](docs/screenshots/08-pcap-replay.png) | PCAP stream replay of `sample_traffic.pcap`, completed flows and live event metrics | **VERIFIED** |
| [`09-benchmark-overview.png`](docs/screenshots/09-benchmark-overview.png) | 10k benchmark configuration, dataset selection, schema validation provenance | **VERIFIED** |
| [`10-benchmark-confusion-matrix.png`](docs/screenshots/10-benchmark-confusion-matrix.png) | 2x2 confusion matrices for Random Forest, PyTorch LSTM, and RF-LSTM Fusion | **VERIFIED** |
| [`11-benchmark-model-comparison.png`](docs/screenshots/11-benchmark-model-comparison.png) | Head-to-head comparison table and empirical inference latency bar chart | **VERIFIED** |
| [`12-postgres-event-history.png`](docs/screenshots/12-postgres-event-history.png) | Historical security events retrieved from PostgreSQL database store | **VERIFIED** |

---

## 8. Remaining Known Limitations

1. **User-Space Ingestion Rate**: Scapy Python-space packet capture is bounded by CPU scheduling ($\approx 2,000 \to 5,000\,\text{pps}$). High-speed traffic bursts rely on canonical flow aggregation before event generation.
2. **Asynchronous Write Delay**: Events dispatched via the non-blocking persistence worker are buffered for up to 0.5s before batch flush. Historical SQL queries executed immediately within sub-millisecond windows after `publish()` may not yet see the uncommitted batch in PostgreSQL, although the events are immediately readable from the in-memory ring buffer.
3. **Advisory Execution**: All automated mitigations operate in dry-run mode to ensure zero uncommanded host network disruption.
