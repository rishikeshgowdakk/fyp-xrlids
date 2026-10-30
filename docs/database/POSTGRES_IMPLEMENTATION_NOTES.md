# XRL-IDARS — PostgreSQL Event Persistence Implementation Notes

## 1. Architectural Overview & Design Philosophy

XRL-IDARS (Explainable Reinforcement Learning-Based Intrusion Detection and Autonomous Response System) operates a real-time, low-latency network intrusion detection and response pipeline. In this architecture, **Random Forest (RF)** serves as the sole operational ML detector, **TreeSHAP** provides local feature attributions, and a **Dueling Deep Q-Network (DQN)** coupled with a **Deterministic Safety Gate** recommends autonomous response actions.

The event persistence layer integrates PostgreSQL into this event lifecycle without modifying the perception, explainability, or decision engines.

### End-to-End Operational Pipeline
```
[Live Scapy / PCAP Replay]
           │
           ▼
[Canonical FlowEngine (Bidirectional Flow Tracking)]
           │
           ▼
[R10 Feature Extraction & StandardScaler]
           │
           ▼
[Random Forest Perception Engine] (Sole Operational ML Detector)
           │
           ▼
[SecurityEvent Object Assembly]
    ├── Detection Tier (RF Score, Multi-Class Family, Thresholds)
    ├── Rule Tier (Deterministic Protocol Invariants)
    ├── Source Activity Tracker (Rate Bursts, Threat History)
    ├── Explainability Tier (TreeSHAP Attributions)
    └── Response Tier (Dueling DQN State, Q-Values, Safety Gate Enforced Action)
           │
           ▼
[EventManager.publish()]
    ├── 1. In-Memory Ring Buffer (O(1), 5000 Events) ──► Immediate UI Reactivity
    ├── 2. Append-Only JSONL Audit Log (Independent Audit Trail)
    ├── 3. Subscriber Callbacks (Non-blocking notification)
    └── 4. Bounded Asynchronous Persistence Queue (Capacity: 10,000)
                 │
                 ▼
     [PostgresAsyncPersistenceWorker Daemon Thread]
                 │
                 ▼ (Batch Inserts with Parameterized JSONB)
     [PostgreSQL Database: security_events]
```

---

## 2. Critical Contract: Non-Blocking Persistence

`EventManager.publish()` is an operational method executed directly in the packet capture and flow reconstruction path. Network packet ingestion must never stall due to database network latency, connection pooling waits, lock contention, or transient database outages.

### Invariant Guarantees:
1. **$O(1)$ Submission**: `publish()` appends to the in-memory ring buffer and submits to `async_worker.enqueue(event)` using non-blocking `queue.Queue.put_nowait()`.
2. **Queue Capacity & Saturation Policy**:
   - Default queue capacity is bounded to 10,000 events (`XRLIDS_ASYNC_QUEUE_SIZE`).
   - If the persistence queue fills completely (e.g., during sustained database outage under heavy attack traffic), `enqueue()` safely drops the database persistence job for excess events while keeping them in the in-memory ring buffer and JSONL log.
   - Dropped events increment `total_dropped_queue_full` and log rate-limited warnings. The operational detection pipeline experiences zero stalling.
3. **Dedicated Batch Ingestion Daemon**:
   - `PostgresAsyncPersistenceWorker` executes in an independent Python daemon thread (`xrlids-pg-worker`).
   - Gathers batches up to 100 events (`XRLIDS_ASYNC_BATCH_SIZE`) or flushes every 0.5s (`XRLIDS_ASYNC_FLUSH_INTERVAL`).
   - Submits multi-row parameterized `executemany` transactions.
4. **Outage Backoff**:
   - On database write failure, the worker logs the error, tracks error counters, and implements exponential backoff (0.5s to 3.0s) before retrying.
5. **Graceful Shutdown**:
   - `close()` / `flush_and_stop()` drains all queued items to the database within a configurable timeout before thread termination.

---

## 3. Storage Modes & Fault Isolation

The storage subsystem supports three explicit operational modes via the `XRLIDS_STORAGE_MODE` environment variable:

| Mode | Behaviour | Database Unreachable Handling |
| :--- | :--- | :--- |
| **`auto`** (Default) | Attempts PostgreSQL initialization. If reachable, enables async worker and schema verification. | Logs informational warning and falls back seamlessly to `memory` mode with JSONL logging. Pipeline never crashes. |
| **`postgres`** | PostgreSQL is strictly required for production deployment. | Raises explicit `ConnectionError` on initial startup if unreachable, preventing silent unpersisted execution. If outage occurs post-startup, worker absorbs errors and preserves pipeline flow. |
| **`memory`** | Bypasses PostgreSQL entirely. Uses in-memory ring buffer and secondary JSONL export. | Standard offline mode. Zero external service dependencies; perfectly suited for local unit testing and development. |

---

## 4. Historical Event Retrieval & Process Restart Resilience

1. **Empty Ring Buffer Auto-Query**:
   When the XRL-IDARS dashboard or daemon restarts, the in-memory ring buffer is initially empty (`len(_buffer) == 0`). When `get_recent_events()` is called with an active PostgreSQL connection, it automatically queries the persistent database, ensuring that historical security events appear on dashboard pages across restarts.
2. **Dual-Mode Filtering**:
   - **In-Memory**: Fast slicing over ring buffer with predicate matching (`severity`, `hybrid_verdict`, `source_ip`, `source_mode`).
   - **PostgreSQL**: Parameterized SQL queries using B-tree indexes on `timestamp DESC`, `source_ip`, `severity`, and `hybrid_verdict`.
3. **Idempotent Storage**:
   Inserts utilize `ON CONFLICT (event_id) DO NOTHING`, ensuring that duplicate event delivery or replayed batches never corrupt existing security event records.
