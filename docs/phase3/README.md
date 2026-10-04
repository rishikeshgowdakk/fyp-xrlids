# Phase 3 — Live Network + Validation + Controlled Response (Week 3)

The most operationally important phase. Everything here is gated on earlier evidence.

## Deliverables

| Deliverable | Purpose | Subphase | Status |
| --- | --- | --- | --- |
| `PacketCaptureService` | Capture abstraction with interface/filter/permission handling | Phase 3A | 🟡 Implemented (Pure-Python + Scapy-ready) |
| Flow construction | Packets → 5-tuple flows → statistics → R10 feature vector | Phase 3B | ✅ Reusable & Extended (`xrlids.live.flow_builder`) |
| Flow timeout policy | Option D Hybrid: TCP FIN/RST + 120s idle timeout (Decision D-006) | Phase 3B | ✅ RESOLVED (D-006 Hybrid Policy) |
| Live feature parity harness | Multi-sample dataset vs live streaming flow comparison | Phase 3C | 🟡 Implemented (`xrlids.live.parity`) |
| `LIVE_FEATURE_PARITY.md` | Documented parity results + numerical tolerances | Phase 3C | ✅ Documented |
| Replay vs live distinction | Separate, non-combinable conclusions | Phase 3D | ✅ Documented (`CONTROLLED_UNSEEN_TRAFFIC.md`) |
| `CONTROLLED_UNSEEN_TRAFFIC.md` | Distinguish synthetic rows / controlled packets / replay / held-out / cross-dataset / live | Phase 3D | ✅ Documented |
| Performance profiling | P50/P95/P99 latency per component + end-to-end | Phase 3E | ✅ EMPIRICALLY OBSERVED (`EXP-P3-BURST-1000-001`) |
| Observability | Logs, metrics, health checks, error counters | Phase 3F | ✅ EMPIRICALLY OBSERVED & DOCUMENTED (`EXP-P3F-OBSERVABILITY-001`) |
| Safety layer | Deterministic gate for every autonomous action | Cross-cutting | ✅ Reusable (`xrlids.response.safety`) |
| Dry-run mode | Log-only enforcement with guaranteed zero network mutation | Phase 3B/3C | ✅ Implemented (`LiveMode.DRY_RUN`) |
| Controlled enforcement | Real actuation in an isolated lab (strictly locked behind rollback) | Controlled Lab | 🔒 LOCKED (Simulated Rollback Verified; Physical Netns Pending) |
| Rollback specification | Atomic rollback, state snapshot, failure handling | Phase 3G | ✅ EMPIRICALLY OBSERVED & AUDITED (`EXP-P3G-ROLLBACK-001`) |
| Traffic burst case | "1000 packets from one click" experiment execution | Lab Experiment | ✅ EXECUTED & COMMITTED (`EXP-P3-BURST-1000-001`) |
| Failure injection | Fail-safe behaviour for every dependency | Robustness | ✅ VERIFIED & AUDITED (6/6 Scenarios Pass) |
| Atomic rollback harness | Formal transaction lifecycle, SHA-256 snapshots, auto-compensation | Phase 3G | ✅ VERIFIED & AUDITED (12/12 Scenarios Pass) |
| Final operational report | Evidence-driven summary | Final Closure | ⬜ Planned |

## Flow Completion Policy (Decision D-006)
 
Per Decision `D-006` (`docs/03_DECISIONS/DECISION_LOG.md`), the flow completion policy is **Option D (Hybrid flow completion policy)**:
1. **TCP FIN/RST termination**: When a TCP packet bearing the `FIN` or `RST` flag is observed, the active flow tracking state is immediately marked closed (`is_closed = True`) and flushed for feature extraction and model inference.
2. **120.0s idle timeout fallback**: For connectionless protocols (e.g., UDP) or TCP connections lacking clean teardown, flows exceeding `120.0` seconds of inactivity since the last packet arrival are expired and flushed.
3. **Temporal separation invariant**: The implementation preserves the strict distinction between:
   - **Replay timing**: Flow expiration is driven strictly by packet header timestamps (`pkt.timestamp`).
   - **Live streaming timing**: Flow expiration is driven by system arrival clock (`time.monotonic()` or arrival timestamps).

## Phase 3 Execution Architecture & Subphase Roadmap

```text
Live Network / Controlled PCAP
            │
    [Phase 3A: PacketCaptureService] (Interface/BPF/Perms/Observational)
            │ PacketInfo stream
    [Phase 3B: Live Flow Construction] (Canonical 5-Tuple + D-006 Hybrid Policy)
            │ Completed Flow
    [Phase 1 Frozen R10 Feature Vector] (Exact mathematical formulas)
            │
    [Frozen Phase 1 RF Detector] (EXP-P1-CIC2017-R10-001)
            │ Threat score S_t in [0.0, 1.0]
    [Phase 2 State Builder] (Causal 6D state: S_t, ΔS_t, N_alert, a_{t-1}, c_t, v_t)
            │
    [Phase 2 Frozen Policy] (Dueling DQN or Deterministic Baselines)
            │ Proposed action a_t
    [Phase 2 Deterministic Safety Gate] (Cooldown, Blast Radius Breaker, Critical Exemptions)
            │ Enforced action a*_t
    [Dry-Run Auditor] (Immutable structured audit record; ZERO network mutations)
```

### Subphases:
- **Phase 3A — Live Capture Foundation**:
  - `PacketCaptureService` abstraction supporting live interface capture, mock packet streams, and PCAP replay.
  - BPF filtering, permission detection (`CAP_NET_RAW`), packet/drop/error counters.
  - Observational mode only.
- **Phase 3B — Live Flow Construction**:
  - Packets → Canonical 5-tuple (`FlowKey`) → Bidirectional Flow Accumulator (`Flow`) → D-006 Completion → R10 Feature Vector.
  - Strict reuse of Phase 1 canonical definitions (`R10_FEATURES`).
- **Phase 3C — Live Feature Parity**:
  - Reproducible harness comparing offline canonical formulas vs streaming flow accumulator across multi-packet scenarios.
  - Formally documented in [`LIVE_FEATURE_PARITY.md`](LIVE_FEATURE_PARITY.md).
- **Phase 3D — Replay vs Live Separation**:
  - Formal taxonomic boundary documented in [`CONTROLLED_UNSEEN_TRAFFIC.md`](CONTROLLED_UNSEEN_TRAFFIC.md).
- **Phase 3E — Performance Profiling**:
  - Component-level latency profiling (P50, P95, P99).
- **Phase 3F — Observability & Safety Audit**:
  - Structured audit logging, health metrics, and backpressure handling documented in [`PHASE3F_OBSERVABILITY_REPORT.md`](PHASE3F_OBSERVABILITY_REPORT.md).
- **Phase 3G — Atomic Rollback & Controlled Response Transaction Harness**:
  - Atomic transaction lifecycle (`IDLE -> SNAPSHOT -> VALIDATE -> PREPARE -> APPLY -> VERIFY -> COMMITTED`), SHA-256 snapshots, auto-compensation rollback, watchdog TTL monitoring, and permanent safety locking documented in [`PHASE3G_ROLLBACK_REPORT.md`](PHASE3G_ROLLBACK_REPORT.md).


## Enforcement precondition chain (§75)

> Controlled enforcement may only be enabled after **all** of:

```text
feature parity PASS → replay PASS → dry-run PASS → safety tests PASS → rollback PASS
```

Any failure stops the chain. Do not proceed to enforcement.

## Ground-truth rule (§64)

Live predictions are **not** accuracy without ground truth. Report flows processed,
predictions generated, latency, throughput, stability and action distribution instead.

## Exit criteria (§93)

Scapy ✓ · Flow builder ✓ · Live feature parity ✓ · Replay/live distinction ✓ ·
Performance profiling ✓ · Observability ✓ · Safety layer ✓ · Dry-run ✓ ·
Controlled enforcement ✓ · Rollback ✓ · Controlled network experiment ✓ · Final report ✓

