# Phase 3 — Live Network + Validation + Controlled Response (Week 3)

The most operationally important phase. Everything here is gated on earlier evidence.

## Deliverables

| Deliverable | Purpose | Status |
| --- | --- | --- |
| `PacketCaptureService` | Scapy capture with documented interface/filter/permissions | ⬜ |
| Flow construction | Packets → 5-tuple flows → statistics → feature vector | ⬜ |
| Flow timeout policy | Chosen per D-006, documented | ⬜ blocked |
| Live feature parity harness | Per-feature dataset vs Scapy comparison | ⬜ |
| `LIVE_FEATURE_PARITY.md` | Documented parity results + tolerances | ⬜ |
| Replay vs live distinction | Separate, non-combinable conclusions | ⬜ |
| `CONTROLLED_UNSEEN_TRAFFIC.md` | Distinguish synthetic rows / controlled packets / replay / held-out / cross-dataset / live | ⬜ |
| Performance profiling | P50/P95/P99 per component + end-to-end | ⬜ |
| Observability | Logs, metrics, health checks, error counters | ⬜ |
| Safety layer | Gate for every BLOCK | ⬜ |
| Dry-run mode | Log-only enforcement | ⬜ |
| Controlled enforcement | Real actuation in an isolated lab | ⬜ |
| Rollback | Undo any applied block, audited | ⬜ |
| Traffic burst case | "1000 packets from one click" experiment | ⬜ |
| Failure injection | Fail-safe behaviour for every dependency | ⬜ |
| Final operational report | Evidence-driven summary | ⬜ |

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
