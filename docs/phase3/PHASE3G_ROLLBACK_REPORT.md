# Phase 3G Empirical Research Report: Atomic Rollback & Controlled Response Transaction Harness

**Document Identifier**: `REPORT-P3G-ROLLBACK-001`  
**Experiment Identifier**: `EXP-P3G-ROLLBACK-001`  
**Git Baseline**: `bab43665fff76f5623cdd0dc0755d309c1b93027`  
**Execution Timestamp**: `2026-10-04T13:59:49.556074+00:00`  
**Operational Mode**: `LiveMode.CONTROLLED_ENFORCEMENT (SIMULATED_BACKEND_ONLY)`  
**Zero System Network Mutation**: `VERIFIED (True)` (0 iptables, 0 nftables, 0 tc, 0 sockets dropped)  
**Status**: `EMPIRICALLY VERIFIED & AUDITED`  

---

## 1. Executive Summary

Phase 3E characterized the latency profile of the perception-to-response loop under burst traffic, and Phase 3F demonstrated observability, health classification, and failsafe backpressure handling under subsystem failures.

**Phase 3G establishes the transaction safety foundation for autonomous response.** Before any autonomous mitigation action can ever be physically applied in a live or lab network, the system must guarantee that every mitigation is treated as an **atomic, reversible transaction**.

Phase 3G designs, implements, and empirically validates an isolated **Atomic Rollback & Controlled Response Transaction Harness** with:
1. **Pre-Action State Snapshotting**: Deterministic capture of baseline host/network rules and rate limits with canonical SHA-256 state hashing.
2. **Atomic Lifecycle Management**: Strict state transitions (`IDLE -> SNAPSHOT -> VALIDATE -> PREPARE -> APPLY -> VERIFY -> COMMITTED`) with automatic compensation rollback on any exception, timeout, or state verification failure.
3. **Restoration Verification**: Rollback operations are not declared successful until the restored state's SHA-256 digest is recomputed and matches the pre-action baseline digest.
4. **Permanent Safety Lock**: If a rollback itself fails or restoration verification fails, the system immediately engages a permanent `SAFETY_LOCKED` state, preventing any further network mutations.
5. **Rollback Idempotency**: Repeated rollback invocations are safely handled as `IDEMPOTENT_NOOP`, avoiding state oscillation or double-reversal defects.
6. **Watchdog TTL Monitoring**: An active watchdog monitors transactions with configurable Time-To-Live (TTL); missing heartbeats automatically trigger compensation rollback.

All empirical evaluations were performed using a simulated, purely in-memory actuator backend with **zero host network mutations**.

---

## 2. Transaction Lifecycle & Architecture

The transaction architecture implements the formal specification defined in `docs/phase3/CONTROLLED_RESPONSE_SAFETY.md`:

```text
               ┌──────────┐
               │   IDLE   │
               └────┬─────┘
                    │ Execute Transaction
                    ▼
               ┌──────────┐
               │ SNAPSHOT │ (Capture baseline state + SHA256 digest)
               └────┬─────┘
                    │ Digest Valid?
         ┌──────────┴──────────┐
         │ No                  │ Yes
         ▼                     ▼
    ┌─────────┐          ┌──────────┐
    │ ABORTED │          │ VALIDATE │ (Verify snapshot schema & integrity)
    └─────────┘          └────┬─────┘
                              │
                              ▼
                         ┌──────────┐
                         │ PREPARE  │ (Evaluate Deterministic Safety Gate)
                         └────┬─────┘
                              │ Clamped to ALLOW?
                   ┌──────────┴──────────┐
                   │ Yes                 │ No (ISOLATE / RATE_LIMIT)
                   ▼                     ▼
            ┌───────────┐           ┌──────────┐
            │ COMMITTED │           │  APPLY   │ (Apply mutation via Actuator)
            └───────────┘           └────┬─────┘
                                         │ Exception / Timeout?
                              ┌──────────┴──────────┐
                              │ Failure             │ Success
                              ▼                     ▼
                     ┌────────────────┐        ┌──────────┐
                     │  ROLLING_BACK  │        │  VERIFY  │ (Post-action state verification)
                     └────────┬───────┘        └────┬─────┘
                              │                     │ Verification Passed?
                              │          ┌──────────┴──────────┐
                              │          │ Yes                 │ No
                              │          ▼                     ▼
                              │    ┌───────────┐      ┌────────────────┐
                              │    │ COMMITTED │      │  ROLLING_BACK  │
                              │    └───────────┘      └────────┬───────┘
                              │                                │
                              └────────────────┬───────────────┘
                                               │
                                               ▼
                                    ┌───────────────────────┐
                                    │ Restored Digest Match?│
                                    └──────────┬────────────┘
                                               │
                                  ┌────────────┴────────────┐
                                  │ Yes                     │ No
                                  ▼                         ▼
                           ┌─────────────┐          ┌───────────────┐
                           │ ROLLED_BACK │          │ SAFETY_LOCKED │
                           └─────────────┘          └───────────────┘
```

### 2.1 Core Architectural Components

- **`StateSnapshot`**: Frozen dataclass capturing target host, timestamp, canonical baseline dictionary (`rules`, `rate_limits`, `isolated_hosts`, `active_qdiscs`), and the canonical SHA-256 hash computed via `dict_hash`. Validation checks that the computed hash equals `state_digest`.
- **`RollbackResult`**: Structured audit record capturing `success`, `transaction_id`, `snapshot_id`, `rollback_attempts`, `restoration_verified`, `failure_reason`, and `final_safety_state` (`RESTORED`, `IDEMPOTENT_NOOP`, or `SAFETY_LOCKED`).
- **`SimulatedActuatorBackend`**: Memory-only backend implementing the `RollbackBackend` and `ActuatorBackend` protocols. Features zero host system mutations and precise fault-injection controls:
  - `fail_snapshot`: Simulates snapshot capture failure.
  - `corrupt_snapshot_hash`: Simulates snapshot digest corruption.
  - `fail_mutation`: Simulates runtime exception during actuator execution.
  - `timeout_mutation`: Simulates actuator execution timeout (`TimeoutError`).
  - `partial_mutation`: Simulates incomplete mutation (e.g., rate limit set but firewall rule missing).
  - `fail_verification`: Simulates post-action state verification mismatch.
  - `fail_rollback`: Simulates rollback failure during compensation restoration.
- **`ControlledResponseTransactionManager`**: Orchestrates transaction lifecycle, integrates with the `DeterministicSafetyGate`, triggers automatic compensation rollback on errors, and latches into `SAFETY_LOCKED` if rollback fails.
- **`TransactionWatchdog`**: Monitors transaction lifetimes against TTL deadlines. If no heartbeat renewal is received, the watchdog automatically issues a compensation rollback.

---

## 3. Empirical Experiment Design (`EXP-P3G-ROLLBACK-001`)

The experiment evaluated 12 distinct deterministic scenarios covering nominal lifecycles, safety invariants, fault injections, watchdog timeouts, and idempotency:

| Scenario ID | Test Scenario Description | Injected Condition / Action | Expected Final State | Verified Invariant |
|---|---|---|---|---|
| `SCENARIO_1` | Nominal ISOLATE Transaction | Proposed `ISOLATE` on `192.168.1.101` | `COMMITTED` $\to$ `ROLLED_BACK` | Full lifecycle commit and explicit manual rollback verified. |
| `SCENARIO_2` | Nominal RATE_LIMIT Transaction | Proposed `RATE_LIMIT` (5 Mbps) on `192.168.1.102` | `COMMITTED` $\to$ `ROLLED_BACK` | Parameterized rate-limit commit and explicit rollback verified. |
| `SCENARIO_3` | Nominal ALLOW Transaction | Proposed `ALLOW` on `192.168.1.103` | `COMMITTED` | Direct commit with zero actuator mutation verified. |
| `SCENARIO_4` | Critical Infrastructure Exemption | Proposed `ISOLATE` on `192.168.10.1` (Gateway) | `COMMITTED` (`ALERT`) | Safety gate clamps `ISOLATE` to `ALERT`; zero isolation mutation. |
| `SCENARIO_5` | Mutation Exception Rollback | Fault injected: `fail_mutation = True` | `ROLLED_BACK` | Actuator exception triggers automatic rollback to baseline. |
| `SCENARIO_6` | Actuator Timeout Rollback | Fault injected: `timeout_mutation = True` | `ROLLED_BACK` | Actuator timeout triggers automatic rollback to baseline. |
| `SCENARIO_7` | Partial Mutation Rollback | Fault injected: `partial_mutation = True` | `ROLLED_BACK` | Partial state update caught by verification; rollback restores baseline. |
| `SCENARIO_8` | Verification Failure Rollback | Fault injected: `fail_verification = True` | `ROLLED_BACK` | Verification failure triggers automatic rollback to baseline. |
| `SCENARIO_9` | Corrupted Snapshot Abort | Fault injected: `corrupt_snapshot_hash = True` | `ABORTED` | Validation failure aborts transaction before mutation is attempted. |
| `SCENARIO_10`| Rollback Failure Safety Lock | Injected: `fail_mutation = True`, `fail_rollback = True` | `SAFETY_LOCKED` | Rollback failure latches `SAFETY_LOCKED`; subsequent calls blocked. |
| `SCENARIO_11`| Watchdog TTL Expiration | TTL = 60s, advance clock to 95s after heartbeat | `ROLLED_BACK` | Expired TTL triggers automatic compensation rollback via watchdog. |
| `SCENARIO_12`| Rollback Idempotency | Consecutive rollback calls on same transaction | `IDEMPOTENT_NOOP` | Second rollback returns success without repeated state mutation. |

---

## 4. Empirical Results & Findings

The experiment completed deterministically with **100% scenario pass rate** (12/12):

```json
{
  "experiment_id": "EXP-P3G-ROLLBACK-001",
  "operational_mode": "LiveMode.CONTROLLED_ENFORCEMENT (SIMULATED_BACKEND_ONLY)",
  "zero_network_mutation_guaranteed": true,
  "total_scenarios_evaluated": 12,
  "total_scenarios_passed": 12,
  "all_scenarios_passed": true,
  "total_transactions": 13,
  "total_rollbacks": 9,
  "rollback_success_rate_nominal": 1.0,
  "restoration_digest_verification_rate": 1.0,
  "safety_lock_behavior_verified": true,
  "watchdog_ttl_rollback_verified": true,
  "rollback_idempotency_verified": true
}
```

### 4.1 Key Quantitative Metrics

- **Total Transactions Executed**: 13 (10 primary scenarios + 1 follow-up safety lock verification + 1 watchdog transaction + 1 idempotency transaction).
- **Transaction Lifecycle Distribution**:
  - `COMMITTED`: 5 (Scenarios 1, 2, 3, 4, 11 prior to expiration)
  - `ROLLED_BACK`: 5 (Scenarios 5, 6, 7, 8, and Scenario 11 post-TTL)
  - `ABORTED`: 1 (Scenario 9: corrupted snapshot digest)
  - `SAFETY_LOCKED`: 2 (Scenario 10 primary failure + Scenario 10 blocked subsequent transaction)
- **Mean Transaction Execution Latency**: $0.021\,\text{ms}$ (pure in-memory simulation).
- **Rollback Operations Attempted**: 9 total.
- **Rollback Success Rate (Nominal Paths)**: $100.0\%$ (8/8 non-faulted rollback operations succeeded and verified).
- **Restoration Digest Verification Rate**: $100.0\%$ (all successful rollbacks confirmed that post-restoration SHA-256 matched pre-action snapshot SHA-256).
- **Idempotency Invariant**: Scenario 12 verified that a duplicate rollback on an already-restored transaction returned `success=True` with `final_safety_state="IDEMPOTENT_NOOP"` and zero state alteration.

### 4.2 Failure Mode Handling & Safety Lock Verification

1. **Pre-Mutation Abort (Scenario 9)**: When a snapshot digest mismatch is detected, the transaction terminates in `ABORTED` before `apply_mutation` is called. The backend state remains in pristine baseline.
2. **Automatic Compensation (Scenarios 5, 6, 7, 8)**: Any error during mutation application or post-action verification immediately triggers `_trigger_rollback`. In all 4 failure modes, the backend state was restored to baseline and verified.
3. **Permanent Safety Lock (Scenario 10)**: When rollback itself fails (`fail_rollback = True`), the manager enters `SAFETY_LOCKED` with an explicit reason logged (`Simulated rollback failure during state restoration`). All subsequent transaction requests (such as `ALLOW` on `192.168.1.110`) are immediately rejected with `TransactionState.SAFETY_LOCKED`, preventing unsafe operations.

---

## 5. Architectural Delineation: Implemented vs. Untested

To maintain absolute scientific rigor, the operational boundaries of Phase 3G must be explicitly demarcated:

### 5.1 Implemented & Empirically Verified
- **Formal Transaction State Machine**: Enforces atomicity across 11 lifecycle states.
- **Hash-Verified Snapshots**: SHA-256 digest validation of baseline state dictionaries.
- **Automatic Compensation Engine**: Safe restoration on exceptions, timeouts, partial mutations, and verification mismatches.
- **Restoration Verification Loop**: Strict comparison of post-rollback digest against snapshot digest.
- **Permanent Safety Lock Mechanism**: Non-bypassable lock preventing subsequent actions upon rollback failure.
- **Rollback Idempotency**: Safe, state-preserving handling of duplicate rollback requests.
- **Transaction Watchdog**: Heartbeat renewal and TTL expiration triggering automatic rollback.
- **Unit Test Suite**: 12/12 dedicated unit tests (`tests/unit/test_phase3_rollback.py`) + 336/336 global pytest suite green.

### 5.2 Untested Behavior & Current Limitations
- **Kernel-Level Network Mutations**: Linux `iptables`, `nftables`, `tc`, Open vSwitch, or physical switch flow table mutations were **NOT executed**. All tests utilized `SimulatedActuatorBackend`.
- **Operating System Race Conditions**: Concurrent modifications to host routing or firewall tables by external administrative processes (e.g., `ufw`, `firewalld`, Docker, Kubernetes CNI) are not modeled.
- **Physical Command Execution Latency**: Real subprocess invocation latencies (e.g., `iptables -A ...` taking $5\text{--}50\,\text{ms}$) were not part of this in-memory simulation.
- **Host Reboot Persistence**: Snapshots and transaction records reside in-memory; survivability across host crashes or system reboots is not implemented.

### 5.3 Requirements for Future Physical Lab Testing
Before any physical network mutation may be enabled in a future phase:
1. **Isolated Network Namespaces**: Testing must occur in isolated network namespaces (`netns`) connected via `veth` pairs, never on production interfaces.
2. **Atomic Kernel Transactions**: Actuator implementations must use atomic batch updates (e.g., `nft -f` or `iptables-restore --noflush`) rather than sequential CLI commands.
3. **Hardware / Daemon Watchdog**: A standalone daemon with an independent process supervisor or hardware watchdog to enforce TTL even if Python crashes.
4. **Physical Break-Glass Procedure**: Out-of-band management access and physical rollback scripts to flush all transient firewall tables.

---

## 6. Phase 3G Deliverables & Verification Checklist

- [x] `src/xrlids/response/transaction.py`: Complete transaction manager, simulated actuator, watchdog, and snapshot data models.
- [x] `src/xrlids/response/__init__.py`: Clean public API export of transaction classes.
- [x] `tests/unit/test_phase3_rollback.py`: 12 comprehensive unit tests covering all lifecycle transitions and failure paths.
- [x] `scripts/phase3/run_rollback_experiment.py`: Deterministic runner evaluating 12 empirical scenarios of `EXP-P3G-ROLLBACK-001`.
- [x] `results/phase3/EXP-P3G-ROLLBACK-001/`: 8 machine-readable artifacts with SHA-256 provenance metadata sidecars.
- [x] `docs/phase3/PHASE3G_ROLLBACK_REPORT.md`: Comprehensive empirical research report.
- [x] Zero system network mutation verified across all tests.
- [x] All 336 repository tests green (`.venv/bin/pytest -q`).
