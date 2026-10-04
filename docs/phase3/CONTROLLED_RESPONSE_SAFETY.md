# Controlled Autonomous Response: Safety Architecture & Rollback Specification

**Document Identifier**: `SPEC-P3-SAFETY-ROLLBACK-001`  
**Status**: `PRE-REGISTERED SAFETY CONTRACT`  
**Mandate**: Zero real network mutations may occur until the complete rollback contract is formally specified, implemented in isolation, and independently verified.  

---

## 1. Safety Invariants & Operational Modes

XRL-IDARS governs autonomous mitigation actions through three strictly isolated operating modes:

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        XRL-IDARS OPERATING MODES                       │
├────────────────────────────────────────────────────────────────────────┤
│ 1. OBSERVE (Default)                                                   │
│    - Passively captures packets and builds flows.                     │
│    - Evaluates detector scores S_t and state s_t.                     │
│    - Emits read-only monitoring telemetry.                            │
│    - NEVER executes response policy, safety gate, or enforcement.     │
├────────────────────────────────────────────────────────────────────────┤
│ 2. DRY_RUN (Next Safe Development Target)                              │
│    - Executes complete pipeline: Capture → Flows → Detector → State   │
│      → RL Policy → Deterministic Safety Gate → Audit Cards.           │
│    - Computes both proposed action a_t and enforced action a*_t.      │
│    - Generates full explainability audit cards and logs overrides.    │
│    - STRICT INVARIANT: ZERO mutations to iptables, nftables, routing  │
│      tables, traffic control (tc), or network sockets.                │
├────────────────────────────────────────────────────────────────────────┤
│ 3. CONTROLLED_ENFORCEMENT (Strictly Locked Behind Gating Preconditions)│
│    - Only permitted in dedicated, isolated lab network environments.  │
│    - Gated on the verified precondition chain:                         │
│      parity PASS → replay PASS → dry-run PASS → safety PASS → rollback PASS │
│    - Requires cryptographically signed operator activation token.      │
│    - Requires live transactional rollback daemon.                     │
└────────────────────────────────────────────────────────────────────────┘
```

The system configuration **strictly defaults to `OBSERVE`**.

---

## 2. Enforcement Precondition Chain (§75)

```text
┌─────────────────────────────────────────────────────────┐
│ 1. Live Feature Parity Verified (atol <= 1e-4)          │
└───────────────────────────┬─────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────┐
│ 2. PCAP Replay Pipeline Verified (Deterministic Ladder) │
└───────────────────────────┬─────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────┐
│ 3. Dry-Run Autonomous Pipeline Verified (Zero Mutations)│
└───────────────────────────┬─────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────┐
│ 4. Deterministic Safety Invariants Pass Automated Audit │
└───────────────────────────┬─────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────┐
│ 5. Rollback Mechanism Independently Tested & Verified   │
└───────────────────────────┬─────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────┐
│ 6. Optional Controlled Enforcement (Isolated Lab Only)   │
└─────────────────────────────────────────────────────────┘
```

**Non-Bypassable Rule**: If any stage in the chain produces an error, exception, or test failure, the system remains locked in `OBSERVE` or `DRY_RUN`.

---

## 3. Atomic Transaction & State Snapshot Architecture

When operating in `CONTROLLED_ENFORCEMENT` (in a future lab deployment), any mitigation action (e.g., `RATE_LIMIT` or `ISOLATE`) must follow an atomic transactional lifecycle:

```text
State Snapshot S_pre
        ↓
Validate Safety Invariants (Safety Gate)
        ↓
Begin Enforcement Transaction
        ↓
Apply Action via Actuator Backend
        ↓
Verify Actuator Health & Socket Status
        ↓ [Success]                    ↓ [Failure / Timeout / Crash]
Commit Transaction & Log Audit Card    Automatic Rollback to S_pre
```

### Transaction Steps:
1. **Pre-Action Snapshot ($S_{\text{pre}}$)**:
   - Capture current kernel firewall state (table rules, chains, active rate limits).
   - Record active timestamps, affected host IP/subnet, and reason code.
2. **Deterministic Safety Validation**:
   - Verify critical host exemption (default gateway, DNS, DC can never be isolated).
   - Verify blast radius circuit breaker ($\le 5\%$ isolated hosts).
   - Verify 30-step action cooldown.
3. **Execution Window & Heartbeat**:
   - Each applied mitigation action is assigned an automatic **Time-To-Live (TTL)** (default: 60.0s).
   - If the controller crashes or the daemon fails to emit a heartbeat before TTL expires, the kernel watchdog automatically flushes the transient rules.
4. **Post-Action State Verification**:
   - Actuator executes command and verifies zero non-zero return codes.
   - If actuator fails, immediate compensation rollback is triggered.

---

## 4. Rollback Mechanism

### Rollback Contract:
```python
class RollbackBackend(Protocol):
    def snapshot(self) -> StateSnapshot:
        """Capture current firewall / network state."""
        ...
    def rollback(self, snapshot: StateSnapshot) -> RollbackResult:
        """Atomically restore network state to snapshot."""
        ...
    def verify_clean_state(self) -> bool:
        """Verify all temporary rules/chains are purged."""
        ...
```

### Rollback Guarantees:
- **Idempotency**: Invoking `rollback()` multiple times produces identical state without error.
- **Fail-Safe Restoration**: On any failure during rollback, the system defaults to safe state (flushing custom XRL-IDARS chains, preserving baseline host connectivity).
- **Operator Override**: A dedicated CLI command (`xrlids rollback --force`) and manual killswitch script immediately restores baseline network configurations.

---

## 5. Dependency Failure Handling & Fail-Safe Invariants

Any failure of an upstream or internal dependency **MUST FAIL SAFE**:

| Component Failure | Nature of Failure | Fail-Safe Behavior | Policy Action Clamped To |
|:---|:---|:---|:---:|
| **Packet Capture Buffer** | Buffer overflow / dropped packets | Log error counter, continue processing without crashing | N/A (Observational) |
| **Flow Assembler** | Malformed packet / invalid IP header | Increment `malformed_packets` counter, skip packet | N/A |
| **Phase 1 Detector** | Inference exception / unhandled NaN | Catch exception, record failure event, log error | **`ALLOW`** |
| **Phase 2 DQN Agent** | GPU/CPU exception / tensor dimension mismatch | Fall back to deterministic Baseline 1 or default | **`ALLOW` / `ALERT`** |
| **TreeSHAP Explainer** | Attribution timeout or memory error | Log unexplainable event; do NOT block safety gate | Keep proposed action if valid, log warning |
| **Deterministic Safety Gate** | Corrupted state / unexpected input | Strict fail-safe clamp: forbid disruptive actions | **`ALLOW`** |
| **Actuator Backend** | Command failure / iptables lock contention | Abort transaction, trigger rollback, downgrade action | **`ALERT`** |
| **Audit Persistence** | Disk full / write error | Log to emergency stderr buffer; fail safe | **`ALLOW`** |

**Zero Fail-Open Guarantee**: Under no circumstance does an unhandled exception lead to unmanaged network isolation or persistent network partition.
