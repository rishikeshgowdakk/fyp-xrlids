# Autonomous Response Architecture & Safety Governance
**Project:** Explainable Reinforcement Learning-Based Intrusion Detection and Autonomous Response System (XRL-IDARS)  
**Artifact ID:** `SPEC-AUTONOMOUS-RESPONSE-001`  
**Classification:** Operational Security & Response Architecture Specification  
**Status:** IMPLEMENTED & EMPIRICALLY VERIFIED  

---

## 1. Non-Negotiable Operational Safety Invariants

Autonomous response in production networks carries immense operational risk: an incorrect isolation of a core service (e.g., DNS, Domain Controller, Default Gateway) can inflict greater business disruption than the cyberattack itself.

XRL-IDARS enforces five non-negotiable safety invariants:

1. **Advisory / Dry-Run Default:** The system boots in `advisory_mode = True` by default. Mitigation actions are evaluated, authorized, and logged, but actual kernel mutations (`iptables`, `nftables`, `tc`, routing tables) are strictly simulated via `SimulatedActuatorBackend`.
2. **Critical Infrastructure Immunity:** Whitelisted critical hosts (`192.168.10.1` Gateway, `192.168.10.50` DNS/DC, `192.168.10.2` Backup DNS) are mathematically exempt from `ISOLATE` and `RATE_LIMIT`. The Safety Gate clamps any proposed disruptive action on these hosts to `ALERT`.
3. **Blast Radius Circuit Breaker:** The system monitors the simultaneous isolation fraction across all tracked endpoints. If active isolations exceed **5.0%** of the host population, subsequent `ISOLATE` actions are automatically downgraded to `ALERT` to prevent cascading outages.
4. **Mandatory Action Cooldown ($T_{\text{cool}} = 30\text{s}$):** Disruptive actions are locked against rapid oscillation (action chattering). An isolated or rate-limited host cannot be rapidly toggled back to `ALLOW` without completing the cooldown period.
5. **Atomic Transaction Lifecycle with Verified Rollback:** Every mitigation must be verified by `ResponseVerifier`. If post-action verification detects collateral impact or fails to observe the mitigation effect, the `ControlledResponseTransactionManager` automatically executes compensation rollback.

---

## 2. The 5-Stage Action Lifecycle

```
[PROPOSED] ──> [AUTHORIZED] ──> [EXECUTED] ──> [VERIFIED] ──> [EXPIRED / ROLLED_BACK]
     │              │               │               │
     └──> [REJECTED]                 └──> [ABORTED]  └──> [COMPENSATION ROLLBACK]
```

### Stage 1: PROPOSED
- Upstream Reinforcement Learning policy (Dueling DQN) or Hybrid Decision Engine recommends an action $a_t \in \{\text{ALLOW}, \text{ALERT}, \text{RATE\_LIMIT}, \text{ISOLATE}\}$ based on the causal state vector $\mathbf{s}_t$.

### Stage 2: AUTHORIZED
- The `DeterministicSafetyGate` evaluates inviolable safety invariants:
  - Is the target host on the Critical Infrastructure Exemption list?
  - Does this action exceed the 5% blast-radius threshold?
  - Is the endpoint currently bound by an active cooldown timer?
- If all checks pass, the action transitions to `AUTHORIZED`. If an invariant is violated, the action is clamped or transitioned to `REJECTED`.

### Stage 3: EXECUTED
- Handed off to the `ControlledResponseTransactionManager`.
- In `advisory_mode=True`, execution is dispatched to the in-memory `SimulatedActuatorBackend` with zero host mutations.
- In hardware lab mode (`advisory_mode=False`), an immutable SHA256 snapshot of system state is recorded prior to applying firewall/traffic-shaping rules.

### Stage 4: VERIFIED
- `ResponseVerifier` executes active post-action verification:
  - Confirms target host is present in active mitigation tables.
  - Confirms zero collateral disruption to critical services (DNS port 53, Gateway, DHCP).
  - Computes verification latency.
- If verified, the transaction transitions to `COMMITTED` and logs an execution report. If collateral disruption is detected, automatic rollback is triggered immediately.

### Stage 5: EXPIRED / ROLLED_BACK
- Every active mitigation carries a strict Time-To-Live (default $TTL = 300\text{ seconds}$).
- The `TransactionWatchdog` or `ResponseExecutor.check_expirations()` scans active mitigations; upon TTL expiration, normal network access is automatically restored.
- If compensation rollback fails during an abort, the manager permanently locks into `SAFETY_LOCKED` requiring administrative intervention.

---

## 3. RL Outcome Feedback & Experience Logging

To enable offline reinforcement learning without risking online policy instability:
- Live production runs with **frozen DQN inference** (`torch.no_grad()`).
- The `ResponseOutcomeFeedbackLoop` records each transition tuple:
  $$\tau_t = (\mathbf{s}_t, a_t, r_t, \mathbf{s}_{t+1}, d_t)$$
- Environmental reward $r_t$ is computed via the multi-objective reward function:
  $$r_t = R_{\text{containment}} - R_{\text{disruption}} - R_{\text{overhead}}$$
- Transitions are buffered in memory and appended to `results/audits/rl_transitions.jsonl` for offline policy evaluation (OPE) and batch RL refinement.
