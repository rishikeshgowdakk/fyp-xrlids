# Phase 3H Empirical Research Report: Enforcement Readiness, Evidence Provenance & Non-Bypassable Activation Gate

**Document Identifier**: `REPORT-P3H-ENFORCEMENT-GATE-001`  
**Experiment Identifier**: `EXP-P3H-ENFORCEMENT-GATE-001`  
**Git Baseline**: `7d92f90893d2c91cd3ced78bed501cd9e34def4b`  
**Execution Timestamp**: `2026-10-04T14:30:00+00:00`  
**Operational Mode**: `LiveMode.OBSERVE / LiveMode.DRY_RUN`  
**Zero System Network Mutation**: `VERIFIED (True)` (0 iptables, 0 nftables, 0 tc, 0 sockets dropped)  
**Status**: `EMPIRICALLY VERIFIED & AUDITED`  

---

## 1. Executive Summary & Critical Safety Principle

Phase 3A through 3G established streaming packet capture, flow construction (D-006), R10 live feature parity, deterministic PCAP replay, latency characterization, observability telemetry, and atomic rollback harnesses.

However, having technical response infrastructure implemented is fundamentally different from being scientifically and operationally eligible to activate response in an isolated lab:

$$\mathbf{READY} \ne \mathbf{ENFORCEMENT}$$

A status of `READY` signifies exclusively that:
> *All required evidence and safety prerequisites across the lifecycle have been cryptographically and empirically verified, and the system is eligible to enter the isolated-lab activation boundary.*

**Under no circumstances does `READY` execute physical network mutations.** It does not mutate host firewall rules (iptables/nftables), alter routing tables, modify traffic control queues, drop host network sockets, or manipulate developer/host interfaces.

Phase 3H implements the formal, fail-closed **`PreconditionGate`** that stands between validated offline/live evidence and any response actuation.

---

## 2. Gating Architecture & Pipeline Placement

The `PreconditionGate` sits hierarchically above the Phase 3G transaction manager:

```text
       Existing Scientific Experiments (Phase 1, 2, 3A-3G)
                               │
                               ▼
               Evidence Collection & Provenance
             (Artifacts, Checksums, Commit Bindings)
                               │
                               ▼
        ┌──────────────────────────────────────────────┐
        │               PreconditionGate               │
        │                                              │
        │  [P1] Live Feature Parity Check              │
        │  [P2] Deterministic PCAP Replay Check        │
        │  [P3] Dry-Run Zero Mutation Check            │
        │  [P4] Deterministic Safety Invariants Check  │
        │  [P5] Phase 3G Rollback Verification Check   │
        │  [P6] Lab Activation Authorization Check     │
        └──────────────────────┬───────────────────────┘
                               │
                   Fail-Closed Evaluation
                               │
               ┌───────────────┴───────────────┐
               │                               │
        [Any Failure]                    [All Verified]
               │                               │
               ▼                               ▼
       ┌───────────────┐               ┌───────────────┐
       │ Status:LOCKED │               │ Status: READY │
       └───────┬───────┘               └───────┬───────┘
               │                               │
               ▼                               ▼
      Enforcement Refused             Transaction Manager
   (Default: OBSERVE/DRY_RUN)         (Lab-Only Actuator)
                                               │
                                               ▼
                                      Zero System Mutation
```

### Non-Bypassability Guarantee
The architecture strictly enforces:
$$\text{Configuration} \to \text{Policy} \to \text{Safety Gate} \to \text{PreconditionGate} \to \text{Authorization} \to \text{Transaction Manager} \to \text{Approved Actuator}$$

No CLI argument, configuration setting, or environment variable (e.g. `XRLIDS_FORCE_ENFORCEMENT`) can force or bypass gating. Attempts to bypass are caught as critical security alerts and immediately lock the gate.

---

## 3. Required Preconditions & Evidence Model

To eliminate fragile boolean flags (`if all_checks_pass:`), Phase 3H introduces structured, immutable **`PreconditionEvidence`** models:

```python
@dataclass(frozen=True)
class PreconditionEvidence:
    precondition: str        # e.g., P1_FEATURE_PARITY
    experiment_id: str       # Bound experiment ID
    status: str              # Must be "PASS"
    commit_sha: str          # Cryptographic commit binding
    artifact_id: str         # File identifier
    artifact_path: str       # Physical path on disk
    artifact_digest: str     # SHA-256 digest of artifact
    generated_at: str        # ISO 8601 UTC timestamp
    schema_version: str      # Version identifier
    metrics: dict[str, Any]  # Domain metrics
    provenance: dict[str, Any]
```

### The 6 Preconditions Evaluated:

1. **P1 — Live Feature Parity (`P1_FEATURE_PARITY`)**:
   - Live streaming flow extraction vs. offline canonical formulas across all 10 features.
   - Verification: `status == PASS`, `all_features_pass == True`, `max_feature_error <= 1e-3`.
2. **P2 — Deterministic PCAP Replay (`P2_PCAP_REPLAY`)**:
   - Replay pipeline processing reproducibility under burst conditions (`EXP-P3-BURST-1000-001`).
   - Verification: `status == PASS`, `packets_captured > 0`, `capture_errors == 0`.
3. **P3 — Dry-Run Pipeline (`P3_DRY_RUN`)**:
   - Full perception-to-decision pipeline running in non-enforcing dry-run mode (`EXP-P3F-OBSERVABILITY-001`).
   - Verification: `status == PASS`, `zero_network_mutation_guaranteed == True`, `firewall_rules_mutated == 0`.
4. **P4 — Safety Invariants (`P4_SAFETY_INVARIANTS`)**:
   - Automated audit of deterministic safety constraints (cooldown, blast radius, critical infrastructure exemptions).
   - Verification: `status == PASS`, `critical_infrastructure_exemptions_passed >= 1`, `zero_network_mutation_guaranteed == True`.
5. **P5 — Rollback Mechanism (`P5_ROLLBACK_HARNESS`)**:
   - Empirical proof of atomic transaction snapshots, auto-compensation rollback, and permanent safety locking (`EXP-P3G-ROLLBACK-001`).
   - Verification: `status == PASS`, `rollback_success_rate_nominal == 1.0`, `restoration_digest_verification_rate == 1.0`, `safety_lock_behavior_verified == True`.
6. **P6 — Activation Authorization (`P6_ACTIVATION_AUTHORIZATION`)**:
   - Explicit, signed, time-bounded token issued specifically for isolated lab activation (`LabActivationAuthorization`).
   - Verification: `status == ACTIVE`, `scope == "ISOLATED_LAB_CONTROLLED_RESPONSE_ONLY"`, `lab_environment_id == "LAB-ISOLATED-NETNS-01"`, `allowed_actuator_backend_id == "SIMULATED_ACTUATOR_V1"`, valid time window, valid signature.

---

## 4. Cryptographic Provenance, Integrity & Freshness

The gate enforces three layers of artifact verification:

1. **Commit Binding**: The evidence's `commit_sha` must match `target_commit_sha` (or an explicitly registered ancestor). Evidence from an unrelated commit is rejected with `COMMIT_SHA_MISMATCH`.
2. **Disk Digest Verification**: The physical artifact file on disk is read, and its SHA-256 checksum is recomputed via `sha256_file`. Any discrepancy between the recorded `artifact_digest` and the physical file triggers `ARTIFACT_DIGEST_MISMATCH`. Missing files trigger `ARTIFACT_NOT_FOUND`; corrupt JSON triggers `ARTIFACT_MALFORMED`.
3. **Deterministic Freshness**: The timestamp `generated_at` is evaluated against the current clock. Evidence exceeding `max_evidence_age_s` (7 days) or with future timestamps triggers `EVIDENCE_STALE`.

---

## 5. Empirical Results (`EXP-P3H-ENFORCEMENT-GATE-001`)

The experiment evaluated 18 deterministic scenarios designed to test every nominal path, boundary condition, and failure mode:

| Scenario | Condition / Injected Failure | Result Status | Triggered Reason Code | Verified Behavior |
|---|---|---|---|---|
| `SCENARIO_1` | Complete Valid Chain | **READY** | None | Full prerequisite chain and authorization verified |
| `SCENARIO_2` | Feature Parity Failure (`status="FAIL"`) | **LOCKED** | `EVIDENCE_STATUS_NOT_PASS` | Parity regression immediately halts eligibility |
| `SCENARIO_3` | PCAP Replay Failure (`capture_errors=5`) | **LOCKED** | `METRIC_VERIFICATION_FAILED` | Replay errors halt eligibility |
| `SCENARIO_4` | Dry Run Failure (`mutations=3`) | **LOCKED** | `METRIC_VERIFICATION_FAILED` | Non-zero mutation in dry run halts eligibility |
| `SCENARIO_5` | Safety Invariant Failure (Exemption failed) | **LOCKED** | `METRIC_VERIFICATION_FAILED` | Critical host violation halts eligibility |
| `SCENARIO_6` | Rollback Evidence Failure (rate < 1.0) | **LOCKED** | `METRIC_VERIFICATION_FAILED` | Incomplete rollback evidence halts eligibility |
| `SCENARIO_7` | Missing Evidence (Omit P5 rollback) | **LOCKED** | `PRECONDITION_MISSING` | Omission of any prerequisite halts eligibility |
| `SCENARIO_8` | Stale Evidence (Age = 30 days) | **LOCKED** | `EVIDENCE_STALE` | Expired evidence halts eligibility |
| `SCENARIO_9` | Wrong Commit (`deadbeef...`) | **LOCKED** | `COMMIT_SHA_MISMATCH` | Evidence from foreign commit halts eligibility |
| `SCENARIO_10`| Artifact Tampering (Digest mismatch) | **LOCKED** | `ARTIFACT_DIGEST_MISMATCH` | Content modification detected and halted |
| `SCENARIO_11`| Expired Authorization Token | **LOCKED** | `AUTHORIZATION_EXPIRED` | Expired token halts eligibility |
| `SCENARIO_12`| Wrong Lab ID (`PROD-EXTERNAL-NET`) | **LOCKED** | `AUTHORIZATION_LAB_MISMATCH` | Out-of-lab authorization halts eligibility |
| `SCENARIO_13`| Unauthorized Backend (`IPTABLES_DIRECT`) | **LOCKED** | `AUTHORIZATION_ACTUATOR_MISMATCH` | Non-approved actuator halts eligibility |
| `SCENARIO_14`| Multiple Simultaneous Failures | **LOCKED** | Multiple Codes | All failure reasons captured; fail closed |
| `SCENARIO_15`| Malformed Evidence File (Corrupt JSON) | **LOCKED** | `ARTIFACT_MALFORMED` | Handled gracefully without crash |
| `SCENARIO_16`| Internal Evaluation Exception | **LOCKED** | `INTERNAL_EVALUATION_EXCEPTION` | Unexpected exception fails closed safely |
| `SCENARIO_17`| Config Bypass Attempt (`FORCE=1`) | **LOCKED** | `CONFIGURATION_BYPASS_ATTEMPT` | Bypass detected; zero actuator calls |
| `SCENARIO_18`| Valid Activation Boundary Execution | **READY** | None | Transaction committed in simulator; **0 host mutations** |

### Summary Statistics ([`run_summary.json`](../../results/phase3/EXP-P3H-ENFORCEMENT-GATE-001/run_summary.json)):
- **Total Scenarios Evaluated**: 18
- **Total Scenarios Passed**: 18 (100.0%)
- **READY Scenarios**: 2 (Scenarios 1 and 18)
- **LOCKED Scenarios**: 16 (Scenarios 2–17)
- **Host Firewall Mutations**: Exactly 0
- **Host Routing Table Mutations**: Exactly 0
- **Traffic Control (tc/qdisc) Mutations**: Exactly 0
- **Network Sockets Dropped**: Exactly 0
- **Real Physical Actuator Executions**: Exactly 0

---

## 6. What Phase 3H Proves vs. What It Does NOT Prove

### What Phase 3H Proves:
1. **Deterministic Fail-Closed Boundary**: The system reliably refuses enforcement eligibility on any missing, corrupted, stale, or unauthorized evidence.
2. **Cryptographic & Artifact Traceability**: Precondition evidence cannot be spoofed by modifying JSON files or pointing to unrelated commits.
3. **Non-Bypassability**: Environment variables and configuration overrides cannot force actuation.
4. **Integration with Phase 3G**: `ControlledResponseTransactionManager` strictly honors the gate output and blocks execution when locked.

### What Phase 3H Does NOT Prove:
1. **Does NOT prove production readiness**: The system is intended strictly for research and isolated laboratory validation.
2. **Does NOT prove safe operation on unmanaged public networks**: Gating applies only to an isolated network namespace (`LAB-ISOLATED-NETNS-01`).
3. **Does NOT prove immunity to kernel bugs**: The underlying kernel network stack (`veth`, `ebpf`, `nftables`) may have separate concurrency or OS-level failure modes not captured by the Python layer.
4. **Does NOT authorize physical actuation**: Phase 3H evaluated readiness using the approved in-memory simulator (`SIMULATED_ACTUATOR_V1`).

---

## 7. Deliverables Checklist

- [x] `src/xrlids/enforcement/gate.py`: Implemented `PreconditionGate`, `PreconditionEvidence`, `LabActivationAuthorization`, `EnforcementEligibility`.
- [x] `src/xrlids/enforcement/__init__.py`: Clean public API export.
- [x] `src/xrlids/response/transaction.py`: Integrated readiness verification into `ControlledResponseTransactionManager`.
- [x] `src/xrlids/response/__init__.py`: Re-exported enforcement gate models.
- [x] `tests/unit/test_phase3_gate.py`: 17 dedicated unit tests covering all prerequisite checks, bypass detection, and manager integration.
- [x] `scripts/phase3/run_enforcement_gate_experiment.py`: Deterministic runner evaluating 18 empirical scenarios.
- [x] `results/phase3/EXP-P3H-ENFORCEMENT-GATE-001/`: 8 machine-readable artifacts with SHA-256 metadata sidecars.
- [x] Zero physical network mutations verified.
- [x] Full test suite regression passes (353 passed, 3 warnings).
