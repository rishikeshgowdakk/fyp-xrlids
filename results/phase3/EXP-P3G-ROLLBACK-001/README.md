# Phase 3G Experiment Artifacts: Atomic Rollback & Controlled Response Transaction Harness

**Experiment Identifier**: `EXP-P3G-ROLLBACK-001`  
**Git Commit**: `bab43665fff76f5623cdd0dc0755d309c1b93027`  
**Operational Mode**: `LiveMode.CONTROLLED_ENFORCEMENT (SIMULATED_BACKEND_ONLY)`  
**Zero System Mutation**: `VERIFIED (True)` (0 iptables, 0 nftables, 0 tc, 0 sockets)  

## Artifact Inventory

- `experiment_config.json`: Specification of all 12 evaluated transaction lifecycle scenarios and fault injection parameters.
- `environment.json`: Execution environment fingerprint, hardware details, Python/PyTorch dependencies.
- `transaction_metrics.json`: Per-transaction timing, lifecycle state distribution, and audit card indicators.
- `rollback_metrics.json`: Compensation rollback outcomes, hash restoration verification counts, idempotency results, and safety lock triggers.
- `failure_injection_results.json`: Detailed scenario-by-scenario results across all 12 failure and nominal conditions.
- `safety_metrics.json`: Zero-mutation verification, critical host protection counters, and safety lock enforcement metrics.
- `run_summary.json`: Consolidated high-level execution summary.
