# Phase 3F Experiment Artifacts: Observability & Operational Health

**Experiment Identifier**: `EXP-P3F-OBSERVABILITY-001`  
**Git Commit**: `2bd1507a865f746a82afb9f0d5251a1189932b0c`  
**Operational Mode**: `LiveMode.DRY_RUN`  
**Zero System Mutation**: `VERIFIED (True)`  

## Artifact Inventory

- `experiment_config.json`: Complete specification of experimental conditions, queue parameters, and health thresholds.
- `environment.json`: Execution environment fingerprint, hardware details, Python/PyTorch dependencies.
- `health_metrics.json`: Evaluated HealthState transitions (HEALTHY, DEGRADED, FAILED_SAFE).
- `queue_metrics.json`: High watermark, queue latencies, and backpressure drop metrics.
- `failure_injection_results.json`: Outcomes of the 6 fault injection scenarios.
- `safety_metrics.json`: Deterministic safety gate telemetry, failsafe event counters, and zero-mutation verification.
- `run_summary.json`: Consolidated multi-condition execution summary.
