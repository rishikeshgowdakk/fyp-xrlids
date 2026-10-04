# EXP-P3J-CONCURRENCY-001: Multi-Flow Soak + Concurrency + Shared-State Stress Report

## 1. Experiment Overview
- **Experiment Identifier**: `EXP-P3J-CONCURRENCY-001`
- **Git Commit**: `ed9bd59e5ef24c4cef90aea131bcd1fa788c0690`
- **Timestamp**: `2026-10-04T15:30:20.649400+00:00`
- **Subnet**: `10.200.1.0/24`
- **Victim Pool**: `['10.200.1.3', '10.200.1.4', '10.200.1.5', '10.200.1.6', '10.200.1.7', '10.200.1.8']`
- **Concurrency Level**: `8` workers
- **Backend**: `LAB_NETNS_ACTUATOR_V1` (VIRTUAL_ISOLATED_NETNS)

## 2. Experimental Scenarios Evaluated
1. **Scenario A — Sequential Baseline**: 10 transactions sequentially executed, verified, and rolled back.
2. **Scenario B — Two Concurrent Victims**: 12 simultaneous transactions across `10.200.1.3` and `10.200.1.4`, verifying independent isolation and zero cross-contamination.
3. **Scenario C — Many Concurrent Victims**: 24 transactions across 6 victim endpoints with 8 concurrent workers.
4. **Scenario D — Overlapping One Victim**: 12 concurrent requests targeting the same victim endpoint, verifying lock contention tracking and safe serialization.
5. **Soak Workload**: 120 synthetic flows (~1,200 packets) generated across 6 victim endpoints, concurrent transaction processing, watchdog TTL enforcement, and clean state restoration.
6. **Failure Injection Matrix**: 12/12 scenarios passed under concurrency.

## 3. Strict Safety & Host Immutability
- **Zero Host Network Mutations**: `100% GUARANTEED`
- **Host Interfaces Mutated**: `0`
- **Host Routes Mutated**: `0`
- **Host iptables Rules Mutated**: `0`
- **Host nftables Rules Mutated**: `0`
- **Host tc qdiscs Mutated**: `0`
- **Host Sockets Dropped**: `0`
- **Pre-Execution Baseline SHA256**: `aaec733f8e2ffe2277eda36d871c2c187e5db2a14389fba89281f4626636c84f`
- **Post-Execution Baseline SHA256**: `aaec733f8e2ffe2277eda36d871c2c187e5db2a14389fba89281f4626636c84f`
- **Baseline Match**: `TRUE` (Mathematically identical)

## 4. Generated Artifacts
1. `experiment_config.json` (+ `.meta.json`)
2. `environment.json` (+ `.meta.json`)
3. `concurrency_metrics.json` (+ `.meta.json`)
4. `transaction_metrics.json` (+ `.meta.json`)
5. `rollback_metrics.json` (+ `.meta.json`)
6. `queue_metrics.json` (+ `.meta.json`)
7. `failure_injection_results.json` (+ `.meta.json`)
8. `safety_metrics.json` (+ `.meta.json`)
9. `resource_cleanup.json` (+ `.meta.json`)
10. `run_summary.json` (+ `.meta.json`)
