# Experiment EXP-P3I-ISOLATED-LAB-001: Isolated Lab Network Namespace & Controlled Response Loop

## 1. Experiment Overview
- **Experiment Identifier**: `EXP-P3I-ISOLATED-LAB-001`
- **Git Commit**: `d28f358bd31d3aeba97455e0bd2617d626447dfa`
- **Execution Date**: `2026-10-04T14:48:07.260679+00:00`
- **Lab Environment ID**: `LAB-ISOLATED-NETNS-01`
- **Actuator Backend ID**: `LAB_NETNS_ACTUATOR_V1`
- **Backend Execution Mode**: `VIRTUAL_ISOLATED_NETNS`
- **Attacker IP / NS**: `10.200.1.2` / `xrlids_att_01`
- **Victim IP / NS**: `10.200.1.3` / `xrlids_vic_01`
- **Lab Subnet**: `10.200.1.0/24`

## 2. Strict Safety Guarantees & Host Accounting
- **Zero Host Network Mutations**: `100% GUARANTEED`
- **Host Interfaces Mutated**: `0`
- **Host Routes Mutated**: `0`
- **Host iptables Rules Mutated**: `0`
- **Host nftables Rules Mutated**: `0`
- **Host tc qdiscs Mutated**: `0`
- **Host Sockets Dropped**: `0`
- **Pre-Execution Baseline SHA256**: `aaec733f8e2ffe2277eda36d871c2c187e5db2a14389fba89281f4626636c84f`
- **Post-Execution Baseline SHA256**: `aaec733f8e2ffe2277eda36d871c2c187e5db2a14389fba89281f4626636c84f`
- **Baseline Match**: `TRUE` (Mathematically unmodified)

## 3. Results Summary
- **16-Stage End-to-End Execution**: `16/16` stages PASSED (100.0%)
- **16-Scenario Failure Injection Matrix**: `16/16` scenarios PASSED (100.0%)
- **Packets Ingested**: `100`
- **Flows Constructed**: `50`
- **Mitigation Transaction**: `RATE_LIMIT` committed -> verified -> rolled back -> verified clean state.
- **Rollback Success Rate**: `100.0%`
- **Restoration Verification Rate**: `100.0%`
- **Lab Teardown State**: `CLEANED`

## 4. Generated Artifacts
1. `host_network_baseline_pre.json` (+ `.meta.json`)
2. `host_network_baseline_post.json` (+ `.meta.json`)
3. `host_network_mutation_accounting.json` (+ `.meta.json`)
4. `lab_topology_manifest.json` (+ `.meta.json`)
5. `lab_traffic_execution.json` (+ `.meta.json`)
6. `lab_response_transactions.json` (+ `.meta.json`)
7. `failure_injection_matrix.json` (+ `.meta.json`)
8. `phase3i_metrics.json` (+ `.meta.json`)
