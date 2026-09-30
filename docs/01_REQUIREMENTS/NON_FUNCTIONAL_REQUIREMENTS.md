# NON-FUNCTIONAL REQUIREMENTS

Status: draft.

## Reproducibility

| ID | Requirement | Target | Status |
| --- | --- | --- | --- |
| NFR-001 | Any published metric is regenerable from config + code + commit | 100% of claims | ⬜ |
| NFR-002 | Random seeds are recorded for every stochastic step | all training/eval | ⬜ |
| NFR-003 | Library versions are pinned and hashed per experiment | lockfile + env hash | ⬜ |
| NFR-004 | Dataset integrity is checksum-enforced | SHA256 per file | ⬜ |

## Auditability

| ID | Requirement | Target | Status |
| --- | --- | --- | --- |
| NFR-005 | Every prediction is traceable to a model version and input population | event schema | ⬜ |
| NFR-006 | Every response action is reversible and logged | audit log entry per action | ⬜ |
| NFR-007 | Documentation cannot drift from evidence | metrics injected by report generator, never hand-typed | ⬜ |

## Performance (Phase 3)

| ID | Requirement | Target | Status |
| --- | --- | --- | --- |
| NFR-008 | Component and end-to-end latency are measured separately (feature extraction, RF, LSTM, Fusion, SHAP, DQN, API, E2E) | report P50/P95/P99 | ⬜ |
| NFR-009 | Throughput and resource use are profiled (packets/s, flows/s, CPU, RAM, queue depth, drops) | `results/realtime/` | ⬜ |
| NFR-010 | Performance targets are set only after a baseline measurement exists | avoid invented SLOs | ⬜ |

## Safety and security

| ID | Requirement | Target | Status |
| --- | --- | --- | --- |
| NFR-011 | Default operating mode is non-enforcing (OBSERVE or DRY-RUN) | config default | ⬜ |
| NFR-012 | Protected/management/localhost/gateway sources can never be blocked | `configs/safety/protected_sources.yaml` | ⬜ |
| NFR-013 | Blocking requires minimum confidence, repeat observation, cooldown, and is duration-limited | safety policy | ⬜ |
| NFR-014 | No environment-specific network addresses are hard-coded in the repository | review | ⬜ |
| NFR-015 | The system only enforces on traffic it has authority over | controlled lab only | ⬜ |
| NFR-016 | Secrets are never committed | `.gitignore` + review | ⬜ |

## Scientific integrity

| ID | Requirement | Target | Status |
| --- | --- | --- | --- |
| NFR-017 | Test set is touched once, after all selection is frozen | split policy | ⬜ |
| NFR-018 | Negative and non-reproduced results are reported, not dropped | all experiments | ⬜ |
| NFR-019 | Claims are registered with evidence and can be downgraded | `CLAIMS_REGISTRY.md` | ⬜ |
| NFR-020 | Uncertainty and blockers are surfaced, never hidden | blocked-decision format | ⬜ |

## Maintainability

| ID | Requirement | Target | Status |
| --- | --- | --- | --- |
| NFR-021 | Research code and operational code are separated | `src/` vs `services/` | ⬜ |
| NFR-022 | Tests cover data, model, API and system layers | `tests/` | ⬜ |
| NFR-023 | The repository answers the five levels of questions (What/How/Why/Evidence/Failure) | `docs/viva/` | ⬜ |
