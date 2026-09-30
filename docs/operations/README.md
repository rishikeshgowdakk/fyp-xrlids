# OPERATIONS

Operational documentation for running XRL-IDARS, including how to reverse everything it does.

| Document | Purpose | Status |
| --- | --- | --- |
| `DEPLOYMENT_RUNBOOK.md` | Start/stop, configuration, modes, health checks | ⬜ |
| `ROLLBACK.md` | Reversing any applied block and returning to OBSERVE | ⬜ |
| `INCIDENT_REPLAY.md` | Replaying a historical incident through the system | ⬜ |
| `OBSERVABILITY.md` | Metrics and alerting expectations | ⬜ |

## Fail-safe behaviour (must hold in every mode)

| Failure | Required behaviour |
| --- | --- |
| ML API unavailable | Do not block; degrade to OBSERVE |
| Database unavailable | Do not block; buffer or drop events with a counter |
| Capture stops | Log and alert; do not fail silently |
| Model missing or wrong version | Refuse to enforce |
| Invalid / NaN feature | Refuse to enforce |
| DQN checkpoint missing | Fall back to non-enforcing default |
| Firewall command fails | Log and alert; verify state, never assume it applied |
| Queue overflow | Drop oldest with a counted metric; alert |

## Invariant

The system may fail to detect. It must **never** fail into blocking. Enforcement is opt-in and
gated; the default is non-enforcing.
