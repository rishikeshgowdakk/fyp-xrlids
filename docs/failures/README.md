# FAILURE INVESTIGATIONS

Failures are findings, not embarrassments. A failed experiment that is documented is worth
more than a success that cannot be reproduced.

Use [`../templates/FAILURE_REPORT_TEMPLATE.md`](../templates/FAILURE_REPORT_TEMPLATE.md) and
record each investigation as `docs/failures/<FAILURE_ID>.md`.

## Categorisation (§80)

| Category | Who decides |
| --- | --- |
| Technical bug (ImportError, shape mismatch, path error) | Agent may fix independently: fix → test → document |
| Data problem (unexpected label, schema mismatch, missing field) | Agent investigates, then reports problem/evidence/interpretations/fixes/impact; **asks user if methodology changes** |
| Scientific ambiguity (which metric is primary, merge families, drop outliers) | Agent presents alternatives; **does not decide** |
| Safety issue | **Stop before enforcement** |

## Planned failure injections (§72)

| ID | Injected failure | Expected safe behaviour | Status |
| --- | --- | --- | --- |
| F-001 | ML API unavailable | degrade, do not block | ⬜ |
| F-002 | Database unavailable | buffer/drop with counter, do not block | ⬜ |
| F-003 | Scapy capture stops | log + alert | ⬜ |
| F-004 | Model file missing | refuse to enforce | ⬜ |
| F-005 | Wrong model version | refuse to enforce | ⬜ |
| F-006 | Invalid feature value | refuse to enforce | ⬜ |
| F-007 | NaN feature | refuse to enforce | ⬜ |
| F-008 | DQN checkpoint missing | non-enforcing fallback | ⬜ |
| F-009 | Firewall command fails | log + alert + verify | ⬜ |
| F-010 | Network interface disappears | log + alert | ⬜ |
| F-011 | Excessive packet rate | shed load, counted metric | ⬜ |
| F-012 | Queue overflow | drop oldest, alert | ⬜ |

## Recorded investigations

_None yet._
