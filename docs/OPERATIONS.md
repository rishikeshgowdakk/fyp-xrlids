# XRL-IDARS — Operations & Maintenance Runbook

**Document ID:** `DOC-OPS-RUNBOOK-001`  
**Version:** 1.0.0  
**Status:** COMPLETE & AUTHORITATIVE  
**Date:** October 30, 2026  

---

## 1. Routine Service Management

### Starting the Telemetry Dashboard:
```bash
.venv/bin/python scripts/demo/run_dashboard.py 8000
```

### Performing System Health Checks:
Verify that the REST API responds with healthy status:
```bash
curl -s http://localhost:8000/api/overview | grep '"status": "running"'
```

### Stopping or Restarting:
Use standard process termination (`Ctrl+C` or `SIGINT`). The dashboard server cleanly unbinds HTTP ports and flushes in-memory queues before exiting.

---

## 2. Telemetry Log Rotation & Memory Management

- **Flow Observations**: The dashboard maintains an in-memory deque capped at 500 recent flows.
- **Alert Records**: The alert history deque is capped at 200 records.
- **Garbage Collection**: Python memory remains strictly bounded under continuous operation.
- **Log Export**: Operators can export historical flows in CSV format via `GET /api/flows/export`.
