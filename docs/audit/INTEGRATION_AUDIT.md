# XRL-IDARS — Backend, Dashboard & API Integration Audit

**Document Path:** `docs/audit/INTEGRATION_AUDIT.md`  
**Date:** 2026-10-28  
**Repository:** `https://github.com/rishikeshgowdakk/fyp-xrlids`  
**Status:** Verification of Backend API Contracts, Security Boundaries & UI State

---

## 1. System Architecture & Service Topology

The demonstration and operations dashboard is implemented with a lightweight, zero-dependency architecture:
- **Backend:** Python standard library `ThreadingHTTPServer` (`dashboard/server.py`), binding exclusively to `127.0.0.1`.
- **Frontend:** Pure HTML5, CSS3, and vanilla JavaScript (`dashboard/index.html`, `dashboard/app.js`). No Node.js, npm, or webpack build pipeline required.

```
Browser Client (127.0.0.1:8000)
       │  HTTP GET / POST (JSON / CSV / Static Assets)
       ▼
dashboard.server.DashboardHandler
 ├── Origin & CSRF Validator (_validate_origin)
 ├── Static Asset Handler (index.html, app.js, figures/*.png)
 ├── REST API Endpoints:
 │    ├── /api/overview, /api/benchmarks, /api/evaluation
 │    ├── /api/flows, /api/flows/export, /api/explainability
 │    ├── /api/live (snapshot, start, stop, devices, scenarios)
 │    └── /api/csv (sample, evaluate, explain, export)
 └── Subsystem Bridges:
      ├── CSVEvaluator (src/xrlids/evaluation/csv_evaluator.py)
      ├── LiveLabMonitor (src/xrlids/demo/live_lab.py)
      └── PacketCaptureService (src/xrlids/live/capture.py)
```

---

## 2. API Contract & Endpoint Schema Audit

| Endpoint | HTTP Method | Request Body / Parameters | Response Schema | Status Codes | Error Handling |
|:---|:---:|:---|:---|:---:|:---|
| `/api/overview` | `GET` | None | System status, benchmark counts, fleet accuracy, active mode | `200` | Fallback default structure |
| `/api/benchmarks` | `GET` | None | List of registered benchmarks (CIC2017, CSE2018, UNSW) | `200` | Static registry |
| `/api/evaluation` | `GET` | `?benchmark=...&slice=...` | Metrics, confusion matrices, ROC/PR curves | `200` | Defaults to CIC-IDS2017 |
| `/api/flows` | `GET` | `?page=1&limit=50&status=...` | Paginated flow records with endpoints and verdicts | `200` | Clamped pagination |
| `/api/flows/export` | `GET` | `?benchmark=...&status=...` | CSV download (`text/csv; charset=utf-8`) | `200` | Streaming buffer |
| `/api/live` | `GET` | None | Current live session snapshot, rolling flows, active alerts | `200` | Thread-safe copy |
| `/api/live/devices`| `GET` | None | Passive observed devices (IP, MAC, vendor, evidence) | `200` | Memory table |
| `/api/live/start` | `POST` | `{"mode": "...", "interface": "...", "pcap": "..."}` | Session status, capture backend, config echo | `200`, `400` | Path traversal & interface checks |
| `/api/live/stop` | `POST` | None | `{"status": "stopped", "stats": {...}}` | `200` | Idempotent stop |
| `/api/live/inject-attack`| `POST`| `{"scenario": "syn_flood_burst"}` | Injected scenario metadata and packet counts | `200`, `400` | Scenario validation |
| `/api/csv/evaluate`| `POST` | `{"mode": "...", "csv_text": "...", "benchmark": "..."}` | Multi-model evaluation results, metrics, 3 confusion matrices | `200`, `400`, `500`| Structured `CSVValidationError` |
| `/api/csv/explain` | `POST` | `{"features": {...}, "benchmark": "..."}` | TreeSHAP per-feature attributions & base value | `200`, `400` | Shape normalized |
| `/api/csv/export` | `POST` | `{"evaluation_id": "..."}` | Server-side verified evaluated CSV string | `200`, `404` | Anti-tampering cache check |

---

## 3. Web Security & Boundary Defenses

### A. Origin & Host Header Validation (`_validate_origin`)
- **DNS Rebinding Defense:** Rejects requests where `Host` header does not match `127.0.0.1`, `localhost`, `::1`, or `testserver`.
- **CSRF / Cross-Origin Protection:** Inspects `Origin` and `Sec-Fetch-Site`. Rejects any request originating from an external web domain or marked `cross-site` with `HTTP 403 Forbidden`.

### B. Path Traversal Defense (`_is_safe_pcap_path`)
- PCAP paths provided to `/api/live/start` are validated:
  - Must resolve to an existing regular file with `.pcap`, `.pcapng`, or `.cap` extension.
  - Path must reside strictly within the repository tree or system `/tmp` directory.
  - Directory traversal sequences (`../`) are neutralized by `Path.resolve()`.

---

## 4. UI Transparency & Honest Status Disclosure

1. **Simulation vs Operational Reality:**
   - Synthetic attack injection (`/api/live/inject-attack`) is prominently labeled in the UI as *In-Memory Synthetic Traffic Generator*.
   - Sample traffic replay is clearly distinguished from live hardware packet capture with a warning badge when running without `CAP_NET_RAW`.
2. **Offline Evaluation Separation:**
   - Mode B (200-flow exhibition demo) is explicitly marked as a *Subset Demonstration*, preventing confusion with the full 355k held-out test evaluation.
   - The UI displays three independent confusion matrices (Random Forest, LSTM, and Fusion) so operators can inspect the individual contributions of each detection layer.
