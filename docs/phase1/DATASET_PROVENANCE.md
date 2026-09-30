# DATASET PROVENANCE

Status: **partial acquisition complete; 1 verified real dataset file present.**
Authoritative machine record: [`../../data/manifests/dataset_registry.yaml`](../../data/manifests/dataset_registry.yaml)

## Provenance declared

| Dataset | Source | Official page | Version declared | License | Status |
| --- | --- | --- | --- | --- | --- |
| CIC-IDS2017 | CIC, University of New Brunswick | https://www.unb.ca/cic/datasets/ids-2017.html | as-published-2017 | research use per CIC terms | `DATA_NOT_AVAILABLE` |
| CSE-CIC-IDS2018 | CSE + CIC, UNB / AWS Open Data | https://www.unb.ca/cic/datasets/ids-2018.html | as-published-2018 | research use / AWS Open Data | `PARTIAL` (1 file verified) |
| UNSW-NB15 | UNSW Canberra Cyber | https://research.unsw.edu.au/projects/unsw-nb15-dataset | as-published-2015 | research use per UNSW terms | `DATA_NOT_AVAILABLE` |

## Acquisition status and findings (checked 2026-09-30)

### 1. CSE-CIC-IDS2018 (`PARTIAL / VERIFIED FILE`)
- **Acquired File:** `data/raw/cse_cic_ids2018/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv`
- **Source:** AWS Registry of Open Data (`s3://cse-cic-ids2018/Processed Traffic Data for ML Algorithms/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv`)
- **File size:** 107,842,858 bytes (102.8 MB)
- **SHA-256:** `b0534c5d7d8b41e03df71c6966c995d116a8ed28e61f377c8b14cdf5d28f4edf`
- **Row count:** 331,125 data rows (+ 1 header row)
- **Column count:** 80 columns
- **Acquisition date:** 2026-09-30
- **Status:** Registered in manifest and verified against SHA-256 checksum.

### 2. CIC-IDS2017 (`DATA_NOT_AVAILABLE`)
- Primary mirror `iscxdownloads.cs.unb.ca` does not resolve from this network (DNS NXDOMAIN).
- Web portal `https://cicresearch.ca/CICDataset/CIC-IDS-2017/` requires manual web registration form and browser session; unauthenticated automated downloads return HTTP 403 Forbidden.
- Manual acquisition instructions: see `python scripts/phase1/prepare_dataset.py instructions`.

### 3. UNSW-NB15 (`DATA_NOT_AVAILABLE`)
- Official source link on UNSW research page directs to a personal Microsoft SharePoint repository requiring interactive Microsoft web authentication.
- Historical AARNet CloudStor mirror is decommissioned.
- Manual acquisition instructions: see `python scripts/phase1/prepare_dataset.py instructions`.

## Expected files

| Dataset | Expected CSVs | Reference notes recorded |
| --- | --- | --- |
| CIC-IDS2017 | 9 machine CSVs (one per capture day, CICFlowMeter) | label-header and duplicate-row artifacts to be re-verified by audit |
| CSE-CIC-IDS2018 | 8 day CSVs (names vary across mirrors) | heterogeneous per-file schemas expected; each file audited independently |
| UNSW-NB15 | testing-set, training-set, LIST_EVENTS | published reference row counts (175,341 / 82,332) recorded for later verification — NOT audit results |

## How to complete acquisition

```bash
python scripts/phase1/prepare_dataset.py instructions   # exact per-file instructions
# ... place files in data/raw/<dataset>/ ...
python scripts/phase1/prepare_dataset.py register --dataset <key> --all
python scripts/phase1/prepare_dataset.py verify   --dataset <key>
python scripts/phase1/03_run_audit.py             # schema + audit + label accounting
```

States used by the manifest: `not_acquired | partial | available | verified | failed`
(files: `expected | registered | verified | mismatch`). Nothing advances a state without
the corresponding evidence.
