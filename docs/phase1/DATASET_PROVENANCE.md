# DATASET PROVENANCE

Status: **All 3 datasets acquired and verified (20 CSV files physically present, verified against SHA-256 digests).**
Authoritative machine record: [`../../data/manifests/dataset_registry.yaml`](../../data/manifests/dataset_registry.yaml)

## Provenance declared

| Dataset | Source | Official page | Version declared | License | Status | Provenance Class |
| --- | --- | --- | --- | --- | --- | --- |
| CIC-IDS2017 | CIC, University of New Brunswick | https://www.unb.ca/cic/datasets/ids-2017.html | as-published-2017 | research use per CIC terms | `VERIFIED` (8 files) | `third_party_mirror` |
| CSE-CIC-IDS2018 | CSE + CIC, UNB / AWS Open Data | https://www.unb.ca/cic/datasets/ids-2018.html | as-published-2018 | research use / AWS Open Data | `VERIFIED` (10 files) | `recognized_mirror` |
| UNSW-NB15 | UNSW Canberra Cyber | https://research.unsw.edu.au/projects/unsw-nb15-dataset | as-published-2015 | research use per UNSW terms | `VERIFIED` (2 modeling files) | `recognized_mirror` |

---

## Acquisition status and findings (verified 2026-10-01)

### 1. CIC-IDS2017 (`VERIFIED`)
- **Files present:** 8 day capture CSV files in `data/raw/cicids2017/`:
  - `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` (77,123,859 bytes) — SHA-256: `6ff1580f5f81c0ae28a26f7631721018577f5f7c5e0feac28b795fcfe7b411ee`
  - `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` (76,906,168 bytes) — SHA-256: `ca1824c51bfbb7b3c72290a11be04366ba8815878c6a1cc5c44cb1cee269e99b`
  - `Friday-WorkingHours-Morning.pcap_ISCX.csv` (64,078,574 bytes) — SHA-256: `b6770f5e1ad87bfd078ba1c3f914979e2c66ee6eb2e62eb747e70498eb18a7b9`
  - `Monday-WorkingHours.pcap_ISCX.csv` (150,915,084 bytes) — SHA-256: `a9b400780211f5619196d4981fe972e2cf3ab8a29906d4e51147055ec0319409`
  - `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` (83,439,788 bytes) — SHA-256: `4f7b60ea262c5a0fb76b9e289bf65d8365215c0e1ae5b184ef4fa682e0dfbc26`
  - `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` (48,154,643 bytes) — SHA-256: `955ae25178fc0480a4231b26543265ef25154378f895fb42a61ee48bc2109559`
  - `Tuesday-WorkingHours.pcap_ISCX.csv` (129,567,118 bytes) — SHA-256: `a3fec02c1144901f4c78161f3d64c0628e4fe66b8b0e60805fa60799ea48f95c`
  - `Wednesday-workingHours.pcap_ISCX.csv` (197,294,668 bytes) — SHA-256: `ea5447a16e7dd787ec38c4149fa89481229a8a7226db263889166f2ae9b4c022`
- **Source:** Third party mirror of CIC-IDS2017 `MachineLearningCSV.zip` (`third_party_mirror`). Primary UNB server `iscxdownloads.cs.unb.ca` is unreachable (NXDOMAIN), so mirror archive was verified by SHA-256.
- **Status:** All 8 files registered in manifest, verified against SHA-256, schema validated, and audited.

### 2. CSE-CIC-IDS2018 (`VERIFIED`)
- **Files present:** 10 day capture CSV files in `data/raw/cse_cic_ids2018/`:
  - `Friday-02-03-2018_TrafficForML_CICFlowMeter.csv` (352,368,373 bytes)
  - `Friday-16-02-2018_TrafficForML_CICFlowMeter.csv` (333,723,605 bytes)
  - `Friday-23-02-2018_TrafficForML_CICFlowMeter.csv` (382,840,456 bytes)
  - `Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv` (4,054,925,350 bytes; ~7.95M rows)
  - `Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv` (107,842,858 bytes)
  - `Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv` (375,945,899 bytes)
  - `Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv` (382,636,202 bytes)
  - `Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv` (358,223,333 bytes)
  - `Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv` (328,893,673 bytes)
  - `Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv` (209,249,758 bytes)
- **Source:** Recognized mirror / AWS Open Data mirror (`recognized_mirror`).
- **Status:** All 10 files registered in manifest, verified against SHA-256, schema validated, and audited.
- **Engineering Note:** The largest file (`Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv`, ~3.8 GiB) is processed strictly using chunked streaming pipelines (`chunk_size=100_000`) and float32 downcasting to prevent exceeding host memory limits.

### 3. UNSW-NB15 (`VERIFIED`)
- **Files present:** 2 modeling CSV files in `data/raw/unsw_nb15/`:
  - `UNSW_NB15_training-set.csv` (32,293,018 bytes) — SHA-256: `bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa`, reference rows: 175,341
  - `UNSW_NB15_testing-set.csv` (15,380,800 bytes) — SHA-256: `734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559`, reference rows: 82,332
- **Auxiliary file:** `UNSW-NB15_LIST_EVENTS.csv` is not present (`DATA_NOT_AVAILABLE`). This is an event metadata listing and not required for network flow modeling.
- **Source:** Recognized mirror of UNSW Canberra Cyber (`recognized_mirror`).
- **Status:** All 2 modeling files registered in manifest, verified against SHA-256, schema validated, and audited (total 257,673 rows).

---

## Verification and Audit Workflow

```bash
# Verify integrity of all registered files
python scripts/phase1/prepare_dataset.py verify --dataset cicids2017
python scripts/phase1/prepare_dataset.py verify --dataset cse_cic_ids2018
python scripts/phase1/prepare_dataset.py verify --dataset unsw_nb15

# Run chunked streaming audit across all datasets
python scripts/phase1/03_run_audit.py --chunk-size 100000
```
