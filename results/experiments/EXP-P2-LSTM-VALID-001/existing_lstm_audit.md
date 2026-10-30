# Forensic Audit of Existing LSTM Checkpoints & Sequence Infrastructure

**Experiment ID:** EXP-P2-LSTM-VALID-001  
**Project:** XRL-IDARS  
**Date:** 2026-10-30  
**Artifacts Audited:**
- `models/lstm/lstm_cicids2017.pt` (SHA256: `2cdbf88d2eda358619d66a5d001fa7dde8ab3a36d8e0548c8c529ae8e8870f5c`)
- `models/lstm/lstm_cse2018.pt` (SHA256: `ea5b8198c20faa15d5d45ae7d081b754a76dbae1342a93b8234e0e06cfe8a33a`)
- `models/lstm/lstm_unswnb15.pt` (SHA256: `4d9386ff44c99eed822f8ace5c64429fab571b4f8aad847d6cc78bae5f308fbd`)
- Training source scripts: `src/xrlids/pipeline.py`, `src/xrlids/models/lstm.py`

---

## 1. Forensic Inspection of Existing Checkpoints

The three canonical LSTM models registered in `models/registry/registry.yaml` were inspected:

```python
LSTMDetector(
    params={'hidden_size': 32, 'num_layers': 2, 'dropout': 0.2, 'learning_rate': 0.001, 'batch_size': 256, 'epochs': 15, 'patience': 3},
    feature_names=['flow_duration_ms', 'flow_packets_per_s', 'flow_bytes_per_s', 'packet_length_mean', 'packet_length_std', 'syn_count', 'ack_count', 'rst_count', 'fin_count', 'syn_ack_ratio'],
    seq_len=5,
    label_rule='last',
    seed=42
)
```

### Registered Performance in `registry.yaml`:
- `lstm_cicids2017.pt`: Test F1 = 0.9633, Test Accuracy = 0.9867 (vs RF F1 = 0.9512)
- `lstm_cse2018.pt`: Test F1 = 0.9603, Test Accuracy = 0.9912 (vs RF F1 = 0.8861)
- `lstm_unswnb15.pt`: Test F1 = 0.8637, Test Accuracy = 0.8683 (vs RF F1 = 0.8548)

---

## 2. Root Cause Analysis: How Were the Existing Sequences Generated?

Inspection of `results/experiments/EXP-P1-CIC2017-R10-001/split_manifest.json` and `results/experiments/EXP-P1-CSE2018-R10-MULTI-001/split_manifest.json` revealed:

```json
{
  "methodology": "stratified_random",
  "ordering_basis": "arrival_order",
  "group_column": null,
  "time_column": null,
  "ratios": { "train": 0.6, "validation": 0.2, "test": 0.2 }
}
```

In `src/xrlids/pipeline.py` (lines 185-214):
```python
split_result = build_splits(feature_frame, labels, available, split_config, dataset=dataset)
train = split_result.splits["train"]
...
train_seqs = build_sequences(X_train, y_train, split="train", seq_len=seq_len)
```

In `src/xrlids/models/lstm.py` (`build_sequences`):
```python
for start in range(0, n_rows - seq_len + 1, stride):
    if grp_arr is not None:
        ...
    origins_list.append(start)
    label = int(targets[start + seq_len - 1])
```

### Critical Flaws Identified:
1. **Random Flow Adjacency**: Because the data was split using `stratified_random`, adjacent rows in `X_train` and `X_test` were randomly sampled flows. A single sequence of 5 rows contained flows from different hours, different machines, and different IP subnets.
2. **Pseudo-Sequences**: The LSTM was not learning temporal recurrence or packet-flow dynamics; it was acting as an ensemble smoother over 5 randomly juxtaposed feature vectors.
3. **No Inter-Flow Timing**: The sequence input vectors lacked any temporal interval feature ($\Delta t$).
4. **Empirical Proof via Ablation**: In `results/ablations/lstm_temporal_ablation.json`, when row order was deliberately destroyed by shuffling before sequence generation, the model's F1-score changed by $\Delta F1 = -0.0038$. The "temporal" advantage was completely non-existent.

---

## 3. Audit Verdict on Existing Checkpoints

| Checkpoint | Suitability for Live Inference | Suitability for Research Claims | Action Required |
| :--- | :---: | :---: | :--- |
| `lstm_cicids2017.pt` | ❌ Unsuitable | ❌ Unsuitable | Retain frozen for auditability; do not use as scientific evidence. |
| `lstm_cse2018.pt` | ❌ Unsuitable | ❌ Unsuitable | Retain frozen for auditability; do not use as scientific evidence. |
| `lstm_unswnb15.pt` | ❌ Unsuitable | ❌ Unsuitable | Retain frozen for auditability; do not use as scientific evidence. |

**Conclusion:** The existing LSTM checkpoints cannot be claimed as valid temporal sequence models. A genuine, scientifically defensible LSTM must be trained on authentic chronological sequences grouped by host IP.
