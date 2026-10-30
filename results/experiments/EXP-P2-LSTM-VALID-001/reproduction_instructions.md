# Reproduction Instructions: Valid LSTM Training & RF Comparison

**Experiment ID:** EXP-P2-LSTM-VALID-001  
**Target:** Reproducing the audit, training the verified LSTM, and executing the head-to-head comparison against Random Forest.  

---

## 1. Prerequisites & Environment
Ensure the pinned Python virtual environment is activated:
```bash
cd /home/rishikesh/Desktop/fyp-xrlids
source .venv/bin/activate
python --version  # Python 3.14.4
```

## 2. Dataset Verification
Verify the cached processed dataset or source CSV:
```bash
# Check raw file availability
ls -lh data/raw/cse_cic_ids2018/Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv

# Check preprocessed parquet cache
ls -lh data/processed/cse2018_flowseq/cse2018_flowseq_r10.parquet
```

## 3. Running the Valid Experiment
Execute the training and comparative evaluation runner:
```bash
python scripts/experiments/run_valid_lstm_experiment.py \
    --config results/experiments/EXP-P2-LSTM-VALID-001/training_config.yaml \
    --output-dir results/experiments/EXP-P2-LSTM-VALID-001 \
    --sample-limit 100000 \
    --epochs 10 \
    --seed 42
```

## 4. Expected Artifacts Generated
Upon completion, the experiment directory will contain:
- `split_manifest.json`: Verified chronological train/val/test boundary timestamps and sample counts.
- `training_log.json`: Epoch-by-epoch loss, training time, and validation PR-AUC metrics.
- `lstm_flowseq_best.pt`: Fresh PyTorch model checkpoint selected by early stopping.
- `preprocessor.joblib`: StandardScaler fitted strictly on Train split flows.
- `evaluation_metrics.json`: Multi-dimensional metrics (Acc, Prec, Rec, F1, PR-AUC, ROC-AUC, FPR, FNR, Latency) for RF vs LSTM on identical held-out test sequences.
- `rf_vs_lstm_comparison.md`: Scientific comparative report answering the flagship research question.
