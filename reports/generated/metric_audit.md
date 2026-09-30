# Metric implementation audit (generated)

Every metric used in this project comes from one module (`src/xrlids/evaluation/metrics.py`).

| metric | formula | implementation | input | edge cases |
| --- | --- | --- | --- | --- |
| accuracy | (TP+TN)/(TP+TN+FP+FN) | explicit counts | hard labels | defined for all populations |
| precision | TP/(TP+FP) | sklearn.metrics.precision_score(pos_label=1, zero_division=0) | hard labels | 0 when no positive predictions |
| recall | TP/(TP+FN) | sklearn.metrics.recall_score(pos_label=1, zero_division=0) | hard labels | 0 when no positive support |
| f1 | 2PR/(P+R) | sklearn.metrics.f1_score(pos_label=1, zero_division=0) | hard labels | 0 when P=R=0 |
| macro_f1 | mean of per-class F1 | sklearn.metrics.f1_score(average='macro') | hard labels | unweighted; sensitive to minority class |
| weighted_f1 | support-weighted mean of per-class F1 | sklearn.metrics.f1_score(average='weighted') | hard labels | dominated by majority class |
| balanced_accuracy | (TPR+TNR)/2 | sklearn.metrics.balanced_accuracy_score | hard labels | robust to imbalance |
| specificity | TN/(TN+FP) | explicit counts | hard labels | None when no negatives |
| fpr | FP/(FP+TN) | explicit counts | hard labels | None when no negatives |
| fnr | FN/(FN+TP) | explicit counts | hard labels | None when no positives |
| roc_auc | area under TPR-vs-FPR curve | sklearn.metrics.roc_auc_score | CONTINUOUS scores | None if one class present; rejects 0/1 scores |
| pr_auc | average precision | sklearn.metrics.average_precision_score | CONTINUOUS scores | None if one class present; prefer over ROC-AUC under imbalance |
