# METRICS

Status: **implemented** in `src/xrlids/evaluation/metrics.py` — the single metrics module.

There is exactly one implementation. No script re-derives a metric, so a number cannot
mean two different things in two places. The generated implementation audit
([`../../reports/generated/metric_audit.md`](../../reports/generated/metric_audit.md)) is
produced from `metric_audit()` in that module.

## Conventions

- Positive class = `1` (ATTACK); negative class = `0` (BENIGN).
- `y_true` are hard labels; `y_score` are continuous scores.
- Every reported metric carries the **evaluation population** (counts and supports).

## Formulas

```text
Accuracy      = (TP + TN) / (TP + TN + FP + FN)
Precision     = TP / (TP + FP)
Recall        = TP / (TP + FN)              # sensitivity / TPR
F1            = 2PR / (P + R)
Macro-F1      = mean of per-class F1 (unweighted)
Weighted-F1   = support-weighted mean of per-class F1
Balanced Acc  = (TPR + TNR) / 2
Specificity   = TN / (TN + FP)
FPR           = FP / (FP + TN) = 1 - Specificity
FNR           = FN / (FN + TP) = 1 - Recall
```

- **ROC-AUC** — area under the TPR-vs-FPR curve, computed from **continuous scores**.
- **PR-AUC** — average precision, computed from **continuous scores**; preferred under
  heavy class imbalance because ROC-AUC can look optimistic when negatives dominate.

## Guard: AUC from scores, never from labels

`score_metrics()` rejects inputs whose values are a subset of `{0, 1}`. Passing thresholded
predictions into `roc_auc_score` silently produces a meaningless (often 0.5) AUC, so the
function raises `MetricError` instead.

## Undefined metrics return `None`, with a reason

If `y_true` contains a single class, ROC-AUC and PR-AUC are undefined. The function returns
`{"roc_auc": None, "pr_auc": None, "reason": "..."}` rather than a plausible-looking number.

## Imbalance

Accuracy is misleading when the classes are imbalanced, so every baseline report includes
macro-F1, balanced accuracy, FPR and FNR alongside accuracy, plus the confusion matrix.
