"""Metrics tests: hand-computed values and the guard against 0/1 scores."""

from __future__ import annotations

import numpy as np
import pytest

from xrlids.evaluation.metrics import (
    MetricError,
    binary_metrics,
    confusion_counts,
    evaluate,
    metric_audit,
    score_metrics,
)


def test_confusion_counts_known_values():
    y_true = [0, 0, 1, 1]
    y_pred = [0, 1, 0, 1]
    assert confusion_counts(y_true, y_pred) == {"tn": 1, "fp": 1, "fn": 1, "tp": 1}


def test_binary_metrics_hand_computed():
    # TN=1 FP=1 FN=1 TP=1 -> accuracy .5, precision .5, recall .5, f1 .5, fpr .5, fnr .5
    m = binary_metrics([0, 0, 1, 1], [0, 1, 0, 1])
    assert m["accuracy"] == pytest.approx(0.5)
    assert m["precision"] == pytest.approx(0.5)
    assert m["recall"] == pytest.approx(0.5)
    assert m["f1"] == pytest.approx(0.5)
    assert m["fpr"] == pytest.approx(0.5)
    assert m["fnr"] == pytest.approx(0.5)
    assert m["specificity"] == pytest.approx(0.5)
    assert m["population"] == 4


def test_binary_metrics_perfect():
    m = binary_metrics([0, 1, 1], [0, 1, 1])
    assert m["accuracy"] == 1.0 and m["f1"] == 1.0 and m["fnr"] == 0.0


def test_all_negative_prediction_does_not_divide_by_zero():
    m = binary_metrics([0, 1, 1], [0, 0, 0])
    assert m["recall"] == 0.0
    assert m["precision"] == 0.0
    assert m["fpr"] == 0.0


def test_score_metrics_rejects_thresholded_predictions():
    with pytest.raises(MetricError, match="thresholded"):
        score_metrics([0, 1, 1, 0], [0, 1, 1, 0])


def test_score_metrics_returns_none_for_single_class():
    out = score_metrics([1, 1, 1], [0.2, 0.7, 0.9])
    assert out["roc_auc"] is None
    assert "one class" in out["reason"]


def test_score_metrics_auc_on_separable_scores():
    out = score_metrics([0, 0, 1, 1], [0.1, 0.2, 0.8, 0.9])
    assert out["roc_auc"] == pytest.approx(1.0)
    assert out["pr_auc"] == pytest.approx(1.0)


def test_evaluate_combines_thresholded_and_continuous():
    out = evaluate([0, 0, 1, 1], [0.1, 0.4, 0.6, 0.9], threshold=0.5)
    assert out["confusion"] == {"tn": 2, "fp": 0, "fn": 0, "tp": 2}
    assert out["threshold"] == 0.5
    assert out["roc_auc"] == pytest.approx(1.0)


def test_metric_audit_documents_every_metric():
    audit = metric_audit()
    names = {a["metric"] for a in audit}
    for required in {"accuracy", "precision", "recall", "f1", "macro_f1", "roc_auc", "pr_auc", "fpr", "fnr"}:
        assert required in names


def test_non_finite_scores_rejected():
    with pytest.raises(MetricError):
        score_metrics([0, 1], [0.2, np.inf])
