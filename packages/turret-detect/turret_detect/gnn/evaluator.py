"""
turret_detect.gnn.evaluator
=============================
Comprehensive metrics evaluator for TURRET OS GNN.
Computes all metrics required for Tables I–V in the paper:
- ROC-AUC, PR-AUC
- F1 @ FPR ∈ {0.1%, 0.5%, 1%}
- Matthews Correlation Coefficient
- Brier score
- Time-to-Detect (mean, p50, p95, p99)
"""

from __future__ import annotations

import logging
import time
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)


class Evaluator:
    """Compute all paper metrics from predictions and ground truth."""

    def __init__(self, fpr_thresholds: list[float] | None = None) -> None:
        self.fpr_thresholds = fpr_thresholds or [0.001, 0.005, 0.01]

    def evaluate(
        self,
        y_true: np.ndarray,
        y_prob: np.ndarray,
        detect_times: np.ndarray | None = None,
    ) -> dict[str, Any]:
        """
        Compute all evaluation metrics.

        Args:
            y_true:       (N,) binary ground truth labels
            y_prob:       (N,) predicted probabilities
            detect_times: (N,) time-to-detect in minutes (None if unavailable)

        Returns:
            dict with all metric values
        """
        from sklearn.metrics import (
            roc_auc_score, average_precision_score,
            matthews_corrcoef, brier_score_loss,
            roc_curve, precision_recall_curve, f1_score
        )

        metrics: dict[str, Any] = {}

        # ── Basic scores ──────────────────────────────────────────────────
        try:
            metrics["roc_auc"] = float(roc_auc_score(y_true, y_prob))
            metrics["pr_auc"] = float(average_precision_score(y_true, y_prob))
            metrics["brier_score"] = float(brier_score_loss(y_true, y_prob))
        except Exception as e:
            logger.warning("Basic metric computation failed: %s", e)
            metrics.update({"roc_auc": 0.0, "pr_auc": 0.0, "brier_score": 1.0})

        # ── F1 at target FPR thresholds ────────────────────────────────
        try:
            fpr_arr, tpr_arr, thresholds = roc_curve(y_true, y_prob)
            for target_fpr in self.fpr_thresholds:
                # Find threshold closest to target FPR
                idx = np.argmin(np.abs(fpr_arr - target_fpr))
                thresh = thresholds[idx] if idx < len(thresholds) else 0.5
                y_pred = (y_prob >= thresh).astype(int)
                f1 = float(f1_score(y_true, y_pred, zero_division=0))
                mcc = float(matthews_corrcoef(y_true, y_pred))
                key = f"f1_at_fpr_{int(target_fpr * 1000):03d}"
                metrics[key] = f1
                metrics[f"mcc_at_fpr_{int(target_fpr * 1000):03d}"] = mcc
        except Exception as e:
            logger.warning("FPR-threshold metrics failed: %s", e)

        # ── Global MCC at 0.5 threshold ────────────────────────────────
        try:
            y_pred_05 = (y_prob >= 0.5).astype(int)
            metrics["mcc"] = float(matthews_corrcoef(y_true, y_pred_05))
            metrics["f1"] = float(f1_score(y_true, y_pred_05, zero_division=0))
        except Exception as e:
            logger.warning("MCC/F1 computation failed: %s", e)

        # ── Time-to-detect ────────────────────────────────────────────
        if detect_times is not None and len(detect_times) > 0:
            positive_ttd = detect_times[y_true == 1]
            if len(positive_ttd) > 0:
                metrics["ttd_mean"] = float(np.mean(positive_ttd))
                metrics["ttd_p50"] = float(np.percentile(positive_ttd, 50))
                metrics["ttd_p95"] = float(np.percentile(positive_ttd, 95))
                metrics["ttd_p99"] = float(np.percentile(positive_ttd, 99))
            else:
                metrics.update({"ttd_mean": None, "ttd_p50": None, "ttd_p95": None, "ttd_p99": None})

        return metrics

    def evaluate_with_ci(
        self,
        y_true: np.ndarray,
        y_prob: np.ndarray,
        n_bootstrap: int = 1000,
        seed: int = 42,
    ) -> dict[str, Any]:
        """
        Compute metrics with 95% confidence intervals via bootstrap.
        Used for the paper's mean ± 95% CI reporting.
        """
        rng = np.random.default_rng(seed)
        n = len(y_true)

        bootstrap_metrics: dict[str, list[float]] = {}
        for _ in range(n_bootstrap):
            idx = rng.integers(0, n, size=n)
            m = self.evaluate(y_true[idx], y_prob[idx])
            for k, v in m.items():
                if isinstance(v, (int, float)) and v is not None:
                    bootstrap_metrics.setdefault(k, []).append(float(v))

        results: dict[str, Any] = {}
        for k, vals in bootstrap_metrics.items():
            arr = np.array(vals)
            results[k] = {
                "mean": float(np.mean(arr)),
                "ci_lower": float(np.percentile(arr, 2.5)),
                "ci_upper": float(np.percentile(arr, 97.5)),
                "std": float(np.std(arr)),
            }
        return results
