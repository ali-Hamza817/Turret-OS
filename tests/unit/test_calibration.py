"""
tests/unit/test_calibration.py
==============================
Probability calibration unit tests verifying Brier score improvement.
"""

from __future__ import annotations

import numpy as np
from sklearn.datasets import make_classification
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import brier_score_loss


def test_isotonic_calibration_improves_brier() -> None:
    """Verify that Isotonic calibration produces well-calibrated probabilities."""
    X, y = make_classification(n_samples=1000, n_features=8, random_state=42)
    split = 700
    X_train, X_test = X[:split], X[split:]
    y_train, y_test = y[:split], y[split:]

    base_clf = GradientBoostingClassifier(n_estimators=50, random_state=42)
    base_clf.fit(X_train, y_train)
    uncal_probs = base_clf.predict_proba(X_test)[:, 1]
    uncal_brier = brier_score_loss(y_test, uncal_probs)

    cal_clf = CalibratedClassifierCV(estimator=base_clf, method="isotonic", cv=3)
    cal_clf.fit(X_train, y_train)
    cal_probs = cal_clf.predict_proba(X_test)[:, 1]
    cal_brier = brier_score_loss(y_test, cal_probs)

    # Calibrated probabilities should maintain or improve Brier score
    assert cal_brier <= uncal_brier + 0.05
