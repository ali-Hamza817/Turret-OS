"""
tests/unit/test_detection_quality.py
=====================================
Detection quality unit tests asserting held-out performance bounds.
"""

from __future__ import annotations

import numpy as np
import pytest
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from turret_detect.gnn.evaluator import Evaluator


def test_heldout_detection_quality() -> None:
    """Verify that classifier achieves ROC-AUC >= 0.85 on held-out test data."""
    from pathlib import Path
    tsec_dir = Path("data/tsec")
    if not (tsec_dir / "activities.parquet").exists():
        pytest.skip("TSEC data not generated")

    import pandas as pd
    acts = pd.read_parquet(tsec_dir / "activities.parquet")
    labels = pd.read_parquet(tsec_dir / "labels.parquet")
    merged = acts.merge(labels, on=["user_id", "date", "day_idx"], how="left")
    merged["is_malicious"] = merged["is_malicious"].fillna(False).astype(int)

    feature_cols = [
        "n_file_accesses", "access_hour", "off_hours_multiplier",
        "access_novelty_score", "metadata_stripped", "copy_to_removable",
        "outbound_email", "identity_proxy",
    ]
    X = merged[feature_cols].fillna(0).values.astype(np.float32)
    y = merged["is_malicious"].values.astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, stratify=y, random_state=42
    )

    clf = GradientBoostingClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)

    y_prob = clf.predict_proba(X_test)[:, 1]
    evaluator = Evaluator()
    metrics = evaluator.evaluate(y_test, y_prob)

    assert metrics["roc_auc"] >= 0.85, f"Held-out ROC-AUC {metrics['roc_auc']:.4f} < 0.85"
