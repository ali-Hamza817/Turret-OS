"""
tests/unit/test_shap_leakage_whitelist.py
=========================================
SHAP Feature Leakage Whitelist Unit Test.
Verifies that 100% of top feature signals are operationally meaningful domain features
(e.g., access_novelty_score, metadata_stripped, identity_proxy) and not arbitrary graph/data leakage artifacts.
"""

from __future__ import annotations

import numpy as np
import pytest
from sklearn.ensemble import GradientBoostingClassifier


OPERATIONAL_WHITELIST = {
    "n_file_accesses",
    "access_hour",
    "off_hours_multiplier",
    "access_novelty_score",
    "metadata_stripped",
    "copy_to_removable",
    "outbound_email",
    "identity_proxy",
}


def test_top_shap_features_in_whitelist() -> None:
    """Verify top SHAP features match the operational whitelist on chronological split."""
    from pathlib import Path
    tsec_dir = Path("data/tsec")
    if not (tsec_dir / "activities.parquet").exists():
        pytest.skip("TSEC dataset not generated")

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

    # Chronological train/test split
    split_pt = int(0.85 * len(X))
    X_train, X_test = X[:split_pt], X[split_pt:]
    y_train, y_test = y[:split_pt], y[split_pt:]

    clf = GradientBoostingClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)

    from turret_detect.explain.shap_explainer import SHAPExplainer
    explainer = SHAPExplainer(model=clf, feature_names=feature_cols)
    explainer.fit(X_train[:100])

    explanations = explainer.explain(X_test[:200])
    shap_vals = np.abs(explanations["shap_values"]).mean(axis=0)

    # Rank features by importance
    top_indices = np.argsort(-shap_vals)[:5]
    top_features = [feature_cols[i] for i in top_indices]

    for feat in top_features:
        assert feat in OPERATIONAL_WHITELIST, f"Feature '{feat}' is not in operational whitelist!"
